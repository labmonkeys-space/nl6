/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// NETCONF call home: the device opens the TCP connection to a NETCONF
// client, writes its dialect's preamble, and then serves NETCONF over SSH on
// that connection exactly as its listener would. The timing values come from
// vJunos 25.4R1.12 with `outbound-ssh client ... keep-alive retry 3 timeout
// 15`: attempts on a fixed 15 s grid with no backoff, one keepalive per 15 s.
// See context/netconf.md.

// These are variables so tests can shorten them. An exporter copies them
// when it is built.
var (
	netconfCallHomeCycle           = 15 * time.Second
	netconfCallHomeKeepAlive       = 15 * time.Second
	netconfCallHomeKeepAliveMisses = 3
	// netconfCallHomePreambleTimeout bounds the preamble write, so a client
	// that accepts and never reads cannot park the exporter.
	netconfCallHomePreambleTimeout = 10 * time.Second
)

// netconfCallHomeMaxDeviceID bounds the device id, which goes on the wire
// in the preamble.
const netconfCallHomeMaxDeviceID = 255

// netconfCallHomeUnsupportedLogged remembers the profiles already logged as
// having no call home, so each is named once.
var netconfCallHomeUnsupportedLogged sync.Map

// DeviceNetconfCallHomeConfig is the per-device call-home configuration. A
// nil pointer on the device means no call home.
//
// Client is the NETCONF client to dial, host:port. DeviceID is the id the
// preamble carries; empty means the device's sysName.
type DeviceNetconfCallHomeConfig struct {
	Client   string `json:"client"`
	DeviceID string `json:"device_id,omitempty"`
}

// Validate checks the block. Safe on nil.
func (c *DeviceNetconfCallHomeConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.Client == "" {
		return fmt.Errorf("netconf_callhome: client is required (host:port)")
	}
	host, port, err := net.SplitHostPort(c.Client)
	if err != nil || host == "" {
		return fmt.Errorf("netconf_callhome: client %q is not host:port", c.Client)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("netconf_callhome: client %q has an invalid port (must be 1..65535)", c.Client)
	}
	// Devices dial from an IPv4-only namespace, so an IPv6 client would
	// fail every attempt.
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return fmt.Errorf("netconf_callhome: client %q is IPv6; devices dial over IPv4 only", c.Client)
	}
	if len(c.DeviceID) > netconfCallHomeMaxDeviceID {
		return fmt.Errorf("netconf_callhome: device_id is %d bytes, at most %d", len(c.DeviceID), netconfCallHomeMaxDeviceID)
	}
	for i := 0; i < len(c.DeviceID); i++ {
		if !netconfCallHomeIDByte(c.DeviceID[i]) {
			return fmt.Errorf("netconf_callhome: device_id must be printable ASCII without spaces")
		}
	}
	return nil
}

// ValidateFor also refuses a device id for more than one device: every
// device would announce the same DEVICE-ID, and a client that keys devices
// by it could not tell them apart.
func (c *DeviceNetconfCallHomeConfig) ValidateFor(deviceCount int) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c != nil && c.DeviceID != "" && deviceCount > 1 {
		return fmt.Errorf("netconf_callhome: device_id names one device but %d are requested; omit it so each device sends its sysName", deviceCount)
	}
	return nil
}

func netconfCallHomeIDByte(b byte) bool { return b >= 0x21 && b <= 0x7e }

// netconfCallHomeDefaultID turns a sysName into a DEVICE-ID that keeps the
// preamble well-formed: bytes outside printable ASCII, spaces included,
// become '-', and the result is cut to netconfCallHomeMaxDeviceID.
func netconfCallHomeDefaultID(sysName string) string {
	b := []byte(sysName)
	if len(b) > netconfCallHomeMaxDeviceID {
		b = b[:netconfCallHomeMaxDeviceID]
	}
	for i := range b {
		if !netconfCallHomeIDByte(b[i]) {
			b[i] = '-'
		}
	}
	return string(b)
}

// netconfCallHomeExporter is one device's call-home loop. srv owns no
// listener: it only tracks the one connection the loop dialed, so Close
// stops the session the same way a listener's Close does.
type netconfCallHomeExporter struct {
	client   string
	preamble []byte
	srv      *netconfServer
	dial     func(ctx context.Context) (net.Conn, error)
	phase    time.Duration
	cycle    time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// agg is the client's aggregate. The exporter counts into it directly,
	// so the totals include deleted devices without a fold at stop, and a
	// status read never sees one device twice.
	agg       *netconfCallHomeAggregate
	sessionUp atomic.Bool
}

func (e *netconfCallHomeExporter) start() {
	e.wg.Add(1)
	go e.run()
}

// close stops the loop and the session and waits for both.
func (e *netconfCallHomeExporter) close() {
	e.cancel()
	_ = e.srv.Close()
	e.wg.Wait()
}

// run makes one attempt per cycle tick. Ticks sit on a grid anchored at the
// first one, so an attempt after a session ends waits for the next tick.
func (e *netconfCallHomeExporter) run() {
	defer e.wg.Done()
	t := time.NewTimer(e.phase)
	defer t.Stop()
	var anchor time.Time
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		if anchor.IsZero() {
			anchor = now
		}
		e.attempt()
		if e.ctx.Err() != nil {
			return
		}
		now = time.Now()
		next := anchor.Add((now.Sub(anchor)/e.cycle + 1) * e.cycle)
		t.Reset(next.Sub(now))
	}
}

// attempt dials once and, on success, serves the session until it ends.
// The server's onHandshake marks the session up, so a connection whose SSH
// handshake fails counts as a handshake failure, not as a session.
func (e *netconfCallHomeExporter) attempt() {
	e.agg.connectAttempts.Add(1)
	conn, err := e.dial(e.ctx)
	if err != nil {
		e.agg.connectFailures.Add(1)
		return
	}
	if len(e.preamble) > 0 {
		// close cancels ctx before it closes srv, and srv does not track
		// conn yet, so ctx must interrupt a stalled write.
		stop := context.AfterFunc(e.ctx, func() { _ = conn.Close() })
		_ = conn.SetWriteDeadline(time.Now().Add(netconfCallHomePreambleTimeout))
		_, err := conn.Write(e.preamble)
		stop()
		if err != nil {
			e.agg.connectFailures.Add(1)
			_ = conn.Close()
			return
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}
	if !e.srv.track(conn) {
		_ = conn.Close()
		return
	}
	e.srv.serveConn(conn)
	if e.sessionUp.Swap(false) {
		e.agg.sessionsEnded.Add(1)
	} else {
		e.agg.handshakeFailures.Add(1)
	}
}

// netconfCallHomeAggregate holds a client's counters, live and deleted
// devices together.
type netconfCallHomeAggregate struct {
	connectAttempts    atomic.Uint64
	connectFailures    atomic.Uint64
	handshakeFailures  atomic.Uint64
	sessionsEnded      atomic.Uint64
	devicesUnsupported atomic.Uint64
}

func (sm *SimulatorManager) netconfCallHomeAggregateFor(client string) *netconfCallHomeAggregate {
	v, _ := sm.netconfCallHomeAggregates.LoadOrStore(client, &netconfCallHomeAggregate{})
	return v.(*netconfCallHomeAggregate)
}

// startDeviceNetconfCallHome builds and starts the call-home exporter of a
// device that has netconfCallHomeConfig set and whose NETCONF listener runs.
// A profile without call home is skipped and counted, not refused, so one
// batch config can cover a mixed fleet. On error the caller clears the
// config.
func (sm *SimulatorManager) startDeviceNetconfCallHome(d *DeviceSimulator) error {
	if d == nil || d.netconfCallHomeConfig == nil {
		return nil
	}
	cfg := *d.netconfCallHomeConfig
	if !sm.netconfSubsystemActive.Load() {
		return fmt.Errorf("netconf call home: NETCONF subsystem is off (-netconf-enable)")
	}
	dia, ok := netconfDialectFor(d)
	if !ok || !dia.CallHome {
		sm.netconfCallHomeAggregateFor(cfg.Client).devicesUnsupported.Add(1)
		profile := resourceDirName(d.resourceFile)
		if _, seen := netconfCallHomeUnsupportedLogged.LoadOrStore(profile, true); !seen {
			log.Printf("netconf call home: profile %s has no call home; its devices are skipped and counted as unsupported", profile)
		}
		d.mu.Lock()
		d.netconfCallHomeConfig = nil
		d.mu.Unlock()
		return nil
	}
	if sm.sharedSSHSigner == nil {
		return fmt.Errorf("netconf call home: no shared SSH host key")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.netconfCallHome != nil {
		return nil
	}
	if d.netconfSessions == nil {
		return fmt.Errorf("netconf call home: device %s serves no NETCONF listener", d.IP)
	}
	id := cfg.DeviceID
	if id == "" {
		id = netconfCallHomeDefaultID(d.sysName)
	}
	var preamble []byte
	if dia.CallHomePreamble != nil {
		preamble = dia.CallHomePreamble(id)
	}
	srv := d.newNetconfServer(nil, sm, dia)
	srv.cfg = newDeviceSSHConfig(sm.sharedSSHSigner)
	srv.keepAlive = netconfCallHomeKeepAlive
	srv.keepAliveMisses = netconfCallHomeKeepAliveMisses
	// A client that accepts and never speaks SSH is as dead as one that
	// misses every keepalive, so it gets the same time.
	srv.handshakeTimeout = netconfCallHomeKeepAlive * time.Duration(netconfCallHomeKeepAliveMisses)

	ns, ip, client := d.netNamespace, d.IP, cfg.Client
	if !sm.useNamespace {
		ns = nil
	}
	dial := func(ctx context.Context) (net.Conn, error) {
		return dialFromDevice(ctx, netconfCallHomeDialSem, ns, ip, client)
	}

	cycle := netconfCallHomeCycle
	ctx, cancel := context.WithCancel(context.Background())
	e := &netconfCallHomeExporter{
		client:   cfg.Client,
		preamble: preamble,
		srv:      srv,
		dial:     dial,
		phase:    netconfCallHomePhase(cycle),
		cycle:    cycle,
		agg:      sm.netconfCallHomeAggregateFor(cfg.Client),
		ctx:      ctx,
		cancel:   cancel,
	}
	srv.onHandshake = func() { e.sessionUp.Store(true) }
	d.netconfCallHome = e
	e.start()
	return nil
}

// stopNetconfCallHome closes the device's call-home exporter. Its counters
// already live in the client aggregate. Idempotent.
//
// Caller MUST hold d.mu. No exporter goroutine takes d.mu.
func (d *DeviceSimulator) stopNetconfCallHome() {
	e := d.netconfCallHome
	if e == nil {
		return
	}
	d.netconfCallHome = nil
	e.close()
}

// NetconfCallHomeStatus is the body of GET /api/v1/netconf/callhome/status.
type NetconfCallHomeStatus struct {
	SubsystemActive bool                          `json:"subsystem_active"`
	Clients         []NetconfCallHomeClientStatus `json:"clients"`
}

// NetconfCallHomeClientStatus is one client's row. Devices and SessionsUp
// are live; the other counters include deleted devices.
type NetconfCallHomeClientStatus struct {
	Client             string `json:"client"`
	Devices            int    `json:"devices"`
	SessionsUp         int    `json:"sessions_up"`
	ConnectAttempts    uint64 `json:"connect_attempts"`
	ConnectFailures    uint64 `json:"connect_failures"`
	HandshakeFailures  uint64 `json:"handshake_failures"`
	SessionsEnded      uint64 `json:"sessions_ended"`
	DevicesUnsupported uint64 `json:"devices_unsupported"`
}

// GetNetconfCallHomeStatus folds live exporters and the aggregates per
// client.
func (sm *SimulatorManager) GetNetconfCallHomeStatus() NetconfCallHomeStatus {
	rows := map[string]*NetconfCallHomeClientStatus{}
	row := func(client string) *NetconfCallHomeClientStatus {
		r, ok := rows[client]
		if !ok {
			r = &NetconfCallHomeClientStatus{Client: client}
			rows[client] = r
		}
		return r
	}
	sm.mu.RLock()
	for _, d := range sm.devices {
		d.mu.RLock()
		e := d.netconfCallHome
		d.mu.RUnlock()
		if e == nil {
			continue
		}
		r := row(e.client)
		r.Devices++
		if e.sessionUp.Load() {
			r.SessionsUp++
		}
	}
	sm.mu.RUnlock()
	sm.netconfCallHomeAggregates.Range(func(k, v any) bool {
		agg := v.(*netconfCallHomeAggregate)
		r := row(k.(string))
		r.ConnectAttempts += agg.connectAttempts.Load()
		r.ConnectFailures += agg.connectFailures.Load()
		r.HandshakeFailures += agg.handshakeFailures.Load()
		r.SessionsEnded += agg.sessionsEnded.Load()
		r.DevicesUnsupported += agg.devicesUnsupported.Load()
		return true
	})
	st := NetconfCallHomeStatus{
		SubsystemActive: sm.netconfSubsystemActive.Load(),
		Clients:         make([]NetconfCallHomeClientStatus, 0, len(rows)),
	}
	for _, r := range rows {
		st.Clients = append(st.Clients, *r)
	}
	slices.SortFunc(st.Clients, func(a, b NetconfCallHomeClientStatus) int {
		return strings.Compare(a.Client, b.Client)
	})
	return st
}

// netconfCallHomeStatusHandler serves GET /api/v1/netconf/callhome/status.
func netconfCallHomeStatusHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(manager.GetNetconfCallHomeStatus())
}

// attachNetconfCallHome starts call home for a device created with a
// call-home config. A failure is logged and clears the config, so the device
// listing shows no ghost, as for gNMI dial-out.
func (sm *SimulatorManager) attachNetconfCallHome(d *DeviceSimulator) {
	if d == nil || d.netconfCallHomeConfig == nil {
		return
	}
	if err := sm.startDeviceNetconfCallHome(d); err != nil {
		log.Printf("netconf call home: skipping device %s: %v", d.IP, err)
		d.mu.Lock()
		d.netconfCallHomeConfig = nil
		d.mu.Unlock()
	}
}

// netconfCallHomeSeedFromFlags builds the auto-start batch's call-home block
// from -netconf-callhome-client and -netconf-callhome-device-id for a batch
// of deviceCount devices. No client means no call home.
func netconfCallHomeSeedFromFlags(client, deviceID string, netconfEnabled bool, deviceCount int) (*DeviceNetconfCallHomeConfig, error) {
	if client == "" {
		if deviceID != "" {
			return nil, fmt.Errorf("-netconf-callhome-device-id requires -netconf-callhome-client")
		}
		return nil, nil
	}
	if !netconfEnabled {
		return nil, fmt.Errorf("-netconf-callhome-client requires -netconf-enable")
	}
	c := &DeviceNetconfCallHomeConfig{Client: client, DeviceID: deviceID}
	if err := c.ValidateFor(deviceCount); err != nil {
		return nil, err
	}
	return c, nil
}

// netconfCallHomePhase picks a device's offset into the cycle. Real devices
// boot at different times; a uniform phase keeps a fleet created in one
// batch from dialing at one instant.
func netconfCallHomePhase(cycle time.Duration) time.Duration {
	return rand.N(cycle) // #nosec G404 -- spreads attempts, not a secret
}

// netconfCallHomeIncapableRequest reports whether a creation request with a
// netconf_callhome block resolves only to profiles without call home, and
// returns one of them to name. Same shape as flowIncapableRequest: a mixed
// round-robin batch is accepted and its incapable devices are counted as
// unsupported.
func netconfCallHomeIncapableRequest(req CreateDevicesRequest) (string, bool) {
	capable := func(rf string) bool { return netconfDialects[resourceDirName(rf)].CallHome }
	if req.ResourceFile != "" {
		return req.ResourceFile, !capable(req.ResourceFile)
	}
	if !req.RoundRobin {
		return "", false
	}
	types := roundRobinTypesForCategory(req.Category)
	if len(types) == 0 || slices.ContainsFunc(types, capable) {
		return "", false
	}
	return types[0], true
}
