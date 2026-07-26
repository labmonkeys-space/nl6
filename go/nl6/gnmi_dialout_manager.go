/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// gnmiDialoutMaxConcurrentDials bounds concurrent in-namespace dials.
	// DialContextInNamespace pins an OS thread for the connect duration, so
	// this cap (not the device count) determines the worst-case pinned-thread
	// count when a collector is unreachable.
	gnmiDialoutMaxConcurrentDials = 64
	// gnmiDialoutDialTimeout hard-bounds a single dial so a blackholed
	// collector releases the thread promptly instead of parking for gRPC's
	// full connect timeout.
	gnmiDialoutDialTimeout = 10 * time.Second
)

// gnmiDialoutDialSem throttles concurrent in-namespace dials across all
// dial-out exporters (see gnmiDialoutMaxConcurrentDials).
var gnmiDialoutDialSem = make(chan struct{}, gnmiDialoutMaxConcurrentDials)

// gnmiDialoutKey identifies a status/aggregate bucket: one per unique
// (collector, flavor) tuple.
type gnmiDialoutKey struct {
	collector string
	flavor    string
}

// gnmiDialoutAggregate holds monotonic counters for a (collector, flavor)
// tuple that survive device deletion. Written by persistGnmiDialoutCounters
// on device Stop; folded into GetGnmiDialoutStatus for cumulative totals.
type gnmiDialoutAggregate struct {
	updatesSent    atomic.Uint64
	updatesDropped atomic.Uint64
	reconnects     atomic.Uint64
	sendFailures   atomic.Uint64
}

// GnmiDialoutStatus is the JSON body of GET /api/v1/gnmi/dialout/status.
type GnmiDialoutStatus struct {
	SubsystemActive  bool                         `json:"subsystem_active"`
	Collectors       []GnmiDialoutCollectorStatus `json:"collectors"`
	DevicesExporting int                          `json:"devices_exporting"`
}

// GnmiDialoutCollectorStatus is one (collector, flavor) row.
type GnmiDialoutCollectorStatus struct {
	Collector      string `json:"collector"`
	Flavor         string `json:"flavor"`
	Devices        int    `json:"devices"`
	StreamsActive  int64  `json:"streams_active"`
	UpdatesSent    uint64 `json:"updates_sent"`
	UpdatesDropped uint64 `json:"updates_dropped"`
	Reconnects     uint64 `json:"reconnects"`
	SendFailures   uint64 `json:"send_failures"`
}

// StartGnmiDialoutSubsystem marks the dial-out subsystem active so
// per-device exporters may attach (from the CLI seed or REST). Always-on
// like the flow/trap/syslog subsystems. Idempotent-at-start; a second call
// is a programming error.
func (sm *SimulatorManager) StartGnmiDialoutSubsystem() error {
	if sm.gnmiDialoutSubsystemActive.Load() {
		return fmt.Errorf("gnmi dial-out: subsystem already started")
	}
	sm.gnmiDialoutSubsystemActive.Store(true)
	log.Printf("gNMI dial-out subsystem enabled (per-device opt-in)")
	return nil
}

// StopGnmiDialout closes every device's dial-out exporter. Shutdown-only,
// matching StopTrapExport / StopGnmiSubsystem — the attach path captures
// manager pointers under a short RLock and uses them outside it, so a
// runtime restart would race. Called only from the process-exit path.
func (sm *SimulatorManager) StopGnmiDialout() {
	if !sm.gnmiDialoutSubsystemActive.Load() {
		return
	}
	sm.mu.RLock()
	devices := make([]*DeviceSimulator, 0, len(sm.devices))
	for _, d := range sm.devices {
		devices = append(devices, d)
	}
	sm.mu.RUnlock()
	for _, d := range devices {
		d.mu.Lock()
		if d.gnmiDialoutExporter != nil {
			sm.persistGnmiDialoutCounters(d.gnmiDialoutExporter)
			_ = d.gnmiDialoutExporter.Close()
			d.gnmiDialoutExporter = nil
		}
		d.mu.Unlock()
	}
	sm.gnmiDialoutSubsystemActive.Store(false)
}

// startDeviceGnmiDialoutExporter constructs and starts a dial-out exporter
// for a device that already has gnmiDialoutConfig populated. On failure the
// caller nils gnmiDialoutConfig so ListDevices shows no ghost. Mirrors the
// trap/syslog attach discipline: manager pointers are snapshotted under a
// short RLock and used outside it.
func (sm *SimulatorManager) startDeviceGnmiDialoutExporter(device *DeviceSimulator) error {
	if device == nil || device.gnmiDialoutConfig == nil {
		return nil
	}
	cfg := device.gnmiDialoutConfig

	sm.mu.RLock()
	active := sm.gnmiDialoutSubsystemActive.Load()
	sharedCert := sm.sharedTLSCert
	useNS := sm.useNamespace
	sm.mu.RUnlock()

	if !active {
		return fmt.Errorf("gnmi dial-out: subsystem not started; call StartGnmiDialoutSubsystem first")
	}

	transport, canonical, err := buildDialoutTransport(cfg.Flavor)
	if err != nil {
		return err
	}
	enc, err := parseDialoutEncoding(cfg.Encoding)
	if err != nil {
		return err
	}
	paths := make([]*gnmipb.Path, 0, len(cfg.Paths))
	for _, ps := range cfg.Paths {
		p, err := parseGnmiPath(ps)
		if err != nil {
			return fmt.Errorf("gnmi dial-out: parse path %q: %w", ps, err)
		}
		paths = append(paths, p)
	}

	// ON_CHANGE emits only state-engine-backed leaves; counter leaves under a
	// path are silently ignored at emit time (pushChange filters via
	// subChangeMatch). So a subtree path like the default
	// `/interfaces/interface[name=*]/state` (which expands to state leaves +
	// counters) is fine — it fires on oper/admin transitions and ignores the
	// counters. Reject only a path that covers NO state leaf at all (e.g. a
	// pure `state/counters/...` path), which could never fire on-change.
	if cfg.Mode == "on-change" {
		resolver := newPathResolver(device)
		for _, p := range paths {
			leaves, err := resolver.ClassifyLeaves(p)
			if err != nil {
				return fmt.Errorf("gnmi dial-out: on-change path %q: %w", pathToString(p), err)
			}
			hasState := false
			optical := false
			for _, leaf := range leaves {
				if isStateOnlyLeaf(leaf) {
					hasState = true
					break
				}
				if isOpticalLeafSelector(leaf) {
					optical = true
				}
			}
			if !hasState {
				// Same class split as the dial-in validator: ClassifyLeaves now
				// answers for `/components` too, so without this branch an optical
				// path would be reported as "only counters" and pointed at a
				// remedy — subscribing a state leaf — that does not exist for it.
				if optical {
					return fmt.Errorf("gnmi dial-out: on-change path %q is optical telemetry; optical values are analog measurements that change continuously and cannot be delivered on-change — use mode: sample", pathToString(p))
				}
				return fmt.Errorf("gnmi dial-out: on-change path %q covers no state leaves (only counters); counters cannot be delivered on-change — subscribe a state leaf or the state subtree", pathToString(p))
			}
		}
	}

	creds, err := buildDialoutCreds(cfg.TLS, sharedCert)
	if err != nil {
		return fmt.Errorf("gnmi dial-out: TLS config: %w", err)
	}
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	// Per-device dialer: dial from inside the device's netns with source IP =
	// device IP, so the collector attributes the stream to the right device.
	// When namespaces are off (tests, -no-namespace) fall back to the default
	// dialer (no source binding).
	//
	// A package-level semaphore bounds concurrent in-namespace dials, and each
	// dial gets a hard timeout. Both matter because DialContextInNamespace
	// pins an OS thread for the connect duration — without a cap, 30k devices
	// re-dialing a blackholed collector would pin enough threads to hit Go's
	// 10k-thread limit and crash. Excess dials wait on the semaphore (a parked
	// goroutine, not a pinned thread).
	if useNS && device.netNamespace != nil {
		ns := device.netNamespace
		localIP := device.IP
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			select {
			case gnmiDialoutDialSem <- struct{}{}:
				defer func() { <-gnmiDialoutDialSem }()
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			dctx, cancel := context.WithTimeout(ctx, gnmiDialoutDialTimeout)
			defer cancel()
			return ns.DialContextInNamespace(dctx, "tcp", addr, &net.TCPAddr{IP: localIP})
		}))
	}

	exporter := NewGnmiDialoutExporter(device, cfg.Collector, canonical, transport, enc,
		cfg.Mode, paths, time.Duration(cfg.SampleInterval), dialOpts)
	// Publish under device.mu (matching the trap/syslog attach discipline) so
	// the write is safe even for a future post-registration attach path —
	// GetGnmiDialoutStatus and StopGnmiDialout read/clear this field under
	// the same lock.
	device.mu.Lock()
	device.gnmiDialoutExporter = exporter
	device.mu.Unlock()
	exporter.Start()
	return nil
}

// buildDialoutCreds turns a DialoutTLSConfig into gRPC transport
// credentials. A nil block or Enabled=false selects plaintext (Arista
// -collector_tls=false parity). Otherwise TLS: verify against CAFile (or
// system roots), or skip verification in dev; present the shared cert for
// mTLS when requested. The shared server cert can only be used AS a client
// cert — it cannot build a trust pool, which is why CAFile exists.
func buildDialoutCreds(cfg *DialoutTLSConfig, sharedCert *tls.Certificate) (credentials.TransportCredentials, error) {
	if cfg == nil || !cfg.Enabled {
		return insecure.NewCredentials(), nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file %q: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %q: no PEM certificates found", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.MTLS {
		if sharedCert == nil {
			return nil, fmt.Errorf("mtls requested but no shared TLS certificate is available")
		}
		tlsCfg.Certificates = []tls.Certificate{*sharedCert}
	}
	return credentials.NewTLS(tlsCfg), nil
}

// persistGnmiDialoutCounters folds a dying exporter's cumulative counters
// into the per-(collector, flavor) aggregate so the status endpoint reports
// monotonic totals across device churn. Guarded by the exporter's
// countersPersisted sync.Once so it is single-shot even if both device.Stop
// and StopGnmiDialout run.
func (sm *SimulatorManager) persistGnmiDialoutCounters(e *GnmiDialoutExporter) {
	if e == nil || e.collectorStr == "" {
		return
	}
	e.countersPersisted.Do(func() {
		key := gnmiDialoutKey{collector: e.collectorStr, flavor: e.flavor}
		v, _ := sm.gnmiDialoutAggregates.LoadOrStore(key, &gnmiDialoutAggregate{})
		agg := v.(*gnmiDialoutAggregate)
		agg.updatesSent.Add(atomic.LoadUint64(&e.statUpdatesSent))
		agg.updatesDropped.Add(atomic.LoadUint64(&e.statUpdatesDropped))
		agg.reconnects.Add(atomic.LoadUint64(&e.statReconnects))
		agg.sendFailures.Add(atomic.LoadUint64(&e.statSendFailures))
	})
}

// GetGnmiDialoutStatus aggregates live exporters by (collector, flavor) and
// folds the persisted aggregates for monotonic totals.
func (sm *SimulatorManager) GetGnmiDialoutStatus() GnmiDialoutStatus {
	active := sm.gnmiDialoutSubsystemActive.Load()
	agg := make(map[gnmiDialoutKey]*GnmiDialoutCollectorStatus)

	sm.mu.RLock()
	for _, d := range sm.devices {
		d.mu.RLock()
		e := d.gnmiDialoutExporter
		d.mu.RUnlock()
		if e == nil {
			continue
		}
		k := gnmiDialoutKey{collector: e.collectorStr, flavor: e.flavor}
		rec, ok := agg[k]
		if !ok {
			rec = &GnmiDialoutCollectorStatus{Collector: e.collectorStr, Flavor: e.flavor}
			agg[k] = rec
		}
		rec.Devices++
		rec.StreamsActive += atomic.LoadInt64(&e.statStreamsActive)
		rec.UpdatesSent += atomic.LoadUint64(&e.statUpdatesSent)
		rec.UpdatesDropped += atomic.LoadUint64(&e.statUpdatesDropped)
		rec.Reconnects += atomic.LoadUint64(&e.statReconnects)
		rec.SendFailures += atomic.LoadUint64(&e.statSendFailures)
	}
	sm.mu.RUnlock()

	sm.gnmiDialoutAggregates.Range(func(k, v interface{}) bool {
		key := k.(gnmiDialoutKey)
		pers := v.(*gnmiDialoutAggregate)
		rec, ok := agg[key]
		if !ok {
			rec = &GnmiDialoutCollectorStatus{Collector: key.collector, Flavor: key.flavor}
			agg[key] = rec
		}
		rec.UpdatesSent += pers.updatesSent.Load()
		rec.UpdatesDropped += pers.updatesDropped.Load()
		rec.Reconnects += pers.reconnects.Load()
		rec.SendFailures += pers.sendFailures.Load()
		return true
	})

	collectors := make([]GnmiDialoutCollectorStatus, 0, len(agg))
	total := 0
	for _, rec := range agg {
		collectors = append(collectors, *rec)
		total += rec.Devices
	}
	return GnmiDialoutStatus{
		SubsystemActive:  active,
		Collectors:       collectors,
		DevicesExporting: total,
	}
}

// WriteGnmiDialoutStatusJSON encodes the status to w.
func (sm *SimulatorManager) WriteGnmiDialoutStatusJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sm.GetGnmiDialoutStatus())
}

// gnmiDialoutStatusHandler serves GET /api/v1/gnmi/dialout/status.
func gnmiDialoutStatusHandler(w http.ResponseWriter, _ *http.Request) {
	manager.WriteGnmiDialoutStatusJSON(w)
}
