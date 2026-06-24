/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// dns_manager.go wires the DNS service-discovery server into the
// SimulatorManager lifecycle: it implements the zoneDataProvider the server
// reads from, owns the shared SOA serial, and runs the debounce worker that
// coalesces a burst of device create/delete events into a single serial bump
// plus one NOTIFY round to the configured secondaries.

// DnsSubsystemConfig captures the simulator-wide DNS knobs (from the -dns-*
// flags). Enabled=false is the default and makes StartDnsSubsystem a no-op.
type DnsSubsystemConfig struct {
	Enabled      bool
	Domain       string
	ReverseZones []string
	Listen       string
	NS           string
	Mbox         string
	Secondaries  []string
	Debounce     time.Duration
}

// StartDnsSubsystem binds the authoritative DNS server and starts the debounce
// worker. A no-op when cfg.Enabled is false. Idempotent-guarded: a second start
// is a programming error.
func (sm *SimulatorManager) StartDnsSubsystem(cfg DnsSubsystemConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if sm.dnsSubsystemActive.Load() {
		return fmt.Errorf("dns: subsystem already started")
	}

	debounce := cfg.Debounce
	if debounce <= 0 {
		debounce = time.Second
	}

	srv := newDNSServer(dnsServerConfig{
		Domain:       cfg.Domain,
		ReverseZones: cfg.ReverseZones,
		Listen:       cfg.Listen,
		NS:           cfg.NS,
		Mbox:         cfg.Mbox,
		Secondaries:  cfg.Secondaries,
	}, sm)

	// Seed the serial before serving so the first AXFR carries a sane value.
	sm.dnsSerial.Store(nextSerial(0, time.Now().Unix()))

	if err := srv.start(); err != nil {
		return fmt.Errorf("dns: %w", err)
	}

	sm.dnsServer = srv
	sm.dnsDebounce = debounce
	sm.dnsWake = make(chan struct{}, 1)
	sm.dnsStopCh = make(chan struct{})
	sm.dnsCtx, sm.dnsCancel = context.WithCancel(context.Background())
	sm.dnsSubsystemActive.Store(true)
	sm.dnsWg.Add(1)
	go sm.dnsWorker()

	log.Printf("DNS service-discovery enabled on %s (domain %s, %d reverse zone(s), %d secondary(ies), debounce %s)",
		srv.cfg.Listen, srv.cfg.Domain, len(srv.cfg.ReverseZones), len(srv.cfg.Secondaries), debounce)
	return nil
}

// StopDnsSubsystem stops the debounce worker and closes the listeners.
// Shutdown-only, matching Stop{Trap,Syslog,Gnmi}: the start path captures the
// server pointer and uses it without re-locking, so a runtime restart would
// race. Today this is only called from the process-exit path.
//
// The CompareAndSwap makes Stop run exactly once (no double-close of dnsStopCh)
// and flips the active flag *first* so any concurrent markDNSDirty short-
// circuits. dnsCancel aborts an in-flight NOTIFY so dnsWg.Wait() doesn't block
// on the 3 s Exchange timeout of an unreachable secondary.
func (sm *SimulatorManager) StopDnsSubsystem() {
	if !sm.dnsSubsystemActive.CompareAndSwap(true, false) {
		return
	}
	if sm.dnsCancel != nil {
		sm.dnsCancel()
	}
	if sm.dnsStopCh != nil {
		close(sm.dnsStopCh)
	}
	sm.dnsWg.Wait()
	if sm.dnsServer != nil {
		sm.dnsServer.stop()
	}
}

// markDNSDirty flags the zones as changed and nudges the debounce worker. A
// cheap no-op when the subsystem is disabled, so device create/delete paths can
// call it unconditionally. The non-blocking send coalesces a burst: the
// buffered(1) channel holds at most one pending wake.
func (sm *SimulatorManager) markDNSDirty() {
	if !sm.dnsSubsystemActive.Load() {
		return
	}
	sm.dnsDirty.Store(true)
	select {
	case sm.dnsWake <- struct{}{}:
	default:
	}
}

// dnsWorker debounces change notifications: it waits for dnsDebounce of
// quiescence after the last change before bumping the serial and notifying, so
// a 30k-device batch produces one serial bump and one NOTIFY round, not 30k.
func (sm *SimulatorManager) dnsWorker() {
	defer sm.dnsWg.Done()
	for {
		select {
		case <-sm.dnsStopCh:
			return
		case <-sm.dnsWake:
		}

		// Collapse the burst: extend the quiescence window each time another
		// change arrives before the timer fires.
		timer := time.NewTimer(sm.dnsDebounce)
	debounce:
		for {
			select {
			case <-sm.dnsStopCh:
				timer.Stop()
				return
			case <-sm.dnsWake:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(sm.dnsDebounce)
			case <-timer.C:
				break debounce
			}
		}

		if sm.dnsDirty.Swap(false) {
			sm.dnsBumpAndNotify()
		}
	}
}

// dnsBumpAndNotify advances the SOA serial once and sends a NOTIFY for every
// served zone to every configured secondary.
func (sm *SimulatorManager) dnsBumpAndNotify() {
	sm.bumpDNSSerial()
	atomic.AddUint64(&sm.dnsZoneBumps, 1)

	srv := sm.dnsServer
	if srv == nil {
		return
	}
	for _, origin := range srv.servedOrigins() {
		for _, res := range srv.sendNotify(sm.dnsCtx, origin) {
			atomic.AddUint64(&sm.dnsNotifiesSent, 1)
			if res.Err != nil {
				atomic.AddUint64(&sm.dnsNotifyErrors, 1)
				log.Printf("dns: NOTIFY %s -> %s failed: %v", origin, res.Secondary, res.Err)
			}
		}
	}
}

// bumpDNSSerial advances the shared serial monotonically. The mutex makes the
// load-compute-store atomic against a concurrent bump; ZoneSerial reads the
// atomic value lock-free.
func (sm *SimulatorManager) bumpDNSSerial() uint32 {
	sm.dnsSerialMu.Lock()
	defer sm.dnsSerialMu.Unlock()
	next := nextSerial(sm.dnsSerial.Load(), time.Now().Unix())
	sm.dnsSerial.Store(next)
	return next
}

// DNSDevices implements zoneDataProvider: a snapshot of the live device set as
// (IP, sysName) pairs. The IP is copied so the caller can't alias device state.
func (sm *SimulatorManager) DNSDevices() []deviceDNS {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	out := make([]deviceDNS, 0, len(sm.devices))
	for _, d := range sm.devices {
		ip := make(net.IP, len(d.IP))
		copy(ip, d.IP)
		name := d.sysName
		if v := d.cachedSysName.Load(); v != nil {
			if s, ok := v.(string); ok && s != "" {
				name = s
			}
		}
		out = append(out, deviceDNS{IP: ip, SysName: name})
	}
	return out
}

// ZoneSerial implements zoneDataProvider: the current shared SOA serial (all
// zones advance in lockstep, so origin is ignored).
func (sm *SimulatorManager) ZoneSerial(string) uint32 {
	return sm.dnsSerial.Load()
}
