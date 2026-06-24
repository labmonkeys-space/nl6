/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStartDnsSubsystem_DisabledIsNoop(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.StartDnsSubsystem(DnsSubsystemConfig{Enabled: false}); err != nil {
		t.Fatalf("Start(disabled): %v", err)
	}
	if mgr.dnsSubsystemActive.Load() {
		t.Errorf("subsystem active after disabled Start")
	}
	// markDNSDirty must be a safe no-op with the subsystem off.
	mgr.markDNSDirty()
}

func TestStartStopDnsSubsystem(t *testing.T) {
	mgr := newTestManager()
	cfg := DnsSubsystemConfig{Enabled: true, Domain: "nl6.local", Listen: "127.0.0.1:0"}
	if err := mgr.StartDnsSubsystem(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !mgr.dnsSubsystemActive.Load() {
		t.Errorf("subsystem inactive after Start")
	}
	if err := mgr.StartDnsSubsystem(cfg); err == nil {
		t.Errorf("double Start should error")
	}
	mgr.StopDnsSubsystem()
	if mgr.dnsSubsystemActive.Load() {
		t.Errorf("subsystem active after Stop")
	}
	mgr.StopDnsSubsystem() // idempotent
}

func TestDNSDevices_SnapshotFromManager(t *testing.T) {
	mgr := newTestManager()
	mgr.devices["d1"] = &DeviceSimulator{IP: net.ParseIP("10.42.0.5"), sysName: "core-rtr-01"}
	got := mgr.DNSDevices()
	if len(got) != 1 || got[0].SysName != "core-rtr-01" || !got[0].IP.Equal(net.ParseIP("10.42.0.5")) {
		t.Fatalf("DNSDevices = %+v", got)
	}
	// Mutating the returned IP must not alias device state.
	got[0].IP[0] = 0
	if !mgr.devices["d1"].IP.Equal(net.ParseIP("10.42.0.5")) {
		t.Errorf("returned IP aliases device state")
	}
}

func TestZoneSerial_AdvancesOnChange(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.StartDnsSubsystem(DnsSubsystemConfig{
		Enabled: true, Domain: "nl6.local", Listen: "127.0.0.1:0", Debounce: 30 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.StopDnsSubsystem)

	before := mgr.ZoneSerial("nl6.local.")
	mgr.markDNSDirty()
	waitFor(t, time.Second, func() bool { return mgr.ZoneSerial("nl6.local.") > before })
}

// captureSecondary stands up a UDP DNS server that counts inbound NOTIFYs.
func captureSecondary(t *testing.T, count *int64) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Opcode == dns.OpcodeNotify {
			atomic.AddInt64(count, 1)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDebounce_CoalescesBurst(t *testing.T) {
	var notifies int64
	sec := captureSecondary(t, &notifies)

	mgr := newTestManager()
	if err := mgr.StartDnsSubsystem(DnsSubsystemConfig{
		Enabled:      true,
		Domain:       "nl6.local",
		ReverseZones: []string{"42.10.in-addr.arpa"},
		Listen:       "127.0.0.1:0",
		Secondaries:  []string{sec},
		Debounce:     100 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.StopDnsSubsystem)

	// A rapid burst of many changes (each well within the debounce window)
	// must coalesce into ONE serial bump.
	for i := 0; i < 50; i++ {
		mgr.markDNSDirty()
		time.Sleep(time.Millisecond)
	}
	waitFor(t, 2*time.Second, func() bool { return atomic.LoadUint64(&mgr.dnsZoneBumps) >= 1 })
	// Give any erroneous extra rounds a chance to (not) happen.
	time.Sleep(250 * time.Millisecond)

	if bumps := atomic.LoadUint64(&mgr.dnsZoneBumps); bumps != 1 {
		t.Fatalf("zone bumps = %d, want 1 (burst must coalesce)", bumps)
	}
	// Two served zones (forward + one reverse) -> one NOTIFY each per burst.
	if n := atomic.LoadInt64(&notifies); n != 2 {
		t.Errorf("NOTIFYs = %d, want 2 (one per zone for the single burst)", n)
	}

	// A second, separate burst advances to exactly two bumps.
	mgr.markDNSDirty()
	waitFor(t, 2*time.Second, func() bool { return atomic.LoadUint64(&mgr.dnsZoneBumps) == 2 })
}

func TestStopDnsSubsystem_DoesNotHangOnUnreachableSecondary(t *testing.T) {
	mgr := newTestManager()
	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — guaranteed unroutable, so a NOTIFY
	// would otherwise block on the 3 s Exchange timeout.
	if err := mgr.StartDnsSubsystem(DnsSubsystemConfig{
		Enabled:     true,
		Domain:      "nl6.local",
		Listen:      "127.0.0.1:0",
		Secondaries: []string{"192.0.2.1:5353"},
		Debounce:    20 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	mgr.markDNSDirty()
	// Let the worker fire and get stuck in the in-flight NOTIFY.
	time.Sleep(80 * time.Millisecond)

	done := make(chan struct{})
	go func() { mgr.StopDnsSubsystem(); close(done) }()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("StopDnsSubsystem hung on an unreachable secondary's NOTIFY")
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}
