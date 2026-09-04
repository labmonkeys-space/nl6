/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// scenario_flow_ipfix_test.go — gated, counted IPFIX export (story 4.2) plus
// the D1 flow-cadence adaptation. Proves: templates pre-announce while ZERO
// data records are emitted before T0 (the data-record sequence starts at 0 at
// T0, golden-byte asserted); the scenario-owned flow ticker drives participant
// emission during [T0,T1) at the scenario cadence, deterministically.

func newIPFIXTestExporter(ip string, active, inactive, templ time.Duration) *FlowExporter {
	dev := testDevice(ip)
	dev.ID = "device-" + ip
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	fe := NewFlowExporter(dev, zeroGenFlowProfile(), active, inactive, templ,
		"127.0.0.1:0", addr, "ipfix", IPFIXEncoder{}, 0)
	dev.flowExporter = fe
	return fe
}

// TestScenarioIPFIX_GatedArmingAndSequence: the data-record sequence starts at
// 0 at T0 — pre-T0 packets carry templates and ZERO data records; in-window
// data records count and decode as valid IPFIX (v10).
func TestScenarioIPFIX_GatedArmingAndSequence(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	fe := newIPFIXTestExporter("10.42.0.1", time.Millisecond, time.Millisecond, 10*time.Minute)
	fe.collectorAddr = addr

	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now}
	fe.scenPart.Store(part)

	t0 := time.Unix(1_700_000_000, 0)
	tick := func(now time.Time) *ipfixPacket {
		for receivePacket(ch) != nil { // clear
		}
		tickWithEncoder(fe, now, IPFIXEncoder{}, conn, addr, testPool())
		if pkt := receivePacket(ch); pkt != nil {
			return decodeIPFIXPacket(t, pkt)
		}
		return nil
	}

	// Pre-T0 (armed): the data-record sequence is 0 — templates flow, no data.
	gate.Store(&gateState{phase: phaseArmed})
	injectExpiredFlows(fe, 3, t0.Add(-time.Second))
	pre := tick(t0.Add(-time.Second))
	if pre == nil {
		t.Fatal("pre-T0 tick sent nothing — templates must flow to arm")
	}
	if pre.Header.Version != 10 {
		t.Fatalf("IPFIX version = %d, want 10", pre.Header.Version)
	}
	if len(pre.Records) != 0 {
		t.Fatalf("pre-T0 data records = %d, want 0 (data-record sequence starts at 0 at T0)", len(pre.Records))
	}
	if len(pre.Templates) == 0 {
		t.Fatal("pre-T0 packet carried no template")
	}
	if led.inWindow.Load() != 0 {
		t.Fatalf("pre-T0 in_window = %d, want 0", led.inWindow.Load())
	}

	// In-window: data records emitted, counted, decode clean.
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour)})
	injectExpiredFlows(fe, 3, t0.Add(time.Minute))
	win := tick(t0.Add(time.Minute))
	if win == nil || win.Header.Version != 10 || len(win.Records) != 3 {
		t.Fatalf("in-window IPFIX packet wrong: %+v", win)
	}
	if led.inWindow.Load() != 3 {
		t.Fatalf("in_window = %d, want 3 (wire parity)", led.inWindow.Load())
	}
	s := led.snapshot()
	if s.Emitted != s.InWindow+s.Drain+s.SuppressedPreWindow+s.SendFailures+s.Dropped {
		t.Fatalf("ledger identity violated: %+v", s)
	}
}

// TestScenarioIPFIX_FleetTickerYields: while a scenario owns an exporter
// (scenDriven), the fleet flow ticker skips it — the scenario ticker owns the
// cadence (D1). Before start, the fleet ticker still drives it (arming).
func TestScenarioIPFIX_FleetTickerYields(t *testing.T) {
	fe := newIPFIXTestExporter("10.42.0.5", time.Millisecond, time.Millisecond, 10*time.Minute)
	send := testSender(t)
	defer send.Close()
	fe.conn.Store(send) // per-device conn → skips the shared-pool lookup
	sm := &SimulatorManager{
		devices:     map[string]*DeviceSimulator{"d": {ID: "d", IP: net.ParseIP("10.42.0.5").To4(), flowExporter: fe}},
		devicesByIP: map[string]*DeviceSimulator{},
	}
	sm.flowBufPool.New = func() any { b := make([]byte, 1500); return &b }
	// This test asks "was Tick called", so it counts ATTEMPTS — sends plus
	// failures. statPackets alone stopped being that proxy in nl6#491, where it
	// narrowed to "reached the kernel"; the collector here is never listened
	// on, so a delivered-only counter can legitimately read zero.
	attempts := func() uint64 { return fe.statPackets.Load() + fe.statFailures.Load() }

	// scenDriven=false → fleet ticker DOES tick it (packets attempted).
	fe.scenDriven.Store(false)
	injectExpiredFlows(fe, 2, time.Now())
	sm.tickAllFlowExporters(context.Background(), time.Now())
	before := attempts()
	if before == 0 {
		t.Fatal("fleet ticker should tick a non-scenario-driven exporter")
	}
	// scenDriven=true → fleet ticker SKIPS it.
	fe.scenDriven.Store(true)
	injectExpiredFlows(fe, 2, time.Now())
	sm.tickAllFlowExporters(context.Background(), time.Now())
	if attempts() != before {
		t.Fatal("fleet ticker must skip a scenario-driven exporter")
	}
}

// TestScenarioIPFIX_CadenceAdaptationDeterministic: the scenario-owned flow
// ticker drives participant emission during the window at the scenario cadence,
// and two same-seed runs produce identical in-window counts (synctest;
// measured via the ledger — the collector isn't listened on).
func TestScenarioIPFIX_CadenceAdaptationDeterministic(t *testing.T) {
	run := func() uint64 {
		var inWin uint64
		synctest.Test(t, func(t *testing.T) {
			// A per-device send socket to a discard addr; short timeouts so
			// generated flows expire each scenario tick.
			send, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer send.Close()
			dev := testDevice("10.42.0.1")
			dev.ID = "device-10.42.0.1"
			addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}
			p := *flowProfileEdgeRouter // real generation
			fe := NewFlowExporter(dev, &p, time.Millisecond, time.Millisecond, time.Hour,
				"127.0.0.1:9", addr, "ipfix", IPFIXEncoder{}, 0)
			fe.conn.Store(send)
			dev.flowExporter = fe
			sm := &SimulatorManager{
				devices: map[string]*DeviceSimulator{dev.ID: dev}, deviceIPs: map[string]struct{}{"10.42.0.1": {}},
				deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{"10.42.0.1": dev},
			}
			sm.flowBufPool.New = func() any { b := make([]byte, 1500); return &b }
			c := newScenarioController(sm, time.Now)
			// rate 5 → scenario flow tick every 200ms; 2s window → ~10 ticks.
			spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "ipfix", Rate: 5, Window: 2 * time.Second, Seed: 1}
			if err := c.Submit(spec, "s-000001"); err != nil {
				t.Fatal(err)
			}
			if _, _, err := c.Arm(); err != nil {
				t.Fatal(err)
			}
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !fe.scenDriven.Load() {
				t.Fatal("participant not marked scenario-driven at start")
			}
			time.Sleep(2*time.Second + 300*time.Millisecond)
			synctest.Wait()
			res := c.Result()
			if res == nil {
				t.Fatal("scenario did not finalize")
			}
			if fe.scenDriven.Load() {
				t.Fatal("scenDriven not cleared after finalize")
			}
			inWin = res.PerDevice["10.42.0.1"].InWindow
		})
		return inWin
	}

	a := run()
	b := run()
	if a == 0 {
		t.Fatal("scenario flow ticker produced no in-window emission")
	}
	if a != b {
		t.Fatalf("cadence emission not deterministic: %d vs %d", a, b)
	}
}
