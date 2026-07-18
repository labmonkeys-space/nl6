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
	"time"
)

// scenario_flow_v9_test.go — gated, counted NetFlow v9 export (story 4.1,
// FR15/FR17–FR20/FR23 + template arming). Proves: templates flow pre-T0 while
// DATA records are generation-suppressed (zero data before T0); in-window data
// records count at datagram-write-return; templates are excluded from `sent`;
// v9 packet-sequence + golden-byte decode hold; loopback parity + identity.

// zeroGenFlowProfile is the edge-router profile with auto-generation disabled
// (ConcurrentFlows=0), so only the flows a test injects expire — giving
// deterministic record counts for the gate assertions.
func zeroGenFlowProfile() *FlowProfile {
	p := *flowProfileEdgeRouter
	p.ConcurrentFlows = 0
	return &p
}

// injectExpiredFlows adds n flows timestamped an hour before `ref` (the tick's
// `now`) so the tick at `ref` expires and emits them as data records.
func injectExpiredFlows(fe *FlowExporter, n int, ref time.Time) {
	past := ref.Add(-1 * time.Hour)
	for i := 0; i < n; i++ {
		fe.cache.Add(FlowRecord{
			SrcIP: net.ParseIP("10.0.0.1").To4(), DstIP: net.ParseIP("10.0.0.2").To4(),
			NextHop: net.IPv4(0, 0, 0, 0).To4(), SrcPort: uint16(1000 + i), DstPort: 443,
			Protocol: 6, Bytes: 1024, Packets: 10,
		}, past)
	}
}

func TestScenarioFlowV9_GatedArmingAndCounting(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	// 1ms timeouts so injected flows expire on the next tick.
	fe := newTestFlowExporter(testDevice("10.42.0.1"), zeroGenFlowProfile(),
		time.Millisecond, time.Millisecond, 10*time.Minute)

	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	drain := &drainGate{}
	part := &scenarioPart{gate: gate, ledger: led, drain: drain, now: time.Now}
	fe.scenPart.Store(part)

	t0 := time.Unix(1_700_000_000, 0)
	tick := func(now time.Time) *nf9Packet {
		if pkt := receivePacket(ch); pkt != nil {
			t.Fatalf("stale packet before tick")
		}
		tickWithEncoder(fe, now, NetFlow9Encoder{}, conn, collectorAddr, testPool())
		if pkt := receivePacket(ch); pkt != nil {
			return decodeNF9Packet(t, pkt)
		}
		return nil
	}

	// --- ARMED / pre-T0: data suppressed, template flows (arming) ---
	gate.Store(&gateState{phase: phaseArmed})
	injectExpiredFlows(fe, 3, t0.Add(-time.Second))
	pre := tick(t0.Add(-time.Second))
	if pre == nil {
		t.Fatal("pre-T0 tick sent nothing — the template must flow to arm the collector")
	}
	if len(pre.Records) != 0 {
		t.Fatalf("pre-T0 data records = %d, want 0 (generation-suppressed)", len(pre.Records))
	}
	if len(pre.Templates) == 0 {
		t.Fatal("pre-T0 packet carried no template — collector not armed")
	}
	if led.inWindow.Load() != 0 {
		t.Fatalf("pre-T0 in_window = %d, want 0", led.inWindow.Load())
	}
	if led.backgroundSuppressed.Load() != 3 {
		t.Fatalf("pre-T0 background_suppressed = %d, want 3 (suppressed data records disclosed)", led.backgroundSuppressed.Load())
	}
	preSeq := fe.seqNo

	// --- RUNNING / in-window: data emitted + counted ---
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour), drainEnd: t0.Add(time.Hour + time.Second)})
	injectExpiredFlows(fe, 3, t0.Add(time.Minute))
	win := tick(t0.Add(time.Minute))
	if win == nil || len(win.Records) != 3 {
		t.Fatalf("in-window data records = %v, want 3", win)
	}
	// Golden-byte: valid v9, sequence advanced past the pre-T0 packet.
	if win.Header.Version != 9 {
		t.Fatalf("version = %d, want 9", win.Header.Version)
	}
	if fe.seqNo <= preSeq {
		t.Fatalf("packet sequence did not advance: pre=%d now=%d", preSeq, fe.seqNo)
	}
	// Loopback parity: records on the wire == ledger in_window.
	if led.inWindow.Load() != 3 {
		t.Fatalf("in_window = %d, want 3 (wire parity)", led.inWindow.Load())
	}

	// --- STOPPED / post-window: data suppressed again ---
	gate.Store(&gateState{phase: phaseStopped, t0: t0, t1: t0.Add(time.Hour), drainEnd: t0.Add(time.Hour + time.Second)})
	injectExpiredFlows(fe, 2, t0.Add(2*time.Hour))
	post := tick(t0.Add(2 * time.Hour))
	if post != nil && len(post.Records) != 0 {
		t.Fatalf("post-window data records = %d, want 0", len(post.Records))
	}
	if led.inWindow.Load() != 3 {
		t.Fatalf("post-window in_window = %d, want still 3", led.inWindow.Load())
	}

	// Ledger identity holds; templates never counted as sent.
	s := led.snapshot()
	if s.Emitted != s.InWindow+s.Drain+s.SuppressedPreWindow+s.SendFailures+s.Dropped {
		t.Fatalf("ledger identity violated: %+v", s)
	}
	if s.InWindow != 3 {
		t.Fatalf("sent (in_window) = %d, want exactly 3 data records (templates excluded)", s.InWindow)
	}
}

// TestScenarioFlowV9_ControllerLifecycle exercises the protocol-aware
// controller: a netflow9 scenario arms (installs on the flow exporter, no
// scheduler), runs (the flow ticker emits, gated), and reports the join tuple
// keyed on (netflow9, source_ip, collector).
func TestScenarioFlowV9_ControllerLifecycle(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	dev := testDevice("10.42.0.1")
	dev.ID = "device-10.42.0.1"
	fe := newTestFlowExporter(dev, zeroGenFlowProfile(), time.Millisecond, time.Millisecond, 10*time.Minute)
	fe.collectorAddr = addr
	fe.collectorStr = "127.0.0.1:2055"
	dev.flowExporter = fe

	sm := &SimulatorManager{
		devices: map[string]*DeviceSimulator{dev.ID: dev}, deviceIPs: map[string]struct{}{"10.42.0.1": {}},
		deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{"10.42.0.1": dev},
	}

	base := time.Unix(1_700_000_000, 0)
	c := newScenarioController(sm, func() time.Time { return base })
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "netflow9", Rate: 1, Window: time.Hour, Seed: 1}
	if err := c.Submit(spec, "s-000001"); err != nil {
		t.Fatal(err)
	}
	armed, _, err := c.Arm()
	if err != nil || armed != 1 {
		t.Fatalf("arm netflow9: armed=%d err=%v", armed, err)
	}
	if fe.scenPart.Load() == nil {
		t.Fatal("arm did not install the participation handle on the flow exporter")
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.sched != nil {
		t.Fatal("netflow9 scenario must not create a syslog scheduler")
	}

	// The flow ticker emits, gated: drive an in-window tick.
	injectExpiredFlows(fe, 5, base.Add(time.Minute))
	tickWithEncoder(fe, base.Add(time.Minute), NetFlow9Encoder{}, conn, addr, testPool())
	for receivePacket(ch) != nil { // drain
	}

	res, err := c.Stop()
	if err != nil || res == nil {
		t.Fatalf("stop: %v", err)
	}
	if fe.scenPart.Load() != nil {
		t.Fatal("stop did not detach the flow participation handle")
	}

	rep := buildScenarioReport(sm, c)
	if len(rep.Counters) != 1 {
		t.Fatalf("counters = %d, want 1", len(rep.Counters))
	}
	row := rep.Counters[0]
	if row.Protocol != "netflow9" || row.SourceIP != "10.42.0.1" || row.Collector != "127.0.0.1:2055" {
		t.Fatalf("join tuple wrong: %+v", row)
	}
	if row.InWindow != 5 || row.Sent != 5 {
		t.Fatalf("netflow9 in_window/sent = %d/%d, want 5/5", row.InWindow, row.Sent)
	}
}

// TestScenarioFlowV9_WriteFailureBucket: a failed datagram moves its records
// to send_failures, never to sent.
func TestScenarioFlowV9_WriteFailureBucket(t *testing.T) {
	fe := newTestFlowExporter(testDevice("10.42.0.2"), zeroGenFlowProfile(),
		time.Millisecond, time.Millisecond, 10*time.Minute)
	// A closed sender socket makes WriteTo fail.
	conn := testSender(t)
	conn.Close()
	badAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}

	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now}
	fe.scenPart.Store(part)
	t0 := time.Unix(1_700_000_000, 0)
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour), drainEnd: t0.Add(time.Hour + time.Second)})

	injectExpiredFlows(fe, 4, t0.Add(time.Minute))
	tickWithEncoder(fe, t0.Add(time.Minute), NetFlow9Encoder{}, conn, badAddr, testPool())

	if led.sendFailures.Load() != 4 {
		t.Fatalf("send_failures = %d, want 4 (failed datagram)", led.sendFailures.Load())
	}
	if led.inWindow.Load() != 0 {
		t.Fatalf("in_window = %d, want 0 (a failed datagram is never sent)", led.inWindow.Load())
	}
	if !led.identityHolds() {
		t.Fatalf("identity violated after write failure: %+v", led.snapshot())
	}
}
