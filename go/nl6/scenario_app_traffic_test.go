/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// scenario_app_traffic_test.go — fleet-wide per-application traffic ground
// truth in the scenario report (scenario-app-traffic): sent-basis totals per
// (l4_proto, dst_port), ledger reconciliation, sub-window byte series,
// sFlow/non-flow exclusion, determinism, hints, and the source-port floor.

// injectExpiredFlowsTo mirrors injectExpiredFlows but with caller-chosen
// protocol/port/bytes/packets so application rows are distinguishable.
func injectExpiredFlowsTo(fe *FlowExporter, n int, ref time.Time,
	proto uint8, dstPort uint16, byteCount uint64, pkts uint32) {
	past := ref.Add(-1 * time.Hour)
	for i := 0; i < n; i++ {
		fe.cache.Add(FlowRecord{
			SrcIP: net.ParseIP("10.0.0.1").To4(), DstIP: net.ParseIP("10.0.0.2").To4(),
			NextHop: net.IPv4(0, 0, 0, 0).To4(), SrcPort: uint16(50000 + i), DstPort: dstPort,
			Protocol: proto, Bytes: byteCount, Packets: pkts,
		}, past)
	}
}

// TestScenarioAppTraffic_RowsAndLedgerReconciliation runs a netflow9 scenario
// lifecycle with flows to two applications and asserts the report's
// applications block: row per (l4_proto, dst_port), sent-basis totals,
// Σ records == summary.sent, and avg_bytes_per_second derivation.
func TestScenarioAppTraffic_RowsAndLedgerReconciliation(t *testing.T) {
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
	clockNow := base
	c := newScenarioController(sm, func() time.Time { return clockNow })
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "netflow9", Rate: 1, Window: time.Hour, Seed: 1}
	if err := c.Submit(spec, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 3 tcp/443 flows of 1000B/10pkts + 2 udp/53 flows of 200B/2pkts.
	injectExpiredFlowsTo(fe, 3, base.Add(time.Minute), 6, 443, 1000, 10)
	injectExpiredFlowsTo(fe, 2, base.Add(time.Minute), 17, 53, 200, 2)
	tickWithEncoder(fe, base.Add(time.Minute), NetFlow9Encoder{}, conn, addr, testPool())
	for receivePacket(ch) != nil { // drain the wire
	}

	clockNow = base.Add(time.Hour) // advance so T1Actual−T0Actual = the window
	if _, err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	rep := buildScenarioReport(sm, c)
	if rep == nil {
		t.Fatal("no report")
	}

	if len(rep.Applications) != 2 {
		t.Fatalf("applications rows = %d, want 2: %+v", len(rep.Applications), rep.Applications)
	}
	// Sorted ascending by (l4_proto, dst_port): tcp/443 before udp/53.
	tcp, udp := rep.Applications[0], rep.Applications[1]
	if tcp.L4Proto != "tcp" || tcp.DstPort != 443 || tcp.AppHint != "https" {
		t.Fatalf("row 0 = %+v, want tcp/443/https", tcp)
	}
	if udp.L4Proto != "udp" || udp.DstPort != 53 || udp.AppHint != "domain" {
		t.Fatalf("row 1 = %+v, want udp/53/domain", udp)
	}
	if tcp.Records != 3 || tcp.Bytes != 3000 || tcp.Packets != 30 {
		t.Fatalf("tcp/443 = %d rec / %d B / %d pkts, want 3/3000/30", tcp.Records, tcp.Bytes, tcp.Packets)
	}
	if udp.Records != 2 || udp.Bytes != 400 || udp.Packets != 4 {
		t.Fatalf("udp/53 = %d rec / %d B / %d pkts, want 2/400/4", udp.Records, udp.Bytes, udp.Packets)
	}

	// Ledger reconciliation: Σ applications[].records == summary.sent.
	var appRecords uint64
	for _, r := range rep.Applications {
		appRecords += r.Records
	}
	if appRecords != rep.Summary.Sent {
		t.Fatalf("Σ applications records = %d, want summary.sent = %d", appRecords, rep.Summary.Sent)
	}

	// avg_bytes_per_second = bytes / actual duration (clock advanced 1h).
	seconds := time.Hour.Seconds()
	if want := 3000 / seconds; tcp.AvgBytesPerSecond != want {
		t.Fatalf("tcp avg_bytes_per_second = %g, want %g", tcp.AvgBytesPerSecond, want)
	}

	// Sub-window bytes sum to the in-window byte total (all sends in-window
	// here), and the record sub-windows sum to in_window (batch-aware fix).
	var swBytes, swRecords uint64
	for i := range tcp.SubWindowBytes {
		swBytes += tcp.SubWindowBytes[i] + udp.SubWindowBytes[i]
		swRecords += rep.Summary.SubWindows[i]
	}
	if swBytes != 3400 {
		t.Fatalf("Σ sub_window_bytes = %d, want 3400 (all in-window)", swBytes)
	}
	if swRecords != rep.Summary.InWindow {
		t.Fatalf("Σ sub_windows = %d, want in_window = %d (batch-aware localization)", swRecords, rep.Summary.InWindow)
	}
}

// TestScenarioAppTraffic_FailedWriteExcluded: a failed datagram's records
// appear in send_failures but contribute nothing to the application tally.
func TestScenarioAppTraffic_FailedWriteExcluded(t *testing.T) {
	fe := newTestFlowExporter(testDevice("10.42.0.2"), zeroGenFlowProfile(),
		time.Millisecond, time.Millisecond, 10*time.Minute)
	conn := testSender(t)
	conn.Close() // closed socket → WriteTo fails
	badAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}

	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now, countApps: true}
	fe.scenPart.Store(part)
	t0 := time.Unix(1_700_000_000, 0)
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour)})

	injectExpiredFlowsTo(fe, 4, t0.Add(time.Minute), 6, 443, 1000, 10)
	tickWithEncoder(fe, t0.Add(time.Minute), NetFlow9Encoder{}, conn, badAddr, testPool())

	if led.sendFailures.Load() != 4 {
		t.Fatalf("send_failures = %d, want 4", led.sendFailures.Load())
	}
	if apps := led.appSnapshot(); apps != nil {
		t.Fatalf("failed batch reached the application tally: %+v", apps)
	}
}

// TestScenarioAppTraffic_DrainBytes: bucketFlowBatch with a write-return time
// past T1 counts drain records and drain bytes (in totals) but no sub-window
// bytes — mirroring the records convention — and avg_bytes_per_second stays
// on the in-window basis (drain bytes never inflate the rate).
func TestScenarioAppTraffic_DrainBytes(t *testing.T) {
	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now, countApps: true}
	t0 := time.Unix(1_700_000_000, 0)
	t1 := t0.Add(10 * time.Second)
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1})

	inWin := []FlowRecord{{Protocol: 6, DstPort: 443, Bytes: 100, Packets: 1}}
	drain := []FlowRecord{{Protocol: 6, DstPort: 443, Bytes: 40, Packets: 1}}
	part.bucketFlowBatch(t0.Add(time.Second), inWin)
	part.bucketFlowBatch(t1.Add(200*time.Millisecond), drain)

	if led.inWindow.Load() != 1 || led.drain.Load() != 1 {
		t.Fatalf("in_window/drain = %d/%d, want 1/1", led.inWindow.Load(), led.drain.Load())
	}
	apps := led.appSnapshot()
	c := apps[appKey{proto: 6, dstPort: 443}]
	if c.bytes != 140 || c.records != 2 {
		t.Fatalf("app totals = %d B / %d rec, want 140/2 (in-window + drain)", c.bytes, c.records)
	}
	var sw uint64
	for _, b := range c.subWindowBytes {
		sw += b
	}
	if sw != 100 {
		t.Fatalf("Σ sub_window_bytes = %d, want 100 (drain bytes excluded)", sw)
	}

	// Rate basis: 100 in-window bytes over the 10s window = 10 B/s — the 40
	// drain bytes appear in `bytes` but must not inflate the rate.
	rows := buildAppRows(&ScenarioResult{T0Actual: t0, T1Actual: t1, Apps: map[appKey]appCounters{
		{proto: 6, dstPort: 443}: c,
	}})
	if len(rows) != 1 || rows[0].AvgBytesPerSecond != 10 {
		t.Fatalf("avg_bytes_per_second = %+v, want 10 (in-window basis)", rows)
	}
}

// TestScenarioAppTraffic_SflowExcluded: installScenPart wires countApps per
// protocol — false for sflow (collector byte math is sampling extrapolation),
// true for template protocols — and an uncounted participant's batches never
// reach the application tally while records are still ledgered.
func TestScenarioAppTraffic_SflowExcluded(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	fe := newTestFlowExporter(testDevice("10.42.0.3"), zeroGenFlowProfile(),
		time.Millisecond, time.Millisecond, 10*time.Minute)
	fe.protocol = "sflow"
	dev := testDevice("10.42.0.3")
	dev.flowExporter = fe

	// installScenPart is the single wiring point for the exclusion.
	sm := &SimulatorManager{devicesByIP: map[string]*DeviceSimulator{"10.42.0.3": dev}}
	cSflow := newScenarioController(sm, nil)
	cSflow.spec = &Scenario{Protocol: "sflow"}
	part := &scenarioPart{gate: &atomic.Pointer[gateState]{}, ledger: &ledgerEntry{}, drain: &drainGate{}, now: time.Now}
	if ok, reason, _ := cSflow.installScenPart(dev, part); !ok {
		t.Fatalf("installScenPart sflow: %s", reason)
	}
	if part.countApps {
		t.Fatal("installScenPart must set countApps=false for sflow")
	}
	cNF9 := newScenarioController(sm, nil)
	cNF9.spec = &Scenario{Protocol: "netflow9"}
	fe.protocol = "netflow9"
	partNF9 := &scenarioPart{gate: &atomic.Pointer[gateState]{}, ledger: &ledgerEntry{}, drain: &drainGate{}, now: time.Now}
	if ok, reason, _ := cNF9.installScenPart(dev, partNF9); !ok {
		t.Fatalf("installScenPart netflow9: %s", reason)
	}
	if !partNF9.countApps {
		t.Fatal("installScenPart must set countApps=true for netflow9")
	}
	fe.protocol = "sflow"
	fe.scenPart.Store(part)

	led := part.ledger
	t0 := time.Unix(1_700_000_000, 0)
	part.gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour)})

	injectExpiredFlowsTo(fe, 3, t0.Add(time.Minute), 6, 443, 1000, 10)
	tickWithEncoder(fe, t0.Add(time.Minute), SFlowEncoder{}, conn, addr, testPool())
	for receivePacket(ch) != nil {
	}

	if led.inWindow.Load() != 3 {
		t.Fatalf("in_window = %d, want 3 (records still ledgered)", led.inWindow.Load())
	}
	if apps := led.appSnapshot(); apps != nil {
		t.Fatalf("sflow batch reached the application tally: %+v", apps)
	}
}

// TestScenarioAppTraffic_EmptyForNonFlow: an empty fold serializes as
// "applications": [] — present, never null.
func TestScenarioAppTraffic_EmptyForNonFlow(t *testing.T) {
	res := &ScenarioResult{T0Actual: time.Unix(0, 0), T1Actual: time.Unix(10, 0)}
	rep := scenarioReport{Applications: buildAppRows(res)}
	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"applications":[]`)) {
		t.Fatalf("empty fold must serialize as \"applications\":[], got: %s", out)
	}
}

// TestScenarioAppTraffic_Determinism: the same fold projects byte-identically
// across builds (sorted rows defeat map iteration order).
func TestScenarioAppTraffic_Determinism(t *testing.T) {
	res := &ScenarioResult{
		T0Actual: time.Unix(0, 0), T1Actual: time.Unix(10, 0),
		Apps: map[appKey]appCounters{
			{6, 443}:   {records: 3, bytes: 3000, packets: 30},
			{17, 53}:   {records: 2, bytes: 400, packets: 4},
			{6, 80}:    {records: 1, bytes: 100, packets: 1},
			{1, 0}:     {records: 1, bytes: 64, packets: 1},
			{17, 4789}: {records: 5, bytes: 5000, packets: 50},
		},
	}
	a, _ := json.Marshal(buildAppRows(res))
	for i := 0; i < 20; i++ {
		b, _ := json.Marshal(buildAppRows(res))
		if !bytes.Equal(a, b) {
			t.Fatalf("non-deterministic serialization:\n%s\n%s", a, b)
		}
	}
	// Numeric key order: icmp(1) < tcp(6) < udp(17); ports ascending within.
	rows := buildAppRows(res)
	if rows[0].L4Proto != "icmp" || rows[1].DstPort != 80 || rows[2].DstPort != 443 || rows[4].DstPort != 4789 {
		t.Fatalf("row order wrong: %+v", rows)
	}
}

// TestScenarioAppTraffic_HintsAndPortFloor: hint mapping for known/unknown
// ports; every shipped profile floors SrcPortMin at the IANA dynamic range
// and generated records respect it.
func TestScenarioAppTraffic_HintsAndPortFloor(t *testing.T) {
	if got := appHintForPort(443); got != "https" {
		t.Fatalf("hint(443) = %q, want https", got)
	}
	if got := appHintForPort(12345); got != "" {
		t.Fatalf("hint(12345) = %q, want empty", got)
	}
	rng := rand.New(rand.NewSource(42))
	deviceIP := net.ParseIP("10.42.0.9").To4()
	for name, p := range flowProfileMap {
		if p.SrcPortMin != 49152 || p.SrcPortMax != 65535 {
			t.Fatalf("profile %s src port range = [%d,%d], want [49152,65535]", name, p.SrcPortMin, p.SrcPortMax)
		}
		// Every profile's dst ports carry a hint (ground-truth readability).
		for _, pw := range p.DstPorts {
			if appHintForPort(pw.Port) == "" {
				t.Errorf("profile %s dst port %d has no app_hint", name, pw.Port)
			}
		}
		for i := 0; i < 200; i++ {
			r := syntheticFlow(p, deviceIP, rng, 1000)
			if r.Protocol == 1 {
				// ICMP has no transport ports — both must be zero.
				if r.SrcPort != 0 || r.DstPort != 0 {
					t.Fatalf("profile %s ICMP record carries ports %d/%d, want 0/0", name, r.SrcPort, r.DstPort)
				}
				continue
			}
			if r.SrcPort < 49152 {
				t.Fatalf("profile %s generated SrcPort %d < 49152", name, r.SrcPort)
			}
		}
	}
}
