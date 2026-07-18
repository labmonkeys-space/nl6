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
)

// scenario_flow_nf5_test.go — gated, counted NetFlow v5 (story 4.6). The
// simplest protocol: no templates, 30-record datagram cap. Gating/counting
// ride the flow machinery from 4.1/4.2 unchanged; this proves the wire.

func TestScenarioNF5_GatedCountedAndCap(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	fe := newTestFlowExporter(testDevice("10.42.0.1"), zeroGenFlowProfile(),
		time.Millisecond, time.Millisecond, 10*time.Minute)
	fe.protocol = "netflow5"

	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now}
	fe.scenPart.Store(part)

	t0 := time.Unix(1_700_000_000, 0)
	// v5 records count across as many datagrams as pagination needs.
	tickRecords := func(now time.Time) (records int, firstCount uint16) {
		tickWithEncoder(fe, now, &NetFlow5Encoder{}, conn, addr, testPool())
		first := true
		for pkt := receivePacket(ch); pkt != nil; pkt = receivePacket(ch) {
			h, recs := decodeNetFlow5(t, pkt)
			if h.Version != 5 {
				t.Fatalf("version = %d, want 5", h.Version)
			}
			if first {
				firstCount = h.Count
				first = false
			}
			records += len(recs)
		}
		return
	}

	// Pre-T0 (armed): no templates, no counters → nothing on the wire.
	gate.Store(&gateState{phase: phaseArmed})
	injectExpiredFlows(fe, 5, t0.Add(-time.Second))
	if r, _ := tickRecords(t0.Add(-time.Second)); r != 0 {
		t.Fatalf("pre-T0 records on the wire = %d, want 0 (suppressed)", r)
	}
	if led.inWindow.Load() != 0 {
		t.Fatalf("pre-T0 in_window = %d, want 0", led.inWindow.Load())
	}

	// In-window: 5 records counted, one datagram, golden-byte v5.
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour), drainEnd: t0.Add(time.Hour + time.Second)})
	injectExpiredFlows(fe, 5, t0.Add(time.Minute))
	if r, _ := tickRecords(t0.Add(time.Minute)); r != 5 {
		t.Fatalf("in-window records = %d, want 5", r)
	}
	if led.inWindow.Load() != 5 {
		t.Fatalf("in_window = %d, want 5 (wire parity)", led.inWindow.Load())
	}

	// 30-record datagram cap: 35 injected → first datagram carries exactly 30,
	// all 35 count.
	injectExpiredFlows(fe, 35, t0.Add(2*time.Minute))
	r, first := tickRecords(t0.Add(2 * time.Minute))
	if r != 35 {
		t.Fatalf("capped-tick records = %d, want 35 (paginated)", r)
	}
	if first != 30 {
		t.Fatalf("first datagram count = %d, want 30 (Cisco v5 cap)", first)
	}
	if led.inWindow.Load() != 40 {
		t.Fatalf("in_window = %d, want 40 (5 + 35)", led.inWindow.Load())
	}
	if !led.identityHolds() {
		t.Fatalf("ledger identity violated: %+v", led.snapshot())
	}
}
