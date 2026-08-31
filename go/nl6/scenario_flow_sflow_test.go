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

// scenario_flow_sflow_test.go — gated, counted sFlow (story 4.5). flow_sample
// DATA records are gated + counted on RAW sample counts (never
// samples × sampling_rate); counters_sample is a KEEPALIVE — it flows pre-T0
// (agent liveness) and is never counted as scenario `sent`.

// sflowSamples counts flow_sample flow-records and counters_sample samples
// across all decoded datagrams.
func sflowSamples(t *testing.T, pkts [][]byte) (flowRecords, counterSamples int, agentVersion uint32) {
	t.Helper()
	for _, pkt := range pkts {
		dg := decodeSFlow(t, pkt)
		agentVersion = dg.Header.Version
		for _, s := range dg.Samples {
			switch s.Type {
			case sflowSampleTypeFlow:
				if s.FlowSample != nil {
					flowRecords += int(s.FlowSample.NumFlowRecords)
				}
			case sflowSampleTypeCounters:
				counterSamples++
			}
		}
	}
	return
}

func TestScenarioSFlow_GatedRawSamplesAndKeepalive(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	// Zero-generation profile so only injected flows expire → deterministic
	// raw sample counts.
	p := *sflowTickTestProfile()
	p.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.42.0.1"), &p, time.Millisecond, time.Millisecond, 10*time.Minute)
	fe.protocol = "sflow"
	fe.counterSources = []CounterSource{NewCPUCounterSource(nil)} // forces a counters_sample

	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now}
	fe.scenPart.Store(part)

	t0 := time.Unix(1_700_000_000, 0)
	drainAll := func() [][]byte {
		var out [][]byte
		for pkt := receivePacket(ch); pkt != nil; pkt = receivePacket(ch) {
			out = append(out, pkt)
		}
		return out
	}

	// --- ARMED / pre-T0: flow_sample suppressed, counters_sample keepalive ---
	gate.Store(&gateState{phase: phaseArmed})
	injectExpiredFlows(fe, 3, t0.Add(-time.Second))
	tickWithEncoder(fe, t0.Add(-time.Second), SFlowEncoder{}, conn, addr, testPool())
	flow, counters, _ := sflowSamples(t, drainAll())
	if flow != 0 {
		t.Fatalf("pre-T0 flow_sample records = %d, want 0 (data suppressed)", flow)
	}
	if counters == 0 {
		t.Fatal("pre-T0 counters_sample did not flow — keepalive broken")
	}
	if led.inWindow.Load() != 0 {
		t.Fatalf("pre-T0 in_window = %d, want 0", led.inWindow.Load())
	}

	// --- RUNNING / in-window: flow_sample counted on RAW sample counts ---
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour)})
	injectExpiredFlows(fe, 3, t0.Add(time.Minute))
	tickWithEncoder(fe, t0.Add(time.Minute), SFlowEncoder{}, conn, addr, testPool())
	flow, _, ver := sflowSamples(t, drainAll())
	if ver == 0 {
		t.Fatal("no sFlow datagram decoded in-window")
	}
	if flow != 3 {
		t.Fatalf("in-window flow_sample records = %d, want 3", flow)
	}
	// RAW counting: the ledger counts raw samples, never samples × sampling_rate.
	if led.inWindow.Load() != 3 {
		t.Fatalf("in_window = %d, want 3 (raw sample parity, not extrapolated by sampling_rate)", led.inWindow.Load())
	}

	// --- STOPPED / post-window: data suppressed; keepalive still flows ---
	gate.Store(&gateState{phase: phaseStopped, t0: t0, t1: t0.Add(time.Hour)})
	injectExpiredFlows(fe, 2, t0.Add(2*time.Hour))
	tickWithEncoder(fe, t0.Add(2*time.Hour), SFlowEncoder{}, conn, addr, testPool())
	flow, counters, _ = sflowSamples(t, drainAll())
	if flow != 0 {
		t.Fatalf("post-window flow_sample records = %d, want 0", flow)
	}
	if counters == 0 {
		t.Fatal("post-window counters_sample keepalive stopped")
	}
	if led.inWindow.Load() != 3 {
		t.Fatalf("post-window in_window = %d, want still 3", led.inWindow.Load())
	}
	if !led.identityHolds() {
		t.Fatalf("ledger identity violated: %+v", led.snapshot())
	}
}
