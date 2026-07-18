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

// scenario_trap_test.go — gated, counted SNMP trap/INFORM (story 4.4). The
// gate at TrapExporter.Fire covers all sources (scheduler/state-driven/
// on-demand, mirroring 1.2's interception); INFORM originations count exactly
// at first-transmit with ack settlement as a best-effort informational bucket.

func newScenarioTrapExporter(t *testing.T, mode TrapMode, collector *net.UDPAddr) *TrapExporter {
	t.Helper()
	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:  net.IPv4(127, 0, 0, 1),
		Community: "public",
		Mode:      mode,
		Collector: collector,
		IfIndexFn: func() int { return 3 },
		IfNameFn:  func(int) string { return "Gi0/3" },
	})
	e.SetConn(openTestUDPConn(t))
	e.StartBackgroundLoops(context.Background())
	return e
}

// TestScenarioTrap_GateCountingAllSources (interception mirror of 1.2): the
// gate at Fire covers background / state-driven / on-demand / scenario.
func TestScenarioTrap_GateCountingAllSources(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	mc := newMockCollector(t, false)
	defer mc.Close()
	e := newScenarioTrapExporter(t, TrapModeTrap, mc.addr)
	defer e.Close()

	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now}
	e.scenPart.Store(part)
	entry := cat.ByName["linkDown"]

	// ARMED / pre-T0: background generation-suppressed; exogenous (state-driven
	// + on-demand) emission-suppressed (counted); scenario silent. No wire.
	gate.Store(&gateState{phase: phaseArmed})
	e.fireBackground(entry, nil)
	e.FireForInterface(entry, 3)
	e.Fire(entry, nil)
	e.fireScenario(entry, nil)
	time.Sleep(80 * time.Millisecond)
	if led.backgroundSuppressed.Load() != 1 {
		t.Fatalf("background_suppressed = %d, want 1", led.backgroundSuppressed.Load())
	}
	if led.suppressedPreWindow.Load() != 2 {
		t.Fatalf("suppressed_pre_window = %d, want 2 (state-driven + on-demand)", led.suppressedPreWindow.Load())
	}
	if led.inWindow.Load() != 0 || mc.received.Load() != 0 {
		t.Fatalf("pre-T0 leaked to the wire: in_window=%d received=%d", led.inWindow.Load(), mc.received.Load())
	}

	// RUNNING / in-window: scenario + state-driven counted + on the wire;
	// background still suppressed.
	now := time.Now()
	gate.Store(&gateState{phase: phaseRunning, t0: now.Add(-time.Minute), t1: now.Add(time.Hour), drainEnd: now.Add(time.Hour + time.Second)})
	e.fireScenario(entry, nil)
	e.FireForInterface(entry, 3)
	e.fireBackground(entry, nil)
	time.Sleep(120 * time.Millisecond)
	if led.inWindow.Load() != 2 {
		t.Fatalf("in_window = %d, want 2", led.inWindow.Load())
	}
	if led.backgroundSuppressed.Load() != 2 {
		t.Fatalf("background_suppressed = %d, want 2 (still suppressed in-window)", led.backgroundSuppressed.Load())
	}
	if mc.received.Load() != 2 {
		t.Fatalf("collector received = %d, want 2 (only in-window fires on the wire)", mc.received.Load())
	}
	if !led.identityHolds() {
		t.Fatalf("ledger identity violated: %+v", led.snapshot())
	}
}

// TestScenarioTrap_InformOriginationAndAck: INFORM originations count `sent`
// at first-transmit; auto-acks settle the informational informs_acked bucket,
// and informs_pending drains toward 0.
func TestScenarioTrap_InformOriginationAndAck(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	mc := newMockCollector(t, true) // auto-ack
	defer mc.Close()
	e := newScenarioTrapExporter(t, TrapModeInform, mc.addr)
	defer e.Close()

	now := time.Now()
	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now}
	gate.Store(&gateState{phase: phaseRunning, t0: now.Add(-time.Minute), t1: now.Add(time.Hour), drainEnd: now.Add(time.Hour + time.Second)})
	e.scenPart.Store(part)

	for i := 0; i < 3; i++ {
		e.fireScenario(cat.ByName["linkDown"], nil)
	}
	// Originations count exactly at first-transmit.
	if led.inWindow.Load() != 3 || led.informsOriginated.Load() != 3 {
		t.Fatalf("in_window=%d informs_originated=%d, want 3/3", led.inWindow.Load(), led.informsOriginated.Load())
	}

	// Acks settle the best-effort bucket.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && led.informsAcked.Load() < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	if led.informsAcked.Load() != 3 {
		t.Fatalf("informs_acked = %d, want 3 (all auto-acked)", led.informsAcked.Load())
	}
	if p := informsPending(led.snapshot()); p != 0 {
		t.Fatalf("informs_pending = %d, want 0 (all settled)", p)
	}
	if !led.identityHolds() {
		t.Fatalf("identity violated (ack settlement must be outside it): %+v", led.snapshot())
	}
}
