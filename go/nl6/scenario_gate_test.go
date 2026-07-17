/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// gateHarness wires a real SyslogExporter to a scenarioPart with a
// controllable clock and an in-memory write sink, so the gate + counter
// discipline can be exercised without UDP or the scheduler.
type gateHarness struct {
	exp        *SyslogExporter
	part       *scenarioPart
	gate       *atomic.Pointer[gateState]
	ledger     *ledgerEntry
	drain      *drainGate
	clock      atomic.Int64 // unix nanos, driven by tests
	writes     atomic.Uint64
	failWrites atomic.Bool
}

func newGateHarness(t *testing.T) *gateHarness {
	t.Helper()
	h := &gateHarness{}
	h.clock.Store(time.Unix(1_700_000_000, 0).UnixNano())
	now := func() time.Time { return time.Unix(0, h.clock.Load()) }

	h.gate = &atomic.Pointer[gateState]{}
	h.ledger = &ledgerEntry{}
	h.drain = &drainGate{}
	h.part = &scenarioPart{gate: h.gate, ledger: h.ledger, drain: h.drain, now: now}

	h.exp = newSinkExporter(t, net.IPv4(10, 42, 0, 7), func(_ []byte) error {
		if h.failWrites.Load() {
			return fmt.Errorf("induced write failure")
		}
		h.writes.Add(1)
		return nil
	})
	h.exp.scenPart.Store(h.part)
	return h
}

func (h *gateHarness) setClock(base time.Time, d time.Duration) {
	h.clock.Store(base.Add(d).UnixNano())
}

func mustEntry(t *testing.T) *SyslogCatalogEntry {
	t.Helper()
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	e := cat.ByName["interface-down"]
	if e == nil {
		t.Fatal("interface-down entry missing")
	}
	return e
}

// AC1: the source-flag counting matrix — every source × phase lands in the
// right bucket, and nothing reaches the wire before T0.
func TestScenarioGate_CountingMatrix(t *testing.T) {
	entry := mustEntry(t)
	base := time.Unix(1_700_000_000, 0)
	t0 := base.Add(1 * time.Minute)
	t1 := t0.Add(5 * time.Minute)
	drainEnd := t1.Add(2 * time.Second)

	h := newGateHarness(t)

	// --- Pre-T0 (armed) ---
	h.gate.Store(&gateState{phase: phaseArmed})
	h.setClock(base, 0)
	_ = h.exp.fireBackground(entry, nil) // generation-suppressed, informational
	_ = h.exp.FireForInterface(entry, 3) // state-driven → suppressed_pre_window (counted)
	_ = h.exp.Fire(entry, nil)           // on-demand → suppressed_pre_window (counted)
	_ = h.exp.fireScenario(entry, nil)   // scenario pre-T0 → silent (defensive)

	if got := h.writes.Load(); got != 0 {
		t.Fatalf("pre-T0: %d records reached the wire, want 0 (FR15)", got)
	}
	if got := h.ledger.backgroundSuppressed.Load(); got != 1 {
		t.Errorf("background_suppressed = %d, want 1", got)
	}
	if got := h.ledger.suppressedPreWindow.Load(); got != 2 {
		t.Errorf("suppressed_pre_window = %d, want 2 (state-driven + on-demand)", got)
	}

	// --- In-window (running) ---
	h.gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1, drainEnd: drainEnd})
	h.setClock(t0, 1*time.Second)
	_ = h.exp.fireScenario(entry, nil)   // allowed → sent (in_window)
	_ = h.exp.FireForInterface(entry, 3) // in-window state-driven → sent (in_window)
	_ = h.exp.fireBackground(entry, nil) // background still suppressed

	if got := h.ledger.inWindow.Load(); got != 2 {
		t.Errorf("in_window = %d, want 2", got)
	}
	if got := h.writes.Load(); got != 2 {
		t.Errorf("in-window wire writes = %d, want 2", got)
	}
	if got := h.ledger.backgroundSuppressed.Load(); got != 2 {
		t.Errorf("background_suppressed = %d, want 2 (still suppressed in-window)", got)
	}

	// --- Post-T1 within drain (stopped) ---
	h.gate.Store(&gateState{phase: phaseStopped, t0: t0, t1: t1, drainEnd: drainEnd})
	h.setClock(t1, 1*time.Second)      // within drain grace
	_ = h.exp.fireScenario(entry, nil) // stopped → decide() suppresses new initiation

	if got := h.ledger.drain.Load(); got != 0 {
		t.Errorf("drain = %d; a NEW post-T1 initiation must not create a drain record", got)
	}

	// Identity holds after quiesce.
	if !h.ledger.identityHolds() {
		s := h.ledger.snapshot()
		t.Errorf("ledger identity violated: %+v", s)
	}
}

// AC3 (write-failure half): a socket write failing after the gate passes
// counts send_failures, never sent.
func TestScenarioGate_WriteFailureBucket(t *testing.T) {
	entry := mustEntry(t)
	t0 := time.Unix(1_700_000_000, 0)
	t1 := t0.Add(time.Minute)
	h := newGateHarness(t)
	h.gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1, drainEnd: t1.Add(time.Second)})
	h.setClock(t0, time.Second)
	h.failWrites.Store(true)

	_ = h.exp.fireScenario(entry, nil)

	if got := h.ledger.sendFailures.Load(); got != 1 {
		t.Errorf("send_failures = %d, want 1", got)
	}
	if got := h.ledger.inWindow.Load(); got != 0 {
		t.Errorf("in_window = %d, want 0 (a failed write is never sent)", got)
	}
	if !h.ledger.identityHolds() {
		t.Errorf("identity violated after write failure: %+v", h.ledger.snapshot())
	}
}

// AC1 (non-participant): with nil scenPart every fire path behaves exactly
// as the legacy exporter — no ledger, straight to the wire (FR18).
func TestScenarioGate_NonParticipantUntouched(t *testing.T) {
	entry := mustEntry(t)
	h := newGateHarness(t)
	h.exp.scenPart.Store(nil) // not participating

	if err := h.exp.Fire(entry, nil); err != nil {
		t.Fatalf("Fire on non-participant: %v", err)
	}
	if got := h.writes.Load(); got != 1 {
		t.Errorf("non-participant wire writes = %d, want 1", got)
	}
	if got := h.exp.Stats().Sent.Load(); got != 1 {
		t.Errorf("legacy Sent stat = %d, want 1", got)
	}
}
