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

// AC2 — Fire-altitude interception, failing-then-passing.
//
// The state-driven path (wireStateNotify → FireForInterface) is the Tier-C
// retrofit that bypasses the scheduler. Winston's condition: prove the gate
// altitude with a test that first FAILS against a scheduler-altitude-only
// gate, then PASSES at exporter-Fire altitude.
//
// schedulerAltitudeGate models the WRONG design: a gate consulted only on
// the scheduler pop path. FireForInterface never passes through it, so a
// pre-T0 state-driven fire leaks to the wire — which this test asserts, so
// if someone "simplifies" the real gate down to scheduler altitude the
// leak is caught here.
func TestFireAltitudeInterception(t *testing.T) {
	entry := mustEntry(t)

	// --- Part 1: scheduler-altitude gate LEAKS (documents the wrong design) ---
	t.Run("scheduler_altitude_leaks", func(t *testing.T) {
		var wireWrites atomic.Uint64
		exp := newInterceptExporter(t, &wireWrites)
		// No scenPart installed = no Fire-altitude gate. A "scheduler
		// altitude" gate would gate the scheduler's Fire() call, but the
		// state-driven FireForInterface path does not go through the
		// scheduler at all — so it reaches the wire pre-T0.
		if err := exp.FireForInterface(entry, 3); err != nil {
			t.Fatalf("FireForInterface: %v", err)
		}
		if wireWrites.Load() == 0 {
			t.Fatal("expected the scheduler-altitude design to LEAK a state-driven fire to the wire; it did not — the premise of AC2 is broken")
		}
	})

	// --- Part 2: Fire-altitude gate INTERCEPTS the same path ---
	t.Run("fire_altitude_intercepts", func(t *testing.T) {
		var wireWrites atomic.Uint64
		exp := newInterceptExporter(t, &wireWrites)

		gate := &atomic.Pointer[gateState]{}
		gate.Store(&gateState{phase: phaseArmed}) // pre-T0
		led := &ledgerEntry{}
		exp.scenPart.Store(&scenarioPart{
			gate: gate, ledger: led, drain: &drainGate{},
			now: func() time.Time { return time.Unix(1_700_000_000, 0) },
		})

		if err := exp.FireForInterface(entry, 3); err != nil {
			t.Fatalf("FireForInterface: %v", err)
		}
		if got := wireWrites.Load(); got != 0 {
			t.Errorf("Fire-altitude gate failed to intercept the state-driven path: %d wire writes pre-T0 (want 0)", got)
		}
		if got := led.suppressedPreWindow.Load(); got != 1 {
			t.Errorf("state-driven pre-T0 fire should count suppressed_pre_window=1, got %d", got)
		}
	})
}

func newInterceptExporter(t *testing.T, wireWrites *atomic.Uint64) *SyslogExporter {
	t.Helper()
	return newSinkExporter(t, net.IPv4(10, 42, 0, 7), func(_ []byte) error {
		wireWrites.Add(1)
		return nil
	})
}
