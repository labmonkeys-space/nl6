/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"testing"
	"time"
)

// TestFlowTicker_HonorsConfiguredInterval is the nl6#446 regression guard.
//
// The defect was an ORDERING bug, not a logic bug: startFlowTicker latches its
// period during construction, and the flag path called a setter afterwards that
// only wrote a field nothing re-read. Every deployment ticked at the 5s default
// however the flag was set, so a load test sized by that flag offered a
// different rate than the operator asked for.
//
// The test asserts the latched period, not the field, because the field was
// always correct — it was the latch that never saw it.
func TestFlowTicker_HonorsConfiguredInterval(t *testing.T) {
	const want = 30 * time.Second

	sm := &SimulatorManager{}
	WithFlowTickInterval(want)(sm) // what the constructor now does, BEFORE init
	sm.flowStopCh = make(chan struct{})
	if sm.flowTickInterval == 0 {
		sm.flowTickInterval = defaultFlowTickInterval
	}
	sm.startFlowTicker()
	defer func() { close(sm.flowStopCh); sm.flowWg.Wait() }()

	if got := time.Duration(sm.flowTickerPeriod.Load()); got != want {
		t.Errorf("ticker latched %s, want %s — the configured cadence never reached the ticker (nl6#446)", got, want)
	}
}

// TestFlowTicker_RejectsOutOfRange pins that the option is a guard, not just an
// assignment: a value outside (0, maxFlowTickInterval] must leave the field
// untouched so the caller's defaulting applies.
//
// The overflow cases are the reason for an upper bound at all. `-flow-tick-
// interval` is a plain flag.Int multiplied by time.Second, so a large value
// wraps int64 — and can wrap POSITIVE, passing a bare `d > 0` gate. Before the
// bound, 999999999999 latched ~123 years and the simulator exported zero flow
// records for the life of the process with nothing in the log.
func TestFlowTicker_RejectsOutOfRange(t *testing.T) {
	// Computed at runtime, not as constants: the compiler rejects a literal
	// that overflows time.Duration, but `flag.Int` * time.Second overflows at
	// RUNTIME and silently wraps, which is the case under test.
	// Slice-indexed so the compiler cannot constant-fold (and reject) these;
	// the real path is a *flag.Int deref, equally opaque at compile time.
	secs := []int64{999999999999, 10000000000}
	overflowPos := time.Duration(secs[0]) * time.Second
	overflowNeg := time.Duration(secs[1]) * time.Second

	for _, tc := range []struct {
		name string
		opt  time.Duration
	}{
		{"zero", 0},
		{"negative", -1 * time.Second},
		{"above-cap", maxFlowTickInterval + time.Second},
		{"overflow-positive", overflowPos},
		{"overflow-negative", overflowNeg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm := &SimulatorManager{}
			WithFlowTickInterval(tc.opt)(sm)
			if sm.flowTickInterval != 0 {
				t.Fatalf("out-of-range %v was accepted as %v; it must leave the field untouched",
					tc.opt, sm.flowTickInterval)
			}
			// ...and the latch must then floor it rather than panic.
			sm.flowStopCh = make(chan struct{})
			sm.startFlowTicker()
			defer func() { close(sm.flowStopCh); sm.flowWg.Wait() }()

			if got := time.Duration(sm.flowTickerPeriod.Load()); got != defaultFlowTickInterval {
				t.Errorf("latched %s, want the default %s", got, defaultFlowTickInterval)
			}
		})
	}
}

// TestFlowTicker_AcceptsInRange is the positive half: the guard must not reject
// legitimate values, including the cap itself.
func TestFlowTicker_AcceptsInRange(t *testing.T) {
	for _, d := range []time.Duration{time.Second, 7 * time.Second, maxFlowTickInterval} {
		sm := &SimulatorManager{}
		WithFlowTickInterval(d)(sm)
		if sm.flowTickInterval != d {
			t.Errorf("in-range %v was rejected (field=%v)", d, sm.flowTickInterval)
		}
	}
}

// TestFlowTicker_NilOptionIsSkipped: a conditional option leaves a nil in the
// slice, and dereferencing it would panic AFTER the constructor has created the
// nl6sim netns and its iptables rule but before any path that removes them —
// leaking both along with the process.
func TestFlowTicker_NilOptionIsSkipped(t *testing.T) {
	sm := NewSimulatorManagerWithOptions(false, nil, WithFlowTickInterval(7*time.Second))
	defer func() { _ = sm.Shutdown() }()

	if got := time.Duration(sm.flowTickerPeriod.Load()); got != 7*time.Second {
		t.Errorf("latched %s, want 7s — a nil option must be skipped, not fatal", got)
	}
}

// TestFlowTicker_ConstructorHonorsTheFlag exercises the REAL constructor rather
// than hand-rolling the init sequence, so it would catch the option seam being
// wired into the wrong place — the exact failure mode nl6#446 was. The tests
// above pin startFlowTicker's contract; this one pins that the constructor
// actually honours it.
func TestFlowTicker_ConstructorHonorsTheFlag(t *testing.T) {
	sm := NewSimulatorManagerWithOptions(false, WithFlowTickInterval(30*time.Second))
	defer func() { _ = sm.Shutdown() }()

	if got := time.Duration(sm.flowTickerPeriod.Load()); got != 30*time.Second {
		t.Fatalf("constructor latched %s, want 30s; the option did not reach the ticker (nl6#446)", got)
	}
}
