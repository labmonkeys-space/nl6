/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkScenarioGateDecide measures the per-fire gate participation load:
// one atomic scenPart load + decide() on the in-window fast path. NFR-P1
// requires this to be 0-alloc so the gate imposes no steady-state cost at
// 30k devices.
func BenchmarkScenarioGateDecide(b *testing.B) {
	t0 := time.Unix(1_700_000_000, 0)
	t1 := t0.Add(time.Hour)
	gate := &atomic.Pointer[gateState]{}
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1})
	p := &scenarioPart{
		gate: gate, ledger: &ledgerEntry{}, drain: &drainGate{},
		now: func() time.Time { return t0.Add(time.Minute) },
	}
	var part atomic.Pointer[scenarioPart]
	part.Store(p)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lp := part.Load()
		if lp != nil {
			_ = lp.decide(sourceScenario, lp.now())
		}
	}
}
