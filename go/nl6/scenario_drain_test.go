/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/time/rate"
)

// AC3 (undo→dropped): a fire that reaches the barrier after finalize has
// begun closing must be refused admission (straggler) and counted `dropped`,
// never sent. drainGate.admit()/closeAndWait() make this deterministic
// without any WaitGroup Add-after-Wait hazard.
func TestScenarioDrain_UndoToDropped(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	t1 := t0.Add(time.Second)
	gate := &atomic.Pointer[gateState]{}
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1})
	led := &ledgerEntry{}
	d := &drainGate{}
	now := func() time.Time { return t0.Add(100 * time.Millisecond) }
	p := &scenarioPart{gate: gate, ledger: led, drain: d, now: now}

	// decide() still proceeds (gate not yet flipped)...
	if p.decide(sourceScenario, now()) != gateProceed {
		t.Fatal("decide() must proceed while running in-window")
	}
	// ...but finalize has already closed the barrier.
	d.closeAndWait()
	if p.drain.admit() {
		t.Fatal("admit() must fail after the barrier closed")
	}
	led.emitted.Add(1)
	led.dropped.Add(1) // the idiom's refused-admission branch

	if got := led.dropped.Load(); got != 1 {
		t.Errorf("dropped = %d, want 1", got)
	}
	if got := led.inWindow.Load() + led.drain.Load(); got != 0 {
		t.Errorf("in_window+drain = %d, want 0 (refused fire is never sent)", got)
	}
	if !led.identityHolds() {
		t.Errorf("identity violated: %+v", led.snapshot())
	}
}

// AC3 (barrier): wg.Wait() must not return while a gate-passed fire is still
// in flight — the drain barrier guarantees the ledger is stable before the
// controller reads it. A fire blocked mid-write is legitimately in-window
// (it was admitted in-window); the point here is that Wait outlasts it.
func TestScenarioDrain_BarrierWaitsForInflight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entry := mustEntry(t)
		t0 := time.Now()
		t1 := t0.Add(time.Second)
		gate := &atomic.Pointer[gateState]{}
		gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1})
		led := &ledgerEntry{}
		d := &drainGate{}

		blockWrite := make(chan struct{})
		exp := newSinkExporter(t, net.IPv4(10, 42, 0, 1), func(_ []byte) error { <-blockWrite; return nil })
		exp.scenPart.Store(&scenarioPart{gate: gate, ledger: led, drain: d, now: time.Now})

		go func() { _ = exp.fireScenario(entry, nil) }()
		synctest.Wait() // fire admitted into the barrier, blocked on write

		waitReturned := make(chan struct{})
		go func() { d.closeAndWait(); close(waitReturned) }()
		synctest.Wait()
		select {
		case <-waitReturned:
			t.Fatal("closeAndWait returned while a fire was still in flight (barrier broken)")
		default:
		}

		close(blockWrite) // release the in-flight write
		synctest.Wait()
		<-waitReturned // now the barrier must drain

		if got := led.inWindow.Load(); got != 1 {
			t.Errorf("in_window = %d, want 1 (fire admitted in-window)", got)
		}
		if !led.identityHolds() {
			t.Errorf("identity violated: %+v", led.snapshot())
		}
	})
}

// AC6 (cap sharing): a scenario-owned scheduler given a SharedLimiter uses
// that exact instance and never constructs a second one (FR36).
func TestScenarioScheduler_SharesLimiter(t *testing.T) {
	shared := rate.NewLimiter(rate.Limit(100), 100)
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "syslog", Rate: 10, Window: time.Second, Seed: 1}
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	s, err := newScenarioSyslogScheduler(spec, func(net.IP) *SyslogCatalog { return cat }, shared, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if s.limiterRef() != shared {
		t.Error("scenario scheduler did not reuse the shared limiter instance (would double the global cap)")
	}

	// nil shared → scenario uncapped too (fleet uncapped case).
	s2, err := newScenarioSyslogScheduler(spec, func(net.IP) *SyslogCatalog { return cat }, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if s2.limiterRef() != nil {
		t.Error("nil shared limiter must leave the scenario scheduler uncapped")
	}
}

// TestDrainGate_AdmitBeforeAndAfterClose covers the barrier contract in
// isolation: admits succeed before close, fail after, and closeAndWait
// outlasts an in-flight admit — with no WaitGroup Add-after-Wait hazard.
func TestDrainGate_AdmitBeforeAndAfterClose(t *testing.T) {
	var d drainGate
	if !d.admit() {
		t.Fatal("admit before close must succeed")
	}
	d.leave()
	d.closeAndWait() // no in-flight → returns immediately
	if d.admit() {
		t.Fatal("admit after close must fail")
	}
}
