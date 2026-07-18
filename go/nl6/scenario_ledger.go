/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sync/atomic"
	"time"
)

// scenarioSubWindowCount is the fixed number of equal time sub-windows the
// in-window measurement span [T0,T1) is sliced into for loss localization
// (FR28, story 5.3). A fixed COUNT (not a fixed duration) keeps the report
// bounded and window-length-independent: bucket width = actual (t1−t0)/N.
const scenarioSubWindowCount = 10

// ledgerEntry is one participant's exact sent-record accounting for a
// scenario window. All counters are written by producer sites (atomics,
// adjacent to the outcome per the counter-discipline pattern) and read for
// the report only after the drain barrier (wg.Wait) — approximate mid-run
// atomic reads are allowed for predicates/live counts (Growth).
//
// Ledger identity (FR23, PR0 boundary decisions in scenario_boundary.go):
//
//	emitted = sent + send_failures + dropped + suppressed_pre_window
//	sent    = in_window + drain
//
// `emitted` counts records actually GENERATED: gate-passed fires plus
// emission-suppressed (counted) pre-T0 fires. Generation-suppressed
// background skips never generate and live only in the informational
// backgroundSuppressed counter — outside the identity by design.
type ledgerEntry struct {
	emitted             atomic.Uint64
	inWindow            atomic.Uint64
	drain               atomic.Uint64
	suppressedPreWindow atomic.Uint64
	sendFailures        atomic.Uint64
	dropped             atomic.Uint64

	// backgroundSuppressed is informational disclosure (FR15/FR21): how
	// many background fires the gate skipped for this participant. NOT
	// part of the ledger identity.
	backgroundSuppressed atomic.Uint64

	// requested / deferred make a global-cap throttle visible (FR22).
	// requested counts every scheduler pop for this participant (the demand,
	// pre-limiter); deferred counts pops the shared cap had no token for (not
	// fired — throttled, NOT lost). Both sit OUTSIDE the ledger identity and
	// the loss denominator: deferral is not loss.
	requested atomic.Uint64
	deferred  atomic.Uint64

	// informsOriginated / informsAcked are the best-effort SNMP INFORM ack
	// settlement (FR: trap/INFORM), both informational (outside the identity).
	// An origination is counted at first-transmit ONLY in INFORM mode (0 for
	// fire-and-forget traps and every other protocol); informs_pending =
	// originated − acked at report time.
	informsOriginated atomic.Uint64
	informsAcked      atomic.Uint64

	// subWindows localizes in-window fires (FR28): N equal time buckets over
	// [T0,T1), incremented from bucketFor's in-window branch. Purely additive
	// — sum(subWindows) == inWindow, and it touches no identity counter.
	subWindows [scenarioSubWindowCount]atomic.Uint64
}

// recordSubWindow attributes a successful in-window fire at write-return time
// t to its time bucket. Called only from bucketFor's in-window branch, so
// t ∈ [t0,t1) is guaranteed; the index is clamped defensively anyway.
func (l *ledgerEntry) recordSubWindow(gs *gateState, t time.Time) {
	span := gs.t1.Sub(gs.t0)
	if span <= 0 {
		return
	}
	off := t.Sub(gs.t0)
	if off < 0 {
		off = 0
	}
	idx := int(int64(off) * scenarioSubWindowCount / int64(span))
	if idx < 0 {
		idx = 0
	} else if idx >= scenarioSubWindowCount {
		idx = scenarioSubWindowCount - 1
	}
	l.subWindows[idx].Add(1)
}

// identityHolds checks the ledger identity exactly. Call only after the
// drain barrier (or under synctest quiesce) — mid-run the counters move.
func (l *ledgerEntry) identityHolds() bool {
	sent := l.inWindow.Load() + l.drain.Load()
	return l.emitted.Load() == sent+l.sendFailures.Load()+l.dropped.Load()+l.suppressedPreWindow.Load()
}

// ledgerSnapshot is an immutable copy taken at finalize.
type ledgerSnapshot struct {
	Emitted              uint64
	InWindow             uint64
	Drain                uint64
	SuppressedPreWindow  uint64
	SendFailures         uint64
	Dropped              uint64
	BackgroundSuppressed uint64
	Requested            uint64
	Deferred             uint64
	InformsOriginated    uint64
	InformsAcked         uint64
	// SubWindows is the per-time-bucket in-window tally (FR28); sums to
	// InWindow. A fixed array (not a slice) keeps ledgerSnapshot comparable.
	SubWindows [scenarioSubWindowCount]uint64
}

func (l *ledgerEntry) snapshot() ledgerSnapshot {
	var sw [scenarioSubWindowCount]uint64
	for i := range l.subWindows {
		sw[i] = l.subWindows[i].Load()
	}
	return ledgerSnapshot{
		Emitted:              l.emitted.Load(),
		InWindow:             l.inWindow.Load(),
		Drain:                l.drain.Load(),
		SuppressedPreWindow:  l.suppressedPreWindow.Load(),
		SendFailures:         l.sendFailures.Load(),
		Dropped:              l.dropped.Load(),
		BackgroundSuppressed: l.backgroundSuppressed.Load(),
		Requested:            l.requested.Load(),
		Deferred:             l.deferred.Load(),
		InformsOriginated:    l.informsOriginated.Load(),
		InformsAcked:         l.informsAcked.Load(),
		SubWindows:           sw,
	}
}
