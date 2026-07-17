/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "sync/atomic"

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
}

func (l *ledgerEntry) snapshot() ledgerSnapshot {
	return ledgerSnapshot{
		Emitted:              l.emitted.Load(),
		InWindow:             l.inWindow.Load(),
		Drain:                l.drain.Load(),
		SuppressedPreWindow:  l.suppressedPreWindow.Load(),
		SendFailures:         l.sendFailures.Load(),
		Dropped:              l.dropped.Load(),
		BackgroundSuppressed: l.backgroundSuppressed.Load(),
	}
}
