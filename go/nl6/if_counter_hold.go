/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"runtime"
	"time"
)

// counterHold is one interface's hold ledger. Every counter the cycler derives
// from the octet dial holds while the interface's DERIVED ifOperStatus is not
// up(1): a down link, an admin-down port, a subinterface whose parent is down
// and an interface seeded down at boot all carry no traffic, as on a router.
//
// The dial is a pure function of elapsed time with a strictly positive
// derivative, so the hold is expressed on the dial rather than on a stored
// counter value: the delta served is delta(clamp(t)) - skipped, where
// skipped is the dial output accumulated over every COMPLETED down interval.
// That keeps the counter a function of the dial, needs no clamp to stay
// monotonic, and resumes from the held value without a jump when the
// interface comes back up. A shifted clock would do the same for the linear
// term and jump by the phase difference of the sine term at recovery.
//
// A ledger entry is immutable once published. Reads happen on every poll of
// every column and are one atomic load; writes happen on oper transitions
// only and are serialised by holdMu. A nil entry means the interface has
// never been held and reads the dial directly, so an always-up interface
// pays one load and one nil check.
type counterHold struct {
	down bool
	// downAt is the cycler-time instant the interface last left up(1).
	// Meaningful only while down.
	downAt float64
	// upAt is the instant the interface last returned to up(1). A read at an
	// earlier instant that loads this entry is clamped up to it: the reader
	// sampled its clock before the close and would otherwise apply the new
	// skipped total to an older dial reading, which is below the held value.
	// Carried across the next open for the same reason.
	upAt       float64
	skippedIn  uint64
	skippedOut uint64
}

// heldDeltasAt is the inbound and outbound dial delta for slot at t with the
// hold applied, read under ONE bracket so both directions come from one
// ledger entry. It is the only place GetDynamicAt reads the dial, so every
// surface (SNMP, both gNMI resolvers, dial-out, sFlow) observes the hold at
// once.
//
// The read is bracketed by holdSeq, a seqlock: a writer makes holdSeq odd,
// THEN samples the clock, stores the entry and makes it even again. A read
// that overlaps a write retries, so a read that completes either finished
// before the writer sampled its instant, in which case the caller's t is the
// earlier one and the held value is at or above what was served, or saw the
// new entry and was clamped by it. Without the bracket a reader that sampled
// t just after the writer's sample and loaded the ledger just before the
// store served a value above the hold, and the next poll went backwards:
// measured at eighteen thousand backwards reads in 200 ms of tight flapping.
// The bracket costs readers two atomic loads and no write; the odd window is
// one engine load and four dial evaluations under holdMu.
func (ic *IfCounterCycler) heldDeltasAt(slot int, t float64) (in, out uint64) {
	if slot >= len(ic.hold) {
		// A cycler built outside InitIfCountersWithScenario has no ledger.
		return ic.deltaOctetsAt(slot, t, true), ic.deltaOctetsAt(slot, t, false)
	}
	for {
		seq := ic.holdSeq.Load()
		if seq&1 == 1 {
			runtime.Gosched()
			continue
		}
		h := ic.hold[slot].Load()
		in, out = ic.heldDeltaFor(h, slot, t, true), ic.heldDeltaFor(h, slot, t, false)
		if ic.holdSeq.Load() == seq {
			return in, out
		}
	}
}

func (ic *IfCounterCycler) heldDeltaFor(h *counterHold, slot int, t float64, inbound bool) uint64 {
	if h == nil {
		return ic.deltaOctetsAt(slot, t, inbound)
	}
	skipped := h.skippedIn
	if !inbound {
		skipped = h.skippedOut
	}
	if h.down && t > h.downAt {
		t = h.downAt
	}
	if t < h.upAt {
		t = h.upAt
	}
	d := ic.deltaOctetsAt(slot, t, inbound)
	if d < skipped {
		// Unreachable on one binary: skipped is a sum of differences of this
		// same function at instants no later than the clamped t, evaluated
		// by the same instructions on the same inputs, and the dial is
		// strictly increasing. Kept because the alternative is a wrap to a
		// counter near 2^64; serving the base is the lesser wrong answer.
		return 0
	}
	return d - skipped
}

// reconcileHoldAt brings the ledger for ifIndex into agreement with the
// engine's CURRENT derived oper-status at cycler instant now(), sampled
// inside the write bracket after holdSeq goes odd, which is what orders it
// after every read that will not retry. It is idempotent and reads the
// engine rather than the event that triggered it, so two hooks for one
// interface that run out of order converge on the state the engine holds.
// The clock is a parameter so a test can hand it a fixed instant; production
// passes the cycler's own clock through onOperTransition.
func (ic *IfCounterCycler) reconcileHoldAt(ifIndex int, now func() float64) {
	ic.holdMu.Lock()
	defer ic.holdMu.Unlock()
	ic.holdSeq.Add(1)
	// Deferred so a panic below cannot leave the parity odd, which would
	// spin every reader of this cycler for the rest of its life.
	defer ic.holdSeq.Add(1)
	slot := ifIndex - 1
	if slot < 0 || slot >= len(ic.hold) || ic.state == nil {
		return
	}
	if _, known := ic.knownIfIndexes[ifIndex]; !known {
		return
	}
	up := ic.state.OperStatus(ifIndex) == OperUp
	h := ic.hold[slot].Load()
	t := now()
	switch {
	case up && h != nil && h.down:
		if t < h.downAt {
			t = h.downAt
		}
		ic.hold[slot].Store(&counterHold{
			upAt:       t,
			skippedIn:  h.skippedIn + ic.deltaOctetsAt(slot, t, true) - ic.deltaOctetsAt(slot, h.downAt, true),
			skippedOut: h.skippedOut + ic.deltaOctetsAt(slot, t, false) - ic.deltaOctetsAt(slot, h.downAt, false),
		})
	case !up && (h == nil || !h.down):
		n := &counterHold{down: true, downAt: t}
		if h != nil {
			// upAt is carried so a reader that sampled before the previous
			// close and loads this entry is still clamped up to that close.
			n.upAt, n.skippedIn, n.skippedOut = h.upAt, h.skippedIn, h.skippedOut
		}
		ic.hold[slot].Store(n)
	}
}

// onOperTransition is the engine's oper hook.
func (ic *IfCounterCycler) onOperTransition(ifIndex int) {
	ic.reconcileHoldAt(ifIndex, func() float64 { return time.Since(ic.startTime).Seconds() })
}

// seedHolds opens a hold at t = 0 for every known interface whose derived
// oper-status is not up(1) at engine construction, so an empty bay or a shut
// port reads its pre-seeded base from the first poll. Runs after the parent
// table is set, so a child of a seeded-down parent is included, and before
// publish, so no reader can observe it.
func (ic *IfCounterCycler) seedHolds() {
	for idx := range ic.knownIfIndexes {
		if ic.state.OperStatus(idx) != OperUp {
			ic.hold[idx-1].Store(&counterHold{down: true})
		}
	}
}
