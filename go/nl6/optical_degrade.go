/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"sort"
	"time"
)

// optical_degrade.go — on-demand degradation of a named optical channel
// (#334). This is the primary tool the epic exists to provide: a monitoring
// team cannot validate threshold or alarm logic without driving a wavelength
// across the FEC threshold on demand.
//
// # Why episodes, and why they are immutable
//
// The obvious implementation — an install-and-clear `atomic.Pointer` holding
// "current sag" — is WRONG here, and quietly so. `fec-uncorrectable-blocks`
// is the time integral of an above-threshold indicator over [0, t]. Clearing
// a sag pointer removes the degradation from the whole integral, including
// the part already elapsed, so the counter DECREASES. A monotonically
// non-decreasing counter is a contract every collector relies on; a counter
// that walks backwards is read as a device reboot.
//
// So degradation is an append-only list of immutable episodes, each frozen
// at publish with its own [t0, t1) window and dial offsets. Two properties
// follow, and both are load-bearing:
//
//  1. A past segment's contribution to the integral can never change, so the
//     counter is monotonic by construction rather than by care.
//  2. An episode's t0 is never in the past, so no value that a reader could
//     already have observed is retroactively altered.
//
// # Why no revert timer
//
// The interface-state convention (`POST .../oper-status` with `duration`)
// needs a goroutine because it MUTATES state that must later be put back. An
// optical episode does not: it carries its own end time, and the value engine
// is a pure function of t, so the revert happens by arithmetic when t passes
// t1. No timer, no goroutine, no cancel race, and nothing to leak. The
// user-visible contract of task 5.4 is preserved — `duration` is capped at
// maxRevertAfter, a second POST supersedes the first, and an unknown
// component is a 404 — but the mechanism is a frozen end time instead of a
// scheduled mutation. See DEVIATION note on the handler.

// maxOpticalSagDB bounds a single episode's offset on either dial. 40 dB is
// far past "dark fibre" for a coherent receive path, so anything larger is a
// caller mistake rather than a scenario; bounding it also keeps the derived
// Q/BER inside the cascade's clamps.
const maxOpticalSagDB = 40.0

// opticalEpisode is one frozen degradation window on one channel. All times
// are elapsed seconds from the cycler's startTime, matching every other
// value-engine input.
//
// An episode is IMMUTABLE once published, with one exception that preserves
// the invariant rather than breaking it: an open-ended episode's end may be
// truncated to "now" (never earlier) when a later POST supersedes it. That
// cannot change any already-observable value, because no reader can have
// evaluated a t beyond now.
type opticalEpisode struct {
	t0 float64
	// t1 is the exclusive end. Open-ended when t1 is +Inf.
	t1 float64
	// pInSagDB reduces received power; nAseRiseDB raises accumulated noise.
	// Two knobs, not one, so the attenuation quadrant (power down, OSNR
	// roughly held) and the ASE quadrant (power held, OSNR down) are both
	// reachable — the discrimination real operators perform, and the reason
	// the engine has two dials at all.
	pInSagDB   float64
	nAseRiseDB float64
}

// active reports whether the episode covers elapsed time t.
func (e opticalEpisode) active(t float64) bool { return t >= e.t0 && t < e.t1 }

// opticalEpisodeCap bounds the retained episode list per channel. Beyond it,
// fully-elapsed episodes are folded into a running total (collapseSettled).
// 256 is far more than an operator drives by hand, so a normal session never
// collapses and keeps exact history; a looping harness stays bounded.
const opticalEpisodeCap = 256

// opticalEpisodeLog is one channel's degradation history: the episodes still
// needed to evaluate the present, plus the folded contribution of those
// already discarded. Published as one immutable value so a reader takes a
// consistent snapshot of both halves with a single atomic load.
type opticalEpisodeLog struct {
	// settledAbove is above-threshold seconds already accounted over
	// [0, settledUntil); settledUntil is 0 until the first collapse.
	settledAbove float64
	settledUntil float64
	episodes     []opticalEpisode
}

// opticalOffsets is the summed dial offset in force at one instant.
type opticalOffsets struct {
	pInSagDB   float64
	nAseRiseDB float64
}

// osnrDropDB is how far OSNR is pushed down.
//
// ONLY the noise rise appears here, deliberately. OSNR is pIn − nAse, and a
// span loss attenuates signal and accumulated ASE equally, so the sag
// cancels out of the difference:
//
//	(pIn − sag) − (nAse + rise − sag) = pIn − nAse − rise
//
// That cancellation is what keeps the attenuation quadrant (power down, OSNR
// held, no FEC errors) distinguishable from the ASE quadrant (power held,
// OSNR down). Adding pInSagDB here would make a pure power sag drop OSNR 1:1
// and erase the distinction the two knobs exist to expose.
func (o opticalOffsets) osnrDropDB() float64 { return o.nAseRiseDB }

// offsetsAt sums every episode active at elapsed time t. Overlapping
// episodes accumulate — two concurrent faults on one span attenuate
// cumulatively, and summing in dB is the physically right composition.
func (oc *OpticalCycler) offsetsAt(slot int, t float64) opticalOffsets {
	if oc == nil || slot < 0 || slot >= len(oc.episodes) {
		return opticalOffsets{}
	}
	return offsetsIn(oc.episodes[slot].Load(), t)
}

// offsetsIn is offsetsAt against an EXPLICIT log rather than the published
// one. collapseSettled needs it: it integrates the log it is in the middle of
// building, which has not been published yet.
func offsetsIn(log *opticalEpisodeLog, t float64) opticalOffsets {
	var out opticalOffsets
	if log == nil {
		return out
	}
	for _, e := range log.episodes {
		if e.active(t) {
			out.pInSagDB += e.pInSagDB
			out.nAseRiseDB += e.nAseRiseDB
		}
	}
	return out
}

// breakpointsIn returns the episode boundaries strictly inside (from, to) for
// an explicit log, sorted and deduplicated.
func breakpointsIn(log *opticalEpisodeLog, from, to float64) []float64 {
	if log == nil || len(log.episodes) == 0 {
		return nil
	}
	pts := make([]float64, 0, 2*len(log.episodes))
	for _, e := range log.episodes {
		for _, b := range [2]float64{e.t0, e.t1} {
			if b > from && b < to {
				pts = append(pts, b)
			}
		}
	}
	if len(pts) == 0 {
		return nil
	}
	sort.Float64s(pts)
	out := pts[:1]
	for _, p := range pts[1:] {
		if p != out[len(out)-1] {
			out = append(out, p)
		}
	}
	return out
}

// Degrade publishes a degradation episode on one channel.
//
// `at` is the wall-clock instant the episode begins and is clamped forward to
// the cycler's "now" so t0 is never in the past (invariant 2 above). A
// non-positive `dur` means open-ended. Any episode still open on this channel
// is truncated to `at`, which is what makes a second POST supersede the first
// without ever rewriting observable history.
//
// Returns an error for an unknown component or an out-of-range offset; the
// REST layer maps those to 404 and 400.
func (oc *OpticalCycler) Degrade(component string, at time.Time, dur time.Duration, pInSagDB, nAseRiseDB float64) error {
	if oc == nil {
		return fmt.Errorf("no optical engine")
	}
	slot, ok := oc.slot[component]
	if !ok {
		return fmt.Errorf("unknown optical component %q", component)
	}
	if pInSagDB < 0 || nAseRiseDB < 0 {
		return fmt.Errorf("degradation offsets must be non-negative (got input_power_drop_db=%g noise_rise_db=%g)", pInSagDB, nAseRiseDB)
	}
	if pInSagDB > maxOpticalSagDB || nAseRiseDB > maxOpticalSagDB {
		return fmt.Errorf("degradation offset exceeds maximum %g dB", maxOpticalSagDB)
	}

	// Copy-on-append. Operator-frequency, so an O(n) copy per call is free,
	// and it keeps readers lock-free on an immutable snapshot.
	for {
		cur := oc.episodes[slot].Load()

		// t0 is recomputed on EVERY attempt, inside the loop. Hoisting it
		// above the retry would let two concurrent POSTs interleave as:
		// A computes t0=100; B computes t0=101 and commits, truncating the
		// open episode to 101; A's CAS fails, reloads, and its truncation
		// predicate no longer matches B's episode (101 > 100), so A appends
		// [100, ...) OVERLAPPING B's [101, ...). The two would then sum
		// instead of superseding, and A's t0 would sit before B's commit
		// instant — retroactively changing values a reader could already have
		// observed, which is exactly the invariant this type exists to hold.
		now := time.Since(oc.startTime).Seconds()
		t0 := at.Sub(oc.startTime).Seconds()
		if t0 < now {
			t0 = now
		}
		t1 := positiveInf
		if dur > 0 {
			t1 = t0 + dur.Seconds()
		}

		next := opticalEpisodeLog{}
		if cur != nil {
			next.settledAbove, next.settledUntil = cur.settledAbove, cur.settledUntil
			next.episodes = make([]opticalEpisode, 0, len(cur.episodes)+1)
			for _, e := range cur.episodes {
				// Truncate a still-open episode to the new start. This only
				// ever moves an end FORWARD to now, so no observed value
				// changes.
				if e.t1 > t0 && e.t0 <= t0 {
					e.t1 = t0
				}
				next.episodes = append(next.episodes, e)
			}
		}
		// A zero-offset request is a CLEAR: the truncation above already
		// ended the active episode, so publishing an empty episode would only
		// add noise to the breakpoint set.
		if pInSagDB > 0 || nAseRiseDB > 0 {
			next.episodes = append(next.episodes, opticalEpisode{t0: t0, t1: t1, pInSagDB: pInSagDB, nAseRiseDB: nAseRiseDB})
		}
		if len(next.episodes) > opticalEpisodeCap {
			oc.collapseSettled(slot, &next, now)
		}
		if oc.episodes[slot].CompareAndSwap(cur, &next) {
			return nil
		}
	}
}

// collapseSettled bounds the episode list so a harness looping
// degrade/clear cannot grow it without limit.
//
// Past episodes cannot simply be dropped — they are part of the
// above-threshold integral, and dropping them would make the counter jump
// backwards, the very failure the episode model prevents. So their
// contribution over [settledUntil, now) is FOLDED into a running total first,
// and only then are the fully-elapsed ones discarded. Still-open episodes are
// always retained.
//
// Cost of not doing this: offsetsAt is O(n) and runs once per statistics
// sample (33 per leaf read), and episodeBreakpoints allocates and sorts a 2n
// slice on every uncorrectable-block read.
//
// Trade-off, stated because it is real: after a collapse, evaluating an
// elapsed time BEFORE settledUntil can no longer reproduce the exact past —
// aboveThresholdSeconds clamps to the settled total there. Every production
// read is at ~now, which is at or after settledUntil, so this is invisible in
// practice; it only shows up in a backdated query.
func (oc *OpticalCycler) collapseSettled(slot int, log *opticalEpisodeLog, now float64) {
	// Integrate what is being dropped, using the pre-collapse list.
	settled := log.settledAbove + oc.aboveThresholdOver(slot, log, log.settledUntil, now)
	kept := make([]opticalEpisode, 0, len(log.episodes))
	for _, e := range log.episodes {
		if e.t1 > now { // still open or still to come
			kept = append(kept, e)
		}
	}
	log.settledAbove = settled
	log.settledUntil = now
	log.episodes = kept
}

// ActiveDegradation reports the offsets in force on a component right now,
// for the REST status view. ok=false for an unknown component.
func (oc *OpticalCycler) ActiveDegradation(component string) (pInSagDB, nAseRiseDB float64, ok bool) {
	if oc == nil {
		return 0, 0, false
	}
	slot, found := oc.slot[component]
	if !found {
		return 0, 0, false
	}
	o := oc.offsetsAt(slot, time.Since(oc.startTime).Seconds())
	return o.pInSagDB, o.nAseRiseDB, true
}
