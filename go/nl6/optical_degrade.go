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

// opticalOffsets is the summed dial offset in force at one instant.
type opticalOffsets struct {
	pInSagDB   float64
	nAseRiseDB float64
}

// osnrDropDB is how far OSNR is pushed down. OSNR is pIn − nAse, so a power
// sag and a noise rise both reduce it and their effects add.
func (o opticalOffsets) osnrDropDB() float64 { return o.pInSagDB + o.nAseRiseDB }

// offsetsAt sums every episode active at elapsed time t. Overlapping
// episodes accumulate — two concurrent faults on one span attenuate
// cumulatively, and summing in dB is the physically right composition.
func (oc *OpticalCycler) offsetsAt(slot int, t float64) opticalOffsets {
	var out opticalOffsets
	if oc == nil || slot < 0 || slot >= len(oc.episodes) {
		return out
	}
	eps := oc.episodes[slot].Load()
	if eps == nil {
		return out
	}
	for _, e := range *eps {
		if e.active(t) {
			out.pInSagDB += e.pInSagDB
			out.nAseRiseDB += e.nAseRiseDB
		}
	}
	return out
}

// episodeBreakpoints returns the episode boundaries strictly inside (0, t),
// sorted and deduplicated. These are the only instants at which the summed
// offset can change, so they are exactly where the above-threshold integral
// must be split.
func (oc *OpticalCycler) episodeBreakpoints(slot int, t float64) []float64 {
	if oc == nil || slot < 0 || slot >= len(oc.episodes) {
		return nil
	}
	eps := oc.episodes[slot].Load()
	if eps == nil || len(*eps) == 0 {
		return nil
	}
	pts := make([]float64, 0, 2*len(*eps))
	for _, e := range *eps {
		for _, b := range [2]float64{e.t0, e.t1} {
			if b > 0 && b < t {
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

	now := time.Since(oc.startTime).Seconds()
	t0 := at.Sub(oc.startTime).Seconds()
	if t0 < now {
		t0 = now
	}
	t1 := positiveInf
	if dur > 0 {
		t1 = t0 + dur.Seconds()
	}

	// Copy-on-append. Operator-frequency, so an O(n) copy per call is free,
	// and it keeps readers lock-free on an immutable snapshot.
	for {
		cur := oc.episodes[slot].Load()
		var next []opticalEpisode
		if cur != nil {
			next = make([]opticalEpisode, 0, len(*cur)+1)
			for _, e := range *cur {
				// Truncate a still-open episode to the new start. Never moves
				// an end backwards past `now`, so no observed value changes.
				if e.t1 > t0 && e.t0 <= t0 {
					e.t1 = t0
				}
				next = append(next, e)
			}
		} else {
			next = make([]opticalEpisode, 0, 1)
		}
		// A zero-offset request is a CLEAR: the truncation above already
		// ended the active episode, so publishing an empty episode would only
		// add noise to the breakpoint set.
		if pInSagDB > 0 || nAseRiseDB > 0 {
			next = append(next, opticalEpisode{t0: t0, t1: t1, pInSagDB: pInSagDB, nAseRiseDB: nAseRiseDB})
		}
		if oc.episodes[slot].CompareAndSwap(cur, &next) {
			return nil
		}
	}
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
