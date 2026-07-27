/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math"
	"sync"
	"testing"
	"time"
)

// optical_degrade_test.go — the invariants that make on-demand degradation
// safe to build a collector against (#334, tasks 5.1-5.3, 5.6).

// degradeAt publishes an episode whose window is expressed in elapsed
// seconds from the cycler's startTime, bypassing the wall-clock clamp in
// Degrade so a test can place a window deterministically.
func degradeAt(oc *OpticalCycler, component string, t0, dur, pInSag, nAseRise float64) {
	slot := oc.slot[component]
	t1 := positiveInf
	if dur > 0 {
		t1 = t0 + dur
	}
	next := opticalEpisodeLog{}
	if cur := oc.episodes[slot].Load(); cur != nil {
		next = *cur
		next.episodes = append([]opticalEpisode(nil), cur.episodes...)
	}
	next.episodes = append(next.episodes, opticalEpisode{t0: t0, t1: t1, pInSagDB: pInSag, nAseRiseDB: nAseRise})
	oc.episodes[slot].Store(&next)
}

// TestDegradeCrossesFECThreshold: a clean channel accrues no uncorrectable
// blocks; a degraded window drives it past the SD-FEC threshold. This is the
// capability the epic exists to provide.
func TestDegradeCrossesFECThreshold(t *testing.T) {
	oc := newOpticalCycler(t, 11, opticalBandFor(OpticalClean))
	const och = "OCH-1-1"

	if before := mustU64(t, oc, och, 600); before != mustU64(t, oc, och, 0) {
		t.Fatal("clean channel accrued uncorrectable blocks before any degradation")
	}

	// Crossing the threshold is an OSNR phenomenon, so it takes a NOISE rise:
	// clean sits ~18.3 dB OSNR against a 13.13 dB threshold, and attenuation
	// alone would not move OSNR at all (see TestDegradeQuadrants). A small
	// power sag rides along to prove the two compose.
	degradeAt(oc, och, 600, 300, 2, 8)

	base := mustU64(t, oc, och, 600)
	during := mustU64(t, oc, och, 900)
	if during <= base {
		t.Errorf("degradation did not accrue uncorrectable blocks (%d -> %d)", base, during)
	}
	ber := decOf(t, oc, och, OpticalLeafPreFECBER+"/instant", 750)
	if ber <= opticalSDFECThresholdBER {
		t.Errorf("pre-FEC BER %g during degradation is not above the SD-FEC threshold %g", ber, opticalSDFECThresholdBER)
	}
}

// TestDegradeCounterNeverDecreases is the invariant the episode model exists
// to protect (task 5.1). An install-and-clear pointer would remove the
// elapsed degradation from the integral on revert and walk the counter
// backwards — which a collector reads as a device reboot.
func TestDegradeCounterNeverDecreases(t *testing.T) {
	oc := newOpticalCycler(t, 12, opticalBandFor(OpticalClean))
	const och = "OCH-1-1"
	degradeAt(oc, och, 1000, 500, 0, 9) // one closed window: degrade then revert

	prev := uint64(0)
	for at := 0.0; at <= 4000; at += 25 {
		got := mustU64(t, oc, och, at)
		if got < prev {
			t.Fatalf("uncorrectable blocks decreased at t=%v: %d -> %d", at, prev, got)
		}
		prev = got
	}

	// And the accrual must actually stop after the window closes, or the
	// "revert" did nothing.
	afterA := mustU64(t, oc, och, 2000)
	afterB := mustU64(t, oc, och, 3500)
	if afterA != afterB {
		t.Errorf("counter still accruing after the episode ended (%d -> %d); revert did not take effect", afterA, afterB)
	}
}

// TestDegradeRevertReturnsToBand: after the window closes the channel is back
// in its configured band, bit-for-bit with an undegraded engine of the same
// seed. That equality is what makes "revert" mean revert.
func TestDegradeRevertReturnsToBand(t *testing.T) {
	const och = "OCH-1-1"
	band := opticalBandFor(OpticalTypical)
	degraded := newOpticalCycler(t, 13, band)
	clean := newOpticalCycler(t, 13, band)
	degradeAt(degraded, och, 100, 200, 6, 2)

	// During: the two must differ, or the test proves nothing.
	if decOf(t, degraded, och, OpticalLeafOSNR+"/instant", 200) == decOf(t, clean, och, OpticalLeafOSNR+"/instant", 200) {
		t.Fatal("degraded and clean OSNR agree DURING the episode; the sag is not being applied")
	}
	// After: identical.
	for _, leaf := range []string{OpticalLeafOSNR, OpticalLeafInputPower, OpticalLeafQValue, OpticalLeafESNR} {
		for _, at := range []float64{300, 500, 1800} {
			d := decOf(t, degraded, och, leaf+"/instant", at)
			c := decOf(t, clean, och, leaf+"/instant", at)
			if d != c {
				t.Errorf("%s at t=%v after revert: degraded %v != clean %v", leaf, at, d, c)
			}
		}
	}
}

// TestDegradeStatsInvariantHolds: min <= instant <= max must survive
// degradation, including a window that starts or ends INSIDE the statistics
// window — the case a closed-form summary over the sinusoid would get wrong,
// and the reason statsFor samples.
func TestDegradeStatsInvariantHolds(t *testing.T) {
	oc := newOpticalCycler(t, 14, opticalBandFor(OpticalClean))
	const och = "OCH-1-1"
	degradeAt(oc, och, 1000, 400, 7, 1)

	for _, leaf := range []string{OpticalLeafOSNR, OpticalLeafInputPower, OpticalLeafPreFECBER, OpticalLeafQValue} {
		// Sample across the episode edges at a finer step than the window.
		for at := 700.0; at <= 1700; at += 37 {
			inst := decOf(t, oc, och, leaf+"/instant", at)
			min := decOf(t, oc, och, leaf+"/min", at)
			max := decOf(t, oc, och, leaf+"/max", at)
			avg := decOf(t, oc, och, leaf+"/avg", at)
			if min > inst || inst > max {
				t.Fatalf("%s at t=%v: min %v <= instant %v <= max %v violated", leaf, at, min, inst, max)
			}
			if avg < min || avg > max {
				t.Fatalf("%s at t=%v: avg %v outside [%v, %v]", leaf, at, avg, min, max)
			}
		}
	}
}

// TestDegradeLeavesOffSpineFlat: the fibre-vs-transponder diagnostic. A
// receive-side fault must not move transmit power, laser bias, dispersion or
// PDL — if every needle moves together the simulator teaches a collector
// nothing.
func TestDegradeLeavesOffSpineFlat(t *testing.T) {
	const och = "OCH-1-1"
	band := opticalBandFor(OpticalClean)
	degraded := newOpticalCycler(t, 15, band)
	clean := newOpticalCycler(t, 15, band)
	degradeAt(degraded, och, 0, 3600, 10, 3)

	offSpine := []string{
		OpticalLeafOutputPower, OpticalLeafLaserBias, OpticalLeafChromaticDisp,
		OpticalLeafPMD, OpticalLeafPDL,
	}
	for _, leaf := range offSpine {
		for _, at := range []float64{60, 900, 1800} {
			d := decOf(t, degraded, och, leaf+"/instant", at)
			c := decOf(t, clean, och, leaf+"/instant", at)
			if d != c {
				t.Errorf("off-spine %s moved under receive degradation at t=%v: %v != %v", leaf, at, d, c)
			}
		}
	}
	// Sanity: the receive spine DID move, so the comparison above is meaningful.
	if decOf(t, degraded, och, OpticalLeafOSNR+"/instant", 900) == decOf(t, clean, och, OpticalLeafOSNR+"/instant", 900) {
		t.Fatal("receive spine did not move; the off-spine assertions prove nothing")
	}
}

// TestDegradeOnlyAffectsNamedChannel: degradation is keyed by component, so a
// sibling channel on the same device stays in band.
func TestDegradeOnlyAffectsNamedChannel(t *testing.T) {
	oc := newOpticalCycler(t, 16, opticalBandFor(OpticalClean))
	clean := newOpticalCycler(t, 16, opticalBandFor(OpticalClean))
	degradeAt(oc, "OCH-1-1", 0, 3600, 0, 9)

	if decOf(t, oc, "OCH-1-2", OpticalLeafOSNR+"/instant", 600) != decOf(t, clean, "OCH-1-2", OpticalLeafOSNR+"/instant", 600) {
		t.Error("degrading OCH-1-1 moved OCH-1-2")
	}
	if decOf(t, oc, "OCH-1-1", OpticalLeafOSNR+"/instant", 600) == decOf(t, clean, "OCH-1-1", OpticalLeafOSNR+"/instant", 600) {
		t.Error("OCH-1-1 was not degraded")
	}
}

// TestDegradeQuadrants: the two knobs must be independently reachable, which
// is the entire justification for two dials. A pure power sag attenuates
// signal and noise together, so OSNR barely moves; a pure noise rise leaves
// power intact and drops OSNR.
func TestDegradeQuadrants(t *testing.T) {
	const och = "OCH-1-1"
	band := opticalBandFor(OpticalClean)
	base := newOpticalCycler(t, 17, band)
	atten := newOpticalCycler(t, 17, band)
	ase := newOpticalCycler(t, 17, band)
	degradeAt(atten, och, 0, 3600, 5, 0) // attenuation quadrant
	degradeAt(ase, och, 0, 3600, 0, 5)   // ASE quadrant

	at := 600.0
	basePwr := decOf(t, base, och, OpticalLeafInputPower+"/instant", at)
	baseOsnr := decOf(t, base, och, OpticalLeafOSNR+"/instant", at)

	// Attenuation: power falls...
	if got := decOf(t, atten, och, OpticalLeafInputPower+"/instant", at); math.Abs(got-(basePwr-5)) > 0.02 {
		t.Errorf("attenuation: input power %v, want ~%v", got, basePwr-5)
	}
	// ...and OSNR HOLDS. This is the assertion whose absence let a bug ship in
	// review: signal and accumulated ASE attenuate together through the same
	// fibre, so the loss cancels out of their difference. Without it, a pure
	// power sag drops OSNR 1:1 and the attenuation quadrant silently becomes
	// the ASE quadrant — so a collector rule for "dirty connector: low power,
	// normal OSNR, no FEC errors" could never be exercised.
	if got := decOf(t, atten, och, OpticalLeafOSNR+"/instant", at); got != baseOsnr {
		t.Errorf("attenuation must leave OSNR intact: %v != %v (signal and ASE attenuate together)", got, baseOsnr)
	}
	// And it must stay clear of the FEC threshold: attenuation alone is not
	// service-affecting, which is exactly what makes it diagnostically
	// distinct from an ASE fault of the same magnitude.
	if got := mustU64(t, atten, och, 1800); got != mustU64(t, base, och, 1800) {
		t.Errorf("attenuation alone accrued uncorrectable blocks; power loss does not degrade OSNR")
	}

	// ASE: power intact, OSNR down.
	if got := decOf(t, ase, och, OpticalLeafInputPower+"/instant", at); got != basePwr {
		t.Errorf("ASE quadrant must leave received power intact: %v != %v", got, basePwr)
	}
	if got := decOf(t, ase, och, OpticalLeafOSNR+"/instant", at); math.Abs(got-(baseOsnr-5)) > 0.02 {
		t.Errorf("ASE quadrant: OSNR %v, want ~%v", got, baseOsnr-5)
	}

	// Both together: power down AND OSNR down — the fourth quadrant.
	both := newOpticalCycler(t, 17, band)
	degradeAt(both, och, 0, 3600, 5, 5)
	if got := decOf(t, both, och, OpticalLeafInputPower+"/instant", at); math.Abs(got-(basePwr-5)) > 0.02 {
		t.Errorf("combined: input power %v, want ~%v", got, basePwr-5)
	}
	if got := decOf(t, both, och, OpticalLeafOSNR+"/instant", at); math.Abs(got-(baseOsnr-5)) > 0.02 {
		t.Errorf("combined: OSNR %v, want ~%v", got, baseOsnr-5)
	}
}

// TestDegradeSupersedeTruncatesOpenEpisode: a second request supersedes the
// first (the observable half of the interface-state convention). Truncation
// only ever moves an open end FORWARD to now, so no already-observable value
// changes — which the monotonic counter check guards.
func TestDegradeSupersedeTruncatesOpenEpisode(t *testing.T) {
	oc := newOpticalCycler(t, 18, opticalBandFor(OpticalClean))
	const och = "OCH-1-1"

	if err := oc.Degrade(och, time.Now(), 0, 6, 0); err != nil { // open-ended
		t.Fatalf("first Degrade: %v", err)
	}
	sag, _, ok := oc.ActiveDegradation(och)
	if !ok || sag != 6 {
		t.Fatalf("active sag = %v (ok=%v), want 6", sag, ok)
	}
	// Supersede with a different sag.
	if err := oc.Degrade(och, time.Now(), time.Hour, 3, 0); err != nil {
		t.Fatalf("second Degrade: %v", err)
	}
	sag, _, _ = oc.ActiveDegradation(och)
	if sag != 3 {
		t.Errorf("after supersede active sag = %v, want 3 (the first episode must be truncated, not summed)", sag)
	}
	// A zero-offset request clears.
	if err := oc.Degrade(och, time.Now(), 0, 0, 0); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if sag, rise, _ := oc.ActiveDegradation(och); sag != 0 || rise != 0 {
		t.Errorf("after clear active offsets = (%v, %v), want (0, 0)", sag, rise)
	}
}

// TestDegradeRejectsBadInput covers the validation the REST layer maps to
// 400 / 404.
func TestDegradeRejectsBadInput(t *testing.T) {
	oc := newOpticalCycler(t, 19, opticalBandFor(OpticalClean))
	if err := oc.Degrade("OCH-9-9", time.Now(), time.Minute, 3, 0); err == nil {
		t.Error("unknown component must be rejected")
	}
	if err := oc.Degrade("OCH-1-1", time.Now(), time.Minute, -1, 0); err == nil {
		t.Error("negative offset must be rejected")
	}
	if err := oc.Degrade("OCH-1-1", time.Now(), time.Minute, maxOpticalSagDB+1, 0); err == nil {
		t.Error("over-cap offset must be rejected")
	}
}

// TestDegradeT0NeverInThePast is invariant 2 (task 5.2): a caller asking for
// a window that began in the past gets it clamped to now, so no value a
// reader could already have observed changes retroactively.
func TestDegradeT0NeverInThePast(t *testing.T) {
	oc := newOpticalCycler(t, 20, opticalBandFor(OpticalClean))
	const och = "OCH-1-1"
	if err := oc.Degrade(och, time.Now().Add(-time.Hour), time.Hour, 8, 0); err != nil {
		t.Fatalf("Degrade: %v", err)
	}
	log := oc.episodes[oc.slot[och]].Load()
	if log == nil || len(log.episodes) != 1 {
		t.Fatalf("expected 1 episode, got %v", log)
	}
	if log.episodes[0].t0 < 0 {
		t.Errorf("episode t0 = %v; a backdated request must clamp to now, never to a negative elapsed time", log.episodes[0].t0)
	}
	// The counter at t=0 must still be the pristine base — the backdated
	// request must not have retroactively degraded the start of time.
	if got, want := mustU64(t, oc, och, 0), oc.uncorrBase[oc.slot[och]]; got != want {
		t.Errorf("counter at t=0 = %d, want the untouched base %d", got, want)
	}
}

// TestDegradeConcurrentSupersede is the race the review caught: with t0
// computed once outside the CAS retry, two concurrent POSTs could each win a
// round and leave OVERLAPPING episodes that sum instead of superseding — and
// the loser's t0 would predate the winner's commit, retroactively changing
// already-observable values. Recomputing inside the loop closes it.
//
// Run under -race. The assertion is on the outcome, not the timing: whatever
// order they land in, exactly one episode may be active afterwards.
func TestDegradeConcurrentSupersede(t *testing.T) {
	oc := newOpticalCycler(t, 21, opticalBandFor(OpticalClean))
	const och = "OCH-1-1"

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = oc.Degrade(och, time.Now(), 0, 4, 0) // open-ended, identical
		}()
	}
	wg.Wait()

	sag, _, _ := oc.ActiveDegradation(och)
	if sag != 4 {
		t.Errorf("active sag = %v after 8 concurrent identical requests, want 4 — overlapping episodes summed instead of superseding", sag)
	}
	// No episode may start before the last commit: an overlap would show up as
	// two simultaneously-active windows.
	log := oc.episodes[oc.slot[och]].Load()
	now := time.Since(oc.startTime).Seconds()
	active := 0
	for _, e := range log.episodes {
		if e.active(now) {
			active++
		}
	}
	if active != 1 {
		t.Errorf("%d episodes active at once, want exactly 1", active)
	}
}

// TestDegradeEpisodeListStaysBounded: a harness looping degrade/clear must not
// grow memory without limit, and the collapse that bounds it must not disturb
// the counter — folding elapsed episodes into a running total is only safe if
// the total is preserved.
func TestDegradeEpisodeListStaysBounded(t *testing.T) {
	oc := newOpticalCycler(t, 22, opticalBandFor(OpticalClean))
	const och = "OCH-1-1"
	slot := oc.slot[och]

	prev := uint64(0)
	for i := 0; i < opticalEpisodeCap*3; i++ {
		if err := oc.Degrade(och, time.Now(), time.Millisecond, 0, 9); err != nil {
			t.Fatalf("Degrade %d: %v", i, err)
		}
		// The counter must never walk backwards across a collapse.
		now := time.Since(oc.startTime).Seconds()
		got := oc.uncorrBlocksAt(slot, now)
		if got < prev {
			t.Fatalf("counter decreased across collapse at iteration %d: %d -> %d", i, prev, got)
		}
		prev = got
	}

	log := oc.episodes[slot].Load()
	if len(log.episodes) > opticalEpisodeCap+1 {
		t.Errorf("retained %d episodes after %d requests; the list must stay bounded",
			len(log.episodes), opticalEpisodeCap*3)
	}
	if log.settledUntil == 0 {
		t.Error("no collapse happened, so this test did not exercise the bound")
	}
}
