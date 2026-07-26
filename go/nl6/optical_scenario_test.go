/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math"
	"strings"
	"testing"
)

func TestParseOpticalScenario(t *testing.T) {
	valid := map[string]OpticalScenario{
		"":          OpticalClean,
		"clean":     OpticalClean,
		"CLEAN":     OpticalClean,
		"  Clean  ": OpticalClean,
		"typical":   OpticalTypical,
		"Typical":   OpticalTypical,
		"degraded":  OpticalDegraded,
		"failing":   OpticalFailing,
		"FAILING":   OpticalFailing,
	}
	for in, want := range valid {
		got, err := ParseOpticalScenario(in)
		if err != nil {
			t.Errorf("ParseOpticalScenario(%q) errored: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseOpticalScenario(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"broken", "cleanish", "worst", "0", "clean typical"} {
		got, err := ParseOpticalScenario(in)
		if err == nil {
			t.Errorf("ParseOpticalScenario(%q) = %q, want an error", in, got)
			continue
		}
		// The message must be self-service on both the CLI and REST.
		for _, tier := range []string{"clean", "typical", "degraded", "failing"} {
			if !strings.Contains(err.Error(), tier) {
				t.Errorf("error %q does not name the accepted tier %q", err, tier)
			}
		}
	}
}

// TestOpticalBandsProgressMonotonically pins the tier semantics: each
// step must be strictly worse on the receive spine, and only `failing`
// may be service-affecting.
func TestOpticalBandsProgressMonotonically(t *testing.T) {
	tiers := []OpticalScenario{OpticalClean, OpticalTypical, OpticalDegraded, OpticalFailing}

	var prevOsnr, prevBer float64
	for i, tier := range tiers {
		oc := newOpticalCycler(t, 101, opticalBandFor(tier))
		osnr := decOf(t, oc, "OCH-1-1", OpticalLeafOSNR+"/avg", 1800)
		ber := decOf(t, oc, "OCH-1-1", OpticalLeafPreFECBER+"/avg", 1800)
		pwr := decOf(t, oc, "OCH-1-1", OpticalLeafInputPower+"/avg", 1800)

		if i > 0 {
			if osnr >= prevOsnr {
				t.Errorf("%s: OSNR %v did not fall below the previous tier's %v", tier, osnr, prevOsnr)
			}
			if ber <= prevBer {
				t.Errorf("%s: pre-FEC BER %v did not rise above the previous tier's %v", tier, ber, prevBer)
			}
		}
		prevOsnr, prevBer = osnr, ber

		// Both dials move per tier — a tier that only moved one would
		// collapse the two-dial model the engine exists to provide.
		if tier != OpticalClean && pwr >= decOf(t,
			newOpticalCycler(t, 101, opticalBandFor(OpticalClean)),
			"OCH-1-1", OpticalLeafInputPower+"/avg", 1800) {
			t.Errorf("%s: received power %v did not fall below clean", tier, pwr)
		}
	}
}

// TestOpticalFailingIsServiceAffecting is the tier contract that matters
// to a collector: only `failing` accrues uncorrectable blocks, and it
// does so reliably rather than intermittently.
func TestOpticalFailingIsServiceAffecting(t *testing.T) {
	for _, tier := range []OpticalScenario{OpticalClean, OpticalTypical, OpticalDegraded} {
		oc := newOpticalCycler(t, 202, opticalBandFor(tier))
		start := mustU64(t, oc, "OCH-1-1", 0)
		for off := 0.0; off <= 2*opticalDialPeriodSec; off += 137 {
			if got := mustU64(t, oc, "OCH-1-1", off); got != start {
				t.Fatalf("%s accrued uncorrectable blocks at %v (%d -> %d); only failing should",
					tier, off, start, got)
			}
		}
	}

	oc := newOpticalCycler(t, 202, opticalBandFor(OpticalFailing))
	start := mustU64(t, oc, "OCH-1-1", 0)
	end := mustU64(t, oc, "OCH-1-1", 2*opticalDialPeriodSec)
	if end <= start {
		t.Errorf("failing tier accrued no uncorrectable blocks over two dial periods (%d -> %d)", start, end)
	}
	// And it must be continuous, not a brief excursion: the band sits past
	// the threshold even at its best moment.
	prev := start
	stalled := 0
	for off := 0.0; off <= opticalDialPeriodSec; off += 60 {
		got := mustU64(t, oc, "OCH-1-1", off)
		if got == prev {
			stalled++
		}
		prev = got
	}
	if stalled > 3 {
		t.Errorf("failing tier stalled at %d of the sampled points; it should be persistently "+
			"past the FEC threshold, not intermittent", stalled)
	}
}

// TestOpticalBandContractsHoldAcrossSeeds sweeps seeds because the tier
// contracts are broken by the TAILS of the per-channel jitter, not by the
// nominal operating point — a single-seed test (as the two above are) sees
// only one draw and passes while a fleet-sized share of channels violates
// the contract. Both dial means are jittered independently, so the OSNR
// mean spreads over +-2*opticalMeanJitterDB on top of the sine amplitude.
//
// Asserted per channel, against the engine's own threshold:
//
//	clean/typical/degraded: NEVER above the FEC threshold (no blocks ever)
//	failing:                ALWAYS above it, for the entire dial period
//
// Both directions have been observed to fail: at +-0.4 dB per dial, 98 of
// 6000 degraded channels crossed the threshold, and 877 of 6000 failing
// channels cleared it for part of each hour.
func TestOpticalBandContractsHoldAcrossSeeds(t *testing.T) {
	const seeds = 3000
	threshold := osnrThresholdDB()

	for _, tier := range []OpticalScenario{OpticalClean, OpticalTypical, OpticalDegraded, OpticalFailing} {
		band := opticalBandFor(tier)
		wantAbove := tier == OpticalFailing
		for seed := int64(0); seed < seeds; seed++ {
			oc := newOpticalCycler(t, seed, band)
			for slot, name := range oc.names {
				// A full dial period covers every phase, so the extremes of
				// this channel's excursion are necessarily inside it.
				above := oc.aboveThresholdSeconds(slot, opticalDialPeriodSec)
				lo := oc.osnrMean[slot] - oc.osnrAmp[slot]
				hi := oc.osnrMean[slot] + oc.osnrAmp[slot]
				if wantAbove && above < opticalDialPeriodSec {
					t.Fatalf("failing seed=%d %s: cleared the FEC threshold for %.0fs of the period "+
						"(OSNR peaks at %.2f, threshold %.2f) — the tier must be persistently service-affecting",
						seed, name, opticalDialPeriodSec-above, hi, threshold)
				}
				if !wantAbove && above > 0 {
					t.Fatalf("%s seed=%d %s: spent %.0fs above the FEC threshold "+
						"(OSNR dips to %.2f, threshold %.2f) — only failing may accrue blocks",
						tier, seed, name, above, lo, threshold)
				}
			}
		}
	}
}

// TestOpticalTierMeansDoNotOverlap pins the other half of the jitter
// budget: the per-channel spread must stay narrower than the gaps between
// tiers, so a `degraded` channel can never report a better OSNR mean than
// a `typical` one elsewhere in the same fleet. (Instantaneous values may
// still interleave — that is the sine amplitude doing its job.)
func TestOpticalTierMeansDoNotOverlap(t *testing.T) {
	const seeds = 500
	tiers := []OpticalScenario{OpticalClean, OpticalTypical, OpticalDegraded, OpticalFailing}

	type span struct{ lo, hi float64 }
	spans := make([]span, len(tiers))
	for i, tier := range tiers {
		s := span{lo: math.Inf(1), hi: math.Inf(-1)}
		for seed := int64(0); seed < seeds; seed++ {
			oc := newOpticalCycler(t, seed, opticalBandFor(tier))
			for slot := range oc.names {
				s.lo = math.Min(s.lo, oc.osnrMean[slot])
				s.hi = math.Max(s.hi, oc.osnrMean[slot])
			}
		}
		spans[i] = s
	}
	for i := 1; i < len(tiers); i++ {
		if spans[i].hi >= spans[i-1].lo {
			t.Errorf("%s OSNR means reach %.2f, overlapping %s which dips to %.2f — "+
				"tier gaps must exceed the +-%.1f dB mean jitter envelope",
				tiers[i], spans[i].hi, tiers[i-1], spans[i-1].lo, 2*opticalMeanJitterDB)
		}
	}
}

// TestOpticalScenarioSeedCollapseGuard is the trap this field walks into.
// web.go nils the whole ExportSeed when no export block is supplied and
// every scenario field is at its clean default — so a request carrying
// ONLY optical_scenario would be silently discarded and the device would
// come up clean. The guard's own comment exists because this already bit
// the two interface scenario fields.
func TestOpticalScenarioSeedCollapseGuard(t *testing.T) {
	// Mirrors the condition in createDevicesHandler.
	collapses := func(seed *ExportSeed) bool {
		return seed.Flow == nil && seed.Traps == nil && seed.Syslog == nil && seed.GnmiDialout == nil &&
			seed.IfErrorScenario == IfErrorClean && seed.IfFlapScenario == IfFlapClean &&
			seed.OpticalScenario == OpticalClean
	}

	if !collapses(&ExportSeed{IfErrorScenario: IfErrorClean, IfFlapScenario: IfFlapClean, OpticalScenario: OpticalClean}) {
		t.Error("an all-clean seed with no export block should collapse to nil")
	}
	for _, tier := range []OpticalScenario{OpticalTypical, OpticalDegraded, OpticalFailing} {
		seed := &ExportSeed{IfErrorScenario: IfErrorClean, IfFlapScenario: IfFlapClean, OpticalScenario: tier}
		if collapses(seed) {
			t.Errorf("a seed carrying only optical_scenario=%s collapsed to nil; the field would be "+
				"silently discarded and the device would come up clean", tier)
		}
	}
}

// TestOpticalScenarioSeedApplies covers the seed -> device copy, and the
// REST opt-in contract: a request that omits the field yields clean even
// when the auto-start seed says otherwise.
func TestOpticalScenarioSeedApplies(t *testing.T) {
	dev := &DeviceSimulator{}
	applyExportSeed(dev, &ExportSeed{OpticalScenario: OpticalFailing})
	if dev.OpticalScenario != string(OpticalFailing) {
		t.Errorf("seed did not reach the device: got %q", dev.OpticalScenario)
	}

	// An empty seed field must not overwrite a device value.
	dev2 := &DeviceSimulator{OpticalScenario: string(OpticalDegraded)}
	applyExportSeed(dev2, &ExportSeed{})
	if dev2.OpticalScenario != string(OpticalDegraded) {
		t.Errorf("empty seed overwrote the device value: got %q", dev2.OpticalScenario)
	}

	// The REST contract: omitting the field parses to clean regardless of
	// what any seed elsewhere is set to.
	got, err := ParseOpticalScenario("")
	if err != nil || got != OpticalClean {
		t.Errorf("omitted optical_scenario = %q (%v), want clean", got, err)
	}
}

// TestOpticalScenarioCanonicalisedForDeviceInfo checks the value surfaced
// on GET /api/v1/devices is the canonical lowercase form, and that clean
// is omitted like the two interface scenarios.
func TestOpticalScenarioCanonicalisedForDeviceInfo(t *testing.T) {
	canon, err := ParseOpticalScenario("FAILING")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(canon) != "failing" {
		t.Errorf("canonical form = %q, want %q", canon, "failing")
	}
	// Mirrors the omit-when-clean condition in ListDevices.
	for _, tc := range []struct {
		val  string
		emit bool
	}{{"", false}, {"clean", false}, {"typical", true}, {"failing", true}} {
		emit := tc.val != "" && tc.val != string(OpticalClean)
		if emit != tc.emit {
			t.Errorf("optical_scenario %q: emit=%v, want %v", tc.val, emit, tc.emit)
		}
	}
}

// TestOpticalScenarioWiredInBothCreatePaths guards the divergence that
// has bitten this repo: the scenario must be canonicalised and the band
// applied in both the sequential and parallel creation paths.
func TestOpticalScenarioWiredInBothCreatePaths(t *testing.T) {
	src := readSourceFile(t, "device.go")
	if n := strings.Count(src, "opticalBandFor("); n != 2 {
		t.Errorf("device.go uses opticalBandFor %d time(s), want 2 (sequential + parallel paths)", n)
	}
	if n := strings.Count(src, "ParseOpticalScenario("); n != 2 {
		t.Errorf("device.go canonicalises the scenario %d time(s), want 2; a path that skips it "+
			"leaves a non-canonical value in GET /api/v1/devices", n)
	}
}
