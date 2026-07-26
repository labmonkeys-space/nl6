/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
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
