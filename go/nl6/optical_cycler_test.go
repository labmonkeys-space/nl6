/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

// twoChannelInventory is the shipped Waveserver shape: two WL5e modems.
func twoChannelInventory() *DeviceResources {
	return &DeviceResources{Optical: []OpticalChannel{
		{Name: "OCH-1-2", LinePort: "1-2", FrequencyMHz: 193150000, OperationalMode: 1, TargetOutputPowerDBm: 1.0},
		{Name: "OCH-1-1", LinePort: "1-1", FrequencyMHz: 193100000, OperationalMode: 1, TargetOutputPowerDBm: 1.0},
	}}
}

func newOpticalCycler(t *testing.T, seed int64, band opticalBand) *OpticalCycler {
	t.Helper()
	mc := &MetricsCycler{}
	mc.InitOpticalCycler(twoChannelInventory(), seed, band)
	oc := mc.OpticalCyclerOf()
	if oc == nil {
		t.Fatal("InitOpticalCycler published no engine")
	}
	return oc
}

func decOf(t *testing.T, oc *OpticalCycler, component, leaf string, at float64) float64 {
	t.Helper()
	v, ok := oc.GetDynamicAt(component, leaf, at)
	if !ok {
		t.Fatalf("GetDynamicAt(%s, %s) not resolved", component, leaf)
	}
	d, isDec := v.(gnmiDecimal)
	if !isDec {
		t.Fatalf("GetDynamicAt(%s, %s) = %T, want gnmiDecimal", component, leaf, v)
	}
	return d.val
}

// TestOpticalComponentsSortedAndKeyed pins the ordering contract a
// wildcard gNMI subscription depends on. The fixture is deliberately
// supplied out of order.
func TestOpticalComponentsSortedAndKeyed(t *testing.T) {
	oc := newOpticalCycler(t, 42, defaultOpticalBand)
	got := oc.Components()
	if len(got) != 2 || got[0] != "OCH-1-1" || got[1] != "OCH-1-2" {
		t.Fatalf("Components() = %v, want sorted [OCH-1-1 OCH-1-2]", got)
	}
	if _, ok := oc.GetDynamicAt("OCH-9-9", OpticalLeafFrequency, 0); ok {
		t.Error("unknown component resolved; callers rely on this to return NotFound")
	}
	if _, ok := oc.GetDynamicAt("OCH-1-1", "no-such-leaf/instant", 0); ok {
		t.Error("unknown leaf resolved")
	}
	if _, ok := oc.GetDynamicAt("OCH-1-1", OpticalLeafOSNR+"/median", 0); ok {
		t.Error("unknown statistic resolved")
	}
}

// TestOpticalDeterminismAtEqualOffsets asserts the reproducibility the
// engine actually offers: identical values at equal ELAPSED offsets from
// each engine's own startTime, across independently built engines. Equal
// absolute timestamps is a different (and unsatisfiable) claim, since the
// engine is start-time-relative.
func TestOpticalDeterminismAtEqualOffsets(t *testing.T) {
	a := newOpticalCycler(t, 1234, defaultOpticalBand)
	b := newOpticalCycler(t, 1234, defaultOpticalBand)

	leaves := []string{
		OpticalLeafInputPower + "/instant", OpticalLeafOSNR + "/instant",
		OpticalLeafQValue + "/instant", OpticalLeafPreFECBER + "/instant",
		OpticalLeafOutputPower + "/avg", OpticalLeafLaserBias + "/max",
		OpticalLeafChromaticDisp + "/min", OpticalLeafPDL + "/instant",
	}
	for _, off := range []float64{0, 137.5, 1800, 3599.9, 86400} {
		for _, comp := range a.Components() {
			for _, leaf := range leaves {
				va := decOf(t, a, comp, leaf, off)
				vb := decOf(t, b, comp, leaf, off)
				if va != vb {
					t.Fatalf("%s %s at offset %v: %v != %v (engines must agree at equal offsets)",
						comp, leaf, off, va, vb)
				}
			}
			if x, y := mustU64(t, a, comp, off), mustU64(t, b, comp, off); x != y {
				t.Fatalf("%s uncorrectable blocks at %v: %d != %d", comp, off, x, y)
			}
		}
	}

	// A different seed must actually change the jitter, or the seed is
	// doing nothing.
	c := newOpticalCycler(t, 99, defaultOpticalBand)
	if decOf(t, a, "OCH-1-1", OpticalLeafInputPower+"/instant", 500) ==
		decOf(t, c, "OCH-1-1", OpticalLeafInputPower+"/instant", 500) {
		t.Error("different seeds produced identical values; per-device jitter is not seeded")
	}
}

func mustU64(t *testing.T, oc *OpticalCycler, component string, at float64) uint64 {
	t.Helper()
	v, ok := oc.GetDynamicAt(component, OpticalLeafUncorrBlock, at)
	if !ok {
		t.Fatalf("uncorrectable blocks not resolved for %s", component)
	}
	u, isU := v.(uint64)
	if !isU {
		t.Fatalf("uncorrectable blocks = %T, want uint64 (bare counter leaf, no stats container)", v)
	}
	return u
}

// TestOpticalStatsInvariant checks min <= instant <= max, with avg
// inside, across a long sweep. The engine derives all four from the same
// dial functions specifically so this holds by construction.
func TestOpticalStatsInvariant(t *testing.T) {
	oc := newOpticalCycler(t, 7, defaultOpticalBand)
	for _, leaf := range []string{
		OpticalLeafInputPower, OpticalLeafOSNR, OpticalLeafESNR, OpticalLeafQValue,
		OpticalLeafPreFECBER, OpticalLeafOutputPower, OpticalLeafLaserBias,
		OpticalLeafChromaticDisp, OpticalLeafPMD, OpticalLeafPDL,
	} {
		for off := 0.0; off <= 7200; off += 173 {
			inst := decOf(t, oc, "OCH-1-1", leaf+"/instant", off)
			avg := decOf(t, oc, "OCH-1-1", leaf+"/avg", off)
			lo := decOf(t, oc, "OCH-1-1", leaf+"/min", off)
			hi := decOf(t, oc, "OCH-1-1", leaf+"/max", off)
			if !(lo <= inst && inst <= hi) {
				t.Fatalf("%s at %v: min<=instant<=max violated (%v, %v, %v)", leaf, off, lo, inst, hi)
			}
			if !(lo <= avg && avg <= hi) {
				t.Fatalf("%s at %v: avg outside [min,max] (%v, %v, %v)", leaf, off, lo, avg, hi)
			}
		}
	}
}

// TestPreFecBerMonotonicNotACliff pins the corrected physics claim. At
// the SD-FEC threshold the erfc tail is shallow: BER must move
// monotonically in OSNR, but NOT by an order of magnitude across a 2 dB
// span there. The decade-scale behaviour lives well above the threshold.
func TestPreFecBerMonotonicNotACliff(t *testing.T) {
	prev := math.Inf(1)
	for osnr := 20.0; osnr >= 10.0; osnr -= 0.25 {
		ber := berFromQDB(clampFloat(osnr-opticalQOffsetDB, opticalQFloorDB, opticalQCeilDB))
		if ber < prev && prev != math.Inf(1) {
			t.Fatalf("BER decreased as OSNR fell (osnr=%v): must be monotonically increasing", osnr)
		}
		prev = ber
	}

	// Near the threshold: a modest factor, not a decade.
	thr := osnrThresholdDB()
	hi := berFromQDB(thr + 1 - opticalQOffsetDB)
	lo := berFromQDB(thr - 1 - opticalQOffsetDB)
	ratio := lo / hi
	if ratio > 6 {
		t.Errorf("BER moved %.1fx across +-1 dB at the FEC threshold; the erfc tail is shallow "+
			"there (~3x), so a decade-scale assertion would be wrong physics", ratio)
	}
	if ratio < 1.5 {
		t.Errorf("BER moved only %.2fx across +-1 dB at the threshold; expected roughly 3x", ratio)
	}

	// Well above the threshold the same 2 dB span IS decade-scale.
	steep := berFromQDB(11) / berFromQDB(13)
	if steep < 10 {
		t.Errorf("BER moved only %.1fx across Q 11->13 dB; expected order-of-magnitude behaviour "+
			"in the low-BER region", steep)
	}
}

// TestOpticalReceiveSagPropagates is the spine correlation: depress the
// receive dial and everything downstream must follow.
func TestOpticalReceiveSagPropagates(t *testing.T) {
	clean := newOpticalCycler(t, 3, defaultOpticalBand)
	sagged := newOpticalCycler(t, 3, opticalBand{
		pInMeanDBm:  defaultOpticalBand.pInMeanDBm - 6,
		nAseMeanDBm: defaultOpticalBand.nAseMeanDBm,
		pInAmpDB:    defaultOpticalBand.pInAmpDB,
		nAseAmpDB:   defaultOpticalBand.nAseAmpDB,
	})
	const at = 900

	if p := decOf(t, sagged, "OCH-1-1", OpticalLeafInputPower+"/instant", at); p >=
		decOf(t, clean, "OCH-1-1", OpticalLeafInputPower+"/instant", at) {
		t.Error("receive power did not fall")
	}
	for _, leaf := range []string{OpticalLeafOSNR, OpticalLeafQValue} {
		if decOf(t, sagged, "OCH-1-1", leaf+"/instant", at) >=
			decOf(t, clean, "OCH-1-1", leaf+"/instant", at) {
			t.Errorf("%s did not fall with receive power", leaf)
		}
	}
	if decOf(t, sagged, "OCH-1-1", OpticalLeafPreFECBER+"/instant", at) <=
		decOf(t, clean, "OCH-1-1", OpticalLeafPreFECBER+"/instant", at) {
		t.Error("pre-FEC BER did not rise with a receive-power sag")
	}
}

// TestOpticalOffSpineLeavesFlatUnderReceiveFault is the diagnostic that
// gives this device type its value: a span problem must be
// distinguishable from a transponder problem, which requires the
// transmit side to hold while the receive spine collapses.
func TestOpticalOffSpineLeavesFlatUnderReceiveFault(t *testing.T) {
	clean := newOpticalCycler(t, 5, defaultOpticalBand)
	faulted := newOpticalCycler(t, 5, opticalBand{
		pInMeanDBm:  defaultOpticalBand.pInMeanDBm - 12, // deep into FEC failure
		nAseMeanDBm: defaultOpticalBand.nAseMeanDBm,
		pInAmpDB:    defaultOpticalBand.pInAmpDB,
		nAseAmpDB:   defaultOpticalBand.nAseAmpDB,
	})
	const at = 1500

	// Sanity: the fault is real.
	if decOf(t, faulted, "OCH-1-1", OpticalLeafPreFECBER+"/instant", at) <= opticalSDFECThresholdBER {
		t.Fatal("test setup did not push the channel past the FEC threshold")
	}

	for _, leaf := range []string{
		OpticalLeafOutputPower, OpticalLeafLaserBias,
		OpticalLeafChromaticDisp, OpticalLeafPMD, OpticalLeafPDL,
	} {
		a := decOf(t, clean, "OCH-1-1", leaf+"/instant", at)
		b := decOf(t, faulted, "OCH-1-1", leaf+"/instant", at)
		if a != b {
			t.Errorf("off-spine leaf %s moved with the receive fault (%v -> %v); the "+
				"fibre-vs-transponder diagnosis depends on it holding", leaf, a, b)
		}
	}
	// Scalars must hold too.
	for _, leaf := range []string{OpticalLeafFrequency, OpticalLeafOperationalMode, OpticalLeafLinePort} {
		x, _ := clean.GetDynamicAt("OCH-1-1", leaf, at)
		y, _ := faulted.GetDynamicAt("OCH-1-1", leaf, at)
		if x != y {
			t.Errorf("scalar %s moved with the receive fault (%v -> %v)", leaf, x, y)
		}
	}
}

// TestOpticalQuadrantsReachable is why the engine has two independent
// dials rather than one. A single power dial makes OSNR perfectly
// correlated with power, and these two quadrants become unreachable — so
// a collector rule keyed on either could never be exercised.
func TestOpticalQuadrantsReachable(t *testing.T) {
	base := newOpticalCycler(t, 11, defaultOpticalBand)
	const at = 600
	basePwr := decOf(t, base, "OCH-1-1", OpticalLeafInputPower+"/instant", at)
	baseOsnr := decOf(t, base, "OCH-1-1", OpticalLeafOSNR+"/instant", at)

	// Attenuation downstream of the amplifiers: signal and accumulated
	// noise attenuate together, so power drops and OSNR holds.
	atten := newOpticalCycler(t, 11, opticalBand{
		pInMeanDBm:  defaultOpticalBand.pInMeanDBm - 5,
		nAseMeanDBm: defaultOpticalBand.nAseMeanDBm - 5,
		pInAmpDB:    defaultOpticalBand.pInAmpDB,
		nAseAmpDB:   defaultOpticalBand.nAseAmpDB,
	})
	if p := decOf(t, atten, "OCH-1-1", OpticalLeafInputPower+"/instant", at); p >= basePwr-4 {
		t.Errorf("attenuation quadrant: power did not fall (%v vs %v)", p, basePwr)
	}
	if o := decOf(t, atten, "OCH-1-1", OpticalLeafOSNR+"/instant", at); math.Abs(o-baseOsnr) > 0.01 {
		t.Errorf("attenuation quadrant: OSNR moved by %v dB, expected it to hold", o-baseOsnr)
	}

	// Noise accumulation / sick amplifier: OSNR falls, power holds.
	noisy := newOpticalCycler(t, 11, opticalBand{
		pInMeanDBm:  defaultOpticalBand.pInMeanDBm,
		nAseMeanDBm: defaultOpticalBand.nAseMeanDBm + 5,
		pInAmpDB:    defaultOpticalBand.pInAmpDB,
		nAseAmpDB:   defaultOpticalBand.nAseAmpDB,
	})
	if p := decOf(t, noisy, "OCH-1-1", OpticalLeafInputPower+"/instant", at); math.Abs(p-basePwr) > 0.01 {
		t.Errorf("noise quadrant: power moved by %v dB, expected it to hold", p-basePwr)
	}
	if o := decOf(t, noisy, "OCH-1-1", OpticalLeafOSNR+"/instant", at); o >= baseOsnr-4 {
		t.Errorf("noise quadrant: OSNR did not fall (%v vs %v)", o, baseOsnr)
	}
}

// TestUncorrectableBlocksMonotonicAndGated covers the counter's two
// contracts: it never decreases, and it accrues only above the FEC
// threshold.
func TestUncorrectableBlocksMonotonicAndGated(t *testing.T) {
	// A clean channel sits far above the threshold OSNR and must never accrue.
	clean := newOpticalCycler(t, 21, defaultOpticalBand)
	first := mustU64(t, clean, "OCH-1-1", 0)
	for off := 0.0; off <= 4*opticalDialPeriodSec; off += 97 {
		if got := mustU64(t, clean, "OCH-1-1", off); got != first {
			t.Fatalf("clean channel accrued uncorrectable blocks at %v (%d -> %d)", off, first, got)
		}
	}

	// A failing channel is permanently past the threshold: it must accrue,
	// and never step backwards.
	failing := newOpticalCycler(t, 21, opticalBand{
		pInMeanDBm:  defaultOpticalBand.pInMeanDBm - 12,
		nAseMeanDBm: defaultOpticalBand.nAseMeanDBm,
		pInAmpDB:    defaultOpticalBand.pInAmpDB,
		nAseAmpDB:   defaultOpticalBand.nAseAmpDB,
	})
	prev := mustU64(t, failing, "OCH-1-1", 0)
	grew := false
	for off := 0.0; off <= 3*opticalDialPeriodSec; off += 31 {
		got := mustU64(t, failing, "OCH-1-1", off)
		if got < prev {
			t.Fatalf("uncorrectable blocks decreased at %v (%d -> %d)", off, prev, got)
		}
		if got > prev {
			grew = true
		}
		prev = got
	}
	if !grew {
		t.Error("failing channel never accrued uncorrectable blocks")
	}
}

// TestAboveThresholdSecondsClosedForm checks the closed-form
// above-threshold integral against brute-force numeric integration. The
// closed form is what keeps the counter O(1) and exactly monotonic, so it
// has to actually be right.
func TestAboveThresholdSecondsClosedForm(t *testing.T) {
	// Band straddling the threshold, so the indicator genuinely toggles.
	straddle := opticalBand{
		pInMeanDBm:  defaultOpticalBand.pInMeanDBm - 5.2,
		nAseMeanDBm: defaultOpticalBand.nAseMeanDBm,
		pInAmpDB:    1.2,
		nAseAmpDB:   0.5,
	}
	oc := newOpticalCycler(t, 77, straddle)
	thr := osnrThresholdDB()

	for _, horizon := range []float64{600, 3600, 5400, 12000} {
		const steps = 240000
		dt := horizon / steps
		var brute float64
		for i := 0; i < steps; i++ {
			ti := (float64(i) + 0.5) * dt
			if oc.osnrAt(0, ti) < thr {
				brute += dt
			}
		}
		got := oc.aboveThresholdSeconds(0, horizon)
		if math.Abs(got-brute) > horizon*0.002 {
			t.Errorf("horizon %v: closed form %v, numeric %v (diff %v)", horizon, got, brute, math.Abs(got-brute))
		}
	}

	// Degenerate ends of the range must not misbehave.
	if v := oc.aboveThresholdSeconds(0, 0); v != 0 {
		t.Errorf("above-threshold time at t=0 = %v, want 0", v)
	}
}

// TestSinBelowMeasureAgainstNumeric checks the closed form against brute
// force, including NEGATIVE theta: the phase offset comes from atan2,
// whose range is (-pi, pi], so production genuinely reaches that branch
// and it must be signed correctly or the counter drifts.
func TestSinBelowMeasureAgainstNumeric(t *testing.T) {
	for _, u := range []float64{-0.9, -0.4, 0, 0.3, 0.85} {
		for _, theta := range []float64{-6.1, -math.Pi, -0.8, 0.7, math.Pi, 5, 2 * math.Pi, 9.3, 20} {
			const steps = 400000
			dt := theta / steps // negative dt when theta is negative, giving a signed measure
			var brute float64
			for i := 0; i < steps; i++ {
				if math.Sin((float64(i)+0.5)*dt) < u {
					brute += dt
				}
			}
			got := sinBelowMeasure(theta, u)
			if math.Abs(got-brute) > 0.01 {
				t.Errorf("u=%v theta=%v: got %v, numeric %v", u, theta, got, brute)
			}
		}
	}
}

// TestOpticalValueTypesAndPrecision pins the representations the pinned
// model mandates — the layer where a mismatch breaks a consumer's parser
// in production while looking fine in development.
func TestOpticalValueTypesAndPrecision(t *testing.T) {
	oc := newOpticalCycler(t, 13, defaultOpticalBand)

	// Statistics leaves: 2 fraction digits.
	for _, leaf := range []string{OpticalLeafInputPower, OpticalLeafOSNR, OpticalLeafQValue, OpticalLeafPDL} {
		v, _ := oc.GetDynamicAt("OCH-1-1", leaf+"/instant", 100)
		d := v.(gnmiDecimal)
		if d.digits != 2 {
			t.Errorf("%s digits = %d, want 2 (pinned model uses fraction-digits 2)", leaf, d.digits)
		}
		if frac := strings.SplitN(d.String(), ".", 2); len(frac) != 2 || len(frac[1]) != 2 {
			t.Errorf("%s rendered %q, want exactly 2 fraction digits", leaf, d.String())
		}
	}

	// BER: 18 fraction digits, NOT scientific notation.
	v, _ := oc.GetDynamicAt("OCH-1-1", OpticalLeafPreFECBER+"/instant", 100)
	d := v.(gnmiDecimal)
	if d.digits != 18 {
		t.Errorf("pre-FEC BER digits = %d, want 18", d.digits)
	}
	s := d.String()
	if strings.ContainsAny(s, "eE") {
		t.Errorf("pre-FEC BER rendered %q; the pinned model is decimal64, not a sci-notation string", s)
	}
	if frac := strings.SplitN(s, ".", 2); len(frac) != 2 || len(frac[1]) != 18 {
		t.Errorf("pre-FEC BER rendered %q, want exactly 18 fraction digits", s)
	}
	if parsed, err := strconv.ParseFloat(s, 64); err != nil || parsed <= 0 {
		t.Errorf("pre-FEC BER %q did not parse to a positive value (%v)", s, err)
	}

	// Scalars keep their model types.
	if fv, _ := oc.GetDynamicAt("OCH-1-1", OpticalLeafFrequency, 0); fv != uint64(193100000) {
		t.Errorf("frequency = %v (%T), want uint64 193100000", fv, fv)
	}
	if mv, _ := oc.GetDynamicAt("OCH-1-1", OpticalLeafOperationalMode, 0); mv != uint32(1) {
		t.Errorf("operational-mode = %v (%T), want uint32 1", mv, mv)
	}
	if pv, _ := oc.GetDynamicAt("OCH-1-1", OpticalLeafLinePort, 0); pv != "1-1" {
		t.Errorf("line-port = %v, want \"1-1\"", pv)
	}
}

// TestPostFecBerNotServed guards the deliberate omission: OpenConfig
// defines the leaf, but the modelled device does not report it, so
// serving it would invite a collector rule that never fires against real
// hardware.
func TestPostFecBerNotServed(t *testing.T) {
	oc := newOpticalCycler(t, 17, defaultOpticalBand)
	for _, leaf := range []string{"post-fec-ber/instant", "post-fec-ber/avg", "post-fec-ber"} {
		if _, ok := oc.GetDynamicAt("OCH-1-1", leaf, 100); ok {
			t.Errorf("%s is served; it must not be", leaf)
		}
	}
}

// TestInitOpticalCyclerSingleInit mirrors the interface cycler's guard: a
// second init would orphan readers of the published engine.
func TestInitOpticalCyclerSingleInit(t *testing.T) {
	mc := &MetricsCycler{}
	mc.InitOpticalCycler(twoChannelInventory(), 1, defaultOpticalBand)
	defer func() {
		if recover() == nil {
			t.Error("second InitOpticalCycler did not panic")
		}
	}()
	mc.InitOpticalCycler(twoChannelInventory(), 1, defaultOpticalBand)
}

// TestInitOpticalCyclerNoInventory keeps packet devices unaffected.
func TestInitOpticalCyclerNoInventory(t *testing.T) {
	mc := &MetricsCycler{}
	mc.InitOpticalCycler(&DeviceResources{}, 1, defaultOpticalBand)
	if mc.OpticalCyclerOf() != nil {
		t.Error("published an engine for a device with no optical inventory")
	}
	mc.InitOpticalCycler(nil, 1, defaultOpticalBand)
	if mc.OpticalCyclerOf() != nil {
		t.Error("published an engine for nil resources")
	}
	// Nil-receiver reads must be safe, since callers hold a possibly-nil pointer.
	var nilOC *OpticalCycler
	if _, ok := nilOC.GetDynamicAt("OCH-1-1", OpticalLeafOSNR+"/instant", 0); ok {
		t.Error("nil cycler resolved a leaf")
	}
	if nilOC.Components() != nil {
		t.Error("nil cycler returned components")
	}
}

// TestOsnrPhasorCollapseIsExact verifies the optimisation the counter's
// closed form rests on: because both dials share a period, their
// difference is exactly a single sinusoid.
func TestOsnrPhasorCollapseIsExact(t *testing.T) {
	oc := newOpticalCycler(t, 31, defaultOpticalBand)
	for slot := range oc.names {
		for _, at := range []float64{0, 12.5, 900, 1800, 2700, 3599, 7200.25} {
			direct := oc.pInAt(slot, at) - oc.nAseAt(slot, at)
			collapsed := oc.osnrAt(slot, at)
			if math.Abs(direct-collapsed) > 1e-9 {
				t.Fatalf("slot %d at %v: pIn-nAse = %v but osnrAt = %v", slot, at, direct, collapsed)
			}
		}
	}
}

// TestOpticalChannelsIndependent guards against a slot-indexing bug
// silently making both modems identical.
func TestOpticalChannelsIndependent(t *testing.T) {
	oc := newOpticalCycler(t, 55, defaultOpticalBand)
	a := decOf(t, oc, "OCH-1-1", OpticalLeafInputPower+"/instant", 450)
	b := decOf(t, oc, "OCH-1-2", OpticalLeafInputPower+"/instant", 450)
	if a == b {
		t.Error("both channels report identical receive power; per-channel jitter is not applied")
	}
	if p, _ := oc.GetDynamicAt("OCH-1-2", OpticalLeafLinePort, 0); p != "1-2" {
		t.Errorf("OCH-1-2 line-port = %v, want \"1-2\"", p)
	}
}

// TestBothCreatePathsInitOpticalCycler guards the divergence that has
// bitten this repo before: the sequential and parallel device-creation
// paths must both initialise the engine. Asserted by source inspection
// because exercising the real paths needs root and a network namespace.
func TestBothCreatePathsInitOpticalCycler(t *testing.T) {
	src, err := os.ReadFile("device.go")
	if err != nil {
		t.Fatalf("reading device.go: %v", err)
	}
	if n := strings.Count(string(src), "InitOpticalCycler("); n != 2 {
		t.Errorf("device.go calls InitOpticalCycler %d time(s), want 2 — the sequential "+
			"(CreateDevicesWithOptions) and parallel (createSingleDevice) paths must both "+
			"initialise the engine, or optical devices silently vary by batch size", n)
	}
	// The interface cycler is the reference: both paths init it too.
	if n := strings.Count(string(src), "InitIfCountersWithScenario("); n != 2 {
		t.Errorf("InitIfCountersWithScenario appears %d time(s); this test's premise assumed 2", n)
	}
}

// TestSinBelowMeasureDifferenceIsNonNegative mirrors the way
// aboveThresholdSeconds consumes the measure — as a difference between
// two thetas, where theta0 is a possibly-negative phase. The difference
// must never be negative, or elapsed above-threshold time (and so the
// block counter) would run backwards.
func TestSinBelowMeasureDifferenceIsNonNegative(t *testing.T) {
	for _, u := range []float64{-0.95, -0.3, 0, 0.5, 0.99} {
		for _, phase := range []float64{-3.1, -1.2, 0, 0.4, 2.9} {
			prev := 0.0
			for _, dTheta := range []float64{0, 0.1, 1, 3, 7, 12, 40} {
				got := sinBelowMeasure(phase+dTheta, u) - sinBelowMeasure(phase, u)
				if got < -1e-9 {
					t.Fatalf("u=%v phase=%v dTheta=%v: measure difference %v is negative", u, phase, dTheta, got)
				}
				if got < prev-1e-9 {
					t.Fatalf("u=%v phase=%v: measure decreased as the interval grew (%v -> %v)", u, phase, prev, got)
				}
				if got > dTheta+1e-9 {
					t.Fatalf("u=%v phase=%v dTheta=%v: measure %v exceeds the interval length", u, phase, dTheta, got)
				}
				prev = got
			}
		}
	}
}
