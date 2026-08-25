/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestFlowPacing_OverrideIsPerExporter is the guard for design D2's hazard, and
// the single most likely way to get this change wrong.
//
// GetFlowProfile returns a SHARED package-level pointer, and every exporter of
// a device type stores that same pointer. The natural implementation of "pace
// this device" is `fe.profile.ConcurrentFlows = n`, which compiles, reads
// correctly, and silently resizes the cache of every device of that type in the
// fleet — including devices the scenario never armed, and past the end of the
// run. That would corrupt the fleet-silence property a measurement window
// depends on.
func TestFlowPacing_OverrideIsPerExporter(t *testing.T) {
	profile := flowProfileEdgeRouter
	original := profile.ConcurrentFlows

	participant := newTestFlowExporter(testDevice("10.0.0.1"), profile, 30*time.Second, 15*time.Second, time.Minute)
	bystander := newTestFlowExporter(testDevice("10.0.0.2"), profile, 30*time.Second, 15*time.Second, time.Minute)

	// Same pointer, as production has it — the precondition that makes the
	// hazard real rather than theoretical.
	if participant.profile != bystander.profile {
		t.Fatal("precondition: both exporters must share one profile pointer")
	}

	participant.setConcurrentOverride(16)

	if got := participant.targetFlows(); got != 16 {
		t.Errorf("participant target = %d, want the override 16", got)
	}
	if got := bystander.targetFlows(); got != original {
		t.Errorf("BYSTANDER target = %d, want its profile's %d — pacing one device changed another", got, original)
	}
	if profile.ConcurrentFlows != original {
		t.Fatalf("the SHARED profile was mutated (%d, was %d) — this leaks to every device of this type, fleet-wide",
			profile.ConcurrentFlows, original)
	}
}

// TestFlowPacing_OverrideClears pins that clearing returns the exporter to its
// profile. Every path that ends participation must reach this; an override that
// outlives its scenario leaves a device emitting at a rate nothing asked for.
func TestFlowPacing_OverrideClears(t *testing.T) {
	profile := flowProfileEdgeRouter
	fe := newTestFlowExporter(testDevice("10.0.0.3"), profile, 30*time.Second, 15*time.Second, time.Minute)

	fe.setConcurrentOverride(16)
	if fe.targetFlows() != 16 {
		t.Fatal("override did not take")
	}
	fe.setConcurrentOverride(0)
	if got := fe.targetFlows(); got != profile.ConcurrentFlows {
		t.Errorf("after clearing, target = %d, want the profile's %d", got, profile.ConcurrentFlows)
	}
}

// (TestFlowPacing_OverrideChangesEmission was removed. Its comment claimed it
// "proves the override actually reaches the emission path", but it never called
// setConcurrentOverride, targetFlows() or Tick — it varied ConcurrentFlows on a
// profile copy and observed that GenerateFlows honours its target argument.
// Reviewers proved the gap by disconnecting the override from Tick and getting a
// fully green suite. TestFlowPacing_TickAchievesRateFromWarmCache replaces it and
// drives the real path.)

// TestFlowPacing_AchievesRequestedRate is the point of the change. It measures
// what the engine emits when paced, rather than re-deriving the arithmetic that
// chose the cache size — that would only prove the formula equals itself.
//
// Tolerance is DERIVED, not picked: `0.04 + 0.5/target`.
//
// The cache is an integer count of flows, so rounding alone costs up to half a
// flow out of `target` — 8.3% at target 6, 0.5% at target 95. A flat band wide
// enough for the small caches is far too slack for the large ones, and it was:
// the previous flat 8% let a 4% model error pass unnoticed at target 95 while
// leaving the smallest case sitting exactly on the edge. The 0.04 term is the
// model band the quantisation does not explain, and that is the part a
// regression would move. About a quarter of it is already spoken for on the
// campus-switch profile: symmetric jitter on a deadline is not symmetric in
// min(deadline, duration+inactive), and that concavity costs it 1.18 % of mean
// lifetime (0.05-0.57 % on the others).
func TestFlowPacing_AchievesRequestedRate(t *testing.T) {
	const active, inactive, tick = 30 * time.Second, 15 * time.Second, 5 * time.Second

	for _, tc := range []struct {
		name    string
		profile *FlowProfile
		rate    float64
	}{
		{"edge/1.0", flowProfileEdgeRouter, 1.0},
		{"edge/3.0", flowProfileEdgeRouter, 3.0},
		{"edge/0.5", flowProfileEdgeRouter, 0.5},
		{"gpu/0.2", flowProfileGPUServer, 0.2},
		{"campus/2.0", flowProfileCampusSwitch, 2.0},
		{"storage/1.0", flowProfileStorage, 1.0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fe := newTestFlowExporter(testDevice("10.0.0.9"), tc.profile, active, inactive, time.Hour)
			target := flowPacingTarget(fe, tc.rate, tick)
			if target < 1 {
				t.Fatalf("pacing target %d for rate %v", target, tc.rate)
			}

			// Copy, never mutate the shared profile (design D2).
			paced := *tc.profile
			paced.ConcurrentFlows = target
			perTick := expiryProbe(t, &paced, tick, active, inactive, 3000*time.Second)

			settle := len(perTick) / 4
			total := 0
			for _, n := range perTick[settle:] {
				total += n
			}
			window := float64(len(perTick)-settle) * tick.Seconds()
			achieved := float64(total) / window

			deviation := achieved/tc.rate - 1
			tolerance := 0.04 + 0.5/float64(target)
			if deviation < -tolerance || deviation > tolerance {
				t.Errorf("requested %.2f rec/s, achieved %.2f (%+.1f%%, tolerance %.1f%%) with cache target %d",
					tc.rate, achieved, deviation*100, tolerance*100, target)
			}
			t.Logf("requested %.2f  achieved %.2f  (%+.1f%%, tol %.1f%%)  cache=%d",
				tc.rate, achieved, deviation*100, tolerance*100, target)
		})
	}
}

// TestFlowPacing_LowRateFloorsAtOne: a rate small enough that
// rate x lifetime rounds below one flow must still emit. Silencing a device is
// not what "a low rate" means, and a silent participant would reconcile as loss.
func TestFlowPacing_LowRateFloorsAtOne(t *testing.T) {
	const tick = 5 * time.Second
	fe := newTestFlowExporter(testDevice("10.0.0.10"), flowProfileEdgeRouter, 30*time.Second, 15*time.Second, time.Hour)
	if got := flowPacingTarget(fe, 0.001, tick); got < 1 {
		t.Errorf("target = %d for a very low rate; it must floor at 1, not silence the device", got)
	}
}

// TestFlowPacing_NoRateNoOverride: a scenario without a rate must leave the
// device on its profile, not pace it to zero.
func TestFlowPacing_NoRateNoOverride(t *testing.T) {
	const tick = 5 * time.Second
	fe := newTestFlowExporter(testDevice("10.0.0.11"), flowProfileEdgeRouter, 30*time.Second, 15*time.Second, time.Hour)
	for _, r := range []float64{0, -1} {
		if got := flowPacingTarget(fe, r, tick); got != 0 {
			t.Errorf("rate %v produced target %d, want 0 (meaning: keep the profile)", r, got)
		}
	}
}

// TestFlowPacing_LifecycleThroughInstallAndDetach closes the gap the other
// tests leave: they exercise the accessor, not the paths that install and clear
// it during a run. Removing the clear from detachScenPart compiles and passes
// everything else, which is precisely how an override outlives its scenario and
// leaves a device emitting at a rate nothing asked for.
func TestFlowPacing_LifecycleThroughInstallAndDetach(t *testing.T) {
	profile := flowProfileEdgeRouter
	dev := testDevice("10.42.0.1")
	dev.flowExporter = newTestFlowExporter(dev, profile, 30*time.Second, 15*time.Second, time.Hour)
	dev.flowExporter.protocol = "netflow9"

	c := newScenarioController(&SimulatorManager{}, nil)
	c.id = "s-000001"
	c.spec = &Scenario{Protocol: "netflow9", Rate: 2.0}

	part := &scenarioPart{owner: c.id}
	ok, reason, _ := c.installScenPart(dev, part)
	if !ok {
		t.Fatalf("installScenPart refused: %s", reason)
	}

	want := flowPacingTarget(dev.flowExporter, 2.0,
		scenarioFlowTickInterval(c.sm.effectiveFlowTickInterval(), c.spec.Window))
	if got := dev.flowExporter.targetFlows(); got != want {
		t.Fatalf("after arm, target = %d, want the paced %d", got, want)
	}
	if got := dev.flowExporter.targetFlows(); got == profile.ConcurrentFlows {
		t.Fatalf("pacing did not change the target away from the profile default (%d)", got)
	}

	c.detachScenPart(dev)

	if got := dev.flowExporter.targetFlows(); got != profile.ConcurrentFlows {
		t.Errorf("after detach, target = %d, want the profile's %d — the override outlived the run",
			got, profile.ConcurrentFlows)
	}
}

// TestFlowPacing_LosingClaimDoesNotPace guards the ordering inside
// installScenPart: the override is installed only AFTER a successful claim.
//
// Under per-device overlap two scenarios can target the same device, and one
// loses. A loser that paced first would resize the WINNER's device — changing
// the rate of a run it has nothing to do with, and leaving it changed. The
// code comment asserts this ordering; without this test, reversing it passes
// every other check.
func TestFlowPacing_LosingClaimDoesNotPace(t *testing.T) {
	profile := flowProfileEdgeRouter
	dev := testDevice("10.42.0.2")
	dev.flowExporter = newTestFlowExporter(dev, profile, 30*time.Second, 15*time.Second, time.Hour)
	dev.flowExporter.protocol = "netflow9"

	winner := newScenarioController(&SimulatorManager{}, nil)
	winner.id = "s-winner"
	winner.spec = &Scenario{Protocol: "netflow9", Rate: 2.0}
	if ok, reason, _ := winner.installScenPart(dev, &scenarioPart{owner: winner.id}); !ok {
		t.Fatalf("winner could not arm: %s", reason)
	}
	wantWinner := flowPacingTarget(dev.flowExporter, 2.0,
		scenarioFlowTickInterval(winner.sm.effectiveFlowTickInterval(), winner.spec.Window))

	// A second scenario wants the same device at a very different rate.
	loser := newScenarioController(&SimulatorManager{}, nil)
	loser.id = "s-loser"
	loser.spec = &Scenario{Protocol: "netflow9", Rate: 8.0}
	ok, _, _ := loser.installScenPart(dev, &scenarioPart{owner: loser.id})
	if ok {
		t.Fatal("precondition: the second claim on a held device must fail")
	}

	if got := dev.flowExporter.targetFlows(); got != wantWinner {
		t.Errorf("target = %d, want the winner's %d — a losing claim repaced the winner's device",
			got, wantWinner)
	}
}

// TestFlowPacing_RefusesUnreachableRateAtArm: a rate the cache cannot sustain
// is refused with a reason, not clamped. Delivering 8.8/s against a requested
// 50/s while the report names 50 as the target is the defect this change
// exists to remove, relocated one layer up.
func TestFlowPacing_RefusesUnreachableRateAtArm(t *testing.T) {
	dev := testDevice("10.42.0.3")
	dev.flowExporter = newTestFlowExporter(dev, flowProfileEdgeRouter, 30*time.Second, 15*time.Second, time.Hour)
	dev.flowExporter.protocol = "netflow9"

	c := newScenarioController(&SimulatorManager{}, nil)
	c.id = "s-greedy"
	c.spec = &Scenario{Protocol: "netflow9", Rate: 50}

	ok, reason, hint := c.installScenPart(dev, &scenarioPart{owner: c.id})
	if ok {
		t.Fatal("a 50/s per-device flow rate was accepted; the cache cannot sustain it")
	}
	for _, want := range []string{"exceeds", "ceiling", "cache holds at most"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not mention %q", reason, want)
		}
	}
	if !strings.Contains(hint, "add participants") {
		t.Errorf("hint %q should say what the operator can change", hint)
	}
	// Refused BEFORE claiming: the device must be left exactly as found.
	if dev.flowExporter.scenPart.Load() != nil {
		t.Error("a refused arm left a participation handle installed")
	}
	if got := dev.flowExporter.targetFlows(); got != flowProfileEdgeRouter.ConcurrentFlows {
		t.Errorf("a refused arm paced the device anyway (target=%d)", got)
	}
}

// TestFlowPacing_AcceptsRateAtTheCeiling pins the boundary is inclusive, so a
// rate exactly at the ceiling is not refused by an off-by-one.
func TestFlowPacing_AcceptsRateAtTheCeiling(t *testing.T) {
	const tick = 5 * time.Second
	p := flowProfileEdgeRouter
	fe := newTestFlowExporter(testDevice("10.42.0.4"), p, 30*time.Second, 15*time.Second, time.Hour)
	ceiling := float64(p.MaxFlows) / effectiveFlowLifetime(fe, tick).Seconds()

	if _, _, ok := flowRateReachable(fe, ceiling, tick); !ok {
		t.Errorf("a rate exactly at the ceiling %.4f/s was refused", ceiling)
	}
	if _, _, ok := flowRateReachable(fe, ceiling*1.01, tick); ok {
		t.Errorf("a rate 1%% above the ceiling %.4f/s was accepted", ceiling)
	}
}

// TestScenarioValidate_RejectsRateProfileForFlowOnly: the shape refusal is
// protocol-scoped. Rejecting it globally would break syslog, which paces per
// event and can reproduce any shape.
func TestScenarioValidate_RejectsRateProfileForFlowOnly(t *testing.T) {
	profile := &RateProfileSpec{Kind: "linear", StartRate: 1, EndRate: 5}

	flow := &Scenario{Protocol: "netflow9", Rate: 2, Window: time.Minute, RateProfile: profile, Participants: []string{"10.42.0.1"}}
	err := flow.Validate()
	if err == nil {
		t.Fatal("rate_profile was accepted for a flow protocol")
	}
	for _, want := range []string{"rate_profile", "flow", "smeared"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	syslog := &Scenario{Protocol: "syslog", Rate: 2, Window: time.Minute, RateProfile: profile, Participants: []string{"10.42.0.1"}}
	if err := syslog.Validate(); err != nil {
		t.Errorf("rate_profile must still be accepted for syslog, got: %v", err)
	}
}

// TestScenarioFlowTickInterval_DoesNotDeriveFromRate is the guard for the
// coupling this change removed.
//
// The scenario flow ticker used to run at 1s/rate. That applied `rate` to
// cadence, and cadence sets batching rather than volume, so it never produced
// the requested record rate. Worse, once the cache sets volume, a rate-derived
// period would apply one number to two quantities: at 0.01/s the period is 100s
// against a ~29s flow lifetime, so the cache turns over between ticks and a slow
// steady rate emerges as bursts.
func TestScenarioFlowTickInterval_DoesNotDeriveFromRate(t *testing.T) {
	const fleet = 5 * time.Second

	// Long window: the fleet cadence governs, whatever the rate.
	if got := scenarioFlowTickInterval(fleet, time.Hour); got != fleet {
		t.Errorf("long window: cadence = %s, want the fleet's %s", got, fleet)
	}

	// Short window: divided into enough batches to report a rate at all,
	// rather than emitting once or not at all.
	if got := scenarioFlowTickInterval(fleet, 2*time.Second); got != 100*time.Millisecond {
		t.Errorf("2s window: cadence = %s, want 100ms (window/20)", got)
	}

	// Never faster than the floor, however short the window.
	if got := scenarioFlowTickInterval(fleet, 10*time.Millisecond); got != scenarioFlowTickFloor {
		t.Errorf("tiny window: cadence = %s, want the floor %s", got, scenarioFlowTickFloor)
	}

	// Never slower than the fleet, however long the window.
	if got := scenarioFlowTickInterval(fleet, 100*time.Hour); got != fleet {
		t.Errorf("huge window: cadence = %s, want the fleet's %s", got, fleet)
	}

	// A window of zero (unset) must not divide by anything.
	if got := scenarioFlowTickInterval(fleet, 0); got != fleet {
		t.Errorf("zero window: cadence = %s, want the fleet's %s", got, fleet)
	}
}

// TestScenarioMetrics_TargetRateOnlyWhenPaced: a gauge named "target" for a run
// that never pursued one is indistinguishable, in an archived scrape, from a run
// that hit it. That is the reporting half of nl6#456, and it survives for
// gnmi-dialout, whose cadence is the dial-out SAMPLE interval.
func TestScenarioMetrics_TargetRateOnlyWhenPaced(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		want     bool
	}{
		{"syslog", true},        // scenario-owned NHPP scheduler
		{"snmp-trap", true},     // scenario-owned trap scheduler
		{"netflow9", true},      // paced by cache sizing, this change
		{"ipfix", true},         // ditto
		{"gnmi-dialout", false}, // streams at its own SAMPLE interval
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			c := newScenarioController(&SimulatorManager{}, nil)
			c.spec = &Scenario{Protocol: tc.protocol, Rate: 5}
			if got := c.pacesRate(); got != tc.want {
				t.Errorf("pacesRate() = %v, want %v", got, tc.want)
			}
			// Assert on the RENDERED scrape, not just the predicate. Asserting
			// the predicate alone leaves the guard in renderScenarioMetrics
			// untested: deleting it restores the gauge for an unpaced run and
			// this test stays green.
			c.id = "s-metrics"
			rendered := string(renderScenarioMetrics(&SimulatorManager{}, c))
			if got := strings.Contains(rendered, "nl6_scenario_target_rate"); got != tc.want {
				t.Errorf("target-rate gauge present = %v, want %v, in:\n%s", got, tc.want, rendered)
			}
		})
	}
}

// TestAchievedPerDeviceRate_ExcludesDrain: drain records were produced during
// the window but written after it. Counting them against the window's own
// duration inflates the achieved rate — the same error the per-application
// block avoids by keeping drain bytes out of its rate.
func TestAchievedPerDeviceRate_ExcludesDrain(t *testing.T) {
	t0 := time.Now()
	res := &ScenarioResult{
		T0Actual: t0,
		T1Actual: t0.Add(10 * time.Second),
		PerDevice: map[string]ledgerSnapshot{
			"10.42.0.1": {InWindow: 100, Drain: 50},
			"10.42.0.2": {InWindow: 100, Drain: 50},
		},
	}
	// 200 in-window records / 10s / 2 devices = 10/s. With drain it would be 15.
	if got := achievedPerDeviceRate(res); got != 10 {
		t.Errorf("achieved = %v, want 10 (drain must not inflate the in-window rate)", got)
	}
}

// TestAchievedPerDeviceRate_Degenerate: no participants, or a zero-length
// window, must not divide by zero.
func TestAchievedPerDeviceRate_Degenerate(t *testing.T) {
	t0 := time.Now()
	for name, res := range map[string]*ScenarioResult{
		"nil":             nil,
		"no participants": {T0Actual: t0, T1Actual: t0.Add(time.Second)},
		"zero window":     {T0Actual: t0, T1Actual: t0, PerDevice: map[string]ledgerSnapshot{"a": {InWindow: 5}}},
	} {
		if got := achievedPerDeviceRate(res); got != 0 {
			t.Errorf("%s: achieved = %v, want 0", name, got)
		}
	}
}

// tickRate drives the REAL emission path — FlowExporter.Tick, the override, the
// encoder, a UDP socket — and returns records/second over the window.
//
// warm decides whether the cache is at its profile population before pacing
// starts, which is what production always looks like: the fleet ticker keeps
// every exporter full right up to T0.
func tickRate(t *testing.T, fe *FlowExporter, conn *net.UDPConn, addr *net.UDPAddr,
	pool *sync.Pool, start time.Time, tick, window time.Duration) float64 {
	t.Helper()
	var records uint64
	for el := time.Duration(0); el < window; el += tick {
		st := tickWithEncoder(fe, start.Add(el), NetFlow9Encoder{}, conn, addr, pool)
		records += st.RecordsSent
	}
	return float64(records) / window.Seconds()
}

// TestFlowPacing_TickAchievesRateFromWarmCache is the test whose absence let
// two HIGH findings through.
//
// Every other pacing test asserts on targetFlows() or drives FlowCache
// directly, so the override could be disconnected from Tick entirely and the
// whole suite stayed green — reviewers proved that by reverting
// `fe.targetFlows()` to `fe.profile.ConcurrentFlows` and getting a clean run.
//
// It also starts from a WARM cache. expiryProbe starts empty, which hid that
// pacing DOWN never converged: the cache only ever grew, so a run drained
// toward its target over a mean flow lifetime and over-delivered by up to 8.6x
// on a short window.
func TestFlowPacing_TickAchievesRateFromWarmCache(t *testing.T) {
	const active, inactive, tick = 30 * time.Second, 15 * time.Second, 5 * time.Second

	ln, _ := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	for _, rate := range []float64{0.5, 1.0, 3.0} {
		t.Run(fmt.Sprintf("rate=%.1f", rate), func(t *testing.T) {
			fe := newTestFlowExporter(testDevice("10.0.0.20"), flowProfileEdgeRouter, active, inactive, time.Hour)
			base := time.Now()

			// Warm to the profile population, as the fleet ticker would.
			warm := tickRate(t, fe, conn, addr, testPool(), base, tick, 600*time.Second)
			if warm < 3 {
				t.Fatalf("fixture: warm-up rate %.2f/s is not the profile's ~4.4/s", warm)
			}

			// Now pace it, and measure over a window a real run would use —
			// SHORT relative to the flow lifetime, which is the regime that
			// exposed the defect.
			fe.setConcurrentOverride(flowPacingTarget(fe, rate, tick))
			achieved := tickRate(t, fe, conn, addr, testPool(), base.Add(600*time.Second), tick, 60*time.Second)

			if deviation := achieved/rate - 1; deviation < -0.25 || deviation > 0.25 {
				t.Errorf("requested %.2f rec/s, achieved %.2f over a 60s window from a warm cache (%+.0f%%)",
					rate, achieved, deviation*100)
			}
		})
	}
}

// TestFlowPacing_UnreachableRateStopsTheRun exercises the REAL Arm -> Start
// path, which the previous evidence claim skipped.
//
// tasks.md 4.5 asserted the existing arm "already fails when no device can be
// armed". It does not: Arm returns nil with armed=0 and phase=armed. The run is
// still refused — by Start — and nothing was claimed, so the fleet is
// undisturbed and the excluded list carries the ceiling. That is the property
// worth pinning, and no test reached it before: the sibling test calls
// installScenPart directly.
func TestFlowPacing_UnreachableRateStopsTheRun(t *testing.T) {
	sm := &SimulatorManager{
		devices:         make(map[string]*DeviceSimulator),
		deviceIPs:       make(map[string]struct{}),
		deviceTypesByIP: make(map[string]string),
		devicesByIP:     make(map[string]*DeviceSimulator),
	}
	dev := testDevice("10.42.0.1")
	dev.flowExporter = newTestFlowExporter(dev, flowProfileEdgeRouter, 30*time.Second, 15*time.Second, time.Hour)
	dev.flowExporter.protocol = "netflow9"
	sm.devicesByIP["10.42.0.1"] = dev
	sm.devices["10.42.0.1"] = dev

	c := newScenarioController(sm, nil)
	if err := c.Submit(&Scenario{
		Participants: []string{"10.42.0.1"},
		Protocol:     "netflow9",
		Rate:         50, // far above the ~8.8/s ceiling
		Window:       time.Minute,
	}, "s-unreachable"); err != nil {
		t.Fatalf("submit: %v", err)
	}

	armed, excluded, err := c.Arm()
	if err != nil {
		t.Fatalf("arm returned an error; the documented behaviour is armed=0 with reasons: %v", err)
	}
	if armed != 0 {
		t.Fatalf("armed = %d, want 0 — a rate above the ceiling must exclude every participant", armed)
	}
	if len(excluded) != 1 {
		t.Fatalf("excluded = %d entries, want 1", len(excluded))
	}
	// The reason must reach the operator, not just the count.
	if !strings.Contains(excluded[0].Reason, "ceiling") {
		t.Errorf("excluded reason %q does not name the ceiling", excluded[0].Reason)
	}

	// Nothing claimed: the fleet is undisturbed and the device is unpaced.
	if dev.flowExporter.scenPart.Load() != nil {
		t.Error("a fully-excluded arm left a participation handle installed")
	}
	if got := dev.flowExporter.targetFlows(); got != flowProfileEdgeRouter.ConcurrentFlows {
		t.Errorf("a fully-excluded arm paced the device (target=%d)", got)
	}

	// And the run must not start.
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded with 0 armed participants; the run must be refused")
	}
}

// TestFlowJitter_DrawIsUnconditional protects design D4, which the existing
// determinism test cannot.
//
// TestScenarioAppTraffic_Determinism compares two runs of the SAME code, so a
// conditional jitter draw — one taken only for flows whose deadline it would
// actually move — reproduces itself perfectly and passes. The defect is
// invisible from inside a single build.
//
// It is visible across builds, which is what matters: a conditional draw makes
// the number of RNG calls depend on the flow, so a later change to the branch
// condition silently re-rolls every subsequent flow on that device and the
// scenario ground truth stops reconciling against captures taken before it.
//
// The probe: two caches, same seed, active timeouts far enough apart that a
// branch-dependent draw would diverge. The RECORDS are drawn before the jitter,
// so under an unconditional draw they must be identical; under a conditional
// one they desynchronise from the first flow whose branch differs.
func TestFlowJitter_DrawIsUnconditional(t *testing.T) {
	const flows = 64
	ip := net.ParseIP("10.42.0.7").To4()
	now := time.Unix(1700000000, 0)

	gen := func(active time.Duration) []string {
		fc := NewFlowCache(active, 15*time.Second, 4096)
		// Skip the warm first fill. warmStartOffset legitimately reads the
		// jittered deadline, so a warm batch differs between the two timeouts
		// by design and would mask the property under test.
		fc.warmed = true
		fc.GenerateFlows(flowProfileEdgeRouter, flows, ip, rand.New(rand.NewSource(42)), now, 0)
		// Canonical whole-record strings, not a field subset: the cache is a
		// map, so the read order is arbitrary, and ICMP records carry zero
		// ports — a (SrcPort, DstPort) key is not a total order and ties
		// resolve differently per run.
		got := make([]string, 0, flows)
		fc.mu.Lock()
		defer fc.mu.Unlock()
		for _, e := range fc.flows {
			got = append(got, fmt.Sprintf("%+v", e.record))
		}
		sort.Strings(got)
		return got
	}

	// 5s puts nearly every flow on the active branch; 5m puts nearly none.
	short, long := gen(5*time.Second), gen(5*time.Minute)
	if len(short) != len(long) {
		t.Fatalf("fixture: %d vs %d flows", len(short), len(long))
	}
	for i := range short {
		if short[i] != long[i] {
			t.Fatalf("flow %d differs between active timeouts under the same seed:\n  %s\n  %s\n"+
				"the jitter draw is branch-dependent, which desynchronises the RNG stream (design D4)",
				i, short[i], long[i])
		}
	}
}
