/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Per-device overlap (#392, FR38). Exclusivity lives on the devices, not in a
// submit slot: disjoint scenarios run concurrently, overlapping ones are
// refused at arm, and an armed scenario holds its fleet until it runs, is
// cancelled, or is deleted.

package main

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// overlapFixture builds n syslog devices at 10.42.0.1..n plus a netflow9
// device at 10.43.0.1, so a test can run two scenarios of DIFFERENT protocols
// concurrently — the capability #392 exists for, since Scenario.Protocol is a
// single field and mixed load is otherwise inexpressible.
func overlapFixture(t *testing.T, n int) (*SimulatorManager, *FlowExporter) {
	t.Helper()
	sm, _ := scenarioTestManager(t, n)

	flowSM, fe := flowTickerFixture(t)
	dev := flowSM.devicesByIP["10.42.0.1"]
	dev.ID = "device-10.43.0.1"
	dev.IP = net.ParseIP("10.43.0.1").To4()
	sm.devices[dev.ID] = dev
	sm.deviceIPs["10.43.0.1"] = struct{}{}
	sm.devicesByIP["10.43.0.1"] = dev
	sm.flowBufPool.New = flowSM.flowBufPool.New
	return sm, fe
}

func newScenario(t *testing.T, sm *SimulatorManager, id, proto string, participants ...string) *ScenarioController {
	t.Helper()
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(&Scenario{
		Participants: participants,
		Protocol:     proto,
		Rate:         5,
		Window:       time.Minute,
	}, id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = c.Stop() })
	return c
}

// TestScenarioOverlap_DisjointRunConcurrently is the headline capability: two
// scenarios over disjoint devices, on DIFFERENT protocols, live at once. This
// is the first time the syslog scheduler and the flow cadence handoff are
// running against overlapping windows in one process.
func TestScenarioOverlap_DisjointRunConcurrently(t *testing.T) {
	sm, fe := overlapFixture(t, 2)

	syslogScen := newScenario(t, sm, "s-000001", "syslog", "10.42.0.1", "10.42.0.2")
	flowScen := newScenario(t, sm, "s-000002", "netflow9", "10.43.0.1")

	if armed, _, err := syslogScen.Arm(); err != nil || armed != 2 {
		t.Fatalf("syslog arm: armed=%d err=%v", armed, err)
	}
	if armed, _, err := flowScen.Arm(); err != nil || armed != 1 {
		t.Fatalf("flow arm while syslog is armed: armed=%d err=%v", armed, err)
	}
	if err := syslogScen.Start(context.Background()); err != nil {
		t.Fatalf("syslog start: %v", err)
	}
	if err := flowScen.Start(context.Background()); err != nil {
		t.Fatalf("flow start while syslog runs: %v", err)
	}

	// Both are genuinely live and own their own devices.
	if !fe.scenDriven.Load() {
		t.Error("flow participant is not scenario-driven")
	}
	if got := sm.devicesByIP["10.42.0.1"].syslogExporter.scenPart.Load(); got == nil || got.owner != "s-000001" {
		t.Errorf("syslog device is not held by s-000001: %+v", got)
	}
	if got := fe.scenPart.Load(); got == nil || got.owner != "s-000002" {
		t.Errorf("flow device is not held by s-000002: %+v", got)
	}

	// And each reports only its own participants.
	sRes, err := syslogScen.Stop()
	if err != nil {
		t.Fatal(err)
	}
	fRes, err := flowScen.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if len(sRes.PerDevice) != 2 {
		t.Errorf("syslog report covers %d devices, want 2", len(sRes.PerDevice))
	}
	if _, leaked := sRes.PerDevice["10.43.0.1"]; leaked {
		t.Error("syslog report includes the other scenario's device")
	}
	if len(fRes.PerDevice) != 1 {
		t.Errorf("flow report covers %d devices, want 1", len(fRes.PerDevice))
	}
}

// TestScenarioOverlap_RefusedAtArm: a device held by another scenario refuses
// the whole arm, names the holder and the contended device, and leaves both the
// holder and our own previous state untouched.
func TestScenarioOverlap_RefusedAtArm(t *testing.T) {
	sm, _ := overlapFixture(t, 3)
	holder := newScenario(t, sm, "s-000001", "syslog", "10.42.0.1", "10.42.0.2")
	if _, _, err := holder.Arm(); err != nil {
		t.Fatal(err)
	}

	// Overlaps on .2 only.
	intruder := newScenario(t, sm, "s-000002", "syslog", "10.42.0.2", "10.42.0.3")
	_, _, err := intruder.Arm()
	if err == nil {
		t.Fatal("arm over a claimed device should be refused")
	}
	for _, want := range []string{"s-000001", "10.42.0.2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal should name %q: %v", want, err)
		}
	}

	// The holder is unaffected...
	if got := sm.devicesByIP["10.42.0.2"].syslogExporter.scenPart.Load(); got == nil || got.owner != "s-000001" {
		t.Errorf("holder lost its claim to a refused arm: %+v", got)
	}
	// ...and the refused scenario claimed NOTHING, not even the free device it
	// could have taken. The refusal precedes every mutation.
	if got := sm.devicesByIP["10.42.0.3"].syslogExporter.scenPart.Load(); got != nil {
		t.Errorf("refused arm claimed a device anyway: %+v", got)
	}
	if got := intruder.Phase(); got != phaseSubmitted {
		t.Errorf("phase after refused arm = %s, want submitted", got)
	}
}

// TestScenarioOverlap_ArmedHoldsItsFleet pins the deliberate deviation from
// FR38's letter (design D3): FR38 says a RUNNING scenario claims devices, but
// the claim is taken at arm — where the handle is installed — so an armed
// scenario reserves its fleet. Cancelling releases it.
func TestScenarioOverlap_ArmedHoldsItsFleet(t *testing.T) {
	sm, _ := overlapFixture(t, 1)
	first := newScenario(t, sm, "s-000001", "syslog", "10.42.0.1")
	if _, _, err := first.Arm(); err != nil {
		t.Fatal(err)
	}
	if got := first.Phase(); got != phaseArmed {
		t.Fatalf("phase = %s, want armed (not running)", got)
	}

	second := newScenario(t, sm, "s-000002", "syslog", "10.42.0.1")
	if _, _, err := second.Arm(); err == nil {
		t.Fatal("an armed-but-not-running scenario must still hold its devices")
	}

	// Cancel is the escape hatch the deviation relies on.
	if err := first.Cancel(); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if armed, _, err := second.Arm(); err != nil || armed != 1 {
		t.Fatalf("arm after the holder cancelled: armed=%d err=%v", armed, err)
	}
}

// TestScenarioOverlap_ReArmKeepsOwnDevices: the claim must not conflict with
// itself. A re-arm replaces its own handles rather than colliding with them.
func TestScenarioOverlap_ReArmKeepsOwnDevices(t *testing.T) {
	sm, _ := overlapFixture(t, 2)
	c := newScenario(t, sm, "s-000001", "syslog", "10.42.0.1", "10.42.0.2")
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	firstPart := sm.devicesByIP["10.42.0.1"].syslogExporter.scenPart.Load()

	if armed, _, err := c.Arm(); err != nil || armed != 2 {
		t.Fatalf("re-arm: armed=%d err=%v", armed, err)
	}
	got := sm.devicesByIP["10.42.0.1"].syslogExporter.scenPart.Load()
	if got == nil || got.owner != "s-000001" {
		t.Fatalf("re-arm lost its own claim: %+v", got)
	}
	if got == firstPart {
		t.Error("re-arm reused the old handle; each arm installs a fresh part")
	}
}

// TestScenarioOverlap_StopReleasesClaims: a finished scenario's devices become
// claimable, which is what makes back-to-back runs over the same fleet work.
func TestScenarioOverlap_StopReleasesClaims(t *testing.T) {
	sm, _ := overlapFixture(t, 1)
	first := newScenario(t, sm, "s-000001", "syslog", "10.42.0.1")
	if _, _, err := first.Arm(); err != nil {
		t.Fatal(err)
	}
	if err := first.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := sm.devicesByIP["10.42.0.1"].syslogExporter.scenPart.Load(); got != nil {
		t.Fatalf("claim survived the run: %+v", got)
	}

	second := newScenario(t, sm, "s-000002", "syslog", "10.42.0.1")
	if armed, _, err := second.Arm(); err != nil || armed != 1 {
		t.Fatalf("arm after the holder finished: armed=%d err=%v", armed, err)
	}
}

// TestScenarioOverlap_ClaimPrimitives pins the CAS semantics the whole design
// rests on. Tested here rather than by staging an arm-vs-arm interleaving:
// the race window is between the pre-check and the install, which cannot be
// forced without a seam, and the primitive is what actually decides the
// outcome (same reasoning as the flow-ticker join in #440 — assert the
// contract, not the symptom).
func TestScenarioOverlap_ClaimPrimitives(t *testing.T) {
	var slot atomic.Pointer[scenarioPart]
	mine := &scenarioPart{owner: "s-000001"}
	mineAgain := &scenarioPart{owner: "s-000001"}
	theirs := &scenarioPart{owner: "s-000002"}

	if ok, holder := claimScenPart(&slot, mine); !ok || holder != "" {
		t.Fatalf("claiming a free slot: ok=%v holder=%q", ok, holder)
	}
	// mine → mine: a re-arm must re-claim its own device, with a fresh handle.
	if ok, _ := claimScenPart(&slot, mineAgain); !ok {
		t.Fatal("a scenario must be able to re-claim its own device")
	}
	if slot.Load() != mineAgain {
		t.Error("re-claim did not install the new handle")
	}
	// foreign → refused, and named.
	ok, holder := claimScenPart(&slot, theirs)
	if ok {
		t.Fatal("claimed a device held by another scenario")
	}
	if holder != "s-000001" {
		t.Errorf("holder = %q, want s-000001", holder)
	}
	if slot.Load() != mineAgain {
		t.Error("a refused claim modified the slot")
	}

	// Release is ownership-checked: the loser's teardown must not free the
	// winner's claim. This is what keeps the arm→start prune safe under
	// overlap, since it detaches devices it is dropping.
	releaseScenPart(&slot, "s-000002")
	if slot.Load() != mineAgain {
		t.Error("a foreign release cleared the owner's claim")
	}
	releaseScenPart(&slot, "s-000001")
	if slot.Load() != nil {
		t.Error("the owner could not release its own claim")
	}
	releaseScenPart(&slot, "s-000001") // idempotent on an empty slot
}

// TestScenarioOverlap_LostRaceBecomesExclusion covers the CAS fallback inside
// installScenPart, which is what a lost race reaches. The arm-time pre-check
// cannot be atomic with the install (ArmReadiness holds c.mu, and
// submit/delete take scenarioMu before c.mu, so taking it there would invert
// the lock order), so a claim landing in that window must degrade to an honest
// excluded row rather than silently stealing the device.
func TestScenarioOverlap_LostRaceBecomesExclusion(t *testing.T) {
	sm, _ := overlapFixture(t, 1)
	c := newScenario(t, sm, "s-000002", "syslog", "10.42.0.1")

	dev := sm.devicesByIP["10.42.0.1"]
	winner := &scenarioPart{owner: "s-000001"}
	dev.syslogExporter.scenPart.Store(winner)

	ok, reason, hint := c.installScenPart(dev, &scenarioPart{owner: "s-000002"})
	if ok {
		t.Fatal("install succeeded against a device held by another scenario")
	}
	for _, want := range []string{"s-000001"} {
		if !strings.Contains(reason, want) {
			t.Errorf("exclusion reason should name the holder: %q", reason)
		}
		if !strings.Contains(hint, want) {
			t.Errorf("remediation hint should name the holder: %q", hint)
		}
	}
	if dev.syslogExporter.scenPart.Load() != winner {
		t.Error("the lost race stole the device from its owner")
	}
}
