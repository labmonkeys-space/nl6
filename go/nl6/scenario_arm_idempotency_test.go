/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"testing"
	"time"
)

// scenario_arm_idempotency_test.go — Arm() rebuilds its derived view instead of
// accumulating into it. `transitionLocked` permits armed→armed as legal
// idempotent re-entry, so a re-arm must reset the excluded set and the parts map
// while (a) detaching handles it drops and (b) carrying ledgers forward.
//
// (a) is the one that bites hardest and is asserted on the EXPORTER, not on the
// bookkeeping: an earlier version of this fix reset the parts map without
// detaching, which leaked the handle onto a live exporter and muted that device
// for the process lifetime. The map-only assertions below passed throughout —
// checking the bookkeeping instead of the resource it exists to release is
// exactly how that escaped review.

// armFixtureFlow builds a one-device manager whose flow exporter can be made to
// fail installScenPart on a later arm WITHOUT removing the exporter — the
// in-process stand-in for a gnmi-dialout participant whose streamLive() blips
// during a collector outage, which is the reachable production trigger.
func armFixtureFlow(t *testing.T, ip string) (*SimulatorManager, *DeviceSimulator, *FlowExporter) {
	t.Helper()
	dev := testDevice(ip)
	dev.ID = "device-" + ip
	dev.IP = net.ParseIP(ip).To4()
	fe := newTestFlowExporter(dev, zeroGenFlowProfile(), time.Millisecond, time.Millisecond, 10*time.Minute)
	fe.protocol = "netflow9"
	dev.flowExporter = fe
	sm := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{dev.ID: dev},
		deviceIPs:       map[string]struct{}{ip: {}},
		deviceTypesByIP: map[string]string{},
		devicesByIP:     map[string]*DeviceSimulator{ip: dev},
	}
	return sm, dev, fe
}

// TestScenarioArm_ReArmDetachesDroppedHandle is the regression for the handle
// leak. A device armed on pass 1 and excluded on pass 2 must have its handle
// nil-swapped off the exporter — otherwise the terminal gate suppresses that
// device's own background telemetry forever.
func TestScenarioArm_ReArmDetachesDroppedHandle(t *testing.T) {
	sm, _, fe := armFixtureFlow(t, "10.42.0.1")
	c := newScenarioController(sm, nil)
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "netflow9",
		Rate: 1, Window: time.Minute, Seed: 1}
	if err := c.Submit(spec, "s-000110"); err != nil {
		t.Fatal(err)
	}

	if armed, _, err := c.Arm(); err != nil || armed != 1 {
		t.Fatalf("arm#1: armed=%d err=%v, want 1 and nil", armed, err)
	}
	if fe.scenPart.Load() == nil {
		t.Fatal("arm#1 installed no handle — fixture is not exercising the install path")
	}

	// The exporter stays alive and reachable; only the install predicate flips.
	fe.protocol = "ipfix"

	armed, excluded, err := c.Arm()
	if err != nil {
		t.Fatal(err)
	}
	if armed != 0 || len(excluded) != 1 {
		t.Fatalf("arm#2: armed=%d excluded=%d, want 0 and 1", armed, len(excluded))
	}
	if got := fe.scenPart.Load(); got != nil {
		t.Fatal("dropped participant still carries a scenarioPart: the handle leaked onto a live exporter")
	}

	// And the consequence the leak caused is gone: with no handle, the device's
	// own background telemetry is ungated once the scenario ends.
	if err := c.Cancel(); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if got := fe.scenPart.Load(); got != nil {
		t.Fatal("handle still installed after Cancel — device would stay muted for the process lifetime")
	}
}

// TestScenarioArm_ReArmPreservesLedgers pins the second obligation. Counts do
// accrue while armed (background fires increment backgroundSuppressed at any
// phase; exogenous pre-T0 fires are gateSuppressCounted), they are reported
// disclosure, and they are exported as Prometheus counters — so a re-arm must
// carry the ledger forward rather than replace it.
func TestScenarioArm_ReArmPreservesLedgers(t *testing.T) {
	sm, _, _ := armFixtureFlow(t, "10.42.0.1")
	c := newScenarioController(sm, nil)
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "netflow9",
		Rate: 1, Window: time.Minute, Seed: 1}
	if err := c.Submit(spec, "s-000111"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}

	// Simulate what the gate does to an armed participant's ledger pre-T0.
	led := c.ledgers["10.42.0.1"]
	if led == nil {
		t.Fatal("no ledger after arm")
	}
	led.emitted.Add(3)
	led.suppressedPreWindow.Add(3)
	led.backgroundSuppressed.Add(2)

	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	after := c.ledgers["10.42.0.1"]
	if after == nil {
		t.Fatal("participant lost its ledger across a re-arm")
	}
	if after != led {
		t.Error("re-arm replaced the ledger entry; a reported counter would appear to reset")
	}
	if got := after.emitted.Load(); got != 3 {
		t.Errorf("emitted = %d after re-arm, want 3 (counters must stay monotonic)", got)
	}
	if got := after.suppressedPreWindow.Load(); got != 3 {
		t.Errorf("suppressed_pre_window = %d after re-arm, want 3", got)
	}
	if got := after.backgroundSuppressed.Load(); got != 2 {
		t.Errorf("background_suppressed = %d after re-arm, want 2", got)
	}
	// The live part must reference the same ledger, or subsequent fires would
	// count into an entry the report never reads.
	if c.parts["10.42.0.1"].ledger != after {
		t.Error("reinstalled part points at a different ledger than the controller holds")
	}
}

// TestScenarioArm_ReArmDoesNotAccumulateExcluded pins the reset. c.excluded was
// append-only and never cleared, so each re-arm added another full round of
// exclusion rows — at the raised participant ceiling that is ~100k rows and
// ~14 MB of readiness JSON per extra arm, retained for the scenario's lifetime.
func TestScenarioArm_ReArmDoesNotAccumulateExcluded(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, nil)
	spec := &Scenario{
		Participants: []string{"10.42.0.1", "10.42.0.98", "10.42.0.99"},
		Protocol:     "syslog", Rate: 1, Window: time.Second, Seed: 1,
	}
	if err := c.Submit(spec, "s-000112"); err != nil {
		t.Fatal(err)
	}

	armed1, excluded1, err := c.Arm()
	if err != nil {
		t.Fatal(err)
	}
	if armed1 != 1 || len(excluded1) != 2 {
		t.Fatalf("first arm: armed=%d excluded=%d, want 1 and 2", armed1, len(excluded1))
	}

	// Re-arm: same list, same fleet, so the same answer — not a doubled one.
	for i := 2; i <= 4; i++ {
		armed, excluded, err := c.Arm()
		if err != nil {
			t.Fatalf("arm #%d: %v", i, err)
		}
		if armed != 1 {
			t.Errorf("arm #%d: armed = %d, want 1", i, armed)
		}
		if len(excluded) != 2 {
			t.Errorf("arm #%d: excluded = %d rows, want 2 (rows must not accumulate across arms)", i, len(excluded))
		}
	}
	// The first arm's returned slice must not have been mutated underneath a
	// caller still serving it (why the reset allocates instead of truncating).
	if len(excluded1) != 2 {
		t.Errorf("the first arm's returned slice was mutated by a later arm: len=%d", len(excluded1))
	}
}

// TestScenarioArm_ReArmDropsDeletedDevice covers the fleet-mutation path: a
// device armed on one pass and gone on the next must leave no trace in either
// map. (DeleteDevice also nils the device's exporters, so the handle-leak vector
// asserted above is not reachable this way — hence the separate test.)
func TestScenarioArm_ReArmDropsDeletedDevice(t *testing.T) {
	sm, _ := scenarioTestManager(t, 2)
	c := newScenarioController(sm, nil)
	spec := &Scenario{
		Participants: []string{"10.42.0.1", "10.42.0.2"},
		Protocol:     "syslog", Rate: 1, Window: time.Second, Seed: 1,
	}
	if err := c.Submit(spec, "s-000113"); err != nil {
		t.Fatal(err)
	}
	if armed, _, err := c.Arm(); err != nil || armed != 2 {
		t.Fatalf("first arm: armed=%d err=%v, want 2 and nil", armed, err)
	}

	// Retire one device from the fleet between arms, the way DeleteDevice leaves
	// the maps (its exporter teardown is covered by the device tests).
	dev := sm.devicesByIP["10.42.0.2"]
	if dev == nil {
		t.Fatal("fixture missing 10.42.0.2")
	}
	dev.syslogExporter = nil
	delete(sm.devicesByIP, "10.42.0.2")
	delete(sm.devices, dev.ID)
	delete(sm.deviceIPs, "10.42.0.2")

	armed, excluded, err := c.Arm()
	if err != nil {
		t.Fatal(err)
	}
	if armed != 1 {
		t.Errorf("armed = %d after re-arm with one device deleted, want 1", armed)
	}
	if len(excluded) != 1 || excluded[0].Device != "10.42.0.2" {
		t.Fatalf("excluded = %+v, want one entry for 10.42.0.2", excluded)
	}
	if _, stale := c.parts["10.42.0.2"]; stale {
		t.Error("deleted device left a stale entry in the parts map")
	}
	if _, stale := c.ledgers["10.42.0.2"]; stale {
		t.Error("deleted device left a stale entry in the ledgers map")
	}
	// The surviving participant is still armed and still counted.
	if _, ok := c.parts["10.42.0.1"]; !ok {
		t.Error("re-arm dropped a participant that is still present")
	}
}
