/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"testing"
	"time"
)

// scenario_arm_idempotency_test.go — Arm() rebuilds its derived view instead of
// accumulating into it. `transitionLocked` permits armed→armed as legal
// idempotent re-entry, and the participant list is a set, so three counts that
// an operator reconciles against can be corrupted: the armed count, the
// excluded set, and (via a stale parts map) both after a re-arm.
//
// These are pre-existing defects surfaced by the code review of #383, where
// raising the participant ceiling from ~4,400 to 100,000 widened the achievable
// inflation by ~23x.

// TestScenarioArm_DuplicateParticipantsCountOnce pins the set semantics: the
// same device named twice is one participant. Before the fix the armed counter
// incremented per slice element while the parts map was keyed by IP, so the
// readiness response reported 2 while the report's len(PerDevice) said 1 — a
// disagreement on the exact dimension the ledger reconciles on
// (protocol, source_ip, collector).
func TestScenarioArm_DuplicateParticipantsCountOnce(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, nil)
	spec := &Scenario{
		Participants: []string{"10.42.0.1", "10.42.0.1", "10.42.0.1"},
		Protocol:     "syslog", Rate: 1, Window: time.Second, Seed: 1,
	}
	if err := c.Submit(spec, "s-000100"); err != nil {
		t.Fatal(err)
	}
	armed, excluded, err := c.Arm()
	if err != nil {
		t.Fatal(err)
	}
	if armed != 1 {
		t.Errorf("armed = %d for 3 copies of one IP, want 1", armed)
	}
	if len(excluded) != 0 {
		t.Errorf("excluded = %+v, want empty", excluded)
	}
	// The invariant that makes the count trustworthy: what Arm reports is what
	// the rest of the lifecycle sees (Start's 0/N check, the report's PerDevice).
	if armed != len(c.parts) || len(c.parts) != len(c.ledgers) {
		t.Errorf("armed=%d, parts=%d, ledgers=%d — must agree", armed, len(c.parts), len(c.ledgers))
	}
}

// TestScenarioArm_DuplicateUnknownExcludedOnce is the exclusion-side mirror:
// duplicates must not inflate participants_excluded either.
func TestScenarioArm_DuplicateUnknownExcludedOnce(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, nil)
	spec := &Scenario{
		Participants: []string{"10.42.0.99", "10.42.0.99"},
		Protocol:     "syslog", Rate: 1, Window: time.Second, Seed: 1,
	}
	if err := c.Submit(spec, "s-000101"); err != nil {
		t.Fatal(err)
	}
	armed, excluded, err := c.Arm()
	if err != nil {
		t.Fatal(err)
	}
	if armed != 0 {
		t.Errorf("armed = %d, want 0", armed)
	}
	if len(excluded) != 1 {
		t.Fatalf("excluded has %d rows for 2 copies of one unknown IP, want 1: %+v", len(excluded), excluded)
	}
}

// TestScenarioArm_ReArmDoesNotAccumulateExcluded pins the reset. c.excluded was
// append-only and never cleared, so each re-arm added another full round of
// exclusion rows — at the raised ceiling that is ~100k rows and ~14 MB of
// readiness JSON per extra arm, retained for the scenario's lifetime.
func TestScenarioArm_ReArmDoesNotAccumulateExcluded(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, nil)
	spec := &Scenario{
		Participants: []string{"10.42.0.1", "10.42.0.98", "10.42.0.99"},
		Protocol:     "syslog", Rate: 1, Window: time.Second, Seed: 1,
	}
	if err := c.Submit(spec, "s-000102"); err != nil {
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
			t.Errorf("arm #%d: excluded = %d rows, want 2 (accumulating across arms)", i, len(excluded))
		}
	}
}

// TestScenarioArm_ReArmDropsDeletedDevice is why the parts map must be reset
// and not merely overwritten: a device armed on the first pass and deleted
// before the second would otherwise linger in c.parts, and a count derived from
// that map would report a participant that no longer exists.
func TestScenarioArm_ReArmDropsDeletedDevice(t *testing.T) {
	sm, _ := scenarioTestManager(t, 2)
	c := newScenarioController(sm, nil)
	spec := &Scenario{
		Participants: []string{"10.42.0.1", "10.42.0.2"},
		Protocol:     "syslog", Rate: 1, Window: time.Second, Seed: 1,
	}
	if err := c.Submit(spec, "s-000103"); err != nil {
		t.Fatal(err)
	}
	if armed, _, err := c.Arm(); err != nil || armed != 2 {
		t.Fatalf("first arm: armed=%d err=%v, want 2 and nil", armed, err)
	}

	// Retire one device from the fleet between arms.
	dev := sm.devicesByIP["10.42.0.2"]
	if dev == nil {
		t.Fatal("fixture missing 10.42.0.2")
	}
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
}
