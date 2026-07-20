/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// fidelity_test.go — -fidelity keeps the fleet silent outside a scenario
// window: autonomous background + state-driven push is muted for devices with
// no active scenario gate, explicit on-demand fires still go through, and a
// running scenario's traffic (the participant path) is unaffected.

func TestFidelityMutesBackground_SourceMatrix(t *testing.T) {
	restore := fidelitySilent.Load()
	t.Cleanup(func() { fidelitySilent.Store(restore) })

	fidelitySilent.Store(false)
	for _, s := range []fireSource{sourceBackground, sourceStateDriven, sourceOnDemand, sourceScenario} {
		if fidelityMutesBackground(s) {
			t.Errorf("fidelity off: source %d must not be muted", s)
		}
	}

	fidelitySilent.Store(true)
	if !fidelityMutesBackground(sourceBackground) || !fidelityMutesBackground(sourceStateDriven) {
		t.Error("fidelity on: background + state-driven must be muted")
	}
	if fidelityMutesBackground(sourceOnDemand) {
		t.Error("fidelity on: on-demand must NOT be muted (explicit operator action)")
	}
	if fidelityMutesBackground(sourceScenario) {
		t.Error("fidelity on: scenario source must NOT be muted here (participant path handles it)")
	}
}

// TestFidelity_SilencesNonParticipant: with no scenario gate (scenPart nil),
// fidelity mutes a device's autonomous background + state-driven syslog while
// still delivering an explicit on-demand fire.
func TestFidelity_SilencesNonParticipant(t *testing.T) {
	restore := fidelitySilent.Load()
	t.Cleanup(func() { fidelitySilent.Store(restore) })

	var writes atomic.Uint64
	exp := newSinkExporter(t, net.IPv4(10, 42, 0, 7), func(_ []byte) error {
		writes.Add(1)
		return nil
	})
	// scenPart stays nil — this device is not part of any scenario.
	entry := mustEntry(t)

	// Fidelity OFF: background reaches the wire (legacy behavior).
	fidelitySilent.Store(false)
	_ = exp.fireBackground(entry, nil)
	if writes.Load() != 1 {
		t.Fatalf("fidelity off: background writes=%d, want 1", writes.Load())
	}

	// Fidelity ON: background + state-driven muted; count must not move.
	fidelitySilent.Store(true)
	_ = exp.fireBackground(entry, nil)
	_ = exp.FireForInterface(entry, 3) // state-driven
	if got := writes.Load(); got != 1 {
		t.Fatalf("fidelity on: background/state writes=%d, want still 1 (muted)", got)
	}

	// On-demand is an explicit action — it still fires.
	_ = exp.Fire(entry, nil)
	if got := writes.Load(); got != 2 {
		t.Fatalf("fidelity on: on-demand write not delivered (writes=%d, want 2)", got)
	}
}

// TestFidelity_ScenarioStillEmits: fidelity mode must not touch the scenario
// itself — a participant still emits its window traffic while the rest of the
// fleet is silent.
func TestFidelity_ScenarioStillEmits(t *testing.T) {
	restore := fidelitySilent.Load()
	t.Cleanup(func() { fidelitySilent.Store(restore) })
	fidelitySilent.Store(true) // fleet silent...

	synctest.Test(t, func(t *testing.T) {
		sm, _ := scenarioTestManager(t, 1)
		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: []string{"10.42.0.1"}, Protocol: "syslog",
			Rate: 20, Window: 2 * time.Second, Drain: 200 * time.Millisecond, Seed: 42,
		}
		if err := c.Submit(spec, "s-000001"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(spec.Window + spec.drainOrDefault() + 100*time.Millisecond)
		synctest.Wait()

		res := c.Result()
		if res == nil {
			t.Fatal("scenario did not finalize")
		}
		var sent uint64
		for _, s := range res.PerDevice {
			sent += s.InWindow + s.Drain
		}
		if sent == 0 {
			t.Fatal("scenario emitted nothing under fidelity — the participant path must be unaffected")
		}
	})
}
