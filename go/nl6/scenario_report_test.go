/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"testing"
	"time"
)

// scenario_report_test.go — report-projection contract (story 2.1): every
// loss bucket is exposed flat and forms the ledger identity, while the
// disclosure counter is quarantined in a separate `informational` sub-object
// so it can never pollute the identity (FR21/FR23).

// reportFixture builds a finalized controller whose result carries the given
// per-device ledger snapshots, so the report projection can be exercised
// without running a scenario.
func reportFixture(t *testing.T, snaps map[string]ledgerSnapshot) (*SimulatorManager, *ScenarioController) {
	t.Helper()
	sm := &SimulatorManager{
		devices: map[string]*DeviceSimulator{}, deviceIPs: map[string]struct{}{},
		deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{},
	}
	for ip := range snaps {
		sm.devicesByIP[ip] = &DeviceSimulator{ID: "device-" + ip,
			syslogConfig: &DeviceSyslogConfig{Collector: "10.0.0.9:514"}}
	}
	c := newScenarioController(sm, nil)
	c.id, c.spec, c.configSHA = "s-000001", &Scenario{Protocol: "syslog", Seed: 1}, "cafef00d"
	t0 := time.Unix(1_700_000_000, 0)
	c.result = &ScenarioResult{
		ID: "s-000001", Phase: phaseStopped, T0Actual: t0, T1Actual: t0.Add(2 * time.Second),
		PerDevice: snaps,
	}
	return sm, c
}

// TestScenarioReport_InformationalSeparation (AC1/AC2): with every bucket
// live, the report exposes the five loss buckets + emitted flat (forming the
// identity), and background_suppressed ONLY inside `informational` — never as
// a sibling identity term.
func TestScenarioReport_InformationalSeparation(t *testing.T) {
	// One device with every bucket non-zero; identity: emitted = 20+3+2+4+1 = 30.
	snap := ledgerSnapshot{
		Emitted: 30, InWindow: 20, Drain: 3, SuppressedPreWindow: 2,
		SendFailures: 4, Dropped: 1, BackgroundSuppressed: 99,
	}
	sm, c := reportFixture(t, map[string]ledgerSnapshot{"10.42.0.1": snap})
	rep := buildScenarioReport(sm, c)
	if rep == nil {
		t.Fatal("nil report")
	}

	// Typed view: identity buckets flat, disclosure nested.
	row := rep.Counters[0]
	if row.InWindow != 20 || row.Drain != 3 || row.SuppressedPreWindow != 2 || row.SendFailures != 4 || row.Dropped != 1 {
		t.Fatalf("counter identity buckets wrong: %+v", row)
	}
	if row.Emitted != row.InWindow+row.Drain+row.SuppressedPreWindow+row.SendFailures+row.Dropped {
		t.Fatalf("counter identity violated: %+v", row)
	}
	if row.Informational.BackgroundSuppressed != 99 {
		t.Fatalf("informational.background_suppressed = %d, want 99", row.Informational.BackgroundSuppressed)
	}
	// Summary rolls up identically (single device → same numbers).
	s := rep.Summary
	if s.Emitted != s.InWindow+s.Drain+s.SuppressedPreWindow+s.SendFailures+s.Dropped {
		t.Fatalf("summary identity violated: %+v", s)
	}
	if s.Informational.BackgroundSuppressed != 99 {
		t.Fatalf("summary informational = %d, want 99", s.Informational.BackgroundSuppressed)
	}
	if s.Duration != "2s" {
		t.Fatalf("duration = %q, want 2s (monotonic T1-T0)", s.Duration)
	}

	// Structural view over raw JSON: background_suppressed must appear ONLY
	// under an `informational` object, never as a direct sibling of the
	// identity buckets (that separation is the whole point of FR21).
	raw, _ := json.Marshal(rep)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	summary := doc["summary"].(map[string]any)
	if _, flat := summary["background_suppressed"]; flat {
		t.Fatal("summary has a flat background_suppressed — it must live under informational")
	}
	info := summary["informational"].(map[string]any)
	if info["background_suppressed"].(float64) != 99 {
		t.Fatalf("summary.informational.background_suppressed = %v, want 99", info["background_suppressed"])
	}
	counter := doc["counters"].([]any)[0].(map[string]any)
	if _, flat := counter["background_suppressed"]; flat {
		t.Fatal("counter row has a flat background_suppressed — must live under informational")
	}
	// Every identity bucket IS a flat sibling in the row.
	for _, k := range []string{"emitted", "in_window", "drain", "suppressed_pre_window", "send_failures", "dropped"} {
		if _, ok := counter[k]; !ok {
			t.Fatalf("counter row missing flat identity bucket %q", k)
		}
	}
}

// TestScenarioReport_ExplicitZeros (AC1): a clean run with zero everywhere
// still serializes every bucket explicitly (no omitempty), so a monitor can
// diff a silent participant.
func TestScenarioReport_ExplicitZeros(t *testing.T) {
	sm, c := reportFixture(t, map[string]ledgerSnapshot{"10.42.0.1": {}})
	raw, _ := json.Marshal(buildScenarioReport(sm, c))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	counter := doc["counters"].([]any)[0].(map[string]any)
	for _, k := range []string{"emitted", "in_window", "drain", "suppressed_pre_window", "send_failures", "dropped"} {
		if v, ok := counter[k]; !ok || v.(float64) != 0 {
			t.Fatalf("counter row bucket %q = %v (present=%v), want explicit 0", k, v, ok)
		}
	}
	info := counter["informational"].(map[string]any)
	if info["background_suppressed"].(float64) != 0 {
		t.Fatalf("informational.background_suppressed = %v, want explicit 0", info["background_suppressed"])
	}
}
