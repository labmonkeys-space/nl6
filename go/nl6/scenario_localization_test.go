/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

// scenario_localization_test.go — loss localization (story 5.3, FR28): the
// report additively carries per-time-sub-window in-window counts. Two proofs:
// the mechanism/identity (sub-windows sum to in_window; metadata describes the
// granularity) and time-attribution (a linear rate ramp lands more fires in
// later buckets than earlier ones).

// TestScenarioLocalization_SubWindowsSumToInWindow: the N sub-window buckets
// partition the in-window sends exactly — per participant and fleet-wide — and
// the metadata describes the granularity.
func TestScenarioLocalization_SubWindowsSumToInWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, _ := scenarioTestManager(t, 2)
		c := newScenarioController(sm, nil)
		// 2 devices × 20/s × 10 s = 400 in-window sends, evenly spread → every
		// one of the 10 one-second buckets is populated.
		spec := &Scenario{
			Participants: []string{"10.42.0.1", "10.42.0.2"},
			Protocol:     "syslog", Rate: 20, Window: 10 * time.Second, Seed: 42,
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
		time.Sleep(spec.Window + 200*time.Millisecond)
		synctest.Wait()

		rep := buildScenarioReport(sm, c)
		if rep == nil {
			t.Fatal("no report")
		}

		if rep.Summary.Metadata.SubWindowCount != scenarioSubWindowCount {
			t.Fatalf("sub_window_count = %d, want %d", rep.Summary.Metadata.SubWindowCount, scenarioSubWindowCount)
		}
		// 10s / 10 buckets = 1s each.
		if rep.Summary.Metadata.SubWindowDuration != "1s" {
			t.Fatalf("sub_window_duration = %q, want 1s", rep.Summary.Metadata.SubWindowDuration)
		}

		// Per-participant: sub-windows partition in_window exactly.
		for _, row := range rep.Counters {
			var sum uint64
			for _, n := range row.SubWindows {
				sum += n
			}
			if sum != row.InWindow {
				t.Fatalf("%s: sum(sub_windows)=%d != in_window=%d", row.SourceIP, sum, row.InWindow)
			}
		}
		// Fleet-wide: summary sub-windows partition summary in_window, and every
		// bucket is populated (dense fire schedule).
		var fleet uint64
		for i, n := range rep.Summary.SubWindows {
			if n == 0 {
				t.Fatalf("summary sub_window[%d] = 0 — a dense window should populate every bucket", i)
			}
			fleet += n
		}
		if fleet != rep.Summary.InWindow {
			t.Fatalf("sum(summary.sub_windows)=%d != summary.in_window=%d", fleet, rep.Summary.InWindow)
		}
	})
}

// TestScenarioLocalization_EarlyStopKeepsPlannedBasis: an early stop (actual
// window < planned) still reports the PLANNED bucket width — the basis fires
// were bucketed against — so an operator's per-bucket received tally aligns.
// Buckets past the stop instant are simply empty.
func TestScenarioLocalization_EarlyStopKeepsPlannedBasis(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, _ := scenarioTestManager(t, 1)
		c := newScenarioController(sm, nil)
		// Planned 10s window (→ 1s buckets); stop early at ~3s.
		spec := &Scenario{
			Participants: []string{"10.42.0.1"},
			Protocol:     "syslog", Rate: 20, Window: 10 * time.Second, Seed: 42,
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
		time.Sleep(3 * time.Second)
		if _, err := c.Stop(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()

		rep := buildScenarioReport(sm, c)
		if rep == nil {
			t.Fatal("no report")
		}
		// Bucket width reflects the PLANNED 10s window, not the ~3s actual.
		if rep.Summary.Metadata.SubWindowDuration != "1s" {
			t.Fatalf("sub_window_duration = %q, want 1s (planned basis, not actual ~3s)", rep.Summary.Metadata.SubWindowDuration)
		}
		sw := rep.Summary.SubWindows
		if sw[0] == 0 {
			t.Fatalf("first bucket empty — early fires not localized: %v", sw)
		}
		// The last bucket (planned [T0+9s,T0+10s)) is well past the ~3s stop → 0.
		if sw[scenarioSubWindowCount-1] != 0 {
			t.Fatalf("bucket past the stop instant should be empty, got %d: %v", sw[scenarioSubWindowCount-1], sw)
		}
		var sum uint64
		for _, n := range sw {
			sum += n
		}
		if sum != rep.Summary.InWindow {
			t.Fatalf("sum(sub_windows)=%d != in_window=%d", sum, rep.Summary.InWindow)
		}
	})
}

// TestScenarioLocalization_TimeAttribution: a linear rate ramp (low→high)
// attributes strictly more fires to the last bucket than the first, proving
// the sub-windows localize by actual write-return time and not by a flat
// even split.
func TestScenarioLocalization_TimeAttribution(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, _ := scenarioTestManager(t, 1)
		c := newScenarioController(sm, nil)
		// Linear 5/s → 50/s over 10s: later buckets carry many more sends.
		spec := &Scenario{
			Participants: []string{"10.42.0.1"},
			Protocol:     "syslog", Rate: 5, Window: 10 * time.Second, Seed: 7,
			RateProfile: &RateProfileSpec{
				Kind: "linear", StartRate: 5, EndRate: 50,
			},
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
		time.Sleep(spec.Window + 200*time.Millisecond)
		synctest.Wait()

		rep := buildScenarioReport(sm, c)
		if rep == nil {
			t.Fatal("no report")
		}
		sw := rep.Summary.SubWindows
		first, last := sw[0], sw[scenarioSubWindowCount-1]
		if last <= first {
			t.Fatalf("ramp not localized: first bucket=%d, last bucket=%d (want last > first)\nsub_windows=%v", first, last, sw)
		}
		// Sanity: the partition identity still holds under a rate profile.
		var sum uint64
		for _, n := range sw {
			sum += n
		}
		if sum != rep.Summary.InWindow {
			t.Fatalf("sum(sub_windows)=%d != in_window=%d", sum, rep.Summary.InWindow)
		}
	})
}
