/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// scenario_cap_deferral_test.go — cap-deferral visibility (story 3.3, FR22):
// when demand exceeds the shared global cap, the report distinguishes
// `requested` (demand, at pop) from `sent` and `deferred` (throttled, NOT
// lost), and `deferred` sits outside both the ledger identity and the loss
// denominator.

// TestScenarioCapDeferral_Visibility drives an over-cap staged profile through
// a tight shared limiter and asserts the throttle is visible and distinct.
func TestScenarioCapDeferral_Visibility(t *testing.T) {
	const window = 1 * time.Second
	const capTPS = 40
	sm, ips, _ := profileManager(t, 3, window, time.Now)

	shared := rate.NewLimiter(rate.Limit(capTPS), capTPS)
	bg := NewSyslogScheduler(SyslogSchedulerOptions{
		CatalogFor: func(net.IP) *SyslogCatalog { return sm.syslogCatalog }, MeanInterval: time.Second,
		SharedLimiter: shared,
	})
	sm.syslogScheduler.Store(bg)

	c := newScenarioController(sm, nil)
	// ~900 demand (300/s × 3 devices × 1s) against a 40-tps cap.
	spec := &Scenario{
		Participants: ips, Protocol: "syslog", Rate: 100, Window: window, Drain: 200 * time.Millisecond, Seed: 1,
		RateProfile: &RateProfileSpec{Kind: "staged", Stages: []ProfileStage{{Duration: "1s", Rate: 300}}},
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
	time.Sleep(window + 400*time.Millisecond)
	res := c.Result() // auto-closed at T1
	if res == nil {
		t.Fatal("scenario did not finalize")
	}

	rep := buildScenarioReport(sm, c)
	s := rep.Summary

	// Demand (requested) is far above what was sent (cap-bounded).
	if s.Informational.Requested < 700 {
		t.Fatalf("requested %d — demand not captured at pop (want ≥700 for a 900-demand run)", s.Informational.Requested)
	}
	if s.Sent > 150 {
		t.Fatalf("sent %d — the %d-tps cap did not bound throughput", s.Sent, capTPS)
	}
	// The shortfall shows up as DEFERRED (throttle), not loss.
	if s.Informational.Deferred < 500 {
		t.Fatalf("deferred %d — the throttle is invisible (want ≥500)", s.Informational.Deferred)
	}
	// Accounting closes: every requested pop is either sent or deferred (a
	// handful may be send_failures/dropped/window-boundary — allow slack).
	accounted := s.Sent + s.Informational.Deferred + s.SendFailures + s.Dropped
	if d := int(s.Informational.Requested) - int(accounted); d < -20 || d > 20 {
		t.Fatalf("requested (%d) != sent+deferred+failures+dropped (%d)", s.Informational.Requested, accounted)
	}

	// Deferred is OUTSIDE the ledger identity...
	if s.Emitted != s.InWindow+s.Drain+s.SuppressedPreWindow+s.SendFailures+s.Dropped {
		t.Fatalf("identity violated (deferred must not be a term): %+v", s)
	}
	// ...and outside the loss denominator (sent == in_window+drain, no deferral).
	if s.Sent != s.InWindow+s.Drain {
		t.Fatalf("sent (%d) must be exactly in_window+drain (%d) — deferral is not sent", s.Sent, s.InWindow+s.Drain)
	}
	t.Logf("cap-deferral: requested=%d sent=%d deferred=%d", s.Informational.Requested, s.Sent, s.Informational.Deferred)
}

// TestScenarioCapDeferral_UncappedNoDeferral: with no cap, nothing is deferred
// and requested == sent (the demand all fires).
func TestScenarioCapDeferral_UncappedNoDeferral(t *testing.T) {
	const window = 400 * time.Millisecond
	sm, ips, _ := profileManager(t, 2, window, time.Now)
	// No background scheduler → no shared limiter → uncapped.

	c := newScenarioController(sm, nil)
	spec := &Scenario{
		Participants: ips, Protocol: "syslog", Rate: 50, Window: window, Drain: 100 * time.Millisecond, Seed: 2,
		RateProfile: &RateProfileSpec{Kind: "linear", StartRate: 20, EndRate: 80},
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
	time.Sleep(window + 200*time.Millisecond)
	res := c.Result()
	if res == nil {
		t.Fatal("scenario did not finalize")
	}
	rep := buildScenarioReport(sm, c)
	s := rep.Summary
	if s.Informational.Deferred != 0 {
		t.Fatalf("uncapped run deferred %d, want 0", s.Informational.Deferred)
	}
	if s.Informational.Requested != s.Sent {
		t.Fatalf("uncapped: requested %d != sent %d (all demand should fire)", s.Informational.Requested, s.Sent)
	}
	if s.Sent == 0 {
		t.Fatal("no emission")
	}
}
