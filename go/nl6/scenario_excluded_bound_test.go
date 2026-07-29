/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// scenario_excluded_bound_test.go — exclusion disclosure is bounded in ROWS but
// complete in the AGGREGATE, and the ceiling is exercised rather than assumed.
//
// Raising the participant ceiling to 100,000 made an unbounded exclusion list a
// ~14 MB control-plane response (one ~145-byte row per unresolved participant,
// held for the scenario's lifetime, copied into the readiness response, again
// into the report, and rendered one table row each into the HTML view under a
// 30 s WriteTimeout). Capping the rows without keeping the totals would have
// been worse than the blowup: `participants_excluded` is a number operators
// reconcile against.

// ceilingBody renders a submit naming n distinct participants, none of which
// exist in a small test fleet.
func ceilingBody(n int) string {
	var b strings.Builder
	b.Grow(n*17 + 128)
	b.WriteString(`{"participants":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		// 10.100.x.y — disjoint from scenarioTestManager's 10.42.0.x fleet.
		fmt.Fprintf(&b, `"10.100.%d.%d"`, (i>>8)&0xff, i&0xff)
	}
	b.WriteString(`],"protocol":"syslog","rate":1,"window":"1s","seed":42}`)
	return b.String()
}

// TestScenarioExcluded_RowsBoundedTotalsComplete arms a ceiling-adjacent
// participant list against a fleet that resolves none of it, and pins both
// halves of the contract: the rows are capped, the accounting is not.
func TestScenarioExcluded_RowsBoundedTotalsComplete(t *testing.T) {
	const n = scenarioMaxExcludedRows * 20 // 20k: well past the cap, fast to run
	router := scenarioAPIManager(t, 1)
	id := submitOK(t, router, ceilingBody(n))

	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
	if w.Code != http.StatusOK {
		t.Fatalf("arm = %d (body %s)", w.Code, truncateBody(w.Body.String()))
	}
	var rd readinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &rd); err != nil {
		t.Fatal(err)
	}

	if rd.ParticipantsArmed != 0 {
		t.Errorf("participants_armed = %d, want 0 (no participant exists)", rd.ParticipantsArmed)
	}
	if len(rd.Excluded) != scenarioMaxExcludedRows {
		t.Errorf("excluded rows = %d, want the %d cap", len(rd.Excluded), scenarioMaxExcludedRows)
	}
	if rd.ExcludedTotal != n {
		t.Errorf("excluded_total = %d, want %d — the total must count every exclusion, capped or not", rd.ExcludedTotal, n)
	}
	if !rd.ExcludedTruncated {
		t.Error("excluded_truncated not set while rows were dropped: the sampling would be silent")
	}
	if got := rd.ExcludedByReason["device not found"]; got != n {
		t.Errorf("excluded_by_reason[device not found] = %d, want %d", got, n)
	}
	// Every retained row must still carry the full readiness contract.
	for i, row := range rd.Excluded {
		if row.Device == "" || row.Reason == "" || row.RemediationHint == "" {
			t.Fatalf("row %d incomplete: %+v", i, row)
		}
	}

	// The point of the cap: the control-plane response stays small. Unbounded,
	// this body would be ~2.9 MB at n=20k and ~14 MB at the ceiling.
	if size := w.Body.Len(); size > 512<<10 {
		t.Errorf("readiness body is %d bytes; the row cap is supposed to bound it", size)
	}
	t.Logf("%d participants, 0 armed → %d-byte readiness body (%d rows, total %d)",
		n, w.Body.Len(), len(rd.Excluded), rd.ExcludedTotal)
}

// TestScenarioExcluded_ReportCountIsTheTrueTotal is the regression guard for the
// trap this change could have introduced: participants_excluded used to be
// len(res.Excluded), so capping the rows would have silently understated it.
func TestScenarioExcluded_ReportCountIsTheTrueTotal(t *testing.T) {
	const n = scenarioMaxExcludedRows * 3
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, nil)

	participants := make([]string, 0, n+1)
	participants = append(participants, "10.42.0.1") // the one that resolves
	for i := 0; i < n; i++ {
		participants = append(participants, fmt.Sprintf("10.100.%d.%d", (i>>8)&0xff, i&0xff))
	}
	spec := &Scenario{Participants: participants, Protocol: "syslog",
		Rate: 1, Window: 50 * time.Millisecond, Drain: 10 * time.Millisecond, Seed: 3}
	if err := c.Submit(spec, "s-000300"); err != nil {
		t.Fatal(err)
	}
	armed, excluded, err := c.Arm()
	if err != nil {
		t.Fatal(err)
	}
	if armed != 1 {
		t.Fatalf("armed = %d, want 1", armed)
	}
	if len(excluded) != scenarioMaxExcludedRows {
		t.Fatalf("excluded rows = %d, want the %d cap", len(excluded), scenarioMaxExcludedRows)
	}

	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	res, err := c.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if res.ExcludedTotal != n {
		t.Fatalf("result ExcludedTotal = %d, want %d", res.ExcludedTotal, n)
	}

	rep := buildScenarioReport(sm, c)
	if rep == nil {
		t.Fatal("no report")
	}
	if rep.Summary.ParticipantsExcluded != n {
		t.Errorf("participants_excluded = %d, want %d (derived from the total, not the capped row count)",
			rep.Summary.ParticipantsExcluded, n)
	}
	if !rep.Summary.ExcludedTruncated {
		t.Error("report does not flag the exclusion rows as truncated")
	}
	if got := rep.Summary.ExcludedByReason["device not found"]; got != n {
		t.Errorf("report excluded_by_reason = %d, want %d", got, n)
	}
	if len(rep.Summary.Excluded) != scenarioMaxExcludedRows {
		t.Errorf("report carries %d rows, want the %d cap", len(rep.Summary.Excluded), scenarioMaxExcludedRows)
	}
}

// TestScenarioExcluded_NotTruncatedBelowTheCap keeps the common case honest: a
// small exclusion set is reported whole, with no truncation flag and a total
// that equals the row count.
func TestScenarioExcluded_NotTruncatedBelowTheCap(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	id := submitOK(t, router, `{"participants":["10.42.0.1","10.100.0.1","10.100.0.2"],"protocol":"syslog","rate":1,"window":"1s","seed":1}`)
	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
	var rd readinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &rd); err != nil {
		t.Fatal(err)
	}
	if rd.ExcludedTruncated {
		t.Error("excluded_truncated set for 2 exclusions")
	}
	if rd.ExcludedTotal != 2 || len(rd.Excluded) != 2 {
		t.Errorf("total=%d rows=%d, want 2 and 2", rd.ExcludedTotal, len(rd.Excluded))
	}
}

// BenchmarkScenarioArmAtCeiling is the missing evidence at the raised ceiling:
// arm resolves 100,000 participants against a fleet that holds one of them, the
// worst case for the exclusion path. Reported as ns/op so a regression in the
// arm loop (or a reintroduced unbounded row list) is visible in benchstat.
func BenchmarkScenarioArmAtCeiling(b *testing.B) {
	sm := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
		devicesByIP:     map[string]*DeviceSimulator{},
	}
	participants := make([]string, 0, scenarioMaxParticipants)
	for i := 0; i < scenarioMaxParticipants; i++ {
		participants = append(participants, fmt.Sprintf("10.%d.%d.%d",
			100+i/(156*156), 100+(i/156)%156, 100+i%156))
	}
	spec := &Scenario{Participants: participants, Protocol: "syslog",
		Rate: 1, Window: time.Minute, Seed: 1}
	if err := spec.Validate(); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		c := newScenarioController(sm, nil)
		if err := c.Submit(spec, "s-000400"); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		armed, excluded, err := c.Arm()
		if err != nil {
			b.Fatal(err)
		}
		if armed != 0 || len(excluded) != scenarioMaxExcludedRows {
			b.Fatalf("armed=%d rows=%d", armed, len(excluded))
		}
	}
}
