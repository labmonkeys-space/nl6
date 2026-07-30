/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// scenario_excluded_bound_test.go — exclusion disclosure is bounded in ROWS but
// complete in the AGGREGATE, and the participant ceiling is exercised by a test
// (not only by a benchmark, which `go test ./...` never runs).
//
// Raising the participant ceiling to 100,000 made an unbounded exclusion list a
// ~14 MB control-plane response (one ~145-byte row per unresolved participant,
// held for the scenario's lifetime, copied into the readiness response, again
// into the report, and rendered one table row each into the HTML view under a
// 30 s WriteTimeout). Capping the rows without keeping the totals would have
// been worse than the blowup: `participants_excluded` is a number operators
// reconcile against.

// excludedIP maps i to a distinct IPv4 in 10.100/16 — disjoint from
// scenarioTestManager's 10.42.0.x fleet, so every participant it names is an
// arm-time exclusion. One definition; this arithmetic was previously
// copy-pasted at four sites that had to agree.
func excludedIP(i int) string {
	return fmt.Sprintf("10.100.%d.%d", (i>>8)&0xff, i&0xff)
}

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
		b.WriteByte('"')
		b.WriteString(excludedIP(i))
		b.WriteByte('"')
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

	if rd.Phase != "armed" {
		t.Errorf("phase = %q, want armed (must come from the arm snapshot, not a later read)", rd.Phase)
	}
	if rd.ParticipantsArmed != 0 {
		t.Errorf("participants_armed = %d, want 0 (no participant exists)", rd.ParticipantsArmed)
	}
	if len(rd.Excluded) != scenarioExcludedArmRows {
		t.Errorf("excluded rows = %d, want the %d arm-phase share of the %d-row cap",
			len(rd.Excluded), scenarioExcludedArmRows, scenarioMaxExcludedRows)
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
	// Scaled to the constant it guards, generously but not vacuously: at ~145
	// bytes a row, 300/row leaves envelope headroom while still failing if the cap
	// is raised or removed. A flat 512 KiB passed with the cap at 3000.
	if budget := scenarioMaxExcludedRows * 300; w.Body.Len() > budget {
		t.Errorf("readiness body is %d bytes, over the %d-byte budget implied by the %d-row cap",
			w.Body.Len(), budget, scenarioMaxExcludedRows)
	}
	t.Logf("%d participants, 0 armed → %d-byte readiness body (%d rows, total %d)",
		n, w.Body.Len(), len(rd.Excluded), rd.ExcludedTotal)
}

// TestScenarioExcluded_ReportCountIsTheTrueTotal is the regression guard for the
// trap this change could have introduced: participants_excluded used to be
// len(res.Excluded), so capping the rows would have silently understated it.
func TestScenarioExcluded_ReportCountIsTheTrueTotal(t *testing.T) {
	const n = scenarioExcludedArmRows * 3
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, nil)

	participants := make([]string, 0, n+1)
	participants = append(participants, "10.42.0.1") // the one that resolves
	for i := 0; i < n; i++ {
		participants = append(participants, excludedIP(i))
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
	if len(excluded) != scenarioExcludedArmRows {
		t.Fatalf("excluded rows = %d, want the %d arm-phase share", len(excluded), scenarioExcludedArmRows)
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
	if len(rep.Summary.Excluded) != scenarioExcludedArmRows {
		t.Errorf("report carries %d rows, want the %d arm-phase share", len(rep.Summary.Excluded), scenarioExcludedArmRows)
	}
}

// TestScenarioExcluded_NotTruncatedBelowTheCap keeps the common case honest: a
// small exclusion set is reported whole, with no truncation flag and a total
// that equals the row count.
func TestScenarioExcluded_NotTruncatedBelowTheCap(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	id := submitOK(t, router, `{"participants":["10.42.0.1","10.100.0.1","10.100.0.2"],"protocol":"syslog","rate":1,"window":"1s","seed":1}`)
	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
	if w.Code != http.StatusOK {
		// Without this, an error body unmarshals into a zero readinessResponse and
		// the truncation assertion below passes vacuously.
		t.Fatalf("arm = %d (body %s)", w.Code, w.Body.String())
	}
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

// TestScenarioExcluded_ReArmResetsTheAccounting is the guard the first version of
// this change lacked: every other test here arms once, so deleting either reset
// line left the suite green while a real operator loop — arm against an empty
// fleet, provision the devices, re-arm — reported thousands of exclusions for a
// run in which every participant armed.
func TestScenarioExcluded_ReArmResetsTheAccounting(t *testing.T) {
	const n = scenarioExcludedArmRows * 2
	router := scenarioAPIManager(t, 1)
	id := submitOK(t, router, ceilingBody(n))

	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
	if w.Code != http.StatusOK {
		// An error body unmarshals into a zero readinessResponse, turning the
		// assertions below into misleading "total=0" failures.
		t.Fatalf("first arm = %d (body %s)", w.Code, truncateBody(w.Body.String()))
	}
	var first readinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.ExcludedTotal != n || !first.ExcludedTruncated {
		t.Fatalf("first arm: total=%d truncated=%v, want %d and true", first.ExcludedTotal, first.ExcludedTruncated, n)
	}

	// Provision every participant, then re-arm. The exclusion accounting must be
	// rebuilt, not carried.
	manager.mu.Lock()
	for i := 0; i < n; i++ {
		ip := excludedIP(i)
		dev := &DeviceSimulator{ID: "device-" + ip, IP: net.ParseIP(ip).To4(),
			syslogExporter: newSinkExporter(t, net.ParseIP(ip).To4(), func([]byte) error { return nil })}
		manager.devicesByIP[ip] = dev
		manager.devices[dev.ID] = dev
		manager.deviceIPs[ip] = struct{}{}
	}
	manager.mu.Unlock()

	w = doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
	if w.Code != http.StatusOK {
		t.Fatalf("re-arm = %d (body %s)", w.Code, truncateBody(w.Body.String()))
	}
	var second readinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if second.ExcludedTotal != 0 {
		t.Errorf("excluded_total = %d after a re-arm that resolved everything, want 0 (accounting carried across arms)", second.ExcludedTotal)
	}
	if len(second.Excluded) != 0 {
		t.Errorf("excluded rows = %d after a clean re-arm, want 0", len(second.Excluded))
	}
	if second.ExcludedTruncated {
		t.Error("excluded_truncated still set after a clean re-arm")
	}
	if len(second.ExcludedByReason) != 0 {
		t.Errorf("excluded_by_reason = %v after a clean re-arm, want empty", second.ExcludedByReason)
	}
	if second.ParticipantsArmed != n {
		t.Errorf("participants_armed = %d, want %d", second.ParticipantsArmed, n)
	}
}

// TestScenarioExcluded_ExactlyAtTheArmShare pins the boundary the other tests
// straddle: at exactly the arm-phase share every exclusion still gets a row and
// the truncation flag must stay absent.
func TestScenarioExcluded_ExactlyAtTheArmShare(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	id := submitOK(t, router, ceilingBody(scenarioExcludedArmRows))
	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
	if w.Code != http.StatusOK {
		t.Fatalf("arm = %d", w.Code)
	}
	var rd readinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &rd); err != nil {
		t.Fatal(err)
	}
	if rd.ExcludedTotal != scenarioExcludedArmRows || len(rd.Excluded) != scenarioExcludedArmRows {
		t.Errorf("total=%d rows=%d, want %d and %d", rd.ExcludedTotal, len(rd.Excluded),
			scenarioExcludedArmRows, scenarioExcludedArmRows)
	}
	if rd.ExcludedTruncated {
		t.Error("excluded_truncated set when nothing was dropped")
	}
}

// TestScenarioExcluded_StartPhaseRowsSurviveAFullArmBudget is why the budget is
// split. Arm's loop runs to completion before Start's arm→start gap check, so a
// single first-come cap dropped EVERY "device deleted between arm and start"
// row — the only exclusions whose device identity an operator cannot recover
// from (participants − fleet).
func TestScenarioExcluded_StartPhaseRowsSurviveAFullArmBudget(t *testing.T) {
	const missing = scenarioExcludedArmRows * 2 // enough to exhaust the arm share
	sm, _ := scenarioTestManager(t, 2)

	participants := make([]string, 0, missing+2)
	for i := 0; i < missing; i++ {
		participants = append(participants, excludedIP(i))
	}
	participants = append(participants, "10.42.0.1", "10.42.0.2")

	c := newScenarioController(sm, nil)
	spec := &Scenario{Participants: participants, Protocol: "syslog",
		Rate: 1, Window: 50 * time.Millisecond, Drain: 10 * time.Millisecond, Seed: 5}
	if err := c.Submit(spec, "s-000500"); err != nil {
		t.Fatal(err)
	}
	if armed, _, err := c.Arm(); err != nil || armed != 2 {
		t.Fatalf("arm: armed=%d err=%v, want 2", armed, err)
	}

	// Retire one armed device in the arm→start gap.
	dev := sm.devicesByIP["10.42.0.2"]
	dev.syslogExporter = nil
	delete(sm.devicesByIP, "10.42.0.2")
	delete(sm.devices, dev.ID)
	delete(sm.deviceIPs, "10.42.0.2")

	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	res, err := c.Stop()
	if err != nil {
		t.Fatal(err)
	}

	if got := res.ExcludedByReason["device deleted between arm and start"]; got != 1 {
		t.Errorf("by-reason count for the gap exclusion = %d, want 1", got)
	}
	var found bool
	for _, ex := range res.Excluded {
		if ex.Device == "10.42.0.2" && ex.Reason == "device deleted between arm and start" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("the arm→start gap exclusion has no ROW among %d retained; the arm phase consumed the whole budget",
			len(res.Excluded))
	}
}

// TestScenarioExcluded_AtParticipantCeiling exercises the ceiling itself rather
// than leaving it to a benchmark `go test ./...` never runs. Cheap enough for the
// default lane: the arm loop is ~1 ms at 100k.
func TestScenarioExcluded_AtParticipantCeiling(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	participants := make([]string, 0, scenarioMaxParticipants)
	for i := 0; i < scenarioMaxParticipants; i++ {
		participants = append(participants, fmt.Sprintf("10.%d.%d.%d",
			100+i/(156*156), 100+(i/156)%156, 100+i%156))
	}
	c := newScenarioController(sm, nil)
	spec := &Scenario{Participants: participants, Protocol: "syslog",
		Rate: 1, Window: time.Minute, Seed: 9}
	if err := c.Submit(spec, "s-000600"); err != nil {
		t.Fatal(err)
	}

	rd, err := c.ArmReadiness()
	if err != nil {
		t.Fatal(err)
	}
	if rd.Armed != 0 {
		t.Errorf("armed = %d, want 0", rd.Armed)
	}
	if rd.ExcludedTotal != scenarioMaxParticipants {
		t.Errorf("excluded_total = %d, want %d", rd.ExcludedTotal, scenarioMaxParticipants)
	}
	if len(rd.Excluded) != scenarioExcludedArmRows {
		t.Errorf("rows = %d, want %d", len(rd.Excluded), scenarioExcludedArmRows)
	}
	if len(rd.ExcludedByReason) != 1 {
		t.Errorf("by-reason has %d keys, want 1: the map must not scale with participants", len(rd.ExcludedByReason))
	}
	// The claim the cap exists to make true, checked at the ceiling.
	rows := make([]scenarioExcludedRow, 0, len(rd.Excluded))
	for _, ex := range rd.Excluded {
		rows = append(rows, scenarioExcludedRow(ex))
	}
	body, err := json.Marshal(readinessResponse{Excluded: rows, ExcludedTotal: rd.ExcludedTotal,
		ExcludedTruncated: true, ExcludedByReason: rd.ExcludedByReason})
	if err != nil {
		t.Fatal(err)
	}
	if budget := scenarioMaxExcludedRows * 300; len(body) > budget {
		t.Errorf("readiness body at the ceiling is %d bytes, over the %d-byte budget", len(body), budget)
	}
	t.Logf("ceiling: %d participants → %d-byte readiness payload (%d rows, total %d)",
		scenarioMaxParticipants, len(body), len(rows), rd.ExcludedTotal)
}

// BenchmarkScenarioArmAtCeiling times arm resolving 100,000 participants against
// an EMPTY fleet. Be precise about what that measures: every participant
// short-circuits on `dev == nil`, so this covers the exclusion path end to end
// (lookup, accounting, capped append) and does NOT cover installScenPart or
// ledger construction, which no participant here reaches. Right shape for this
// change — the exclusion path is what got a cap — but not a general "arm at the
// ceiling" number.
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

	// ONE controller, re-armed every iteration. armed→armed is legal re-entry
	// and each re-arm resets and rebuilds the whole exclusion view, so this
	// measures the same path as a first arm — without pre-building b.N
	// controllers, which performed b.N full 100k-participant Validate passes in
	// setup and pinned O(b.N × rows) memory for the whole run, skewing
	// ReportAllocs with setup garbage.
	c := newScenarioController(sm, nil)
	if err := c.Submit(spec, "s-000400"); err != nil {
		b.Fatal(err)
	}
	var sink armReadiness // keep the result live so the call cannot be elided

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rd, err := c.ArmReadiness()
		if err != nil {
			b.Fatal(err)
		}
		sink = rd
	}
	b.StopTimer()

	if sink.Armed != 0 || len(sink.Excluded) != scenarioExcludedArmRows || sink.ExcludedTotal != scenarioMaxParticipants {
		b.Fatalf("armed=%d rows=%d total=%d", sink.Armed, len(sink.Excluded), sink.ExcludedTotal)
	}
}
