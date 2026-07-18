/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// scenario_status_list_test.go — extended status + scenario list (story 5.1):
// live per-protocol counts, elapsed/remaining, planned+actual T0/T1 via
// approximate mid-run reads, and GET /api/v1/scenarios.

// TestScenarioStatus_LiveWindowAndCounts: a running scenario's status carries
// protocol, window, actual T0/T1, elapsed/remaining, and a live counts block.
func TestScenarioStatus_LiveWindowAndCounts(t *testing.T) {
	router := scenarioAPIManager(t, 2)
	id := submitOK(t, router, `{"participants":["10.42.0.1","10.42.0.2"],"protocol":"syslog","rate":50,"window":"30s","drain":"1s","seed":7}`)
	mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
	mustPost(t, router, "/api/v1/scenarios/"+id+"/start")

	// Let some in-window fires accumulate, then read live status.
	time.Sleep(150 * time.Millisecond)
	w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var st statusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Phase != "running" || st.Protocol != "syslog" || st.Window != "30s" {
		t.Fatalf("status header wrong: %+v", st)
	}
	if st.T0 == "" || st.T1 == "" || st.Elapsed == "" || st.Remaining == "" {
		t.Fatalf("live window fields missing: t0=%q t1=%q elapsed=%q remaining=%q", st.T0, st.T1, st.Elapsed, st.Remaining)
	}
	if _, err := time.Parse(rfc3339ms, st.T0); err != nil {
		t.Fatalf("t0 not RFC3339-ms: %v", err)
	}
	if st.Counts == nil {
		t.Fatal("live counts block missing on a running scenario")
	}
	if st.Counts.ParticipantsArmed != 2 {
		t.Fatalf("participants_armed = %d, want 2", st.Counts.ParticipantsArmed)
	}
	// Approximate mid-run read: something should have been sent by now.
	if st.Counts.InWindow == 0 {
		t.Fatal("live in_window = 0 — mid-run counts not surfacing")
	}
	if st.Counts.Sent != st.Counts.InWindow+st.Counts.Drain {
		t.Fatalf("sent (%d) != in_window+drain (%d)", st.Counts.Sent, st.Counts.InWindow+st.Counts.Drain)
	}
	_ = doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/stop", "")
}

// TestScenarioList: GET /api/v1/scenarios lists scenarios with phases.
func TestScenarioList(t *testing.T) {
	router := scenarioAPIManager(t, 1)

	// Empty before any submit.
	w := doReq(t, router, http.MethodGet, "/api/v1/scenarios", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d", w.Code)
	}
	var empty struct {
		Scenarios []scenarioListEntry `json:"scenarios"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &empty)
	if len(empty.Scenarios) != 0 {
		t.Fatalf("empty list = %d, want 0", len(empty.Scenarios))
	}

	// After submit + arm, the list shows the scenario with its phase.
	id := submitOK(t, router, validScenarioBody)
	mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
	w = doReq(t, router, http.MethodGet, "/api/v1/scenarios", "")
	var got struct {
		Scenarios []scenarioListEntry `json:"scenarios"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Scenarios) != 1 || got.Scenarios[0].ID != id || got.Scenarios[0].Phase != "armed" {
		t.Fatalf("list = %+v, want [{%s armed}]", got.Scenarios, id)
	}
}
