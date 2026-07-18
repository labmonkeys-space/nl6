/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// scenarioAPIManager installs a fresh manager with n syslog-capable devices
// (10.42.0.1..n) as the process-global `manager` and returns the real
// router. Devices get a syslog collector so the report join tuple is
// populated. Restores the previous global on cleanup.
func scenarioAPIManager(t *testing.T, n int) http.Handler {
	t.Helper()
	sm, _ := scenarioTestManager(t, n)
	for _, dev := range sm.devicesByIP {
		dev.syslogConfig = &DeviceSyslogConfig{Collector: "10.0.0.9:514"}
	}
	old := manager
	manager = sm
	t.Cleanup(func() { manager = old })
	return setupRoutes()
}

// submitOK submits a valid one-device syslog scenario and returns its id.
func submitOK(t *testing.T, router http.Handler, body string) string {
	t.Helper()
	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit status = %d, want 202 (body %s)", w.Code, w.Body.String())
	}
	var resp struct {
		ID           string `json:"id"`
		ConfigSHA256 string `json:"config_sha256"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("submit body: %v", err)
	}
	if resp.ID == "" || resp.ConfigSHA256 == "" {
		t.Fatalf("submit response missing id/config_sha256: %s", w.Body.String())
	}
	return resp.ID
}

const validScenarioBody = `{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"60ms","drain":"10ms","seed":42}`

// TestScenarioAPI_SubmitValidation is the fail-fast 400 contract: every bad
// submit returns 400 with an {"error"} body (and "field" where attributable).
func TestScenarioAPI_SubmitValidation(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantField string // "" = field key not required
	}{
		{"unknown_field", `{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"1s","bogus":true}`, ""},
		{"bad_protocol", `{"participants":["10.42.0.1"],"protocol":"snmp","rate":5,"window":"1s"}`, ""},
		{"rate_over_cap", `{"participants":["10.42.0.1"],"protocol":"syslog","rate":5000,"window":"1s"}`, ""},
		{"zero_rate", `{"participants":["10.42.0.1"],"protocol":"syslog","rate":0,"window":"1s"}`, ""},
		{"bad_window", `{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"nope"}`, "window"},
		{"bad_drain", `{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"1s","drain":"xx"}`, "drain"},
		{"empty_participants", `{"participants":[],"protocol":"syslog","rate":5,"window":"1s"}`, ""},
		{"bad_ip", `{"participants":["not-an-ip"],"protocol":"syslog","rate":5,"window":"1s"}`, ""},
		{"malformed_json", `{`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := scenarioAPIManager(t, 1)
			w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("error body: %v", err)
			}
			if body["error"] == "" {
				t.Fatalf("400 body missing error: %s", w.Body.String())
			}
			if tc.wantField != "" && body["field"] != tc.wantField {
				t.Fatalf("field = %q, want %q", body["field"], tc.wantField)
			}
		})
	}
}

// TestScenarioAPI_NotFoundAnd409 covers the 404 and 409 phase-conflict paths.
func TestScenarioAPI_NotFoundAnd409(t *testing.T) {
	router := scenarioAPIManager(t, 1)

	// 404 — unknown id on every verb.
	for _, ep := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/scenarios/s-999999"},
		{http.MethodGet, "/api/v1/scenarios/s-999999/report"},
		{http.MethodPost, "/api/v1/scenarios/s-999999/arm"},
		{http.MethodPost, "/api/v1/scenarios/s-999999/start"},
		{http.MethodPost, "/api/v1/scenarios/s-999999/stop"},
		{http.MethodDelete, "/api/v1/scenarios/s-999999"},
	} {
		w := doReq(t, router, ep.method, ep.path, "")
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404", ep.method, ep.path, w.Code)
		}
	}

	id := submitOK(t, router, validScenarioBody)

	// 409 — second submit while one is active.
	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", validScenarioBody)
	if w.Code != http.StatusConflict {
		t.Fatalf("double submit = %d, want 409", w.Code)
	}

	// 409 — report before the scenario reaches a terminal phase.
	w = doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id+"/report", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("premature report = %d, want 409 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), id) {
		t.Fatalf("409 body should name the scenario id: %s", w.Body.String())
	}

	// 409 — start before arm (submitted -> running is not a legal transition).
	w = doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/start", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("start-before-arm = %d, want 409", w.Code)
	}
}

// TestScenarioAPI_ExcludedAndZeroArmRefusal exercises the readiness excluded
// shape (FR9) and the 0/N start refusal (FR40).
func TestScenarioAPI_ExcludedAndZeroArmRefusal(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	// One known + one unknown participant.
	id := submitOK(t, router, `{"participants":["10.42.0.1","10.99.0.9"],"protocol":"syslog","rate":5,"window":"1s"}`)

	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
	if w.Code != http.StatusOK {
		t.Fatalf("arm = %d, want 200", w.Code)
	}
	var rd readinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &rd); err != nil {
		t.Fatalf("readiness body: %v", err)
	}
	if rd.ParticipantsArmed != 1 || len(rd.Excluded) != 1 {
		t.Fatalf("armed=%d excluded=%d, want 1/1", rd.ParticipantsArmed, len(rd.Excluded))
	}
	ex := rd.Excluded[0]
	if ex.Device != "10.99.0.9" || ex.Reason == "" || ex.RemediationHint == "" {
		t.Fatalf("excluded row incomplete: %+v", ex)
	}

	// Now an all-unknown scenario: 0/N armed -> start refused.
	_ = doReq(t, router, http.MethodDelete, "/api/v1/scenarios/"+id, "")
	id2 := submitOK(t, router, `{"participants":["10.99.0.1"],"protocol":"syslog","rate":5,"window":"1s"}`)
	_ = doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id2+"/arm", "")
	w = doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id2+"/start", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("0/N start = %d, want 409 (body %s)", w.Code, w.Body.String())
	}
}

// TestScenarioAPI_HappyPathReport drives submit->arm->start->stop->report and
// asserts the report opens with the summary block before the join-tuple
// counters, with explicit zero-valued ledger fields (AC3).
func TestScenarioAPI_HappyPathReport(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	// Long window so only the explicit stop below finalizes — the T1
	// auto-close timer must not race the test.
	id := submitOK(t, router, `{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"30s","drain":"10ms","seed":42}`)

	if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", ""); w.Code != http.StatusOK {
		t.Fatalf("arm = %d, want 200", w.Code)
	}
	if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/start", ""); w.Code != http.StatusOK {
		t.Fatalf("start = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/stop", "")
	if w.Code != http.StatusOK {
		t.Fatalf("stop = %d, want 200 (body %s)", w.Code, w.Body.String())
	}

	raw := w.Body.String()
	// AC3: summary serializes BEFORE counters.
	si, ci := strings.Index(raw, `"summary"`), strings.Index(raw, `"counters"`)
	if si < 0 || ci < 0 || si > ci {
		t.Fatalf("report field order wrong (summary@%d, counters@%d): %s", si, ci, raw)
	}
	// AC3: explicit zero fields present (no omitempty).
	for _, key := range []string{`"in_window"`, `"send_failures"`, `"suppressed_pre_window"`, `"background_suppressed"`} {
		if !strings.Contains(raw, key) {
			t.Fatalf("report missing explicit key %s: %s", key, raw)
		}
	}

	var rep scenarioReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("report body: %v", err)
	}
	if rep.Summary.ID != id || rep.Summary.Phase != "stopped" || rep.Summary.Protocol != "syslog" {
		t.Fatalf("summary = %+v", rep.Summary)
	}
	if rep.Summary.ConfigSHA256 == "" || rep.Summary.Nl6Version == "" {
		t.Fatalf("summary fingerprint incomplete: %+v", rep.Summary)
	}
	if len(rep.Counters) != 1 {
		t.Fatalf("counters = %d rows, want 1", len(rep.Counters))
	}
	row := rep.Counters[0]
	if row.Protocol != "syslog" || row.SourceIP != "10.42.0.1" || row.Collector != "10.0.0.9:514" {
		t.Fatalf("counter join tuple wrong: %+v", row)
	}

	// Report is idempotent: GET returns the same terminal report.
	w2 := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id+"/report", "")
	if w2.Code != http.StatusOK {
		t.Fatalf("GET report = %d, want 200", w2.Code)
	}

	// Stop is idempotent: a redundant POST /stop on an already-stopped
	// scenario returns 200 + the same report, not a 409 (mirrors an
	// operator stopping after the window auto-closed at T1).
	w3 := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/stop", "")
	if w3.Code != http.StatusOK {
		t.Fatalf("idempotent stop = %d, want 200 (body %s)", w3.Code, w3.Body.String())
	}
}

// TestScenarioAPI_FingerprintStableAndDelete asserts config_sha256 is stable
// across identical submits (canonicalization) and that DELETE frees the slot.
func TestScenarioAPI_FingerprintStableAndDelete(t *testing.T) {
	router := scenarioAPIManager(t, 1)

	// Two key orderings of the SAME config must fingerprint identically.
	bodyA := `{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"1s","seed":7}`
	bodyB := `{"seed":7,"window":"1s","rate":5,"protocol":"syslog","participants":["10.42.0.1"]}`

	sha := func(body string) string {
		id := submitOK(t, router, body)
		w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id, "")
		var st statusResponse
		_ = json.Unmarshal(w.Body.Bytes(), &st)
		if w := doReq(t, router, http.MethodDelete, "/api/v1/scenarios/"+id, ""); w.Code != http.StatusOK {
			t.Fatalf("delete = %d, want 200", w.Code)
		}
		// After delete the slot is free — GET now 404.
		if w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id, ""); w.Code != http.StatusNotFound {
			t.Fatalf("post-delete GET = %d, want 404", w.Code)
		}
		return st.ConfigSHA256
	}
	if a, b := sha(bodyA), sha(bodyB); a != b {
		t.Fatalf("config_sha256 not canonical: %q != %q", a, b)
	}
}
