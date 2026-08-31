/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// scenario_drain_knob_test.go — nl6#500: the scenario `drain` duration
// configured nothing (the post-window phase is a barrier, not a duration), so
// it is REJECTED at submit rather than accepted, echoed and ignored — the
// nl6#445 rule. These tests pin the rejection, the fingerprint consequence for
// an old run being re-submitted, and the absence of any production reader.

// TestScenarioAPI_DrainIsRejected: a submit carrying `drain` is a 400
// attributed to the `drain` field, and the message says the barrier is
// automatic instead of merely reporting an unknown/invalid field. The message
// is what makes the rejection actionable — an operator who had a drain
// configured needs to be told their grace period never existed, not that their
// JSON key is unwelcome.
func TestScenarioAPI_DrainIsRejected(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	for _, body := range []string{
		`{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"1s","drain":"2s","seed":42}`,
		// A zero drain and an unparseable one take the same path: the field is
		// gone, so its VALUE is never inspected.
		`{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"1s","drain":"0s"}`,
		`{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"1s","drain":"xx"}`,
	} {
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("submit with drain = %d, want 400 (body %s)", w.Code, w.Body.String())
		}
		var resp struct {
			Error string `json:"error"`
			Field string `json:"field"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("400 body: %v (%s)", err, w.Body.String())
		}
		if resp.Field != "drain" {
			t.Errorf("field = %q, want %q (body %s)", resp.Field, "drain", w.Body.String())
		}
		if !strings.Contains(resp.Error, "not supported") || !strings.Contains(resp.Error, "automatic") {
			t.Errorf("message must name the automatic barrier, got %q", resp.Error)
		}
	}
}

// TestScenarioFingerprint_DrainFreeBodyKeepsItsDigest is the reproduce-from-
// fingerprint decision (nl6#500 Block If). A recorded fingerprint is a SHA-256
// of the submit body and carries no drain of its own, so replaying a run means
// a human re-submitting that body. Two outcomes had to be explicit:
//
//   - a body that CARRIED a drain no longer submits at all (400, above) — an
//     error the operator reads, never a silent replay of something different;
//   - a body that omitted it must hash EXACTLY as before, or every baseline
//     taken before this change would read as a different configuration.
//
// The digest below was computed on main@44ef67f, BEFORE the field stopped being
// honoured — not re-derived from the current code, which would prove nothing.
// `omitempty` on the DTO field is what makes it hold: an absent drain never
// reaches the canonical form.
func TestScenarioFingerprint_DrainFreeBodyKeepsItsDigest(t *testing.T) {
	const wantPreChangeDigest = "57cd3804ceee6b8a0b9143c497f40693cb6f6918270d0beb7974aee67333c1a6"
	req := scenarioRequest{
		Participants: []string{"10.42.0.1", "10.42.0.2"},
		Protocol:     "syslog",
		Rate:         10,
		Window:       "1s",
		Seed:         42,
	}
	if got := configSHA256(&req); got != wantPreChangeDigest {
		t.Fatalf("config_sha256 = %s, want %s (pre-change digest from main@44ef67f — a "+
			"submit that reproduced a run before nl6#500 must reproduce it after)", got, wantPreChangeDigest)
	}
}

// TestNoProductionCodeConfiguresADrain is the regression stop: nothing in the
// package may carry a configured drain duration again. Two independent checks,
// because either alone passes on a plausible reintroduction:
//
//   - reflection over the two structs that held it, so re-adding a field is
//     caught by name whatever it is called;
//   - a source scan for the identifiers the old model was built from, so a
//     package-level default or helper is caught even if no struct changes.
//
// The `drain` ledger bucket, the `drain_end` timestamp and the drainGate are
// deliberately NOT in scope: those are observed, not configured.
func TestNoProductionCodeConfiguresADrain(t *testing.T) {
	for _, st := range []struct {
		name string
		typ  reflect.Type
	}{
		{"Scenario", reflect.TypeOf(Scenario{})},
		{"gateState", reflect.TypeOf(gateState{})},
	} {
		for i := 0; i < st.typ.NumField(); i++ {
			if strings.Contains(strings.ToLower(st.typ.Field(i).Name), "drain") {
				t.Errorf("%s regained a drain field (%s): the post-window phase is a "+
					"barrier, not a duration (nl6#500)", st.name, st.typ.Field(i).Name)
			}
		}
	}

	banned := []string{"drainOrDefault", "defaultScenarioDrain", "drainEnd"}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for _, id := range banned {
			if strings.Contains(string(b), id) {
				t.Errorf("%s mentions %s: a configured drain duration is gone (nl6#500) — "+
					"the barrier ends when the writes admitted before T1 return", f, id)
			}
		}
	}
	// Positive control: a glob that matched nothing would pass silently.
	if scanned < 100 {
		t.Fatalf("scanned only %d production files — the glob is not covering the package", scanned)
	}
}
