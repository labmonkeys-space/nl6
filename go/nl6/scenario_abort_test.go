/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

// scenario_abort_test.go — graceful-abort report artifact (story 2.3, FR14):
// a run interrupted by the SIGTERM abort pipeline still finalizes an
// immutable report marked `aborted`, with actual T0/T-abort, served by
// GET .../report exactly like a `stopped` report.

// TestScenarioAbort_ReportArtifact drives a run, aborts it mid-window via the
// same pipeline the SIGTERM handler uses, and asserts the served report is a
// finalized `aborted` artifact with the abort instant as T1 — immutable and
// schema-identical to a stopped report.
func TestScenarioAbort_ReportArtifact(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := scenarioAPIManager(t, 2)
		// Long window so only the abort finalizes (never the auto-close).
		id := submitOK(t, router, `{"participants":["10.42.0.1","10.42.0.2"],"protocol":"syslog","rate":10,"window":"10s","drain":"500ms","seed":7}`)
		mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
		mustPost(t, router, "/api/v1/scenarios/"+id+"/start")

		// Let ~300 ms of the window run (fires at 0,100,200 ms → 3/device),
		// then trigger the abort pipeline (what the SIGTERM handler calls).
		time.Sleep(300 * time.Millisecond)
		manager.abortActiveScenario()
		synctest.Wait()

		w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id+"/report", "")
		if w.Code != http.StatusOK {
			t.Fatalf("report after abort = %d (body %s)", w.Code, w.Body.String())
		}
		var rep scenarioReport
		if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}

		// Marked aborted, with real measurement data captured pre-abort.
		if rep.Summary.Phase != "aborted" {
			t.Fatalf("phase = %s, want aborted", rep.Summary.Phase)
		}
		if rep.Summary.InWindow == 0 {
			t.Fatal("aborted report has no in-window data — the pre-abort window was discarded")
		}
		// T-abort is the actual window close: earlier than the planned 10 s.
		t0, err := time.Parse(rfc3339ms, rep.Summary.Metadata.T0)
		if err != nil {
			t.Fatalf("metadata.t0: %v", err)
		}
		t1, err := time.Parse(rfc3339ms, rep.Summary.Metadata.T1)
		if err != nil {
			t.Fatalf("metadata.t1: %v", err)
		}
		if !t1.After(t0) || t1.Sub(t0) >= 10*time.Second {
			t.Fatalf("abort T1 (%s) not a mid-window instant after T0 (%s)", rep.Summary.Metadata.T1, rep.Summary.Metadata.T0)
		}
		if rep.Summary.Duration != t1.Sub(t0).String() {
			t.Fatalf("duration %q != t1-t0 %s", rep.Summary.Duration, t1.Sub(t0))
		}
		// Ledger identity holds on the aborted artifact.
		s := rep.Summary
		if s.Emitted != s.InWindow+s.Drain+s.SuppressedPreWindow+s.SendFailures+s.Dropped {
			t.Fatalf("identity violated on aborted report: %+v", s)
		}

		// Immutable: a second GET is byte-identical.
		w2 := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id+"/report", "")
		if w2.Body.String() != w.Body.String() {
			t.Fatal("aborted report is not immutable across GETs")
		}

		// Served exactly like a stopped report: same top-level shape, and the
		// idempotent POST /stop returns the same aborted artifact (200, not 409).
		w3 := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/stop", "")
		if w3.Code != http.StatusOK {
			t.Fatalf("stop after abort = %d, want 200 (idempotent)", w3.Code)
		}
		var rep3 scenarioReport
		if err := json.Unmarshal(w3.Body.Bytes(), &rep3); err != nil {
			t.Fatal(err)
		}
		if rep3.Summary.Phase != "aborted" || rep3.Summary.InWindow != rep.Summary.InWindow {
			t.Fatalf("idempotent stop returned a different artifact: %+v", rep3.Summary)
		}
	})
}
