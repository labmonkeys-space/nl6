/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

// scenario_scheduled_start_test.go — absolute-T0 scheduled start (story 3.2,
// FR11): POST .../start {"at": RFC3339} begins emission at that instant via a
// controller timer; a past timestamp is 400; a DELETE before T0 cancels
// cleanly (timer stopped, transports released, no report).

// TestScenarioScheduledStart_FiresAtT0 (FR11): a future `at` keeps the
// scenario armed until the instant, then runs and finalizes.
func TestScenarioScheduledStart_FiresAtT0(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := scenarioAPIManager(t, 2)
		id := submitOK(t, router, `{"participants":["10.42.0.1","10.42.0.2"],"protocol":"syslog","rate":10,"window":"1s","seed":9}`)
		mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")

		at := time.Now().Add(2 * time.Second).Format(time.RFC3339)
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/start", fmt.Sprintf(`{"at":%q}`, at))
		if w.Code != http.StatusOK {
			t.Fatalf("scheduled start = %d (body %s)", w.Code, w.Body.String())
		}
		var st statusResponse
		_ = json.Unmarshal(w.Body.Bytes(), &st)
		if st.Phase != "armed" || st.ScheduledStart == "" {
			t.Fatalf("expected armed + scheduled_start, got %+v", st)
		}

		// Before T0: still armed, not running.
		time.Sleep(1 * time.Second)
		synctest.Wait()
		if p := statusPhase(t, router, id); p != "armed" {
			t.Fatalf("phase before T0 = %s, want armed", p)
		}

		// Past T0 + window + drain: the timer fired, the scenario ran and
		// auto-closed. Report is available and marked stopped.
		time.Sleep(3 * time.Second)
		synctest.Wait()
		rw := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id+"/report", "")
		if rw.Code != http.StatusOK {
			t.Fatalf("report after scheduled run = %d (body %s)", rw.Code, rw.Body.String())
		}
		var rep scenarioReport
		_ = json.Unmarshal(rw.Body.Bytes(), &rep)
		if rep.Summary.Phase != "stopped" || rep.Summary.InWindow == 0 {
			t.Fatalf("scheduled run did not emit: %+v", rep.Summary)
		}
	})
}

// TestScenarioScheduledStart_PastRejected (FR11): a past `at` is a 400.
func TestScenarioScheduledStart_PastRejected(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	id := submitOK(t, router, validScenarioBody)
	mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")

	past := time.Now().Add(-1 * time.Minute).Format(time.RFC3339)
	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/start", fmt.Sprintf(`{"at":%q}`, past))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("past start = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["field"] != "at" {
		t.Fatalf("400 field = %q, want at", body["field"])
	}
	// A garbage timestamp is also a 400.
	w = doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/start", `{"at":"not-a-time"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad start timestamp = %d, want 400", w.Code)
	}
}

// TestScenarioScheduledStart_DeleteBeforeT0 (FR11): DELETE before the timer
// fires cancels cleanly — the timer is stopped, transports released, no
// report is produced, and T0 passing never starts it.
func TestScenarioScheduledStart_DeleteBeforeT0(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := scenarioAPIManager(t, 1)
		id := submitOK(t, router, `{"participants":["10.42.0.1"],"protocol":"syslog","rate":10,"window":"1s","seed":3}`)
		mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")

		// Grab the controller handle before delete detaches it.
		ctrl, err := manager.scenarioByID(id)
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(10 * time.Second).Format(time.RFC3339)
		mustPostBody(t, router, "/api/v1/scenarios/"+id+"/start", fmt.Sprintf(`{"at":%q}`, at))

		// DELETE before T0 → clean cancel.
		if w := doReq(t, router, http.MethodDelete, "/api/v1/scenarios/"+id, ""); w.Code != http.StatusOK {
			t.Fatalf("delete before T0 = %d, want 200", w.Code)
		}
		if ctrl.Phase() != phaseCanceled {
			t.Fatalf("phase after delete = %s, want canceled", ctrl.Phase())
		}
		// Transports released.
		if manager.devicesByIP["10.42.0.1"].syslogExporter.scenPart.Load() != nil {
			t.Fatal("participation handle not released on scheduled-start cancel")
		}
		// Advance well past the would-be T0: the stopped timer must not run it.
		time.Sleep(15 * time.Second)
		synctest.Wait()
		if ctrl.Phase() != phaseCanceled {
			t.Fatalf("scheduled start fired after cancel: phase=%s", ctrl.Phase())
		}
		if ctrl.Result() != nil {
			t.Fatal("a canceled scheduled scenario produced a report")
		}
		// The slot is free: GET is 404.
		if w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id, ""); w.Code != http.StatusNotFound {
			t.Fatalf("GET after delete = %d, want 404", w.Code)
		}
	})
}

func statusPhase(t *testing.T, router http.Handler, id string) string {
	t.Helper()
	w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id, "")
	var st statusResponse
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	return st.Phase
}

func mustPostBody(t *testing.T, router http.Handler, path, body string) {
	t.Helper()
	if w := doReq(t, router, http.MethodPost, path, body); w.Code != http.StatusOK {
		t.Fatalf("POST %s = %d (body %s)", path, w.Code, w.Body.String())
	}
}
