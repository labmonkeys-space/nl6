/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// POST /api/v1/scenarios/{id}/stop waits for the finalize inside the handler.
// The finalize is bounded at finalizeBudget (60 s) and the API server's
// WriteTimeout is 30 s, so a slow finalize lost its response while the report
// was built all the same. The handler re-arms its write deadline once the
// finalize returns.
//
// The finalize holds the controller lock, so the test holds that lock past a
// short server WriteTimeout. The scenario was never started, so the answer is
// a 409. The 200 with the report goes out after the same re-arm.
func TestStopScenarioAnswersPastTheWriteTimeout(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	id := submitOK(t, router, validScenarioBody)
	ctrl, err := manager.scenarioByID(id)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(router)
	srv.Config.WriteTimeout = deadlineTestWriteTimeout
	srv.Start()
	t.Cleanup(srv.Close)

	ctrl.mu.Lock()
	time.AfterFunc(deadlineTestBatchSleep, ctrl.mu.Unlock)
	begin := time.Now()
	resp, err := http.Post(srv.URL+"/api/v1/scenarios/"+id+"/stop", "application/json", nil)
	if err == nil {
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
	}
	if err != nil {
		t.Fatalf("stop past the %v WriteTimeout: %v (connection dropped)", deadlineTestWriteTimeout, err)
	}
	if took := time.Since(begin); took < deadlineTestBatchSleep {
		t.Fatalf("stop answered after %v, before the lock was released: the test proves nothing", took)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
}
