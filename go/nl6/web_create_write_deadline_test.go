/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// nl6#746: POST /api/v1/devices runs the whole batch inside the handler, and
// the API server's WriteTimeout is 30 s. A longer batch completed while the
// client saw a dropped connection with no status. The handler now re-arms its
// write deadline once the batch returns, which replaces the expired one.
//
// A completed batch needs root and a Linux TUN device, so these tests stand
// inside a REAL batch through createBatchStageProbe, sleep past a short server
// WriteTimeout, and abort through the ordinary error return. The success and
// error responses share the one re-arm above the branch, so the error path
// covers the deadline handling of both.

const (
	deadlineTestWriteTimeout = 300 * time.Millisecond
	deadlineTestBatchSleep   = 2 * deadlineTestWriteTimeout
	deadlineTestBody         = `{"start_ip":"10.42.0.1","device_count":1,"netmask":"16","resource_file":"gategood.json"}`
	deadlineTestProbeErr     = "probe outlasted the write timeout"
)

// newDeadlineTestServer serves the production router plus a control route that
// sleeps past the deadline WITHOUT lifting it. The control is what proves the
// short WriteTimeout is live on this server: without it, a server whose timeout
// silently was not applied would pass the main assertion.
func newDeadlineTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/", setupRoutes())
	mux.HandleFunc("/control/slow", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(deadlineTestBatchSleep)
		_, _ = io.WriteString(w, "too late")
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.WriteTimeout = deadlineTestWriteTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// withSlowFailingBatch makes the real batch sleep past the write timeout at
// entry and then fail.
func withSlowFailingBatch(t *testing.T) {
	t.Helper()
	withCreateBatchProbe(t, func(stage createBatchStage) error {
		if stage != stageBatchEntered {
			return nil
		}
		time.Sleep(deadlineTestBatchSleep)
		return errors.New(deadlineTestProbeErr)
	})
}

func postCreate(t *testing.T, url string) (*http.Response, string, error) {
	t.Helper()
	resp, err := http.Post(url+"/api/v1/devices", "application/json", strings.NewReader(deadlineTestBody))
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, string(b), err
}

// TestCreateWriteDeadlineSlowBatchStillAnswers is the nl6#746 pin: a batch that
// outlasts the server WriteTimeout delivers its response instead of a dropped
// connection.
func TestCreateWriteDeadlineSlowBatchStillAnswers(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := newCreateGateRESTManager(t)
	t.Cleanup(swapGlobalManager(sm))
	withSlowFailingBatch(t)
	srv := newDeadlineTestServer(t)

	t.Run("control-route-is-cut-off", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/control/slow")
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		if err == nil {
			t.Fatalf("control route answered %d past the %v WriteTimeout; the timeout is not live, so the create assertion proves nothing",
				resp.StatusCode, deadlineTestWriteTimeout)
		}
	})

	t.Run("create-answers-past-the-deadline", func(t *testing.T) {
		resp, body, err := postCreate(t, srv.URL)
		if err != nil {
			t.Fatalf("create past the %v WriteTimeout: %v (connection dropped, nl6#746)", deadlineTestWriteTimeout, err)
		}
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body=%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, deadlineTestProbeErr) {
			t.Errorf("body %q does not carry the batch error", body)
		}
	})
}

// TestCreateWriteDeadlineIsReArmedBeforeTheResponse pins the bound on the
// response write: without it a client that stopped reading during the batch
// pins the connection with no limit. A well-behaved client cannot observe the
// re-arm, hence the seam.
func TestCreateWriteDeadlineIsReArmedBeforeTheResponse(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := newCreateGateRESTManager(t)
	t.Cleanup(swapGlobalManager(sm))
	withSlowFailingBatch(t)
	srv := newDeadlineTestServer(t)

	var (
		mu    sync.Mutex
		calls []time.Time
	)
	prev := armCreateResponseDeadline
	armCreateResponseDeadline = func(rc *http.ResponseController, deadline time.Time) error {
		mu.Lock()
		calls = append(calls, deadline)
		mu.Unlock()
		return prev(rc, deadline)
	}
	t.Cleanup(func() { armCreateResponseDeadline = prev })

	before := time.Now()
	if _, _, err := postCreate(t, srv.URL); err != nil {
		t.Fatalf("create: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("re-arm ran %d times, want exactly 1", len(calls))
	}
	d := calls[0]
	if d.IsZero() {
		t.Fatal("re-armed deadline is zero, which clears it instead of bounding the write")
	}
	// Armed AFTER the batch returned, and no further out than the constant.
	if earliest := before.Add(deadlineTestBatchSleep); d.Before(earliest) {
		t.Errorf("deadline %v is before the batch ended (%v): it was armed too early", d, earliest)
	}
	if latest := time.Now().Add(createResponseWriteTimeout); d.After(latest) {
		t.Errorf("deadline %v is beyond now+%v", d, createResponseWriteTimeout)
	}
}

// TestCreateWriteDeadlineUnsupportedWriterStillAnswers: handler tests drive a
// ResponseRecorder, which answers http.ErrNotSupported for deadline control.
// That must never turn into an error response.
func TestCreateWriteDeadlineUnsupportedWriterStillAnswers(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := newCreateGateRESTManager(t)
	t.Cleanup(swapGlobalManager(sm))

	reached := false
	withCreateBatchProbe(t, func(stage createBatchStage) error {
		if stage == stageBatchEntered {
			reached = true
			return errors.New(deadlineTestProbeErr)
		}
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(deadlineTestBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, req)

	if !reached {
		t.Fatal("batch was not reached: the deadline lift failed the request before the batch")
	}
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), deadlineTestProbeErr) {
		t.Fatalf("status = %d body = %q, want 500 carrying the batch error", rr.Code, rr.Body.String())
	}
}
