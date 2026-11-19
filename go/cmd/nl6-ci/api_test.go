/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// createBatchWithin posts one batch with a budget of its own.
func (c client) createBatchWithin(batch json.RawMessage, budget time.Duration) error {
	return c.createBatchBy(batch, time.Now().Add(budget), budget)
}

func TestClientVersionStatusDevices(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":"v1.2.3"}`))
	})
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"message":"Success","data":{"create_batch_in_progress":false,"resource_reload_in_progress":true,"total_devices":5}}`))
	})
	mux.HandleFunc("/api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"message":"Success","data":[{"ip":"10.42.0.2"},{"ip":"10.42.0.1"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newClient(srv.URL)
	if v, err := c.version(); err != nil || v != "v1.2.3" {
		t.Fatalf("version %q, %v", v, err)
	}
	if busy, n, err := c.status(); err != nil || !busy || n != 5 {
		t.Fatalf("status %v %d %v", busy, n, err)
	}
	ips, err := c.deviceIPs()
	if err != nil || !reflect.DeepEqual(ips, []string{"10.42.0.1", "10.42.0.2"}) {
		t.Fatalf("ips %v, %v", ips, err)
	}
}

func TestCreateBatchRetriesOn409(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"success":false,"message":"busy"}`))
			return
		}
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()
	if err := newClient(srv.URL).createBatchWithin([]byte(`{}`), time.Minute); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("%d requests", n)
	}
}

func TestCreateBatchReportsMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success":false,"message":"start_ip is required"}`))
	}))
	defer srv.Close()
	err := newClient(srv.URL).createBatchWithin([]byte(`{}`), time.Minute)
	if err == nil || !contains(err.Error(), "start_ip is required") {
		t.Fatalf("got %v", err)
	}
}

func TestClientTimesOutOnSilentServer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)
	c := newClientTimeout(srv.URL, 50*time.Millisecond)
	start := time.Now()
	_, err := c.deviceIPs()
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("call took %s", d)
	}
}

func TestCreateBatchIgnoresRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()
	c := newClientTimeout(srv.URL, 50*time.Millisecond)
	if err := c.createBatchWithin([]byte(`{}`), time.Minute); err != nil {
		t.Fatalf("createBatch cut off by the request timeout: %v", err)
	}
}

// A response that declares more bytes than it sends must fail the call, even
// when the bytes that arrived are valid on their own.
func TestClientFailsOnShortBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"success\":true,\"data\":[]}")
		_ = buf.Flush()
	}))
	defer srv.Close()
	c := newClient(srv.URL)
	calls := map[string]func() error{
		"get":         func() error { _, err := c.deviceIPs(); return err },
		"createBatch": func() error { return c.createBatchWithin([]byte(`{}`), time.Minute) },
		"scenario":    func() error { _, err := c.stop("s-000001"); return err },
	}
	for name, call := range calls {
		if err := call(); err == nil {
			t.Errorf("%s: a short body was accepted", name)
		}
	}
}

// nl6 answers a stop only after it finalized the scenario, which takes up to
// 60s on a slow drain. The short request timeout must not cut that off.
func TestStopIgnoresRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte(`{"summary":{}}`))
	}))
	defer srv.Close()
	c := newClientTimeout(srv.URL, 50*time.Millisecond)
	if _, err := c.stop("s-000001"); err != nil {
		t.Fatalf("stop cut off by the request timeout: %v", err)
	}
}

// Each attempt gets what is left of the budget, not a fresh one.
func TestCreateBatchStaysWithinItsBudget(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)
	start := time.Now()
	err := newClient(srv.URL).createBatchWithin([]byte(`{}`), 50*time.Millisecond)
	if err == nil || !contains(err.Error(), "create devices: not done after 50ms") {
		t.Fatalf("err %v, want a timeout that names the budget", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("call took %s", d)
	}
}

// A 409 whose retry could not start inside the budget ends the call.
func TestCreateBatchGivesUpWhenTheRetryWouldOverrun(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"success":false,"message":"busy"}`))
	}))
	defer srv.Close()
	start := time.Now()
	err := newClient(srv.URL).createBatchWithin([]byte(`{}`), time.Second)
	if err == nil || !contains(err.Error(), "still refused with 409 after 1s") || n != 1 {
		t.Fatalf("err %v after %d posts", err, n)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("call took %s, it slept through the budget", d)
	}
}
