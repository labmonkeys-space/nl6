/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// scenario_fingerprint_test.go — reproducibility contract (story 2.2): the
// metadata fingerprint, the CSV projection, and the reproduce-from-
// fingerprint round-trip (FR25/FR27/FR34).

// TestScenarioReport_MetadataFingerprint (FR25): the finalized report carries
// the (config_sha256, seed, nl6_version) triple plus RFC3339-ms actual
// T0/T1/drain timestamps, grouped under summary.metadata.
func TestScenarioReport_MetadataFingerprint(t *testing.T) {
	sm, c := reportFixture(t, map[string]ledgerSnapshot{"10.42.0.1": {Emitted: 5, InWindow: 5}})
	raw, _ := json.Marshal(buildScenarioReport(sm, c))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	meta, ok := doc["summary"].(map[string]any)["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("summary.metadata missing: %s", raw)
	}
	if meta["config_sha256"] != "cafef00d" || meta["nl6_version"] == "" || meta["seed"].(float64) != 1 {
		t.Fatalf("metadata fingerprint incomplete: %+v", meta)
	}
	for _, k := range []string{"t0", "t1", "drain_end"} {
		ts, _ := meta[k].(string)
		if _, err := time.Parse(rfc3339ms, ts); err != nil {
			t.Fatalf("metadata.%s = %q not RFC3339-ms: %v", k, ts, err)
		}
	}
}

// TestScenarioReport_CSVProjection (FR27): GET .../report?format=csv serves a
// flat text/csv projection of counters[] with a header row, join-ready on
// (protocol, source_ip, collector).
func TestScenarioReport_CSVProjection(t *testing.T) {
	router := scenarioAPIManager(t, 2)
	id := submitOK(t, router, `{"participants":["10.42.0.1","10.42.0.2"],"protocol":"syslog","rate":5,"window":"40ms","drain":"10ms","seed":1}`)
	mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
	mustPost(t, router, "/api/v1/scenarios/"+id+"/start")
	time.Sleep(120 * time.Millisecond)
	// stop (idempotent — window may have auto-closed).
	_ = doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/stop", "")

	w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id+"/report?format=csv", "")
	if w.Code != http.StatusOK {
		t.Fatalf("csv report = %d (body %s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type = %q, want text/csv", ct)
	}
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	// Header + one row per participant.
	if len(rows) != 3 {
		t.Fatalf("csv rows = %d, want 3 (header + 2 devices)", len(rows))
	}
	wantHeader := []string{"protocol", "source_ip", "collector", "emitted", "in_window", "drain", "suppressed_pre_window", "send_failures", "dropped", "background_suppressed"}
	if strings.Join(rows[0], ",") != strings.Join(wantHeader, ",") {
		t.Fatalf("csv header = %v, want %v", rows[0], wantHeader)
	}
	// Join keys populated on every data row.
	for _, r := range rows[1:] {
		if r[0] != "syslog" || !strings.HasPrefix(r[1], "10.42.0.") || r[2] == "" {
			t.Fatalf("csv join keys wrong: %v", r)
		}
	}
}

// TestScenarioReport_NoSniff (issue #281 / CodeQL go/reflected-xss): every
// report representation carries X-Content-Type-Options: nosniff so a browser
// can't MIME-sniff the CSV/JSON body (which echoes operator-set collector /
// source_ip strings) as HTML.
func TestScenarioReport_NoSniff(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	id := submitOK(t, router, `{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"40ms","drain":"10ms","seed":1}`)
	mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
	mustPost(t, router, "/api/v1/scenarios/"+id+"/start")
	time.Sleep(120 * time.Millisecond)
	_ = doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/stop", "")

	for _, path := range []string{
		"/api/v1/scenarios/" + id + "/report",
		"/api/v1/scenarios/" + id + "/report?format=csv",
		"/api/v1/scenarios/" + id + "/report?format=html",
	} {
		w := doReq(t, router, http.MethodGet, path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, w.Code)
		}
		if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
	}
}

// runReportViaAPI drives a full API lifecycle under synctest with the given
// seed and returns the parsed report — used by the reproduce round-trip.
func runReportViaAPI(t *testing.T, seed int) scenarioReport {
	t.Helper()
	var out scenarioReport
	synctest.Test(t, func(t *testing.T) {
		router := scenarioAPIManager(t, 2)
		body := fmt.Sprintf(`{"participants":["10.42.0.1","10.42.0.2"],"protocol":"syslog","rate":10,"window":"1s","drain":"500ms","seed":%d}`, seed)
		id := submitOK(t, router, body)
		mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
		mustPost(t, router, "/api/v1/scenarios/"+id+"/start")
		time.Sleep(time.Second + 600*time.Millisecond)
		synctest.Wait()
		w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id+"/report", "")
		if w.Code != http.StatusOK {
			t.Fatalf("report = %d", w.Code)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	})
	return out
}

// TestScenarioReport_ReproduceFromFingerprint (FR34): the same config + seed
// on the same nl6_version reproduces identical scheduled/sent counts and the
// same fingerprint — a run is exactly re-runnable.
func TestScenarioReport_ReproduceFromFingerprint(t *testing.T) {
	a := runReportViaAPI(t, 42)
	b := runReportViaAPI(t, 42)

	if a.Summary.Metadata.ConfigSHA256 != b.Summary.Metadata.ConfigSHA256 {
		t.Fatalf("config_sha256 differs across identical submits: %s vs %s",
			a.Summary.Metadata.ConfigSHA256, b.Summary.Metadata.ConfigSHA256)
	}
	if a.Summary.InWindow == 0 {
		t.Fatal("no in-window traffic — nothing to reproduce")
	}
	if a.Summary.InWindow != b.Summary.InWindow || a.Summary.Emitted != b.Summary.Emitted {
		t.Fatalf("counts not reproducible: a{in=%d em=%d} b{in=%d em=%d}",
			a.Summary.InWindow, a.Summary.Emitted, b.Summary.InWindow, b.Summary.Emitted)
	}
	if len(a.Counters) != len(b.Counters) {
		t.Fatalf("counter row count differs: %d vs %d", len(a.Counters), len(b.Counters))
	}
	for i := range a.Counters {
		if a.Counters[i].SourceIP != b.Counters[i].SourceIP || a.Counters[i].InWindow != b.Counters[i].InWindow {
			t.Fatalf("per-device counts not reproducible at row %d: %+v vs %+v", i, a.Counters[i], b.Counters[i])
		}
	}
}
