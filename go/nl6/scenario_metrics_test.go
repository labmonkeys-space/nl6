/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// scenario_metrics_test.go — the scrapeable-gauges + structured-log surface
// (story 5.2, FR32/NFR-O2): a Prometheus text exposition whose sent_total
// counters reproduce the report totals, and the `scenario=<id> phase=<p>`
// transition log line.

// metricValue pulls the numeric value of the first exposition sample whose
// line begins with prefix (a `name{` or `name ` token). Returns ok=false when
// absent.
func metricValue(t *testing.T, body, prefix string) (float64, bool) {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			t.Fatalf("metric %q value parse: %v (line %q)", prefix, err, line)
		}
		return v, true
	}
	return 0, false
}

// sumFamily sums the value of every sample line for a counter family name.
func sumFamily(t *testing.T, body, name string) uint64 {
	t.Helper()
	var sum uint64
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, name+"{") {
			continue
		}
		fields := strings.Fields(line)
		v, err := strconv.ParseUint(fields[len(fields)-1], 10, 64)
		if err != nil {
			t.Fatalf("family %q value parse: %v (line %q)", name, err, line)
		}
		sum += v
	}
	return sum
}

// TestScenarioMetrics_ReproducesReportTotals (NFR-O2): after a scenario
// finalizes, the metrics exposition carries the phase + target-rate gauges and
// per-participant sent_total counters that sum to the report's summary totals.
func TestScenarioMetrics_ReproducesReportTotals(t *testing.T) {
	router := scenarioAPIManager(t, 2)
	id := submitOK(t, router, `{"participants":["10.42.0.1","10.42.0.2"],"protocol":"syslog","rate":200,"window":"250ms","seed":9}`)
	mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
	mustPost(t, router, "/api/v1/scenarios/"+id+"/start")

	// Let the window self-close (250ms + 50ms drain), then finalize via stop.
	time.Sleep(350 * time.Millisecond)
	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/stop", "")
	if w.Code != http.StatusOK {
		t.Fatalf("stop = %d (%s)", w.Code, w.Body.String())
	}
	var rep scenarioReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("report body: %v", err)
	}
	if rep.Summary.Sent == 0 {
		t.Fatal("report sent = 0 — scenario emitted nothing; can't validate reproduction")
	}

	m := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id+"/metrics", "")
	if m.Code != http.StatusOK {
		t.Fatalf("metrics = %d", m.Code)
	}
	if ct := m.Header().Get("Content-Type"); ct != prometheusTextVersion {
		t.Fatalf("Content-Type = %q, want %q", ct, prometheusTextVersion)
	}
	body := m.Body.String()

	// Phase gauge carries the terminal phase as a label with value 1.
	if !strings.Contains(body, `nl6_scenario_phase{id="`+id+`",phase="stopped"} 1`) {
		t.Fatalf("phase gauge missing/wrong:\n%s", body)
	}
	// Target-rate gauge reflects the configured rate.
	if rate, ok := metricValue(t, body, `nl6_scenario_target_rate{`); !ok || rate != 200 {
		t.Fatalf("target_rate = %v ok=%v, want 200", rate, ok)
	}

	// NFR-O2: summing the labeled sent_total reproduces the report total.
	if got := sumFamily(t, body, "nl6_scenario_sent_total"); got != rep.Summary.Sent {
		t.Fatalf("sum(sent_total) = %d, report sent = %d", got, rep.Summary.Sent)
	}
	if got := sumFamily(t, body, "nl6_scenario_emitted_total"); got != rep.Summary.Emitted {
		t.Fatalf("sum(emitted_total) = %d, report emitted = %d", got, rep.Summary.Emitted)
	}

	// sent_total is labeled on the full report tuple (protocol + collector).
	if !strings.Contains(body, `protocol="syslog"`) || !strings.Contains(body, `collector="10.0.0.9:514"`) {
		t.Fatalf("sent_total not labeled on the report tuple:\n%s", body)
	}
}

// TestScenarioMetrics_UnknownID: a metrics scrape of a missing scenario 404s.
func TestScenarioMetrics_UnknownID(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/s-999999/metrics", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown metrics = %d, want 404", w.Code)
	}
}

// TestScenarioTransitionLog_StructuredFormat (AC3): every lifecycle transition
// logs the `scenario=<id> phase=<phase>` key=value pair a monitoring stack can
// parse.
func TestScenarioTransitionLog_StructuredFormat(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })

	router := scenarioAPIManager(t, 1)
	id := submitOK(t, router, validScenarioBody)
	mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
	mustPost(t, router, "/api/v1/scenarios/"+id+"/start")
	time.Sleep(120 * time.Millisecond) // let the window auto-close → stopped
	_ = doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/stop", "")

	logs := buf.String()
	for _, want := range []string{
		"scenario=" + id + " phase=armed",
		"scenario=" + id + " phase=running",
		"scenario=" + id + " phase=stopped",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("transition log missing %q in:\n%s", want, logs)
		}
	}
}
