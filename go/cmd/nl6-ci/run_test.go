/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeScenarioAPI serves the device list and one scenario.
type fakeScenarioAPI struct {
	mu        sync.Mutex
	srv       *httptest.Server
	submitted scenarioConfig
	phases    []string // phase answers, the last one repeats
	arm       string   // arm response body
	report    string
	calls     []string
}

func (f *fakeScenarioAPI) called(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == name {
			return true
		}
	}
	return false
}

func newFakeScenarioAPI(t *testing.T, ips []string) *fakeScenarioAPI {
	f := &fakeScenarioAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		var rows []map[string]string
		for _, ip := range ips {
			rows = append(rows, map[string]string{"ip": ip})
		}
		b, _ := json.Marshal(map[string]any{"success": true, "data": rows})
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/api/v1/scenarios", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, "submit")
		_ = json.NewDecoder(r.Body).Decode(&f.submitted)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"s-000001","config_sha256":"x"}`))
	})
	mux.HandleFunc("/api/v1/scenarios/s-000001/arm", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, "arm")
		f.mu.Unlock()
		_, _ = w.Write([]byte(f.arm))
	})
	mux.HandleFunc("/api/v1/scenarios/s-000001/start", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, "start")
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"id":"s-000001","phase":"running"}`))
	})
	mux.HandleFunc("/api/v1/scenarios/s-000001/stop", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, "stop")
		f.mu.Unlock()
		_, _ = w.Write([]byte(f.report))
	})
	mux.HandleFunc("/api/v1/scenarios/s-000001", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodDelete {
			f.calls = append(f.calls, "remove")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		p := f.phases[0]
		if len(f.phases) > 1 {
			f.phases = f.phases[1:]
		}
		_, _ = fmt.Fprintf(w, `{"id":"s-000001","phase":%q}`, p)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func runFixture(t *testing.T, apiURL string) string {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nl6.log")
	_ = os.WriteFile(logPath, []byte("line one\nline two\n"), 0o644)
	if err := saveState(dir, state{PID: 1, API: apiURL, Log: logPath, Devices: 4}); err != nil {
		t.Fatal(err)
	}
	return dir
}

const goodReport = `{"summary":{"phase":"stopped","participants_armed":4,"sent":200},"counters":[` +
	`{"source_ip":"10.42.0.1","sent":50},{"source_ip":"10.42.0.2","sent":50},` +
	`{"source_ip":"10.42.0.3","sent":50},{"source_ip":"10.42.0.4","sent":50}]}`

var fourIPs = []string{"10.42.0.1", "10.42.0.2", "10.42.0.3", "10.42.0.4"}

func TestRunHappyPath(t *testing.T) {
	f := newFakeScenarioAPI(t, fourIPs)
	f.phases = []string{"armed", "running", "stopped"}
	f.arm = `{"id":"s-000001","phase":"armed","participants_armed":4,"excluded":[],"excluded_total":0}`
	f.report = goodReport
	dir := runFixture(t, f.srv.URL)
	report := filepath.Join(dir, "report.json")
	var out bytes.Buffer
	err := run(dir, runOptions{Protocol: "syslog", Rate: 5, Window: 10 * time.Second,
		Report: report, Grace: time.Second, Poll: 5 * time.Millisecond}, &out)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	c := f.submitted
	if c.Protocol != "syslog" || c.Rate != 5 || c.Window != "10s" || c.ExpectParticipants != 4 ||
		!reflect.DeepEqual(c.Participants, fourIPs) {
		t.Fatalf("submit body %+v", c)
	}
	if b, err := os.ReadFile(report); err != nil || string(b) != goodReport {
		t.Fatalf("report file %q, %v", b, err)
	}
	want := "run: sent 200 records from 4 devices, report " + report + "\n"
	if !strings.HasSuffix(out.String(), want) {
		t.Fatalf("out %q, want suffix %q", out.String(), want)
	}
}

// -request-timeout bounds one API call. A large fleet needs more than the
// default to list or arm its devices.
func TestRunBoundsOneCallByTheGivenTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"success":true,"data":[]}`))
	}))
	t.Cleanup(slow.Close)
	dir := runFixture(t, slow.URL)
	o := runOptions{Protocol: "syslog", Rate: 5, Window: time.Second, Timeout: 20 * time.Millisecond}
	if err := run(dir, o, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "list devices") {
		t.Fatalf("err %v, want the device listing to time out", err)
	}
	o.Timeout = 5 * time.Second
	if err := run(dir, o, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "the fixture has no devices") {
		t.Fatalf("err %v, want an answer within the longer timeout", err)
	}
}

func TestRunPrintsExclusionsAndCleansUp(t *testing.T) {
	f := newFakeScenarioAPI(t, fourIPs)
	f.phases = []string{"armed"}
	f.arm = `{"id":"s-000001","phase":"armed","participants_armed":0,"excluded_total":4,"excluded":[` +
		`{"device":"10.42.0.1","reason":"requested rate 10.00/s exceeds this device's flow ceiling of 8.80/s","remediation_hint":"lower the rate"},` +
		`{"device":"10.42.0.2","reason":"requested rate 10.00/s exceeds this device's flow ceiling of 8.80/s","remediation_hint":"lower the rate"},` +
		`{"device":"10.42.0.3","reason":"requested rate 10.00/s exceeds this device's flow ceiling of 8.80/s","remediation_hint":"lower the rate"},` +
		`{"device":"10.42.0.4","reason":"requested rate 10.00/s exceeds this device's flow ceiling of 8.80/s","remediation_hint":"lower the rate"}]}`
	dir := runFixture(t, f.srv.URL)
	var out bytes.Buffer
	err := run(dir, runOptions{Protocol: "ipfix", Rate: 10, Window: time.Second,
		Grace: time.Second, Poll: 5 * time.Millisecond}, &out)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, ip := range fourIPs {
		line := "run: excluded " + ip + ": requested rate 10.00/s exceeds this device's flow ceiling of 8.80/s. lower the rate\n"
		if !strings.Contains(out.String(), line) {
			t.Errorf("missing line %q in %q", line, out.String())
		}
	}
	if !f.called("remove") {
		t.Error("scenario was not removed")
	}
	if f.called("start") {
		t.Error("start was called")
	}
}

func TestRunRemovesAStaleReport(t *testing.T) {
	f := newFakeScenarioAPI(t, fourIPs)
	f.phases = []string{"armed"}
	f.arm = `{"id":"s-000001","phase":"armed","participants_armed":0,"excluded_total":4,"excluded":[]}`
	dir := runFixture(t, f.srv.URL)
	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(report, []byte(goodReport), 0o644); err != nil { // left by an earlier run
		t.Fatal(err)
	}
	err := run(dir, runOptions{Protocol: "ipfix", Rate: 10, Window: time.Second}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if _, err := os.Stat(report); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %v: check would verify the report of the earlier run", err)
	}
}

// dropStatusPolls makes the fake API close the connection on the first n
// status polls after start, as an nl6 that does not answer would.
func dropStatusPolls(f *fakeScenarioAPI, n int) {
	mux := f.srv.Config.Handler
	var mu sync.Mutex
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/scenarios/") && f.called("start") {
			mu.Lock()
			drop := n > 0
			n--
			mu.Unlock()
			if drop {
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					conn.Close()
				}
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func inspectAs(st procState) func(int, string, uint64) procState {
	return func(int, string, uint64) procState { return st }
}

func TestRunFailsWhenNL6Dies(t *testing.T) {
	f := newFakeScenarioAPI(t, fourIPs)
	f.phases = []string{"running"}
	f.arm = `{"id":"s-000001","phase":"armed","participants_armed":4,"excluded":[],"excluded_total":0}`
	dir := runFixture(t, f.srv.URL)
	dropStatusPolls(f, 1<<30)
	var out bytes.Buffer
	begin := time.Now()
	// The window is long: a dead nl6 must fail the run at the first poll.
	err := run(dir, runOptions{Protocol: "syslog", Rate: 5, Window: time.Minute,
		Poll: 10 * time.Millisecond, inspect: inspectAs(procGone)}, &out)
	if err == nil || !strings.Contains(err.Error(), "nl6 did not finish the window: nl6 (pid 1) is gone") {
		t.Fatalf("err %v", err)
	}
	if d := time.Since(begin); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
	if !strings.Contains(out.String(), "nl6 log (tail)") || !strings.Contains(out.String(), "line two") {
		t.Fatalf("out %q", out.String())
	}
}

func TestRunSurvivesAFailedPoll(t *testing.T) {
	f := newFakeScenarioAPI(t, fourIPs)
	f.phases = []string{"stopped"}
	f.arm = `{"id":"s-000001","phase":"armed","participants_armed":4,"excluded":[],"excluded_total":0}`
	f.report = goodReport
	dir := runFixture(t, f.srv.URL)
	dropStatusPolls(f, 2)
	err := run(dir, runOptions{Protocol: "syslog", Rate: 5, Window: time.Second,
		Poll: 10 * time.Millisecond, inspect: inspectAs(procOurs)}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("a failed poll with nl6 alive ended the run: %v", err)
	}
}

func TestRunGivesUpAtTheDeadlineAndStopsTheScenario(t *testing.T) {
	f := newFakeScenarioAPI(t, fourIPs)
	f.phases = []string{"running"}
	f.arm = `{"id":"s-000001","phase":"armed","participants_armed":4,"excluded":[],"excluded_total":0}`
	dir := runFixture(t, f.srv.URL)
	err := run(dir, runOptions{Protocol: "syslog", Rate: 5, Window: 50 * time.Millisecond,
		Grace: 200 * time.Millisecond, Poll: 10 * time.Millisecond, inspect: inspectAs(procOurs)}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `nl6 did not finish the window: still "running" after 250ms`) {
		t.Fatalf("err %v", err)
	}
	if !f.called("stop") {
		t.Error("the scenario run gave up on was not stopped")
	}
}

// An nl6 that does not answer at the deadline would hold a stop for the whole
// finalize budget. run must not send one.
func TestRunDoesNotStopAScenarioOnAnNL6ThatDoesNotAnswer(t *testing.T) {
	f := newFakeScenarioAPI(t, fourIPs)
	f.phases = []string{"running"}
	f.arm = `{"id":"s-000001","phase":"armed","participants_armed":4,"excluded":[],"excluded_total":0}`
	dir := runFixture(t, f.srv.URL)
	dropStatusPolls(f, 1<<30)
	err := run(dir, runOptions{Protocol: "syslog", Rate: 5, Window: 50 * time.Millisecond,
		Grace: 200 * time.Millisecond, Poll: 10 * time.Millisecond, inspect: inspectAs(procOurs)}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "nl6 did not finish the window: no status after 250ms") {
		t.Fatalf("err %v", err)
	}
	if f.called("stop") {
		t.Error("a stop was sent to an nl6 that does not answer")
	}
}

func TestVerifyReportHintsAtTheWindowForAZeroDevice(t *testing.T) {
	report := `{"summary":{"phase":"stopped","participants_armed":2,"sent":3},"counters":[` +
		`{"source_ip":"10.42.0.1","sent":3},{"source_ip":"10.42.0.2","sent":0}]}`
	err := verifyReport([]byte(report), 2, time.Time{})
	if err == nil || !strings.Contains(err.Error(), "device 10.42.0.2 sent nothing") || !strings.Contains(err.Error(), "window") {
		t.Fatalf("err %v", err)
	}
}

func TestRunFailsWhenTheFleetShrank(t *testing.T) {
	f := newFakeScenarioAPI(t, fourIPs[:3])
	dir := runFixture(t, f.srv.URL) // up created 4
	err := run(dir, runOptions{Protocol: "syslog", Rate: 5, Window: time.Second}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "the fixture has 3 devices, up created 4") {
		t.Fatalf("err %v", err)
	}
	if f.called("submit") {
		t.Error("a scenario was submitted for the smaller fleet")
	}
}

func TestRunRequiresState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing") // before the first up there is no state directory
	err := run(dir, runOptions{Protocol: "syslog", Rate: 5, Window: time.Second}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no running fixture, run nl6-ci up first") {
		t.Fatalf("err %v", err)
	}
}

// After down the report of the finished cycle is still there. A run without a
// fixture must not delete it.
func TestRunWithoutStateKeepsTheReport(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(report, []byte(goodReport), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run(dir, runOptions{Protocol: "syslog", Rate: 5, Window: time.Second}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no running fixture, run nl6-ci up first") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(report); err != nil {
		t.Fatalf("the report of the finished cycle is gone: %v", err)
	}
}

func TestVerifyReport(t *testing.T) {
	for _, tc := range []struct {
		name, report, want string
		devices            int
	}{
		{"nothing sent", `{"summary":{"phase":"stopped","participants_armed":4,"sent":0},"counters":[]}`, "nothing was sent", 4},
		{"silent device", `{"summary":{"phase":"stopped","participants_armed":2,"sent":50},"counters":[{"source_ip":"10.42.0.1","sent":50},{"source_ip":"10.42.0.2","sent":0}]}`, "10.42.0.2", 2},
		{"too few devices", `{"summary":{"phase":"stopped","participants_armed":3,"sent":150},"counters":[{"source_ip":"10.42.0.1","sent":50}]}`, "3 devices took part, the fixture has 4", 4},
		{"too many devices", `{"summary":{"phase":"stopped","participants_armed":6,"sent":150},"counters":[{"source_ip":"10.42.0.1","sent":50}]}`, "6 devices took part, the fixture has 4", 4},
		{"cut counters", `{"summary":{"phase":"stopped","participants_armed":4,"sent":150},"counters":[{"source_ip":"10.42.0.1","sent":50}]}`, "1 counter rows for 4 devices", 4},
		{"no counters", `{"summary":{"phase":"stopped","participants_armed":4,"sent":150},"counters":[]}`, "no counters", 4},
		{"negative total", `{"summary":{"phase":"stopped","participants_armed":4,"sent":-1},"counters":[{"source_ip":"10.42.0.1","sent":50}]}`, "not an nl6 scenario report", 4},
		{"negative device", `{"summary":{"phase":"stopped","participants_armed":4,"sent":50},"counters":[{"source_ip":"10.42.0.1","sent":-50}]}`, "not an nl6 scenario report", 4},
		{"aborted", `{"summary":{"phase":"aborted","participants_armed":4,"sent":150},"counters":[]}`, "scenario aborted", 4},
		{"stragglers", `{"summary":{"phase":"stopped","metadata":{"drain_stragglers":3},"participants_armed":1,"sent":50},"counters":[{"source_ip":"10.42.0.1","sent":50}]}`, "nl6 cut its finalize short (drain_stragglers 3, incomplete_joins [])", 1},
		{"incomplete joins", `{"summary":{"phase":"stopped","metadata":{"incomplete_joins":["flow-ticker"]},"participants_armed":1,"sent":50},"counters":[{"source_ip":"10.42.0.1","sent":50}]}`, "nl6 cut its finalize short (drain_stragglers 0, incomplete_joins [flow-ticker])", 1},
		{"good", goodReport, "", 4},
		{"count unknown", goodReport, "", 0},
	} {
		err := verifyReport([]byte(tc.report), tc.devices, time.Time{})
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

// Scenario ids restart with every nl6, so the window start is what tells the
// report of this fixture from one an earlier fixture left behind.
func TestVerifyReportRefusesAReportFromBeforeTheFixture(t *testing.T) {
	started := time.Date(2026, 11, 18, 12, 0, 0, 500e6, time.UTC)
	report := func(t0 string) []byte {
		return []byte(`{"summary":{"phase":"stopped","metadata":{"t0":"` + t0 + `"},"participants_armed":1,"sent":5},` +
			`"counters":[{"source_ip":"10.42.0.1","sent":5}]}`)
	}
	for _, tc := range []struct {
		name, t0 string
		refused  bool
	}{
		{"an earlier fixture", "2026-11-18T11:59:00.000Z", true},
		{"no window start", "", true},
		{"this fixture", "2026-11-18T12:00:09.000Z", false},
	} {
		err := verifyReport(report(tc.t0), 1, started)
		if tc.refused != (err != nil && strings.Contains(err.Error(), "not from this fixture")) {
			t.Errorf("%s: got %v, want refused=%v", tc.name, err, tc.refused)
		}
	}
	if err := verifyReport(report("2026-11-18T11:59:00.000Z"), 1, time.Time{}); err != nil {
		t.Errorf("fixture start unknown: unexpected %v", err)
	}
}

// An unwritable report path must fail before the window, not after it.
func TestRunProbesTheReportPathBeforeItSubmits(t *testing.T) {
	f := newFakeScenarioAPI(t, fourIPs)
	dir := runFixture(t, f.srv.URL)
	report := filepath.Join(dir, "missing", "report.json")
	err := run(dir, runOptions{Protocol: "syslog", Rate: 5, Window: time.Second, Report: report}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "the report path is not writable") {
		t.Fatalf("err %v", err)
	}
	if f.called("submit") {
		t.Error("a scenario was submitted before the report path was probed")
	}
}
