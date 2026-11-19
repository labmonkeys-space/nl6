/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// reconcileBin is the real nl6-reconcile, built once for the package.
var reconcileBin string

func TestMain(m *testing.M) {
	// make test-interop-ci-fixture has built it already.
	if reconcileBin = os.Getenv("NL6_RECONCILE_BIN"); reconcileBin != "" {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "nl6-ci-reconcile")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	reconcileBin = filepath.Join(dir, "nl6-reconcile")
	if out, err := exec.Command("go", "build", "-o", reconcileBin, "../nl6-reconcile").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build nl6-reconcile: %v\n%s", err, out)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func deviceIP(i int) string { return fmt.Sprintf("10.42.0.%d", i+1) }

// writeCheckFixture writes a report with one counter per sent entry and a
// received CSV with one row per received entry (header only when empty).
func writeCheckFixture(t *testing.T, sent, received []int, skipRecv map[int]bool) (report, csv string) {
	t.Helper()
	dir := t.TempDir()
	var counters []string
	total := 0
	for i, n := range sent {
		total += n
		counters = append(counters, fmt.Sprintf(
			`{"protocol":"syslog","source_ip":%q,"collector":"10.0.0.9:514","sent":%d}`, deviceIP(i), n))
	}
	report = filepath.Join(dir, "report.json")
	summary := fmt.Sprintf(`{"phase":"stopped","participants_armed":%d,"sent":%d}`, len(sent), total)
	if err := os.WriteFile(report, []byte(`{"summary":`+summary+`,"counters":[`+strings.Join(counters, ",")+`]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("protocol,source_ip,collector,received\n")
	for i, n := range received {
		if skipRecv[i] {
			continue
		}
		fmt.Fprintf(&b, "syslog,%s,10.0.0.9:514,%d\n", deviceIP(i), n)
	}
	csv = filepath.Join(dir, "received.csv")
	if err := os.WriteFile(csv, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return report, csv
}

func checkRun(t *testing.T, sent, received []int, skip map[int]bool, tol float64) (int, string) {
	t.Helper()
	report, csv := writeCheckFixture(t, sent, received, skip)
	var out, errb bytes.Buffer
	code, err := check(t.TempDir(), checkOptions{Report: report, Received: csv, Tolerance: tol, Reconcile: reconcileBin}, &out, &errb)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	return code, out.String() + errb.String()
}

func TestReconcileArgs(t *testing.T) {
	got := reconcileArgs(checkOptions{Report: "r.json", Received: "c.csv", Tolerance: 0})
	want := []string{"-report", "r.json", "-received", "c.csv", "-tolerance", "0", "-drained"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCheckExactMatch(t *testing.T) {
	if code, out := checkRun(t, []int{50, 50}, []int{50, 50}, nil, 0); code != 0 {
		t.Errorf("exit %d, want 0:\n%s", code, out)
	}
}

func TestCheckLossIsRed(t *testing.T) {
	code, out := checkRun(t, []int{50, 50}, []int{50, 45}, nil, 0)
	if code != 1 {
		t.Errorf("exit %d, want 1:\n%s", code, out)
	}
	found := false
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, deviceIP(1)) && strings.Contains(l, "LOSS") {
			found = true
		}
	}
	if !found {
		t.Errorf("no LOSS row for %s:\n%s", deviceIP(1), out)
	}
}

func TestCheckPerDeviceBudget(t *testing.T) {
	// One device at 50 % loss, the fleet at 12.5 %: the per-device row fails.
	if code, out := checkRun(t, []int{50, 50, 50, 50}, []int{25, 50, 50, 50}, nil, 0.15); code != 1 {
		t.Errorf("exit %d, want 1:\n%s", code, out)
	}
}

func TestCheckWithinBudget(t *testing.T) {
	if code, out := checkRun(t, []int{50, 50, 50, 50}, []int{45, 45, 45, 45}, nil, 0.15); code != 0 {
		t.Errorf("exit %d, want 0:\n%s", code, out)
	}
}

func TestCheckMissingDevice(t *testing.T) {
	code, out := checkRun(t, []int{50, 50}, []int{50, 50}, map[int]bool{1: true}, 0)
	if code != 1 || !strings.Contains(out, "MISSING") {
		t.Errorf("exit %d, want 1 with MISSING:\n%s", code, out)
	}
}

func TestCheckEmptyReceived(t *testing.T) {
	code, out := checkRun(t, []int{50, 50}, nil, nil, 0)
	if code != 1 {
		t.Errorf("exit %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "MISSING") {
		t.Errorf("want the missing rows shown:\n%s", out)
	}
}

// checkReport runs check on a hand-written report and a matching CSV.
func checkReport(t *testing.T, dir, report, csv string) (int, error) {
	t.Helper()
	tmp := t.TempDir()
	rp, cp := filepath.Join(tmp, "report.json"), filepath.Join(tmp, "received.csv")
	if err := os.WriteFile(rp, []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	return check(dir, checkOptions{Report: rp, Received: cp, Reconcile: reconcileBin}, &bytes.Buffer{}, &bytes.Buffer{})
}

func TestCheckRefusesAZeroReport(t *testing.T) {
	for _, tc := range []struct{ name, report, csv string }{
		{"zero sent, zero received",
			`{"summary":{"phase":"stopped","participants_armed":2,"sent":0},"counters":[` +
				`{"protocol":"syslog","source_ip":"10.42.0.1","collector":"10.0.0.9:514","sent":0},` +
				`{"protocol":"syslog","source_ip":"10.42.0.2","collector":"10.0.0.9:514","sent":0}]}`,
			"protocol,source_ip,collector,received\nsyslog,10.42.0.1,10.0.0.9:514,0\nsyslog,10.42.0.2,10.0.0.9:514,0\n"},
		{"no counters, header-only CSV", `{"summary":{"phase":"stopped"},"counters":[]}`,
			"protocol,source_ip,collector,received\n"},
	} {
		code, err := checkReport(t, t.TempDir(), tc.report, tc.csv)
		if err == nil || !strings.Contains(err.Error(), "nothing was sent") {
			t.Errorf("%s: exit %d, err %v, want the nothing-was-sent refusal", tc.name, code, err)
		}
	}
}

// checkFiles runs check on a report body (nil means no report file) and a
// received CSV body, and returns the exit code, stderr and the error.
func checkFiles(t *testing.T, report *string, received, reconcile string) (int, string, error) {
	t.Helper()
	tmp := t.TempDir()
	rp, cp := filepath.Join(tmp, "report.json"), filepath.Join(tmp, "received.csv")
	if report != nil {
		if err := os.WriteFile(rp, []byte(*report), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(cp, []byte(received), 0o644); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	code, err := check(t.TempDir(), checkOptions{Report: rp, Received: cp, Reconcile: reconcile}, &bytes.Buffer{}, &errb)
	return code, errb.String(), err
}

func TestCheckExitCodesForBadAndRefusedReports(t *testing.T) {
	str := func(s string) *string { return &s }
	zeroCSV := "protocol,source_ip,collector,received\nsyslog,10.42.0.1,10.0.0.9:514,0\n"
	// A path that does not exist: a report check refuses never starts it.
	notStarted := filepath.Join(t.TempDir(), "no-such-nl6-reconcile")
	const notJSON = "check needs the JSON report that nl6-ci run writes"

	// Missing report: exit 2, and nl6-reconcile is not started.
	code, stderr, err := checkFiles(t, nil, zeroCSV, notStarted)
	if code != 2 || err != nil || !strings.Contains(stderr, "report.json") || !strings.Contains(stderr, "Run nl6-ci run first") {
		t.Errorf("missing report: exit %d, err %v, stderr %q", code, err, stderr)
	}
	// Not JSON at all: exit 2 without starting nl6-reconcile.
	for name, body := range map[string]string{"empty": "", "broken JSON": `{"summary": {`} {
		code, stderr, err := checkFiles(t, str(body), zeroCSV, notStarted)
		if code != 2 || err != nil || !strings.Contains(stderr, notJSON) || !strings.Contains(stderr, "nl6-reconcile directly") {
			t.Errorf("%s: exit %d, err %v, stderr %q", name, code, err, stderr)
		}
	}
	// The CSV projection of an all-zero report with an all-zero received CSV.
	// nl6-reconcile alone reconciles it as OK, so check must refuse it before.
	projection := "protocol,source_ip,collector,emitted,in_window,drain,suppressed_pre_window,send_failures,dropped,background_suppressed\n" +
		"syslog,10.42.0.1,10.0.0.9:514,0,0,0,0,0,0,0\n"
	code, stderr, err = checkFiles(t, str(projection), zeroCSV, reconcileBin)
	if code != 2 || err != nil || !strings.Contains(stderr, notJSON) {
		t.Errorf("all-zero CSV projection: exit %d, err %v, stderr %q, want exit 2", code, err, stderr)
	}
	// Valid JSON that is not the report shape: refused by check itself.
	_, _, err = checkFiles(t, str(`{"summary":{"sent":"x"},"counters":[]}`), zeroCSV, notStarted)
	if err == nil || !strings.Contains(err.Error(), "not an nl6 scenario report") || !strings.Contains(err.Error(), "cannot unmarshal") {
		t.Errorf("wrong shape: err %v, want a refusal that names the decode error", err)
	}
	// Valid JSON that sent nothing: refused by check itself.
	zero := `{"summary":{"phase":"stopped","participants_armed":1,"sent":0},"counters":[` +
		`{"protocol":"syslog","source_ip":"10.42.0.1","collector":"10.0.0.9:514","sent":0}]}`
	if _, _, err := checkFiles(t, str(zero), zeroCSV, notStarted); err == nil || !strings.Contains(err.Error(), "is refused: nothing was sent") {
		t.Errorf("zero report: err %v, want the refusal", err)
	}
	// A good report with a bad received CSV: exit 2 from nl6-reconcile.
	good := `{"summary":{"phase":"stopped","participants_armed":1,"sent":50},"counters":[` +
		`{"protocol":"syslog","source_ip":"10.42.0.1","collector":"10.0.0.9:514","sent":50}]}`
	code, stderr, err = checkFiles(t, str(good), "not,a,received,csv\n1,2,3,4\n", reconcileBin)
	if code != 2 || err != nil || !strings.Contains(stderr, "nl6-reconcile:") {
		t.Errorf("bad received CSV: exit %d, err %v, stderr %q, want exit 2 from nl6-reconcile", code, err, stderr)
	}
}

func TestCheckUsesTheDeviceCountFromState(t *testing.T) {
	dir := t.TempDir()
	if err := saveState(dir, state{PID: 1, Devices: 4}); err != nil {
		t.Fatal(err)
	}
	report := `{"summary":{"phase":"stopped","participants_armed":2,"sent":100},"counters":[` +
		`{"protocol":"syslog","source_ip":"10.42.0.1","collector":"10.0.0.9:514","sent":50},` +
		`{"protocol":"syslog","source_ip":"10.42.0.2","collector":"10.0.0.9:514","sent":50}]}`
	csv := "protocol,source_ip,collector,received\nsyslog,10.42.0.1,10.0.0.9:514,50\nsyslog,10.42.0.2,10.0.0.9:514,50\n"
	_, err := checkReport(t, dir, report, csv)
	if err == nil || !strings.Contains(err.Error(), "2 devices took part, the fixture has 4") {
		t.Fatalf("err %v", err)
	}
	// Without state.json the count is unknown and the same report passes.
	if code, err := checkReport(t, t.TempDir(), report, csv); code != 0 || err != nil {
		t.Fatalf("without state: exit %d, err %v", code, err)
	}
}

// A fresh up with no run must not let check reconcile the report an earlier
// fixture left in the same state directory.
func TestCheckRefusesTheReportOfAnEarlierFixture(t *testing.T) {
	dir := t.TempDir()
	if err := saveState(dir, state{PID: 1, Devices: 1, Started: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	report := `{"summary":{"phase":"stopped","metadata":{"t0":"2026-11-18T11:00:00.000Z"},"participants_armed":1,"sent":50},"counters":[` +
		`{"protocol":"syslog","source_ip":"10.42.0.1","collector":"10.0.0.9:514","sent":50}]}`
	csv := "protocol,source_ip,collector,received\nsyslog,10.42.0.1,10.0.0.9:514,50\n"
	_, err := checkReport(t, dir, report, csv)
	if err == nil || !strings.Contains(err.Error(), "not from this fixture") || !strings.Contains(err.Error(), "Run nl6-ci run first") {
		t.Fatalf("err %v", err)
	}
}

func TestCheckNoReconcileBinary(t *testing.T) {
	report, csv := writeCheckFixture(t, []int{50}, []int{50}, nil)
	_, err := check(t.TempDir(), checkOptions{Report: report, Received: csv, Reconcile: "/nonexistent"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "/nonexistent") || !strings.Contains(err.Error(), "nl6 package") {
		t.Errorf("want an error naming the binary and the package that ships it, got %v", err)
	}
}

func TestCheckReconcileKilledBySignal(t *testing.T) {
	script := filepath.Join(t.TempDir(), "nl6-reconcile")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nkill -KILL $$\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	report, csv := writeCheckFixture(t, []int{50}, []int{50}, nil)
	code, err := check(t.TempDir(), checkOptions{Report: report, Received: csv, Reconcile: script}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "killed") {
		t.Fatalf("exit %d, err %v, want an error that names the signal", code, err)
	}
}

func TestCheckCLIRequiresReceived(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runCLI([]string{"check"}, &out, &errb); code != 2 {
		t.Errorf("missing -received: exit %d, want 2", code)
	}
}
