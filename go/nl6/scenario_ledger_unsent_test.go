/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLedgerCountUnsent_SnapshotKeepsIdentity pins the unsent-fire rule: a
// fire that sends nothing moves two counters, and a snapshot taken while such
// fires run must see both moves or neither. Four writers also pin that
// concurrent unsent fires on one device count exactly.
func TestLedgerCountUnsent_SnapshotKeepsIdentity(t *testing.T) {
	const perWriter = 250000
	l := &ledgerEntry{}

	var wg sync.WaitGroup
	var done atomic.Bool
	for _, bucket := range []*atomic.Uint64{&l.dropped, &l.dropped, &l.suppressedPreWindow, &l.suppressedPreWindow} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWriter {
				l.countUnsent(bucket, 1)
			}
		}()
	}
	go func() {
		wg.Wait()
		done.Store(true)
	}()

	for !done.Load() {
		s := l.snapshot()
		if s.Emitted != s.InWindow+s.Drain+s.SendFailures+s.Dropped+s.SuppressedPreWindow {
			t.Fatalf("snapshot breaks the ledger identity: %+v", s)
		}
	}

	s := l.snapshot()
	if s.Emitted != 4*perWriter || s.Dropped != 2*perWriter || s.SuppressedPreWindow != 2*perWriter {
		t.Fatalf("emitted=%d dropped=%d suppressed_pre_window=%d, want %d %d %d",
			s.Emitted, s.Dropped, s.SuppressedPreWindow, 4*perWriter, 2*perWriter, 2*perWriter)
	}
	if !l.identityHolds() {
		t.Fatal("identity does not hold at rest")
	}
}

// TestLedgerUnsent_NoBareAdds keeps every unsent fire on countUnsent.
// A new exporter that adds emitted and then dropped by hand reopens the race,
// and no behaviour test would see it.
//
// The one allowed bare dropped.Add is the admitted syslog fire whose write is
// abandoned. It already counted emitted inside the drain barrier.
func TestLedgerUnsent_NoBareAdds(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) < 50 {
		t.Fatalf("scanned only %d files; the guard is not looking where it thinks it is", len(files))
	}
	mustScan := map[string]bool{
		"syslog_exporter.go": false, "trap_exporter.go": false, "flow_exporter.go": false,
		"gnmi_dialout_exporter.go": false, "yangpush_exporter.go": false,
	}
	droppedAdds := map[string]int{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		if _, ok := mustScan[f]; ok {
			mustScan[f] = true
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if n := bytes.Count(src, []byte("suppressedPreWindow.Add(")); n > 0 {
			t.Errorf("%s adds suppressedPreWindow directly %d time(s); use countUnsent", f, n)
		}
		if n := bytes.Count(src, []byte("dropped.Add(")); n > 0 {
			droppedAdds[f] = n
		}
	}
	for f, seen := range mustScan {
		if !seen {
			t.Errorf("%s was never scanned, so this guard says nothing about it", f)
		}
	}
	for f, n := range droppedAdds {
		if f == "syslog_exporter.go" && n == 1 {
			continue
		}
		t.Errorf("%s adds dropped directly %d time(s); use countUnsent for a fire that sends nothing", f, n)
	}
}

// TestLedgerCountUnsent_FireAfterSnapshotLeavesTheReportAlone is the late
// refused fire: the exporter loaded its participation handle before
// finalize detached it, and it reaches the closed barrier after the snapshot.
// The fire must return without a write, count as emitted and dropped in the
// live ledger only, and leave the live ledger on the identity. The report is
// a value copy taken before the fire, so the fire cannot reach it.
func TestLedgerCountUnsent_FireAfterSnapshotLeavesTheReportAlone(t *testing.T) {
	entry := mustEntry(t)
	h := newGateHarness(t)
	t0 := time.Unix(0, h.clock.Load())
	h.gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Minute)})
	h.setClock(t0, time.Second)

	if stragglers := h.drain.closeAndWait("test"); stragglers != 0 {
		t.Fatalf("stragglers = %d, want 0", stragglers)
	}
	report := h.ledger.snapshot()
	if report != (ledgerSnapshot{}) {
		t.Fatalf("the snapshot taken before the fire is not empty: %+v", report)
	}

	if err := h.exp.fireScenario(entry, nil); err != nil {
		t.Fatalf("fireScenario after the snapshot: %v", err)
	}

	if got := h.writes.Load(); got != 0 {
		t.Errorf("wire writes = %d, want 0", got)
	}
	live := h.ledger.snapshot()
	if live.Emitted != 1 || live.Dropped != 1 {
		t.Errorf("live emitted=%d dropped=%d, want 1 and 1", live.Emitted, live.Dropped)
	}
	if !h.ledger.identityHolds() {
		t.Error("the live ledger breaks the identity after a refused fire")
	}
}
