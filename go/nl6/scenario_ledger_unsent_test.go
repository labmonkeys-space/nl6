/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
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
	for _, bucket := range []*unsentCount{&l.dropped, &l.dropped, &l.suppressedPreWindow, &l.suppressedPreWindow} {
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

// TestLedgerUnsentCountersMoveOnlyThroughTheLedger backs the unsentCount
// type. The type has no Add, so the compiler refuses a bare add to dropped or
// suppressedPreWindow, and to an alias of either. What still compiles is
// reaching the inner field, so this test keeps every use of it inside the
// three methods in scenario_ledger.go that own it, test files included.
//
// It also pins countAbandonedWrite to its one caller, syslog's abandoned
// write. A refused path that called it would compile and skip unsentMu. The
// pin is per function: that the caller of fireWithCtx passes a non-nil p
// only after admit(), which the lock-free add relies on, is not checked here.
func TestLedgerUnsentCountersMoveOnlyThroughTheLedger(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) < 50 {
		t.Fatalf("scanned only %d files; the guard is not looking where it thinks it is", len(files))
	}
	mustScan := map[string]bool{
		"syslog_exporter.go": false, "trap_exporter.go": false, "flow_exporter.go": false,
		"gnmi_dialout_exporter.go": false, "yangpush_exporter.go": false, "scenario_ledger.go": false,
	}
	fset := token.NewFileSet()
	fieldUses, abandonedCalls := map[string]int{}, map[string]int{}
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		if _, ok := mustScan[f]; ok {
			mustScan[f] = true
		}
		maps.Copy(fieldUses, selectorUsesByFunc(f, af, "viaLedgerMethodsOnly"))
		if !strings.HasSuffix(f, "_test.go") {
			maps.Copy(abandonedCalls, selectorUsesByFunc(f, af, "countAbandonedWrite"))
		}
	}
	for f, seen := range mustScan {
		if !seen {
			t.Errorf("%s was never scanned, so this guard says nothing about it", f)
		}
	}

	wantField := map[string]int{
		"scenario_ledger.go:Load":                1,
		"scenario_ledger.go:countUnsent":         1,
		"scenario_ledger.go:countAbandonedWrite": 1,
	}
	if !maps.Equal(fieldUses, wantField) {
		t.Errorf("unsentCount's inner field is used at %v, want only %v: move dropped and "+
			"suppressedPreWindow through countUnsent, or countAbandonedWrite for an admitted write", fieldUses, wantField)
	}
	wantAbandoned := map[string]int{"syslog_exporter.go:fireWithCtx": 1}
	if !maps.Equal(abandonedCalls, wantAbandoned) {
		t.Errorf("countAbandonedWrite is called at %v, want only %v: a fire the barrier refused "+
			"must use countUnsent", abandonedCalls, wantAbandoned)
	}

	// Control: the scan sees an alias of the inner field, the shape the
	// substring guard this replaced could not see.
	const planted = `package main
func refused(p *scenarioPart) { d := &p.ledger.dropped.viaLedgerMethodsOnly; d.Add(1) }`
	af, err := parser.ParseFile(fset, "planted.go", planted, 0)
	if err != nil {
		t.Fatalf("control: parse: %v", err)
	}
	if got := selectorUsesByFunc("planted.go", af, "viaLedgerMethodsOnly"); got["planted.go:refused"] != 1 {
		t.Errorf("control: an alias of the inner field is reported as %v, want planted.go:refused once", got)
	}
}

// selectorUsesByFunc counts the selector expressions .name in af, keyed by
// file and enclosing top-level declaration (the function or method name, or
// "" outside one).
func selectorUsesByFunc(file string, af *ast.File, name string) map[string]int {
	out := map[string]int{}
	for _, d := range af.Decls {
		fn := ""
		if fd, ok := d.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
		}
		ast.Inspect(d, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
				out[file+":"+fn]++
			}
			return true
		})
	}
	return out
}

// TestLedgerCountUnsent_RefusedFireAfterSnapshotCountsInTheLiveLedger is the
// late refused fire: the exporter loaded its participation handle before
// finalize detached it, and it reaches the closed barrier after the snapshot.
// The fire must return without a write, count 1 emitted and 1 dropped in the
// live ledger, and leave the live ledger on the identity.
//
// It runs in one goroutine, so it does not see the race between a snapshot
// and the two adds; TestLedgerCountUnsent_SnapshotKeepsIdentity does.
func TestLedgerCountUnsent_RefusedFireAfterSnapshotCountsInTheLiveLedger(t *testing.T) {
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
