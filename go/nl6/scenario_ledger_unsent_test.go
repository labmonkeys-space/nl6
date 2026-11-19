/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sync"
	"sync/atomic"
	"testing"
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
