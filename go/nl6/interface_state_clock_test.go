/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sync/atomic"
	"testing"
	"time"
)

// nl6#575. THE ENGINE'S CLOCK IS INJECTABLE, AND ALL THREE READS MOVE TOGETHER.
//
// lastChange is derived from the WALL clock: time.Now()'s monotonic reading is
// stripped by UnixNano, and wallRelNs carries a rewind sentinel for the
// backwards step that follows. A test asserting lastChange is non-decreasing was
// therefore asserting something the engine does not promise, and could fail on
// any NTP step. The seam lets such a test drive a strictly-increasing clock so
// the property holds by construction.
//
// The constructor's read is part of the seam and that is the load-bearing part:
// bootTimeUnixNs is the origin every relative lastChange is measured from, so an
// engine whose boot time came from the real clock and whose transitions come
// from an injected one subtracts a real timestamp from a fake one.

// TestInterfaceStateClockDefaultsToWallClock pins that production is unchanged:
// no injection means time.Now, at the same sites, with a boot time that tracks
// the real clock.
func TestInterfaceStateClockDefaultsToWallClock(t *testing.T) {
	before := uint64(time.Now().UnixNano())
	s := NewInterfaceState(4, nil, nil)
	after := uint64(time.Now().UnixNano())

	if s.now != nil {
		t.Error("NewInterfaceState installed a clock. Production must leave it nil so every read is " +
			"time.Now(), or the seam has changed behaviour rather than exposed it")
	}
	if s.bootTimeUnixNs < before || s.bootTimeUnixNs > after {
		t.Errorf("boot time %d is outside [%d, %d]: the default clock is not the wall clock",
			s.bootTimeUnixNs, before, after)
	}
	if ok, _ := s.SetOperStatus(1, OperDown); !ok {
		t.Fatal("SetOperStatus did not apply")
	}
	if lc := s.LastChangeNs(1); lc < before {
		t.Errorf("lastChange %d predates the test start %d; the setter is not reading the wall clock", lc, before)
	}
}

// TestInterfaceStateInjectedClockIsUsedEverywhere is the mutation-facing test:
// every one of the three reads must come from the injected clock. If the
// constructor still read time.Now() while the setters read the injection, the
// engine would subtract a real timestamp from a fake one and this fails.
func TestInterfaceStateInjectedClockIsUsedEverywhere(t *testing.T) {
	var tick atomic.Int64
	clock := func() time.Time { return time.Unix(0, tick.Add(1000)) }
	s := newInterfaceStateWithClock(4, nil, nil, clock)

	// The boot time came from the injected clock, so it is tiny rather than a
	// real Unix nanosecond count.
	if s.bootTimeUnixNs > 1_000_000 {
		t.Fatalf("boot time is %d, which is a real wall-clock reading: the constructor did not use "+
			"the injected clock, so every relative lastChange is measured against the wrong origin",
			s.bootTimeUnixNs)
	}

	// BOTH setters, because each reads the clock independently. An earlier cut
	// exercised only SetOperStatus, and reverting SetAdminStatus's read to
	// time.Now() was then detected by nothing: verified by mutation, not assumed.
	var prev uint64
	for i, want := range []uint8{OperDown, OperUp, OperDown} {
		if ok, _ := s.SetOperStatus(1, want); !ok {
			t.Fatalf("transition %d did not apply", i)
		}
		lc := s.LastChangeNs(1)
		if lc == LastChangeRewindSentinel {
			t.Fatalf("transition %d produced the rewind sentinel under a strictly-increasing clock. "+
				"That is the signature of a boot time and a transition time coming from different "+
				"clocks", i)
		}
		if i > 0 && lc <= prev {
			t.Errorf("transition %d: lastChange %d did not advance past %d under a strictly-increasing "+
				"clock", i, lc, prev)
		}
		prev = lc
	}

	// SetAdminStatus on its own interface, so the assertion is about that
	// setter's clock read and nothing else.
	if ok, _ := s.SetAdminStatus(2, AdminDown); !ok {
		t.Fatal("admin transition did not apply")
	}
	adminLC := s.LastChangeNs(2)
	if adminLC == LastChangeRewindSentinel {
		t.Fatal("SetAdminStatus produced the rewind sentinel under a strictly-increasing clock, which " +
			"is the signature of it reading a different clock from the constructor")
	}
	if adminLC > 1_000_000 {
		t.Errorf("SetAdminStatus stamped lastChange %d, a real wall-clock reading: it did not use the "+
			"injected clock", adminLC)
	}
}

// TestInterfaceStateInjectedClockCanStepBackwards keeps the rewind sentinel
// reachable. It is shipped production behaviour, so a seam that made it
// untestable would have traded one blind spot for another.
func TestInterfaceStateInjectedClockCanStepBackwards(t *testing.T) {
	var reading atomic.Int64
	reading.Store(5_000_000_000)
	s := newInterfaceStateWithClock(4, nil, nil, func() time.Time {
		return time.Unix(0, reading.Load())
	})

	// Step the clock behind the engine's boot time, as an NTP step would.
	reading.Store(1_000_000_000)
	if ok, _ := s.SetOperStatus(1, OperDown); !ok {
		t.Fatal("SetOperStatus did not apply")
	}
	if lc := s.LastChangeNs(1); lc != LastChangeRewindSentinel {
		t.Errorf("lastChange = %d, want the rewind sentinel %d. A transition timed before the engine's "+
			"boot time is exactly what the sentinel exists for, and it is what the flap test's "+
			"monotonicity assertion used to be exposed to", lc, LastChangeRewindSentinel)
	}
}

// TestInterfaceStateEqualClockReadingsAreNotADecrease covers the coarse-clock
// case named in wallRelNs: two transitions in the same tick carry equal
// lastChange, and equality is not a violation of a non-decreasing assertion.
func TestInterfaceStateEqualClockReadingsAreNotADecrease(t *testing.T) {
	frozen := time.Unix(0, 7_000_000_000)
	s := newInterfaceStateWithClock(4, nil, nil, func() time.Time { return frozen })

	if ok, _ := s.SetOperStatus(1, OperDown); !ok {
		t.Fatal("first transition did not apply")
	}
	first := s.LastChangeNs(1)
	if ok, _ := s.SetOperStatus(1, OperUp); !ok {
		t.Fatal("second transition did not apply")
	}
	second := s.LastChangeNs(1)

	if second != first {
		t.Errorf("two transitions under a frozen clock carry %d then %d, want equal values", first, second)
	}
	if second < first {
		t.Error("a frozen clock produced a decreasing lastChange")
	}
}
