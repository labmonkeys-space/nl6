/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// injectedTickNs is how far a test clock advances per reading, and
// wallClockFloorNs is the value below which a timestamp cannot be a real
// wall-clock reading (a real UnixNano is ~1.7e18). Named and kept together so
// raising the tick cannot silently invalidate the threshold that distinguishes
// an injected stamp from a real one.
const (
	injectedTickNs   = 1000
	wallClockFloorNs = uint64(1_000_000_000)
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

	// Deliberately NOT asserting that s.now is nil. The clock is normalised to
	// time.Now at construction, matching the four other clock seams in this
	// package, so pinning the field's nil-ness would pin an implementation
	// detail and make converging on that shape a test failure rather than a
	// refactor. What matters is the BEHAVIOUR asserted below: an un-injected
	// engine reads the real wall clock.
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
	clock := func() time.Time { return time.Unix(0, tick.Add(injectedTickNs)) }
	s := newInterfaceStateWithClock(4, nil, nil, clock)

	// The boot time came from the injected clock, so it is tiny rather than a
	// real Unix nanosecond count.
	if s.bootTimeUnixNs > wallClockFloorNs {
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
		// MAGNITUDE, not just ordering. Review demonstrated that without this
		// the setter reverting to time.Now() is caught only by clock
		// granularity: on darwin 964/1000 back-to-back time.Now() pairs are
		// identical so it trips the ordering check, while on a ns-resolution
		// Linux clock both readings differ and the mutant survives.
		if lc > wallClockFloorNs {
			t.Errorf("transition %d stamped lastChange %d, which is a real wall-clock reading: that "+
				"setter is not using the injected clock", i, lc)
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
	if adminLC > wallClockFloorNs {
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
	// The frozen reading is OFFSET from the boot reading, deliberately. An
	// earlier cut froze the clock at the same instant the constructor captured,
	// so relNs was 0 and lastChange equalled exactly what LastChangeNs returns
	// for a slot that never transitioned: review demonstrated the test stayed
	// green when SetOperStatus was mutated to carry the previous relNs forward
	// and never restamp.
	reading := time.Unix(0, 7_000_000_000)
	s := newInterfaceStateWithClock(4, nil, nil, func() time.Time { return reading })
	untouched := s.LastChangeNs(1)
	reading = time.Unix(0, 9_000_000_000) // frozen, but past boot

	if ok, _ := s.SetOperStatus(1, OperDown); !ok {
		t.Fatal("first transition did not apply")
	}
	first := s.LastChangeNs(1)
	if ok, _ := s.SetOperStatus(1, OperUp); !ok {
		t.Fatal("second transition did not apply")
	}
	second := s.LastChangeNs(1)

	if first == untouched {
		t.Errorf("lastChange after a transition (%d) equals the never-transitioned value (%d), so this "+
			"test cannot tell a stamped timestamp from an unstamped slot", first, untouched)
	}
	if second != first {
		t.Errorf("two transitions under a frozen clock carry %d then %d, want equal values", first, second)
	}
	if second < first {
		t.Error("a frozen clock produced a decreasing lastChange")
	}
}

// TestInterfaceStateClockSampleStaysInsideTheCASLoop is the guard for the
// property this change newly asserts in prose and nothing pinned.
//
// Both setters sample the clock INSIDE the CAS loop so that a retry records the
// timestamp of the WINNING attempt, not of the attempt that entered the
// function. Hoisting the sample above `for {` reads as a harmless refactor and
// is not: a mutator that loses several CAS rounds then stamps the slot with a
// timestamp older than one already stored, and LastChangeNs goes BACKWARDS for
// a collector.
//
// Review demonstrated the gap rather than arguing it: with the sample hoisted in
// both setters the entire package stayed green, because the flap test has a
// SINGLE writer so its CAS never retries, and TestInterfaceState_ConcurrentCAS_
// NoLostTransitions has eight writers but reads no timestamp. This test is the
// intersection the suite was missing: real CAS contention AND a timestamp read.
func TestInterfaceStateClockSampleStaysInsideTheCASLoop(t *testing.T) {
	var tick atomic.Int64
	s := newInterfaceStateWithClock(1, nil, nil, func() time.Time {
		return time.Unix(0, tick.Add(injectedTickNs))
	})

	const writers = 8
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var regressions atomic.Int64

	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// Alternating targets on ONE slot, so the writers genuinely contend
			// and the CAS retry path is executed rather than merely present.
			want := []uint8{OperUp, OperDown}[w%2]
			for {
				select {
				case <-stop:
					return
				default:
					s.SetOperStatus(1, want)
				}
			}
		}(w)
	}

	wg.Add(1)
	go func() { // reader
		defer wg.Done()
		var prev uint64
		for {
			select {
			case <-stop:
				return
			default:
				lc := s.LastChangeNs(1)
				if lc == LastChangeRewindSentinel {
					continue // not what this test is about
				}
				if lc < prev {
					regressions.Add(1)
				}
				prev = lc
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()

	if got := regressions.Load(); got != 0 {
		t.Errorf("LastChangeNs went backwards %d times under CAS contention with a strictly-increasing "+
			"clock.\nThat is the signature of the clock being sampled OUTSIDE the CAS loop: a mutator "+
			"that loses several rounds stamps the slot with a timestamp older than one already stored, "+
			"and ifLastChange / gNMI last-change go backwards for a collector whenever REST and the "+
			"flap scheduler contend on one interface", got)
	}
}

// TestInterfaceStateSnapshotAgreesWithLastChangeNs covers the third copy of the
// sentinel-and-absolute reconstruction. LastChangeNs, Snapshot and lastChangeAbs
// each rebuild it, and Snapshot is the accessor callers are told to use for a
// consistent multi-leaf view, yet every other test here reads only LastChangeNs.
func TestInterfaceStateSnapshotAgreesWithLastChangeNs(t *testing.T) {
	var tick atomic.Int64
	s := newInterfaceStateWithClock(2, nil, nil, func() time.Time {
		return time.Unix(0, tick.Add(injectedTickNs))
	})
	if ok, _ := s.SetOperStatus(1, OperDown); !ok {
		t.Fatal("transition did not apply")
	}
	if snap := s.Snapshot(1); snap.LastChangeNs != s.LastChangeNs(1) {
		t.Errorf("Snapshot reports lastChange %d, LastChangeNs reports %d; the two reconstructions "+
			"have diverged", snap.LastChangeNs, s.LastChangeNs(1))
	}

	// And under rewind, where the two copies are most likely to drift. The clock
	// must read LATER at construction and earlier at the transition; a constant
	// clock gives boot == now, which is rel 0 and not a rewind at all.
	var reading atomic.Int64
	reading.Store(5_000_000_000)
	back := newInterfaceStateWithClock(2, nil, nil, func() time.Time {
		return time.Unix(0, reading.Load())
	})
	reading.Store(1_000_000_000) // steps behind boot
	if ok, _ := back.SetOperStatus(1, OperDown); !ok {
		t.Fatal("rewind transition did not apply")
	}
	if snap := back.Snapshot(1); snap.LastChangeNs != LastChangeRewindSentinel {
		t.Errorf("Snapshot reports %d under a rewound clock, want the sentinel %d",
			snap.LastChangeNs, LastChangeRewindSentinel)
	}
}

// TestInterfaceStateSetterReturnsTheSameClockReading pins the event the setters
// return. Both build StateChange{LastChangeNs, At} from the same clock read, and
// that event is what Broadcast, the Tier-C notify hook and gNMI ON_CHANGE
// consume. Every other test here reads the slot back and discards the event, so
// a setter stamping At from time.Now() while relNs used the injected clock was
// invisible.
func TestInterfaceStateSetterReturnsTheSameClockReading(t *testing.T) {
	var tick atomic.Int64
	s := newInterfaceStateWithClock(2, nil, nil, func() time.Time {
		return time.Unix(0, tick.Add(injectedTickNs))
	})

	ok, ev := s.SetOperStatus(1, OperDown)
	if !ok {
		t.Fatal("transition did not apply")
	}
	if ev.LastChangeNs != s.LastChangeNs(1) {
		t.Errorf("the returned event carries lastChange %d, the slot carries %d", ev.LastChangeNs, s.LastChangeNs(1))
	}
	if uint64(ev.At.UnixNano()) > wallClockFloorNs {
		t.Errorf("the returned event's At is %d, a real wall-clock reading: the setter stamped the "+
			"event from time.Now() while the slot used the injected clock", ev.At.UnixNano())
	}
}
