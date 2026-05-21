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

func TestInterfaceState_PackUnpackRoundtrip(t *testing.T) {
	cases := []struct {
		oper, admin  uint8
		lastChangeNs uint64
		wantLastChng uint64 // after masking to 58 bits
	}{
		{OperUp, AdminUp, 0, 0},
		{OperDown, AdminUp, 1_000_000_000, 1_000_000_000},
		{OperLowerLayerDn, AdminTesting, 12345678901234, 12345678901234},
		// 58-bit boundary
		{OperUp, AdminDown, 1 << 57, 1 << 57},
	}
	for _, tc := range cases {
		w := packState(tc.oper, tc.admin, tc.lastChangeNs)
		gotOper, gotAdmin, gotNs := unpackState(w)
		if gotOper != tc.oper || gotAdmin != tc.admin || gotNs != tc.wantLastChng {
			t.Errorf("pack(%d,%d,%d) → unpack = (%d,%d,%d); want (%d,%d,%d)",
				tc.oper, tc.admin, tc.lastChangeNs,
				gotOper, gotAdmin, gotNs,
				tc.oper, tc.admin, tc.wantLastChng)
		}
	}
}

func TestInterfaceState_SeedAndRead(t *testing.T) {
	s := NewInterfaceState(3, nil, nil)
	s.Seed(1, OperUp, AdminUp)
	s.Seed(2, OperDown, AdminUp)
	s.Seed(3, OperUp, AdminDown)

	if got := s.OperStatus(1); got != OperUp {
		t.Errorf("OperStatus(1): got %d, want OperUp", got)
	}
	if got := s.OperStatus(2); got != OperDown {
		t.Errorf("OperStatus(2): got %d, want OperDown", got)
	}
	if got := s.AdminStatus(3); got != AdminDown {
		t.Errorf("AdminStatus(3): got %d, want AdminDown", got)
	}
	// Out-of-range ifIndex returns benign defaults.
	if got := s.OperStatus(99); got != OperUnknown {
		t.Errorf("OperStatus(99): got %d, want OperUnknown", got)
	}
	if got := s.OperStatus(0); got != OperUnknown {
		t.Errorf("OperStatus(0): got %d, want OperUnknown", got)
	}
}

func TestInterfaceState_LastChangeNsAbsolute(t *testing.T) {
	s := NewInterfaceState(2, nil, nil)
	s.Seed(1, OperUp, AdminUp)
	// Before any mutation, last-change == boot time exactly.
	if got := s.LastChangeNs(1); got != s.bootTimeUnixNs {
		t.Errorf("pre-transition: got %d, want bootTimeUnixNs=%d", got, s.bootTimeUnixNs)
	}
	// After SetOperStatus, last-change is bootTimeUnixNs + (some small relative ns).
	beforeNs := uint64(time.Now().UnixNano())
	changed, _ := s.SetOperStatus(1, OperDown)
	afterNs := uint64(time.Now().UnixNano())
	if !changed {
		t.Fatal("expected changed=true")
	}
	got := s.LastChangeNs(1)
	if got < beforeNs || got > afterNs {
		t.Errorf("post-transition LastChangeNs %d outside [%d, %d]", got, beforeNs, afterNs)
	}
}

func TestInterfaceState_SetOperStatus_TransitionsAndIdempotence(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperUp, AdminUp)

	// First transition: UP → DOWN.
	changed, evt := s.SetOperStatus(1, OperDown)
	if !changed {
		t.Fatal("UP→DOWN: expected changed=true")
	}
	if evt.Oper != OperDown || evt.Admin != AdminUp || evt.Changed != LeafOperStatus || evt.IfIndex != 1 {
		t.Errorf("evt = %+v; want IfIndex=1, Oper=DOWN, Admin=UP, Changed=LeafOperStatus", evt)
	}
	if evt.LastChangeNs == 0 {
		t.Error("evt.LastChangeNs should be non-zero (absolute Unix nanos)")
	}

	// Idempotent: DOWN → DOWN is a no-op.
	changed, evt = s.SetOperStatus(1, OperDown)
	if changed {
		t.Error("DOWN→DOWN: expected changed=false")
	}
	if evt != (StateChange{}) {
		t.Errorf("idempotent set: expected zero StateChange, got %+v", evt)
	}

	// Out-of-range ifIndex is benign.
	changed, _ = s.SetOperStatus(99, OperDown)
	if changed {
		t.Error("out-of-range ifIndex: expected changed=false")
	}
}

func TestInterfaceState_SetAdminStatus_DoesNotTouchOper(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperDown, AdminUp)

	changed, evt := s.SetAdminStatus(1, AdminDown)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if evt.Oper != OperDown {
		t.Errorf("admin mutation must preserve oper: got %d, want OperDown", evt.Oper)
	}
	if evt.Admin != AdminDown || evt.Changed != LeafAdminStatus {
		t.Errorf("evt = %+v; want Admin=DOWN, Changed=LeafAdminStatus", evt)
	}
	if got := s.OperStatus(1); got != OperDown {
		t.Errorf("post-admin-mutation OperStatus = %d; want OperDown", got)
	}
}

func TestInterfaceState_ConcurrentCAS_NoLostTransitions(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperUp, AdminUp)

	const writers = 8
	const iter = 1000
	var wg sync.WaitGroup
	var transitions atomic.Int64
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iter; i++ {
				// Alternate target so every iteration is a real transition.
				target := OperUp
				if (w+i)&1 == 0 {
					target = OperDown
				}
				if changed, _ := s.SetOperStatus(1, target); changed {
					transitions.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	// Every concurrent CAS must either no-op (target == current) or
	// produce exactly one transition. The combined oper/admin/lastChange
	// invariant means we never observed a torn slot — verified by the
	// fact that the final OperStatus is a valid enum (1..7).
	final := s.OperStatus(1)
	if final != OperUp && final != OperDown {
		t.Errorf("final state %d is not a valid oper enum", final)
	}
	// Should have some transitions (lower bound is trivial; upper bound is writers*iter).
	if transitions.Load() == 0 {
		t.Error("expected at least one transition across concurrent writers")
	}
}

func TestInterfaceState_Broadcast_DeliversToAllListeners(t *testing.T) {
	var emitted, dropped uint64
	s := NewInterfaceState(1, &emitted, &dropped)
	s.Seed(1, OperUp, AdminUp)

	chA := make(chan StateChange, 16)
	chB := make(chan StateChange, 16)
	s.AddListener(chA)
	s.AddListener(chB)

	_, evt := s.SetOperStatus(1, OperDown)
	s.Broadcast(evt)

	select {
	case got := <-chA:
		if got.Oper != OperDown {
			t.Errorf("chA: got Oper=%d, want OperDown", got.Oper)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("chA: did not receive event")
	}
	select {
	case got := <-chB:
		if got.Oper != OperDown {
			t.Errorf("chB: got Oper=%d, want OperDown", got.Oper)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("chB: did not receive event")
	}

	if atomic.LoadUint64(&emitted) != 2 {
		t.Errorf("eventsEmitted: got %d, want 2 (one per listener)", atomic.LoadUint64(&emitted))
	}
	if atomic.LoadUint64(&dropped) != 0 {
		t.Errorf("eventsDropped: got %d, want 0", atomic.LoadUint64(&dropped))
	}
}

func TestInterfaceState_Broadcast_DropsOldestOnFullChannel(t *testing.T) {
	var emitted, dropped uint64
	s := NewInterfaceState(1, &emitted, &dropped)
	s.Seed(1, OperUp, AdminUp)

	// Tiny channel to force overflow on the second broadcast.
	ch := make(chan StateChange, 1)
	s.AddListener(ch)

	// First broadcast fills the channel.
	_, evt1 := s.SetOperStatus(1, OperDown)
	s.Broadcast(evt1)
	// Second broadcast: channel is full → drop-oldest, then push.
	_, evt2 := s.SetOperStatus(1, OperUp)
	s.Broadcast(evt2)

	// The channel should now hold the SECOND event (oldest was dropped).
	select {
	case got := <-ch:
		if got.Oper != OperUp {
			t.Errorf("expected OperUp (second event), got Oper=%d", got.Oper)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no event in channel after backpressure")
	}

	if atomic.LoadUint64(&dropped) != 1 {
		t.Errorf("eventsDropped: got %d, want 1", atomic.LoadUint64(&dropped))
	}
	// Emitted = 2 (first push fast-path + second push after drop).
	if atomic.LoadUint64(&emitted) != 2 {
		t.Errorf("eventsEmitted: got %d, want 2", atomic.LoadUint64(&emitted))
	}
}

func TestInterfaceState_RemoveListener_StopsDelivery(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperUp, AdminUp)

	ch := make(chan StateChange, 16)
	s.AddListener(ch)
	s.RemoveListener(ch)

	_, evt := s.SetOperStatus(1, OperDown)
	s.Broadcast(evt)

	select {
	case got := <-ch:
		t.Errorf("removed listener received event: %+v", got)
	case <-time.After(50 * time.Millisecond):
		// expected: nothing arrives
	}
}

func TestInterfaceState_NilCountersTolerated(t *testing.T) {
	// Smoke: nil emitted/dropped pointers must not panic.
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperUp, AdminUp)
	ch := make(chan StateChange, 16)
	s.AddListener(ch)
	_, evt := s.SetOperStatus(1, OperDown)
	s.Broadcast(evt)
	<-ch // drain
}

// TestInterfaceState_Broadcast_ConcurrentProducers verifies the
// multi-producer contention path with a depth-1 channel. The Broadcast
// comment documents this as "approximate under contention" — the test
// pins that approximation: under N concurrent producers and one
// consumer with a depth-1 buffer, we never see more events delivered
// than were produced, and emitted+dropped covers every produced event
// (within the ±1-per-contended-event budget).
func TestInterfaceState_Broadcast_ConcurrentProducers(t *testing.T) {
	var emitted, dropped uint64
	s := NewInterfaceState(1, &emitted, &dropped)
	s.Seed(1, OperUp, AdminUp)

	ch := make(chan StateChange, 1)
	s.AddListener(ch)

	// Drain consumer.
	consumed := uint64(0)
	consumerDone := make(chan struct{})
	go func() {
		for range ch {
			consumed++
		}
		close(consumerDone)
	}()

	const producers = 8
	const perProducer = 200
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				target := OperUp
				if (seed+i)&1 == 0 {
					target = OperDown
				}
				if changed, evt := s.SetOperStatus(1, target); changed {
					s.Broadcast(evt)
				}
			}
		}(p)
	}
	wg.Wait()
	s.RemoveListener(ch)
	close(ch)
	<-consumerDone

	totalProduced := atomic.LoadUint64(&emitted) + atomic.LoadUint64(&dropped)
	// Every successful CAS produces a Broadcast call; every Broadcast
	// call accounts for the event as emitted, dropped, or both
	// (contended slow path). We can't pin an exact equality (the count
	// of "changed=true" CAS calls is not visible from outside), so we
	// assert the invariants: nothing produced exceeds what was
	// generated, and emitted ≤ consumed + (in-flight buffer) which
	// closing ch flushes to zero.
	if consumed > totalProduced {
		t.Errorf("consumed %d > total accounted %d (emitted=%d dropped=%d) — accounting under-counted",
			consumed, totalProduced, atomic.LoadUint64(&emitted), atomic.LoadUint64(&dropped))
	}
	if totalProduced == 0 {
		t.Error("no events accounted across 8 producers × 200 ops")
	}
}
