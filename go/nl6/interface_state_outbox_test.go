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

// Several producers change one interface at once. Every listener must see the
// events in the order of the mutations: each event starts from the oper-status
// the one before it ended on, and the last event is the engine's state.
func TestStateChangesArriveInMutationOrder(t *testing.T) {
	f := newLLDPFixture(t)
	dev := f.addDevice(t, 1, 4, "alpha")
	st := deviceInterfaceState(dev)
	ip := dev.IP.String()
	const ifIndex, workers, rounds = 3, 4, 500

	ch := make(chan StateChange, 1<<16) // deeper than every event of the run, so drop-oldest never applies
	st.AddListener(ch)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if w%2 == 0 {
					target := uint8(AdminDown)
					if i%2 == 1 {
						target = AdminUp
					}
					f.mgr.publishStateChanges(ip, st, ifIndex, st.ApplyAdminStatus(ifIndex, target))
					continue
				}
				target := uint8(OperDown)
				if i%2 == 1 {
					target = OperUp
				}
				if res, evts := st.SetLinkState(ifIndex, target); res != LinkUnchanged {
					f.mgr.publishStateChanges(ip, st, ifIndex, evts)
				}
			}
		}(w)
	}
	wg.Wait()
	st.RemoveListener(ch) // before close: Broadcast must never send to a closed channel
	close(ch)

	wantMutationOrder(t, ch, st, ifIndex)
}

// wantMutationOrder reads a closed listener channel and asserts that the
// events of ifIndex form one chain: each starts from the oper-status the one
// before it ended on, an admin event that moved oper is followed directly by
// its twin, and the last event is the engine's state.
func wantMutationOrder(t *testing.T, ch <-chan StateChange, st *InterfaceState, ifIndex int) {
	t.Helper()
	var prev *StateChange
	n := 0
	for evt := range ch {
		if evt.IfIndex != ifIndex {
			continue
		}
		n++
		if prev != nil {
			wantTwin := prev.Changed == LeafAdminStatus && prev.PrevOper != prev.Oper
			isTwin := evt.Changed == LeafOperStatus && evt.At.Equal(prev.At) && evt.PrevOper == prev.PrevOper && evt.Oper == prev.Oper
			switch {
			case wantTwin && !isTwin:
				t.Fatalf("event %d: an admin event that moved oper is not followed by its twin", n)
			case !wantTwin && evt.PrevOper != prev.Oper:
				t.Fatalf("event %d starts from oper %d, the one before ended on %d", n, evt.PrevOper, prev.Oper)
			}
		}
		prev = &evt
	}
	if prev == nil {
		t.Fatal("no events")
	}
	if snap := st.Snapshot(ifIndex); prev.Admin != snap.Admin || prev.Oper != st.OperStatus(ifIndex) {
		t.Fatalf("last event admin=%d oper=%d, engine admin=%d oper=%d", prev.Admin, prev.Oper, snap.Admin, st.OperStatus(ifIndex))
	}
}

// blockFirstNotify installs a notify hook that blocks on its first call until
// release is closed, and reports the entry on entered. A watchdog closes
// release after two seconds and sets stalled, so a producer that waits behind
// the blocked drain fails the test instead of hanging it.
func blockFirstNotify(t *testing.T, st *InterfaceState) (entered <-chan struct{}, release func(), stalled *atomic.Bool) {
	t.Helper()
	in, out := make(chan struct{}), make(chan struct{})
	var first, once sync.Once
	stalled = &atomic.Bool{}
	release = func() { once.Do(func() { close(out) }) }
	st.SetNotify(func(StateChange) {
		first.Do(func() {
			close(in)
			<-out
		})
	})
	watchdog := time.AfterFunc(2*time.Second, func() {
		stalled.Store(true)
		release()
	})
	t.Cleanup(func() {
		watchdog.Stop()
		release()
	})
	return in, release, stalled
}

// One producer sees its events out before Deliver returns, and a mutation
// that moved nothing queues nothing.
func TestDeliverSingleProducerIsSynchronous(t *testing.T) {
	st := NewInterfaceState(4, nil, nil)
	ch := make(chan StateChange, 16)
	st.AddListener(ch)

	st.Deliver()
	if len(ch) != 0 {
		t.Fatalf("empty outbox delivered %d events", len(ch))
	}
	evts := st.ApplyAdminStatus(1, AdminDown)
	if len(evts) != 2 {
		t.Fatalf("admin down returned %d events, want 2", len(evts))
	}
	if len(ch) != 0 {
		t.Fatalf("mutator delivered %d events itself", len(ch))
	}
	st.Deliver()
	if len(ch) != 2 {
		t.Fatalf("delivered %d events, want 2", len(ch))
	}
	admin, oper := <-ch, <-ch
	if admin.Changed != LeafAdminStatus || oper.Changed != LeafOperStatus || !admin.At.Equal(oper.At) {
		t.Fatalf("want the admin event then its twin, got %+v then %+v", admin, oper)
	}
	if again := st.ApplyAdminStatus(1, AdminDown); again != nil {
		t.Fatalf("same value returned %d events", len(again))
	}
	st.Deliver()
	if len(ch) != 0 {
		t.Fatalf("a mutation that moved nothing delivered %d events", len(ch))
	}
}

// A drain blocked in the notify hook does not block other producers, and
// their events follow in mutation order once it resumes.
func TestDeliverBlockedDrainKeepsOrder(t *testing.T) {
	st := NewInterfaceState(4, nil, nil)
	ch := make(chan StateChange, 16)
	st.AddListener(ch)
	entered, release, stalled := blockFirstNotify(t, st)

	done := make(chan struct{})
	go func() {
		defer close(done)
		st.SetLinkState(1, OperDown)
		st.Deliver()
	}()
	<-entered

	st.SetLinkState(1, OperUp)
	st.Deliver()
	if stalled.Load() {
		t.Fatal("a second producer waited behind the blocked drain")
	}
	if len(ch) != 1 {
		t.Fatalf("%d events out while the drain is blocked, want 1", len(ch))
	}
	release()
	<-done
	if len(ch) != 2 {
		t.Fatalf("%d events after release, want 2", len(ch))
	}
	if first, second := <-ch, <-ch; first.Oper != OperDown || second.Oper != OperUp {
		t.Fatalf("order is oper %d then %d, want down then up", first.Oper, second.Oper)
	}
}

// A panic in the notify hook reaches the caller, loses no event behind the
// one that caused it, and leaves the engine able to deliver.
func TestDeliverSurvivesNotifyPanic(t *testing.T) {
	st := NewInterfaceState(4, nil, nil)
	ch := make(chan StateChange, 16)
	st.AddListener(ch)
	var once sync.Once
	st.SetNotify(func(StateChange) {
		once.Do(func() { panic("notify hook failed") })
	})

	st.SetLinkState(1, OperDown)
	st.SetLinkState(2, OperDown)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the panic did not reach the caller")
			}
		}()
		st.Deliver()
	}()
	if len(ch) != 1 {
		t.Fatalf("%d events out after the panic, want 1", len(ch))
	}
	if evt := <-ch; evt.IfIndex != 1 {
		t.Fatalf("first event is for interface %d, want 1", evt.IfIndex)
	}
	st.Deliver()
	if len(ch) != 1 {
		t.Fatalf("%d events out after the second drain, want 1", len(ch))
	}
	if evt := <-ch; evt.IfIndex != 2 {
		t.Fatalf("second event is for interface %d, want 2", evt.IfIndex)
	}
}
