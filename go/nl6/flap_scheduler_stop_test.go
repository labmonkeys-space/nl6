/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Awaited-Stop contract tests (#414). Ports of the syslog suite (#410):
// flap fires are inline in Run, so Run's exit is itself the fire barrier and
// Stop() blocking on runDone means "no scheduler-driven fire in flight".
// Flap has no injectable firer interface — the blocking point is the Tier C
// notify hook, which Broadcast invokes synchronously on oper transitions.
// All ordering synchronisation is via channels; timers appear only as
// positive-hold checks or generous failsafe deadlines.

package main

import (
	"container/heap"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// accelerateFlapEntries rewrites every scheduled entry to be due now so Run
// pops them immediately. Same idiom as TestFlapScheduler_StopUnblocksLimiterWait.
func accelerateFlapEntries(s *FlapScheduler) {
	s.mu.Lock()
	for _, e := range s.byKey {
		e.nextFire = s.now()
	}
	heap.Init(&s.heap)
	s.mu.Unlock()
}

// TestFlapSchedulerStop_BlocksUntilFireCompletes pins the core #414 contract:
// Stop() must not return while an inline fire is executing in Run, and the
// fire count is final once it returns.
func TestFlapSchedulerStop_BlocksUntilFireCompletes(t *testing.T) {
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 1})
	state := NewInterfaceState(1, nil, nil)
	state.Seed(1, OperUp, AdminUp)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var count atomic.Uint64
	state.SetNotify(func(StateChange) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		count.Add(1)
	})

	s.Register(net.IPv4(10, 0, 0, 1), []int{1}, IfFlapAggressive, state)
	accelerateFlapEntries(s)

	go s.Run(context.Background())

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no fire entered within 5s — scheduler not firing")
	}

	stopReturned := make(chan struct{})
	go func() {
		s.Stop()
		close(stopReturned)
	}()

	// Positive-hold check: with the fire blocked inside Run, Stop must not
	// have returned.
	select {
	case <-stopReturned:
		t.Fatal("Stop returned while a fire was still executing in Run")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)

	select {
	case <-stopReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after the fire was released")
	}

	final := count.Load()
	if final == 0 {
		t.Fatal("no fire completed")
	}
	time.Sleep(50 * time.Millisecond) // grace to catch a straggler increment
	if again := count.Load(); again != final {
		t.Fatalf("fire count moved after Stop returned: %d -> %d", final, again)
	}
}

// TestFlapSchedulerStop_NeverRunReturnsImmediately guards the started-flag:
// schedulers constructed but never run (plenty of tests do this) must not
// hang Stop.
func TestFlapSchedulerStop_NeverRunReturnsImmediately(t *testing.T) {
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 1})
	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked on a scheduler that was never Run")
	}
}

// TestFlapSchedulerStop_SurvivesFirePanic pins the panic path: unlike syslog,
// flap contains a panicking fire per-fire (fireWithRecover), so Run survives
// the panic, keeps scheduling, and a later Stop still awaits Run's clean exit.
// (Run's own top-level defer closes runDone before its recover, so even a
// panic escaping non-fire code cannot strand a Stop waiter.)
func TestFlapSchedulerStop_SurvivesFirePanic(t *testing.T) {
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 1})
	state := NewInterfaceState(1, nil, nil)
	state.Seed(1, OperUp, AdminUp)

	fired := make(chan struct{})
	var after atomic.Uint64
	var first atomic.Bool
	state.SetNotify(func(StateChange) {
		if first.CompareAndSwap(false, true) {
			close(fired)
			panic("boom (test)")
		}
		after.Add(1)
	})

	s.Register(net.IPv4(10, 0, 0, 1), []int{1}, IfFlapAggressive, state)
	accelerateFlapEntries(s)

	go s.Run(context.Background())

	select {
	case <-fired:
	case <-time.After(5 * time.Second):
		t.Fatal("no fire happened within 5s")
	}

	// Run must have survived the contained panic: accelerate the counterpart
	// event and require a post-panic fire.
	deadline := time.After(5 * time.Second)
	for after.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("no fire after the panicking one — Run did not survive the fire panic")
		case <-time.After(time.Millisecond):
			accelerateFlapEntries(s)
		}
	}

	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop hung after a fire panic — runDone not closed on Run's exit")
	}
}

// TestFlapSchedulerStop_BoundedUnderGlobalCap pins the stop-derived limiter
// context Stop's self-sufficiency depends on: with an awaited Stop, an
// un-derived ctx would make a bare Stop (no prior context cancel — unlike the
// StopFlapSubsystem choreography) inherit up to a full token interval, or
// hang if the context never dies.
func TestFlapSchedulerStop_BoundedUnderGlobalCap(t *testing.T) {
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 1, GlobalCapPerSecond: 1})
	state := NewInterfaceState(2, nil, nil)
	state.Seed(1, OperUp, AdminUp)
	state.Seed(2, OperUp, AdminUp)

	var count atomic.Uint64
	state.SetNotify(func(StateChange) { count.Add(1) })

	s.Register(net.IPv4(10, 0, 0, 1), []int{1, 2}, IfFlapAggressive, state)
	accelerateFlapEntries(s)

	go s.Run(context.Background())

	// Wait for the burst token to be consumed so Run parks in limiter.Wait.
	deadline := time.After(3 * time.Second)
	for count.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("first fire never happened")
		case <-time.After(time.Millisecond):
		}
	}

	start := time.Now()
	s.Stop()
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Fatalf("Stop took %v under cap=1/s — limiter wait not cancelled on stop", el)
	}
}
