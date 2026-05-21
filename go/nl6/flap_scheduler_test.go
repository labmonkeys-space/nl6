/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"container/heap"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// drainEvents pulls every event off ch with a brief timeout per call. The
// scheduler tests are tight: a stalled drain means the broadcast path is
// stuck and the test should fail loudly.
func drainEvents(ch chan StateChange, want int, timeout time.Duration) []StateChange {
	got := make([]StateChange, 0, want)
	deadline := time.After(timeout)
	for len(got) < want {
		select {
		case ev := <-ch:
			got = append(got, ev)
		case <-deadline:
			return got
		}
	}
	return got
}

func TestFlapScheduler_ValidFlapScenario(t *testing.T) {
	for _, s := range []IfFlapScenario{IfFlapClean, IfFlapRare, IfFlapTypical, IfFlapAggressive} {
		if !ValidFlapScenario(s) {
			t.Errorf("ValidFlapScenario(%q) = false; want true", s)
		}
	}
	for _, s := range []IfFlapScenario{"", "blast", "Clean", "aggresive"} {
		if ValidFlapScenario(s) {
			t.Errorf("ValidFlapScenario(%q) = true; want false", s)
		}
	}
}

func TestFlapScheduler_CleanScenarioNoEvents(t *testing.T) {
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 1})
	state := NewInterfaceState(2, nil, nil)
	state.Seed(1, OperUp, AdminUp)
	state.Seed(2, OperUp, AdminUp)
	ch := make(chan StateChange, 16)
	state.AddListener(ch)

	s.Register(net.IPv4(10, 0, 0, 1), []int{1, 2}, IfFlapClean, state)

	if got := s.pendingCountForTest(); got != 0 {
		t.Errorf("clean scenario: pending=%d, want 0", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	time.Sleep(50 * time.Millisecond)
	s.Stop()
	<-done

	select {
	case ev := <-ch:
		t.Errorf("clean scenario fired event: %+v", ev)
	default:
	}
}

func TestFlapScheduler_AggressiveScenarioFiresDownThenUp(t *testing.T) {
	// Aggressive: mean=1min between flap cycles; uniform 1-5s down
	// duration. With one interface starting at boot we should see at
	// least one (down, up) pair within ~6s. Use real time to keep the
	// state-machine sequencing honest.
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 42})
	state := NewInterfaceState(1, nil, nil)
	state.Seed(1, OperUp, AdminUp)
	ch := make(chan StateChange, 64)
	state.AddListener(ch)

	// Cheat: register with a very short mean by using flapBand's
	// `IfFlapAggressive` value (1 min). To make the test fast we'd want
	// a much smaller mean. Instead, manually push a single immediate
	// down event into the heap to short-circuit the wait.
	s.Register(net.IPv4(10, 0, 0, 1), []int{1}, IfFlapAggressive, state)

	// Forcibly accelerate: re-seed the entry's nextFire to now.
	s.mu.Lock()
	for _, e := range s.byKey {
		e.nextFire = s.now()
	}
	// Re-establish heap invariant after bulk mutation. heap.Init
	// O(n) re-heapifies the underlying slice; the prior Swap-loop did
	// not actually restore the invariant — it only worked by accident
	// because all nextFire values were equal.
	heap.Init(&s.heap)
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	// Expect: one down event (oper UP→DOWN), then one up event within
	// the 1-5s uniform window.
	events := drainEvents(ch, 2, 7*time.Second)
	s.Stop()
	<-done

	if len(events) < 2 {
		t.Fatalf("got %d events, want at least 2 (down + up)", len(events))
	}
	if events[0].Oper != OperDown {
		t.Errorf("first event Oper = %d, want OperDown (2)", events[0].Oper)
	}
	if events[1].Oper != OperUp {
		t.Errorf("second event Oper = %d, want OperUp (1)", events[1].Oper)
	}
	// Down→up gap must fall within [1s, 5s] (aggressive band, ±100ms slack
	// for goroutine wakeup jitter).
	gap := events[1].At.Sub(events[0].At)
	if gap < 900*time.Millisecond || gap > 5500*time.Millisecond {
		t.Errorf("down→up gap = %v; want in [1s, 5s]", gap)
	}
}

func TestFlapScheduler_GlobalCapHonored(t *testing.T) {
	const capPerSec = 10
	s := NewFlapScheduler(FlapSchedulerOptions{
		GlobalCapPerSecond: capPerSec,
		Seed:               7,
	})

	// Many devices × many interfaces, all accelerated to immediate.
	const N = 100
	const ifsPerDev = 5
	states := make([]*InterfaceState, N)
	for d := 0; d < N; d++ {
		states[d] = NewInterfaceState(ifsPerDev, nil, nil)
		for i := 1; i <= ifsPerDev; i++ {
			states[d].Seed(i, OperUp, AdminUp)
		}
		s.Register(net.IPv4(10, byte(d>>8), byte(d&0xff), 1),
			[]int{1, 2, 3, 4, 5}, IfFlapAggressive, states[d])
	}

	// Accelerate every entry to fire immediately. heap.Init restores
	// the invariant after the bulk mutation.
	s.mu.Lock()
	for _, e := range s.byKey {
		e.nextFire = s.now()
	}
	heap.Init(&s.heap)
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	// Count total fires by listening on a shared collector channel per
	// state. Each listener channel is closed after the scheduler has
	// stopped so the consumer goroutines exit cleanly (no leak across
	// test runs).
	var totalFires atomic.Uint64
	var wg sync.WaitGroup
	chans := make([]chan StateChange, N)
	for d := 0; d < N; d++ {
		ch := make(chan StateChange, 64)
		chans[d] = ch
		states[d].AddListener(ch)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ev := range ch {
				_ = ev
				totalFires.Add(1)
			}
		}()
	}

	time.Sleep(2 * time.Second)
	s.Stop()
	<-done

	// Drain by removing listeners and closing channels — no Broadcast
	// can land after Stop, so close is safe.
	for d := 0; d < N; d++ {
		states[d].RemoveListener(chans[d])
		close(chans[d])
	}
	wg.Wait()

	fires := totalFires.Load()

	// Over 2 seconds at cap=10/s we expect ≤ 20 + initial burst (cap=10)
	// = 30. Allow goroutine-wakeup slack: cap × 4 = 40.
	if fires > 40 {
		t.Errorf("global cap breached: %d fires in 2s with cap=%d/s (want ≤ 40)", fires, capPerSec)
	}
	if fires < 5 {
		t.Errorf("too few fires: %d in 2s with cap=%d/s (want ≥ 5)", fires, capPerSec)
	}
}

func TestFlapScheduler_DeregisterRemovesAllEntries(t *testing.T) {
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 11})
	state := NewInterfaceState(3, nil, nil)
	for i := 1; i <= 3; i++ {
		state.Seed(i, OperUp, AdminUp)
	}
	ip := net.IPv4(10, 0, 0, 5)
	s.Register(ip, []int{1, 2, 3}, IfFlapTypical, state)
	if got := s.pendingCountForTest(); got != 3 {
		t.Fatalf("post-register pending = %d, want 3", got)
	}
	s.Deregister(ip)
	if got := s.pendingCountForTest(); got != 0 {
		t.Errorf("post-deregister pending = %d, want 0", got)
	}
}

func TestFlapScheduler_PoissonDistributionShape(t *testing.T) {
	// Verify Poisson inter-arrival shape: over many samples drawn from
	// ExpFloat64 × meanInterval, the empirical mean is within ±10% of
	// the configured mean. This is a sanity check on the math, not a
	// full goodness-of-fit test.
	const samples = 5000
	mean, _, _ := flapBand(IfFlapTypical)
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 99})

	total := time.Duration(0)
	s.mu.Lock()
	for i := 0; i < samples; i++ {
		total += time.Duration(s.rnd.ExpFloat64() * float64(mean))
	}
	s.mu.Unlock()
	empirical := total / samples

	lo := time.Duration(float64(mean) * 0.9)
	hi := time.Duration(float64(mean) * 1.1)
	if empirical < lo || empirical > hi {
		t.Errorf("empirical mean = %v, want in [%v, %v]", empirical, lo, hi)
	}
}

func TestFlapScheduler_StopUnwindsCleanly(t *testing.T) {
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 1})
	state := NewInterfaceState(1, nil, nil)
	state.Seed(1, OperUp, AdminUp)
	s.Register(net.IPv4(10, 0, 0, 1), []int{1}, IfFlapTypical, state)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	s.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not exit within 1s of Stop()")
	}

	// Stop is idempotent.
	s.Stop()
}

// TestFlapScheduler_ConcurrentRegisterDuringRun stresses the
// Register-during-Run path that the rest of the suite doesn't probe.
// Registers and Deregisters interleaved with the scheduler firing
// events; verifies no panics, no data races (run under -race), and a
// graceful Stop afterwards.
func TestFlapScheduler_ConcurrentRegisterDuringRun(t *testing.T) {
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 1, GlobalCapPerSecond: 100})

	const N = 32
	states := make([]*InterfaceState, N)
	for i := 0; i < N; i++ {
		states[i] = NewInterfaceState(4, nil, nil)
		for ifI := 1; ifI <= 4; ifI++ {
			states[i].Seed(ifI, OperUp, AdminUp)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	// Two churners: one Registers + Deregisters new devices, another
	// repeatedly Registers and Deregisters a fixed pool.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for d := 0; d < N; d++ {
				ip := net.IPv4(10, 0, byte(d>>8), byte(d&0xff))
				s.Register(ip, []int{1, 2, 3, 4}, IfFlapAggressive, states[d])
			}
			for d := 0; d < N; d++ {
				ip := net.IPv4(10, 0, byte(d>>8), byte(d&0xff))
				s.Deregister(ip)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			ip := net.IPv4(192, 168, 0, 1)
			s.Register(ip, []int{1, 2}, IfFlapTypical, states[0])
			s.Deregister(ip)
		}
	}()

	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
	s.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit within 2s after Stop")
	}
}

// TestFlapScheduler_StopUnblocksLimiterWait — H1/H2 regression: a
// scheduler with an aggressively low rate cap that has burned its
// burst should unblock Run when Stop is called, even though
// limiter.Wait would otherwise block until the next token.
//
// Without the H1/H2 fix (cancellable context paired with Stop), Run
// would remain blocked indefinitely after Stop. The fix lives in
// flap_manager.go (StartFlapSubsystem/StopFlapSubsystem); this test
// exercises the manager-level lifecycle via the FlapScheduler's own
// Run+Stop pair plus a context that the test cancels alongside Stop.
func TestFlapScheduler_StopUnblocksLimiterWait(t *testing.T) {
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 1, GlobalCapPerSecond: 1})
	state := NewInterfaceState(2, nil, nil)
	state.Seed(1, OperUp, AdminUp)
	state.Seed(2, OperUp, AdminUp)
	s.Register(net.IPv4(10, 0, 0, 1), []int{1, 2}, IfFlapAggressive, state)

	// Accelerate all entries to fire immediately so Run pops them
	// rapidly, exhausting the 1-token-burst limiter.
	s.mu.Lock()
	for _, e := range s.byKey {
		e.nextFire = s.now()
	}
	heap.Init(&s.heap)
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	// Burn the burst — let cap=1/s actually be exhausted.
	time.Sleep(1100 * time.Millisecond)

	// Now Run should be blocked in limiter.Wait. Stop alone would not
	// unblock it; we must also cancel the context (mirroring what
	// StopFlapSubsystem does in production).
	cancel()
	s.Stop()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Run did not exit within 1s of cancel + Stop (limiter.Wait not unblocked)")
	}
}

func TestFlapScheduler_FlapBand(t *testing.T) {
	cases := []struct {
		s          IfFlapScenario
		wantMean   time.Duration
		wantNoFlap bool
	}{
		{IfFlapClean, 0, true},
		{IfFlapRare, 6 * time.Hour, false},
		{IfFlapTypical, 15 * time.Minute, false},
		{IfFlapAggressive, 1 * time.Minute, false},
		{IfFlapScenario("unknown"), 0, true},
	}
	for _, tc := range cases {
		mean, lo, hi := flapBand(tc.s)
		if tc.wantNoFlap {
			if mean != 0 {
				t.Errorf("%q: mean=%v, want 0 (no-flap)", tc.s, mean)
			}
			continue
		}
		if mean != tc.wantMean {
			t.Errorf("%q: mean=%v, want %v", tc.s, mean, tc.wantMean)
		}
		if lo <= 0 || hi <= lo {
			t.Errorf("%q: down range [%v, %v] is degenerate", tc.s, lo, hi)
		}
	}
}
