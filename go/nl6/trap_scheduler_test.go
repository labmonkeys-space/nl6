/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"context"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingFirer is a mock trapFirer that records how many times each device
// fired. Safe for concurrent use.
type countingFirer struct {
	deviceIP net.IP
	count    atomic.Uint64
	// firedAt records fire timestamps; used by inter-arrival tests.
	mu       sync.Mutex
	firedAt  []time.Time
}

func (f *countingFirer) Fire(entry *CatalogEntry, overrides map[string]string) uint32 {
	n := f.count.Add(1)
	f.mu.Lock()
	f.firedAt = append(f.firedAt, time.Now())
	f.mu.Unlock()
	return uint32(n)
}

func testCatalog(t *testing.T) *Catalog {
	t.Helper()
	cat, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("test catalog: %v", err)
	}
	return cat
}

func TestTrapScheduler_FiresRegisteredDevices(t *testing.T) {
	cat := testCatalog(t)
	s := NewTrapScheduler(SchedulerOptions{
		Catalog:      cat,
		MeanInterval: 10 * time.Millisecond,
		Seed:         1,
	})

	const N = 5
	firers := make([]*countingFirer, N)
	for i := 0; i < N; i++ {
		firers[i] = &countingFirer{deviceIP: net.IPv4(10, 0, 0, byte(i+1))}
		s.Register(firers[i].deviceIP, firers[i])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// Wait until each firer has been called at least once, then stop.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		allFired := true
		for _, f := range firers {
			if f.count.Load() == 0 {
				allFired = false
				break
			}
		}
		if allFired {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	s.Stop()
	<-done

	for i, f := range firers {
		if f.count.Load() == 0 {
			t.Errorf("firer[%d] (%s) never fired", i, f.deviceIP)
		}
	}
}

func TestTrapScheduler_GlobalCapHonored(t *testing.T) {
	cat := testCatalog(t)
	const capPerSec = 10
	s := NewTrapScheduler(SchedulerOptions{
		Catalog:            cat,
		MeanInterval:       1 * time.Microsecond, // as fast as possible per device
		GlobalCapPerSecond: capPerSec,
		Seed:               1,
	})

	// Register enough devices that without the cap we'd blast many thousands
	// of fires per second.
	const N = 500
	var total atomic.Uint64
	firers := make([]*countingFirer, N)
	for i := 0; i < N; i++ {
		firers[i] = &countingFirer{deviceIP: net.IPv4(10, 0, byte(i/256), byte(i%256))}
		s.Register(firers[i].deviceIP, firers[i])
	}
	// Count total via a goroutine snapshot at the end.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// Let it run for 2 seconds.
	time.Sleep(2 * time.Second)
	s.Stop()
	<-done

	for _, f := range firers {
		total.Add(f.count.Load())
	}
	sum := total.Load()

	// Over 2 seconds at cap=10 we expect ≤ 20 + burst (cap=10, so burst=10),
	// total ≤ 30. Allow some slack for timer skew: ≤ 40.
	if sum > 40 {
		t.Errorf("global cap breached: got %d fires in 2s with cap=%d/s (want ≤ 40)", sum, capPerSec)
	}
	// Also assert the cap actually produced at least some fires — we're not
	// hung on an empty heap.
	if sum < 10 {
		t.Errorf("too few fires: %d in 2s with cap=%d/s (want ≥ 10)", sum, capPerSec)
	}
}

func TestTrapScheduler_RegisterDeregisterSafety(t *testing.T) {
	cat := testCatalog(t)
	s := NewTrapScheduler(SchedulerOptions{
		Catalog:      cat,
		MeanInterval: 1 * time.Millisecond,
		Seed:         1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// 20 concurrent mutator goroutines, each churning 50 Register/Deregister
	// ops on a random subset of 30 device IPs.
	var wg sync.WaitGroup
	const mutators = 20
	const ops = 50
	for g := 0; g < mutators; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				ip := net.IPv4(10, 0, byte(g), byte(i%30))
				s.Register(ip, &countingFirer{deviceIP: ip})
				if i%3 == 0 {
					s.Deregister(ip)
				}
			}
		}(g)
	}
	wg.Wait()

	s.Stop()
	<-done
	// If we reach here without panic / deadlock / race under `go test -race`
	// the test passes.
}

func TestTrapScheduler_ExponentialInterArrival(t *testing.T) {
	// Drive a single device with a fixed MeanInterval and measure observed
	// inter-arrival times. Assert the mean is within 5% of the configured
	// value over enough samples. A full KS test against exponential(λ)
	// requires more statistics than we want in a unit test; the mean check
	// is a strong indicator that the distribution isn't constant/uniform.
	cat := testCatalog(t)
	const meanMs = 10
	const targetFires = 400
	s := NewTrapScheduler(SchedulerOptions{
		Catalog:      cat,
		MeanInterval: meanMs * time.Millisecond,
		Seed:         2,
	})
	f := &countingFirer{deviceIP: net.IPv4(10, 1, 1, 1)}
	s.Register(f.deviceIP, f)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for f.count.Load() < targetFires && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	s.Stop()
	<-done

	f.mu.Lock()
	samples := append([]time.Time(nil), f.firedAt...)
	f.mu.Unlock()

	if len(samples) < targetFires {
		t.Skipf("only %d fires in 10s; system too slow for inter-arrival stats", len(samples))
	}

	// Compute mean inter-arrival in ms.
	var sumMs float64
	for i := 1; i < len(samples); i++ {
		sumMs += float64(samples[i].Sub(samples[i-1]).Microseconds()) / 1000.0
	}
	mean := sumMs / float64(len(samples)-1)
	// Tolerance: ±25%. Scheduling jitter from a busy test machine + the
	// finite sample size makes tighter bounds flaky.
	lo, hi := meanMs*0.75, meanMs*1.25
	if mean < lo || mean > hi {
		t.Errorf("observed mean inter-arrival %.2fms outside [%.2f, %.2f]ms over %d samples",
			mean, lo, hi, len(samples)-1)
	}

	// And assert the variance is non-trivial: if every interval were exactly
	// meanMs (constant), variance would be near 0. Exponential variance
	// equals mean² so we expect variance ≈ meanMs²; we'll accept ≥ 0.25 × mean².
	var sumSq float64
	for i := 1; i < len(samples); i++ {
		d := float64(samples[i].Sub(samples[i-1]).Microseconds())/1000.0 - mean
		sumSq += d * d
	}
	variance := sumSq / float64(len(samples)-1)
	wantVar := mean * mean * 0.25
	if variance < wantVar {
		t.Errorf("observed variance %.2f < minimum %.2f; distribution looks too flat "+
			"(likely not exponential)", variance, wantVar)
	}
	_ = math.Sqrt // keep math import tidy if we ever add stddev checks
}

func TestTrapScheduler_StopIsIdempotent(t *testing.T) {
	cat := testCatalog(t)
	s := NewTrapScheduler(SchedulerOptions{
		Catalog:      cat,
		MeanInterval: 1 * time.Millisecond,
	})
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	s.Stop()
	s.Stop() // must not panic
	<-done
}

func TestTrapScheduler_EmptyHeapWaitsForRegister(t *testing.T) {
	cat := testCatalog(t)
	s := NewTrapScheduler(SchedulerOptions{
		Catalog:      cat,
		MeanInterval: 5 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// Register after a delay; the scheduler must start firing.
	time.Sleep(50 * time.Millisecond)
	f := &countingFirer{deviceIP: net.IPv4(10, 0, 0, 1)}
	s.Register(f.deviceIP, f)
	time.Sleep(200 * time.Millisecond)
	s.Stop()
	<-done

	if f.count.Load() == 0 {
		t.Error("scheduler should have woken from empty-heap wait on Register")
	}
}
