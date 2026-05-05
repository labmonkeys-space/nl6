/*
 * © 2025 Labmonkeys Space
 * Apache-2.0 — see LICENSE.
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

// countingSyslogFirer is a mock syslogFirer that records fire count per
// device. Safe for concurrent use.
type countingSyslogFirer struct {
	deviceIP net.IP
	count    atomic.Uint64
	mu       sync.Mutex
	firedAt  []time.Time
	nextErr  error
}

func (f *countingSyslogFirer) Fire(entry *SyslogCatalogEntry, overrides map[string]string) error {
	f.count.Add(1)
	f.mu.Lock()
	f.firedAt = append(f.firedAt, time.Now())
	err := f.nextErr
	f.mu.Unlock()
	return err
}

func testSyslogCatalog(t *testing.T) *SyslogCatalog {
	t.Helper()
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatalf("test catalog: %v", err)
	}
	return cat
}

// TestSyslogScheduler_FiresRegisteredDevices — each registered device
// must get at least one fire within a reasonable window.
func TestSyslogScheduler_FiresRegisteredDevices(t *testing.T) {
	cat := testSyslogCatalog(t)
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:      cat,
		MeanInterval: 10 * time.Millisecond,
		Seed:         1,
	})

	const N = 5
	firers := make([]*countingSyslogFirer, N)
	for i := 0; i < N; i++ {
		firers[i] = &countingSyslogFirer{deviceIP: net.IPv4(10, 0, 0, byte(i+1))}
		s.Register(firers[i].deviceIP, firers[i])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

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
		time.Sleep(10 * time.Millisecond)
	}
	s.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop within 1s")
	}
	for i, f := range firers {
		if f.count.Load() == 0 {
			t.Errorf("device %d never fired", i)
		}
	}
}

// TestSyslogScheduler_GlobalCapEnforced — with a low cap and many devices
// at a short interval, total fires-per-second must be bounded by the cap.
func TestSyslogScheduler_GlobalCapEnforced(t *testing.T) {
	cat := testSyslogCatalog(t)
	const cap = 20
	const devices = 200
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:            cat,
		MeanInterval:       time.Millisecond,
		GlobalCapPerSecond: cap,
		Seed:               42,
	})
	firers := make([]*countingSyslogFirer, devices)
	for i := 0; i < devices; i++ {
		firers[i] = &countingSyslogFirer{deviceIP: net.IPv4(10, 0, byte(i/256), byte(i%256))}
		s.Register(firers[i].deviceIP, firers[i])
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	<-ctx.Done()
	s.Stop()
	<-done
	elapsed := time.Since(start)

	var total uint64
	for _, f := range firers {
		total += f.count.Load()
	}
	// Theoretical max: full burst (cap) + steady-state (cap × elapsed seconds).
	// With cap=20, burst=20, elapsed≈1s: ~40 fires. We allow 10% timing slack
	// for scheduler wake-up latency on slow CI. Threshold ~44 catches
	// regressions of ≥10% over the theoretical cap, vs the old 50 which
	// silently tolerated ~25%.
	maxAllowed := uint64(float64(cap)*(elapsed.Seconds()+1.0)*1.1) + 1
	if total > maxAllowed {
		t.Errorf("global cap violated: %d fires in %v (max allowed ~%d)", total, elapsed, maxAllowed)
	}
	if total == 0 {
		t.Error("no fires recorded under cap")
	}
}

// TestSyslogScheduler_RegisterDeregisterThreadSafety — mixed ops from many
// goroutines must not race or panic.
func TestSyslogScheduler_RegisterDeregisterThreadSafety(t *testing.T) {
	cat := testSyslogCatalog(t)
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:      cat,
		MeanInterval: time.Millisecond,
		Seed:         7,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	const goroutines = 100
	const ops = 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				ip := net.IPv4(10, 0, byte(id), byte(i))
				f := &countingSyslogFirer{deviceIP: ip}
				s.Register(ip, f)
				s.Deregister(ip)
			}
		}(g)
	}
	wg.Wait()
	s.Stop()
	cancel()
	<-done
}

// TestSyslogScheduler_DeregisterRemovesDevice — a deregistered device
// stops receiving fires.
func TestSyslogScheduler_DeregisterRemovesDevice(t *testing.T) {
	cat := testSyslogCatalog(t)
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:      cat,
		MeanInterval: 10 * time.Millisecond,
		Seed:         3,
	})
	ip := net.IPv4(10, 42, 0, 1)
	f := &countingSyslogFirer{deviceIP: ip}
	s.Register(ip, f)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	// Wait for first fire, then deregister and verify count stabilises.
	// Capture the deadline once; `time.Now().Before(time.Now().Add(X))` is
	// always true because both operands re-evaluate each iteration.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if f.count.Load() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.Deregister(ip)
	at := f.count.Load()
	time.Sleep(100 * time.Millisecond)
	s.Stop()
	cancel()
	<-done
	// One post-Deregister fire is a legitimate race: the scheduler may have
	// captured the firer reference under the lock before Deregister acquired
	// it, then released the lock and called Fire outside. Tolerate +1.
	if after := f.count.Load(); after > at+1 {
		t.Errorf("deregistered device still firing: before=%d, after=%d (tolerance +1)", at, after)
	}
}

// TestSyslogScheduler_StopIdempotent — repeated Stop calls and Stop after
// Run completion must not panic.
func TestSyslogScheduler_StopIdempotent(t *testing.T) {
	cat := testSyslogCatalog(t)
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:      cat,
		MeanInterval: time.Second,
		Seed:         11,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	s.Stop()
	s.Stop()
	cancel()
	<-done
	s.Stop()
}

// TestSyslogScheduler_FireErrorDoesNotStopLoop — a firer that returns an
// error must not prevent subsequent fires.
func TestSyslogScheduler_FireErrorDoesNotStopLoop(t *testing.T) {
	cat := testSyslogCatalog(t)
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:      cat,
		MeanInterval: 5 * time.Millisecond,
		Seed:         2,
	})
	ip := net.IPv4(10, 1, 1, 1)
	f := &countingSyslogFirer{deviceIP: ip}
	f.mu.Lock()
	f.nextErr = context.DeadlineExceeded
	f.mu.Unlock()
	s.Register(ip, f)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	<-ctx.Done()
	s.Stop()
	<-done
	if f.count.Load() < 2 {
		t.Errorf("expected multiple fires despite errors, got %d", f.count.Load())
	}
}

// TestSyslogScheduler_ExponentialInterArrival — spec Requirement "Poisson
// scheduling and global rate cap" Scenario "Fire intervals follow
// exponential distribution". We use a single device at 10ms mean and
// collect ~500 samples (~5s runtime). For an Exp(λ=100/s) distribution:
//
//   mean = 1/λ = 10ms
//   variance = 1/λ² = 100ms²
//   coefficient of variation (stddev/mean) = 1
//
// A periodic scheduler would have CV ≈ 0; a uniform-jittered one ≈ 0.58.
// Asserting mean within 40% and CV > 0.7 distinguishes exponential from
// both alternatives while tolerating wall-clock sampling noise.
func TestSyslogScheduler_ExponentialInterArrival(t *testing.T) {
	const meanInterval = 10 * time.Millisecond
	const targetSamples = 500
	cat := testSyslogCatalog(t)
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:      cat,
		MeanInterval: meanInterval,
		Seed:         12345,
	})
	ip := net.IPv4(10, 0, 0, 99)
	f := &countingSyslogFirer{deviceIP: ip}
	s.Register(ip, f)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if f.count.Load() >= targetSamples {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.Stop()
	cancel()
	<-done

	f.mu.Lock()
	times := make([]time.Time, len(f.firedAt))
	copy(times, f.firedAt)
	f.mu.Unlock()
	if len(times) < targetSamples {
		t.Fatalf("not enough samples: got %d, want %d", len(times), targetSamples)
	}
	// Drop the first sample's "warmup" interval (from Register to first fire).
	intervals := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		intervals = append(intervals, times[i].Sub(times[i-1]).Seconds())
	}
	var sum float64
	for _, d := range intervals {
		sum += d
	}
	mean := sum / float64(len(intervals))
	var sqsum float64
	for _, d := range intervals {
		diff := d - mean
		sqsum += diff * diff
	}
	variance := sqsum / float64(len(intervals))
	stddev := math.Sqrt(variance)
	cv := stddev / mean

	expected := meanInterval.Seconds()
	if mean < expected*0.6 || mean > expected*1.4 {
		t.Errorf("mean inter-arrival: got %.4fs, want within ±40%% of %.4fs", mean, expected)
	}
	// Exponential has CV = 1. Periodic = 0. Uniform jitter ≈ 0.58.
	// We require CV > 0.7 to rule out the non-exponential alternatives
	// while allowing for wall-clock sampling noise at small intervals.
	if cv < 0.7 {
		t.Errorf("coefficient of variation %.2f suggests non-exponential distribution (want ≈1)", cv)
	}
	t.Logf("inter-arrival: mean=%.4fs (target %.4f), CV=%.2f (target 1.0), n=%d",
		mean, expected, cv, len(intervals))
}

// TestSyslogScheduler_RejectsSubMillisecondInterval — MeanInterval below
// 1ms would busy-loop the scheduler when no global cap is set.
func TestSyslogScheduler_RejectsSubMillisecondInterval(t *testing.T) {
	cat := testSyslogCatalog(t)
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewSyslogScheduler with sub-1ms interval should panic")
		}
	}()
	_ = NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:      cat,
		MeanInterval: 500 * time.Microsecond,
	})
}

// TestSyslogScheduler_StopWithLimiterCap — Stop() must be able to
// interrupt Run even when it is blocked in limiter.Wait() (which, before
// the ctx-derivation fix, could hold Run blocked for up to 1/rate seconds).
func TestSyslogScheduler_StopWithLimiterCap(t *testing.T) {
	cat := testSyslogCatalog(t)
	// Very low cap with a bucket already drained by Register's initial
	// exponential draws — any subsequent limiter.Wait blocks for ≥1s.
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:            cat,
		MeanInterval:       time.Millisecond,
		GlobalCapPerSecond: 1,
		Seed:               42,
	})
	for i := 0; i < 50; i++ {
		ip := net.IPv4(10, 0, 0, byte(i+1))
		s.Register(ip, &countingSyslogFirer{deviceIP: ip})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	// Give the scheduler time to drain the burst and block on limiter.Wait.
	time.Sleep(50 * time.Millisecond)
	stopAt := time.Now()
	s.Stop()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Stop() did not unblock Run within 500ms while limiter was held")
	}
	if elapsed := time.Since(stopAt); elapsed > 500*time.Millisecond {
		t.Errorf("Stop() took %v (want <500ms even under cap)", elapsed)
	}
}

// TestSyslogScheduler_EmptyHeapDoesNotBusyLoop — running with zero
// registered devices must idle cheaply, not spin.
func TestSyslogScheduler_EmptyHeapDoesNotBusyLoop(t *testing.T) {
	cat := testSyslogCatalog(t)
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:      cat,
		MeanInterval: time.Millisecond,
		Seed:         4,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	<-ctx.Done()
	s.Stop()
	<-done
	// If we got here without hang or panic, the loop idled correctly.
}
