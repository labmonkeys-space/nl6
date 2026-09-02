/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Central syslog scheduler. A single goroutine owns a min-heap of
// (nextFire, deviceIP) entries. On each iteration it waits until the earliest
// due entry, consumes one token from the global rate limiter, and fires the
// device's SyslogExporter. Firing is a Poisson process per device: after each
// fire the device is requeued with an exponential-distributed next-fire offset
// (mean = -syslog-interval), naturally avoiding thundering-herd tick-boundary
// bursts (design.md §D1, §D2).
//
// This is intentionally the same shape as trap_scheduler.go — one min-heap
// goroutine keeps total timer count O(1) regardless of the 30k device fleet.
// Per design.md §D1 we copy rather than share: the trap and syslog subsystems
// carry independent rate caps and intervals, and a shared scheduler would
// require an abstract event interface that we'd rather defer until a third
// push-based capability appears.

package main

import (
	"container/heap"
	"context"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// syslogFirer is the behaviour the scheduler needs from each registered
// device's SyslogExporter. Narrow interface to keep the scheduler decoupled
// from SyslogExporter internals and to let tests substitute mocks.
type syslogFirer interface {
	// Fire emits one message from the given catalog entry. Implementations
	// MUST be safe to call concurrently with Close; a fire on a closed
	// exporter SHOULD be a silent no-op so the scheduler can never deadlock
	// on a racing Deregister. The return value is the error from the encode
	// or UDP write if any — the scheduler logs and continues.
	Fire(entry *SyslogCatalogEntry, overrides map[string]string) error
}

// syslogHeapEntry is one queued device.
type syslogHeapEntry struct {
	nextFire time.Time
	deviceIP net.IP
	index    int
}

// syslogHeap implements heap.Interface. Earliest nextFire is popped first.
type syslogHeap []*syslogHeapEntry

func (h syslogHeap) Len() int           { return len(h) }
func (h syslogHeap) Less(i, j int) bool { return h[i].nextFire.Before(h[j].nextFire) }
func (h syslogHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *syslogHeap) Push(x interface{}) {
	e := x.(*syslogHeapEntry)
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *syslogHeap) Pop() interface{} {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	e.index = -1
	*h = old[:n-1]
	return e
}

// MeanInterval returns the simulator-wide mean firing interval. Exposed
// for per-device-attach divergence warnings — per-device intervals are
// stored on DeviceSyslogConfig but not yet honored by the scheduler.
func (s *SyslogScheduler) MeanInterval() time.Duration { return s.meanInterval }

// SyslogScheduler coordinates per-device syslog firing with a single
// goroutine and a global token-bucket rate limiter. All fields are private;
// callers interact via Register / Deregister / Run / Stop.
type SyslogScheduler struct {
	mu            sync.Mutex
	fixedInterval bool // exact cadence instead of Poisson draws (scenario stub)
	deferOnCap    bool // scenario: count demand + Allow-or-defer (FR22)
	heap          syslogHeap
	byIP          map[string]*syslogHeapEntry // lookup for Deregister
	devices       map[string]syslogFirer      // exporter by device IP

	// Profile mode (scenario λ(t), FR5): when arrivalFor is non-nil the
	// scheduler fires each device at precomputed NHPP arrival offsets from
	// `epoch` (= T0) instead of drawing cadence per requeue. streams holds
	// each device's ordered offsets, streamIdx the next index to fire.
	arrivalFor func(net.IP) []time.Duration
	epoch      time.Time
	streams    map[string][]time.Duration
	streamIdx  map[string]int

	catalogFor   func(deviceIP net.IP) *SyslogCatalog
	meanInterval time.Duration
	limiter      *rate.Limiter // nil → no global cap

	// Injectable time/rand for deterministic tests. Production: now =
	// time.Now, rnd seeded from crypto/rand-derived time.
	now func() time.Time
	rnd *rand.Rand

	wake     chan struct{} // signalled by Register/Deregister/Stop to nudge Run
	stopCh   chan struct{}
	stopOnce sync.Once

	// started records that Run was entered; runDone is closed by Run's defer.
	// Fires are INLINE in Run (no worker pool), so Run's return already means
	// "no scheduler-driven fire in flight" — runDone is that signal made
	// awaitable. Stop waits on runDone only when started is set, so a
	// constructed-but-never-run scheduler (tests build these) cannot hang its
	// caller. Same shape as TrapScheduler (await-trap-emission-drain D1),
	// minus the pool teardown.
	started atomic.Bool
	runDone chan struct{}
}

// SyslogSchedulerOptions groups the tunables NewSyslogScheduler accepts. The
// zero value is not valid — a Catalog and a non-zero MeanInterval are
// required.
type SyslogSchedulerOptions struct {
	Catalog      *SyslogCatalog
	CatalogFor   func(deviceIP net.IP) *SyslogCatalog
	MeanInterval time.Duration
	// GlobalCapPerSecond is the maximum number of fires per second. Zero
	// means unlimited (the limiter is elided).
	GlobalCapPerSecond int
	// Seed, when non-zero, pins the RNG used for catalog picks and the
	// exponential inter-arrival draw. Primarily for tests.
	Seed int64
	// Now, when non-nil, overrides time.Now. Primarily for tests.
	Now func() time.Time
	// SharedLimiter, when non-nil, is used verbatim as the global rate
	// limiter INSTEAD of constructing one from GlobalCapPerSecond. The
	// scenario-owned scheduler instance (D1b) passes the background
	// scheduler's limiter here so fleet + scenario share ONE cap budget —
	// constructing a second limiter would silently double the global cap
	// (FR36; architecture anti-pattern list).
	SharedLimiter *rate.Limiter
	// FixedInterval, when true, replaces the Poisson (exponential)
	// inter-arrival draw with a fixed cadence: first fire at registration
	// time (offset 0), then exactly MeanInterval apart — giving precisely
	// rate × window fires inside a half-open [T0,T1) window (FR4, scenario
	// constant-rate stub). The seeded-Poisson path remains the default; a
	// constant scenario profile keeps this exact cadence.
	FixedInterval bool
	// ArrivalStreamFor, when non-nil, puts the scheduler in λ(t) profile mode
	// (FR5): it returns the device's precomputed, ordered NHPP arrival offsets
	// (from T0, drawn by Λ-inversion). The device fires at epoch+offset[i] and
	// stops when its stream is exhausted. Mutually exclusive with the Poisson /
	// FixedInterval requeue paths.
	ArrivalStreamFor func(deviceIP net.IP) []time.Duration
	// DeferOnCap (scenario mode, FR22): count demand at pop and use a
	// non-blocking limiter Allow — an over-cap fire is DEFERRED (counted, not
	// fired) instead of delayed. The fleet leaves this false so its steady-
	// state cadence is throttled (delayed) rather than dropped.
	DeferOnCap bool
}

// NewSyslogScheduler constructs a scheduler but does not start it. Call Run
// to begin firing.
func NewSyslogScheduler(opts SyslogSchedulerOptions) *SyslogScheduler {
	if opts.Catalog == nil && opts.CatalogFor == nil {
		panic("NewSyslogScheduler: Catalog or CatalogFor required")
	}
	// Sub-millisecond intervals busy-loop the scheduler with no global cap.
	// 1ms is a generous floor — the 30k-device steady-state with cap=3k tps
	// (design.md §D2 default operating point) implies mean interval = 10s
	// per device, so a 1ms floor is well below any realistic production
	// setting and catches misconfiguration early.
	if opts.MeanInterval < time.Millisecond {
		panic("NewSyslogScheduler: MeanInterval must be >= 1ms")
	}
	catalogFor := opts.CatalogFor
	if catalogFor == nil {
		fixed := opts.Catalog
		catalogFor = func(net.IP) *SyslogCatalog { return fixed }
	}
	s := &SyslogScheduler{
		byIP:         make(map[string]*syslogHeapEntry),
		devices:      make(map[string]syslogFirer),
		catalogFor:   catalogFor,
		meanInterval: opts.MeanInterval,
		wake:         make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
		runDone:      make(chan struct{}),
	}
	s.fixedInterval = opts.FixedInterval
	s.deferOnCap = opts.DeferOnCap
	if opts.SharedLimiter != nil {
		// Cap sharing (scenario D1b): use the caller's limiter instance
		// verbatim; never construct a second one.
		s.limiter = opts.SharedLimiter
	} else if opts.GlobalCapPerSecond > 0 {
		// Burst = cap so short-term excursions fit within one second of
		// steady-state tokens. Matches trap_scheduler.go reasoning.
		s.limiter = rate.NewLimiter(rate.Limit(opts.GlobalCapPerSecond), opts.GlobalCapPerSecond)
	}
	if opts.Now != nil {
		s.now = opts.Now
	} else {
		s.now = time.Now
	}
	if opts.ArrivalStreamFor != nil {
		// λ(t) profile mode: capture T0 as the offset epoch now that the
		// clock is set. Offsets from ArrivalStreamFor are relative to this.
		s.arrivalFor = opts.ArrivalStreamFor
		s.epoch = s.now()
		s.streams = make(map[string][]time.Duration)
		s.streamIdx = make(map[string]int)
	}
	seed := opts.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	s.rnd = rand.New(rand.NewSource(seed))
	return s
}

// Register wires a device into the scheduler. If the device is already
// registered (same IP), its exporter is replaced but the next-fire time is
// preserved so re-registration doesn't double-fire.
func (s *SyslogScheduler) Register(deviceIP net.IP, firer syslogFirer) {
	if firer == nil {
		return
	}
	key := deviceIP.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[key] = firer
	if _, already := s.byIP[key]; already {
		return
	}
	// Profile mode (λ(t)): fire at the device's precomputed NHPP arrival
	// offsets from T0. A device whose stream is empty never fires.
	if s.arrivalFor != nil {
		offsets := s.arrivalFor(deviceIP)
		if len(offsets) == 0 {
			return
		}
		s.streams[key] = offsets
		s.streamIdx[key] = 1
		entry := &syslogHeapEntry{
			nextFire: s.epoch.Add(offsets[0]),
			deviceIP: append(net.IP(nil), deviceIP...),
		}
		heap.Push(&s.heap, entry)
		s.byIP[key] = entry
		s.nudge()
		return
	}

	// Initial fire: draw a Poisson offset from now — first-fire jitter
	// prevents every device firing immediately at startup. FixedInterval
	// mode fires at registration time instead (offset 0): the scenario
	// scheduler registers participants at T0, and first-fire-at-T0 is what
	// makes the half-open [T0,T1) window hold exactly rate×window fires.
	var offset time.Duration
	if !s.fixedInterval {
		offset = time.Duration(s.rnd.ExpFloat64() * float64(s.meanInterval))
	}
	entry := &syslogHeapEntry{
		nextFire: s.now().Add(offset),
		deviceIP: append(net.IP(nil), deviceIP...), // defensive copy
	}
	heap.Push(&s.heap, entry)
	s.byIP[key] = entry
	s.nudge()
}

// Deregister removes a device from the scheduler. Safe to call for devices
// that were never registered (no-op).
func (s *SyslogScheduler) Deregister(deviceIP net.IP) {
	key := deviceIP.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.byIP[key]
	if !ok {
		delete(s.devices, key)
		return
	}
	if entry.index >= 0 && entry.index < s.heap.Len() {
		heap.Remove(&s.heap, entry.index)
	}
	delete(s.byIP, key)
	delete(s.devices, key)
	s.nudge()
}

// Run blocks until ctx is cancelled or Stop is called. Loop: peek earliest,
// wait until its nextFire, Wait() for a limiter token, pop, requeue, fire
// outside the lock.
func (s *SyslogScheduler) Run(ctx context.Context) {
	s.started.Store(true)

	// Derive a context that also cancels when Stop closes stopCh. Without
	// this, `limiter.Wait(ctx)` cannot observe Stop — callers would see
	// Run stay blocked for up to 1/rate seconds after Stop when a global
	// cap is configured.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-s.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	// runDone must close on EVERY exit path (including a panic and the
	// "stopCh already closed at first iteration" case), or a Stop that
	// observed started=true would hang. Fires are inline in this loop, so
	// closing runDone here IS the "no fire in flight" barrier that Stop —
	// and via Stop, StopSyslogExport's counter persistence and scenario
	// finalize's ledger snapshot — relies on.
	defer func() {
		close(s.runDone)
		if r := recover(); r != nil {
			log.Printf("syslog scheduler: Run panicked: %v", r)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		s.mu.Lock()
		if s.heap.Len() == 0 {
			s.mu.Unlock()
			// Wait until someone registers or we're stopped.
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				return
			case <-s.wake:
				continue
			}
		}
		nextFire := s.heap[0].nextFire
		s.mu.Unlock()

		delay := nextFire.Sub(s.now())
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-s.stopCh:
				timer.Stop()
				return
			case <-s.wake:
				// Heap changed while waiting (Register/Deregister). Re-peek.
				timer.Stop()
				continue
			case <-timer.C:
			}
		}

		// Fleet mode throttles by DELAYING (blocking Wait). Scenario mode
		// (deferOnCap) instead counts demand at pop and defers over-cap fires
		// via a non-blocking Allow below — so it must NOT block here.
		if s.limiter != nil && !s.deferOnCap {
			if err := s.limiter.Wait(ctx); err != nil {
				return
			}
		}

		s.mu.Lock()
		if s.heap.Len() == 0 {
			s.mu.Unlock()
			continue
		}
		entry := heap.Pop(&s.heap).(*syslogHeapEntry)
		key := entry.deviceIP.String()
		firer, firerExists := s.devices[key]

		if !firerExists {
			// Deregistered while we waited; drop the entry.
			delete(s.byIP, key)
			s.mu.Unlock()
			continue
		}

		// Requeue. Profile mode (λ(t)): pop the device's next precomputed NHPP
		// offset; when the stream is exhausted the device fires no more (do NOT
		// requeue), so the scenario emits exactly its drawn arrivals.
		if s.arrivalFor != nil {
			offs := s.streams[key]
			idx := s.streamIdx[key]
			if idx >= len(offs) {
				delete(s.byIP, key)
				delete(s.streams, key)
				delete(s.streamIdx, key)
				// Fire this last popped arrival, but don't requeue.
				deviceIP := entry.deviceIP
				s.mu.Unlock()
				s.fireOrDefer(deviceIP, firer)
				continue
			}
			entry.nextFire = s.epoch.Add(offs[idx])
			s.streamIdx[key] = idx + 1
			heap.Push(&s.heap, entry)
			s.byIP[key] = entry
			deviceIP := entry.deviceIP
			s.mu.Unlock()
			s.fireOrDefer(deviceIP, firer)
			continue
		}

		// Requeue: exponential-distributed offset (Poisson default) or the
		// exact cadence (FixedInterval / scenario constant-rate stub).
		offset := s.meanInterval
		if !s.fixedInterval {
			offset = time.Duration(s.rnd.ExpFloat64() * float64(s.meanInterval))
		}
		entry.nextFire = s.now().Add(offset)
		heap.Push(&s.heap, entry)
		s.byIP[key] = entry

		// Snapshot IP and release before the manager callback to avoid
		// holding s.mu across sm.mu.RLock (same reasoning as trap
		// scheduler — decouples lock domains).
		deviceIP := entry.deviceIP
		s.mu.Unlock()
		s.fireOrDefer(deviceIP, firer)
	}
}

// scenarioCounters is the optional behaviour the scheduler uses in
// DeferOnCap mode to record cap-deferral visibility (FR22). The scenario
// firer implements it; the fleet firer does not.
type scenarioCounters interface {
	CountScenarioRequested()
	CountScenarioDeferred()
}

// fireOrDefer is the fire entrypoint. In DeferOnCap (scenario) mode it counts
// the pop as demand (`requested`) and, if the shared cap has no token, records
// a `deferred` and skips the fire — so a throttle is visible and never
// masquerades as loss (FR22). Otherwise (fleet, or no cap) it fires directly;
// the blocking Wait already happened for the fleet path.
func (s *SyslogScheduler) fireOrDefer(deviceIP net.IP, firer syslogFirer) {
	if s.deferOnCap {
		if sc, ok := firer.(scenarioCounters); ok {
			sc.CountScenarioRequested()
			if s.limiter != nil && !s.limiter.Allow() {
				sc.CountScenarioDeferred()
				return
			}
		}
	}
	s.fireOne(deviceIP, firer)
}

// fireOne resolves the device's catalog, picks a weighted-random entry, and
// fires it (with panic recovery). Called with s.mu NOT held. Shared by the
// Poisson / FixedInterval requeue tail and the λ(t) profile-mode branches.
func (s *SyslogScheduler) fireOne(deviceIP net.IP, firer syslogFirer) {
	cat := s.catalogFor(deviceIP)
	s.mu.Lock()
	var catEntry *SyslogCatalogEntry
	if cat != nil {
		catEntry = cat.Pick(s.rnd)
	}
	s.mu.Unlock()
	if catEntry != nil {
		s.fireWithRecover(firer, deviceIP, catEntry)
	}
}

// fireWithRecover wraps Fire with panic recovery so a misbehaving exporter
// can never take out the whole scheduler.
func (s *SyslogScheduler) fireWithRecover(firer syslogFirer, deviceIP net.IP, entry *SyslogCatalogEntry) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("syslog scheduler: Fire panicked for %s (entry=%s): %v",
				deviceIP, entry.Name, r)
		}
	}()
	if err := firer.Fire(entry, nil); err != nil {
		// Non-fatal: log and continue. Exporter-level stats track send
		// failures; the scheduler keeps firing for other devices.
		log.Printf("syslog scheduler: fire %s for %s: %v", entry.Name, deviceIP, err)
	}
}

// limiterRef exposes the scheduler's rate limiter so the scenario-owned
// scheduler instance can SHARE it (SyslogSchedulerOptions.SharedLimiter,
// D1b cap sharing). nil when the fleet runs uncapped.
func (s *SyslogScheduler) limiterRef() *rate.Limiter { return s.limiter }

// Stop signals Run to exit and, when Run was started, BLOCKS until it has —
// fires are inline in Run, so Stop's return means no scheduler-driven fire is
// in flight (#410). Both snapshot sites lean on this: StopSyslogExport
// persists counters after Stop, and scenario finalize snapshots ledgers after
// c.sched.Stop(). Bounded-time under a global cap via the stop-derived
// limiter context in Run.
//
// Safe to call multiple times and from any goroutine (waiting on the closed
// runDone is free). A scheduler that was never Run returns immediately; Stop
// racing Run entry collapses safely — either started is still false (no
// wait; Run sees the closed stopCh at its first iteration and exits, closing
// runDone anyway) or started is true and every Run exit path closes runDone.
func (s *SyslogScheduler) Stop() {
	if done := s.StopAsync(); done != nil {
		<-done
	}
}

// StopAsync signals the run loop to stop and returns the channel that closes
// when it has exited, or nil when it never started. Split out of Stop for
// nl6#618 so finalize can JOIN that exit against a deadline: this scheduler
// fires inline, so a stalled write parks the run loop, and a bare `<-runDone`
// held finalize open with nothing able to cut it short.
//
// Signalling is still unconditional and idempotent; only the waiting moved to
// the caller.
func (s *SyslogScheduler) StopAsync() <-chan struct{} {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	if !s.started.Load() {
		return nil
	}
	return s.runDone
}

// nudge signals the Run goroutine that the heap has changed. Non-blocking:
// a pending nudge collapses with this one.
func (s *SyslogScheduler) nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
