/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"container/heap"
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IfFlapScenario controls per-device interface-state flap behavior.
// Mirrors IfErrorScenario in spirit — the same band model, different
// dimension (link state vs error counters). Scenarios are independent:
// a device can run `clean` errors + `aggressive` flaps or any other
// combination.
type IfFlapScenario string

const (
	IfFlapClean      IfFlapScenario = "clean"      // default; no flaps
	IfFlapRare       IfFlapScenario = "rare"       // ~6h mean inter-flap per interface
	IfFlapTypical    IfFlapScenario = "typical"    // ~15min mean
	IfFlapAggressive IfFlapScenario = "aggressive" // ~1min mean
)

// flapBand returns the Poisson mean inter-arrival and the uniform
// down-duration bounds for a scenario. Locked decisions §D7.
func flapBand(s IfFlapScenario) (mean, downLow, downHigh time.Duration) {
	switch s {
	case IfFlapRare:
		return 6 * time.Hour, 1 * time.Second, 10 * time.Second
	case IfFlapTypical:
		return 15 * time.Minute, 1 * time.Second, 30 * time.Second
	case IfFlapAggressive:
		return 1 * time.Minute, 1 * time.Second, 5 * time.Second
	default:
		// `clean` and any unknown value produce no flaps (mean=∞ → no
		// initial event scheduled at Register time).
		return 0, 0, 0
	}
}

// ValidFlapScenario returns true when s is one of the four canonical
// values. Used by CLI flag parsing and POST-body validation.
func ValidFlapScenario(s IfFlapScenario) bool {
	switch s {
	case IfFlapClean, IfFlapRare, IfFlapTypical, IfFlapAggressive:
		return true
	}
	return false
}

// ParseIfFlapScenario canonicalises s (case-insensitive) to one of the
// four known scenarios. Empty input maps to IfFlapClean. Unknown values
// return an error naming the accepted scenarios — mirrors
// ParseIfErrorScenario so CLI and REST surfaces share validation shape.
func ParseIfFlapScenario(s string) (IfFlapScenario, error) {
	switch IfFlapScenario(strings.ToLower(strings.TrimSpace(s))) {
	case "", IfFlapClean:
		return IfFlapClean, nil
	case IfFlapRare:
		return IfFlapRare, nil
	case IfFlapTypical:
		return IfFlapTypical, nil
	case IfFlapAggressive:
		return IfFlapAggressive, nil
	default:
		return "", fmt.Errorf("invalid if_flap_scenario %q (accepted: clean, rare, typical, aggressive)", s)
	}
}

// flapAction names the transition a heap entry will perform when it fires.
type flapAction uint8

const (
	flapActionDown flapAction = iota
	flapActionUp
)

// flapHeapEntry is one queued (device, ifIndex, action) tuple.
type flapHeapEntry struct {
	nextFire time.Time
	deviceIP net.IP
	ifIndex  int
	action   flapAction
	scenario IfFlapScenario
	state    *InterfaceState
	index    int
}

// flapHeap implements heap.Interface. Earliest nextFire is popped first.
type flapHeap []*flapHeapEntry

func (h flapHeap) Len() int           { return len(h) }
func (h flapHeap) Less(i, j int) bool { return h[i].nextFire.Before(h[j].nextFire) }
func (h flapHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *flapHeap) Push(x any) {
	e := x.(*flapHeapEntry)
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *flapHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	e.index = -1
	*h = old[:n-1]
	return e
}

// flapKey identifies a registered (device, ifIndex) pair for byKey lookup.
type flapKey struct {
	ip      string
	ifIndex int
}

// FlapScheduler coordinates per-(device, ifIndex) link-state flaps with a
// single goroutine and a global token-bucket rate limiter. Mirrors
// `TrapScheduler` and `SyslogScheduler` in shape; the differences are:
//
//   - schedulable unit is (device, ifIndex), not device — each interface
//     flaps independently with its own Poisson stream
//   - each fire mutates `InterfaceState` instead of emitting a packet —
//     no exporter, no catalog, no wire format
//   - down/up actions are a state machine: a down event schedules its
//     matching up event at uniform(downLow, downHigh); the up event
//     then schedules the next down at exp(meanInterval)
//
// Callers interact via NewFlapScheduler / Register / Deregister / Run /
// Stop. Stop is shutdown-only (matching trap/syslog convention).
type FlapScheduler struct {
	mu    sync.Mutex
	heap  flapHeap
	byKey map[flapKey]*flapHeapEntry

	limiter *rate.Limiter // nil → no global cap

	now func() time.Time
	rnd *rand.Rand

	wake     chan struct{}
	stopCh   chan struct{}
	stopOnce sync.Once
}

// FlapSchedulerOptions configures a new scheduler. Pass GlobalCapPerSecond=0
// for no cap. Now/Seed are exposed for deterministic tests.
type FlapSchedulerOptions struct {
	GlobalCapPerSecond int
	Seed               int64
	Now                func() time.Time
}

// NewFlapScheduler constructs a scheduler. Call Run to start the loop.
func NewFlapScheduler(opts FlapSchedulerOptions) *FlapScheduler {
	s := &FlapScheduler{
		byKey:  make(map[flapKey]*flapHeapEntry),
		wake:   make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
	if opts.GlobalCapPerSecond > 0 {
		// Burst = cap so a one-second steady-state budget is the
		// tightest sane value. Matches trap/syslog convention.
		s.limiter = rate.NewLimiter(rate.Limit(opts.GlobalCapPerSecond), opts.GlobalCapPerSecond)
	}
	if opts.Now != nil {
		s.now = opts.Now
	} else {
		s.now = time.Now
	}
	seed := opts.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	s.rnd = rand.New(rand.NewSource(seed))
	return s
}

// Register attaches a device's interfaces to the scheduler under a
// scenario. Each ifIndex gets one initial "down" event scheduled at
// `now + exp(meanInterval)`. Clean scenarios are skipped (no events
// scheduled). Idempotent: re-registering the same (device, ifIndex)
// replaces the old entry.
func (s *FlapScheduler) Register(deviceIP net.IP, ifIndexes []int, scenario IfFlapScenario, state *InterfaceState) {
	mean, _, _ := flapBand(scenario)
	if mean == 0 {
		// `clean` is the legitimate quiet path; anything else is a
		// programmer error (uncanonicalised scenario string).
		if scenario != IfFlapClean && scenario != "" {
			log.Printf("flap scheduler: Register skipped for %s ifs=%v — unknown scenario %q (use ParseIfFlapScenario to canonicalise before Register)", deviceIP, ifIndexes, scenario)
		}
		return
	}
	if state == nil || len(ifIndexes) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, ifIndex := range ifIndexes {
		key := flapKey{ip: deviceIP.String(), ifIndex: ifIndex}
		if old, ok := s.byKey[key]; ok && old.index >= 0 {
			heap.Remove(&s.heap, old.index)
		}
		offset := time.Duration(s.rnd.ExpFloat64() * float64(mean))
		entry := &flapHeapEntry{
			nextFire: now.Add(offset),
			deviceIP: append(net.IP(nil), deviceIP...),
			ifIndex:  ifIndex,
			action:   flapActionDown,
			scenario: scenario,
			state:    state,
		}
		heap.Push(&s.heap, entry)
		s.byKey[key] = entry
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Deregister removes every scheduled entry for the device. Called from
// DeleteDevice and from process shutdown.
//
// Performance note: this walks the full `byKey` map (O(M) where M is
// total scheduled (device, ifIndex) entries) to find the device's
// entries. At 30k devices × ~30 ifIndexes each = ~900k key compares per
// DeleteDevice call. Acceptable for the deletion rate the simulator
// sees today; if bulk delete becomes a hot path, switch to a
// per-IP-prefix secondary index.
func (s *FlapScheduler) Deregister(deviceIP net.IP) {
	if deviceIP == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ipStr := deviceIP.String()
	for key, entry := range s.byKey {
		if key.ip != ipStr {
			continue
		}
		if entry.index >= 0 {
			heap.Remove(&s.heap, entry.index)
		}
		delete(s.byKey, key)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Stop is shutdown-only (per §D2 / trap+syslog convention). Idempotent.
func (s *FlapScheduler) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// Run blocks until ctx is cancelled or Stop is called. The loop: peek
// earliest, wait until its nextFire, acquire a limiter token, pop, fire
// outside the lock, reschedule the counterpart action.
func (s *FlapScheduler) Run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("flap scheduler: Run panicked: %v", r)
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
				timer.Stop()
				continue
			case <-timer.C:
			}
		}

		if s.limiter != nil {
			if err := s.limiter.Wait(ctx); err != nil {
				return
			}
		}

		s.mu.Lock()
		if s.heap.Len() == 0 {
			s.mu.Unlock()
			continue
		}
		entry := heap.Pop(&s.heap).(*flapHeapEntry)
		key := flapKey{ip: entry.deviceIP.String(), ifIndex: entry.ifIndex}
		if cur, ok := s.byKey[key]; !ok || cur != entry {
			// Deregistered/replaced while we waited; drop.
			s.mu.Unlock()
			continue
		}
		// Compute next event under the lock (rnd is not concurrent-safe),
		// then push it back. We need the counterpart action.
		var nextOffset time.Duration
		var nextAction flapAction
		mean, downLow, downHigh := flapBand(entry.scenario)
		switch entry.action {
		case flapActionDown:
			// After down → schedule up at now + uniform(downLow, downHigh).
			// Defensive: span <= 0 would panic Int63n. Today flapBand
			// returns values where downHigh > downLow strictly, but the
			// helper accepts equality by clamping the random draw to 0.
			span := downHigh - downLow
			if span <= 0 {
				nextOffset = downLow
			} else {
				nextOffset = downLow + time.Duration(s.rnd.Int63n(int64(span)+1))
			}
			nextAction = flapActionUp
		default: // flapActionUp
			// After up → schedule next down at now + exp(meanInterval).
			// Mean-zero guard: if the entry's scenario was somehow
			// corrupted to an unknown value, flapBand returns mean=0
			// and `nextOffset=0` would busy-loop the scheduler. Drop
			// the entry (no reschedule, no fire counterpart) and log.
			if mean == 0 {
				log.Printf("flap scheduler: dropping orphaned entry with unknown scenario %q (ip=%s ifIndex=%d) — no counterpart scheduled", entry.scenario, entry.deviceIP, entry.ifIndex)
				s.mu.Unlock()
				continue
			}
			nextOffset = time.Duration(s.rnd.ExpFloat64() * float64(mean))
			nextAction = flapActionDown
		}
		next := &flapHeapEntry{
			nextFire: s.now().Add(nextOffset),
			deviceIP: entry.deviceIP,
			ifIndex:  entry.ifIndex,
			action:   nextAction,
			scenario: entry.scenario,
			state:    entry.state,
		}
		heap.Push(&s.heap, next)
		s.byKey[key] = next
		s.mu.Unlock()

		// Fire outside the lock. SetOperStatus is idempotent; if a REST
		// POST flipped the interface to the action's target state
		// between schedule and fire, the mutator no-ops and the
		// scheduler self-corrects on the counterpart.
		var target uint8
		if entry.action == flapActionDown {
			target = OperDown
		} else {
			target = OperUp
		}
		s.fireWithRecover(entry.state, entry.ifIndex, target, entry.deviceIP)
	}
}

func (s *FlapScheduler) fireWithRecover(state *InterfaceState, ifIndex int, target uint8, deviceIP net.IP) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("flap scheduler: fire panicked for %s ifIndex=%d: %v", deviceIP, ifIndex, r)
		}
	}()
	if state == nil {
		return
	}
	changed, evt := state.SetOperStatus(ifIndex, target)
	if changed {
		state.Broadcast(evt)
		return
	}
	// changed=false means the slot is already in `target` (e.g., REST
	// POST flipped it between schedule and fire, or an admin-down
	// override means oper transitions are being suppressed). The next
	// counterpart event was already scheduled before fire; the scheduler
	// will keep cycling and the state machine self-corrects on the next
	// genuine transition. Log once for visibility — silent no-ops are a
	// debugging trap if a real coverage gap shows up at scale.
	log.Printf("flap scheduler: fire was a no-op for %s ifIndex=%d target=%d (state already at target — REST race or admin-down suppression)", deviceIP, ifIndex, target)
}

// pendingCountForTest returns the number of scheduled entries.
// Test-only — not part of the public API.
func (s *FlapScheduler) pendingCountForTest() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heap.Len()
}

// String returns a human-readable summary for logs / status.
func (s *FlapScheduler) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	globalCap := "unlimited"
	if s.limiter != nil {
		globalCap = fmt.Sprintf("%.0f/s", float64(s.limiter.Limit()))
	}
	return fmt.Sprintf("flap scheduler: %d scheduled (cap=%s)", s.heap.Len(), globalCap)
}
