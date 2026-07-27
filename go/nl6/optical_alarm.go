/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"container/heap"
	"context"
	"math"
	"net"
	"sync"
	"time"
)

// optical_alarm.go — SD/SF threshold detection for coherent optical channels
// (#347, tasks 6.2-6.4). This file is detection only: it decides WHEN a
// channel crosses a threshold and in which direction. Turning a crossing into
// a Ciena notification is the catalog/exporter half.
//
// # Why this needs a goroutine at all
//
// Tier C's interface notifications work because `SetOperStatus` is a mutator:
// something calls it, and the broadcast hook fires. Optical values have no
// mutator. They are pure functions of elapsed time, so a channel can drift
// across the FEC threshold with nothing in the process aware of it.
//
// Three ways to notice, two of them wrong:
//
//   - Lazily, on read. Then an alarm exists only if somebody happens to poll,
//     and a fleet nobody is watching is silently healthy. Alarms must not
//     depend on observation.
//   - A goroutine per device or per channel. 30k devices means 30k goroutines
//     to do arithmetic that takes microseconds.
//   - One shared evaluator over a min-heap, which is what the flap and trap
//     schedulers already do at fleet scale. That is this file.
//
// # Why hysteresis is mandatory rather than nice
//
// Both dials are sinusoids. A channel whose mean sits near a threshold does
// not cross it once; it crosses on every period, forever, generating an
// unbounded alarm/clear storm that would be indistinguishable from a real
// flapping span. Real gear carries soak timers for exactly this reason, so
// there are two independent guards here: a dB margin the signal must recover
// through before a clear, and a soak interval the new condition must hold for
// before either transition is published.

// Threshold semantics, in OTN terms:
//
//	SD (Signal Degrade) — predictive. BER is visibly elevated but FEC is still
//	    correcting, so traffic is unaffected. This is the alarm worth acting on.
//	SF (Signal Fail)    — service-affecting. Past the SD-FEC threshold, so
//	    uncorrectable blocks accrue and traffic is damaged.
//
// SF deliberately reuses the SD-FEC threshold that already gates
// `fec-uncorrectable-blocks`, so "SF raised" and "the counter is advancing"
// can never disagree. Deriving them from two independent constants would let
// them drift into contradicting each other.
const (
	// opticalSFThresholdBER is the service-affecting threshold. Same constant
	// as the block counter's, by construction.
	opticalSFThresholdBER = opticalSDFECThresholdBER

	// opticalSDThresholdBER is the predictive threshold. Chosen to sit between
	// the shipped `typical` and `degraded` bands (1.0e-03 and 3.2e-03), so a
	// `degraded` device raises SD and stays clear of SF — which is exactly the
	// window the degraded tier exists to represent — while a `typical` device
	// stays quiet.
	opticalSDThresholdBER = 2e-3

	// opticalAlarmHysteresisDB is how far OSNR must recover ABOVE a raise
	// threshold before the corresponding clear is published. Without it a
	// channel idling at the threshold alarms once per dial period forever.
	opticalAlarmHysteresisDB = 0.5

	// opticalAlarmSoak is how long a new condition must hold before it is
	// published, in either direction. The second guard: hysteresis handles a
	// channel resting near the line, soak handles a brief excursion through
	// it.
	opticalAlarmSoak = 30 * time.Second

	// opticalAlarmInterval is the evaluation cadence per channel. Fast enough
	// that a crossing is noticed promptly relative to the soak, cheap enough
	// that 30k channels cost nothing: each evaluation is a handful of flops.
	opticalAlarmInterval = 5 * time.Second
)

// opticalSDThresholdDB / opticalSFThresholdDB are the BER thresholds expressed
// on the OSNR axis, which is where hysteresis is applied.
//
// Hysteresis in dB rather than in BER is deliberate. BER is an erfc tail:
// near the SD-FEC threshold it moves only ~3x per 2 dB, so a "10% of BER"
// margin would be a vanishing fraction of a dB and would not damp anything.
// OSNR is the underlying near-linear quantity, so a margin there means what
// it looks like.
//
// Derived from the same cascade as the thresholds themselves, by bisection,
// so the two can never drift apart. Memoised: each costs ~100 erfc+pow pairs.
var (
	opticalSDThresholdDB = sync.OnceValue(func() float64 { return osnrForBER(opticalSDThresholdBER) })
	opticalSFThresholdDB = sync.OnceValue(func() float64 { return osnrForBER(opticalSFThresholdBER) })
)

// osnrForBER inverts the OSNR -> Q -> BER cascade by bisection. BER is
// monotonically decreasing in OSNR, so the bisection is well-posed.
func osnrForBER(targetBER float64) float64 {
	lo, hi := opticalQFloorDB, opticalQCeilDB
	for i := 0; i < 100; i++ {
		mid := (lo + hi) / 2
		if berFromQDB(mid) > targetBER {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo + opticalQOffsetDB
}

// opticalCondition identifies which threshold an event concerns.
type opticalCondition uint8

const (
	opticalCondSD opticalCondition = iota
	opticalCondSF
)

func (c opticalCondition) String() string {
	if c == opticalCondSF {
		return "SF"
	}
	return "SD"
}

// OpticalAlarmEvent is one published transition. `Raised` false is a CLEAR,
// which is a distinct event rather than the absence of one: a collector
// cannot infer a clear from silence.
type OpticalAlarmEvent struct {
	DeviceIP  net.IP
	Component string
	Condition opticalCondition
	Raised    bool
	// OSNRdB is the value that triggered the transition, for the
	// notification's description varbind.
	OSNRdB float64
	At     time.Time
}

// OpticalAlarmNotifyFn receives published transitions. Installed by the
// manager; called from the evaluator goroutine, so implementations must not
// block on it (the exporter wiring snapshots and fires asynchronously).
type OpticalAlarmNotifyFn func(OpticalAlarmEvent)

// alarmLatch is the per-(channel, condition) debounce state. Published state
// is what a collector has been told; pending/since track a candidate change
// that has not yet soaked.
type alarmLatch struct {
	raised   bool
	pending  bool
	since    time.Time
	hasSince bool
}

// evaluate folds one observation into the latch and reports whether a
// transition should be published.
//
// The asymmetry between raise and clear is the hysteresis: raising needs OSNR
// below the threshold, clearing needs it above threshold+margin. Between the
// two lies a dead band where neither fires, which is what stops a channel
// resting on the line from oscillating.
func (l *alarmLatch) evaluate(osnr, thresholdDB float64, now time.Time, soak time.Duration) (publish bool) {
	var want bool
	switch {
	case osnr < thresholdDB:
		want = true
	case osnr > thresholdDB+opticalAlarmHysteresisDB:
		want = false
	default:
		// Dead band: hold whatever is published and abandon any candidate,
		// since the signal has not committed in either direction.
		l.pending, l.hasSince = l.raised, false
		return false
	}

	if want == l.raised {
		// Back to the published state; a candidate in flight is abandoned.
		l.pending, l.hasSince = want, false
		return false
	}
	if !l.hasSince || l.pending != want {
		// A new candidate starts its soak now. Deliberately falls through to
		// the elapsed check rather than returning: with soak == 0 the caller
		// means "no debounce", and requiring a second observation anyway would
		// silently turn that into "one evaluation interval".
		l.pending, l.since, l.hasSince = want, now, true
	}
	if now.Sub(l.since) < soak {
		return false
	}
	l.raised, l.hasSince = want, false
	return true
}

// opticalAlarmEntry is one enrolled channel in the evaluator's heap.
type opticalAlarmEntry struct {
	nextEval  time.Time
	deviceIP  net.IP
	component string
	oc        *OpticalCycler
	sd        alarmLatch
	sf        alarmLatch
	index     int
}

type opticalAlarmHeap []*opticalAlarmEntry

func (h opticalAlarmHeap) Len() int           { return len(h) }
func (h opticalAlarmHeap) Less(i, j int) bool { return h[i].nextEval.Before(h[j].nextEval) }
func (h opticalAlarmHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *opticalAlarmHeap) Push(x interface{}) {
	e := x.(*opticalAlarmEntry)
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *opticalAlarmHeap) Pop() interface{} {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	e.index = -1
	*h = old[:n-1]
	return e
}

// OpticalAlarmEvaluator is the single shared goroutine that notices threshold
// crossings for every optical channel in the fleet. Same shape as
// FlapScheduler and the trap/syslog schedulers: one min-heap, one goroutine,
// O(1) timers regardless of fleet size.
type OpticalAlarmEvaluator struct {
	mu    sync.Mutex
	heap  opticalAlarmHeap
	byKey map[opticalAlarmKey]*opticalAlarmEntry

	notify   OpticalAlarmNotifyFn
	now      func() time.Time
	interval time.Duration
	soak     time.Duration

	wake     chan struct{}
	stopCh   chan struct{}
	stopOnce sync.Once
}

type opticalAlarmKey struct {
	ip        string
	component string
}

// OpticalAlarmEvaluatorOptions groups the injectable bits. Zero values are
// replaced with the package defaults, so tests can pin a clock and shorten the
// soak without every caller naming them.
type OpticalAlarmEvaluatorOptions struct {
	Notify   OpticalAlarmNotifyFn
	Now      func() time.Time
	Interval time.Duration
	Soak     time.Duration
}

func NewOpticalAlarmEvaluator(opts OpticalAlarmEvaluatorOptions) *OpticalAlarmEvaluator {
	e := &OpticalAlarmEvaluator{
		byKey:    make(map[opticalAlarmKey]*opticalAlarmEntry),
		notify:   opts.Notify,
		now:      opts.Now,
		interval: opts.Interval,
		soak:     opts.Soak,
		wake:     make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.interval <= 0 {
		e.interval = opticalAlarmInterval
	}
	if e.soak <= 0 {
		e.soak = opticalAlarmSoak
	}
	return e
}

// Register enrolls every channel of one device. Idempotent per (device,
// channel): re-registering keeps the existing latch so a restart of the
// enrolling caller cannot replay alarms a collector has already seen.
func (e *OpticalAlarmEvaluator) Register(deviceIP net.IP, oc *OpticalCycler) {
	if oc == nil || len(deviceIP) == 0 {
		return
	}
	ip := deviceIP.String()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, name := range oc.Components() {
		key := opticalAlarmKey{ip: ip, component: name}
		if _, exists := e.byKey[key]; exists {
			continue
		}
		entry := &opticalAlarmEntry{
			nextEval:  e.now().Add(e.interval),
			deviceIP:  append(net.IP(nil), deviceIP...),
			component: name,
			oc:        oc,
		}
		heap.Push(&e.heap, entry)
		e.byKey[key] = entry
	}
	e.nudge()
}

// Deregister drops every channel of a device. Called on device deletion so a
// removed device's channels stop being evaluated.
func (e *OpticalAlarmEvaluator) Deregister(deviceIP net.IP) {
	ip := deviceIP.String()
	e.mu.Lock()
	defer e.mu.Unlock()
	for key, entry := range e.byKey {
		if key.ip != ip {
			continue
		}
		if entry.index >= 0 && entry.index < e.heap.Len() {
			heap.Remove(&e.heap, entry.index)
		}
		delete(e.byKey, key)
	}
	e.nudge()
}

// Run blocks until ctx is cancelled or Stop is called.
func (e *OpticalAlarmEvaluator) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		default:
		}

		e.mu.Lock()
		if e.heap.Len() == 0 {
			e.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-e.stopCh:
				return
			case <-e.wake:
				continue
			}
		}
		next := e.heap[0].nextEval
		e.mu.Unlock()

		if delay := next.Sub(e.now()); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-e.stopCh:
				timer.Stop()
				return
			case <-e.wake:
				timer.Stop()
				continue
			case <-timer.C:
			}
		}

		e.mu.Lock()
		if e.heap.Len() == 0 {
			e.mu.Unlock()
			continue
		}
		entry := heap.Pop(&e.heap).(*opticalAlarmEntry)
		now := e.now()
		events := entry.evaluateAt(now, e.soak)
		entry.nextEval = now.Add(e.interval)
		heap.Push(&e.heap, entry)
		e.mu.Unlock()

		// Publish outside the lock: the notify hook reaches into device state
		// and the exporters, and holding the evaluator lock across that would
		// couple two lock domains for no reason.
		for _, ev := range events {
			if e.notify != nil {
				e.notify(ev)
			}
		}
	}
}

// evaluateAt folds one observation into both latches and returns the
// transitions to publish. Caller holds e.mu.
//
// Ordering matters on the way in and on the way out: SD is the predictive
// alarm and SF the service-affecting one, so a channel degrading fast enough
// to cross both in a single evaluation raises SD before SF, and on recovery
// clears SF before SD. A collector watching the pair sees a coherent
// escalation and de-escalation rather than an arbitrary order.
func (a *opticalAlarmEntry) evaluateAt(now time.Time, soak time.Duration) []OpticalAlarmEvent {
	slot, ok := a.oc.slot[a.component]
	if !ok {
		return nil
	}
	t := now.Sub(a.oc.StartTime()).Seconds()
	osnr := a.oc.osnrAt(slot, t)
	if math.IsNaN(osnr) {
		return nil
	}

	var events []OpticalAlarmEvent
	sdWas, sfWas := a.sd.raised, a.sf.raised
	sdPub := a.sd.evaluate(osnr, opticalSDThresholdDB(), now, soak)
	sfPub := a.sf.evaluate(osnr, opticalSFThresholdDB(), now, soak)

	emit := func(c opticalCondition, raised bool) {
		events = append(events, OpticalAlarmEvent{
			DeviceIP: a.deviceIP, Component: a.component,
			Condition: c, Raised: raised, OSNRdB: osnr, At: now,
		})
	}
	// Raises escalate SD -> SF; clears de-escalate SF -> SD.
	if sdPub && !sdWas {
		emit(opticalCondSD, true)
	}
	if sfPub && !sfWas {
		emit(opticalCondSF, true)
	}
	if sfPub && sfWas {
		emit(opticalCondSF, false)
	}
	if sdPub && sdWas {
		emit(opticalCondSD, false)
	}
	return events
}

func (e *OpticalAlarmEvaluator) Stop() {
	e.stopOnce.Do(func() { close(e.stopCh) })
}

func (e *OpticalAlarmEvaluator) nudge() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// ActiveAlarms reports the currently published conditions for one channel,
// for the status surface and for tests. ok=false when the channel is not
// enrolled.
func (e *OpticalAlarmEvaluator) ActiveAlarms(deviceIP, component string) (sd, sf bool, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	entry, found := e.byKey[opticalAlarmKey{ip: deviceIP, component: component}]
	if !found {
		return false, false, false
	}
	return entry.sd.raised, entry.sf.raised, true
}
