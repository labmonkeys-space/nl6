/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// drainGate is the scenario's admission + drain barrier. It replaces a bare
// sync.WaitGroup to make the "admit a fire" and "close and wait for
// in-flight fires" operations mutually safe — a raw wg.Add racing wg.Wait
// (counter already drained to 0) panics with "WaitGroup misuse: Add called
// concurrently with Wait", which is reachable when an out-of-band fire
// (state-driven / on-demand — NOT stopped by the scheduler) admits itself
// just as the controller finalizes.
//
// admit() takes the read lock, checks the closed flag, and Adds — all
// atomically w.r.t. closeAndWait, which takes the write lock to set closed
// before Wait. So every admitted fire's Add happens-before Wait observes
// the counter, and no fire can Add after closeAndWait has begun waiting.
type drainGate struct {
	mu     sync.RWMutex
	closed atomic.Bool
	wg     sync.WaitGroup

	// inflight shadows wg's counter, because a sync.WaitGroup cannot be read.
	// Since nl6#567 closeAndWait can give up while fires are still running, and
	// a report that says "finalized with stragglers" has to say how many. Moved
	// under the same read lock as wg.Add, so it cannot be incremented after
	// closeAndWait has taken the write lock; the decrement in leave() is
	// deliberately NOT locked, matching wg.Done, since a straggler decrements
	// long after the gate closed and taking the lock there would serialise
	// every completion against finalize for no gain.
	inflight atomic.Int64
}

// admit registers one in-flight fire. Returns false if the gate has closed
// (the caller must then treat the fire as a straggler → dropped). On true,
// the caller MUST call leave() exactly once (defer).
func (d *drainGate) admit() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed.Load() {
		return false
	}
	d.wg.Add(1)
	d.inflight.Add(1)
	return true
}

// leave marks one admitted fire complete.
//
// wg.Done() FIRST, then the shadow counter. The order matters at exactly one
// instant: the ceiling firing between the two. Decrementing inflight first left
// a window in which the LAST fire had taken the count to 0 while `done` was not
// yet closed, so a give-up in that window logged "gave up with 0 in-flight
// send(s)" and returned 0 — which omitempty then drops, making a truncated
// finalize byte-identical to a clean one. This order inverts the error: the
// count can transiently read one HIGH, and closeAndWait prefers a closed `done`
// over the ceiling, so the high read is never the one that gets reported.
func (d *drainGate) leave() {
	d.wg.Done()
	d.inflight.Add(-1)
}

// drainWatchdogInterval is how long the barrier waits before it starts saying
// so. It is a LOG cadence, not the ceiling: the ceiling is drainBarrierTimeout
// below. Without it, an admitted fire that never calls leave(), because of a
// panic on a write path or a dropped callback, would hold finalize with no line
// anywhere until the ceiling expired. The interval is far longer than any
// legitimate write can take (the longest bound in the tree is syslog TCP's 2s
// per write) so a healthy run never logs.
const drainWatchdogInterval = 30 * time.Second

// drainBarrierTimeout is the ceiling on the barrier (nl6#567). Before it the
// wait was a bare wg.Wait(), so a single admitted fire that never returned held
// finalize open forever: abortActiveScenario runs closeAndWait on the
// graceful-shutdown path.
//
// PRIMARY, not derived. An earlier cut wrote it as 2*drainWatchdogInterval,
// which coupled the two in the wrong direction: lowering the watchdog to see
// the log sooner would silently shorten the CEILING, and at a 5s watchdog it
// would fall to 10s, below the worst case the next paragraph computes.
// TestDrainBarrierCeilingClearsItsInputs asserts the relationships instead, so
// they cannot drift without a test saying so.
//
// What it has to clear: the longest legitimate single write in the tree is
// syslog TCP/TLS at syslogTCPWriteTimeout (2s), and tcpTransport.Send holds
// writeMu across it, so a device's worst case is 2s times the fires queued
// behind that mutex before T1. 60s therefore covers roughly 30 queued syslog
// TCP fires on one device. It is NOT an unconditional margin: a device with a
// deeper queue than that has its legitimate writes counted and reported as
// stragglers. Stated as a number rather than as "wide" because the same
// paragraph computes an unbounded quantity, so "wide" would be self-refuting.
//
// It also replaced a maxDrainWatchdogReports cap that existed only to stop an
// endlessly-armed ticker keeping a `synctest` bubble live. A real ceiling does
// that job properly, so the cap went rather than sitting beside it.
//
// OPERATIONAL CAVEAT: 60s is longer than `docker stop`'s default 10s grace, so
// on a containerised deployment the process may be SIGKILLed before the ceiling
// fires and no report is written at all. Raise `stop_grace_period` above this
// value if a truncated report matters more than a fast stop.
const drainBarrierTimeout = 60 * time.Second

// closeAndWait stops admitting new fires and waits for every admitted fire to
// leave, giving up after drainBarrierTimeout. It returns the number of fires
// STILL IN FLIGHT when it returned: 0 on every healthy run, at least 1 when the
// ceiling expired. id names the scenario in the log lines, because a fleet can
// hold more than one controller and "which run truncated" is the operator's
// first question.
//
// Call it ONCE per scenario, at finalize. A second call with a live straggler
// arms a second ceiling and parks a second waiter, so the residual below is per
// call rather than per scenario; production has exactly one call site, inside
// the phase transition, so that does not arise.
//
// WHAT THIS BOUNDS, AND WHAT IT DOES NOT. It bounds the BARRIER. It does not by
// itself bound shutdown: finish() joins the scenario-owned trap and flow tickers
// BEFORE it reaches here, and those joins are unbounded, so a parked flow Tick
// write still holds finalize without the ceiling ever being armed. See
// abortActiveScenario.
//
// No configurable grace bounds it (nl6#500 removed the inert `drain` knob that
// was once claimed to) and none should: this is an internal ceiling, not a
// scenario field. What normally ends the wait is the work itself returning; see
// abortActiveScenario for the per-transport bounds.
//
// THE STRAGGLERS ARE NOT CANCELLED, and cannot be. Nothing here can interrupt a
// write parked in the kernel. They keep running, keep holding their
// *scenarioPart, and keep moving ledger counters after the caller has
// snapshotted them. Those counters are atomics, so there is no data race; the
// cost is that a report finalized with stragglers may not satisfy the ledger
// identity for the affected participants, which is why the count is reported
// rather than swallowed. Production never asserts that identity (every
// identityHolds call site is a test), so nothing fails on a live simulator.
func (d *drainGate) closeAndWait(id string) int64 {
	d.mu.Lock()
	d.closed.Store(true)
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	started := time.Now()
	tick := time.NewTicker(drainWatchdogInterval)
	defer tick.Stop()
	// A timer rather than a deadline loop: it arms once, and under synctest it
	// is what lets the fake clock reach the give-up instead of the bubble
	// blocking forever on a write that will never return.
	ceiling := time.NewTimer(drainBarrierTimeout)
	defer ceiling.Stop()
	for {
		select {
		case <-done:
			return 0
		case <-ceiling.C:
			// PREFER A COMPLETED DRAIN. select chooses uniformly at random among
			// ready cases, so a drain that finished at the very instant the
			// ceiling fired would otherwise be reported as a give-up: a WARNING
			// line and a straggler count describing a run that actually drained.
			select {
			case <-done:
				return 0
			default:
			}
			// At least one fire has not called wg.Done(), or `done` would be
			// closed and the check above would have returned. So the count is at
			// least 1 by construction, and flooring it is a statement of that
			// invariant rather than a fudge: leave() decrements the shadow after
			// wg.Done(), so a concurrent completion can only make this read LOW.
			// Reporting 0 here would drop the field via omitempty and make a
			// truncated finalize indistinguishable from a clean one.
			stragglers := max(d.inflight.Load(), 1)
			log.Printf("WARNING: [scenario %s] drain barrier gave up after %s with %d in-flight send(s) "+
				"still outstanding; the scenario is finalized WITH STRAGGLERS and its report says so. "+
				"Those sends are not cancelled and may still move ledger counters, so the affected "+
				"participants' counters may not add up (nl6#567)",
				id, time.Since(started).Round(time.Second), stragglers)
			return stragglers
		case <-tick.C:
			// The ticker and the ceiling both fire at the ceiling instant when
			// one is a multiple of the other, and select picks between them at
			// random: measured, that emitted a second "still waiting" line in 21
			// of 60 runs, telling the operator finalize was blocked "until the
			// ceiling expires" at the instant it had expired. Suppressing it
			// here is deterministic, where relying on the constants not being
			// multiples would be an accident waiting to be undone.
			if time.Since(started) >= drainBarrierTimeout {
				continue
			}
			// Repeats deliberately: the operator needs to know it is STILL
			// stuck, and one line at the 30s mark reads like a blip that
			// resolved.
			log.Printf("WARNING: [scenario %s] drain barrier still waiting after %s for in-flight sends "+
				"to return; finalize is blocked until they return or the %s ceiling expires (nl6#567)",
				id, time.Since(started).Round(time.Second), drainBarrierTimeout)
		}
	}
}
