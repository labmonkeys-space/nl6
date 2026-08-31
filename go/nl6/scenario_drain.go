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
	return true
}

// leave marks one admitted fire complete.
func (d *drainGate) leave() { d.wg.Done() }

// drainWatchdogInterval is how long the barrier waits before it starts saying
// so. It is a LOG cadence, not a timeout: the wait is still unbounded (see
// nl6#567). Without it, an admitted fire that never calls leave() — a panic on
// a write path, a dropped callback — hangs finalize and shutdown with no line
// anywhere, which is indistinguishable from a deadlock in the controller. The
// interval is far longer than any legitimate write can take (the longest bound
// in the tree is syslog TCP's 2s per write) so a healthy run never logs.
const drainWatchdogInterval = 30 * time.Second

// maxDrainWatchdogReports caps how many times the watchdog speaks. The cap is
// not politeness: an endlessly-armed timer keeps a `synctest` bubble live, so a
// deadlock in a test that finalizes a scenario would advance the fake clock
// forever instead of failing as the deadlock it is. Ten reports (five minutes)
// is long past any legitimate write and short enough that the bubble goes back
// to a plain, deadlock-detectable wait afterwards.
const maxDrainWatchdogReports = 10

// closeAndWait stops admitting new fires and blocks until every admitted
// fire has left. Idempotent-safe to call once per scenario at finalize.
//
// There is NO timeout, and no configurable grace bounds it (nl6#500 removed the
// inert `drain` knob that was once claimed to). What bounds it in practice is
// what an admitted write can block on — see abortActiveScenario for the
// per-transport bound and the cases where it does not hold. Bounding it for
// real is nl6#567; until then the watchdog below makes the pathological case
// visible instead of silent.
func (d *drainGate) closeAndWait() {
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
	for reports := 0; reports < maxDrainWatchdogReports; reports++ {
		select {
		case <-done:
			return
		case <-tick.C:
			// Repeats deliberately: the operator needs to know it is STILL
			// stuck, and one line at the 30s mark of an hour-long hang reads
			// like a blip that resolved.
			log.Printf("WARNING: scenario drain barrier still waiting after %s for in-flight sends to return; "+
				"shutdown is blocked until they do (nl6#567)", time.Since(started).Round(time.Second))
		}
	}
	tick.Stop()
	<-done
}
