/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sync"
	"sync/atomic"
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

// closeAndWait stops admitting new fires and blocks until every admitted
// fire has left. Idempotent-safe to call once per scenario at finalize.
//
// There is NO timeout, and no configurable grace bounds it (nl6#500 removed the
// inert `drain` knob that was once claimed to). What bounds it is what an
// admitted write can block on — see abortActiveScenario for the per-transport
// bound and the case where it does not hold.
func (d *drainGate) closeAndWait() {
	d.mu.Lock()
	d.closed.Store(true)
	d.mu.Unlock()
	d.wg.Wait()
}
