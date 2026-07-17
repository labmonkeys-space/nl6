/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

// Scenario accounting boundary decisions (load-test scenario subsystem,
// PR0). This file is the binding decision record the scenario ledger
// (story 1.2) implements against. Changing either decision after counters
// exist reworks every producer site — it is deliberately settled BEFORE any
// counter is placed (architecture: "the single riskiest sequencing
// assumption").
//
//  1. SENT is counted at socket-write-return. A record is "sent" exactly
//     when its socket write returns success — never at enqueue or
//     scheduling time. Local write failures count `send_failures`;
//     pre-attempt drops (drop-oldest buffers) count `dropped`; gate
//     suppression of a generated record counts `suppressed_pre_window`.
//
//  2. The measurement window is half-open [T0, T1). A record whose write
//     returns at time t with T0 <= t < T1 buckets `in_window`; a write
//     completing at t >= T1 within the drain grace buckets `drain`. Bucket
//     classification always uses a FRESH clock read taken after the write
//     returns — never the fire-decision timestamp.
const (
	// scenarioCountAtWriteReturn records decision 1 (SENT@socket-write-return).
	scenarioCountAtWriteReturn = true
	// scenarioWindowHalfOpen records decision 2 (half-open [T0,T1) window).
	scenarioWindowHalfOpen = true
)
