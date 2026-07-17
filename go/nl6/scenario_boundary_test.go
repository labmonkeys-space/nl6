/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

// TestScenarioBoundaryDecisionsAreSettled pins the PR0 boundary decision
// record: flipping either constant is an architecture change that reworks
// every producer site and MUST NOT happen casually. If you are editing this
// test, read the PR0 section of the architecture document first.
func TestScenarioBoundaryDecisionsAreSettled(t *testing.T) {
	if !scenarioCountAtWriteReturn {
		t.Fatal("PR0 decision violated: SENT must be counted at socket-write-return")
	}
	if !scenarioWindowHalfOpen {
		t.Fatal("PR0 decision violated: the measurement window must be half-open [T0, T1)")
	}
}
