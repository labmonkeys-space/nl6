/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

// restoreLinkMTU puts the package-global MTU and every derived budget back to
// the default when the test ends. These are process-wide startup values, so a
// test that changes one must not leak it into the next.
func restoreLinkMTU(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		linkMTU = defaultLinkMTU
		recomputeDatagramBudgets()
	})
}

// TestSetLinkMTU_RecomputesDerivedBudgets is the guarantee the -datagram-mtu
// flag rests on: one flag reaches every subsystem. A budget that captured its
// value at package-init time would keep the 1500-derived number and silently
// fragment on exactly the lower-MTU paths the flag exists to serve — which is
// the failure mode the whole nl6#485 / #487 / #489 family is made of.
func TestSetLinkMTU_RecomputesDerivedBudgets(t *testing.T) {
	restoreLinkMTU(t)

	// Default: the values every other test in this package assumes.
	if maxFlowPayloadIPv4 != 1472 || maxFlowPayloadIPv6 != 1452 || flowBufSize != 1500 {
		t.Fatalf("at default MTU: v4=%d v6=%d buf=%d, want 1472/1452/1500",
			maxFlowPayloadIPv4, maxFlowPayloadIPv6, flowBufSize)
	}

	// A stock Docker overlay. Measured on this build at 1500, NetFlow v9
	// frames reach 1480, IPFIX 1484 and NetFlow v5 1492 — all of which
	// fragment at 1450, which is why this knob exists (nl6#488, design D2).
	if err := SetLinkMTU(1450); err != nil {
		t.Fatalf("SetLinkMTU(1450): %v", err)
	}
	if got, want := maxFlowPayloadIPv4, 1450-20-8; got != want {
		t.Errorf("maxFlowPayloadIPv4 = %d, want %d — the flag did not reach flow's IPv4 budget", got, want)
	}
	if got, want := maxFlowPayloadIPv6, 1450-40-8; got != want {
		t.Errorf("maxFlowPayloadIPv6 = %d, want %d — the flag did not reach flow's IPv6 budget", got, want)
	}
	if flowBufSize != 1450 {
		t.Errorf("flowBufSize = %d, want 1450 — a pooled buffer must never be smaller "+
			"than a budget derived from it, so it tracks the MTU", flowBufSize)
	}
}

// TestSetLinkMTU_RejectsOutOfRange checks the value is refused at startup
// rather than surfacing later as silent per-emission encode errors across the
// whole fleet.
func TestSetLinkMTU_RejectsOutOfRange(t *testing.T) {
	restoreLinkMTU(t)

	for _, tc := range []struct {
		name string
		mtu  int
		ok   bool
	}{
		{"zero", 0, false},
		{"negative", -1, false},
		{"below the IPv4 minimum reassembly buffer", minLinkMTU - 1, false},
		{"at the floor", minLinkMTU, true},
		{"standard ethernet", 1500, true},
		{"docker overlay", 1450, true},
		{"jumbo", 9000, true},
		{"above a 16-bit datagram", 65536, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := SetLinkMTU(tc.mtu)
			if tc.ok && err != nil {
				t.Errorf("SetLinkMTU(%d) = %v, want accepted", tc.mtu, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("SetLinkMTU(%d) accepted, want rejected", tc.mtu)
			}
		})
	}
}

// TestSetLinkMTU_RejectionLeavesBudgetsIntact checks a refused value does not
// half-apply. SetLinkMTU validates before assigning, so a startup that logs
// the error and exits never runs on a partially-updated budget set — and a
// caller that chose to continue would still see coherent values.
func TestSetLinkMTU_RejectionLeavesBudgetsIntact(t *testing.T) {
	restoreLinkMTU(t)

	if err := SetLinkMTU(1450); err != nil {
		t.Fatalf("SetLinkMTU(1450): %v", err)
	}
	before := [3]int{maxFlowPayloadIPv4, maxFlowPayloadIPv6, flowBufSize}

	if err := SetLinkMTU(0); err == nil {
		t.Fatal("SetLinkMTU(0) accepted, want rejected")
	}
	after := [3]int{maxFlowPayloadIPv4, maxFlowPayloadIPv6, flowBufSize}

	if before != after {
		t.Errorf("budgets changed on a rejected value: %v -> %v", before, after)
	}
	if linkMTU != 1450 {
		t.Errorf("linkMTU = %d after a rejected call, want the previous 1450", linkMTU)
	}
}
