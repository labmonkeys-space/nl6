/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

// Test shims for the nl6#694 mutator reshape.
//
// SetOperStatus became SetLinkState with a THREE-way outcome, and
// SetAdminStatus was unexported behind the ApplyAdminStatus funnel. The great
// majority of this package's tests mutate an admin-up interface, where "the
// link moved" and "the observable oper-status moved" are the same statement —
// for those, a shim preserving the old (bool, StateChange) shape keeps the
// diff honest and small.
//
// THESE SHIMS DELIBERATELY COLLAPSE THE MASKED OUTCOME. A test that cares
// whether a move was masked MUST call SetLinkState directly and switch on the
// LinkMutation; if it used setLinkVisible it would read LinkMovedMasked as
// "nothing happened", which is the exact conflation nl6#694 removed from the
// flap scheduler. Masking behaviour is covered in interface_state_test.go and
// flap_scheduler_test.go against the real API.

// setLinkVisible drives SetLinkState and reports whether the DERIVED
// oper-status moved — the old SetOperStatus `changed` bool. A masked move
// (admin down or testing) reports false here even though the link was stored.
func setLinkVisible(s *InterfaceState, ifIndex int, v uint8) (bool, StateChange) {
	res, evt := s.SetLinkState(ifIndex, v)
	return res == LinkMovedVisible, evt
}

// setAdminOne drives the admin funnel and returns the ADMIN leaf event plus
// whether the admin leaf moved. The funnel may also return a derived
// oper-status event; a test asserting on that second event calls
// ApplyAdminStatus directly.
func setAdminOne(s *InterfaceState, ifIndex int, v uint8) (bool, StateChange) {
	evts := s.ApplyAdminStatus(ifIndex, v)
	if len(evts) == 0 {
		return false, StateChange{}
	}
	return true, evts[0]
}
