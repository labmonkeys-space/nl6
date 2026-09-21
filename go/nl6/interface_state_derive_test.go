/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"strings"
	"testing"
)

// The derivation (nl6#694): oper-status is a function of (admin, link), not a
// stored leaf, and RFC 2863's rule for it is ASYMMETRIC.

// TestDeriveOperMatchesRFC2863 pins the rule against the CHECKED-IN MIB text
// rather than against a paraphrase in a comment.
//
// The extract is testdata/rfc/rfc2863-if-status-objects.txt, the same
// convention as rfc3414-a3-password-to-key.txt. Reading it here means a future
// edit that "tidies" the derivation has to disagree with the published
// definition in the same repo, not merely with a sentence somebody wrote.
func TestDeriveOperMatchesRFC2863(t *testing.T) {
	raw, err := os.ReadFile("testdata/rfc/rfc2863-if-status-objects.txt")
	if err != nil {
		t.Fatalf("read the RFC 2863 extract: %v", err)
	}
	// Normalise the MIB's hanging indentation to single spaces so the
	// assertions below are about wording, not about column positions.
	text := strings.Join(strings.Fields(string(raw)), " ")

	// Each clause of the rule, quoted from the DESCRIPTION, with the behaviour
	// it dictates. If a clause is not in the extract the test fails rather than
	// silently asserting nothing — a substring check that never matches is the
	// classic vacuous guard.
	clauses := []struct {
		quote string
		check func(t *testing.T)
	}{
		{
			quote: "If ifAdminStatus is down(2) then ifOperStatus should be down(2).",
			check: func(t *testing.T) {
				for link := OperUp; link <= OperLowerLayerDn; link++ {
					if got := deriveOper(AdminDown, link); got != OperDown {
						t.Errorf("deriveOper(down, link=%d) = %d, want down(2)", link, got)
					}
				}
			},
		},
		{
			// The half nl6 inverted before this change. "should change to up(1)
			// IF the interface is ready" is conditional; a faulted link is not
			// ready, and the next clause says so explicitly.
			quote: "If ifAdminStatus is changed to up(1) then ifOperStatus should change to up(1) if the interface is ready to transmit and receive network traffic",
			check: func(t *testing.T) {
				if got := deriveOper(AdminUp, OperUp); got != OperUp {
					t.Errorf("deriveOper(up, link=up) = %d, want up(1)", got)
				}
			},
		},
		{
			quote: "it should remain in the down(2) state if and only if there is a fault that prevents it from going to the up(1) state",
			check: func(t *testing.T) {
				if got := deriveOper(AdminUp, OperDown); got != OperDown {
					t.Errorf("deriveOper(up, link=down) = %d, want down(2): admin-up does not "+
						"clear a fault, and treating it as if it did is what let an admin "+
						"bounce repair a simulated cable pull", got)
				}
			},
		},
		{
			quote: "The testing(3) state indicates that no operational packets can be passed.",
			check: func(t *testing.T) {
				for link := OperUp; link <= OperLowerLayerDn; link++ {
					if got := deriveOper(AdminTesting, link); got != OperTesting {
						t.Errorf("deriveOper(testing, link=%d) = %d, want testing(3)", link, got)
					}
				}
			},
		},
	}

	for _, c := range clauses {
		want := strings.Join(strings.Fields(c.quote), " ")
		if !strings.Contains(text, want) {
			t.Fatalf("the checked-in RFC 2863 extract does not contain the clause this test "+
				"claims to implement:\n  %q\n"+
				"Either the extract was re-cut and lost text, or the quote was mistyped. "+
				"A clause that is not present makes its assertion vacuous.", want)
		}
		c.check(t)
	}
}

// TestDeriveOperIsTheOnlyRule sweeps every reachable (admin, link) pair and
// requires the snapshot's derived oper to equal the derivation applied to that
// same snapshot's own fields. A read site that hand-rolled the rule — or a
// Snapshot that read the slot twice — fails here.
func TestDeriveOperIsTheOnlyRule(t *testing.T) {
	s := NewInterfaceState(64, nil, nil)
	slot := 0
	for admin := AdminUp; admin <= AdminTesting; admin++ {
		for link := OperUp; link <= OperLowerLayerDn; link++ {
			slot++
			s.Seed(slot, link, admin)

			snap := s.Snapshot(slot)
			if !snap.Found {
				t.Fatalf("slot %d not found after Seed", slot)
			}
			if snap.Link != link || snap.Admin != admin {
				t.Errorf("slot %d stored (link=%d admin=%d), want (%d %d)",
					slot, snap.Link, snap.Admin, link, admin)
			}
			if want := deriveOper(snap.Admin, snap.Link); snap.Oper != want {
				t.Errorf("slot %d: Snapshot.Oper = %d, want deriveOper(%d, %d) = %d",
					slot, snap.Oper, snap.Admin, snap.Link, want)
			}
			// The standalone accessor must agree with the snapshot, or SNMP and
			// gNMI can disagree at one instant.
			if got := s.OperStatus(slot); got != snap.Oper {
				t.Errorf("slot %d: OperStatus() = %d but Snapshot().Oper = %d", slot, got, snap.Oper)
			}
			if got := s.LinkState(slot); got != snap.Link {
				t.Errorf("slot %d: LinkState() = %d but Snapshot().Link = %d", slot, got, snap.Link)
			}
		}
	}
}

// TestAdminDownWithOperUpIsUnrepresentable is the invariant stated as a
// property rather than as a sequence: no reachable combination of mutations can
// produce the state RFC 2863 forbids.
//
// It drives the REAL mutators in every order, which is what distinguishes it
// from asserting the derivation function in isolation — the defect nl6#694
// reported was reachable precisely because a mutator wrote oper directly.
func TestAdminDownWithOperUpIsUnrepresentable(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperUp, AdminUp)

	admins := []uint8{AdminUp, AdminDown, AdminTesting}
	links := []uint8{OperUp, OperDown, OperTesting, OperUnknown, OperDormant, OperNotPresent, OperLowerLayerDn}

	assert := func(where string) {
		t.Helper()
		snap := s.Snapshot(1)
		if snap.Admin == AdminDown && snap.Oper == OperUp {
			t.Fatalf("%s: reached admin=down(2) with oper=up(1), which RFC 2863 forbids: %+v", where, snap)
		}
		if snap.Admin == AdminTesting && snap.Oper != OperTesting {
			t.Fatalf("%s: admin=testing(3) with oper=%d, want testing(3): %+v", where, snap.Oper, snap)
		}
	}

	// Every admin x link ordering, both ways round.
	for _, a := range admins {
		for _, l := range links {
			s.ApplyAdminStatus(1, a)
			assert("after admin")
			s.SetLinkState(1, l)
			assert("after link")

			s.SetLinkState(1, l)
			assert("after link (repeat)")
			s.ApplyAdminStatus(1, a)
			assert("after admin (repeat)")
		}
	}
}

// TestMaskedLinkMoveIsStoredSilentlyAndSurfacesOnAdminUp is the masking
// contract end to end on the engine: stored, unobservable, no event, no
// lastChange, and visible the moment admin rises — with no further mutation.
func TestMaskedLinkMoveIsStoredSilentlyAndSurfacesOnAdminUp(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperDown, AdminDown) // shut port, dead cable

	ch := make(chan StateChange, 8)
	s.AddListener(ch)
	defer s.RemoveListener(ch)
	hooks := 0
	s.SetNotify(func(StateChange) { hooks++ })
	defer s.SetNotify(nil)

	before := s.Snapshot(1)

	res, evt := s.SetLinkState(1, OperUp)
	if res != LinkMovedMasked {
		t.Fatalf("SetLinkState under admin-down = %v, want LinkMovedMasked", res)
	}
	s.Broadcast(evt) // a caller that broadcasts the zero event must not fire anything

	after := s.Snapshot(1)
	if after.Link != OperUp {
		t.Errorf("link = %d, want up(1): a masked move is STORED, not discarded", after.Link)
	}
	if after.Oper != OperDown {
		t.Errorf("oper = %d, want down(2): admin-down masks the link", after.Oper)
	}
	if after.LastChangeNs != before.LastChangeNs {
		t.Errorf("ifLastChange moved (%d -> %d) for a masked link change; RFC 2863 defines it as "+
			"the time the interface entered its current OPERATIONAL state",
			before.LastChangeNs, after.LastChangeNs)
	}
	if len(ch) != 0 {
		t.Errorf("a masked move broadcast %d events, want 0", len(ch))
	}
	if hooks != 0 {
		t.Errorf("a masked move fired the notify hook %d times, want 0 (no linkUp trap for a shut port)", hooks)
	}

	// Raising admin surfaces it, with no further link mutation.
	evts := s.ApplyAdminStatus(1, AdminUp)
	if len(evts) != 2 {
		t.Fatalf("admin up returned %d events, want 2 (admin then the surfaced oper): %+v", len(evts), evts)
	}
	if got := s.OperStatus(1); got != OperUp {
		t.Errorf("oper after admin up = %d, want up(1)", got)
	}
	for _, e := range evts {
		s.Broadcast(e)
	}
	if hooks != 1 {
		t.Errorf("notify hook fired %d times on the surfacing transition, want 1", hooks)
	}
}

// TestRepeatedMaskedFlapsNeverStampLastChange is the fleet-scale version: under
// `-if-scenario 1 -if-flap-scenario aggressive` every fire is masked, and a
// build that stamped lastChange on the stored-but-masked write would make every
// shut interface report a fresh transition on every flap.
func TestRepeatedMaskedFlapsNeverStampLastChange(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperUp, AdminDown)
	before := s.Snapshot(1)

	for i := 0; i < 50; i++ {
		target := OperDown
		if i%2 == 1 {
			target = OperUp
		}
		if res, _ := s.SetLinkState(1, target); res != LinkMovedMasked {
			t.Fatalf("flap %d: got %v, want LinkMovedMasked", i, res)
		}
	}
	after := s.Snapshot(1)
	if after.LastChangeNs != before.LastChangeNs {
		t.Errorf("50 masked flaps moved ifLastChange (%d -> %d)", before.LastChangeNs, after.LastChangeNs)
	}
	if after.Oper != OperDown {
		t.Errorf("oper = %d, want down(2) throughout", after.Oper)
	}
}

// TestLinkMutationOutcomesAreDistinct pins that the three outcomes are actually
// distinguishable. The bool this replaced conflated LinkUnchanged with
// LinkMovedMasked, which is why the flap scheduler's no-op log line had to name
// two causes — one of which described a guard that did not exist.
func TestLinkMutationOutcomesAreDistinct(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperUp, AdminUp)

	if res, _ := s.SetLinkState(1, OperUp); res != LinkUnchanged {
		t.Errorf("already at target: got %v, want LinkUnchanged", res)
	}
	if res, _ := s.SetLinkState(1, OperDown); res != LinkMovedVisible {
		t.Errorf("visible move: got %v, want LinkMovedVisible", res)
	}
	s.ApplyAdminStatus(1, AdminDown)
	if res, _ := s.SetLinkState(1, OperUp); res != LinkMovedMasked {
		t.Errorf("masked move: got %v, want LinkMovedMasked", res)
	}
	if res, _ := s.SetLinkState(1, 0); res != LinkUnchanged {
		t.Errorf("invalid enum: got %v, want LinkUnchanged", res)
	}
	if res, _ := s.SetLinkState(99, OperUp); res != LinkUnchanged {
		t.Errorf("out-of-range ifIndex: got %v, want LinkUnchanged", res)
	}
}
