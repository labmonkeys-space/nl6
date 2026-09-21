/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Masking across the mutation sources and the read surfaces (nl6#694).

// decodeOutcome reads the 202 body the oper/admin handlers now return. The
// body exists so a masked request is distinguishable from an applied one
// WITHOUT a second read — an accepted request whose read-back does not move is
// otherwise indistinguishable from the accepted-echoed-ignored family
// (nl6#445).
func decodeOutcome(t *testing.T, body string) stateChangeOutcome {
	t.Helper()
	var got stateChangeOutcome
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("202 body %q does not decode: %v", body, err)
	}
	return got
}

// TestRESTOperPostOnAdminDownIsAcceptedAndMasked is the endpoint contract: 202,
// link stored, read unmoved, and the response says so.
//
// Deliberately NOT 409. The caller is simulating a cable and the device is the
// thing masking it, so refusing would make this endpoint's contract depend on
// another leaf and would remove a legitimate harness sequence — stage a fault,
// then unshut the port.
func TestRESTOperPostOnAdminDownIsAcceptedAndMasked(t *testing.T) {
	f := newStateAPIFixture(t)
	st := f.device.metricsCycler.ifCounters.Load().State()

	// Shut the port first.
	postInterfaceStatus(t, f, "admin-status", 1, `{"status":"DOWN"}`)
	if got := st.OperStatus(1); got != OperDown {
		t.Fatalf("precondition: oper = %d, want down after admin-down", got)
	}

	rr := postInterfaceStatus(t, f, "oper-status", 1, `{"status":"UP"}`)
	out := decodeOutcome(t, rr.Body.String())
	if !out.Masked {
		t.Errorf("202 body = %+v, want masked=true", out)
	}
	if out.Link != "UP" || out.OperStatus != "DOWN" || out.AdminStatus != "DOWN" {
		t.Errorf("202 body = %+v, want link UP / oper DOWN / admin DOWN", out)
	}

	// Every read surface still reports down.
	if got := st.OperStatus(1); got != OperDown {
		t.Errorf("engine oper = %d, want down", got)
	}
	ic := f.device.metricsCycler.ifCounters.Load()
	if got := ic.GetDynamic(fmt.Sprintf("%s.%d", oidIfOperStatus, 1)); got != "2" {
		t.Errorf("SNMP ifOperStatus.1 = %s, want 2", got)
	}
	// ...and the link really was stored.
	if got := st.LinkState(1); got != OperUp {
		t.Errorf("link = %d, want up(1): the POST must be applied, not discarded", got)
	}
}

// TestRESTMaskedPostIsReportedEvenWhenOperAlreadyMatches is the case a
// post-hoc `oper != link` comparison gets wrong, and the reason `masked` comes
// from the mutator's verdict instead.
//
// Interface at admin DOWN with link UP — a port shut while its cable is fine.
// A POST of DOWN moves the link, fires nothing, stamps no `ifLastChange`, and
// leaves oper == link == DOWN. Comparing the two would report `masked: false`
// and the console would show a green toast for a request that changed nothing
// observable.
func TestRESTMaskedPostIsReportedEvenWhenOperAlreadyMatches(t *testing.T) {
	f := newStateAPIFixture(t)
	st := f.device.metricsCycler.ifCounters.Load().State()

	postInterfaceStatus(t, f, "admin-status", 1, `{"status":"DOWN"}`)
	if snap := st.Snapshot(1); snap.Link != OperUp || snap.Oper != OperDown {
		t.Fatalf("precondition: %+v, want link up / oper down", snap)
	}
	before := st.Snapshot(1)

	rr := postInterfaceStatus(t, f, "oper-status", 1, `{"status":"DOWN"}`)
	out := decodeOutcome(t, rr.Body.String())

	if !out.Masked {
		t.Errorf("202 body = %+v, want masked=true. The link moved UP→DOWN and nothing "+
			"observable changed; reporting success here tells the caller a request that "+
			"fired no trap, no syslog and no ON_CHANGE was applied normally.", out)
	}
	if out.Link != "DOWN" || out.OperStatus != "DOWN" {
		t.Errorf("202 body = %+v, want link DOWN / oper DOWN", out)
	}
	if st.LinkState(1) != OperDown {
		t.Errorf("link = %d, want down: the POST must still be applied", st.LinkState(1))
	}
	if after := st.Snapshot(1); after.LastChangeNs != before.LastChangeNs {
		t.Errorf("ifLastChange moved for a masked POST (%d -> %d)", before.LastChangeNs, after.LastChangeNs)
	}
}

// TestRESTRaisingAdminSurfacesTheMaskedLink is the other half: no second
// request is needed.
func TestRESTRaisingAdminSurfacesTheMaskedLink(t *testing.T) {
	f := newStateAPIFixture(t)
	st := f.device.metricsCycler.ifCounters.Load().State()

	postInterfaceStatus(t, f, "admin-status", 1, `{"status":"DOWN"}`)
	postInterfaceStatus(t, f, "oper-status", 1, `{"status":"UP"}`) // masked

	rr := postInterfaceStatus(t, f, "admin-status", 1, `{"status":"UP"}`)
	out := decodeOutcome(t, rr.Body.String())
	if out.Masked {
		t.Errorf("admin POST reported masked=true: %+v", out)
	}
	if out.OperStatus != "UP" {
		t.Errorf("202 body = %+v, want oper UP once admin rises", out)
	}
	if got := st.OperStatus(1); got != OperUp {
		t.Errorf("oper = %d, want up(1) with no further mutation", got)
	}
}

// TestRESTOperPostReportsUnmaskedOnAnAdminUpInterface is the control. Without
// it, a handler that hardcoded masked=false would pass the masked test's
// inverse and nothing would notice.
func TestRESTOperPostReportsUnmaskedOnAnAdminUpInterface(t *testing.T) {
	f := newStateAPIFixture(t)
	rr := postInterfaceStatus(t, f, "oper-status", 1, `{"status":"DOWN"}`)
	out := decodeOutcome(t, rr.Body.String())
	if out.Masked {
		t.Errorf("202 body = %+v, want masked=false on an admin-up interface", out)
	}
	if out.Link != "DOWN" || out.OperStatus != "DOWN" {
		t.Errorf("202 body = %+v, want link DOWN / oper DOWN", out)
	}
}

// TestRESTOperAutoRevertRestoresTheLinkNotTheDerivedOper is the auto-revert
// correction.
//
// The handler snapshots the pre-mutation value to restore later. Under
// derivation that MUST be the link: snapshotting the derived oper on a masked
// POST would capture the mask (DOWN) and the revert would write it into the
// link, destroying the pre-POST state instead of restoring it.
func TestRESTOperAutoRevertRestoresTheLinkNotTheDerivedOper(t *testing.T) {
	f := newStateAPIFixture(t)
	st := f.device.metricsCycler.ifCounters.Load().State()

	// Shut the port; the link stays UP underneath.
	postInterfaceStatus(t, f, "admin-status", 1, `{"status":"DOWN"}`)
	if got := st.LinkState(1); got != OperUp {
		t.Fatalf("precondition: link = %d, want up", got)
	}

	// A masked, time-bounded fault.
	postInterfaceStatus(t, f, "oper-status", 1, `{"status":"DOWN","duration":"60ms"}`)
	if got := st.LinkState(1); got != OperDown {
		t.Fatalf("link = %d, want down while the fault is staged", got)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st.LinkState(1) == OperUp {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := st.LinkState(1); got != OperUp {
		t.Fatalf("after auto-revert the link = %d, want up(1) — the value found at POST time. "+
			"Reverting to the DERIVED oper would write the mask into the link.", got)
	}
	// And the whole point: unshutting now brings the interface back.
	postInterfaceStatus(t, f, "admin-status", 1, `{"status":"UP"}`)
	if got := st.OperStatus(1); got != OperUp {
		t.Errorf("oper after unshut = %d, want up(1)", got)
	}
}

// TestFlapSchedulerFireUnderAdminDownIsMaskedNotLogged drives the scheduler's
// own fire path.
//
// The engine tests cover the masking; this covers the SCHEDULER's reaction to
// it. Before nl6#694 the mutator returned a bare `changed=false` for both "the
// slot is already at target" and "suppressed", so fireWithRecover logged a line
// naming both — and at `-if-flap-scenario aggressive` on a shut fleet that is
// one line per fire per interface, roughly 30k a minute describing the feature
// working.
func TestFlapSchedulerFireUnderAdminDownIsMaskedNotLogged(t *testing.T) {
	st := NewInterfaceState(1, nil, nil)
	st.Seed(1, OperUp, AdminDown)

	s := &FlapScheduler{}
	out := captureLog(t, func() { s.fireWithRecover(st, 1, OperDown, nil) })

	if got := st.LinkState(1); got != OperDown {
		t.Errorf("link = %d, want down: a masked fire still moves real state", got)
	}
	if got := st.OperStatus(1); got != OperDown {
		t.Errorf("oper = %d, want down throughout (admin-down)", got)
	}
	if out != "" {
		t.Errorf("a masked fire logged %q, want silence: masking is the designed behaviour, "+
			"not an anomaly", out)
	}
}

// TestFlapSchedulerFireAtTargetStillLogs is the control for the test above: the
// one condition that DOES reach the no-op branch must still be visible, or the
// silence above would be indistinguishable from a scheduler that never logs.
func TestFlapSchedulerFireAtTargetStillLogs(t *testing.T) {
	st := NewInterfaceState(1, nil, nil)
	st.Seed(1, OperDown, AdminUp)

	s := &FlapScheduler{}
	out := captureLog(t, func() { s.fireWithRecover(st, 1, OperDown, nil) }) // already at target

	if out == "" {
		t.Error("an at-target fire logged nothing; the REST-race no-op must stay visible")
	}
}
