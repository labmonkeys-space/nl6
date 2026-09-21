/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// InterfaceState.ApplyAdminStatus — the RFC 2863 admin-to-oper cascade behind
// one funnel (add-snmp-set D4). Before it, SetAdminStatus preserved oper and
// only the REST handler called it; nl6#684 assumed the cascade existed.

func newApplyTestState(t *testing.T) *InterfaceState {
	t.Helper()
	res := buildTestResources(t, []uint64{1_000_000_000, 1_000_000_000})
	mc := &MetricsCycler{}
	mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
	st := mc.ifCounters.Load().State()
	st.Seed(1, OperUp, AdminUp)
	st.Seed(2, OperUp, AdminUp)
	return st
}

func TestApplyAdminStatus_DownCascadesToOper(t *testing.T) {
	st := newApplyTestState(t)
	evts := st.ApplyAdminStatus(1, AdminDown)
	if len(evts) != 2 {
		t.Fatalf("got %d events, want 2 (admin then oper): %+v", len(evts), evts)
	}
	if evts[0].Changed != LeafAdminStatus || evts[0].Admin != AdminDown {
		t.Errorf("first event = %+v, want admin leaf DOWN", evts[0])
	}
	if evts[1].Changed != LeafOperStatus || evts[1].Oper != OperDown {
		t.Errorf("second event = %+v, want oper leaf DOWN", evts[1])
	}
	if snap := st.Snapshot(1); snap.Admin != AdminDown || snap.Oper != OperDown {
		t.Errorf("slot = %+v, want admin down / oper down", snap)
	}
	if snap := st.Snapshot(2); snap.Admin != AdminUp || snap.Oper != OperUp {
		t.Errorf("interface 2 moved: %+v", snap)
	}
}

func TestApplyAdminStatus_UpCascadesToOper(t *testing.T) {
	st := newApplyTestState(t)
	st.Seed(1, OperDown, AdminDown)
	evts := st.ApplyAdminStatus(1, AdminUp)
	if len(evts) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(evts), evts)
	}
	if snap := st.Snapshot(1); snap.Admin != AdminUp || snap.Oper != OperUp {
		t.Errorf("slot = %+v, want up/up", snap)
	}
}

func TestApplyAdminStatus_TestingCascadesToOperTesting(t *testing.T) {
	st := newApplyTestState(t)
	if n := len(st.ApplyAdminStatus(1, AdminTesting)); n != 2 {
		t.Fatalf("%d events, want 2", n)
	}
	if snap := st.Snapshot(1); snap.Admin != AdminTesting || snap.Oper != OperTesting {
		t.Errorf("slot = %+v, want testing/testing", snap)
	}
}

// admin already DOWN, oper raised by the flap scheduler: the cascade puts oper
// back and reports exactly the oper event.
func TestApplyAdminStatus_CorrectsFlappedOperOnAdminDown(t *testing.T) {
	st := newApplyTestState(t)
	st.Seed(1, OperUp, AdminDown)
	evts := st.ApplyAdminStatus(1, AdminDown)
	if len(evts) != 1 || evts[0].Changed != LeafOperStatus || evts[0].Oper != OperDown {
		t.Fatalf("events = %+v, want exactly one oper DOWN event", evts)
	}
}

func TestApplyAdminStatus_NoOpAtTarget(t *testing.T) {
	st := newApplyTestState(t)
	st.ApplyAdminStatus(1, AdminDown)
	before := st.Snapshot(1)
	time.Sleep(2 * time.Millisecond)
	if evts := st.ApplyAdminStatus(1, AdminDown); len(evts) != 0 {
		t.Errorf("at-target apply returned %+v, want none", evts)
	}
	if after := st.Snapshot(1); after != before {
		t.Errorf("at-target apply moved the slot: %+v -> %+v", before, after)
	}
}

func TestApplyAdminStatus_RejectsBadInputs(t *testing.T) {
	st := newApplyTestState(t)
	if evts := st.ApplyAdminStatus(99, AdminDown); evts != nil {
		t.Errorf("out-of-range ifIndex returned %+v", evts)
	}
	if evts := st.ApplyAdminStatus(1, 0); evts != nil {
		t.Errorf("target 0 returned %+v", evts)
	}
	if evts := st.ApplyAdminStatus(1, AdminTesting+1); evts != nil {
		t.Errorf("target 4 returned %+v", evts)
	}
	if snap := st.Snapshot(1); snap.Admin != AdminUp || snap.Oper != OperUp {
		t.Errorf("a rejected apply moved the slot: %+v", snap)
	}
}

// The primitive mutator is unchanged: it still moves ONE leaf. The cascade is
// the funnel's, not SetAdminStatus's (interface-state spec, MODIFIED mutator
// requirement).
func TestSetAdminStatusPrimitiveStillMovesOneLeaf(t *testing.T) {
	st := newApplyTestState(t)
	if changed, _ := st.SetAdminStatus(1, AdminDown); !changed {
		t.Fatal("no change")
	}
	if snap := st.Snapshot(1); snap.Oper != OperUp {
		t.Errorf("SetAdminStatus moved oper: %+v", snap)
	}
}

// ── REST admin-status now takes the funnel ──────────────────────────────────

// postInterfaceStatus drives the real router.
func postInterfaceStatus(t *testing.T, f *stateAPIFixture, leaf string, ifIndex int, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/"+strconv.Itoa(ifIndex)+"/"+leaf,
		strings.NewReader(body))
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST %s: %d %s", leaf, rr.Code, rr.Body.String())
	}
	return rr
}

func TestRestAdminStatusPostCascadesOperAndFiresHook(t *testing.T) {
	f := newStateAPIFixture(t)
	st := f.device.metricsCycler.ifCounters.Load().State()
	var hooked []StateChange
	st.SetNotify(func(e StateChange) { hooked = append(hooked, e) })
	defer st.SetNotify(nil)

	postInterfaceStatus(t, f, "admin-status", 1, `{"status":"DOWN"}`)
	if snap := st.Snapshot(1); snap.Admin != AdminDown || snap.Oper != OperDown {
		t.Fatalf("after admin DOWN: %+v, want oper to follow", snap)
	}
	if len(hooked) != 1 || hooked[0].Oper != OperDown || hooked[0].Changed != LeafOperStatus {
		t.Errorf("notify hook saw %+v, want one oper DOWN event", hooked)
	}

	postInterfaceStatus(t, f, "admin-status", 1, `{"status":"UP"}`)
	if snap := st.Snapshot(1); snap.Admin != AdminUp || snap.Oper != OperUp {
		t.Fatalf("after admin UP: %+v", snap)
	}
	if len(hooked) != 2 || hooked[1].Oper != OperUp {
		t.Errorf("notify hook saw %+v, want a second, oper UP event", hooked)
	}
}

// The oper-status endpoint is untouched: oper DOWN leaves admin alone.
func TestRestOperStatusPostDoesNotTouchAdmin(t *testing.T) {
	f := newStateAPIFixture(t)
	st := f.device.metricsCycler.ifCounters.Load().State()
	postInterfaceStatus(t, f, "oper-status", 1, `{"status":"DOWN"}`)
	if snap := st.Snapshot(1); snap.Admin != AdminUp || snap.Oper != OperDown {
		t.Errorf("after oper DOWN: %+v, want admin untouched", snap)
	}
}

func TestRestAdminStatusAutoRevertCascadesBack(t *testing.T) {
	f := newStateAPIFixture(t)
	st := f.device.metricsCycler.ifCounters.Load().State()
	var ups int
	st.SetNotify(func(e StateChange) {
		if e.Oper == OperUp {
			ups++
		}
	})
	defer st.SetNotify(nil)

	postInterfaceStatus(t, f, "admin-status", 1, `{"status":"DOWN","duration":"50ms"}`)
	if snap := st.Snapshot(1); snap.Admin != AdminDown || snap.Oper != OperDown {
		t.Fatalf("after POST: %+v", snap)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if snap := st.Snapshot(1); snap.Admin == AdminUp && snap.Oper == OperUp {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if snap := st.Snapshot(1); snap.Admin != AdminUp || snap.Oper != OperUp {
		t.Fatalf("after revert: %+v, want up/up", snap)
	}
	f.mgr.awaitAutoRevertsForDevice(f.device.IP.String())
	if ups != 1 {
		t.Errorf("notify hook saw %d oper UP events on the revert, want 1", ups)
	}
}

// ── LLDP: a cascaded oper-down drops the remote row like a direct one ───────

func TestLLDP_AdminDownCascadeDropsRemoteRow(t *testing.T) {
	_, a, _, _ := lineTopology(t)
	row := remOID(colLldpRemSysName, 1)
	if got := a.snmpServer.findResponse(row); got != "bravo" {
		t.Fatalf("precondition: row present, got %q", got)
	}
	st := a.metricsCycler.ifCounters.Load().State()
	for _, e := range st.ApplyAdminStatus(1, AdminDown) {
		st.Broadcast(e)
	}
	if got := a.snmpServer.findResponse(row); got != valueNoSuchObject {
		t.Errorf("admin down: row = %q, want absent", got)
	}
	for _, e := range st.ApplyAdminStatus(1, AdminUp) {
		st.Broadcast(e)
	}
	if got := a.snmpServer.findResponse(row); got != "bravo" {
		t.Errorf("admin up again: row = %q, want bravo", got)
	}
}
