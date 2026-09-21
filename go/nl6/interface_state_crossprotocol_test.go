/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"testing"
	"time"
)

// The nl6#694 acceptance criteria, as tests.

// TestScenario3AdminBounceLeavesOperDownOnEverySurface is the headline: under
// `-if-scenario 3` — documented as "link failures, SFP issues, cable pull" — a
// SET of ifAdminStatus down then up must leave ifOperStatus down on SNMP, gNMI
// and the engine alike.
//
// The three surfaces are asserted together on ONE device because the defect
// class this change closes is a surface disagreeing with another, not any one
// of them being wrong in isolation.
func TestScenario3AdminBounceLeavesOperDownOnEverySurface(t *testing.T) {
	withIfScenario(t, IfScenarioAllFailure, 0)
	s, state := newSetTestServer(t, 2)

	if got := v2cGet(t, s, oidIfOperStatus+".1"); got != "2" {
		t.Fatalf("precondition: ifOperStatus.1 = %s, want 2 under scenario 3", got)
	}

	for _, step := range []struct {
		name string
		to   int
	}{{"shut", 2}, {"unshut", 1}} {
		if status, _ := setVia(t, s, snmpVersion2c,
			[]testBind{intBind(oidIfAdminStatus+".1", step.to)}); status != snmpErrNoError {
			t.Fatalf("%s: SET status %d", step.name, status)
		}
	}

	// SNMP GET.
	if got := v2cGet(t, s, oidIfOperStatus+".1"); got != "2" {
		t.Errorf("after the bounce, SNMP GET ifOperStatus.1 = %s, want 2", got)
	}
	// SNMP walk — GET and the walk must not diverge.
	if name, val := v2cGetNextValue(t, s, oidIfOperStatus+".0"); name != oidIfOperStatus+".1" || val != "2" {
		t.Errorf("after the bounce, walk = (%s, %s), want (%s.1, 2)", name, val, oidIfOperStatus)
	}
	// The admin SET itself did land.
	if got := v2cGet(t, s, oidIfAdminStatus+".1"); got != "1" {
		t.Errorf("after the bounce, ifAdminStatus.1 = %s, want 1", got)
	}
	// The engine, which gNMI and REST read.
	if got := state.OperStatus(1); got != OperDown {
		t.Errorf("engine OperStatus = %d, want down(2)", got)
	}
	if got := state.LinkState(1); got != OperDown {
		t.Errorf("engine LinkState = %d, want down(2): the fault is in the link", got)
	}
}

// TestScenario1WithAggressiveFlapsNeverExposesAdminDownOperUp is the fleet-wide
// invariant from the issue: `-if-scenario 1 -if-flap-scenario aggressive` used
// to produce admin-down with oper-up across the whole fleet within a minute.
//
// It drives the engine through the scheduler's own fire path rather than
// asserting the derivation directly — the state was reachable precisely because
// a mutation source wrote oper.
func TestScenario1WithAggressiveFlapsNeverExposesAdminDownOperUp(t *testing.T) {
	withIfScenario(t, IfScenarioAllShutdown, 0)
	s, state := newSetTestServer(t, 8)

	hooks := 0
	state.SetNotify(func(StateChange) { hooks++ })
	defer state.SetNotify(nil)
	ch := make(chan StateChange, 256)
	state.AddListener(ch)
	defer state.RemoveListener(ch)

	sched := &FlapScheduler{}
	for round := 0; round < 40; round++ {
		for ifIndex := 1; ifIndex <= 8; ifIndex++ {
			target := OperDown
			if (round+ifIndex)%2 == 0 {
				target = OperUp
			}
			sched.fireWithRecover(state, ifIndex, target, nil)

			snap := state.Snapshot(ifIndex)
			if snap.Admin == AdminDown && snap.Oper == OperUp {
				t.Fatalf("round %d ifIndex %d: admin=down with oper=up: %+v", round, ifIndex, snap)
			}
			// And the SNMP surface agrees, so this is not an engine-only claim.
			admin := v2cGet(t, s, fmt.Sprintf("%s.%d", oidIfAdminStatus, ifIndex))
			oper := v2cGet(t, s, fmt.Sprintf("%s.%d", oidIfOperStatus, ifIndex))
			if admin == "2" && oper == "1" {
				t.Fatalf("round %d ifIndex %d: SNMP reports admin=2 with oper=1", round, ifIndex)
			}
		}
	}

	if hooks != 0 {
		t.Errorf("masked flaps fired the notify hook %d times, want 0: no link trap or syslog "+
			"may fire for a flap nobody can observe", hooks)
	}
	if len(ch) != 0 {
		t.Errorf("masked flaps broadcast %d gNMI events, want 0", len(ch))
	}
	for ifIndex := 1; ifIndex <= 8; ifIndex++ {
		ic := s.device.metricsCycler.ifCounters.Load()
		if got := ic.GetDynamic(fmt.Sprintf("%s.%d", oidIfLastChange, ifIndex)); got != "0" {
			t.Errorf("ifLastChange.%d = %s, want 0: no masked flap may move it", ifIndex, got)
		}
	}
}

// TestMaskedFleetSurfacesOnUnshut is the payoff of preserving the link under
// scenario 1: after the fleet has flapped beneath the mask, unshutting a port
// shows whatever its link had reached, with no further mutation.
func TestMaskedFleetSurfacesOnUnshut(t *testing.T) {
	withIfScenario(t, IfScenarioAllShutdown, 0)
	s, state := newSetTestServer(t, 2)

	sched := &FlapScheduler{}
	sched.fireWithRecover(state, 1, OperUp, nil)   // masked: link up
	sched.fireWithRecover(state, 2, OperDown, nil) // masked: link down

	if status, _ := setVia(t, s, snmpVersion2c,
		[]testBind{intBind(oidIfAdminStatus+".1", 1), intBind(oidIfAdminStatus+".2", 1)}); status != snmpErrNoError {
		t.Fatalf("SET admin up: status %d", status)
	}
	if got := v2cGet(t, s, oidIfOperStatus+".1"); got != "1" {
		t.Errorf("ifOperStatus.1 = %s, want 1: its link had flapped up beneath the mask", got)
	}
	if got := v2cGet(t, s, oidIfOperStatus+".2"); got != "2" {
		t.Errorf("ifOperStatus.2 = %s, want 2: its link had flapped down beneath the mask", got)
	}
}

// TestSNMPAndGnmiAgreeUnderMasking pins the cross-protocol claim at one
// instant, which is the property Tier B exists to provide.
func TestSNMPAndGnmiAgreeUnderMasking(t *testing.T) {
	r := newTestPathResolver(t, 1)
	state := r.device.metricsCycler.ifCounters.Load().State()
	ic := r.device.metricsCycler.ifCounters.Load()

	cases := []struct {
		name        string
		admin, link uint8
		wantSNMP    string
		wantGnmi    string
	}{
		{"admin up, link up", AdminUp, OperUp, "1", "openconfig-interfaces:UP"},
		{"admin up, link down", AdminUp, OperDown, "2", "openconfig-interfaces:DOWN"},
		{"admin down, link up (masked)", AdminDown, OperUp, "2", "openconfig-interfaces:DOWN"},
		{"admin down, link down", AdminDown, OperDown, "2", "openconfig-interfaces:DOWN"},
		{"admin testing, link up", AdminTesting, OperUp, "3", "openconfig-interfaces:TESTING"},
	}
	p := pathFromString(t, "/interfaces/interface[name=TestIf1]/state/oper-status")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state.Seed(1, c.link, c.admin)
			if got := ic.GetDynamic(fmt.Sprintf("%s.%d", oidIfOperStatus, 1)); got != c.wantSNMP {
				t.Errorf("SNMP ifOperStatus.1 = %s, want %s", got, c.wantSNMP)
			}
			updates, _ := r.Resolve(p, time.Now())
			if got := updates[0].Value.(string); got != c.wantGnmi {
				t.Errorf("gNMI oper-status = %q, want %q", got, c.wantGnmi)
			}
		})
	}
}
