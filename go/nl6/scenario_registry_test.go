/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Registry behaviour that the single-slot version got for free and a map does
// not. These pin the properties the slot implied structurally, so the policy
// change that follows (per-device overlap, #392) cannot quietly drop one.

package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestScenarioRegistry_TerminalReportsSurvivePeerSubmit pins the retention
// contract. The single-slot version reaped every terminal scenario on submit,
// because overwriting the slot did — unsurprising when submits were serialised,
// since you only submitted after your own run finished. With concurrency it
// would delete the report a peer is reading, so recent finished runs are kept.
func TestScenarioRegistry_TerminalReportsSurvivePeerSubmit(t *testing.T) {
	router := scenarioAPIManager(t, 1)

	first := submitOK(t, router, validScenarioBody)
	for _, verb := range []string{"arm", "start", "stop"} {
		if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+first+"/"+verb, ""); w.Code != http.StatusOK {
			t.Fatalf("%s = %d (%s)", verb, w.Code, w.Body.String())
		}
	}

	// A peer submit must NOT destroy the finished run's report.
	second := submitOK(t, router, validScenarioBody)
	if second == first {
		t.Fatal("the second submit reused the first ID")
	}
	if w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+first+"/report", ""); w.Code != http.StatusOK {
		t.Fatalf("finished report after a peer submit = %d, want 200 — a peer's submit deleted it", w.Code)
	}
}

// TestScenarioRegistry_RetentionIsBounded: retention cannot be unlimited, or
// the registry grows for the life of the process. The oldest terminal
// scenarios are reaped first, so the reports most likely still being read are
// the ones kept.
func TestScenarioRegistry_RetentionIsBounded(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	old := manager
	manager = sm
	t.Cleanup(func() { manager = old })

	// More finished scenarios than the retention bound.
	for i := 0; i < scenarioMaxRetained+3; i++ {
		c, _, err := sm.submitScenario(&Scenario{
			Participants: []string{"10.42.0.1"}, Protocol: "syslog", Rate: 5, Window: time.Millisecond,
		}, "sha")
		if err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Stop(); err != nil {
			t.Fatal(err)
		}
	}

	listed := sm.listScenarios()
	if len(listed) > scenarioMaxRetained+1 { // +1: the newest submit is still registered
		t.Fatalf("registry holds %d scenarios, want at most %d", len(listed), scenarioMaxRetained+1)
	}
	// The survivors are the NEWEST, and the listing is sequence-ordered.
	if first := listed[0].ID; first == "s-000001" {
		t.Error("retention kept the oldest scenarios; it should reap those first")
	}
}

// TestScenarioRegistry_ListIsIDOrdered pins a property the single slot could
// not have: with more than one entry the listing must not inherit Go's random
// map order, or a client polling it sees rows shuffle between calls.
func TestScenarioRegistry_ListIsIDOrdered(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	// s-1000000 is the case a byte comparison gets wrong: %06d is a minimum
	// width, not a clamp, so past the millionth submit the ID grows a digit and
	// "s-1000000" sorts before "s-999999" byte-wise.
	for _, id := range []string{"s-1000000", "s-000003", "s-999999", "s-000001", "s-000002"} {
		c := newScenarioController(sm, nil)
		if err := c.Submit(&Scenario{
			Participants: []string{"10.42.0.1"}, Protocol: "syslog", Rate: 5, Window: 1,
		}, id); err != nil {
			t.Fatal(err)
		}
		if sm.scenarios == nil {
			sm.scenarios = map[string]*ScenarioController{}
		}
		sm.scenarios[id] = c
	}
	want := []string{"s-000001", "s-000002", "s-000003", "s-999999", "s-1000000"}
	for i := 0; i < 10; i++ {
		got := sm.listScenarios()
		if len(got) != len(want) {
			t.Fatalf("listed %d, want %d", len(got), len(want))
		}
		for j, w := range want {
			if got[j].ID != w {
				t.Fatalf("listing is not sequence-ordered: got %v, want %v", got, want)
			}
		}
	}
}

// TestScenarioRegistry_ConcurrencyBound replaces the one-at-a-time assertion
// this file carried while the registry landed. Per-device overlap (#392) moved
// exclusivity to the devices, so submit now refuses only at the resource bound
// — each live scenario retains ledgers, a drain barrier, and possibly a
// scheduler goroutine.
func TestScenarioRegistry_ConcurrencyBound(t *testing.T) {
	router := scenarioAPIManager(t, 1)

	// Disjoint participants, so nothing collides at arm; these are admitted
	// purely on the bound.
	body := func(n int) string {
		return fmt.Sprintf(
			`{"participants":["10.99.%d.1"],"protocol":"syslog","rate":5,"window":"1s"}`, n)
	}
	for i := 0; i < scenarioMaxConcurrent; i++ {
		if id := submitOK(t, router, body(i)); id == "" {
			t.Fatalf("submit %d produced no id", i)
		}
	}

	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body(scenarioMaxConcurrent))
	if w.Code != http.StatusConflict {
		t.Fatalf("submit over the bound = %d, want 409 (body %s)", w.Code, w.Body.String())
	}
	if b := w.Body.String(); !strings.Contains(b, fmt.Sprint(scenarioMaxConcurrent)) {
		t.Errorf("409 should name the bound: %s", b)
	}

	// Freeing one admits the next: the bound counts LIVE scenarios, not
	// lifetime submits.
	if err := manager.deleteScenario("s-000001"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if id := submitOK(t, router, body(scenarioMaxConcurrent)); id == "" {
		t.Fatal("submit after freeing a slot produced no id")
	}
}
