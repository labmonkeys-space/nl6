/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Registry behaviour that the single-slot version got for free and a map does
// not. These pin the properties the slot implied structurally, so the policy
// change that follows (per-device overlap, #392) cannot quietly drop one.

package main

import (
	"net/http"
	"strings"
	"testing"
)

// TestScenarioRegistry_TerminalIsReapedOnSubmit pins the reaping that keeps the
// refactor behaviour-identical. Overwriting the old single slot made the
// previous terminal scenario's report unreachable; a map would retain it
// forever, which is both a behaviour change and an unbounded growth path.
func TestScenarioRegistry_TerminalIsReapedOnSubmit(t *testing.T) {
	router := scenarioAPIManager(t, 1)

	first := submitOK(t, router, validScenarioBody)
	// Terminal without ever running: a submitted scenario is dropped by DELETE,
	// so drive it to a terminal phase the registry must then reap.
	if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+first+"/arm", ""); w.Code != http.StatusOK {
		t.Fatalf("arm = %d (%s)", w.Code, w.Body.String())
	}
	if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+first+"/start", ""); w.Code != http.StatusOK {
		t.Fatalf("start = %d (%s)", w.Code, w.Body.String())
	}
	if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+first+"/stop", ""); w.Code != http.StatusOK {
		t.Fatalf("stop = %d (%s)", w.Code, w.Body.String())
	}
	// While it is the only scenario, its report is still queryable.
	if w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+first+"/report", ""); w.Code != http.StatusOK {
		t.Fatalf("report before the next submit = %d, want 200", w.Code)
	}

	second := submitOK(t, router, validScenarioBody)
	if second == first {
		t.Fatal("the second submit reused the first ID")
	}
	// The successor's submit reaps it, exactly as overwriting the slot did.
	if w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+first+"/report", ""); w.Code != http.StatusNotFound {
		t.Errorf("reaped scenario report = %d, want 404", w.Code)
	}
	if got := len(manager.listScenarios()); got != 1 {
		t.Errorf("registry holds %d scenarios after reaping, want 1", got)
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

// TestScenarioRegistry_PolicyUnchanged: this PR is a refactor, so the admission
// policy must still be one non-terminal scenario at a time. The per-device
// overlap change replaces this; until then a second submit is a 409.
func TestScenarioRegistry_PolicyUnchanged(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	id := submitOK(t, router, validScenarioBody)

	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", validScenarioBody)
	if w.Code != http.StatusConflict {
		t.Fatalf("second submit = %d, want 409", w.Code)
	}
	// The refusal still names the holder, which is what makes it actionable.
	if body := w.Body.String(); !strings.Contains(body, id) {
		t.Errorf("409 should name the active scenario %s: %s", id, body)
	}
}
