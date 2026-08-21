/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"log"
	"slices"
	"strings"
)

// scenario_manager.go — the SimulatorManager-level glue between the REST
// surface (scenario_api.go) and the transport-agnostic ScenarioController
// (scenario_controller.go): single-active enforcement (MVP FR38), the
// zero-padded monotonic ID counter (D5), and ID-scoped lookup. The
// controller stays HTTP-unaware; this file owns the manager-side policy.

// errNoActiveScenario is returned when a scenario ID is looked up but no
// scenario with that ID exists (maps to 404).
var errNoActiveScenario = fmt.Errorf("no scenario with that id")

// errScenarioActive is returned when a submit is attempted while a
// non-terminal scenario already exists (maps to 409). MVP allows exactly
// one active scenario.
var errScenarioActive = fmt.Errorf("a scenario is already active")

// errScenarioRunning is returned when a DELETE targets a running scenario;
// it must be stopped or aborted first (maps to 409).
var errScenarioRunning = fmt.Errorf("scenario is running; stop or abort it before deleting")

// submitScenario validates the spec, allocates the next s-%06d ID, and
// registers a fresh controller. It refuses (errScenarioActive) while an
// existing scenario has not reached a terminal phase; terminal scenarios are
// reaped. Returns the new controller and its ID.
//
// The admission policy here is unchanged from the single-slot version this
// replaced — one non-terminal scenario at a time. Per-device overlap (#392)
// replaces the policy; the registry it needs lands first, by itself, so a
// structural change and a semantic one are never in the same diff.
func (sm *SimulatorManager) submitScenario(spec *Scenario, configSHA string) (*ScenarioController, string, error) {
	sm.scenarioMu.Lock()
	defer sm.scenarioMu.Unlock()

	for _, c := range sm.scenarios {
		if !isTerminalPhase(c.Phase()) {
			return nil, "", fmt.Errorf("%w: %s (phase %s); MVP allows one active scenario",
				errScenarioActive, c.id, c.Phase())
		}
	}

	sm.scenarioSeq++
	id := fmt.Sprintf("s-%06d", sm.scenarioSeq)
	ctrl := newScenarioController(sm, nil)
	if err := ctrl.Submit(spec, id); err != nil {
		sm.scenarioSeq-- // roll back the ID allocation on a rejected submit
		return nil, "", err
	}
	ctrl.configSHA = configSHA

	// Reap terminal scenarios, which reproduces the old slot's behaviour
	// EXACTLY: overwriting it made the previous terminal scenario's report
	// unreachable, so a GET on it 404s. Retaining them here instead would be a
	// behaviour change (reports outliving their successor's submit) smuggled
	// into a refactor, and would grow the map without bound. A retention policy
	// belongs with the change that makes several scenarios coexist.
	for sid, c := range sm.scenarios {
		if isTerminalPhase(c.Phase()) {
			delete(sm.scenarios, sid)
		}
	}
	if sm.scenarios == nil {
		// Lazily created: SimulatorManager is built as a struct literal in many
		// places (tests especially), so no constructor can be relied on.
		sm.scenarios = make(map[string]*ScenarioController, 1)
	}
	sm.scenarios[id] = ctrl
	return ctrl, id, nil
}

// scenarioByID returns the registered controller for id, else
// errNoActiveScenario (404).
func (sm *SimulatorManager) scenarioByID(id string) (*ScenarioController, error) {
	sm.scenarioMu.Lock()
	defer sm.scenarioMu.Unlock()
	c := sm.scenarios[id]
	if c == nil {
		return nil, errNoActiveScenario
	}
	return c, nil
}

// listScenarios returns the registered scenarios with their phases, in ID
// order so the listing is stable across calls (map order is not).
func (sm *SimulatorManager) listScenarios() []scenarioListEntry {
	sm.scenarioMu.Lock()
	ctrls := make([]*ScenarioController, 0, len(sm.scenarios))
	for _, c := range sm.scenarios {
		ctrls = append(ctrls, c)
	}
	sm.scenarioMu.Unlock()

	out := make([]scenarioListEntry, 0, len(ctrls))
	for _, c := range ctrls {
		out = append(out, scenarioListEntry{ID: c.id, Phase: string(c.Phase())})
	}
	slices.SortFunc(out, func(a, b scenarioListEntry) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// deleteScenario releases the identified scenario. An armed scenario is
// canceled (transports released, no report — FR39); a submitted or terminal
// scenario is simply dropped. A running scenario is refused
// (errScenarioRunning) — stop or abort it first. On success the registration
// is removed, so a subsequent GET returns 404.
func (sm *SimulatorManager) deleteScenario(id string) error {
	sm.scenarioMu.Lock()
	defer sm.scenarioMu.Unlock()
	c := sm.scenarios[id]
	if c == nil {
		return errNoActiveScenario
	}
	switch c.Phase() {
	case phaseRunning:
		return errScenarioRunning
	case phaseArmed:
		if err := c.Cancel(); err != nil {
			return err
		}
	}
	delete(sm.scenarios, id)
	return nil
}

// abortActiveScenario aborts a running load-test scenario as part of
// graceful shutdown (D7). Abort()'s drain barrier is bounded by the drain
// grace, so shutdown cannot hang. No-op when no scenario is running; the
// finalized report stays queryable (via the still-live controller) until
// the process exits. Called at the top of Shutdown, before the export
// subsystems tear down, so participant exporters still exist during drain.
func (sm *SimulatorManager) abortActiveScenario() {
	sm.scenarioMu.Lock()
	ctrls := make([]*ScenarioController, 0, len(sm.scenarios))
	for _, c := range sm.scenarios {
		ctrls = append(ctrls, c)
	}
	sm.scenarioMu.Unlock()

	// Iterates the registry rather than a single slot. The admission policy
	// still admits only one non-terminal scenario, so this aborts at most one
	// today; written as a loop so per-device overlap does not have to remember
	// to revisit the shutdown path.
	for _, c := range ctrls {
		if c.Phase() != phaseRunning {
			continue
		}
		if _, err := c.Abort(); err != nil {
			log.Printf("[scenario] abort during shutdown failed: %v", err)
			continue
		}
		log.Printf("[scenario] %s aborted for shutdown", c.id)
	}
}
