/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "fmt"

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
// installs a fresh controller. It refuses (errScenarioActive) while an
// existing scenario has not reached a terminal phase; a terminal scenario
// is transparently replaced. Returns the new controller and its ID.
func (sm *SimulatorManager) submitScenario(spec *Scenario, configSHA string) (*ScenarioController, string, error) {
	sm.scenarioMu.Lock()
	defer sm.scenarioMu.Unlock()

	if sm.scenarioController != nil && !isTerminalPhase(sm.scenarioController.Phase()) {
		return nil, "", fmt.Errorf("%w: %s (phase %s); MVP allows one active scenario",
			errScenarioActive, sm.scenarioController.id, sm.scenarioController.Phase())
	}

	sm.scenarioSeq++
	id := fmt.Sprintf("s-%06d", sm.scenarioSeq)
	ctrl := newScenarioController(sm, nil)
	if err := ctrl.Submit(spec, id); err != nil {
		sm.scenarioSeq-- // roll back the ID allocation on a rejected submit
		return nil, "", err
	}
	ctrl.configSHA = configSHA
	sm.scenarioController = ctrl
	return ctrl, id, nil
}

// scenarioByID returns the active controller iff its ID matches, else
// errNoActiveScenario. MVP holds one scenario, so a mismatch is a 404.
func (sm *SimulatorManager) scenarioByID(id string) (*ScenarioController, error) {
	sm.scenarioMu.Lock()
	defer sm.scenarioMu.Unlock()
	if sm.scenarioController == nil || sm.scenarioController.id != id {
		return nil, errNoActiveScenario
	}
	return sm.scenarioController, nil
}

// deleteScenario releases the identified scenario. An armed scenario is
// canceled (transports released, no report — FR39); a submitted or terminal
// scenario is simply dropped so the single-active slot frees. A running
// scenario is refused (errScenarioRunning) — stop or abort it first. On
// success the controller slot is cleared, so a subsequent GET returns 404.
func (sm *SimulatorManager) deleteScenario(id string) error {
	sm.scenarioMu.Lock()
	defer sm.scenarioMu.Unlock()
	c := sm.scenarioController
	if c == nil || c.id != id {
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
	sm.scenarioController = nil
	return nil
}
