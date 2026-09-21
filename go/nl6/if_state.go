/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
)

// Interface state scenarios
const (
	IfScenarioAllShutdown = 1 // ifAdminStatus=down, ifOperStatus=down
	IfScenarioAllNormal   = 2 // ifAdminStatus=up,   ifOperStatus=up   (default)
	IfScenarioAllFailure  = 3 // ifAdminStatus=up,   ifOperStatus=down
	IfScenarioPctFailure  = 4 // ifAdminStatus=up,   n% ifOperStatus=down
)

// IfStateConfig holds the active interface state scenario configuration.
type IfStateConfig struct {
	Scenario   int // one of IfScenario* constants
	FailurePct int // only used when Scenario == IfScenarioPctFailure (0–100)
}

// ifStateConfig is the active configuration, initialised to "all-normal" at startup.
//
// Read exactly once per device, at engine construction (`scenarioSeed`, called
// from InitIfCountersWithScenario). It is NOT on any read path: before nl6#692
// a `getIfStateOverride` branch in findResponse answered ifAdminStatus /
// ifOperStatus from this config ahead of the state engine. That branch was
// unreachable on every engine-backed device — the cycler serves .7/.8/.9 from
// the engine and runs first — and was never wired into the GETNEXT/GETBULK
// path at all, so the flag had done nothing since v0.8.0. The scenario now
// shapes the engine's SEED, which every reader (SNMP GET, walk, gNMI, REST)
// already agrees on, and a later SET or POST moves what they all read.
var ifStateConfig = &IfStateConfig{Scenario: IfScenarioAllNormal}

// validate reports whether the configuration is one the simulator can honour.
// Called at startup so an unknown scenario is fatal rather than silently a
// no-op, which is the failure mode this whole change exists to remove
// (nl6#445's family). FailurePct is range-checked for every scenario, not only
// scenario 4: a value outside 0..100 is a typo whichever scenario is selected.
func (c IfStateConfig) validate() error {
	switch c.Scenario {
	case IfScenarioAllShutdown, IfScenarioAllNormal, IfScenarioAllFailure, IfScenarioPctFailure:
	default:
		return fmt.Errorf("-if-scenario must be 1 (all-shutdown), 2 (all-normal), 3 (all-failure) or 4 (pct-failure), got %d", c.Scenario)
	}
	if c.FailurePct < 0 || c.FailurePct > 100 {
		return fmt.Errorf("-if-failure-pct must be in 0..100, got %d", c.FailurePct)
	}
	return nil
}

// scenarioSeed overlays the active interface-state scenario on the oper/admin
// values a device's JSON resources declare for one ifIndex. It is a pure
// function called once per interface at engine construction; the returned pair
// is handed to InterfaceState.Seed, which stamps lastChangeNs = 0 and
// broadcasts nothing.
//
// Seeding rather than mutating is load-bearing: SetOperStatus / SetAdminStatus
// stamp lastChange and broadcast, so applying the scenario through them would
// make a fleet report a transition per interface at boot, fire Tier C link
// traps and syslog for state that never changed, and leave ifLastChange
// non-zero. Scenario 1 therefore writes admin AND oper explicitly instead of
// letting the nl6#684 admin→oper cascade derive oper — a seed is not a change,
// so no cascade runs. A later SET of ifAdminStatus does go through the cascade
// and raises oper, which needs no special case here.
//
// Scenario 2 (all-normal, the default) is the identity, so the default fleet's
// wire output is byte-identical to a build without this function. An unknown
// scenario is the identity too; startup validation refuses it before any
// device exists, and defaulting to "JSON wins" is the safe reading if one ever
// reached here.
func scenarioSeed(cfg *IfStateConfig, ifIndex int, jsonOper, jsonAdmin uint8) (oper, admin uint8) {
	if cfg == nil {
		return jsonOper, jsonAdmin
	}
	switch cfg.Scenario {
	case IfScenarioAllShutdown:
		return OperDown, AdminDown

	case IfScenarioAllFailure:
		return OperDown, AdminUp

	case IfScenarioPctFailure:
		// Deterministic: interfaces whose index modulo 100 falls below
		// FailurePct are down. Reproducible across restarts, which is the
		// documented contract of scenario 4.
		if ifIndex%100 < cfg.FailurePct {
			return OperDown, AdminUp
		}
		return OperUp, AdminUp
	}
	return jsonOper, jsonAdmin
}
