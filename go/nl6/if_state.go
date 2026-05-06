/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strconv"
	"strings"
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
var ifStateConfig = &IfStateConfig{Scenario: IfScenarioAllNormal}

const (
	ifAdminStatusPrefix = ".1.3.6.1.2.1.2.2.1.7."
	ifOperStatusPrefix  = ".1.3.6.1.2.1.2.2.1.8."
)

// getIfStateOverride returns a non-empty response string for ifAdminStatus and
// ifOperStatus OIDs when the active scenario requires it, overriding JSON data.
// Returns "" when the OID is not an interface state OID or no override is needed.
func getIfStateOverride(oid string) string {
	// Scenario 2 (all-normal) means "use whatever the JSON says" — no override.
	if ifStateConfig.Scenario == IfScenarioAllNormal {
		return ""
	}

	isAdmin := strings.HasPrefix(oid, ifAdminStatusPrefix)
	isOper := strings.HasPrefix(oid, ifOperStatusPrefix)
	if !isAdmin && !isOper {
		return ""
	}

	switch ifStateConfig.Scenario {
	case IfScenarioAllShutdown:
		// Admin down and oper down for all interfaces.
		return "2"

	case IfScenarioAllFailure:
		if isAdmin {
			return "1" // admin up
		}
		return "2" // oper down

	case IfScenarioPctFailure:
		if isAdmin {
			return "1" // all interfaces admin up
		}
		// Parse the ifIndex from the OID suffix.
		suffix := strings.TrimPrefix(oid, ifOperStatusPrefix)
		ifIdx, err := strconv.Atoi(suffix)
		if err != nil {
			return ""
		}
		// Deterministic: interfaces whose index modulo 100 falls below FailurePct are down.
		if ifIdx%100 < ifStateConfig.FailurePct {
			return "2" // oper down
		}
		return "1" // oper up
	}

	return ""
}
