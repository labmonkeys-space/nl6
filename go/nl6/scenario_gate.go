/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sync/atomic"
	"time"
)

// scenarioPhase is the canonical lifecycle phase vocabulary (architecture
// D4): submitted → armed → running → stopped; armed → canceled;
// running → aborted. Lowercase strings are the wire values (1.3).
type scenarioPhase string

const (
	phaseSubmitted scenarioPhase = "submitted"
	phaseArmed     scenarioPhase = "armed"
	phaseRunning   scenarioPhase = "running"
	phaseStopped   scenarioPhase = "stopped"
	phaseCanceled  scenarioPhase = "canceled"
	phaseAborted   scenarioPhase = "aborted"
)

// fireSource tags which emission path is attempting a fire — the source
// flag of the architecture's counting matrix. The gate treats each source
// differently; see scenarioPart.decide.
type fireSource uint8

const (
	// sourceBackground: the device's regular Poisson scheduler cadence —
	// the endogenous noise a scenario exists to silence. Suppressed for
	// the entire scenario lifetime; generation-suppressed (no identity
	// count) with informational backgroundSuppressed disclosure.
	sourceBackground fireSource = iota
	// sourceScenario: the scenario-owned scheduler. Allowed in [T0,T1).
	sourceScenario
	// sourceStateDriven: wireStateNotify correlated fires (Tier C) —
	// exogenous events. Pre-T0: emission-suppressed (counted). In-window:
	// allowed and counted. Post-T1: generation-suppressed.
	sourceStateDriven
	// sourceOnDemand: POST /devices/{ip}/syslog test-harness fires. Same
	// matrix row as state-driven (exogenous).
	sourceOnDemand
)

// gateState is the immutable copy-on-write gate snapshot (phase + window
// bounds published together — a torn phase/T0 read is impossible by
// construction). Published via atomic.Pointer by the single-writer
// controller; read once per fire by producer sites.
type gateState struct {
	phase    scenarioPhase
	t0       time.Time
	t1       time.Time
	drainEnd time.Time
}

// gateDecision is the outcome of the pre-generation gate check.
type gateDecision uint8

const (
	// gateProceed: generate and send; bucket at write-return.
	gateProceed gateDecision = iota
	// gateSuppressCounted: emission-suppressed — the record counts as
	// emitted + suppressed_pre_window (n=1, no rendering needed).
	gateSuppressCounted
	// gateSuppressSilent: generation-suppressed — nothing is generated,
	// nothing enters the identity. For a background skip, decide() also
	// increments the informational backgroundSuppressed counter before
	// returning this (the increment needs no rendering, so it lives with
	// the decision).
	gateSuppressSilent
)

// scenarioPart is one participant's handle on the running scenario — the
// architecture's normative struct. A pointer to it is installed on the
// producer (the device's SyslogExporter) at arm and atomically nil-swapped
// at teardown; producer sites load it ONCE per fire and tolerate nil.
type scenarioPart struct {
	gate   *atomic.Pointer[gateState]
	ledger *ledgerEntry
	// drain is the per-scenario admission + drain barrier, owned by the
	// controller. A gate-passed fire admits itself here (which both closes
	// the straggler race against finalize and cannot race the barrier's
	// close), and finalize closeAndWait()s to outlast every in-flight fire.
	drain *drainGate
	now   func() time.Time
}

// decide implements the source-flag counting matrix for the pre-generation
// gate check at fire time t (the fire-decision timestamp — bucketing later
// uses a FRESH write-return read, never t; see scenario_boundary.go).
func (p *scenarioPart) decide(src fireSource, t time.Time) gateDecision {
	gs := p.gate.Load()
	if gs == nil {
		// Teardown race: part loaded before nil-swap, gate already gone.
		return gateSuppressSilent
	}
	if src == sourceBackground {
		// Suppressed for the whole scenario lifetime, whatever the phase.
		p.ledger.backgroundSuppressed.Add(1)
		return gateSuppressSilent
	}
	switch gs.phase {
	case phaseArmed:
		if src == sourceScenario {
			// Scenario scheduler must not run pre-T0; treat defensively.
			return gateSuppressSilent
		}
		// Exogenous (state-driven / on-demand) pre-T0: counted.
		return gateSuppressCounted
	case phaseRunning:
		// Half-open [T0,T1): initiation strictly before T1.
		if t.Before(gs.t1) {
			return gateProceed
		}
		return gateSuppressSilent
	default:
		// stopped/canceled/aborted (pre nil-swap): post-window initiation
		// is generation-suppressed per the matrix.
		return gateSuppressSilent
	}
}

// bucketFor classifies a successful write by its FRESH write-return time
// against the half-open window: t < T1 → in_window, else drain.
func (p *scenarioPart) bucketFor(t time.Time) *atomic.Uint64 {
	gs := p.gate.Load()
	if gs != nil && t.Before(gs.t1) {
		// Localize the in-window fire to its time sub-window (FR28) on the
		// same FRESH write-return time that classifies in_window vs drain,
		// so localization and the identity split agree by construction.
		p.ledger.recordSubWindow(gs, t)
		return &p.ledger.inWindow
	}
	return &p.ledger.drain
}
