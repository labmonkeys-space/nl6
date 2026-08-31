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
//
// There is deliberately no drain-end field: the post-T1 phase is a barrier,
// not a duration (nl6#500), so decide() has nothing to compare a drain
// deadline against and nothing may store one here.
type gateState struct {
	phase scenarioPhase
	t0    time.Time
	t1    time.Time
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
	// countApps marks this participant's flow batches for the per-application
	// ledger (scenario-app-traffic). Set once at installScenPart for
	// netflow5/netflow9/ipfix participants; false for sflow (collector byte
	// math is sampling extrapolation) and every non-flow protocol. Owned here,
	// not passed per call, so a second batch call site cannot disagree.
	countApps bool
	// owner is the scenario ID that installed this handle. It makes the
	// exporter's single scenPart slot self-arbitrating under per-device
	// overlap (#392): a claim is a compare-and-swap that succeeds on an empty
	// slot or one this same scenario already holds, and a release only clears
	// a handle we own. Without it, a re-arm could not re-claim its own devices,
	// a conflict could not name the holder, and a teardown could silently clear
	// another scenario's claim.
	owner string
}

// classify maps a FRESH write-return time to the (in-window, sub-window)
// decision against the half-open window [T0,T1): the single source of truth
// shared by the single-fire (bucketFor) and batch (bucketFlowBatch) paths.
// subIdx is -1 when not in-window or the window span is degenerate.
func (p *scenarioPart) classify(t time.Time) (inWindow bool, subIdx int) {
	gs := p.gate.Load()
	if gs == nil || !t.Before(gs.t1) {
		return false, -1
	}
	return true, subWindowIndex(gs, t)
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

// bucketFor classifies a SINGLE successful fire by its FRESH write-return
// time: t < T1 → in_window (localized to its sub-window), else drain (the
// barrier's tail — bounded by the work admitted before T1, not by any grace:
// one write on the syslog/trap path, a whole paginated batch on the flow path,
// which admits around Tick rather than around each WriteTo). The
// caller Add(1)s the returned counter — multi-record batches must use
// bucketFlowBatch instead, or sub_windows undercounts against in_window.
func (p *scenarioPart) bucketFor(t time.Time) *atomic.Uint64 {
	inWindow, subIdx := p.classify(t)
	if inWindow {
		if subIdx >= 0 {
			p.ledger.subWindows[subIdx].Add(1)
		}
		return &p.ledger.inWindow
	}
	return &p.ledger.drain
}

// bucketFlowBatch classifies a successfully-written multi-record flow batch
// by its FRESH write-return time, attributing ALL len(batch) records to the
// identity and sub-window counters (bucketFor's Add(1) would undercount the
// documented sum(sub_windows)==in_window invariant). When the participant is
// marked countApps (installScenPart: netflow5/9/ipfix, never sflow), the
// batch also folds into the per-application ledger. One classify() drives
// every counter, so the record and application ledgers cannot classify the
// same batch differently even across a teardown nil-swap.
func (p *scenarioPart) bucketFlowBatch(t time.Time, batch []FlowRecord) {
	n := uint64(len(batch))
	inWindow, subIdx := p.classify(t)
	if inWindow {
		if subIdx >= 0 {
			p.ledger.subWindows[subIdx].Add(n)
		}
		p.ledger.inWindow.Add(n)
	} else {
		p.ledger.drain.Add(n)
	}
	if p.countApps {
		p.ledger.addAppBatch(batch, inWindow, subIdx)
	}
}

// claimScenPart installs part into an exporter's participation slot, which is
// the ONLY arbiter of per-device exclusivity (#392 design D4). Making the
// install itself the claim means there is no separate ownership record that can
// drift from the handles actually installed — the failure mode this subsystem
// has already been bitten by once, when re-arm's bookkeeping and its handles
// disagreed.
//
// Succeeds on an empty slot (nil → mine) or one this same scenario already
// holds (mine → mine, so a re-arm re-claims its own devices). Otherwise it
// fails and names the holder. The loop retries a lost CAS rather than failing,
// because losing to a concurrent release means the slot is now free and this
// claim should take it.
func claimScenPart(slot *atomic.Pointer[scenarioPart], part *scenarioPart) (ok bool, holder string) {
	for {
		cur := slot.Load()
		switch {
		case cur == nil:
			if slot.CompareAndSwap(nil, part) {
				return true, ""
			}
		case cur.owner == part.owner:
			if slot.CompareAndSwap(cur, part) {
				return true, ""
			}
		default:
			return false, cur.owner
		}
	}
}

// releaseScenPart clears the slot only if owner still holds it. The ownership
// test is what makes teardown safe under overlap: an arm that failed to claim a
// device must not clear the claim of the scenario that legitimately owns it,
// and the arm→start prune releases handles for devices it is dropping.
// Reports whether it actually released, so callers can gate any DERIVED state
// they own on the same ownership test — clearing that unconditionally would
// undo it for the scenario that legitimately holds the device.
func releaseScenPart(slot *atomic.Pointer[scenarioPart], owner string) bool {
	for {
		cur := slot.Load()
		if cur == nil || cur.owner != owner {
			return false
		}
		if slot.CompareAndSwap(cur, nil) {
			return true
		}
	}
}
