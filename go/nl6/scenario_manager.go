/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"cmp"
	"fmt"
	"log"
	"slices"
	"strconv"
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

// errScenarioActive is returned when a submit would exceed the concurrency
// bound (maps to 409). It no longer means "one at a time": per-device overlap
// (#392) moved exclusivity to the devices themselves, so scenarios with
// disjoint participants run concurrently and only the resource bound applies.
// The name is kept because the HTTP layer discriminates on it.
var errScenarioActive = fmt.Errorf("too many active scenarios")

// scenarioMaxConcurrent bounds simultaneously non-terminal scenarios. Each
// retains ledgers, a drain barrier, and possibly a scheduler goroutine, so the
// count is a resource surface; it is bounded explicitly rather than by accident,
// as every other limit in this subsystem is. Eight is well above the mixed-
// protocol experiments this exists for (#392: syslog against one fleet half
// while IPFIX loads the other) and well below anything that strains the box.
const scenarioMaxConcurrent = 8

// scenarioMaxRetained bounds how many FINISHED scenarios stay queryable for
// their reports. A finished run must outlive a peer's submit — with several
// scenarios in flight, the alternative deletes the report someone is reading —
// but retention cannot be unlimited or the registry grows for the life of the
// process. The oldest are reaped first, so the reports most likely still being
// read are the ones kept.
const scenarioMaxRetained = 8

// errScenarioRunning is returned when a DELETE targets a running scenario;
// it must be stopped or aborted first (maps to 409).
var errScenarioRunning = fmt.Errorf("scenario is running; stop or abort it before deleting")

// submitScenario validates the spec, allocates the next s-%06d ID, and
// registers a fresh controller. It refuses (errScenarioActive) only when the
// concurrency bound is reached; terminal scenarios are reaped. Returns the new
// controller and its ID.
//
// Admission no longer decides exclusivity — the DEVICES do, via the claim in
// ArmReadiness (#392). Two scenarios with disjoint participants both submit and
// both run; overlapping ones are refused at arm, where membership is finally
// known. Submit cannot make that call: participants_cidr resolves against the
// live fleet, so at submit the participant set is not merely unknown but
// unknowable.
func (sm *SimulatorManager) submitScenario(spec *Scenario, configSHA string) (*ScenarioController, string, error) {
	sm.scenarioMu.Lock()
	defer sm.scenarioMu.Unlock()

	live := 0
	for _, c := range sm.scenarios {
		if !isTerminalPhase(c.Phase()) {
			live++
		}
	}
	if live >= scenarioMaxConcurrent {
		return nil, "", fmt.Errorf("%w: %d already active (max %d); stop or delete one first",
			errScenarioActive, live, scenarioMaxConcurrent)
	}

	sm.scenarioSeq++
	id := fmt.Sprintf("s-%06d", sm.scenarioSeq)
	ctrl := newScenarioController(sm, nil)
	if err := ctrl.Submit(spec, id); err != nil {
		sm.scenarioSeq-- // roll back the ID allocation on a rejected submit
		return nil, "", err
	}
	ctrl.configSHA = configSHA

	// Reap the OLDEST terminal scenarios, keeping the most recent
	// scenarioMaxRetained so a finished run's report survives a peer's submit.
	//
	// The single-slot version reaped every terminal scenario, because
	// overwriting the slot did. That was unsurprising when submits were
	// serialised: you only submitted after your own run had finished. With
	// concurrency it is not — a peer submitting would delete the report you are
	// reading. Retention is bounded rather than unlimited because the registry
	// would otherwise grow for the life of the process.
	var terminal []string
	for sid, c := range sm.scenarios {
		if isTerminalPhase(c.Phase()) {
			terminal = append(terminal, sid)
		}
	}
	if excess := len(terminal) - scenarioMaxRetained; excess > 0 {
		slices.SortFunc(terminal, compareScenarioID) // oldest first
		for _, sid := range terminal[:excess] {
			delete(sm.scenarios, sid)
		}
	}
	if sm.scenarios == nil {
		// Lazily created: SimulatorManager is built as a struct literal in many
		// places (tests especially), so no constructor can be relied on.
		sm.scenarios = make(map[string]*ScenarioController, 1)
	}
	sm.scenarios[id] = ctrl
	sm.refreshScenarioSnapLocked()
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
	slices.SortFunc(out, func(a, b scenarioListEntry) int { return compareScenarioID(a.ID, b.ID) })
	return out
}

// compareScenarioID orders scenario IDs by their numeric sequence, not
// lexically. IDs are formatted s-%06d, and %06d is a minimum width, not a
// clamp: at the millionth submit the ID grows a digit and "s-1000000" sorts
// BEFORE "s-999999" byte-wise, silently un-stabilising the very listing the
// sort exists to stabilise. Reaching that needs a million submits in one
// process — and under today's one-at-a-time policy the list holds a single
// entry — but per-device overlap (#392) is what makes multi-entry listings
// real, so the trap is removed before it can be reached rather than after.
//
// Falls back to a byte comparison for anything not in s-<digits> form, since
// controllers can be constructed with arbitrary IDs in tests.
func compareScenarioID(a, b string) int {
	an, aok := scenarioIDSeq(a)
	bn, bok := scenarioIDSeq(b)
	if aok && bok {
		return cmp.Compare(an, bn)
	}
	return strings.Compare(a, b)
}

// scenarioIDSeq extracts the numeric suffix of an s-<digits> scenario ID.
func scenarioIDSeq(id string) (uint64, bool) {
	rest, ok := strings.CutPrefix(id, "s-")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(rest, 10, 64)
	return n, err == nil
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
	sm.refreshScenarioSnapLocked()
	return nil
}

// abortActiveScenario aborts a running load-test scenario as part of
// graceful shutdown (D7). Abort()'s drain barrier gives up at
// drainBarrierTimeout since nl6#567, so the BARRIER is bounded. What is not
// bounded is finalize as a whole: finish() joins the scheduler and the trap and
// flow tickers before it reaches the barrier, and none of those joins has a
// ceiling. No configured grace bounds any of it either (there is none:
// nl6#500). What a write can block on, per transport:
//
//   - UDP parks only while the socket send buffer is full.
//   - syslog TCP/TLS bounds ONE write at syslogTCPWriteTimeout (2s), but
//     tcpTransport.Send holds writeMu across it, so the worst case for a device
//     is 2s × the fires admitted before T1 that queue behind that mutex — not
//     2s flat. The transport's own comment says as much.
//   - gNMI dial-out holds the barrier across an enqueue into a bounded
//     drop-oldest channel, never across the async Send.
//
// Those are the transports that exist, not a guarantee, and two cases fall
// outside them: a stream transport whose write sets no deadline blocks for as
// long as it blocks, and an admitted fire that never calls leave() (a panic on
// a write path, a dropped callback) would never complete at all. No write
// deadline can fix the second, which is why nl6#567 bounded the BARRIER rather
// than the transports: closeAndWait gives up at drainBarrierTimeout, reports
// how many sends were still outstanding, and lets shutdown proceed. The
// stragglers are not cancelled, so a truncated finalize says so in the report
// (drain_stragglers) instead of quietly publishing counters that were still
// moving when they were read.
// No-op when no scenario is running; the
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

// effectiveRateCap returns the fleet-wide events/second ceiling in force for a
// scenario protocol, or 0 when that protocol has none.
//
// Limiters are PER PROTOCOL (syslog, trap and flap each own one; flow and
// gNMI dial-out have none), which is why concurrent scenarios only contend
// when they share a protocol — the mixed-protocol experiments per-device
// overlap exists for share no bucket at all.
func (sm *SimulatorManager) effectiveRateCap(protocol string) int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	// SYSLOG ONLY. Having a global cap configured is not the same as a
	// scenario's emission passing through it, and only syslog does: its
	// scenario scheduler is built with the fleet scheduler's limiter verbatim
	// (SyslogSchedulerOptions.SharedLimiter).
	//
	// -trap-global-cap governs the fleet TrapScheduler's background firing. The
	// scenario trap path is startScenarioTrapTicker → fireScenario →
	// fireWithSource → fireWithCtx and takes no token anywhere; the exporter's
	// own limiter is consumed only for INFORM retransmissions. Disclosing that
	// cap would tell an operator their run was throttled and contended when it
	// was neither — a false statement in the artifact this disclosure exists to
	// make trustworthy, which is worse than no statement.
	if protocol == "syslog" {
		return sm.syslogGlobalCap
	}
	return 0
}

// runningPeers returns the OTHER scenarios of the same protocol that are
// running right now — the ones whose windows overlap this one's and which
// therefore draw from the same token bucket.
//
// Reads the lock-free registry snapshot rather than the map, so it is callable
// with c.mu held. Taking scenarioMu there would invert the established
// scenarioMu → c.mu order.
func (sm *SimulatorManager) runningPeers(protocol, selfID string) []*ScenarioController {
	snap := sm.scenarioSnap.Load()
	if snap == nil {
		return nil
	}
	var peers []*ScenarioController
	for _, c := range *snap {
		// emitting, not phase: finalize publishes the terminal phase BEFORE the
		// drain barrier, so a peer mid-drain is no longer "running" while its
		// already-admitted fires still spend tokens. A scenario starting inside
		// that grace is genuinely contended and must record it.
		if c.id == selfID || !c.emitting.Load() || c.protocol() != protocol {
			continue
		}
		peers = append(peers, c)
	}
	return peers
}

// refreshScenarioSnapLocked republishes the lock-free registry mirror. Callers
// hold scenarioMu.
func (sm *SimulatorManager) refreshScenarioSnapLocked() {
	snap := make([]*ScenarioController, 0, len(sm.scenarios))
	for _, c := range sm.scenarios {
		snap = append(snap, c)
	}
	sm.scenarioSnap.Store(&snap)
}
