/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// ScenarioController owns the single active load-test scenario's lifecycle
// (architecture D2/D4): the sole writer of phase and the published gateState
// snapshot. All transitions are mutex-guarded (operator-frequency, no hot
// path); the atomic gateState pointer each participant reads is the only
// hot-path artifact. MVP: one active scenario at a time (FR38 trivially
// satisfied).
//
// Story 1.2 scope: driven directly in-process (no HTTP — 1.3 wraps this).
type ScenarioController struct {
	sm *SimulatorManager

	mu    sync.Mutex
	spec  *Scenario
	id    string
	phase scenarioPhase

	// configSHA is the SHA-256 fingerprint over the canonicalized submit
	// config (D5). Opaque identity string set once at submit by the manager
	// glue; read for the report/status. Never mutated after Submit.
	configSHA string

	// startTimer / scheduledAt back an absolute-T0 scheduled start (FR11):
	// the scenario stays `armed` until the timer fires Start at scheduledAt.
	// The timer is stopped by Cancel/finish so a DELETE-before-T0 is clean.
	startTimer  *time.Timer
	scheduledAt time.Time

	// gate is the published snapshot; participants hold &gate and Load it.
	gate atomic.Pointer[gateState]
	// drain is the per-scenario admission + drain barrier: every gate-passed
	// fire admits, stop/abort closeAndWait()s. Owned here, referenced via
	// each scenarioPart.
	drain drainGate
	// autoStop fires the window's self-close at T1 (FR12/FR17: emission
	// runs only within [T0,T1)). nil until Start; cancelled at finalize.
	autoStop *time.Timer
	// parts maps participant IP → its installed handle (for teardown).
	parts map[string]*scenarioPart
	// ledgers maps participant IP → its ledger entry (for finalize).
	ledgers map[string]*ledgerEntry
	// excluded lists participants that failed arm-time resolution (FR9).
	excluded []excludedParticipant

	sched     *SyslogScheduler
	schedStop context.CancelFunc

	now func() time.Time // injectable clock (tests); defaults to time.Now

	// transitions is the ordered lifecycle log (D7 abort observability):
	// one entry per actual phase change, appended under c.mu. Surfaced via
	// status so an operator can confirm a SIGTERM-driven abort after the
	// fact. Minimal precursor to the full structured phase log (story 5.2).
	transitions []scenarioTransition

	result *ScenarioResult // populated at finalize
}

// scenarioTransition is one recorded lifecycle step.
type scenarioTransition struct {
	Phase scenarioPhase
	At    time.Time
}

// excludedParticipant records why a declared participant did not arm (FR9;
// the shape Sally's readiness contract mandates — {device, reason,
// remediation_hint}). Serialized by 1.3.
type excludedParticipant struct {
	Device          string
	Reason          string
	RemediationHint string
}

// ScenarioResult is the internal finalized outcome the controller holds
// after stop/abort; 1.3 serializes it into the report. Immutable once set.
type ScenarioResult struct {
	ID        string
	Phase     scenarioPhase
	T0Actual  time.Time
	T1Actual  time.Time
	DrainEnd  time.Time
	Excluded  []excludedParticipant
	PerDevice map[string]ledgerSnapshot
}

// newScenarioController is used by the manager and tests. clock may be nil
// (defaults to time.Now).
func newScenarioController(sm *SimulatorManager, clock func() time.Time) *ScenarioController {
	if clock == nil {
		clock = time.Now
	}
	return &ScenarioController{sm: sm, phase: phaseSubmitted, now: clock}
}

var errInvalidTransition = fmt.Errorf("invalid scenario lifecycle transition")

// isTerminalPhase reports whether no further transition is legal from p.
func isTerminalPhase(p scenarioPhase) bool {
	return p == phaseStopped || p == phaseCanceled || p == phaseAborted
}

// transition validates from→to against the table and applies it. Idempotent
// re-entry (from == current == to intent) returns nil without error. Callers
// hold c.mu.
func (c *ScenarioController) transitionLocked(to scenarioPhase) error {
	from := c.phase
	if from == to {
		// Idempotent re-entry is only valid for non-terminal phases (a
		// re-arm or a re-submit intent). Re-issuing a terminal transition
		// (stopped/canceled/aborted) is a programming error — the scenario
		// is done — so it is rejected, not silently accepted.
		if isTerminalPhase(from) {
			return fmt.Errorf("%w: %s is terminal", errInvalidTransition, from)
		}
		return nil
	}
	ok := false
	switch from {
	case phaseSubmitted:
		ok = to == phaseArmed
	case phaseArmed:
		ok = to == phaseRunning || to == phaseCanceled
	case phaseRunning:
		ok = to == phaseStopped || to == phaseAborted
	}
	if !ok {
		return fmt.Errorf("%w: %s -> %s", errInvalidTransition, from, to)
	}
	c.phase = to
	c.transitions = append(c.transitions, scenarioTransition{Phase: to, At: c.now()})
	log.Printf("[scenario] %s %s -> %s", c.id, from, to)
	return nil
}

// Submit installs a validated spec. submitted is the only legal start state.
func (c *ScenarioController) Submit(spec *Scenario, id string) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase != phaseSubmitted || c.spec != nil {
		return fmt.Errorf("scenario controller already holds scenario %s (phase %s); MVP allows one active scenario", c.id, c.phase)
	}
	c.spec = spec
	c.id = id
	c.parts = make(map[string]*scenarioPart)
	c.ledgers = make(map[string]*ledgerEntry)
	c.transitions = append(c.transitions, scenarioTransition{Phase: phaseSubmitted, At: c.now()})
	return nil
}

// Transitions returns a copy of the ordered lifecycle log (observability).
func (c *ScenarioController) Transitions() []scenarioTransition {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]scenarioTransition, len(c.transitions))
	copy(out, c.transitions)
	return out
}

// usesScheduler reports whether the scenario protocol emits via a scenario-
// owned scheduler (syslog) or via the device's own gated exporter cadence
// (flow protocols — the gate lives in FlowExporter.Tick, no scheduler).
func (c *ScenarioController) usesScheduler() bool { return c.spec.Protocol == "syslog" }

// installScenPart stores the participation handle on the device's exporter for
// the scenario's protocol. ok=false with a reason/hint when the device lacks
// that exporter (→ excluded set, FR9).
func (c *ScenarioController) installScenPart(dev *DeviceSimulator, part *scenarioPart) (ok bool, reason, hint string) {
	switch c.spec.Protocol {
	case "syslog":
		if dev.syslogExporter == nil {
			return false, "device has no syslog exporter", "enable syslog export on the device (seed flag or per-device block)"
		}
		dev.syslogExporter.scenPart.Store(part)
	case "netflow9":
		if dev.flowExporter == nil || dev.flowExporter.protocol != "netflow9" {
			return false, "device has no netflow9 flow exporter", "enable flow export with protocol netflow9 (seed flag or per-device flow block)"
		}
		dev.flowExporter.scenPart.Store(part)
	default:
		return false, "unsupported scenario protocol", ""
	}
	return true, "", ""
}

// detachScenPart nil-swaps the participation handle on the protocol's exporter.
func (c *ScenarioController) detachScenPart(dev *DeviceSimulator) {
	switch c.spec.Protocol {
	case "syslog":
		if dev.syslogExporter != nil {
			dev.syslogExporter.scenPart.Store(nil)
		}
	case "netflow9":
		if dev.flowExporter != nil {
			dev.flowExporter.scenPart.Store(nil)
		}
	}
}

// exporterPresent reports whether dev still carries the scenario protocol's
// exporter (arm→start gap check).
func (c *ScenarioController) exporterPresent(dev *DeviceSimulator) bool {
	switch c.spec.Protocol {
	case "syslog":
		return dev.syslogExporter != nil
	case "netflow9":
		return dev.flowExporter != nil && dev.flowExporter.protocol == "netflow9"
	}
	return false
}

// Arm resolves participants against the live fleet, installs participation
// handles, and publishes the armed gate. Unknown/ineligible devices go to
// the excluded set (FR9) rather than failing the whole arm. Returns the
// count armed and the excluded list.
func (c *ScenarioController) Arm() (armed int, excluded []excludedParticipant, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.transitionLocked(phaseArmed); err != nil {
		return 0, nil, err
	}

	// Membership snapshot under the manager lock keeps arm TOCTOU-safe
	// against concurrent device CRUD (architecture D6). We only READ the
	// device set here; freeze happens at Start.
	c.sm.mu.RLock()
	gs := &gateState{phase: phaseArmed}
	c.gate.Store(gs)
	for _, ip := range c.spec.Participants {
		dev := c.sm.devicesByIP[ip]
		if dev == nil {
			c.excluded = append(c.excluded, excludedParticipant{
				Device: ip, Reason: "device not found",
				RemediationHint: "create the device before arming, or remove it from the scenario",
			})
			continue
		}
		led := &ledgerEntry{}
		part := &scenarioPart{gate: &c.gate, ledger: led, drain: &c.drain, now: c.now}
		if ok, reason, hint := c.installScenPart(dev, part); !ok {
			c.excluded = append(c.excluded, excludedParticipant{Device: ip, Reason: reason, RemediationHint: hint})
			continue
		}
		c.parts[ip] = part
		c.ledgers[ip] = led
		armed++
	}
	c.sm.mu.RUnlock()
	return armed, c.excluded, nil
}

// Start freezes the fleet, publishes the running gate at T0, and starts the
// scenario-owned scheduler. Refused at 0/N armed (FR40).
func (c *ScenarioController) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase != phaseArmed {
		return fmt.Errorf("%w: %s -> running (arm first)", errInvalidTransition, c.phase)
	}
	if len(c.parts) == 0 {
		return fmt.Errorf("cannot start scenario %s: 0/%d participants armed", c.id, len(c.spec.Participants))
	}
	if err := c.sm.freezeFleet(c.id); err != nil {
		return err // e.g. a creation batch is in flight
	}
	if err := c.transitionLocked(phaseRunning); err != nil {
		c.sm.unfreezeFleet()
		return err
	}

	t0 := c.now()
	t1 := t0.Add(c.spec.Window)
	drainEnd := t1.Add(c.spec.drainOrDefault())
	c.gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1, drainEnd: drainEnd})

	// Drop participants deleted in the Arm→Start gap (before the freeze) so the
	// ledger only reports devices that actually ran and the 0/N refusal sees
	// the true count. Protocol-agnostic: the presence check is per-protocol.
	c.sm.mu.RLock()
	registered := 0
	for ip := range c.parts {
		if dev := c.sm.devicesByIP[ip]; dev != nil && c.exporterPresent(dev) {
			registered++
			continue
		}
		delete(c.parts, ip)
		delete(c.ledgers, ip)
		c.excluded = append(c.excluded, excludedParticipant{
			Device: ip, Reason: "device deleted between arm and start",
			RemediationHint: "re-arm the scenario after the fleet is stable",
		})
	}
	c.sm.mu.RUnlock()
	if registered == 0 {
		c.sm.unfreezeFleet()
		c.phase = phaseArmed // roll back the running transition
		c.gate.Store(&gateState{phase: phaseArmed})
		return fmt.Errorf("cannot start scenario %s: all armed participants were deleted before start", c.id)
	}

	schedCtx, cancel := context.WithCancel(ctx)
	c.schedStop = cancel

	// syslog emits via a scenario-owned scheduler (D1b: shared limiter, own
	// seed/clock). Flow protocols emit via the device's own flow ticker, now
	// gated by the participation handle installed at arm — no scheduler.
	if c.usesScheduler() {
		var sharedLimiter *rate.Limiter
		if bg := c.sm.syslogScheduler.Load(); bg != nil {
			sharedLimiter = bg.limiterRef()
		}
		sched, err := newScenarioSyslogScheduler(c.spec, func(ip net.IP) *SyslogCatalog {
			return c.sm.SyslogCatalogFor(ip.String())
		}, sharedLimiter, c.now)
		if err != nil {
			// Validated at submit, so unexpected; unwind defensively.
			cancel()
			c.sm.unfreezeFleet()
			c.phase = phaseArmed
			c.gate.Store(&gateState{phase: phaseArmed})
			return fmt.Errorf("cannot start scenario %s: %w", c.id, err)
		}
		c.sched = sched
		c.sm.mu.RLock()
		for ip := range c.parts {
			if dev := c.sm.devicesByIP[ip]; dev != nil && dev.syslogExporter != nil {
				c.sched.Register(dev.IP, scenarioSyslogFirer{dev.syslogExporter})
			}
		}
		c.sm.mu.RUnlock()
		go c.sched.Run(schedCtx)
	}

	// Abort predicate (FR7): watch a mid-run ledger metric and self-abort a
	// runaway run. Shares schedCtx, so finalize (which cancels schedStop)
	// also stops the watcher. Built at submit (validated), so err is
	// unexpected here; a nil predicate means the watcher never starts.
	if pred, err := buildAbortPredicate(c.spec.AbortPredicate); err == nil && pred != nil {
		go c.watchPredicate(schedCtx, pred)
	}

	// Self-close at T1 (FR12/FR17): the window is [T0,T1). Without this the
	// scenario scheduler would keep popping past T1 — burning shared global-
	// cap tokens on fires the gate silently suppresses, starving the fleet.
	// An explicit early Stop()/Abort() cancels this timer.
	c.autoStop = time.AfterFunc(c.spec.Window, func() { _, _ = c.Stop() })
	return nil
}

// ScheduleStart arms an absolute-T0 start (FR11): the scenario stays `armed`
// and a controller timer fires Start(ctx) at `at`. Requires armed with ≥1
// participant. The caller (REST layer) has already rejected a past `at`.
func (c *ScenarioController) ScheduleStart(ctx context.Context, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase != phaseArmed {
		return fmt.Errorf("%w: %s -> scheduled start (arm first)", errInvalidTransition, c.phase)
	}
	if len(c.parts) == 0 {
		return fmt.Errorf("cannot schedule scenario %s: 0/%d participants armed", c.id, len(c.spec.Participants))
	}
	if c.startTimer != nil {
		return fmt.Errorf("scenario %s already has a scheduled start at %s", c.id, c.scheduledAt.Format(time.RFC3339))
	}
	c.scheduledAt = at
	// AfterFunc and c.now share the clock (both real, or both synctest-fake).
	c.startTimer = time.AfterFunc(at.Sub(c.now()), func() { _ = c.Start(ctx) })
	log.Printf("[scenario] %s start scheduled for %s", c.id, at.Format(time.RFC3339))
	return nil
}

// ScheduledStart returns the pending absolute start time (zero if none).
func (c *ScenarioController) ScheduledStart() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scheduledAt
}

// Stop ends emission at T1, drains in-flight fires, finalizes the ledger,
// and unfreezes the fleet. Terminal.
func (c *ScenarioController) Stop() (*ScenarioResult, error) {
	return c.finish(phaseStopped)
}

// Abort is the graceful-shutdown path (D7): same drain→finalize pipeline
// with phase aborted. Bounded by the drain grace so shutdown cannot hang.
func (c *ScenarioController) Abort() (*ScenarioResult, error) {
	return c.finish(phaseAborted)
}

func (c *ScenarioController) finish(to scenarioPhase) (*ScenarioResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.transitionLocked(to); err != nil {
		return nil, err
	}
	if c.autoStop != nil {
		c.autoStop.Stop() // cancel the self-close timer (no-op if it already fired)
	}

	// Actual T1 = the instant emission stops. For an on-time auto-stop this
	// is ~the planned T1; for an early Abort it is now — so report consumers
	// see the window that actually ran, not the planned one. Bucket
	// classification (in_window vs drain) keeps using the PLANNED t1: a fire
	// admitted before an early abort was still within [T0, planned-T1).
	prev := c.gate.Load() // never nil: Start always published a running gate
	t0, plannedT1 := prev.t0, prev.t1
	actualT1 := c.now()
	if actualT1.After(plannedT1) {
		actualT1 = plannedT1
	}
	// Publish the terminal gate FIRST so no new fire initiates; the drain
	// barrier (below) then outlasts every already-admitted in-flight fire.
	c.gate.Store(&gateState{phase: to, t0: t0, t1: plannedT1, drainEnd: prev.drainEnd})

	if c.schedStop != nil {
		c.schedStop()
	}
	if c.sched != nil {
		c.sched.Stop()
	}
	c.drain.closeAndWait() // admission closes; outlasts every in-flight fire

	// Detach participation handles (atomic nil-swap; producers tolerate nil).
	c.sm.mu.RLock()
	for ip := range c.parts {
		if dev := c.sm.devicesByIP[ip]; dev != nil {
			c.detachScenPart(dev)
		}
	}
	c.sm.mu.RUnlock()

	c.sm.unfreezeFleet()

	perDevice := make(map[string]ledgerSnapshot, len(c.ledgers))
	for ip, led := range c.ledgers {
		perDevice[ip] = led.snapshot()
	}
	c.result = &ScenarioResult{
		ID: c.id, Phase: to, T0Actual: t0, T1Actual: actualT1, DrainEnd: c.now(),
		Excluded: c.excluded, PerDevice: perDevice,
	}
	return c.result, nil
}

// Result returns the finalized result, or nil if the scenario has not
// reached a terminal phase (e.g. auto-stop hasn't fired yet).
func (c *ScenarioController) Result() *ScenarioResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.result
}

// Cancel releases an armed-but-unstarted scenario: detach handles, no
// measurement report (FR39). Only legal from armed.
func (c *ScenarioController) Cancel() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.transitionLocked(phaseCanceled); err != nil {
		return err
	}
	if c.startTimer != nil {
		c.startTimer.Stop() // cancel a pending scheduled start (FR11)
	}
	c.gate.Store(&gateState{phase: phaseCanceled})
	c.sm.mu.RLock()
	for ip := range c.parts {
		if dev := c.sm.devicesByIP[ip]; dev != nil {
			c.detachScenPart(dev)
		}
	}
	c.sm.mu.RUnlock()
	return nil
}

// Phase returns the current lifecycle phase (test/observability helper).
func (c *ScenarioController) Phase() scenarioPhase {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.phase
}
