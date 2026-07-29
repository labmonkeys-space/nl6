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
	// Apps is the fleet-wide per-application flow-traffic fold
	// (scenario-app-traffic): sent-basis totals keyed by (l4 proto, dst
	// port), folded across participants at finalize. Empty for non-flow
	// and sflow scenarios.
	Apps map[appKey]appCounters
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
	// Structured key=value transition log (5.2 / NFR-O2): `scenario=<id>
	// phase=<to>` is the correlation surface a monitoring stack greps/parses;
	// prev is retained for at-a-glance context.
	log.Printf("[scenario] scenario=%s phase=%s prev=%s", c.id, to, from)
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
	if isFlowScenarioProtocol(c.spec.Protocol) {
		if dev.flowExporter == nil || dev.flowExporter.protocol != c.spec.Protocol {
			return false, fmt.Sprintf("device has no %s flow exporter", c.spec.Protocol),
				fmt.Sprintf("enable flow export with protocol %s (seed flag or per-device flow block)", c.spec.Protocol)
		}
		// Per-application ledger participation (scenario-app-traffic):
		// template protocols only — sflow byte totals are sampling
		// extrapolation at the collector and would not reconcile.
		part.countApps = c.spec.Protocol != "sflow"
		dev.flowExporter.scenPart.Store(part)
		return true, "", ""
	}
	if c.spec.Protocol == "snmp-trap" {
		if dev.trapExporter == nil {
			return false, "device has no snmp trap exporter",
				"enable trap export on the device (seed flag or per-device traps block)"
		}
		dev.trapExporter.scenPart.Store(part)
		return true, "", ""
	}
	if c.spec.Protocol == "gnmi-dialout" {
		if dev.gnmiDialoutExporter == nil {
			return false, "device has no gnmi dial-out exporter",
				"enable gNMI dial-out on the device (seed flag or per-device gnmi_dialout block)"
		}
		// Stream-arming proof (FR16): a participant must have a live Publish
		// stream at arm, else the collector is unreachable — surface it.
		if !dev.gnmiDialoutExporter.streamLive() {
			return false, "gnmi dial-out stream not established (collector unreachable?)",
				"ensure the dial-out collector is reachable, then re-arm"
		}
		dev.gnmiDialoutExporter.scenPart.Store(part)
		return true, "", ""
	}
	switch c.spec.Protocol {
	case "syslog":
		if dev.syslogExporter == nil {
			return false, "device has no syslog exporter", "enable syslog export on the device (seed flag or per-device block)"
		}
		dev.syslogExporter.scenPart.Store(part)
	default:
		return false, "unsupported scenario protocol", ""
	}
	return true, "", ""
}

// detachScenPart nil-swaps the participation handle on the protocol's exporter.
func (c *ScenarioController) detachScenPart(dev *DeviceSimulator) {
	if isFlowScenarioProtocol(c.spec.Protocol) {
		if dev.flowExporter != nil {
			dev.flowExporter.scenPart.Store(nil)
			dev.flowExporter.scenDriven.Store(false) // hand cadence back to the fleet ticker
		}
		return
	}
	if c.spec.Protocol == "snmp-trap" {
		if dev.trapExporter != nil {
			dev.trapExporter.scenPart.Store(nil)
		}
		return
	}
	if c.spec.Protocol == "gnmi-dialout" {
		if dev.gnmiDialoutExporter != nil {
			dev.gnmiDialoutExporter.scenPart.Store(nil)
		}
		return
	}
	if c.spec.Protocol == "syslog" && dev.syslogExporter != nil {
		dev.syslogExporter.scenPart.Store(nil)
	}
}

// startScenarioFlowTicker drives participant flow emission at the scenario
// cadence during [T0,T1) (D1 flow-cadence adaptation). It marks each
// participant scenDriven so the fleet ticker yields, then ticks each exporter
// at spec.interval() until ctx is cancelled at finalize.
func (c *ScenarioController) startScenarioFlowTicker(ctx context.Context) {
	c.sm.mu.RLock()
	feList := make([]*FlowExporter, 0, len(c.parts))
	for ip := range c.parts {
		if dev := c.sm.devicesByIP[ip]; dev != nil && dev.flowExporter != nil {
			dev.flowExporter.scenDriven.Store(true)
			feList = append(feList, dev.flowExporter)
		}
	}
	c.sm.mu.RUnlock()

	interval := c.spec.interval()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := c.now()
				for _, fe := range feList {
					c.sm.tickFlowExporter(fe, now)
				}
			}
		}
	}()
}

// exporterPresent reports whether dev still carries the scenario protocol's
// exporter (arm→start gap check).
func (c *ScenarioController) exporterPresent(dev *DeviceSimulator) bool {
	if isFlowScenarioProtocol(c.spec.Protocol) {
		return dev.flowExporter != nil && dev.flowExporter.protocol == c.spec.Protocol
	}
	if c.spec.Protocol == "snmp-trap" {
		return dev.trapExporter != nil
	}
	if c.spec.Protocol == "gnmi-dialout" {
		return dev.gnmiDialoutExporter != nil
	}
	return c.spec.Protocol == "syslog" && dev.syslogExporter != nil
}

// Arm resolves participants against the live fleet, installs participation
// handles, and publishes the armed gate. Unknown/ineligible devices go to
// the excluded set (FR9) rather than failing the whole arm. Returns the
// count armed and the excluded list.
//
// Arm is REBUILDING, not accumulating. `transitionLocked` permits armed→armed as
// legal idempotent re-entry (a re-arm intent — the "device not found" hint tells
// operators to re-arm once the fleet is stable), so the derived view is rebuilt
// here rather than added to. Without that, a second arm doubled the excluded set
// and left stale parts entries for devices dropped between the two calls.
//
// Rebuilding has two obligations that a naive reset gets wrong:
//
//  1. HANDLES MUST BE DETACHED BEFORE THEY ARE FORGOTTEN. installScenPart stores
//     the part on the *device's exporter*; c.parts is only our reference to it,
//     and every detach path (finish, Cancel) iterates c.parts. So dropping an IP
//     from the map without detaching leaks the handle onto a live exporter, and
//     once the gate reaches a terminal phase that exporter is silently muted for
//     the process lifetime (decide → gateSuppressSilent). The accumulating map
//     this rebuild replaced was, accidentally, what kept such devices reachable.
//     Reachable for real: a gnmi-dialout participant whose streamLive() blips
//     fails install on the re-arm the exclusion hint just asked for.
//
//  2. LEDGERS MUST SURVIVE for participants that stay armed. "Nothing has
//     emitted yet" is false while armed: background fires increment
//     backgroundSuppressed at any phase, and exogenous pre-T0 fires are
//     gateSuppressCounted (emitted + suppressedPreWindow). Those are reported
//     disclosure (FR15/FR21) and are exported as Prometheus counters under
//     labels a re-arm does not change, so replacing the ledger would look like a
//     counter reset to rate()/increase(). Carrying it forward keeps it monotonic.
//
// Participant uniqueness is guaranteed upstream: Scenario.Validate rejects a
// duplicated list, so there is no dedup here (and none inside the manager lock).
func (c *ScenarioController) Arm() (int, []excludedParticipant, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.transitionLocked(phaseArmed); err != nil {
		return 0, nil, err
	}

	// A pending scheduled start was authorised against the membership the PREVIOUS
	// arm resolved. Re-resolving membership withdraws that authorisation: the set
	// may now differ, or be empty, and either silently starting at T0 against a
	// set the operator never approved or firing a Start that cannot succeed is
	// worse than requiring the schedule to be re-issued. Cancelling here is also
	// what keeps `scheduled_start` in the status truthful.
	if c.startTimer != nil {
		c.startTimer.Stop()
		c.startTimer = nil
		c.scheduledAt = time.Time{}
		log.Printf("[scenario] scenario=%s re-armed; pending scheduled start cancelled (reschedule after checking readiness)", c.id)
	}

	// Keep the previous arm's view to carry ledgers forward (obligation 2) and to
	// detach whatever does not survive this pass (obligation 1).
	prevParts, prevLedgers := c.parts, c.ledgers
	c.excluded = nil
	// Fresh slice/maps, never truncate-in-place: a previously returned excluded
	// slice must not be mutated under a caller still serving it.
	c.parts = make(map[string]*scenarioPart)
	c.ledgers = make(map[string]*ledgerEntry)

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
		led := prevLedgers[ip] // nil on a first arm
		if led == nil {
			led = &ledgerEntry{}
		}
		part := &scenarioPart{gate: &c.gate, ledger: led, drain: &c.drain, now: c.now}
		if ok, reason, hint := c.installScenPart(dev, part); !ok {
			c.excluded = append(c.excluded, excludedParticipant{Device: ip, Reason: reason, RemediationHint: hint})
			continue
		}
		c.parts[ip] = part
		c.ledgers[ip] = led
	}
	// Obligation 1: release handles from the previous arm that this pass did not
	// reinstall. A participant still armed had its handle overwritten in place by
	// installScenPart above, so only the dropped ones need the nil-swap.
	for ip := range prevParts {
		if _, stillArmed := c.parts[ip]; stillArmed {
			continue
		}
		if dev := c.sm.devicesByIP[ip]; dev != nil {
			c.detachScenPart(dev)
		}
	}
	c.sm.mu.RUnlock()
	// Derive the count from the map rather than counting loop iterations, so it
	// cannot drift from the map the rest of the lifecycle uses: Start's 0/N
	// refusal tests len(c.parts) and the report publishes len(PerDevice).
	return len(c.parts), c.excluded, nil
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
	} else if isFlowScenarioProtocol(c.spec.Protocol) {
		// Flow protocols: the scenario drives participant emission at its own
		// cadence during the window (D1 flow-cadence adaptation).
		c.startScenarioFlowTicker(schedCtx)
	} else if c.spec.Protocol == "snmp-trap" {
		// Traps: a scenario-owned ticker fires each participant at the scenario
		// cadence; the fleet scheduler's fires are gated as background.
		c.startScenarioTrapTicker(schedCtx)
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
	c.startTimer = time.AfterFunc(at.Sub(c.now()), func() { c.startScheduled(ctx) })
	log.Printf("[scenario] %s start scheduled for %s", c.id, at.Format(time.RFC3339))
	return nil
}

// startScheduled is the timer-driven Start. A scheduled start can legitimately
// fail — every armed participant may have been deleted before T0, in which case
// Start rolls back to `armed` and returns an error — and that error used to be
// discarded, which left the scenario in a state no operator could get out of:
// phase `armed`, a `scheduled_start` in the past, and ScheduleStart refusing a
// replacement because startTimer was still non-nil. So log the failure and
// RELEASE the schedule, which both tells the operator what happened and restores
// the ability to reschedule.
func (c *ScenarioController) startScheduled(ctx context.Context) {
	err := c.Start(ctx) // takes c.mu; must not be called under it
	if err == nil {
		return
	}
	c.mu.Lock()
	// Nobody can have installed a new timer in the meantime: ScheduleStart
	// refuses while startTimer is non-nil, and only this path clears it after a
	// fire. Clearing on a Cancel/Stop race is harmless — the schedule is moot.
	c.startTimer = nil
	c.scheduledAt = time.Time{}
	c.mu.Unlock()
	log.Printf("[scenario] scenario=%s scheduled start failed: %v; schedule released — re-arm and reschedule", c.id, err)
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
	apps := make(map[appKey]appCounters)
	for ip, led := range c.ledgers {
		perDevice[ip] = led.snapshot()
		// Fleet-wide application fold (scenario-app-traffic). Element-wise
		// sum, same read-after-drain-barrier discipline as snapshot().
		for k, v := range led.appSnapshot() {
			agg := apps[k]
			agg.records += v.records
			agg.bytes += v.bytes
			agg.packets += v.packets
			agg.inWindowBytes += v.inWindowBytes
			for i := range v.subWindowBytes {
				agg.subWindowBytes[i] += v.subWindowBytes[i]
			}
			apps[k] = agg
		}
	}
	c.result = &ScenarioResult{
		ID: c.id, Phase: to, T0Actual: t0, T1Actual: actualT1, DrainEnd: c.now(),
		Excluded: c.excluded, PerDevice: perDevice, Apps: apps,
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

// LiveCounts sums the participant ledgers with APPROXIMATE mid-run atomic reads
// (the 3.4 seam — no drain barrier) for live status. Exact only after finalize;
// a running read is a progress snapshot that may lag an in-flight fire.
func (c *ScenarioController) LiveCounts() (armed int, sum ledgerSnapshot) {
	c.mu.Lock()
	ledgers := make([]*ledgerEntry, 0, len(c.ledgers))
	for _, l := range c.ledgers {
		ledgers = append(ledgers, l)
	}
	c.mu.Unlock()
	armed = len(ledgers)
	for _, l := range ledgers {
		s := l.snapshot()
		sum.Emitted += s.Emitted
		sum.InWindow += s.InWindow
		sum.Drain += s.Drain
		sum.SuppressedPreWindow += s.SuppressedPreWindow
		sum.SendFailures += s.SendFailures
		sum.Dropped += s.Dropped
		sum.BackgroundSuppressed += s.BackgroundSuppressed
		sum.Requested += s.Requested
		sum.Deferred += s.Deferred
		sum.InformsOriginated += s.InformsOriginated
		sum.InformsAcked += s.InformsAcked
	}
	return armed, sum
}

// LivePerDevice returns per-participant ledger snapshots keyed by source IP —
// the finalized result if terminal, else approximate mid-run atomic reads (the
// same seam as LiveCounts). The metrics exposition labels each snapshot on the
// report tuple, so summing sent over the map reproduces the report totals
// (NFR-O2). Post-finalize the live ledgers equal the result, so the choice is
// only about consistency before the scenario stops.
func (c *ScenarioController) LivePerDevice() map[string]ledgerSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.result != nil {
		out := make(map[string]ledgerSnapshot, len(c.result.PerDevice))
		for ip, s := range c.result.PerDevice {
			out[ip] = s
		}
		return out
	}
	out := make(map[string]ledgerSnapshot, len(c.ledgers))
	for ip, l := range c.ledgers {
		out[ip] = l.snapshot()
	}
	return out
}

// WindowBounds returns the scenario measurement window [t0,t1) — the finalized
// actuals if terminal, else the live running gate. ok=false before running.
func (c *ScenarioController) WindowBounds() (t0, t1 time.Time, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.result != nil {
		return c.result.T0Actual, c.result.T1Actual, true
	}
	if gs := c.gate.Load(); gs != nil && gs.phase == phaseRunning {
		return gs.t0, gs.t1, true
	}
	return time.Time{}, time.Time{}, false
}

// PlannedWindow returns the configured window length.
func (c *ScenarioController) PlannedWindow() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.spec == nil {
		return 0
	}
	return c.spec.Window
}
