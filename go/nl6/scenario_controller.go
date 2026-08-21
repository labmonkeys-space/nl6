/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"log"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
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
	// scheduleGen identifies the current schedule. Every ScheduleStart takes the
	// next value and its timer closure captures it; anything that withdraws a
	// schedule (Arm, finish, Cancel) bumps it. A fire whose captured generation
	// is stale is a fire whose authorisation was withdrawn while it was in
	// flight — timer.Stop() cannot express that, because it reports nothing
	// useful once the timer has already fired and is merely blocked on c.mu.
	scheduleGen uint64

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
	// excluded lists participants that failed arm-time resolution (FR9), capped
	// at scenarioMaxExcludedRows. excludedByReason accounts for every exclusion,
	// capped or not, so the disclosure stays complete in the aggregate even when
	// the row list is a sample. The published total is DERIVED from this map
	// (sumReasonCounts) rather than kept as a second counter, so the contract
	// "participants_excluded == Σ excluded_by_reason" is true by construction
	// instead of by every write site remembering to touch both. See recordExcluded.
	excluded         []excludedParticipant
	excludedByReason map[string]int

	sched     *SyslogScheduler
	schedStop context.CancelFunc

	// trapTickerDone is non-nil only for snmp-trap scenarios: closed by the
	// scenario trap ticker goroutine AFTER its emission pool has fully drained
	// (close(jobs) + wg.Wait()), so finalize can wait for the queued tail
	// before snapshotting ledgers (#409). Guarded by c.mu (set in Start,
	// read in finalize — both hold the lock).
	trapTickerDone chan struct{}

	// flowTickerDone is the same join for flow scenarios: non-nil only when
	// startScenarioFlowTicker ran, closed by that goroutine on return. Same
	// lock discipline as trapTickerDone.
	flowTickerDone chan struct{}

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

// scenarioMaxExcludedRows bounds the per-participant exclusion rows a scenario
// retains. One row costs ~145 JSON bytes and there is one per unresolved
// participant, so at the 100,000-participant ceiling an unbounded list is ~14 MB
// — held for the scenario's lifetime, copied into the readiness response, copied
// again into the report, and rendered one <tr> each into the HTML view, which is
// materialised whole under a 30 s server WriteTimeout.
//
// Capping the ROWS is not the same as dropping the disclosure FR9 requires:
// excludedByReason still accounts for every exclusion, so an
// operator facing 99,999 of them reads "device not found: 99,999" plus a
// thousand concrete examples, which is more actionable than 99,999 rows nobody
// scrolls. Remediation stays iterative — fix what the sample shows, re-arm, and
// the next batch surfaces.
// The by-reason breakdown is the safe replacement for the dropped rows only
// because the reason strings are a small FIXED set — the exporter-shape reasons
// interpolate the scenario's protocol, not the device — so the map's cardinality
// does not grow with the participant count. A reason that ever interpolated
// per-device detail would rebuild the very blowup this cap exists to prevent,
// inside the field advertised as bounded.
const scenarioMaxExcludedRows = 1000

// scenarioExcludedArmRows is the share of the row budget the ARM phase may use.
// The rest is reserved for exclusions recorded later, during Start's arm→start
// gap check. Without a reserve the cap is first-come across a heterogeneous
// population: arm's loop runs to completion first, so at ≥1000 arm exclusions
// every "device deleted between arm and start" row is dropped — and those are
// the only ones whose device identity an operator cannot reconstruct from
// (participants − fleet). Sampling that drops exactly the unpredictable class is
// the one sampling strategy that defeats the cap's own justification.
const scenarioExcludedArmRows = 900

// Compile-time guard: the arm share must leave a non-empty reserve for the
// start phase, or the split silently stops doing its job. The two constants are
// threaded to recordExcluded by its callers, so nothing at the call sites would
// notice a retune that inverted them — this array bound goes negative and fails
// the build instead.
var _ [scenarioMaxExcludedRows - scenarioExcludedArmRows - 1]struct{}

// recordExcluded records one exclusion, retaining a row while the caller's share
// of the budget has room. The by-reason count is unconditional, which is what
// keeps participants_excluded truthful when the row list is a sample. Callers
// hold c.mu.
func (c *ScenarioController) recordExcluded(device, reason, hint string, rowBudget int) {
	if c.excludedByReason == nil {
		c.excludedByReason = make(map[string]int)
	}
	c.excludedByReason[reason]++
	if len(c.excluded) < rowBudget {
		c.excluded = append(c.excluded, excludedParticipant{
			Device: device, Reason: reason, RemediationHint: hint,
		})
	}
}

// sumReasonCounts derives the exclusion total at the publication points, so it
// cannot drift from the breakdown consumers cross-check it against.
func sumReasonCounts(m map[string]int) int {
	total := 0
	for _, n := range m {
		total += n
	}
	return total
}

// ScenarioResult is the internal finalized outcome the controller holds
// after stop/abort; 1.3 serializes it into the report. Immutable once set.
type ScenarioResult struct {
	ID       string
	Phase    scenarioPhase
	T0Actual time.Time
	T1Actual time.Time
	DrainEnd time.Time
	Excluded []excludedParticipant
	// ExcludedTotal counts every exclusion, including those beyond the
	// scenarioMaxExcludedRows row cap; ExcludedByReason breaks the same total
	// down. participants_excluded is derived from ExcludedTotal, NOT from
	// len(Excluded), or capping the rows would understate the count.
	ExcludedTotal    int
	ExcludedByReason map[string]int
	PerDevice        map[string]ledgerSnapshot
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
		return c.claim(&dev.flowExporter.scenPart, part)
	}
	if c.spec.Protocol == "snmp-trap" {
		if dev.trapExporter == nil {
			return false, "device has no snmp trap exporter",
				"enable trap export on the device (seed flag or per-device traps block)"
		}
		return c.claim(&dev.trapExporter.scenPart, part)
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
		return c.claim(&dev.gnmiDialoutExporter.scenPart, part)
	}
	switch c.spec.Protocol {
	case "syslog":
		if dev.syslogExporter == nil {
			return false, "device has no syslog exporter", "enable syslog export on the device (seed flag or per-device block)"
		}
		return c.claim(&dev.syslogExporter.scenPart, part)
	default:
		return false, "unsupported scenario protocol", ""
	}
}

// claim installs part via compare-and-swap, turning a lost claim into the
// exclusion shape installScenPart already speaks.
//
// Reaching this with a conflict is RARE by construction: ArmReadiness
// pre-checks every candidate and refuses the whole arm when any is held, so a
// failure here means another scenario claimed the device in the window between
// that check and this install. The pre-check is what produces the good
// diagnostic; this is what makes the exclusivity true rather than merely
// usually-true, and it degrades to an honest excluded row rather than silently
// stealing a device from its owner.
func (c *ScenarioController) claim(slot *atomic.Pointer[scenarioPart], part *scenarioPart) (ok bool, reason, hint string) {
	if ok, holder := claimScenPart(slot, part); !ok {
		return false, fmt.Sprintf("device claimed by scenario %s", holder),
			fmt.Sprintf("stop or delete scenario %s, or exclude this device from this scenario", holder)
	}
	return true, "", ""
}

// detachScenPart nil-swaps the participation handle on the protocol's exporter.
func (c *ScenarioController) detachScenPart(dev *DeviceSimulator) {
	slot := c.installedSlot(dev)
	if slot == nil {
		return
	}
	// Ownership-checked: this is called for devices this arm is DROPPING, and
	// under per-device overlap a drop can be caused by another scenario holding
	// the device. Clearing unconditionally would release their claim.
	released := releaseScenPart(slot, c.id)
	// scenDriven is DERIVED state owned by whoever holds the claim, so it is
	// gated on the same ownership test. Clearing it unconditionally would hand
	// the holder's device back to the fleet ticker while their scenario ticker
	// still drives it — both would tick, double-counting into their ledger.
	if released && isFlowScenarioProtocol(c.spec.Protocol) && dev.flowExporter != nil {
		dev.flowExporter.scenDriven.Store(false) // hand cadence back to the fleet ticker
	}
}

// scenPartSlot returns the slot this scenario COMPETES for on dev — the one an
// arm would claim — or nil when dev carries no exporter this scenario could
// use. Used by the overlap pre-check. Releasing uses installedSlot instead,
// because a handle already installed must stay releasable even if the exporter
// has since changed protocol.
func (c *ScenarioController) scenPartSlot(dev *DeviceSimulator) *atomic.Pointer[scenarioPart] {
	if isFlowScenarioProtocol(c.spec.Protocol) {
		// The protocol match is part of the identity, exactly as installScenPart
		// requires it: a device whose flow exporter speaks a DIFFERENT protocol
		// could never be a participant here, so it is not a device this scenario
		// competes for. Returning its slot anyway would make a peer's claim on
		// an unrelated protocol refuse this whole arm, when without that claim
		// the device would simply have been one excluded row.
		if dev.flowExporter != nil && dev.flowExporter.protocol == c.spec.Protocol {
			return &dev.flowExporter.scenPart
		}
		return nil
	}
	switch c.spec.Protocol {
	case "snmp-trap":
		if dev.trapExporter != nil {
			return &dev.trapExporter.scenPart
		}
	case "gnmi-dialout":
		if dev.gnmiDialoutExporter != nil {
			return &dev.gnmiDialoutExporter.scenPart
		}
	case "syslog":
		if dev.syslogExporter != nil {
			return &dev.syslogExporter.scenPart
		}
	}
	return nil
}

// installedSlot returns the slot where THIS scenario's handle could be sitting
// on dev, which is not the same question scenPartSlot answers.
//
// A device's flow exporter can change protocol after we armed it; the handle we
// installed is still in that slot and must stay releasable, or it leaks onto a
// live exporter where no detach path can ever reach it (the very failure
// TestScenarioArm_ReArmDetachesDroppedHandle exists for). Release is safe
// without the protocol match because it is ownership-checked: we only ever
// clear a handle that is ours.
func (c *ScenarioController) installedSlot(dev *DeviceSimulator) *atomic.Pointer[scenarioPart] {
	if isFlowScenarioProtocol(c.spec.Protocol) {
		if dev.flowExporter != nil {
			return &dev.flowExporter.scenPart
		}
		return nil
	}
	return c.scenPartSlot(dev)
}

// claimOwner reports the scenario currently holding dev for this scenario's
// protocol ("" = free or no exporter). Caller holds sm.mu (read).
func (c *ScenarioController) claimOwner(dev *DeviceSimulator) string {
	slot := c.scenPartSlot(dev)
	if slot == nil {
		return ""
	}
	if cur := slot.Load(); cur != nil {
		return cur.owner
	}
	return ""
}

// startScenarioFlowTicker drives participant flow emission at the scenario
// cadence during [T0,T1) (D1 flow-cadence adaptation). It marks each
// participant scenDriven so the fleet ticker yields, then ticks each exporter
// at spec.interval() until ctx is cancelled at finalize.
//
// Sets c.flowTickerDone, which finalize JOINS: cancelling this goroutine is not
// the same as it having stopped, and flow was the only one of the four emission
// architectures without that join (syslog #415, trap #409). Callers hold c.mu.
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
	done := make(chan struct{})
	c.flowTickerDone = done
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := c.now()
				for _, fe := range feList {
					// Re-checked per participant, not just per tick: at fleet
					// scale one pass is not instant, and finalize now blocks on
					// this goroutine WHILE HOLDING c.mu, so a cancelled pass
					// that ran to the end would extend every stop — and every
					// concurrent Phase/Result/LiveCounts read — by up to a full
					// pass of UDP writes. Load-bearing, not an optimisation.
					if ctx.Err() != nil {
						return
					}
					c.sm.tickFlowExporter(fe, now)
				}
			}
		}
	}()
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
// Participant uniqueness within each selector is guaranteed upstream:
// Scenario.Validate rejects a duplicated list and redundant prefixes. The one
// cross-selector overlap Validate permits — an explicit entry covered by a
// prefix (the D3 assertion) — is deduplicated where the prefix matches are
// collected (prefixMatchesLocked skips explicit strings), so the install loops
// still never see the same IP twice.
func (c *ScenarioController) Arm() (int, []excludedParticipant, error) {
	rd, err := c.ArmReadiness()
	return rd.Armed, rd.Excluded, err
}

// armReadiness is everything a caller needs to describe one arm, captured under
// a SINGLE hold of c.mu.
//
// That single hold is the whole point. armed→armed is legal re-entry, so a
// concurrent arm can complete between any two lock acquisitions — and every
// field here is reset and rebuilt by it. Reading the rows in one acquisition and
// the totals in another spliced two arms together: 1000 rows with a total of 0,
// or a truncation flag that contradicts the row count. Both violate the contract
// the report schema tells consumers to rely on, and the same
// two-acquisition shape is what stranded a scheduled start two changes ago.
type armReadiness struct {
	// Phase is the lifecycle phase AT THE SNAPSHOT — definitionally armed after a
	// successful arm. The handler must not re-read ctrl.Phase() afterwards: that
	// is a second lock acquisition, and a start (scheduled or concurrent) landing
	// between the two would splice "phase: running" onto this arm's numbers.
	Phase             scenarioPhase
	Armed             int
	Excluded          []excludedParticipant
	ExcludedTotal     int
	ExcludedByReason  map[string]int
	ScheduleCancelled bool
	// Expected is the declared expect_participants (0 when undeclared), and
	// Mismatch the rendered diagnosis (empty when met or undeclared). Both are
	// computed inside the same lock hold as Armed and ExcludedTotal — deriving
	// them in the handler would read c.spec across a second acquisition and
	// could splice one arm's count onto another's expectation.
	Expected int
	Mismatch string
}

// ArmReadiness arms and returns a self-consistent snapshot. Prefer it over Arm()
// whenever more than the armed count is needed — notably in the REST handler,
// which would otherwise have to make three separate reads (rows, totals, and the
// schedule state before/after).
func (c *ScenarioController) ArmReadiness() (armReadiness, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hadSchedule := !c.scheduledAt.IsZero()

	// Membership snapshot under the manager lock keeps arm TOCTOU-safe
	// against concurrent device CRUD (architecture D6). We only READ the
	// device set here; freeze happens at Start.
	c.sm.mu.RLock()

	// Resolved-union ceiling — a COUNT-ONLY pass that must precede EVERY
	// mutation this method makes, transitionLocked INCLUDED (design D5). That
	// call is itself a state change: it sets c.phase and appends to the
	// transition log the status endpoint publishes, so refusing after it would
	// park a first arm in `armed` with zero parts — the next start would then
	// report "0/N armed" instead of "arm first", and the 409 body would read
	// "cannot arm ... in phase armed". Re-arm hides this (armed→armed returns
	// early without mutating), which is why the order, not the re-arm test, is
	// what carries the guarantee. Ordering here also protects the re-arm
	// obligations below: the schedule withdrawal and the prevParts/prevLedgers
	// swap. A refused arm leaves the scenario exactly as it was. The count and
	// the install below share one RLock hold, so they cannot disagree.
	//
	// Skipped when no prefix matched: Validate already bounds len(Participants)
	// by this same constant, so an explicit-only union can never exceed it, and
	// counting explicit hits costs a map lookup per participant (up to the 100k
	// ceiling) while the manager lock is held.
	prefixMatches := c.prefixMatchesLocked()
	if len(prefixMatches) > 0 {
		explicitHits := 0
		for _, ip := range c.spec.Participants {
			if c.sm.devicesByIP[ip] != nil {
				explicitHits++
			}
		}
		if resolved := explicitHits + len(prefixMatches); resolved > scenarioMaxParticipants {
			c.sm.mu.RUnlock()
			return armReadiness{}, fmt.Errorf(
				"selectors resolve to %d live devices, exceeding the %d participant cap; shrink the selector or the fleet and re-arm",
				resolved, scenarioMaxParticipants)
		}
	}

	// Per-device overlap (FR38): refuse the whole arm when any candidate is
	// already claimed. Like the ceiling above, this runs before every mutation,
	// which is what makes "the holding scenario is unaffected, and so is our own
	// previous arm" true by construction rather than by unwinding — nothing has
	// been claimed, transitioned, or swapped yet.
	//
	// Overlap is a property of the REQUEST, not of one participant, which is
	// what distinguishes it from the per-device exclusions below: a device
	// missing an exporter is that device's problem, whereas colliding with a
	// live scenario means this scenario, as declared, cannot run. That is the
	// same reasoning that makes the resolved-set ceiling a wholesale refusal.
	//
	// The CAS in claim() is still the real arbiter. This check cannot be atomic
	// with the install — ArmReadiness holds c.mu, and submitScenario/
	// deleteScenario take scenarioMu BEFORE c.mu, so taking scenarioMu here
	// would invert the lock order. A concurrent arm that claims a device in the
	// window between this check and the install therefore wins, and that single
	// device degrades to an excluded row instead of being silently stolen.
	if conflicts := c.conflictingClaimsLocked(prefixMatches); len(conflicts) > 0 {
		c.sm.mu.RUnlock()
		return armReadiness{}, conflicts.err(c.id)
	}

	if err := c.transitionLocked(phaseArmed); err != nil {
		c.sm.mu.RUnlock()
		return armReadiness{}, err
	}

	// A pending scheduled start was authorised against the membership the PREVIOUS
	// arm resolved. Re-resolving membership withdraws that authorisation: the set
	// may now differ, or be empty, and either silently starting at T0 against a
	// set the operator never approved or firing a Start that cannot succeed is
	// worse than requiring the schedule to be re-issued. Cancelling here is also
	// what keeps `scheduled_start` in the status truthful.
	// Bumping the generation is what actually withdraws the authorisation:
	// Stop() cannot help if the timer already fired and is blocked on c.mu, and
	// this runs under that same lock, so a fire is either fully before us (phase
	// is running → our transitionLocked above already failed) or fully after us
	// (its generation is stale → it no-ops).
	if c.startTimer != nil {
		c.startTimer.Stop()
		c.startTimer = nil
		c.scheduledAt = time.Time{}
		c.scheduleGen++
		log.Printf("[scenario] scenario=%s re-armed; pending scheduled start cancelled (reschedule after checking readiness)", c.id)
	}

	// Keep the previous arm's view to carry ledgers forward (obligation 2) and to
	// detach whatever does not survive this pass (obligation 1).
	prevParts, prevLedgers := c.parts, c.ledgers
	c.excluded = nil
	c.excludedByReason = nil
	// Fresh slice/maps, never truncate-in-place: a previously returned excluded
	// slice must not be mutated under a caller still serving it.
	c.parts = make(map[string]*scenarioPart)
	c.ledgers = make(map[string]*ledgerEntry)

	gs := &gateState{phase: phaseArmed}
	c.gate.Store(gs)
	for _, ip := range c.spec.Participants {
		dev := c.sm.devicesByIP[ip]
		if dev == nil {
			c.recordExcluded(ip, "device not found",
				"create the device before arming, or remove it from the scenario",
				scenarioExcludedArmRows)
			continue
		}
		led := prevLedgers[ip] // nil on a first arm
		if led == nil {
			led = &ledgerEntry{}
		}
		part := &scenarioPart{gate: &c.gate, ledger: led, drain: &c.drain, now: c.now, owner: c.id}
		if ok, reason, hint := c.installScenPart(dev, part); !ok {
			c.recordExcluded(ip, reason, hint, scenarioExcludedArmRows)
			continue
		}
		c.parts[ip] = part
		c.ledgers[ip] = led
	}
	// Prefix-matched devices install through the same path. The slice is
	// IP-sorted (D4) so the install order — and with it the composition of the
	// row-capped excluded[] sample — is identical across arms against an
	// identical fleet; map iteration order must not leak into the readiness
	// response. Matches exclude explicit entries by construction (a covered
	// explicit entry resolved via the explicit loop above — the loud-miss side
	// of the cross-world assertion semantics), so nothing installs twice.
	for _, ip := range prefixMatches {
		dev := c.sm.devicesByIP[ip]
		if dev == nil {
			continue // unreachable: collected under this same RLock
		}
		led := prevLedgers[ip]
		if led == nil {
			led = &ledgerEntry{}
		}
		part := &scenarioPart{gate: &c.gate, ledger: led, drain: &c.drain, now: c.now, owner: c.id}
		if ok, reason, hint := c.installScenPart(dev, part); !ok {
			c.recordExcluded(ip, reason, hint, scenarioExcludedArmRows)
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
	armed := len(c.parts)
	excludedTotal := sumReasonCounts(c.excludedByReason)
	expected := 0
	if c.spec.ExpectParticipants != nil {
		expected = *c.spec.ExpectParticipants
	}
	return armReadiness{
		Phase:    c.phase,
		Armed:    armed,
		Expected: expected,
		// Every arm recomputes this, which is the whole of "re-arm re-evaluates
		// the expectation" — there is no re-arm-specific path to get wrong.
		Mismatch:      expectationDiagnosis(c.spec.ExpectParticipants, armed, excludedTotal),
		Excluded:      c.excluded,
		ExcludedTotal: excludedTotal,
		// Cloned: handing the controller's own map to a caller would let a later
		// arm mutate it mid-response. Both publication paths (this and finish)
		// clone, so neither depends on the accident that no current phase
		// transition lets recordExcluded run after the handover.
		ExcludedByReason: maps.Clone(c.excludedByReason),
		// A pending schedule that is gone after the withdrawal above.
		ScheduleCancelled: hadSchedule && c.scheduledAt.IsZero(),
	}, nil
}

// prefixMatchesLocked resolves participants_cidr against the live fleet:
// every devicesByIP key inside any prefix that is not also an explicit
// participant (a covered explicit entry resolves via the explicit path — the
// loud-miss side of the D3 assertion semantics). Caller holds c.sm.mu (read).
// The result is sorted in address order so callers install deterministically.
func (c *ScenarioController) prefixMatchesLocked() []string {
	if len(c.spec.ParticipantsCIDR) == 0 {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(c.spec.ParticipantsCIDR))
	for _, raw := range c.spec.ParticipantsCIDR {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue // unreachable: Validate guarantees parseability
		}
		prefixes = append(prefixes, p)
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	explicit := make(map[string]struct{}, len(c.spec.Participants))
	for _, ip := range c.spec.Participants {
		explicit[ip] = struct{}{}
	}
	var matches []string
	for ip := range c.sm.devicesByIP {
		if _, isExplicit := explicit[ip]; isExplicit {
			continue
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue // fleet keys are canonical dotted quads
		}
		// Validate rejected nested prefixes, so the set is pairwise disjoint
		// and sorted by base address: the rightmost base <= addr is the ONLY
		// prefix that can contain addr (a second candidate's base would fall
		// inside the first — a nesting). One binary search per device keeps
		// the pass at O(fleet × log prefixes).
		i, found := slices.BinarySearchFunc(prefixes, addr, func(p netip.Prefix, a netip.Addr) int {
			return p.Addr().Compare(a)
		})
		switch {
		case found: // addr IS a prefix base — that prefix contains it
			matches = append(matches, ip)
		case i > 0 && prefixes[i-1].Contains(addr):
			matches = append(matches, ip)
		}
	}
	// Address order, not lexical string order ("10.42.0.10" sorts before
	// "10.42.0.2" lexically) — the excluded[] rows are operator-facing.
	slices.SortFunc(matches, func(a, b string) int {
		aa, _ := netip.ParseAddr(a)
		bb, _ := netip.ParseAddr(b)
		return aa.Compare(bb)
	})
	return matches
}

// rollbackStartLocked undoes a start that got as far as the running transition
// but cannot proceed: unfreeze the fleet, restore the armed phase, and
// re-publish the armed gate so no participant sees a running window that will
// not happen. Caller holds c.mu.
//
// This necessarily runs AFTER gate.Store(running), so a flow exporter's own
// ticker can briefly observe a running gate for a run that then rolls back. The
// membership refusals no longer reach here — they were moved above the
// transition precisely to avoid that window — leaving only scheduler
// construction, which is validated at submit and therefore near-unreachable.
func (c *ScenarioController) rollbackStartLocked() {
	c.sm.unfreezeFleet(c.id)
	c.phase = phaseArmed
	c.gate.Store(&gateState{phase: phaseArmed})
}

// expectationDiagnosis renders a participant-count mismatch, or "" when the
// expectation is met or undeclared. ONE renderer for both the readiness
// disclosure and the start refusal, so an operator reads a single diagnosis
// rather than two phrasings of the same number.
//
// The shortfall branch is the reason the field exists: a shortfall with zero
// exclusions means nothing was rejected and the selectors simply matched fewer
// live devices than expected — the signature of a mis-sized prefix, which is
// otherwise invisible because prefix non-matches are not enumerable.
func expectationDiagnosis(expected *int, armed, excludedTotal int) string {
	if expected == nil || *expected == armed {
		return ""
	}
	want := *expected
	if armed > want {
		return fmt.Sprintf(
			"expected %d participants, %d armed: %d more than declared — the fleet holds devices the selectors match but the expectation does not account for",
			want, armed, armed-want)
	}
	if excludedTotal == 0 {
		return fmt.Sprintf(
			"expected %d participants, %d armed: %d missing and nothing was excluded — the selectors matched fewer live devices than expected (check prefix sizes in participants_cidr, and the fleet itself)",
			want, armed, want-armed)
	}
	return fmt.Sprintf(
		"expected %d participants, %d armed: %d missing, %d excluded — see excluded_by_reason for the causes",
		want, armed, want-armed, excludedTotal)
}

// Start freezes the fleet, publishes the running gate at T0, and starts the
// scenario-owned scheduler. Refused at 0/N armed (FR40).
func (c *ScenarioController) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.startLocked(ctx)
}

// startLocked is Start's body, callable with c.mu already held. The scheduled-
// start path needs that: it has to check whether its fire is still authorised
// AND run the start under a SINGLE lock acquisition, because a concurrent Arm
// can otherwise interleave between the two and change the membership the start
// then runs against (see startScheduled).
func (c *ScenarioController) startLocked(ctx context.Context) error {
	if c.phase != phaseArmed {
		return fmt.Errorf("%w: %s -> running (arm first)", errInvalidTransition, c.phase)
	}
	if len(c.parts) == 0 {
		return fmt.Errorf("cannot start scenario %s: 0/%s participants armed", c.id, c.spec.selectorSummary())
	}
	// Expectation check, pre-freeze twin of the post-prune one below. Both are
	// needed for the same reason FR40 needs both sites: this one refuses
	// cleanly (nothing frozen, no transition, no stamped T0, no rollback), and
	// the later one is authoritative against membership lost in the arm→start
	// gap. Failing here keeps the common case off the rollback path entirely.
	if diag := expectationDiagnosis(c.spec.ExpectParticipants, len(c.parts), sumReasonCounts(c.excludedByReason)); diag != "" {
		return fmt.Errorf("cannot start scenario %s: %s", c.id, diag)
	}
	if err := c.sm.freezeFleet(c.id); err != nil {
		return err // e.g. a creation batch is in flight
	}
	// Drop participants deleted in the Arm→Start gap (before the freeze) so the
	// ledger only reports devices that actually ran and the refusals below see
	// the true count. Protocol-agnostic: the presence check is per-protocol.
	//
	// This runs AFTER freezeFleet (membership must not move underneath it) but
	// BEFORE the running transition and the gate publication, so every refusal
	// it feeds is a plain unfreeze-and-return. Running it after gate.Store left
	// a window in which a flow exporter's own ticker could observe the running
	// gate and emit into a run that then rolled back; the prune reads only the
	// device map and per-protocol exporter fields, never the gate, so it has no
	// reason to be on that side of the transition. T0 is now also stamped after
	// the pruning work rather than before it, which is the more honest instant
	// for the window to begin.
	c.sm.mu.RLock()
	registered := 0
	for ip, part := range c.parts {
		dev := c.sm.devicesByIP[ip]
		if dev == nil {
			delete(c.parts, ip)
			delete(c.ledgers, ip)
			c.recordExcluded(ip, "device deleted between arm and start",
				"re-arm the scenario after the fleet is stable",
				scenarioMaxExcludedRows)
			continue
		}
		// RE-INSTALL rather than merely test for an exporter. Presence is a
		// weaker predicate than the one that armed the device, in two ways that
		// both inflate the count relative to what will actually emit:
		//
		//   - A device deleted and re-created at the same IP in the gap is a
		//     FRESH DeviceSimulator whose exporter carries no handle — arm
		//     stored that on the old object. Presence says yes; the device
		//     would run outside the scenario and never reach its ledger.
		//   - gnmi-dialout additionally requires a live Publish stream (FR16
		//     stream-arming proof). A collector that restarted since arm leaves
		//     the exporter non-nil and the stream dead.
		//
		// Re-installing settles both: it re-establishes the handle on whatever
		// object is live now, and it applies arm's exact admission rule, which
		// is what lets `registered` be called authoritative.
		if ok, reason, hint := c.installScenPart(dev, part); !ok {
			// Release any handle arm left on this still-live device before
			// dropping it from c.parts. Every other detach path iterates
			// c.parts, so a handle orphaned here is unreachable forever — and a
			// stale handle whose gate has reached a terminal phase mutes that
			// device's exporter for the rest of the process.
			c.detachScenPart(dev)
			delete(c.parts, ip)
			delete(c.ledgers, ip)
			c.recordExcluded(ip, reason, hint, scenarioMaxExcludedRows)
			continue
		}
		registered++
	}
	c.sm.mu.RUnlock()
	if registered == 0 {
		c.sm.unfreezeFleet(c.id)
		return fmt.Errorf("cannot start scenario %s: all armed participants were deleted before start", c.id)
	}
	// Authoritative expectation check: `registered` counts the devices that just
	// re-armed successfully, so this is the site that catches membership lost in
	// the arm→start gap — a wrong-sized run reached without any misdeclaration.
	// The exclusion total is re-read AFTER the prune so the diagnosis accounts
	// for the rows it just recorded.
	//
	// Only ever a SHORTFALL: the prune removes and never adds, so registered is
	// at most len(c.parts), which the pre-freeze check already matched against
	// the expectation. The surplus branch of the diagnosis is unreachable here.
	if diag := expectationDiagnosis(c.spec.ExpectParticipants, registered, sumReasonCounts(c.excludedByReason)); diag != "" {
		c.sm.unfreezeFleet(c.id)
		return fmt.Errorf("cannot start scenario %s: %s", c.id, diag)
	}

	if err := c.transitionLocked(phaseRunning); err != nil {
		c.sm.unfreezeFleet(c.id)
		return err
	}

	t0 := c.now()
	t1 := t0.Add(c.spec.Window)
	drainEnd := t1.Add(c.spec.drainOrDefault())
	c.gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1, drainEnd: drainEnd})

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
			c.rollbackStartLocked()
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
		return fmt.Errorf("cannot schedule scenario %s: 0/%s participants armed", c.id, c.spec.selectorSummary())
	}
	// The expectation is checked here for the same reason the zero-armed guard
	// above is: authorising a T0 against a set that already fails the declared
	// cardinality only defers the refusal to the moment the timer fires, hours
	// later, when the schedule is released and the run simply did not happen.
	// Membership can still change before T0 — start re-checks — but a set that
	// is wrong NOW is worth refusing now.
	if diag := expectationDiagnosis(c.spec.ExpectParticipants, len(c.parts), sumReasonCounts(c.excludedByReason)); diag != "" {
		return fmt.Errorf("cannot schedule scenario %s: %s", c.id, diag)
	}
	if c.startTimer != nil {
		return fmt.Errorf("scenario %s already has a scheduled start at %s", c.id, c.scheduledAt.Format(time.RFC3339))
	}
	c.scheduledAt = at
	c.scheduleGen++
	gen := c.scheduleGen
	// AfterFunc and c.now share the clock (both real, or both synctest-fake).
	c.startTimer = time.AfterFunc(at.Sub(c.now()), func() { c.startScheduled(ctx, gen) })
	log.Printf("[scenario] %s start scheduled for %s", c.id, at.Format(time.RFC3339))
	return nil
}

// startScheduled is the timer-driven Start, for the schedule identified by gen.
//
// Everything here happens under ONE acquisition of c.mu, which is the point. A
// timer that has already fired may sit blocked on the mutex for an unbounded
// time, so "decide, then start" across two acquisitions lets a concurrent Arm
// slip in between and leaves two ways to be wrong: the start runs against a
// membership the operator never approved (Arm believes it cancelled and says so),
// or the failure path blanks a schedule that a *newer* ScheduleStart has since
// installed — leaving a live timer with no `scheduled_start` in the status and
// room for a second one. The generation check is what makes a withdrawn
// authorisation stick, since timer.Stop() cannot report it once the timer fired.
//
// A scheduled start can also legitimately fail (every armed participant deleted
// before T0 → Start rolls back to `armed`). That error used to be discarded,
// which stranded the scenario: phase `armed`, a past `scheduled_start`, and
// ScheduleStart refusing a replacement forever. So log it and RELEASE the
// schedule, restoring the ability to reschedule.
func (c *ScenarioController) startScheduled(ctx context.Context, gen uint64) {
	c.mu.Lock()
	if gen != c.scheduleGen {
		// Superseded while this fire was in flight (a re-arm, a replacement
		// schedule, or teardown). Do nothing: not even the release, because the
		// state now belongs to whatever superseded us.
		c.mu.Unlock()
		log.Printf("[scenario] scenario=%s scheduled start superseded before it fired; ignoring", c.id)
		return
	}
	err := c.startLocked(ctx)
	if err != nil && gen == c.scheduleGen {
		c.startTimer = nil
		c.scheduledAt = time.Time{}
		c.scheduleGen++ // this schedule is spent
	}
	c.mu.Unlock()
	if err != nil {
		log.Printf("[scenario] scenario=%s scheduled start failed: %v; schedule released — re-arm and reschedule", c.id, err)
	}
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
	// Withdraw any pending scheduled start. Reachable on a healthy run: an
	// operator can schedule an absolute T0 and then start manually, and without
	// this the stale timer wakes up after the run has finished and logs a
	// spurious "scheduled start failed: invalid transition".
	if c.startTimer != nil {
		c.startTimer.Stop()
		c.startTimer = nil
		c.scheduledAt = time.Time{}
		c.scheduleGen++
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
	// snmp-trap scenarios: wait for the emission pool to drain its queued
	// tail (#409). Queued fires mutate ledger counters (suppressed/emitted)
	// even post-terminal-gate, so snapshotting before this join races them.
	// Bounded: the ticker exits on the schedCtx cancel above, its dispatch
	// select carries ctx.Done, and worker fires never block indefinitely.
	if c.trapTickerDone != nil {
		<-c.trapTickerDone
	}
	// flow scenarios: join the scenario-owned flow ticker. Cancelling it above
	// is not the same as it having stopped, and the difference is observable in
	// two ways. Today: a straggler tick at a terminal gate takes the suppress
	// branch, which still does ledger.backgroundSuppressed.Add — mutating a
	// counter after the drain barrier below has closed, the same race #409
	// fixed for traps, benign only because that counter sits outside the ledger
	// identity. And once a device may be claimed by a SUCCESSOR scenario
	// (per-device overlap), a straggler would load that successor's handle,
	// pass its gate, and be admitted to its drain as an indistinguishable
	// legitimate send — inflating identity terms in a report that has no way to
	// know. Joining here closes both by construction.
	//
	// This join runs under c.mu, so it extends the lock hold across whatever
	// fe.Tick is in flight — a UDP write that can park on a full socket buffer
	// — and Phase/LiveCounts/Result/ScheduledStart block behind it. The
	// per-participant ctx.Err() check in startScenarioFlowTicker is what bounds
	// that to ONE exporter instead of a fleet-sized pass, so it is load-bearing
	// for this reason and not merely a promptness optimisation: do not remove
	// it. (The trap join above has the same shape.)
	if c.flowTickerDone != nil {
		<-c.flowTickerDone
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

	c.sm.unfreezeFleet(c.id)

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
		Excluded: c.excluded, ExcludedTotal: sumReasonCounts(c.excludedByReason),
		ExcludedByReason: maps.Clone(c.excludedByReason),
		PerDevice:        perDevice, Apps: apps,
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
		c.startTimer = nil
		c.scheduledAt = time.Time{}
		c.scheduleGen++ // neutralise a fire that already got past Stop()
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

// claimConflict names one device already claimed by another scenario.
type claimConflict struct {
	device string
	holder string
}

// claimConflicts is the ordered set of overlaps found by the arm-time
// pre-check.
type claimConflicts []claimConflict

// scenarioConflictSample bounds how many contended devices an overlap refusal
// names. The message is an operator-facing string, and a whole-fleet collision
// would otherwise render tens of thousands of addresses into a 409 body — the
// same reasoning that caps the excluded[] rows.
const scenarioConflictSample = 5

// err renders the wholesale overlap refusal: how many devices collided, who
// holds them, and enough concrete addresses to act on.
func (cc claimConflicts) err(id string) error {
	holders := make([]string, 0, 2)
	seen := map[string]struct{}{}
	for _, c := range cc {
		if _, dup := seen[c.holder]; !dup {
			seen[c.holder] = struct{}{}
			holders = append(holders, c.holder)
		}
	}
	slices.Sort(holders)

	sample := make([]string, 0, scenarioConflictSample)
	for _, c := range cc {
		if len(sample) == scenarioConflictSample {
			break
		}
		sample = append(sample, c.device)
	}
	more := ""
	if len(cc) > len(sample) {
		more = fmt.Sprintf(" and %d more", len(cc)-len(sample))
	}
	return fmt.Errorf(
		"cannot arm scenario %s: %d participant(s) are claimed by scenario %s (%s%s); stop or delete it, or narrow this scenario's participants",
		id, len(cc), strings.Join(holders, ", "), strings.Join(sample, ", "), more)
}

// conflictingClaimsLocked reports which of this scenario's candidate
// participants are held by a DIFFERENT scenario. Devices this scenario already
// holds are not conflicts — that is a re-arm. Caller holds c.sm.mu (read).
//
// Returns conflicts in a deterministic order (explicit participants in declared
// order, then prefix matches, which prefixMatchesLocked already sorted by
// address), so the sampled addresses in the refusal do not vary run to run.
func (c *ScenarioController) conflictingClaimsLocked(prefixMatches []string) claimConflicts {
	var out claimConflicts
	check := func(ip string) {
		dev := c.sm.devicesByIP[ip]
		if dev == nil {
			return // resolves to nothing; an exclusion, not a conflict
		}
		if holder := c.claimOwner(dev); holder != "" && holder != c.id {
			out = append(out, claimConflict{device: ip, holder: holder})
		}
	}
	for _, ip := range c.spec.Participants {
		check(ip)
	}
	for _, ip := range prefixMatches {
		check(ip)
	}
	return out
}
