/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// IF-MIB enum values for ifOperStatus (RFC 2863). The state engine
// stores these directly so SNMP and gNMI handlers can read without a
// translation table. gNMI maps the int back to OpenConfig identityref
// strings (UP / DOWN / TESTING / UNKNOWN / DORMANT / NOT_PRESENT /
// LOWER_LAYER_DOWN) at encode time.
const (
	OperUp           uint8 = 1
	OperDown         uint8 = 2
	OperTesting      uint8 = 3
	OperUnknown      uint8 = 4
	OperDormant      uint8 = 5
	OperNotPresent   uint8 = 6
	OperLowerLayerDn uint8 = 7
)

// IF-MIB enum values for ifAdminStatus.
const (
	AdminUp      uint8 = 1
	AdminDown    uint8 = 2
	AdminTesting uint8 = 3
)

// LastChangeRewindSentinel is the value LastChangeNs returns when the
// wall clock has stepped backwards between engine construction and a
// mutation (NTP step, container suspend/resume). The sentinel is
// distinguishable from a legitimate "never transitioned" reading
// (which equals bootTimeUnixNs) and from any realistic future
// timestamp, so downstream consumers can flag clock-rewind events.
const LastChangeRewindSentinel uint64 = ^uint64(0)

// StateLeafBits is a bitset naming the leaves that changed in one
// mutation. last-change is implied whenever any other leaf changes —
// no dedicated bit. ON_CHANGE subscribers on `state/last-change`
// match any non-zero StateLeafBits value.
type StateLeafBits uint8

const (
	LeafOperStatus StateLeafBits = 1 << iota
	LeafAdminStatus
)

// StateChange is the event emitted on every successful mutator call.
// Carries the post-mutation slot values plus a bitset naming which
// leaves moved. One mutator call yields one StateChange — both the
// status leaf and `last-change` are folded into a single event.
type StateChange struct {
	IfIndex      int
	Oper         uint8         // current value after mutation
	Admin        uint8         // current value after mutation
	LastChangeNs uint64        // absolute Unix nanos
	Changed      StateLeafBits // which status leaves moved (last-change implied if non-zero)
	At           time.Time
}

// InterfaceState is the per-device interface state engine: oper-status,
// admin-status, and last-change per ifIndex. Reads are lock-free via
// atomic load on a packed uint64 slot table (§D1 of design.md). Writes
// CAS-loop on the same slot so concurrent mutators serialise without a
// mutex.
//
// Listener fan-out (§D3): ON_CHANGE subscribers register a chan
// StateChange via AddListener; mutators call Broadcast after a
// successful CAS; broadcast walks the listener map and pushes
// non-blocking with drop-oldest on per-channel overflow. Counters
// `eventsEmitted` / `eventsDropped` point at the SimulatorManager-owned
// aggregates exposed in /api/v1/gnmi/status. Stored as atomic.Pointer
// so SetCounters is race-free against in-flight Broadcasts.
//
// Slot layout (single atomic.Uint64 per slot, slot = ifIndex - 1):
//
//	bit 63 ──────────────────────── 0
//	┌─────────────────┬────┬────┐
//	│  lastChangeNs   │ AD │ OP │
//	└─────────────────┴────┴────┘
//	      58 bits      3 b  3 b
//
// 58 bits of nanoseconds-since-boot covers ~9.13 years; sufficient for
// any realistic simulator session. Single atomic word guarantees a
// reader never sees a torn (oper, admin, lastChange) tuple.
type InterfaceState struct {
	slots          []atomic.Uint64 // slot = ifIndex - 1; out-of-range ifIndexes return zero values
	maxIfIndex     int             // upper bound; slots has length maxIfIndex
	bootTimeUnixNs uint64          // captured at construction; used to derive wall-relative lastChange

	// now is the engine's clock, normalised to time.Now at construction so the
	// mutation path never branches on nil. Same shape as the four other clock
	// seams in this package (flap_scheduler, syslog_scheduler, trap_scheduler,
	// optical_alarm), deliberately: a fifth shape is one more thing to learn.
	//
	// It exists because lastChange is derived from the WALL clock: time.Now()'s
	// monotonic reading is stripped by UnixNano, and wallRelNs has a whole
	// rewind sentinel for the backwards step that follows. A test asserting
	// lastChange is non-decreasing was therefore asserting something the engine
	// does not promise, and could fail on any NTP step (nl6#575).
	//
	// It carries no synchronisation, so assign it only while no other goroutine
	// can reach the engine. Prefer newInterfaceStateWithClock; a test that
	// assigns the field afterwards must do so before starting any goroutine
	// that touches the engine, which is what gives the happens-before edge.
	//
	// THE CLOCK MUST RETURN A POSITIVE UnixNano. time.Now() always does; an
	// injected clock returning the zero Time or any pre-epoch instant yields a
	// negative count that wraps to an enormous bootTimeUnixNs, after which every
	// transition reads earlier than boot and reports a rewind forever.
	now func() time.Time

	// Listener channels for ON_CHANGE fan-out. Keys are `chan StateChange`,
	// values are unused (sync.Map used as a concurrent set).
	listeners sync.Map

	// Counter pointers owned by SimulatorManager. Stored atomically so a
	// concurrent SetCounters cannot race a Broadcast-side load.
	eventsEmitted atomic.Pointer[uint64]
	eventsDropped atomic.Pointer[uint64]

	// notify is the correlate-state-notifications (Tier C) hook: invoked
	// synchronously on every successful OPER-status transition (after the slot
	// store commits, alongside Broadcast) to fire correlated link traps/syslog
	// for the transitioned ifIndex. Stored as an atomic.Pointer because the
	// flap scheduler is registered BEFORE the trap/syslog exporters attach, so
	// the manager sets this after the engine is already live and mutating; a
	// transition before attach reads nil and is a safe no-op.
	notify atomic.Pointer[func(StateChange)]
}

// NewInterfaceState builds an engine for `maxIfIndex` interfaces. Slot
// indices are 1-based externally (matching ifIndex) and 0-based
// internally (slot = ifIndex - 1). Pass nil for counter pointers if the
// caller does not need aggregates (tests). Panics on `maxIfIndex < 1` —
// a zero-sized engine permanently no-ops every getter/setter and is
// always a caller bug.
func NewInterfaceState(maxIfIndex int, emitted, dropped *uint64) *InterfaceState {
	return newInterfaceStateWithClock(maxIfIndex, emitted, dropped, nil)
}

// newInterfaceStateWithClock is NewInterfaceState against an injectable clock;
// nil means time.Now and is what every production caller gets (nl6#575).
//
// The clock is taken HERE as well as at the setters, and that is the whole
// point rather than an incidental extra. bootTimeUnixNs is the origin every
// relative lastChange is measured from, so an engine whose boot time came from
// the real clock and whose transitions come from an injected one subtracts a
// real timestamp from a fake one: the result is a garbage 58-bit value, or a
// spurious rewind sentinel when the fake clock reads earlier.
func newInterfaceStateWithClock(maxIfIndex int, emitted, dropped *uint64, clock func() time.Time) *InterfaceState {
	if maxIfIndex < 1 {
		panic("newInterfaceStateWithClock: maxIfIndex must be ≥ 1")
	}
	if clock == nil {
		clock = time.Now
	}
	s := &InterfaceState{
		slots:      make([]atomic.Uint64, maxIfIndex),
		maxIfIndex: maxIfIndex,
		now:        clock,
	}
	s.bootTimeUnixNs = uint64(s.now().UnixNano())
	if emitted != nil {
		s.eventsEmitted.Store(emitted)
	}
	if dropped != nil {
		s.eventsDropped.Store(dropped)
	}
	return s
}

// Seed initialises a slot with the given LINK state and admin-status and
// lastChangeNs=0. The observable oper-status follows from deriveOper, so a
// seed of (link=up, admin=down) reads as oper down while preserving that the
// cable is good — which is what makes "unshut the port and see it come back"
// work under `-if-scenario 1`.
//
// Rejects out-of-range enum values (0 or > OperLowerLayerDn for link, 0 or >
// AdminTesting for admin) — the JSON-validation layer in
// `InitIfCountersWithScenario` already filters these, so Seed's rejection
// is defense-in-depth. Reader-safe via atomic.Store; callers must still
// ensure publication ordering before exposing the engine to consumers.
//
// A seed is NOT a transition: it stamps lastChangeNs = 0 and broadcasts
// nothing, so a fleet does not report a transition per interface at boot and
// fires no Tier C link telemetry for state that never changed.
func (s *InterfaceState) Seed(ifIndex int, link, admin uint8) {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		log.Printf("interface_state: Seed rejected: ifIndex %d out of range [1..%d]", ifIndex, s.maxIfIndex)
		return
	}
	if link < OperUp || link > OperLowerLayerDn {
		log.Printf("interface_state: Seed rejected: ifIndex %d link=%d outside IF-MIB range [%d..%d]", ifIndex, link, OperUp, OperLowerLayerDn)
		return
	}
	if admin < AdminUp || admin > AdminTesting {
		log.Printf("interface_state: Seed rejected: ifIndex %d admin=%d outside IF-MIB range [%d..%d]", ifIndex, admin, AdminUp, AdminTesting)
		return
	}
	s.slots[slot].Store(packState(link, admin, 0))
}

// StateSnapshot is the atomic (oper, admin, lastChange) tuple
// returned by `Snapshot`. All three fields reflect the same
// `slots[slot].Load()` so they cannot tear relative to each other —
// unlike sequential calls to OperStatus / AdminStatus / LastChangeNs.
// `Found` distinguishes an out-of-range or unseeded slot from a real
// one; consumers wanting "real interface vs ghost" should branch on
// it rather than inferring from defaulted enum values.
type StateSnapshot struct {
	// Oper is DERIVED from Admin and Link (see deriveOper). It is not stored.
	Oper uint8
	// Link is the stored physical-layer reading. Callers that must restore or
	// compare what was actually stored — notably the REST oper-status
	// auto-revert — MUST use this, never Oper: reverting to a derived value
	// writes the mask into the link and destroys the pre-mutation state.
	Link         uint8
	Admin        uint8
	LastChangeNs uint64
	Found        bool
}

// Snapshot atomically reads the (oper, admin, lastChange) tuple for
// ifIndex from a single `slots[slot].Load()`. Returns
// `(StateSnapshot{}, false)` for out-of-range ifIndex. For an
// in-range but unseeded slot, returns `(StateSnapshot{Oper:
// OperUnknown, Admin: AdminUp, LastChangeNs: bootTimeUnixNs, Found:
// true})` — same defaults as the individual accessors. Callers that
// need a consistent point-in-time view (e.g. auto-revert pre-state
// capture, gNMI ON_CHANGE initial snapshot, cross-leaf consistency
// tests) MUST use this rather than three separate accessor calls.
func (s *InterfaceState) Snapshot(ifIndex int) StateSnapshot {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return StateSnapshot{}
	}
	link, admin, rel := unpackState(s.slots[slot].Load())
	link, admin = normaliseSlot(link, admin)
	var lc uint64
	if rel == lastChangeMask {
		lc = LastChangeRewindSentinel
	} else {
		lc = s.bootTimeUnixNs + rel
	}
	return StateSnapshot{
		Oper:         deriveOper(admin, link),
		Link:         link,
		Admin:        admin,
		LastChangeNs: lc,
		Found:        true,
	}
}

// LinkState returns the stored physical-layer reading for ifIndex, which is
// what the flap scheduler and the REST oper-status endpoint mutate. Returns
// OperUnknown for an out-of-range or unseeded slot, matching OperStatus.
//
// This is NOT what SNMP, gNMI or REST report: they report OperStatus, which
// masks the link under admin-down. A caller wanting the observable value wants
// OperStatus.
func (s *InterfaceState) LinkState(ifIndex int) uint8 {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return OperUnknown
	}
	link, _, _ := unpackState(s.slots[slot].Load())
	if link == 0 {
		return OperUnknown
	}
	return link
}

// OperStatus returns the current oper-status enum value for ifIndex — DERIVED
// from the stored (admin, link) pair per deriveOper, never stored. Returns
// OperUnknown if ifIndex is out of range or the slot is uninitialised. Single
// atomic load, no allocation, exactly as before the derivation landed. For
// consistent multi-leaf reads see `Snapshot`.
func (s *InterfaceState) OperStatus(ifIndex int) uint8 {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return OperUnknown
	}
	link, admin, _ := unpackState(s.slots[slot].Load())
	link, admin = normaliseSlot(link, admin)
	return deriveOper(admin, link)
}

// AdminStatus returns the current admin-status enum value for ifIndex.
// Returns AdminUp for out-of-range ifIndex OR uninitialised slot —
// asymmetric vs OperStatus's OperUnknown sentinel because IF-MIB has no
// `adminUnknown` enum value. Callers needing to distinguish "unseeded"
// from "explicitly AdminUp" should consult IfIndices() upstream.
func (s *InterfaceState) AdminStatus(ifIndex int) uint8 {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return AdminUp
	}
	_, admin, _ := unpackState(s.slots[slot].Load())
	if admin == 0 {
		return AdminUp
	}
	return admin
}

// LastChangeNs returns the absolute Unix nanosecond timestamp of the
// most recent transition on ifIndex (oper or admin). Returns the
// engine's boot time (`s.bootTimeUnixNs`, captured at
// `NewInterfaceState` — *not* the device's real boot time per RFC
// 2863) if no transition has occurred. Returns 0 if ifIndex is out
// of range. Returns LastChangeRewindSentinel if a transition
// occurred while the wall clock was earlier than the engine boot
// time (NTP step, container suspend/resume) — downstream consumers
// should treat the sentinel as "transition happened but timestamp
// is unreliable". The SNMP layer (`if_counters.go`) collapses both
// `bootTimeUnixNs` (no-transition) and the rewind sentinel to
// `"0"` on the wire; gNMI subscribers see the engine values
// directly.
func (s *InterfaceState) LastChangeNs(ifIndex int) uint64 {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return 0
	}
	_, _, rel := unpackState(s.slots[slot].Load())
	if rel == lastChangeMask {
		// In-band sentinel: the mutator stored the max 58-bit value to
		// flag a clock-rewind event. Surface as the public sentinel.
		return LastChangeRewindSentinel
	}
	return s.bootTimeUnixNs + rel
}

// LinkMutation is the outcome of a SetLinkState call. Three outcomes, because
// the `bool` this replaced conflated two of them: the flap scheduler could not
// tell "the slot was already at the target" from "the move is masked by
// admin-down", so its no-op log line named both possibilities and its comment
// claimed a suppression that did not exist anywhere in the code (nl6#694).
type LinkMutation uint8

const (
	// LinkUnchanged: nothing was stored. Out-of-range ifIndex, out-of-range
	// enum, or the link was already at the requested value.
	LinkUnchanged LinkMutation = iota
	// LinkMovedMasked: the link value WAS stored, but the derived oper-status
	// did not move because admin is down(2) or testing(3). No lastChange
	// stamp, no event, no notify hook — the device is masking a real change,
	// exactly as hardware does. Not an anomaly and not worth a log line: at
	// `-if-flap-scenario aggressive` on a shut fleet that is one line per fire
	// per interface.
	LinkMovedMasked
	// LinkMovedVisible: the link value was stored and the derived oper-status
	// moved. lastChange is stamped and the returned StateChange must be
	// broadcast by the caller.
	LinkMovedVisible
)

// SetLinkState atomically updates the LINK state on ifIndex — the
// physical-layer reading, not the observable oper-status, which is derived.
//
// This replaced SetOperStatus in nl6#694. A caller wanting "make this interface
// go down" still calls this; what changed is that the effect is masked while
// admin is down(2) or testing(3), and the outcome says so rather than the
// caller having to re-read admin (a second read, at a different instant, whose
// verdict could disagree with what was stored).
//
// On LinkMovedVisible the caller is responsible for calling Broadcast(evt).
//
// `s.now()` and `wallRelNs` are sampled INSIDE the CAS loop so that
// retries on contention record the timestamp of the winning CAS, not
// the timestamp at function entry — this preserves the monotonic
// ordering of LastChangeNs across concurrent transitions on the same
// ifIndex.
//
// The clock is `s.now()` rather than `time.Now()` directly since nl6#575,
// and the placement above is unchanged by that: the seam exposes WHICH clock is
// read, never WHERE it is read. Moving the sample out of the loop would be a
// behaviour change wearing a refactor's clothes.
func (s *InterfaceState) SetLinkState(ifIndex int, newLink uint8) (LinkMutation, StateChange) {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return LinkUnchanged, StateChange{}
	}
	if newLink < OperUp || newLink > OperLowerLayerDn {
		return LinkUnchanged, StateChange{}
	}
	for {
		cur := s.slots[slot].Load()
		curLink, curAdmin, curRel := unpackState(cur)
		curLink, curAdmin = normaliseSlot(curLink, curAdmin)
		if curLink == newLink {
			return LinkUnchanged, StateChange{}
		}

		// The transition that matters is the DERIVED one. RFC 2863 defines
		// ifLastChange as the time the interface entered its current
		// OPERATIONAL state, so a link flap on a shut port must not stamp it.
		wasOper := deriveOper(curAdmin, curLink)
		nowOper := deriveOper(curAdmin, newLink)
		if wasOper == nowOper {
			// Masked: store the link, carry lastChange forward untouched.
			if s.slots[slot].CompareAndSwap(cur, packState(newLink, curAdmin, curRel)) {
				return LinkMovedMasked, StateChange{}
			}
			continue
		}

		nowAbs := s.now()
		relNs := wallRelNs(uint64(nowAbs.UnixNano()), s.bootTimeUnixNs)
		if s.slots[slot].CompareAndSwap(cur, packState(newLink, curAdmin, relNs)) {
			// An oper transition changes which lldpRemTable rows are live on
			// both ends of the link, so invalidate cached LLDP served-OID
			// sets. Only a VISIBLE transition can move a row — a masked flap
			// changes no LLDP row, so invalidating on it would be pure cost at
			// fleet scale.
			invalidateLLDPServedCache()
			return LinkMovedVisible, StateChange{
				IfIndex:      ifIndex,
				Oper:         nowOper,
				Admin:        curAdmin,
				LastChangeNs: lastChangeAbs(s.bootTimeUnixNs, relNs),
				Changed:      LeafOperStatus,
				At:           nowAbs,
			}
		}
	}
}

// setAdminLeaf atomically updates admin-status on ifIndex and reports the
// events the single CAS implies: the admin leaf whenever it moved, and the
// derived oper-status whenever the move changed it.
//
// UNEXPORTED DELIBERATELY. ApplyAdminStatus is the funnel, and the funnel's
// whole value is that SNMP SET, the REST POST and the auto-revert are
// indistinguishable to every observer. An exported second door let a caller
// move admin without that guarantee; before nl6#684 exactly that happened and
// an admin-down over REST fired no link trap.
//
// ONE CAS, not two. With oper derived there is nothing to store for it, and a
// second CAS would open a window in which a concurrent link mutation is
// attributed to the admin change.
func (s *InterfaceState) setAdminLeaf(ifIndex int, newVal uint8) []StateChange {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return nil
	}
	if newVal < AdminUp || newVal > AdminTesting {
		return nil
	}
	for {
		cur := s.slots[slot].Load()
		curLink, curAdmin, curRel := unpackState(cur)
		curLink, curAdmin = normaliseSlot(curLink, curAdmin)
		if curAdmin == newVal {
			return nil
		}

		wasOper := deriveOper(curAdmin, curLink)
		nowOper := deriveOper(newVal, curLink)
		operMoved := wasOper != nowOper

		// lastChange keys on the DERIVED transition, so an admin change that
		// leaves the operational state where it was (admin up -> down over an
		// already-down link) does not stamp it.
		relNs, nowAbs := curRel, s.now()
		if operMoved {
			relNs = wallRelNs(uint64(nowAbs.UnixNano()), s.bootTimeUnixNs)
		}
		if !s.slots[slot].CompareAndSwap(cur, packState(curLink, newVal, relNs)) {
			continue
		}

		evts := []StateChange{{
			IfIndex:      ifIndex,
			Oper:         nowOper,
			Admin:        newVal,
			LastChangeNs: lastChangeAbs(s.bootTimeUnixNs, relNs),
			Changed:      LeafAdminStatus,
			At:           nowAbs,
		}}
		if operMoved {
			invalidateLLDPServedCache()
			evts = append(evts, StateChange{
				IfIndex:      ifIndex,
				Oper:         nowOper,
				Admin:        newVal,
				LastChangeNs: lastChangeAbs(s.bootTimeUnixNs, relNs),
				Changed:      LeafOperStatus,
				At:           nowAbs,
			})
		}
		return evts
	}
}

// deriveOper is THE rule, and the only place it is written. Every accessor
// routes through it; no read site computes oper-status by other means.
//
// RFC 2863's ifOperStatus DESCRIPTION, from the extract checked in at
// testdata/rfc/rfc2863-if-status-objects.txt rather than recalled:
//
//	"If ifAdminStatus is down(2) then ifOperStatus should be down(2).  If
//	 ifAdminStatus is changed to up(1) then ifOperStatus should change to
//	 up(1) if the interface is ready to transmit and receive network
//	 traffic; [...] it should remain in the down(2) state if and only if
//	 there is a fault that prevents it from going to the up(1) state"
//
// THE RULE IS ASYMMETRIC AND THE ASYMMETRY IS THE WHOLE MODEL. admin-down
// FORCES oper-down. admin-up FORCES NOTHING: it releases oper to the physical
// layer, which may still be faulted. The predecessor of this function
// (adminCascadeOper, nl6#684) was a total function of admin alone — it modelled
// the first half and inverted the second, which is why an admin bounce used to
// repair a simulated cable pull (nl6#694).
//
// testing(3) is forced likewise: the MIB defines it as "no operational packets
// can be passed", which is a property of the device's intent, not the cable.
//
// `link` carries the physical-layer reading and may be any ifOperStatus enum
// value; the engine never assigns lowerLayerDown(7) itself (deriving it from
// the LLDP peer graph is deliberately out of scope), but it stores and derives
// it through unchanged if something else sets it.
func deriveOper(admin, link uint8) uint8 {
	switch admin {
	case AdminDown:
		return OperDown
	case AdminTesting:
		return OperTesting
	}
	return link
}

// ApplyAdminStatus is THE funnel for every source that changes admin-status:
// the REST admin-status POST, its auto-revert, and SNMP SET (add-snmp-set). It
// returns the StateChange for each leaf that moved, admin first.
//
// The caller broadcasts the returned events (the mutators never do, by the
// engine's existing design), so an ON_CHANGE listener sees admin then oper and
// the Tier C notify hook fires once, on the oper event, exactly as it does for
// the flap scheduler.
//
// IT NO LONGER CASCADES, and that is the point of nl6#694. It writes the admin
// leaf; oper follows by derivation, asymmetrically (see deriveOper). Three
// observable consequences, each of which a reviewer should look for:
//
//   - admin up(1) over a DOWN link returns ONE event, for the admin leaf. It
//     does not raise oper, so an admin bounce no longer repairs a simulated
//     cable pull. This is the defect nl6#694 was filed on.
//   - admin down(2) over an already-down link likewise returns ONE event, and
//     does NOT stamp ifLastChange: the operational state did not change, and
//     RFC 2863 defines that leaf as the time the interface entered its current
//     operational state.
//   - the predecessor applied the cascade EVEN WHEN admin was already at
//     target, to put back an oper the flap scheduler had raised on a shut
//     port. That repair is now structural — the flap scheduler mutates the
//     link, and admin-down masks it — so there is nothing to put back.
//
// An out-of-range ifIndex or a target outside AdminUp..AdminTesting returns
// nil, matching the mutators' zero return.
func (s *InterfaceState) ApplyAdminStatus(ifIndex int, target uint8) []StateChange {
	return s.setAdminLeaf(ifIndex, target)
}

// AddListener registers a channel for state-change events. The channel
// should be buffered (depth onChangeBufferDepth = 16 per §D8); unbuffered
// channels will hit the drop-oldest slow path on every event and lose
// data statistically.
//
// **API protocol:** callers MUST call RemoveListener before closing the
// channel; the Broadcast loop uses non-blocking sends that will panic
// on send-to-closed-channel. Broadcast does have a defer-recover for
// defense-in-depth, but relying on it is a bug.
//
// **Snapshot caveat:** AddListener does NOT emit a current-state
// snapshot. Subscribers that need the current value at registration
// time must call OperStatus/AdminStatus/LastChangeNs separately —
// ideally before AddListener so they observe a consistent prefix. The
// ON_CHANGE Subscribe handler in `gnmi_subscribe_onchange.go` does
// exactly this via `resolver.Resolve` before its AddListener call.
func (s *InterfaceState) AddListener(ch chan StateChange) {
	if ch == nil {
		log.Printf("interface_state: AddListener rejected: nil channel")
		return
	}
	if cap(ch) == 0 {
		log.Printf("interface_state: AddListener rejected: unbuffered channel (every event would hit drop-oldest slow path)")
		return
	}
	s.listeners.Store(ch, struct{}{})
}

// RemoveListener deregisters a channel. Safe to call from any
// goroutine. Idempotent for unknown channels.
func (s *InterfaceState) RemoveListener(ch chan StateChange) {
	s.listeners.Delete(ch)
}

// SetCounters wires the per-engine atomic counter pointers to the
// simulator-wide aggregates. Called by SimulatorManager once per
// device construction; safe to call multiple times at runtime — the
// pointer field is `atomic.Pointer[uint64]` so the swap is race-free
// against in-flight Broadcasts. Nil pointers disable per-event
// accounting (used by tests).
func (s *InterfaceState) SetCounters(emitted, dropped *uint64) {
	s.eventsEmitted.Store(emitted)
	s.eventsDropped.Store(dropped)
}

// SetNotify wires (fn != nil) or clears (fn == nil) the Tier C state-change
// hook invoked on oper transitions by Broadcast. Stored atomically: the manager
// sets it at trap/syslog attach time (after the flap scheduler is already
// registered) and clears it on teardown before the exporters close. Safe to
// call while the engine is live and mutating.
func (s *InterfaceState) SetNotify(fn func(StateChange)) {
	if fn == nil {
		s.notify.Store(nil)
		return
	}
	s.notify.Store(&fn)
}

// Broadcast fans evt out to every registered listener with non-blocking
// drop-oldest semantics. Increments eventsEmitted per successful send,
// eventsDropped per drop.
//
// **Multi-producer notes:** concurrent Broadcast calls on the same
// listener channel can interleave the drain/retry sequences. Drop
// accounting is therefore *approximate under contention* — it remains
// correct to within ±1 per contended event, intended for trend analysis
// rather than exact accounting. Realistic contention requires two
// mutation sources (REST + flap scheduler) racing on the same device's
// state engine within microseconds; rare in practice.
//
// **Subscriber protocol violation:** Each per-listener send is wrapped
// in its own defer-recover so that a misbehaving consumer who closes
// its channel without calling RemoveListener first cannot abort the
// Range walk. The recover logs the panic and continues to the next
// listener — i.e. one bad subscriber never silences the rest. Callers
// that repeatedly trigger this should be audited.
func (s *InterfaceState) Broadcast(evt StateChange) {
	// An event naming no leaf describes nothing, and the zero StateChange
	// carries IfIndex 0 — a gNMI subscriber handed one would encode an update
	// for an interface that does not exist. The mutators return it on every
	// non-transition, including the LinkMovedMasked outcome, so a caller that
	// broadcasts unconditionally is a mistake this must absorb rather than
	// propagate. Production callers already gate on the outcome; this makes
	// the gate an invariant of the API instead of a convention.
	if evt.Changed == 0 {
		return
	}
	s.listeners.Range(func(key, _ any) bool {
		ch, ok := key.(chan StateChange)
		if !ok {
			return true
		}
		// Per-listener recover so one panicking subscriber does not
		// abort the Range walk for every other subscriber.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("interface_state: Broadcast panic recovered for listener: %v (likely send-to-closed-channel; subscriber must RemoveListener before closing)", r)
			}
		}()
		// Fast path: non-blocking send.
		select {
		case ch <- evt:
			s.incEmitted()
			return true
		default:
		}
		// Slow path: drop oldest, then retry once. If retry still
		// fails (another producer raced us), count as drop and move
		// on — we never block the mutator.
		select {
		case <-ch:
			s.incDropped()
		default:
		}
		select {
		case ch <- evt:
			s.incEmitted()
		default:
			s.incDropped()
		}
		return true
	})

	// Tier C (correlate-state-notifications): after the gNMI listener fan-out,
	// fire correlated link telemetry for OPER transitions. Gated on
	// LeafOperStatus so admin-only changes never fire link traps/syslog. The
	// hook is nil until the manager wires it at exporter-attach time.
	if evt.Changed&LeafOperStatus != 0 {
		if fn := s.notify.Load(); fn != nil {
			(*fn)(evt)
		}
	}
}

func (s *InterfaceState) incEmitted() {
	if p := s.eventsEmitted.Load(); p != nil {
		atomic.AddUint64(p, 1)
	}
}

func (s *InterfaceState) incDropped() {
	if p := s.eventsDropped.Load(); p != nil {
		atomic.AddUint64(p, 1)
	}
}

// Packing internals.
//
// Slot layout (LSB-first):
//
//	[0..2]  link state    (3 bits, max 7 — the IF-MIB ifOperStatus enum, 1..7)
//	[3..5]  admin-status  (3 bits, max 7 — only 1..3 used by IF-MIB)
//	[6..63] lastChangeNs  (58 bits, max ~9.13 years)
//
// The low three bits held oper-status until nl6#694. They hold the LINK state
// now and oper-status is derived (see deriveOper) — same three bits, same word,
// same single-Load read, layout guard untouched. Adding a fourth field would
// have cost lastChange 3 of its 58 bits (~9.13 years down to ~1.14) AND created
// a second source of truth for a value that is a pure function of the other
// two, which is the bug class nl6#694 exists to remove.
const (
	_linkWidth   = 3
	_adminWidth  = 3
	_lastChWidth = 58

	adminStatusShift = _linkWidth
	lastChangeShift  = _linkWidth + _adminWidth

	// Masks derived from widths so any change to a width
	// automatically resizes the corresponding mask — fixes the
	// previous independent-constant drift hazard surfaced in chunk A
	// review.
	linkStateMask   uint64 = (1 << _linkWidth) - 1
	adminStatusMask uint64 = (1 << _adminWidth) - 1
	lastChangeMask  uint64 = (1 << _lastChWidth) - 1

	// _layoutGuard is a compile-time guard that the three field
	// widths fit in a uint64 with the documented packing
	// (linkWidth + adminWidth + lastChWidth == 64). If any width
	// changes without rebalancing the others, the array index goes
	// negative and the package fails to compile.
	_layoutGuard = 64 - _linkWidth - _adminWidth - _lastChWidth
)

var _ = [1]struct{}{}[_layoutGuard] // compile error if layout invariant breaks

// wallRelNs returns (nowWallNs - bootWallNs) masked to 58 bits, or the
// in-band rewind sentinel (`lastChangeMask` — all 58 low bits set) if
// the wall clock has stepped backwards between bootWallNs and nowWallNs.
// The sentinel is unpacked by LastChangeNs as LastChangeRewindSentinel
// so observers can detect clock-rewind events. A log line fires once
// per rewind so operators are aware (clock-rewinds usually indicate
// container suspend/resume, NTP step, or host clock skew).
func wallRelNs(nowWallNs, bootWallNs uint64) uint64 {
	if nowWallNs < bootWallNs {
		log.Printf("interface_state: wall clock stepped backwards (now=%d boot=%d); ifLastChange marked with rewind sentinel for this transition", nowWallNs, bootWallNs)
		return lastChangeMask
	}
	// Equal is fine — happens on coarse-clock platforms (macOS µs grain)
	// when bootTimeUnixNs and the mutation timestamp fall in the same
	// tick. relNs = 0 then renders as "interface has been in current
	// state since boot" which is semantically correct.
	return (nowWallNs - bootWallNs) & lastChangeMask
}

// lastChangeAbs reconstructs the absolute Unix-nanosecond timestamp
// from a stored relNs, with the rewind sentinel pass-through. Used by
// SetLinkState/setAdminLeaf to populate StateChange.LastChangeNs.
func lastChangeAbs(bootTimeUnixNs, relNs uint64) uint64 {
	if relNs == lastChangeMask {
		return LastChangeRewindSentinel
	}
	return bootTimeUnixNs + relNs
}

func packState(link, admin uint8, lastChangeNs uint64) uint64 {
	return uint64(link)&linkStateMask |
		(uint64(admin)&adminStatusMask)<<adminStatusShift |
		((lastChangeNs & lastChangeMask) << lastChangeShift)
}

func unpackState(w uint64) (link, admin uint8, lastChangeNs uint64) {
	link = uint8(w & linkStateMask)
	admin = uint8((w >> adminStatusShift) & adminStatusMask)
	lastChangeNs = (w >> lastChangeShift) & lastChangeMask
	return
}

// normaliseSlot applies the defaults an unseeded slot reads as, so every
// accessor and every mutator agrees on what a zero word means. Extracted
// because three call sites open-coded it and a fourth (the derivation) would
// have made a divergence invisible.
func normaliseSlot(link, admin uint8) (uint8, uint8) {
	if link == 0 {
		link = OperUnknown
	}
	if admin == 0 {
		admin = AdminUp
	}
	return link, admin
}
