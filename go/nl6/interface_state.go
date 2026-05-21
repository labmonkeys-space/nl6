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

	// Listener channels for ON_CHANGE fan-out. Keys are `chan StateChange`,
	// values are unused (sync.Map used as a concurrent set).
	listeners sync.Map

	// Counter pointers owned by SimulatorManager. Stored atomically so a
	// concurrent SetCounters cannot race a Broadcast-side load.
	eventsEmitted atomic.Pointer[uint64]
	eventsDropped atomic.Pointer[uint64]
}

// NewInterfaceState builds an engine for `maxIfIndex` interfaces. Slot
// indices are 1-based externally (matching ifIndex) and 0-based
// internally (slot = ifIndex - 1). Pass nil for counter pointers if the
// caller does not need aggregates (tests). Panics on `maxIfIndex < 1` —
// a zero-sized engine permanently no-ops every getter/setter and is
// always a caller bug.
func NewInterfaceState(maxIfIndex int, emitted, dropped *uint64) *InterfaceState {
	if maxIfIndex < 1 {
		panic("NewInterfaceState: maxIfIndex must be ≥ 1")
	}
	s := &InterfaceState{
		slots:          make([]atomic.Uint64, maxIfIndex),
		maxIfIndex:     maxIfIndex,
		bootTimeUnixNs: uint64(time.Now().UnixNano()),
	}
	if emitted != nil {
		s.eventsEmitted.Store(emitted)
	}
	if dropped != nil {
		s.eventsDropped.Store(dropped)
	}
	return s
}

// Seed initialises a slot with the given oper/admin status and
// lastChangeNs=0. Rejects out-of-range enum values (0 or > OperLowerLayerDn
// for oper, 0 or > AdminTesting for admin) — the JSON-validation layer in
// `InitIfCountersWithScenario` already filters these, so Seed's rejection
// is defense-in-depth. Reader-safe via atomic.Store; callers must still
// ensure publication ordering before exposing the engine to consumers.
func (s *InterfaceState) Seed(ifIndex int, oper, admin uint8) {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return
	}
	if oper < OperUp || oper > OperLowerLayerDn {
		return
	}
	if admin < AdminUp || admin > AdminTesting {
		return
	}
	s.slots[slot].Store(packState(oper, admin, 0))
}

// OperStatus returns the current oper-status enum value for ifIndex.
// Returns OperUnknown if ifIndex is out of range or the slot is
// uninitialised. Single atomic load, no allocation.
func (s *InterfaceState) OperStatus(ifIndex int) uint8 {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return OperUnknown
	}
	oper, _, _ := unpackState(s.slots[slot].Load())
	if oper == 0 {
		return OperUnknown
	}
	return oper
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
// device boot time if no transition has occurred. Returns 0 if
// ifIndex is out of range. Returns LastChangeRewindSentinel if a
// transition occurred while the wall clock was earlier than the engine
// boot time (NTP step, container suspend/resume) — downstream
// consumers should treat the sentinel as "transition happened but
// timestamp is unreliable".
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

// SetOperStatus atomically updates oper-status on ifIndex. Returns
// (false, zero) on three distinct conditions:
//  1. `ifIndex` is out of range
//  2. `newVal` is not a valid IF-MIB ifOperStatus enum (1..7)
//  3. `newVal` is identical to the current value (idempotent no-op)
//
// Callers that need to distinguish these conditions must validate the
// inputs upstream — today both production callers (REST handler and
// flap scheduler) do exactly that. On a real transition, updates
// lastChangeNs to "now relative to bootTime" and returns (true, evt).
// The caller is responsible for calling Broadcast(evt) to fan the event
// out to listeners.
//
// `time.Now()` and `wallRelNs` are sampled INSIDE the CAS loop so that
// retries on contention record the timestamp of the winning CAS, not
// the timestamp at function entry — this preserves the monotonic
// ordering of LastChangeNs across concurrent transitions on the same
// ifIndex.
func (s *InterfaceState) SetOperStatus(ifIndex int, newVal uint8) (bool, StateChange) {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return false, StateChange{}
	}
	if newVal < OperUp || newVal > OperLowerLayerDn {
		return false, StateChange{}
	}
	for {
		cur := s.slots[slot].Load()
		curOper, curAdmin, _ := unpackState(cur)
		if curOper == newVal {
			return false, StateChange{}
		}
		nowAbs := time.Now()
		relNs := wallRelNs(uint64(nowAbs.UnixNano()), s.bootTimeUnixNs)
		next := packState(newVal, curAdmin, relNs)
		if s.slots[slot].CompareAndSwap(cur, next) {
			return true, StateChange{
				IfIndex:      ifIndex,
				Oper:         newVal,
				Admin:        curAdmin,
				LastChangeNs: lastChangeAbs(s.bootTimeUnixNs, relNs),
				Changed:      LeafOperStatus,
				At:           nowAbs,
			}
		}
	}
}

// SetAdminStatus atomically updates admin-status on ifIndex. Same
// semantics as SetOperStatus, including the three-condition `(false,
// zero)` return and the inside-the-loop timestamp sampling.
func (s *InterfaceState) SetAdminStatus(ifIndex int, newVal uint8) (bool, StateChange) {
	slot := ifIndex - 1
	if slot < 0 || slot >= s.maxIfIndex {
		return false, StateChange{}
	}
	if newVal < AdminUp || newVal > AdminTesting {
		return false, StateChange{}
	}
	for {
		cur := s.slots[slot].Load()
		curOper, curAdmin, _ := unpackState(cur)
		if curAdmin == newVal {
			return false, StateChange{}
		}
		nowAbs := time.Now()
		relNs := wallRelNs(uint64(nowAbs.UnixNano()), s.bootTimeUnixNs)
		next := packState(curOper, newVal, relNs)
		if s.slots[slot].CompareAndSwap(cur, next) {
			return true, StateChange{
				IfIndex:      ifIndex,
				Oper:         curOper,
				Admin:        newVal,
				LastChangeNs: lastChangeAbs(s.bootTimeUnixNs, relNs),
				Changed:      LeafAdminStatus,
				At:           nowAbs,
			}
		}
	}
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
// **Subscriber protocol violation:** Broadcast contains a defer-recover
// so that a misbehaving consumer who closes its channel without calling
// RemoveListener first cannot crash the mutator goroutine. The recover
// path logs the panic and continues to the next listener. Callers that
// repeatedly trigger this should be audited.
func (s *InterfaceState) Broadcast(evt StateChange) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("interface_state: Broadcast panic recovered: %v (likely send-to-closed-channel; subscriber must RemoveListener before closing)", r)
		}
	}()
	s.listeners.Range(func(key, _ any) bool {
		ch, ok := key.(chan StateChange)
		if !ok {
			return true
		}
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
//	[0..2]  oper-status   (3 bits, max 7 — covers IF-MIB ifOperStatus 1..7)
//	[3..5]  admin-status  (3 bits, max 7 — only 1..3 used by IF-MIB)
//	[6..63] lastChangeNs  (58 bits, max ~9.13 years)
const (
	operStatusMask   uint64 = 0x7
	adminStatusMask  uint64 = 0x7 // duplicate of operStatusMask today; defined separately so a future width-change to one field doesn't silently widen the other
	adminStatusShift        = 3
	lastChangeShift         = 6
	lastChangeMask   uint64 = 0x03FFFFFFFFFFFFFF // 58 bits

	// _fieldLayoutCheck is a compile-time guard that the three field
	// shifts/widths remain consistent. If any change breaks
	// `operWidth + adminWidth == lastChangeShift`, the array index
	// goes negative and the package fails to compile.
	_operWidth   = 3
	_adminWidth  = 3
	_layoutGuard = lastChangeShift - _operWidth - _adminWidth
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
// SetOperStatus/SetAdminStatus to populate StateChange.LastChangeNs.
func lastChangeAbs(bootTimeUnixNs, relNs uint64) uint64 {
	if relNs == lastChangeMask {
		return LastChangeRewindSentinel
	}
	return bootTimeUnixNs + relNs
}

func packState(oper, admin uint8, lastChangeNs uint64) uint64 {
	return uint64(oper)&operStatusMask |
		(uint64(admin)&adminStatusMask)<<adminStatusShift |
		((lastChangeNs & lastChangeMask) << lastChangeShift)
}

func unpackState(w uint64) (oper, admin uint8, lastChangeNs uint64) {
	oper = uint8(w & operStatusMask)
	admin = uint8((w >> adminStatusShift) & adminStatusMask)
	lastChangeNs = (w >> lastChangeShift) & lastChangeMask
	return
}
