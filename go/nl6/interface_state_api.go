/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
)

// ErrIfStateDeviceNotFound is returned when the REST handler cannot
// resolve the {ip} path component to a known device.
var ErrIfStateDeviceNotFound = errors.New("device not found")

// ErrIfStateRevertCapExceeded is returned when a duration POST would
// push the device's pending-revert-timer count past
// `maxRevertTimersPerDevice`. The handler maps this to 429.
var ErrIfStateRevertCapExceeded = errors.New("auto-revert timer capacity exceeded for this device")

// maxRevertTimersPerDevice bounds the number of in-flight auto-revert
// goroutines a single device can have pending. Realistic test
// harness usage stays well under 10; the 100 ceiling is generous but
// caps a misbehaving client that POSTs duration=24h thousands of
// times.
const maxRevertTimersPerDevice = 100

// maxIfIndexREST caps the `ifIndex` path component accepted by the
// REST handlers. The state engine also bounds via `maxIfIndex`, but
// validating early avoids allocating the sorted "valid" list for
// obviously-bogus values like MaxInt.
const maxIfIndexREST = 65535

// ErrIfStateIfIndexInvalid is returned when the {ifIndex} path component
// is not present in the device's known interface set. The error carries
// the valid ifIndex list so the HTTP layer can include it in the body.
type ErrIfStateIfIndexInvalid struct {
	IfIndex int
	Valid   []int
}

func (e *ErrIfStateIfIndexInvalid) Error() string {
	return fmt.Sprintf("ifIndex %d not present on device", e.IfIndex)
}

// maxRevertAfter caps the auto-revert duration accepted by the REST
// handler. 24 h is the longest realistic test-harness scenario;
// values above this would let a misbehaving caller pin a goroutine
// for years.
const maxRevertAfter = 24 * time.Hour

// stateChangeRequest is the body shape for both POST handlers. The
// `Duration` field, when non-empty, schedules an auto-revert.
type stateChangeRequest struct {
	Status   string `json:"status"`
	Duration string `json:"duration,omitempty"`
}

// parseStateChangeRequest decodes and validates the body. Unknown JSON
// fields are rejected (typo'd `Durration` or `state` surface as 400).
// Returns the desired uint8 status value and an optional auto-revert
// duration (zero if none). The 4 KiB body cap is enforced via
// `MaxBytesReader(w, ...)` so over-limit requests can disable
// keep-alive on the response.
func parseStateChangeRequest(w http.ResponseWriter, r *http.Request, isOper bool) (uint8, time.Duration, error) {
	var req stateChangeRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var mbErr *http.MaxBytesError
		if errors.As(err, &mbErr) {
			return 0, 0, fmt.Errorf("payload too large (max 4 KiB)")
		}
		// Empty body and `{}` both indicate the operator forgot the
		// required `status` field; surface that rather than the raw
		// JSON parser error.
		if errors.Is(err, io.EOF) {
			return 0, 0, errors.New("status is required (\"UP\", \"DOWN\", or \"TESTING\")")
		}
		return 0, 0, fmt.Errorf("invalid JSON: %w", err)
	}
	// Reject bodies with trailing tokens (e.g. `{"status":"UP"} EXTRA`).
	if dec.More() {
		return 0, 0, errors.New("invalid JSON: trailing data after first object")
	}
	normalized := strings.ToUpper(strings.TrimSpace(req.Status))
	if normalized == "" {
		return 0, 0, errors.New("status is required (\"UP\", \"DOWN\", or \"TESTING\")")
	}
	var target uint8
	switch normalized {
	case "UP":
		if isOper {
			target = OperUp
		} else {
			target = AdminUp
		}
	case "DOWN":
		if isOper {
			target = OperDown
		} else {
			target = AdminDown
		}
	case "TESTING":
		if isOper {
			target = OperTesting
		} else {
			target = AdminTesting
		}
	default:
		return 0, 0, fmt.Errorf("invalid status %q (accepted: UP, DOWN, TESTING)", req.Status)
	}
	var revertAfter time.Duration
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid duration %q: %w", req.Duration, err)
		}
		if d <= 0 {
			return 0, 0, fmt.Errorf("duration must be positive, got %s", req.Duration)
		}
		if d > maxRevertAfter {
			return 0, 0, fmt.Errorf("duration %s exceeds maximum %s; auto-revert is bounded to prevent goroutine leaks", req.Duration, maxRevertAfter)
		}
		revertAfter = d
	}
	return target, revertAfter, nil
}

// revertKey identifies a pending auto-revert timer in
// `SimulatorManager.revertTimers`. Two duration POSTs on the same
// (ip, ifIndex, leaf) collide on the same key; the second cancels the
// first via Swap-and-Stop.
type revertKey struct {
	ip      string
	ifIndex int
	isOper  bool
}

// revertTimer wraps the cancellable timer for one pending auto-revert.
// `stop` is closed (idempotently via `closeOnce`) by `device.Stop()`,
// `manager.Shutdown()`, or a superseding duration POST. `done` is set
// by the goroutine right after winning the timer-vs-cancel select so
// that cancellers arriving in the cancel-after-fire window can detect
// the race and skip their own close, while the goroutine — if its CAS
// loses — bails before mutating a dead state.
// `finished` is closed as the LAST statement of the goroutine's defer
// (after the counter decrement and map self-removal), so awaiting it
// means the goroutine has fully exited on every path — cancelled,
// fired, CAS-loss bail, or panic-recovered (#417). Consumed by
// awaitAutoRevertsForDevice.
type revertTimer struct {
	timer     *time.Timer
	stop      chan struct{}
	closeOnce sync.Once
	done      atomic.Bool
	finished  chan struct{}
	deviceIP  string // for per-device cap decrement on goroutine exit
}

// closeStop is the only safe way to close rt.stop. Concurrent callers
// (device.Stop racing manager.Shutdown, or a second POST racing
// either) used to panic on double-close.
func (rt *revertTimer) closeStop() {
	rt.closeOnce.Do(func() { close(rt.stop) })
}

// mutateInterfaceState is the shared body of the oper-status / admin-status
// handlers. `isOper` selects the leaf; everything else (device lookup,
// ifIndex resolution, mutation, broadcast, auto-revert) is identical.
//
// Auto-revert semantics (post review): the goroutine SNAPSHOTS the
// pre-mutation slot value at POST time and reverts to that value
// after `revertAfter` elapses. This captures user intent precisely
// ("after the duration, put it back to whatever it was") and avoids
// the surprises that the original flip-to-opposite design had:
//   - POST DOWN duration=5s on already-DOWN slot now stays DOWN
//   - POST TESTING duration=30s reverts to the actual prior value
//   - A subsequent duration POST on the same leaf cancels the first
//     (registered in `sm.revertTimers` keyed by (ip, ifIndex, isOper))
//
// Lifetime: timers are tracked in `sm.revertTimers`; `device.Stop()`
// cancels per-device entries; `manager.Shutdown()` cancels all. The
// 24h max revertAfter (parseStateChangeRequest) bounds the worst case.
// On-demand HTTP fires bypass the flap scheduler's global cap, matching
// trap/syslog convention for test-harness use.
func (sm *SimulatorManager) mutateInterfaceState(ip string, ifIndex int, isOper bool, target uint8, revertAfter time.Duration) error {
	// Use the manager's IP-keyed device lookup (existing helper) rather
	// than a linear scan over `sm.devices`. At 30k devices the linear
	// scan was O(N) per request with a string allocation per entry.
	device := sm.FindDeviceByIP(ip)
	if device == nil {
		return ErrIfStateDeviceNotFound
	}
	sm.mu.RLock()
	mc := device.metricsCycler
	sm.mu.RUnlock()
	if mc == nil {
		return fmt.Errorf("device %s has no metrics cycler", ip)
	}
	ic := mc.ifCounters.Load()
	if ic == nil || ic.State() == nil {
		return fmt.Errorf("device %s has no interface state engine", ip)
	}
	state := ic.State()

	// Validate ifIndex against the known set. The state engine itself
	// would no-op on out-of-range slots, but a polite 400 with the
	// valid list is the contract.
	known := ic.IfIndices()
	if !containsInt(known, ifIndex) {
		valid := append([]int(nil), known...)
		sort.Ints(valid)
		return &ErrIfStateIfIndexInvalid{IfIndex: ifIndex, Valid: valid}
	}

	// Snapshot the pre-mutation tuple atomically. Using the
	// Snapshot API rather than two sequential accessor calls
	// prevents the flap scheduler from flipping the slot between
	// our reads.
	snap := state.Snapshot(ifIndex)
	var preSnap uint8
	if isOper {
		preSnap = snap.Oper
	} else {
		preSnap = snap.Admin
	}

	var (
		changed bool
		evt     StateChange
	)
	if isOper {
		changed, evt = state.SetOperStatus(ifIndex, target)
	} else {
		changed, evt = state.SetAdminStatus(ifIndex, target)
	}
	if changed {
		state.Broadcast(evt)
	}

	if revertAfter > 0 {
		if err := sm.scheduleAutoRevert(ip, ifIndex, isOper, preSnap, revertAfter, state); err != nil {
			return err
		}
	}
	return nil
}

// revertCounterFor returns the per-device atomic counter for in-flight
// auto-revert timers, creating it on first use. Counters live on
// `sm.revertTimerCounts` (sync.Map keyed by IP) so that scheduleAutoRevert
// can do a CAS-style cap check without holding any global lock.
func (sm *SimulatorManager) revertCounterFor(ip string) *atomic.Int64 {
	if v, ok := sm.revertTimerCounts.Load(ip); ok {
		return v.(*atomic.Int64)
	}
	c := new(atomic.Int64)
	actual, _ := sm.revertTimerCounts.LoadOrStore(ip, c)
	return actual.(*atomic.Int64)
}

// scheduleAutoRevert registers a new pending revert timer for the given
// (ip, ifIndex, leaf). If a previous timer is in flight for the same key,
// it is cancelled (Swap + closeStop) — the new POST supersedes it.
//
// Cancellation correctness (post review): three races used to be
// possible — (i) a second POST's `Swap+close` could not stop a
// goroutine already past its select; (ii) `device.Stop()` could not
// prevent a mid-fire mutation on a torn-down state engine; (iii)
// concurrent cancellers could double-close `rt.stop` and panic. The
// `done atomic.Bool` plus `closeOnce sync.Once` close all three
// windows: the goroutine CAS's `done` true the instant it picks the
// timer-fire branch — if a canceller has set `done` first the
// goroutine bails without mutating. Cancellers always go through
// `rt.closeStop()` which is idempotent.
//
// Per-device cap: `maxRevertTimersPerDevice` (100) limits how many
// in-flight goroutines a single device can register. Over-cap POSTs
// return `ErrIfStateRevertCapExceeded`, mapped to 429 at the handler.
func (sm *SimulatorManager) scheduleAutoRevert(ip string, ifIndex int, isOper bool, revertTo uint8, delay time.Duration, state *InterfaceState) error {
	counter := sm.revertCounterFor(ip)
	if counter.Add(1) > maxRevertTimersPerDevice {
		counter.Add(-1)
		return ErrIfStateRevertCapExceeded
	}

	key := revertKey{ip: ip, ifIndex: ifIndex, isOper: isOper}
	rt := &revertTimer{
		stop:     make(chan struct{}),
		timer:    time.NewTimer(delay),
		finished: make(chan struct{}),
		deviceIP: ip,
	}

	// Cancel any prior timer on the same key. Swap returns the previous
	// entry (or nil); closeStop is idempotent so multiple cancellers on
	// the same rt are safe.
	if prev, loaded := sm.revertTimers.Swap(key, rt); loaded {
		if old, ok := prev.(*revertTimer); ok {
			old.timer.Stop()
			old.closeStop()
		}
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("interface_state: auto-revert goroutine panic (recovered): %v (ip=%s ifIndex=%d)", r, ip, ifIndex)
			}
			counter.Add(-1)
			sm.revertTimers.CompareAndDelete(key, rt)
			// LAST: any state read this goroutine performed (notably the
			// global `manager` inside invalidateLLDPServedCache) precedes
			// this close in program order, so a waiter on `finished` — or
			// on the failed LoadAndDelete that the CompareAndDelete above
			// implies — is ordered after it (#417).
			close(rt.finished)
		}()
		select {
		case <-rt.stop:
			// Cancelled by device.Stop, manager.Shutdown, or a
			// subsequent duration POST. No mutation, no broadcast.
			rt.done.Store(true)
			return
		case <-rt.timer.C:
		}
		// CAS-style "this goroutine wins". If a canceller arrived in
		// the cancel-after-fire window and set `done` first, the
		// mutation is no longer authoritative — bail.
		if !rt.done.CompareAndSwap(false, true) {
			return
		}
		var c bool
		var e StateChange
		if isOper {
			c, e = state.SetOperStatus(ifIndex, revertTo)
		} else {
			c, e = state.SetAdminStatus(ifIndex, revertTo)
		}
		if c {
			state.Broadcast(e)
		}
	}()
	return nil
}

// cancelAutoRevertsForDevice cancels every pending auto-revert timer
// for the given device IP. Called from `device.Stop()` so a deleted
// device's pending timers don't fire on an orphaned state engine.
// Uses `rt.closeStop()` (idempotent) and `rt.done.CompareAndSwap` so
// that a goroutine already past its select either (a) sees the CAS
// loss and bails without mutating, or (b) ran to completion before
// cancel reached it and has already self-cleared from the map. The
// per-device counter is decremented by the goroutine on exit.
//
// Deliberately NON-BLOCKING: the fired path takes device.mu.RLock via
// the Broadcast notify hook, so awaiting exit here would be a deadlock
// shape for device teardown. A caller that needs "cancelled AND
// exited" (test teardown) uses awaitAutoRevertsForDevice instead.
func (sm *SimulatorManager) cancelAutoRevertsForDevice(ip string) {
	sm.revertTimers.Range(func(k, v any) bool {
		key, ok := k.(revertKey)
		if !ok || key.ip != ip {
			return true
		}
		if rt, ok := v.(*revertTimer); ok {
			rt.timer.Stop()
			// Pre-empt the goroutine's mutation; the goroutine's CAS
			// will then fail and skip SetOperStatus.
			rt.done.Store(true)
			rt.closeStop()
			// Use CompareAndDelete so a NEW timer that the goroutine's
			// defer hasn't yet self-cleared isn't accidentally removed
			// by this sweep.
			sm.revertTimers.CompareAndDelete(k, rt)
		}
		return true
	})
}

// awaitAutoRevertsForDevice cancels every pending auto-revert timer for
// the given device IP and BLOCKS until every goroutine it claimed has
// exited — "cancel means exited" (#417). For quiescent callers only
// (test teardown before restoring swapped process-global state): no
// concurrent scheduleAutoRevert for the same device may race the sweep.
// NOT for device.Stop() — see cancelAutoRevertsForDevice.
//
// The sweep CLAIMS entries with LoadAndDelete rather than reading them
// via Range: exactly one party — this drain or the goroutine's deferred
// CompareAndDelete — wins removal of each entry. If the drain wins it
// awaits that timer's `finished` (closed last in the goroutine's defer,
// so the wait means fully exited). If the goroutine won, the miss is
// itself the ordering proof: the goroutine's last shared read precedes
// its CompareAndDelete in program order, and sync.Map operations on the
// same entry give the drain's failed load a happens-before edge to it.
// Either way, everything the goroutine read is ordered before this
// function returns.
func (sm *SimulatorManager) awaitAutoRevertsForDevice(ip string) {
	var claimed []*revertTimer
	sm.revertTimers.Range(func(k, v any) bool {
		key, ok := k.(revertKey)
		if !ok || key.ip != ip {
			return true
		}
		prev, loaded := sm.revertTimers.LoadAndDelete(k)
		if !loaded {
			return true // goroutine self-removed; ordered by the miss
		}
		if rt, ok := prev.(*revertTimer); ok {
			rt.timer.Stop()
			// Pre-empt a not-yet-fired mutation, same as the cancel path.
			rt.done.Store(true)
			rt.closeStop()
			claimed = append(claimed, rt)
		}
		return true
	})
	for _, rt := range claimed {
		<-rt.finished
	}
}

// cancelAllAutoReverts cancels every pending timer. Called from
// `manager.Shutdown()`. Same correctness story as
// `cancelAutoRevertsForDevice`.
func (sm *SimulatorManager) cancelAllAutoReverts() {
	count := 0
	sm.revertTimers.Range(func(k, v any) bool {
		if rt, ok := v.(*revertTimer); ok {
			rt.timer.Stop()
			rt.done.Store(true)
			rt.closeStop()
			count++
			sm.revertTimers.CompareAndDelete(k, rt)
		}
		return true
	})
	if count > 0 {
		log.Printf("interface_state: cancelled %d pending auto-revert timers on shutdown", count)
	}
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// setOperStatusHandler implements POST /api/v1/devices/{ip}/interfaces/{ifIndex}/oper-status.
// Body: {"status":"UP"|"DOWN"|"TESTING", "duration":"<go-duration>"?}.
// Returns 202 Accepted with {} on success. 404 for unknown device,
// 400 for unknown ifIndex / malformed body / unsupported status,
// 503 if the state engine is not initialised for this device.
func setOperStatusHandler(w http.ResponseWriter, r *http.Request) {
	handleSetInterfaceStatus(w, r, true)
}

// setAdminStatusHandler implements POST /api/v1/devices/{ip}/interfaces/{ifIndex}/admin-status.
// Same shape and semantics as the oper-status handler; mutates admin-status.
func setAdminStatusHandler(w http.ResponseWriter, r *http.Request) {
	handleSetInterfaceStatus(w, r, false)
}

func handleSetInterfaceStatus(w http.ResponseWriter, r *http.Request, isOper bool) {
	vars := mux.Vars(r)
	ip := vars["ip"]
	ifIndex, err := strconv.Atoi(vars["ifIndex"])
	if err != nil || ifIndex <= 0 || ifIndex > maxIfIndexREST {
		sendErrorResponse(w, fmt.Sprintf("invalid ifIndex %q (must be in [1, %d])", vars["ifIndex"], maxIfIndexREST), http.StatusBadRequest)
		return
	}

	target, revertAfter, err := parseStateChangeRequest(w, r, isOper)
	if err != nil {
		// Distinguish payload-too-large (413) from generic 400.
		if strings.Contains(err.Error(), "payload too large") {
			sendErrorResponse(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := manager.mutateInterfaceState(ip, ifIndex, isOper, target, revertAfter); err != nil {
		var idxErr *ErrIfStateIfIndexInvalid
		switch {
		case errors.Is(err, ErrIfStateDeviceNotFound):
			sendErrorResponse(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrIfStateRevertCapExceeded):
			sendErrorResponse(w, err.Error(), http.StatusTooManyRequests)
		case errors.As(err, &idxErr):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":          idxErr.Error(),
				"validIfIndexes": idxErr.Valid,
			})
		default:
			sendErrorResponse(w, err.Error(), http.StatusServiceUnavailable)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("{}"))
}
