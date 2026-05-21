/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// ErrIfStateDeviceNotFound is returned when the REST handler cannot
// resolve the {ip} path component to a known device.
var ErrIfStateDeviceNotFound = errors.New("device not found")

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
		return 0, 0, fmt.Errorf("invalid JSON: %w", err)
	}
	if req.Status == "" {
		return 0, 0, errors.New("status is required (\"UP\", \"DOWN\", or \"TESTING\")")
	}
	var target uint8
	switch strings.ToUpper(strings.TrimSpace(req.Status)) {
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
// `stop` is closed by `device.Stop()` / `manager.Shutdown()` to cancel
// the goroutine without firing the revert.
type revertTimer struct {
	timer *time.Timer
	stop  chan struct{}
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

	// Snapshot the pre-mutation value BEFORE the SetOperStatus call so
	// auto-revert can restore it accurately. We grab both fields so a
	// future "POST admin-status" doesn't lose a prior oper-status
	// snapshot — the snapshot is leaf-specific.
	var preSnap uint8
	if isOper {
		preSnap = state.OperStatus(ifIndex)
	} else {
		preSnap = state.AdminStatus(ifIndex)
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
		sm.scheduleAutoRevert(ip, ifIndex, isOper, preSnap, revertAfter, state)
	}
	return nil
}

// scheduleAutoRevert registers a new pending revert timer for the given
// (ip, ifIndex, leaf). If a previous timer is in flight for the same key,
// it is cancelled (Swap + Stop + signal) — the new POST supersedes it.
func (sm *SimulatorManager) scheduleAutoRevert(ip string, ifIndex int, isOper bool, revertTo uint8, delay time.Duration, state *InterfaceState) {
	key := revertKey{ip: ip, ifIndex: ifIndex, isOper: isOper}
	rt := &revertTimer{
		stop: make(chan struct{}),
	}
	rt.timer = time.NewTimer(delay)

	// Cancel any prior timer on the same key. LoadAndStore returns the
	// previous value (or nil); if non-nil, stop it cleanly.
	if prev, loaded := sm.revertTimers.Swap(key, rt); loaded {
		if old, ok := prev.(*revertTimer); ok {
			old.timer.Stop()
			close(old.stop)
		}
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("interface_state: auto-revert goroutine panic (recovered): %v (ip=%s ifIndex=%d)", r, ip, ifIndex)
			}
			sm.revertTimers.CompareAndDelete(key, rt)
		}()
		select {
		case <-rt.stop:
			// Cancelled by device.Stop, manager.Shutdown, or a subsequent
			// duration POST. No mutation, no broadcast.
			return
		case <-rt.timer.C:
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
}

// cancelAutoRevertsForDevice cancels every pending auto-revert timer
// for the given device IP. Called from `device.Stop()` so a deleted
// device's pending timers don't fire on an orphaned state engine.
func (sm *SimulatorManager) cancelAutoRevertsForDevice(ip string) {
	ipStr := ip
	sm.revertTimers.Range(func(k, v any) bool {
		if key, ok := k.(revertKey); ok && key.ip == ipStr {
			if rt, ok := v.(*revertTimer); ok {
				rt.timer.Stop()
				select {
				case <-rt.stop:
				default:
					close(rt.stop)
				}
			}
			sm.revertTimers.Delete(k)
		}
		return true
	})
}

// cancelAllAutoReverts cancels every pending timer. Called from
// `manager.Shutdown()`.
func (sm *SimulatorManager) cancelAllAutoReverts() {
	count := 0
	sm.revertTimers.Range(func(k, v any) bool {
		if rt, ok := v.(*revertTimer); ok {
			rt.timer.Stop()
			select {
			case <-rt.stop:
			default:
				close(rt.stop)
			}
			count++
		}
		sm.revertTimers.Delete(k)
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
	if err != nil || ifIndex <= 0 {
		sendErrorResponse(w, fmt.Sprintf("invalid ifIndex %q", vars["ifIndex"]), http.StatusBadRequest)
		return
	}

	target, revertAfter, err := parseStateChangeRequest(w, r, isOper)
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := manager.mutateInterfaceState(ip, ifIndex, isOper, target, revertAfter); err != nil {
		var idxErr *ErrIfStateIfIndexInvalid
		switch {
		case errors.Is(err, ErrIfStateDeviceNotFound):
			sendErrorResponse(w, err.Error(), http.StatusNotFound)
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
