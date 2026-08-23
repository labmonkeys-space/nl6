/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// fidelity_api.go — runtime control of fidelity mode.
//
// `-fidelity` silences the fleet so an operator gets a clean measurement
// window, and it works exactly as documented. It was also startup-only:
// `fidelitySilent.Store` ran once and never again. Bracketing a measurement is
// a runtime activity, so applying it meant restarting, which destroys every
// REST-created device and the measurement setup with them.
//
// Two properties make the runtime toggle cheap rather than delicate, and
// neither is accidental:
//
//   - `fidelitySilent` is ALREADY an atomic.Bool, read concurrently by every
//     exporter goroutine on every fire. It was built for concurrent access and
//     merely happened to be written once, so a handler calling Store adds no
//     synchronisation, no lock ordering, and no plumbing.
//
//   - the mute lives in each exporter's non-participant branch, so flipping it
//     mid-run changes background emission only. A running scenario's gate,
//     ledger and wire-exactness are untouched by construction: a toggle cannot
//     corrupt a measurement in progress.
//
// THE TRAP THIS FILE HAS TO AVOID. Once the value is mutable, `-fidelity` is a
// DEFAULT rather than a fact, and any surface still reporting the flag is
// reporting something that may no longer be true. That is precisely the defect
// class of nl6#445 (a per-device interval accepted, echoed, and ignored), and
// reintroducing it in a change that exists to be honest would be a poor
// outcome. So GET reports both the value in force and the startup flag, and
// their disagreement is the disclosure.

// fidelityStartupFlag records what -fidelity was set to at process start.
// Written once during flag parsing, read by the status handler. Kept separate
// from fidelitySilent so the two can diverge and be reported as diverging.
var fidelityStartupFlag atomic.Bool

// fidelityTransitions counts every committed change to the value in force,
// including auto-reverts. A scenario samples it at T0 and again at finalize;
// a non-zero delta means the fleet's silence changed DURING the measurement
// window, which the report must disclose because the run did not measure what
// its operator believes it measured.
var fidelityTransitions atomic.Uint64

// fidelityRevert guards the single pending auto-revert timer.
//
// One timer, not a map: fidelity is a simulator-wide switch, so there is
// exactly one thing to revert. A later timed request supersedes an earlier one
// rather than stacking, matching the interface-state convention where a second
// duration POST on the same leaf cancels the first.
var fidelityRevert struct {
	mu    sync.Mutex
	timer *time.Timer
	// restore is the value to return to when the pending timer fires. It is
	// the state from BEFORE the current chain of timed toggles began, not the
	// value in force when the latest one arrived.
	//
	// Capturing the current value on every request looks right and is wrong:
	// two chained timed toggles would make the second capture what the first
	// had just set, so the revert restores the TEMPORARY state and the fleet
	// stays silent for good. That is a stuck-silent fleet from two ordinary
	// requests, and it is exactly what an operator shortening a window would
	// do.
	restore bool
	// deadline is when the pending timer fires, so GET can report it. Zero
	// when nothing is armed.
	deadline time.Time
	// gen invalidates a callback that has already fired and is blocked on the
	// mutex. time.Timer.Stop() CANNOT recall such a callback, so it has to
	// recognise itself as superseded: without this, a revert whose deadline
	// elapsed while an operator was POSTing a standing toggle would acquire
	// the lock second and overwrite the operator's change with its own stale
	// captured value. The operator sees 200, and the fleet quietly does the
	// opposite of what they asked.
	gen uint64
}

// FidelityRequest is the body of POST /api/v1/fidelity.
type FidelityRequest struct {
	// Silent is a POINTER so an omitted key is distinguishable from `false`.
	// As a bare bool, `{"duration":"30m"}` — the natural shorthand for "keep
	// it as it is for another 30 minutes" — decoded to Silent=false and
	// un-muted the whole fleet immediately, returning 200. Every other field
	// here was defended; the one deciding the fleet's behaviour was not.
	Silent *bool `json:"silent"`
	// Duration, when set, restores the pre-chain value after it elapses.
	// Capped at maxRevertAfter, shared with the interface-state and optical
	// revert paths. The cap is about bounding how long a single request can
	// commit the fleet, NOT about goroutine leaks: there is one timer here,
	// superseded on every request, and time.AfterFunc occupies no goroutine
	// until it fires. That rationale was copied from interface-state, where
	// many per-leaf timers genuinely can accumulate.
	Duration string `json:"duration,omitempty"`
}

// FidelityStatus is the body of GET /api/v1/fidelity.
//
// InForce and StartupFlag are reported separately on purpose. Once fidelity is
// runtime-mutable the flag is a default, and a surface that reports only the
// flag would assert something the engine may have stopped honouring.
type FidelityStatus struct {
	InForce     bool `json:"silent"`
	StartupFlag bool `json:"startup_flag"`
	// RevertPending is true while a timed toggle is waiting to restore the
	// previous value, so an operator can tell a standing change from a
	// temporary one without waiting to find out.
	RevertPending bool `json:"revert_pending"`
	// RevertAt is when the pending revert fires, omitted when none is armed.
	RevertAt string `json:"revert_at,omitempty"`
	// RevertTo is the value the pending revert will restore. It is NOT the
	// negation of the value in force — chain semantics make it the value from
	// before the current chain began — so an operator cannot infer it and has
	// to be told. Omitted when nothing is armed.
	RevertTo *bool `json:"revert_to,omitempty"`
}

// cancelFidelityRevertLocked stops any pending revert. Caller holds the mutex.
func cancelFidelityRevertLocked() {
	if fidelityRevert.timer != nil {
		fidelityRevert.timer.Stop()
		fidelityRevert.timer = nil
	}
	fidelityRevert.deadline = time.Time{}
	// Bump unconditionally: Stop() returning false means the callback already
	// fired and may be waiting on this mutex right now, and this is the only
	// thing that will stop it acting.
	fidelityRevert.gen++
}

// cancelFidelityRevert stops any pending revert, for shutdown.
func cancelFidelityRevert() {
	fidelityRevert.mu.Lock()
	defer fidelityRevert.mu.Unlock()
	cancelFidelityRevertLocked()
}

// fidelitySnapshot is the state as it was when a request committed, captured
// under the lock. Handlers must build responses from this rather than
// re-reading the globals: a concurrent toggle between the two reads produces a
// composite describing a state the engine was never in, such as
// `{"silent":false,"revert_pending":true}` for a timer that has been cancelled.
type fidelitySnapshot struct {
	inForce  bool
	pending  bool
	deadline time.Time
	revertTo bool
}

// setFidelity applies a value and, when d > 0, arms a revert. Returns the state
// as committed, under the lock.
func setFidelity(silent bool, d time.Duration) fidelitySnapshot {
	fidelityRevert.mu.Lock()
	defer fidelityRevert.mu.Unlock()

	// Supersede rather than stack: an earlier timer would otherwise fire later
	// and revert to a value two requests stale.
	hadPending := fidelityRevert.timer != nil
	cancelFidelityRevertLocked()

	// Preserve the chain's original restore target ONLY while the chain keeps
	// going the same way. cancelFidelityRevertLocked above cleared the timer
	// but deliberately left `restore` intact, so a same-direction toggle
	// shortens or extends the window without moving the destination.
	//
	// A direction change is a NEW chain, not a continuation. Inheriting the
	// old target there discarded the outer window silently: silence for an
	// hour, peek for two minutes, and the peek's revert restored the
	// PRE-SILENCE value, so the fleet emitted for the remaining 58 minutes
	// with GET reporting nothing pending. That is the mirror of the
	// stuck-silent bug, and reasoning only about "shorten or extend" is what
	// hid it.
	sameDirection := hadPending && silent == fidelitySilent.Load()
	if !sameDirection {
		fidelityRevert.restore = fidelitySilent.Load()
	}

	previous := fidelitySilent.Load()
	fidelitySilent.Store(silent)
	if previous != silent {
		fidelityTransitions.Add(1)
	}
	logFidelityTransition(previous, silent, d)

	if d <= 0 {
		// An untimed toggle is a standing change, so there is no chain left to
		// return to.
		fidelityRevert.restore = silent
		return fidelitySnapshot{inForce: silent}
	}
	restore := fidelityRevert.restore
	deadline := time.Now().Add(d)
	fidelityRevert.deadline = deadline
	gen := fidelityRevert.gen
	fidelityRevert.timer = time.AfterFunc(d, func() {
		fidelityRevert.mu.Lock()
		defer fidelityRevert.mu.Unlock()
		if fidelityRevert.gen != gen {
			// Superseded or cancelled while this callback waited for the lock.
			// Acting now would clobber a newer decision with a stale value.
			return
		}
		if fidelitySilent.Load() != restore {
			fidelityTransitions.Add(1)
		}
		fidelitySilent.Store(restore)
		fidelityRevert.timer = nil
		fidelityRevert.deadline = time.Time{}
		log.Printf("[fidelity] auto-revert: fleet silence restored to %v after %s", restore, d)
	})
	return fidelitySnapshot{inForce: silent, pending: true, deadline: deadline, revertTo: restore}
}

// logFidelityTransition leaves a trace of every runtime change.
//
// A measurement whose silence changed mid-run is not the measurement its
// operator thinks it is, and the log is the only record that would show it.
func logFidelityTransition(from, to bool, d time.Duration) {
	// The window matters even when the value does not. Checking `from == to`
	// FIRST meant extending a window logged "unchanged" and never recorded the
	// arming, so the fleet would later start emitting with a lone auto-revert
	// line and no logged cause — flatly contradicting this function's reason
	// for existing.
	switch {
	case d > 0 && from == to:
		log.Printf("[fidelity] silent=%v (unchanged), auto-reverting in %s", to, d)
	case d > 0:
		log.Printf("[fidelity] silent=%v (was %v), auto-reverting in %s", to, from, d)
	case from == to:
		log.Printf("[fidelity] silent=%v (unchanged), no revert armed", to)
	default:
		log.Printf("[fidelity] silent=%v (was %v)", to, from)
	}
}

// fidelityStatusHandler implements GET /api/v1/fidelity.
func fidelityStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Everything under ONE hold, including the in-force value: reading it
	// separately lets a concurrent commit produce a response describing a
	// state that never existed.
	fidelityRevert.mu.Lock()
	deadline := fidelityRevert.deadline
	// An already-fired callback clears `timer` only after it wins the mutex, so
	// a GET landing in that gap would otherwise report a pending revert whose
	// time has passed and which will never advance.
	pending := fidelityRevert.timer != nil && deadline.After(time.Now())
	revertTo := fidelityRevert.restore
	inForce := fidelitySilent.Load()
	fidelityRevert.mu.Unlock()

	st := FidelityStatus{
		InForce:       inForce,
		StartupFlag:   fidelityStartupFlag.Load(),
		RevertPending: pending,
	}
	if pending {
		// An operator who armed a window in one shell polls GET from another;
		// without this they see that a revert is pending but never when, or to
		// what.
		st.RevertAt = deadline.UTC().Format(time.RFC3339)
		rt := revertTo
		st.RevertTo = &rt
	}
	sendDataResponse(w, st)
}

// fidelityToggleHandler implements POST /api/v1/fidelity.
func fidelityToggleHandler(w http.ResponseWriter, r *http.Request) {
	var req FidelityRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	// Matches every other POST on this surface: a typo'd key is a 400, not a
	// silently dropped field.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	// A handler that sets DisallowUnknownFields so a typo'd key is a 400 should
	// not then silently drop a whole second object: `{"silent":true}{"silent":false}`
	// applied only the first and returned 200.
	if dec.More() {
		sendErrorResponse(w, "Invalid JSON: unexpected content after the request object",
			http.StatusBadRequest)
		return
	}

	if req.Silent == nil {
		sendErrorResponse(w, `"silent" is required; omitting it would be read as false `+
			`and un-mute the fleet`, http.StatusBadRequest)
		return
	}

	var d time.Duration
	if req.Duration != "" {
		parsed, err := time.ParseDuration(req.Duration)
		if err != nil {
			sendErrorResponse(w, fmt.Sprintf("invalid duration %q: %v", req.Duration, err), http.StatusBadRequest)
			return
		}
		if parsed <= 0 {
			sendErrorResponse(w, fmt.Sprintf("duration %s must be positive", req.Duration), http.StatusBadRequest)
			return
		}
		if parsed > maxRevertAfter {
			sendErrorResponse(w, fmt.Sprintf(
				"duration %s exceeds maximum %s; a single request may not commit the fleet for longer",
				req.Duration, maxRevertAfter), http.StatusBadRequest)
			return
		}
		d = parsed
	}

	snap := setFidelity(*req.Silent, d)

	st := FidelityStatus{
		InForce:       snap.inForce,
		StartupFlag:   fidelityStartupFlag.Load(),
		RevertPending: snap.pending,
	}
	if snap.pending {
		st.RevertAt = snap.deadline.UTC().Format(time.RFC3339)
		revertTo := snap.revertTo
		st.RevertTo = &revertTo
	}
	sendDataResponse(w, st)
}
