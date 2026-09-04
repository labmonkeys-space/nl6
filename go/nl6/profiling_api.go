/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// profiling_api.go — GET / POST /api/v1/profiling, the runtime control of the
// profiling gate. Mirrors fidelity_api.go line for line where it applies;
// the differences are that the request carries an optional destination
// (server_address) and the response reports whether the SDK is pushing.

// ProfilingRequest is the body of POST /api/v1/profiling.
type ProfilingRequest struct {
	// Enabled is a POINTER so an omitted key is distinguishable from `false`
	// (the FidelityRequest.Silent lesson: `{"duration":"5m"}` must be a 400,
	// not a silent off).
	Enabled *bool `json:"enabled"`
	// ServerAddress is the Pyroscope push URL. Empty means "the startup
	// flag's address, or pull-only when there is none". Ignored when
	// disabling.
	ServerAddress string `json:"server_address,omitempty"`
	// Duration, when set, restores the pre-chain state after it elapses.
	// Capped at maxRevertAfter, shared with fidelity and interface state.
	Duration string `json:"duration,omitempty"`
}

// ProfilingStatus is the body of GET /api/v1/profiling and the data of a
// POST response.
//
// Enabled and StartupFlag are reported separately for the fidelity reason:
// once the value is mutable the flag is a default, not a fact.
type ProfilingStatus struct {
	Enabled bool `json:"enabled"`
	// StartupFlag is what -profiling-pyroscope was at launch; empty when it
	// was not given.
	StartupFlag string `json:"startup_flag"`
	// ServerAddress is the push destination in force; empty when pull-only
	// or off.
	ServerAddress string `json:"server_address"`
	// Pushing is true while the SDK is RUNNING a push. It says nothing about
	// whether uploads succeed: pyroscope.Start never touches the network, so a
	// down or rejecting collector shows in UploadFailures and LastError, not
	// here. It can be false with Enabled true: pull-only mode, or a push whose
	// Start failed (see LastError).
	Pushing bool `json:"pushing"`
	// UploadFailures counts the CURRENT push's failed uploads (reset when a
	// push starts). Omitted while zero.
	UploadFailures uint64 `json:"upload_failures,omitempty"`
	// LastError is the most recent Start failure or, when Start succeeded,
	// the most recent upload failure of the current push. Omitted when none.
	LastError string `json:"last_error,omitempty"`
	// PprofPath is where the gated pull surface lives, so a client need not
	// know it.
	PprofPath string `json:"pprof_path"`
	// RevertPending / RevertAt / RevertTo: the fidelity trio. RevertTo is the
	// gate value the pending revert restores, which chain semantics make
	// non-inferable from Enabled. RevertToAddress is the push address it
	// restores with it (empty: pull-only or off), because a revert restores
	// the whole (gate, address) pair and a reader cannot infer the address
	// from the bool.
	RevertPending   bool   `json:"revert_pending"`
	RevertAt        string `json:"revert_at,omitempty"`
	RevertTo        *bool  `json:"revert_to,omitempty"`
	RevertToAddress string `json:"revert_to_address,omitempty"`
}

// profilingStatusFrom renders a snapshot as the API body.
func profilingStatusFrom(snap profilingSnapshot) ProfilingStatus {
	flag, _ := profilingStartupFlag.Load().(string)
	st := ProfilingStatus{
		Enabled:        snap.enabled,
		StartupFlag:    flag,
		ServerAddress:  snap.addr,
		Pushing:        snap.pushing,
		UploadFailures: snap.uploadFailures,
		LastError:      snap.lastError,
		PprofPath:      profilingPprofPath,
		RevertPending:  snap.pending,
	}
	if snap.pending {
		st.RevertAt = snap.deadline.UTC().Format(time.RFC3339)
		rt := snap.revertTo.enabled
		st.RevertTo = &rt
		st.RevertToAddress = snap.revertTo.addr
	}
	return st
}

// profilingStatusHandler implements GET /api/v1/profiling.
func profilingStatusHandler(w http.ResponseWriter, r *http.Request) {
	sendDataResponse(w, profilingStatusFrom(profilingSnapshotNow()))
}

// profilingToggleHandler implements POST /api/v1/profiling.
func profilingToggleHandler(w http.ResponseWriter, r *http.Request) {
	var req ProfilingRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if dec.More() {
		sendErrorResponse(w, "Invalid JSON: unexpected content after the request object",
			http.StatusBadRequest)
		return
	}

	if req.Enabled == nil {
		sendErrorResponse(w, `"enabled" is required; omitting it would be read as false `+
			`and switch profiling off`, http.StatusBadRequest)
		return
	}

	if req.ServerAddress != "" {
		// Validated-then-ignored is the nl6#445 family; an address on an off
		// request would be exactly that.
		if !*req.Enabled {
			sendErrorResponse(w, "server_address is only meaningful with enabled:true", http.StatusBadRequest)
			return
		}
		if err := validateProfilingAddress(req.ServerAddress); err != nil {
			sendErrorResponse(w, "server_address: "+err.Error(), http.StatusBadRequest)
			return
		}
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
				"duration %s exceeds maximum %s; a single request may not commit the process for longer",
				req.Duration, maxRevertAfter), http.StatusBadRequest)
			return
		}
		d = parsed
	}

	snap, err := setProfiling(*req.Enabled, req.ServerAddress, d)
	st := profilingStatusFrom(snap)
	if err != nil {
		// The gate is open and the pull surface serves, but the push did not
		// start. 500 with the state attached, so the caller sees both.
		sendErrorResponseWithData(w, "profiling enabled but the push to "+snap.addr+
			" could not start: "+err.Error(), http.StatusInternalServerError, st)
		return
	}
	sendDataResponse(w, st)
}
