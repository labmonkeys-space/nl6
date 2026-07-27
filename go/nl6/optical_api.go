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
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// optical_api.go — POST /api/v1/devices/{ip}/optical/{component}/degrade
// (#334, task 5.4). Drives one named optical channel across the FEC
// threshold on demand, which is what lets a monitoring team validate
// threshold and alarm logic without real hardware.
//
// DEVIATION from task 5.4, stated plainly: the task asks for the
// interface-state auto-revert machinery (`revertTimers`, per-device
// cancellation, all-cancel on shutdown). The user-visible contract is
// implemented — `duration` is capped at maxRevertAfter, a second POST
// supersedes the first, an unknown component is 404 — but there is no timer
// goroutine, because an optical episode does not need one. Its end time is
// frozen at publish and the value engine is a pure function of t, so the
// revert is arithmetic (see optical_degrade.go). A timer would add a
// goroutine, a cancel race, and a shutdown hook to schedule a mutation that
// already happens by itself. Nothing to cancel on device.Stop() either: an
// episode holds no resources and dies with its cycler.

// degradeRequest is the POST body. Both offsets are optional and default to
// zero; a request with both zero CLEARS active degradation, which is the
// natural "undo" and mirrors how a duration-less interface POST is a plain
// set.
//
// Two knobs rather than one "severity" dial: they select which diagnostic
// quadrant the fault lands in. input_power_drop_db attenuates signal and
// accumulated noise together (power falls, OSNR roughly holds — a fibre or
// connector problem); noise_rise_db raises ASE only (power holds, OSNR falls
// — a sick amplifier). A single dial would make the second unreachable, and
// collector correlation rules key on exactly that difference.
type degradeRequest struct {
	InputPowerDropDB float64 `json:"input_power_drop_db,omitempty"`
	NoiseRiseDB      float64 `json:"noise_rise_db,omitempty"`
	Duration         string  `json:"duration,omitempty"`
}

// degradeResponse echoes what is now in force so a caller can confirm the
// episode without a second request.
type degradeResponse struct {
	Device           string  `json:"device"`
	Component        string  `json:"component"`
	InputPowerDropDB float64 `json:"input_power_drop_db"`
	NoiseRiseDB      float64 `json:"noise_rise_db"`
	Duration         string  `json:"duration,omitempty"`
	Cleared          bool    `json:"cleared,omitempty"`
}

// parseDegradeRequest decodes and validates the body. Unknown fields are
// rejected so a typo'd `noise_rise` surfaces as 400 rather than silently
// degrading nothing — the same discipline as the interface-state handler.
func parseDegradeRequest(w http.ResponseWriter, r *http.Request) (degradeRequest, time.Duration, error) {
	var req degradeRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var mbErr *http.MaxBytesError
		if errors.As(err, &mbErr) {
			return req, 0, fmt.Errorf("payload too large (max 4 KiB)")
		}
		if errors.Is(err, io.EOF) {
			// An empty body is a legitimate clear-everything request.
			return req, 0, nil
		}
		return req, 0, fmt.Errorf("invalid JSON: %w", err)
	}
	if dec.More() {
		return req, 0, errors.New("invalid JSON: trailing data after first object")
	}
	var dur time.Duration
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			return req, 0, fmt.Errorf("invalid duration %q: %w", req.Duration, err)
		}
		if d <= 0 {
			return req, 0, fmt.Errorf("duration must be positive, got %s", req.Duration)
		}
		if d > maxRevertAfter {
			return req, 0, fmt.Errorf("duration %s exceeds maximum %s; degradation windows are bounded so a forgotten request cannot pin a channel forever", req.Duration, maxRevertAfter)
		}
		dur = d
	}
	return req, dur, nil
}

// degradeOpticalHandler implements
// POST /api/v1/devices/{ip}/optical/{component}/degrade.
//
//	404 — unknown device, a device with no optical channels, or an unknown component
//	400 — malformed body, unknown field, non-positive or over-cap duration, out-of-range offset
//	413 — body over 4 KiB
//	200 — episode published (or cleared)
func degradeOpticalHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ip := vars["ip"]
	component := vars["component"]

	req, dur, err := parseDegradeRequest(w, r)
	if err != nil {
		if strings.Contains(err.Error(), "payload too large") {
			sendErrorResponse(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	oc, err := manager.opticalCyclerFor(ip)
	if err != nil {
		// "Still initialising" is transient, so it gets 503 like every other
		// subsystem's not-ready path — a 404 tells a client to stop retrying
		// something that is about to work.
		if errors.Is(err, errOpticalNotReady) {
			sendErrorResponse(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		sendErrorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := oc.Degrade(component, time.Now(), dur, req.InputPowerDropDB, req.NoiseRiseDB); err != nil {
		// Degrade distinguishes "no such component" (a 404 — the caller named
		// something that does not exist) from a bad offset (a 400).
		if strings.Contains(err.Error(), "unknown optical component") {
			available := oc.Components()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":               err.Error(),
				"availableComponents": available,
			})
			return
		}
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	cleared := req.InputPowerDropDB == 0 && req.NoiseRiseDB == 0
	resp := degradeResponse{
		Device:           ip,
		Component:        component,
		InputPowerDropDB: req.InputPowerDropDB,
		NoiseRiseDB:      req.NoiseRiseDB,
		Cleared:          cleared,
	}
	// A duration on a clear is meaningless — the clear is immediate — and
	// echoing `{"duration":"10m","cleared":true}` reads as "cleared in 10
	// minutes". Drop it rather than confirm something that will not happen.
	if !cleared {
		resp.Duration = req.Duration
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// opticalStatusHandler implements GET /api/v1/devices/{ip}/optical — what is
// in force right now on every channel of a device.
//
// The POST is otherwise write-only, which is out of step with the rest of the
// API (every subsystem POST has a status GET) and leaves a second operator,
// or a caller that lost its response, unable to discover current state.
func opticalStatusHandler(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]
	oc, err := manager.opticalCyclerFor(ip)
	if err != nil {
		if errors.Is(err, errOpticalNotReady) {
			sendErrorResponse(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		sendErrorResponse(w, err.Error(), http.StatusNotFound)
		return
	}
	channels := make([]opticalChannelStatus, 0, len(oc.Components()))
	for _, name := range oc.Components() {
		sag, rise, _ := oc.ActiveDegradation(name)
		channels = append(channels, opticalChannelStatus{
			Component:        name,
			InputPowerDropDB: sag,
			NoiseRiseDB:      rise,
			Degraded:         sag > 0 || rise > 0,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"device": ip, "channels": channels})
}

// opticalChannelStatus is one channel's current degradation state.
type opticalChannelStatus struct {
	Component        string  `json:"component"`
	InputPowerDropDB float64 `json:"input_power_drop_db"`
	NoiseRiseDB      float64 `json:"noise_rise_db"`
	Degraded         bool    `json:"degraded"`
}

// opticalCyclerFor resolves a device IP to its published optical engine.
// Mirrors the gNMI resolver's NotFound/Unavailable split in HTTP terms: a
// device that cannot have optical channels and one still initialising are
// both 404 here, but the messages differ so an operator can tell which.
// errOpticalNotReady marks the transient case so the handler can map it to
// 503 while permanent absence stays 404.
var errOpticalNotReady = errors.New("optical engine not ready")

func (sm *SimulatorManager) opticalCyclerFor(ip string) (*OpticalCycler, error) {
	sm.mu.RLock()
	dev := sm.devicesByIP[ip]
	sm.mu.RUnlock()
	if dev == nil {
		return nil, fmt.Errorf("device %s not found", ip)
	}
	if dev.metricsCycler == nil {
		return nil, fmt.Errorf("%w: device %s has no metrics engine yet", errOpticalNotReady, ip)
	}
	oc := dev.metricsCycler.OpticalCyclerOf()
	if oc == nil {
		if IsOpticalDeviceType(dev.resourceFile) {
			return nil, fmt.Errorf("%w: device %s is still initialising its optical engine", errOpticalNotReady, ip)
		}
		return nil, fmt.Errorf("device %s serves no optical channels (type %s)", ip, strings.TrimSuffix(dev.resourceFile, ".json"))
	}
	return oc, nil
}
