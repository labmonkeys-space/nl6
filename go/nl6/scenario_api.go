/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// scenario_api.go — the REST control surface wrapping the transport-agnostic
// ScenarioController (D2). Seven endpoints under /api/v1/scenarios:
// submit/arm/start/stop/report + status + delete. Wire conventions (per
// architecture Implementation-Patterns): snake_case JSON, direct objects
// (no APIResponse envelope), {"error","field"} for 400 validation and
// {"error"} for 404/409, RFC3339-ms timestamps, two-stage validation.

// scenarioMaxBody bounds the submit body (matches the createDevices limit).
const scenarioMaxBody = 64 << 10

// scenarioRequest is the submit DTO. Durations arrive as Go duration
// strings ("30s", "5m") per the interface-state auto-revert precedent.
type scenarioRequest struct {
	Participants []string `json:"participants"`
	Protocol     string   `json:"protocol"`
	Rate         float64  `json:"rate"`
	Window       string   `json:"window"`
	Drain        string   `json:"drain,omitempty"`
	Seed         int64    `json:"seed,omitempty"`
}

// toScenario maps the wire DTO into the internal Scenario, parsing the
// duration strings. The returned field names the offending JSON key on
// error (for the {"error","field"} 400 body).
func (req *scenarioRequest) toScenario() (spec *Scenario, field string, err error) {
	window, err := time.ParseDuration(req.Window)
	if err != nil {
		return nil, "window", fmt.Errorf("invalid window %q: %v (use a Go duration like \"30s\")", req.Window, err)
	}
	var drain time.Duration
	if req.Drain != "" {
		drain, err = time.ParseDuration(req.Drain)
		if err != nil {
			return nil, "drain", fmt.Errorf("invalid drain %q: %v (use a Go duration like \"2s\")", req.Drain, err)
		}
	}
	return &Scenario{
		Participants: req.Participants,
		Protocol:     req.Protocol,
		Rate:         req.Rate,
		Window:       window,
		Drain:        drain,
		Seed:         req.Seed,
	}, "", nil
}

// configSHA256 fingerprints the submit config over its canonicalized form:
// re-marshal through a map so keys are sorted, independent of the client's
// key order or whitespace (D5).
func configSHA256(req *scenarioRequest) string {
	b, _ := json.Marshal(req)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	canon, _ := json.Marshal(m) // encoding/json sorts map keys
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

// --- wire response helpers ---------------------------------------------

func writeScenarioJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// scenario400 emits the fail-fast validation error shape {"error","field"}.
// field may be empty when the error is not attributable to one key.
func scenario400(w http.ResponseWriter, msg, field string) {
	body := map[string]string{"error": msg}
	if field != "" {
		body["field"] = field
	}
	writeScenarioJSON(w, http.StatusBadRequest, body)
}

// scenarioErr emits the plain {"error"} shape for 404/409/503.
func scenarioErr(w http.ResponseWriter, code int, msg string) {
	writeScenarioJSON(w, code, map[string]string{"error": msg})
}

// --- readiness / status DTOs -------------------------------------------

type readinessResponse struct {
	ID                string                `json:"id"`
	Phase             string                `json:"phase"`
	ParticipantsArmed int                   `json:"participants_armed"`
	Excluded          []scenarioExcludedRow `json:"excluded"`
}

type statusResponse struct {
	ID           string `json:"id"`
	Phase        string `json:"phase"`
	ConfigSHA256 string `json:"config_sha256"`
	Seed         int64  `json:"seed"`
}

// --- handlers ----------------------------------------------------------

// createScenarioHandler: POST /api/v1/scenarios → 202 {id, config_sha256}.
func createScenarioHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, scenarioMaxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req scenarioRequest
	if err := dec.Decode(&req); err != nil {
		scenario400(w, err.Error(), "")
		return
	}
	spec, field, err := req.toScenario()
	if err != nil {
		scenario400(w, err.Error(), field)
		return
	}
	if err := spec.Validate(); err != nil {
		scenario400(w, err.Error(), "")
		return
	}
	sha := configSHA256(&req)
	_, id, err := manager.submitScenario(spec, sha)
	if err != nil {
		if errors.Is(err, errScenarioActive) {
			scenarioErr(w, http.StatusConflict, err.Error())
			return
		}
		scenario400(w, err.Error(), "")
		return
	}
	writeScenarioJSON(w, http.StatusAccepted, map[string]string{"id": id, "config_sha256": sha})
}

// armScenarioHandler: POST /api/v1/scenarios/{id}/arm → 200 readiness.
func armScenarioHandler(w http.ResponseWriter, r *http.Request) {
	ctrl, ok := lookupScenario(w, r)
	if !ok {
		return
	}
	armed, excluded, err := ctrl.Arm()
	if err != nil {
		scenarioErr(w, http.StatusConflict, conflictMsg(ctrl, err, "arm"))
		return
	}
	rows := make([]scenarioExcludedRow, 0, len(excluded))
	for _, ex := range excluded {
		rows = append(rows, scenarioExcludedRow(ex))
	}
	writeScenarioJSON(w, http.StatusOK, readinessResponse{
		ID: ctrl.id, Phase: string(ctrl.Phase()), ParticipantsArmed: armed, Excluded: rows,
	})
}

// startScenarioHandler: POST /api/v1/scenarios/{id}/start → 200 status.
func startScenarioHandler(w http.ResponseWriter, r *http.Request) {
	ctrl, ok := lookupScenario(w, r)
	if !ok {
		return
	}
	if err := ctrl.Start(context.Background()); err != nil {
		scenarioErr(w, http.StatusConflict, conflictMsg(ctrl, err, "start"))
		return
	}
	writeScenarioJSON(w, http.StatusOK, scenarioStatus(ctrl))
}

// stopScenarioHandler: POST /api/v1/scenarios/{id}/stop → 200 report.
func stopScenarioHandler(w http.ResponseWriter, r *http.Request) {
	ctrl, ok := lookupScenario(w, r)
	if !ok {
		return
	}
	// Stop is idempotent: a scenario whose window already auto-closed at T1
	// (or a redundant POST) is terminal, so Stop() errors — but the report
	// already exists, so serve it (200) rather than a spurious 409. Only a
	// stop with no finalized result (e.g. stop-before-start) is a real
	// phase conflict.
	if _, err := ctrl.Stop(); err != nil {
		if rep := buildScenarioReport(manager, ctrl); rep != nil {
			writeScenarioJSON(w, http.StatusOK, rep)
			return
		}
		scenarioErr(w, http.StatusConflict, conflictMsg(ctrl, err, "stop"))
		return
	}
	writeScenarioJSON(w, http.StatusOK, buildScenarioReport(manager, ctrl))
}

// scenarioReportHandler: GET /api/v1/scenarios/{id}/report → 200 report,
// or 409 if the scenario has not reached a terminal phase.
func scenarioReportHandler(w http.ResponseWriter, r *http.Request) {
	ctrl, ok := lookupScenario(w, r)
	if !ok {
		return
	}
	rep := buildScenarioReport(manager, ctrl)
	if rep == nil {
		scenarioErr(w, http.StatusConflict, fmt.Sprintf(
			"scenario %s is in phase %s; the report is available only after stop or abort", ctrl.id, ctrl.Phase()))
		return
	}
	writeScenarioJSON(w, http.StatusOK, rep)
}

// scenarioStatusHandler: GET /api/v1/scenarios/{id} → 200 status.
func scenarioStatusHandler(w http.ResponseWriter, r *http.Request) {
	ctrl, ok := lookupScenario(w, r)
	if !ok {
		return
	}
	writeScenarioJSON(w, http.StatusOK, scenarioStatus(ctrl))
}

// deleteScenarioHandler: DELETE /api/v1/scenarios/{id} → 200 {} (releases
// transports for an armed scenario without producing a report — FR39; 409
// for a running scenario which must be stopped/aborted first).
func deleteScenarioHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	switch err := manager.deleteScenario(id); {
	case err == nil:
		writeScenarioJSON(w, http.StatusOK, map[string]string{})
	case errors.Is(err, errNoActiveScenario):
		scenarioErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errScenarioRunning):
		scenarioErr(w, http.StatusConflict, err.Error())
	default:
		scenarioErr(w, http.StatusConflict, err.Error())
	}
}

// --- shared handler helpers --------------------------------------------

// lookupScenario resolves {id} to the active controller, writing a 404 and
// returning ok=false on mismatch.
func lookupScenario(w http.ResponseWriter, r *http.Request) (*ScenarioController, bool) {
	id := mux.Vars(r)["id"]
	ctrl, err := manager.scenarioByID(id)
	if err != nil {
		scenarioErr(w, http.StatusNotFound, fmt.Sprintf("scenario %q not found", id))
		return nil, false
	}
	return ctrl, true
}

func scenarioStatus(c *ScenarioController) statusResponse {
	return statusResponse{ID: c.id, Phase: string(c.Phase()), ConfigSHA256: c.configSHA, Seed: c.spec.Seed}
}

// conflictMsg builds the 409 body naming the current phase + scenario ID +
// the verb that could not resolve (self-service diagnostics).
func conflictMsg(c *ScenarioController, err error, verb string) string {
	return fmt.Sprintf("cannot %s scenario %s in phase %s: %v", verb, c.id, c.Phase(), err)
}
