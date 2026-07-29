/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// scenarioParticipantWireBytes is the worst-case COMPACT-JSON cost of one
// participant entry, `"255.255.255.255",` — 15 address bytes plus two quotes
// and a comma. Validate accepts only IPv4 dotted quads (via netip Is4, which
// excludes the longer IPv4-mapped IPv6 spellings), so no accepted entry costs
// more than this once encoded compactly.
//
// "Compact" is load-bearing and is the honest limit of what this constant can
// promise: JSON permits unbounded insignificant whitespace, so NO per-entry
// byte constant can bound a raw request body from a semantic entry count. A
// pretty-printed ceiling-sized list (~21 bytes/entry at 4-space indent) exceeds
// scenarioMaxBody and is rejected on size. The byte cap is therefore an
// independent limit, not a guarantee that every ceiling-sized list fits.
const scenarioParticipantWireBytes = 18

// scenarioMaxBody bounds the submit body. It is DERIVED from the participant
// ceiling rather than chosen alongside it: the cap must admit a ceiling-sized
// participant list in compact JSON, or scenarioMaxParticipants is unreachable
// and a fleet-scale submit fails on body size instead of reporting a count.
// Writing it as arithmetic makes that a structural property — raise the ceiling
// and the cap follows — instead of a comment that can rot.
//
// The 64 KiB addend is the envelope budget for every non-participant field
// (protocol, rate, window, drain, seed, rate_profile, abort_predicate): the
// entire allowance of the previous cap, which was copied from createDevices
// where the body size does not scale with the fleet. It is a SHARED budget —
// a ceiling-sized list plus a 70 KiB abort_predicate still exceeds the cap.
//
// Note the two bounds are complementary, not redundant. MaxBytesReader trips
// DURING the decoder's read, capping how many bytes one request can make the
// server consume (the allocation guard); the participant count can only be
// checked once the slice is fully decoded (the semantic guard).
const scenarioMaxBody = scenarioMaxParticipants*scenarioParticipantWireBytes + 64<<10

// scenarioRequest is the submit DTO. Durations arrive as Go duration
// strings ("30s", "5m") per the interface-state auto-revert precedent.
type scenarioRequest struct {
	Participants   []string            `json:"participants"`
	Protocol       string              `json:"protocol"`
	Rate           float64             `json:"rate"`
	Window         string              `json:"window"`
	Drain          string              `json:"drain,omitempty"`
	Seed           int64               `json:"seed,omitempty"`
	RateProfile    *RateProfileSpec    `json:"rate_profile,omitempty"`
	AbortPredicate *AbortPredicateSpec `json:"abort_predicate,omitempty"`
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
		Participants:   req.Participants,
		Protocol:       req.Protocol,
		Rate:           req.Rate,
		Window:         window,
		Drain:          drain,
		Seed:           req.Seed,
		RateProfile:    req.RateProfile,
		AbortPredicate: req.AbortPredicate,
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
	// ExcludedTotal is the authoritative count. `excluded` is capped at
	// scenarioMaxExcludedRows rows so a ceiling-sized submit against a sparse
	// fleet cannot produce a multi-megabyte control-plane response; when the cap
	// bites, ExcludedTruncated is set and ExcludedByReason still accounts for
	// every exclusion.
	ExcludedTotal     int            `json:"excluded_total"`
	ExcludedTruncated bool           `json:"excluded_truncated,omitempty"`
	ExcludedByReason  map[string]int `json:"excluded_by_reason,omitempty"`
	// ScheduledStartCancelled reports that this arm withdrew a pending
	// absolute-T0 start (the membership it was authorised against has been
	// re-resolved). Omitted when there was nothing to cancel, so the field only
	// appears when the client needs to act on it — by rescheduling.
	ScheduledStartCancelled bool `json:"scheduled_start_cancelled,omitempty"`
}

type statusResponse struct {
	ID             string `json:"id"`
	Phase          string `json:"phase"`
	Protocol       string `json:"protocol"`
	ConfigSHA256   string `json:"config_sha256"`
	Seed           int64  `json:"seed"`
	Window         string `json:"window"`
	ScheduledStart string `json:"scheduled_start,omitempty"`
	// Live window observability (FR30/FR31): actual T0/T1 (running gate or
	// finalized result), elapsed since T0, remaining until T1. Empty before
	// the scenario runs.
	T0        string `json:"t0,omitempty"`
	T1        string `json:"t1,omitempty"`
	Elapsed   string `json:"elapsed,omitempty"`
	Remaining string `json:"remaining,omitempty"`
	// Counts is a live mid-run counter snapshot (approximate atomic reads);
	// nil before arm.
	Counts      *statusCounts     `json:"counts,omitempty"`
	Transitions []transitionEntry `json:"transitions"`
}

// statusCounts is a live progress snapshot of the summed participant ledgers.
type statusCounts struct {
	ParticipantsArmed   int    `json:"participants_armed"`
	Emitted             uint64 `json:"emitted"`
	Sent                uint64 `json:"sent"` // in_window + drain
	InWindow            uint64 `json:"in_window"`
	Drain               uint64 `json:"drain"`
	SuppressedPreWindow uint64 `json:"suppressed_pre_window"`
	SendFailures        uint64 `json:"send_failures"`
	Dropped             uint64 `json:"dropped"`
}

// scenarioListEntry is one row of GET /api/v1/scenarios.
type scenarioListEntry struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
}

// transitionEntry is one lifecycle step in the status transition log
// (RFC3339-ms timestamp), so a SIGTERM-driven abort is observable after
// the fact (FR33 / D7 abort observability).
type transitionEntry struct {
	Phase string `json:"phase"`
	At    string `json:"at"`
}

// --- handlers ----------------------------------------------------------

// createScenarioHandler: POST /api/v1/scenarios → 202 {id, config_sha256}.
func createScenarioHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, scenarioMaxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req scenarioRequest
	if err := dec.Decode(&req); err != nil {
		// Name the limit rather than passing Go's bare "http: request body
		// too large" through: the operator needs both numbers to size the next
		// attempt. Same MaxBytesError discipline as the interface-state and
		// optical handlers.
		//
		// Deliberately NO "field" attribution. *http.MaxBytesError carries no
		// information about which field made the body oversized, so naming
		// `participants` would be a guess presented as a diagnosis — and it
		// misdirects outright when the cause is a 2 MB `window` string on a
		// one-participant request. The message states the participant ceiling
		// as the likely cause without asserting it.
		var mbErr *http.MaxBytesError
		if errors.As(err, &mbErr) {
			scenario400(w, fmt.Sprintf(
				"request body exceeds the %d-byte cap (compact JSON); the participant list, capped at %d entries, is the usual cause",
				scenarioMaxBody, scenarioMaxParticipants), "")
			return
		}
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
	// ArmReadiness, not Arm() plus follow-up accessors: every field below is reset
	// and rebuilt by a concurrent arm (armed→armed is legal re-entry), so reading
	// them across separate lock acquisitions can splice two arms into one response
	// — rows from the first with a total from the second.
	rd, err := ctrl.ArmReadiness()
	if err != nil {
		scenarioErr(w, http.StatusConflict, conflictMsg(ctrl, err, "arm"))
		return
	}
	rows := make([]scenarioExcludedRow, 0, len(rd.Excluded))
	for _, ex := range rd.Excluded {
		rows = append(rows, scenarioExcludedRow(ex))
	}
	writeScenarioJSON(w, http.StatusOK, readinessResponse{
		ID: ctrl.id, Phase: string(ctrl.Phase()), ParticipantsArmed: rd.Armed, Excluded: rows,
		ExcludedTotal:           rd.ExcludedTotal,
		ExcludedTruncated:       excludedTruncated(rd.ExcludedTotal, len(rows)),
		ExcludedByReason:        rd.ExcludedByReason,
		ScheduledStartCancelled: rd.ScheduleCancelled,
	})
}

// startRequest is the optional start body: an absolute T0 (FR11). An empty
// body starts immediately.
type startRequest struct {
	At string `json:"at"`
}

// parseStartAt reads the optional {"at": RFC3339} start body. Returns
// hasAt=false for an empty body or omitted field.
func parseStartAt(r *http.Request) (at time.Time, hasAt bool, err error) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<10))
	if len(bytes.TrimSpace(body)) == 0 {
		return time.Time{}, false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req startRequest
	if err := dec.Decode(&req); err != nil {
		return time.Time{}, false, err
	}
	if req.At == "" {
		return time.Time{}, false, nil
	}
	at, err = time.Parse(time.RFC3339, req.At)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("invalid 'at' timestamp %q: %v (want RFC3339)", req.At, err)
	}
	return at, true, nil
}

// startScenarioHandler: POST /api/v1/scenarios/{id}/start → 200 status.
// An optional {"at": RFC3339} body schedules the start at an absolute T0
// (FR11); a past timestamp is rejected 400.
func startScenarioHandler(w http.ResponseWriter, r *http.Request) {
	ctrl, ok := lookupScenario(w, r)
	if !ok {
		return
	}
	at, hasAt, err := parseStartAt(r)
	if err != nil {
		scenario400(w, err.Error(), "at")
		return
	}
	if hasAt {
		if !at.After(time.Now()) {
			scenario400(w, fmt.Sprintf("start time %s is in the past", at.Format(time.RFC3339)), "at")
			return
		}
		if err := ctrl.ScheduleStart(context.Background(), at); err != nil {
			scenarioErr(w, http.StatusConflict, conflictMsg(ctrl, err, "start"))
			return
		}
		writeScenarioJSON(w, http.StatusOK, scenarioStatus(ctrl))
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
	// The report echoes operator-configured strings (collector, source_ip). Send
	// X-Content-Type-Options: nosniff so a browser can never MIME-sniff the CSV
	// or JSON body as HTML and execute embedded markup (reflected-XSS barrier,
	// CodeQL go/reflected-xss). The HTML variant is separately safe: every field
	// is auto-escaped by html/template.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch r.URL.Query().Get("format") {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", ctrl.id))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(reportCSV(rep))
		return
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(reportHTML(rep))
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
	trs := c.Transitions()
	entries := make([]transitionEntry, 0, len(trs))
	for _, tr := range trs {
		entries = append(entries, transitionEntry{Phase: string(tr.Phase), At: tr.At.Format(rfc3339ms)})
	}
	resp := statusResponse{
		ID: c.id, Phase: string(c.Phase()), Protocol: c.spec.Protocol,
		ConfigSHA256: c.configSHA, Seed: c.spec.Seed, Window: c.PlannedWindow().String(),
		Transitions: entries,
	}
	if sa := c.ScheduledStart(); !sa.IsZero() {
		resp.ScheduledStart = sa.Format(rfc3339ms)
	}
	// Live window bounds + elapsed/remaining (FR30).
	if t0, t1, ok := c.WindowBounds(); ok {
		resp.T0 = t0.Format(rfc3339ms)
		resp.T1 = t1.Format(rfc3339ms)
		now := time.Now()
		if now.After(t0) {
			resp.Elapsed = now.Sub(t0).Truncate(time.Millisecond).String()
		}
		if t1.After(now) {
			resp.Remaining = t1.Sub(now).Truncate(time.Millisecond).String()
		} else {
			resp.Remaining = "0s"
		}
	}
	// Live counts (approximate mid-run reads); present once armed.
	if armed, sum := c.LiveCounts(); armed > 0 {
		resp.Counts = &statusCounts{
			ParticipantsArmed:   armed,
			Emitted:             sum.Emitted,
			Sent:                sum.InWindow + sum.Drain,
			InWindow:            sum.InWindow,
			Drain:               sum.Drain,
			SuppressedPreWindow: sum.SuppressedPreWindow,
			SendFailures:        sum.SendFailures,
			Dropped:             sum.Dropped,
		}
	}
	return resp
}

// listScenariosHandler: GET /api/v1/scenarios → the scenarios with their
// phases (MVP: 0 or 1 — one active scenario at a time).
func listScenariosHandler(w http.ResponseWriter, r *http.Request) {
	list := manager.listScenarios()
	writeScenarioJSON(w, http.StatusOK, map[string]any{"scenarios": list})
}

// conflictMsg builds the 409 body naming the current phase + scenario ID +
// the verb that could not resolve (self-service diagnostics).
func conflictMsg(c *ScenarioController, err error, verb string) string {
	return fmt.Sprintf("cannot %s scenario %s in phase %s: %v", verb, c.id, c.Phase(), err)
}
