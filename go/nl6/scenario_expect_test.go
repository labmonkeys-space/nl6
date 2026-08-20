/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// intPtr is the submit-DTO helper: expect_participants is a *int so an explicit
// zero is distinguishable from an omitted field.
func intPtr(n int) *int { return &n }

// TestScenarioAPI_ExpectParticipantsValidation is the submit contract: a
// declared expectation must be reachable (>= 1, <= the participant ceiling).
func TestScenarioAPI_ExpectParticipantsValidation(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	body := func(v string) string {
		return `{"participants":["10.42.0.1"],"expect_participants":` + v +
			`,"protocol":"syslog","rate":5,"window":"1s"}`
	}

	t.Run("rejected", func(t *testing.T) {
		for name, v := range map[string]string{
			"zero":         "0",
			"negative":     "-1",
			"over_ceiling": fmt.Sprint(scenarioMaxParticipants + 1),
		} {
			t.Run(name, func(t *testing.T) {
				w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body(v))
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), "expect_participants") {
					t.Fatalf("400 should name the field: %s", w.Body.String())
				}
			})
		}
	})

	t.Run("accepted", func(t *testing.T) {
		// One declared participant, so only an expectation of 1 is satisfiable
		// without a prefix selector (see unsatisfiable_without_cidr below).
		id := submitOK(t, router, body("1"))
		deleteScenario(t, router, id)

		// The ceiling itself is reachable when a prefix makes the resolved size
		// unknowable at submit.
		id = submitOK(t, router, `{"participants_cidr":["10.42.0.0/16"],"expect_participants":`+
			fmt.Sprint(scenarioMaxParticipants)+`,"protocol":"syslog","rate":5,"window":"1s"}`)
		deleteScenario(t, router, id)
	})

	// An expectation above the declared list, with no prefix selector, is
	// unsatisfiable by construction: the armed set cannot exceed the list. Same
	// class as the bounds above, and knowable with the same submit-time
	// information, so it is refused rather than deferred to a 409 at start.
	t.Run("unsatisfiable_without_cidr", func(t *testing.T) {
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios",
			`{"participants":["10.42.0.1","10.42.0.2"],"expect_participants":3,"protocol":"syslog","rate":5,"window":"1s"}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "can never be satisfied") {
			t.Fatalf("400 should explain why: %s", w.Body.String())
		}
	})

	// The same expectation IS admissible once a prefix can supply the rest —
	// the resolved size is then unknowable until arm.
	t.Run("satisfiable_with_cidr", func(t *testing.T) {
		id := submitOK(t, router,
			`{"participants":["10.43.0.1"],"participants_cidr":["10.42.0.0/24"],"expect_participants":3,"protocol":"syslog","rate":5,"window":"1s"}`)
		deleteScenario(t, router, id)
	})
}

// TestScenarioAPI_ExpectParticipantsFingerprint: the expectation is declared
// intent, so it participates in config_sha256 — and an absent one canonicalizes
// away, leaving pre-feature bodies fingerprinting exactly as before.
func TestScenarioAPI_ExpectParticipantsFingerprint(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	sha := func(body string) string {
		t.Helper()
		id := submitOK(t, router, body)
		w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id, "")
		var st statusResponse
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		deleteScenario(t, router, id)
		return st.ConfigSHA256
	}

	// Two declared participants, so expectations of both 1 and 2 are
	// satisfiable and reach the fingerprint rather than a validation 400.
	bare := sha(`{"participants":["10.42.0.1","10.42.0.2"],"protocol":"syslog","rate":5,"window":"1s"}`)
	withOne := sha(`{"participants":["10.42.0.1","10.42.0.2"],"expect_participants":1,"protocol":"syslog","rate":5,"window":"1s"}`)
	withTwo := sha(`{"participants":["10.42.0.1","10.42.0.2"],"expect_participants":2,"protocol":"syslog","rate":5,"window":"1s"}`)

	if withOne == bare {
		t.Error("declaring an expectation must change config_sha256 (it is declared intent)")
	}
	if withOne == withTwo {
		t.Error("different expectations must fingerprint differently")
	}
	// An absent expectation must canonicalize away entirely, or every
	// pre-feature scenario silently changes fingerprint on upgrade.
	if again := sha(`{"protocol":"syslog","rate":5,"window":"1s","participants":["10.42.0.1","10.42.0.2"]}`); again != bare {
		t.Errorf("absent expectation changed the fingerprint: %s vs %s", again, bare)
	}
}

// TestScenarioAPI_ExpectParticipantsReadiness covers the arm-time disclosure and
// the direction-aware diagnosis (design D5).
func TestScenarioAPI_ExpectParticipantsReadiness(t *testing.T) {
	const tail = `,"protocol":"syslog","rate":5,"window":"1s"}`

	t.Run("met_expectation_has_no_mismatch", func(t *testing.T) {
		router := scenarioAPIManager(t, 3)
		id := submitOK(t, router, `{"participants_cidr":["10.42.0.0/24"],"expect_participants":3`+tail)
		rd := armReadinessOf(t, router, id)
		if rd.ParticipantsExpected != 3 || rd.ParticipantsArmed != 3 {
			t.Fatalf("expected=%d armed=%d, want 3/3", rd.ParticipantsExpected, rd.ParticipantsArmed)
		}
		if rd.ExpectationMismatch != "" {
			t.Fatalf("met expectation should carry no mismatch, got %q", rd.ExpectationMismatch)
		}
	})

	t.Run("silent_shortfall_is_named_as_unexplained", func(t *testing.T) {
		router := scenarioAPIManager(t, 3)
		// A prefix one bit too narrow: matches .0-.1 only, so .2 and .3 are
		// missed SILENTLY — no exclusion row, which is the whole hazard.
		id := submitOK(t, router, `{"participants_cidr":["10.42.0.0/31"],"expect_participants":3`+tail)
		rd := armReadinessOf(t, router, id)
		if rd.ExcludedTotal != 0 {
			t.Fatalf("precondition: prefix misses must be silent, got excluded_total=%d", rd.ExcludedTotal)
		}
		if rd.ExpectationMismatch == "" {
			t.Fatal("a shortfall must be disclosed at arm")
		}
		if !strings.Contains(rd.ExpectationMismatch, "nothing was excluded") {
			t.Fatalf("silent shortfall must be identified as unexplained by exclusions: %q", rd.ExpectationMismatch)
		}
	})

	t.Run("explained_shortfall_points_at_exclusions", func(t *testing.T) {
		router := scenarioAPIManager(t, 3)
		manager.devicesByIP["10.42.0.2"].syslogExporter = nil // excluded, loudly
		id := submitOK(t, router, `{"participants_cidr":["10.42.0.0/24"],"expect_participants":3`+tail)
		rd := armReadinessOf(t, router, id)
		if rd.ExcludedTotal != 1 {
			t.Fatalf("precondition: want one exclusion, got %d", rd.ExcludedTotal)
		}
		if !strings.Contains(rd.ExpectationMismatch, "excluded_by_reason") {
			t.Fatalf("explained shortfall must point at the breakdown: %q", rd.ExpectationMismatch)
		}
	})

	t.Run("surplus_is_reported", func(t *testing.T) {
		router := scenarioAPIManager(t, 3)
		id := submitOK(t, router, `{"participants_cidr":["10.42.0.0/24"],"expect_participants":2`+tail)
		rd := armReadinessOf(t, router, id)
		if !strings.Contains(rd.ExpectationMismatch, "more than declared") {
			t.Fatalf("surplus must be reported as such: %q", rd.ExpectationMismatch)
		}
	})

	t.Run("rearm_reevaluates_with_no_special_path", func(t *testing.T) {
		router := scenarioAPIManager(t, 3)
		manager.devicesByIP["10.42.0.3"].syslogExporter = nil
		id := submitOK(t, router, `{"participants_cidr":["10.42.0.0/24"],"expect_participants":3`+tail)
		if rd := armReadinessOf(t, router, id); rd.ExpectationMismatch == "" {
			t.Fatal("precondition: first arm should mismatch")
		}
		// Fix the fleet, re-arm: the expectation is simply recomputed.
		manager.devicesByIP["10.42.0.3"].syslogExporter = manager.devicesByIP["10.42.0.1"].syslogExporter
		rd := armReadinessOf(t, router, id)
		if rd.ExpectationMismatch != "" || rd.ParticipantsArmed != 3 {
			t.Fatalf("re-arm after fixing the fleet should clear the mismatch: armed=%d mismatch=%q",
				rd.ParticipantsArmed, rd.ExpectationMismatch)
		}
	})

	t.Run("undeclared_omits_both_fields", func(t *testing.T) {
		router := scenarioAPIManager(t, 3)
		id := submitOK(t, router, `{"participants_cidr":["10.42.0.0/24"]`+tail)
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
		if strings.Contains(w.Body.String(), "participants_expected") ||
			strings.Contains(w.Body.String(), "expectation_mismatch") {
			t.Fatalf("undeclared expectation must add no fields: %s", w.Body.String())
		}
	})
}

// TestScenarioAPI_ExpectParticipantsStartRefusal: start enforces in both
// directions, and the refusal reuses the readiness wording verbatim (task 3.3).
func TestScenarioAPI_ExpectParticipantsStartRefusal(t *testing.T) {
	const tail = `,"protocol":"syslog","rate":5,"window":"1s"}`
	for name, body := range map[string]string{
		"shortfall": `{"participants_cidr":["10.42.0.0/31"],"expect_participants":3` + tail,
		"surplus":   `{"participants_cidr":["10.42.0.0/24"],"expect_participants":2` + tail,
	} {
		t.Run(name, func(t *testing.T) {
			router := scenarioAPIManager(t, 3)
			id := submitOK(t, router, body)
			rd := armReadinessOf(t, router, id)

			w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/start", "")
			if w.Code != http.StatusConflict {
				t.Fatalf("start = %d, want 409 (body %s)", w.Code, w.Body.String())
			}
			// One diagnosis, not two phrasings of it.
			if !strings.Contains(w.Body.String(), rd.ExpectationMismatch) {
				t.Fatalf("start refusal should carry the readiness wording.\nreadiness: %q\nstart:     %s",
					rd.ExpectationMismatch, w.Body.String())
			}
			// Re-armable, and no run happened.
			if rd2 := armReadinessOf(t, router, id); rd2.Phase != string(phaseArmed) {
				t.Fatalf("phase after refused start = %s, want armed", rd2.Phase)
			}
		})
	}
}

// TestScenarioController_ExpectParticipantsGapLoss is the reason the guard needs
// BOTH FR40 sites: membership lost in the arm→start gap is invisible to the
// pre-freeze check, so only the post-prune one catches this wrong-sized run.
// No misdeclaration is involved.
func TestScenarioController_ExpectParticipantsGapLoss(t *testing.T) {
	sm, _ := scenarioTestManager(t, 3)
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(&Scenario{
		ParticipantsCIDR:   []string{"10.42.0.0/24"},
		ExpectParticipants: intPtr(3),
		Protocol:           "syslog",
		Rate:               5,
		Window:             time.Second,
	}, "s-000001"); err != nil {
		t.Fatal(err)
	}
	armed, _, err := c.Arm()
	if err != nil || armed != 3 {
		t.Fatalf("arm: armed=%d err=%v, want 3", armed, err)
	}

	// Delete a participant AFTER arm — the pre-freeze check still sees 3.
	sm.mu.Lock()
	delete(sm.devicesByIP, "10.42.0.2")
	sm.mu.Unlock()

	err = c.Start(context.Background())
	if err == nil {
		t.Fatal("start with membership lost in the gap should be refused")
	}
	if !strings.Contains(err.Error(), "expected 3 participants, 2 armed") {
		t.Fatalf("refusal should report the authoritative post-prune count: %v", err)
	}
	// Rolled back cleanly: re-armable, not running, fleet not left frozen.
	c.mu.Lock()
	phase := c.phase
	c.mu.Unlock()
	if phase != phaseArmed {
		t.Fatalf("phase = %s after refused start, want armed", phase)
	}
	if err := sm.freezeFleet("probe"); err != nil {
		t.Fatalf("fleet left frozen by a refused start: %v", err)
	}
	sm.unfreezeFleet()
}

// TestScenarioController_ExpectParticipantsPreFreeze asserts the OTHER site: a
// mismatch visible from arm-time membership is refused before anything moves,
// so the common case never touches the rollback path (design D3).
func TestScenarioController_ExpectParticipantsPreFreeze(t *testing.T) {
	sm, _ := scenarioTestManager(t, 3)
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(&Scenario{
		ParticipantsCIDR:   []string{"10.42.0.0/24"},
		ExpectParticipants: intPtr(2), // surplus: 3 will arm
		Protocol:           "syslog",
		Rate:               5,
		Window:             time.Second,
	}, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("surplus should be refused at start")
	}
	// Nothing moved: still armed, no transition recorded, fleet never frozen.
	c.mu.Lock()
	phase, transitions := c.phase, c.transitions
	c.mu.Unlock()
	if phase != phaseArmed {
		t.Fatalf("phase = %s, want armed", phase)
	}
	for _, tr := range transitions {
		if tr.Phase == phaseRunning {
			t.Errorf("pre-freeze refusal must not publish a running transition: %+v", transitions)
		}
	}
	if err := sm.freezeFleet("probe"); err != nil {
		t.Fatalf("fleet frozen by a pre-freeze refusal: %v", err)
	}
	sm.unfreezeFleet()
}

// TestScenarioController_StartPruneReinstalls: a device deleted and re-created
// at the same IP in the arm→start gap is a FRESH DeviceSimulator whose exporter
// carries no participation handle — arm stored that on the old object. Merely
// testing for an exporter would count it toward the cardinality while it ran
// outside the scenario and never reached its ledger. The prune re-installs, so
// the count stays honest AND the device actually participates.
func TestScenarioController_StartPruneReinstalls(t *testing.T) {
	sm, _ := scenarioTestManager(t, 2)
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(&Scenario{
		ParticipantsCIDR:   []string{"10.42.0.0/24"},
		ExpectParticipants: intPtr(2),
		Protocol:           "syslog",
		Rate:               5,
		Window:             time.Second,
	}, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}

	// Swap in a replacement device at the same IP, as a delete+create would.
	fresh, _ := scenarioTestManager(t, 2)
	replacement := fresh.devicesByIP["10.42.0.2"]
	if replacement.syslogExporter.scenPart.Load() != nil {
		t.Fatal("precondition: a fresh device must carry no participation handle")
	}
	sm.mu.Lock()
	sm.devicesByIP["10.42.0.2"] = replacement
	sm.mu.Unlock()

	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _, _ = c.Stop() }()

	// The replacement must have been re-armed, not merely counted.
	if replacement.syslogExporter.scenPart.Load() == nil {
		t.Error("re-created device was counted toward the expectation but never armed — its emissions would miss the ledger")
	}
}

// TestScenarioController_StartPruneDetaches: when a still-live device fails
// re-arming, its handle from the first arm must be released. Every other detach
// path iterates c.parts, so a handle orphaned here is unreachable forever, and
// once the gate reaches a terminal phase it mutes that device's exporter for the
// rest of the process.
// It reuses armFixtureFlow, built for the re-arm form of this same leak: an
// exporter that stays LIVE while failing installScenPart (the in-process
// stand-in for a dial-out stream blipping during a collector outage). The
// syslog shape cannot express it — there, failing means the exporter is nil, so
// the handle is already unreachable from the device either way.
func TestScenarioController_StartPruneDetaches(t *testing.T) {
	sm, _, fe := armFixtureFlow(t, "10.42.0.1")
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(&Scenario{
		Participants: []string{"10.42.0.1"},
		Protocol:     "netflow9",
		Rate:         5,
		Window:       time.Second,
	}, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	if fe.scenPart.Load() == nil {
		t.Fatal("precondition: arm should have installed a handle")
	}

	// Fail re-arming while the exporter stays live and reachable.
	fe.protocol = "ipfix"

	// The only participant drops, so start refuses — but the detach is the
	// point: the handle must not survive on the live exporter.
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("start should be refused once the only participant drops")
	}
	if fe.scenPart.Load() != nil {
		t.Error("handle left installed on a dropped-but-live exporter; every detach path iterates c.parts, so nothing can ever clear it")
	}
}

// TestScenarioController_ExpectParticipantsSchedule: an absolute-T0 schedule is
// refused immediately when the declared cardinality already fails, rather than
// deferring the refusal to the moment the timer fires.
func TestScenarioController_ExpectParticipantsSchedule(t *testing.T) {
	sm, _ := scenarioTestManager(t, 3)
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(&Scenario{
		ParticipantsCIDR:   []string{"10.42.0.0/24"},
		ExpectParticipants: intPtr(2), // 3 will arm
		Protocol:           "syslog",
		Rate:               5,
		Window:             time.Second,
	}, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	err := c.ScheduleStart(context.Background(), time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("scheduling against a set that fails the expectation should be refused now, not at T0")
	}
	if !strings.Contains(err.Error(), "more than declared") {
		t.Fatalf("refusal should carry the same diagnosis: %v", err)
	}
}

// TestScenarioController_ExpectParticipantsMet: the happy path still starts and
// runs, so the guard is not simply refusing everything.
func TestScenarioController_ExpectParticipantsMet(t *testing.T) {
	sm, _ := scenarioTestManager(t, 3)
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(&Scenario{
		ParticipantsCIDR:   []string{"10.42.0.0/24"},
		ExpectParticipants: intPtr(3),
		Protocol:           "syslog",
		Rate:               5,
		Window:             time.Second,
	}, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("met expectation should start: %v", err)
	}
	if _, err := c.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
}
