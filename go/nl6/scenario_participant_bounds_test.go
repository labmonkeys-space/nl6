/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// scenario_participant_bounds_test.go — the wire-level participant bounds
// (issue #382). Every fleet-scale scenario test before this one constructed
// gates and ledgers in-process and never crossed the HTTP boundary, so the
// 64 KiB submit-body cap capped participants at ~4,400 while the report path
// was benchmarked at 30,000. These tests submit through the real router, which
// is the only place that gap was observable.
//
// Note these need no fleet: submit performs STRUCTURAL validation only —
// participants resolve against live devices at arm (two-stage validation), so
// a 30k-participant submit against a one-device manager is the honest test of
// the body cap and the count bound.

// participantIP maps i to a unique IPv4 in 10/8, valid past 16M so that
// ceiling-sized and over-cap lists carry no aliased entries.
func participantIP(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
}

// participantBody renders a valid syslog submit body naming n participants.
func participantBody(n int) string {
	var b strings.Builder
	b.Grow(n*17 + 128)
	b.WriteString(`{"participants":[`)
	for i := 1; i <= n; i++ {
		if i > 1 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(participantIP(i))
		b.WriteByte('"')
	}
	b.WriteString(`],"protocol":"syslog","rate":1,"window":"1s","seed":42}`)
	return b.String()
}

// TestScenarioAPI_SubmitFleetScaleParticipants is the regression for #382: a
// 30,000-participant submit (~450 KB) must be accepted over HTTP. Under the
// old 64 KiB cap this returned 400 "http: request body too large" at ~4,400.
func TestScenarioAPI_SubmitFleetScaleParticipants(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	body := participantBody(30000)
	if len(body) <= 64<<10 {
		t.Fatalf("body is %d bytes, expected to exceed the old 64 KiB cap — test lost its point", len(body))
	}

	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("30k-participant submit status = %d, want 202 (body %s)", w.Code, w.Body.String())
	}
	var resp struct {
		ID           string `json:"id"`
		ConfigSHA256 string `json:"config_sha256"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("submit body: %v", err)
	}
	// A non-empty fingerprint proves configSHA256's canonicalization round-trip
	// (marshal → map → marshal) survived a 450 KB body.
	if resp.ID == "" || resp.ConfigSHA256 == "" {
		t.Fatalf("missing id/config_sha256: %s", w.Body.String())
	}
	t.Logf("accepted %d-byte body naming 30000 participants", len(body))
}

// TestScenarioAPI_ParticipantCeiling pins the count bound as the binding limit
// at scale: a ceiling-sized list is accepted, one more is refused by COUNT
// (not by body size — the list is ~1.5 MB, under the derived cap), and the
// refusal costs no scenario ID.
func TestScenarioAPI_ParticipantCeiling(t *testing.T) {
	// The derived-cap invariant (design D1): the body cap must admit a
	// ceiling-sized participant list, or the count bound is unreachable and
	// operators get a body-size error instead of a count error. Fails if
	// someone re-hardcodes scenarioMaxBody to a literal.
	if scenarioMaxBody < scenarioMaxParticipants*scenarioParticipantWireBytes {
		t.Fatalf("scenarioMaxBody = %d cannot hold %d worst-case participants (%d bytes)",
			scenarioMaxBody, scenarioMaxParticipants, scenarioMaxParticipants*scenarioParticipantWireBytes)
	}

	t.Run("at_ceiling_accepted", func(t *testing.T) {
		router := scenarioAPIManager(t, 1)
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", participantBody(scenarioMaxParticipants))
		if w.Code != http.StatusAccepted {
			t.Fatalf("ceiling-sized submit status = %d, want 202 (body %s)", w.Code, truncate(w.Body.String()))
		}
	})

	t.Run("over_ceiling_refused_by_count", func(t *testing.T) {
		router := scenarioAPIManager(t, 1)
		body := participantBody(scenarioMaxParticipants + 1)
		if len(body) > scenarioMaxBody {
			t.Fatalf("body is %d bytes, over the %d cap — this would test the body cap, not the count bound",
				len(body), scenarioMaxBody)
		}
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("over-ceiling submit status = %d, want 400 (body %s)", w.Code, truncate(w.Body.String()))
		}
		var errBody map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil {
			t.Fatalf("error body: %v", err)
		}
		if !strings.Contains(errBody["error"], fmt.Sprint(scenarioMaxParticipants)) {
			t.Fatalf("error %q does not name the %d ceiling", errBody["error"], scenarioMaxParticipants)
		}

		// No ID was allocated: the next valid submit gets the FIRST id, which
		// also proves the single-active slot was never occupied.
		w = doReq(t, router, http.MethodPost, "/api/v1/scenarios", validScenarioBody)
		if w.Code != http.StatusAccepted {
			t.Fatalf("follow-up submit status = %d, want 202 (body %s)", w.Code, w.Body.String())
		}
		var resp struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.ID != "s-000001" {
			t.Fatalf("follow-up id = %q, want s-000001 (a rejected submit consumed an ID)", resp.ID)
		}
	})
}

// TestScenarioAPI_OverCapBodyNamesTheCap asserts the over-limit 400 is
// actionable: Go's bare "http: request body too large" named neither the
// limit, the ceiling, nor the field, which is what made #382 require reading
// the source to diagnose.
func TestScenarioAPI_OverCapBodyNamesTheCap(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	// Grow the list until the RENDERED body exceeds the cap, rather than
	// deriving a count from an estimated per-entry cost — the estimate is the
	// kind of thing that silently stops tripping the limit when either
	// constant moves. MaxBytesReader fires during decode, before Validate, so
	// the participant count here is irrelevant; only the byte count matters.
	n := scenarioMaxBody / 14
	body := participantBody(n)
	for len(body) <= scenarioMaxBody {
		n += 8192
		body = participantBody(n)
	}

	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("over-cap submit status = %d, want 400 (body %s)", w.Code, truncate(w.Body.String()))
	}
	var errBody map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("error body: %v", err)
	}
	if got := errBody["field"]; got != "participants" {
		t.Fatalf("field = %q, want participants", got)
	}
	if strings.Contains(errBody["error"], "http: request body too large") {
		t.Fatalf("error is still Go's transport message: %q", errBody["error"])
	}
	for _, want := range []string{fmt.Sprint(scenarioMaxBody), fmt.Sprint(scenarioMaxParticipants)} {
		if !strings.Contains(errBody["error"], want) {
			t.Fatalf("error %q does not name %s", errBody["error"], want)
		}
	}
}

// TestScenarioAPI_ParticipantAddressGrammar covers the IPv4-only narrowing: an
// IPv6 participant could only ever become a "device not found" exclusion on
// this v4-only fleet, so it is refused at submit with a reason.
func TestScenarioAPI_ParticipantAddressGrammar(t *testing.T) {
	cases := []struct {
		name        string
		participant string
		wantSubstr  string
	}{
		{"ipv6_full", "2001:db8::1", "IPv4 dotted quad"},
		{"ipv6_loopback", "::1", "IPv4 dotted quad"},
		{"malformed", "not-an-ip", "not a valid IP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := scenarioAPIManager(t, 1)
			body := fmt.Sprintf(`{"participants":[%q],"protocol":"syslog","rate":5,"window":"1s"}`, tc.participant)
			w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
			}
			var errBody map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil {
				t.Fatalf("error body: %v", err)
			}
			if !strings.Contains(errBody["error"], tc.wantSubstr) {
				t.Fatalf("error %q does not contain %q", errBody["error"], tc.wantSubstr)
			}
			if !strings.Contains(errBody["error"], tc.participant) {
				t.Fatalf("error %q does not name the offending participant", errBody["error"])
			}
		})
	}
}

// TestScenarioValidate_BoundsGuardInProcessPath asserts the bounds live in
// Validate, not the handler, so direct construction (tests, future callers)
// is bounded too — the reason design D3 put them there.
func TestScenarioValidate_BoundsGuardInProcessPath(t *testing.T) {
	base := func(participants []string) *Scenario {
		return &Scenario{Participants: participants, Protocol: "syslog", Rate: 1, Window: scenarioMaxWindow / 2}
	}

	over := make([]string, scenarioMaxParticipants+1)
	for i := range over {
		over[i] = participantIP(i + 1)
	}
	if err := base(over).Validate(); err == nil {
		t.Fatalf("Validate accepted %d participants, want rejection at %d", len(over), scenarioMaxParticipants)
	}

	if err := base([]string{"2001:db8::1"}).Validate(); err == nil {
		t.Fatal("Validate accepted an IPv6 participant")
	}

	// The ceiling itself stays valid — the bound is a ceiling, not an off-by-one.
	at := over[:scenarioMaxParticipants]
	if err := base(at).Validate(); err != nil {
		t.Fatalf("Validate rejected a ceiling-sized list: %v", err)
	}
}

// truncate keeps a failure message readable when the body echoes a huge list.
func truncate(s string) string {
	if len(s) <= 200 {
		return s
	}
	return s[:200] + "…"
}
