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
	"time"
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

// participantIP maps i to a distinct IPv4 in 10/8. Three masked octets give
// exactly 2^24 = 16,777,216 distinct values, so entries are unique for
// i < 16,777,216 and alias beyond that — well past any list this file builds,
// but the bound is real and matters to whoever next raises the ceiling.
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
	t.Run("at_ceiling_accepted", func(t *testing.T) {
		router := scenarioAPIManager(t, 1)
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", participantBody(scenarioMaxParticipants))
		if w.Code != http.StatusAccepted {
			t.Fatalf("ceiling-sized submit status = %d, want 202 (body %s)", w.Code, truncateBody(w.Body.String()))
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
			t.Fatalf("over-ceiling submit status = %d, want 400 (body %s)", w.Code, truncateBody(w.Body.String()))
		}
		var errBody map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil {
			t.Fatalf("error body: %v", err)
		}
		// Assert the message names the ceiling AND the field in prose. Both
		// error paths contain "100000", so matching the number alone would be
		// satisfied by the body-cap message too — and prose is the only channel
		// this 400 has, since Validate errors carry no "field" key (design D3).
		if !strings.Contains(errBody["error"], fmt.Sprint(scenarioMaxParticipants)) {
			t.Fatalf("error %q does not name the %d ceiling", errBody["error"], scenarioMaxParticipants)
		}
		if !strings.Contains(errBody["error"], "participants") {
			t.Fatalf("error %q does not name the participants field", errBody["error"])
		}
		if !strings.Contains(errBody["error"], "exceeding") {
			t.Fatalf("error %q is not the count-bound message (refusal came from the wrong path)", errBody["error"])
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
// actionable: Go's bare "http: request body too large" named neither the limit
// nor the ceiling, which is what made #382 require reading the source to
// diagnose. It also asserts the response does NOT attribute a field, because
// *http.MaxBytesError cannot know which one was oversized.
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
		t.Fatalf("over-cap submit status = %d, want 400 (body %s)", w.Code, truncateBody(w.Body.String()))
	}
	var errBody map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("error body: %v", err)
	}
	// No field attribution: *http.MaxBytesError cannot say which field made the
	// body oversized, so claiming one would misdirect an operator whose 2 MB
	// `window` string tripped the cap on a one-participant request.
	if got, ok := errBody["field"]; ok {
		t.Fatalf("over-cap 400 carries field = %q; MaxBytesError cannot attribute a field", got)
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
		// The IPv4-mapped family is the case net.IP.To4() ACCEPTS: it is
		// non-nil for all three spellings below, so a To4()-based check admits
		// them, they canonicalise to a dotted quad, and then miss Arm's
		// devicesByIP lookup (keyed by the canonical form, looked up by the raw
		// request string) — the exact useless exclusion this check prevents.
		// The expanded form also costs 48 wire bytes against an 18-byte premise.
		{"ipv4_mapped_short", "::ffff:10.42.0.1", "IPv4 dotted quad"},
		{"ipv4_mapped_max", "::ffff:255.255.255.255", "IPv4 dotted quad"},
		{"ipv4_mapped_expanded", "0000:0000:0000:0000:0000:ffff:255.255.255.255", "IPv4 dotted quad"},
		{"malformed", "not-an-ip", "not a valid IP"},
	}
	t.Run("duplicate_rejected", func(t *testing.T) {
		// A repeat is refused, not collapsed: the ledger reconciles per source
		// IP, so a device named twice is one source and the second entry has no
		// meaning. Rejecting also keeps config_sha256 honest — otherwise two
		// distinguishable submits would produce identical runs.
		router := scenarioAPIManager(t, 1)
		body := `{"participants":["10.42.0.1","10.42.0.2","10.42.0.1"],"protocol":"syslog","rate":5,"window":"1s"}`
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
		}
		var errBody map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil {
			t.Fatalf("error body: %v", err)
		}
		for _, want := range []string{"10.42.0.1", "more than once"} {
			if !strings.Contains(errBody["error"], want) {
				t.Fatalf("error %q does not contain %q", errBody["error"], want)
			}
		}
	})
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

	if err := base([]string{"10.42.0.1", "10.42.0.1"}).Validate(); err == nil {
		t.Fatal("Validate accepted a duplicated participant")
	}

	// The ceiling itself stays valid — the bound is a ceiling, not an off-by-one.
	at := over[:scenarioMaxParticipants]
	if err := base(at).Validate(); err != nil {
		t.Fatalf("Validate rejected a ceiling-sized list: %v", err)
	}
}

// TestScenarioBodyCapAdmitsCeilingSizedList is the BEHAVIOURAL form of the
// derived-cap invariant (design D1). The arithmetic form —
// `scenarioMaxBody >= scenarioMaxParticipants*scenarioParticipantWireBytes` —
// compares two compile-time constants where the left is defined as the right
// plus a positive addend, so it is unfalsifiable by any input and cannot catch
// the failure that actually matters: widening the accepted address grammar
// silently falsifies the 18-byte premise while the arithmetic still checks out.
// (That is not hypothetical — a To4()-based grammar admitted 48-byte entries.)
//
// So assert the premise and the consequence instead: nothing longer than
// scenarioParticipantWireBytes is accepted, and a ceiling-sized list of the
// longest accepted address fits under the cap with the envelope budget intact.
func TestScenarioBodyCapAdmitsCeilingSizedList(t *testing.T) {
	const worst = "255.255.255.255" // longest accepted participant
	validate := func(p string) error {
		return (&Scenario{Participants: []string{p}, Protocol: "syslog", Rate: 1, Window: time.Second}).Validate()
	}

	if err := validate(worst); err != nil {
		t.Fatalf("Validate rejected %q, which the wire-cost premise assumes is accepted: %v", worst, err)
	}
	if got := len(worst) + 3; got != scenarioParticipantWireBytes {
		t.Fatalf("%q costs %d compact-JSON bytes but scenarioParticipantWireBytes = %d", worst, got, scenarioParticipantWireBytes)
	}
	// Anything longer must be rejected, or the premise is false.
	for _, longer := range []string{
		"::ffff:255.255.255.255",                        // 25 bytes
		"0:0:0:0:0:ffff:255.255.255.255",                // 33 bytes
		"0000:0000:0000:0000:0000:ffff:255.255.255.255", // 48 bytes
	} {
		if err := validate(longer); err == nil {
			t.Fatalf("Validate accepted %q (%d compact-JSON bytes), breaking the %d-byte premise behind scenarioMaxBody",
				longer, len(longer)+3, scenarioParticipantWireBytes)
		}
	}

	// The consequence, asserted END TO END rather than arithmetically: a real
	// ceiling-sized worst-case submit is accepted by the handler. Given the
	// premise above, comparing len(body) to the cap would only restate the
	// constants' definition; putting the body through MaxBytesReader and the
	// decoder is what actually proves the derivation admits it.
	router := scenarioAPIManager(t, 1)
	var b strings.Builder
	b.WriteString(`{"participants":[`)
	for i := 0; i < scenarioMaxParticipants; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		// Distinct addresses (duplicates are rejected) that are all exactly
		// worst-case length: three variable octets held in 100..255 keep every
		// octet at 3 digits, and 156^3 distinct values covers the ceiling.
		fmt.Fprintf(&b, `"255.%d.%d.%d"`, 100+i/(156*156), 100+(i/156)%156, 100+i%156)
	}
	b.WriteString(`],"protocol":"syslog","rate":1,"window":"1s","seed":42}`)
	body := b.String()
	if len(body) > scenarioMaxBody {
		t.Fatalf("ceiling-sized worst-case body is %d bytes, over the %d cap", len(body), scenarioMaxBody)
	}
	if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body); w.Code != http.StatusAccepted {
		t.Fatalf("ceiling-sized worst-case submit (%d bytes) status = %d, want 202 (body %s)",
			len(body), w.Code, truncateBody(w.Body.String()))
	}
}

// TestScenarioAPI_BodyCapBoundary pins the exact edge. MaxBytesReader admits n
// and fails at n+1, and n is the one size the whole derivation exists to admit —
// every other test here probes strictly over the cap, so an off-by-one that
// rejected a body of exactly scenarioMaxBody would have gone unnoticed.
func TestScenarioAPI_BodyCapBoundary(t *testing.T) {
	// Pad with insignificant whitespace (legal JSON) to hit an exact byte count.
	build := func(total int) string {
		const head = `{"participants":["10.42.0.1"],"protocol":"syslog","rate":1,"window":"1s"`
		const tail = `}`
		pad := total - len(head) - len(tail)
		if pad < 0 {
			t.Fatalf("cannot build a %d-byte body; the minimum is %d", total, len(head)+len(tail))
		}
		return head + strings.Repeat(" ", pad) + tail
	}

	t.Run("exactly_at_cap_accepted", func(t *testing.T) {
		router := scenarioAPIManager(t, 1)
		body := build(scenarioMaxBody)
		if len(body) != scenarioMaxBody {
			t.Fatalf("body is %d bytes, want exactly %d", len(body), scenarioMaxBody)
		}
		if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body); w.Code != http.StatusAccepted {
			t.Fatalf("body of exactly %d bytes: status = %d, want 202 (body %s)",
				scenarioMaxBody, w.Code, truncateBody(w.Body.String()))
		}
	})

	t.Run("one_over_cap_refused", func(t *testing.T) {
		router := scenarioAPIManager(t, 1)
		body := build(scenarioMaxBody + 1)
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body of %d bytes: status = %d, want 400", len(body), w.Code)
		}
		var errBody map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &errBody)
		if !strings.Contains(errBody["error"], fmt.Sprint(scenarioMaxBody)) {
			t.Fatalf("error %q does not name the cap", errBody["error"])
		}
	})
}

// truncateBody keeps a failure message readable when the body echoes a huge
// list. Named for its use, not `truncate`: package main here spans dozens of
// files and a bare generic helper is a redeclaration hazard.
func truncateBody(s string) string {
	if len(s) <= 200 {
		return s
	}
	return s[:200] + "…"
}
