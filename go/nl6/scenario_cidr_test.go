/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// deleteScenario frees the single-active slot between submits in one test.
func deleteScenario(t *testing.T, router http.Handler, id string) {
	t.Helper()
	if w := doReq(t, router, http.MethodDelete, "/api/v1/scenarios/"+id, ""); w.Code != http.StatusOK {
		t.Fatalf("delete = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
}

// TestScenarioAPI_CIDRSubmitAccepted covers the submit-time ACCEPT cases the
// 400 table cannot: cross-world overlap (assertion semantics, design D3), a
// /32 prefix (the open-world spelling of one address), and disjoint prefixes.
func TestScenarioAPI_CIDRSubmitAccepted(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	for _, tc := range []struct{ name, body string }{
		{"covered_explicit_ip", `{"participants":["10.42.1.5"],"participants_cidr":["10.42.1.0/24"],"protocol":"syslog","rate":5,"window":"1s"}`},
		{"slash32_prefix", `{"participants_cidr":["10.42.1.5/32"],"protocol":"syslog","rate":5,"window":"1s"}`},
		{"disjoint_prefixes", `{"participants_cidr":["10.42.0.0/18","10.43.1.0/24"],"protocol":"syslog","rate":5,"window":"1s"}`},
		{"cidr_only", `{"participants_cidr":["10.42.0.0/16"],"protocol":"syslog","rate":5,"window":"1s"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := submitOK(t, router, tc.body)
			deleteScenario(t, router, id)
		})
	}
}

// TestScenarioAPI_CIDRPrefixCap: the 1,024-prefix bound is enforced (and the
// cap itself is reachable), mirroring the participant-ceiling contract shape.
func TestScenarioAPI_CIDRPrefixCap(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	prefixes := func(n int) string {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			// Disjoint /24s: 10.(i/256).(i%256).0/24 — i < 1281 stays in range.
			fmt.Fprintf(&sb, "%q", fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		}
		return sb.String()
	}
	body := func(n int) string {
		return `{"participants_cidr":[` + prefixes(n) + `],"protocol":"syslog","rate":5,"window":"1s"}`
	}

	id := submitOK(t, router, body(scenarioMaxPrefixes)) // at the cap: valid
	deleteScenario(t, router, id)

	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body(scenarioMaxPrefixes+1))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("over-cap submit = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "participants_cidr") || !strings.Contains(w.Body.String(), "1024") {
		t.Fatalf("over-cap error should name the field and the cap: %s", w.Body.String())
	}
}

// TestScenarioAPI_CIDRFingerprint: absent, null, and [] spellings of each
// selector field canonicalize identically (design D6), and the presence of a
// real participants_cidr value changes the fingerprint.
func TestScenarioAPI_CIDRFingerprint(t *testing.T) {
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

	// Unused participants_cidr: absent vs null vs [].
	base := sha(`{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"1s"}`)
	for name, body := range map[string]string{
		"null_cidr":  `{"participants":["10.42.0.1"],"participants_cidr":null,"protocol":"syslog","rate":5,"window":"1s"}`,
		"empty_cidr": `{"participants":["10.42.0.1"],"participants_cidr":[],"protocol":"syslog","rate":5,"window":"1s"}`,
	} {
		if got := sha(body); got != base {
			t.Errorf("%s fingerprint = %s, want %s (spellings of an unused selector must collapse)", name, got, base)
		}
	}

	// Unused participants: absent vs null vs [].
	cidrBase := sha(`{"participants_cidr":["10.42.0.0/24"],"protocol":"syslog","rate":5,"window":"1s"}`)
	for name, body := range map[string]string{
		"null_participants":  `{"participants":null,"participants_cidr":["10.42.0.0/24"],"protocol":"syslog","rate":5,"window":"1s"}`,
		"empty_participants": `{"participants":[],"participants_cidr":["10.42.0.0/24"],"protocol":"syslog","rate":5,"window":"1s"}`,
	} {
		if got := sha(body); got != cidrBase {
			t.Errorf("%s fingerprint = %s, want %s (spellings of an unused selector must collapse)", name, got, cidrBase)
		}
	}

	// A populated participants_cidr is fingerprinted.
	if with := sha(`{"participants":["10.42.0.1"],"participants_cidr":["10.42.0.0/24"],"protocol":"syslog","rate":5,"window":"1s"}`); with == base {
		t.Errorf("fingerprint ignores participants_cidr: %s", with)
	}
}

// armReadinessOf arms via the API and decodes the readiness response.
func armReadinessOf(t *testing.T, router http.Handler, id string) readinessResponse {
	t.Helper()
	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
	if w.Code != http.StatusOK {
		t.Fatalf("arm = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	var rd readinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &rd); err != nil {
		t.Fatal(err)
	}
	return rd
}

// TestScenarioAPI_CIDRArmResolution covers the arm-time union semantics:
// subnet selection, union with the explicit list, the covered explicit entry
// arming exactly once, its loud miss, and a /32 prefix's silent miss.
func TestScenarioAPI_CIDRArmResolution(t *testing.T) {
	// Devices 10.42.0.1 .. 10.42.0.3.
	newRouter := func(t *testing.T) http.Handler { return scenarioAPIManager(t, 3) }
	const tail = `,"protocol":"syslog","rate":5,"window":"1s"}`

	t.Run("subnet_selection", func(t *testing.T) {
		router := newRouter(t)
		// 10.42.0.2/31 covers .2 and .3; .1 is not a participant.
		id := submitOK(t, router, `{"participants_cidr":["10.42.0.2/31"]`+tail)
		rd := armReadinessOf(t, router, id)
		if rd.ParticipantsArmed != 2 || rd.ExcludedTotal != 0 {
			t.Fatalf("armed=%d excluded=%d, want 2/0", rd.ParticipantsArmed, rd.ExcludedTotal)
		}
	})

	t.Run("union_with_explicit", func(t *testing.T) {
		router := newRouter(t)
		id := submitOK(t, router, `{"participants":["10.42.0.1"],"participants_cidr":["10.42.0.2/31"]`+tail)
		rd := armReadinessOf(t, router, id)
		if rd.ParticipantsArmed != 3 {
			t.Fatalf("armed=%d, want 3 (1 explicit + 2 prefix)", rd.ParticipantsArmed)
		}
	})

	t.Run("covered_explicit_armed_once", func(t *testing.T) {
		router := newRouter(t)
		// /29 covers .0-.7, i.e. all three devices including the explicit .1.
		id := submitOK(t, router, `{"participants":["10.42.0.1"],"participants_cidr":["10.42.0.0/29"]`+tail)
		rd := armReadinessOf(t, router, id)
		if rd.ParticipantsArmed != 3 || rd.ExcludedTotal != 0 {
			t.Fatalf("armed=%d excluded=%d, want 3/0 (covered explicit must not double-install)", rd.ParticipantsArmed, rd.ExcludedTotal)
		}
	})

	t.Run("covered_explicit_misses_loudly", func(t *testing.T) {
		router := newRouter(t)
		// .9 has no device; the covering /29 (.8-.15) matches nothing either.
		id := submitOK(t, router, `{"participants":["10.42.0.9"],"participants_cidr":["10.42.0.8/29"]`+tail)
		rd := armReadinessOf(t, router, id)
		if rd.ParticipantsArmed != 0 || rd.ExcludedTotal != 1 {
			t.Fatalf("armed=%d excluded=%d, want 0/1", rd.ParticipantsArmed, rd.ExcludedTotal)
		}
		if len(rd.Excluded) != 1 || rd.Excluded[0].Device != "10.42.0.9" {
			t.Fatalf("excluded rows = %+v, want the explicit loud miss for 10.42.0.9", rd.Excluded)
		}
	})

	t.Run("slash32_misses_silently_then_start_refused", func(t *testing.T) {
		router := newRouter(t)
		id := submitOK(t, router, `{"participants_cidr":["10.42.0.9/32"]`+tail)
		rd := armReadinessOf(t, router, id)
		if rd.ParticipantsArmed != 0 || rd.ExcludedTotal != 0 || len(rd.Excluded) != 0 {
			t.Fatalf("armed=%d excluded_total=%d rows=%d, want 0/0/0 (prefix non-matches are silent)",
				rd.ParticipantsArmed, rd.ExcludedTotal, len(rd.Excluded))
		}
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/start", "")
		if w.Code != http.StatusConflict {
			t.Fatalf("start at 0 armed = %d, want 409 (FR40)", w.Code)
		}
	})

	t.Run("matched_but_unfit_is_excluded", func(t *testing.T) {
		router := newRouter(t)
		manager.devicesByIP["10.42.0.2"].syslogExporter = nil
		id := submitOK(t, router, `{"participants_cidr":["10.42.0.0/29"]`+tail)
		rd := armReadinessOf(t, router, id)
		if rd.ParticipantsArmed != 2 || rd.ExcludedTotal != 1 {
			t.Fatalf("armed=%d excluded=%d, want 2/1", rd.ParticipantsArmed, rd.ExcludedTotal)
		}
		if len(rd.Excluded) != 1 || rd.Excluded[0].Device != "10.42.0.2" {
			t.Fatalf("excluded rows = %+v, want the unfit 10.42.0.2 (matched devices are loud)", rd.Excluded)
		}
	})
}

// TestScenarioAPI_CIDRArmDeterministic: two arms against an identical fleet
// produce byte-identical readiness — including the ORDER of excluded rows,
// which would be map-iteration-random without the sorted install pass (D4).
func TestScenarioAPI_CIDRArmDeterministic(t *testing.T) {
	router := scenarioAPIManager(t, 40)
	// Make 30 prefix-matched devices unfit so the excluded rows exercise order.
	for i := 5; i < 35; i++ {
		manager.devicesByIP[fmt.Sprintf("10.42.0.%d", i)].syslogExporter = nil
	}
	id := submitOK(t, router, `{"participants_cidr":["10.42.0.0/16"],"protocol":"syslog","rate":5,"window":"1s"}`)

	armBody := func() string {
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
		if w.Code != http.StatusOK {
			t.Fatalf("arm = %d (body %s)", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	a, b := armBody(), armBody()
	if a != b {
		t.Fatalf("re-arm against an identical fleet is not reproducible:\n%s\nvs\n%s", a, b)
	}
	var rd readinessResponse
	_ = json.Unmarshal([]byte(a), &rd)
	if rd.ParticipantsArmed != 10 || rd.ExcludedTotal != 30 {
		t.Fatalf("armed=%d excluded=%d, want 10/30", rd.ParticipantsArmed, rd.ExcludedTotal)
	}
	// Sorted address order, not lexical: 10.42.0.5 first, 10.42.0.34 last.
	if rd.Excluded[0].Device != "10.42.0.5" || rd.Excluded[len(rd.Excluded)-1].Device != "10.42.0.34" {
		t.Fatalf("excluded rows not in address order: first=%s last=%s",
			rd.Excluded[0].Device, rd.Excluded[len(rd.Excluded)-1].Device)
	}
}

// growFleetPastCeiling adds enough bare devices to push any 10.0.0.0/8 match
// over scenarioMaxParticipants. The count-only pass reads devicesByIP
// membership, so exporter fitness is irrelevant to the ceiling.
func growFleetPastCeiling(sm *SimulatorManager) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for i := 0; i < scenarioMaxParticipants; i++ {
		ip := net.IPv4(10, byte(50+i/65536), byte(i/256%256), byte(i%256)).String()
		sm.devicesByIP[ip] = &DeviceSimulator{ID: "bare-" + ip, IP: net.ParseIP(ip)}
	}
}

// ceilingScenario is the over-ceiling-capable spec shared by the two refusal
// tests: one prefix wide enough to sweep the grown fleet.
func ceilingScenario() *Scenario {
	return &Scenario{
		ParticipantsCIDR: []string{"10.0.0.0/8"},
		Protocol:         "syslog",
		Rate:             5,
		Window:           time.Second,
	}
}

// TestScenarioController_CIDRCeilingRefusalPrecedesTransition: an over-ceiling
// FIRST arm must not move the scenario out of `submitted`. transitionLocked is
// itself a mutation (phase + the transition log the status endpoint publishes),
// so a refusal ordered after it would park the scenario in `armed` with zero
// parts — and the next start would report "0/N armed" instead of "arm first"
// (design D5: the decision precedes EVERY mutation, transition included). The
// re-arm test below cannot catch this: armed→armed returns early without
// mutating, so only the first-arm path exercises the ordering.
func TestScenarioController_CIDRCeilingRefusalPrecedesTransition(t *testing.T) {
	sm, _ := scenarioTestManager(t, 2)
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(ceilingScenario(), "s-000001"); err != nil {
		t.Fatal(err)
	}
	growFleetPastCeiling(sm)

	if _, _, err := c.Arm(); err == nil {
		t.Fatal("over-ceiling first arm succeeded, want wholesale refusal")
	}
	if got := c.Phase(); got != phaseSubmitted {
		t.Fatalf("phase = %s after a refused first arm, want submitted", got)
	}
	c.mu.Lock()
	for _, tr := range c.transitions {
		if tr.Phase == phaseArmed {
			t.Errorf("refused arm published an %s transition: %+v", phaseArmed, c.transitions)
		}
	}
	c.mu.Unlock()

	// The scenario never armed, so start must fail as an illegal transition
	// ("arm first") — not as the 0/N refusal a phantom `armed` phase produces.
	err := c.Start(context.Background())
	if !errors.Is(err, errInvalidTransition) {
		t.Fatalf("start after a refused first arm = %v, want an invalid-transition error", err)
	}
}

// TestScenarioController_CIDRResolvedCeiling: a re-arm whose selector resolves
// over scenarioMaxParticipants is refused wholesale AND leaves the previous
// arm fully intact — parts, ledger identity, and the armed phase (design D5).
func TestScenarioController_CIDRResolvedCeiling(t *testing.T) {
	sm, _ := scenarioTestManager(t, 2)
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(ceilingScenario(), "s-000001"); err != nil {
		t.Fatal(err)
	}
	armed, _, err := c.Arm()
	if err != nil || armed != 2 {
		t.Fatalf("first arm: armed=%d err=%v, want 2", armed, err)
	}
	prevLedger := c.ledgers["10.42.0.1"]

	growFleetPastCeiling(sm)

	_, _, err = c.Arm()
	if err == nil {
		t.Fatal("over-ceiling re-arm succeeded, want wholesale refusal")
	}
	if !strings.Contains(err.Error(), "100000") {
		t.Fatalf("refusal should name the cap: %v", err)
	}

	// Previous arm intact: same two parts, same ledger identity, still armed.
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.parts) != 2 {
		t.Fatalf("refused arm mutated parts: len=%d, want 2", len(c.parts))
	}
	if c.ledgers["10.42.0.1"] != prevLedger {
		t.Fatal("refused arm replaced a prior ledger (carry-forward corrupted)")
	}
	if c.phase != phaseArmed {
		t.Fatalf("phase = %s, want armed", c.phase)
	}
}

// TestScenarioController_CIDRLedgerCarryForward: a prefix-matched device keeps
// its ledger identity across re-arms (obligation 2 is selector-agnostic), and
// a fleet addition inside the prefix is picked up by the next arm.
func TestScenarioController_CIDRLedgerCarryForward(t *testing.T) {
	sm, wire := scenarioTestManager(t, 2)
	c := newScenarioController(sm, time.Now)
	spec := &Scenario{
		ParticipantsCIDR: []string{"10.42.0.0/24"},
		Protocol:         "syslog",
		Rate:             5,
		Window:           time.Second,
	}
	if err := c.Submit(spec, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if armed, _, err := c.Arm(); err != nil || armed != 2 {
		t.Fatalf("first arm: armed=%d err=%v", armed, err)
	}
	led := c.ledgers["10.42.0.2"]

	// A third device appears inside the prefix between arms.
	sm2, _ := scenarioTestManager(t, 3)
	sm.mu.Lock()
	sm.devicesByIP["10.42.0.3"] = sm2.devicesByIP["10.42.0.3"]
	sm.mu.Unlock()

	if armed, _, err := c.Arm(); err != nil || armed != 3 {
		t.Fatalf("re-arm after fleet growth: armed=%d err=%v, want 3", armed, err)
	}
	if c.ledgers["10.42.0.2"] != led {
		t.Fatal("re-arm replaced a prefix-matched device's ledger (obligation 2 broken)")
	}
	_ = wire
}
