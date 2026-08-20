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
	"net/http"
	"testing"
	"time"
)

// digestOf is the INDEPENDENT reference implementation of the documented
// encoding — deliberately not calling resolvedParticipantsSHA256, so the test
// asserts the encoding rather than merely agreeing with whatever the code does.
// Mirrors `printf '%s\n' "$IPS" | LC_ALL=C sort | sha256sum` (the C locale is
// required: glibc's UTF-8 collation ignores punctuation and would order
// 10.42.10.1 before 10.42.1.2, which byte order reverses).
func digestOf(sortedIPs ...string) string {
	h := sha256.New()
	for _, ip := range sortedIPs {
		h.Write([]byte(ip + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// runScenarioReport submits, arms, starts and stops a scenario through the API,
// returning its finalized report.
func runScenarioReport(t *testing.T, router http.Handler, body string) scenarioReport {
	t.Helper()
	id := submitOK(t, router, body)
	if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", ""); w.Code != http.StatusOK {
		t.Fatalf("arm = %d (%s)", w.Code, w.Body.String())
	}
	if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/start", ""); w.Code != http.StatusOK {
		t.Fatalf("start = %d (%s)", w.Code, w.Body.String())
	}
	if w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/stop", ""); w.Code != http.StatusOK {
		t.Fatalf("stop = %d (%s)", w.Code, w.Body.String())
	}
	w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id+"/report", "")
	if w.Code != http.StatusOK {
		t.Fatalf("report = %d (%s)", w.Code, w.Body.String())
	}
	var rep scenarioReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	deleteScenario(t, router, id)
	return rep
}

// TestResolvedParticipantsSHA_Encoding pins the exact documented encoding
// against an independent reimplementation — including the trailing newline,
// which is the detail an external checker gets wrong.
func TestResolvedParticipantsSHA_Encoding(t *testing.T) {
	got := resolvedParticipantsSHA256(map[string]ledgerSnapshot{
		"10.42.0.2": {}, "10.42.0.1": {}, "10.42.0.10": {},
	})
	// BYTE order: "10.42.0.1" < "10.42.0.10" < "10.42.0.2".
	want := digestOf("10.42.0.1", "10.42.0.10", "10.42.0.2")
	if got != want {
		t.Fatalf("digest = %s, want %s (byte order, each address followed by \\n)", got, want)
	}
	// Map iteration order must not leak in.
	for i := 0; i < 20; i++ {
		if again := resolvedParticipantsSHA256(map[string]ledgerSnapshot{
			"10.42.0.10": {}, "10.42.0.1": {}, "10.42.0.2": {},
		}); again != got {
			t.Fatalf("digest is not order-stable: %s vs %s", again, got)
		}
	}
	// A trailing newline is part of the encoding, not an accident: without it
	// the shell one-liner in the docs would disagree with the implementation.
	noTrailing := sha256.Sum256([]byte("10.42.0.1\n10.42.0.10\n10.42.0.2"))
	if got == hex.EncodeToString(noTrailing[:]) {
		t.Fatal("digest omits the documented trailing newline")
	}
}

// TestResolvedParticipantsSHA_Membership: the digest tracks membership and
// nothing else.
func TestResolvedParticipantsSHA_Membership(t *testing.T) {
	two := map[string]ledgerSnapshot{"10.42.0.1": {}, "10.42.0.2": {}}
	same := map[string]ledgerSnapshot{"10.42.0.2": {}, "10.42.0.1": {}}
	three := map[string]ledgerSnapshot{"10.42.0.1": {}, "10.42.0.2": {}, "10.42.0.3": {}}

	if resolvedParticipantsSHA256(two) != resolvedParticipantsSHA256(same) {
		t.Error("identical membership must digest identically")
	}
	if resolvedParticipantsSHA256(two) == resolvedParticipantsSHA256(three) {
		t.Error("membership differing by one device must digest differently")
	}
	// Ledger CONTENT is not membership: two runs over the same devices with
	// different counters describe the same fleet.
	busy := map[string]ledgerSnapshot{"10.42.0.1": {InWindow: 999}, "10.42.0.2": {InWindow: 7}}
	if resolvedParticipantsSHA256(two) != resolvedParticipantsSHA256(busy) {
		t.Error("digest must depend on the participant set alone, not on their counters")
	}
}

// TestResolvedParticipantsSHA_DeclarationIndependent is the property that makes
// the field useful: an explicit list and a prefix selector resolving to the same
// live devices produce the same digest, so a baseline stays comparable to a
// re-declared repeat of it.
func TestResolvedParticipantsSHA_DeclarationIndependent(t *testing.T) {
	const tail = `,"protocol":"syslog","rate":5,"window":"40ms","drain":"10ms"}`

	router := scenarioAPIManager(t, 3)
	byList := runScenarioReport(t, router,
		`{"participants":["10.42.0.1","10.42.0.2","10.42.0.3"]`+tail)

	router = scenarioAPIManager(t, 3)
	byPrefix := runScenarioReport(t, router, `{"participants_cidr":["10.42.0.0/24"]`+tail)

	listSHA := byList.Summary.Metadata.ResolvedParticipantsSHA256
	prefixSHA := byPrefix.Summary.Metadata.ResolvedParticipantsSHA256
	if listSHA == "" {
		t.Fatal("report carries no resolved_participants_sha256")
	}
	if listSHA != prefixSHA {
		t.Errorf("declaration leaked into the digest:\n  list   %s\n  prefix %s", listSHA, prefixSHA)
	}
	// And it is the documented function of the addresses that ran.
	if want := digestOf("10.42.0.1", "10.42.0.2", "10.42.0.3"); listSHA != want {
		t.Errorf("digest = %s, want %s", listSHA, want)
	}
	// The two runs differ in declaration, so their config fingerprints must NOT
	// agree — the two fields answer different questions.
	if byList.Summary.Metadata.ConfigSHA256 == byPrefix.Summary.Metadata.ConfigSHA256 {
		t.Error("config_sha256 should still distinguish differently-declared scenarios")
	}
}

// TestResolvedParticipantsSHA_ExcludesGapLoss: a device lost between arm and
// start ran in no sense, so the digest identifies the remainder. Hashing the
// arm-time set would let a short run digest identically to a whole one — the
// failure this field exists to make visible.
func TestResolvedParticipantsSHA_ExcludesGapLoss(t *testing.T) {
	sm, _ := scenarioTestManager(t, 3)
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(&Scenario{
		ParticipantsCIDR: []string{"10.42.0.0/24"},
		Protocol:         "syslog",
		Rate:             5,
		Window:           40 * time.Millisecond,
		Drain:            10 * time.Millisecond,
	}, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if armed, _, err := c.Arm(); err != nil || armed != 3 {
		t.Fatalf("arm: armed=%d err=%v", armed, err)
	}
	// Lost after arming, before start.
	sm.mu.Lock()
	delete(sm.devicesByIP, "10.42.0.2")
	sm.mu.Unlock()

	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := c.Stop()
	if err != nil {
		t.Fatal(err)
	}
	got := resolvedParticipantsSHA256(res.PerDevice)
	if want := digestOf("10.42.0.1", "10.42.0.3"); got != want {
		t.Errorf("digest = %s, want the surviving pair %s", got, want)
	}
	if all := digestOf("10.42.0.1", "10.42.0.2", "10.42.0.3"); got == all {
		t.Error("digest covers the arm-time set, so a run that lost a device is indistinguishable from a whole one")
	}
}
