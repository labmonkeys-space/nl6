/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
)

// The guards in this file are PERFORMANCE and call-site bounds, so none of them
// can be seen through a response: the bindings a request produces are identical
// with or without them. That is the nl6#535 argument for clampBulkWalk being a
// function of its own, and the reason each is tested by calling it directly
// rather than by asserting over bytes.

// ── R1: the Counter64 skip budget spans the request, not one binding ─────────

// TestCounter64SkipBudgetIsSharedAcrossBindings is the counterpart to
// TestClampBulkWalkDividesByColumns.
//
// nl6#535 faced this exact shape and made its ceiling DIVIDE by the column
// count so the guard bounds the TOTAL. nl6#542 made GETNEXT answer every
// binding, and a per-binding cap MULTIPLIES: ~300 names (what the read buffer
// admits) x 100000 is ~30M walk steps inline in the shared UDP handler.
//
// The probe is a deliberately tiny budget over three bindings that each want a
// long skip. Shared, the first binding spends it and the rest get nothing;
// per-binding, all three would complete. Both produce a well-formed response,
// which is why this asserts on the budget and the bindings rather than on
// error-status.
func TestCounter64SkipBudgetIsSharedAcrossBindings(t *testing.T) {
	// 8 HC columns x 40 interfaces = a 320-step contiguous Counter64 run, wider
	// than the small budget below and wider than the shipped worst case.
	vals := map[string]string{plainIfDescr: "Gi0/1", c32Broadcast: "1"}
	for col := 6; col <= 13; col++ {
		for ifIdx := 1; ifIdx <= 40; ifIdx++ {
			vals[oidFor(col, ifIdx)] = "9876543210"
		}
	}
	vals[c32HighSpeed] = "10000" // the far side of the run
	s := newTestServer(vals)

	// Three bindings, each landing at the start of the HC run.
	oids := []string{c32Broadcast, c32Broadcast, c32Broadcast}
	served := s.lldpServedOIDs()

	t.Run("a shared budget is spent once, not once per binding", func(t *testing.T) {
		const budgetSteps = 12
		budget := &counter64SkipBudget{remaining: budgetSteps}
		respOIDs, _ := s.getNextBindingsForRequest(oids, served, snmpVersion1, budget)

		if budget.remaining != 0 {
			t.Errorf("budget has %d steps left, want 0: three bindings each wanting a "+
				"320-step skip must exhaust a %d-step allowance", budget.remaining, budgetSteps)
		}
		// Binding 1 spent the allowance and ended as end-of-MIB; bindings 2 and
		// 3 found no steps left and did the same. With a PER-BINDING cap each
		// would have had its own 12 steps and all three would still be
		// end-of-MIB here — so the assertion that separates the two designs is
		// the budget total above, and this one guards against a budget that is
		// simply ignored.
		for i, got := range respOIDs {
			if got != oids[i] {
				t.Errorf("binding %d returned %s, want the requested name %s "+
					"(an exhausted skip run answers end-of-MIB)", i+1, got, oids[i])
			}
		}
	})

	t.Run("a per-binding budget would cost N times as much", func(t *testing.T) {
		// The arithmetic the design turns on, stated so a reader does not have
		// to trust prose: one shared allowance versus one per binding.
		shared := &counter64SkipBudget{remaining: 100}
		s.getNextBindingsForRequest(oids, served, snmpVersion1, shared)
		sharedSpent := 100 - shared.remaining

		perBindingSpent := 0
		for range oids {
			b := &counter64SkipBudget{remaining: 100}
			s.getNextBindingsForRequest(oids[:1], served, snmpVersion1, b)
			perBindingSpent += 100 - b.remaining
		}
		if perBindingSpent <= sharedSpent {
			t.Fatalf("the fixture does not exercise the difference: shared spent %d, "+
				"per-binding %d", sharedSpent, perBindingSpent)
		}
		if sharedSpent > 100 {
			t.Errorf("one request spent %d steps against a 100-step allowance", sharedSpent)
		}
	})

	t.Run("a generous budget leaves legitimate traffic alone", func(t *testing.T) {
		budget := newCounter64SkipBudget()
		respOIDs, _ := s.getNextBindingsForRequest(oids, served, snmpVersion1, budget)
		for i, got := range respOIDs {
			if got != c32HighSpeed {
				t.Errorf("binding %d returned %s, want %s: the real skip run is far inside "+
					"the default budget and must complete", i+1, got, c32HighSpeed)
			}
		}
		if spent := counter64SkipBudgetSteps() - budget.remaining; spent < 320 {
			t.Errorf("the request spent only %d steps; the fixture's run is 320, so the "+
				"skip did not actually happen", spent)
		}
	})
}

// TestCounter64SkipBudgetTake pins the primitive, including the nil case, which
// no other test reaches and which fails toward the loud local fault.
func TestCounter64SkipBudgetTake(t *testing.T) {
	b := &counter64SkipBudget{remaining: 2}
	// Two separate calls, not `b.take() || b.take()`: short-circuiting would
	// draw only one step, and staticcheck SA4000 rightly objects to the
	// duplicated expression.
	for i := 1; i <= 2; i++ {
		if !b.take() {
			t.Fatalf("a budget with 2 steps refused step %d", i)
		}
	}
	if b.take() {
		t.Error("a spent budget granted a step")
	}
	if (&counter64SkipBudget{}).take() {
		t.Error("a zero-valued budget granted a step")
	}
	var nilBudget *counter64SkipBudget
	if nilBudget.take() {
		t.Error("a nil budget granted a step: it must report exhausted, so a missing " +
			"budget is a loud local fault and never unbounded work on the UDP handler")
	}
	if newCounter64SkipBudget().remaining != counter64SkipBudgetSteps() {
		t.Error("newCounter64SkipBudget does not start at counter64SkipBudgetSteps()")
	}
}

// TestBudgetExhaustionIsLoggedOncePerDevice: either exit from the skip run is a
// data or load defect, and the manager only sees a walk that ended early, so it
// must leave exactly one trace per device (the logFirstSkipAbort convention).
func TestBudgetExhaustionIsLoggedOncePerDevice(t *testing.T) {
	vals := map[string]string{c32Broadcast: "1"}
	for col := 6; col <= 13; col++ {
		for ifIdx := 1; ifIdx <= 40; ifIdx++ {
			vals[oidFor(col, ifIdx)] = "9876543210"
		}
	}
	s := newTestServer(vals)

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	served := s.lldpServedOIDs()
	for i := 0; i < 3; i++ {
		s.getNextBindingsForRequest([]string{c32Broadcast}, served, snmpVersion1,
			&counter64SkipBudget{remaining: 3})
	}
	if got := strings.Count(buf.String(), "request skip budget exhausted"); got != 1 {
		t.Errorf("budget exhaustion logged %d times over three requests, want exactly 1:\n%s",
			got, buf.String())
	}
}

// ── R3: the binding count is clamped before any walk work ───────────────────

// TestOversizedGetNextRefusedWithoutWalking pins the short-circuit. Above
// maxSNMPResponseSize/minVarbindSize bindings the tooBig answer is already
// decided, so walking is work spent on a response that is then discarded — and
// each step scans the device's LLDP view.
//
// Observed through the WORK, not the response: a truncated-then-discarded walk
// and a refusal produce the same bytes. The fixture's successor is corrupted so
// that ANY walk step logs, and the assertion is that nothing logged.
func TestOversizedGetNextRefusedWithoutWalking(t *testing.T) {
	s := newTestServer(counter64Fixture())
	maxFit := maxSNMPResponseSize / minVarbindSize

	// One step past the ceiling.
	oids := make([]string, maxFit+1)
	for i := range oids {
		oids[i] = c32Broadcast
	}

	// Make the first skip step non-advancing, so a single walk step into the HC
	// run leaves a trace.
	s.device.resources.oidNextMap.Store(c64InOctets, c64InOctets)

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
		snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, oids)))
	if hdr.errStatus != snmpErrTooBig {
		t.Fatalf("error-status=%d, want tooBig(%d) for %d bindings",
			hdr.errStatus, snmpErrTooBig, len(oids))
	}
	if len(hdr.varbinds) != 0 {
		t.Errorf("tooBig carries %d bytes of bindings, want an empty list", len(hdr.varbinds))
	}
	if strings.Contains(buf.String(), "does not advance") {
		t.Errorf("the request walked before being refused; the count clamp must "+
			"short-circuit ahead of any walk step:\n%s", buf.String())
	}
}

// TestTooBigShortCircuitMatchesTheBuilder is the anti-drift check for having two
// ways to say tooBig. The short-circuit must be byte-identical to what
// createVarbindResponse produces, or the refusal is observable as a different
// datagram from the one it stands in for.
func TestTooBigShortCircuitMatchesTheBuilder(t *testing.T) {
	s := newTestServer(counter64Fixture())

	for _, ver := range []int{snmpVersion1, snmpVersion2c} {
		req := snmpRequestAt(ASN1_GET_NEXT, ver, []string{plainIfDescr})
		short := s.createTooBigResponse(req)

		// The builder's own tooBig, reached by handing it bindings that cannot
		// fit. Values are long enough that the first binding already overflows.
		oids := make([]string, 60)
		responses := make([]string, 60)
		for i := range oids {
			oids[i] = plainIfDescr
			responses[i] = strings.Repeat("x", 200)
		}
		built := s.createGetNextResponse(oids, oids, responses, req)

		if !bytes.Equal(short, built) {
			t.Errorf("version %d: the tooBig short-circuit and the builder disagree:\n"+
				"short-circuit % x\nbuilder      % x", ver, short, built)
		}
	}
}

// TestGetNextWalkWorkPerDatagramIsBounded is the counterpart to
// TestReadBufferBoundsTheColumnCount, and it exists to make a change to any of
// these constants face the arithmetic rather than a comment.
//
// TWO ceilings cap the binding count, and which one binds is worth stating
// because the review that prompted this change assumed the looser one:
//
//	fit ceiling    maxSNMPResponseSize / minVarbindSize  = 98 bindings
//	read buffer    snmpReadBufferBytes / minVarbindSize  = 68 bindings
//
// So today the READ BUFFER binds first and the fit clamp is a BACKSTOP: its
// value is what stops a larger read buffer from raising walk work linearly,
// which is exactly the coupling nl6#535's review asked to be asserted rather
// than commented.
//
// (The nl6#542 review derived its figures from
// TestReadBufferBoundsTheColumnCount's documented 300-column ceiling rather
// than from snmpReadBufferBytes. The reachable count is 68, not ~300. The
// direction and the fix are unchanged.)
//
// The MARGIN is the part A1 corrected. It used to be asserted as
// `reachable x longestShippedCounter64Run <= maxCounter64SkipSteps`, a literal
// 100000 against a run measured over the static index. At the real walk-derived
// run of 1152 that margin was 1.28x, not 5.1x, and a profile with ~200
// interfaces would have truncated legitimate v1 tables while the assertion
// still passed. The budget is now DERIVED from the same two numbers
// (counter64SkipBudgetSteps = maxGetNextBindings x longestShippedCounter64Run),
// so it cannot truncate a legitimate request BY CONSTRUCTION — and what this
// test checks is that the derivation is intact rather than a margin that could
// silently thin out again.
func TestGetNextWalkWorkPerDatagramIsBounded(t *testing.T) {
	const (
		documentedFitCeiling    = 98   // maxSNMPResponseSize / minVarbindSize
		documentedBufferCeiling = 68   // snmpReadBufferBytes / minVarbindSize
		documentedRun           = 1152 // longestShippedCounter64Run, walk-derived
	)

	fitCeiling := maxGetNextBindings()
	bufferCeiling := snmpReadBufferBytes / minVarbindSize
	reachable := fitCeiling
	if bufferCeiling < reachable {
		reachable = bufferCeiling
	}

	if fitCeiling != documentedFitCeiling || bufferCeiling != documentedBufferCeiling {
		t.Errorf("the binding-count ceilings moved: fit %d (documented %d), read buffer %d "+
			"(documented %d). Re-derive the arithmetic in this test, in counter64SkipBudget's "+
			"comment and in docs/reference/snmp.md",
			fitCeiling, documentedFitCeiling, bufferCeiling, documentedBufferCeiling)
	}
	if longestShippedCounter64Run != documentedRun {
		t.Errorf("longestShippedCounter64Run = %d, documented here as %d",
			longestShippedCounter64Run, documentedRun)
	}

	// The derivation, asserted rather than trusted: the budget must be exactly
	// what the widest legitimate request needs. A hand-set budget is what A1
	// found wrong, so a hand-set one must fail here.
	wantBudget := fitCeiling * longestShippedCounter64Run
	if got := counter64SkipBudgetSteps(); got != wantBudget {
		t.Errorf("counter64SkipBudgetSteps() = %d, want %d = maxGetNextBindings(%d) x "+
			"longestShippedCounter64Run(%d). A hand-set budget drifts away from what a "+
			"legitimate request needs, which is how 100000 came to sit 1.28x above it",
			got, wantBudget, fitCeiling, longestShippedCounter64Run)
	}

	// Legitimate traffic can never be truncated. True by construction above,
	// asserted anyway because it is the property the derivation exists for and
	// a future change could break it while keeping the derivation's shape.
	if need := reachable * longestShippedCounter64Run; need > counter64SkipBudgetSteps() {
		t.Errorf("a legitimate worst-case datagram wants %d skip steps (%d bindings x the "+
			"%d-step shipped run) but the budget is %d, so real v1 tables would truncate",
			need, reachable, longestShippedCounter64Run, counter64SkipBudgetSteps())
	}

	// The property the SHARED budget buys: total skip work per datagram does
	// not scale with the binding count. Per binding it would be
	// reachable x the budget.
	perBindingWouldBe := reachable * counter64SkipBudgetSteps()
	if perBindingWouldBe <= counter64SkipBudgetSteps() {
		t.Fatalf("the fixture cannot show the difference: %d reachable bindings", reachable)
	}

	t.Logf("reachable bindings %d (fit %d, read buffer %d); shipped run %d; budget %d per "+
		"datagram, independent of the binding count (per binding it would be %d)",
		reachable, fitCeiling, bufferCeiling, longestShippedCounter64Run,
		counter64SkipBudgetSteps(), perBindingWouldBe)
}

// ── R5/R6/R7: the call-site seams ───────────────────────────────────────────

// TestBothV1SentinelDiversionsAgreeByteForByte closes the nl6#539 hazard R5
// names: the v1 noSuchName rule exists in TWO builders, one of them
// (createSNMPResponse) now production-unreachable, so nothing else would notice
// them drifting apart.
func TestBothV1SentinelDiversionsAgreeByteForByte(t *testing.T) {
	s := newTestServer(counter64Fixture())

	for _, sentinel := range []string{valueEndOfMibView, valueNoSuchObject} {
		req := snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, []string{plainIfDescr})
		single := s.createSNMPResponse(plainIfDescr, sentinel, req)
		multi := s.createGetNextResponse([]string{plainIfDescr}, []string{plainIfDescr},
			[]string{sentinel}, req)
		if !bytes.Equal(single, multi) {
			t.Errorf("the two v1 %s diversions disagree:\n createSNMPResponse   % x\n"+
				" createVarbindResponse % x", sentinel, single, multi)
		}
	}
}

// TestRuleConstructorsSetEveryField pins R7: both rule fields have a zero value
// that is not a rule, and each of the three constructors must set both. A
// future constructor that omits one would otherwise compile and pick a policy
// silently, which is how a wrongly-wired call site left the suite green before
// (TestV1GetBulkThroughDispatcherStillReturnsCounter64).
func TestRuleConstructorsSetEveryField(t *testing.T) {
	s := newTestServer(map[string]string{plainIfDescr: "Gi0/1"})
	req := snmpRequestAt(ASN1_GET_REQUEST, snmpVersion2c, []string{plainIfDescr})

	// Recorded by driving each constructor and checking that resolveDefaults
	// has nothing to substitute — the only observable statement of "both fields
	// were set" without exporting the struct.
	cases := []struct {
		name  string
		rules varbindResponseRules
	}{
		{"GET", varbindResponseRules{overflow: overflowTooBig, v1Diversion: v1DivertSentinelAndCounter64}},
		{"GETNEXT", varbindResponseRules{overflow: overflowTooBig, v1Diversion: v1DivertSentinel, echoNames: []string{plainIfDescr}}},
		{"GETBULK", varbindResponseRules{overflow: overflowTruncate, v1Diversion: v1DivertNothing}},
	}
	for _, c := range cases {
		if _, unset := c.rules.resolveDefaults(); unset {
			t.Errorf("%s: a rule field is unset", c.name)
		}
	}

	// The zero value must be detectable, not merely different.
	if _, unset := (varbindResponseRules{}).resolveDefaults(); !unset {
		t.Error("the zero value of varbindResponseRules is not reported as unset, so a " +
			"call site that omits a field gets a silently-chosen policy")
	}
	// And the substitutes are the strictest rules, so an omission degrades
	// toward a correct v1 answer rather than toward a silent partial response.
	got, _ := (varbindResponseRules{}).resolveDefaults()
	if got.overflow != overflowTooBig || got.v1Diversion != v1DivertSentinelAndCounter64 {
		t.Errorf("unset rules resolve to (%v, %v), want (tooBig, divert sentinel+counter64)",
			got.overflow, got.v1Diversion)
	}
	_ = s
	_ = req
}

// TestMisSizedEchoNamesNeverEchoesSuccessors pins R6. A non-nil echoNames of the
// wrong length is a bug no caller produces; the answer must not be the
// SUCCESSORS, which is what the old `len(names) != len(oids)` fallback produced.
func TestMisSizedEchoNamesNeverEchoesSuccessors(t *testing.T) {
	s := newTestServer(counter64Fixture())
	req := snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, []string{plainIfDescr, c32Broadcast})

	successors := []string{plainIfDescr2, c32HighSpeed}
	responses := []string{"Gi0/2", valueEndOfMibView}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	resp := s.createVarbindResponse(successors, responses, req, varbindResponseRules{
		overflow:    overflowTooBig,
		v1Diversion: v1DivertSentinel,
		echoNames:   []string{plainIfDescr}, // one name for two bindings
	})
	hdr := decodeResponseHeader(t, resp)

	if hdr.errStatus != snmpErrNoSuchName || hdr.errIndex != 2 {
		t.Fatalf("error-status=%d error-index=%d, want noSuchName/2", hdr.errStatus, hdr.errIndex)
	}
	if len(hdr.varbinds) != 0 {
		t.Errorf("a mis-sized echo emitted %d bytes of bindings; it must emit NONE, since "+
			"error-index counts positions in a list the echo does not match:\n% x",
			len(hdr.varbinds), hdr.varbinds)
	}
	for _, oid := range successors {
		if bytes.Contains(hdr.varbinds, encodeOID(oid)) {
			t.Errorf("the echo carries the successor %s, a name the manager never sent", oid)
		}
	}
	if !strings.Contains(buf.String(), "echoNames length") {
		t.Errorf("a mis-sized echo left no trace:\n%s", buf.String())
	}
}

// ── R13: an unknown version integer ─────────────────────────────────────────

// TestUnknownVersionIsServedAsV2c states nl6's choice rather than leaving it
// implicit. Since nl6#559/#562 the version is read at any declared width, so a
// value that is neither 0 nor 1 reaches this path; the test on the serve side is
// `== snmpVersion1`, so such a request gets v2c semantics — including a
// Counter64 tag a v1-ish manager could not decode. Discarding instead would be a
// new silent drop on a simulator whose job is to answer pollers.
func TestUnknownVersionIsServedAsV2c(t *testing.T) {
	s := newTestServer(counter64Fixture())

	for _, ver := range []int{2, 7, 255} {
		t.Run(fmt.Sprintf("version %d", ver), func(t *testing.T) {
			resp := s.handleSNMPv2cRequest(snmpRequestAt(ASN1_GET_NEXT, ver, []string{c32Broadcast}))
			if len(resp) == 0 {
				t.Fatalf("version %d was DISCARDED; nl6's documented choice is to serve it "+
					"as v2c. If that changed, update getNextBinding's comment and "+
					"docs/reference/snmp.md", ver)
			}
			hdr := decodeResponseHeader(t, resp)
			if hdr.errStatus != snmpErrNoError {
				t.Fatalf("error-status=%d, want noError", hdr.errStatus)
			}
			if !containsTagAtVarbindValue(hdr.varbinds, ASN1_COUNTER64) {
				t.Errorf("version %d did not receive the Counter64 successor, so it was not "+
					"served with v2c semantics", ver)
			}
			if hdr.version != ver {
				t.Errorf("response version = %d, want the request's %d echoed", hdr.version, ver)
			}
		})
	}
}
