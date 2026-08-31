/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// nl6#542 item 2: RFC 3416 §4.2.2 defines GETNEXT over the WHOLE
// variable-bindings list. handleSNMPv2cRequest used to read one OID and answer
// one binding, so a walker fetching several columns per round trip got the
// first column and no signal that the rest were dropped.
//
// The regression risk of the fix is the SINGLE-binding case, which is
// essentially all real GETNEXT traffic — that is pinned byte-for-byte by
// TestWellFormedResponsesUnchangedOnTheWire against a digest taken on the
// pre-change tree, over both versions, three community lengths and four
// request-ids. This file pins the behaviour the fix ADDS, plus the three
// diversion behaviours that had to survive it.

// pastTheEnd is above every OID any fixture here serves, and above the
// sysName.0 / sysLocation.0 candidates findNextOID injects, so nothing follows
// it.
const pastTheEnd = ".1.3.6.1.4.1.99999.1.1"
const pastTheEnd2 = ".1.3.6.1.4.1.99999.1.2"

// varbindPair is one decoded binding: its name and its value's ASN.1 tag.
type varbindPair struct {
	oid string
	tag byte
}

// decodeVarbindPairs decodes a whole varbind-list body into (name, value tag)
// pairs. A structural problem FAILS rather than returning a short list: a
// silently-short list is what lets a per-binding assertion pass over a response
// nobody could decode, which is the vacuous pass this file exists to avoid.
//
// It reads each value's LENGTH as well as its tag and requires the value TLV to
// end exactly on the binding boundary — the same rule parseAllOIDsFromRequest
// enforces on the way in (nl6#537). Reading only the tag made this helper LAXER
// than the production parser it inspects, so a binding with a trailing extra
// TLV decoded as valid here (nl6#542 review R14).
func decodeVarbindPairs(t *testing.T, varbinds []byte) []varbindPair {
	t.Helper()
	var out []varbindPair
	pos := 0
	for pos < len(varbinds) {
		if varbinds[pos] != ASN1_SEQUENCE {
			t.Fatalf("expected SEQUENCE at %d, got 0x%02x in % x", pos, varbinds[pos], varbinds)
		}
		vbLen, next := parseLength(varbinds, pos+1)
		if vbLen < 0 || next+vbLen > len(varbinds) {
			t.Fatalf("bad binding length at %d in % x", pos, varbinds)
		}
		body := varbinds[next : next+vbLen]
		if len(body) == 0 || body[0] != ASN1_OID {
			t.Fatalf("binding at %d has no OBJECT IDENTIFIER name in % x", pos, varbinds)
		}
		nameLen, afterName := parseLength(body, 1)
		if nameLen < 0 || afterName+nameLen > len(body) {
			t.Fatalf("bad name length in binding at %d in % x", pos, varbinds)
		}
		name := decodeOID(body[afterName : afterName+nameLen])
		vpos := afterName + nameLen
		if vpos >= len(body) {
			t.Fatalf("binding at %d has a name but no value in % x", pos, varbinds)
		}
		valLen, afterValLen := parseLength(body, vpos+1)
		if valLen < 0 || afterValLen+valLen != len(body) {
			t.Fatalf("binding at %d does not end exactly on one value TLV "+
				"(value length %d, %d bytes of binding left) in % x",
				pos, valLen, len(body)-afterValLen, varbinds)
		}
		out = append(out, varbindPair{oid: name, tag: body[vpos]})
		pos = next + vbLen
	}
	return out
}

// assertBindings checks the decoded names against `want`, positionally. Count
// first, because a length mismatch makes every index assertion below it
// misleading.
//
// Comparison is EXACT after normalising the leading dot, not the dot-lenient
// containsOID membership test this used at first: a membership test written for
// one element reads as if order did not matter, when order is precisely what
// these rows assert (nl6#542 review R14). decodeOID always emits the leading
// dot, so the normalisation only tolerates a `want` constant spelled without
// one.
func assertBindings(t *testing.T, got []varbindPair, want []string) {
	t.Helper()
	if len(got) != len(want) {
		var names []string
		for _, p := range got {
			names = append(names, p.oid)
		}
		t.Fatalf("response carries %d bindings %v, want %d %v",
			len(got), names, len(want), want)
	}
	dotted := func(o string) string {
		if strings.HasPrefix(o, ".") {
			return o
		}
		return "." + o
	}
	for i := range want {
		if dotted(got[i].oid) != dotted(want[i]) {
			t.Errorf("binding %d is %s, want %s (bindings must be in request order, "+
				"each the successor of its OWN name)", i+1, got[i].oid, want[i])
		}
	}
}

// getNextFixture is counter64Fixture plus two OIDs that are the last thing in
// the MIB, so end-of-MIB and normal bindings can appear in one request.
func getNextFixture() map[string]string {
	vals := counter64Fixture()
	vals[pastTheEnd] = "last"
	return vals
}

// ── the substance: every binding is answered ─────────────────────────────────

func TestGetNextAnswersEveryBinding(t *testing.T) {
	s := newTestServer(getNextFixture())

	// Three names whose successors are all ordinary (non-Counter64) OIDs, so
	// the same expectation holds under both versions — the Counter64 rows
	// below are where the two versions are supposed to differ. The third name
	// is the LAST column of the HC run, whose successor is the Gauge32 on the
	// far side of it.
	req := []string{".1.3.6.1.2.1.2.2.1.2.0", plainIfDescr, oidFor(13, 2)}
	want := []string{plainIfDescr, plainIfDescr2, c32HighSpeed}

	for _, ver := range []int{snmpVersion1, snmpVersion2c} {
		name := "v2c"
		if ver == snmpVersion1 {
			name = "v1"
		}
		t.Run(name, func(t *testing.T) {
			hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
				snmpRequestAt(ASN1_GET_NEXT, ver, req)))
			if hdr.errStatus != snmpErrNoError {
				t.Fatalf("error-status=%d, want noError", hdr.errStatus)
			}
			assertBindings(t, decodeVarbindPairs(t, hdr.varbinds), want)
		})
	}
}

// TestGetNextSingleBindingUnchanged is the control for the row above: the
// single-binding answer must be the same OID it always was. Byte identity is
// pinned by TestWellFormedResponsesUnchangedOnTheWire; this states the
// behaviour in terms a reader of this file can check.
func TestGetNextSingleBindingUnchanged(t *testing.T) {
	s := newTestServer(getNextFixture())

	for _, ver := range []int{snmpVersion1, snmpVersion2c} {
		hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
			snmpRequestAt(ASN1_GET_NEXT, ver, []string{plainIfDescr})))
		if hdr.errStatus != snmpErrNoError {
			t.Fatalf("version %d: error-status=%d, want noError", ver, hdr.errStatus)
		}
		assertBindings(t, decodeVarbindPairs(t, hdr.varbinds), []string{plainIfDescr2})
	}
}

// ── end of MIB, mixed and total ──────────────────────────────────────────────

// TestGetNextMixedEndOfMibNamesItsOwnRequest pins that end-of-MIB is PER
// BINDING and that the exhausted binding is named with the OID that was ASKED
// FOR. Naming it with a successor that does not exist, or with another
// binding's name, is the half-fix that leaves a walker unable to tell which
// column ended.
func TestGetNextMixedEndOfMibNamesItsOwnRequest(t *testing.T) {
	s := newTestServer(getNextFixture())

	req := []string{plainIfDescr, pastTheEnd, c32Broadcast}
	hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
		snmpRequestAt(ASN1_GET_NEXT, snmpVersion2c, req)))
	if hdr.errStatus != snmpErrNoError {
		t.Fatalf("error-status=%d, want noError: only SNMPv1 diverts on endOfMibView", hdr.errStatus)
	}

	// Binding 3's successor is the start of the HC run under v2c, which has
	// Counter64, so it comes back as-is.
	pairs := decodeVarbindPairs(t, hdr.varbinds)
	assertBindings(t, pairs, []string{plainIfDescr2, pastTheEnd, c64InOctets})
	if pairs[1].tag != 0x82 {
		t.Errorf("binding 2 value tag = 0x%02x, want endOfMibView 0x82", pairs[1].tag)
	}
}

// TestGetNextAllEndOfMibV2c: every binding carries the endOfMibView exception,
// named with its own requested OID.
func TestGetNextAllEndOfMibV2c(t *testing.T) {
	s := newTestServer(getNextFixture())

	req := []string{pastTheEnd, pastTheEnd2}
	hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
		snmpRequestAt(ASN1_GET_NEXT, snmpVersion2c, req)))
	if hdr.errStatus != snmpErrNoError {
		t.Fatalf("error-status=%d, want noError", hdr.errStatus)
	}
	pairs := decodeVarbindPairs(t, hdr.varbinds)
	assertBindings(t, pairs, req)
	for i, p := range pairs {
		// endOfMibView is [2] IMPLICIT NULL, tag 0x82 (encodeTypedValue). Not
		// a named constant in this package, so it is spelled literally here
		// and in the message.
		if p.tag != 0x82 {
			t.Errorf("binding %d value tag = 0x%02x, want endOfMibView 0x82", i+1, p.tag)
		}
	}
}

// TestGetNextAllEndOfMibV1 : SNMPv1 has no exception values, so the whole
// response diverts to noSuchName with error-index at the FIRST offending
// binding and the request's own names echoed with NULL (RFC 3584 §4.2.2.2.2,
// RFC 1157 §4.1.3).
func TestGetNextAllEndOfMibV1(t *testing.T) {
	s := newTestServer(getNextFixture())

	tests := []struct {
		name      string
		req       []string
		wantIndex int
	}{
		{"both past the end", []string{pastTheEnd, pastTheEnd2}, 1},
		{"second past the end", []string{plainIfDescr, pastTheEnd}, 2},
		{"third past the end", []string{plainIfDescr, c32Broadcast, pastTheEnd}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
				snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, tt.req)))
			if hdr.errStatus != snmpErrNoSuchName || hdr.errIndex != tt.wantIndex {
				t.Fatalf("error-status=%d error-index=%d, want noSuchName/%d",
					hdr.errStatus, hdr.errIndex, tt.wantIndex)
			}
			// The echo carries the REQUEST's names, not the successors the walk
			// found for the other bindings. Getting this wrong answers a v1
			// manager with names it never sent.
			var want []byte
			for _, o := range tt.req {
				want = append(want, encodeVarBind(o, encodeNull())...)
			}
			if !bytesEqual(hdr.varbinds, want) {
				t.Errorf("varbinds are not the REQUEST echoed with NULL:\n got % x\nwant % x",
					hdr.varbinds, want)
			}
		})
	}
}

// ── the Counter64 rule, per binding ──────────────────────────────────────────

// TestGetNextV1Counter64SkipsPerBinding is the row this change is most likely
// to get wrong. Binding 2's successor starts the contiguous HC run, so it must
// SKIP to the far side of it (RFC 3584 §4.2.2.1); bindings 1 and 3 must be
// untouched, and the response must never be a noSuchName.
//
// If the Counter64 diversion were still applied to GETNEXT, this response would
// be noSuchName/2 and a v1 walk of ifXTable would stop dead at the first ifHC*
// column with the table silently truncated.
func TestGetNextV1Counter64SkipsPerBinding(t *testing.T) {
	s := newTestServer(getNextFixture())

	// Precondition, so a fixture change cannot make this pass vacuously.
	if next, _ := s.findNextOID(c32Broadcast); snmpTypeTag(next) != ASN1_COUNTER64 {
		t.Fatalf("precondition failed: successor of %s is %s, expected a Counter64",
			c32Broadcast, next)
	}

	req := []string{".1.3.6.1.2.1.2.2.1.2.0", c32Broadcast, plainIfDescr}
	want := []string{plainIfDescr, c32HighSpeed, plainIfDescr2}

	hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
		snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, req)))
	if hdr.errStatus != snmpErrNoError {
		t.Fatalf("error-status=%d, want noError: a v1 GETNEXT must SKIP a Counter64 "+
			"successor, never divert — diverting truncates the table with no signal",
			hdr.errStatus)
	}
	pairs := decodeVarbindPairs(t, hdr.varbinds)
	assertBindings(t, pairs, want)
	for i, p := range pairs {
		if p.tag == ASN1_COUNTER64 {
			t.Errorf("binding %d carries tag 0x46, which does not exist in SNMPv1", i+1)
		}
	}
}

// TestGetNextV2cCounter64ReturnedPerBinding is the contrapositive: v2c has
// Counter64, so the same request must return the HC column itself. A fix that
// skipped for every version would pass the row above and silently shorten every
// v2c ifXTable walk.
func TestGetNextV2cCounter64ReturnedPerBinding(t *testing.T) {
	s := newTestServer(getNextFixture())

	req := []string{".1.3.6.1.2.1.2.2.1.2.0", c32Broadcast, plainIfDescr}
	want := []string{plainIfDescr, c64InOctets, plainIfDescr2}

	hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
		snmpRequestAt(ASN1_GET_NEXT, snmpVersion2c, req)))
	if hdr.errStatus != snmpErrNoError {
		t.Fatalf("error-status=%d, want noError", hdr.errStatus)
	}
	pairs := decodeVarbindPairs(t, hdr.varbinds)
	assertBindings(t, pairs, want)
	if pairs[1].tag != ASN1_COUNTER64 {
		t.Errorf("binding 2 value tag = 0x%02x, want Counter64 0x46: v1 semantics have "+
			"leaked into v2c", pairs[1].tag)
	}
}

// TestGetNextV1SkipRunEndsInNoSuchNamePerBinding: a binding that skips its way
// PAST the last non-Counter64 OID is at end of MIB, so under v1 the whole
// response diverts with error-index at that binding.
func TestGetNextV1SkipRunEndsInNoSuchNamePerBinding(t *testing.T) {
	vals := counter64Fixture()
	delete(vals, c32HighSpeed) // nothing after the HC run
	s := newTestServer(vals)

	req := []string{".1.3.6.1.2.1.2.2.1.2.0", c32Broadcast}
	hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
		snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, req)))
	if hdr.errStatus != snmpErrNoSuchName || hdr.errIndex != 2 {
		t.Fatalf("error-status=%d error-index=%d, want noSuchName/2",
			hdr.errStatus, hdr.errIndex)
	}
	var want []byte
	for _, o := range req {
		want = append(want, encodeVarBind(o, encodeNull())...)
	}
	if !bytesEqual(hdr.varbinds, want) {
		t.Errorf("varbinds are not the REQUEST echoed with NULL:\n got % x\nwant % x",
			hdr.varbinds, want)
	}
}

// ── overflow: tooBig, never truncated ────────────────────────────────────────

// TestGetNextOverflowIsTooBigNotTruncated pins the third row of the diversion
// table. A GETNEXT is a walk STEP: the manager named N positions, and a
// response carrying fewer bindings than it asked for gives it no way to tell
// which ones were dropped or where to resume them. RFC 3416 §4.2.1's rule
// therefore applies, as it does to GET.
//
// A duplicate name in a variable-bindings list is legal, so the request is one
// predecessor repeated — the cheapest way to build a response far past the
// datagram budget without a 30-interface fixture.
func TestGetNextOverflowIsTooBigNotTruncated(t *testing.T) {
	const long = ".1.3.6.1.2.1.2.2.1.2.9"
	s := newTestServer(map[string]string{
		".1.3.6.1.2.1.2.2.1.2.8": "predecessor",
		long:                     strings.Repeat("x", 200),
	})

	req := make([]string, 40)
	for i := range req {
		req[i] = ".1.3.6.1.2.1.2.2.1.2.8"
	}

	for _, ver := range []int{snmpVersion1, snmpVersion2c} {
		hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
			snmpRequestAt(ASN1_GET_NEXT, ver, req)))
		if hdr.errStatus != snmpErrTooBig {
			t.Fatalf("version %d: error-status=%d, want tooBig(%d): a GETNEXT has no "+
				"resume point for a binding it drops, so it must never be truncated",
				ver, hdr.errStatus, snmpErrTooBig)
		}
		if len(hdr.varbinds) != 0 {
			t.Errorf("version %d: tooBig carries %d bytes of bindings, want an EMPTY list "+
				"(RFC 3416 §4.2.1)", ver, len(hdr.varbinds))
		}
		if len(s.handleSNMPv2cRequest(snmpRequestAt(ASN1_GET_NEXT, ver, req))) > maxSNMPResponseSize {
			t.Errorf("version %d: the response itself exceeds the datagram budget", ver)
		}
	}
}

// ── the rules at the seam, where the walk cannot stand in for them ───────────

// TestGetNextBuilderNeverDivertsOnCounter64 pins the GETNEXT branch of
// v1DiversionRule at the RESPONSE BUILDER, not through the dispatcher.
//
// Through the dispatcher this cannot be reached: getNextBinding's skip run and
// createVarbindResponse's diversion test the same predicate
// (snmpTypeTag == ASN1_COUNTER64), so no Counter64 binding ever arrives here.
// That agreement is the hazard, not the reassurance — it is exactly the drift
// this repo has been bitten by (nl6#539's second predicate), and while it holds,
// flipping the GETNEXT rule to v1DivertSentinelAndCounter64 changes no
// observable behaviour and no dispatcher-level test can see it. So the rule is
// asserted directly.
//
// What the builder does with a Counter64 binding it cannot skip is emit it: tag
// 0x46 is wrong for a v1 manager, but diverting is WORSE, because it truncates
// the walk with no signal (RFC 3584 §4.2.2.1). Skipping is the walk's job and
// the builder has no successor to skip to.
func TestGetNextBuilderNeverDivertsOnCounter64(t *testing.T) {
	s := newTestServer(counter64Fixture())

	names := []string{plainIfDescr}
	oids := []string{c64InOctets}
	responses := []string{"9876543210"}

	hdr := decodeResponseHeader(t, s.createGetNextResponse(names, oids, responses,
		snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, names)))
	if hdr.errStatus != snmpErrNoError {
		t.Fatalf("error-status=%d, want noError: a GETNEXT response must NEVER divert on "+
			"a Counter64 binding — that is the GET rule, and applying it here truncates a "+
			"v1 table with no signal", hdr.errStatus)
	}
	if !containsTagAtVarbindValue(hdr.varbinds, ASN1_COUNTER64) {
		t.Errorf("the binding was dropped rather than emitted; the builder has no successor " +
			"to skip to, so skipping here loses the binding entirely")
	}
}

// TestV1GetBulkThroughDispatcherStillReturnsCounter64 is the WIRING half of
// TestV1GetBulkStillReturnsCounter64. That one calls createVarbindResponse with
// hand-built rules, so it cannot see createGetBulkResponse handing over the
// wrong ones.
//
// The claim is narrow, deliberately (nl6#542 review A4): changing GETBULK's
// rule to v1DivertSentinel ALREADY failed TestGetBulkResponse_SNMPv1NotDiverted
// and TestWellFormedResponsesUnchangedOnTheWire, so the SENTINEL half of that
// wiring was pinned before this test existed. What was NOT pinned is the
// COUNTER64 half — v1DivertSentinelAndCounter64 at that call site — which is
// what this adds.
func TestV1GetBulkThroughDispatcherStillReturnsCounter64(t *testing.T) {
	s := newTestServer(counter64Fixture())

	// max-repetitions 3 from the OID just before the HC run, so the walk lands
	// inside it. snmpRequestAt would ask for zero repetitions.
	req := buildV2cRequestForRoundTrip(ASN1_GET_BULK, snmpVersion1, "public", 42,
		[]string{c32Broadcast}, 0, 3, 0)

	hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(req))
	if hdr.errStatus != snmpErrNoError {
		t.Fatalf("v1 GETBULK error-status=%d, want noError: the divert is not a GETBULK rule",
			hdr.errStatus)
	}
	if !containsTagAtVarbindValue(hdr.varbinds, ASN1_COUNTER64) {
		t.Errorf("v1 GETBULK through the dispatcher no longer carries tag 0x46; the divert " +
			"has escaped into createGetBulkResponse")
	}
}

// TestGetNextEmptyListFallbackFeedsTheEcho covers the new interaction R14
// names: since nl6#542 the nl6#537 `(nil, true)` fallback — an envelope that
// could not be read as far as a variable-bindings list, or an empty list —
// supplies `echoNames` as well as the walk, because both now come from the same
// slice.
//
// `(nil, true)` means "answer from the single OID parseIncomingRequest carries",
// which is parseIncomingRequest's sysDescr.0 default here. So the response must
// carry exactly one binding, and under v1 an exhausted walk must echo THAT
// name — not an empty list, and not a successor.
func TestGetNextEmptyListFallbackFeedsTheEcho(t *testing.T) {
	const defaultOID = ".1.3.6.1.2.1.1.1.0" // parseIncomingRequest's fallback

	// An EMPTY variable-bindings list: well-formed BER, so not the nl6#537
	// discard, and the (nil, true) case by construction.
	emptyList := func(version int) []byte {
		var pduBody []byte
		pduBody = append(pduBody, encodeInteger(42)...)
		pduBody = append(pduBody, encodeInteger(0)...)
		pduBody = append(pduBody, encodeInteger(0)...)
		pduBody = append(pduBody, encodeSequence(nil)...) // zero bindings
		pdu := []byte{ASN1_GET_NEXT}
		pdu = append(pdu, encodeLength(len(pduBody))...)
		pdu = append(pdu, pduBody...)
		var msg []byte
		msg = append(msg, encodeInteger(version)...)
		msg = append(msg, encodeOctetString("public")...)
		msg = append(msg, pdu...)
		return encodeSequence(msg)
	}

	t.Run("v2c answers the single fallback OID", func(t *testing.T) {
		s := newTestServer(map[string]string{
			defaultOID:    "a device",
			plainIfDescr:  "Gi0/1",
			plainIfDescr2: "Gi0/2",
		})
		resp := s.handleSNMPv2cRequest(emptyList(snmpVersion2c))
		if len(resp) == 0 {
			t.Fatal("an EMPTY varbind list was discarded; nl6#537 keeps that distinct " +
				"from a MALFORMED one and answers it from the single parsed OID")
		}
		hdr := decodeResponseHeader(t, resp)
		if hdr.errStatus != snmpErrNoError {
			t.Fatalf("error-status=%d, want noError", hdr.errStatus)
		}
		pairs := decodeVarbindPairs(t, hdr.varbinds)
		if len(pairs) != 1 {
			t.Fatalf("response carries %d bindings, want exactly 1 (the fallback OID)", len(pairs))
		}
	})

	t.Run("v1 answers one binding and logs no rules bug", func(t *testing.T) {
		// The v1 ECHO cannot be reached through this route, and the reason is
		// worth recording rather than working around: findNextOID always
		// injects sysName.0 and sysLocation.0 as walk candidates (see
		// newTestServer), so the fallback sysDescr.0 always HAS a successor and
		// never reaches end of MIB. The echo itself is pinned by
		// TestGetNextAllEndOfMibV1.
		//
		// What this row does pin is the interaction R14 named: the fallback
		// slice feeds BOTH the walk and echoNames, so the two are the same
		// length by construction and createVarbindResponse must not report a
		// mis-sized echo.
		s := newTestServer(map[string]string{defaultOID: "a device"})

		var buf bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&buf)
		t.Cleanup(func() { log.SetOutput(prev) })

		hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(emptyList(snmpVersion1)))
		if hdr.errStatus != snmpErrNoError {
			t.Fatalf("error-status=%d, want noError: sysDescr.0's successor is the injected "+
				"sysName.0, so this walk does not end", hdr.errStatus)
		}
		if pairs := decodeVarbindPairs(t, hdr.varbinds); len(pairs) != 1 {
			t.Fatalf("response carries %d bindings, want exactly 1", len(pairs))
		}
		if strings.Contains(buf.String(), "echoNames length") {
			t.Errorf("the fallback produced a mis-sized echo:\n%s", buf.String())
		}
	})
}

// TestGetNextSingleBindingOverflowIsTooBig is the case the multi-binding
// overflow row above cannot reach: ONE binding whose VALUE alone exceeds the
// datagram budget (nl6#542 review A5).
//
// This is where the behaviour change nl6#542 introduced actually bites. Before
// it, a single-binding GETNEXT went through createSNMPResponse, which applied no
// size bound at all and emitted an over-budget datagram; it now goes through
// createVarbindResponse and answers tooBig. Better, and required by the
// diversion table, but it IS a change to a shape the acceptance criteria called
// frozen — so it gets its own test rather than a line in a commit message.
//
// Not reachable with shipped resources: no shipped value approaches the budget.
// Reachable with an operator resource file, which is why the fixture builds one.
func TestGetNextSingleBindingOverflowIsTooBig(t *testing.T) {
	const pred, long = ".1.3.6.1.2.1.2.2.1.2.8", ".1.3.6.1.2.1.2.2.1.2.9"
	s := newTestServer(map[string]string{
		pred: "predecessor",
		long: strings.Repeat("x", 1600), // one value, past the 1472 B budget
	})

	for _, ver := range []int{snmpVersion1, snmpVersion2c} {
		resp := s.handleSNMPv2cRequest(snmpRequestAt(ASN1_GET_NEXT, ver, []string{pred}))
		hdr := decodeResponseHeader(t, resp)
		if hdr.errStatus != snmpErrTooBig {
			t.Errorf("version %d: error-status=%d, want tooBig(%d) for a single binding whose "+
				"value alone exceeds the budget", ver, hdr.errStatus, snmpErrTooBig)
		}
		if len(hdr.varbinds) != 0 {
			t.Errorf("version %d: tooBig carries %d bytes of bindings, want an empty list",
				ver, len(hdr.varbinds))
		}
		if len(resp) > maxSNMPResponseSize {
			t.Errorf("version %d: the response is %d B, over the %d B budget — which is the "+
				"pre-nl6#542 behaviour this change replaced", ver, len(resp), maxSNMPResponseSize)
		}
	}
}

// ── on a device with a live counter cycler ──────────────────────────────────

// TestGetNextMultiBindingOnALiveCyclerDevice covers what every other test in
// this file cannot: newTestServer has no metricsCycler, so its walk sees only
// the static resource index (nl6#542 review A2).
//
// That matters twice over. A real fleet's ifTable/ifXTable walk mostly returns
// ANALYTICALLY served rows, and those are exactly the OIDs the Counter64 skip
// run steps through — the reason the 288 figure was 4x too small. So the
// multi-binding path is exercised here against a real shipped profile with the
// cycler initialised the way both production creation paths do.
func TestGetNextMultiBindingOnALiveCyclerDevice(t *testing.T) {
	s := deviceForProfile(t, "cisco_crs_x.json")

	// An ifXTable position whose successor is analytically served, so the walk
	// must consult the cycler rather than the static index.
	const beforeHC = ".1.3.6.1.2.1.31.1.1.1.6.99999"
	next, _ := s.findNextOID(beforeHC)
	if snmpTypeTag(next) != ASN1_COUNTER64 {
		t.Fatalf("precondition failed: successor of %s is %s, expected a Counter64", beforeHC, next)
	}
	if _, ok := s.device.resources.oidIndex.Load(next); ok {
		t.Fatalf("precondition failed: %s is statically served, so this test would not "+
			"exercise the cycler at all", next)
	}

	t.Run("v2c returns the analytic Counter64 for every binding", func(t *testing.T) {
		req := []string{beforeHC, beforeHC, ".1.3.6.1.2.1.2.2.1.2.1"}
		hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
			snmpRequestAt(ASN1_GET_NEXT, snmpVersion2c, req)))
		if hdr.errStatus != snmpErrNoError {
			t.Fatalf("error-status=%d, want noError", hdr.errStatus)
		}
		pairs := decodeVarbindPairs(t, hdr.varbinds)
		if len(pairs) != len(req) {
			t.Fatalf("response carries %d bindings, want %d", len(pairs), len(req))
		}
		for i := 0; i < 2; i++ {
			if pairs[i].tag != ASN1_COUNTER64 {
				t.Errorf("binding %d value tag = 0x%02x, want Counter64 0x46", i+1, pairs[i].tag)
			}
			if pairs[i].oid != next {
				t.Errorf("binding %d is %s, want the analytic successor %s", i+1, pairs[i].oid, next)
			}
		}
	})

	t.Run("v1 skips the whole analytic run on every binding", func(t *testing.T) {
		req := []string{beforeHC, beforeHC, beforeHC}
		hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(
			snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, req)))
		if hdr.errStatus != snmpErrNoError {
			t.Fatalf("error-status=%d, want noError: a v1 GETNEXT SKIPS a Counter64", hdr.errStatus)
		}
		pairs := decodeVarbindPairs(t, hdr.varbinds)
		if len(pairs) != len(req) {
			t.Fatalf("response carries %d bindings, want %d", len(pairs), len(req))
		}
		for i, p := range pairs {
			if p.tag == ASN1_COUNTER64 {
				t.Errorf("binding %d carries tag 0x46, which does not exist in SNMPv1", i+1)
			}
			if p.oid == next {
				t.Errorf("binding %d returned the Counter64 OID %s itself", i+1, p.oid)
			}
		}
		// Every binding must land on the SAME successor: the skip is a pure
		// function of the walk, so three identical names cannot disagree.
		if pairs[0].oid != pairs[1].oid || pairs[1].oid != pairs[2].oid {
			t.Errorf("three identical names produced %s, %s, %s",
				pairs[0].oid, pairs[1].oid, pairs[2].oid)
		}
		t.Logf("v1 skipped the analytic Counter64 run and landed on %s", pairs[0].oid)
	})

	t.Run("the shared budget bounds the real profile", func(t *testing.T) {
		// The measured amplification, as an upper bound rather than a timing
		// assertion: the walk work of N identical bindings must stay inside ONE
		// datagram's budget, which is what the shared budget guarantees.
		req := make([]string, 40)
		for i := range req {
			req[i] = beforeHC
		}
		budget := newCounter64SkipBudget()
		served := s.lldpServedOIDs()
		s.getNextBindingsForRequest(req, served, snmpVersion1, budget)
		spent := counter64SkipBudgetSteps() - budget.remaining
		if spent > counter64SkipBudgetSteps() {
			t.Fatalf("spent %d steps against a %d budget", spent, counter64SkipBudgetSteps())
		}
		if spent < len(req)*longestShippedCounter64Run/2 {
			t.Errorf("40 bindings spent only %d steps; the profile's run is %d, so the skip "+
				"did not actually happen and this bound is vacuous",
				spent, longestShippedCounter64Run)
		}
		t.Logf("40 bindings spent %d of %d budgeted skip steps on the widest shipped profile",
			spent, counter64SkipBudgetSteps())
	})
}
