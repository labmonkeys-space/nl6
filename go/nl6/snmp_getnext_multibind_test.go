/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
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
		out = append(out, varbindPair{oid: name, tag: body[vpos]})
		pos = next + vbLen
	}
	return out
}

// assertBindings checks the decoded names against `want`, positionally. Count
// first, because a length mismatch makes every index assertion below it
// misleading.
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
	for i := range want {
		if !containsOID([]string{got[i].oid}, want[i]) {
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
// wrong ones — changing GETBULK's rule to v1DivertSentinelAndCounter64 left the
// whole suite green until this was added.
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
