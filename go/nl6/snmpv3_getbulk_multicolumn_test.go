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

// nl6#535, last piece: an SNMPv3 GETBULK naming several columns used to be
// answered from the FIRST column only — the one binding
// extractOIDAndTypeFromScopedPDU validates — so a manager bundling
// ifDescr/ifName/ifAlias in one request got successors of ifDescr and nothing
// at all for the rest. Wrong under RFC 3416 §4.2.3, not merely small.
//
// One test per row of the change's I/O matrix, plus the property that matters
// most: the v3 binding list agrees with the v2c one for the same columns and
// parameters. Each path being separately plausible is not the same as the two
// agreeing.

// ── fixtures and builders ───────────────────────────────────────────────────

const (
	colIfDescr  = ".1.3.6.1.2.1.2.2.1.2"
	colIfName   = ".1.3.6.1.2.1.31.1.1.1.1"
	colSysOR    = ".1.3.6.1.2.1.1.9.1.3"
	colPastEnd  = ".1.3.6.1.9.9.9.1"
	colPastEnd2 = ".1.3.6.1.9.9.9.2"
)

// multiColFixture serves n rows in each of three DisplayString columns. The
// columns are string-typed on purpose: a type difference between the v2c and
// v3 encoders would be a real finding, but it is not the one these tests are
// looking for, and mixing types in makes a failure ambiguous.
func multiColFixture(n int) map[string]string {
	vals := map[string]string{".1.3.6.1.2.1.1.1.0": "dev"}
	for i := 1; i <= n; i++ {
		vals[fmt.Sprintf("%s.%d", colIfDescr, i)] = fmt.Sprintf("Gi0/%d", i)
		vals[fmt.Sprintf("%s.%d", colIfName, i)] = fmt.Sprintf("Gi0/%d-name", i)
		vals[fmt.Sprintf("%s.%d", colSysOR, i)] = fmt.Sprintf("module-%d", i)
	}
	return vals
}

// v3BulkScopedPDUCols builds a GETBULK scoped PDU in CONTENTS form naming
// several columns, which is the shape parseAllOIDsFromScopedPDU and
// parseSNMPv3GetBulkParams both read.
func v3BulkScopedPDUCols(engineID string, nonRepeaters, maxRepetitions int, oids []string) []byte {
	var vbList []byte
	for _, oid := range oids {
		vbList = append(vbList, encodeSequence(append(encodeOID(oid), encodeNull()...))...)
	}
	var body []byte
	body = append(body, encodeInteger(42)...)
	body = append(body, encodeInteger(nonRepeaters)...)
	body = append(body, encodeInteger(maxRepetitions)...)
	body = append(body, encodeSequence(vbList)...)
	pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)

	var scoped []byte
	scoped = append(scoped, encodeOctetString(engineID)...)
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, pdu...)
	return scoped
}

// v3Bulk serves a multi-column GETBULK and returns the decoded response.
func v3Bulk(t *testing.T, s *SNMPServer, nonRepeaters, maxRepetitions int, cols []string) v3Response {
	t.Helper()
	sp := v3BulkScopedPDUCols(s.v3Config.EngineID, nonRepeaters, maxRepetitions, cols)
	msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: sp}
	resp := s.handleSNMPv3GetBulk(cols[0], msg, sp)
	if len(resp) == 0 {
		t.Fatalf("no response for %d columns, non-repeaters=%d, max-repetitions=%d",
			len(cols), nonRepeaters, maxRepetitions)
	}
	return decodeV3Response(t, resp)
}

// v2cGetBulkRequest is the v2c twin of v3BulkScopedPDUCols. It is a local
// builder rather than snmp_getbulk_test.go's buildGetBulkPDU because that file
// is //go:build linux and its helpers are invisible here.
func v2cGetBulkRequest(nonRepeaters, maxRepetitions int, oids []string) []byte {
	var vbList []byte
	for _, oid := range oids {
		vbList = append(vbList, encodeSequence(append(encodeOID(oid), encodeNull()...))...)
	}
	body := encodeInteger(42)
	body = append(body, encodeInteger(nonRepeaters)...)
	body = append(body, encodeInteger(maxRepetitions)...)
	body = append(body, encodeSequence(vbList)...)
	pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)

	msg := encodeInteger(snmpVersion2c)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// decodeV2cVarbinds decodes every binding of a v2c GetResponse. The existing
// v2cFirstVarbind stops at the first, which cannot see an interleave.
func decodeV2cVarbinds(t *testing.T, resp []byte) []v3Varbind {
	t.Helper()
	body := expectSeq(t, resp, "v2c message")
	pos := skipTLV(t, body, 0, "version")
	pos = skipTLV(t, body, pos, "community")
	if pos >= len(body) {
		t.Fatal("no PDU")
	}
	n, after := parseLength(body, pos+1)
	if n < 0 || after+n > len(body) {
		t.Fatal("bad PDU length")
	}
	pdu := body[after : after+n]

	pp := 0
	_, pp = expectInt(t, pdu, pp, "request-id")
	_, pp = expectInt(t, pdu, pp, "error-status")
	_, pp = expectInt(t, pdu, pp, "error-index")

	vbl := expectSeq(t, pdu[pp:], "variable-bindings")
	var out []v3Varbind
	for vp := 0; vp < len(vbl); {
		vb := expectSeq(t, vbl[vp:], "varbind")
		l, a := parseLength(vbl, vp+1)
		if l < 0 || a+l > len(vbl) {
			t.Fatal("bad varbind length")
		}
		vp = a + l

		if len(vb) == 0 || vb[0] != ASN1_OID {
			t.Fatalf("varbind does not start with an OBJECT IDENTIFIER: % x", vb)
		}
		nameLen, afterName := parseLength(vb, 1)
		if nameLen < 0 || afterName+nameLen > len(vb) {
			t.Fatal("bad varbind name length")
		}
		v := v3Varbind{oid: decodeOID(vb[afterName : afterName+nameLen])}
		vpos := afterName + nameLen
		if vpos >= len(vb) {
			t.Fatal("varbind has a name but no value")
		}
		v.valueTag = vb[vpos]
		vlen, afterV := parseLength(vb, vpos+1)
		if vlen >= 0 && afterV+vlen <= len(vb) {
			v.value = vb[afterV : afterV+vlen]
		}
		out = append(out, v)
	}
	return out
}

func pairs(vbs []v3Varbind) []string {
	out := make([]string, len(vbs))
	for i, vb := range vbs {
		out[i] = fmt.Sprintf("%s=0x%02x:%q", vb.oid, vb.valueTag, vb.value)
	}
	return out
}

// ── matrix rows ─────────────────────────────────────────────────────────────

// Row "Multi-column repeaters": 3 columns, max-repetitions 4, non-repeaters 0
// → 12 bindings, interleaved column by column per repetition.
//
// This is the defect itself: before the fix the response carried 4 bindings,
// all successors of the first column, and the other two were answered with
// nothing at all.
func TestV3GetBulkAnswersEveryColumn(t *testing.T) {
	s := v3TestServer(multiColFixture(10))
	cols := []string{colIfDescr, colIfName, colSysOR}

	r := v3Bulk(t, s, 0, 4, cols)
	if len(r.varbinds) != 12 {
		t.Fatalf("got %d bindings, want 12 (3 columns × 4 repetitions): %v", len(r.varbinds), pairs(r.varbinds))
	}
	if r.errStatus != 0 || r.pduTag != ASN1_GET_RESPONSE {
		t.Errorf("PDU 0x%02x error-status %d, want GetResponse/noError", r.pduTag, r.errStatus)
	}

	// Position i belongs to column i%3, and within a column the OIDs ascend.
	// A handler that answered every slot from the first column would satisfy
	// "12 bindings" and fail here.
	for i, vb := range r.varbinds {
		want := cols[i%len(cols)]
		if !strings.HasPrefix(vb.oid, want+".") {
			t.Errorf("binding %d is %q, want a successor of column %q: the interleave is "+
				"column-by-column within each repetition", i, vb.oid, want)
		}
	}
	for col := range cols {
		prev := ""
		for rep := 0; rep < 4; rep++ {
			got := r.varbinds[rep*len(cols)+col].oid
			if prev != "" && compareOIDsLexicographically(got, prev) <= 0 {
				t.Errorf("column %d: %q does not advance past %q", col, got, prev)
			}
			prev = got
		}
	}
}

// Row "Non-repeaters split": 5 columns, non-repeaters 2, max-repetitions 3 →
// 2 bindings (one successor each) + 9 (3 repetitions × 3 repeater columns).
func TestV3GetBulkNonRepeatersSplit(t *testing.T) {
	s := v3TestServer(multiColFixture(10))
	// Two non-repeater columns first, then three repeater columns. The
	// repeaters repeat the same three tables from different starting rows, so
	// each has successors to give.
	cols := []string{
		".1.3.6.1.2.1.1.1.0",
		colIfDescr + ".1",
		colIfDescr + ".5",
		colIfName + ".5",
		colSysOR + ".5",
	}

	r := v3Bulk(t, s, 2, 3, cols)
	if len(r.varbinds) != 2+9 {
		t.Fatalf("got %d bindings, want 11 (2 non-repeaters + 3 repetitions × 3 columns): %v",
			len(r.varbinds), pairs(r.varbinds))
	}
	// The two non-repeater slots come first and each carries ONE successor of
	// its own column, not max-repetitions of them.
	for i := 0; i < 2; i++ {
		if compareOIDsLexicographically(r.varbinds[i].oid, cols[i]) <= 0 {
			t.Errorf("non-repeater %d answered %q, which does not advance past %q",
				i, r.varbinds[i].oid, cols[i])
		}
	}
	// The repeater section is interleaved over the remaining three columns.
	for i := 2; i < len(r.varbinds); i++ {
		want := cols[2+(i-2)%3]
		base := want[:strings.LastIndex(want, ".")]
		if !strings.HasPrefix(r.varbinds[i].oid, base+".") {
			t.Errorf("binding %d is %q, want a successor within column %q", i, r.varbinds[i].oid, base)
		}
	}
}

// Row "max-repetitions 0 WITH non-repeaters": exactly the non-repeater
// bindings, noError, and NOT an empty list or an endOfMibView.
//
// The single-column handler could not express this row at all: it collapsed
// any non-repeaters into max-repetitions = 1, so the M = 0 test never ran with
// non-repeaters present.
func TestV3GetBulkZeroRepetitionsKeepsNonRepeaters(t *testing.T) {
	s := v3TestServer(multiColFixture(10))
	cols := []string{".1.3.6.1.2.1.1.1.0", colIfDescr + ".1", colIfName + ".1"}

	r := v3Bulk(t, s, 2, 0, cols)
	if len(r.varbinds) != 2 {
		t.Fatalf("got %d bindings, want the 2 non-repeaters: %v", len(r.varbinds), pairs(r.varbinds))
	}
	if r.errStatus != 0 {
		t.Errorf("error-status = %d, want noError", r.errStatus)
	}
	for i, vb := range r.varbinds {
		if vb.valueTag == 0x82 || vb.valueTag == 0x80 {
			t.Errorf("non-repeater %d carries exception 0x%02x; the columns have successors", i, vb.valueTag)
		}
	}
}

// Row "non-repeaters exceeds column count": every column is a non-repeater and
// there is no repeater loop. RFC 3416 §4.2.3 takes N = min(non-repeaters, L).
func TestV3GetBulkNonRepeatersExceedColumnCount(t *testing.T) {
	s := v3TestServer(multiColFixture(10))
	cols := []string{colIfDescr + ".1", colIfName + ".1"}

	r := v3Bulk(t, s, 5, 7, cols)
	if len(r.varbinds) != 2 {
		t.Fatalf("got %d bindings, want 2 (one per column, all non-repeaters): %v",
			len(r.varbinds), pairs(r.varbinds))
	}
	for i, vb := range r.varbinds {
		if compareOIDsLexicographically(vb.oid, cols[i]) <= 0 {
			t.Errorf("binding %d is %q, which does not advance past %q", i, vb.oid, cols[i])
		}
	}
}

// Row "one column exhausts early": the exhausted column's remaining slots are
// named with ITS OWN requested OID and valued endOfMibView, while the other
// column keeps producing.
//
// Naming is the load-bearing half: an exception on a slot named with another
// column's OID tells the manager the wrong column ended, and nl6#526 is the
// record of what a wrongly-named binding costs a walker.
func TestV3GetBulkPadsAnExhaustedColumn(t *testing.T) {
	s := v3TestServer(multiColFixture(10))
	cols := []string{colIfDescr + ".1", colPastEnd}

	r := v3Bulk(t, s, 0, 3, cols)
	if len(r.varbinds) != 6 {
		t.Fatalf("got %d bindings, want 6 (2 columns × 3 repetitions): %v", len(r.varbinds), pairs(r.varbinds))
	}
	for rep := 0; rep < 3; rep++ {
		live, dead := r.varbinds[rep*2], r.varbinds[rep*2+1]
		if live.valueTag == 0x82 {
			t.Errorf("repetition %d: the live column carries endOfMibView; it has successors", rep)
		}
		if dead.valueTag != 0x82 {
			t.Errorf("repetition %d: the exhausted column carries tag 0x%02x, want 0x82", rep, dead.valueTag)
		}
		if dead.oid != colPastEnd {
			t.Errorf("repetition %d: the pad is named %q, want the column's OWN requested OID %q",
				rep, dead.oid, colPastEnd)
		}
	}
}

// Row "all columns exhausted": each column contributes its requested OID and
// endOfMibView, once. Every column the manager named is answered; nothing more
// is emitted, because further repetitions of nothing but exceptions tell a
// walker only what the first already did.
func TestV3GetBulkAllColumnsExhausted(t *testing.T) {
	s := v3TestServer(multiColFixture(10))
	cols := []string{colPastEnd, colPastEnd2}

	r := v3Bulk(t, s, 0, 5, cols)
	if len(r.varbinds) != 2 {
		t.Fatalf("got %d bindings, want one per column: %v", len(r.varbinds), pairs(r.varbinds))
	}
	for i, vb := range r.varbinds {
		if vb.oid != cols[i] {
			t.Errorf("binding %d named %q, want the requested %q", i, vb.oid, cols[i])
		}
		if vb.valueTag != 0x82 {
			t.Errorf("binding %d tag 0x%02x, want 0x82 (endOfMibView)", i, vb.valueTag)
		}
	}
	if r.errStatus != 0 {
		t.Errorf("error-status = %d, want noError: the exception is a VALUE", r.errStatus)
	}
}

// Row "single column": unchanged. Two shapes matter and they end differently.
//
// A single column that runs out mid-response ships exactly what it collected —
// no trailing exception — which is the nl6#526 contract, and a single column
// already past the end ships one binding named with the requested OID. This is
// where the handler deliberately parts company with v2c, which would pad both
// to max-repetitions; see TestV3GetBulkOrderMatchesV2c.
func TestV3GetBulkSingleColumnUnchanged(t *testing.T) {
	s := v3TestServer(multiColFixture(4))

	t.Run("runs out mid-response", func(t *testing.T) {
		// Four rows in the column, ten asked for. The walk continues past the
		// column into the rest of the MIB and then ends, so the oracle is the
		// collection loop itself.
		var want []string
		cur := colIfDescr + ".1"
		for i := 0; i < 10; i++ {
			n, v := s.findNextOID(cur)
			if n == "" || v == valueEndOfMibView {
				break
			}
			want = append(want, n)
			cur = n
		}
		if len(want) >= 10 {
			t.Fatalf("fixture does not run out within 10 repetitions (%d successors)", len(want))
		}
		r := v3Bulk(t, s, 0, 10, []string{colIfDescr + ".1"})
		if len(r.varbinds) != len(want) {
			t.Fatalf("got %d bindings, want the %d collected and no trailing exception: %v",
				len(r.varbinds), len(want), pairs(r.varbinds))
		}
		for i, vb := range r.varbinds {
			if vb.oid != want[i] {
				t.Errorf("binding %d is %q, want %q", i, vb.oid, want[i])
			}
		}
	})

	t.Run("already past the end", func(t *testing.T) {
		r := v3Bulk(t, s, 0, 10, []string{colPastEnd})
		if len(r.varbinds) != 1 {
			t.Fatalf("got %d bindings, want 1: %v", len(r.varbinds), pairs(r.varbinds))
		}
		if r.varbinds[0].oid != colPastEnd || r.varbinds[0].valueTag != 0x82 {
			t.Errorf("got %s tag 0x%02x, want %s with 0x82", r.varbinds[0].oid, r.varbinds[0].valueTag, colPastEnd)
		}
	})
}

// Row "budget overflow": many columns × a large max-repetitions truncates to
// the largest fitting PREFIX and always ships at least one binding. Never a
// tooBig — RFC 3416 §4.2.3 lets a GETBULK truncate because the walker resumes
// from the last OID returned.
func TestV3GetBulkMultiColumnRespectsTheBudget(t *testing.T) {
	vals := map[string]string{".1.3.6.1.2.1.1.1.0": "dev"}
	for i := 1; i <= 40; i++ {
		vals[fmt.Sprintf("%s.%d", colIfDescr, i)] = strings.Repeat("A", 200)
		vals[fmt.Sprintf("%s.%d", colIfName, i)] = strings.Repeat("B", 200)
		vals[fmt.Sprintf("%s.%d", colSysOR, i)] = strings.Repeat("C", 200)
	}
	s := v3TestServer(vals)
	cols := []string{colIfDescr, colIfName, colSysOR}

	sp := v3BulkScopedPDUCols(s.v3Config.EngineID, 0, 100, cols)
	msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: sp}
	resp := s.handleSNMPv3GetBulk(cols[0], msg, sp)
	if len(resp) == 0 {
		t.Fatal("no response")
	}
	if len(resp) > maxSNMPResponseSize {
		t.Fatalf("response is %d bytes, over the %d-byte budget: it would fragment",
			len(resp), maxSNMPResponseSize)
	}
	r := decodeV3Response(t, resp)
	if len(r.varbinds) == 0 {
		t.Fatal("no bindings; a GETBULK must emit at least one or the walk stalls")
	}
	if r.errStatus != 0 {
		t.Errorf("error-status = %d, want noError: a GETBULK truncates rather than answering tooBig", r.errStatus)
	}
	// Premise: the untruncated collection really was bigger than what shipped.
	if len(r.varbinds) >= 300 {
		t.Fatalf("fixture no longer overflows (%d bindings shipped of 300 asked)", len(r.varbinds))
	}
	// Truncation drops from the END, so what shipped is a prefix of the
	// interleave: position i still belongs to column i%3.
	for i, vb := range r.varbinds {
		if !strings.HasPrefix(vb.oid, cols[i%3]+".") {
			t.Fatalf("binding %d is %q, want column %q: truncation must drop from the end, "+
				"or a walker resuming from the last OID silently skips rows", i, vb.oid, cols[i%3])
		}
	}
}

// Row "malformed binding list": the datagram is discarded and the discard is
// logged once per device. The nl6#537/#547 rule is not relaxed by the multi-
// column parse; if anything it widens, because a LATER binding can now be the
// malformed one.
func TestV3GetBulkMalformedListDiscarded(t *testing.T) {
	s := v3TestServer(multiColFixture(10))

	// A well-formed first binding followed by one whose name is not a valid
	// OBJECT IDENTIFIER. The dispatcher's extractor validates the first only,
	// so before the multi-column parse this was answered.
	good := encodeSequence(append(encodeOID(colIfDescr), encodeNull()...))
	badName := []byte{ASN1_OID, 0x02, 0x80, 0x80} // unterminated varint
	bad := encodeSequence(append(append([]byte{}, badName...), encodeNull()...))

	var body []byte
	body = append(body, encodeInteger(42)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeInteger(5)...)
	body = append(body, encodeSequence(append(good, bad...))...)
	pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)

	var sp []byte
	sp = append(sp, encodeOctetString(s.v3Config.EngineID)...)
	sp = append(sp, encodeOctetString("")...)
	sp = append(sp, pdu...)

	// Premise: the first name is fine, so this is not caught upstream.
	if _, _, err := s.extractOIDAndTypeFromScopedPDU(sp); err != nil {
		t.Fatalf("premise broken: the dispatcher already rejects this PDU (%v)", err)
	}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: sp}
	if resp := s.handleSNMPv3GetBulk(colIfDescr, msg, sp); len(resp) != 0 {
		t.Fatalf("a malformed variable-bindings list was answered with %d bytes; RFC 3412 §7.2 "+
			"discards the datagram", len(resp))
	}
	// Answering a second one logs nothing further: the condition is
	// attacker-controlled, so an ungated line is a log-flood primitive.
	_ = s.handleSNMPv3GetBulk(colIfDescr, msg, sp)
	if n := strings.Count(buf.String(), "does not parse"); n != 1 {
		t.Errorf("logged the discard %d times, want exactly 1 per device: %q", n, buf.String())
	}
}

// Row "empty binding list": discarded, as today. The list never reaches this
// handler — extractOIDAndTypeFromScopedPDU refuses it — so the assertion runs
// through the dispatcher, which is where the behaviour lives.
func TestV3GetBulkEmptyBindingListDiscarded(t *testing.T) {
	s := v3TestServer(multiColFixture(10))

	var body []byte
	body = append(body, encodeInteger(42)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeInteger(5)...)
	body = append(body, encodeSequence(nil)...)
	pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)

	var scoped []byte
	scoped = append(scoped, encodeOctetString(s.v3Config.EngineID)...)
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, pdu...)

	if _, _, err := s.extractOIDAndTypeFromScopedPDU(scoped); err == nil {
		t.Fatal("an empty variable-bindings list parsed cleanly; nl6#547 discards it")
	}
	if oids, ok := parseAllOIDsFromScopedPDU(scoped); !ok || len(oids) != 0 {
		t.Errorf("parseAllOIDsFromScopedPDU on an empty list = (%v, %v), want (nil, true): an "+
			"empty list is ABSENT, not malformed, and the two take different answers", oids, ok)
	}
}

// ── the property: v3 agrees with v2c ────────────────────────────────────────

// TestV3GetBulkOrderMatchesV2c is the point of the change. Each path being
// separately plausible is not the property; the two agreeing is.
//
// The agreement is asserted over the bindings BOTH paths emit. There is one
// known divergence, in the tail only, and it is asserted here rather than
// papered over: when every column has been exhausted, v2c keeps padding for
// each remaining repetition while v3 stops. The v3 behaviour is the one
// nl6#526 established (a walk that runs out ships what it collected, and the
// next request gets the exception); the v2c behaviour is not wrong under RFC
// 3416 either, since the padded slots carry the right names and the right
// exception. Reported, not resolved by changing the reference.
func TestV3GetBulkOrderMatchesV2c(t *testing.T) {
	cases := []struct {
		name           string
		nonRep, maxRep int
		cols           []string
	}{
		{"three columns, four repetitions", 0, 4, []string{colIfDescr, colIfName, colSysOR}},
		{"two columns, one repetition", 0, 1, []string{colIfDescr, colIfName}},
		{"non-repeaters split", 2, 3, []string{
			".1.3.6.1.2.1.1.1.0", colIfDescr + ".1", colIfDescr + ".5", colIfName + ".5", colSysOR + ".5",
		}},
		{"one column exhausted, one live", 0, 3, []string{colIfDescr + ".1", colPastEnd}},
		{"single column", 0, 5, []string{colIfDescr}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := multiColFixture(20)
			v3 := v3Bulk(t, v3TestServer(fixture), tc.nonRep, tc.maxRep, tc.cols)
			v2c := decodeV2cVarbinds(t, newTestServer(fixture).handleGetBulk(
				tc.cols[0], v2cGetBulkRequest(tc.nonRep, tc.maxRep, tc.cols)))

			gotV3, gotV2c := pairs(v3.varbinds), pairs(v2c)
			if len(gotV3) != len(gotV2c) {
				t.Fatalf("v3 emitted %d bindings, v2c %d\nv3:  %v\nv2c: %v",
					len(gotV3), len(gotV2c), gotV3, gotV2c)
			}
			for i := range gotV3 {
				if gotV3[i] != gotV2c[i] {
					t.Errorf("binding %d differs:\n v3:  %s\n v2c: %s", i, gotV3[i], gotV2c[i])
				}
			}
		})
	}
}

// TestV3GetBulkTailDivergesFromV2cOnlyWhenExhausted documents the one case the
// agreement test above deliberately excludes, so the divergence is pinned
// rather than merely described in a comment: with every column exhausted, v2c
// pads to max-repetitions and v3 answers each column once. If either side
// changes, this fails and the decision gets revisited.
func TestV3GetBulkTailDivergesFromV2cOnlyWhenExhausted(t *testing.T) {
	fixture := multiColFixture(10)
	cols := []string{colPastEnd, colPastEnd2}
	const maxRep = 4

	v3 := v3Bulk(t, v3TestServer(fixture), 0, maxRep, cols)
	v2c := decodeV2cVarbinds(t, newTestServer(fixture).handleGetBulk(
		cols[0], v2cGetBulkRequest(0, maxRep, cols)))

	if len(v3.varbinds) != len(cols) {
		t.Errorf("v3 emitted %d bindings, want one per column: %v", len(v3.varbinds), pairs(v3.varbinds))
	}
	if len(v2c) != len(cols)*maxRep {
		t.Errorf("v2c emitted %d bindings, want %d (it pads every repetition): %v",
			len(v2c), len(cols)*maxRep, pairs(v2c))
	}
	// What they DO emit agrees: v3's bindings are the prefix of v2c's.
	gotV3, gotV2c := pairs(v3.varbinds), pairs(v2c)
	for i := range gotV3 {
		if i < len(gotV2c) && gotV3[i] != gotV2c[i] {
			t.Errorf("binding %d differs:\n v3:  %s\n v2c: %s", i, gotV3[i], gotV2c[i])
		}
	}
}

// ── the parser's two zero cases ─────────────────────────────────────────────

// parseAllOIDsFromScopedPDU carries parseAllOIDsFromRequest's contract, and
// the bool is what separates "discard the datagram" from "answer it from the
// single OID the dispatcher already validated". Collapsing them either drops
// requests this server used to answer or answers ones RFC 3412 requires it to
// discard, and neither shows up in a response-shaped assertion.
func TestParseAllOIDsFromScopedPDUContract(t *testing.T) {
	const engine = "0x80001234"

	t.Run("well formed multi-column", func(t *testing.T) {
		cols := []string{colIfDescr, colIfName, colSysOR}
		got, ok := parseAllOIDsFromScopedPDU(v3BulkScopedPDUCols(engine, 0, 5, cols))
		if !ok {
			t.Fatal("a well-formed list reported malformed")
		}
		if len(got) != len(cols) {
			t.Fatalf("parsed %v, want %v", got, cols)
		}
		for i := range cols {
			if got[i] != cols[i] {
				t.Errorf("name %d = %q, want %q (order must be preserved)", i, got[i], cols[i])
			}
		}
	})

	t.Run("unreadable envelope is absent, not malformed", func(t *testing.T) {
		for name, sp := range map[string][]byte{
			"nil":                 nil,
			"garbage":             {0x00, 0x01, 0x02},
			"truncated":           {ASN1_OCTET_STRING, 0x02, 0x41},
			"a GET, no bulk ints": validScopedPDU(".1.3.6.1.2.1.1.1.0"),
		} {
			t.Run(name, func(t *testing.T) {
				got, ok := parseAllOIDsFromScopedPDU(sp)
				if !ok {
					t.Errorf("reported malformed; an unreadable envelope is the ABSENT case, "+
						"which the dispatcher's single OID still covers (got %v)", got)
				}
			})
		}
	})

	t.Run("broken list is malformed", func(t *testing.T) {
		good := encodeSequence(append(encodeOID(colIfDescr), encodeNull()...))
		for name, vbList := range map[string][]byte{
			"name is not an OID":        encodeSequence([]byte{ASN1_OID, 0x02, 0x80, 0x80, 0x05, 0x00}),
			"binding is not a SEQUENCE": {ASN1_INTEGER, 0x01, 0x00},
			"binding has no value":      encodeSequence(encodeOID(colIfDescr)),
			"second binding broken":     append(append([]byte{}, good...), ASN1_INTEGER, 0x01, 0x00),
		} {
			t.Run(name, func(t *testing.T) {
				var body []byte
				body = append(body, encodeInteger(42)...)
				body = append(body, encodeInteger(0)...)
				body = append(body, encodeInteger(5)...)
				body = append(body, encodeSequence(vbList)...)
				pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)
				var sp []byte
				sp = append(sp, encodeOctetString(engine)...)
				sp = append(sp, encodeOctetString("")...)
				sp = append(sp, pdu...)

				if got, ok := parseAllOIDsFromScopedPDU(sp); ok {
					t.Errorf("parsed as %v, want malformed: a short binding list answers fewer "+
						"bindings than the request carried, against RFC 3416's correspondence "+
						"requirement", got)
				}
			})
		}
	})

	t.Run("list is bounded by the PDU, not the datagram", func(t *testing.T) {
		// A PDU whose declared length ends before the list does. Bounding the
		// list by the datagram instead would read into bytes the PDU does not
		// claim — the nl6#537 rule.
		sp := v3BulkScopedPDUCols(engine, 0, 5, []string{colIfDescr, colIfName})
		full, _ := parseAllOIDsFromScopedPDU(sp)
		if len(full) != 2 {
			t.Fatalf("premise: parsed %v, want 2 names", full)
		}
		// Shorten the PDU's declared length by one binding's worth.
		pduStart := len(encodeOctetString(engine)) + len(encodeOctetString(""))
		if sp[pduStart] != ASN1_GET_BULK {
			t.Fatalf("premise: no GETBULK tag at %d", pduStart)
		}
		short := append([]byte(nil), sp...)
		short[pduStart+1] -= 4
		if _, ok := parseAllOIDsFromScopedPDU(short); ok {
			t.Error("a list running past its PDU's declared length parsed cleanly")
		}
	})
}
