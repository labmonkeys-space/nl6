/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
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

// brokenMultiColumnScopedPDUs is the malformed-list shape table for the
// multi-column walk: one entry per structural check parseVarBindNames makes on
// a binding AFTER the first, plus the container-length lies R1 reclassified.
//
// Shared between the fuzz seeds and the contract test, so every shape is
// replayed by an ordinary `go test` rather than reached only by live fuzzing
// (nl6#535 review R8).
func brokenMultiColumnScopedPDUs(engineID string) map[string][]byte {
	good := encodeSequence(append(encodeOID(colIfDescr), encodeNull()...))
	wrap := func(vbList []byte) []byte {
		var body []byte
		body = append(body, encodeInteger(42)...)
		body = append(body, encodeInteger(0)...)
		body = append(body, encodeInteger(4)...)
		body = append(body, encodeSequence(vbList)...)
		pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)
		var sp []byte
		sp = append(sp, encodeOctetString(engineID)...)
		sp = append(sp, encodeOctetString("")...)
		sp = append(sp, pdu...)
		return sp
	}

	out := map[string][]byte{
		"second name is not an OID": wrap(append(append([]byte{}, good...),
			encodeSequence(append([]byte{ASN1_OID, 0x02, 0x80, 0x80}, encodeNull()...))...)),
		"second binding is not a SEQUENCE": wrap(append(append([]byte{}, good...), ASN1_INTEGER, 0x01, 0x00)),
		"second binding has no value":      wrap(append(append([]byte{}, good...), encodeSequence(encodeOID(colIfName))...)),
		"trailing bytes after the list":    nil, // filled below
	}

	// Trailing bytes between the list and the end of the PDU.
	var body []byte
	body = append(body, encodeInteger(42)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeInteger(4)...)
	body = append(body, encodeSequence(append(append([]byte{}, good...), good...))...)
	body = append(body, 0x05, 0x00)
	pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)
	var sp []byte
	sp = append(sp, encodeOctetString(engineID)...)
	sp = append(sp, encodeOctetString("")...)
	out["trailing bytes after the list"] = append(sp, pdu...)

	// The container-length lies, in both directions.
	base := v3BulkScopedPDUCols(engineID, 0, 4, []string{colIfDescr, colIfName, colSysOR})
	pduStart := len(encodeOctetString(engineID)) + len(encodeOctetString(""))
	for name, delta := range map[string]int{
		"PDU length lengthened": 8,
		"PDU length shortened":  -4,
	} {
		b := append([]byte(nil), base...)
		b[pduStart+1] = byte(int(b[pduStart+1]) + delta)
		out[name] = b
	}
	return out
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

// Row "all columns exhausted": every column is padded with its OWN requested
// OID and endOfMibView, for every repetition, exactly as v2c pads.
//
// The matrix row this replaces read "each column contributes its requested OID
// + endOfMibView" once, which was written for a stop-when-all-exhausted rule
// this change no longer has: nl6#526's stop applies to the SINGLE-column loop,
// and a multi-column loop is byte-identical to v2c (nl6#535 review R4). See
// the Spec Change Log in the spec file.
func TestV3GetBulkAllColumnsExhausted(t *testing.T) {
	s := v3TestServer(multiColFixture(10))
	cols := []string{colPastEnd, colPastEnd2}
	const maxRep = 5

	r := v3Bulk(t, s, 0, maxRep, cols)
	if len(r.varbinds) != len(cols)*maxRep {
		t.Fatalf("got %d bindings, want %d (every column padded in every repetition, as v2c pads): %v",
			len(r.varbinds), len(cols)*maxRep, pairs(r.varbinds))
	}
	for i, vb := range r.varbinds {
		want := cols[i%len(cols)]
		if vb.oid != want {
			t.Errorf("binding %d named %q, want the column's OWN requested OID %q", i, vb.oid, want)
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
	if n := strings.Count(buf.String(), errV3VarBindListMalformed.Error()); n != 1 {
		t.Errorf("logged the discard %d times, want exactly 1 per device: %q", n, buf.String())
	}
}

// TestV3MalformedListHasItsOwnLogGate pins that the GETBULK list discard does
// not share a sync.Once with the dispatcher's malformed-scoped-PDU discard.
//
// They shared one, so whichever fault a device saw first silenced the other for
// the life of the process (nl6#535 review R7). The two have different causes
// and different fixes, and the v1/v2c side already keeps them apart.
func TestV3MalformedListHasItsOwnLogGate(t *testing.T) {
	s := v3TestServer(multiColFixture(4))

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Fault 1: the dispatcher's malformed scoped PDU (a name that is not an
	// OBJECT IDENTIFIER in the FIRST binding).
	s.logFirstMalformedV3(fmt.Errorf("first fault"))
	// Fault 2: a malformed list, which must still be reported.
	s.logFirstMalformedV3List(errV3VarBindListMalformed)

	if !strings.Contains(buf.String(), "first fault") {
		t.Error("the dispatcher's discard was not logged")
	}
	if !strings.Contains(buf.String(), errV3VarBindListMalformed.Error()) {
		t.Errorf("the list discard was swallowed by the other fault's gate; one sync.Once "+
			"across two faults hides whichever arrives second: %q", buf.String())
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
// MULTI-COLUMN v3 is byte-identical to v2c, tail included — including the rows
// where a column runs out mid-response, which is where an earlier cut of this
// change diverged and reported the difference as unavoidable. It was not
// (nl6#535 review R4).
//
// The single-column row is the one shape where the two legitimately differ
// once a column is exhausted, since nl6#526 gives the single-column v3 loop a
// stop rather than a pad; the row here keeps max-repetitions inside the
// column so no exhaustion occurs and the orders can still be compared. The
// divergence itself is pinned by
// TestV3GetBulkSingleColumnStopIsNotAppliedToMultiColumn.
func TestV3GetBulkOrderMatchesV2c(t *testing.T) {
	cases := []struct {
		name           string
		rows           int
		nonRep, maxRep int
		cols           []string
		// wantFull is the RFC 3416 §4.2.3 binding count, N + M×R. Asserting it
		// is a PREMISE, not decoration: v2c and v3 measure their responses
		// against the same byte budget through DIFFERENT envelopes, so a case
		// large enough to truncate compares two different truncation points
		// and fails for a reason that has nothing to do with walk order. Every
		// row here must fit.
		wantFull int
	}{
		{"three columns, four repetitions", 20, 0, 4,
			[]string{colIfDescr, colIfName, colSysOR}, 12},
		{"two columns, one repetition", 20, 0, 1,
			[]string{colIfDescr, colIfName}, 2},
		{"non-repeaters split", 20, 2, 3, []string{
			".1.3.6.1.2.1.1.1.0", colIfDescr + ".1", colIfDescr + ".5", colIfName + ".5", colSysOR + ".5",
		}, 11},
		{"one column exhausted, one live", 20, 0, 3,
			[]string{colIfDescr + ".1", colPastEnd}, 6},
		// The middle case: a live column that runs out at repetition k of n
		// with another already dead. This is where the tail divergence used to
		// begin, so it is the row that must agree now (nl6#535 review R10).
		// colIfName holds the fixture's LAST OIDs, so a column starting near
		// its end reaches the true end of the MIB part-way through.
		{"live column runs out mid-response", 4, 0, 5,
			[]string{colIfName + ".2", colPastEnd}, 10},
		{"both columns run out mid-response", 4, 0, 6,
			[]string{colIfName + ".2", colIfDescr + ".3"}, 12},
		{"all columns dead from the start", 20, 0, 4,
			[]string{colPastEnd, colPastEnd2}, 8},
		{"single column", 20, 0, 5, []string{colIfDescr}, 5},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := multiColFixture(tc.rows)
			v3 := v3Bulk(t, v3TestServer(fixture), tc.nonRep, tc.maxRep, tc.cols)
			v2c := decodeV2cVarbinds(t, newTestServer(fixture).handleGetBulk(
				tc.cols[0], v2cGetBulkRequest(tc.nonRep, tc.maxRep, tc.cols)))

			if len(v2c) != tc.wantFull {
				t.Fatalf("premise: v2c emitted %d bindings, want the full %d — the row is "+
					"truncating, so the comparison is between two different truncation points",
					len(v2c), tc.wantFull)
			}

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

// TestV3GetBulkSingleColumnStopIsNotAppliedToMultiColumn is the mutation guard
// for nl6#535 review R4. nl6#526's stop-instead-of-pad rule belongs to the
// SINGLE-column loop; applying it to a multi-column loop makes the response
// diverge from v2c in the tail, which the spec forbids ("the two rules govern
// different loops and SHALL NOT be applied to each other").
//
// The two shapes are asserted side by side, because a fix that applied the
// multi-column rule everywhere would satisfy the agreement test above and
// silently break nl6#526's contract instead.
func TestV3GetBulkSingleColumnStopIsNotAppliedToMultiColumn(t *testing.T) {
	fixture := multiColFixture(10)
	const maxRep = 4

	t.Run("multi-column pads to max-repetitions", func(t *testing.T) {
		cols := []string{colPastEnd, colPastEnd2}
		r := v3Bulk(t, v3TestServer(fixture), 0, maxRep, cols)
		if len(r.varbinds) != len(cols)*maxRep {
			t.Errorf("got %d bindings, want %d: a multi-column loop pads every repetition, "+
				"as v2c does", len(r.varbinds), len(cols)*maxRep)
		}
	})

	t.Run("single column stops", func(t *testing.T) {
		r := v3Bulk(t, v3TestServer(fixture), 0, maxRep, []string{colPastEnd})
		if len(r.varbinds) != 1 {
			t.Errorf("got %d bindings, want 1: the single-column loop keeps nl6#526's stop, so a "+
				"walk that finds nothing answers the exception once", len(r.varbinds))
		}
	})
}

// ── the clamp's column argument ─────────────────────────────────────────────

// TestV3GetBulkClampsTheWalkPerColumn is the WIRING test for the clamp's
// column count. TestClampBulkWalkDividesByColumns pins the pure function and
// TestV3GetBulkClampsTheWalk is single-column, where ceiling/1 == ceiling — so
// a reviewer changed the call site to clampBulkWalk(maxRepetitions, 1), which
// reverts the entire point of the division, and the whole suite passed
// (nl6#535 review R3).
//
// Same probe as the single-column test: the clamp cannot be seen through the
// binding count, because the encode bound trims to the same bindings either
// way. It IS visible through the WORK. Corrupt each column's successor one
// step past ceiling/N and the once-per-device logFirstBulkAbort line fires
// only if the walk got there.
func TestV3GetBulkClampsTheWalkPerColumn(t *testing.T) {
	const columns = 3
	perCol := maxSNMPResponseSize/minVarbindSize/columns + 1
	rows := perCol + 5

	// Three independent columns, wide enough that a clamped walk never leaves
	// its own column and a walk clamped as if there were ONE column would.
	colOf := func(c int) string { return fmt.Sprintf(".1.3.6.1.4.1.9999.%d.1", c) }
	vals := map[string]string{}
	for c := 1; c <= columns; c++ {
		for i := 1; i <= rows; i++ {
			vals[fmt.Sprintf("%s.%03d", colOf(c), i)] = "v"
		}
	}
	s := v3TestServer(vals)

	cols := make([]string, columns)
	for c := 1; c <= columns; c++ {
		cols[c-1] = colOf(c)
		// Step k of a column's walk lands on row k, so the clamped loop's last
		// call is findNextOID(row perCol-1) and it stops holding row perCol.
		// The entry an UNCLAMPED loop would consult next is this one.
		past := fmt.Sprintf("%s.%03d", colOf(c), perCol)
		s.device.resources.oidNextMap.Store(past, past)
	}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	r := v3Bulk(t, s, 0, 100000, cols)
	if len(r.varbinds) == 0 {
		t.Fatal("clamped walk produced nothing")
	}
	if strings.Contains(buf.String(), "does not advance") {
		t.Errorf("the walk reached row %d of a column, one step past the %d ceiling for %d "+
			"columns: the clamp is being called with a column count of 1, which is the same as "+
			"not dividing at all. The binding count cannot show this, only the work can",
			perCol, perCol, columns)
	}
}

// TestClampBulkWalkPreservesTheV2cArithmetic pins that routing handleGetBulk
// through the shared clampBulkWalk changed nothing: the function computes,
// input for input, exactly the expression that was inlined there (nl6#535
// review R11). The v2c EFFECT is covered by
// TestGetBulkWalkClampAppliesBelowTheGlobalCeiling, which is //go:build linux.
func TestClampBulkWalkPreservesTheV2cArithmetic(t *testing.T) {
	inlined := func(maxRepetitions, cols int) int {
		if perRep := maxSNMPResponseSize/minVarbindSize/cols + 1; maxRepetitions > perRep {
			return perRep
		}
		return maxRepetitions
	}
	for _, cols := range []int{1, 2, 3, 7, 30, 98} {
		for _, m := range []int{0, 1, 2, 10, 97, 98, 99, 127, 128, 1000, 100000} {
			if got, want := clampBulkWalk(m, cols), inlined(m, cols); got != want {
				t.Errorf("clampBulkWalk(%d, %d) = %d, the expression v2c inlined gives %d",
					m, cols, got, want)
			}
		}
	}
}

// TestV2cGetBulkCallsTheSharedClamp pins the WIRING of the shared walk clamp
// into handleGetBulk (nl6#535 review R11), and it is a SOURCE-LEVEL assertion
// on purpose.
//
// The v2c clamp cannot be observed through a response. The encode bound trims
// the collection to the same bindings whether the walk ran 4 repetitions or
// 98, and the v2c path has no once-per-device abort log for a probe to detect
// (which is how the v3 side is pinned, in TestV3GetBulkClampsTheWalkPerColumn).
// Its own behavioural test, TestGetBulkWalkClampAppliesBelowTheGlobalCeiling,
// guards against an INERT clamp by asserting the datagram stays full — it
// cannot see a clamp that is merely too LOOSE, which is exactly what
// re-inlining the expression without the column divisor would produce. A
// mutation doing that fails no test on any platform.
//
// So the property asserted here is the one the change actually claims: there is
// ONE copy of the arithmetic. That is checkable, and it is what stops the two
// copies drifting the way nl6#529's encodeOID/appendOID and nl6#539's
// validateDottedOID did.
func TestV2cGetBulkCallsTheSharedClamp(t *testing.T) {
	src, err := os.ReadFile("snmp_handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "func (s *SNMPServer) handleGetBulk(")
	if start < 0 {
		t.Fatal("handleGetBulk not found")
	}
	end := strings.Index(body[start:], "\n}\n")
	if end < 0 {
		t.Fatal("could not delimit handleGetBulk")
	}
	fn := body[start : start+end]

	if !strings.Contains(fn, "clampBulkWalk(maxRepetitions, len(repeaterCols))") {
		t.Error("handleGetBulk no longer calls clampBulkWalk(maxRepetitions, len(repeaterCols)). " +
			"The v2c and v3 walk clamps must be ONE function: the response cannot show a clamp " +
			"that is too loose, so a second copy drifts silently")
	}
	if strings.Contains(fn, "maxSNMPResponseSize/minVarbindSize") {
		t.Error("handleGetBulk has re-inlined the clamp arithmetic. clampBulkWalk is the single " +
			"definition; a copy here agrees on the day it is written and is unobservable when " +
			"it stops agreeing")
	}
}

// TestReadBufferBoundsTheColumnCount pins the coupling the clamp relies on
// (nl6#535 review R12). Nothing caps the COLUMN count explicitly: the repeater
// walk is bounded because clampBulkWalk divides by it, but the non-repeater
// loop is one walk step per column with no other bound, and what actually
// stops a request naming thousands of columns is the read buffer.
//
// If snmpReadBufferBytes grows, that work grows linearly, so the coupling is
// asserted rather than left as a comment someone can miss.
func TestReadBufferBoundsTheColumnCount(t *testing.T) {
	const documentedCeiling = 300 // columns, at the buffer this test was written for
	if maxColumns := snmpReadBufferBytes / minVarbindSize; maxColumns > documentedCeiling {
		t.Errorf("the read buffer (%d B) now admits %d columns, over the %d this change reasoned "+
			"about. The non-repeater loop walks once PER COLUMN with no cap, so raising the "+
			"buffer raises that work linearly: add an explicit column cap in "+
			"handleSNMPv3GetBulk, or re-derive the bound here",
			snmpReadBufferBytes, maxColumns, documentedCeiling)
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
		// Every row here must be BOTH ok and EMPTY. Asserting only ok let a
		// mutation that returned names alongside true pass the block, and the
		// "a GET" row that used to sit here was not the absent case at all:
		// validScopedPDU carries a well-formed varbind list, so the parser
		// reads it and returns one name (nl6#535 review R9).
		for name, sp := range map[string][]byte{
			"nil":                          nil,
			"garbage":                      {0x00, 0x01, 0x02},
			"contextEngineID tag missing":  {ASN1_INTEGER, 0x01, 0x00},
			"ends before the PDU tag":      append(encodeOctetString("eng"), encodeOctetString("")...),
			"unparseable long-form length": {ASN1_OCTET_STRING, 0x84},
		} {
			t.Run(name, func(t *testing.T) {
				got, ok := parseAllOIDsFromScopedPDU(sp)
				if !ok {
					t.Fatalf("reported malformed; this is the ABSENT case, which the "+
						"dispatcher's single OID still covers (got %v)", got)
				}
				if len(got) != 0 {
					t.Errorf("returned %v with ok=true; the absent case must return no names, "+
						"or the handler walks columns nobody sent", got)
				}
			})
		}
	})

	// A GET scoped PDU is NOT the absent case: it carries request-id,
	// error-status, error-index and a well-formed list, so the parser reads it
	// and returns the name. The row used to sit under "absent" and passed on a
	// false premise (nl6#535 review R9).
	t.Run("a GET scoped PDU parses like any other", func(t *testing.T) {
		got, ok := parseAllOIDsFromScopedPDU(validScopedPDU(".1.3.6.1.2.1.1.1.0"))
		if !ok {
			t.Fatal("a GET scoped PDU reported malformed")
		}
		if len(got) != 1 || got[0] != ".1.3.6.1.2.1.1.1.0" {
			t.Errorf("parsed %v, want the one name the GET carries", got)
		}
	})

	// The same shapes the fuzz corpus seeds, asserted directly so a change in
	// the parser is caught by an ordinary run and not only by live fuzzing.
	t.Run("shared malformed shape table", func(t *testing.T) {
		for name, sp := range brokenMultiColumnScopedPDUs(engine) {
			t.Run(name, func(t *testing.T) {
				if got, ok := parseAllOIDsFromScopedPDU(sp); ok {
					t.Errorf("parsed as %v, want malformed", got)
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

	// R1: a declared length that OVERRUNS its container is malformed, in every
	// direction and at every container. Lengthening the PDU byte used to be
	// classified ABSENT, so the handler fell back to the dispatcher's single
	// OID and answered the first column only — nl6#535's defect restored by a
	// one-byte lie, with no discard and no log line — while SHORTENING the
	// same byte was already malformed.
	t.Run("an overrunning container length is malformed", func(t *testing.T) {
		base := v3BulkScopedPDUCols(engine, 0, 4, []string{colIfDescr, colIfName, colSysOR})
		if got, ok := parseAllOIDsFromScopedPDU(base); !ok || len(got) != 3 {
			t.Fatalf("premise: base input parsed as (%v, %v), want 3 names and ok", got, ok)
		}
		pduStart := len(encodeOctetString(engine)) + len(encodeOctetString(""))
		if base[pduStart] != ASN1_GET_BULK {
			t.Fatalf("premise: no GETBULK tag at %d", pduStart)
		}

		for name, mutate := range map[string]func([]byte){
			"PDU length lengthened":       func(b []byte) { b[pduStart+1] += 8 },
			"PDU length shortened":        func(b []byte) { b[pduStart+1] -= 4 },
			"contextEngineID length long": func(b []byte) { b[1] += byte(len(b)) },
		} {
			t.Run(name, func(t *testing.T) {
				b := append([]byte(nil), base...)
				mutate(b)
				if got, ok := parseAllOIDsFromScopedPDU(b); ok {
					t.Errorf("parsed as %v, want malformed: a container length that overruns "+
						"what contains it is an ASN.1 error, and treating it as ABSENT hands "+
						"the handler a single-column fallback that answers the wrong question", got)
				}
			})
		}
	})

	// The whole point of R1, at the level a manager sees: a one-byte lie must
	// not turn a served multi-column request back into a first-column-only
	// answer.
	t.Run("a lengthened PDU byte does not revert the fix", func(t *testing.T) {
		s := v3TestServer(multiColFixture(10))
		cols := []string{colIfDescr, colIfName, colSysOR}
		sp := v3BulkScopedPDUCols(s.v3Config.EngineID, 0, 4, cols)
		pduStart := len(encodeOctetString(s.v3Config.EngineID)) + len(encodeOctetString(""))
		sp[pduStart+1] += 8

		msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: sp}
		resp := s.handleSNMPv3GetBulk(cols[0], msg, sp)
		if len(resp) != 0 {
			r := decodeV3Response(t, resp)
			t.Fatalf("answered %d bindings instead of discarding: %v", len(r.varbinds), pairs(r.varbinds))
		}
	})

	t.Run("trailing bytes after the list are malformed", func(t *testing.T) {
		// Bytes between the end of the variable-bindings list and the end of
		// the PDU are not the SEQUENCE RFC 1157 defines; the same nl6#537 rule
		// that refuses them after a VarBind's value refuses them here.
		vbList := encodeSequence(append(encodeOID(colIfDescr), encodeNull()...))
		var body []byte
		body = append(body, encodeInteger(42)...)
		body = append(body, encodeInteger(0)...)
		body = append(body, encodeInteger(5)...)
		body = append(body, encodeSequence(vbList)...)
		body = append(body, 0x05, 0x00) // a stray NULL after the list
		pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)
		var sp []byte
		sp = append(sp, encodeOctetString(engine)...)
		sp = append(sp, encodeOctetString("")...)
		sp = append(sp, pdu...)

		if got, ok := parseAllOIDsFromScopedPDU(sp); ok {
			t.Errorf("parsed as %v, want malformed: bytes after the list are an ASN.1 error", got)
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
		// Shorten the PDU's declared length so the list runs past it. The
		// list must be bounded by the PDU, not by the datagram: a name read
		// across its container's end decodes to an OID nobody sent.
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
