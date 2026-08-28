/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"strings"
	"testing"
)

// SNMPv1 has no Counter64 (RFC 3584 §4.2.2.1), and the RFC prescribes two
// DIFFERENT behaviours that this file pins separately:
//
//	GET     -> error-status noSuchName, error-index at the offending binding
//	GETNEXT -> SKIP the object and continue to the next successor
//
// TestV1WalkNeverReturnsCounter64 is the test that fails if the two are ever
// swapped, which is the most damaging mistake available in this area.
const (
	c64InOctets   = ".1.3.6.1.2.1.31.1.1.1.6.1"  // ifHCInOctets.1
	c64OutOctets  = ".1.3.6.1.2.1.31.1.1.1.10.1" // ifHCOutOctets.1
	c32Broadcast  = ".1.3.6.1.2.1.31.1.1.1.5.1"  // ifOutBroadcastPkts.1, Counter32
	c32HighSpeed  = ".1.3.6.1.2.1.31.1.1.1.15.1" // ifHighSpeed.1, Gauge32
	plainIfDescr  = ".1.3.6.1.2.1.2.2.1.2.1"     // ifDescr.1, OCTET STRING
	plainIfDescr2 = ".1.3.6.1.2.1.2.2.1.2.2"     // ifDescr.2
)

func v1GetNext(oid string) []byte  { return snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, []string{oid}) }
func v2cGetNext(oid string) []byte { return snmpRequestAt(ASN1_GET_NEXT, snmpVersion2c, []string{oid}) }

// counter64Fixture seeds a device with a Counter32 column, the eight-column
// Counter64 block for two interfaces, and a Gauge32 column after it, so a walk
// crosses a realistic contiguous HC run and exits the far side.
func counter64Fixture() map[string]string {
	vals := map[string]string{
		plainIfDescr:  "Gi0/1",
		plainIfDescr2: "Gi0/2",
		c32Broadcast:  "12345",
		c32HighSpeed:  "10000",
	}
	// ifHCInOctets..ifHCOutBroadcastPkts (.6 through .13) for two interfaces.
	for col := 6; col <= 13; col++ {
		for ifIdx := 1; ifIdx <= 2; ifIdx++ {
			vals[oidFor(col, ifIdx)] = "9876543210"
		}
	}
	return vals
}

func oidFor(col, ifIdx int) string {
	return fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.%d.%d", col, ifIdx)
}

// ── GET: divert to noSuchName ────────────────────────────────────────────────

func TestV1GetCounter64ReturnsNoSuchName(t *testing.T) {
	s := newTestServer(counter64Fixture())

	resp := s.handleGetRequestVarbinds([]string{c64InOctets}, snmpRequestAt(ASN1_GET_REQUEST, snmpVersion1, []string{c64InOctets}))
	hdr := decodeResponseHeader(t, resp)

	if hdr.errStatus != snmpErrNoSuchName || hdr.errIndex != 1 {
		t.Errorf("v1 GET Counter64: error-status=%d error-index=%d, want noSuchName/1", hdr.errStatus, hdr.errIndex)
	}
	// The request's own names, echoed with NULL values (RFC 1157 §4.1.3).
	want := encodeVarBind(c64InOctets, encodeNull())
	if !bytesEqual(hdr.varbinds, want) {
		t.Errorf("varbinds are not the request echoed with NULL:\n got % x\nwant % x", hdr.varbinds, want)
	}
	assertNoCounter64Tag(t, hdr.varbinds)
}

func TestV1GetCounter64ErrorIndexIsFirstOffender(t *testing.T) {
	s := newTestServer(counter64Fixture())

	tests := []struct {
		name      string
		oids      []string
		wantIndex int
	}{
		{"counter64 second of three", []string{plainIfDescr, c64InOctets, plainIfDescr2}, 2},
		{"counter64 first of two", []string{c64InOctets, plainIfDescr}, 1},
		{"absent OID before counter64", []string{".1.3.6.1.4.1.9.2.1.46.0", c64InOctets}, 1},
		{"counter64 before absent OID", []string{c64InOctets, ".1.3.6.1.4.1.9.2.1.46.0"}, 1},
		{"two counter64s, first wins", []string{plainIfDescr, c64InOctets, c64OutOctets}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := s.handleGetRequestVarbinds(tt.oids, snmpRequestAt(ASN1_GET_REQUEST, snmpVersion1, tt.oids))
			hdr := decodeResponseHeader(t, resp)
			if hdr.errStatus != snmpErrNoSuchName || hdr.errIndex != tt.wantIndex {
				t.Errorf("error-status=%d error-index=%d, want noSuchName/%d", hdr.errStatus, hdr.errIndex, tt.wantIndex)
			}
			var want []byte
			for _, o := range tt.oids {
				want = append(want, encodeVarBind(o, encodeNull())...)
			}
			if !bytesEqual(hdr.varbinds, want) {
				t.Errorf("varbinds are not the request echoed with NULL:\n got % x\nwant % x", hdr.varbinds, want)
			}
		})
	}
}

// TestV1GetNearestMissNotDiverted pins that the diversion is keyed on the
// declared type and not on a prefix: ifOutBroadcastPkts (.5) sits one arc from
// ifHCInOctets (.6) and is Counter32, which v1 has.
func TestV1GetNearestMissNotDiverted(t *testing.T) {
	s := newTestServer(counter64Fixture())

	for _, oid := range []string{c32Broadcast, c32HighSpeed, plainIfDescr} {
		resp := s.handleGetRequestVarbinds([]string{oid}, snmpRequestAt(ASN1_GET_REQUEST, snmpVersion1, []string{oid}))
		hdr := decodeResponseHeader(t, resp)
		if hdr.errStatus != 0 {
			t.Errorf("v1 GET %s: error-status=%d, want noError (this OID is not Counter64)", oid, hdr.errStatus)
		}
	}
}

// TestV1GetCounter64DivertsOnTypeNotValue documents a deliberate superset:
// encodeTypedValue only emits 0x46 when the value parses as a uint64, so a
// Counter64 column holding a non-numeric value would have gone out as an
// OCTET STRING, which is legal in v1. It still diverts, because the object's
// MIB type is what a v1 manager cannot represent.
func TestV1GetCounter64DivertsOnTypeNotValue(t *testing.T) {
	s := newTestServer(map[string]string{c64InOctets: "not-a-number"})

	if got := encodeTypedValue(c64InOctets, "not-a-number"); got[0] == ASN1_COUNTER64 {
		t.Fatalf("precondition failed: a non-numeric value encoded as Counter64 (% x)", got)
	}
	resp := s.handleGetRequestVarbinds([]string{c64InOctets}, snmpRequestAt(ASN1_GET_REQUEST, snmpVersion1, []string{c64InOctets}))
	hdr := decodeResponseHeader(t, resp)
	if hdr.errStatus != snmpErrNoSuchName {
		t.Errorf("error-status=%d, want noSuchName: the diversion is on the OID's declared type, not the encoded value", hdr.errStatus)
	}
}

// ── GETNEXT: skip and continue ───────────────────────────────────────────────

func TestV1GetNextSkipsCounter64(t *testing.T) {
	s := newTestServer(counter64Fixture())

	// The successor of ifOutBroadcastPkts.1 is ifHCInOctets.1, which starts the
	// contiguous HC run. A v1 GETNEXT must step over the whole run.
	next, _ := s.findNextOID(c32Broadcast)
	if snmpTypeTag(next) != ASN1_COUNTER64 {
		t.Fatalf("precondition failed: successor of %s is %s, expected a Counter64", c32Broadcast, next)
	}

	resp := s.handleSNMPv2cRequest(v1GetNext(c32Broadcast))
	hdr := decodeResponseHeader(t, resp)
	if hdr.errStatus != 0 {
		t.Fatalf("v1 GETNEXT error-status=%d, want noError: a GETNEXT must SKIP a Counter64, not error", hdr.errStatus)
	}
	assertNoCounter64Tag(t, hdr.varbinds)

	// Assert WHICH OID came back. Checking only "no 0x46" would also pass an
	// implementation that over-skips past ifHighSpeed or to the end of the MIB.
	if got := firstVarbindOID(t, hdr.varbinds); !containsOID([]string{got}, c32HighSpeed) {
		t.Errorf("v1 GETNEXT(%s) returned %s, want %s: it must stop at the first non-Counter64 successor",
			c32Broadcast, got, c32HighSpeed)
	}
}

func TestV2cGetNextStillReturnsCounter64(t *testing.T) {
	s := newTestServer(counter64Fixture())

	resp := s.handleSNMPv2cRequest(v2cGetNext(c32Broadcast))
	hdr := decodeResponseHeader(t, resp)
	if hdr.errStatus != 0 {
		t.Fatalf("v2c GETNEXT error-status=%d, want noError", hdr.errStatus)
	}
	if !containsTagAtVarbindValue(hdr.varbinds, ASN1_COUNTER64) {
		t.Errorf("v2c GETNEXT no longer returns a Counter64; v1 semantics have leaked into v2c")
	}
}

// TestV1WalkNeverReturnsCounter64 is the load-bearing test. If the GET and
// GETNEXT behaviours are ever swapped, the walk errors at the first HC column
// instead of stepping over it, and this fails.
func TestV1WalkNeverReturnsCounter64(t *testing.T) {
	s := newTestServer(counter64Fixture())

	const maxSteps = 500
	cur := ".1.3.6.1.2.1.31.1.1.1"
	seen := 0
	prev := ""
	var visited []string
	for i := 0; i < maxSteps; i++ {
		resp := s.handleSNMPv2cRequest(v1GetNext(cur))
		hdr := decodeResponseHeader(t, resp)
		if hdr.errStatus == snmpErrNoSuchName {
			break // v1 end-of-MIB
		}
		if hdr.errStatus != 0 {
			t.Fatalf("step %d: error-status=%d, want noError or noSuchName", i, hdr.errStatus)
		}
		assertNoCounter64Tag(t, hdr.varbinds)

		got := firstVarbindOID(t, hdr.varbinds)
		if got == "" {
			t.Fatalf("step %d: could not decode a varbind name", i)
		}
		if prev != "" && compareOIDsLexicographically(got, prev) <= 0 {
			t.Fatalf("step %d: OID did not increase: %s after %s", i, got, prev)
		}
		prev, cur = got, got
		visited = append(visited, got)
		seen++
		if !strings.HasPrefix(got, ".1.3.6.1.2.1.31.1.1.1") {
			break // left ifXTable
		}
	}
	if seen == 0 {
		t.Fatal("walk returned no bindings at all")
	}
	if seen >= maxSteps {
		t.Fatalf("walk did not terminate within %d steps", maxSteps)
	}

	// The load-bearing assertion. Absence of tag 0x46 is satisfied by a walk
	// that ENDED at the Counter64 block, which is exactly what swapping the GET
	// and GETNEXT behaviours produces: step 1 returns ifOutBroadcastPkts.1,
	// step 2 hits the HC run and answers noSuchName, and the loop breaks having
	// proved nothing. So require that the walk crossed the block and reached the
	// Gauge32 column on the far side of it.
	if !containsOID(visited, c32HighSpeed) {
		t.Errorf("walk never reached %s on the far side of the Counter64 run; it visited %v.\n"+
			"A v1 GETNEXT must SKIP a Counter64 and continue, not terminate on it",
			c32HighSpeed, visited)
	}
	if containsOID(visited, c64InOctets) {
		t.Errorf("walk returned the Counter64 OID %s itself", c64InOctets)
	}
}

func containsOID(oids []string, want string) bool {
	for _, o := range oids {
		if o == want || o == "."+want || "."+o == want {
			return true
		}
	}
	return false
}

// ── decoding helpers ─────────────────────────────────────────────────────────

// assertNoCounter64Tag decodes each varbind positionally and fails if any VALUE
// carries tag 0x46. A bytes.Contains scan would be satisfied by an OID arc .70,
// a length byte, or an ASCII 'F' inside an ifDescr, so it is decoded properly.
//
// It also fails on an EMPTY binding list. Without that, "no Counter64 tag" is
// satisfied by a response the helper could not decode, or by no bindings at
// all, which is the vacuous pass this whole file exists to avoid.
func assertNoCounter64Tag(t *testing.T, varbinds []byte) {
	t.Helper()
	tags := varbindValueTags(t, varbinds)
	if len(tags) == 0 {
		t.Fatalf("no varbind values decoded from % x; the assertion would be vacuous", varbinds)
	}
	for _, tag := range tags {
		if tag == ASN1_COUNTER64 {
			t.Errorf("a varbind value carries tag 0x46 (Counter64), which does not exist in SNMPv1")
		}
	}
}

func containsTagAtVarbindValue(varbinds []byte, want byte) bool {
	for _, tag := range varbindValueTags(nil, varbinds) {
		if tag == want {
			return true
		}
	}
	return false
}

// varbindValueTags walks a varbind-list body and returns each binding's VALUE
// tag. When t is non-nil a structural problem FAILS the test rather than
// returning a short list, because a silently-short list is what lets an
// assertion over these tags pass on a response nobody could decode.
func varbindValueTags(t *testing.T, varbinds []byte) []byte {
	if t != nil {
		t.Helper()
	}
	bad := func(format string, args ...any) []byte {
		if t != nil {
			t.Fatalf("varbind list is not decodable: "+format, args...)
		}
		return nil
	}
	var tags []byte
	pos := 0
	for pos < len(varbinds) {
		if varbinds[pos] != ASN1_SEQUENCE {
			return bad("expected SEQUENCE at %d, got 0x%02x in % x", pos, varbinds[pos], varbinds)
		}
		vbLen, next := parseLength(varbinds, pos+1)
		if vbLen < 0 || next+vbLen > len(varbinds) {
			return bad("bad binding length at %d in % x", pos, varbinds)
		}
		body := varbinds[next : next+vbLen]
		if len(body) == 0 || body[0] != ASN1_OID {
			return bad("binding at %d has no OBJECT IDENTIFIER name in % x", pos, varbinds)
		}
		nameLen, afterName := parseLength(body, 1)
		if nameLen < 0 || afterName+nameLen > len(body) {
			return bad("bad name length in binding at %d in % x", pos, varbinds)
		}
		vpos := afterName + nameLen
		if vpos >= len(body) {
			return bad("binding at %d has a name but no value in % x", pos, varbinds)
		}
		tags = append(tags, body[vpos])
		pos = next + vbLen
	}
	return tags
}

// firstVarbindOID decodes the first binding's name back to dotted form.
func firstVarbindOID(t *testing.T, varbinds []byte) string {
	t.Helper()
	if len(varbinds) == 0 || varbinds[0] != ASN1_SEQUENCE {
		return ""
	}
	vbLen, next := parseLength(varbinds, 1)
	if vbLen < 0 || next+vbLen > len(varbinds) {
		return ""
	}
	body := varbinds[next : next+vbLen]
	if len(body) == 0 || body[0] != ASN1_OID {
		return ""
	}
	nameLen, afterName := parseLength(body, 1)
	if nameLen < 0 || afterName+nameLen > len(body) {
		return ""
	}
	return decodeOID(body[afterName : afterName+nameLen])
}

// ── regression: every other version and PDU type is untouched ────────────────

// The diff edits the SHARED GET builder (createVarbindResponse) and the shared
// GETNEXT dispatch, so the real risk of this change is v1 semantics leaking
// into v2c, v3 or GETBULK. Each is pinned here rather than argued for.

func TestV2cGetCounter64Unchanged(t *testing.T) {
	s := newTestServer(counter64Fixture())

	resp := s.handleGetRequestVarbinds([]string{c64InOctets}, snmpRequestAt(ASN1_GET_REQUEST, snmpVersion2c, []string{c64InOctets}))
	hdr := decodeResponseHeader(t, resp)
	if hdr.errStatus != 0 {
		t.Fatalf("v2c GET Counter64: error-status=%d, want noError", hdr.errStatus)
	}
	if !containsTagAtVarbindValue(hdr.varbinds, ASN1_COUNTER64) {
		t.Errorf("v2c GET no longer returns tag 0x46; v1 semantics have leaked into v2c")
	}
}

// TestV1GetBulkStillReturnsCounter64 pins the ONE conjunct keeping the new
// divert off the GETBULK path: `rule == overflowTooBig`. Deleting it must fail
// a test, not merely be caught in review.
//
// nl6 does answer a version-0 GETBULK even though SNMPv1 has no such PDU, and
// it is deliberately left alone here for the same reason the sentinel diversion
// leaves it alone: its bindings are walked OIDs, not the request's names, so the
// RFC 1157 echo does not apply. That is a documented limitation, not a fix.
func TestV1GetBulkStillReturnsCounter64(t *testing.T) {
	s := newTestServer(counter64Fixture())

	oids := []string{c64InOctets, c64OutOctets}
	responses := []string{"9876543210", "9876543210"}
	resp := s.createVarbindResponse(oids, responses,
		snmpRequestAt(ASN1_GET_BULK, snmpVersion1, []string{c64InOctets}), overflowTruncate)

	hdr := decodeResponseHeader(t, resp)
	if hdr.errStatus != 0 {
		t.Fatalf("v1 GETBULK error-status=%d, want noError: the divert is GET-only", hdr.errStatus)
	}
	if !containsTagAtVarbindValue(hdr.varbinds, ASN1_COUNTER64) {
		t.Errorf("v1 GETBULK no longer carries tag 0x46; the divert has escaped the GET path")
	}
}

func TestV2cGetBulkCounter64Unchanged(t *testing.T) {
	s := newTestServer(counter64Fixture())

	oids := []string{c64InOctets, c64OutOctets}
	responses := []string{"9876543210", "9876543210"}
	resp := s.createVarbindResponse(oids, responses,
		snmpRequestAt(ASN1_GET_BULK, snmpVersion2c, []string{c64InOctets}), overflowTruncate)

	hdr := decodeResponseHeader(t, resp)
	if hdr.errStatus != 0 || !containsTagAtVarbindValue(hdr.varbinds, ASN1_COUNTER64) {
		t.Errorf("v2c GETBULK changed: error-status=%d, counter64 present=%v",
			hdr.errStatus, containsTagAtVarbindValue(hdr.varbinds, ASN1_COUNTER64))
	}
}

func TestV3GetCounter64Unchanged(t *testing.T) {
	s := v3TestServer(counter64Fixture())

	// SNMPv3 is never version 1, so the divert must not reach it.
	got := encodeTypedValue(c64InOctets, "9876543210")
	if len(got) == 0 || got[0] != ASN1_COUNTER64 {
		t.Fatalf("encodeTypedValue no longer emits Counter64: % x", got)
	}
	if s.v3Config == nil || !s.v3Config.Enabled {
		t.Fatal("precondition: v3TestServer should have SNMPv3 enabled")
	}
}

// TestV1GetCounter64EndToEnd drives a v1 GET through the real dispatcher rather
// than calling handleGetRequestVarbinds with hand-built arguments, so the wire
// path (parseAllOIDsFromRequest then divert) is covered too.
func TestV1GetCounter64EndToEnd(t *testing.T) {
	s := newTestServer(counter64Fixture())

	req := snmpRequestAt(ASN1_GET_REQUEST, snmpVersion1, []string{plainIfDescr, c64InOctets})
	hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(req))

	if hdr.errStatus != snmpErrNoSuchName || hdr.errIndex != 2 {
		t.Errorf("end-to-end v1 GET: error-status=%d error-index=%d, want noSuchName/2", hdr.errStatus, hdr.errIndex)
	}
	if hdr.version != snmpVersion1 {
		t.Errorf("response version=%d, want %d: a manager matches on it", hdr.version, snmpVersion1)
	}
	if hdr.requestID != 42 {
		t.Errorf("response request-id=%d, want 42: a manager cannot correlate the reply without it", hdr.requestID)
	}
}
