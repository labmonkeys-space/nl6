/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// SNMP SetRequest (add-snmp-set, nl6#684).
//
// Every test here drives the DISPATCHER (handleSNMPv2cRequest /
// handleSNMPv3Request), never the ladder or the builder directly: the seam
// nl6#527 broke was a dispatcher-versus-direct-call difference, and a SET that
// validates perfectly in isolation but is still routed to the GET branch is
// exactly the defect being fixed.

const (
	oidIfAdminStatus = ".1.3.6.1.2.1.2.2.1.7"
	oidIfOperStatus  = ".1.3.6.1.2.1.2.2.1.8"
	oidIfLastChange  = ".1.3.6.1.2.1.2.2.1.9"
	oidSysDescr0     = ".1.3.6.1.2.1.1.1.0"
	oidSysContact0   = ".1.3.6.1.2.1.1.4.0"
)

// testBind is one binding of a SET under test: a name and an already-encoded
// value TLV.
type testBind struct {
	oid   string
	value []byte
}

func intBind(oid string, v int) testBind    { return testBind{oid, encodeInteger(v)} }
func strBind(oid string, s string) testBind { return testBind{oid, encodeOctetString(s)} }

// setRequestAt builds a v1/v2c SetRequest with typed values, request-id 42,
// community "public" — snmpRequestAt's shape with the NULLs replaced.
func setRequestAt(version int, binds []testBind) []byte {
	var varbinds []byte
	for _, b := range binds {
		varbinds = append(varbinds, encodeVarBind(b.oid, b.value)...)
	}
	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(42)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeSequence(varbinds)...)
	pdu := []byte{ASN1_SET_REQUEST}
	pdu = append(pdu, encodeLength(len(pduBody))...)
	pdu = append(pdu, pduBody...)
	var msg []byte
	msg = append(msg, encodeInteger(version)...)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// v3SetRequest builds a v3 SetRequest for s with typed values and request-id
// 42, in the plaintext shape buildV3RequestAt uses (signed when s
// authenticates).
func v3SetRequest(t testing.TB, s *SNMPServer, binds []testBind) []byte {
	t.Helper()
	var varbinds []byte
	for _, b := range binds {
		varbinds = append(varbinds, encodeVarBind(b.oid, b.value)...)
	}
	var body []byte
	body = append(body, encodeInteger(42)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeSequence(varbinds)...)
	pdu := append([]byte{ASN1_SET_REQUEST}, append(encodeLength(len(body)), body...)...)
	var scoped []byte
	scoped = append(scoped, encodeOctetString(s.v3Config.EngineID)...)
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, pdu...)
	return assembleV3(s, encodeSequence(scoped), nil, false)
}

// requestListContents returns the variable-bindings list CONTENTS of a v1/v2c
// request, which is what a SET response must echo byte-for-byte.
func requestListContents(t *testing.T, req []byte) []byte {
	t.Helper()
	pos, _, ok := requestVarBindListPos(req)
	if !ok {
		t.Fatal("request envelope unreadable")
	}
	_, contents, ok := parseVarBinds(req, pos)
	if !ok {
		t.Fatal("request list malformed")
	}
	return contents
}

// newSetTestServer is newTestServer plus a live interface-state engine over
// ifIndex 1..nIf, every interface at admin up / oper up, and sysDescr.0 as a
// read-only probe. v3 is enabled at noAuthNoPriv (v3TestServer's shape) so the
// same server answers both dispatchers.
func newSetTestServer(t *testing.T, nIf int) (*SNMPServer, *InterfaceState) {
	t.Helper()
	s := v3TestServer(map[string]string{oidSysDescr0: "nl6 set probe"})
	speeds := make([]uint64, nIf)
	for i := range speeds {
		speeds[i] = 1_000_000_000
	}
	res := buildTestResources(t, speeds)
	for i := 1; i <= nIf; i++ {
		res.oidIndex.Store(fmt.Sprintf("%s.%d", oidIfAdminStatus, i), "1")
		res.oidIndex.Store(fmt.Sprintf("%s.%d", oidIfOperStatus, i), "1")
	}
	mc := NewMetricsCycler(0, GetDeviceProfile(""))
	mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
	s.device.metricsCycler = mc
	s.device.ID = "set-test"
	state := mc.ifCounters.Load().State()
	if state == nil {
		t.Fatal("fixture has no interface state engine")
	}
	return s, state
}

func v2cGet(t *testing.T, s *SNMPServer, oid string) string {
	t.Helper()
	resp := s.handleSNMPv2cRequest(getRequestAtVersion(snmpVersion2c, oid))
	vbs := decodeV2cVarbinds(t, resp)
	if len(vbs) != 1 {
		t.Fatalf("GET %s: %d bindings", oid, len(vbs))
	}
	if vbs[0].valueTag != ASN1_INTEGER {
		t.Fatalf("GET %s: tag 0x%02X, want INTEGER", oid, vbs[0].valueTag)
	}
	v, ok := parseBERInt(vbs[0].value, 0, len(vbs[0].value))
	if !ok {
		t.Fatalf("GET %s: unparseable INTEGER % x", oid, vbs[0].value)
	}
	return strconv.Itoa(v)
}

// ── every SET is answered ───────────────────────────────────────────────────

// The defect nl6#684 reported: a v2c SET of a read-only object was answered
// as a GET of that object, current value, noError. It is now notWritable at
// index 1 with the request's bindings echoed, value included, and NO read.
func TestSetOnReadOnlyObjectIsNotWritableNotARead(t *testing.T) {
	s, _ := newSetTestServer(t, 2)
	req := setRequestAt(snmpVersion2c, []testBind{strBind(oidSysDescr0, "x")})
	resp := s.handleSNMPv2cRequest(req)
	if len(resp) == 0 {
		t.Fatal("SET was discarded; RFC 3416 §4.2.5 wants notWritable")
	}
	h := decodeResponseHeader(t, resp)
	if h.errStatus != snmpErrNotWritable || h.errIndex != 1 {
		t.Fatalf("error-status/index = %d/%d, want notWritable(17)/1", h.errStatus, h.errIndex)
	}
	if h.requestID != 42 {
		t.Errorf("request-id = %d, want 42", h.requestID)
	}
	if want := requestListContents(t, req); !bytes.Equal(h.varbinds, want) {
		t.Errorf("echoed bindings differ from the request's:\n got % x\nwant % x", h.varbinds, want)
	}
	if bytes.Contains(resp, []byte("nl6 set probe")) {
		t.Error("the response carries the object's CURRENT value: the SET was answered as a read")
	}
}

func TestV3SetIsAnsweredNotDropped(t *testing.T) {
	s, _ := newSetTestServer(t, 2)
	resp := s.handleSNMPv3Request(v3SetRequest(t, s, []testBind{strBind(oidSysDescr0, "x")}))
	if len(resp) == 0 {
		t.Fatal("v3 SET was discarded (the nl6#547 gate still refuses 0xA3)")
	}
	r := decodeV3Response(t, resp)
	if r.pduTag != ASN1_GET_RESPONSE || r.errStatus != snmpErrNotWritable || r.errIndex != 1 {
		t.Fatalf("v3 response tag/status/index = 0x%02X/%d/%d, want 0xA2/17/1", r.pduTag, r.errStatus, r.errIndex)
	}
	if len(r.varbinds) != 1 || r.varbinds[0].valueTag != ASN1_OCTET_STRING || string(r.varbinds[0].value) != "x" {
		t.Errorf("v3 echo = %+v, want the request's OCTET STRING binding", r.varbinds)
	}
}

// The tags nl6 still does not serve are still discarded, and BOTH v3 tag
// classifiers agree on every tag: widening one list without the other answers
// request-id 1 to every request of the new type.
func TestV3TagClassifiersAgreeAndUnservedTagsDiscard(t *testing.T) {
	s, _ := newSetTestServer(t, 1)
	for tag := byte(0xA0); tag <= 0xA8; tag++ {
		var body []byte
		body = append(body, encodeInteger(77)...)
		body = append(body, encodeInteger(0)...)
		body = append(body, encodeInteger(0)...)
		body = append(body, encodeSequence(encodeVarBind(oidSysDescr0, encodeNull()))...)
		pdu := append([]byte{tag}, append(encodeLength(len(body)), body...)...)
		var scoped []byte
		scoped = append(scoped, encodeOctetString(s.v3Config.EngineID)...)
		scoped = append(scoped, encodeOctetString("")...)
		scoped = append(scoped, pdu...)

		_, _, err := s.extractOIDAndTypeFromScopedPDU(scoped)
		served := err == nil
		gotID := s.extractRequestIDFromScopedPDU(scoped)
		if served != (gotID == 77) {
			t.Errorf("tag 0x%02X: extractOIDAndType served=%v but extractRequestID read %d; the two tag lists disagree",
				tag, served, gotID)
		}
		wantServed := servedPDUTag(tag)
		if served != wantServed {
			t.Errorf("tag 0x%02X: served=%v, want %v", tag, served, wantServed)
		}
		resp := s.handleSNMPv3Request(assembleV3(s, encodeSequence(scoped), nil, false))
		if !wantServed && len(resp) != 0 {
			t.Errorf("tag 0x%02X was answered; it must still be discarded", tag)
		}
		if wantServed && len(resp) == 0 {
			t.Errorf("tag 0x%02X was discarded; it must be answered", tag)
		}
	}
}

// getPDUType defaults to the GET branch on an envelope it cannot read, and
// that must stay: the SET branch is reached only by an explicit 0xA3.
func TestUnreadableEnvelopeStillTakesTheGetBranch(t *testing.T) {
	s, _ := newSetTestServer(t, 1)
	resp := s.handleSNMPv2cRequest([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	if len(resp) == 0 {
		t.Fatal("an unreadable envelope used to be answered from the GET branch's default OID; it is now discarded")
	}
	if h := decodeResponseHeader(t, resp); h.errStatus != snmpErrNoError {
		t.Errorf("error-status = %d, want the GET branch's noError", h.errStatus)
	}
}

// ── the ladder, through every dispatcher ────────────────────────────────────

// setVia sends binds as a SET at the given version and returns the decoded
// (error-status, error-index). version 3 goes through handleSNMPv3Request.
func setVia(t *testing.T, s *SNMPServer, version int, binds []testBind) (int, int) {
	t.Helper()
	if version == 3 {
		resp := s.handleSNMPv3Request(v3SetRequest(t, s, binds))
		if len(resp) == 0 {
			t.Fatal("v3 SET discarded")
		}
		r := decodeV3Response(t, resp)
		return r.errStatus, r.errIndex
	}
	resp := s.handleSNMPv2cRequest(setRequestAt(version, binds))
	if len(resp) == 0 {
		t.Fatal("SET discarded")
	}
	h := decodeResponseHeader(t, resp)
	return h.errStatus, h.errIndex
}

func TestSetLadderInRFCOrderAcrossVersions(t *testing.T) {
	rows := []struct {
		name   string
		binds  []testBind
		wantV2 int // RFC 3416 verdict (v2c and v3)
		wantV1 int // RFC 3584 §4.3 mapping
		index  int
	}{
		{"read-only object", []testBind{strBind(oidSysDescr0, "x")}, snmpErrNotWritable, snmpErrNoSuchName, 1},
		{"absent object", []testBind{intBind(oidSysContact0, 1)}, snmpErrNotWritable, snmpErrNoSuchName, 1},
		{"wrong type", []testBind{strBind(oidIfAdminStatus+".1", "down")}, snmpErrWrongType, snmpErrBadValue, 1},
		{"wrong encoding", []testBind{{oidIfAdminStatus + ".1", []byte{ASN1_INTEGER, 0x00}}}, snmpErrWrongEncoding, snmpErrBadValue, 1},
		{"out of range high", []testBind{intBind(oidIfAdminStatus+".1", 5)}, snmpErrWrongValue, snmpErrBadValue, 1},
		{"out of range zero", []testBind{intBind(oidIfAdminStatus+".1", 0)}, snmpErrWrongValue, snmpErrBadValue, 1},
		{"unknown instance", []testBind{intBind(oidIfAdminStatus+".999", 2)}, snmpErrNoCreation, snmpErrNoSuchName, 1},
		// ORDER PIN: the value test runs before the instance test.
		{"value before instance", []testBind{intBind(oidIfAdminStatus+".999", 7)}, snmpErrWrongValue, snmpErrBadValue, 1},
		{"bare column", []testBind{intBind(oidIfAdminStatus, 2)}, snmpErrNoCreation, snmpErrNoSuchName, 1},
		{"wrong arity", []testBind{intBind(oidIfAdminStatus+".1.2", 2)}, snmpErrNoCreation, snmpErrNoSuchName, 1},
		{"second binding offends", []testBind{intBind(oidIfAdminStatus+".1", 2), strBind(oidSysDescr0, "x")}, snmpErrNotWritable, snmpErrNoSuchName, 2},
		{"valid", []testBind{intBind(oidIfAdminStatus+".1", 1)}, snmpErrNoError, snmpErrNoError, 0},
	}
	for _, version := range []int{snmpVersion1, snmpVersion2c, 3} {
		for _, r := range rows {
			t.Run(fmt.Sprintf("v%d/%s", version, r.name), func(t *testing.T) {
				s, state := newSetTestServer(t, 2)
				before := state.Snapshot(1)
				status, index := setVia(t, s, version, r.binds)
				want := r.wantV2
				if version == snmpVersion1 {
					want = r.wantV1
				}
				if status != want || index != r.index {
					t.Fatalf("status/index = %d/%d, want %d/%d", status, index, want, r.index)
				}
				if want != snmpErrNoError && state.Snapshot(1) != before {
					t.Errorf("a refused SET mutated interface 1: %+v -> %+v", before, state.Snapshot(1))
				}
			})
		}
	}
}

// A binding that fails LATE applies nothing that came before it.
func TestSetIsAllOrNothing(t *testing.T) {
	s, state := newSetTestServer(t, 2)
	status, index := setVia(t, s, snmpVersion2c, []testBind{
		intBind(oidIfAdminStatus+".1", 2),
		strBind(oidSysDescr0, "x"),
	})
	if status != snmpErrNotWritable || index != 2 {
		t.Fatalf("status/index = %d/%d, want 17/2", status, index)
	}
	if snap := state.Snapshot(1); snap.Admin != AdminUp || snap.Oper != OperUp {
		t.Errorf("interface 1 = %+v; the first binding was applied although the second failed", snap)
	}
}

func TestSetTwoWritableBindingsBothApply(t *testing.T) {
	s, state := newSetTestServer(t, 2)
	if status, _ := setVia(t, s, snmpVersion2c, []testBind{
		intBind(oidIfAdminStatus+".1", 2), intBind(oidIfAdminStatus+".2", 2),
	}); status != snmpErrNoError {
		t.Fatalf("status = %d, want noError", status)
	}
	for i := 1; i <= 2; i++ {
		if snap := state.Snapshot(i); snap.Admin != AdminDown || snap.Oper != OperDown {
			t.Errorf("interface %d = %+v, want admin down / oper down", i, snap)
		}
	}
}

// ── the writable set: admin down, oper follows, GET reads it back ───────────

func TestSetAdminStatusCascadesAndReadsBack(t *testing.T) {
	for _, version := range []int{snmpVersion1, snmpVersion2c, 3} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			s, state := newSetTestServer(t, 3)
			steps := []struct {
				set  int
				want string
			}{{2, "2"}, {1, "1"}, {3, "3"}, {2, "2"}}
			for _, st := range steps {
				if status, _ := setVia(t, s, version, []testBind{intBind(oidIfAdminStatus+".3", st.set)}); status != snmpErrNoError {
					t.Fatalf("SET %d: status %d", st.set, status)
				}
				if got := v2cGet(t, s, oidIfAdminStatus+".3"); got != st.want {
					t.Errorf("after SET %d, GET ifAdminStatus.3 = %s", st.set, got)
				}
				if got := v2cGet(t, s, oidIfOperStatus+".3"); got != st.want {
					t.Errorf("after SET %d, GET ifOperStatus.3 = %s; oper did not follow admin", st.set, got)
				}
			}
			// Interfaces 1 and 2 were never named.
			for i := 1; i <= 2; i++ {
				if snap := state.Snapshot(i); snap.Admin != AdminUp || snap.Oper != OperUp {
					t.Errorf("interface %d moved: %+v", i, snap)
				}
			}
		})
	}
}

// A SET to the value already held succeeds and moves nothing, lastChange
// included.
func TestSetToCurrentValueIsNoErrorAndNoTransition(t *testing.T) {
	s, state := newSetTestServer(t, 1)
	if status, _ := setVia(t, s, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".1", 2)}); status != snmpErrNoError {
		t.Fatal(status)
	}
	before := state.Snapshot(1)
	time.Sleep(2 * time.Millisecond)
	status, index := setVia(t, s, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".1", 2)})
	if status != snmpErrNoError || index != 0 {
		t.Fatalf("status/index = %d/%d", status, index)
	}
	if after := state.Snapshot(1); after != before {
		t.Errorf("a SET to the current value moved the slot: %+v -> %+v", before, after)
	}
}

// ── v3 equals v2c inside the envelope ───────────────────────────────────────

func TestV3SetResponsePDUEqualsV2c(t *testing.T) {
	rows := map[string][]testBind{
		"success": {intBind(oidIfAdminStatus+".1", 2)},
		"error":   {intBind(oidIfAdminStatus+".1", 5)},
	}
	for name, binds := range rows {
		t.Run(name, func(t *testing.T) {
			s2, _ := newSetTestServer(t, 1)
			s3, _ := newSetTestServer(t, 1)
			h := decodeResponseHeader(t, s2.handleSNMPv2cRequest(setRequestAt(snmpVersion2c, binds)))
			r := decodeV3Response(t, s3.handleSNMPv3Request(v3SetRequest(t, s3, binds)))
			v2 := v3Response{pduTag: ASN1_GET_RESPONSE, requestID: h.requestID, errStatus: h.errStatus, errIndex: h.errIndex}
			for vp := 0; vp < len(h.varbinds); {
				n, after := parseLength(h.varbinds, vp+1)
				vb := h.varbinds[after : after+n]
				nameLen, afterName := parseLength(vb, 1)
				v := v3Varbind{oid: decodeOID(vb[afterName : afterName+nameLen])}
				vpos := afterName + nameLen
				v.valueTag = vb[vpos]
				vlen, afterV := parseLength(vb, vpos+1)
				v.value = vb[afterV : afterV+vlen]
				v2.varbinds = append(v2.varbinds, v)
				vp = after + n
			}
			if !reflect.DeepEqual(v2, r) {
				t.Errorf("v3 Response-PDU differs from v2c:\n v2c %+v\n v3  %+v", v2, r)
			}
		})
	}
}

// ── malformed and empty ─────────────────────────────────────────────────────

func TestSetMalformedListIsDiscarded(t *testing.T) {
	s, _ := newSetTestServer(t, 1)
	good := setRequestAt(snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".1", 2)})
	// The list SEQUENCE sits after: outer(2) version(3) community(8) pdu hdr(2)
	// reqid(3) err(3) idx(3). Find it structurally rather than by offset.
	pos, _, _ := requestVarBindListPos(good)
	if good[pos] != ASN1_SEQUENCE {
		t.Fatal("fixture: no list at the computed offset")
	}
	lengthened := append([]byte(nil), good...)
	lengthened[pos+1] += 8 // list length overruns the PDU
	if resp := s.handleSNMPv2cRequest(lengthened); len(resp) != 0 {
		t.Errorf("a list length that overruns the PDU was answered: % x", resp)
	}
	// Value TLV not ending on the binding boundary: shorten the value length.
	// List length overruns the PDU but NOT the datagram: a whole well-formed
	// varbind appended after the PDU, with the outer SEQUENCE and the list
	// length grown to cover it and the PDU length left alone. Unbounded, the
	// parser reads TWO bindings and answers; bounded by the PDU it is a list
	// that does not end on the PDU boundary. A stray byte is not enough here:
	// the parser refuses a non-SEQUENCE where a binding should start whether or
	// not the bound exists (a mutation showed that shape had no detection power).
	extra := encodeVarBind(oidSysDescr0, encodeNull())
	pastPDU := append(append([]byte(nil), good...), extra...)
	pastPDU[1] += byte(len(extra))     // outer SEQUENCE covers the extra binding
	pastPDU[pos+1] += byte(len(extra)) // list claims it, PDU length does not
	if resp := s.handleSNMPv2cRequest(pastPDU); len(resp) != 0 {
		t.Errorf("a list overrunning the PDU inside a longer datagram was answered: % x", resp)
	}
	valueShort := append([]byte(nil), good...)
	valueShort[len(valueShort)-2] = 0x00 // INTEGER length 1 -> 0, leaving a stray byte
	if resp := s.handleSNMPv2cRequest(valueShort); len(resp) != 0 {
		t.Errorf("a value TLV that does not end its binding was answered: % x", resp)
	}
}

func TestSetEmptyListIsNoError(t *testing.T) {
	s, _ := newSetTestServer(t, 1)
	resp := s.handleSNMPv2cRequest(setRequestAt(snmpVersion2c, nil))
	if len(resp) == 0 {
		t.Fatal("an empty SET was discarded")
	}
	h := decodeResponseHeader(t, resp)
	if h.errStatus != snmpErrNoError || len(h.varbinds) != 0 {
		t.Errorf("status %d with %d binding bytes, want noError and none", h.errStatus, len(h.varbinds))
	}
}

// ── the v1 mapping is a table over EVERY constant ───────────────────────────

func TestV1SetErrorStatusMapsEveryConstant(t *testing.T) {
	want := map[int]int{
		snmpErrNoError: snmpErrNoError, snmpErrTooBig: snmpErrTooBig, snmpErrNoSuchName: snmpErrNoSuchName,
		snmpErrBadValue: snmpErrBadValue, snmpErrReadOnly: snmpErrReadOnly, snmpErrGenErr: snmpErrGenErr,
		snmpErrNoAccess: snmpErrNoSuchName, snmpErrWrongType: snmpErrBadValue, snmpErrWrongLength: snmpErrBadValue,
		snmpErrWrongEncoding: snmpErrBadValue, snmpErrWrongValue: snmpErrBadValue, snmpErrNoCreation: snmpErrNoSuchName,
		snmpErrInconsistentValue: snmpErrBadValue, snmpErrResourceUnavailable: snmpErrGenErr,
		snmpErrCommitFailed: snmpErrGenErr, snmpErrUndoFailed: snmpErrGenErr,
		snmpErrAuthorizationError: snmpErrNoSuchName, snmpErrNotWritable: snmpErrNoSuchName,
		snmpErrInconsistentName: snmpErrNoSuchName,
	}
	if len(want) != 19 {
		t.Fatalf("table covers %d constants, RFC 3416 §3 defines 19", len(want))
	}
	for v2, v1 := range want {
		if got := v1SetErrorStatus(v2); got != v1 {
			t.Errorf("v1SetErrorStatus(%d) = %d, want %d", v2, got, v1)
		}
	}
	// The ladder never emits readOnly, so the identity row above is only there
	// for completeness; RFC 3584 §4.3 never MAPS TO it either.
	for v2 := 0; v2 <= 18; v2++ {
		if v2 != snmpErrReadOnly && v1SetErrorStatus(v2) == snmpErrReadOnly {
			t.Errorf("v1SetErrorStatus(%d) produced readOnly, which RFC 3584 §4.3 never emits", v2)
		}
	}
}

// ── the Tier C hook fires for a SET exactly as for a REST POST ──────────────

func TestSetFiresLinkTrapAndSyslog(t *testing.T) {
	fx := buildWired(t, true, true)
	s := &SNMPServer{device: fx.device}
	if status, _ := setVia(t, s, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".1", 2)}); status != snmpErrNoError {
		t.Fatal(status)
	}
	time.Sleep(100 * time.Millisecond)
	if got := fx.trapExp.Stats().Sent.Load(); got != 1 {
		t.Errorf("trap Sent after admin-down SET = %d, want 1 (linkDown)", got)
	}
	if got := fx.syslogExp.Stats().Sent.Load(); got != 1 {
		t.Errorf("syslog Sent after admin-down SET = %d, want 1", got)
	}
	if status, _ := setVia(t, s, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".1", 1)}); status != snmpErrNoError {
		t.Fatal(status)
	}
	time.Sleep(100 * time.Millisecond)
	if got := fx.trapExp.Stats().Sent.Load(); got != 2 {
		t.Errorf("trap Sent after admin-up SET = %d, want 2 (linkUp)", got)
	}
	if got := fx.syslogExp.Stats().Sent.Load(); got != 2 {
		t.Errorf("syslog Sent after admin-up SET = %d, want 2", got)
	}
}

// A SET and a REST admin POST are indistinguishable to an ON_CHANGE listener
// and to the notify hook.
func TestSetAndRestProduceTheSameEventSequence(t *testing.T) {
	type key struct {
		ifIndex     int
		oper, admin uint8
		changed     StateLeafBits
	}
	observe := func(t *testing.T, state *InterfaceState, drive func()) ([]key, int) {
		ch := make(chan StateChange, 16)
		state.AddListener(ch)
		defer state.RemoveListener(ch)
		var hooks int
		state.SetNotify(func(StateChange) { hooks++ })
		defer state.SetNotify(nil)
		drive()
		var got []key
		for {
			select {
			case e := <-ch:
				got = append(got, key{e.IfIndex, e.Oper, e.Admin, e.Changed})
				continue
			default:
			}
			break
		}
		return got, hooks
	}

	// SNMP SET.
	sSet, stSet := newSetTestServer(t, 1)
	viaSet, hooksSet := observe(t, stSet, func() {
		if status, _ := setVia(t, sSet, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".1", 2)}); status != snmpErrNoError {
			t.Fatal(status)
		}
	})

	// REST POST, through the real handler.
	f := newStateAPIFixture(t)
	stRest := f.device.metricsCycler.ifCounters.Load().State()
	viaRest, hooksRest := observe(t, stRest, func() {
		postInterfaceStatus(t, f, "admin-status", 1, `{"status":"DOWN"}`)
	})

	// Both events come from ONE compare-and-swap since nl6#694, so both carry
	// the post-swap derived oper. The predecessor made two swaps and its admin
	// event reported the pre-cascade oper (UP), which described a state that
	// no reader could observe by the time the event was delivered.
	want := []key{{1, OperDown, AdminDown, LeafAdminStatus}, {1, OperDown, AdminDown, LeafOperStatus}}
	if !reflect.DeepEqual(viaSet, want) {
		t.Errorf("SET events = %+v, want %+v", viaSet, want)
	}
	if !reflect.DeepEqual(viaRest, want) {
		t.Errorf("REST events = %+v, want %+v", viaRest, want)
	}
	if hooksSet != 1 || hooksRest != 1 {
		t.Errorf("notify hook fired %d (SET) / %d (REST) times, want 1 each", hooksSet, hooksRest)
	}
}

// ── admission equals GET's ──────────────────────────────────────────────────

func TestV3SetForUnknownUserOrWrongDigestIsReportedAndUnapplied(t *testing.T) {
	t.Run("unknown user", func(t *testing.T) {
		s, state := newSetTestServer(t, 1)
		req := v3SetRequest(t, s, []testBind{intBind(oidIfAdminStatus+".1", 2)})
		s.v3Config.Username = "somebody-else" // the request already names "testuser"
		resp := s.handleSNMPv3Request(req)
		if got := reportOIDOf(t, s, resp); got != oidUsmStatsUnknownUserNames && "."+got != oidUsmStatsUnknownUserNames {
			t.Errorf("report OID = %q, want usmStatsUnknownUserNames", got)
		}
		if snap := state.Snapshot(1); snap.Admin != AdminUp {
			t.Errorf("an unknown user's SET was applied: %+v", snap)
		}
	})
	t.Run("wrong digest", func(t *testing.T) {
		s, state := newSetTestServer(t, 1)
		// Set BEFORE the first usmState() call (v3SetRequest makes it), since
		// the derived keys are cached once per server.
		s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
		s.v3Config.Password = "authpassword"
		req := v3SetRequest(t, s, []testBind{intBind(oidIfAdminStatus+".1", 2)})
		off, n, ok := locateAuthParams(req)
		if !ok || n == 0 {
			t.Fatal("fixture: no auth params to corrupt")
		}
		req[off] ^= 0xFF
		resp := s.handleSNMPv3Request(req)
		if got := reportOIDOf(t, s, resp); got != oidUsmStatsWrongDigests && "."+got != oidUsmStatsWrongDigests {
			t.Errorf("report OID = %q, want usmStatsWrongDigests", got)
		}
		if snap := state.Snapshot(1); snap.Admin != AdminUp {
			t.Errorf("a wrongly-signed SET was applied: %+v", snap)
		}
	})
}

// ── the parser agrees with the GET-family parser on every input ─────────────

// FuzzParseVarBinds pins parseVarBinds against parseVarBindNames at the ENTRY
// point (the nl6#513 rule): both parse the same list, so they must agree on the
// malformed/absent/ok verdict and on every name, and neither may panic.
func FuzzParseVarBinds(f *testing.F) {
	f.Add(setRequestAt(snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".1", 2), strBind(oidSysDescr0, "x")}))
	f.Add(setRequestAt(snmpVersion1, nil))
	f.Add(snmpRequestAt(ASN1_GET_REQUEST, snmpVersion2c, []string{oidSysDescr0}))
	f.Fuzz(func(t *testing.T, data []byte) {
		pos, _, reached := requestVarBindListPos(data)
		if !reached {
			return
		}
		names, okNames := parseVarBindNames(data, pos)
		binds, contents, okBinds := parseVarBinds(data, pos)
		if okNames != okBinds {
			t.Fatalf("verdicts differ: names ok=%v binds ok=%v for % x", okNames, okBinds, data)
		}
		if !okBinds {
			return
		}
		if len(names) != len(binds) {
			t.Fatalf("%d names but %d binds", len(names), len(binds))
		}
		for i := range names {
			if names[i] != binds[i].name {
				t.Fatalf("name %d: %q vs %q", i, names[i], binds[i].name)
			}
		}
		if len(names) == 0 && binds != nil && len(contents) != 0 {
			t.Fatalf("empty list with %d content bytes", len(contents))
		}
	})
}

// ── SNMP and gNMI read the same engine after a SET ──────────────────────────

func TestSetSNMPAndGnmiAgree(t *testing.T) {
	device := newTestGnmiDevice(t, 3)
	s := &SNMPServer{device: device}
	if status, _ := setVia(t, s, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".2", 2)}); status != snmpErrNoError {
		t.Fatal(status)
	}
	if got := v2cGet(t, s, oidIfOperStatus+".2"); got != "2" {
		t.Errorf("SNMP GET ifOperStatus.2 = %s, want 2", got)
	}
	srv := newGnmiServer(device, new(int64), new(uint64), new(uint64))
	srv.resolver = newPathResolver(device)
	resp, err := srv.Get(context.Background(), &gnmipb.GetRequest{
		Path: []*gnmipb.Path{pathFromString(t, "/interfaces/interface[name=TestIf2]/state/oper-status")},
	})
	if err != nil {
		t.Fatalf("gNMI Get: %v", err)
	}
	if len(resp.GetNotification()) != 1 || len(resp.GetNotification()[0].GetUpdate()) != 1 {
		t.Fatalf("gNMI Get returned %+v, want one update", resp)
	}
	val := string(resp.GetNotification()[0].GetUpdate()[0].GetVal().GetJsonIetfVal())
	if !strings.Contains(val, "DOWN") {
		t.Errorf("gNMI oper-status after SNMP SET = %s, want DOWN", val)
	}
	// Interface 1 was not named and reads UP on both surfaces.
	if got := v2cGet(t, s, oidIfOperStatus+".1"); got != "1" {
		t.Errorf("SNMP GET ifOperStatus.1 = %s, want 1", got)
	}
}
