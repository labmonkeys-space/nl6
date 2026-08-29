/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// A GETBULK-driven SNMPv3 walk used never to terminate (nl6#526). The handler
// broke out of its collection loop on the endOfMibView sentinel without
// appending it, and with nothing collected the response builder answered a
// placeholder sysDescr.0 = "No data" binding.
//
// Two things were wrong with that, and the second is the one that broke walks:
// a string stood where an RFC 3416 exception belongs, AND sysDescr.0 sorts
// before almost any requested OID, so snmp4j's TreeUtils saw a non-increasing
// OID. An exception on a wrongly-named binding would fix only the first.
//
// These tests therefore assert BOTH the tag and the name.

// v3BulkFixture is a small profile whose last OID is known, so a walk can be
// driven to the end of the MIB deterministically.
func v3BulkFixture() map[string]string {
	vals := map[string]string{".1.3.6.1.2.1.1.1.0": "fuzz device"}
	for i := 1; i <= 6; i++ {
		vals[fmt.Sprintf(".1.3.6.1.2.1.2.2.1.2.%d", i)] = fmt.Sprintf("Gi0/%d", i)
	}
	return vals
}

func v3BulkMsg() *SNMPv3Message {
	return &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}}
}

// lastOIDOf walks the fixture to find its final OID.
func lastOIDOf(t *testing.T, s *SNMPServer) string {
	t.Helper()
	cur, last := ".1", ""
	for i := 0; i < 1000; i++ {
		n, _ := s.findNextOID(cur)
		if n == "" {
			break
		}
		last, cur = n, n
	}
	if last == "" {
		t.Fatal("fixture has no OIDs")
	}
	return last
}

func TestV3GetBulkPastEndOfMibReturnsException(t *testing.T) {
	s := v3TestServer(v3BulkFixture())
	last := lastOIDOf(t, s)

	resp := s.handleSNMPv3GetBulk(last, v3BulkMsg(), nil)
	r := decodeV3Response(t, resp)
	if len(r.varbinds) != 1 {
		t.Fatalf("end-of-MIB response carries %d bindings, want 1", len(r.varbinds))
	}
	name, tag := r.varbinds[0].oid, r.varbinds[0].valueTag

	// RFC 3416: the exception travels as a VALUE under noError, not as an
	// error-status. The v1 diversion pattern two functions away in
	// createVarbindResponse answers noSuchName instead, and without these
	// assertions a "fix" that copied it would pass.
	if r.pduTag != ASN1_GET_RESPONSE {
		t.Errorf("PDU tag = 0x%02x, want 0xA2 (GetResponse)", r.pduTag)
	}
	if r.errStatus != 0 || r.errIndex != 0 {
		t.Errorf("error-status=%d error-index=%d, want 0/0: the exception is a VALUE, not an error",
			r.errStatus, r.errIndex)
	}
	if tag != 0x82 {
		t.Errorf("v3 GETBULK past the last OID: value tag = 0x%02x, want 0x82 (endOfMibView)", tag)
	}
	if len(r.varbinds[0].value) != 0 {
		t.Errorf("endOfMibView carries %d content octets, want 0 (it is an IMPLICIT NULL)", len(r.varbinds[0].value))
	}
	// The name matters as much as the tag: sysDescr.0 sorts before the request,
	// which is what produced "OID not increasing".
	if name != last {
		t.Errorf("exception binding is named %q, want the REQUESTED OID %q: a walker matches "+
			"the response against its request, and a wrongly-named binding breaks the walk "+
			"even when the tag is right", name, last)
	}
	if bytes.Contains(resp, []byte("No data")) {
		t.Error("response still carries the \"No data\" placeholder")
	}
}

// TestV3GetBulkOnMinimalDeviceReturnsException uses a device with no resource
// OIDs at all. Note that such a device is NOT empty to a walker: findNextOID
// always injects sysName and sysLocation as candidates, since those are served
// from device fields rather than the OID index. So the end of its MIB view is
// past those two, not past the requested OID.
func TestV3GetBulkOnMinimalDeviceReturnsException(t *testing.T) {
	s := v3TestServer(map[string]string{})
	asked := lastOIDOf(t, s)

	resp := s.handleSNMPv3GetBulk(asked, v3BulkMsg(), nil)
	name, tag := v3ScopedVarbind(t, resp)

	if tag != 0x82 {
		t.Errorf("v3 GETBULK past a minimal device's last OID: value tag = 0x%02x, want 0x82", tag)
	}
	if name != asked {
		t.Errorf("exception binding named %q, want %q", name, asked)
	}
}

// TestV3GetBulkMidMibPairsNameWithItsOwnValue pins that where successors
// exist the response is unchanged AND that the binding's name and value come
// from the SAME MIB object.
//
// The pairing assertion is not decorative: mutating the builder to
// responses[len(responses)-1] — a name from one object and a value from
// another — passed the entire package suite before this test existed. The
// fixture uses distinct values per OID precisely so the pairing is observable
// rather than inferred.
func TestV3GetBulkMidMibPairsNameWithItsOwnValue(t *testing.T) {
	fixture := v3BulkFixture()
	s := v3TestServer(fixture)

	r := decodeV3Response(t, s.handleSNMPv3GetBulk(".1.3.6.1.2.1.1.1.0", v3BulkMsg(), nil))
	if len(r.varbinds) == 0 {
		t.Fatal("mid-MIB response carries no bindings")
	}
	vb := r.varbinds[0]

	if vb.valueTag == 0x82 || vb.valueTag == 0x80 {
		t.Fatalf("mid-MIB GETBULK returned an exception (tag 0x%02x); successors exist", vb.valueTag)
	}
	// Deliberately NOT asserting an exact successor. Doing that requires an
	// oracle, and the only convenient one is findNextOID, which is the call the
	// handler itself makes: any change in walk order would move both sides and
	// the test would see nothing. What IS independently checkable is that the
	// answer advances, which is the property a walker depends on.
	const asked = ".1.3.6.1.2.1.1.1.0"
	if compareOIDsLexicographically(vb.oid, asked) <= 0 {
		t.Errorf("mid-MIB GETBULK returned %q, which does not advance past the requested %q", vb.oid, asked)
	}
	// If the OID is one the fixture supplied, the value must be ITS value.
	if fixtureVal, ok := fixture[vb.oid]; ok && string(vb.value) != fixtureVal {
		t.Errorf("binding %q carries value %q, but the fixture defines it as %q: "+
			"the name and value came from different objects", vb.oid, vb.value, fixtureVal)
	}
}

// TestV3GetBulkBindingValuesMatchTheirOIDs walks several steps and checks the
// pairing at each, so the mutation above is caught wherever it is introduced.
func TestV3GetBulkBindingValuesMatchTheirOIDs(t *testing.T) {
	fixture := v3BulkFixture()
	s := v3TestServer(fixture)

	cur := ".1.3.6.1.2.1.2.2.1.2.0"
	for i := 0; i < 6; i++ {
		r := decodeV3Response(t, s.handleSNMPv3GetBulk(cur, v3BulkMsg(), nil))
		if len(r.varbinds) == 0 {
			t.Fatalf("step %d: no bindings", i)
		}
		vb := r.varbinds[0]
		if vb.valueTag == 0x82 {
			return
		}
		if want, ok := fixture[vb.oid]; ok && string(vb.value) != want {
			t.Fatalf("step %d: binding %q carries %q, fixture says %q", i, vb.oid, vb.value, want)
		}
		cur = vb.oid
	}
}

// TestV3BulkWalkTerminates is the load-bearing test. It is what fails if the
// placeholder comes back, or if the exception is named with anything other
// than the requested OID.
func TestV3BulkWalkTerminates(t *testing.T) {
	s := v3TestServer(v3BulkFixture())

	const maxSteps = 200
	cur := ".1"
	prev := ""
	visited := 0

	for i := 0; i < maxSteps; i++ {
		resp := s.handleSNMPv3GetBulk(cur, v3BulkMsg(), nil)
		name, tag := v3ScopedVarbind(t, resp)

		if bytes.Contains(resp, []byte("No data")) {
			t.Fatalf("step %d: response carries the \"No data\" placeholder", i)
		}
		if tag == 0x82 {
			if name != cur {
				t.Errorf("terminating binding named %q, want the requested %q", name, cur)
			}
			if visited == 0 {
				t.Fatal("walk terminated immediately without visiting any OID")
			}
			return // walk terminated correctly
		}
		if prev != "" && compareOIDsLexicographically(name, prev) <= 0 {
			t.Fatalf("step %d: OID did not increase: %s after %s (this is exactly what a "+
				"walker reports as \"OID not increasing\")", i, name, prev)
		}
		prev, cur = name, name
		visited++
	}
	t.Fatalf("v3 bulk walk did not terminate within %d steps, having visited %d OIDs", maxSteps, visited)
}

// TestV2cGetBulkUnaffected pins that the v2c path did not move.
//
// An earlier version asserted only that the response was non-empty and free of
// the string "No data" — a literal that only ever existed on the v3 path, so
// it could never fire for a v2c regression. Transplanting nl6#526's bug into
// handleGetBulk left it green. It now decodes the binding.
func TestV2cGetBulkUnaffected(t *testing.T) {
	s := newTestServer(v3BulkFixture())
	last := lastOIDOf(t, s)

	resp := s.handleGetBulk(last, buildGetBulkPDUForFuzz(0, 10, last))
	if len(resp) == 0 {
		t.Fatal("v2c GETBULK returned nothing")
	}
	if bytes.Contains(resp, []byte("No data")) {
		t.Error("v2c GETBULK carries a \"No data\" placeholder")
	}

	// The v2c end-of-MIB pad must be named with the requested OID and carry the
	// exception, the same contract nl6#526 established for v3.
	name, tag := v2cFirstVarbind(t, resp)
	if tag != 0x82 {
		t.Errorf("v2c GETBULK past the last OID: value tag = 0x%02x, want 0x82", tag)
	}
	if name != last {
		t.Errorf("v2c pad binding named %q, want the requested %q", name, last)
	}
}

// v2cFirstVarbind decodes a v2c GetResponse down to its first varbind.
func v2cFirstVarbind(t *testing.T, resp []byte) (string, byte) {
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
	vb := expectSeq(t, vbl, "varbind")
	if len(vb) == 0 || vb[0] != ASN1_OID {
		t.Fatalf("varbind does not start with an OID: % x", vb)
	}
	nl, an := parseLength(vb, 1)
	if nl < 0 || an+nl > len(vb) {
		t.Fatal("bad name length")
	}
	return decodeOID(vb[an : an+nl]), vb[an+nl]
}

// ── decoding ────────────────────────────────────────────────────────────────

// v3Response is a decoded SNMPv3 GetResponse: the fields a walker actually
// uses to decide whether to keep walking.
type v3Response struct {
	pduTag    byte
	requestID int
	errStatus int
	errIndex  int
	varbinds  []v3Varbind
}

type v3Varbind struct {
	oid      string
	valueTag byte
	value    []byte
}

// decodeV3Response walks the SNMPv3 message STRUCTURALLY down to the scoped
// PDU's variable-bindings, rather than scanning the message for an OID tag.
//
// An earlier version of this helper did scan, and was demonstrably foolable:
// an engine ID whose bytes happen to look like an OID TLV made it report that
// engine ID as the varbind name. Every assertion in this file rests on this
// helper, so it decodes the nesting it claims to decode.
//
// v3TestServer runs with privacy off, so the scoped PDU is in the clear.
func decodeV3Response(t *testing.T, resp []byte) v3Response {
	t.Helper()

	// SNMPv3 message: SEQUENCE { version, globalData, securityParams, scopedPDU }
	body := expectSeq(t, resp, "v3 message")
	pos := 0
	pos = skipTLV(t, body, pos, "msgVersion")
	pos = skipTLV(t, body, pos, "msgGlobalData")
	pos = skipTLV(t, body, pos, "msgSecurityParameters")

	// scopedPDU: SEQUENCE { contextEngineID, contextName, data }
	if pos >= len(body) {
		t.Fatalf("no scoped PDU in % x", resp)
	}
	scoped := expectSeq(t, body[pos:], "scopedPDU")
	sp := 0
	sp = skipTLV(t, scoped, sp, "contextEngineID")
	sp = skipTLV(t, scoped, sp, "contextName")

	// data: the PDU itself.
	if sp >= len(scoped) {
		t.Fatalf("no PDU inside the scoped PDU")
	}
	out := v3Response{pduTag: scoped[sp]}
	pduLen, afterLen := parseLength(scoped, sp+1)
	if pduLen < 0 || afterLen+pduLen > len(scoped) {
		t.Fatalf("bad PDU length in scoped PDU")
	}
	pdu := scoped[afterLen : afterLen+pduLen]

	pp := 0
	out.requestID, pp = expectInt(t, pdu, pp, "request-id")
	out.errStatus, pp = expectInt(t, pdu, pp, "error-status")
	out.errIndex, pp = expectInt(t, pdu, pp, "error-index")

	vbl := expectSeq(t, pdu[pp:], "variable-bindings")
	for vp := 0; vp < len(vbl); {
		vb := expectSeq(t, vbl[vp:], "varbind")
		// advance vp past this varbind
		n, after := parseLength(vbl, vp+1)
		if n < 0 || after+n > len(vbl) {
			t.Fatalf("bad varbind length")
		}
		vp = after + n

		if len(vb) == 0 || vb[0] != ASN1_OID {
			t.Fatalf("varbind does not start with an OBJECT IDENTIFIER: % x", vb)
		}
		nameLen, afterName := parseLength(vb, 1)
		if nameLen < 0 || afterName+nameLen > len(vb) {
			t.Fatalf("bad varbind name length")
		}
		v := v3Varbind{oid: decodeOID(vb[afterName : afterName+nameLen])}
		vpos := afterName + nameLen
		if vpos >= len(vb) {
			t.Fatalf("varbind has a name but no value")
		}
		v.valueTag = vb[vpos]
		vlen, afterV := parseLength(vb, vpos+1)
		if vlen >= 0 && afterV+vlen <= len(vb) {
			v.value = vb[afterV : afterV+vlen]
		}
		out.varbinds = append(out.varbinds, v)
	}
	return out
}

// expectSeq asserts a SEQUENCE at the start of b and returns its contents.
func expectSeq(t *testing.T, b []byte, what string) []byte {
	t.Helper()
	if len(b) == 0 || b[0] != ASN1_SEQUENCE {
		t.Fatalf("%s: expected SEQUENCE, got % x", what, b[:min(8, len(b))])
	}
	n, after := parseLength(b, 1)
	if n < 0 || after+n > len(b) {
		t.Fatalf("%s: bad SEQUENCE length", what)
	}
	return b[after : after+n]
}

func skipTLV(t *testing.T, b []byte, pos int, what string) int {
	t.Helper()
	if pos >= len(b) {
		t.Fatalf("%s: ran off the end", what)
	}
	n, after := parseLength(b, pos+1)
	if n < 0 || after+n > len(b) {
		t.Fatalf("%s: bad length", what)
	}
	return after + n
}

func expectInt(t *testing.T, b []byte, pos int, what string) (int, int) {
	t.Helper()
	if pos >= len(b) || b[pos] != ASN1_INTEGER {
		t.Fatalf("%s: expected INTEGER at %d, got % x", what, pos, b[pos:min(pos+4, len(b))])
	}
	n, after := parseLength(b, pos+1)
	if n < 0 || after+n > len(b) {
		t.Fatalf("%s: bad INTEGER length", what)
	}
	// BER INTEGER is two's complement: sign-extend from the first content
	// octet so a negative value (or a request-id >= 0x80000000) decodes as
	// the number that was encoded.
	v := 0
	if n > 0 && b[after]&0x80 != 0 {
		v = -1
	}
	for _, c := range b[after : after+n] {
		v = v<<8 | int(c)
	}
	return v, after + n
}

// v3ScopedVarbind is the single-binding convenience over decodeV3Response.
func v3ScopedVarbind(t *testing.T, resp []byte) (name string, valueTag byte) {
	t.Helper()
	r := decodeV3Response(t, resp)
	if len(r.varbinds) == 0 {
		t.Fatalf("response carries no variable bindings: % x", resp)
	}
	return r.varbinds[0].oid, r.varbinds[0].valueTag
}

// TestV3GetBulkTerminatesOnNonAdvancingMap covers the other route to nl6#526's
// symptom. oidNextMap is built from operator-supplied resource files, and a map
// that sends an OID to itself would otherwise make the collection loop hand
// back a non-increasing OID with no exception — which is precisely what a
// walker cannot terminate on. The v1/v2c GETNEXT path grew the same bound in
// nl6#524; this pins it for v3 bulk.
//
// Both halves of the bound are pinned: an entry that maps to ITSELF and one
// that maps BACKWARD. Loosening the guard from <= 0 to == 0 keeps the self
// case green and answers the backward case with a non-increasing OID under
// noError, which is the nl6#526 symptom by the route this guard closes.
func TestV3GetBulkTerminatesOnNonAdvancingMap(t *testing.T) {
	cases := []struct {
		name, stuck, next string
	}{
		{"self", ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.1.0"},
		{"backward", ".1.3.6.1.2.1.2.2.1.2.3", ".1.3.6.1.2.1.2.2.1.2.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := v3TestServer(v3BulkFixture())
			s.device.resources.oidNextMap.Store(tc.stuck, tc.next)

			r := decodeV3Response(t, s.handleSNMPv3GetBulk(tc.stuck, v3BulkMsg(), nil))
			if len(r.varbinds) != 1 {
				t.Fatalf("got %d bindings, want 1", len(r.varbinds))
			}
			vb := r.varbinds[0]
			if vb.valueTag != 0x82 {
				t.Errorf("non-advancing map (%s -> %s): value tag = 0x%02x, want 0x82; a walker cannot "+
					"terminate on a non-increasing OID that carries no exception", tc.stuck, tc.next, vb.valueTag)
			}
			if vb.oid != tc.stuck {
				t.Errorf("terminating binding named %q, want the requested %q", vb.oid, tc.stuck)
			}
		})
	}
}

// TestV3GetBulkShipsEveryCollectedBinding replaces the nl6#526-era
// TestV3GetBulkShipsOneBinding, which asserted that the response was
// byte-identical for 1 and many collected OIDs and was written to FAIL when
// nl6#535 landed. It did.
//
// A v3 GETBULK now carries every binding the collection loop gathered, in
// order, each paired with its own value.
func TestV3GetBulkShipsEveryCollectedBinding(t *testing.T) {
	fixture := v3BulkFixture()
	s := v3TestServer(fixture)
	msg := v3BulkMsg()

	// What the collection loop will gather, computed the same way it does.
	var want []string
	cur := ".1.3.6.1.2.1.1.1.0"
	for i := 0; i < 10; i++ {
		n, v := s.findNextOID(cur)
		if n == "" || v == valueEndOfMibView {
			break
		}
		want = append(want, n)
		cur = n
	}
	if len(want) < 3 {
		t.Fatalf("fixture yielded only %d successors; need at least 3 to show more than one ships", len(want))
	}

	r := decodeV3Response(t, s.handleSNMPv3GetBulk(".1.3.6.1.2.1.1.1.0", msg, nil))
	if len(r.varbinds) != len(want) {
		t.Fatalf("response carries %d bindings, want %d: a GETBULK must not discard what it collected",
			len(r.varbinds), len(want))
	}
	for i, vb := range r.varbinds {
		if vb.oid != want[i] {
			t.Errorf("binding %d is %q, want %q: order must be preserved", i, vb.oid, want[i])
		}
		if v, ok := fixture[vb.oid]; ok && string(vb.value) != v {
			t.Errorf("binding %d (%s) carries %q, fixture says %q: name and value came from "+
				"different objects", i, vb.oid, vb.value, v)
		}
	}
}

// TestV3GetBulkThroughDispatcher drives the fix through handleSNMPv3Request
// rather than calling the handler directly, so the parts every other test in
// this file bypasses are covered: the ASN1_GET_BULK branch in snmp.go, the OID
// arriving from extractOIDAndTypeFromScopedPDU rather than from a literal, and
// the request-id a walker uses to correlate the terminating response.
//
// Without this, routing GETBULK to the GET branch would keep the suite green.
func TestV3GetBulkThroughDispatcher(t *testing.T) {
	s := v3TestServer(v3BulkFixture())
	last := lastOIDOf(t, s)

	req := buildV3GetBulkRequest(t, s, last, 4242)
	resp := s.handleSNMPv3Request(req)
	if len(resp) == 0 {
		t.Fatal("dispatcher returned nothing for a v3 GETBULK")
	}

	r := decodeV3Response(t, resp)
	if len(r.varbinds) != 1 {
		t.Fatalf("got %d bindings, want 1", len(r.varbinds))
	}
	if r.varbinds[0].valueTag != 0x82 {
		t.Errorf("through the dispatcher: value tag = 0x%02x, want 0x82", r.varbinds[0].valueTag)
	}
	if r.varbinds[0].oid != last {
		t.Errorf("binding named %q, want the requested %q", r.varbinds[0].oid, last)
	}
	// A walker correlates the terminating response by request-id; a response it
	// cannot match is as useless as one it cannot terminate on.
	if r.requestID != 4242 {
		t.Errorf("response request-id = %d, want the request's 4242", r.requestID)
	}
}

// buildV3GetBulkRequest assembles a plaintext SNMPv3 GETBULK message.
func buildV3GetBulkRequest(t *testing.T, s *SNMPServer, oid string, reqID int) []byte {
	t.Helper()

	vb := encodeSequence(append(encodeOID(oid), encodeNull()...))
	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(reqID)...)
	pduBody = append(pduBody, encodeInteger(0)...)  // non-repeaters
	pduBody = append(pduBody, encodeInteger(10)...) // max-repetitions
	pduBody = append(pduBody, encodeSequence(vb)...)
	pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(pduBody)), pduBody...)...)

	var scoped []byte
	scoped = append(scoped, encodeOctetString(s.v3Config.EngineID)...)
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, pdu...)
	scopedPDU := encodeSequence(scoped)

	var global []byte
	global = append(global, encodeInteger(1)...)     // msgID
	global = append(global, encodeInteger(65507)...) // msgMaxSize
	global = append(global, encodeOctetString(string([]byte{0x00}))...)
	global = append(global, encodeInteger(3)...) // USM
	globalData := encodeSequence(global)

	var usm []byte
	usm = append(usm, encodeOctetString(s.v3Config.EngineID)...)
	usm = append(usm, encodeInteger(0)...)
	usm = append(usm, encodeInteger(0)...)
	usm = append(usm, encodeOctetString(s.v3Config.Username)...)
	usm = append(usm, encodeOctetString("")...)
	usm = append(usm, encodeOctetString("")...)
	secParams := encodeOctetString(string(encodeSequence(usm)))

	var msg []byte
	msg = append(msg, encodeInteger(3)...)
	msg = append(msg, globalData...)
	msg = append(msg, secParams...)
	msg = append(msg, scopedPDU...)
	return encodeSequence(msg)
}

// TestV3GetBulkRespectsTheDatagramBudget covers the bound nl6#535 added. The
// v3 path had NO size ceiling at all: createSNMPv3GetBulkResponse built its own
// message and consulted nothing. That was survivable only because the handler
// shipped one binding and max-repetitions was hardcoded to 10; making it ship
// every collected binding is what makes the bound necessary rather than
// theoretical.
//
// The size is MEASURED rather than predicted, because a v3 message's envelope
// depends on the engine ID, user name and privacy parameters, and under privacy
// the scoped PDU is padded to a cipher block. This test drives real values
// through the real builder rather than asserting an arithmetic model.
func TestV3GetBulkRespectsTheDatagramBudget(t *testing.T) {
	// Values long enough that a handful of bindings would exceed a datagram.
	long := strings.Repeat("X", 400)
	vals := map[string]string{".1.3.6.1.2.1.1.1.0": "dev"}
	for i := 1; i <= 20; i++ {
		vals[fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.18.%d", i)] = long
	}
	s := v3TestServer(vals)

	resp := s.handleSNMPv3GetBulk(".1.3.6.1.2.1.1.1.0", v3BulkMsg(), nil)
	if len(resp) == 0 {
		t.Fatal("no response")
	}
	if len(resp) > maxSNMPResponseSize {
		t.Errorf("v3 GETBULK response is %d bytes, over the %d-byte budget: the datagram would "+
			"fragment on a standard-MTU path", len(resp), maxSNMPResponseSize)
	}

	r := decodeV3Response(t, resp)
	if len(r.varbinds) == 0 {
		t.Error("response carries no bindings; a GETBULK must emit at least one or a walk stalls")
	}
	// Truncation drops from the END, so a walker resumes from the last OID
	// returned (RFC 3416 §4.2.3). Order must still be ascending.
	prev := ""
	for i, vb := range r.varbinds {
		if prev != "" && compareOIDsLexicographically(vb.oid, prev) <= 0 {
			t.Fatalf("binding %d (%s) does not increase after %s; a truncated response must still "+
				"let the walker resume", i, vb.oid, prev)
		}
		prev = vb.oid
	}
}

// TestV3GetBulkEmitsOneBindingEvenIfOversized pins the carve-out the v2c
// truncate rule also makes: a response with an empty binding list and no error
// stalls a walk forever with no signal, which is worse than one oversized
// datagram.
func TestV3GetBulkEmitsOneBindingEvenIfOversized(t *testing.T) {
	huge := strings.Repeat("Y", maxSNMPResponseSize*2)
	s := v3TestServer(map[string]string{
		".1.3.6.1.2.1.1.1.0":         "dev",
		".1.3.6.1.2.1.31.1.1.1.18.1": huge,
	})

	r := decodeV3Response(t, s.handleSNMPv3GetBulk(".1.3.6.1.2.1.1.1.0", v3BulkMsg(), nil))
	if len(r.varbinds) == 0 {
		t.Error("a single oversized binding produced an empty binding list; that stalls a walk " +
			"with no signal, which is why the v2c truncate rule always emits at least one")
	}
}
