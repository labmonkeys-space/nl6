/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"log"
	"math/bits"
	"strings"
	"testing"
	"time"
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

// buildV3GetBulkRequest assembles a plaintext SNMPv3 GETBULK message with
// non-repeaters 0 and max-repetitions 10.
func buildV3GetBulkRequest(t *testing.T, s *SNMPServer, oid string, reqID int) []byte {
	t.Helper()
	return buildV3GetBulkRequestWith(t, s, []string{oid}, reqID, 0, 10)
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
	// The bound is MEASURED through the real envelope, so the test has to be
	// able to catch a builder that measures the wrong thing. With one value
	// length, consecutive candidates differ by ~410 B and the ~70 B
	// noAuthNoPriv envelope never falls between two of them: a builder that
	// measured the bare scoped PDU passed. So the value length is SWEPT, which
	// puts the envelope, and under privacy the cipher-block padding, on the
	// wrong side of the boundary for some length in the range.
	privs := []struct {
		name  string
		proto int
	}{
		{"noAuthNoPriv", SNMPV3_PRIV_NONE},
		{"des", SNMPV3_PRIV_DES},
		{"aes128", SNMPV3_PRIV_AES128},
	}
	for _, priv := range privs {
		t.Run(priv.name, func(t *testing.T) {
			for length := 300; length <= 420; length++ {
				checkV3BulkBudget(t, priv.proto, length, maxSNMPResponseSize, 0)
			}
		})
	}
}

// checkV3BulkBudget builds a 20-row ifAlias table of values `length` bytes long,
// asks a GETBULK from sysDescr.0 under the given privacy protocol with the given
// msgMaxSize declaration (0 = none), and asserts three things about the reply:
// it fits `limit`; its bindings are the PREFIX of what an unbounded collection
// would have returned (truncation drops from the END, so a walker resumes
// without a gap); and the fit is maximal (one more binding would not fit).
//
// The prefix check is what catches a builder that drops from the head: that
// still returns ascending bindings under budget, and a walker resuming from
// the last one silently skips the rows that were dropped.
func checkV3BulkBudget(t *testing.T, privProto, length, limit, declaredMax int) {
	t.Helper()
	vals := map[string]string{".1.3.6.1.2.1.1.1.0": "dev"}
	for i := 1; i <= 20; i++ {
		vals[fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.18.%d", i)] = strings.Repeat("X", length)
	}
	s := v3TestServer(vals)
	msg := v3PrivSeed(s)
	msg.GlobalData.MsgMaxSize = declaredMax
	encrypted := privProto != SNMPV3_PRIV_NONE
	if encrypted {
		s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
		s.v3Config.PrivProtocol = privProto
		msg.GlobalData.MsgFlags = SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV
	}

	resp := s.handleSNMPv3GetBulk(".1.3.6.1.2.1.1.1.0", msg, nil)
	if len(resp) == 0 {
		t.Fatalf("length %d: no response", length)
	}
	if len(resp) > limit {
		t.Fatalf("length %d: v3 GETBULK response is %d bytes, over the %d-byte limit: the datagram "+
			"would fragment on a standard-MTU path (or exceed what the manager said it accepts)",
			length, len(resp), limit)
	}

	r := decodeV3ResponsePossiblyEncrypted(t, s, resp, encrypted)
	if len(r.varbinds) == 0 {
		t.Fatalf("length %d: response carries no bindings; a GETBULK must emit at least one or a walk stalls", length)
	}

	// Oracle: what the collection loop gathers, unbounded.
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
	if len(r.varbinds) > len(want) {
		t.Fatalf("length %d: %d bindings shipped, only %d collected", length, len(r.varbinds), len(want))
	}
	for i, vb := range r.varbinds {
		if vb.oid != want[i] {
			t.Fatalf("length %d: binding %d is %s, want %s: truncation must drop from the END so a "+
				"walker resuming from the last OID returned sees every row", length, i, vb.oid, want[i])
		}
	}

	// Maximal: the next binding would not have fit. Measured the same way the
	// builder measures, so this cannot disagree with it on arithmetic.
	if n := len(r.varbinds); n < len(want) {
		scoped, err := s.createScopedPDUMulti(want[:n+1], valuesFor(s, want[:n+1]), msg)
		if err != nil {
			t.Fatal(err)
		}
		bigger, err := s.wrapScopedPDUInV3Message(scoped, msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(bigger) <= limit {
			t.Fatalf("length %d: %d bindings shipped but %d would still fit in %d bytes (%d): the "+
				"truncation is not maximal", length, n, n+1, limit, len(bigger))
		}
	}
}

func valuesFor(s *SNMPServer, oids []string) []string {
	out := make([]string, len(oids))
	for i, oid := range oids {
		out[i] = s.findResponse(oid)
	}
	return out
}

// TestV3GetBulkHonoursManagerMsgMaxSize pins RFC 3412 §7.1: a response fits the
// msgMaxSize the requester declared when that is smaller than the datagram
// budget. A declaration below the RFC 3412 §7.2 floor of 484 is malformed and
// is ignored rather than honoured, which the second case pins from the other
// side.
func TestV3GetBulkHonoursManagerMsgMaxSize(t *testing.T) {
	for _, tc := range []struct {
		name          string
		declared      int
		expectedLimit int
	}{
		{"declared 700 clamps the budget", 700, 700},
		{"declared 100 is below the floor and ignored", 100, maxSNMPResponseSize},
		{"declared 65507 does not raise the budget", 65507, maxSNMPResponseSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for length := 100; length <= 140; length++ {
				checkV3BulkBudget(t, SNMPV3_PRIV_NONE, length, tc.expectedLimit, tc.declared)
			}
		})
	}
	// The ignored-floor case asserts a LIMIT of the full budget, which a
	// response under 100 bytes would also satisfy; make sure it actually went
	// over the declared value.
	vals := map[string]string{".1.3.6.1.2.1.1.1.0": "dev"}
	for i := 1; i <= 6; i++ {
		vals[fmt.Sprintf(".1.3.6.1.2.1.2.2.1.2.%d", i)] = strings.Repeat("Z", 60)
	}
	s := v3TestServer(vals)
	msg := v3BulkMsg()
	msg.GlobalData.MsgMaxSize = 100
	if resp := s.handleSNMPv3GetBulk(".1.3.6.1.2.1.1.1.0", msg, nil); len(resp) <= 100 {
		t.Errorf("a sub-484 msgMaxSize of 100 was honoured (%d-byte response); it is malformed and must be ignored", len(resp))
	}
}

// TestV3GetBulkTruncatedWalkResumesWithoutGapOrRepeat is the v3 twin of the
// v2c test of the same name: the RFC 3416 §4.2.3 property the truncation
// relies on, driven as a collector drives it.
func TestV3GetBulkTruncatedWalkResumesWithoutGapOrRepeat(t *testing.T) {
	vals := map[string]string{".1.3.6.1.2.1.1.1.0": "dev"}
	for i := 1; i <= 20; i++ {
		vals[fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.18.%d", i)] = strings.Repeat("X", 400)
	}
	s := v3TestServer(vals)

	first := decodeV3Response(t, s.handleSNMPv3GetBulk(".1.3.6.1.2.1.1.1.0", v3BulkMsg(), nil))
	if len(first.varbinds) == 0 || len(first.varbinds) >= 10 {
		t.Fatalf("first response carries %d bindings; the fixture is sized so that the 10 collected do not fit", len(first.varbinds))
	}
	last := first.varbinds[len(first.varbinds)-1].oid
	second := decodeV3Response(t, s.handleSNMPv3GetBulk(last, v3BulkMsg(), nil))
	if len(second.varbinds) == 0 {
		t.Fatal("resume returned no bindings")
	}

	// No repeat, no gap: the two responses together are a prefix of the
	// column in walk order.
	var got []string
	for _, vb := range first.varbinds {
		got = append(got, vb.oid)
	}
	for _, vb := range second.varbinds {
		got = append(got, vb.oid)
	}
	cur := ".1.3.6.1.2.1.1.1.0"
	for i, oid := range got {
		next, _ := s.findNextOID(cur)
		if oid != next {
			t.Fatalf("walk position %d is %s, want %s: the resume from %s skipped or repeated a row", i, oid, next, last)
		}
		cur = next
	}
}

// TestV3GetBulkMultiBindingThroughDispatcher drives a real datagram through
// handleSNMPv3Request, so the request-id echo, the flags copy and the USM
// envelope are exercised on a MANY-binding response and not only on the
// single-binding responses the older dispatcher tests use.
func TestV3GetBulkMultiBindingThroughDispatcher(t *testing.T) {
	s := v3TestServer(v3BulkFixture())
	resp := s.handleSNMPv3Request(buildV3GetBulkRequest(t, s, ".1.3.6.1.2.1.1.1.0", 7777))
	if len(resp) == 0 {
		t.Fatal("dispatcher returned nothing")
	}
	r := decodeV3Response(t, resp)
	if r.requestID != 7777 {
		t.Errorf("request-id = %d, want 7777", r.requestID)
	}
	if len(r.varbinds) != 6 {
		t.Errorf("response carries %d bindings, want the 6 successors the fixture holds", len(r.varbinds))
	}
}

func TestV3GetBulkEmitsOneBindingEvenIfOversized(t *testing.T) {
	huge := strings.Repeat("Y", maxSNMPResponseSize*2)
	s := v3TestServer(map[string]string{
		".1.3.6.1.2.1.1.1.0":         "dev",
		".1.3.6.1.2.1.31.1.1.1.18.1": huge,
	})

	resp := s.handleSNMPv3GetBulk(".1.3.6.1.2.1.1.1.0", v3BulkMsg(), nil)
	// Premise first: the one binding really is over budget. Without this a
	// shrunken fixture would pass the test while exercising nothing.
	if len(resp) <= maxSNMPResponseSize {
		t.Fatalf("fixture no longer produces an oversized response (%d bytes <= %d); the carve-out is untested",
			len(resp), maxSNMPResponseSize)
	}
	r := decodeV3Response(t, resp)
	if len(r.varbinds) == 0 {
		t.Error("a single oversized binding produced an empty binding list; that stalls a walk " +
			"with no signal, which is why the v2c truncate rule always emits at least one")
	}
}

// ── nl6#535: max-repetitions is honoured ────────────────────────────────────

// v3BulkScopedPDUBytes builds a GETBULK scoped PDU in CONTENTS form with the
// given parameters, which is the shape parseSNMPv3GetBulkParams reads. Pure so
// the fuzz targets can seed from it without a *testing.T or a server.
func v3BulkScopedPDUBytes(engineID, oid string, nonRepeaters, maxRepetitions int) []byte {
	vb := encodeSequence(append(encodeOID(oid), encodeNull()...))
	var body []byte
	body = append(body, encodeInteger(42)...)
	body = append(body, encodeInteger(nonRepeaters)...)
	body = append(body, encodeInteger(maxRepetitions)...)
	body = append(body, encodeSequence(vb)...)
	pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)

	var scoped []byte
	scoped = append(scoped, encodeOctetString(engineID)...)
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, pdu...)
	return scoped // CONTENTS form, as parseSNMPv3Message stores it
}

func v3BulkScopedPDU(t *testing.T, s *SNMPServer, oid string, nonRepeaters, maxRepetitions int) []byte {
	t.Helper()
	return v3BulkScopedPDUBytes(s.v3Config.EngineID, oid, nonRepeaters, maxRepetitions)
}

// brokenBulkScopedPDUs is the shape table for parseSNMPv3GetBulkParams: one
// entry per check the parser makes AFTER the GETBULK tag, so each of its
// length reads is reached by a committed input on an ordinary `go test`. The
// earlier rows all bailed at or before the tag, which left the five new
// parseLength sites and both parseBERInt reads covered by live fuzzing only.
// Shared between TestV3GetBulkMalformedParamsFallBack and the fuzz seeds.
func brokenBulkScopedPDUs(engineID string) map[string][]byte {
	const oid = ".1.3.6.1.2.1.1.1.0"
	good := v3BulkScopedPDUBytes(engineID, oid, 0, 5)
	engIDTLV := len(encodeOctetString(engineID))
	ctxNameTLV := len(encodeOctetString(""))
	pduStart := engIDTLV + ctxNameTLV // offset of the 0xA5 tag
	// Inside the PDU: tag(1) len(1) then request-id (02 01 2a), non-repeaters
	// (02 01 00), max-repetitions (02 01 05).
	reqID := pduStart + 2
	nonRep := reqID + 3
	maxRep := nonRep + 3

	cut := func(n int) []byte { return append([]byte(nil), good[:n]...) }
	withPDULen := func(l byte) []byte {
		b := cut(len(good))
		b[pduStart+1] = l
		return b
	}
	// A GETBULK-tagged PDU whose declared length is shorter than its fields:
	// the container bound must stop the reads even though the datagram has
	// the bytes.
	shortContainer := withPDULen(byte(maxRep - pduStart - 2)) // ends before max-repetitions
	// max-repetitions carried as a 9-octet INTEGER, wider than parseBERInt
	// accepts.
	wide := cut(maxRep)
	wide = append(wide, ASN1_INTEGER, 9, 0x01, 0, 0, 0, 0, 0, 0, 0, 0)
	// A long-form length claiming four bytes that are not there.
	badLen := cut(nonRep + 1)
	badLen = append(badLen, 0x84)

	return map[string][]byte{
		"truncated after contextEngineID":  cut(engIDTLV),
		"truncated after contextName":      cut(pduStart),
		"truncated after PDU tag":          cut(pduStart + 1),
		"truncated after PDU length":       cut(pduStart + 2),
		"truncated inside request-id":      cut(reqID + 2),
		"truncated after request-id":       cut(nonRep),
		"truncated inside non-repeaters":   cut(nonRep + 2),
		"truncated after non-repeaters":    cut(maxRep),
		"truncated inside max-repetitions": cut(maxRep + 2),
		"PDU length overruns datagram":     withPDULen(0x7f),
		"PDU length ends before max-reps":  shortContainer,
		"max-repetitions nine octets":      wide,
		"non-repeaters bad long-form len":  badLen,
	}
}

// wideBulkFixture has enough OIDs to distinguish max-repetitions values.
func wideBulkFixture(n int) map[string]string {
	vals := map[string]string{".1.3.6.1.2.1.1.1.0": "dev"}
	for i := 1; i <= n; i++ {
		vals[fmt.Sprintf(".1.3.6.1.2.1.2.2.1.2.%03d", i)] = fmt.Sprintf("Gi0/%d", i)
	}
	return vals
}

func TestV3GetBulkHonoursMaxRepetitions(t *testing.T) {
	s := v3TestServer(wideBulkFixture(300))
	const start = ".1.3.6.1.2.1.1.1.0"

	for _, want := range []int{1, 2, 5, 10} {
		t.Run(fmt.Sprintf("max-repetitions=%d", want), func(t *testing.T) {
			sp := v3BulkScopedPDU(t, s, start, 0, want)
			msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: sp}

			r := decodeV3Response(t, s.handleSNMPv3GetBulk(start, msg, sp))
			if len(r.varbinds) != want {
				t.Errorf("max-repetitions=%d produced %d bindings; the value used to be a "+
					"hardcoded 10 regardless", want, len(r.varbinds))
			}
		})
	}
}

// TestV3GetBulkZeroRepetitionsIsEmptyNotEndOfMib pins RFC 3416 §4.2.3 with
// N = 0 and M = 0: a response with no bindings and noError. The collection
// loop gathers nothing for max-repetitions = 0, and the builder's empty branch
// means "end of MIB", so without a distinct answer a manager asking for zero
// repetitions was told the MIB had ended. Unreachable while 10 was hardcoded.
func TestV3GetBulkZeroRepetitionsIsEmptyNotEndOfMib(t *testing.T) {
	s := v3TestServer(wideBulkFixture(20))
	const start = ".1.3.6.1.2.1.1.1.0"

	sp := v3BulkScopedPDU(t, s, start, 0, 0)
	msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: sp}

	resp := s.handleSNMPv3GetBulk(start, msg, sp)
	if len(resp) == 0 {
		t.Fatal("max-repetitions=0 produced no response at all")
	}
	r := decodeV3Response(t, resp)
	if r.pduTag != ASN1_GET_RESPONSE || r.errStatus != 0 {
		t.Errorf("PDU 0x%02x error-status %d, want GetResponse/noError", r.pduTag, r.errStatus)
	}
	if r.requestID != 42 {
		t.Errorf("request-id = %d, want the request's 42", r.requestID)
	}
	if len(r.varbinds) != 0 {
		t.Errorf("max-repetitions=0 produced %d bindings, want none: %+v. An endOfMibView "+
			"here tells a walker the MIB ended when nothing about the MIB was asked",
			len(r.varbinds), r.varbinds)
	}
}

// TestV3GetBulkMaxRepetitionsAbove127 is the specific case that bit the v2c
// parser: it read single-byte BER content only, so anything >= 128 silently
// became 10. Benchmark numbers taken above 127 before that fix were not
// comparable with ones after it, and repeating the bug here would reintroduce
// the same silent discontinuity on the v3 path.
func TestV3GetBulkMaxRepetitionsAbove127(t *testing.T) {
	s := v3TestServer(wideBulkFixture(400))
	const start = ".1.3.6.1.2.1.1.1.0"

	for _, n := range []int{127, 128, 200, 300} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			sp := v3BulkScopedPDU(t, s, start, 0, n)
			gotNR, gotMR := s.parseSNMPv3GetBulkParams(sp)
			if gotMR != n {
				t.Errorf("parsed max-repetitions = %d, want %d: a value >= 128 needs a "+
					"multi-octet BER read", gotMR, n)
			}
			if gotNR != 0 {
				t.Errorf("parsed non-repeaters = %d, want 0", gotNR)
			}
		})
	}
}

// TestV3GetBulkNonRepeatersMakesItAGetNext pins RFC 3416's non-repeaters split
// as it applies to a request naming ONE column: that column is a non-repeater,
// so it gets exactly one successor and there is no repeater section left. The
// rule is non-repeaters > 0, not == 1, and it wins over max-repetitions = 0.
//
// The handler is no longer single-column (nl6#535), but N = min(non-repeaters,
// column count) makes this the same assertion it always was.
func TestV3GetBulkNonRepeatersMakesItAGetNext(t *testing.T) {
	s := v3TestServer(wideBulkFixture(50))
	const start = ".1.3.6.1.2.1.1.1.0"

	for _, tc := range []struct{ nonRep, maxRep int }{
		{1, 10},
		{5, 10},
		{1, 0},
	} {
		t.Run(fmt.Sprintf("non-repeaters=%d,max-repetitions=%d", tc.nonRep, tc.maxRep), func(t *testing.T) {
			sp := v3BulkScopedPDU(t, s, start, tc.nonRep, tc.maxRep)
			msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: sp}

			r := decodeV3Response(t, s.handleSNMPv3GetBulk(start, msg, sp))
			if len(r.varbinds) != 1 {
				t.Errorf("produced %d bindings, want 1: the only column is a non-repeater, "+
					"so it gets GETNEXT semantics", len(r.varbinds))
			}
		})
	}
}

// TestV3GetBulkClampsTheWalk pins that an absurd max-repetitions does not make
// the device perform that many walk steps before the encode bound discards
// them. Without the clamp a manager asking for 100000 costs 100000 findNextOID
// calls inline on the UDP handler for the ~dozens of bindings that can fit.
//
// The clamp cannot be seen through the binding count: the encode bound trims
// the collection to the same bindings either way. It IS visible through the
// walk: corrupt the successor just past the ceiling so it does not advance,
// and the once-per-device logFirstBulkAbort line fires only if the loop got
// there. With the clamp wired in, it never does.
func TestV3GetBulkClampsTheWalk(t *testing.T) {
	s := v3TestServer(wideBulkFixture(400))
	const start = ".1.3.6.1.2.1.1.1.0"
	ceiling := maxSNMPResponseSize/minVarbindSize + 1
	if ceiling >= 400 {
		t.Fatalf("fixture too small for ceiling %d", ceiling)
	}

	// Step k of the walk from sysDescr.0 lands on ifDescr.k, so the clamped
	// loop's last call is findNextOID(ifDescr.<ceiling-1>). The next entry
	// is the first one an unclamped loop would consult.
	past := fmt.Sprintf(".1.3.6.1.2.1.2.2.1.2.%03d", ceiling)
	s.device.resources.oidNextMap.Store(past, past)

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	sp := v3BulkScopedPDU(t, s, start, 0, 100000)
	msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: sp}

	// The parser must return the real value; the CLAMP is the handler's job,
	// so a test that only checked the parser would miss it being absent.
	if _, mr := s.parseSNMPv3GetBulkParams(sp); mr != 100000 {
		t.Fatalf("parser returned %d, want the requested 100000", mr)
	}

	done := make(chan []byte, 1)
	go func() { done <- s.handleSNMPv3GetBulk(start, msg, sp) }()
	var resp []byte
	select {
	case resp = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("v3 GETBULK did not return")
	}

	r := decodeV3Response(t, resp)
	if len(r.varbinds) > ceiling {
		t.Errorf("walk produced %d bindings, above the %d ceiling", len(r.varbinds), ceiling)
	}
	if len(r.varbinds) == 0 {
		t.Error("clamped walk produced nothing")
	}
	if strings.Contains(buf.String(), "does not advance") {
		t.Errorf("the walk reached %s, one step past the %d ceiling: clampBulkWalk is not "+
			"applied in handleSNMPv3GetBulk. The binding count cannot show this, only the "+
			"work can", past, ceiling)
	}
}

// TestV3GetBulkMalformedParamsFallBack pins that an unreadable scoped PDU
// yields the historical defaults rather than an unbounded or negative value,
// at every check the parser makes.
func TestV3GetBulkMalformedParamsFallBack(t *testing.T) {
	s := v3TestServer(wideBulkFixture(20))

	cases := map[string][]byte{
		"empty":         nil,
		"garbage":       {0x00, 0x01, 0x02},
		"truncated":     {ASN1_OCTET_STRING, 0x02, 0x41},
		"not a getbulk": validScopedPDU(".1.3.6.1.2.1.1.1.0"), // a GET; only a GETBULK carries the fields
	}
	for name, sp := range brokenBulkScopedPDUs(s.v3Config.EngineID) {
		cases[name] = sp
	}
	for name, sp := range cases {
		t.Run(name, func(t *testing.T) {
			nr, mr := s.parseSNMPv3GetBulkParams(sp)
			if nr != 0 || mr != 10 {
				t.Errorf("got (%d, %d), want the (0, 10) defaults: a malformed request must "+
					"behave as it did rather than as an unbounded one", nr, mr)
			}
		})
	}

	// Positive control: the table's base input parses, so a parser that
	// returned the defaults for everything would not pass by accident.
	if nr, mr := s.parseSNMPv3GetBulkParams(v3BulkScopedPDU(t, s, ".1.3.6.1.2.1.1.1.0", 0, 5)); nr != 0 || mr != 5 {
		t.Errorf("well-formed base input parsed as (%d, %d), want (0, 5)", nr, mr)
	}
}

// TestV3GetBulkNegativeParamsRejected pins the clamp at the parse site. A
// negative reaching the handler becomes a negative loop bound on the inline
// serve path, where there is no recover().
func TestV3GetBulkNegativeParamsRejected(t *testing.T) {
	s := v3TestServer(wideBulkFixture(20))

	sp := v3BulkScopedPDU(t, s, ".1.3.6.1.2.1.1.1.0", -1, -5)
	nr, mr := s.parseSNMPv3GetBulkParams(sp)
	if nr < 0 || mr < 0 {
		t.Fatalf("negative parameters survived the parse: (%d, %d)", nr, mr)
	}

	msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: sp}
	if resp := s.handleSNMPv3GetBulk(".1.3.6.1.2.1.1.1.0", msg, sp); len(resp) == 0 {
		t.Error("negative parameters produced no response at all")
	}
}

// buildV3GetBulkRequestWith is buildV3GetBulkRequest with the two GETBULK
// integers and the COLUMN LIST exposed. Every dispatcher-level test used to
// send 10, which is also the parser's fallback, so a parser handed the wrong
// buffer at the dispatcher (the wrapped decrypt, say) returned (0, 10) and
// nothing noticed.
//
// It takes several columns because that same seam swallows the multi-column
// fix: hand parseAllOIDsFromScopedPDU the WRAPPED scoped PDU and it reports
// "no list here", the handler falls back to the single dispatcher OID, and the
// response carries the first column only — silently, with every direct-call
// test still green. That is nl6#527's failure shape on the same
// decrypt-unwrap seam (nl6#535 review R2).
func buildV3GetBulkRequestWith(t *testing.T, s *SNMPServer, oids []string, reqID, nonRepeaters, maxRepetitions int) []byte {
	t.Helper()

	var vb []byte
	for _, oid := range oids {
		vb = append(vb, encodeSequence(append(encodeOID(oid), encodeNull()...))...)
	}
	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(reqID)...)
	pduBody = append(pduBody, encodeInteger(nonRepeaters)...)
	pduBody = append(pduBody, encodeInteger(maxRepetitions)...)
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

// TestV3GetBulkParamsSurviveTheDispatcher asserts, through handleSNMPv3Request,
// that a declared max-repetitions other than the fallback 10 is what gets
// honoured, in the clear and under both privacy protocols. The authPriv rows
// are the point: the scoped PDU reaches the parser only after the decrypt is
// unwrapped (nl6#527), and a parser handed the wrapped form falls back to 10
// silently, which is the benchmark discontinuity this change exists to close.
func TestV3GetBulkParamsSurviveTheDispatcher(t *testing.T) {
	const start = ".1.3.6.1.2.1.1.1.0"
	privs := []struct {
		name  string
		proto int
	}{
		{"noPriv", SNMPV3_PRIV_NONE},
		{"des", SNMPV3_PRIV_DES},
		{"aes128", SNMPV3_PRIV_AES128},
	}
	// cols nil means "the single start column". The multi-column rows are the
	// only ones that can see a parser handed the wrapped scoped PDU: with one
	// column the fallback returns the same answer as the fix (review R2).
	multi := []string{".1.3.6.1.2.1.2.2.1.2", ".1.3.6.1.2.1.31.1.1.1.1", ".1.3.6.1.2.1.1.9.1.3"}
	params := []struct {
		nonRep, maxRep, want int
		cols                 []string
	}{
		{nonRep: 0, maxRep: 3, want: 3},
		{nonRep: 0, maxRep: 25, want: 25},
		{nonRep: 1, maxRep: 10, want: 1},
		{nonRep: 0, maxRep: 4, want: 12, cols: multi},
		{nonRep: 1, maxRep: 3, want: 7, cols: multi},
	}

	for _, priv := range privs {
		for _, p := range params {
			t.Run(fmt.Sprintf("%s/nr=%d,mr=%d,cols=%d", priv.name, p.nonRep, p.maxRep, max(len(p.cols), 1)), func(t *testing.T) {
				s := v3TestServer(wideBulkFixture(60))
				cols := p.cols
				if cols == nil {
					cols = []string{start}
				} else {
					// The multi-column rows need every column populated, which
					// wideBulkFixture does not do.
					s = v3TestServer(multiColFixture(20))
				}
				var req []byte
				if priv.proto == SNMPV3_PRIV_NONE {
					req = buildV3GetBulkRequestWith(t, s, cols, 4242, p.nonRep, p.maxRep)
				} else {
					s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
					s.v3Config.PrivProtocol = priv.proto
					plain, err := s.parseSNMPv3Message(buildV3GetBulkRequestWith(t, s, cols, 4242, p.nonRep, p.maxRep))
					if err != nil {
						t.Fatalf("parse plaintext: %v", err)
					}
					cipherText, privParams, err := s.encryptScopedPDU(encodeSequence(plain.ScopedPDU), v3PrivSeed(s))
					if err != nil {
						t.Fatalf("encryptScopedPDU: %v", err)
					}
					req = buildV3EncryptedRequest(t, s, cipherText, privParams)
				}

				resp := s.handleSNMPv3Request(req)
				if len(resp) == 0 {
					t.Fatal("dispatcher returned nothing")
				}
				r := decodeV3ResponsePossiblyEncrypted(t, s, resp, priv.proto != SNMPV3_PRIV_NONE)
				if r.requestID != 4242 {
					t.Errorf("request-id = %d, want 4242", r.requestID)
				}
				if len(r.varbinds) != p.want {
					t.Errorf("got %d bindings, want %d: the value the dispatcher handed the "+
						"parser was not the one the manager sent (10 is the fallback)", len(r.varbinds), p.want)
				}
				if len(p.cols) > 1 {
					// EVERY column must be represented. A dispatcher that hands
					// the parser the wrapped scoped PDU answers the first column
					// only, and the binding COUNT alone cannot see that.
					seen := map[string]bool{}
					for _, vb := range r.varbinds {
						for _, c := range p.cols {
							if strings.HasPrefix(vb.oid, c+".") {
								seen[c] = true
							}
						}
					}
					for _, c := range p.cols {
						if !seen[c] {
							t.Errorf("no binding from column %s: the scoped PDU the dispatcher "+
								"handed the multi-column parser was not the CONTENTS form, so "+
								"the walk fell back to the first column", c)
						}
					}
				}
			})
		}
	}
}

// TestLargestFittingPrefixBisects pins the search shape. Every other assertion
// about a GETBULK response is satisfied equally by a linear descent, which is
// what this replaced: a descent fully builds and, under privacy, fully encrypts
// every over-budget candidate, so at a real max-repetitions it costs O(n^2)
// bytes and n encryptions per request, inline on the UDP handler.
//
// Counting calls is the only way to see the difference; timing would be flaky.
func TestLargestFittingPrefixBisects(t *testing.T) {
	// A synthetic builder whose result grows 10 bytes per binding, so the
	// largest n fitting `limit` is known exactly.
	const perBinding = 10
	for _, tc := range []struct{ count, fits int }{
		{count: 1000, fits: 37},
		{count: 500, fits: 499},
		{count: 64, fits: 1},
		{count: 300, fits: 300},
	} {
		t.Run(fmt.Sprintf("count=%d,fits=%d", tc.count, tc.fits), func(t *testing.T) {
			calls := 0
			build := func(n int) ([]byte, error) {
				calls++
				return make([]byte, n*perBinding), nil
			}
			limit := tc.fits * perBinding

			resp, err := largestFittingPrefix(tc.count, limit, build)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := len(resp) / perBinding; got != tc.fits {
				t.Errorf("selected %d bindings, want %d (maximal fit)", got, tc.fits)
			}

			// The bisection budget: one build for the full set, one for the
			// floor, then a search over [1, count] that halves the interval
			// each step, so at most bits.Len(count) more. A descent needs
			// count-fits calls, which for the first case is 963.
			ceiling := 2 + bits.Len(uint(tc.count))
			if calls > ceiling {
				t.Errorf("took %d builds for count=%d; a bisection needs at most %d. A linear "+
					"descent passes every other test in this file, so this is the only "+
					"assertion that catches its return", calls, tc.count, ceiling)
			}
			t.Logf("count=%d fits=%d -> %d builds (ceiling %d)", tc.count, tc.fits, calls, ceiling)
		})
	}
}

// Even one binding over the limit must still come back, matching the v2c
// truncate carve-out.
func TestLargestFittingPrefixAlwaysReturnsOne(t *testing.T) {
	resp, err := largestFittingPrefix(5, 1, func(n int) ([]byte, error) {
		return make([]byte, n*100), nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp) != 100 {
		t.Errorf("got %d bytes, want the single-binding 100: an empty binding list with no "+
			"error stalls a walk forever", len(resp))
	}
}

// TestClampBulkWalkBoundsTheWalk pins the walk clamp's arithmetic directly;
// TestV3GetBulkClampsTheWalk pins that the handler applies it.
func TestClampBulkWalkBoundsTheWalk(t *testing.T) {
	ceiling := maxSNMPResponseSize/minVarbindSize + 1

	for _, in := range []int{100000, 1 << 20, ceiling + 1} {
		if got := clampBulkWalk(in, 1); got != ceiling {
			t.Errorf("clampBulkWalk(%d, 1) = %d, want the %d ceiling: without it the device performs "+
				"that many findNextOID steps before the encode bound discards them", in, got, ceiling)
		}
	}
	// Values at or below the ceiling pass through untouched, or the clamp would
	// silently reduce what a reasonable manager asked for.
	for _, in := range []int{0, 1, 10, ceiling} {
		if got := clampBulkWalk(in, 1); got != in {
			t.Errorf("clampBulkWalk(%d, 1) = %d, want it unchanged", in, got)
		}
	}
}

// TestClampBulkWalkDividesByColumns pins the decision nl6#535 had to make: a
// repetition costs one walk step PER COLUMN, so the ceiling is divided by the
// column count and the guard bounds the TOTAL work — what it bounded when
// there was only ever one column.
//
// Left undivided the clamp is C times looser, which is the amplification it
// exists to stop; applied to the total it is C times tighter and silently
// truncates a reasonable request. Both mistakes pass every response-level
// assertion, because the encode bound trims to the same bindings either way.
func TestClampBulkWalkDividesByColumns(t *testing.T) {
	for _, cols := range []int{1, 2, 5, 30} {
		want := maxSNMPResponseSize/minVarbindSize/cols + 1
		if got := clampBulkWalk(1<<20, cols); got != want {
			t.Errorf("clampBulkWalk(1<<20, %d) = %d, want %d: the ceiling must divide by the "+
				"column count, since the walk is columns × repetitions", cols, got, want)
		}
		// Total work stays within the single-column ceiling, which is the
		// property the division buys.
		if total := clampBulkWalk(1<<20, cols) * cols; total > maxSNMPResponseSize/minVarbindSize+cols {
			t.Errorf("%d columns walk %d steps in total, above the single-column ceiling", cols, total)
		}
	}
	// A column count of zero cannot reach the handler (the repeater section
	// returns early), but a divisor of zero panics on the serve path where
	// there is no recover(), so it is guarded rather than assumed.
	if got := clampBulkWalk(5, 0); got != 5 {
		t.Errorf("clampBulkWalk(5, 0) = %d, want 5: a zero column count must not divide by zero", got)
	}
}
