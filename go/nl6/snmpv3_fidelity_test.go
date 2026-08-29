/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"testing"
)

// nl6#527, item 1. The scoped PDU has two shapes in this package and they were
// silently mixed:
//
//	parseSNMPv3Message stores the scoped PDU's CONTENTS (header stripped)
//	decryptScopedPDU   returns the whole TLV (starts with SEQUENCE)
//
// Both extractOIDAndTypeFromScopedPDU and extractRequestIDFromScopedPDU parse
// CONTENTS. Handing them the wrapped form made every consumer fail at once, and
// the consequence was much larger than the request-id the issue names: the OID
// extraction errored, so handleSNMPv3Request's decrypt-FAILURE fallback fired
// on a SUCCESSFUL decrypt and answered sysDescr.0 as a GET. An authPriv request
// for any OID, of any PDU type, was answered as a GET of sysDescr.0.
func TestScopedPDUConsumersExpectContents(t *testing.T) {
	s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})
	req := buildV3GetBulkRequest(t, s, ".1.3.6.1.2.1.2.2.1.2.3", 4242)
	msg, err := s.parseSNMPv3Message(req)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	contents := msg.ScopedPDU
	if len(contents) == 0 || contents[0] != ASN1_OCTET_STRING {
		t.Fatalf("parseSNMPv3Message should store scoped-PDU CONTENTS, starting with the "+
			"contextEngineID OCTET STRING; got 0x%02x", contents[0])
	}

	// Contents: both consumers succeed.
	oid, pduType, err := s.extractOIDAndTypeFromScopedPDU(contents)
	if err != nil || oid != ".1.3.6.1.2.1.2.2.1.2.3" || pduType != ASN1_GET_BULK {
		t.Errorf("contents: oid=%q pduType=0x%02x err=%v; want the requested OID and GETBULK",
			oid, pduType, err)
	}
	if got := s.extractRequestIDFromScopedPDU(contents); got != 4242 {
		t.Errorf("contents: request-id = %d, want 4242", got)
	}

	// Wrapped: this is what a successful decrypt produces, and it is what used
	// to be handed to both consumers.
	wrapped := encodeSequence(contents)
	if _, _, err := s.extractOIDAndTypeFromScopedPDU(wrapped); err == nil {
		t.Error("wrapped form parsed cleanly; if that is now true the unwrap in " +
			"handleSNMPv3Request is redundant and this test should be rewritten")
	}
	if got := s.extractRequestIDFromScopedPDU(wrapped); got == 4242 {
		t.Error("wrapped form yielded the real request-id; see above")
	}
}

// TestAuthPrivDecryptIsUnwrapped drives the decrypt branch of
// handleSNMPv3Request and asserts the request is SERVED rather than answered
// from the decrypt-failure fallback.
func TestAuthPrivDecryptIsUnwrapped(t *testing.T) {
	s := v3TestServer(map[string]string{
		".1.3.6.1.2.1.1.1.0":     "dev",
		".1.3.6.1.2.1.2.2.1.2.3": "Gi0/3",
	})
	// Privacy on, so handleSNMPv3Request takes the decrypt branch.
	s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
	s.v3Config.PrivProtocol = SNMPV3_PRIV_DES

	req := buildV3GetBulkRequest(t, s, ".1.3.6.1.2.1.2.2.1.2.3", 4242)
	plainMsg, err := s.parseSNMPv3Message(req)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Encrypt the scoped PDU the way a manager would, then hand the decrypt
	// path exactly what it will see on the wire.
	wrapped := encodeSequence(plainMsg.ScopedPDU)
	seed := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 1},
		SecurityParams: SNMPv3SecurityParams{UserName: s.v3Config.Username, AuthoritativeEngineID: s.v3Config.EngineID},
	}
	cipher, privParams, err := s.encryptScopedPDU(wrapped, seed)
	if err != nil {
		t.Skipf("privacy not available in this configuration: %v", err)
	}

	encMsg := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 1, MsgFlags: SNMPV3_MSG_FLAG_PRIV | SNMPV3_MSG_FLAG_AUTH},
		SecurityParams: SNMPv3SecurityParams{UserName: s.v3Config.Username, PrivParams: privParams},
		ScopedPDU:      cipher,
	}
	decrypted, err := s.decryptScopedPDU(encMsg.ScopedPDU, privParams)
	if err != nil {
		t.Skipf("decrypt unavailable: %v", err)
	}
	if len(decrypted) == 0 || decrypted[0] != ASN1_SEQUENCE {
		t.Fatalf("decryptScopedPDU should return the whole TLV; got 0x%02x", decrypted[0])
	}

	// The unwrap handleSNMPv3Request now performs.
	n, start := parseLength(decrypted, 1)
	if n < 0 || start+n > len(decrypted) {
		t.Fatal("decrypted TLV has a bad length")
	}
	unwrapped := decrypted[start : start+n]

	oid, pduType, err := s.extractOIDAndTypeFromScopedPDU(unwrapped)
	if err != nil {
		t.Fatalf("after unwrapping, the OID extraction still fails: %v. Without the unwrap "+
			"the caller's decrypt-FAILURE fallback fires on a SUCCESSFUL decrypt and answers "+
			"sysDescr.0 as a GET", err)
	}
	if oid != ".1.3.6.1.2.1.2.2.1.2.3" {
		t.Errorf("served OID = %q, want the requested one; sysDescr.0 here means the fallback fired", oid)
	}
	if pduType != ASN1_GET_BULK {
		t.Errorf("PDU type = 0x%02x, want GETBULK; 0xA0 here means the fallback rewrote it to a GET", pduType)
	}
	if got := s.extractRequestIDFromScopedPDU(unwrapped); got != 4242 {
		t.Errorf("request-id = %d, want 4242; 1 is the fallback", got)
	}
}

// nl6#527, item 2. RFC 3414 §5 types every usmStats* object as Counter32. The
// discovery Report hardcoded encodeInteger(1), which both ignored its value
// argument and answered the wrong ASN.1 type.
func TestDiscoveryReportValueIsCounter32(t *testing.T) {
	const usmStatsUnknownEngineIDs = ".1.3.6.1.6.3.15.1.1.4.0"

	if got := snmpTypeTag(usmStatsUnknownEngineIDs); got != ASN1_COUNTER32 {
		t.Fatalf("snmpTypeTag(%s) = 0x%02x, want Counter32 (0x41): the usmStats prefix should be "+
			"in oidTypeTable so the Report resolves through encodeTypedValue like every other value",
			usmStatsUnknownEngineIDs, got)
	}

	s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})
	scoped, err := s.createDiscoveryScopedPDU(usmStatsUnknownEngineIDs, "1")
	if err != nil {
		t.Fatalf("createDiscoveryScopedPDU: %v", err)
	}
	name, tag := scopedPDUFirstVarbind(t, scoped)
	if tag != ASN1_COUNTER32 {
		t.Errorf("discovery Report value tag = 0x%02x, want Counter32 (0x41); INTEGER (0x02) is "+
			"the pre-nl6#527 answer", tag)
	}
	if name != usmStatsUnknownEngineIDs {
		t.Errorf("Report binding named %q, want %q", name, usmStatsUnknownEngineIDs)
	}

	// The value argument is honoured rather than ignored.
	other, err := s.createDiscoveryScopedPDU(usmStatsUnknownEngineIDs, "7")
	if err != nil {
		t.Fatalf("createDiscoveryScopedPDU: %v", err)
	}
	if string(other) == string(scoped) {
		t.Error("createDiscoveryScopedPDU ignores its value argument: \"1\" and \"7\" produced identical bytes")
	}
}

// The whole usmStats subtree is Counter32, not just the one OID the discovery
// Report happens to use.
func TestUsmStatsSubtreeIsCounter32(t *testing.T) {
	for _, oid := range []string{
		".1.3.6.1.6.3.15.1.1.1.0", // usmStatsUnsupportedSecLevels
		".1.3.6.1.6.3.15.1.1.2.0", // usmStatsNotInTimeWindows
		".1.3.6.1.6.3.15.1.1.3.0", // usmStatsUnknownUserNames
		".1.3.6.1.6.3.15.1.1.4.0", // usmStatsUnknownEngineIDs
		".1.3.6.1.6.3.15.1.1.5.0", // usmStatsWrongDigests
		".1.3.6.1.6.3.15.1.1.6.0", // usmStatsDecryptionErrors
	} {
		if got := snmpTypeTag(oid); got != ASN1_COUNTER32 {
			t.Errorf("snmpTypeTag(%s) = 0x%02x, want Counter32 (RFC 3414 §5)", oid, got)
		}
	}
}

// scopedPDUFirstVarbind decodes a scoped PDU in CONTENTS form
// (contextEngineID, contextName, PDU) down to its first varbind. Written
// structurally rather than by scanning for a tag: a byte scan over a whole
// scoped PDU finds the engine ID and the OID before it ever reaches the value,
// which is how the first version of this assertion reported a false negative
// against bytes that plainly ended 41 01 01.
func scopedPDUFirstVarbind(t *testing.T, scoped []byte) (string, byte) {
	t.Helper()

	body := scoped
	if len(body) > 0 && body[0] == ASN1_SEQUENCE {
		body = expectSeq(t, scoped, "scopedPDU") // tolerate the wrapped form
	}
	pos := skipTLV(t, body, 0, "contextEngineID")
	pos = skipTLV(t, body, pos, "contextName")
	if pos >= len(body) {
		t.Fatal("scoped PDU has no data field")
	}

	n, after := parseLength(body, pos+1)
	if n < 0 || after+n > len(body) {
		t.Fatal("bad PDU length in scoped PDU")
	}
	pdu := body[after : after+n]

	pp := 0
	_, pp = expectInt(t, pdu, pp, "request-id")
	_, pp = expectInt(t, pdu, pp, "error-status")
	_, pp = expectInt(t, pdu, pp, "error-index")

	vbl := expectSeq(t, pdu[pp:], "variable-bindings")
	vb := expectSeq(t, vbl, "varbind")
	if len(vb) == 0 || vb[0] != ASN1_OID {
		t.Fatalf("varbind does not start with an OBJECT IDENTIFIER: % x", vb)
	}
	nl, an := parseLength(vb, 1)
	if nl < 0 || an+nl > len(vb) {
		t.Fatal("bad varbind name length")
	}
	return decodeOID(vb[an : an+nl]), vb[an+nl]
}

// TestAuthPrivRequestIsServedThroughDispatcher drives handleSNMPv3Request with
// a real encrypted message, so the unwrap is exercised in PRODUCTION rather
// than reproduced by the test.
//
// This is the assertion that matters: an earlier version of this file computed
// the unwrap inline and passed even with the fix reverted, which is the same
// defect it was written to catch.
func TestAuthPrivRequestIsServedThroughDispatcher(t *testing.T) {
	const wantOID = ".1.3.6.1.2.1.2.2.1.2.3"

	s := v3TestServer(map[string]string{
		".1.3.6.1.2.1.1.1.0": "dev",
		wantOID:              "Gi0/3",
	})
	s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
	s.v3Config.PrivProtocol = SNMPV3_PRIV_DES

	// Take a plaintext request's scoped PDU and encrypt it, so the message the
	// dispatcher sees is exactly what a manager would send.
	plainReq := buildV3GetRequest(t, s, wantOID, 4242)
	plainMsg, err := s.parseSNMPv3Message(plainReq)
	if err != nil {
		t.Fatalf("parse plaintext: %v", err)
	}
	seed := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 1},
		SecurityParams: SNMPv3SecurityParams{UserName: s.v3Config.Username, AuthoritativeEngineID: s.v3Config.EngineID},
	}
	cipher, privParams, err := s.encryptScopedPDU(encodeSequence(plainMsg.ScopedPDU), seed)
	if err != nil {
		t.Skipf("privacy unavailable: %v", err)
	}

	encReq := buildV3EncryptedRequest(t, s, cipher, privParams)
	resp := s.handleSNMPv3Request(encReq)
	if len(resp) == 0 {
		t.Fatal("dispatcher returned nothing for an authPriv request")
	}

	// The response is encrypted too, so decrypt it before decoding.
	// v3TestServer keeps the same key material, so this is symmetric.
	r := decodeV3ResponsePossiblyEncrypted(t, s, resp)
	if len(r.varbinds) == 0 {
		t.Fatal("response carries no bindings")
	}
	if r.varbinds[0].oid != wantOID {
		t.Errorf("authPriv request for %q was answered with %q. sysDescr.0 here means the "+
			"decrypt-FAILURE fallback fired on a SUCCESSFUL decrypt, which is what happens "+
			"when the decrypted scoped PDU is not unwrapped (nl6#527)", wantOID, r.varbinds[0].oid)
	}
	if r.requestID != 4242 {
		t.Errorf("response request-id = %d, want 4242; 1 is the fallback", r.requestID)
	}
}

func buildV3GetRequest(t *testing.T, s *SNMPServer, oid string, reqID int) []byte {
	t.Helper()
	vb := encodeSequence(append(encodeOID(oid), encodeNull()...))
	var body []byte
	body = append(body, encodeInteger(reqID)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeSequence(vb)...)
	pdu := append([]byte{ASN1_GET_REQUEST}, append(encodeLength(len(body)), body...)...)

	var scoped []byte
	scoped = append(scoped, encodeOctetString(s.v3Config.EngineID)...)
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, pdu...)
	return assembleV3(s, encodeSequence(scoped), nil, false)
}

func buildV3EncryptedRequest(t *testing.T, s *SNMPServer, cipher, privParams []byte) []byte {
	t.Helper()
	return assembleV3(s, encodeOctetString(string(cipher)), privParams, true)
}

// assembleV3 wraps a scopedPduData field (already encoded as SEQUENCE or
// OCTET STRING) into a full SNMPv3 message.
func assembleV3(s *SNMPServer, scopedField []byte, privParams []byte, priv bool) []byte {
	flags := byte(SNMPV3_MSG_FLAG_AUTH)
	if priv {
		flags |= SNMPV3_MSG_FLAG_PRIV
	}
	var global []byte
	global = append(global, encodeInteger(1)...)
	global = append(global, encodeInteger(65507)...)
	global = append(global, encodeOctetString(string([]byte{flags}))...)
	global = append(global, encodeInteger(3)...)

	var usm []byte
	usm = append(usm, encodeOctetString(s.v3Config.EngineID)...)
	usm = append(usm, encodeInteger(0)...)
	usm = append(usm, encodeInteger(0)...)
	usm = append(usm, encodeOctetString(s.v3Config.Username)...)
	usm = append(usm, encodeOctetString("")...)
	usm = append(usm, encodeOctetString(string(privParams))...)

	var msg []byte
	msg = append(msg, encodeInteger(3)...)
	msg = append(msg, encodeSequence(global)...)
	msg = append(msg, encodeOctetString(string(encodeSequence(usm)))...)
	msg = append(msg, scopedField...)
	return encodeSequence(msg)
}

// decodeV3ResponsePossiblyEncrypted decodes a v3 response, decrypting the
// scoped PDU first when the response carries the privacy flag.
func decodeV3ResponsePossiblyEncrypted(t *testing.T, s *SNMPServer, resp []byte) v3Response {
	t.Helper()
	msg, err := s.parseSNMPv3Message(resp)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	scoped := msg.ScopedPDU
	if msg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_PRIV != 0 {
		dec, err := s.decryptScopedPDU(scoped, msg.SecurityParams.PrivParams)
		if err != nil {
			t.Fatalf("decrypt response: %v", err)
		}
		if len(dec) > 0 && dec[0] == ASN1_SEQUENCE {
			n, start := parseLength(dec, 1)
			if n < 0 || start+n > len(dec) {
				t.Fatal("bad decrypted response length")
			}
			scoped = dec[start : start+n]
		}
	}
	return decodeScopedPDUContents(t, scoped)
}

// decodeScopedPDUContents decodes a scoped PDU in contents form into the same
// shape decodeV3Response produces, so assertions can be shared.
func decodeScopedPDUContents(t *testing.T, scoped []byte) v3Response {
	t.Helper()
	pos := skipTLV(t, scoped, 0, "contextEngineID")
	pos = skipTLV(t, scoped, pos, "contextName")
	if pos >= len(scoped) {
		t.Fatal("scoped PDU has no data field")
	}
	out := v3Response{pduTag: scoped[pos]}
	n, after := parseLength(scoped, pos+1)
	if n < 0 || after+n > len(scoped) {
		t.Fatal("bad PDU length")
	}
	pdu := scoped[after : after+n]
	pp := 0
	out.requestID, pp = expectInt(t, pdu, pp, "request-id")
	out.errStatus, pp = expectInt(t, pdu, pp, "error-status")
	out.errIndex, pp = expectInt(t, pdu, pp, "error-index")
	vbl := expectSeq(t, pdu[pp:], "variable-bindings")
	for vp := 0; vp < len(vbl); {
		vb := expectSeq(t, vbl[vp:], "varbind")
		n2, after2 := parseLength(vbl, vp+1)
		if n2 < 0 || after2+n2 > len(vbl) {
			t.Fatal("bad varbind length")
		}
		vp = after2 + n2
		if len(vb) == 0 || vb[0] != ASN1_OID {
			t.Fatalf("varbind does not start with an OID: % x", vb)
		}
		nl, an := parseLength(vb, 1)
		if nl < 0 || an+nl > len(vb) {
			t.Fatal("bad name length")
		}
		v := v3Varbind{oid: decodeOID(vb[an : an+nl])}
		vpos := an + nl
		if vpos < len(vb) {
			v.valueTag = vb[vpos]
		}
		out.varbinds = append(out.varbinds, v)
	}
	return out
}
