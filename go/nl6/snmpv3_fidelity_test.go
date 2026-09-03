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
	if len(contents) == 0 {
		t.Fatal("parseSNMPv3Message stored an empty scoped PDU")
	}
	if contents[0] != ASN1_OCTET_STRING {
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

// TestDecryptScopedPDUReturnsWrappedTLV pins the one fact the dispatcher test
// below does not: decryptScopedPDU hands back the WHOLE TLV, SEQUENCE header
// included, for both privacy protocols. That is the premise of the unwrap in
// handleSNMPv3Request. It deliberately does NOT perform the unwrap itself: an
// earlier test did, and passed with the production fix reverted because it
// reproduced the fix instead of exercising it.
func TestDecryptScopedPDUReturnsWrappedTLV(t *testing.T) {
	for _, priv := range []struct {
		name  string
		proto int
	}{
		{"des", SNMPV3_PRIV_DES},
		{"aes128", SNMPV3_PRIV_AES128},
	} {
		t.Run(priv.name, func(t *testing.T) {
			s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})
			s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
			s.v3Config.PrivProtocol = priv.proto

			plainMsg, err := s.parseSNMPv3Message(buildV3GetBulkRequest(t, s, ".1.3.6.1.2.1.2.2.1.2.3", 4242))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			wrapped := encodeSequence(plainMsg.ScopedPDU)

			cipherText, privParams, err := s.encryptScopedPDU(wrapped, v3PrivSeed(s))
			if err != nil {
				// Deterministic config with a non-empty password: a failure
				// here is a crypto regression, not an unavailable feature.
				t.Fatalf("encryptScopedPDU: %v", err)
			}
			decrypted, err := s.decryptScopedPDU(cipherText, privParams)
			if err != nil {
				t.Fatalf("decryptScopedPDU: %v", err)
			}
			if len(decrypted) == 0 {
				t.Fatal("decryptScopedPDU returned nothing")
			}
			if decrypted[0] != ASN1_SEQUENCE {
				t.Fatalf("decryptScopedPDU should return the whole TLV; got 0x%02x", decrypted[0])
			}
			// AES-CFB returns the exact length; DES may carry padding past the
			// SEQUENCE, which the unwrap's length read is what discards.
			if len(decrypted) < len(wrapped) || string(decrypted[:len(wrapped)]) != string(wrapped) {
				t.Errorf("decrypted TLV does not start with the plaintext TLV")
			}
		})
	}
}

// nl6#527, item 2. RFC 3414 §5 types every usmStats* object as Counter32. The
// discovery Report hardcoded encodeInteger(1), which both ignored its value
// argument and answered the wrong ASN.1 type.
func TestDiscoveryReportValueIsCounter32(t *testing.T) {
	const usmStatsUnknownEngineIDs = ".1.3.6.1.6.3.15.1.1.4.0"

	s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})
	scoped, err := s.createDiscoveryScopedPDU(usmStatsUnknownEngineIDs, "1")
	if err != nil {
		t.Fatalf("createDiscoveryScopedPDU: %v", err)
	}
	r := decodeScopedPDUContents(t, expectSeq(t, scoped, "scopedPDU"))
	if len(r.varbinds) == 0 {
		t.Fatal("Report carries no binding")
	}
	if r.varbinds[0].valueTag != ASN1_COUNTER32 {
		t.Errorf("discovery Report value tag = 0x%02x, want Counter32 (0x41); INTEGER (0x02) is "+
			"the pre-nl6#527 answer", r.varbinds[0].valueTag)
	}
	if r.varbinds[0].oid != usmStatsUnknownEngineIDs {
		t.Errorf("Report binding named %q, want %q", r.varbinds[0].oid, usmStatsUnknownEngineIDs)
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

// TestDiscoveryReportThroughDispatcher pins the Report a MANAGER receives, not
// the helper's output: the caller supplies the value literal, and a value the
// Counter32 branch cannot parse would fall through to OCTET STRING with the
// helper test above still passing on its own "1".
func TestDiscoveryReportThroughDispatcher(t *testing.T) {
	const usmStatsUnknownEngineIDs = ".1.3.6.1.6.3.15.1.1.4.0"
	const reportPDU = 0xA8 // Report-PDU, RFC 3416 §3

	s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})
	resp := s.handleSNMPv3Request(v3DiscoveryRequest(t, s, false))
	if len(resp) == 0 {
		t.Fatal("dispatcher returned nothing for a discovery probe")
	}
	r := decodeV3ResponsePossiblyEncrypted(t, s, resp, false)
	if r.pduTag != reportPDU {
		t.Fatalf("discovery answered with PDU 0x%02x, want Report (0xA8)", r.pduTag)
	}
	if len(r.varbinds) == 0 {
		t.Fatal("Report carries no binding")
	}
	if r.varbinds[0].oid != usmStatsUnknownEngineIDs {
		t.Errorf("Report binding named %q, want %q", r.varbinds[0].oid, usmStatsUnknownEngineIDs)
	}
	if r.varbinds[0].valueTag != ASN1_COUNTER32 {
		t.Errorf("Report value tag on the wire = 0x%02x, want Counter32 (0x41)", r.varbinds[0].valueTag)
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
			t.Errorf("snmpTypeTag(%s) = 0x%02x, want Counter32 (RFC 3414 §5): the usmStats prefix "+
				"should be in oidTypeTable so the Report resolves through encodeTypedValue", oid, got)
		}
	}
}

// TestAuthPrivRequestIsServedThroughDispatcher drives handleSNMPv3Request with
// a real encrypted message, so the unwrap is exercised in PRODUCTION rather
// than reproduced by the test.
//
// This is the assertion that matters: an earlier version of this file computed
// the unwrap inline and passed even with the fix reverted, which is the same
// defect it was written to catch.
//
// Table-driven over both privacy protocols because decryptDES and
// decryptAES128 are separate implementations with different output shapes
// (DES strips padding, AES-CFB returns the exact length), and over the three
// request PDU types because the docs claim "any PDU type" and GETBULK takes a
// different handler from GET/GETNEXT.
func TestAuthPrivRequestIsServedThroughDispatcher(t *testing.T) {
	const wantOID = ".1.3.6.1.2.1.2.2.1.2.3"
	const wantValue = "Gi0/3"

	privs := []struct {
		name  string
		proto int
	}{
		{"des", SNMPV3_PRIV_DES},
		{"aes128", SNMPV3_PRIV_AES128},
	}
	pdus := []struct {
		name string
		tag  byte
		ask  string // the OID in the request
	}{
		{"get", ASN1_GET_REQUEST, wantOID},
		{"getnext", ASN1_GET_NEXT, ".1.3.6.1.2.1.2.2.1.2"}, // wantOID is the successor
		{"getbulk", ASN1_GET_BULK, ".1.3.6.1.2.1.2.2.1.2"}, // first repetition is wantOID
	}

	for _, priv := range privs {
		for _, pdu := range pdus {
			t.Run(priv.name+"/"+pdu.name, func(t *testing.T) {
				s := v3TestServer(map[string]string{
					".1.3.6.1.2.1.1.1.0": "dev",
					wantOID:              wantValue,
				})
				s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
				s.v3Config.PrivProtocol = priv.proto

				// Take a plaintext request's scoped PDU and encrypt it, so the
				// message the dispatcher sees is what a manager would send.
				plainMsg, err := s.parseSNMPv3Message(buildV3RequestAt(t, s, pdu.tag, pdu.ask, 4242))
				if err != nil {
					t.Fatalf("parse plaintext: %v", err)
				}
				cipherText, privParams, err := s.encryptScopedPDU(encodeSequence(plainMsg.ScopedPDU), v3PrivSeed(s))
				if err != nil {
					t.Fatalf("encryptScopedPDU: %v", err)
				}

				resp := s.handleSNMPv3Request(buildV3EncryptedRequest(t, s, cipherText, privParams))
				if len(resp) == 0 {
					t.Fatal("dispatcher returned nothing for an authPriv request")
				}

				// The response must be encrypted too; v3TestServer keeps the
				// same key material, so decrypting it here is symmetric.
				r := decodeV3ResponsePossiblyEncrypted(t, s, resp, true)
				if r.pduTag != ASN1_GET_RESPONSE {
					t.Errorf("response PDU = 0x%02x, want GetResponse (0xA2)", r.pduTag)
				}
				if r.errStatus != 0 {
					t.Errorf("response error-status = %d, want noError", r.errStatus)
				}
				if r.requestID != 4242 {
					t.Errorf("response request-id = %d, want 4242; 1 is the fallback", r.requestID)
				}
				if len(r.varbinds) == 0 {
					t.Fatal("response carries no bindings")
				}
				vb := r.varbinds[0]
				if vb.oid != wantOID {
					t.Fatalf("authPriv %s for %q was answered with %q. sysDescr.0 here means the "+
						"decrypt-FAILURE fallback fired on a SUCCESSFUL decrypt, which is what happens "+
						"when the decrypted scoped PDU is not unwrapped (nl6#527)", pdu.name, pdu.ask, vb.oid)
				}
				if vb.valueTag != ASN1_OCTET_STRING || string(vb.value) != wantValue {
					t.Errorf("binding value = tag 0x%02x %q, want OCTET STRING %q", vb.valueTag, vb.value, wantValue)
				}
			})
		}
	}
}

// v3PrivSeed is the request-side message the privacy layer derives its
// parameters from (engine ID for the salt, user for the key).
func v3PrivSeed(s *SNMPServer) *SNMPv3Message {
	return &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 1},
		SecurityParams: SNMPv3SecurityParams{UserName: s.v3Config.Username, AuthoritativeEngineID: s.v3Config.EngineID},
	}
}

// buildV3RequestAt builds a plaintext (authNoPriv-shaped) SNMPv3 request with
// the given PDU tag and a single NULL-valued binding. For a GETBULK the two
// integers after the request-id are non-repeaters (0) and max-repetitions
// (10); for GET/GETNEXT they are error-status and error-index (both 0).
func buildV3RequestAt(tb testing.TB, s *SNMPServer, pduTag byte, oid string, reqID int) []byte {
	tb.Helper()
	vb := encodeSequence(append(encodeOID(oid), encodeNull()...))
	var body []byte
	body = append(body, encodeInteger(reqID)...)
	body = append(body, encodeInteger(0)...)
	if pduTag == ASN1_GET_BULK {
		body = append(body, encodeInteger(10)...)
	} else {
		body = append(body, encodeInteger(0)...)
	}
	body = append(body, encodeSequence(vb)...)
	pdu := append([]byte{pduTag}, append(encodeLength(len(body)), body...)...)

	var scoped []byte
	scoped = append(scoped, encodeOctetString(s.v3Config.EngineID)...)
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, pdu...)
	return assembleV3(s, encodeSequence(scoped), nil, false)
}

func buildV3EncryptedRequest(tb testing.TB, s *SNMPServer, cipherText, privParams []byte) []byte {
	tb.Helper()
	return assembleV3(s, encodeOctetString(string(cipherText)), privParams, true)
}

// assembleV3 wraps a scopedPduData field (already encoded as SEQUENCE or
// OCTET STRING) into a full SNMPv3 message.
func assembleV3(s *SNMPServer, scopedField []byte, privParams []byte, priv bool) []byte {
	st := s.usmState()
	return assembleV3At(s, scopedField, privParams, priv, st.engineBoots, st.engineTimeSeconds())
}

// assembleV3At declares the boots and time the caller passes in.
//
// A caller that ENCRYPTS must use this and pass the same pair to both, because
// the AES IV is built from the declared values: sampling the clock once for the
// ciphertext and again for the envelope makes them disagree whenever the two
// calls straddle a second boundary, and the request then fails to decrypt. That
// is the same defect nl6#624 fixed in the response path, and it is just as easy
// to write in a test helper.
func assembleV3At(s *SNMPServer, scopedField []byte, privParams []byte, priv bool, boots, engineTime int) []byte {
	// The AUTH flag is set only when this server actually authenticates.
	// It used to be set unconditionally, which claimed a security level a
	// noAuthNoPriv device does not support — accepted while nothing verified
	// inbound messages, answered with a usmStatsUnsupportedSecLevels Report
	// since nl6#624, and never something a real manager would send.
	st := s.usmState()
	authenticates := st.newHash != nil && len(st.authKey) > 0
	var flags byte
	if authenticates {
		flags |= SNMPV3_MSG_FLAG_AUTH
	}
	if priv {
		flags |= SNMPV3_MSG_FLAG_PRIV
	}
	var global []byte
	global = append(global, encodeInteger(1)...)
	global = append(global, encodeInteger(65507)...)
	global = append(global, encodeOctetString(string([]byte{flags}))...)
	global = append(global, encodeInteger(3)...)

	// A REAL MANAGER'S MESSAGE, not a hand-waved one (nl6#624). Before inbound
	// verification existed, this builder could send an empty
	// msgAuthenticationParameters with the AUTH flag set and the dispatcher
	// accepted it. It no longer does, and it should not: every request these
	// tests drive through the dispatcher is now authenticated the way a manager
	// authenticates one, which makes the whole v3 test surface a round-trip
	// proof of the digest rather than a proof that nothing checked it.
	//
	// The engine boots and time come from the engine itself, which is what a
	// manager learns by discovery. Sending zeros would now fail the RFC 3414
	// §3.2 time window.
	var usm []byte
	usm = append(usm, encodeOctetString(string(st.engineID))...)
	usm = append(usm, encodeInteger(boots)...)
	usm = append(usm, encodeInteger(engineTime)...)
	usm = append(usm, encodeOctetString(s.v3Config.Username)...)
	usm = append(usm, encodeOctetString(string(usmZeroedAuthParams()))...)
	usm = append(usm, encodeOctetString(string(privParams))...)

	var msg []byte
	msg = append(msg, encodeInteger(3)...)
	msg = append(msg, encodeSequence(global)...)
	msg = append(msg, encodeOctetString(string(encodeSequence(usm)))...)
	msg = append(msg, scopedField...)
	whole := encodeSequence(msg)

	if !authenticates {
		return whole
	}
	signed, err := substituteAuthParams(whole, usmAuthDigest(whole, st.authKey, st.newHash))
	if err != nil {
		panic("assembleV3: cannot sign the request: " + err.Error())
	}
	return signed
}

// decodeV3ResponsePossiblyEncrypted decodes a v3 response, decrypting the
// scoped PDU first when the response carries the privacy flag. wantEncrypted
// asserts the flag itself, so a response that leaked plaintext for an
// authPriv request is a failure rather than something silently decoded.
func decodeV3ResponsePossiblyEncrypted(t *testing.T, s *SNMPServer, resp []byte, wantEncrypted bool) v3Response {
	t.Helper()
	msg, err := s.parseSNMPv3Message(resp)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	encrypted := msg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_PRIV != 0
	if encrypted != wantEncrypted {
		t.Fatalf("response privacy flag = %v, want %v", encrypted, wantEncrypted)
	}
	scoped := msg.ScopedPDU
	if encrypted {
		// DECRYPT WITH WHAT THE RESPONSE ADVERTISES, which is all a real manager
		// has (RFC 3826 §3.1.2.1). This used to call decryptScopedPDU, which
		// reads the server's own live clock — so both sides sampled
		// independently and agreed by accident, and an IV built from a
		// different engine time than the message advertised was invisible to
		// every authPriv test in the package. With the advertised values, each
		// of those rows becomes an assertion that the two agree.
		dec, err := s.decryptScopedPDUAt(scoped, msg.SecurityParams.PrivParams,
			msg.SecurityParams.AuthoritativeEngineBoots, msg.SecurityParams.AuthoritativeEngineTime)
		if err != nil {
			t.Fatalf("decrypt response: %v", err)
		}
		if len(dec) == 0 || dec[0] != ASN1_SEQUENCE {
			t.Fatalf("decrypted response is not a SEQUENCE TLV: % x", dec)
		}
		n, start := parseLength(dec, 1)
		if n < 0 || start+n > len(dec) {
			t.Fatal("bad decrypted response length")
		}
		scoped = dec[start : start+n]
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
		if vpos >= len(vb) {
			t.Fatal("varbind has a name but no value")
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

// ── nl6#547: a malformed scoped PDU and a decrypt failure are different ─────
//
// Both used to take the same fallback and be answered with a GET of sysDescr.0
// carrying request-id 1. RFC 3412 §7.2 discards a malformed datagram; RFC 3414
// §3.2 step 8 answers a decryption failure with a usmStatsDecryptionErrors
// Report. Opposite answers, so they had to be separated before either could be
// right.

// v3ScopedContentsWithName builds the CONTENTS of a scoped PDU (contextEngineID,
// contextName, PDU) carrying one binding whose name is the given raw TLV, so
// the seam test and the dispatcher tests cannot drift apart.
func v3ScopedContentsWithName(s *SNMPServer, pduTag byte, name []byte, reqID int) []byte {
	vb := encodeSequence(append(name, encodeNull()...))
	var body []byte
	body = append(body, encodeInteger(reqID)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeSequence(vb)...)
	pdu := append([]byte{pduTag}, append(encodeLength(len(body)), body...)...)

	var scoped []byte
	scoped = append(scoped, encodeOctetString(s.v3Config.EngineID)...)
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, pdu...)
	return scoped
}

// malformedOIDName is an unterminated varint: structurally a valid TLV, but
// not a valid OBJECT IDENTIFIER.
var malformedOIDName = []byte{ASN1_OID, 0x02, 0x2b, 0xff}

// v3RequestWithMalformedOID builds a plaintext v3 GETNEXT whose varbind name
// is malformedOIDName.
func v3RequestWithMalformedOID(t *testing.T, s *SNMPServer) []byte {
	t.Helper()
	return assembleV3(s, encodeSequence(v3ScopedContentsWithName(s, ASN1_GET_NEXT, malformedOIDName, 42)), nil, false)
}

// v3PrivRequestFromScoped encrypts scoped contents under the server's own
// key material and wraps them as an authPriv request.
func v3PrivRequestFromScoped(t *testing.T, s *SNMPServer, scoped []byte) []byte {
	t.Helper()
	// ONE sample for the ciphertext and the envelope; see assembleV3At.
	st := s.usmState()
	boots, engineTime := st.engineBoots, st.engineTimeSeconds()
	cipherText, privParams, err := s.encryptScopedPDUAt(encodeSequence(scoped), boots, engineTime)
	if err != nil {
		t.Fatalf("encryptScopedPDUAt: %v", err)
	}
	return assembleV3At(s, encodeOctetString(string(cipherText)), privParams, true, boots, engineTime)
}

// TestV3MalformedOIDIsDiscarded drives a malformed name through the
// dispatcher in the clear and under both privacy protocols. The privacy rows
// are the case where the two branches are adjacent: the PDU DECRYPTS, so the
// decrypt arm must not claim it, and then fails to parse, so the discard must.
func TestV3MalformedOIDIsDiscarded(t *testing.T) {
	privs := []struct {
		name  string
		proto int
	}{
		{"noPriv", SNMPV3_PRIV_NONE},
		{"des", SNMPV3_PRIV_DES},
		{"aes128", SNMPV3_PRIV_AES128},
	}
	for _, priv := range privs {
		t.Run(priv.name, func(t *testing.T) {
			s := v3TestServer(map[string]string{
				".1.3.6.1.2.1.1.1.0":     "dev",
				".1.3.6.1.2.1.2.2.1.2.1": "Gi0/1",
			})
			var req []byte
			if priv.proto == SNMPV3_PRIV_NONE {
				req = v3RequestWithMalformedOID(t, s)
			} else {
				s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
				s.v3Config.PrivProtocol = priv.proto
				req = v3PrivRequestFromScoped(t, s, v3ScopedContentsWithName(s, ASN1_GET_NEXT, malformedOIDName, 42))
			}

			resp := s.handleSNMPv3Request(req)
			if len(resp) != 0 {
				r := decodeV3ResponsePossiblyEncrypted(t, s, resp, false)
				name := ""
				if len(r.varbinds) > 0 {
					name = r.varbinds[0].oid
				}
				t.Errorf("a malformed v3 varbind name was answered with %d bytes (PDU 0x%02x) naming %q. It "+
					"used to be answered as a GET of sysDescr.0, which reads as a walk RESTART because "+
					"that OID sorts before almost any request; RFC 3412 §7.2 discards instead. A Report "+
					"here means the decrypt arm claimed a PDU that decrypted fine", len(resp), r.pduTag, name)
			}

			// Positive control on the SAME PDU type: a well-formed GETNEXT is
			// still answered, so an unconditional discard cannot pass.
			var good []byte
			goodScoped := v3ScopedContentsWithName(s, ASN1_GET_NEXT, encodeOID(".1.3.6.1.2.1.1.1.0"), 43)
			if priv.proto == SNMPV3_PRIV_NONE {
				good = assembleV3(s, encodeSequence(goodScoped), nil, false)
			} else {
				good = v3PrivRequestFromScoped(t, s, goodScoped)
			}
			gr := decodeV3ResponsePossiblyEncrypted(t, s, s.handleSNMPv3Request(good), priv.proto != SNMPV3_PRIV_NONE)
			if len(gr.varbinds) != 1 || gr.varbinds[0].oid != ".1.3.6.1.2.1.2.2.1.2.1" {
				t.Errorf("a well-formed v3 GETNEXT was not answered with its successor: %+v", gr.varbinds)
			}
		})
	}
}

// TestV3ExtractReportsMalformedOIDAsError pins the seam. The extractor used to
// return ("", pduType, nil) — a NIL error — so the caller treated a malformed
// name as a successful parse and findNextOID("") returned the first OID in the
// MIB.
func TestV3ExtractReportsMalformedOIDAsError(t *testing.T) {
	s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})

	oid, _, err := s.extractOIDAndTypeFromScopedPDU(v3ScopedContentsWithName(s, ASN1_GET_NEXT, malformedOIDName, 42))
	if err == nil {
		t.Errorf("a malformed varbind name parsed cleanly, returning oid=%q with a nil error: "+
			"the caller cannot then tell it from a successful parse", oid)
	}

	// And a well-formed one still parses.
	good, _, err := s.extractOIDAndTypeFromScopedPDU(v3ScopedContentsWithName(s, ASN1_GET_NEXT, encodeOID(".1.3.6.1.2.1.1.1.0"), 42))
	if err != nil || good != ".1.3.6.1.2.1.1.1.0" {
		t.Errorf("a well-formed name did not parse: oid=%q err=%v", good, err)
	}
}

// TestV3MalformedIsLoggedOncePerDevice pins the sync.Once gate on the v3
// discard, the same way TestMalformedListIsLoggedOncePerDevice does for the
// v2c list: the condition is attacker-controlled, so ungated it is a log
// flood, while no line at all makes the discard look like a network drop.
func TestV3MalformedIsLoggedOncePerDevice(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	const marker = "scoped PDU does not parse"
	s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})
	for i := 0; i < 3; i++ {
		s.handleSNMPv3Request(v3RequestWithMalformedOID(t, s))
	}
	if got := strings.Count(buf.String(), marker); got != 1 {
		t.Errorf("expected exactly one discard log line for the device, got %d:\n%s", got, buf.String())
	}

	s2 := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})
	s2.handleSNMPv3Request(v3RequestWithMalformedOID(t, s2))
	if got := strings.Count(buf.String(), marker); got != 2 {
		t.Errorf("expected the second device to log its own first discard, total %d", got)
	}
}

// assertUsmReport decodes a plaintext Report and checks the counter it names.
func assertUsmReport(t *testing.T, s *SNMPServer, resp []byte, wantOID string) {
	t.Helper()
	if len(resp) == 0 {
		t.Fatal("no datagram; RFC 3414 answers a Report, and silence is indistinguishable from an " +
			"unreachable device")
	}
	r := decodeV3ResponsePossiblyEncrypted(t, s, resp, false)
	if r.pduTag != 0xA8 {
		t.Errorf("PDU tag = 0x%02x, want 0xA8 (Report)", r.pduTag)
	}
	if len(r.varbinds) == 0 {
		t.Fatal("Report carries no bindings")
	}
	if r.varbinds[0].oid != wantOID {
		t.Errorf("Report names %q, want %s", r.varbinds[0].oid, wantOID)
	}
	if r.varbinds[0].valueTag != ASN1_COUNTER32 {
		t.Errorf("Report value tag = 0x%02x, want Counter32 (RFC 3414 §5)", r.varbinds[0].valueTag)
	}
}

// TestV3DecryptFailureAnswersReport pins the other half. A wrong privacy key
// must still be ANSWERED, with the RFC 3414 Report rather than a value for an
// object the manager never asked about — and never with silence, which would
// be indistinguishable from an unreachable device.
//
// Both decrypt arms are driven, under both protocols. "noise" is well-formed
// input that decrypts without error to bytes that are not a SEQUENCE; the
// other rows make decryptScopedPDU itself return an error, which is the arm a
// single 32-byte/8-byte garbage case never reaches.
func TestV3DecryptFailureAnswersReport(t *testing.T) {
	noise := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*7 + 3)
		}
		return b
	}
	cases := []struct {
		name       string
		proto      int
		cipherText []byte
		privParams []byte
	}{
		{"des/noise", SNMPV3_PRIV_DES, noise(32), make([]byte, 8)},
		{"des/odd-length ciphertext", SNMPV3_PRIV_DES, noise(31), make([]byte, 8)},
		{"des/short privParams", SNMPV3_PRIV_DES, noise(32), make([]byte, 4)},
		{"aes128/noise", SNMPV3_PRIV_AES128, noise(32), make([]byte, 8)},
		{"aes128/short privParams", SNMPV3_PRIV_AES128, noise(32), make([]byte, 4)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})
			s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
			s.v3Config.PrivProtocol = tc.proto

			// Confirm the row exercises the arm it claims to.
			_, err := s.decryptScopedPDU(tc.cipherText, tc.privParams)
			if strings.Contains(tc.name, "noise") && err != nil {
				t.Fatalf("noise row hit the hard-error arm (%v); it is meant to decrypt cleanly", err)
			}
			if !strings.Contains(tc.name, "noise") && err == nil {
				t.Fatalf("hard-error row decrypted without error; it is meant to make decryptScopedPDU fail")
			}

			resp := s.handleSNMPv3Request(buildV3EncryptedRequest(t, s, tc.cipherText, tc.privParams))
			assertUsmReport(t, s, resp, oidUsmStatsDecryptionErrors)
		})
	}
}

// TestV3PrivFlagOnNoPrivDeviceReportsUnsupportedSecLevel pins RFC 3414 §3.2
// step 5. A PRIV-flagged message to a device configured without privacy is a
// security level the device does not support, not a wrong key; without the
// check decryptScopedPDU hands the ciphertext back and the SEQUENCE test
// reports usmStatsDecryptionErrors, telling the manager its key is wrong when
// its configuration is.
func TestV3PrivFlagOnNoPrivDeviceReportsUnsupportedSecLevel(t *testing.T) {
	s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})
	if s.v3Config.PrivProtocol != SNMPV3_PRIV_NONE {
		t.Fatalf("fixture has privacy %d; this test needs a no-priv device", s.v3Config.PrivProtocol)
	}
	garbage := make([]byte, 32)
	resp := s.handleSNMPv3Request(buildV3EncryptedRequest(t, s, garbage, make([]byte, 8)))
	assertUsmReport(t, s, resp, oidUsmStatsUnsupportedSecLevels)
}

// Discovery must still name usmStatsUnknownEngineIDs, since it now shares the
// Report builder with the error cases.
func TestV3DiscoveryStillNamesUnknownEngineIDs(t *testing.T) {
	s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})

	resp := s.createSNMPv3DiscoveryResponse(&SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}})
	assertUsmReport(t, s, resp, oidUsmStatsUnknownEngineIDs)
}
