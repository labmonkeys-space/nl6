/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"strings"
	"testing"
)

// nl6#624. WHAT nl6'S SNMPv3 USM DOES, PINNED.
//
// THIS FILE REPLACES A SET OF ABSENCE PINS, AND THAT HISTORY IS THE POINT.
// nl6#625 found that nl6 documented MD5/SHA1 authentication in seven places and
// implemented none of it: it emitted twelve zero bytes where the digest goes,
// read `AuthProtocol` nowhere, derived the AES key from the AUTH password with
// a hardcoded SHA1 and the DES key with a hardcoded MD5, built both IVs
// non-conformantly, put the engine ID on the wire as the ASCII of its hex
// spelling while localizing keys with the decoded bytes, sent a UNIX EPOCH as
// msgAuthoritativeEngineTime, and accepted any inbound message whose username
// matched. Rather than only correct the documents, nl6#625 pinned the absence
// so the docs could not drift back — and those pins are what made this change
// land as a deliberate edit to a named list of files instead of a surprise.
//
// The absence pins named the documents to update on the day USM was
// implemented. Today is that day, so they are rewritten here as presence pins.
// The convention is kept: a failure names what to re-check.
//
// THE VECTORS THAT PROVE THIS RIGHT ARE NOT HERE. Key derivation is verified in
// snmpv3_usm_test.go against RFC 3414 Appendix A.3's published values, read
// from a checked-in extract of the RFC rather than from nl6's own output. This
// file pins the WIRING: that the derived material reaches the wire, that
// inbound messages are actually checked, and that the knobs are read.

// docsDescribingUSMAuth lists every file whose text describes what USM does.
// Named in failure messages so a behaviour change is followed by a documentation
// edit rather than by silence.
var docsDescribingUSMAuth = []string{
	"docs/reference/snmp.md",
	"docs/reference/cli-flags.md",
	"docs/reference/architecture.md",
	"docs/reference/device-types.md",
	"docs/reference/web-api.md",
	"README.md",
	"CLAUDE.md",
}

func docsToUpdate() string { return strings.Join(docsDescribingUSMAuth, ", ") }

// authTestServer builds a server with auth (and optionally privacy) configured,
// with distinct auth and privacy passwords so a derivation that reads the wrong
// one is visible.
func authTestServer(t *testing.T, auth, priv int) *SNMPServer {
	t.Helper()
	s := v3TestServer(map[string]string{".1.3.6.1.4.1.99999.1.0": "probe"})
	s.v3Config.AuthProtocol = auth
	s.v3Config.PrivProtocol = priv
	s.v3Config.Password = "authpassword"
	s.v3Config.PrivPassword = "privpassword"
	return s
}

// TestV3ResponseCarriesARealDigest pins the emitted field, which is the fact a
// peer actually sees, and it pins it by VERIFYING rather than by asserting the
// bytes are non-zero.
//
// Non-zero is satisfied by any twelve bytes, including twelve bytes of the
// wrong thing, which is exactly the failure that would look like success. So
// the test recomputes the digest the way a manager does — re-zero the field,
// HMAC the whole message — and requires a match.
func TestV3ResponseCarriesARealDigest(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth int
	}{{"md5", SNMPV3_AUTH_MD5}, {"sha1", SNMPV3_AUTH_SHA1}} {
		t.Run(tc.name, func(t *testing.T) {
			s := authTestServer(t, tc.auth, SNMPV3_PRIV_NONE)
			req := &SNMPv3Message{
				GlobalData:     SNMPv3GlobalData{MsgID: 7, MsgFlags: SNMPV3_MSG_FLAG_AUTH},
				SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
			}
			scoped, err := s.createScopedPDU(".1.3.6.1.4.1.99999.1.0", "probe", req)
			if err != nil {
				t.Fatalf("createScopedPDU: %v", err)
			}
			raw, err := s.wrapScopedPDUInV3Message(scoped, req)
			if err != nil {
				t.Fatalf("wrapScopedPDUInV3Message: %v", err)
			}
			msg, err := s.parseSNMPv3Message(raw)
			if err != nil {
				t.Fatalf("parse our own response: %v", err)
			}
			got := msg.SecurityParams.AuthParams
			if len(got) != usmAuthParamsLen {
				t.Fatalf("msgAuthenticationParameters is %d bytes, want %d.\nRe-check: %s",
					len(got), usmAuthParamsLen, docsToUpdate())
			}
			if bytes.Equal(got, usmZeroedAuthParams()) {
				t.Fatalf("msgAuthenticationParameters is twelve zero bytes, so nothing computed a "+
					"digest — the nl6#625 defect is back.\nRe-check: %s", docsToUpdate())
			}
			u := s.usmState()
			if !usmVerifyAuthDigest(raw, got, u.authKey, u.newHash) {
				t.Errorf("the emitted digest does not verify against the localized key, so a peer "+
					"rejects this response. Non-zero is not the property; VERIFYING is.\nRe-check: %s",
					docsToUpdate())
			}
		})
	}
}

// TestNoAuthNoPrivCarriesAZeroLengthField pins the other side of the same
// field. RFC 3414 §6.3.1 wants a zero-LENGTH msgAuthenticationParameters when
// the message is not authenticated; nl6 sent twelve zero bytes at every level
// before nl6#624, so even the security level it could serve was non-conformant.
func TestNoAuthNoPrivCarriesAZeroLengthField(t *testing.T) {
	s := v3TestServer(map[string]string{".1.3.6.1.4.1.99999.1.0": "probe"})
	req := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 7, MsgFlags: 0},
		SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
	}
	scoped, err := s.createScopedPDU(".1.3.6.1.4.1.99999.1.0", "probe", req)
	if err != nil {
		t.Fatalf("createScopedPDU: %v", err)
	}
	raw, err := s.wrapScopedPDUInV3Message(scoped, req)
	if err != nil {
		t.Fatalf("wrapScopedPDUInV3Message: %v", err)
	}
	msg, err := s.parseSNMPv3Message(raw)
	if err != nil {
		t.Fatalf("parse our own response: %v", err)
	}
	if n := len(msg.SecurityParams.AuthParams); n != 0 {
		t.Errorf("noAuthNoPriv response carries a %d-byte msgAuthenticationParameters, want zero "+
			"length (RFC 3414 §6.3.1).\nRe-check: %s", n, docsToUpdate())
	}
}

// TestAuthProtocolReachesEveryDerivation pins the sharpest of the nl6#625
// findings in reverse: -snmpv3-auth was parsed, stored, and consulted by
// nothing.
//
// It is asserted through DERIVED MATERIAL rather than through an AST scan for
// reads of the field. A scan proves the identifier appears; only the keys prove
// it changes anything. All three must move, and the privacy keys are the two
// that did not before: generateDESKey hardcoded MD5 and generateAESKey
// hardcoded SHA1, so md5+des happened to match RFC 3414 while sha1+des did not.
func TestAuthProtocolReachesEveryDerivation(t *testing.T) {
	for _, priv := range []struct {
		name  string
		proto int
	}{{"des", SNMPV3_PRIV_DES}, {"aes128", SNMPV3_PRIV_AES128}} {
		t.Run(priv.name, func(t *testing.T) {
			md5Srv := authTestServer(t, SNMPV3_AUTH_MD5, priv.proto).usmState()
			shaSrv := authTestServer(t, SNMPV3_AUTH_SHA1, priv.proto).usmState()

			if bytes.Equal(md5Srv.authKey, shaSrv.authKey) {
				t.Errorf("the AUTH key is identical under MD5 and SHA1, so AuthProtocol is ignored "+
					"again.\nRe-check: %s", docsToUpdate())
			}
			if bytes.Equal(md5Srv.privKey, shaSrv.privKey) {
				t.Errorf("the %s PRIVACY key is identical under MD5 and SHA1. RFC 3414 §2.6 localizes "+
					"the privacy key with the AUTHENTICATION protocol's digest; this is the nl6#625 "+
					"hardcoding returning.\nRe-check: %s", priv.name, docsToUpdate())
			}
		})
	}
}

// TestPrivacyKeyComesFromThePrivacyPassword pins the other half of the same
// defect: the AES path derived from the AUTH password, so an operator who set
// -snmpv3-priv-password got a key that ignored it.
//
// The documented fallback is pinned too, because it is load-bearing: with no
// privacy password the auth password is used, which is what net-snmp does and
// what most deployments rely on.
func TestPrivacyKeyComesFromThePrivacyPassword(t *testing.T) {
	for _, priv := range []struct {
		name  string
		proto int
	}{{"des", SNMPV3_PRIV_DES}, {"aes128", SNMPV3_PRIV_AES128}} {
		t.Run(priv.name, func(t *testing.T) {
			withPriv := authTestServer(t, SNMPV3_AUTH_MD5, priv.proto).usmState()

			same := authTestServer(t, SNMPV3_AUTH_MD5, priv.proto)
			same.v3Config.PrivPassword = ""
			fellBack := same.usmState()

			if bytes.Equal(withPriv.privKey, fellBack.privKey) {
				t.Errorf("the %s privacy key did not change when priv_password was removed, so it is "+
					"derived from the auth password regardless.\nRe-check: %s", priv.name, docsToUpdate())
			}
			if !bytes.Equal(fellBack.privKey, fellBack.authKey) {
				t.Errorf("with no priv_password the %s privacy key is not the auth password's key, so "+
					"the documented fallback is gone.\nRe-check: %s", priv.name, docsToUpdate())
			}
		})
	}
}

// TestEngineIDGoesOnTheWireAsOctets pins the defect that would have made every
// other fix useless.
//
// nl6 emitted msgAuthoritativeEngineID as the ASCII of its hex spelling while
// localizing keys with the decoded bytes. A manager localizes with the octets it
// RECEIVED, so it would have derived a different key from the same password and
// rejected a correctly computed digest. Correcting the digest alone would not
// have produced an interoperable agent, which is why nl6#624 had to be one
// change rather than several.
func TestEngineIDGoesOnTheWireAsOctets(t *testing.T) {
	s := authTestServer(t, SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
	s.v3Config.EngineID = "80001f8880e9630000d61ff449"

	req := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 3, MsgFlags: SNMPV3_MSG_FLAG_AUTH},
		SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
	}
	scoped, err := s.createScopedPDU(".1.3.6.1.4.1.99999.1.0", "probe", req)
	if err != nil {
		t.Fatalf("createScopedPDU: %v", err)
	}
	raw, err := s.wrapScopedPDUInV3Message(scoped, req)
	if err != nil {
		t.Fatalf("wrapScopedPDUInV3Message: %v", err)
	}
	msg, err := s.parseSNMPv3Message(raw)
	if err != nil {
		t.Fatalf("parse our own response: %v", err)
	}

	want := parseEngineIDOctets(s.v3Config.EngineID)
	if len(want) != 13 {
		t.Fatalf("test fixture: expected a 13-octet engine ID, decoded %d", len(want))
	}
	if got := []byte(msg.SecurityParams.AuthoritativeEngineID); !bytes.Equal(got, want) {
		t.Errorf("msgAuthoritativeEngineID is % x (%d octets), want % x (%d octets).\n"+
			"Emitting the hex SPELLING makes a manager localize its key with different bytes than "+
			"this engine did, so a correct digest is rejected.\nRe-check: %s",
			got, len(got), want, len(want), docsToUpdate())
	}
	// And the material actually used must be the same octets.
	if u := s.usmState(); !bytes.Equal(u.engineID, want) {
		t.Errorf("key localization used % x but the wire carries % x; they must be the same octets",
			u.engineID, want)
	}
}

// TestEngineTimeIsSecondsSinceBoot pins the field a manager runs its RFC 3414
// §3.2 window against. nl6 sent a UNIX EPOCH, which is roughly 1.7e9 seconds
// out and which any manager enforcing the 150-second window rejects outright.
func TestEngineTimeIsSecondsSinceBoot(t *testing.T) {
	s := authTestServer(t, SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
	req := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 4, MsgFlags: SNMPV3_MSG_FLAG_AUTH},
		SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
	}
	scoped, err := s.createScopedPDU(".1.3.6.1.4.1.99999.1.0", "probe", req)
	if err != nil {
		t.Fatalf("createScopedPDU: %v", err)
	}
	raw, err := s.wrapScopedPDUInV3Message(scoped, req)
	if err != nil {
		t.Fatalf("wrapScopedPDUInV3Message: %v", err)
	}
	msg, err := s.parseSNMPv3Message(raw)
	if err != nil {
		t.Fatalf("parse our own response: %v", err)
	}
	// A freshly built server has been up for approximately no time. The bound is
	// loose because a slow CI box is not a defect; an epoch is nine orders of
	// magnitude away from it either way.
	if et := msg.SecurityParams.AuthoritativeEngineTime; et < 0 || et > 3600 {
		t.Errorf("msgAuthoritativeEngineTime is %d on a server that just booted. It must be seconds "+
			"since THIS engine booted (RFC 3414 §2.2); a UNIX epoch is what nl6#625 found and it "+
			"fails every manager's §3.2 window.\nRe-check: %s", et, docsToUpdate())
	}
	if boots := msg.SecurityParams.AuthoritativeEngineBoots; boots < 1 {
		t.Errorf("msgAuthoritativeEngineBoots is %d, want at least 1 (RFC 3414 §2.2)", boots)
	}
}

// TestInboundV3RequestsAreAuthenticated pins the half the first draft of the
// nl6#625 docs missed entirely, and the one an operator can actually be bitten
// by: nl6 answered a request carrying any auth parameters at all, because
// validateSNMPv3Credentials checked the username and nothing else.
//
// The consequence was that a collector's wrong-credential handling could not be
// tested against nl6, and a "successful" authNoPriv exchange proved nothing.
//
// DRIVEN THROUGH THE DISPATCHER, not through the verifier, because the verifier
// returning false is worth nothing if nothing calls it. Each row asserts the
// usmStats OID the RFC prescribes, so a rejection for the wrong REASON — which
// tells the operator to fix the wrong thing — fails too.
func TestInboundV3RequestsAreAuthenticated(t *testing.T) {
	const probeOID = ".1.3.6.1.4.1.99999.1.0"

	// A properly signed request is the control: without it, a dispatcher that
	// refused everything would pass every row below.
	t.Run("a signed request is answered", func(t *testing.T) {
		s := authTestServer(t, SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
		resp := s.handleSNMPv3Request(buildV3RequestAt(t, s, ASN1_GET_REQUEST, probeOID, 1))
		if len(resp) == 0 {
			t.Fatal("a correctly authenticated request was discarded")
		}
		if oid := reportOIDOf(t, s, resp); oid != "" {
			t.Fatalf("a correctly authenticated request was answered with a Report naming %q", oid)
		}
	})

	t.Run("a wrong digest is refused with usmStatsWrongDigests", func(t *testing.T) {
		s := authTestServer(t, SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
		req := buildV3RequestAt(t, s, ASN1_GET_REQUEST, probeOID, 2)

		// Corrupt one octet of the digest in place. The length is unchanged, so
		// this reaches the comparison rather than a shape check.
		u := s.usmState()
		msg, err := s.parseSNMPv3Message(req)
		if err != nil {
			t.Fatalf("parse the request we built: %v", err)
		}
		idx := bytes.Index(req, append([]byte{0x04, usmAuthParamsLen}, msg.SecurityParams.AuthParams...))
		if idx < 0 {
			t.Fatal("could not locate the digest in the request we built")
		}
		tampered := append([]byte(nil), req...)
		tampered[idx+2] ^= 0xFF

		if usmVerifyAuthDigest(tampered, msg.SecurityParams.AuthParams, u.authKey, u.newHash) {
			t.Fatal("test is inert: the tampered digest still verifies")
		}
		resp := s.handleSNMPv3Request(tampered)
		if got := reportOIDOf(t, s, resp); got != strings.TrimPrefix(oidUsmStatsWrongDigests, ".") &&
			got != oidUsmStatsWrongDigests {
			t.Errorf("a request with a wrong digest was answered with %q, want a Report naming "+
				"usmStatsWrongDigests (%s).\nRe-check: %s", got, oidUsmStatsWrongDigests, docsToUpdate())
		}
	})

	t.Run("a stale engine time is refused with usmStatsNotInTimeWindows", func(t *testing.T) {
		s := authTestServer(t, SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
		// Age the engine past the window without waiting: the state is derived
		// from bootedAt, so moving that back is the whole simulation.
		u := s.usmState()
		u.bootedAt = u.bootedAt.Add(-2 * usmTimeWindowSeconds * 1e9 * 10)

		// Build with a time inside the (now old) window, then age further.
		req := buildV3RequestAt(t, s, ASN1_GET_REQUEST, probeOID, 3)
		u.bootedAt = u.bootedAt.Add(-2 * usmTimeWindowSeconds * 1e9 * 10)

		resp := s.handleSNMPv3Request(req)
		got := reportOIDOf(t, s, resp)
		if got != strings.TrimPrefix(oidUsmStatsNotInTimeWindows, ".") && got != oidUsmStatsNotInTimeWindows {
			t.Errorf("a request whose engine time is far outside the 150-second window was answered "+
				"with %q, want a Report naming usmStatsNotInTimeWindows (%s).\nRe-check: %s",
				got, oidUsmStatsNotInTimeWindows, docsToUpdate())
		}
	})

	t.Run("auth requested of a device with none is unsupportedSecLevels", func(t *testing.T) {
		// The distinction matters to an operator: their KEY is not wrong, their
		// device is not configured to authenticate at all. It is the same
		// distinction the privacy path already drew.
		s := v3TestServer(map[string]string{probeOID: "probe"})
		msg := &SNMPv3Message{
			GlobalData: SNMPv3GlobalData{MsgID: 5, MsgFlags: SNMPV3_MSG_FLAG_AUTH},
			SecurityParams: SNMPv3SecurityParams{
				UserName:   "testuser",
				AuthParams: usmZeroedAuthParams(),
			},
		}
		oid, ok := s.authenticateInbound([]byte{}, msg)
		if ok || oid != oidUsmStatsUnsupportedSecLevels {
			t.Errorf("an AUTH-flagged request to a noAuth device gave (%q, %v), want (%s, false).\n"+
				"Re-check: %s", oid, ok, oidUsmStatsUnsupportedSecLevels, docsToUpdate())
		}
	})
}

// reportOIDOf returns the OID a Report response names, or "" when the response
// is not a Report.
func reportOIDOf(t *testing.T, s *SNMPServer, resp []byte) string {
	t.Helper()
	if len(resp) == 0 {
		return ""
	}
	msg, err := s.parseSNMPv3Message(resp)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	scoped := msg.ScopedPDU
	if msg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_PRIV != 0 {
		dec, err := s.decryptScopedPDUAt(scoped, msg.SecurityParams.PrivParams,
			msg.SecurityParams.AuthoritativeEngineBoots, msg.SecurityParams.AuthoritativeEngineTime)
		if err != nil {
			t.Fatalf("decrypt response: %v", err)
		}
		scoped = dec
	}
	// A Report PDU is tag 0xA8 AT THE PDU'S POSITION. Scanning the whole scoped
	// PDU for the byte matched it inside a value, a length or a digest, so an
	// ordinary response could be reported as a Report.
	if !scopedPDUHasTag(scoped, v3ReportPDUTag) {
		return ""
	}
	oids, ok := parseAllOIDsFromScopedPDU(scoped)
	if !ok || len(oids) == 0 {
		return ""
	}
	return oids[0]
}

// TestEveryEmitterAgreesOnTheEngineIdentity pins the defect the net-snmp
// interop check found while every in-package test was green.
//
// nl6 has FOUR paths that put msgAuthoritativeEngineID on the wire: the data
// response, the discovery response, the Report response, and the scoped PDU's
// contextEngineID. nl6#624 corrected one and left three sending the hex
// SPELLING of the engine ID and a UNIX epoch. A manager discovers the engine
// from the discovery response and localizes its key with the octets it
// RECEIVED, so it derived a different key than nl6 did and rejected every
// authenticated response — an interop failure with a green suite, because
// nothing compared one emitter against another.
//
// The property is AGREEMENT, not correctness against a literal: the octets are
// checked against parseEngineIDOctets, and the point is that all four paths
// answer the same thing.
func TestEveryEmitterAgreesOnTheEngineIdentity(t *testing.T) {
	s := authTestServer(t, SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
	s.v3Config.EngineID = "0x80001234"
	want := parseEngineIDOctets(s.v3Config.EngineID)
	if len(want) != 4 {
		t.Fatalf("fixture: expected 4 octets, got %d", len(want))
	}

	req := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 9, MsgFlags: SNMPV3_MSG_FLAG_AUTH},
		SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
	}

	check := func(label string, raw []byte) {
		t.Helper()
		if len(raw) == 0 {
			t.Fatalf("%s produced no message", label)
		}
		msg, err := s.parseSNMPv3Message(raw)
		if err != nil {
			t.Fatalf("%s: parse: %v", label, err)
		}
		if got := []byte(msg.SecurityParams.AuthoritativeEngineID); !bytes.Equal(got, want) {
			t.Errorf("%s emits msgAuthoritativeEngineID % x, but the engine's identity is % x.\n"+
				"A manager that discovers the engine from one path and authenticates against another "+
				"derives a different key and rejects everything.\nRe-check: %s",
				label, got, want, docsToUpdate())
		}
		// Engine time must be seconds since boot on every path too: a manager
		// runs its RFC 3414 §3.2 window against whichever one it saw last.
		if et := msg.SecurityParams.AuthoritativeEngineTime; et < 0 || et > 3600 {
			t.Errorf("%s emits msgAuthoritativeEngineTime %d, which is not seconds since boot.\n"+
				"Re-check: %s", label, et, docsToUpdate())
		}
	}

	scoped, err := s.createScopedPDU(".1.3.6.1.4.1.99999.1.0", "probe", req)
	if err != nil {
		t.Fatalf("createScopedPDU: %v", err)
	}
	data, err := s.wrapScopedPDUInV3Message(scoped, req)
	if err != nil {
		t.Fatalf("wrapScopedPDUInV3Message: %v", err)
	}
	check("the data response", data)
	check("the discovery response", s.createSNMPv3DiscoveryResponse(req))
	check("the Report response", s.createSNMPv3ReportResponse(oidUsmStatsWrongDigests, req))

	// contextEngineID lives inside the scoped PDU rather than in the security
	// parameters, so it is checked directly. It is the same identity and a
	// manager that filters on it drops a response naming a different engine.
	if !bytes.Contains(scoped, append([]byte{0x04, byte(len(want))}, want...)) {
		t.Errorf("the scoped PDU's contextEngineID is not % x.\nRe-check: %s", want, docsToUpdate())
	}
}

// scopedPDUHasTag reports whether the PDU inside a scoped PDU carries tag.
//
// It walks to the PDU rather than scanning for the byte: contextEngineID and
// contextName come first, and either can contain any byte at all.
func scopedPDUHasTag(scoped []byte, tag byte) bool {
	buf := scoped
	// Accept both forms: the wrapped SEQUENCE and the contents the parser
	// stores for a plaintext request.
	if len(buf) > 0 && buf[0] == ASN1_SEQUENCE {
		n, start := parseLength(buf, 1)
		if n < 0 || start < 0 || start > len(buf) || n > len(buf)-start {
			return false
		}
		buf = buf[start : start+n]
	}
	pos := 0
	for i := 0; i < 2; i++ { // contextEngineID, contextName
		if pos >= len(buf) {
			return false
		}
		n, start := parseLength(buf, pos+1)
		if n < 0 || start < 0 || start > len(buf) || n > len(buf)-start {
			return false
		}
		pos = start + n
	}
	return pos < len(buf) && buf[pos] == tag
}
