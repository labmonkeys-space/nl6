/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
)

// SET write admission (nl6#690).
//
// nl6#684 admitted a SetRequest on exactly a GetRequest's terms. That was right
// while every served PDU was a read; it is not right for a PDU that mutates
// state, fires link traps and syslog and is visible to gNMI. These tests assert
// the two gates that close it and, just as importantly, that the READ paths did
// not move with them.
//
// Every test drives a DISPATCHER (handleSNMPv2cRequest / handleSNMPv3Request),
// never admitSetV2c or admitSetV3 directly. A gate that returns the right
// verdict to a unit test and is not wired into the dispatcher is the defect,
// not the fix — this package has shipped exactly that shape before, and a
// hand-written mirror of the gated body pinned nothing (nl6#565).
//
// None of these use allowSetsForTest: the whole point is what a server's own
// configuration admits.

// setRequestWithCommunity is setRequestAt with the community as a parameter.
// setRequestAt hardcodes "public", which cannot express a mismatch.
func setRequestWithCommunity(version int, community string, binds []testBind) []byte {
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
	msg = append(msg, encodeOctetString(community)...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// setRequestWithNoCommunityField builds a v2c SetRequest that REACHES THE SET
// BRANCH while leaving req.Community at its "public" default with
// CommunityParsed false. That combination is the whole hazard: a fleet
// configured `-snmp-write-community public` would, under a naive
// `req.Community == want` test, admit a datagram that carried no community
// nl6 could read.
//
// The shape is an OCTET STRING whose DECLARED length overruns the datagram,
// with the PDU sitting immediately after the length octet. Both envelope
// readers — parseIncomingRequest's community read and getPDUType's skip —
// refuse to advance past a length they cannot honour and therefore land on the
// same byte, which is the SET tag. So the dispatcher routes it to SET while the
// parser has no community to report.
//
// A simpler fixture (a BOOLEAN where the community belongs) does NOT work and
// the difference is worth keeping: getPDUType then fails to find the PDU at all
// and the datagram falls into the dispatcher's GET branch, so it never reaches
// the gate and proves nothing about it.
func setRequestWithNoCommunityField(binds []testBind) []byte {
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
	msg = append(msg, encodeInteger(snmpVersion2c)...)
	// 0x04 0x7F: an OCTET STRING claiming 127 octets, with fewer than that
	// left in the datagram.
	msg = append(msg, ASN1_OCTET_STRING, 0x7F)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// snmpRequestAtCommunity is snmpRequestAt with the community as a parameter,
// so a READ can be sent with a community that is not "public".
func snmpRequestAtCommunity(pduTag byte, version int, community string, oids []string) []byte {
	var varbinds []byte
	for _, oid := range oids {
		varbinds = append(varbinds, encodeVarBind(oid, encodeNull())...)
	}
	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(42)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeSequence(varbinds)...)
	pdu := []byte{pduTag}
	pdu = append(pdu, encodeLength(len(pduBody))...)
	pdu = append(pdu, pduBody...)
	var msg []byte
	msg = append(msg, encodeInteger(version)...)
	msg = append(msg, encodeOctetString(community)...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// ── v1/v2c: the write community ────────────────────────────────────────────

func TestSetCommunityAdmission(t *testing.T) {
	rows := []struct {
		name      string
		configure string // the device's write community
		send      string // the community on the wire
		admitted  bool
	}{
		{"right community is admitted", "secret", "secret", true},
		{"wrong community is discarded", "secret", "public", false},
		{"read community is not a write community", "secret", "", false},
		{"no write community configured refuses every SET", "", "public", false},
		{"no write community configured refuses an empty community too", "", "", false},
		{"a configured community that matches the read default still works", "public", "public", true},
	}
	for _, version := range []int{snmpVersion1, snmpVersion2c} {
		for _, r := range rows {
			t.Run(versionLabel(version)+"/"+r.name, func(t *testing.T) {
				s, state := newSetTestServer(t, 3)
				s.setAdmission = setAdmissionConfig{
					WriteCommunity:   r.configure,
					MinSecurityLevel: securityLevelNoAuthNoPriv,
				}
				before := state.Snapshot(2).Admin

				req := setRequestWithCommunity(version, r.send, []testBind{intBind(oidIfAdminStatus+".2", 2)})
				resp := s.handleSNMPv2cRequest(req)

				if r.admitted {
					if len(resp) == 0 {
						t.Fatal("an admitted SET was discarded")
					}
					if h := decodeResponseHeader(t, resp); h.errStatus != snmpErrNoError {
						t.Fatalf("error-status = %d, want noError", h.errStatus)
					}
					if got := state.Snapshot(2).Admin; got != 2 {
						t.Errorf("ifAdminStatus.2 = %d after an admitted SET, want 2", got)
					}
					return
				}

				// Silence, not an error response: this is what real hardware
				// does for a community it does not accept, and what snmpset
				// reports as a timeout.
				if len(resp) != 0 {
					t.Errorf("a refused SET was ANSWERED with % x; the refusal must be silent", resp)
				}
				if got := state.Snapshot(2).Admin; got != before {
					t.Errorf("ifAdminStatus.2 moved %d -> %d on a refused SET", before, got)
				}
			})
		}
	}
}

// CommunityParsed is DEFENCE IN DEPTH, and this test says so rather than
// claiming a fix it cannot demonstrate.
//
// The hazard is real in principle: parseIncomingRequest leaves Community at
// "public" when the field is unreadable, because that default only ever fed an
// echo, so a naive `req.Community == want` would admit a datagram carrying no
// community on any fleet configured `-snmp-write-community public`.
//
// It is NOT reachable through the dispatcher today, and that was established by
// deleting the gate and watching this test keep passing. The reason is that all
// three envelope readers — parseIncomingRequest's community read, getPDUType's
// skip and requestVarBindListPos's walk — share the same refusal to advance
// past a length they cannot honour, so a datagram whose community is unreadable
// also fails the varbind walk and is discarded as malformed before admission is
// consulted.
//
// That agreement is a property of three functions, not a guarantee: nl6#559 and
// nl6#562 both moved one of these walks. The flag costs a bool and holds if one
// of them ever diverges again, so it stays — and the assertion below is on
// admitSetV2c DIRECTLY, the one place in this file that bypasses the
// dispatcher, because the dispatcher cannot currently express the input.
func TestAdmitSetRefusesAnUnparsedCommunityEvenWhenItsDefaultWouldMatch(t *testing.T) {
	s, _ := newSetTestServer(t, 2)
	s.setAdmission = setAdmissionConfig{WriteCommunity: "public"} // the parser's own default

	if s.admitSetV2c(SNMPRequest{Community: "public", CommunityParsed: false}) {
		t.Error("admitSetV2c accepted a community the parser never read, because its DEFAULT matched; " +
			"the comparison must require CommunityParsed")
	}
	if !s.admitSetV2c(SNMPRequest{Community: "public", CommunityParsed: true}) {
		t.Error("admitSetV2c refused the community it is configured with")
	}
}

// The malformed-community datagram is refused whichever layer refuses it, and
// nothing is applied. Kept as a regression on the OUTCOME (see the note above
// on why it does not, on its own, pin the gate).
func TestSetWithNoCommunityFieldIsRefusedEvenWhenTheDefaultWouldMatch(t *testing.T) {
	s, state := newSetTestServer(t, 3)
	s.setAdmission = setAdmissionConfig{
		WriteCommunity:   "public", // deliberately the parser's default
		MinSecurityLevel: securityLevelNoAuthNoPriv,
	}

	// The fixture is honest only if BOTH halves hold: the parser falls back to
	// the default, AND the dispatcher still routes the datagram to SET. Without
	// the second check the test passes on a datagram that never reached the
	// gate, which is the shape of a test that pins nothing.
	req := setRequestWithNoCommunityField([]testBind{intBind(oidIfAdminStatus+".2", 2)})
	parsed := s.parseIncomingRequest(req)
	if parsed.Community != "public" || parsed.CommunityParsed {
		t.Fatalf("fixture does not reproduce the default: Community=%q parsed=%v, want \"public\"/false",
			parsed.Community, parsed.CommunityParsed)
	}
	if got := s.getPDUType(req); got != ASN1_SET_REQUEST {
		t.Fatalf("fixture is routed to PDU 0x%02X, not SET (0xA3): it never reaches the gate", got)
	}

	before := state.Snapshot(2).Admin
	if resp := s.handleSNMPv2cRequest(req); len(resp) != 0 {
		t.Errorf("a SET with no community field was answered: % x", resp)
	}
	if got := state.Snapshot(2).Admin; got != before {
		t.Errorf("ifAdminStatus.2 moved %d -> %d on a SET that carried no community", before, got)
	}
}

// The one site that assigns Community from the wire is the one site that sets
// the flag. A second assignment elsewhere would make an unread community
// comparable, which is the whole hazard above.
func TestCommunityParsedTracksTheWireNotTheDefault(t *testing.T) {
	binds := []testBind{intBind(oidIfAdminStatus+".1", 2)}
	s, _ := newSetTestServer(t, 2)

	for _, c := range []string{"public", "secret", ""} {
		got := s.parseIncomingRequest(setRequestWithCommunity(snmpVersion2c, c, binds))
		if !got.CommunityParsed || got.Community != c {
			t.Errorf("community %q on the wire read back as %q (parsed=%v)", c, got.Community, got.CommunityParsed)
		}
	}
	if got := s.parseIncomingRequest(setRequestWithNoCommunityField(binds)); got.CommunityParsed {
		t.Error("a datagram with no community field reported CommunityParsed = true")
	}
}

// ── v1/v2c: the reads are untouched ────────────────────────────────────────

// The asymmetry is deliberate and this is the test that says so: a device that
// requires a community to WRITE still requires none to READ, at every version
// and every read PDU, and still echoes whatever it was sent.
func TestReadsAreAdmittedWhateverTheCommunityOnAWriteRestrictedDevice(t *testing.T) {
	s, _ := newSetTestServer(t, 3)
	s.setAdmission = setAdmissionConfig{WriteCommunity: "secret"}

	for _, tag := range []byte{ASN1_GET_REQUEST, ASN1_GET_NEXT, ASN1_GET_BULK} {
		for _, community := range []string{"public", "anything", "secret", ""} {
			req := snmpRequestAtCommunity(tag, snmpVersion2c, community, []string{oidSysDescr0})
			resp := s.handleSNMPv2cRequest(req)
			if len(resp) == 0 {
				t.Fatalf("PDU 0x%02X with community %q was discarded; reads must not be gated", tag, community)
			}
			if got := s.parseIncomingRequest(resp).Community; got != community {
				t.Errorf("PDU 0x%02X echoed community %q, want %q", tag, got, community)
			}
		}
	}
}

// ── v3: the minimum security level ─────────────────────────────────────────

func TestSetV3SecurityLevelAdmission(t *testing.T) {
	rows := []struct {
		name string
		// how the DEVICE is configured, which decides the level its manager
		// can reach: assembleV3 sets the AUTH flag only when the server
		// authenticates, exactly as a real manager would.
		auth     int
		priv     int
		min      snmpSecurityLevel
		admitted bool
	}{
		{"noAuthNoPriv request below an authNoPriv minimum", SNMPV3_AUTH_NONE, SNMPV3_PRIV_NONE, securityLevelAuthNoPriv, false},
		{"noAuthNoPriv request below an authPriv minimum", SNMPV3_AUTH_NONE, SNMPV3_PRIV_NONE, securityLevelAuthPriv, false},
		{"noAuthNoPriv request at a noAuthNoPriv minimum", SNMPV3_AUTH_NONE, SNMPV3_PRIV_NONE, securityLevelNoAuthNoPriv, true},
		{"authNoPriv request at an authNoPriv minimum", SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE, securityLevelAuthNoPriv, true},
		{"authNoPriv request above a noAuthNoPriv minimum", SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE, securityLevelNoAuthNoPriv, true},
		{"authNoPriv request below an authPriv minimum", SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE, securityLevelAuthPriv, false},
		// The UNSET zero value must behave as authNoPriv, not as the
		// permissive level: every SNMPServer literal in this package has it.
		{"the zero minimum refuses a noAuthNoPriv write", SNMPV3_AUTH_NONE, SNMPV3_PRIV_NONE, securityLevelUnset, false},
		{"the zero minimum admits an authNoPriv write", SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE, securityLevelUnset, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s, state := newSetTestServer(t, 3)
			s.v3Config.AuthProtocol = r.auth
			s.v3Config.PrivProtocol = r.priv
			s.setAdmission = setAdmissionConfig{WriteCommunity: "secret", MinSecurityLevel: r.min}

			before := state.Snapshot(2).Admin
			resp := s.handleSNMPv3Request(v3SetRequest(t, s, []testBind{intBind(oidIfAdminStatus+".2", 2)}))
			if len(resp) == 0 {
				t.Fatal("v3 SET produced no datagram at all; a level refusal is a Report, not silence")
			}

			if r.admitted {
				got := decodeV3Response(t, resp)
				if got.pduTag != ASN1_GET_RESPONSE || got.errStatus != snmpErrNoError {
					t.Fatalf("tag/status = 0x%02X/%d, want a Response-PDU with noError", got.pduTag, got.errStatus)
				}
				if a := state.Snapshot(2).Admin; a != 2 {
					t.Errorf("ifAdminStatus.2 = %d after an admitted v3 SET, want 2", a)
				}
				return
			}

			assertUnsupportedSecLevelsReport(t, s, resp)
			if a := state.Snapshot(2).Admin; a != before {
				t.Errorf("ifAdminStatus.2 moved %d -> %d on a refused v3 SET", before, a)
			}
		})
	}
}

// An authPriv request clears an authNoPriv minimum. Its own test because
// building one needs the encryption path, which the table above does not use.
func TestSetV3AuthPrivClearsAnAuthNoPrivMinimum(t *testing.T) {
	s, state := newSetTestServer(t, 3)
	s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
	s.v3Config.PrivProtocol = SNMPV3_PRIV_AES128
	s.v3Config.PrivPassword = "s3cret"
	s.setAdmission = setAdmissionConfig{MinSecurityLevel: securityLevelAuthNoPriv}

	plain, err := s.parseSNMPv3Message(v3SetRequest(t, s, []testBind{intBind(oidIfAdminStatus+".2", 2)}))
	if err != nil {
		t.Fatalf("parse the plaintext request: %v", err)
	}
	cipher, privParams, err := s.encryptScopedPDU(encodeSequence(plain.ScopedPDU), v3PrivSeed(s))
	if err != nil {
		t.Fatalf("encryptScopedPDU: %v", err)
	}
	resp := s.handleSNMPv3Request(assembleV3(s, encodeOctetString(string(cipher)), privParams, true))
	if len(resp) == 0 {
		t.Fatal("authPriv SET was discarded")
	}
	if got := decodeV3ResponsePossiblyEncrypted(t, s, resp, true); got.errStatus != snmpErrNoError {
		t.Fatalf("error-status = %d, want noError", got.errStatus)
	}
	if a := state.Snapshot(2).Admin; a != 2 {
		t.Errorf("ifAdminStatus.2 = %d after an authPriv SET, want 2", a)
	}
}

// A minimum the device's own configuration cannot reach admits no v3 SET. Not
// a bug — it is the same writes-are-opt-in outcome as an empty write community
// — but an operator has to be able to see it, so describe() says so.
func TestSetV3MinimumTheDeviceCannotReachAdmitsNothingAndIsAnnounced(t *testing.T) {
	s, state := newSetTestServer(t, 3)
	s.v3Config.AuthProtocol = SNMPV3_AUTH_NONE
	s.setAdmission = setAdmissionConfig{} // the shipped default: authNoPriv

	before := state.Snapshot(2).Admin
	resp := s.handleSNMPv3Request(v3SetRequest(t, s, []testBind{intBind(oidIfAdminStatus+".2", 2)}))
	assertUnsupportedSecLevelsReport(t, s, resp)
	if a := state.Snapshot(2).Admin; a != before {
		t.Errorf("ifAdminStatus.2 moved %d -> %d", before, a)
	}

	got := s.setAdmission.describe(s.v3Config)
	if !strings.Contains(got, "UNREACHABLE") {
		t.Errorf("describe() = %q, which does not warn that no v3 SET can be admitted", got)
	}
}

// A manager that got its KEY right and only its LEVEL wrong must be able to
// verify the refusal.
//
// The unsigned Report carries the discovery shape — no user name, no digest —
// which a strict manager discards, turning a refusal the operator could act on
// into a timeout they cannot. So the level Report follows the same
// request-driven rule verification does: signed when the REQUEST authenticated,
// unsigned when it did not, because a noAuthNoPriv request demonstrates no key
// agreement to sign against.
//
// The interop rows cover only the noAuthNoPriv arm, where unsigned is correct,
// so without this test the authenticated arm is unmeasured.
func TestSetV3LevelReportIsSignedWhenTheRequestAuthenticated(t *testing.T) {
	t.Run("authenticated request gets a verifiable Report", func(t *testing.T) {
		s, state := newSetTestServer(t, 3)
		s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
		s.v3Config.Password = "authpassword"
		// authNoPriv is what this device's manager can reach; the minimum is
		// one step above it.
		s.setAdmission = setAdmissionConfig{MinSecurityLevel: securityLevelAuthPriv}

		before := state.Snapshot(2).Admin
		resp := s.handleSNMPv3Request(v3SetRequest(t, s, []testBind{intBind(oidIfAdminStatus+".2", 2)}))
		assertUnsupportedSecLevelsReport(t, s, resp)

		m, err := s.parseSNMPv3Message(resp)
		if err != nil {
			t.Fatalf("parse the Report: %v", err)
		}
		if m.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_AUTH == 0 {
			t.Error("the level Report does not set the AUTH flag, so a manager that authenticated " +
				"correctly reads its refusal as unauthenticated and discards it")
		}
		u := s.usmState()
		if !usmVerifyAuthDigest(resp, m.SecurityParams.AuthParams, u.authKey, u.newHash) {
			t.Error("the level Report does not verify, so a strict manager cannot distinguish it " +
				"from a forgery and the refusal reaches the operator as a timeout")
		}
		if m.SecurityParams.UserName != s.v3Config.Username {
			t.Errorf("the signed Report names user %q, want the request's %q",
				m.SecurityParams.UserName, s.v3Config.Username)
		}
		if a := state.Snapshot(2).Admin; a != before {
			t.Errorf("ifAdminStatus.2 moved %d -> %d on a refused v3 SET", before, a)
		}
	})

	t.Run("noAuthNoPriv request gets an unsigned Report", func(t *testing.T) {
		s, _ := newSetTestServer(t, 3)
		s.v3Config.AuthProtocol = SNMPV3_AUTH_NONE
		s.setAdmission = setAdmissionConfig{MinSecurityLevel: securityLevelAuthNoPriv}

		resp := s.handleSNMPv3Request(v3SetRequest(t, s, []testBind{intBind(oidIfAdminStatus+".2", 2)}))
		assertUnsupportedSecLevelsReport(t, s, resp)

		m, err := s.parseSNMPv3Message(resp)
		if err != nil {
			t.Fatalf("parse the Report: %v", err)
		}
		if m.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_AUTH != 0 || len(m.SecurityParams.AuthParams) != 0 {
			t.Error("a noAuthNoPriv refusal was signed; there is no key agreement to demonstrate, " +
				"and on a device configured without auth there is no key to sign with")
		}
	})
}

// Ordering: the user check and the USM verification come FIRST, so a manager
// with the wrong user or the wrong password is told which of THOSE is wrong
// rather than being told about a security level it did in fact clear.
func TestSetV3UserAndDigestVerdictsPrecedeTheLevelVerdict(t *testing.T) {
	t.Run("unknown user", func(t *testing.T) {
		s, _ := newSetTestServer(t, 2)
		s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
		s.setAdmission = setAdmissionConfig{MinSecurityLevel: securityLevelAuthPriv}

		req := v3SetRequest(t, s, []testBind{intBind(oidIfAdminStatus+".1", 2)})
		s.v3Config.Username = "somebody-else" // the device now knows a different user
		assertReportOID(t, s, s.handleSNMPv3Request(req), oidUsmStatsUnknownUserNames,
			"an unknown user must be reported as such, not as a security level")
	})

	t.Run("wrong password", func(t *testing.T) {
		s, _ := newSetTestServer(t, 2)
		// Set BEFORE the first usmState() call (v3SetRequest makes it): the
		// derived keys are cached once per server.
		s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
		s.v3Config.Password = "authpassword"
		s.setAdmission = setAdmissionConfig{MinSecurityLevel: securityLevelAuthPriv}

		req := v3SetRequest(t, s, []testBind{intBind(oidIfAdminStatus+".1", 2)})
		// Corrupt the digest on the wire rather than re-keying the device,
		// which would not take: usmState() caches.
		off, n, ok := locateAuthParams(req)
		if !ok || n == 0 {
			t.Fatal("fixture: no auth params to corrupt")
		}
		req[off] ^= 0xFF
		assertReportOID(t, s, s.handleSNMPv3Request(req), oidUsmStatsWrongDigests,
			"a wrong digest must be reported as such, not as a security level")
	})
}

// ── the level itself ───────────────────────────────────────────────────────

func TestSecurityLevelOfMsgFlags(t *testing.T) {
	rows := []struct {
		flags byte
		want  snmpSecurityLevel
	}{
		{0x00, securityLevelNoAuthNoPriv},
		{SNMPV3_MSG_FLAG_AUTH, securityLevelAuthNoPriv},
		{SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV, securityLevelAuthPriv},
		// Not a level USM defines. Reported as the LOWEST, so it can never
		// clear a minimum a well-formed message could not: an admission test
		// must fail toward the strict answer.
		{SNMPV3_MSG_FLAG_PRIV, securityLevelNoAuthNoPriv},
		// The reportable flag says nothing about security.
		{SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_REPORT, securityLevelAuthNoPriv},
	}
	for _, r := range rows {
		if got := securityLevelOf(r.flags); got != r.want {
			t.Errorf("securityLevelOf(0x%02X) = %v, want %v", r.flags, got, r.want)
		}
	}
	// Ordering is what makes "at least this level" a >= comparison.
	if !(securityLevelNoAuthNoPriv < securityLevelAuthNoPriv && securityLevelAuthNoPriv < securityLevelAuthPriv) {
		t.Fatal("the security levels are no longer ordered; every >= comparison in the gate is now wrong")
	}
}

func TestParseSetMinSecurityLevel(t *testing.T) {
	good := map[string]snmpSecurityLevel{
		"":             securityLevelUnset,
		"none":         securityLevelNoAuthNoPriv,
		"noAuthNoPriv": securityLevelNoAuthNoPriv,
		"auth":         securityLevelAuthNoPriv,
		"AUTHNOPRIV":   securityLevelAuthNoPriv,
		"priv":         securityLevelAuthPriv,
		" authPriv ":   securityLevelAuthPriv,
	}
	for in, want := range good {
		got, err := parseSetMinSecurityLevel(in)
		if err != nil || got != want {
			t.Errorf("parseSetMinSecurityLevel(%q) = %v, %v; want %v, nil", in, got, err, want)
		}
	}
	for _, bad := range []string{"loose", "authnopriv2", "1", "yes", "off"} {
		if _, err := parseSetMinSecurityLevel(bad); err == nil {
			t.Errorf("parseSetMinSecurityLevel(%q) was accepted; an unrecognised security level must be an error, "+
				"never a silent default — accepted-and-ignored is worse here than anywhere else", bad)
		}
	}
	// Unset resolves to authNoPriv, not to the permissive level.
	if got := (setAdmissionConfig{}).effectiveMinSecurityLevel(); got != securityLevelAuthNoPriv {
		t.Errorf("the zero setAdmissionConfig resolves to %v, want authNoPriv", got)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func versionLabel(v int) string {
	if v == snmpVersion1 {
		return "v1"
	}
	return "v2c"
}

// assertReportOID reuses reportOIDOf, the package's existing Report reader: it
// locates the tag AT THE PDU'S POSITION rather than scanning for the byte,
// which a hand-rolled check in this file would have got wrong the same way the
// original did.
func assertReportOID(t *testing.T, s *SNMPServer, resp []byte, wantOID, why string) {
	t.Helper()
	if len(resp) == 0 {
		t.Fatalf("no response at all: %s", why)
	}
	got := reportOIDOf(t, s, resp)
	if got != wantOID && "."+got != wantOID {
		t.Fatalf("Report OID = %q, want %s: %s", got, wantOID, why)
	}
}

func assertUnsupportedSecLevelsReport(t *testing.T, s *SNMPServer, resp []byte) {
	t.Helper()
	assertReportOID(t, s, resp, oidUsmStatsUnsupportedSecLevels,
		"a SET below the minimum security level must be answered with the RFC 3414 §3.2 step 5 Report")
}
