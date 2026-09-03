/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G503 -- RFC 3414 mandates DES-CBC for usmDESPrivProtocol
	"strings"
	"testing"
	"time"
)

// snmpv3_usm_wire_test.go — the checks that reconstruct nl6's output
// INDEPENDENTLY, without calling the code that produced it (nl6#624).
//
// WHY THESE ARE SEPARATE FROM THE REST. Every round-trip test in the package
// encrypts with nl6's encryptX and decrypts with nl6's decryptX, so an IV that
// is wrong but SYMMETRIC passes all of them — which is precisely the
// self-agreement failure mode that let the original defects ship. Until these
// existed, the only check on either IV construction was the opt-in net-snmp
// test, so an ordinary CI run pinned nothing about the substance of the fix.
//
// Each test below builds the IV from the RFC's own recipe using the values the
// message ADVERTISES, and decrypts with Go's standard library. Nothing here
// calls decryptDES, decryptAES128At or decryptScopedPDU.

// v3AuthPrivResponse builds a real authPriv response and returns it with the
// server that made it.
func v3AuthPrivResponse(t *testing.T, auth, priv int) (*SNMPServer, []byte) {
	t.Helper()
	s := authTestServer(t, auth, priv)
	req := &SNMPv3Message{
		GlobalData: SNMPv3GlobalData{
			MsgID:    21,
			MsgFlags: SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV,
		},
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
	return s, raw
}

// TestAESIVIsBuiltFromTheAdvertisedEngineTime is the pin for RFC 3826
// §3.1.2.1, and for the defect that survived the first cut of nl6#624.
//
// The IV's first eight octets are the engine boots and time — and the ONLY
// values a peer has for them are the ones the message itself carries. nl6 read
// the clock once for the IV and again for msgAuthoritativeEngineTime, so a
// response that straddled a second boundary shipped an IV built from T while
// advertising T+1, and a conforming peer decrypted garbage intermittently.
//
// A round-trip through nl6's own decryptor cannot see this: it reads the same
// clock a third time and, most of the time, agrees. So this test decrypts with
// the standard library using ONLY what is on the wire.
func TestAESIVIsBuiltFromTheAdvertisedEngineTime(t *testing.T) {
	for _, auth := range usmAuthProtocolsUnderTest {
		t.Run(auth.name, func(t *testing.T) { checkAESIV(t, auth.proto) })
	}
}

// usmAuthProtocolsUnderTest exists so every privacy check runs under BOTH
// hashes. The localized privacy key is 16 octets under MD5 and 20 under SHA1,
// and both consumers slice it at fixed indices (privKey[:8]/[8:16] for DES,
// privKey[:16] for AES) — so a slice written as "the last 8 octets" is
// identical for MD5 and wrong for SHA1. Before this, every encrypt/decrypt
// round trip in the package configured MD5, and sha1+des was exercised by
// nothing at all while the docs called it conformant.
var usmAuthProtocolsUnderTest = []struct {
	name  string
	proto int
}{{"md5", SNMPV3_AUTH_MD5}, {"sha1", SNMPV3_AUTH_SHA1}}

func checkAESIV(t *testing.T, auth int) {
	t.Helper()
	s, raw := v3AuthPrivResponse(t, auth, SNMPV3_PRIV_AES128)
	msg, err := s.parseSNMPv3Message(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	boots := msg.SecurityParams.AuthoritativeEngineBoots
	engineTime := msg.SecurityParams.AuthoritativeEngineTime
	salt := []byte(msg.SecurityParams.PrivParams)
	if len(salt) != 8 {
		t.Fatalf("privParams is %d octets, want 8", len(salt))
	}

	iv := make([]byte, aes.BlockSize)
	iv[0], iv[1], iv[2], iv[3] = byte(boots>>24), byte(boots>>16), byte(boots>>8), byte(boots)
	iv[4], iv[5], iv[6], iv[7] = byte(engineTime>>24), byte(engineTime>>16), byte(engineTime>>8), byte(engineTime)
	copy(iv[8:], salt)

	block, err := aes.NewCipher(s.usmState().privKey[:16])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	out := make([]byte, len(msg.ScopedPDU))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(out, msg.ScopedPDU) //nolint:staticcheck // RFC 3826 mandates CFB

	if len(out) == 0 || out[0] != ASN1_SEQUENCE {
		t.Fatalf("decrypting with the ADVERTISED (boots=%d, time=%d) did not yield a SEQUENCE: % x\n"+
			"The IV nl6 encrypted with disagrees with the engine time nl6 advertised, so a peer "+
			"following RFC 3826 §3.1.2.1 cannot decrypt this message.", boots, engineTime, out[:min(16, len(out))])
	}

	// The control: a different engine time must NOT decrypt, or the assertion
	// above would be satisfied by an IV that ignores the time entirely.
	iv[7] ^= 0xFF
	other := make([]byte, len(msg.ScopedPDU))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(other, msg.ScopedPDU) //nolint:staticcheck // RFC 3826 mandates CFB
	if bytes.Equal(out, other) {
		t.Error("changing the engine time in the IV changed nothing, so the IV does not depend on it")
	}
}

// TestDESIVIsSaltXorPreIV pins RFC 3414 §8.1.1.1.
//
// nl6 used to emit one random 8-octet value as BOTH the CBC IV and privParams,
// which is not what the RFC says and is not what a peer reconstructs. The pre-IV
// is the last 8 octets of the 16-octet localized key, and privParams carries the
// salt alone.
func TestDESIVIsSaltXorPreIV(t *testing.T) {
	for _, auth := range usmAuthProtocolsUnderTest {
		t.Run(auth.name, func(t *testing.T) { checkDESIV(t, auth.proto) })
	}
}

func checkDESIV(t *testing.T, auth int) {
	t.Helper()
	s, raw := v3AuthPrivResponse(t, auth, SNMPV3_PRIV_DES)
	msg, err := s.parseSNMPv3Message(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	salt := []byte(msg.SecurityParams.PrivParams)
	if len(salt) != 8 {
		t.Fatalf("privParams is %d octets, want 8", len(salt))
	}
	key := s.usmState().privKey
	if len(key) < 16 {
		t.Fatalf("localized privacy key is %d octets, want at least 16", len(key))
	}

	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = salt[i] ^ key[8:16][i]
	}
	block, err := des.NewCipher(key[:8]) // #nosec G405 -- RFC 3414 mandates DES-CBC
	if err != nil {
		t.Fatalf("des.NewCipher: %v", err)
	}
	if len(msg.ScopedPDU)%8 != 0 || len(msg.ScopedPDU) == 0 {
		t.Fatalf("ciphertext is %d octets, not a positive multiple of the block size", len(msg.ScopedPDU))
	}
	out := make([]byte, len(msg.ScopedPDU))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, msg.ScopedPDU)

	if out[0] != ASN1_SEQUENCE {
		t.Fatalf("IV = salt XOR pre-IV did not decrypt to a SEQUENCE: % x\n"+
			"privParams must carry the SALT, and the IV must be that salt XORed with the last 8 "+
			"octets of the localized key (RFC 3414 §8.1.1.1).", out[:min(16, len(out))])
	}

	// The control: privParams must not BE the IV, which is the shape nl6 shipped.
	naive := make([]byte, len(msg.ScopedPDU))
	cipher.NewCBCDecrypter(block, salt).CryptBlocks(naive, msg.ScopedPDU)
	if bytes.Equal(out, naive) {
		t.Error("using privParams directly as the IV produced the same plaintext, so the pre-IV " +
			"is not being XORed in — the last 8 octets of the key must be all zero")
	}
}

// TestNoAuthNoPrivWireDeltaIsRecorded is the answer to nl6#624's one explicit
// proof obligation, and the answer is that the obligation cannot be met.
//
// The issue asked for a proof that the noAuthNoPriv poll path stays
// byte-identical, "since that is the configuration in use today". It was
// written on the assumption that the fix touched only the authenticated paths.
// It does not: THREE of the defects are in the message envelope, which every
// security level shares.
//
//   - msgAuthoritativeEngineID was the ASCII of the engine ID's hex spelling
//     and is now the octets. A manager localizes its key against what it
//     receives, so this had to change for any level to interoperate — and it
//     is what discovery hands out, which noAuthNoPriv also uses.
//   - msgAuthoritativeEngineTime was a UNIX epoch and is now seconds since
//     boot (RFC 3414 §2.2).
//   - msgAuthenticationParameters was twelve zero octets at every level and is
//     now zero-LENGTH when the message is not authenticated (§6.3.1).
//
// So noAuthNoPriv is unchanged in what it ACCEPTS and ANSWERS, and changed on
// the wire in exactly these three fields. This test records that rather than
// asserting a byte-identity that would require keeping three defects. Any
// FURTHER drift in the unauthenticated envelope fails here.
func TestNoAuthNoPrivWireDeltaIsRecorded(t *testing.T) {
	s := v3TestServer(map[string]string{".1.3.6.1.4.1.99999.1.0": "probe"})
	s.v3Config.EngineID = "0x80001234"

	req := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 31, MsgFlags: 0},
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
		t.Fatalf("parse: %v", err)
	}

	// (1) octets, not the hex spelling.
	if got, want := []byte(msg.SecurityParams.AuthoritativeEngineID), []byte{0x80, 0x00, 0x12, 0x34}; !bytes.Equal(got, want) {
		t.Errorf("msgAuthoritativeEngineID = % x, want % x", got, want)
	}
	// (2) seconds since boot, not an epoch.
	if et := msg.SecurityParams.AuthoritativeEngineTime; et < 0 || et > 3600 {
		t.Errorf("msgAuthoritativeEngineTime = %d on a freshly booted engine, want seconds since boot", et)
	}
	// (3) zero LENGTH, not twelve zero octets.
	if n := len(msg.SecurityParams.AuthParams); n != 0 {
		t.Errorf("msgAuthenticationParameters is %d octets at noAuthNoPriv, want zero length", n)
	}
	// And the answer itself is unchanged: the value asked for comes back.
	if !bytes.Contains(raw, []byte("probe")) {
		t.Error("the noAuthNoPriv response no longer carries the value it was asked for")
	}
}

// TestUnknownUserIsAnsweredNotIgnored pins RFC 3414 §3.2 step 4.
//
// A wrong USER used to be a silent drop while a wrong DIGEST got a Report, so a
// collector could not tell an unknown user from an unreachable device and only
// half of "you can test wrong-credential handling" was true.
func TestUnknownUserIsAnsweredNotIgnored(t *testing.T) {
	s := authTestServer(t, SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
	req := buildV3RequestAt(t, s, ASN1_GET_REQUEST, ".1.3.6.1.4.1.99999.1.0", 1)

	// Rename the user in the assembled request, AT THE SAME LENGTH: a different
	// length would leave the BER length octet stale, the message would fail to
	// parse, and the handler would return before it ever reached the user check
	// — a silent pass for the wrong reason.
	tampered := bytes.Replace(req, []byte("testuser"), []byte("nosuchus"), 1)
	if bytes.Equal(tampered, req) {
		t.Fatal("test is inert: the user name was not substituted")
	}

	resp := s.handleSNMPv3Request(tampered)
	if len(resp) == 0 {
		t.Fatal("an unknown user was met with silence, which a collector cannot tell from an " +
			"unreachable device")
	}
	if got := reportOIDOf(t, s, resp); got != strings.TrimPrefix(oidUsmStatsUnknownUserNames, ".") &&
		got != oidUsmStatsUnknownUserNames {
		t.Errorf("an unknown user was answered with %q, want a Report naming usmStatsUnknownUserNames (%s)",
			got, oidUsmStatsUnknownUserNames)
	}
}

// TestTimeWindowReportIsSignedAndWrongDigestReportIsNot pins the asymmetry that
// makes engine time recoverable.
//
// RFC 3414 §3.2 step 7 generates the notInTimeWindows Report at authNoPriv so a
// manager can TRUST the (boots, time) it carries and resynchronise. Sent
// unauthenticated, a strict manager discards it and the device is permanently
// unreachable to it rather than transiently. A wrongDigests Report is
// deliberately NOT signed: the peer's key disagrees with ours, so a signature it
// cannot verify adds nothing.
func TestTimeWindowReportIsSignedAndWrongDigestReportIsNot(t *testing.T) {
	s := authTestServer(t, SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
	req := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 41, MsgFlags: SNMPV3_MSG_FLAG_AUTH},
		SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
	}
	u := s.usmState()

	signed := s.createSNMPv3ReportResponseSigned(oidUsmStatsNotInTimeWindows, req, true)
	m, err := s.parseSNMPv3Message(signed)
	if err != nil {
		t.Fatalf("parse the signed Report: %v", err)
	}
	if m.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_AUTH == 0 {
		t.Error("the notInTimeWindows Report does not set the AUTH flag, so a manager reads it as " +
			"unauthenticated and discards it")
	}
	if !usmVerifyAuthDigest(signed, m.SecurityParams.AuthParams, u.authKey, u.newHash) {
		t.Error("the notInTimeWindows Report does not verify, so a manager cannot trust the engine " +
			"time it carries and can never resynchronise")
	}
	if m.SecurityParams.UserName != "testuser" {
		t.Errorf("the signed Report names user %q, want the request's user", m.SecurityParams.UserName)
	}

	unsigned := s.createSNMPv3ReportResponse(oidUsmStatsWrongDigests, req)
	m2, err := s.parseSNMPv3Message(unsigned)
	if err != nil {
		t.Fatalf("parse the wrongDigests Report: %v", err)
	}
	if m2.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_AUTH != 0 || len(m2.SecurityParams.AuthParams) != 0 {
		t.Error("the wrongDigests Report is signed. The peer's key disagrees with ours by " +
			"definition, so a signature it cannot verify adds nothing")
	}
}

// TestPrivWithoutAuthIsAnUnsupportedSecurityLevel pins RFC 3414 §3.2 step 5.
//
// Letting a PRIV-flagged, unauthenticated message through would decrypt using
// engine boots and time this engine has not verified — and those are the input
// to the AES IV.
func TestPrivWithoutAuthIsAnUnsupportedSecurityLevel(t *testing.T) {
	s := authTestServer(t, SNMPV3_AUTH_MD5, SNMPV3_PRIV_AES128)
	msg := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 51, MsgFlags: SNMPV3_MSG_FLAG_PRIV},
		SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
	}
	oid, ok := s.authenticateInbound([]byte{}, msg)
	if ok || oid != oidUsmStatsUnsupportedSecLevels {
		t.Errorf("a PRIV-without-AUTH message gave (%q, %v), want (%s, false)",
			oid, ok, oidUsmStatsUnsupportedSecLevels)
	}
}

// TestTimeWindowRejectsAnExtremeDeclaredValue pins the range check that has to
// happen BEFORE the absolute value is taken.
//
// Negating math.MinInt is a no-op, so a declared engine time of MinInt stayed
// negative and sailed through the |delta| <= 150 comparison — passing the
// replay window on a value as far from it as an integer can be.
func TestTimeWindowRejectsAnExtremeDeclaredValue(t *testing.T) {
	u := &usmServerState{engineBoots: 1, bootedAt: time.Now()}
	for _, tc := range []struct {
		name string
		time int
	}{
		{"most negative int", -1 << 62},
		{"negative", -1},
		{"past the 32-bit range", 1 << 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if u.withinTimeWindow(1, tc.time) {
				t.Errorf("engineTime %d was accepted into the 150-second window", tc.time)
			}
		})
	}
	if !u.withinTimeWindow(1, 0) {
		t.Error("a freshly booted engine rejected its own engine time; the guard is too strict")
	}
}
