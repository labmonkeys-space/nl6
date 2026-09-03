/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/md5"  // #nosec G501 -- test vectors for RFC 3414's mandated HMAC-MD5-96
	"crypto/sha1" // #nosec G505 -- test vectors for RFC 3414's mandated HMAC-SHA-96
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// nl6#624. THE KEY DERIVATION IS CHECKED AGAINST THE RFC, NOT AGAINST ITSELF.
//
// RFC 3414 Appendix A.3 publishes exact byte values for both hashes, so this is
// one of the rare places a correctness claim can rest on an authority outside
// this repository. The extract is checked in under testdata/rfc/ and PARSED
// here rather than transcribed, on the nl6#541 principle: a hand-copied
// constant is a recollection wearing a fixture's clothes, and the whole reason
// this change exists is that nl6 shipped SNMPv3 claims nobody had checked.
//
// The vectors cover derivation only. They say nothing about the message
// envelope, the IVs, or interoperability; that needs an external stack, and the
// manual net-snmp check is recorded in the PR rather than run here, since no
// workflow installs net-snmp and a t.Skip would assert nothing.

// rfc3414Vectors is the parsed Appendix A.3 fixture.
type rfc3414Vectors struct {
	password        string
	engineID        []byte
	kuMD5, kulMD5   []byte
	kuSHA1, kulSHA1 []byte
}

var hexLiteral = regexp.MustCompile(`'([0-9a-fA-F ]+)'H`)

// loadRFC3414Vectors reads the six hex literals out of the checked-in extract,
// in document order: MD5 Ku, engineID, MD5 Kul, SHA Ku, engineID, SHA Kul.
func loadRFC3414Vectors(t *testing.T) rfc3414Vectors {
	t.Helper()

	path := filepath.Join("testdata", "rfc", "rfc3414-a3-password-to-key.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	body := string(raw)
	if !strings.Contains(body, `"maplesyrup"`) {
		t.Fatalf("%s does not name the RFC's sample password; the fixture is not the appendix", path)
	}

	matches := hexLiteral.FindAllStringSubmatch(body, -1)
	if len(matches) != 6 {
		t.Fatalf("found %d hex literals in %s, want the appendix's 6 (MD5 Ku, engineID, MD5 Kul, "+
			"SHA Ku, engineID, SHA Kul). The fixture is truncated or reformatted", len(matches), path)
	}
	decode := func(i int) []byte {
		b, err := hex.DecodeString(strings.ReplaceAll(matches[i][1], " ", ""))
		if err != nil {
			t.Fatalf("hex literal %d does not decode: %v", i, err)
		}
		return b
	}
	v := rfc3414Vectors{
		password: "maplesyrup",
		kuMD5:    decode(0), engineID: decode(1), kulMD5: decode(2),
		kuSHA1: decode(3), kulSHA1: decode(5),
	}
	// The appendix states the engine ID twice; if the two ever differ the
	// document order assumed above is wrong.
	if string(decode(4)) != string(v.engineID) {
		t.Fatalf("the two engineID literals differ (%x vs %x), so the positional read above is "+
			"mis-parsing the appendix", v.engineID, decode(4))
	}
	// Lengths are a cheap check that the positions were not transposed.
	if len(v.kuMD5) != 16 || len(v.kulMD5) != 16 || len(v.kuSHA1) != 20 || len(v.kulSHA1) != 20 {
		t.Fatalf("vector lengths are wrong (MD5 %d/%d, SHA %d/%d): the literals were read in the "+
			"wrong order", len(v.kuMD5), len(v.kulMD5), len(v.kuSHA1), len(v.kulSHA1))
	}
	return v
}

// TestUSMKeyDerivationMatchesRFC3414Vectors is the load-bearing correctness
// test for USM key derivation. nl6 shipped SNMPv3 for its whole life with no
// HMAC and no check of any kind; this is the first assertion here that rests on
// something other than nl6's own output.
func TestUSMKeyDerivationMatchesRFC3414Vectors(t *testing.T) {
	v := loadRFC3414Vectors(t)

	if got := usmPasswordToKey(v.password, md5.New); string(got) != string(v.kuMD5) {
		t.Errorf("MD5 password-to-key:\n got %x\nwant %x (RFC 3414 A.3.1)", got, v.kuMD5)
	}
	if got := usmLocalizeKey(v.kuMD5, v.engineID, md5.New); string(got) != string(v.kulMD5) {
		t.Errorf("MD5 localization:\n got %x\nwant %x (RFC 3414 A.3.1)", got, v.kulMD5)
	}
	if got := usmPasswordToKey(v.password, sha1.New); string(got) != string(v.kuSHA1) {
		t.Errorf("SHA password-to-key:\n got %x\nwant %x (RFC 3414 A.3.2)", got, v.kuSHA1)
	}
	if got := usmLocalizeKey(v.kuSHA1, v.engineID, sha1.New); string(got) != string(v.kulSHA1) {
		t.Errorf("SHA localization:\n got %x\nwant %x (RFC 3414 A.3.2)", got, v.kulSHA1)
	}

	// And the two steps compose, which is how production calls them.
	if got := usmLocalizeKey(usmPasswordToKey(v.password, md5.New), v.engineID, md5.New); string(got) != string(v.kulMD5) {
		t.Errorf("composed MD5 derivation:\n got %x\nwant %x", got, v.kulMD5)
	}
}

// TestUSMLocalizationUsesEngineIDOctets pins the mistake that would have made
// every other fix useless: localizing against the engine ID's HEX SPELLING
// rather than its octets. nl6 emitted the spelling on the wire while localizing
// with the octets, so a manager could never have derived the same key.
func TestUSMLocalizationUsesEngineIDOctets(t *testing.T) {
	v := loadRFC3414Vectors(t)
	spelling := []byte(hex.EncodeToString(v.engineID))

	if got := usmLocalizeKey(v.kuMD5, spelling, md5.New); string(got) == string(v.kulMD5) {
		t.Error("localizing with the engine ID's hex SPELLING produced the RFC's value, which cannot " +
			"be: the two inputs differ, so one of them is not reaching the hash")
	}
	if got := parseEngineIDOctets("0x" + hex.EncodeToString(v.engineID)); string(got) != string(v.engineID) {
		t.Errorf("parseEngineIDOctets(0x-prefixed) = %x, want the octets %x", got, v.engineID)
	}
	if got := parseEngineIDOctets(hex.EncodeToString(v.engineID)); string(got) != string(v.engineID) {
		t.Errorf("parseEngineIDOctets(bare hex) = %x, want the octets %x", got, v.engineID)
	}
}

// TestUSMAuthDigestRoundTrips covers substitution and verification together,
// because they are the two halves of one contract: the digest is computed over
// a message containing its own zeroed field, so a verifier must reproduce that
// exact byte sequence or nothing ever matches.
func TestUSMAuthDigestRoundTrips(t *testing.T) {
	// Built by the PRODUCTION assembler, not by hand. The field is located
	// structurally now (locateAuthParams), so a hand-rolled blob that merely
	// contains the pattern is not the thing under test — and a test that used
	// one would keep passing while the real message stopped being locatable.
	s := authTestServer(t, SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
	req := &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 11, MsgFlags: SNMPV3_MSG_FLAG_AUTH},
		SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
	}
	scoped, err := s.createScopedPDU(".1.3.6.1.4.1.99999.1.0", "probe", req)
	if err != nil {
		t.Fatalf("createScopedPDU: %v", err)
	}
	signed, err := s.wrapScopedPDUInV3Message(scoped, req)
	if err != nil {
		t.Fatalf("wrapScopedPDUInV3Message: %v", err)
	}
	u := s.usmState()

	off, n, ok := locateAuthParams(signed)
	if !ok || n != usmAuthParamsLen {
		t.Fatalf("locateAuthParams on a real message: ok=%v len=%d", ok, n)
	}
	digest := append([]byte(nil), signed[off:off+n]...)

	if !usmVerifyAuthDigest(signed, digest, u.authKey, u.newHash) {
		t.Error("a message signed with this key does not verify against it")
	}
	if usmVerifyAuthDigest(signed, digest, loadRFC3414Vectors(t).kulSHA1, u.newHash) {
		t.Error("a message verified against the WRONG key; the digest is not being checked")
	}
	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-1] ^= 0xFF
	if usmVerifyAuthDigest(tampered, digest, u.authKey, u.newHash) {
		t.Error("a tampered message still verified; the digest does not cover the whole message")
	}
}

// TestTwelveZeroByteValueDoesNotBreakSigning is a REGRESSION TEST FOR A DEFECT
// THIS CHANGE SHIPPED AND REVIEW CAUGHT.
//
// substituteAuthParams originally located the auth field by searching for its
// zeroed form, `04 0C` followed by twelve zero octets. That is byte-for-byte
// how an OCTET STRING value of twelve zero bytes encodes, so a device serving
// such a value made the pattern ambiguous, made substitution refuse, and made
// the entire response fail to assemble — an authNoPriv GET of that OID returned
// NOTHING AT ALL, with no log line. Reachable from an ordinary operator
// resource file.
//
// The comment defending the search argued that an offset threaded through four
// encoding layers was the riskier choice. It had the trade backwards: an offset
// can go stale, but a search can be defeated by the message's own data, and
// only one of those is reachable by data nl6 does not control. Both are avoided
// by walking the structure.
//
// The value is asserted to survive the round trip, not merely for a response to
// exist: a fix that located the field correctly but clobbered the varbind would
// also produce a response.
func TestTwelveZeroByteValueDoesNotBreakSigning(t *testing.T) {
	const probeOID = ".1.3.6.1.4.1.99999.1.0"
	value := strings.Repeat("\x00", usmAuthParamsLen)

	s := v3TestServer(map[string]string{probeOID: value})
	s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
	s.v3Config.Password = "authpassword"

	resp := s.handleSNMPv3Request(buildV3RequestAt(t, s, ASN1_GET_REQUEST, probeOID, 1))
	if len(resp) == 0 {
		t.Fatal("an authNoPriv GET of a twelve-zero-byte value produced NO RESPONSE. The auth field " +
			"is being located by a pattern the message's own data can match.")
	}

	// The response must still verify, and must still carry the value.
	msg, err := s.parseSNMPv3Message(resp)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	u := s.usmState()
	if !usmVerifyAuthDigest(resp, msg.SecurityParams.AuthParams, u.authKey, u.newHash) {
		t.Error("the response does not verify: the digest was written over the wrong octets")
	}
	if !bytes.Contains(resp, append([]byte{0x04, usmAuthParamsLen}, make([]byte, usmAuthParamsLen)...)) {
		t.Error("the twelve-zero-byte VALUE is no longer in the response; signing clobbered the varbind")
	}
}

// TestLocateAuthParamsRefusesAMalformedMessage pins the failure side. A message
// that is not shaped like an SNMPv3 message has no auth field to find, and
// guessing at one would mean signing octets chosen by accident.
func TestLocateAuthParamsRefusesAMalformedMessage(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  []byte
	}{
		{"empty", nil},
		{"bare sequence", []byte{0x30, 0x00}},
		{"truncated after version", []byte{0x30, 0x03, 0x02, 0x01, 0x03}},
		{"length overruns the buffer", []byte{0x30, 0x7F, 0x02, 0x01, 0x03}},
		{"pattern present but not structural", append([]byte{0x04, usmAuthParamsLen}, usmZeroedAuthParams()...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := locateAuthParams(tc.msg); ok {
				t.Error("located an auth field in a message that has none")
			}
			if _, err := substituteAuthParams(tc.msg, make([]byte, usmAuthParamsLen)); err == nil {
				t.Error("substituted into a message with no locatable auth field")
			}
		})
	}
}
