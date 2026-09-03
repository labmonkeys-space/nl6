/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
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
	v := loadRFC3414Vectors(t)
	key := v.kulMD5

	// A message shaped like the real one: the auth field is an OCTET STRING of
	// twelve zeros somewhere inside other content.
	msg := append([]byte{0x30, 0x20, 0x02, 0x01, 0x03}, append([]byte{0x04, usmAuthParamsLen},
		append(usmZeroedAuthParams(), 0x04, 0x03, 'a', 'b', 'c')...)...)

	digest := usmAuthDigest(msg, key, md5.New)
	if len(digest) != usmAuthParamsLen {
		t.Fatalf("digest is %d octets, want %d", len(digest), usmAuthParamsLen)
	}
	signed, err := substituteAuthParams(msg, digest)
	if err != nil {
		t.Fatalf("substituteAuthParams: %v", err)
	}
	if string(signed) == string(msg) {
		t.Fatal("substitution changed nothing")
	}
	if len(signed) != len(msg) {
		t.Fatalf("substitution changed the message length (%d -> %d)", len(msg), len(signed))
	}

	if !usmVerifyAuthDigest(signed, digest, key, md5.New) {
		t.Error("a message signed with this key does not verify against it")
	}
	if usmVerifyAuthDigest(signed, digest, v.kulSHA1, md5.New) {
		t.Error("a message verified against the WRONG key; the digest is not being checked")
	}
	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-1] ^= 0xFF
	if usmVerifyAuthDigest(tampered, digest, key, md5.New) {
		t.Error("a tampered message still verified; the digest does not cover the whole message")
	}
}

// TestSubstituteAuthParamsRefusesAmbiguity pins the safety valve. The field is
// located by pattern rather than by an offset threaded through four encoding
// layers; the cost of that choice is that a second identical pattern would make
// the target ambiguous, and signing the wrong octets silently is worse than
// failing.
func TestSubstituteAuthParamsRefusesAmbiguity(t *testing.T) {
	field := append([]byte{0x04, usmAuthParamsLen}, usmZeroedAuthParams()...)
	twice := append(append([]byte{0x30, 0x30}, field...), field...)

	if _, err := substituteAuthParams(twice, make([]byte, usmAuthParamsLen)); err == nil {
		t.Error("two candidate fields were accepted. The digest would cover octets chosen by " +
			"whichever matched first, which is not something to guess at")
	}
	if _, err := substituteAuthParams([]byte{0x30, 0x00}, make([]byte, usmAuthParamsLen)); err == nil {
		t.Error("a message with no auth field was accepted")
	}
}
