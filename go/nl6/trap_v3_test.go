/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G503 -- RFC 3414 §8 mandates CBC-DES for usmDESPrivProtocol
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// trap_v3_test.go — nl6#98's in-package half.
//
// WHAT THESE TESTS DO NOT PROVE, said first because it is the lesson nl6#624
// paid for: nl6 parsing its own trap proves nothing about interoperability.
// Every assertion here reads nl6's bytes, and a shared misunderstanding of RFC
// 3414 satisfies all of them. The check with detection power is
// TestSNMPv3TrapInteropWithSnmptrapd (snmpv3_usm_interop_test.go), where
// snmptrapd derives its OWN key from the password and the engine ID it received
// and decrypts with an IV it built itself. nl6#624's first interop run failed
// every row with this package green.
//
// So these tests are structured to be as un-tautological as an in-package test
// can be:
//
//   - The message is decoded with the INDEPENDENT BER reader from
//     trap_v1_test.go (v1TLV / v1Int / v1OctetString), never with nl6's parser.
//   - The auth digest is verified against a key localized from the engine ID
//     READ OFF THE WIRE, which is what a collector does — not against the
//     encoder's own cached key. That is the difference between "the digest is
//     self-consistent" and "the digest is verifiable by the receiver".
//   - The scoped PDU is DECRYPTED by this file, from the RFC 3414 §8.1.1 and RFC
//     3826 §3.1.2.1 rules, with the IV built from the boots and time the message
//     ADVERTISES. That is what catches the two-clock-reads defect
//     (encryptScopedPDUAt): an IV built from T against an advertised T+1 leaves
//     nl6's own decrypt path green and this one failing.
//   - The recovered plaintext is compared against encodeNotificationPDU's output
//     for the same inputs, so "carries the varbinds v2c sends" is a byte
//     comparison rather than a field-presence check.

// v3TrapTestConfig is the USM configuration every row below is built from.
//
// The auth and privacy passwords DIFFER, for the reason v3ExtractionServer
// documents: a derivation that reads the wrong one is then visible rather than
// hidden behind a shared secret.
func v3TrapTestConfig(auth, priv int) TrapV3Config {
	return TrapV3Config{
		UserName:     "trapuser",
		AuthProtocol: auth,
		PrivProtocol: priv,
		Password:     "trapauthpassword",
		PrivPassword: "trapprivpassword",
	}
}

// v3TrapRow is one auth x priv protocol combination.
//
// NOT "one security level": RFC 3414 defines THREE (noAuthNoPriv, authNoPriv,
// authPriv). These seven rows are those three expanded over the protocol
// choices, which is a different count and the one that matters here.
//
// BOTH HASHES ARE CROSSED WITH BOTH CIPHERS, the same four rows
// v3ExtractionLevels sweeps and for the same reason: nl6#624 found the two
// privacy derivations hardcoding OPPOSITE hashes, so md5+des and sha1+aes128
// were accidentally right while the other two were wrong. A diagonal saw
// nothing.
var v3TrapRows = []struct {
	name  string
	auth  int
	priv  int
	flags byte
}{
	{"noAuthNoPriv", SNMPV3_AUTH_NONE, SNMPV3_PRIV_NONE, 0},
	{"authNoPriv/md5", SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE, SNMPV3_MSG_FLAG_AUTH},
	{"authNoPriv/sha1", SNMPV3_AUTH_SHA1, SNMPV3_PRIV_NONE, SNMPV3_MSG_FLAG_AUTH},
	{"authPriv/md5+des", SNMPV3_AUTH_MD5, SNMPV3_PRIV_DES, SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV},
	{"authPriv/sha1+des", SNMPV3_AUTH_SHA1, SNMPV3_PRIV_DES, SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV},
	{"authPriv/md5+aes", SNMPV3_AUTH_MD5, SNMPV3_PRIV_AES128, SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV},
	{"authPriv/sha1+aes", SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128, SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV},
}

// v3TrapVarbinds is the notification body every row encodes. Two varbinds of
// different types so a value-encoding regression is visible in the recovered
// plaintext rather than only in a length.
var v3TrapVarbinds = []Varbind{
	{OID: "1.3.6.1.2.1.2.2.1.1.7", Type: TrapVTInteger, Value: "7"},
	{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: "sim-9"},
}

const (
	v3TrapOID        = "1.3.6.1.6.3.1.1.5.3" // linkDown
	v3TrapEnterprise = "1.3.6.1.4.1.9"
	v3TrapUptime     = uint32(123456)
)

// decodedV3Trap is an SNMPv3 message taken apart by the independent reader.
type decodedV3Trap struct {
	version     int
	msgID       int
	msgMaxSize  int
	msgFlags    byte
	secModel    int
	engineID    []byte
	boots       int
	engineTime  int
	userName    string
	authParams  []byte
	privParams  []byte
	scopedPDU   []byte // ciphertext when the PRIV flag is set, plaintext otherwise
	wholeMsgLen int
}

// decodeV3Trap walks an emitted message with the trap_v1_test.go BER reader.
//
// STRUCTURAL, and deliberately not nl6's parseSNMPv3Message: a decoder sharing
// code with the encoder lets one misreading satisfy both sides, which is the
// standard the v1 reader was written to.
func decodeV3Trap(t *testing.T, msg []byte) decodedV3Trap {
	t.Helper()
	var d decodedV3Trap
	d.wholeMsgLen = len(msg)

	body, rest := v1TLV(t, msg, ASN1_SEQUENCE, "v3 message")
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after the SNMPv3 message: % x", rest)
	}
	d.version, body = v1Int(t, body, "msgVersion")

	global, body := v1TLV(t, body, ASN1_SEQUENCE, "msgGlobalData")
	d.msgID, global = v1Int(t, global, "msgID")
	d.msgMaxSize, global = v1Int(t, global, "msgMaxSize")
	flags, global := v1OctetString(t, global, "msgFlags")
	if len(flags) != 1 {
		t.Fatalf("msgFlags is %d octets, want 1: % x", len(flags), flags)
	}
	d.msgFlags = flags[0]
	d.secModel, global = v1Int(t, global, "msgSecurityModel")
	if len(global) != 0 {
		t.Fatalf("trailing bytes in msgGlobalData: % x", global)
	}

	secBytes, body := v1OctetString(t, body, "msgSecurityParameters")
	usm, secRest := v1TLV(t, []byte(secBytes), ASN1_SEQUENCE, "USM parameters")
	if len(secRest) != 0 {
		t.Fatalf("trailing bytes in msgSecurityParameters: % x", secRest)
	}
	eid, usm := v1OctetString(t, usm, "msgAuthoritativeEngineID")
	d.engineID = []byte(eid)
	d.boots, usm = v1Int(t, usm, "msgAuthoritativeEngineBoots")
	d.engineTime, usm = v1Int(t, usm, "msgAuthoritativeEngineTime")
	d.userName, usm = v1OctetString(t, usm, "msgUserName")
	auth, usm := v1OctetString(t, usm, "msgAuthenticationParameters")
	d.authParams = []byte(auth)
	priv, usm := v1OctetString(t, usm, "msgPrivacyParameters")
	d.privParams = []byte(priv)
	if len(usm) != 0 {
		t.Fatalf("trailing bytes in the USM parameters: % x", usm)
	}

	// Encrypted: an OCTET STRING wrapping the ciphertext. In the clear: the
	// ScopedPDU SEQUENCE itself.
	if d.msgFlags&SNMPV3_MSG_FLAG_PRIV != 0 {
		ct, tail := v1OctetString(t, body, "encryptedPDU")
		d.scopedPDU = []byte(ct)
		body = tail
	} else {
		// v1TLV returns the CONTENTS; the caller wants the whole ScopedPDU TLV,
		// exactly as wrapInScopedPDU produced it, so that the encrypted and
		// unencrypted branches hand back the same shape.
		_, tail := v1TLV(t, body, ASN1_SEQUENCE, "scopedPDU")
		d.scopedPDU = append([]byte(nil), body[:len(body)-len(tail)]...)
		body = tail
	}
	if len(body) != 0 {
		t.Fatalf("trailing bytes after the scoped PDU: % x", body)
	}
	return d
}

// v3TrapDecryptScopedPDU recovers the plaintext scoped PDU the way a COLLECTOR
// does: with a key it localized itself, and an IV it built from the boots and
// time the message advertises.
//
// Written from RFC 3414 §8.1.1.1 (DES) and RFC 3826 §3.1.2.1 (AES) rather than
// calling nl6's decryptAES128At, which reads nl6's own engine state. That is
// what makes it able to catch an IV built from a different clock sample than
// the one on the wire — the defect encryptScopedPDUAt exists to prevent, and
// one that nl6's own decrypt path cannot see.
func v3TrapDecryptScopedPDU(t *testing.T, d decodedV3Trap, cfg TrapV3Config) []byte {
	t.Helper()
	newHash, ok := usmHashFor(cfg.AuthProtocol)
	if !ok {
		t.Fatalf("privacy without an authentication protocol has no key derivation")
	}
	privPassword := cfg.PrivPassword
	if privPassword == "" {
		privPassword = cfg.Password
	}
	// Localized against the engine ID FROM THE WIRE, which is the whole point.
	key := usmLocalizeKey(usmPasswordToKey(privPassword, newHash), d.engineID, newHash)
	if len(key) < 16 {
		t.Fatalf("localized privacy key is %d octets, want at least 16", len(key))
	}

	switch cfg.PrivProtocol {
	case SNMPV3_PRIV_DES:
		if len(d.privParams) != 8 {
			t.Fatalf("DES privParams is %d octets, want the 8-octet salt", len(d.privParams))
		}
		iv := make([]byte, 8)
		for i := range iv {
			iv[i] = d.privParams[i] ^ key[8+i] // salt XOR pre-IV
		}
		block, err := des.NewCipher(key[:8]) // #nosec G405 -- RFC 3414 §8 mandates DES here
		if err != nil {
			t.Fatalf("des.NewCipher: %v", err)
		}
		if len(d.scopedPDU)%8 != 0 {
			t.Fatalf("DES ciphertext is %d octets, not a multiple of the 8-octet block",
				len(d.scopedPDU))
		}
		out := make([]byte, len(d.scopedPDU))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, d.scopedPDU)
		return out

	case SNMPV3_PRIV_AES128:
		if len(d.privParams) != 8 {
			t.Fatalf("AES privParams is %d octets, want the 8-octet salt", len(d.privParams))
		}
		iv := make([]byte, aes.BlockSize)
		iv[0], iv[1], iv[2], iv[3] = byte(d.boots>>24), byte(d.boots>>16), byte(d.boots>>8), byte(d.boots)
		iv[4], iv[5], iv[6], iv[7] = byte(d.engineTime>>24), byte(d.engineTime>>16),
			byte(d.engineTime>>8), byte(d.engineTime)
		copy(iv[8:], d.privParams)
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			t.Fatalf("aes.NewCipher: %v", err)
		}
		out := make([]byte, len(d.scopedPDU))
		cipher.NewCFBDecrypter(block, iv).XORKeyStream(out, d.scopedPDU) //nolint:staticcheck // RFC 3826 mandates CFB
		return out

	default:
		t.Fatalf("no privacy protocol to decrypt with")
		return nil
	}
}

// v3TrapEncoderFor builds an encoder for a device address at one security
// level, failing the test rather than returning an error.
func v3TrapEncoderFor(t *testing.T, ip net.IP, auth, priv int) (*SNMPv3TrapEncoder, TrapV3Config) {
	t.Helper()
	cfg := v3TrapTestConfig(auth, priv)
	enc, err := NewSNMPv3TrapEncoder(ip, cfg)
	if err != nil {
		t.Fatalf("NewSNMPv3TrapEncoder(%s, %s): %v", ip, cfg.securityLevel(), err)
	}
	return enc, cfg
}

// v2cPDURegion returns the PDU bytes inside a real SNMPv2c trap message, with
// the version and community stripped by the independent BER reader.
//
// It is what makes "the v3 notification carries the same PDU as v2c" a claim
// about the two ENCODERS rather than about one shared builder called twice.
func v2cPDURegion(t *testing.T, reqID uint32, trapOID, enterprise string,
	uptime uint32, varbinds []Varbind) []byte {
	t.Helper()
	buf := make([]byte, maxTrapPDU)
	n, err := SNMPv2cEncoder{}.EncodeTrap("public", reqID, trapOID, enterprise, uptime, varbinds, buf)
	if err != nil {
		t.Fatalf("SNMPv2cEncoder.EncodeTrap: %v", err)
	}
	body, rest := v1TLV(t, buf[:n], ASN1_SEQUENCE, "v2c outer message")
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after the v2c message: % x", rest)
	}
	version, body := v1Int(t, body, "version")
	if version != 1 {
		t.Fatalf("v2c version = %d, want 1", version)
	}
	community, body := v1OctetString(t, body, "community")
	if community != "public" {
		t.Fatalf("v2c community = %q", community)
	}
	return body
}

// ── the matrix ──────────────────────────────────────────────────────────────

// TestV3TrapAtEverySecurityLevel sweeps all three RFC 3414 security levels,
// expanded over the protocol choices: noAuthNoPriv, authNoPriv under both
// hashes, and authPriv at all four hash × cipher pairs.
//
// It asserts the ENVELOPE, VERIFIES the digest against a receiver-derived key,
// DECRYPTS the scoped PDU, and compares the recovered PDU against
// encodeNotificationPDU byte for byte. Field presence is not asserted anywhere:
// a message whose fields are all present and whose digest does not verify is
// exactly the message nl6 shipped for years.
func TestV3TrapAtEverySecurityLevel(t *testing.T) {
	deviceIP := net.IPv4(10, 42, 0, 9)
	buf := make([]byte, maxTrapPDU)

	// The PDU every row must be carrying, taken from what the SNMPv2c ENCODER
	// actually emits.
	//
	// NOT from encodeNotificationPDU. An earlier cut built the expectation with
	// the very call EncodeTrap makes, so "the v3 scoped PDU carries the varbinds
	// v2c sends" was proved by asking one function twice — true of any two
	// callers of anything, and silent if v2c's own message ever stopped
	// containing that builder's output. This strips the community envelope off a
	// real v2c trap with the independent reader and compares what is left.
	wantPDU := v2cPDURegion(t, 4242, v3TrapOID, v3TrapEnterprise, v3TrapUptime, v3TrapVarbinds)

	for _, row := range v3TrapRows {
		t.Run(row.name, func(t *testing.T) {
			enc, cfg := v3TrapEncoderFor(t, deviceIP, row.auth, row.priv)

			n, err := enc.EncodeTrap("ignored-community", 4242, v3TrapOID, v3TrapEnterprise,
				v3TrapUptime, v3TrapVarbinds, buf)
			if err != nil {
				t.Fatalf("EncodeTrap: %v", err)
			}
			msg := append([]byte(nil), buf[:n]...)
			d := decodeV3Trap(t, msg)

			if d.version != SNMPV3_VERSION {
				t.Errorf("msgVersion = %d, want %d", d.version, SNMPV3_VERSION)
			}
			if d.secModel != SNMPV3_SECURITY_MODEL_USM {
				t.Errorf("msgSecurityModel = %d, want %d (USM)", d.secModel, SNMPV3_SECURITY_MODEL_USM)
			}
			if d.msgFlags != row.flags {
				t.Errorf("msgFlags = 0x%02X, want 0x%02X. The reportable bit must be CLEAR on an "+
					"unacknowledged notification (RFC 3412 §6.4)", d.msgFlags, row.flags)
			}
			if d.userName != cfg.UserName {
				t.Errorf("msgUserName = %q, want %q", d.userName, cfg.UserName)
			}

			// The engine identity: the device's OWN, on the wire as OCTETS.
			wantEngine := snmpv3TrapEngineID(deviceIP)
			if !bytes.Equal(d.engineID, wantEngine) {
				t.Errorf("msgAuthoritativeEngineID = %x, want %x. It goes on the wire as octets, "+
					"never as its hex spelling (nl6#624), and it is this device's own identity, "+
					"never the fleet-wide poll engine's", d.engineID, wantEngine)
			}
			// A v3 TRAP sender is the authoritative engine: there is no
			// discovery and nothing to echo, so boots is this engine's own and
			// time is seconds since IT booted — not a Unix epoch, which a
			// manager applying the RFC 3414 §3.2 window rejects outright.
			if d.boots != 1 {
				t.Errorf("msgAuthoritativeEngineBoots = %d, want 1 (this engine's own)", d.boots)
			}
			if d.engineTime < 0 || d.engineTime > 60 {
				t.Errorf("msgAuthoritativeEngineTime = %d; seconds since this engine booted should be "+
					"small in a test. A Unix epoch here is the nl6#624 defect", d.engineTime)
			}

			// ── the digest ──────────────────────────────────────────────────
			if row.auth == SNMPV3_AUTH_NONE {
				// RFC 3414 §6.3.1: noAuthNoPriv sends a ZERO-LENGTH field. nl6
				// sent twelve zero octets at every level before nl6#624, which
				// is indistinguishable from a computed digest that happened to
				// be zero.
				if len(d.authParams) != 0 {
					t.Errorf("msgAuthenticationParameters is %d octets at noAuthNoPriv, want a "+
						"zero-length field (RFC 3414 §6.3.1): % x", len(d.authParams), d.authParams)
				}
			} else {
				if len(d.authParams) != usmAuthParamsLen {
					t.Fatalf("msgAuthenticationParameters is %d octets, want %d",
						len(d.authParams), usmAuthParamsLen)
				}
				if bytes.Equal(d.authParams, make([]byte, usmAuthParamsLen)) {
					t.Fatal("msgAuthenticationParameters is twelve ZERO octets: the placeholder was " +
						"never substituted, which is exactly what nl6 shipped before nl6#624")
				}
				newHash, ok := usmHashFor(row.auth)
				if !ok {
					t.Fatalf("no hash for auth protocol %d", row.auth)
				}
				// THE RECEIVER'S KEY: localized against the engine ID that
				// arrived, not the encoder's cached one. A trap keyed on the
				// fleet-wide poll engine ID would produce a digest that
				// verifies against the sender's own key and against nothing a
				// collector can derive — so verifying with the encoder's key
				// would pass while the trap is unusable.
				key := usmLocalizeKey(usmPasswordToKey(cfg.Password, newHash), d.engineID, newHash)
				if !usmVerifyAuthDigest(msg, d.authParams, key, newHash) {
					t.Errorf("the digest does not verify against a key localized from the engine ID "+
						"this message ADVERTISES (%x). A collector derives its key exactly this way, "+
						"so it would reject the trap", d.engineID)
				}
			}

			// ── the payload ─────────────────────────────────────────────────
			scoped := d.scopedPDU
			if row.priv != SNMPV3_PRIV_NONE {
				if len(d.privParams) != 8 {
					t.Fatalf("msgPrivacyParameters is %d octets, want the 8-octet salt", len(d.privParams))
				}
				scoped = v3TrapDecryptScopedPDU(t, d, cfg)
			} else if len(d.privParams) != 0 {
				t.Errorf("msgPrivacyParameters is %d octets with privacy off, want empty", len(d.privParams))
			}

			// The recovered ScopedPDU: contextEngineID, contextName, then the
			// PDU. DES pads to the block size, so the SEQUENCE header's own
			// length is what bounds the content rather than the buffer.
			inner, tail := v1TLV(t, scoped, ASN1_SEQUENCE, "recovered scopedPDU")
			if row.priv == SNMPV3_PRIV_DES {
				// RFC 3414 §8.1.1.2 permits trailing pad octets after the
				// SEQUENCE; anything else must be exact.
				if len(tail) >= 8 {
					t.Errorf("%d octets follow the recovered ScopedPDU, more than one DES pad block",
						len(tail))
				}
			} else if len(tail) != 0 {
				t.Errorf("%d trailing octets after the recovered ScopedPDU: % x", len(tail), tail)
			}

			ctxEngine, inner := v1OctetString(t, inner, "contextEngineID")
			if !bytes.Equal([]byte(ctxEngine), wantEngine) {
				t.Errorf("contextEngineID = %x, want the originator's own engine ID %x",
					[]byte(ctxEngine), wantEngine)
			}
			ctxName, inner := v1OctetString(t, inner, "contextName")
			if ctxName != "" {
				t.Errorf("contextName = %q, want the default (empty) context", ctxName)
			}
			if !bytes.Equal(inner, wantPDU) {
				t.Errorf("the scoped PDU does not carry the PDU encodeNotificationPDU builds.\n"+
					"got:  % x\nwant: % x\nA v3 notification must carry the SAME SNMPv2-Trap-PDU the "+
					"v2c path emits, prepends included", inner, wantPDU)
			}
			if len(inner) == 0 || inner[0] != ASN1_TRAP_V2C {
				t.Errorf("the scoped PDU's data is tagged 0x%02X, want 0x%02X (SNMPv2-Trap-PDU)",
					inner[0], ASN1_TRAP_V2C)
			}
		})
	}
}

// TestV3TrapEngineIdentityIsPerDevice is the matrix's "per-device identity"
// row, and the property the whole design rests on.
//
// TWO DEVICES SHARING A USER AND PASSWORD MUST NOT SHARE A KEY. If they did,
// the trap identity would be the shared-identity defect nl6#588 and nl6#599 each
// corrected once, and a collector could not tell two simulated devices apart by
// engine.
//
// It asserts the keys as well as the identities: identical engine IDs would be
// caught by the first check alone, but a localization that IGNORED the engine ID
// would leave the identities different and the keys the same, which is the
// mutation that actually matters.
func TestV3TrapEngineIdentityIsPerDevice(t *testing.T) {
	a := net.IPv4(10, 42, 0, 9)
	b := net.IPv4(10, 42, 1, 200)

	for _, row := range v3TrapRows {
		if row.auth == SNMPV3_AUTH_NONE {
			continue // no keys to compare
		}
		t.Run(row.name, func(t *testing.T) {
			encA, cfg := v3TrapEncoderFor(t, a, row.auth, row.priv)
			encB, _ := v3TrapEncoderFor(t, b, row.auth, row.priv)

			if bytes.Equal(encA.EngineID(), encB.EngineID()) {
				t.Fatalf("two devices derived the SAME engine ID %x; the identity must be per device",
					encA.EngineID())
			}

			usmA, usmB := encA.engine.usmState(), encB.engine.usmState()
			if bytes.Equal(usmA.authKey, usmB.authKey) {
				t.Errorf("two devices sharing user %q and one password localized the SAME auth key. "+
					"The localization is H(Ku || engineID || Ku) — an engine ID that does not reach "+
					"it makes every device's key identical", cfg.UserName)
			}
			if row.priv != SNMPV3_PRIV_NONE && bytes.Equal(usmA.privKey, usmB.privKey) {
				t.Error("two devices localized the SAME privacy key")
			}
			// And the localization must be the one a receiver reproduces from
			// the wire, not merely "some function of the engine ID".
			newHash, _ := usmHashFor(row.auth)
			want := usmLocalizeKey(usmPasswordToKey(cfg.Password, newHash), encA.EngineID(), newHash)
			if !bytes.Equal(usmA.authKey, want) {
				t.Errorf("the encoder's auth key is not H(Ku || its own engineID || Ku); a collector " +
					"derives exactly that and would reject every trap")
			}
		})
	}
}

// TestV3TrapEngineIDIsRFC3411Format3 pins the derivation's LAYOUT.
//
// The identity is an RFC 3411 §5 SnmpEngineID: four octets of enterprise number
// with the high bit set, a format octet, then the format's payload. Format 3 is
// a 6-octet IEEE MAC, and nl6 already synthesises one per device
// (synthChassisID) — reusing it is what keeps the engine identity the same
// identity the device asserts over LLDP and in {{.ChassisID}}.
//
// THE PEN IS CHECKED AGAINST THE IANA EXTRACT, not against a literal repeated
// here: 32473 is RFC 5612's documentation PEN, and testdata/iana carries the
// registry rows nl6#576 checked in for exactly this kind of claim.
func TestV3TrapEngineIDIsRFC3411Format3(t *testing.T) {
	ip := net.IPv4(10, 42, 0, 9)
	got := snmpv3TrapEngineID(ip)

	if len(got) != 11 {
		t.Fatalf("engine ID is %d octets (%x), want 11: 4 PEN + 1 format + 6 MAC", len(got), got)
	}
	if got[0]&0x80 == 0 {
		t.Errorf("the first octet is 0x%02X: RFC 3411 §5 sets the high bit to mark the enterprise "+
			"format", got[0])
	}
	pen := uint32(got[0]&0x7F)<<24 | uint32(got[1])<<16 | uint32(got[2])<<8 | uint32(got[3])
	if pen != snmpv3TrapPEN {
		t.Errorf("engine ID carries PEN %d, want %d", pen, snmpv3TrapPEN)
	}
	if got[4] != snmpv3EngineIDFormatMAC {
		t.Errorf("format octet = %d, want 3 (IEEE MAC address)", got[4])
	}

	// The MAC is the device's own, spelled the way synthChassisID spells it.
	wantMAC := synthChassisID(ip)
	gotMAC := make([]string, 0, 6)
	for _, b := range got[5:] {
		gotMAC = append(gotMAC, fmt.Sprintf("%02x", b))
	}
	if strings.Join(gotMAC, ":") != wantMAC {
		t.Errorf("engine ID MAC = %s, want the device's own chassis ID %s. Reusing synthChassisID is "+
			"what keeps the engine identity and the LLDP chassis identity the same identity",
			strings.Join(gotMAC, ":"), wantMAC)
	}

	// Distinct for distinct addresses, across a spread that moves every octet.
	seen := map[string]string{}
	for _, ip := range []net.IP{
		net.IPv4(10, 42, 0, 1), net.IPv4(10, 42, 0, 2), net.IPv4(10, 42, 1, 1),
		net.IPv4(10, 43, 0, 1), net.IPv4(192, 168, 0, 1),
	} {
		k := hex.EncodeToString(snmpv3TrapEngineID(ip))
		if prev, dup := seen[k]; dup {
			t.Errorf("%s and %s derive the same engine ID %s", prev, ip, k)
		}
		seen[k] = ip.String()
	}
}

// TestV3TrapRefusesAnUnderivableEngineIdentity is the DECISION nl6#627 deferred.
//
// wrapInScopedPDU accepts a nil engine ID and usmState silently substitutes
// defaultSNMPv3EngineID for an empty one. Both are right for their own callers
// and both are wrong for a notification originator: a trap naming no
// authoritative engine, or naming the same default one as every other device,
// gives a collector an identity it cannot localize a distinct key against.
//
// So the encoder REFUSES. A device whose address is not IPv4 gets no v3 trap
// encoder and an error at attach, rather than a fleet of identically-keyed
// notifications.
func TestV3TrapRefusesAnUnderivableEngineIdentity(t *testing.T) {
	cfg := v3TrapTestConfig(SNMPV3_AUTH_MD5, SNMPV3_PRIV_AES128)

	for _, tc := range []struct {
		name string
		ip   net.IP
	}{
		{"nil", nil},
		{"empty", net.IP{}},
		{"ipv6", net.ParseIP("2001:db8::1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSNMPv3TrapEncoder(tc.ip, cfg); err == nil {
				t.Error("NewSNMPv3TrapEncoder accepted a device with no derivable IPv4 identity. " +
					"It would then fall back to the fleet-wide default engine ID, and every device " +
					"sharing it would localize the same key")
			}
		})
	}

	// The positive control: a guard that only ever refuses proves nothing.
	if _, err := NewSNMPv3TrapEncoder(net.IPv4(10, 42, 0, 9), cfg); err != nil {
		t.Fatalf("a normal IPv4 device was refused: %v", err)
	}

	// And the substitution itself must not be reachable: the engine's derived
	// ID must be the device's, never defaultSNMPv3EngineID.
	enc, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 9), SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
	if bytes.Equal(enc.engine.usmState().engineID, parseEngineIDOctets(defaultSNMPv3EngineID)) {
		t.Error("the trap engine settled on defaultSNMPv3EngineID, the fleet-wide substitute")
	}
}

// TestV3TrapConfigIsValidated pins the refusals that stop an unusable fleet at
// startup instead of at every fire.
func TestV3TrapConfigIsValidated(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  TrapV3Config
		want string
	}{
		{"no user", TrapV3Config{AuthProtocol: SNMPV3_AUTH_MD5, Password: "x"}, "trap-snmpv3-user"},
		{"auth without password", TrapV3Config{UserName: "u", AuthProtocol: SNMPV3_AUTH_MD5},
			"trap-snmpv3-password"},
		{"priv without auth", TrapV3Config{UserName: "u", PrivProtocol: SNMPV3_PRIV_AES128,
			Password: "x"}, "requires an authentication protocol"},
		// The seams validate NOTHING, so the originator has to. Before these
		// rules an out-of-range protocol built a perfectly good encoder whose
		// every fire then failed at the cipher or the digest.
		{"user name over RFC 3414's 32 octets",
			TrapV3Config{UserName: strings.Repeat("u", 33), AuthProtocol: SNMPV3_AUTH_MD5,
				Password: "x"}, "32"},
		{"user name over 32 OCTETS though under 32 runes",
			TrapV3Config{UserName: strings.Repeat("é", 20), AuthProtocol: SNMPV3_AUTH_MD5,
				Password: "x"}, "octets"},
		{"unknown auth protocol",
			TrapV3Config{UserName: "u", AuthProtocol: 99, Password: "x"},
			"authentication protocol 99"},
		{"unknown priv protocol",
			TrapV3Config{UserName: "u", AuthProtocol: SNMPV3_AUTH_MD5, PrivProtocol: 99,
				Password: "x"}, "privacy protocol 99"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %+v", tc.cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate said %q, want it to name %q so an operator knows which flag to set",
					err, tc.want)
			}
		})
	}

	// Controls, both directions: the shipped combinations must be accepted.
	for _, row := range v3TrapRows {
		if err := v3TrapTestConfig(row.auth, row.priv).Validate(); err != nil {
			t.Errorf("%s was refused: %v", row.name, err)
		}
	}
	// And the privacy password falls back to the auth password, matching
	// usmState's own rule for the poll path.
	if err := (TrapV3Config{UserName: "u", AuthProtocol: SNMPV3_AUTH_SHA1,
		PrivProtocol: SNMPV3_PRIV_DES, Password: "shared"}).Validate(); err != nil {
		t.Errorf("one password for both auth and privacy was refused: %v", err)
	}
	// Exactly 32 octets is legal — the bound is inclusive.
	if err := (TrapV3Config{UserName: strings.Repeat("u", usmMaxUserNameOctets),
		AuthProtocol: SNMPV3_AUTH_MD5, Password: "x"}).Validate(); err != nil {
		t.Errorf("a %d-octet user name was refused; RFC 3414 §2.1's bound is inclusive: %v",
			usmMaxUserNameOctets, err)
	}

	// The name that reaches the WIRE is the trimmed one Validate measured, not
	// what the shell handed in. A collector matches msgUserName literally, so
	// leading whitespace is a silent mismatch.
	enc, err := NewSNMPv3TrapEncoder(net.IPv4(10, 42, 0, 9), TrapV3Config{
		UserName: "  padded  ", AuthProtocol: SNMPV3_AUTH_MD5, Password: "x"})
	if err != nil {
		t.Fatalf("NewSNMPv3TrapEncoder: %v", err)
	}
	buf := make([]byte, maxTrapPDU)
	n, err := enc.EncodeTrap("", 1, v3TrapOID, "", v3TrapUptime, v3TrapVarbinds, buf)
	if err != nil {
		t.Fatalf("EncodeTrap: %v", err)
	}
	if got := decodeV3Trap(t, append([]byte(nil), buf[:n]...)).userName; got != "padded" {
		t.Errorf("msgUserName = %q, want %q — Validate trims before measuring, so the wire must "+
			"carry the trimmed name too", got, "padded")
	}
}

// TestV3TrapRefusesInformAtAllThreeLayers is the matrix's "v3 + inform" row.
//
// An SNMPv3 InformRequest is authoritative at the RECEIVER (RFC 3414 §3.1): it
// needs an engine-discovery exchange with each collector and a key localized
// against THAT engine. nl6 has neither, so the combination is refused rather
// than degraded — at startup, at attach, and at fire, the same three layers
// SNMPv1 uses.
func TestV3TrapRefusesInformAtAllThreeLayers(t *testing.T) {
	t.Run("startup", func(t *testing.T) {
		err := trapVersionModeConflict(TrapSNMPv3, "inform")
		if err == nil {
			t.Fatal("trapVersionModeConflict accepted -trap-snmp-version=v3 with -trap-mode=inform")
		}
		// The v1 and v3 refusals must not share a message: the REASONS differ
		// (v1 defines no InformRequest at all; v3 defines one nl6 cannot serve),
		// and an operator reading "no InformRequest-PDU" about v3 would go
		// looking for a spec that says otherwise.
		if !strings.Contains(err.Error(), "RFC 3414") {
			t.Errorf("the v3 refusal reads %q; it should name the receiver-authoritative reason, "+
				"not v1's", err)
		}
		// Every other pairing is fine.
		for _, mode := range []string{"", "trap"} {
			if err := trapVersionModeConflict(TrapSNMPv3, mode); err != nil {
				t.Errorf("v3 + %q was refused: %v", mode, err)
			}
		}
		if err := trapVersionModeConflict(TrapSNMPv2c, "inform"); err != nil {
			t.Errorf("v2c + inform was refused: %v", err)
		}
	})

	t.Run("attach", func(t *testing.T) {
		sm := newTestSimulatorManager()
		if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
			PDUBudget:             maxTrapPDU,
			SNMPVersion:           TrapSNMPv3,
			SNMPv3:                v3TrapTestConfig(SNMPV3_AUTH_MD5, SNMPV3_PRIV_AES128),
			SourcePerDevice:       true,
			MeanSchedulerInterval: time.Hour,
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(sm.StopTrapExport)

		device := setupTestDeviceForAttach(t, sm, "dev-v3-inform", net.IPv4(127, 0, 0, 3))
		device.trapConfig = &DeviceTrapConfig{
			Collector:     "127.0.0.1:16233",
			Mode:          "inform",
			Community:     "public",
			Interval:      jsonDuration(time.Second),
			InformTimeout: jsonDuration(200 * time.Millisecond),
		}
		err := sm.startDeviceTrapExporter(device)
		if err == nil {
			t.Fatal("a REST device asked for mode=inform under a v3 fleet and was ATTACHED")
		}
		if !strings.Contains(err.Error(), "inform") {
			t.Errorf("the attach refusal reads %q; it should name the mode", err)
		}
	})

	t.Run("fire", func(t *testing.T) {
		enc, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 9), SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
		if _, err := enc.EncodeInform("public", 1, v3TrapOID, "", 1, nil, make([]byte, 1024)); err == nil {
			t.Error("EncodeInform returned no error; it is the backstop for a mode this version " +
				"does not serve")
		}
		if _, _, err := enc.ParseAck([]byte{0x30, 0x00}); err == nil {
			t.Error("ParseAck returned no error; nothing acknowledges an SNMPv3 trap")
		}
	})
}

// TestV3TrapAttachBuildsAPerDeviceEncoder drives the real attach path.
//
// The attach site is where the version branch lives, and a missed branch there
// would leave a v3 fleet emitting v2c with every encoder test in this file still
// green — the same shape as nl6#527's dispatcher-versus-direct-call defect.
func TestV3TrapAttachBuildsAPerDeviceEncoder(t *testing.T) {
	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		PDUBudget:             maxTrapPDU,
		SNMPVersion:           TrapSNMPv3,
		SNMPv3:                v3TrapTestConfig(SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128),
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopTrapExport)

	ips := []net.IP{net.IPv4(127, 0, 0, 4), net.IPv4(127, 0, 0, 5)}
	encoders := make([]*SNMPv3TrapEncoder, 0, len(ips))
	for i, ip := range ips {
		device := setupTestDeviceForAttach(t, sm, fmt.Sprintf("dev-v3-%d", i), ip)
		device.trapConfig = &DeviceTrapConfig{
			Collector:     "127.0.0.1:16234",
			Mode:          "trap",
			Community:     "public",
			Interval:      jsonDuration(time.Second),
			InformTimeout: jsonDuration(200 * time.Millisecond),
		}
		if err := sm.startDeviceTrapExporter(device); err != nil {
			t.Fatalf("startDeviceTrapExporter(%s): %v", ip, err)
		}
		device.mu.RLock()
		exp := device.trapExporter
		device.mu.RUnlock()
		if exp == nil {
			t.Fatalf("%s: no exporter after attach", ip)
		}
		v3enc, ok := exp.encoder.(*SNMPv3TrapEncoder)
		if !ok {
			t.Fatalf("%s attached with a %T, not an *SNMPv3TrapEncoder; the fleet is configured v3",
				ip, exp.encoder)
		}
		if want := snmpv3TrapEngineID(ip); !bytes.Equal(v3enc.EngineID(), want) {
			t.Errorf("%s: encoder engine ID = %x, want %x", ip, v3enc.EngineID(), want)
		}
		encoders = append(encoders, v3enc)
	}
	if bytes.Equal(encoders[0].EngineID(), encoders[1].EngineID()) {
		t.Error("both attached devices carry the same engine ID")
	}

	// The v3 encoder must NOT be picked up as a fast encoder: v1 does not
	// implement fastTrapEncoder either, and the fast path is a v2c-only encoder
	// by decision (see encodeV2cNotification).
	if _, isFast := any(encoders[0]).(fastTrapEncoder); isFast {
		t.Error("SNMPv3TrapEncoder implements fastTrapEncoder; the fast path assembles its own v2c " +
			"community envelope and cannot carry a USM message")
	}
}

// TestV3TrapEngineTimeAdvances is the matrix's "engine time" row.
//
// msgAuthoritativeEngineTime is seconds since THIS engine booted (RFC 3414
// §2.2). It was a Unix epoch before nl6#624, which a manager applying the §3.2
// 150-second window rejects outright — so a value that never moves and a value
// that is an epoch are both wrong, and only a two-sample comparison separates
// "small" from "advancing".
func TestV3TrapEngineTimeAdvances(t *testing.T) {
	enc, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 9), SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
	usm := enc.engine.usmState()

	buf := make([]byte, maxTrapPDU)
	n, err := enc.EncodeTrap("", 1, v3TrapOID, "", v3TrapUptime, v3TrapVarbinds, buf)
	if err != nil {
		t.Fatalf("EncodeTrap: %v", err)
	}
	first := decodeV3Trap(t, append([]byte(nil), buf[:n]...))

	// Rewind the engine's boot instant rather than sleeping: the value is a
	// pure function of (now - bootedAt), so moving bootedAt is the same
	// observation without the wall-clock wait.
	usm.bootedAt = usm.bootedAt.Add(-90 * time.Second)

	n, err = enc.EncodeTrap("", 2, v3TrapOID, "", v3TrapUptime, v3TrapVarbinds, buf)
	if err != nil {
		t.Fatalf("EncodeTrap: %v", err)
	}
	second := decodeV3Trap(t, append([]byte(nil), buf[:n]...))

	if second.engineTime <= first.engineTime {
		t.Errorf("msgAuthoritativeEngineTime went %d -> %d; it must advance with the clock",
			first.engineTime, second.engineTime)
	}
	if delta := second.engineTime - first.engineTime; delta < 89 || delta > 92 {
		t.Errorf("engine time advanced by %d seconds for a 90-second rewind; it is not seconds since "+
			"boot", delta)
	}
	if first.boots != second.boots {
		t.Errorf("msgAuthoritativeEngineBoots changed within one process: %d -> %d",
			first.boots, second.boots)
	}
}

// TestV3TrapEngineTimeIsPerDevice is matrix row 5's other half.
//
// TestV3TrapEngineTimeAdvances shows one engine's time moving; it cannot show
// that the time is the DEVICE'S OWN. An originator that read a package-level
// clock — or, worse, the polling engine's — would advance identically and pass
// that test, while every device on the fleet advertised one engine's uptime.
//
// So this rewinds ONE encoder's boot instant and requires the other's advertised
// time to be unmoved.
func TestV3TrapEngineTimeIsPerDevice(t *testing.T) {
	a, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 9), SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)
	b, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 10), SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)

	emit := func(enc *SNMPv3TrapEncoder) decodedV3Trap {
		t.Helper()
		buf := make([]byte, maxTrapPDU)
		n, err := enc.EncodeTrap("", 1, v3TrapOID, "", v3TrapUptime, v3TrapVarbinds, buf)
		if err != nil {
			t.Fatalf("EncodeTrap: %v", err)
		}
		return decodeV3Trap(t, append([]byte(nil), buf[:n]...))
	}

	beforeA, beforeB := emit(a), emit(b)

	// Rewind A's engine only. Single-goroutine, and after the sync.Once
	// derivation has completed, so no other reader exists at this instant —
	// this package runs no test in parallel (see pinPrivSalt's note).
	a.engine.usmState().bootedAt = a.engine.usmState().bootedAt.Add(-120 * time.Second)

	afterA, afterB := emit(a), emit(b)

	if afterA.engineTime-beforeA.engineTime < 119 {
		t.Errorf("device A's engine time moved by %d for a 120-second rewind",
			afterA.engineTime-beforeA.engineTime)
	}
	if afterB.engineTime != beforeB.engineTime {
		t.Errorf("device B's engine time moved from %d to %d when device A's engine was rewound. "+
			"Each device is its OWN authoritative engine (RFC 3414 §2.1); a shared clock would make "+
			"every device on the fleet advertise one engine's uptime",
			beforeB.engineTime, afterB.engineTime)
	}
	if bytes.Equal(beforeA.engineID, beforeB.engineID) {
		t.Error("the two devices share an engine ID, so this test could not have distinguished them")
	}
}

// TestV3TrapEncoderIsSafeForConcurrentFires is a -race pin.
//
// ONE ENCODER IS SHARED BY TWO CALLERS ON A LIVE DEVICE: the syslog/trap
// scheduler fires INLINE for the whole fleet, and POST /api/v1/devices/{ip}/trap
// fires from a net/http handler goroutine, both through the same TrapExporter
// and therefore the same *SNMPv3TrapEncoder. Nothing else in the package
// exercises that, and the encoder holds mutable state (the msgID counter, and
// the engine's lazily-derived USM material).
//
// It asserts a PROPERTY as well as the absence of a race: every msgID drawn
// across every goroutine must be distinct, which a non-atomic counter breaks
// even on a run the detector happens not to flag.
func TestV3TrapEncoderIsSafeForConcurrentFires(t *testing.T) {
	enc, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 9), SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128)

	const goroutines, firesEach = 8, 40
	ids := make(chan int, goroutines*firesEach)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			buf := make([]byte, maxTrapPDU)
			<-start // a handshake, so the fires actually overlap
			for i := 0; i < firesEach; i++ {
				n, err := enc.EncodeTrap("", uint32(g*firesEach+i), v3TrapOID, v3TrapEnterprise,
					v3TrapUptime, v3TrapVarbinds, buf)
				if err != nil {
					t.Errorf("goroutine %d: EncodeTrap: %v", g, err)
					return
				}
				// Read the msgID out of the emitted bytes rather than off the
				// counter, so a torn write is visible on the wire where it
				// matters.
				ids <- decodeV3Trap(t, append([]byte(nil), buf[:n]...)).msgID
			}
		}(g)
	}
	close(start)
	wg.Wait()
	close(ids)

	seen := map[int]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatalf("msgID %d was emitted twice across concurrent fires; the counter is not atomic", id)
		}
		seen[id] = true
	}
	if len(seen) != goroutines*firesEach {
		t.Errorf("%d distinct msgIDs from %d fires", len(seen), goroutines*firesEach)
	}
}

// TestV3TrapMsgIDIsInRangeAndAdvances pins the one envelope input the
// originator supplies out of thin air.
//
// wrapScopedPDUInV3MessageWith documents that it range-checks NOTHING, and RFC
// 3412 types msgID as INTEGER (0..2147483647). A negative or oversized value
// would encode as a multi-octet INTEGER a manager reads as out of range, and
// nothing else in the package would notice.
func TestV3TrapMsgIDIsInRangeAndAdvances(t *testing.T) {
	enc, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 9), SNMPV3_AUTH_NONE, SNMPV3_PRIV_NONE)
	buf := make([]byte, maxTrapPDU)

	// The counter is seeded randomly, so start it somewhere the whole run stays
	// below the 31-bit wrap; advancement is then a plain comparison rather than
	// modular arithmetic, and the wrap itself is asserted separately below.
	enc.nextMsgID.Store(1000)

	seen := map[int]bool{}
	prev := -1
	for i := 0; i < 32; i++ {
		n, err := enc.EncodeTrap("", uint32(i), v3TrapOID, "", v3TrapUptime, v3TrapVarbinds, buf)
		if err != nil {
			t.Fatalf("EncodeTrap: %v", err)
		}
		d := decodeV3Trap(t, append([]byte(nil), buf[:n]...))
		if d.msgID < 0 || d.msgID > snmpv3MsgIDMask {
			t.Fatalf("msgID = %d, outside RFC 3412's 0..%d", d.msgID, snmpv3MsgIDMask)
		}
		if seen[d.msgID] {
			t.Fatalf("msgID %d repeated within %d messages", d.msgID, i+1)
		}
		// ADVANCEMENT, not merely distinctness. An earlier cut tracked `prev`
		// and never compared it, so a generator that emitted 32 distinct
		// values in any order — or one fixed value per fire drawn from a set —
		// satisfied the test the name promises.
		if prev >= 0 && d.msgID != prev+1 {
			t.Fatalf("msgID went %d -> %d; RFC 3412 asks an originator for a value it does not "+
				"reuse, and this one is a counter", prev, d.msgID)
		}
		seen[d.msgID] = true
		prev = d.msgID
	}
	if prev != 1032 {
		t.Fatalf("after 32 fires from a counter at 1000 the msgID is %d, want 1032", prev)
	}

	// The 31-bit wrap is the one place the mask does work. Nothing else in the
	// package reaches it, and an unmasked counter would emit a negative INTEGER
	// after 2^31 fires.
	enc.nextMsgID.Store(snmpv3MsgIDMask)
	n, err := enc.EncodeTrap("", 1, v3TrapOID, "", v3TrapUptime, v3TrapVarbinds, buf)
	if err != nil {
		t.Fatalf("EncodeTrap at the wrap: %v", err)
	}
	if d := decodeV3Trap(t, append([]byte(nil), buf[:n]...)); d.msgID != 0 {
		t.Errorf("the msgID after 0x%X is %d, want 0 — RFC 3412 types it INTEGER (0..%d), so it "+
			"must wrap rather than go negative", snmpv3MsgIDMask, d.msgID, snmpv3MsgIDMask)
	}

	// Two devices must not walk the same sequence from the same start.
	other, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 10), SNMPV3_AUTH_NONE, SNMPV3_PRIV_NONE)
	if other.nextMsgID.Load() == enc.nextMsgID.Load() {
		t.Error("two encoders start from the same msgID; the seed is not random")
	}
}

// TestV3TrapFitsTheDatagramBudgetForEveryShippedEntry measures the USM
// envelope's cost against the shipped catalogs.
//
// A v3 message is the LARGEST of the three formats for one entry: the same PDU,
// plus the engine ID, user name, digest and — under privacy — the cipher's
// padding. The Ciena optical alarms already encode to 989-1000 bytes under v2c
// and are DISABLED below roughly -datagram-mtu 1028, so the headroom the USM
// envelope eats is an operational fact worth pinning rather than discovering.
//
// It also asserts the overhead is BOUNDED: an entry that fits under v2c and not
// under v3 would fire on a v2c fleet and fail silently on a v3 one.
func TestV3TrapFitsTheDatagramBudgetForEveryShippedEntry(t *testing.T) {
	rows := notificationCorpus(t)
	buf := make([]byte, maxTrapPDU)
	v2c := SNMPv2cEncoder{}

	// authPriv under SHA1 is the largest envelope: a 20-octet localized key
	// changes nothing on the wire, but AES pads and the digest is present.
	enc, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 9), SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128)

	encoded, worst, worstLabel := 0, 0, ""
	for _, r := range rows {
		v3n, v3err := enc.EncodeTrap("", 42, r.trapOID, r.enterprise, v3TrapUptime, r.varbinds, buf)
		ref := make([]byte, maxTrapPDU)
		v2n, v2err := v2c.EncodeTrap("public", 42, r.trapOID, r.enterprise, v3TrapUptime, r.varbinds, ref)

		// FAULT PARITY with the reference encoder, and the DIAGNOSIS matters as
		// much as the comparison. Both refuse through encodeNotificationPDU, so
		// an input one accepts and the other refuses means the v3 path grew a
		// rule of its own (nl6#540's lesson, applied to a third encoder) — EXCEPT
		// for one shape that is not a parity break at all: an entry that fits a
		// maxTrapPDU buffer under v2c and does not under v3, which EncodeTrap
		// refuses on the buffer bound before any parity question arises. An
		// earlier cut reported that case as an encodeNotificationPDU
		// disagreement, blaming the shared builder for the USM envelope's ~91
		// bytes, and its own `if v3n > maxTrapPDU` guard was unreachable because
		// the refusal came first.
		if v3err != nil && v2err == nil {
			if strings.Contains(v3err.Error(), "exceeds buffer") {
				t.Errorf("%s: the entry fits the %d B datagram budget under v2c (%d B) and does NOT "+
					"under v3. That is the USM envelope, not encodeNotificationPDU: %v\n"+
					"StartTrapSubsystem sizes the load-time budget at the fleet's own version, so "+
					"such an entry must be DISABLED at load rather than fail at every fire",
					r.label, maxTrapPDU, v2n, v3err)
				continue
			}
		}
		if (v3err == nil) != (v2err == nil) {
			t.Errorf("%s: v3 err=%v but v2c err=%v — both refuse through encodeNotificationPDU and "+
				"must refuse the same inputs", r.label, v3err, v2err)
			continue
		}
		if v3err != nil {
			continue
		}
		if over := v3n - v2n; over > worst {
			worst, worstLabel = over, r.label
		}
		encoded++
	}
	if encoded < 20 {
		t.Fatalf("only %d entries encoded; the corpus walk collapsed", encoded)
	}

	// The overhead is the number the docs quote. A ceiling rather than an
	// equality, because it moves with the user name's length and the cipher's
	// padding, and pinning it exactly would make a longer -trap-snmpv3-user a
	// test failure.
	const maxUSMOverhead = 96
	t.Logf("worst-case USM envelope overhead over v2c: %d bytes (%s), across %d shipped entries",
		worst, worstLabel, encoded)
	if worst > maxUSMOverhead {
		t.Errorf("the USM envelope adds up to %d bytes over v2c (%s), more than the %d this is "+
			"documented at; docs/reference/snmp-traps.md quotes the number", worst, worstLabel,
			maxUSMOverhead)
	}
}

// TestV3TrapDoesNotTouchThePollEngine is the mutation guard the spec names:
// "the poll engine ID used for a trap must fail a test".
//
// The device's polling SNMPServer keeps a FLEET-WIDE engine ID by explicit
// decision, so a trap keyed on it would be identical across every device — and
// every assertion about a single message would still pass. This drives both
// engines side by side and requires them to disagree.
func TestV3TrapDoesNotTouchThePollEngine(t *testing.T) {
	ip := net.IPv4(10, 42, 0, 9)

	// The poll engine, configured the way -snmpv3-engine-id configures it: one
	// value for the whole fleet.
	poll := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "probe"})
	poll.v3Config = &SNMPv3Config{
		Enabled: true, EngineID: defaultSNMPv3EngineID, Username: "polluser",
		Password: "trapauthpassword", AuthProtocol: SNMPV3_AUTH_MD5,
	}
	pollBefore := append([]byte(nil), poll.usmState().engineID...)

	enc, _ := v3TrapEncoderFor(t, ip, SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE)

	if bytes.Equal(enc.EngineID(), pollBefore) {
		t.Fatalf("the trap engine ID equals the poll engine's (%x). The poll identity is fleet-wide "+
			"by decision, so a trap keyed on it makes every device's notification identity the same",
			pollBefore)
	}
	// The poll engine's own state must be untouched by anything the trap
	// encoder did — including the shared usmPasswordToKey cache, which is keyed
	// on (password, hash size) and must not be keyed on an engine ID.
	if !bytes.Equal(poll.usmState().engineID, pollBefore) {
		t.Errorf("the poll engine's ID changed from %x to %x while a trap encoder was built",
			pollBefore, poll.usmState().engineID)
	}
	if bytes.Equal(poll.usmState().authKey, enc.engine.usmState().authKey) {
		t.Error("the poll engine and the trap engine localized the SAME auth key from one password. " +
			"Localization must bind the engine ID, and the shared Ku cache must be keyed on the " +
			"password alone")
	}

	// And the trap encoder must not be reachable FROM the poll server's state:
	// its engine is a separate object, so mutating one cannot move the other.
	if enc.engine == poll {
		t.Fatal("the trap encoder is using the device's polling SNMPServer as its engine")
	}
}

// TestV3TrapBoundsTheCallersBuffer pins the one size rule this encoder owns.
//
// encodeNotificationPDU enforces no budget (its doc comment says so explicitly),
// and the USM envelope is added after it, so an over-budget v3 message would be
// handed to writePDU unchecked. The reference v2c and v1 encoders both bound by
// the caller's buffer; this one must too.
func TestV3TrapBoundsTheCallersBuffer(t *testing.T) {
	enc, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 9), SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128)

	full := make([]byte, maxTrapPDU)
	n, err := enc.EncodeTrap("", 1, v3TrapOID, v3TrapEnterprise, v3TrapUptime, v3TrapVarbinds, full)
	if err != nil {
		t.Fatalf("EncodeTrap into a full-size buffer: %v", err)
	}
	if _, err := enc.EncodeTrap("", 1, v3TrapOID, v3TrapEnterprise, v3TrapUptime, v3TrapVarbinds,
		make([]byte, n-1)); err == nil {
		t.Errorf("a %d-byte message was accepted into a %d-byte buffer", n, n-1)
	}
}

// ── the golden digest ───────────────────────────────────────────────────────

// TestV3TrapOutputIsPinned is the byte-level pin on the new path.
//
// WHY IT EXISTS. Every other test in this file asserts a PROPERTY — the flags
// are right, the digest verifies, the plaintext is the v2c PDU — and a refactor
// of the shared v3 envelope can move every byte of every v3 notification while
// satisfying all of them, because they re-derive their expectations through the
// same code. The four digests in trap_pdu_extraction_test.go cover the POLL path
// and the v1/v2c trap paths; nothing covered this one, so a change to
// wrapScopedPDUInV3MessageWith would have been reported by the net-snmp gate
// alone — and only when someone ran it.
//
// HOW THE CONSTANT WAS MEASURED, and this is the part that gives it value. The
// SNMPv3 trap encoder does not exist at the baseline commit
// e3c53c630e00a396f7972c8b1ab687dc1c08ce8f, so a digest of ITS output cannot be
// taken there — unlike the four in trap_pdu_extraction_test.go, which pin code
// that predates their own change. What CAN be measured at the baseline is every
// input this digest is a function of, and that is what was done: the assembly
// below was reproduced in a worktree at e3c53c6 from the seams already present
// there (encodeNotificationPDU, wrapInScopedPDU, wrapScopedPDUInV3MessageWith on
// a bare SNMPServer carrying the same v3Config), and it produced this value.
//
//	git worktree add /tmp/nl6-baseline-98 e3c53c630e00a396f7972c8b1ab687dc1c08ce8f
//	# copy v3PinnedDigestOverBaselineSeams into a _test.go there, then:
//	cd /tmp/nl6-baseline-98/go && go test ./nl6/ -run V3TrapDigestBaseline -count=1 -v
//
// So the constant is a statement about the SEAMS, measured where they already
// shipped, rather than a number read off the new tree and pasted back. If it
// moves, either the envelope changed or trap_v3.go stopped being a pure
// assembly of those three seams — say which.
//
// TWO INPUTS ARE PINNED so the message is reproducible at all: the privacy salt
// (via pinPrivSalt — an authPriv message is random by construction) and the
// engine's boot instant, zeroed so engineTimeSeconds() answers exactly 0 rather
// than however long the test took.
func TestV3TrapOutputIsPinned(t *testing.T) {
	pinPrivSalt(t, fixedSalt)

	h := sha256.New()
	writes := 0
	for _, row := range v3TrapRows {
		enc, _ := v3TrapEncoderFor(t, net.IPv4(10, 42, 0, 9), row.auth, row.priv)
		// Both varying inputs pinned: the engine's clock and the msgID.
		enc.engine.usmState().bootedAt = time.Time{}
		if got := enc.engine.usmState().engineTimeSeconds(); got != 0 {
			t.Fatalf("engineTimeSeconds() = %d with a zero bootedAt, want 0; this digest would be a "+
				"function of how long the test took", got)
		}

		buf := make([]byte, maxTrapPDU)
		for _, reqID := range []uint32{1, 4242} {
			enc.nextMsgID.Store(0x2A2A - 1) // Add(1) lands on a fixed msgID
			n, err := enc.EncodeTrap("ignored", reqID, v3TrapOID, v3TrapEnterprise,
				v3TrapUptime, v3TrapVarbinds, buf)
			if err != nil {
				t.Fatalf("%s: EncodeTrap: %v", row.name, err)
			}
			h.Write([]byte(row.name + ":"))
			h.Write(buf[:n])
			writes++
		}
	}
	if want := len(v3TrapRows) * 2; writes != want {
		t.Fatalf("digested %d messages, want %d; the sweep collapsed", writes, want)
	}

	const want = "b0530899c4c1484292128a490a3a6452e304e0034108c35b4d9d4493bffcfef0"
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Errorf("the SNMPv3 trap encoding over %d messages digests to %s, measured through the "+
			"baseline commit's own seams as %s.\ntrap_v3.go is a pure assembly of "+
			"encodeNotificationPDU, wrapInScopedPDU and wrapScopedPDUInV3MessageWith; if this moved, "+
			"say which of the three changed, or say that the assembly did", writes, got, want)
	}
}

// ── the shared protocol-name table ──────────────────────────────────────────

// TestUSMProtocolParsersBackTwoFailurePolicies pins ONE table serving TWO
// policies.
//
// nl6#98 made parseAuthProtocol / parsePrivProtocol delegate to the strict
// parseUSMAuthProtocol / parseUSMPrivProtocol so the accepted spellings exist in
// one place. That is a change to the `-snmpv3-*` POLL flags, which the spec puts
// under Ask First: the delegation is behaviour-preserving only if every spelling
// resolves as it did AND the lenient form still falls back instead of failing.
// Nothing asserted either half — neither the strict parsers nor the delegation —
// so this pins both directions:
//
//   - the STRICT form (the -trap-snmpv3-* flags) REPORTS an unknown spelling,
//     because a typo that silently became MD5 would produce a fleet whose
//     notifications no collector can verify, with nothing said;
//   - the LENIENT form (the -snmpv3-* poll flags) falls back to MD5 / none,
//     which is what shipped and what this change must not alter.
//
// Note the two defaults DIFFER — auth falls back to MD5, privacy to none — so a
// test that checked only "it returns something" would miss a swapped fallback.
func TestUSMProtocolParsersBackTwoFailurePolicies(t *testing.T) {
	t.Run("auth/accepted", func(t *testing.T) {
		for in, want := range map[string]int{
			"md5": SNMPV3_AUTH_MD5, "MD5": SNMPV3_AUTH_MD5,
			"sha1": SNMPV3_AUTH_SHA1, "SHA1": SNMPV3_AUTH_SHA1, "sha": SNMPV3_AUTH_SHA1,
			"none": SNMPV3_AUTH_NONE, "": SNMPV3_AUTH_NONE, "NONE": SNMPV3_AUTH_NONE,
		} {
			got, err := parseUSMAuthProtocol(in)
			if err != nil {
				t.Errorf("parseUSMAuthProtocol(%q): %v", in, err)
				continue
			}
			if got != want {
				t.Errorf("parseUSMAuthProtocol(%q) = %d, want %d", in, got, want)
			}
			// The poll flag must resolve identically, or the delegation
			// changed the -snmpv3-auth surface.
			if lenient := parseAuthProtocol(in); lenient != want {
				t.Errorf("parseAuthProtocol(%q) = %d, want %d — the lenient form must agree with the "+
					"table it now delegates to", in, lenient, want)
			}
		}
	})

	t.Run("priv/accepted", func(t *testing.T) {
		for in, want := range map[string]int{
			"des": SNMPV3_PRIV_DES, "DES": SNMPV3_PRIV_DES,
			"aes128": SNMPV3_PRIV_AES128, "aes": SNMPV3_PRIV_AES128, "AES128": SNMPV3_PRIV_AES128,
			"none": SNMPV3_PRIV_NONE, "": SNMPV3_PRIV_NONE,
		} {
			got, err := parseUSMPrivProtocol(in)
			if err != nil {
				t.Errorf("parseUSMPrivProtocol(%q): %v", in, err)
				continue
			}
			if got != want {
				t.Errorf("parseUSMPrivProtocol(%q) = %d, want %d", in, got, want)
			}
			if lenient := parsePrivProtocol(in); lenient != want {
				t.Errorf("parsePrivProtocol(%q) = %d, want %d", in, lenient, want)
			}
		}
	})

	t.Run("rejected/strict-and-lenient", func(t *testing.T) {
		// " sha1" is in here deliberately: NEITHER form trims, so it is
		// rejected by the strict one and falls back by the lenient one. That is
		// exactly what shipped, and trimming in the strict parser would have
		// silently changed -snmpv3-auth's resolution for a padded value.
		for _, in := range []string{"shaa", "sha256", "md-5", " sha1", "1"} {
			if _, err := parseUSMAuthProtocol(in); err == nil {
				t.Errorf("parseUSMAuthProtocol(%q) accepted an unknown spelling", in)
			}
			if got := parseAuthProtocol(in); got != SNMPV3_AUTH_MD5 {
				t.Errorf("parseAuthProtocol(%q) = %d, want the MD5 fallback (%d); the poll flag logs "+
					"and defaults, it does not fail", in, got, SNMPV3_AUTH_MD5)
			}
		}
		for _, in := range []string{"aes256", "3des", "aes-128", " des"} {
			if _, err := parseUSMPrivProtocol(in); err == nil {
				t.Errorf("parseUSMPrivProtocol(%q) accepted an unknown spelling", in)
			}
			if got := parsePrivProtocol(in); got != SNMPV3_PRIV_NONE {
				t.Errorf("parsePrivProtocol(%q) = %d, want the none fallback (%d)",
					in, got, SNMPV3_PRIV_NONE)
			}
		}
	})

	t.Run("names round-trip", func(t *testing.T) {
		// usmAuthProtocolName / usmPrivProtocolName spell what the flags accept,
		// and they reach operators through the status endpoint and the startup
		// log. A spelling the parser would reject is a config an operator cannot
		// copy back.
		for _, p := range []int{SNMPV3_AUTH_NONE, SNMPV3_AUTH_MD5, SNMPV3_AUTH_SHA1} {
			got, err := parseUSMAuthProtocol(usmAuthProtocolName(p))
			if err != nil || got != p {
				t.Errorf("usmAuthProtocolName(%d) = %q, which parses back to (%d, %v)",
					p, usmAuthProtocolName(p), got, err)
			}
		}
		for _, p := range []int{SNMPV3_PRIV_NONE, SNMPV3_PRIV_DES, SNMPV3_PRIV_AES128} {
			got, err := parseUSMPrivProtocol(usmPrivProtocolName(p))
			if err != nil || got != p {
				t.Errorf("usmPrivProtocolName(%d) = %q, which parses back to (%d, %v)",
					p, usmPrivProtocolName(p), got, err)
			}
		}
	})
}

// ── the load-time datagram budget ───────────────────────────────────────────

// v3SizingBandBudget sits inside the band where the shipped Ciena optical alarms
// fit a v2c datagram and do NOT fit a v3 one.
//
// MEASURED, NOT CHOSEN. At the worst-case dry-render context, the four
// opticalPreFecS[DF]{Raise,Clear} entries encode to 989-1000 B under v2c and
// 1080-1091 B under v3 authPriv/SHA1+AES. Any budget in 1000..1079 separates
// them; 1040 is the middle of that band so a few bytes of catalog drift on
// either side does not silently turn this test into a tautology.
const v3SizingBandBudget = 1040

// TestSizeBudgetIsMeasuredAtTheFleetsWireFormat is the regression test for the
// defect nl6#98 shipped and this fixes.
//
// ApplySizeBudget dry-rendered with encodeV2cNotificationFast unconditionally
// while the fire path encoded whatever -trap-snmp-version selected. Under v3 the
// USM envelope adds ~91 bytes, so for a PDUBudget anywhere in the band above, a
// v3 fleet disabled NOTHING, logged NOTHING, and failed at EVERY fire into
// send_failures behind a sync.Once log line.
//
// THE v2c CONTROL IS WHAT MAKES THIS TEST MEAN ANYTHING. Asserting only that the
// Ciena entries are disabled under v3 is satisfied by a budget so low that
// everything is disabled, and by a sizer that always refuses. The control
// requires the SAME budget to leave those same entries ENABLED under v2c.
func TestSizeBudgetIsMeasuredAtTheFleetsWireFormat(t *testing.T) {
	opticalEntries := []string{
		"opticalPreFecSdRaise", "opticalPreFecSdClear",
		"opticalPreFecSfRaise", "opticalPreFecSfClear",
	}

	// A catalog per subtest: ApplySizeBudget MUTATES the entries it disables.
	load := func(t *testing.T) *Catalog {
		t.Helper()
		u, err := LoadEmbeddedCatalog()
		if err != nil {
			t.Fatalf("LoadEmbeddedCatalog: %v", err)
		}
		per, err := ScanPerTypeTrapCatalogs(u, "resources")
		if err != nil {
			t.Fatalf("ScanPerTypeTrapCatalogs: %v", err)
		}
		c := per["ciena_waveserver5"]
		if c == nil {
			t.Fatal("no ciena_waveserver5 catalog; this test has nothing large enough to measure")
		}
		return c
	}

	named := func(disabled []string, name string) bool {
		for _, d := range disabled {
			if strings.Contains(d, name) {
				return true
			}
		}
		return false
	}

	t.Run("v2c control: the same budget leaves them enabled", func(t *testing.T) {
		sizer, err := trapDryRenderSizer(TrapSubsystemConfig{SNMPVersion: TrapSNMPv2c})
		if err != nil {
			t.Fatalf("trapDryRenderSizer: %v", err)
		}
		disabled := load(t).ApplySizeBudgetWith(v3SizingBandBudget, "ciena_waveserver5", sizer)
		for _, name := range opticalEntries {
			if named(disabled, name) {
				t.Errorf("%s was disabled at a %d B budget under v2c, where it encodes to at most "+
					"1000 B. The band this test measures in has moved, so the v3 arm below no longer "+
					"proves anything: re-measure both sizes and pick a new budget", name,
					v3SizingBandBudget)
			}
		}
	})

	t.Run("v3: they are disabled and NAMED", func(t *testing.T) {
		cfg := TrapSubsystemConfig{
			SNMPVersion: TrapSNMPv3,
			SNMPv3:      v3TrapTestConfig(SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128),
		}
		sizer, err := trapDryRenderSizer(cfg)
		if err != nil {
			t.Fatalf("trapDryRenderSizer: %v", err)
		}
		c := load(t)
		disabled := c.ApplySizeBudgetWith(v3SizingBandBudget, "ciena_waveserver5", sizer)
		for _, name := range opticalEntries {
			if !named(disabled, name) {
				t.Errorf("%s was NOT disabled at a %d B budget under v3 authPriv, where it encodes "+
					"to ~1080-1091 B. It would fire on every scheduler tick and fail on every one, "+
					"counted into send_failures behind a sync.Once log line.\ndisabled: %v",
					name, v3SizingBandBudget, disabled)
			}
		}
		// And they are actually unschedulable, not merely reported.
		for _, name := range opticalEntries {
			if e := c.ByName[name]; e != nil && !e.oversized {
				t.Errorf("%s is reported as disabled but its oversized flag is false, so Pick and "+
					"EntriesByRole would still fire it", name)
			}
		}
		// The small entries must survive, or "disabled" is just "everything".
		for _, name := range []string{"linkDown", "linkUp", "coldStart"} {
			if named(disabled, name) {
				t.Errorf("%s was disabled at %d B; it encodes to ~229 B under v3, so the sizer is "+
					"refusing indiscriminately", name, v3SizingBandBudget)
			}
		}
	})

	t.Run("shipped catalogs survive the default MTU under v3", func(t *testing.T) {
		// The positive control at the PRODUCTION budget: nothing may be
		// disabled at the default -datagram-mtu, or v3 would be unusable
		// out of the box.
		u, err := LoadEmbeddedCatalog()
		if err != nil {
			t.Fatalf("LoadEmbeddedCatalog: %v", err)
		}
		per, err := ScanPerTypeTrapCatalogs(u, "resources")
		if err != nil {
			t.Fatalf("ScanPerTypeTrapCatalogs: %v", err)
		}
		per["_universal"] = u
		sizer, err := trapDryRenderSizer(TrapSubsystemConfig{
			SNMPVersion: TrapSNMPv3,
			SNMPv3:      v3TrapTestConfig(SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128),
		})
		if err != nil {
			t.Fatalf("trapDryRenderSizer: %v", err)
		}
		for slug, c := range per {
			if d := c.ApplySizeBudgetWith(maxTrapPDU, slug, sizer); len(d) != 0 {
				t.Errorf("%s: entries disabled at the default MTU under v3: %v", slug, d)
			}
		}
	})
}

// TestV3SizerIsIndependentOfTheProbeDevice pins the assumption dryRenderV3DeviceIP
// rests on: the encoded LENGTH of a v3 notification does not depend on which
// device sends it.
//
// It holds because snmpv3TrapEngineID is 11 octets for every IPv4, the user name
// is fleet-wide, the digest is 12 octets and the salt is 8. If a future engine-ID
// format made the length address-dependent, the load-time budget would be
// measured against the wrong device and this fires.
func TestV3SizerIsIndependentOfTheProbeDevice(t *testing.T) {
	cfg := v3TrapTestConfig(SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128)
	entry := &CatalogEntry{Name: "probe", SnmpTrapOID: v3TrapOID, SnmpTrapEnterprise: v3TrapEnterprise}

	want := -1
	for _, ip := range []net.IP{
		net.IPv4(10, 0, 0, 1), net.IPv4(10, 42, 255, 254),
		net.IPv4(192, 168, 1, 1), net.IPv4(255, 255, 255, 255),
	} {
		saved := dryRenderV3DeviceIP
		dryRenderV3DeviceIP = ip
		sizer, err := v3DryRenderSizer(cfg)
		dryRenderV3DeviceIP = saved
		if err != nil {
			t.Fatalf("%s: v3DryRenderSizer: %v", ip, err)
		}
		got, err := sizer(entry, v3TrapVarbinds, v3TrapUptime)
		if err != nil {
			t.Fatalf("%s: sizer: %v", ip, err)
		}
		if want < 0 {
			want = got
			continue
		}
		if got != want {
			t.Errorf("the same entry sizes to %d B from %s and %d B from another device; the "+
				"load-time budget is measured from one probe address and would be wrong for the rest",
				got, ip, want)
		}
	}
	if want <= 0 {
		t.Fatal("the sweep measured nothing")
	}
}

// TestTrapStatusReportsTheV3Identity pins the one value a receiver cannot
// discover for itself.
//
// A trap carries no engine-discovery exchange, so snmptrapd needs
// `createUser -e <engineID>` BEFORE the first trap arrives — and the engine ID
// is derived, not configured, so it appears in no config file the operator
// wrote. Reporting it is the difference between the feature being usable and
// the operator having to read snmpv3TrapEngineID.
func TestTrapStatusReportsTheV3Identity(t *testing.T) {
	sm := newTestSimulatorManager()
	cfg := v3TrapTestConfig(SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128)
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		PDUBudget:             maxTrapPDU,
		SNMPVersion:           TrapSNMPv3,
		SNMPv3:                cfg,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopTrapExport)

	ip := net.IPv4(127, 0, 0, 8)
	device := setupTestDeviceForAttach(t, sm, "dev-v3-status", ip)
	device.trapConfig = &DeviceTrapConfig{
		Collector: "127.0.0.1:16240", Mode: "trap", Community: "public",
		Interval: jsonDuration(time.Second), InformTimeout: jsonDuration(200 * time.Millisecond),
	}
	if err := sm.startDeviceTrapExporter(device); err != nil {
		t.Fatalf("startDeviceTrapExporter: %v", err)
	}

	st := sm.GetTrapStatus()
	if st.SNMPVersion != "v3" {
		t.Errorf("snmp_version = %q, want %q", st.SNMPVersion, "v3")
	}
	if st.SNMPv3 == nil {
		t.Fatal("snmpv3 block absent from the status body")
	}
	if st.SNMPv3.UserName != cfg.UserName {
		t.Errorf("user = %q, want %q", st.SNMPv3.UserName, cfg.UserName)
	}
	if st.SNMPv3.SecurityLevel != "authPriv" {
		t.Errorf("security_level = %q, want authPriv", st.SNMPv3.SecurityLevel)
	}
	if st.SNMPv3.AuthProtocol != "sha1" || st.SNMPv3.PrivProtocol != "aes128" {
		t.Errorf("protocols = %q/%q, want sha1/aes128", st.SNMPv3.AuthProtocol, st.SNMPv3.PrivProtocol)
	}
	want := hex.EncodeToString(snmpv3TrapEngineID(ip))
	if got := st.SNMPv3.EngineIDsByDevice[ip.String()]; got != want {
		t.Errorf("engine_ids_by_device[%s] = %q, want %q — this is the string `createUser -e 0x...` "+
			"needs, and it is derivable from nothing else the endpoint reports", ip, got, want)
	}
	// The prose description must actually describe THIS derivation, or it is a
	// second statement of the format that can drift from the function.
	for _, frag := range []string{"format 3", "80007ed9", "0242"} {
		if !strings.Contains(st.SNMPv3.EngineIDFormat, frag) {
			t.Errorf("engine_id_format %q does not mention %q", st.SNMPv3.EngineIDFormat, frag)
		}
	}
	if !strings.HasPrefix(want, "80007ed903"+"0242") {
		t.Errorf("the derived engine ID %q does not match the format string beside it", want)
	}

	// A v2c fleet must report neither block, or every operator reading the
	// endpoint sees a v3 identity that does not apply.
	sm2 := newTestSimulatorManager()
	if err := sm2.StartTrapSubsystem(TrapSubsystemConfig{
		PDUBudget: maxTrapPDU, MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm2.StopTrapExport)
	if st2 := sm2.GetTrapStatus(); st2.SNMPVersion != "v2c" || st2.SNMPv3 != nil {
		t.Errorf("a v2c fleet reports snmp_version=%q snmpv3=%+v", st2.SNMPVersion, st2.SNMPv3)
	}
}

// TestWarnTrapVersionFlagsIgnored pins the nl6#445 refusal-to-be-silent.
//
// A flag that is accepted, echoed and ignored is this repo's most-repeated
// defect. `-trap-snmpv3-password` under a v2c fleet is the worst instance of it
// available here, because what the operator gets instead is PLAINTEXT.
func TestWarnTrapVersionFlagsIgnored(t *testing.T) {
	collect := func(version TrapSNMPVersion, v3 TrapV3Config, community string, set bool) string {
		var sb strings.Builder
		warnTrapVersionFlagsIgnored(version, v3, community, set,
			func(f string, a ...any) { fmt.Fprintf(&sb, f+"\n", a...) })
		return sb.String()
	}

	t.Run("v3 credentials under a v2c fleet", func(t *testing.T) {
		got := collect(TrapSNMPv2c, v3TrapTestConfig(SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128), "public", false)
		for _, want := range []string{
			"-trap-snmpv3-user", "-trap-snmpv3-auth", "-trap-snmpv3-priv",
			"-trap-snmpv3-password", "-trap-snmpv3-priv-password", "UNAUTHENTICATED",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the warning does not name %q:\n%s", want, got)
			}
		}
	})

	t.Run("nothing set, nothing said", func(t *testing.T) {
		if got := collect(TrapSNMPv2c, TrapV3Config{}, "public", false); got != "" {
			t.Errorf("a plain v2c fleet warned about something:\n%s", got)
		}
		if got := collect(TrapSNMPv3, v3TrapTestConfig(SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE), "public", false); got != "" {
			t.Errorf("a v3 fleet that did not set -trap-community warned anyway:\n%s", got)
		}
	})

	t.Run("community under v3", func(t *testing.T) {
		got := collect(TrapSNMPv3, v3TrapTestConfig(SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE), "s3cret", true)
		if !strings.Contains(got, "-trap-community") || !strings.Contains(got, "IGNORED") {
			t.Errorf("an explicitly-set -trap-community under v3 was not reported as ignored:\n%s", got)
		}
	})

	t.Run("v1 fleet carrying v3 credentials", func(t *testing.T) {
		// v1 is as plaintext as v2c; the warning must not be v2c-only.
		if got := collect(TrapSNMPv1, v3TrapTestConfig(SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE), "public", false); got == "" {
			t.Error("a v1 fleet carrying -trap-snmpv3-* credentials said nothing")
		}
	})
}

// TestUnrecognisedTrapVersionIsRefused pins that a new enum member cannot
// silently inherit the v2c path.
//
// `encoder` still holds the v2c stand-in at the attach site, and the load-time
// budget still has a v2c sizer, so a fall-through would emit the wrong wire
// format AND size it wrong — both silently.
func TestUnrecognisedTrapVersionIsRefused(t *testing.T) {
	const bogus = TrapSNMPVersion(99)

	if got := bogus.String(); !strings.Contains(got, "99") {
		t.Errorf("TrapSNMPVersion(99).String() = %q; an unrecognised value must name itself rather "+
			"than read as v2c in the startup log", got)
	}
	if _, err := trapDryRenderSizer(TrapSubsystemConfig{SNMPVersion: bogus}); err == nil {
		t.Error("trapDryRenderSizer accepted an unrecognised version; it would size a larger format " +
			"with the v2c measurement, which is the defect nl6#98 fixed for v3")
	}

	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		PDUBudget: maxTrapPDU, SNMPVersion: bogus, MeanSchedulerInterval: time.Hour,
	}); err == nil {
		t.Error("StartTrapSubsystem accepted an unrecognised version")
		sm.StopTrapExport()
	}
}
