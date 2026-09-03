/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"  // #nosec G501 -- RFC 3414 USM mandates HMAC-MD5-96; not a security choice
	"crypto/sha1" // #nosec G505 -- RFC 3414 USM mandates HMAC-SHA-96; not a security choice
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"sync"
	"time"
)

// snmpv3_usm.go — RFC 3414 User-based Security Model primitives, as free
// functions (nl6#624).
//
// Free rather than *SNMPServer methods for two reasons. The trap path
// (nl6#98) needs the same primitives from a different caller, and every one of
// them is a pure function of its inputs, which is what lets them be tested
// against RFC 3414 Appendix A's published vectors instead of against nl6's own
// output.
//
// WHAT WAS WRONG BEFORE. nl6 emitted a 12-byte zero digest and computed no
// HMAC, `AuthProtocol` was read by no code, the two privacy key derivations
// hardcoded opposite hashes (MD5 for DES, SHA1 for AES) instead of using the
// auth protocol's, the AES key came from the auth password rather than the
// privacy password, both IV constructions were non-conformant, and the engine
// ID went on the wire as the ASCII of its hex string while key localization
// used the decoded bytes. Every one of those is a separate interop failure and
// they had to be fixed together: a manager localizes its key with the engine ID
// it RECEIVED, so correcting the digest alone would still have failed.

// usmAuthKeyLen is the digest length each auth protocol localizes to, and
// usmAuthParamsLen the truncation RFC 3414 puts on the wire. Both HMAC-MD5-96
// and HMAC-SHA-96 truncate to 12 octets; only the key length differs.
const usmAuthParamsLen = 12

// usmHashFor returns the hash constructor for an auth protocol, and whether the
// protocol authenticates at all.
func usmHashFor(authProtocol int) (func() hash.Hash, bool) {
	switch authProtocol {
	case SNMPV3_AUTH_MD5:
		return md5.New, true
	case SNMPV3_AUTH_SHA1:
		return sha1.New, true
	default:
		return nil, false
	}
}

// usmPasswordToKey is RFC 3414 §A.2's password-to-key: the password repeated
// into a 1 MB buffer and hashed once.
//
// SPLIT FROM LOCALIZATION DELIBERATELY. This step depends only on the password,
// so a fleet sharing one password computes it once, while localization against
// each device's engine ID is a short hash. Fused, a per-device engine ID would
// repeat a megabyte of hashing per device (nl6#98's design note).
//
// An empty password yields nil rather than a valid-length key of zeros, so a
// misconfiguration fails at the cipher instead of encrypting under a guessable
// key. That behaviour predates this change and is kept.
func usmPasswordToKey(password string, newHash func() hash.Hash) []byte {
	if password == "" || newHash == nil {
		return nil
	}
	const expandTo = 1048576 // RFC 3414 §A.2: exactly 2^20 octets
	pw := []byte(password)
	h := newHash()
	buf := make([]byte, 64)
	for written := 0; written < expandTo; written += len(buf) {
		for i := range buf {
			buf[i] = pw[(written+i)%len(pw)]
		}
		h.Write(buf)
	}
	return h.Sum(nil)
}

// usmLocalizeKey is RFC 3414 §A.2's localization: H(Ku || engineID || Ku).
//
// engineID is the raw ENGINE ID OCTETS, never its hex spelling. Getting that
// wrong is invisible locally and fatal on the wire, because the manager
// localizes with the octets it received.
func usmLocalizeKey(ku, engineID []byte, newHash func() hash.Hash) []byte {
	if len(ku) == 0 || newHash == nil {
		return nil
	}
	h := newHash()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	return h.Sum(nil)
}

// usmAuthDigest computes the msgAuthenticationParameters for a fully assembled
// message whose auth field is already present and zeroed.
//
// RFC 3414 §6.3.1: the digest is HMAC over the WHOLE message with the auth
// field zero-filled to its final length, truncated to 12 octets. It therefore
// cannot be computed before the message exists, which is why the caller
// assembles first and substitutes after.
func usmAuthDigest(wholeMessage, localizedAuthKey []byte, newHash func() hash.Hash) []byte {
	if newHash == nil || len(localizedAuthKey) == 0 {
		return nil
	}
	mac := hmac.New(newHash, localizedAuthKey)
	mac.Write(wholeMessage)
	return mac.Sum(nil)[:usmAuthParamsLen]
}

// usmZeroedAuthParams is the placeholder the assembler writes so the digest can
// be computed over a message of final length.
func usmZeroedAuthParams() []byte { return make([]byte, usmAuthParamsLen) }

// substituteAuthParams overwrites the zeroed auth field in an assembled message
// with the computed digest.
//
// It locates the field by searching for its zeroed form rather than tracking an
// offset through the encoder, and REFUSES when the pattern is not unique. An
// offset threaded through four encoding layers is the kind of thing that goes
// silently wrong on an unrelated edit; an ambiguous match here means the
// message shape changed and the caller must not ship a message whose digest
// might cover the wrong bytes.
func substituteAuthParams(message, digest []byte) ([]byte, error) {
	if len(digest) != usmAuthParamsLen {
		return nil, fmt.Errorf("auth digest is %d octets, want %d", len(digest), usmAuthParamsLen)
	}
	// The field as encodeOctetString writes it: tag, length, then the zeros.
	needle := append([]byte{0x04, usmAuthParamsLen}, usmZeroedAuthParams()...)
	first := bytes.Index(message, needle)
	if first < 0 {
		return nil, fmt.Errorf("zeroed msgAuthenticationParameters not found in the assembled message")
	}
	if bytes.Contains(message[first+1:], needle) {
		return nil, fmt.Errorf("zeroed msgAuthenticationParameters is ambiguous: the pattern occurs " +
			"more than once, so the digest could cover the wrong octets")
	}
	out := make([]byte, len(message))
	copy(out, message)
	copy(out[first+2:], digest)
	return out, nil
}

// usmVerifyAuthDigest checks an inbound message's digest by recomputing it over
// the message with the auth field re-zeroed.
//
// The field is located by the CLAIMED digest, never by searching for zeros: an
// authenticated inbound message carries a real digest there, so a zero-pattern
// search would match some other twelve zero octets in the message and verify a
// digest over the wrong bytes. An ambiguous claimed value is refused for the
// same reason substituteAuthParams refuses one.
//
// Constant-time compare, because a timing oracle on a digest comparison is the
// classic USM implementation mistake even where the simulator's threat model is
// mild.
func usmVerifyAuthDigest(wholeMessage, claimed, localizedAuthKey []byte, newHash func() hash.Hash) bool {
	if len(claimed) != usmAuthParamsLen || len(localizedAuthKey) == 0 || newHash == nil {
		return false
	}
	needle := append([]byte{0x04, usmAuthParamsLen}, claimed...)
	idx := bytes.Index(wholeMessage, needle)
	if idx < 0 || bytes.Contains(wholeMessage[idx+1:], needle) {
		return false
	}
	zeroed := make([]byte, len(wholeMessage))
	copy(zeroed, wholeMessage)
	copy(zeroed[idx+2:], usmZeroedAuthParams())

	want := usmAuthDigest(zeroed, localizedAuthKey, newHash)
	return want != nil && hmac.Equal(want, claimed)
}

// parseEngineIDOctets turns a configured engine ID into the octets that go on
// the wire and into key localization.
//
// Accepts "0x"-prefixed and bare hex, and falls back to the literal bytes of
// the string when it is not hex at all, so an operator who configures a
// non-hex engine ID gets something stable rather than an error at fire time.
// An odd-length hex string is left-padded rather than rejected for the same
// reason.
func parseEngineIDOctets(configured string) []byte {
	s := strings.TrimSpace(configured)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if s == "" {
		return nil
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b
	}
	return []byte(configured)
}

// ── per-server USM state ────────────────────────────────────────────────────

// usmServerState is the material an engine derives once and then reuses.
//
// Derived lazily under sync.Once rather than at construction, because
// SNMPv3Config is assigned after the server is built in several paths and a
// constructor-time derivation would capture an empty password.
type usmServerState struct {
	once        sync.Once
	engineID    []byte
	authKey     []byte // localized, nil when the protocol is none
	privKey     []byte // localized, nil when privacy is off
	newHash     func() hash.Hash
	bootedAt    time.Time
	engineBoots int
}

// usmState returns this server's derived USM material.
//
// PRIVACY KEYS ARE DERIVED WITH THE AUTH PROTOCOL'S HASH, from the PRIVACY
// password with the documented fallback. Both were wrong before nl6#624:
// generateDESKey hardcoded MD5 and generateAESKey hardcoded SHA1 regardless of
// configuration, and the AES path read the auth password. RFC 3414 §2.6 and
// RFC 3826 §3.1.2.1 both localize the privacy key with the authentication
// protocol's digest, so a manager configured md5/aes derives with MD5.
func (s *SNMPServer) usmState() *usmServerState {
	s.usm.once.Do(func() {
		s.usm.bootedAt = time.Now()
		s.usm.engineBoots = 1
		if s.v3Config == nil {
			return
		}
		s.usm.engineID = parseEngineIDOctets(s.v3Config.EngineID)
		newHash, authenticates := usmHashFor(s.v3Config.AuthProtocol)
		if !authenticates {
			return
		}
		s.usm.newHash = newHash
		s.usm.authKey = usmLocalizeKey(
			usmPasswordToKey(s.v3Config.Password, newHash), s.usm.engineID, newHash)

		if s.v3Config.PrivProtocol == SNMPV3_PRIV_NONE {
			return
		}
		privPassword := s.v3Config.PrivPassword
		if privPassword == "" {
			privPassword = s.v3Config.Password
		}
		s.usm.privKey = usmLocalizeKey(
			usmPasswordToKey(privPassword, newHash), s.usm.engineID, newHash)
	})
	return &s.usm
}

// engineTimeSeconds is msgAuthoritativeEngineTime: seconds since this engine
// booted, per RFC 3414 §2.2. It was a Unix epoch before nl6#624, which a
// manager applying the §3.2 150-second window rejects outright.
func (u *usmServerState) engineTimeSeconds() int {
	if u.bootedAt.IsZero() {
		return 0
	}
	return int(time.Since(u.bootedAt).Seconds())
}

// usmTimeWindowSeconds is RFC 3414 §3.2's replay window.
const usmTimeWindowSeconds = 150

// withinTimeWindow reports whether a claimed (boots, time) is acceptable.
func (u *usmServerState) withinTimeWindow(boots, engineTime int) bool {
	if boots != u.engineBoots {
		return false
	}
	delta := engineTime - u.engineTimeSeconds()
	if delta < 0 {
		delta = -delta
	}
	return delta <= usmTimeWindowSeconds
}

// ── inbound verification ────────────────────────────────────────────────────

// authenticateInbound applies RFC 3414 §3.2 to a parsed request, returning the
// usmStats OID to Report when the message must be rejected.
//
// It runs BEFORE decryption. A message whose digest does not verify must not
// have its ciphertext fed to a cipher, and its declared engine time must not be
// trusted to build an IV.
//
// VERIFICATION IS CONDITIONAL ON THE REQUEST'S AUTH FLAG, not on the device's
// configuration. USM authenticates a MESSAGE at the security level that message
// declares; a user holding auth keys may still send noAuthNoPriv, and RFC 3414
// §3.2 step 6 acts only "if the securityLevel specifies that the message is to
// be authenticated". Rejecting an unauthenticated request from a configured-auth
// device would be nl6 inventing a policy the RFC does not state.
func (s *SNMPServer) authenticateInbound(requestData []byte, msg *SNMPv3Message) (string, bool) {
	if msg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_AUTH == 0 {
		return "", true
	}
	usm := s.usmState()
	if usm.newHash == nil || len(usm.authKey) == 0 {
		// The manager asked for authentication and this device has no auth
		// protocol configured. That is a security level the device does not
		// support, not a wrong digest — the same distinction the privacy path
		// already draws (RFC 3414 §3.2 step 5).
		return oidUsmStatsUnsupportedSecLevels, false
	}
	if !usmVerifyAuthDigest(requestData, msg.SecurityParams.AuthParams, usm.authKey, usm.newHash) {
		return oidUsmStatsWrongDigests, false
	}
	// RFC 3414 §3.2 step 7, the 150-second window.
	//
	// nl6 SKIPPED THIS BEFORE nl6#624, and the comment that justified skipping it
	// cited operators with "intentionally skewed clocks". That reason was an
	// artefact of the defect beside it: msgAuthoritativeEngineTime carried a UNIX
	// EPOCH, so a manager's window check against its own clock really was at the
	// mercy of clock skew. The field is seconds since THIS engine booted, a value
	// the manager learns from us by discovery, so wall-clock skew does not enter
	// it and the check is safe to enforce.
	if !usm.withinTimeWindow(msg.SecurityParams.AuthoritativeEngineBoots,
		msg.SecurityParams.AuthoritativeEngineTime) {
		return oidUsmStatsNotInTimeWindows, false
	}
	return "", true
}
