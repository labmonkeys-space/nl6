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
	"math"
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

// usmAuthParamsLen is the truncation RFC 3414 puts on the wire. Both
// HMAC-MD5-96 and HMAC-SHA-96 truncate to 12 octets; only the localized key
// length differs (16 for MD5, 20 for SHA1), and that is read from the hash
// rather than named by a constant.
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
	// SHARED ACROSS DEVICES, which is the reason this step is split from
	// localization at all. Ku depends only on the password and the hash, and
	// the expansion is a megabyte of hashing — measured at ~2.1 ms/op. Held
	// per device it ran once per SNMPServer, twice when privacy is on, so a
	// 30,000-device v3 fleet spent roughly two CPU-minutes on an intermediate
	// that is identical for every one of them, inline on the shared UDP
	// handler at each device's first poll. The comment above this function
	// already claimed a fleet computed it once; now that is true.
	//
	// Keyed on the hash's OUTPUT SIZE as well as the password: two protocols
	// with one password must not share an entry, and size distinguishes the
	// two RFC 3414 protocols without needing a name.
	type kuKey struct {
		password string
		hashSize int
	}
	key := kuKey{password, newHash().Size()}
	if cached, ok := usmKuCache.Load(key); ok {
		return append([]byte(nil), cached.([]byte)...)
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
	ku := h.Sum(nil)
	// A copy is stored and a copy is returned, so a caller that localizes in
	// place cannot corrupt the shared entry.
	usmKuCache.Store(key, append([]byte(nil), ku...))
	return ku
}

// usmKuCache holds the password-to-key intermediates. Unbounded, which is safe
// because the key space is the set of CONFIGURED passwords: a fleet has a
// handful, and nothing an SNMP peer sends can add an entry.
var usmKuCache sync.Map

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

// locateAuthParams finds msgAuthenticationParameters in an assembled SNMPv3
// message by WALKING ITS STRUCTURE, returning the offset and length of the
// field's content.
//
// IT USED TO BE A BYTE SEARCH, AND THAT WAS A REACHABLE DEFECT rather than a
// theoretical one. The needle `04 0C` followed by twelve zeros is exactly how
// an OCTET STRING value of twelve zero bytes encodes, so a device serving such
// a value made the search ambiguous, made substitution refuse, and made the
// whole response fail to assemble: an authNoPriv GET of that OID returned
// NOTHING. The comment that argued a search was safer than tracking an offset
// had the trade backwards — an offset can go stale, but a search can be
// defeated by the message's own data, and only one of those is reachable by
// an operator's resource file.
//
// A structural walk has neither problem. Nothing here depends on the message's
// byte content, only on its shape:
//
//	SEQUENCE { version INTEGER, msgGlobalData SEQUENCE,
//	           msgSecurityParameters OCTET STRING {
//	               SEQUENCE { engineID OCTET STRING, boots INTEGER,
//	                          time INTEGER, userName OCTET STRING,
//	                          msgAuthenticationParameters OCTET STRING, ... } }, ... }
func locateAuthParams(message []byte) (offset, length int, ok bool) {
	// readTLV returns the content bounds of the TLV at pos and the position
	// just past it. Every bound is written `n > len(buf)-start` rather than
	// `start+n > len(buf)` because parseLength accepts a four-octet long form
	// whose addition can wrap on a 32-bit build (the nl6#537 rule).
	readTLV := func(buf []byte, pos int) (tag byte, start, end, next int, ok bool) {
		if pos < 0 || pos >= len(buf) {
			return 0, 0, 0, 0, false
		}
		tag = buf[pos]
		n, contentStart := parseLength(buf, pos+1)
		if n < 0 || contentStart < 0 || contentStart > len(buf) || n > len(buf)-contentStart {
			return 0, 0, 0, 0, false
		}
		return tag, contentStart, contentStart + n, contentStart + n, true
	}

	_, start, end, _, ok := readTLV(message, 0)
	if !ok {
		return 0, 0, false
	}
	pos := start
	// version INTEGER, then msgGlobalData SEQUENCE.
	for i := 0; i < 2; i++ {
		_, _, _, next, ok := readTLV(message[:end], pos)
		if !ok {
			return 0, 0, false
		}
		pos = next
	}
	// msgSecurityParameters OCTET STRING, whose content is the USM SEQUENCE.
	_, secStart, secEnd, _, ok := readTLV(message[:end], pos)
	if !ok {
		return 0, 0, false
	}
	_, usmStart, usmEnd, _, ok := readTLV(message[:secEnd], secStart)
	if !ok {
		return 0, 0, false
	}
	// engineID, boots, time, userName — then the auth field.
	pos = usmStart
	for i := 0; i < 4; i++ {
		_, _, _, next, ok := readTLV(message[:usmEnd], pos)
		if !ok {
			return 0, 0, false
		}
		pos = next
	}
	tag, authStart, authEnd, _, ok := readTLV(message[:usmEnd], pos)
	if !ok || tag != ASN1_OCTET_STRING {
		return 0, 0, false
	}
	return authStart, authEnd - authStart, true
}

// substituteAuthParams overwrites the auth field in an assembled message with
// the computed digest, leaving every other octet untouched.
func substituteAuthParams(message, digest []byte) ([]byte, error) {
	if len(digest) != usmAuthParamsLen {
		return nil, fmt.Errorf("auth digest is %d octets, want %d", len(digest), usmAuthParamsLen)
	}
	off, n, ok := locateAuthParams(message)
	if !ok {
		return nil, fmt.Errorf("could not locate msgAuthenticationParameters in the assembled message")
	}
	if n != usmAuthParamsLen {
		return nil, fmt.Errorf("msgAuthenticationParameters is %d octets, want %d: the placeholder must "+
			"be written at its final length so the digest covers a message of the right size", n, usmAuthParamsLen)
	}
	out := make([]byte, len(message))
	copy(out, message)
	copy(out[off:], digest)
	return out, nil
}

// usmVerifyAuthDigest checks an inbound message's digest by recomputing it over
// the message with the auth field re-zeroed.
//
// The field is located STRUCTURALLY, not by searching for the claimed value,
// for the reason locateAuthParams documents.
//
// Constant-time compare, because a timing oracle on a digest comparison is the
// classic USM implementation mistake even where the simulator's threat model is
// mild.
func usmVerifyAuthDigest(wholeMessage, claimed, localizedAuthKey []byte, newHash func() hash.Hash) bool {
	if len(claimed) != usmAuthParamsLen || len(localizedAuthKey) == 0 || newHash == nil {
		return false
	}
	off, n, ok := locateAuthParams(wholeMessage)
	if !ok || n != usmAuthParamsLen {
		return false
	}
	// The located field must BE the claimed value, so a message that carries
	// its digest somewhere else is refused rather than verified against bytes
	// the caller never saw.
	if !bytes.Equal(wholeMessage[off:off+n], claimed) {
		return false
	}
	zeroed := make([]byte, len(wholeMessage))
	copy(zeroed, wholeMessage)
	copy(zeroed[off:], usmZeroedAuthParams())

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
	// Not hex at all: use the trimmed literal. Returning the ORIGINAL string
	// here put back the "0x" prefix and the surrounding whitespace this
	// function had just removed, so the octets depended on formatting that was
	// meant to be insignificant.
	return []byte(strings.TrimSpace(configured))
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
		if len(s.usm.engineID) == 0 {
			// A zero-length msgAuthoritativeEngineID is not a legal engine
			// identity (RFC 3411 wants 5-32 octets) and, worse, it is what
			// a manager keys its localized key on — so discovery would
			// hand out an identity that cannot be localized against.
			// nl6 substitutes its documented default rather than emitting
			// nothing. Lengths outside 5..32 are left alone: nl6's own
			// fixtures use shorter ones and refusing them would break
			// working configurations for a conformance point no manager
			// enforces.
			s.usm.engineID = parseEngineIDOctets(defaultSNMPv3EngineID)
		}
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
	// RANGE-CHECK BEFORE NEGATING. msgAuthoritativeEngineTime is an unsigned
	// 32-bit value in RFC 3414 §2.2, so anything outside that range is not a
	// time at all — and negating math.MinInt is a no-op, so a declared
	// MinInt sailed through the |delta| <= 150 test below on a value that is
	// as far from the window as an integer can be.
	if engineTime < 0 || engineTime > math.MaxUint32 {
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
		// PRIVACY WITHOUT AUTHENTICATION IS NOT A SECURITY LEVEL (RFC 3414
		// §3.2 step 5). Letting it through would decrypt using boots and time
		// this engine has not verified, which is the input to the AES IV.
		if msg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_PRIV != 0 {
			return oidUsmStatsUnsupportedSecLevels, false
		}
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
