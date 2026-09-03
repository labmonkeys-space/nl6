/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
)

// trap_v3.go — the SNMPv3 notification originator (nl6#98).
//
// An SNMPv3 trap is the SAME SNMPv2-Trap-PDU (0xA7) the v2c path emits, wrapped
// in an RFC 3412 §6 ScopedPDU and an RFC 3414 USM envelope instead of a
// community string. All three of those already exist as seams nl6#627 lifted —
// encodeNotificationPDU, wrapInScopedPDU and wrapScopedPDUInV3MessageWith — so
// this file assembles rather than encodes. It contains NO crypto and NO BER of
// its own; that is the point.
//
// ── WHY THE ENCODER HOLDS AN *SNMPServer ────────────────────────────────────
//
// THIS IS THE ONE DESIGN DECISION IN THE FILE, AND IT IS NOT THE DEVICE'S
// POLLING SERVER. In nl6, `SNMPServer` is RFC 3411's SNMP ENGINE: it is what
// owns `usmServerState` (the engine ID octets, the localized auth and privacy
// keys, the instant engine time counts from) and what the v3 envelope is a
// method on. A notification originator IS an authoritative SNMP engine — RFC
// 3414 §2.1 — with its own engine ID, its own boots and its own time. So the
// encoder holds ONE, private to itself, constructed at trap-attach time from
// the -trap-snmpv3-* configuration and a per-device engine ID.
//
// It is emphatically NOT `device.snmpServer.usmState()`. That engine's ID is
// FLEET-WIDE by explicit decision (`-snmpv3-engine-id` is one value for the
// whole simulator), and a one-line edit to make it per-device would silently
// re-identify every POLLED device — the shipped poll path, whose bytes this
// change must not move. Two engines, two identities, no shared mutable state.
//
// The alternative considered and rejected was parameterising
// wrapScopedPDUInV3MessageWith over an injected `usmServerState`. That reaches
// through `encryptScopedPDUAt`, `encryptDES`, `encryptAES128At`, `padData`,
// `encodeUSMSecurityParameters` and `encodeSNMPv3Message` — six more *SNMPServer
// methods on the shipped poll path — to save one struct literal. nl6#627's
// extraction is done; re-lifting it here is exactly what this change was told
// not to do, and duplicating any of it is what it was told never to do.
//
// ── THE CONSEQUENCE TO DOCUMENT, NOT HIDE ───────────────────────────────────
//
// A collector that POLLS a device over v3 and RECEIVES a trap from it sees TWO
// different snmpEngineID values. That is correct per RFC 3414 — the notification
// originator is authoritative for its own engine — and it is also the first
// thing that looks like a defect when someone debugs it, so it is stated in
// docs/reference/snmp-traps.md as well as here.
//
// ── WHAT IS DELIBERATELY ABSENT ─────────────────────────────────────────────
//
// NO INFORM AND NO ENGINE DISCOVERY. An SNMPv3 InformRequest is RECEIVER
// authoritative: the originator must first discover the collector's engine ID,
// boots and time, then localize a SECOND key per collector and track that
// engine's time window. That is per-collector state this subsystem does not
// have, so `-trap-mode inform` under v3 is REFUSED at startup, at attach, and
// here at fire time — the same three layers SNMPv1 uses (nl6#97).

// snmpv3TrapPEN is the enterprise number the derived engine ID carries.
//
// 32473 is RFC 5612's DOCUMENTATION PEN, held by IANA for examples. It is the
// honest choice and it is the precedent nl6 already set: nl6#588 replaced
// `aws_s3_storage`'s `sysObjectID` of 1.3.6.1.4.1.9999 (which belongs to an
// unrelated German engineering firm) with this same number rather than borrow a
// real vendor's. An engine ID is an IDENTITY CLAIM in exactly the way a
// sysObjectID is, and nl6 has no PEN of its own, so it claims nobody's.
const snmpv3TrapPEN = 32473

// snmpv3EngineIDFormatMAC is the fifth octet of an RFC 3411 §5 SnmpEngineID
// whose remaining octets are a 6-octet IEEE MAC address (format 3).
const snmpv3EngineIDFormatMAC = 0x03

// snmpv3TrapEngineID derives a device's authoritative engine ID from its IPv4.
//
//	80 00 7E D9 | 03 | 02 42 aa bb cc dd        (11 octets)
//	 PEN 32473  |fmt |  the device's own MAC
//
// RFC 3411 §5 format 3 is "the lowest IEEE MAC address of the entity", and nl6
// already synthesises a canonical per-device MAC from the device IP —
// `synthChassisID`, which is what `{{.ChassisID}}` renders and what the LLDP
// provider advertises as this device's chassis ID. Reusing it means the engine
// identity a collector learns from a trap is the SAME identity the device
// asserts everywhere else, rather than a third synthetic namespace.
//
// DERIVED, NOT CONFIGURABLE. Making it settable per device would need new
// per-device state and is out of scope for nl6#98 (it is an "Ask First" item in
// the spec). Derived also means DISTINCT: two devices sharing a user and
// password localize different keys, which is the property the shared-identity
// defects of nl6#588 and nl6#599 are about.
//
// THE SIX MAC OCTETS ARE WRITTEN OUT HERE RATHER THAN TAKEN FROM synthChassisID,
// and saying why is the rule this file follows for anything not shared:
// synthChassisID returns a colon-separated STRING for template rendering, so
// reusing it would mean formatting six bytes and parsing them straight back. The
// two must not drift, so TestV3TrapEngineIDIsRFC3411Format3 compares them —
// asserting the property rather than sharing the code, because the shared thing
// would be worse than either.
//
// Returns nil for anything that is not an IPv4 address. The caller REFUSES in
// that case rather than substituting a default — see NewSNMPv3TrapEncoder.
func snmpv3TrapEngineID(ip net.IP) []byte {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	// The high bit of the first octet marks the RFC 3411 §5 "modern" format, in
	// which the first four octets are the enterprise number. Masking each byte
	// is not decoration: an untyped constant conversion that does not fit a
	// byte is a compile error, so the masks are what let the PEN be written as
	// one readable number above.
	return []byte{
		byte((snmpv3TrapPEN>>24)&0xFF) | 0x80,
		byte((snmpv3TrapPEN >> 16) & 0xFF),
		byte((snmpv3TrapPEN >> 8) & 0xFF),
		byte(snmpv3TrapPEN & 0xFF),
		snmpv3EngineIDFormatMAC,
		0x02, 0x42, v4[0], v4[1], v4[2], v4[3],
	}
}

// snmpv3TrapEngineIDFormat describes the derivation for the status endpoint, so
// an operator can compute any device's identity without polling for it. Kept
// beside snmpv3TrapEngineID so the two cannot drift silently; pinned together by
// TestTrapStatusReportsTheV3Identity.
const snmpv3TrapEngineIDFormat = "RFC 3411 section 5 format 3: " +
	"80007ed9 (PEN 32473) || 03 || 0242 || the device's IPv4 in hex"

// TrapV3Config is the -trap-snmpv3-* flag set: the USM user this fleet's
// notifications are sent as, and the security level they are sent at.
//
// NO ENGINE ID FIELD, deliberately. Each device's engine ID is derived from its
// own address (snmpv3TrapEngineID); a configured one would be shared by the
// fleet, which is the defect the derivation exists to avoid.
type TrapV3Config struct {
	// UserName is msgUserName. Required: USM has no anonymous user, and an
	// empty name is what a discovery request carries, not a notification.
	UserName string
	// AuthProtocol / PrivProtocol are SNMPV3_AUTH_* / SNMPV3_PRIV_*.
	AuthProtocol int
	PrivProtocol int
	// Password is the authentication password; PrivPassword falls back to it,
	// matching usmState's own rule for the poll path.
	Password     string
	PrivPassword string
}

// securityLevel renders the configured level the way net-snmp spells it, for
// log lines and error messages.
func (c TrapV3Config) securityLevel() string {
	switch {
	case c.AuthProtocol == SNMPV3_AUTH_NONE:
		return "noAuthNoPriv"
	case c.PrivProtocol == SNMPV3_PRIV_NONE:
		return "authNoPriv"
	default:
		return "authPriv"
	}
}

// Validate rejects a trap v3 configuration that cannot produce a message.
//
// It defers the auth/priv coupling rules to SNMPv3Config.Validate rather than
// restating them: privacy requires authentication (USM defines no such security
// level, and the privacy key is localized with the AUTH protocol's hash), and
// privacy requires a password. Restating those is how two validators drift.
// IT VALIDATES WHAT THE ORIGINATOR SUPPLIES, because the seams do not. Both
// wrapScopedPDUInV3MessageWith and wrapInScopedPDU document that they check none
// of their inputs — correct for the poll path, whose values come from a request
// the dispatcher already parsed, and not correct here, where every one of them
// is configuration. A protocol constant outside the SNMPV3_* set used to build a
// perfectly good encoder whose every fire then failed.
func (c TrapV3Config) Validate() error {
	if strings.TrimSpace(c.UserName) == "" {
		return fmt.Errorf("trap export: -trap-snmp-version=v3 requires -trap-snmpv3-user: " +
			"USM authenticates a named user and has no anonymous identity")
	}
	// RFC 3414 §2.1 bounds a userName at 32 octets. Measured in OCTETS, not
	// runes: the field is an OCTET STRING and a manager's own buffer is sized in
	// bytes, so a 20-rune name of 3-byte runes is over the limit.
	if n := len(strings.TrimSpace(c.UserName)); n > usmMaxUserNameOctets {
		return fmt.Errorf("trap export: -trap-snmpv3-user is %d octets, over RFC 3414 §2.1's "+
			"limit of %d", n, usmMaxUserNameOctets)
	}
	if _, ok := usmHashFor(c.AuthProtocol); !ok && c.AuthProtocol != SNMPV3_AUTH_NONE {
		return fmt.Errorf("trap export: unknown SNMPv3 authentication protocol %d "+
			"(valid: %d none, %d md5, %d sha1)", c.AuthProtocol,
			SNMPV3_AUTH_NONE, SNMPV3_AUTH_MD5, SNMPV3_AUTH_SHA1)
	}
	switch c.PrivProtocol {
	case SNMPV3_PRIV_NONE, SNMPV3_PRIV_DES, SNMPV3_PRIV_AES128:
	default:
		return fmt.Errorf("trap export: unknown SNMPv3 privacy protocol %d "+
			"(valid: %d none, %d des, %d aes128)", c.PrivProtocol,
			SNMPV3_PRIV_NONE, SNMPV3_PRIV_DES, SNMPV3_PRIV_AES128)
	}
	if c.AuthProtocol != SNMPV3_AUTH_NONE && c.Password == "" {
		return fmt.Errorf("trap export: -trap-snmpv3-auth=%s requires -trap-snmpv3-password",
			usmAuthProtocolName(c.AuthProtocol))
	}
	return c.asV3Config("").Validate()
}

// usmMaxUserNameOctets is RFC 3414 §2.1's bound on msgUserName.
const usmMaxUserNameOctets = 32

// asV3Config projects the trap configuration onto the SNMPv3Config the engine
// derives its material from. engineIDHex is the per-device identity.
func (c TrapV3Config) asV3Config(engineIDHex string) *SNMPv3Config {
	return &SNMPv3Config{
		Enabled:      true,
		EngineID:     engineIDHex,
		Username:     c.UserName,
		Password:     c.Password,
		PrivPassword: c.PrivPassword,
		AuthProtocol: c.AuthProtocol,
		PrivProtocol: c.PrivProtocol,
	}
}

// SNMPv3TrapEncoder emits RFC 3416 SNMPv2-Trap-PDUs inside an RFC 3414 USM
// envelope. PER DEVICE, like SNMPv1Encoder and for a stronger reason: the
// engine identity and the keys localized against it are per-device state.
type SNMPv3TrapEncoder struct {
	// engine is this originator's OWN SNMP engine — see the file header. It
	// carries no device, no listener and no resources; it exists to own
	// usmServerState and to be the receiver the lifted v3 envelope is a method
	// on.
	engine *SNMPServer

	// engineID is the derived identity, cached so EncodeTrap does not go
	// through usmState() for the scoped PDU's contextEngineID.
	engineID []byte

	// userName is msgUserName, and msgFlags is the security level every message
	// this encoder emits is sent at. Both are fixed for the encoder's life: USM
	// gives a notification no way to negotiate either.
	userName string
	msgFlags byte

	// nextMsgID is RFC 3412's msgID, which is the originator's own and is NOT
	// the PDU's request-id. Seeded randomly so two devices do not walk the same
	// sequence, and masked to 31 bits because RFC 3412 types it
	// INTEGER (0..2147483647) — wrapScopedPDUInV3MessageWith documents that it
	// range-checks nothing, so the originator must.
	nextMsgID atomic.Uint32
}

// snmpv3MsgIDMask keeps a generated msgID inside RFC 3412's 0..2^31-1.
const snmpv3MsgIDMask = 0x7FFFFFFF

// NewSNMPv3TrapEncoder builds a device's notification originator.
//
// IT REFUSES AN EMPTY ENGINE IDENTITY, which is the question nl6#627 left open
// and this change had to DECIDE rather than inherit. `wrapInScopedPDU` accepts
// a nil engine ID and `usmState` silently substitutes `defaultSNMPv3EngineID`
// when the configured one is empty — both are right for their callers and both
// are wrong here. A notification originator that names no authoritative engine,
// or names the same default one as every other device, hands the collector an
// identity it cannot localize a distinct key against: the shared-identity
// defect nl6#588 and nl6#599 each had to correct once already. So a device
// whose address is not IPv4 gets NO v3 trap encoder and an error at attach.
//
// The substitution is checked rather than assumed: usmState() runs here (its
// sync.Once derivation is the one localization this costs) and the engine ID it
// settled on must be the derived one byte for byte. Without that check, a
// future change to usmState's empty-ID fallback would silently re-share the
// identity across the fleet with every test in this file still green.
func NewSNMPv3TrapEncoder(deviceIP net.IP, cfg TrapV3Config) (*SNMPv3TrapEncoder, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	engineID := snmpv3TrapEngineID(deviceIP)
	if len(engineID) == 0 {
		return nil, fmt.Errorf("trap export: cannot derive an SNMPv3 engine ID for device %q: "+
			"the identity is derived from the device's IPv4 address (RFC 3411 §5 format 3), and a "+
			"notification originator that names no authoritative engine cannot be authenticated "+
			"against", deviceIP)
	}

	enc := &SNMPv3TrapEncoder{
		engine:   &SNMPServer{v3Config: cfg.asV3Config(hex.EncodeToString(engineID))},
		engineID: engineID,
		// TRIMMED, so the name on the wire is the one Validate measured and
		// approved. Storing it raw let a shell-quoting accident put leading
		// whitespace into msgUserName, which a collector matches literally.
		userName: strings.TrimSpace(cfg.UserName),
	}
	if cfg.AuthProtocol != SNMPV3_AUTH_NONE {
		enc.msgFlags |= SNMPV3_MSG_FLAG_AUTH
	}
	if cfg.PrivProtocol != SNMPV3_PRIV_NONE {
		enc.msgFlags |= SNMPV3_MSG_FLAG_PRIV
	}

	usm := enc.engine.usmState()
	if !bytes.Equal(usm.engineID, engineID) {
		return nil, fmt.Errorf("trap export: the engine derived identity %x but this device's is %x; "+
			"a notification originator must key on its OWN engine ID, and a fleet-wide substitute "+
			"makes every device's localized key identical", usm.engineID, engineID)
	}
	if cfg.AuthProtocol != SNMPV3_AUTH_NONE && len(usm.authKey) == 0 {
		return nil, fmt.Errorf("trap export: SNMPv3 authentication is configured (%s) but no key could "+
			"be localized; check -trap-snmpv3-password", cfg.securityLevel())
	}
	if cfg.PrivProtocol != SNMPV3_PRIV_NONE && len(usm.privKey) < 16 {
		return nil, fmt.Errorf("trap export: SNMPv3 privacy is configured (%s) but no key could be "+
			"localized; check -trap-snmpv3-priv-password", cfg.securityLevel())
	}

	// #nosec G404 -- msgID is a correlation number for a message nothing
	// answers; it is not a secret and RFC 3412 asks only that it not repeat
	// inside a short window.
	enc.nextMsgID.Store(uint32(rand.Int31()))
	return enc, nil
}

// EngineID returns the derived authoritative engine ID octets. Exposed for the
// status/log surfaces and for tests that must compare two devices' identities.
func (e *SNMPv3TrapEncoder) EngineID() []byte {
	return append([]byte(nil), e.engineID...)
}

// msgID draws the next RFC 3412 message identifier.
func (e *SNMPv3TrapEncoder) msgID() int {
	return int(e.nextMsgID.Add(1) & snmpv3MsgIDMask)
}

// EncodeTrap — see TrapEncoder.
//
// community is IGNORED and that is not an oversight: there is no community
// string anywhere in an SNMPv3 message, exactly as SNMPv1Encoder ignores reqID
// because a Trap-PDU has no request-id field. Widening the interface would put a
// parameter meaningless to v2c on the hot path this change must leave
// byte-identical.
//
// THE ASSEMBLY IS THREE LIFTED SEAMS AND NOTHING ELSE:
//
//	encodeNotificationPDU  -> the identical 0xA7 PDU the v2c encoder emits
//	wrapInScopedPDU        -> RFC 3412 §6, contextEngineID = our own engine ID
//	wrapScopedPDU...With   -> RFC 3414 USM: encrypt, assemble, digest, substitute
//
// ONE CLOCK SAMPLE FOR THE WHOLE MESSAGE is a property of the third seam, not of
// this function: it reads boots and time once and passes them to both the AES IV
// and msgAuthoritativeEngineTime. Two reads shipped an IV built from T while
// advertising T+1, with every in-package test green (see encryptScopedPDUAt).
func (e *SNMPv3TrapEncoder) EncodeTrap(_ string, reqID uint32, trapOID, enterpriseOID string,
	uptimeHundredths uint32, varbinds []Varbind, buf []byte) (int, error) {
	pdu, err := encodeNotificationPDU(ASN1_TRAP_V2C, reqID, trapOID, enterpriseOID,
		uptimeHundredths, varbinds)
	if err != nil {
		return 0, err
	}

	// contextEngineID is the originator's own engine ID (RFC 3412 §6.3.1); the
	// default context name is the empty string.
	scoped := wrapInScopedPDU(e.engineID, "", pdu)

	msg, err := e.engine.wrapScopedPDUInV3MessageWith(scoped, e.msgID(), e.msgFlags, e.userName)
	if err != nil {
		return 0, fmt.Errorf("snmpv3 trap: %w", err)
	}

	// Bounded by the caller's buffer, the same way the v2c and v1 reference
	// encoders are. encodeNotificationPDU enforces no budget of its own, and
	// the USM envelope adds engine ID, user name, digest and — under privacy —
	// cipher padding on top of the PDU, so the v3 message is the largest of the
	// three for one catalog entry.
	if len(msg) > len(buf) {
		return 0, fmt.Errorf("encoded SNMPv3 trap (%d bytes) exceeds buffer (%d); the USM envelope "+
			"adds roughly %d bytes to the same PDU a v2c trap carries", len(msg), len(buf), len(msg)-len(pdu))
	}
	return copy(buf, msg), nil
}

// EncodeInform always fails.
//
// An SNMPv3 InformRequest is RECEIVER-authoritative (RFC 3414 §3.1): the
// originator must discover the COLLECTOR's engine ID, boots and time, localize a
// second key against that engine, and track its time window per collector. None
// of that state exists here, and inventing an inform that authenticates against
// our OWN engine would be a message no collector accepts.
//
// Startup and attach refuse the flag combination that reaches here, so this is
// the backstop rather than the diagnosis — the same three-layer arrangement
// SNMPv1 uses (nl6#97).
func (*SNMPv3TrapEncoder) EncodeInform(string, uint32, string, string, uint32, []Varbind, []byte) (int, error) {
	return 0, fmt.Errorf("SNMPv3 InformRequest is not implemented: an inform is authoritative at the " +
		"RECEIVER, so it needs an engine-discovery exchange and a key localized against each " +
		"collector's engine. Use -trap-mode=trap, or -trap-snmp-version=v2c")
}

// ParseAck always fails: nothing acknowledges an SNMPv3 trap, so a datagram
// arriving on the trap socket is not an ack. Same reasoning as EncodeInform.
func (*SNMPv3TrapEncoder) ParseAck([]byte) (uint32, bool, error) {
	return 0, false, fmt.Errorf("SNMPv3 traps are never acknowledged; there is no ack to parse")
}

// usmAuthProtocolName spells an SNMPV3_AUTH_* constant the way the flags do.
func usmAuthProtocolName(p int) string {
	switch p {
	case SNMPV3_AUTH_MD5:
		return "md5"
	case SNMPV3_AUTH_SHA1:
		return "sha1"
	default:
		return "none"
	}
}

// usmPrivProtocolName spells an SNMPV3_PRIV_* constant the way the flags do.
func usmPrivProtocolName(p int) string {
	switch p {
	case SNMPV3_PRIV_DES:
		return "des"
	case SNMPV3_PRIV_AES128:
		return "aes128"
	default:
		return "none"
	}
}

// parseUSMAuthProtocol is the STRICT auth-protocol parser: it reports an
// unknown spelling rather than substituting one.
//
// It is the single table. parseAuthProtocol (simulator.go) delegates to it and
// keeps its own log-and-default behaviour for the -snmpv3-auth poll flag, which
// this change must not alter. The trap flags use the strict form directly,
// because a typo'd -trap-snmpv3-auth that silently became MD5 would produce a
// fleet whose notifications no collector can verify, with nothing said.
//
// IT DOES NOT TRIM, and that is deliberate rather than sloppy: the lenient form
// never did either, so delegating preserves the poll flag's accepted spellings
// exactly. Trimming here would make `-snmpv3-auth " sha1"` resolve to SHA1
// where it resolves to MD5 today — a change to the SNMPv3 poll path's flag
// handling, which is out of this change's scope.
func parseUSMAuthProtocol(proto string) (int, error) {
	switch strings.ToLower(proto) {
	case "md5":
		return SNMPV3_AUTH_MD5, nil
	case "sha1", "sha":
		return SNMPV3_AUTH_SHA1, nil
	case "none", "":
		return SNMPV3_AUTH_NONE, nil
	default:
		return 0, fmt.Errorf("unknown SNMPv3 authentication protocol %q (valid: none, md5, sha1)", proto)
	}
}

// parseUSMPrivProtocol is the strict privacy-protocol parser. See
// parseUSMAuthProtocol.
func parseUSMPrivProtocol(proto string) (int, error) {
	switch strings.ToLower(proto) {
	case "des":
		return SNMPV3_PRIV_DES, nil
	case "aes128", "aes":
		return SNMPV3_PRIV_AES128, nil
	case "none", "":
		return SNMPV3_PRIV_NONE, nil
	default:
		return 0, fmt.Errorf("unknown SNMPv3 privacy protocol %q (valid: none, des, aes128)", proto)
	}
}
