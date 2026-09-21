/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"strconv"
	"strings"
)

// SNMP SetRequest (0xA3) — add-snmp-set, nl6#684.
//
// Before this file a v1/v2c SET fell through handleSNMPv2cRequest's GET branch
// and was answered with the object's CURRENT value under noError, and a v3 SET
// was discarded by the nl6#547 gate. Neither is an SNMP answer. Every SET is now
// answered: a binding on an object nl6 does not write is refused with the RFC
// 3416 §4.2.5 error-status (RFC 3584 §4.3-mapped for v1), and a binding on the
// one writable object is applied through the interface-state engine's funnel.
//
// The writable set is CURATED here, one row with a reason, never derived from a
// type table: writability is a MAX-ACCESS property no nl6 rule models
// (nl6#591), so an object is writable only when someone has decided it is.

// writableObject is one row of the writable set: a table COLUMN whose
// instances (column.<N>) accept a SET.
type writableObject struct {
	// column is the dotted OID of the column, without the instance suffix
	// and without a leading dot.
	column string
	// tag is the ASN.1 tag a value must carry (RFC 3416 §4.2.5 test 3).
	tag byte
	// inRange decides RFC 3416 §4.2.5 test 6: a value the object could hold
	// under SOME circumstance.
	inRange func(v int) bool
	// reason is why this row exists. Mandatory, like every curated table in
	// this package.
	reason string
}

// writableColumns is the whole writable set. ONE row. sysName / sysLocation /
// sysContact are candidates nothing has asked for; ifOperStatus is read-only in
// RFC 2863; cycler-owned counters are analytic and have no value to set.
var writableColumns = []writableObject{
	{
		column:  "1.3.6.1.2.1.2.2.1.7", // IF-MIB ifAdminStatus, MAX-ACCESS read-write
		tag:     ASN1_INTEGER,
		inRange: func(v int) bool { return v >= int(AdminUp) && v <= int(AdminTesting) },
		reason: "RFC 2863 ifAdminStatus is read-write and its up/down/testing values " +
			"are exactly the interface-state engine's AdminUp..AdminTesting; a SET " +
			"drives the same funnel the REST admin-status POST does (nl6#684)",
	},
}

// ifAdminStatusColumn is the one shipped writable column, named so the apply
// step can dispatch on it without re-reading the table.
const ifAdminStatusColumn = "1.3.6.1.2.1.2.2.1.7"

// setVerdict is what the ladder decided for a whole SetRequest: an RFC 3416
// error-status (snmpErrNoError on success) and the 1-based error-index of the
// first offending binding (0 on success).
type setVerdict struct {
	errStatus int
	errIndex  int
}

// setAction is one validated binding, ready to apply.
type setAction struct {
	column  string
	ifIndex int
	value   int
}

// writableFor returns the writable row whose column PREFIXES name on a
// sub-identifier boundary, and the instance suffix after it ("" for the bare
// column). ok is false when no row matches, which is RFC 3416 §4.2.5 test 2's
// notWritable.
func writableFor(name string) (row writableObject, suffix string, ok bool) {
	n := strings.TrimPrefix(name, ".")
	for _, w := range writableColumns {
		if n == w.column {
			return w, "", true
		}
		if strings.HasPrefix(n, w.column+".") {
			return w, n[len(w.column)+1:], true
		}
	}
	return writableObject{}, "", false
}

// instanceIndex parses the instance suffix of a writable column as exactly ONE
// positive sub-identifier. Anything else — the bare column, two sub-ids, a
// zero — is a variable that could never be created (RFC 3416 §4.2.5 test 7,
// noCreation), not a non-writable one.
func instanceIndex(suffix string) (int, bool) {
	if suffix == "" || strings.Contains(suffix, ".") {
		return 0, false
	}
	n, err := strconv.Atoi(suffix)
	if err != nil || n <= 0 || strconv.Itoa(n) != suffix {
		return 0, false
	}
	return n, true
}

// validateSetBindings runs RFC 3416 §4.2.5's per-binding tests, IN THE RFC'S
// ORDER, over every binding and stops at the first failure. Nothing is applied
// here: a request in which any binding fails must mutate nothing ("as if
// simultaneously"), so validation of the whole list precedes any apply.
//
// Order is load-bearing and pinned: the VALUE tests (3, 5, 6) come before the
// INSTANCE test (7), so `ifAdminStatus.999 = 7` is wrongValue, not noCreation.
// Tests 1 (noAccess: nl6 has no MIB views), 4 (wrongLength: INTEGER has no
// declared length), 8 and 10 (inconsistentName/Value: no row creation) cannot
// arise with one INTEGER column and are not encoded.
func (s *SNMPServer) validateSetBindings(binds []snmpVarBind) ([]setAction, setVerdict) {
	actions := make([]setAction, 0, len(binds))
	for i, b := range binds {
		idx := i + 1

		// (2) No writable variable shares this name's prefix → notWritable.
		row, suffix, ok := writableFor(b.name)
		if !ok {
			return nil, setVerdict{snmpErrNotWritable, idx}
		}
		// (3) Wrong ASN.1 type for the object → wrongType.
		if b.tag != row.tag {
			return nil, setVerdict{snmpErrWrongType, idx}
		}
		// (5) Content that is not a valid encoding of the declared type →
		// wrongEncoding. parseBERInt refuses an empty content and one wider
		// than 8 significant octets; it is the reader every other INTEGER on
		// the serve path already uses.
		v, ok := parseBERInt(b.content, 0, len(b.content))
		if !ok {
			return nil, setVerdict{snmpErrWrongEncoding, idx}
		}
		// (6) A value the object could never hold → wrongValue.
		if !row.inRange(v) {
			return nil, setVerdict{snmpErrWrongValue, idx}
		}
		// (7) An instance that does not exist and could never be created →
		// noCreation. Wrong arity under the column is this case too.
		n, ok := instanceIndex(suffix)
		if !ok || !s.ownsIfIndex(n) {
			return nil, setVerdict{snmpErrNoCreation, idx}
		}
		actions = append(actions, setAction{column: row.column, ifIndex: n, value: v})
	}
	return actions, setVerdict{snmpErrNoError, 0}
}

// interfaceState returns the device's state engine, or nil when the device
// has none. Same walk findResponse uses for the IF-MIB columns.
func (s *SNMPServer) interfaceState() *InterfaceState {
	if s.device == nil || s.device.metricsCycler == nil {
		return nil
	}
	ic := s.device.metricsCycler.ifCounters.Load()
	if ic == nil {
		return nil
	}
	return ic.State()
}

// ownsIfIndex reports whether the device's interface engine knows ifIndex n,
// the same set the REST handler validates against (ErrIfStateIfIndexInvalid).
func (s *SNMPServer) ownsIfIndex(n int) bool {
	if s.device == nil || s.device.metricsCycler == nil {
		return false
	}
	ic := s.device.metricsCycler.ifCounters.Load()
	if ic == nil {
		return false
	}
	for _, i := range ic.IfIndices() {
		if i == n {
			return true
		}
	}
	return false
}

// applySetActions performs every validated assignment. Each ifAdminStatus SET
// goes through InterfaceState.ApplyAdminStatus — the SAME funnel the REST
// admin-status POST uses — and broadcasts every event it returns, so a gNMI
// ON_CHANGE listener and the Tier C notify hook cannot tell a SET from a POST.
//
// The only apply is a CAS loop on an atomic slot, which cannot fail once the
// instance exists, so commitFailed / undoFailed are unreachable. A device whose
// engine vanished between validate and apply answers genErr rather than
// panicking on the UDP handler, which has no recover().
func (s *SNMPServer) applySetActions(actions []setAction) setVerdict {
	state := s.interfaceState()
	for i, a := range actions {
		if a.column != ifAdminStatusColumn || state == nil {
			return setVerdict{snmpErrGenErr, i + 1}
		}
		for _, evt := range state.ApplyAdminStatus(a.ifIndex, uint8(a.value)) {
			state.Broadcast(evt)
		}
	}
	return setVerdict{snmpErrNoError, 0}
}

// decideSet is the version-independent half of a SET: validate every binding,
// then apply all or none. The caller frames the verdict for its version.
func (s *SNMPServer) decideSet(binds []snmpVarBind) setVerdict {
	actions, verdict := s.validateSetBindings(binds)
	if verdict.errStatus != snmpErrNoError {
		return verdict
	}
	return s.applySetActions(actions)
}

// handleSetRequest answers a v1/v2c SetRequest.
//
// A malformed variable-bindings list is discarded, as for every other PDU
// (nl6#537), and the list is bounded by the PDU's declared length, as the v3
// sibling bounds its own (nl6#535 R1): a list that overruns the PDU but sits
// inside a longer datagram is malformed, not a list to echo bytes from outside
// the PDU. So is an envelope that cannot be read as far as a list: a GET has
// the dispatcher's single fallback OID to answer from, a SET has nothing it
// could honestly report as "identical to the request". An EMPTY list is a legal
// SET that assigns nothing and is answered noError with an empty list under
// v1/v2c; under v3 the pre-existing extractor gate discards an empty list for
// every PDU type, SET included, so that one shape is version-dependent.
func (s *SNMPServer) handleSetRequest(requestData []byte) []byte {
	pos, pduEnd, reached := requestVarBindListPos(requestData)
	if !reached {
		s.logFirstMalformedSet("envelope ends before the variable-bindings list")
		return nil
	}
	if pduEnd > len(requestData) || pos > pduEnd {
		s.logFirstMalformedSet("PDU length overruns the datagram")
		return nil
	}
	// The list must END exactly on the PDU boundary (the v3 rule, applied
	// here too): bytes between the list and the PDU's end are not RFC 1157's
	// SEQUENCE, and a list length past the PDU is a lie about the PDU.
	if pos < pduEnd && requestData[pos] == ASN1_SEQUENCE {
		listLen, afterLen := parseLength(requestData, pos+1)
		if listLen >= 0 && (listLen > pduEnd-afterLen || afterLen+listLen != pduEnd) {
			s.logFirstMalformedSet("variable-bindings list does not end on the PDU boundary")
			return nil
		}
	}
	binds, echoed, ok := parseVarBinds(requestData[:pduEnd], pos)
	if !ok || binds == nil {
		s.logFirstMalformedSet("variable-bindings list is not a valid ASN.1 encoding")
		return nil
	}
	v := s.decideSet(binds)
	return s.createSetResponse(requestData, echoed, v.errStatus, v.errIndex)
}

// handleSNMPv3Set answers a v3 SetRequest whose scoped PDU has already been
// authenticated, decrypted and unwrapped by handleSNMPv3Request. The verdict is
// the SAME ladder as v2c; the Response-PDU inside the scoped PDU is byte-
// identical to the v2c one for the same bindings (pinned), and only the
// envelope differs. No v1 mapping: a v3 PDU is an RFC 3416 PDU.
func (s *SNMPServer) handleSNMPv3Set(v3Msg *SNMPv3Message, scopedPDU []byte) []byte {
	binds, echoed, ok := parseSetVarBindsFromScopedPDU(scopedPDU)
	if !ok || binds == nil {
		s.logFirstMalformedSet("SNMPv3 variable-bindings list is not a valid ASN.1 encoding")
		return []byte{}
	}
	v := s.decideSet(binds)
	errIndex := v.errIndex
	if v.errStatus == snmpErrNoError {
		errIndex = 0
	}
	scoped := s.createScopedPDUEncoded(echoed, v.errStatus, errIndex, v3Msg)
	resp, err := s.wrapScopedPDUInV3Message(scoped, v3Msg)
	if err != nil {
		log.Printf("Error creating SNMPv3 SET response: %v", err)
		return []byte{}
	}
	return resp
}

// logFirstMalformedSet emits at most one line per device when a SetRequest is
// discarded as malformed. Gated like its siblings: the condition is
// attacker-controlled, so ungated it is a log-flood primitive.
func (s *SNMPServer) logFirstMalformedSet(what string) {
	s.firstMalformedSet.Do(func() {
		log.Printf("SNMP %s: discarded a SetRequest: %s (further discards suppressed for this device)",
			s.device.ID, what)
	})
}

// ── Write admission (nl6#690) ──────────────────────────────────────────────
//
// nl6#684 admitted a SetRequest on exactly a GetRequest's terms, which was
// right while every served PDU was a read and is not right now that one of them
// mutates state, fires link traps and syslog and is visible to gNMI. Writes are
// now OPT-IN at every version, and BOTH gates ship together because they cover
// disjoint halves: a v3 message carries no community, a v1/v2c message carries
// no security level, so either one alone leaves the other version exactly as
// nl6#690 reported it.
//
// The rule is written ONCE, here, and the two dispatchers only frame the
// verdict. A predicate copied per version is the failure this package has
// already paid for three times — servedPDUTag had three readers and add-snmp-set
// found the third still carrying its own tag list, so every SET answered
// request-id 123. The copy of an ADMISSION rule fails the same way, and its
// failure is a write one version admits and the other refuses.
//
// Both gates run BEFORE the bindings are parsed, so a refused SET validates
// nothing, applies nothing, and cannot reach logFirstMalformedSet to report a
// parse verdict about a request that was never admitted.

// snmpSecurityLevel is the RFC 3411 §5 security level of a v3 message, ordered
// so that "at least this level" is a `>=` comparison.
//
// securityLevelUnset is the ZERO VALUE and is deliberately not a level: it means
// the device was built without an explicit policy, and effectiveMinSecurityLevel
// reads it as authNoPriv. Ordering the constants with noAuthNoPriv at zero would
// have made every SNMPServer literal in the package — and any future one — admit
// an unauthenticated write by default, which is the defect this change exists to
// remove. The permissive level has to be asked for by name.
type snmpSecurityLevel int

const (
	securityLevelUnset snmpSecurityLevel = iota
	securityLevelNoAuthNoPriv
	securityLevelAuthNoPriv
	securityLevelAuthPriv
)

// String names the level as RFC 3411 spells it, for logs and errors.
func (l snmpSecurityLevel) String() string {
	switch l {
	case securityLevelNoAuthNoPriv:
		return "noAuthNoPriv"
	case securityLevelAuthNoPriv:
		return "authNoPriv"
	case securityLevelAuthPriv:
		return "authPriv"
	default:
		return "unset"
	}
}

// parseSetMinSecurityLevel reads the -snmp-set-min-security-level flag value and
// the REST set_min_security_level field. Empty means unset, which is authNoPriv;
// anything unrecognised is an ERROR the caller must make fatal (startup) or a 400
// (REST), never a silent fallback — an accepted-and-ignored security knob is the
// nl6#445 family with a worse consequence.
func parseSetMinSecurityLevel(s string) (snmpSecurityLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return securityLevelUnset, nil
	case "none", "noauthnopriv":
		return securityLevelNoAuthNoPriv, nil
	case "auth", "authnopriv":
		return securityLevelAuthNoPriv, nil
	case "priv", "authpriv":
		return securityLevelAuthPriv, nil
	}
	return securityLevelUnset, fmt.Errorf(
		"unknown SET minimum security level %q: use none (noAuthNoPriv), auth (authNoPriv) or priv (authPriv)", s)
}

// newSetAdmission builds the resolved write-admission policy from the two
// places an operator states it: the write community (a v1/v2c concept, so a
// flag and a top-level REST field) and the v3 block's set_min_security_level.
//
// ONE constructor, so the CLI and the REST handler cannot drift on what an
// empty field means, and both get the same error text for a bad level. Callers
// make the error fatal (startup) or a 400 (REST).
func newSetAdmission(writeCommunity string, v3 *SNMPv3Config) (setAdmissionConfig, error) {
	level := ""
	if v3 != nil {
		level = v3.SetMinSecurityLevel
	}
	min, err := parseSetMinSecurityLevel(level)
	if err != nil {
		return setAdmissionConfig{}, err
	}
	return setAdmissionConfig{WriteCommunity: writeCommunity, MinSecurityLevel: min}, nil
}

// describe states the policy for the startup log, in the operator's terms.
// Both halves, always, including the case where the device's own auth
// configuration cannot reach the minimum — the alternative is a fleet that
// refuses every write with nothing on the console saying why.
func (c setAdmissionConfig) describe(v3 *SNMPv3Config) string {
	v1v2 := "v1/v2c SET: refused (no write community configured)"
	if c.WriteCommunity != "" {
		v1v2 = "v1/v2c SET: admitted with the configured write community"
	}
	min := c.effectiveMinSecurityLevel()
	v3s := fmt.Sprintf("v3 SET: minimum security level %s", min)
	switch {
	case v3 == nil || !v3.Enabled:
		v3s += " (SNMPv3 disabled)"
	case v3.AuthProtocol == SNMPV3_AUTH_NONE && min > securityLevelNoAuthNoPriv:
		v3s += " — UNREACHABLE: this fleet is configured with no authentication protocol, so no v3 SET can be admitted"
	case v3.PrivProtocol == SNMPV3_PRIV_NONE && min > securityLevelAuthNoPriv:
		v3s += " — UNREACHABLE: this fleet is configured with no privacy protocol, so no v3 SET can be admitted"
	}
	return v1v2 + "; " + v3s
}

// effectiveMinSecurityLevel resolves the zero value to the shipped default.
func (c setAdmissionConfig) effectiveMinSecurityLevel() snmpSecurityLevel {
	if c.MinSecurityLevel == securityLevelUnset {
		return securityLevelAuthNoPriv
	}
	return c.MinSecurityLevel
}

// securityLevelOf reads a v3 message's level off its msgFlags (RFC 3412 §6.4).
//
// The PRIV bit without the AUTH bit is not a level USM defines; it is reported
// as noAuthNoPriv, which is the lowest, so such a message can never clear a
// minimum a well-formed one could not. Failing toward the strict answer is the
// only safe direction for an admission test.
func securityLevelOf(flags byte) snmpSecurityLevel {
	auth := flags&SNMPV3_MSG_FLAG_AUTH != 0
	priv := flags&SNMPV3_MSG_FLAG_PRIV != 0
	switch {
	case auth && priv:
		return securityLevelAuthPriv
	case auth:
		return securityLevelAuthNoPriv
	default:
		return securityLevelNoAuthNoPriv
	}
}

// admitSetV2c decides whether a v1/v2c SetRequest is admitted.
//
// The community must have been READ FROM THE DATAGRAM and must equal the
// device's write community. req.Community carries "public" when the field is
// absent or its length is unreadable — a default that exists only so a response
// can echo something — so comparing it without req.CommunityParsed would admit
// an unparseable SET on any fleet configured `-snmp-write-community public`.
//
// An empty write community admits nothing, which is the default and needs no
// separate disable flag: the first test below refuses before the comparison is
// reached, so a manager cannot send the empty string and match.
//
// The comparison is constant-time. It is not load-bearing — nl6 is a simulator
// and this community protects nothing real — but it costs nothing and spares
// every future reader the same review comment.
func (s *SNMPServer) admitSetV2c(req SNMPRequest) bool {
	want := s.setAdmission.WriteCommunity
	if want == "" {
		return false
	}
	if !req.CommunityParsed {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(req.Community), []byte(want)) == 1
}

// admitSetV3 decides whether a v3 SetRequest is admitted.
//
// Called AFTER the user check and the USM verification a GET receives, so an
// unknown user or a wrong digest is still answered with its own Report rather
// than with a level verdict — the manager is told which of the two things is
// wrong. On a device configured with no authentication protocol no request can
// ever reach the default minimum, so no v3 SET is admitted; that is the same
// writes-are-opt-in outcome as an empty write community, and the startup log
// says so rather than leaving it as a silent dead end.
func (s *SNMPServer) admitSetV3(v3Msg *SNMPv3Message) bool {
	return securityLevelOf(v3Msg.GlobalData.MsgFlags) >= s.setAdmission.effectiveMinSecurityLevel()
}

// refusedSetReason names why a v1/v2c SET was refused, distinguishing the two
// cases an operator confuses: a fleet that was never configured for writes at
// all, and one whose write community the manager got wrong.
func refusedSetReason(writeCommunity string) string {
	if writeCommunity == "" {
		return "no write community is configured, so no v1/v2c write is admitted " +
			"(set -snmp-write-community, or write_community on the REST create body)"
	}
	return "community does not match the configured write community"
}

// logFirstRefusedSet emits at most one line per device when a v1/v2c SetRequest
// is discarded for its community. Its own sync.Once, not firstMalformedSet's:
// sharing one would let whichever fault a device saw first silence the other for
// its whole life, and a refused write and an unparseable one have different
// causes and different fixes.
//
// The line names the cause because the manager cannot: a discarded SET is a
// TIMEOUT at snmpset, which reads as an unreachable device rather than a refused
// write. That is the price of answering the way real hardware answers, and this
// line is what pays it.
func (s *SNMPServer) logFirstRefusedSet(why string) {
	s.firstRefusedSet.Do(func() {
		log.Printf("SNMP %s: discarded a SetRequest: %s (further refusals suppressed for this device)",
			s.device.ID, why)
	})
}
