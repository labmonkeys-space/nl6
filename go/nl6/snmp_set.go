/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
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
