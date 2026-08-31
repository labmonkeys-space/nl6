/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	"log"
)

// SNMPv3 message parsing and authentication functions

// parseSNMPv3Message parses an SNMPv3 message from raw bytes
func (s *SNMPServer) parseSNMPv3Message(data []byte) (*SNMPv3Message, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("SNMPv3 message too short")
	}

	msg := &SNMPv3Message{}
	pos := 0

	// Parse outer SEQUENCE
	if data[pos] != ASN1_SEQUENCE {
		return nil, fmt.Errorf("expected SEQUENCE tag")
	}
	pos++
	_, newPos := parseLength(data, pos)
	pos = newPos

	// Parse version (should be 3)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return nil, fmt.Errorf("expected version INTEGER")
	}
	pos++
	versionLen, newPos := parseLength(data, pos)
	if versionLen < 0 {
		return nil, fmt.Errorf("invalid version length")
	}
	pos = newPos
	// The declared width, not one octet (nl6#559's assumption, third site).
	// parseBERInt bounds the read against the datagram, so it also answers the
	// case this replaces: a declared length is not a delivered byte.
	v, ok := parseBERInt(data, pos, versionLen)
	if !ok {
		return nil, fmt.Errorf("unexpected end of data when parsing version")
	}
	msg.Version = v
	pos += versionLen

	if msg.Version != SNMPV3_VERSION {
		return nil, fmt.Errorf("unsupported SNMP version: %d", msg.Version)
	}

	// Parse global data (SEQUENCE)
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return nil, fmt.Errorf("expected global data SEQUENCE")
	}
	pos++
	_, newPos = parseLength(data, pos)
	pos = newPos

	// Parse msgID, msgMaxSize, msgFlags, msgSecurityModel
	var err error
	msg.GlobalData.MsgID, pos, err = parseInteger(data, pos)
	if err != nil {
		return nil, fmt.Errorf("failed to parse msgID: %v", err)
	}

	msg.GlobalData.MsgMaxSize, pos, err = parseInteger(data, pos)
	if err != nil {
		return nil, fmt.Errorf("failed to parse msgMaxSize: %v", err)
	}

	// Parse msgFlags (OCTET STRING of 1 byte)
	if pos >= len(data) || data[pos] != ASN1_OCTET_STRING {
		return nil, fmt.Errorf("expected msgFlags OCTET STRING")
	}
	pos++
	flagsLen, newPos := parseLength(data, pos)
	if flagsLen != 1 {
		return nil, fmt.Errorf("invalid msgFlags length")
	}
	pos = newPos
	if pos >= len(data) {
		return nil, fmt.Errorf("unexpected end of data when parsing msgFlags")
	}
	msg.GlobalData.MsgFlags = data[pos]
	pos++

	msg.GlobalData.MsgSecurityModel, pos, err = parseInteger(data, pos)
	if err != nil {
		return nil, fmt.Errorf("failed to parse msgSecurityModel: %v", err)
	}

	// Parse msgSecurityParameters (OCTET STRING)
	//
	// The `||` short-circuits, but the error message it guards does not: its
	// arguments are evaluated whenever the branch is taken, so reporting
	// data[pos] here panicked on precisely the truncated input the bounds
	// check was added to reject. Report the length instead of the byte.
	if pos >= len(data) {
		return nil, fmt.Errorf("unexpected end of data at pos %d when parsing msgSecurityParameters", pos)
	}
	if data[pos] != ASN1_OCTET_STRING {
		return nil, fmt.Errorf("expected msgSecurityParameters OCTET STRING at pos %d, got 0x%02X", pos, data[pos])
	}
	pos++
	secParamsLen, newPos := parseLength(data, pos)
	if secParamsLen == -1 {
		return nil, fmt.Errorf("failed to parse security parameters length")
	}
	pos = newPos

	if secParamsLen > 0 {
		if pos+secParamsLen > len(data) {
			return nil, fmt.Errorf("security parameters length %d exceeds remaining data %d", secParamsLen, len(data)-pos)
		}
		secParamsData := data[pos : pos+secParamsLen]
		// USM security-param parse errors are non-fatal in simulation
		// mode — fall through with empty params so the message still
		// dispatches. Capture-but-ignore is intentional.
		_ = s.parseUSMSecurityParameters(secParamsData, &msg.SecurityParams)
		pos += secParamsLen
	}

	// Parse scopedPduData - can be either OCTET STRING (encrypted) or SEQUENCE (plaintext)
	if pos >= len(data) {
		return nil, fmt.Errorf("unexpected end of data when parsing scopedPduData")
	}

	if data[pos] == ASN1_OCTET_STRING {
		// Encrypted scoped PDU
		pos++
		pduLen, newPos := parseLength(data, pos)
		pos = newPos
		if pduLen < 0 || pos+pduLen > len(data) {
			return nil, fmt.Errorf("invalid encrypted scopedPduData length: %d", pduLen)
		}
		msg.ScopedPDU = data[pos : pos+pduLen]
	} else if data[pos] == ASN1_SEQUENCE {
		// Plaintext scoped PDU
		pos++
		pduLen, newPos := parseLength(data, pos)
		pos = newPos
		if pduLen < 0 || pos+pduLen > len(data) {
			return nil, fmt.Errorf("invalid plaintext scopedPduData length: %d", pduLen)
		}
		msg.ScopedPDU = data[pos : pos+pduLen]
	} else {
		return nil, fmt.Errorf("expected scopedPduData OCTET STRING or SEQUENCE, got 0x%02X at pos %d", data[pos], pos)
	}

	return msg, nil
}

// parseUSMSecurityParameters parses USM security parameters
func (s *SNMPServer) parseUSMSecurityParameters(data []byte, params *SNMPv3SecurityParams) error {
	if len(data) == 0 {
		return nil
	}

	pos := 0

	// Parse outer SEQUENCE
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return fmt.Errorf("expected USM parameters SEQUENCE")
	}
	pos++
	seqLen, newPos := parseLength(data, pos)
	if seqLen == -1 {
		return fmt.Errorf("invalid USM SEQUENCE length")
	}
	pos = newPos

	// Parse authoritativeEngineID
	engineID, newPos, err := parseOctetString(data, pos)
	if err != nil {
		return fmt.Errorf("failed to parse authoritativeEngineID: %v", err)
	}
	params.AuthoritativeEngineID = string(engineID)
	pos = newPos

	// Parse authoritativeEngineBoots
	params.AuthoritativeEngineBoots, pos, err = parseInteger(data, pos)
	if err != nil {
		return fmt.Errorf("failed to parse authoritativeEngineBoots: %v", err)
	}

	// Parse authoritativeEngineTime
	params.AuthoritativeEngineTime, pos, err = parseInteger(data, pos)
	if err != nil {
		return fmt.Errorf("failed to parse authoritativeEngineTime: %v", err)
	}

	// Parse userName
	userName, newPos, err := parseOctetString(data, pos)
	if err != nil {
		return fmt.Errorf("failed to parse userName: %v", err)
	}
	params.UserName = string(userName)
	pos = newPos

	// Parse authenticationParameters
	params.AuthParams, pos, err = parseOctetString(data, pos)
	if err != nil {
		return fmt.Errorf("failed to parse authParams: %v", err)
	}

	// Parse privacyParameters. `pos` is reassigned but unused after this
	// call (function returns next); the underscore makes that explicit.
	params.PrivParams, _, err = parseOctetString(data, pos)
	if err != nil {
		return fmt.Errorf("failed to parse privParams: %v", err)
	}

	return nil
}

// Helper function to parse integers from ASN.1 encoded data
func parseInteger(data []byte, pos int) (int, int, error) {
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return 0, pos, fmt.Errorf("expected INTEGER tag at pos %d", pos)
	}
	pos++

	length, newPos := parseLength(data, pos)
	if length == -1 || newPos+length > len(data) {
		return 0, pos, fmt.Errorf("invalid integer length")
	}
	pos = newPos

	value := 0
	for i := 0; i < length; i++ {
		value = (value << 8) | int(data[pos])
		pos++
	}

	return value, pos, nil
}

// Helper function to parse octet strings from ASN.1 encoded data
func parseOctetString(data []byte, pos int) ([]byte, int, error) {
	if pos >= len(data) || data[pos] != ASN1_OCTET_STRING {
		return nil, pos, fmt.Errorf("expected OCTET STRING tag at pos %d", pos)
	}
	pos++

	length, newPos := parseLength(data, pos)
	if length == -1 || newPos+length > len(data) {
		return nil, pos, fmt.Errorf("invalid octet string length")
	}
	pos = newPos

	value := make([]byte, length)
	copy(value, data[pos:pos+length])
	pos += length

	return value, pos, nil
}

// isSNMPv3Request checks if the incoming request is SNMPv3
func isSNMPv3Request(data []byte) bool {
	if len(data) < 10 {
		return false
	}

	pos := 0

	// Skip SEQUENCE tag and length
	if data[pos] != ASN1_SEQUENCE {
		return false
	}
	pos++
	length, newPos := parseLength(data, pos)
	if length == -1 {
		return false
	}
	pos = newPos

	// Check version
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return false
	}
	pos++
	versionLen, newPos := parseLength(data, pos)
	if versionLen < 0 {
		return false
	}
	pos = newPos

	// Read the version at its DECLARED width, the same as every other
	// envelope reader since nl6#559. `versionLen != 1` was the identical
	// one-octet assumption: a BER-legal `02 02 00 03` was classified
	// not-v3 and fell through to the v2c path, which then read msgGlobalData
	// where it expects a community. parseSNMPv3Message carries the same fix,
	// so the classifier and the parser still agree — which matters more than
	// either answer on its own, because this is the gate every request passes
	// through and a v3 datagram admitted here that the parser then rejects is
	// a discard, not a wrong answer.
	//
	// parseBERInt bounds its own read against the datagram, so the explicit
	// end-of-data guard this replaces is subsumed: a declared length is not a
	// delivered byte, and this classifier runs for the whole fleet.
	v, ok := parseBERInt(data, pos, versionLen)
	return ok && v == SNMPV3_VERSION
}

// validateSNMPv3Credentials validates SNMPv3 user credentials
func (s *SNMPServer) validateSNMPv3Credentials(msg *SNMPv3Message) bool {
	if s.v3Config == nil || !s.v3Config.Enabled {
		return false
	}

	// Handle SNMPv3 discovery requests (empty security parameters)
	if msg.SecurityParams.UserName == "" &&
		msg.SecurityParams.AuthoritativeEngineID == "" &&
		msg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_REPORT != 0 {
		return true
	}

	// Check username for non-discovery requests
	if msg.SecurityParams.UserName != s.v3Config.Username {
		return false
	}

	// For simulation/testing purposes, we use simplified validation
	// In a production implementation, we would:
	// - Validate authentication parameters (HMAC-MD5/SHA1)
	// - Check timing parameters for replay protection
	// - Verify engine boots and time values
	// - Use proper RFC 3414 key derivation functions

	// Simulation deliberately skips the SNMPv3 150-second engine-time
	// window check — operators using nl6 may have intentionally skewed
	// clocks. Production agents MUST enforce RFC 3414 §3.2.

	return true
}

// handleSNMPv3GetBulk processes SNMPv3 GetBulk requests.
//
// It serves EVERY column the request names (nl6#535). It used to walk from a
// single start OID — the first variable binding, the only one
// extractOIDAndTypeFromScopedPDU validates — so a manager bundling
// ifDescr/ifName/ifAlias/ifSpeed in one v3 GETBULK got successors of the first
// column and nothing at all for the rest. That is a wrong answer under RFC
// 3416 §4.2.3, not merely a small one, and it also forced non-repeaters to be
// collapsed into "max-repetitions = 1", which is not what the field means.
//
// The order and the per-column end-of-MIB padding match handleGetBulk, the
// v2c reference: N non-repeater successors, then max-repetitions repetitions
// each carrying one binding per remaining column, interleaved column by
// column. Everything downstream is reused rather than rebuilt — the measured
// bound in createSNMPv3GetBulkResponse, the walk clamp, the end-of-MIB naming.
//
// A MULTI-COLUMN request is byte-identical to v2c, tail included: an exhausted
// column is padded for every remaining repetition, exactly as handleGetBulk
// pads. An earlier cut of this change stopped the loop once every column was
// exhausted and reported the difference as an unavoidable divergence. It was
// not unavoidable: nl6#526 constrains the SINGLE-column loop only, and the
// spec keys its two padding rules on LOOP SHAPE rather than on version — "the
// two rules govern different loops and SHALL NOT be applied to each other".
// The stated rationale did not hold either, since a multi-column response
// already carries exception pads after real bindings inside every mixed
// repetition.
//
// The SINGLE-column loop keeps nl6#526's contract and stops instead of
// padding: a v3 walk that runs out mid-response ships what it collected, and
// the NEXT request, collecting nothing, gets the exception on its own
// (TestV3GetBulkShipsEveryCollectedBinding, TestV3BulkWalkTerminates). A first
// repetition that produced nothing is still emitted, so a single column
// already past the end of the MIB is answered with its own OID and
// endOfMibView rather than an empty list.
//
// What still differs from v2c, and only on DEFECTIVE data: bulkStep ends a
// column on the endOfMibView SENTINEL and on a non-advancing successor as well
// as on an absent one, and names that binding with the REQUESTED OID, where
// v2c's non-repeater loop tests only for an absent successor. Both extra exits
// are nl6#526/#524 properties that a shared walk must not lose, and neither is
// reachable on data that loads (validateSNMPResourceValues rejects the
// sentinel; a non-advancing oidNextMap is a resource-file defect).
func (s *SNMPServer) handleSNMPv3GetBulk(startOID string, msg *SNMPv3Message, scopedPDU []byte) []byte {
	nonRepeaters, maxRepetitions := s.parseSNMPv3GetBulkParams(scopedPDU)
	// Defence in depth, as on the v2c path: the parser already rejects
	// negatives, but one slipping through is a negative loop bound or a
	// negative slice index inline on the serve path, where there is no
	// recover().
	if nonRepeaters < 0 {
		nonRepeaters = 0
	}
	if maxRepetitions < 0 {
		maxRepetitions = 0
	}

	allOIDs, ok := parseAllOIDsFromScopedPDU(scopedPDU)
	if !ok {
		// A variable-bindings list that is not a valid ASN.1 encoding makes
		// the PDU malformed; RFC 3412 §7.2 discards it. Returning nothing
		// means handleSingleRequest sends no datagram (nl6#537/#547).
		s.logFirstMalformedV3List(errV3VarBindListMalformed)
		return []byte{}
	}
	if len(allOIDs) == 0 {
		// The envelope before the list was unreadable, or the list is empty.
		// The OID the dispatcher already validated still covers that, exactly
		// as the v2c handler falls back to its single parsed OID.
		allOIDs = []string{startOID}
	}

	// One LLDP served-OID snapshot for the whole request, as the v2c handler
	// takes: rebuilding the device's entire LLDP/ifAlias view per walk step is
	// what turned a fabric-wide Enlinkd walk into O(steps × links), and two
	// snapshots could straddle a topology generation bump.
	lldpServed := s.lldpServedOIDs()

	// The exact upper bound is known before any walking: one binding per
	// non-repeater column plus columns × repetitions. Sizing here keeps the
	// shared UDP serve path from regrowing these slices per repetition.
	oids := make([]string, 0, len(allOIDs))
	responses := make([]string, 0, len(allOIDs))

	// ── Non-repeater section (GETNEXT semantics) ──────────────────────────
	// RFC 3416 §4.2.3: N = min(non-repeaters, number of bindings), so a
	// non-repeaters larger than the column count simply makes every column a
	// non-repeater and leaves no repeater loop.
	nonRep := nonRepeaters
	if nonRep > len(allOIDs) {
		nonRep = len(allOIDs)
	}
	for i := 0; i < nonRep; i++ {
		nextOID, nextVal, advanced := s.bulkStep(allOIDs[i], lldpServed)
		if !advanced {
			nextOID, nextVal = allOIDs[i], valueEndOfMibView
		}
		oids = append(oids, nextOID)
		responses = append(responses, nextVal)
	}

	// ── Repeater section (multi-column GETNEXT × max-repetitions) ─────────
	repeaterCols := allOIDs[nonRep:]
	if len(repeaterCols) == 0 || maxRepetitions == 0 {
		if len(oids) == 0 {
			// RFC 3416 §4.2.3 with N = 0 and M = 0 is a response with NO
			// bindings, not an end-of-MIB exception: the builder's empty
			// branch means the walk found nothing, which tells a walker the
			// MIB ended when nothing about the MIB was asked.
			return s.createSNMPv3EmptyGetBulkResponse(msg)
		}
		// M = 0 WITH non-repeaters is neither of those: the non-repeater
		// bindings are the whole legitimate answer. The old single-column
		// collapse hid this row entirely.
		return s.createSNMPv3GetBulkResponse(allOIDs[0], oids, responses, msg)
	}

	// The clamp bounds the TOTAL walk, not each column: the work is columns ×
	// repetitions, so dividing the ceiling by the column count is what keeps
	// the guard's meaning constant as columns are added. Per-column it would
	// be C times looser — 30 columns × 98 repetitions is precisely the
	// amplification the v2c guard exists to stop — and applying the undivided
	// ceiling to the total would be C times tighter, silently truncating what
	// a reasonable manager asked for. handleGetBulk calls the same function.
	//
	// The COLUMN count itself is not clamped here, and what bounds it is
	// implicit: the read buffer (snmpBufPool, snmpReadBufferBytes) caps a
	// request at 1024 bytes, and the smallest encodable VarBind is
	// minVarbindSize, so a datagram cannot name more than a few hundred
	// columns. The repeater walk is bounded regardless — the division above
	// makes columns × repetitions a constant — but the non-repeater loop above
	// is one step PER COLUMN with no other bound, so raising the read buffer
	// raises that work linearly. TestReadBufferBoundsTheColumnCount pins the
	// coupling so a buffer change has to acknowledge it (nl6#535 review R12).
	maxRepetitions = clampBulkWalk(maxRepetitions, len(repeaterCols))

	// currentOIDs tracks the cursor in each column; endOfMib[i] latches once
	// column i has exhausted its MIB view.
	currentOIDs := make([]string, len(repeaterCols))
	copy(currentOIDs, repeaterCols)
	endOfMib := make([]bool, len(repeaterCols))
	repOIDs := make([]string, 0, len(repeaterCols))
	repVals := make([]string, 0, len(repeaterCols))

	// Grow the collection to its full bound once, rather than per repetition.
	if total := len(oids) + len(repeaterCols)*maxRepetitions; cap(oids) < total {
		oids = append(make([]string, 0, total), oids...)
		responses = append(make([]string, 0, total), responses...)
	}

	// singleColumn selects nl6#526's stop-instead-of-pad rule, which applies
	// to the single-column loop ONLY. Keyed on the loop's shape, not on the
	// protocol version: the multi-column loop pads exactly as v2c does.
	singleColumn := len(repeaterCols) == 1

	for rep := 0; rep < maxRepetitions; rep++ {
		// A repetition is assembled before it is committed, because under the
		// single-column rule whether it is emitted at all depends on whether
		// the column produced a real binding in it. Reused across repetitions:
		// this runs inline on the shared UDP handler, and a fresh pair of
		// slices per repetition is up to ~99 allocations per request.
		repOIDs = repOIDs[:0]
		repVals = repVals[:0]
		produced := false

		for col, startCol := range repeaterCols {
			if endOfMib[col] {
				// RFC 3416: pad with the column's ORIGINAL requested OID and
				// the exception, so the interleave stays aligned and a manager
				// can still tell which column the slot belongs to.
				repOIDs = append(repOIDs, startCol)
				repVals = append(repVals, valueEndOfMibView)
				continue
			}
			nextOID, nextVal, advanced := s.bulkStep(currentOIDs[col], lldpServed)
			if !advanced {
				endOfMib[col] = true
				repOIDs = append(repOIDs, startCol)
				repVals = append(repVals, valueEndOfMibView)
				continue
			}
			repOIDs = append(repOIDs, nextOID)
			repVals = append(repVals, nextVal)
			currentOIDs[col] = nextOID
			produced = true
		}

		if !produced && rep > 0 && singleColumn {
			// nl6#526, single-column loop: the column is exhausted and earlier
			// repetitions carried real bindings, so this response ends here
			// and the next request — collecting nothing — receives the
			// exception on its own. A multi-column loop does NOT take this
			// exit; it pads, like v2c, so the interleave stays aligned to the
			// last repetition.
			break
		}

		oids = append(oids, repOIDs...)
		responses = append(responses, repVals...)

		if !produced && singleColumn {
			// A single column that was already past the end of its MIB view.
			// It has now been answered once, with its own OID and the
			// exception, which is the whole answer.
			break
		}
	}

	// allOIDs[0] names the binding only in the builder's empty-collection
	// branch, which the padding above makes unreachable from here; it is kept
	// as the defensive naming for an internal invariant violation, and the
	// first requested column is the right OID for it (nl6#526).
	return s.createSNMPv3GetBulkResponse(allOIDs[0], oids, responses, msg)
}

// bulkStep is one GETNEXT step of a GETBULK column. advanced is false when the
// column has reached the end of its MIB view, by any of three routes that are
// NOT the same thing but take the same answer — each ends the walk with a
// well-formed exception a manager cannot distinguish from a genuine end of MIB:
//
//	nextOID == ""          genuine end of the MIB view.
//	response == sentinel   a RESOURCE VALUE that is literally the string
//	                       "endOfMibView". That truncates the walk early and
//	                       undetectably. validateSNMPResourceValues (nl6#523)
//	                       rejects such a file at load, which is the
//	                       mitigation; this is the consequence if one gets past
//	                       it.
//	non-advancing          an oidNextMap that maps an OID to itself or to a
//	                       smaller one. Without this the loop hands back a
//	                       non-increasing OID with no exception, which is
//	                       EXACTLY the symptom nl6#526 set out to remove,
//	                       arriving by a different route. The v1/v2c GETNEXT
//	                       path grew the same bound in nl6#524.
//
// The v2c reference tests only the first two; the non-advance guard is a v3
// property (nl6#526) and is kept per column rather than dropped for symmetry.
func (s *SNMPServer) bulkStep(currentOID string, lldpServed []kvOID) (string, string, bool) {
	nextOID, response := s.findNextOIDWithServed(currentOID, lldpServed)
	if nextOID == "" || response == valueEndOfMibView {
		return "", "", false
	}
	if compareOIDsLexicographically(nextOID, currentOID) <= 0 {
		// A data defect, so log it once per device (same gate as the v1 skip
		// loop): without a line here the manager sees a walk that ends early,
		// indistinguishable from a short MIB.
		s.logFirstBulkAbort(nextOID, currentOID)
		return "", "", false
	}
	return nextOID, response, true
}

// logFirstBulkAbort emits at most one log line per device when the SNMPv3
// GETBULK collection loop ends on a non-advancing successor (nl6#526). Same
// gating rationale as logFirstSkipAbort: the condition is a resource-file
// defect present from load, so ungated it would repeat on every bulk walk of
// every device sharing the profile.
func (s *SNMPServer) logFirstBulkAbort(next, at string) {
	s.firstBulkAbort.Do(func() {
		log.Printf("SNMP %s: v3 GETBULK successor %s does not advance past %s; answering end-of-MIB (further aborts suppressed for this device)",
			s.device.ID, next, at)
	})
}

// clampBulkWalk bounds how far a GETBULK walks, as distinct from how much it
// emits.
//
// The encode bound trims what does not fit, but without this a manager asking
// for max-repetitions of 100000 would still make the device perform 100000
// findNextOID steps before a single binding was discarded. That amplification
// is what the v2c path guards against for the same reason (nl6#489 review), and
// each step is expensive: CLAUDE.md records ~29 req/s saturating all cores on
// the LLDP walk path.
//
// A separate function rather than an inline expression because it is a
// PERFORMANCE guard: the binding count is identical with or without it once the
// encode bound has trimmed, so no assertion about a response can see it. Only
// calling it directly can.
//
// minVarbindSize is a floor on what any binding can encode to, so
// budget/minVarbindSize is a hard ceiling on how many could ever fit. The +1
// keeps it from ever under-walking; the encode bound trims the remainder, so
// being generous here costs nothing while being tight would under-fill.
//
// columns is the number of REPEATER columns, and the ceiling is divided by it
// because a repetition costs one walk step PER COLUMN: the guard bounds the
// total work, which is what it bounded when there was only ever one column
// (nl6#535). Leaving it undivided would make it C times looser — 30 columns ×
// 98 repetitions still walks 2940 steps to emit the ~60 bindings that fit,
// which is the amplification it exists to stop — and applying the undivided
// ceiling to the total instead would be C times tighter, truncating what a
// reasonable manager asked for. handleGetBulk divides identically.
func clampBulkWalk(maxRepetitions, columns int) int {
	if columns < 1 {
		columns = 1
	}
	if ceiling := maxSNMPResponseSize/minVarbindSize/columns + 1; maxRepetitions > ceiling {
		return ceiling
	}
	return maxRepetitions
}

// parseSNMPv3GetBulkParams reads non-repeaters and max-repetitions from a
// GETBULK scoped PDU, in CONTENTS form (contextEngineID, contextName, PDU) as
// parseSNMPv3Message and handleSNMPv3Request supply it.
//
// It used to be a TODO returning a hardcoded (0, 10), which made an oversized
// v3 response unreachable by accident rather than by design (nl6#535). Reading
// a real value is only safe now that createSNMPv3GetBulkResponse bounds what it
// emits; the reverse order was the unsafe one.
//
// Integers are read via parseBERInt at ANY width. The v2c parser originally
// read single-byte BER content only, so any max-repetitions >= 128 silently
// became 10 — benchmark numbers taken above 127 before that fix are not
// comparable with ones after it. Repeating that here would reintroduce the same
// silent discontinuity on the v3 path.
//
// Both values are clamped at the PARSE SITE rather than by the caller, matching
// the v2c parser: a negative reaching the handler becomes a negative loop bound
// or a negative slice index on the inline serve path, where there is no
// recover().
//
// The three INTEGER fields are bounded by the PDU they sit in, not by the
// datagram (the nl6#537 rule): a field read across its container's end is a
// value nobody sent.
func (s *SNMPServer) parseSNMPv3GetBulkParams(scopedPDU []byte) (int, int) {
	// Defaults if the PDU does not parse. Ten matches the historical hardcoded
	// value, so a malformed request behaves as it did rather than as an
	// unbounded one.
	nonRepeaters, maxRepetitions := 0, 10

	pos := 0
	// contextEngineID and contextName, both OCTET STRING.
	for i := 0; i < 2; i++ {
		if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
			return nonRepeaters, maxRepetitions
		}
		pos++
		n, newPos := parseLength(scopedPDU, pos)
		if n < 0 || newPos+n > len(scopedPDU) {
			return nonRepeaters, maxRepetitions
		}
		pos = newPos + n
	}

	// The PDU itself. Only a GETBULK carries these two fields.
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_GET_BULK {
		return nonRepeaters, maxRepetitions
	}
	pos++
	pduLen, newPos := parseLength(scopedPDU, pos)
	if pduLen < 0 || newPos+pduLen > len(scopedPDU) {
		return nonRepeaters, maxRepetitions
	}
	pos = newPos
	end := newPos + pduLen // the PDU's own boundary bounds every read below

	// request-id, skipped.
	if pos >= end || scopedPDU[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	reqLen, newPos := parseLength(scopedPDU, pos)
	if reqLen < 0 || newPos+reqLen > end {
		return nonRepeaters, maxRepetitions
	}
	pos = newPos + reqLen

	// non-repeaters.
	if pos >= end || scopedPDU[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	nrLen, newPos := parseLength(scopedPDU, pos)
	if nrLen < 0 || newPos+nrLen > end {
		return nonRepeaters, maxRepetitions
	}
	pos = newPos
	if v, ok := parseBERInt(scopedPDU, pos, nrLen); ok && v >= 0 {
		nonRepeaters = v
	}
	pos += nrLen

	// max-repetitions.
	if pos >= end || scopedPDU[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	mrLen, newPos := parseLength(scopedPDU, pos)
	if mrLen < 0 || newPos+mrLen > end {
		return nonRepeaters, maxRepetitions
	}
	if v, ok := parseBERInt(scopedPDU, newPos, mrLen); ok && v >= 0 {
		maxRepetitions = v
	}

	return nonRepeaters, maxRepetitions
}

// createSNMPv3EmptyGetBulkResponse answers a GETBULK that asked for zero
// repetitions: a GetResponse with an empty variable-bindings list and noError.
// Distinct from the len(oids) == 0 branch of createSNMPv3GetBulkResponse, which
// means the walk found nothing and is an end-of-MIB exception.
func (s *SNMPServer) createSNMPv3EmptyGetBulkResponse(msg *SNMPv3Message) []byte {
	scopedPDU, err := s.createScopedPDUMulti(nil, nil, msg)
	if err != nil {
		return []byte{}
	}
	resp, err := s.wrapScopedPDUInV3Message(scopedPDU, msg)
	if err != nil {
		return []byte{}
	}
	return resp
}

// createSNMPv3GetBulkResponse creates an SNMPv3 GetBulk response.
//
// requestedOID is the OID the manager asked to walk from, and it is what names
// the binding when nothing follows it. That naming is load-bearing (nl6#526).
// This used to answer a placeholder sysDescr.0 = "No data" binding, and the
// damage was not only that a string stood where an RFC 3416 exception belongs:
// sysDescr.0 sorts BEFORE almost any requested OID, so a v3 bulk walker
// (snmp4j TreeUtils, which OpenNMS uses) saw a non-increasing OID and either
// reported "OID not increasing" or kept walking. The walk never terminated.
// An exception on a wrongly-named binding would have fixed only half of that.
//
// The encoder needs nothing here: nl6#518 and nl6#522 already route the scoped
// PDU builder (createScopedPDUMulti, which createScopedPDU delegates to)
// through encodeTypedValue, so the sentinel becomes the 82 00 tag on its own.
// The defect was purely that handleSNMPv3GetBulk discarded the sentinel before
// the encoder ever saw it.
func (s *SNMPServer) createSNMPv3GetBulkResponse(requestedOID string, oids []string, responses []string, msg *SNMPv3Message) []byte {
	if len(oids) == 0 {
		// Nothing follows the requested OID, so this is the end of the MIB
		// view. RFC 3416: answer the exception, named with what was asked for.
		responseBytes, err := s.createSNMPv3Response(requestedOID, valueEndOfMibView, msg)
		if err != nil {
			return []byte{}
		}
		return responseBytes
	}

	// Emit as many bindings as fit the datagram budget, dropping from the end
	// (RFC 3416 §4.2.3: a GETBULK truncates, and the walker resumes from the
	// last OID returned).
	//
	// The size is MEASURED, not predicted. The v2c path can compute its length
	// arithmetically because its envelope is fixed, but a v3 message wraps the
	// scoped PDU in globalData and securityParameters whose sizes depend on the
	// engine ID, the user name and the privacy parameters, and under privacy
	// the scoped PDU is encrypted and PADDED to a cipher block. Predicting that
	// is exactly the kind of estimate this package has been bitten by:
	// "every bug in this family was a predicted size disagreeing with an
	// emitted one". Building the candidate and measuring it cannot disagree
	// with itself.
	//
	// The search over n is a BISECTION, not a linear descent. A descent fully
	// builds and, under privacy, fully encrypts every over-budget candidate:
	// immaterial while max-repetitions was the hardcoded 10, but O(n^2) bytes
	// and n encryptions per request once a real value is honoured (nl6#535),
	// inline on the UDP handler. len(resp) is monotone in n, so bisection finds
	// the same answer in O(log n) encodes while still MEASURING every candidate
	// rather than predicting any of them.
	//
	// The ceiling is the datagram budget, further reduced by the manager's
	// own msgMaxSize when it declares a smaller one: RFC 3412 §7.1 requires a
	// response to fit what the requester said it can receive. RFC 3412 §7.2
	// puts the legal range at 484 and up, so a declaration below that is
	// malformed and is ignored rather than honoured.
	limit := maxSNMPResponseSize
	if m := msg.GlobalData.MsgMaxSize; m >= snmpV3MinMsgMaxSize && m < limit {
		limit = m
	}
	resp, err := largestFittingPrefix(len(oids), limit, func(n int) ([]byte, error) {
		scopedPDU, err := s.createScopedPDUMulti(oids[:n], responses[:n], msg)
		if err != nil {
			return nil, err
		}
		return s.wrapScopedPDUInV3Message(scopedPDU, msg)
	})
	if err != nil {
		return []byte{}
	}
	return resp
}

// largestFittingPrefix returns build(n) for the largest n in [1, count] whose
// result is within limit, or build(1) when even one does not fit.
//
// Extracted so the search can be driven with a counting builder in a test:
// every other assertion about the response is satisfied equally by a linear
// descent, so without a way to count encodes there is nothing to stop one
// coming back.
//
// It BISECTS. len(build(n)) is monotone in n, so bisection reaches the same
// answer as a descent in O(log n) calls while still measuring every candidate
// rather than predicting any. That matters because each call fully builds and,
// under privacy, fully encrypts a candidate: a descent is O(n^2) bytes and n
// encryptions per request at a real max-repetitions, inline on the UDP handler.
//
// Returning build(1) when nothing fits is the v2c truncate rule's carve-out: an
// empty binding list with no error stalls a walk forever with no signal, which
// is worse than one oversized datagram.
func largestFittingPrefix(count, limit int, build func(int) ([]byte, error)) ([]byte, error) {
	if count <= 0 {
		return nil, fmt.Errorf("largestFittingPrefix: count must be positive, got %d", count)
	}

	// The common case is that everything fits, and it costs one call.
	full, err := build(count)
	if err != nil {
		return nil, err
	}
	if len(full) <= limit || count == 1 {
		return full, nil
	}

	best, err := build(1)
	if err != nil {
		return nil, err
	}

	// Invariant: lo fits or is the floor; hi does not fit.
	lo, hi := 1, count
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		resp, err := build(mid)
		if err != nil {
			return nil, err
		}
		if len(resp) <= limit {
			lo, best = mid, resp
		} else {
			hi = mid
		}
	}
	return best, nil
}

// snmpV3MinMsgMaxSize is the smallest msgMaxSize an SNMPv3 message may declare
// (RFC 3412 §7.2, "484..2147483647"). A declaration below it is not honoured.
const snmpV3MinMsgMaxSize = 484
