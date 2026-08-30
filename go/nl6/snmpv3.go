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
	if versionLen != 1 {
		return nil, fmt.Errorf("invalid version length")
	}
	pos = newPos
	// A declared length is not a delivered byte: the datagram can end here.
	if pos >= len(data) {
		return nil, fmt.Errorf("unexpected end of data when parsing version")
	}
	msg.Version = int(data[pos])
	pos++

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
	if versionLen != 1 {
		return false
	}
	pos = newPos

	// A datagram may declare a one-byte version and then end. This is the
	// classifier every request passes through before dispatch, so an
	// unguarded read here takes down the whole fleet, not one device.
	if pos >= len(data) {
		return false
	}

	version := int(data[pos])
	return version == SNMPV3_VERSION
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

// handleSNMPv3GetBulk processes SNMPv3 GetBulk requests
func (s *SNMPServer) handleSNMPv3GetBulk(startOID string, msg *SNMPv3Message, scopedPDU []byte) []byte {
	nonRepeaters, maxRepetitions := s.parseSNMPv3GetBulkParams(scopedPDU)

	// This handler serves ONE column (startOID), so RFC 3416's non-repeaters
	// split reduces to a single question: is that column a non-repeater? If it
	// is, it gets exactly one successor, which is GETNEXT semantics. Ignoring
	// non-repeaters would over-answer a manager that asked for one binding.
	if nonRepeaters > 0 {
		maxRepetitions = 1
	}

	maxRepetitions = clampBulkWalk(maxRepetitions)

	// Collect multiple OIDs starting from startOID
	var oids []string
	var responses []string

	currentOID := startOID
	count := 0

	// Collect up to maxRepetitions OIDs.
	//
	// An empty collection is answered as the endOfMibView exception, named with
	// startOID, by createSNMPv3GetBulkResponse (nl6#526). The sentinel is not
	// appended to oids here: the builder ships every binding collected, so
	// appending it would put the exception after real bindings mid-walk and
	// make the walker stop early. The NEXT request, starting from the last
	// OID returned, collects nothing and gets the exception on its own.
	//
	// The three break conditions are NOT the same thing, and the difference
	// matters because each ends the walk with a well-formed exception that a
	// manager cannot distinguish from a genuine end of MIB:
	//
	//   nextOID == ""          genuine end of the MIB view.
	//   response == sentinel   a RESOURCE VALUE that is literally the string
	//                          "endOfMibView". That truncates the walk early
	//                          and undetectably. validateSNMPResourceValues
	//                          (nl6#523) rejects such a file at load, which is
	//                          the mitigation; this is the consequence if one
	//                          ever gets past it.
	//   non-advancing          an oidNextMap that maps an OID to itself or to a
	//                          smaller one. Without this check the loop would
	//                          hand back a non-increasing OID with no
	//                          exception, which is EXACTLY the symptom nl6#526
	//                          set out to remove, arriving by a different
	//                          route. The v1/v2c GETNEXT path grew the same
	//                          bound in nl6#524.
	for count < maxRepetitions {
		nextOID, response := s.findNextOID(currentOID)
		if nextOID == "" || response == valueEndOfMibView {
			break
		}
		if compareOIDsLexicographically(nextOID, currentOID) <= 0 {
			// A data defect, so log it once per device (same gate as the v1
			// skip loop): without a line here the manager sees a walk that
			// ends early, indistinguishable from a short MIB.
			s.logFirstBulkAbort(nextOID, currentOID)
			break
		}

		oids = append(oids, nextOID)
		responses = append(responses, response)
		currentOID = nextOID
		count++
	}

	// Create SNMPv3 GetBulk response
	return s.createSNMPv3GetBulkResponse(startOID, oids, responses, msg)
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

// parseSNMPv3GetBulkParams extracts non-repeaters and max-repetitions from SNMPv3 GetBulk scoped PDU
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
func clampBulkWalk(maxRepetitions int) int {
	if ceiling := maxSNMPResponseSize/minVarbindSize + 1; maxRepetitions > ceiling {
		return ceiling
	}
	return maxRepetitions
}

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
	if _, newPos := parseLength(scopedPDU, pos); true {
		if newPos <= pos {
			return nonRepeaters, maxRepetitions
		}
		pos = newPos
	}

	// request-id, skipped.
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	reqLen, newPos := parseLength(scopedPDU, pos)
	if reqLen < 0 || newPos+reqLen > len(scopedPDU) {
		return nonRepeaters, maxRepetitions
	}
	pos = newPos + reqLen

	// non-repeaters.
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	nrLen, newPos := parseLength(scopedPDU, pos)
	if nrLen < 0 || newPos+nrLen > len(scopedPDU) {
		return nonRepeaters, maxRepetitions
	}
	pos = newPos
	if v, ok := parseBERInt(scopedPDU, pos, nrLen); ok && v >= 0 {
		nonRepeaters = v
	}
	pos += nrLen

	// max-repetitions.
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	mrLen, newPos := parseLength(scopedPDU, pos)
	if mrLen < 0 || newPos+mrLen > len(scopedPDU) {
		return nonRepeaters, maxRepetitions
	}
	if v, ok := parseBERInt(scopedPDU, newPos, mrLen); ok && v >= 0 {
		maxRepetitions = v
	}

	return nonRepeaters, maxRepetitions
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
