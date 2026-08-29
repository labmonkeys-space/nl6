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
	// Parse GetBulk parameters from the scoped PDU
	_, maxRepetitions := s.parseSNMPv3GetBulkParams(scopedPDU)

	// Collect multiple OIDs starting from startOID
	var oids []string
	var responses []string

	currentOID := startOID
	count := 0

	// Collect up to maxRepetitions OIDs.
	//
	// An empty collection is answered as the endOfMibView exception, named with
	// startOID, by createSNMPv3GetBulkResponse (nl6#526). The sentinel is not
	// appended to oids here because that builder still ships a single binding.
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

// parseSNMPv3GetBulkParams extracts non-repeaters and max-repetitions from SNMPv3 GetBulk scoped PDU
func (s *SNMPServer) parseSNMPv3GetBulkParams(scopedPDU []byte) (int, int) {
	// Default values
	nonRepeaters := 0
	maxRepetitions := 10

	// NOT bounded by maxSNMPResponseSize, unlike the v2c path (nl6#489).
	//
	// Unreachable today rather than safe by design: this hardcoded 10, walking
	// a single column, yields ~10 variable bindings (~500 B) and cannot
	// approach the budget. The moment this TODO is done and a real
	// max-repetitions is honoured, the v3 response needs the same bound the
	// v2c path got — createSNMPv3GetBulkResponse builds its own message and
	// consults no ceiling.
	//
	// Stated in docs/reference/snmp.md as a known gap so it reads as a decision
	// rather than an oversight.
	//
	// TODO: Implement proper SNMPv3 GetBulk parameter parsing
	// For now, use defaults

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
// The encoder needs nothing here: nl6#518 and nl6#522 already route
// createScopedPDU through encodeTypedValue, so the sentinel becomes the 82 00
// tag on its own. The defect was purely that handleSNMPv3GetBulk discarded the
// sentinel before the encoder ever saw it.
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

	// Ships ONE binding however many the collection loop gathered, so a v3
	// GETBULK is correct but no more efficient than a GETNEXT (nl6#535).
	// Verified: the response is byte-identical for 1 and 10 collected OIDs.
	// That, honouring a real max-repetitions, and bounding the response are one
	// change, and max-repetitions must NOT be honoured without the bound.
	responseBytes, err := s.createSNMPv3Response(oids[0], responses[0], msg)
	if err != nil {
		return []byte{}
	}
	return responseBytes
}
