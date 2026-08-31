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
	"time"
)

// handleSNMPv3Request handles SNMPv3 requests with USM authentication
func (s *SNMPServer) handleSNMPv3Request(requestData []byte) []byte {
	// Check if SNMPv3 is enabled
	if s.v3Config == nil || !s.v3Config.Enabled {
		// log.Printf("SNMPv3 request received but SNMPv3 not enabled")
		return []byte{} // Return empty response
	}

	// Parse SNMPv3 message
	v3Msg, err := s.parseSNMPv3Message(requestData)
	if err != nil {
		// log.Printf("Error parsing SNMPv3 message: %v", err)
		return []byte{}
	}

	// Check if this is a discovery request
	isDiscovery := v3Msg.SecurityParams.UserName == "" &&
		v3Msg.SecurityParams.AuthoritativeEngineID == ""

	// Validate credentials (discovery requests are allowed through)
	if !s.validateSNMPv3Credentials(v3Msg) {
		// log.Printf("SNMPv3 authentication failed")
		return []byte{}
	}

	if isDiscovery {
		// log.Printf("SNMPv3: Processing discovery request")
		// For discovery, return a report with our engine ID
		return s.createSNMPv3DiscoveryResponse(v3Msg)
	}

	// log.Printf("SNMPv3: Authenticated user: %s, flags: 0x%02X",
	//	v3Msg.SecurityParams.UserName, v3Msg.GlobalData.MsgFlags)

	// Handle scoped PDU decryption
	scopedPDU := v3Msg.ScopedPDU
	decryptFailed := false
	if v3Msg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_PRIV != 0 {
		// A PRIV-flagged message to a device configured without privacy is
		// not a decryption failure, it is a security level the device does
		// not support: RFC 3414 §3.2 step 5, usmStatsUnsupportedSecLevels.
		// Without this test decryptScopedPDU hands the ciphertext back
		// untouched, the SEQUENCE check below fails, and the manager is told
		// its KEY is wrong when its CONFIGURATION is.
		if s.v3Config.PrivProtocol == SNMPV3_PRIV_NONE {
			return s.createSNMPv3ReportResponse(oidUsmStatsUnsupportedSecLevels, v3Msg)
		}
		decryptedPDU, err := s.decryptScopedPDU(v3Msg.ScopedPDU, v3Msg.SecurityParams.PrivParams)
		if err != nil {
			// A hard error: bad privParams length, ciphertext not a multiple
			// of the block size, no usable key.
			decryptFailed = true
		} else {
			// UNWRAP the SEQUENCE before using it. parseSNMPv3Message stores
			// the scoped PDU's CONTENTS for a plaintext request (it strips the
			// header), while decryptScopedPDU returns the whole TLV, and both
			// extractOIDAndTypeFromScopedPDU and extractRequestIDFromScopedPDU
			// parse contents. Handing them the wrapped form made every
			// consumer fail: the OID extraction errored, so the caller's
			// decrypt-FAILURE fallback fired on a SUCCESSFUL decrypt and
			// answered sysDescr.0 as a GET, and the request-id fell back to 1
			// (nl6#527). An authPriv request of any OID and any PDU type was
			// therefore answered as a GET of sysDescr.0.
			//
			// A decrypt that returns without error but does not yield a
			// SEQUENCE is a wrong key just as surely as a hard error is:
			// block ciphers happily "decrypt" under the wrong key and produce
			// noise. Both count as decryption failures. The test is a
			// HEURISTIC, not a proof: noise starts with 0x30 and a plausible
			// length about one time in 256, and that request falls through
			// to the extractor, fails there, and is discarded as malformed
			// rather than answered with the Report. A padding check would
			// not close it either, since RFC 3414 privacy has no MAC.
			unwrapped := false
			if len(decryptedPDU) > 0 && decryptedPDU[0] == ASN1_SEQUENCE {
				contentLen, contentStart := parseLength(decryptedPDU, 1)
				if contentLen >= 0 && contentStart+contentLen <= len(decryptedPDU) {
					scopedPDU = decryptedPDU[contentStart : contentStart+contentLen]
					// The response builder reads the request id from the
					// message, not from this local, so it needs the plaintext
					// too.
					v3Msg.ScopedPDU = scopedPDU
					unwrapped = true
				}
			}
			if !unwrapped {
				decryptFailed = true
			}
		}
	}

	// Parse the scoped PDU to extract OID and request type
	// A decryption failure and a malformed PDU are DIFFERENT faults and RFC
	// 3414 and RFC 3412 give them opposite answers. They shared this fallback
	// and both got a GET of sysDescr.0 with request-id 1 (nl6#547).
	//
	// Decryption failure: the manager used the wrong privacy key, or none. RFC
	// 3414 §3.2 step 8 answers a usmStatsDecryptionErrors Report, so the
	// manager learns WHY rather than being handed a plausible-looking value
	// for an object it did not ask about. Silence would be worse still: a
	// wrong-password probe would be indistinguishable from an unreachable
	// device.
	if decryptFailed {
		return s.createSNMPv3ReportResponse(oidUsmStatsDecryptionErrors, v3Msg)
	}

	oid, pduType, err := s.extractOIDAndTypeFromScopedPDU(scopedPDU)
	if err != nil {
		// The scoped PDU decrypted (or was never encrypted) and still does not
		// parse, so the datagram is malformed. RFC 1157 §4.1 and RFC 3412 §7.2
		// discard rather than answering, which is what the v1/v2c path does
		// since nl6#537. Returning nothing means handleSingleRequest sends no
		// datagram.
		//
		// The extractor's error is broader than the v2c list check: it also
		// covers a PDU type this server does not serve (SET, INFORM, TRAP,
		// Report) and an empty variable-bindings list, and it validates the
		// FIRST binding's name only. All of those are discarded here; the
		// v2c path answers an empty list from its default OID. Before nl6#547
		// every one of them was answered as a GET of sysDescr.0.
		//
		// This is also the last route to nl6#526's symptom: answering here
		// substituted sysDescr.0, an OID sorting before almost any request, so
		// a walker that hit a malformed binding mid-walk never terminated.
		s.logFirstMalformedV3(err)
		return []byte{}
	}

	// Handle GetNext request for SNMP walk (same logic as SNMPv2)
	var responseOID string
	var response string

	if pduType == ASN1_GET_NEXT {
		// log.Printf("SNMPv3: Processing GetNext request for OID: %s", oid)
		responseOID, response = s.findNextOID(oid)
		if responseOID == "" {
			// End of MIB view - use a special response
			responseOID = oid
			response = valueEndOfMibView
		}
		// log.Printf("SNMPv3 %s: GetNext %s -> %s = %s", s.device.ID, oid, responseOID, response)
	} else if pduType == ASN1_GET_BULK {
		// Handle GetBulk request for SNMPv3
		return s.handleSNMPv3GetBulk(oid, v3Msg, scopedPDU)
	} else {
		// Handle regular Get request
		responseOID = oid
		response = s.findResponse(oid)
		// log.Printf("SNMPv3 %s: Get %s -> %s", s.device.ID, oid, response)
	}

	// Create SNMPv3 response (use responseOID for the response)
	responseBytes, err := s.createSNMPv3Response(responseOID, response, v3Msg)
	if err != nil {
		log.Printf("Error creating SNMPv3 response: %v", err)
		return []byte{}
	}
	return responseBytes
}

// extractOIDAndTypeFromScopedPDU extracts both OID and PDU type from a scoped PDU
func (s *SNMPServer) extractOIDAndTypeFromScopedPDU(scopedPDU []byte) (string, byte, error) {
	if len(scopedPDU) < 10 {
		return "", ASN1_GET_REQUEST, fmt.Errorf("scoped PDU too short")
	}

	pos := 0

	// Parse contextEngineID (OCTET STRING)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
		return "", ASN1_GET_REQUEST, fmt.Errorf("expected contextEngineID OCTET STRING")
	}
	pos++
	engineIDLen, newPos := parseLength(scopedPDU, pos)
	if engineIDLen < 0 {
		return "", ASN1_GET_REQUEST, fmt.Errorf("invalid contextEngineID length")
	}
	pos = newPos + engineIDLen

	// Parse contextName (OCTET STRING)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
		return "", ASN1_GET_REQUEST, fmt.Errorf("expected contextName OCTET STRING")
	}
	pos++
	contextNameLen, newPos := parseLength(scopedPDU, pos)
	if contextNameLen < 0 {
		return "", ASN1_GET_REQUEST, fmt.Errorf("invalid contextName length")
	}
	pos = newPos + contextNameLen

	// Parse PDU - should be GetRequest (0xA0) or GetNext (0xA1)
	if pos >= len(scopedPDU) {
		return "", ASN1_GET_REQUEST, fmt.Errorf("unexpected end of scoped PDU")
	}

	pduType := scopedPDU[pos]

	if pduType != ASN1_GET_REQUEST && pduType != ASN1_GET_NEXT && pduType != ASN1_GET_BULK {
		return "", ASN1_GET_REQUEST, fmt.Errorf("unsupported PDU type in scoped PDU: 0x%02X", pduType)
	}
	pos++

	// Skip PDU length
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos

	// Parse request ID, error status, error index (skip them)
	for i := 0; i < 3; i++ {
		if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_INTEGER {
			return "", pduType, fmt.Errorf("expected INTEGER in PDU")
		}
		pos++
		intLen, newPos := parseLength(scopedPDU, pos)
		if intLen < 0 {
			return "", pduType, fmt.Errorf("invalid INTEGER length in PDU")
		}
		pos = newPos + intLen
	}

	// Parse variable bindings (SEQUENCE)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_SEQUENCE {
		return "", pduType, fmt.Errorf("expected variable bindings SEQUENCE")
	}
	pos++
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos

	// Parse first variable binding (SEQUENCE)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_SEQUENCE {
		return "", pduType, fmt.Errorf("expected first variable binding SEQUENCE")
	}
	pos++
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos

	// Parse OID (OBJECT IDENTIFIER)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OBJECT_ID {
		return "", pduType, fmt.Errorf("expected OID in variable binding")
	}
	pos++
	oidLen, newPos := parseLength(scopedPDU, pos)
	pos = newPos

	// oidLen < 0 is parseLength's "unparseable" signal. Testing only the
	// upper bound lets it through — pos+(-1) is below len — and the slice
	// expression below then panics on an inverted range.
	if oidLen < 0 || pos+oidLen > len(scopedPDU) {
		return "", pduType, fmt.Errorf("OID length exceeds remaining data")
	}

	oidBytes := scopedPDU[pos : pos+oidLen]
	oid := decodeOID(oidBytes)
	if oid == "" {
		// decodeOID refuses a name that is not a valid OBJECT IDENTIFIER
		// encoding (nl6#529). Returning it as an empty string with a NIL error
		// made the caller treat it as a successful parse: findNextOID("")
		// returns the first OID in the MIB, so a malformed v3 GETNEXT read as
		// "start of walk" rather than being refused (nl6#547).
		return "", pduType, fmt.Errorf("variable binding name is not a valid OBJECT IDENTIFIER")
	}

	return oid, pduType, nil
}

// parseAllOIDsFromScopedPDU extracts every variable-binding NAME from an
// SNMPv3 scoped PDU in CONTENTS form (contextEngineID, contextName, PDU), the
// shape parseSNMPv3Message and handleSNMPv3Request supply.
//
// It is the v3 sibling of parseAllOIDsFromRequest and carries the SAME
// two-zero-case contract, because the callers must behave the same way:
//
//	(nil, false)  the variable-bindings list is present but is not a valid
//	              ASN.1 encoding. RFC 1157 §4.1 step 1 and RFC 3412 §7.2
//	              discard the datagram; the caller sends nothing (nl6#537).
//	(nil, true)   the envelope before the list was unreadable, or the list is
//	              empty. The single OID extractOIDAndTypeFromScopedPDU already
//	              validated still covers that case.
//
// Collapsing the two would either drop requests this server used to answer or
// answer ones RFC 3412 requires it to discard, which is why the bool exists
// rather than an empty slice standing for both.
//
// extractOIDAndTypeFromScopedPDU validates the FIRST binding's name and the
// PDU type before this runs, so this function never relaxes the nl6#547
// discard: it can only add discards, for a list whose LATER bindings are
// malformed — the same widening nl6#537 made on the v1/v2c side.
//
// Every length below is bounded by the container it sits in: the PDU's own
// declared length bounds the three INTEGERs and the list, not the datagram. A
// field read across its container's end is a value nobody sent (nl6#537).
func parseAllOIDsFromScopedPDU(scopedPDU []byte) ([]string, bool) {
	pos := 0

	// contextEngineID and contextName, both OCTET STRING.
	for i := 0; i < 2; i++ {
		if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
			return nil, true
		}
		pos++
		n, newPos := parseLength(scopedPDU, pos)
		if n < 0 || newPos+n > len(scopedPDU) {
			return nil, true
		}
		pos = newPos + n
	}

	// The PDU. Any tag: the caller has already rejected the types this server
	// does not serve, and the varbind list sits in the same place in all of
	// them.
	if pos >= len(scopedPDU) {
		return nil, true
	}
	pos++
	pduLen, newPos := parseLength(scopedPDU, pos)
	if pduLen < 0 || newPos+pduLen > len(scopedPDU) {
		return nil, true
	}
	pos = newPos
	end := newPos + pduLen

	// request-id, then error-status/non-repeaters and error-index/
	// max-repetitions. All three are skipped here; parseSNMPv3GetBulkParams
	// reads the two that matter.
	for i := 0; i < 3; i++ {
		if pos >= end || scopedPDU[pos] != ASN1_INTEGER {
			return nil, true
		}
		pos++
		n, newPos := parseLength(scopedPDU, pos)
		if n < 0 || newPos+n > end {
			return nil, true
		}
		pos = newPos + n
	}

	// Slicing to `end` is what bounds the list by its PDU rather than by the
	// datagram.
	return parseVarBindNames(scopedPDU[:end], pos)
}

// usmStats OIDs a Report can name (RFC 3414 §5). The whole subtree is typed
// Counter32 in oidTypeTable, so encodeTypedValue gives them the right tag.
const (
	oidUsmStatsUnsupportedSecLevels = ".1.3.6.1.6.3.15.1.1.1.0"
	oidUsmStatsUnknownEngineIDs     = ".1.3.6.1.6.3.15.1.1.4.0"
	oidUsmStatsDecryptionErrors     = ".1.3.6.1.6.3.15.1.1.6.0"
)

// createSNMPv3DiscoveryResponse answers an engine-ID discovery probe with a
// Report naming usmStatsUnknownEngineIDs.
func (s *SNMPServer) createSNMPv3DiscoveryResponse(requestMsg *SNMPv3Message) []byte {
	return s.createSNMPv3ReportResponse(oidUsmStatsUnknownEngineIDs, requestMsg)
}

// createSNMPv3ReportResponse builds a Report PDU naming the given usmStats
// counter, in the discovery envelope: noAuthNoPriv, report flag, empty user.
// Discovery and the decryption-error Report differ only in which counter they
// name, so they share this rather than growing a second envelope.
//
// RFC 3414 §3.2 step 8 requires a decryption failure to be answered this way.
// It used to share the malformed-PDU fallback and be answered with a GET of
// sysDescr.0 instead, so a manager using the wrong privacy key was handed a
// plausible-looking value for an object it had not asked about, with
// request-id 1 (nl6#547). Answering nothing would be worse than either: a
// wrong-password probe would be indistinguishable from an unreachable device.
//
// The request-id inside the Report is 1 for every caller: on a decryption
// failure the real one is inside the ciphertext. msgID is echoed, which is
// what RFC 3412 §7.2 matches a Report on.
func (s *SNMPServer) createSNMPv3ReportResponse(reportOID string, requestMsg *SNMPv3Message) []byte {
	if s.v3Config == nil || !s.v3Config.Enabled {
		return []byte{}
	}

	scopedPDU, err := s.createDiscoveryScopedPDU(reportOID, "1")
	if err != nil {
		// log.Printf("Failed to create discovery scoped PDU: %v", err)
		return []byte{}
	}

	// Create USM security parameters for discovery response
	secParams := SNMPv3SecurityParams{
		AuthoritativeEngineID:    s.v3Config.EngineID,
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  int(time.Now().Unix()),
		UserName:                 "", // Empty for discovery
		AuthParams:               []byte{},
		PrivParams:               []byte{},
	}

	// Encode USM parameters
	usmParams, err := s.encodeUSMSecurityParameters(&secParams)
	if err != nil {
		// log.Printf("Failed to encode USM parameters for discovery: %v", err)
		return []byte{}
	}

	// Create response message structure
	responseMsg := SNMPv3Message{
		Version: SNMPV3_VERSION,
		GlobalData: SNMPv3GlobalData{
			MsgID:            requestMsg.GlobalData.MsgID,
			MsgMaxSize:       65507,
			MsgFlags:         SNMPV3_MSG_FLAG_REPORT, // Set report flag
			MsgSecurityModel: SNMPV3_SECURITY_MODEL_USM,
		},
		ScopedPDU: scopedPDU,
	}

	// Encode the message
	msgBytes, err := s.encodeSNMPv3Message(&responseMsg, usmParams)
	if err != nil {
		// log.Printf("Failed to encode SNMPv3 discovery message: %v", err)
		return []byte{}
	}

	return msgBytes
}

// createDiscoveryScopedPDU creates a scoped PDU for discovery responses
func (s *SNMPServer) createDiscoveryScopedPDU(oid, value string) ([]byte, error) {
	// Encode through the same path as every other value, so the Report gets
	// the type its OID declares. RFC 3414 §5 makes every usmStats* object a
	// Counter32; this used to hardcode encodeInteger(1), which both ignored
	// the value argument and answered the wrong ASN.1 type (nl6#527). The
	// prefix is in oidTypeTable, so encodeTypedValue resolves it.
	valueBytes := encodeTypedValue(oid, value)

	// Create variable binding
	oidBytes := encodeOID(oid)
	varBind := encodeSequence(append(oidBytes, valueBytes...))
	varBindList := encodeSequence(varBind)

	// Create Report PDU (0xA8)
	pduContents := []byte{}
	pduContents = append(pduContents, encodeInteger(1)...) // request-id
	pduContents = append(pduContents, encodeInteger(0)...) // error-status
	pduContents = append(pduContents, encodeInteger(0)...) // error-index
	pduContents = append(pduContents, varBindList...)      // variable-bindings

	// Report PDU
	pdu := []byte{0xA8} // Report PDU type
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	// Scoped PDU: contextEngineID + contextName + data
	contextEngineID := encodeOctetString(s.v3Config.EngineID)
	contextName := encodeOctetString("") // Default context

	scopedContents := []byte{}
	scopedContents = append(scopedContents, contextEngineID...)
	scopedContents = append(scopedContents, contextName...)
	scopedContents = append(scopedContents, pdu...)

	return encodeSequence(scopedContents), nil
}
