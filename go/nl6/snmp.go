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
	if v3Msg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_PRIV != 0 {
		// log.Printf("SNMPv3: Privacy enabled, attempting decryption")
		decryptedPDU, err := s.decryptScopedPDU(v3Msg.ScopedPDU, v3Msg.SecurityParams.PrivParams)
		if err != nil {
			// log.Printf("SNMPv3: Failed to decrypt scoped PDU: %v", err)
			// log.Printf("SNMPv3: Using default OID for encrypted request (decryption failed)")
		} else {
			// log.Printf("SNMPv3: Successfully decrypted scoped PDU (%d bytes)", len(decryptedPDU))
			// Verify the decrypted data looks valid (starts with SEQUENCE tag)
			if len(decryptedPDU) > 0 && decryptedPDU[0] == ASN1_SEQUENCE {
				scopedPDU = decryptedPDU
				// log.Printf("SNMPv3: Decrypted data appears valid (starts with SEQUENCE)")
			} else {
				// log.Printf("SNMPv3: Decrypted data appears invalid (tag: 0x%02X), using default OID",
				//	func() byte { if len(decryptedPDU) > 0 { return decryptedPDU[0] } else { return 0 } }())
			}
		}
	}

	// Parse the scoped PDU to extract OID and request type
	oid, pduType, err := s.extractOIDAndTypeFromScopedPDU(scopedPDU)
	if err != nil {
		// log.Printf("Failed to extract OID from scoped PDU: %v, using default", err)
		// For encrypted requests where decryption failed, use a reasonable default
		// Since snmpwalk typically starts with 1.3.6.1.2.1.1, use system description
		oid = ".1.3.6.1.2.1.1.1.0" // System description OID
		pduType = ASN1_GET_REQUEST // Default to GET
		// log.Printf("SNMPv3: Using default OID %s for failed decryption case", oid)
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
			response = "endOfMibView"
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

// extractOIDFromScopedPDU extracts the first OID from a scoped PDU
func (s *SNMPServer) extractOIDFromScopedPDU(scopedPDU []byte) (string, error) {
	if len(scopedPDU) < 10 {
		return "", fmt.Errorf("scoped PDU too short")
	}

	pos := 0

	// Parse contextEngineID (OCTET STRING)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
		return "", fmt.Errorf("expected contextEngineID OCTET STRING")
	}
	pos++
	engineIDLen, newPos := parseLength(scopedPDU, pos)
	pos = newPos + engineIDLen

	// Parse contextName (OCTET STRING)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
		return "", fmt.Errorf("expected contextName OCTET STRING")
	}
	pos++
	contextNameLen, newPos := parseLength(scopedPDU, pos)
	pos = newPos + contextNameLen

	// Parse PDU - should be GetRequest (0xA0) or GetNext (0xA1)
	if pos >= len(scopedPDU) {
		return "", fmt.Errorf("unexpected end of scoped PDU")
	}

	pduType := scopedPDU[pos]

	if pduType != ASN1_GET_REQUEST && pduType != ASN1_GET_NEXT && pduType != ASN1_GET_BULK {
		return "", fmt.Errorf("unsupported PDU type in scoped PDU: 0x%02X", pduType)
	}
	pos++

	// Skip PDU length
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos

	// Parse request ID, error status, error index (skip them)
	for i := 0; i < 3; i++ {
		if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_INTEGER {
			return "", fmt.Errorf("expected INTEGER in PDU")
		}
		pos++
		intLen, newPos := parseLength(scopedPDU, pos)
		pos = newPos + intLen
	}

	// Parse variable bindings (SEQUENCE)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_SEQUENCE {
		return "", fmt.Errorf("expected variable bindings SEQUENCE")
	}
	pos++
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos

	// Parse first variable binding (SEQUENCE)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_SEQUENCE {
		return "", fmt.Errorf("expected first variable binding SEQUENCE")
	}
	pos++
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos

	// Parse OID (OBJECT IDENTIFIER)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OBJECT_ID {
		return "", fmt.Errorf("expected OID in variable binding")
	}
	pos++
	oidLen, newPos := parseLength(scopedPDU, pos)
	pos = newPos

	if pos+oidLen > len(scopedPDU) {
		return "", fmt.Errorf("OID length exceeds remaining data")
	}

	oidBytes := scopedPDU[pos : pos+oidLen]
	oid := decodeOID(oidBytes)

	return oid, nil
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
	pos = newPos + engineIDLen

	// Parse contextName (OCTET STRING)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
		return "", ASN1_GET_REQUEST, fmt.Errorf("expected contextName OCTET STRING")
	}
	pos++
	contextNameLen, newPos := parseLength(scopedPDU, pos)
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

	if pos+oidLen > len(scopedPDU) {
		return "", pduType, fmt.Errorf("OID length exceeds remaining data")
	}

	oidBytes := scopedPDU[pos : pos+oidLen]
	oid := decodeOID(oidBytes)

	return oid, pduType, nil
}

// createSNMPv3DiscoveryResponse creates a discovery response with engine ID
func (s *SNMPServer) createSNMPv3DiscoveryResponse(requestMsg *SNMPv3Message) []byte {
	if s.v3Config == nil || !s.v3Config.Enabled {
		return []byte{}
	}

	// log.Printf("SNMPv3: Creating discovery response with engine ID: %s", s.v3Config.EngineID)

	// Create discovery response scoped PDU (typically a report PDU)
	reportOID := ".1.3.6.1.6.3.15.1.1.4.0" // usmStatsUnknownEngineIDs
	reportValue := "1"                     // Counter value

	// Create simple report scoped PDU
	scopedPDU, err := s.createDiscoveryScopedPDU(reportOID, reportValue)
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
	// Create integer value for report counter
	valueBytes := encodeInteger(1)

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
