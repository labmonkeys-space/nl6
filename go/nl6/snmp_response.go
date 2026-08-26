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
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"fmt"
)

// SNMP request parser
type SNMPRequest struct {
	Community string
	RequestID int
	OID       string
	Version   int
}

// Parse incoming SNMP request to extract all needed info
func (s *SNMPServer) parseIncomingRequest(data []byte) SNMPRequest {
	req := SNMPRequest{
		Community: "public",
		RequestID: 123,
		OID:       ".1.3.6.1.2.1.1.1.0",
		Version:   1, // Default to SNMPv2c
	}

	if len(data) < 10 {
		return req
	}

	// Parse the SNMP packet structure
	// SEQUENCE { version, community, PDU }
	pos := 0

	// Skip SEQUENCE tag and length
	if data[pos] != ASN1_SEQUENCE {
		return req
	}
	pos++
	lengthSkip := s.skipLength(data[pos:])
	pos += lengthSkip

	// Parse version
	if pos < len(data) && data[pos] == ASN1_INTEGER {
		pos++
		versionLen, newPos := parseLength(data, pos)
		pos = newPos
		if versionLen == 1 && pos < len(data) {
			req.Version = int(data[pos])
		}
		if versionLen > 0 {
			pos += versionLen
		}
	}

	// Parse community
	if pos < len(data) && data[pos] == ASN1_OCTET_STRING {
		pos++
		communityLen, newPos := parseLength(data, pos)
		pos = newPos
		if communityLen > 0 && pos+communityLen <= len(data) {
			req.Community = string(data[pos : pos+communityLen])
			pos += communityLen
		}
	}

	// Parse PDU (GetRequest = 0xa0, GetNext = 0xa1, GetBulk = 0xa5)
	if pos < len(data) && (data[pos] == 0xa0 || data[pos] == 0xa1 || data[pos] == 0xa5) {
		pos++
		pduLengthSkip := s.skipLength(data[pos:])
		pos += pduLengthSkip

		// Parse request ID
		if pos < len(data) && data[pos] == ASN1_INTEGER {
			pos++
			reqIDLen, newPos := parseLength(data, pos)
			pos = newPos
			if reqIDLen > 0 && reqIDLen <= 4 && pos+reqIDLen <= len(data) {
				req.RequestID = 0
				for i := 0; i < reqIDLen; i++ {
					req.RequestID = (req.RequestID << 8) | int(data[pos+i])
				}
				pos += reqIDLen
			}
		}

		// Skip error-status and error-index
		for i := 0; i < 2; i++ {
			if pos < len(data) && data[pos] == ASN1_INTEGER {
				pos++
				fieldLen, newPos := parseLength(data, pos)
				if fieldLen >= 0 {
					pos = newPos + fieldLen
				}
			}
		}

		// Parse variable bindings
		if pos < len(data) && data[pos] == ASN1_SEQUENCE {
			pos++
			pos += s.skipLength(data[pos:])

			// First variable binding
			if pos < len(data) && data[pos] == ASN1_SEQUENCE {
				pos++
				pos += s.skipLength(data[pos:])

				// Parse OID
				if pos < len(data) && data[pos] == ASN1_OID {
					pos++
					oidLen, newPos := parseLength(data, pos)
					pos = newPos
					if oidLen > 0 && pos+oidLen <= len(data) {
						oidBytes := data[pos : pos+oidLen]
						if oid := decodeOID(oidBytes); oid != "" {
							req.OID = oid
						}
					}
				}
			}
		}
	}

	return req
}

// Create proper SNMP response packet
func (s *SNMPServer) createSNMPResponse(oid, value string, requestData []byte) []byte {
	// Parse incoming request to get actual community and request ID
	req := s.parseIncomingRequest(requestData)

	// Encode value with the correct ASN.1 type for this OID (RFC 1902).
	valueBytes := encodeTypedValue(oid, value)

	// Create variable binding (OID + value)
	oidBytes := encodeOID(oid)
	varBind := encodeSequence(append(oidBytes, valueBytes...))

	// Variable bindings list
	varBindList := encodeSequence(varBind)

	// PDU contents: request-id, error-status, error-index, variable-bindings
	pduContents := []byte{}
	pduContents = append(pduContents, encodeInteger(req.RequestID)...) // Use actual request ID
	pduContents = append(pduContents, encodeInteger(0)...)             // error-status (noError)
	pduContents = append(pduContents, encodeInteger(0)...)             // error-index
	pduContents = append(pduContents, varBindList...)                  // variable-bindings

	// GetResponse PDU
	pdu := []byte{SNMP_GET_RESPONSE}
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	// Message contents: version, community, PDU
	msgContents := []byte{}
	msgContents = append(msgContents, encodeInteger(req.Version)...)       // Use client's version
	msgContents = append(msgContents, encodeOctetString(req.Community)...) // Use actual community
	msgContents = append(msgContents, pdu...)                              // PDU

	// Complete SNMP message
	msg := encodeSequence(msgContents)
	// Debug: Hex dump of regular response
	// log.Printf("SNMP %s: Regular response hex: %x", s.device.ID, msg[:min(len(msg), 100)])
	return msg
}

// createGetBulkResponse creates a GetBulk response with multiple variable bindings
// maxSNMPResponseSize bounds an assembled SNMP response so the resulting UDP
// datagram FRAME fits the link, not so the payload fills it.
//
// Derived from the shared egress-path constants (datagram_budget.go) and
// refreshed by recomputeDatagramBudgets, so it tracks `-datagram-mtu`. udp4
// only, so no address-family branch: an agent answers whoever polls it, and
// nl6's devices bind per-device IPv4 sockets.
//
// Before nl6#489 there was no bound at all — `handleGetBulk` built
// maxRepetitions × repeaterCols bindings and handed the result to the kernel.
// At 10 columns × 127 repetitions that is a ~29 KB datagram in 20 fragments.
var maxSNMPResponseSize = defaultLinkMTU - ipv4HeaderBytes - udpHeaderBytes

// SNMP error-status values (RFC 3416 §3).
const (
	snmpErrNoError = 0
	snmpErrTooBig  = 1
)

// snmpOverflowRule selects what happens when a response will not fit the
// datagram budget. The two PDU types share this response encoder (deliberately
// — see nl6#176) but RFC 3416 gives them opposite rules, so the rule is an
// explicit argument rather than something the encoder infers from its caller.
//
// Getting this backwards is the most damaging mistake available here: a
// truncated GET is a silent partial answer that the requester cannot detect and
// has no way to complete.
type snmpOverflowRule int

const (
	// overflowTruncate: RFC 3416 §4.2.3. Emit as many variable bindings as fit
	// and stop. Safe because a walk resumes from the last OID returned.
	overflowTruncate snmpOverflowRule = iota
	// overflowTooBig: RFC 3416 §4.2.1. Replace the whole response with
	// error-status tooBig and an EMPTY binding list. A GET requester asked for
	// specific bindings and has no resume point.
	overflowTooBig
)

// lenBytesFor returns how many bytes encodeLength spends on a content length of
// n. Needed to size a message without assembling it: the three nested SEQUENCEs
// (variable-bindings, PDU, message) each carry one, and the width steps at 128
// and 256 — which is precisely the boundary region this bound operates in.
func lenBytesFor(n int) int {
	switch {
	case n < 128:
		return 1
	case n < 256:
		return 2
	default:
		return 3
	}
}

// snmpMessageSizeFor computes the exact encoded size of a GetResponse whose
// variable-binding list is varBindLen bytes, given the pre-computed sizes of
// the message prefix (version + community) and the PDU prefix (request-id +
// error-status + error-index).
//
// Exact and O(1), so the encode loop can test each candidate binding without
// assembling anything. An estimate would be the wrong tool here: every bug in
// this family has been a mismatch between a predicted size and an emitted one.
func snmpMessageSizeFor(msgPrefix, pduPrefix, varBindLen int) int {
	vbSeq := 1 + lenBytesFor(varBindLen) + varBindLen
	pduContents := pduPrefix + vbSeq
	pdu := 1 + lenBytesFor(pduContents) + pduContents
	msgContents := msgPrefix + pdu
	return 1 + lenBytesFor(msgContents) + msgContents
}

// createGetBulkResponse encodes a GETBULK response, truncating to fit the
// datagram budget (RFC 3416 §4.2.3).
func (s *SNMPServer) createGetBulkResponse(oids []string, responses []string, requestData []byte) []byte {
	return s.createVarbindResponse(oids, responses, requestData, overflowTruncate)
}

// createGetResponse encodes a GET response, returning tooBig rather than a
// partial one when it will not fit (RFC 3416 §4.2.1).
func (s *SNMPServer) createGetResponse(oids []string, responses []string, requestData []byte) []byte {
	return s.createVarbindResponse(oids, responses, requestData, overflowTooBig)
}

// createVarbindResponse builds a multi-variable-binding GetResponse bounded by
// maxSNMPResponseSize.
//
// `rule` decides what happens on overflow and MUST be supplied by the caller:
// GETBULK truncates, GET returns tooBig. See snmpOverflowRule for why that
// difference cannot be inferred here.
//
// Sizing is exact and incremental. Each binding is encoded once, its size added
// to a running total, and the resulting MESSAGE size computed in O(1) via
// snmpMessageSizeFor before it is committed — so nothing is ever assembled and
// then thrown away, and no estimate can drift from the encoder (the drift that
// produced nl6#486 and nl6#490).
func (s *SNMPServer) createVarbindResponse(oids []string, responses []string,
	requestData []byte, rule snmpOverflowRule) []byte {
	if len(oids) != len(responses) {
		// Fallback to single response
		return s.createSNMPResponse(".1.3.6.1.2.1.1.1.0", "No data", requestData)
	}

	req := s.parseIncomingRequest(requestData)

	// Fixed prefixes, needed to size the message without assembling it.
	msgPrefix := len(encodeInteger(req.Version)) + len(encodeOctetString(req.Community))
	pduPrefix := len(encodeInteger(req.RequestID)) + len(encodeInteger(0)) + len(encodeInteger(0))

	var varBindList []byte
	truncated := false
	for i, oid := range oids {
		valueBytes := encodeTypedValue(oid, responses[i])
		oidBytes := encodeOID(oid)
		varBindingContents := append(oidBytes, valueBytes...)

		varBinding := []byte{ASN1_SEQUENCE}
		varBinding = append(varBinding, encodeLength(len(varBindingContents))...)
		varBinding = append(varBinding, varBindingContents...)

		if snmpMessageSizeFor(msgPrefix, pduPrefix, len(varBindList)+len(varBinding)) > maxSNMPResponseSize {
			// Always emit at least one binding. A response with an empty
			// binding list and no error stalls a collector's walk forever with
			// no signal — the worst outcome available, and unreachable in
			// practice at any sane MTU, but the loop must not permit it.
			if len(varBindList) == 0 {
				varBindList = append(varBindList, varBinding...)
				continue
			}
			truncated = true
			break
		}
		varBindList = append(varBindList, varBinding...)
	}

	if truncated && rule == overflowTooBig {
		// RFC 3416 §4.2.1: the requester asked for specific bindings and cannot
		// resume, so report the failure instead of answering partially.
		return s.encodeGetResponse(req, nil, snmpErrTooBig)
	}
	return s.encodeGetResponse(req, varBindList, snmpErrNoError)
}

// encodeGetResponse wraps an already-encoded variable-binding list in the PDU
// and message framing. Split out so the tooBig path and the normal path cannot
// drift in their framing.
func (s *SNMPServer) encodeGetResponse(req SNMPRequest, varBindList []byte, errStatus int) []byte {
	varBindSequence := []byte{ASN1_SEQUENCE}
	varBindSequence = append(varBindSequence, encodeLength(len(varBindList))...)
	varBindSequence = append(varBindSequence, varBindList...)

	var pduContents []byte
	pduContents = append(pduContents, encodeInteger(req.RequestID)...)
	pduContents = append(pduContents, encodeInteger(errStatus)...) // error-status
	pduContents = append(pduContents, encodeInteger(0)...)         // error-index
	pduContents = append(pduContents, varBindSequence...)

	pdu := []byte{SNMP_GET_RESPONSE}
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	msgContents := []byte{}
	msgContents = append(msgContents, encodeInteger(req.Version)...)
	msgContents = append(msgContents, encodeOctetString(req.Community)...)
	msgContents = append(msgContents, pdu...)

	return encodeSequence(msgContents)
}

// decryptScopedPDU decrypts an encrypted scoped PDU
func (s *SNMPServer) decryptScopedPDU(encryptedPDU []byte, privParams []byte) ([]byte, error) {
	if s.v3Config.PrivProtocol == SNMPV3_PRIV_NONE {
		return encryptedPDU, nil
	}

	// log.Printf("SNMPv3: Attempting to decrypt scoped PDU with privacy protocol")

	// Decrypt based on the configured privacy protocol
	switch s.v3Config.PrivProtocol {
	case SNMPV3_PRIV_DES:
		// log.Printf("SNMPv3: Using DES decryption")
		return s.decryptDES(encryptedPDU, privParams)
	case SNMPV3_PRIV_AES128:
		// log.Printf("SNMPv3: Using AES128 decryption")
		return s.decryptAES128(encryptedPDU, privParams)
	default:
		return nil, fmt.Errorf("unsupported privacy protocol: %d", s.v3Config.PrivProtocol)
	}
}

// generateDESKey generates a DES key from the privacy password using RFC 3414 method
func (s *SNMPServer) generateDESKey() []byte {
	// RFC 3414 compatible key derivation for SNMPv3 privacy
	// This is a simplified version that should work with standard SNMP clients

	// Step 1: Create auth key from password using MD5
	password := s.v3Config.PrivPassword
	if len(password) == 0 {
		password = s.v3Config.Password // Fallback to main password
	}

	// Create 1MB buffer with repeated password (RFC 3414)
	passwordBytes := []byte(password)
	keyBuffer := make([]byte, 1048576) // 1MB
	for i := 0; i < len(keyBuffer); i++ {
		keyBuffer[i] = passwordBytes[i%len(passwordBytes)]
	}

	// Hash the 1MB buffer with MD5
	authKey := md5.Sum(keyBuffer)

	// Step 2: Localize the key with engine ID
	engineID := s.v3Config.EngineID
	if len(engineID) == 0 {
		engineID = "800000090300AABBCCDD" // Default engine ID
	}

	// Convert hex engine ID to bytes
	engineIDBytes, _ := s.parseHexEngineID(engineID)

	// Localize: MD5(authKey + engineID + authKey)
	localizeInput := append(append(authKey[:], engineIDBytes...), authKey[:]...)
	localizedKey := md5.Sum(localizeInput)

	// Step 3: For privacy key, derive from localized auth key
	// Privacy key = first 8 bytes of localized key for DES
	return localizedKey[:8]
}

// parseHexEngineID converts hex engine ID string to bytes
func (s *SNMPServer) parseHexEngineID(hexEngineID string) ([]byte, error) {
	// Remove any spaces or colons
	clean := ""
	for _, c := range hexEngineID {
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') {
			clean += string(c)
		}
	}

	// Convert hex pairs to bytes
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("invalid hex engine ID length")
	}

	result := make([]byte, len(clean)/2)
	for i := 0; i < len(clean); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := clean[i+j]
			b <<= 4
			if c >= '0' && c <= '9' {
				b |= c - '0'
			} else if c >= 'A' && c <= 'F' {
				b |= c - 'A' + 10
			} else if c >= 'a' && c <= 'f' {
				b |= c - 'a' + 10
			}
		}
		result[i/2] = b
	}

	return result, nil
}

// getDESKey returns the cached DES key, computing and caching it on first call
func (s *SNMPServer) getDESKey() []byte {
	if s.cachedDESKey != nil {
		return s.cachedDESKey
	}
	s.cachedDESKey = s.generateDESKey()
	return s.cachedDESKey
}

// decryptDES performs basic DES decryption (simplified for simulation)
func (s *SNMPServer) decryptDES(encryptedData []byte, privParams []byte) ([]byte, error) {
	if len(privParams) < 8 {
		return nil, fmt.Errorf("invalid DES privacy parameters length: %d", len(privParams))
	}

	// Use cached DES key derived from privacy password using RFC 3414 method
	key := s.getDESKey()
	iv := privParams[:8] // Use privacy parameters as IV

	// log.Printf("SNMPv3: DES decryption - key: %d bytes, IV: %d bytes, data: %d bytes",
	//	len(key), len(iv), len(encryptedData))

	// For simulation purposes, implement basic DES-CBC decryption
	// In a real implementation, you'd need proper key derivation from the password

	// Create DES cipher
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher: %v", err)
	}

	if len(encryptedData)%8 != 0 {
		return nil, fmt.Errorf("encrypted data length must be multiple of 8 bytes")
	}

	// Decrypt using CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encryptedData))
	mode.CryptBlocks(decrypted, encryptedData)

	// Remove PKCS padding (simplified)
	if len(decrypted) > 0 {
		paddingLen := int(decrypted[len(decrypted)-1])
		if paddingLen <= len(decrypted) && paddingLen <= 8 {
			decrypted = decrypted[:len(decrypted)-paddingLen]
		}
	}

	// log.Printf("SNMPv3: DES decryption completed - result: %d bytes", len(decrypted))

	return decrypted, nil
}
