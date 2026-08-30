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
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"time"
)

// Validate rejects an SNMPv3 config that cannot derive a privacy key.
//
// Both AES and DES localise the key by repeating the password to fill a 1 MB
// buffer (RFC 3414 §A.2), which is undefined for an empty password. The config
// is settable per device over REST, so without this check a single POST arms
// every subsequent encrypted request on that device to fail key derivation.
// Nil and privacy-disabled configs are valid; only the privacy case needs a
// password. Safe on nil.
func (c *SNMPv3Config) Validate() error {
	if c == nil || !c.Enabled || c.PrivProtocol == SNMPV3_PRIV_NONE {
		return nil
	}

	// Mirror generateDESKey's fallback: PrivPassword when set, else Password.
	// Checking only PrivPassword would reject the common config that carries
	// one password for both auth and privacy.
	if c.PrivPassword == "" && c.Password == "" {
		return fmt.Errorf("snmpv3: privacy protocol %d requires a non-empty password (set \"password\" or \"priv_password\")", c.PrivProtocol)
	}

	return nil
}

// createSNMPv3Response creates a single-binding SNMPv3 response message. The
// "not configured" guard lives in wrapScopedPDUInV3Message, which every
// response passes through.
func (s *SNMPServer) createSNMPv3Response(oid, value string, requestMsg *SNMPv3Message) ([]byte, error) {
	scopedPDU, err := s.createScopedPDU(oid, value, requestMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to create scoped PDU: %v", err)
	}
	return s.wrapScopedPDUInV3Message(scopedPDU, requestMsg)
}

// wrapScopedPDUInV3Message encrypts a scoped PDU when the request asked for
// privacy and wraps it in the SNMPv3 message envelope.
//
// Split out of createSNMPv3Response so a multi-binding GETBULK response can
// reuse the SAME envelope rather than growing a second one. This package has
// been bitten twice by paired encoders that were supposed to agree and drifted
// (nl6#529's encodeOID/appendOID, nl6#539's validateDottedOID), so the
// GETBULK builder measures its candidate through this function rather than
// predicting what it would produce.
func (s *SNMPServer) wrapScopedPDUInV3Message(scopedPDU []byte, requestMsg *SNMPv3Message) ([]byte, error) {
	if s.v3Config == nil || !s.v3Config.Enabled {
		return nil, fmt.Errorf("SNMPv3 not configured")
	}

	// Encrypt scoped PDU if privacy is enabled
	encryptedPDU, privParams := scopedPDU, []byte{}
	if s.v3Config.PrivProtocol != SNMPV3_PRIV_NONE && (requestMsg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_PRIV) != 0 {
		var err error
		encryptedPDU, privParams, err = s.encryptScopedPDU(scopedPDU, requestMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt scoped PDU: %v", err)
		}
	}

	// Create USM security parameters for response
	secParams := SNMPv3SecurityParams{
		AuthoritativeEngineID:    s.v3Config.EngineID,
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  int(time.Now().Unix()),
		UserName:                 requestMsg.SecurityParams.UserName,
		AuthParams:               make([]byte, 12), // Will be filled by authentication
		PrivParams:               privParams,
	}

	// For basic simulation, don't require actual HMAC validation
	// Copy the request's auth params if present (simplified approach)
	if len(requestMsg.SecurityParams.AuthParams) > 0 {
		// log.Printf("SNMPv3: Using simplified auth params for response")
		secParams.AuthParams = make([]byte, 12) // Standard 12-byte auth params
	}

	// Encode USM parameters
	usmParams, err := s.encodeUSMSecurityParameters(&secParams)
	if err != nil {
		return nil, fmt.Errorf("failed to encode USM parameters: %v", err)
	}

	// Create response message structure
	responseMsg := SNMPv3Message{
		Version: SNMPV3_VERSION,
		GlobalData: SNMPv3GlobalData{
			MsgID:            requestMsg.GlobalData.MsgID,
			MsgMaxSize:       65507,                                                          // Standard max UDP payload
			MsgFlags:         requestMsg.GlobalData.MsgFlags &^ byte(SNMPV3_MSG_FLAG_REPORT), // Clear report flag
			MsgSecurityModel: SNMPV3_SECURITY_MODEL_USM,
		},
		ScopedPDU: encryptedPDU,
	}

	// Encode the message - for unencrypted responses, we need to treat scoped PDU differently
	msgBytes, err := s.encodeSNMPv3Message(&responseMsg, usmParams)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SNMPv3 message: %v", err)
	}

	// Simulation deliberately skips HMAC authentication — proper RFC 3414
	// key derivation is out of scope for the simulator. A production agent
	// would authenticate here when AuthProtocol != NONE and the message
	// AUTH flag is set.

	return msgBytes, nil
}

// createScopedPDUMulti builds a scoped PDU carrying SEVERAL variable bindings.
//
// createScopedPDU is the single-binding case and delegates here, so there is
// ONE envelope construction rather than two that can drift. Drift between a
// pair of encoders that were supposed to agree is a recurring defect in this
// package: see nl6#529's encodeOID/appendOID pair and nl6#539's
// validateDottedOID.
//
// Every value goes through encodeTypedValue, so the exception sentinels and the
// per-OID types nl6#518 and nl6#522 established apply to each binding here too.
func (s *SNMPServer) createScopedPDUMulti(oids, values []string, requestMsg *SNMPv3Message) ([]byte, error) {
	if len(oids) != len(values) {
		return nil, fmt.Errorf("createScopedPDUMulti: %d oids but %d values", len(oids), len(values))
	}

	requestID := s.extractRequestIDFromScopedPDU(requestMsg.ScopedPDU)

	var varBinds []byte
	for i, oid := range oids {
		varBinds = append(varBinds, encodeVarBind(oid, encodeTypedValue(oid, values[i]))...)
	}
	varBindList := encodeSequence(varBinds)

	var pduContents []byte
	pduContents = append(pduContents, encodeInteger(requestID)...)
	pduContents = append(pduContents, encodeInteger(0)...) // error-status (noError)
	pduContents = append(pduContents, encodeInteger(0)...) // error-index
	pduContents = append(pduContents, varBindList...)

	pdu := []byte{ASN1_GET_RESPONSE}
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	var scopedContents []byte
	scopedContents = append(scopedContents, encodeOctetString(s.v3Config.EngineID)...)
	scopedContents = append(scopedContents, encodeOctetString("")...)
	scopedContents = append(scopedContents, pdu...)

	return encodeSequence(scopedContents), nil
}

// createScopedPDU creates the scoped PDU carrying one variable binding.
func (s *SNMPServer) createScopedPDU(oid, value string, requestMsg *SNMPv3Message) ([]byte, error) {
	return s.createScopedPDUMulti([]string{oid}, []string{value}, requestMsg)
}

// extractRequestIDFromScopedPDU extracts the request ID from the incoming scoped PDU
func (s *SNMPServer) extractRequestIDFromScopedPDU(scopedPDU []byte) int {
	if len(scopedPDU) < 10 {
		return 1 // Default fallback
	}

	pos := 0

	// Skip contextEngineID (OCTET STRING)
	if pos < len(scopedPDU) && scopedPDU[pos] == ASN1_OCTET_STRING {
		pos++
		engineIDLen, newPos := parseLength(scopedPDU, pos)
		pos = newPos + engineIDLen
	}

	// Skip contextName (OCTET STRING)
	if pos < len(scopedPDU) && scopedPDU[pos] == ASN1_OCTET_STRING {
		pos++
		contextNameLen, newPos := parseLength(scopedPDU, pos)
		pos = newPos + contextNameLen
	}

	// Parse PDU to get request ID
	if pos < len(scopedPDU) && (scopedPDU[pos] == ASN1_GET_REQUEST || scopedPDU[pos] == ASN1_GET_NEXT || scopedPDU[pos] == ASN1_GET_BULK) {
		pos++                                    // Skip PDU type
		_, newPos := parseLength(scopedPDU, pos) // Skip PDU length
		pos = newPos

		// Parse request ID (first INTEGER in PDU)
		if pos < len(scopedPDU) && scopedPDU[pos] == ASN1_INTEGER {
			requestID, _, err := parseInteger(scopedPDU, pos)
			if err == nil {
				return requestID
			}
		}
	}

	return 1 // Default fallback
}

// encryptScopedPDU encrypts the scoped PDU using the configured privacy protocol
func (s *SNMPServer) encryptScopedPDU(scopedPDU []byte, requestMsg *SNMPv3Message) ([]byte, []byte, error) {
	// Encrypt based on the configured privacy protocol
	switch s.v3Config.PrivProtocol {
	case SNMPV3_PRIV_DES:
		return s.encryptDES(scopedPDU)
	case SNMPV3_PRIV_AES128:
		return s.encryptAES128(scopedPDU)
	default:
		return nil, nil, fmt.Errorf("unsupported privacy protocol: %d", s.v3Config.PrivProtocol)
	}
}

// encryptDES encrypts data using DES
func (s *SNMPServer) encryptDES(data []byte) ([]byte, []byte, error) {
	// Use cached DES key from privacy password
	key := s.getDESKey()

	// Generate random IV (8 bytes for DES). `crypto/rand.Read` only
	// errors on a misconfigured kernel entropy source — fail loudly
	// since a non-random IV would be a real SNMPv3 privacy break.
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("failed to generate DES IV: %w", err)
	}

	// Pad data to block size
	padded := s.padData(data, 8)

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// The IV is filled by crypto/rand above; gosec's flow analysis
	// doesn't trace the rand.Read fill, so the slice literal here
	// trips G407 as if it were hardcoded.
	// #nosec G407 -- IV is random (see rand.Read above)
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	return encrypted, iv, nil
}

// getAESKey returns the cached AES key, computing and caching it on first call
func (s *SNMPServer) getAESKey() []byte {
	if s.cachedAESKey != nil {
		return s.cachedAESKey
	}
	s.cachedAESKey = s.generateAESKey(s.v3Config.Password)
	return s.cachedAESKey
}

// encryptAES128 encrypts data using AES-128-CFB
func (s *SNMPServer) encryptAES128(data []byte) ([]byte, []byte, error) {
	// Use cached AES key from password
	aesKey := s.getAESKey()

	// Create AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// For SNMPv3 AES, create IV from engine boots/time + salt
	iv := make([]byte, aes.BlockSize)

	// First 8 bytes: engine boots (4) + engine time (4)
	copy(iv[0:4], []byte{0x00, 0x00, 0x00, 0x01}) // engine boots = 1
	copy(iv[4:8], []byte{0x68, 0xa9, 0x48, 0xcf}) // simplified engine time

	// Last 8 bytes: random salt (privacy parameters)
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	copy(iv[8:16], salt)

	// Create CFB encrypter. SNMPv3 AES privacy (RFC 3826) MANDATES
	// CFB mode; AEAD alternatives would break interoperability with
	// every SNMPv3-capable manager. The IV is per-RFC-3826: 8-byte
	// "engine boots + engine time" prefix + 8-byte random salt. The
	// prefix bytes are intentionally fixed values for the simulation
	// (this is not a security-bearing agent); gosec G407 flags the
	// fixed-prefix slice as if it were a static IV.
	// #nosec G407 -- per RFC 3826 IV layout; simulator deliberately fixes engine-boots/time prefix
	stream := cipher.NewCFBEncrypter(block, iv) //nolint:staticcheck // RFC 3826 requires CFB for SNMPv3 AES privacy

	// Encrypt the data
	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	return encrypted, salt, nil // Return only the 8-byte salt, not full IV
}

// decryptAES128 decrypts data using AES-128-CFB
func (s *SNMPServer) decryptAES128(encrypted []byte, privParams []byte) ([]byte, error) {
	if len(privParams) != 8 {
		return nil, fmt.Errorf("invalid AES salt length: expected 8, got %d", len(privParams))
	}

	// In SNMPv3 AES, the IV is constructed from:
	// - First 8 bytes: engine boots (4) + engine time (4)
	// - Last 8 bytes: privacy parameters (salt)
	iv := make([]byte, aes.BlockSize)

	// Use engine boots and time for first 8 bytes (simplified for simulation)
	copy(iv[0:4], []byte{0x00, 0x00, 0x00, 0x01}) // engine boots = 1
	copy(iv[4:8], []byte{0x68, 0xa9, 0x48, 0xcf}) // simplified engine time

	// Privacy parameters for last 8 bytes
	copy(iv[8:16], privParams)

	// Use cached AES key from password
	aesKey := s.getAESKey()

	// Create AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create CFB decrypter. RFC 3826 requirement — see encryptAES128.
	stream := cipher.NewCFBDecrypter(block, iv) //nolint:staticcheck // RFC 3826 requires CFB for SNMPv3 AES privacy

	// Decrypt the data
	decrypted := make([]byte, len(encrypted))
	stream.XORKeyStream(decrypted, encrypted)

	return decrypted, nil
}

// generateAESKey generates a 16-byte AES key from password using RFC 3414 algorithm
func (s *SNMPServer) generateAESKey(password string) []byte {
	// RFC 3414 key localization algorithm for AES
	// Create 1MB buffer from password
	passwordBytes := []byte(password)
	// See generateDESKey: an empty password divides by zero in the modulo
	// below. nil fails cleanly through aes.NewCipher's KeySizeError; a
	// zero-filled key of the right length would not fail at all.
	if len(passwordBytes) == 0 {
		return nil
	}
	buffer := make([]byte, 1048576) // 1MB

	for i := 0; i < len(buffer); i++ {
		buffer[i] = passwordBytes[i%len(passwordBytes)]
	}

	// Hash the buffer with SHA1 (for AES we typically use SHA1)
	hasher := sha1.New()
	hasher.Write(buffer)
	hash := hasher.Sum(nil)

	// Localize the key with engine ID
	engineIDBytes, err := s.parseHexEngineID(s.v3Config.EngineID)
	if err != nil {
		engineIDBytes = []byte("default")
	}

	localizer := sha1.New()
	localizer.Write(hash)
	localizer.Write(engineIDBytes)
	localizer.Write(hash)
	localKey := localizer.Sum(nil)

	// Return first 16 bytes for AES-128
	aesKey := make([]byte, 16)
	copy(aesKey, localKey[:16])

	return aesKey
}

// padData pads data to the specified block size
func (s *SNMPServer) padData(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}

	padded := make([]byte, len(data)+padding)
	copy(padded, data)

	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

	return padded
}

// encodeUSMSecurityParameters encodes USM security parameters
func (s *SNMPServer) encodeUSMSecurityParameters(params *SNMPv3SecurityParams) ([]byte, error) {
	contents := []byte{}
	contents = append(contents, encodeOctetString(params.AuthoritativeEngineID)...)
	contents = append(contents, encodeInteger(params.AuthoritativeEngineBoots)...)
	contents = append(contents, encodeInteger(params.AuthoritativeEngineTime)...)
	contents = append(contents, encodeOctetString(params.UserName)...)
	contents = append(contents, encodeOctetString(string(params.AuthParams))...)
	contents = append(contents, encodeOctetString(string(params.PrivParams))...)

	return encodeSequence(contents), nil
}

// encodeSNMPv3Message encodes the complete SNMPv3 message
func (s *SNMPServer) encodeSNMPv3Message(msg *SNMPv3Message, usmParams []byte) ([]byte, error) {
	contents := []byte{}

	// Version
	contents = append(contents, encodeInteger(msg.Version)...)

	// Global Data
	globalContents := []byte{}
	globalContents = append(globalContents, encodeInteger(msg.GlobalData.MsgID)...)
	globalContents = append(globalContents, encodeInteger(msg.GlobalData.MsgMaxSize)...)
	globalContents = append(globalContents, encodeOctetString(string([]byte{msg.GlobalData.MsgFlags}))...)
	globalContents = append(globalContents, encodeInteger(msg.GlobalData.MsgSecurityModel)...)

	contents = append(contents, encodeSequence(globalContents)...)

	// Security Parameters (always OCTET STRING)
	contents = append(contents, encodeOctetString(string(usmParams))...)

	// Scoped PDU - encode as SEQUENCE for unencrypted, OCTET STRING for encrypted
	// For unencrypted messages (no privacy), scoped PDU is sent as raw bytes (SEQUENCE)
	// For encrypted messages, it would be wrapped in OCTET STRING
	isEncrypted := (msg.GlobalData.MsgFlags & SNMPV3_MSG_FLAG_PRIV) != 0

	if isEncrypted {
		// Encrypted: wrap in OCTET STRING
		contents = append(contents, encodeOctetString(string(msg.ScopedPDU))...)
	} else {
		// Unencrypted: append as-is (already a SEQUENCE)
		contents = append(contents, msg.ScopedPDU...)
	}

	return encodeSequence(contents), nil
}
