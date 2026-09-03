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
	"fmt"
)

// usmPrivSaltRead fills the USM privacy salt. It IS crypto/rand.Read in
// production and the indirection changes nothing a peer sees.
//
// It exists because an authPriv message is non-deterministic by construction —
// the salt is random, the IV is built from it, and the auth digest covers the
// resulting ciphertext — so there is no way to prove such a message is
// byte-identical to what an earlier commit emitted without pinning that one
// input. A test fixes it and restores it. Same seam convention as
// FlowExporter.writeOverride and createBatchStageProbe: a var whose production
// value is the real thing.
//
// NEVER set it outside a test. A predictable salt is a real SNMPv3 privacy
// break.
var usmPrivSaltRead = rand.Read

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

	// PRIVACY REQUIRES AUTHENTICATION, and this is a real behaviour change
	// (nl6#624). USM defines no privacy-without-authentication security level,
	// and since nl6#624 the privacy key is localized with the AUTH protocol's
	// hash, so with no auth protocol there is no hash and no key. That
	// combination used to be accepted and to encrypt under a key derived with
	// a hardcoded hash; it would now be accepted at startup and then fail on
	// every single request with "no localized key is available", which is the
	// worst of both. Refusing it here turns a per-request runtime failure into
	// one startup message that says what to change.
	if c.AuthProtocol == SNMPV3_AUTH_NONE {
		return fmt.Errorf("snmpv3: privacy protocol %d requires an authentication protocol "+
			"(set -snmpv3-auth md5|sha1, or \"auth_protocol\"): USM defines no "+
			"privacy-without-authentication security level, and the privacy key is derived "+
			"with the authentication protocol's hash (RFC 3414 §2.6)", c.PrivProtocol)
	}

	// The privacy password falls back to the auth password, so checking only
	// PrivPassword would reject the common config that carries one password
	// for both. usmState applies the same fallback.
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
//
// RESPONSE-SHAPED READS ARE EXACTLY THREE — the two flag tests, the user name
// and the echoed msgID — so this is a thin adapter over
// wrapScopedPDUInV3MessageWith, which takes those three directly. Everything
// else the envelope carries is engine-authoritative and was never read off the
// request. A notification originator (nl6#98) has no request to echo: it
// supplies its own msgID, its own flag byte and its own user, and must reach
// the SAME envelope rather than a second one that can drift from it.
func (s *SNMPServer) wrapScopedPDUInV3Message(scopedPDU []byte, requestMsg *SNMPv3Message) ([]byte, error) {
	return s.wrapScopedPDUInV3MessageWith(scopedPDU,
		requestMsg.GlobalData.MsgID,
		requestMsg.GlobalData.MsgFlags,
		requestMsg.SecurityParams.UserName)
}

// wrapScopedPDUInV3MessageWith is wrapScopedPDUInV3Message with the three
// response-shaped inputs supplied explicitly.
//
// msgFlags is the security level ASKED FOR: privacy and authentication are
// applied when its PRIV / AUTH bits are set, and the emitted msgFlags is this
// byte with the reportable bit cleared. Passing a request's own msgFlags
// therefore reproduces the adapter exactly; an originator passes the level it
// intends to send at.
//
// IT VALIDATES NONE OF ITS THREE INPUTS, deliberately and for now: msgID is not
// range-checked against RFC 3412's 0..2^31-1, userName is not length-checked,
// and PRIV without AUTH is not refused here (the poll path refuses it inbound in
// authenticateInbound, and Validate refuses the CONFIGURATION, but this function
// would encrypt an unauthenticated message if asked). Today its only caller is
// the adapter, which sources all three from a request the dispatcher already
// parsed. Deciding what an ORIGINATOR may pass is nl6#98's, not this
// extraction's — do not read the absence of checks as a statement that none are
// needed.
func (s *SNMPServer) wrapScopedPDUInV3MessageWith(scopedPDU []byte, msgID int, msgFlags byte, userName string) ([]byte, error) {
	if s.v3Config == nil || !s.v3Config.Enabled {
		return nil, fmt.Errorf("SNMPv3 not configured")
	}

	// ONE clock sample for the whole message. The IV and the advertised
	// msgAuthoritativeEngineTime must be the same value, and reading the clock
	// on each side made them differ whenever assembly crossed a second
	// boundary — see encryptScopedPDUAt.
	usm := s.usmState()
	boots, engineTime := usm.engineBoots, usm.engineTimeSeconds()

	// Encrypt scoped PDU if privacy is enabled
	encryptedPDU, privParams := scopedPDU, []byte{}
	if s.v3Config.PrivProtocol != SNMPV3_PRIV_NONE && (msgFlags&SNMPV3_MSG_FLAG_PRIV) != 0 {
		var err error
		encryptedPDU, privParams, err = s.encryptScopedPDUAt(scopedPDU, boots, engineTime)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt scoped PDU: %v", err)
		}
	}

	// Create USM security parameters for response.
	//
	// The engine ID goes on the wire as OCTETS (nl6#624). It used to be the
	// ASCII of its hex spelling, while key localization used the decoded bytes,
	// so nl6 advertised one engine identity and keyed on another and no manager
	// could ever have derived the same key.
	//
	// Engine time is seconds since this engine booted (RFC 3414 §2.2), not a
	// Unix epoch: a manager applying the §3.2 window rejects an epoch outright.
	authenticating := usm.newHash != nil && (msgFlags&SNMPV3_MSG_FLAG_AUTH) != 0
	secParams := SNMPv3SecurityParams{
		AuthoritativeEngineID:    string(usm.engineID),
		AuthoritativeEngineBoots: boots,
		AuthoritativeEngineTime:  engineTime,
		UserName:                 userName,
		// Zeroed placeholder: RFC 3414 §6.3.1 computes the digest over the
		// whole message with this field present and zero-filled, so it can only
		// be filled after assembly.
		AuthParams: usmZeroedAuthParams(),
		PrivParams: privParams,
	}
	if !authenticating {
		// noAuthNoPriv sends a zero-LENGTH field, per §6.3.1. nl6 sent twelve
		// zero octets at every level before nl6#624.
		secParams.AuthParams = []byte{}
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
			MsgID:            msgID,
			MsgMaxSize:       65507,                                    // Standard max UDP payload
			MsgFlags:         msgFlags &^ byte(SNMPV3_MSG_FLAG_REPORT), // Clear report flag
			MsgSecurityModel: SNMPV3_SECURITY_MODEL_USM,
		},
		ScopedPDU: encryptedPDU,
	}

	// Encode the message - for unencrypted responses, we need to treat scoped PDU differently
	msgBytes, err := s.encodeSNMPv3Message(&responseMsg, usmParams)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SNMPv3 message: %v", err)
	}

	// Authenticate: digest over the assembled message carrying its own zeroed
	// auth field, then substituted in place (RFC 3414 §6.3.1).
	if authenticating {
		digest := usmAuthDigest(msgBytes, usm.authKey, usm.newHash)
		if digest == nil {
			return nil, fmt.Errorf("SNMPv3 authentication is configured but no key could be derived; " +
				"check that a password is set")
		}
		signed, err := substituteAuthParams(msgBytes, digest)
		if err != nil {
			return nil, fmt.Errorf("failed to insert msgAuthenticationParameters: %w", err)
		}
		msgBytes = signed
	}

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

	return wrapInScopedPDU(s.usmState().engineID, "", pdu), nil
}

// wrapInScopedPDU builds the RFC 3412 §6 ScopedPDU envelope around an
// ALREADY-ENCODED PDU:
//
//	ScopedPDU ::= SEQUENCE { contextEngineID OCTET STRING,
//	                         contextName     OCTET STRING,
//	                         data            ANY }
//
// Free and PDU-AGNOSTIC on purpose. The notification path (nl6#98) has to wrap
// an SNMPv2-Trap-PDU (0xA7), and createScopedPDUMulti structurally cannot carry
// one: it hardcodes ASN1_GET_RESPONSE, derives its request-id from an inbound
// PDU, and types its values by OID prefix rather than by Varbind.Type. So the
// envelope is lifted out rather than the builder generalised, and the pdu bytes
// are carried through UNTOUCHED — this function encodes no PDU of its own and
// inspects none of the bytes it is handed.
//
// engineID is the raw engine ID OCTETS, never its hex spelling — the nl6#624
// distinction, which is invisible locally and fatal on the wire.
func wrapInScopedPDU(engineID []byte, contextName string, pdu []byte) []byte {
	var scopedContents []byte
	scopedContents = append(scopedContents, encodeOctetString(string(engineID))...)
	scopedContents = append(scopedContents, encodeOctetString(contextName)...)
	scopedContents = append(scopedContents, pdu...)

	return encodeSequence(scopedContents)
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

	// Skip contextEngineID (OCTET STRING). Every length read in this function
	// — both skips AND the PDU length below — tests parseLength's -1 failure
	// signal before it is used: `pos = newPos + (-1)` walks the cursor
	// BACKWARD onto a byte already consumed, which is the nl6#560 defect one
	// message layer up, and reading a request id out of a PDU whose own length
	// is unreadable is the same fault without the cursor movement. There is no
	// envelope left to resynchronise against, so an unreadable length takes
	// the same default fallback as every other unparseable shape here.
	if pos < len(scopedPDU) && scopedPDU[pos] == ASN1_OCTET_STRING {
		pos++
		engineIDLen, newPos := parseLength(scopedPDU, pos)
		if engineIDLen < 0 {
			return 1
		}
		pos = newPos + engineIDLen
	}

	// Skip contextName (OCTET STRING)
	if pos < len(scopedPDU) && scopedPDU[pos] == ASN1_OCTET_STRING {
		pos++
		contextNameLen, newPos := parseLength(scopedPDU, pos)
		if contextNameLen < 0 {
			return 1
		}
		pos = newPos + contextNameLen
	}

	// Parse PDU to get request ID. The PDU's declared length BOUNDS the
	// request-id read (the nl6#537 rule: bounded by the PDU's own length, not
	// by the datagram), so a length that over-declares takes the fallback
	// rather than reading an INTEGER out of whatever follows.
	if pos < len(scopedPDU) && (scopedPDU[pos] == ASN1_GET_REQUEST || scopedPDU[pos] == ASN1_GET_NEXT || scopedPDU[pos] == ASN1_GET_BULK) {
		pos++ // Skip PDU type
		pduLen, newPos := parseLength(scopedPDU, pos)
		if pduLen < 0 || newPos+pduLen > len(scopedPDU) {
			return 1
		}
		pos = newPos
		end := pos + pduLen

		// Parse request ID (first INTEGER in PDU)
		if pos < end && scopedPDU[pos] == ASN1_INTEGER {
			requestID, _, err := parseInteger(scopedPDU[:end], pos)
			if err == nil {
				return requestID
			}
		}
	}

	return 1 // Default fallback
}

// encryptScopedPDU encrypts the scoped PDU using the configured privacy protocol
func (s *SNMPServer) encryptScopedPDU(scopedPDU []byte, requestMsg *SNMPv3Message) ([]byte, []byte, error) {
	u := s.usmState()
	return s.encryptScopedPDUAt(scopedPDU, u.engineBoots, u.engineTimeSeconds())
}

// encryptScopedPDUAt encrypts against the engine boots and time the message
// WILL ADVERTISE, which the caller passes in rather than each side reading the
// clock for itself.
//
// THE TWO READS HAD TO BECOME ONE. engineTimeSeconds() truncates to whole
// seconds, so when a response straddled a second boundary between the
// encryption and the assembly of msgSecurityParameters, the IV was built from
// T while the message advertised T+1. A peer building the IV per RFC 3826
// §3.1.2.1 from the values nl6 itself sent then decrypted garbage —
// intermittently, at a rate set by how long assembly takes. That is the exact
// defect class nl6#624 exists to remove, so leaving two reads in place would
// have reintroduced it in a form far harder to see than the original.
func (s *SNMPServer) encryptScopedPDUAt(scopedPDU []byte, boots, engineTime int) ([]byte, []byte, error) {
	// Encrypt based on the configured privacy protocol
	switch s.v3Config.PrivProtocol {
	case SNMPV3_PRIV_DES:
		return s.encryptDES(scopedPDU)
	case SNMPV3_PRIV_AES128:
		return s.encryptAES128At(scopedPDU, boots, engineTime)
	default:
		return nil, nil, fmt.Errorf("unsupported privacy protocol: %d", s.v3Config.PrivProtocol)
	}
}

// encryptDES encrypts data using DES
func (s *SNMPServer) encryptDES(data []byte) ([]byte, []byte, error) {
	// RFC 3414 §8.1.1.1: the localized privacy key is 16 octets. The first 8
	// are the DES key; the last 8 are the PRE-IV, and the IV is salt XOR
	// pre-IV with the salt sent as privParams.
	//
	// Before nl6#624 one random value was used as both the IV and privParams,
	// and the key was 8 octets so no pre-IV existed at all. A conforming peer
	// XORs the salt it received against its own pre-IV and gets a different IV.
	usm := s.usmState()
	if len(usm.privKey) < 16 {
		return nil, nil, fmt.Errorf("SNMPv3 privacy is configured but no localized key is available; " +
			"check that a password or priv_password is set")
	}
	key, preIV := usm.privKey[:8], usm.privKey[8:16]

	// The salt is what goes on the wire. usmPrivSaltRead is `crypto/rand.Read`
	// in production, which only errors on a misconfigured kernel entropy
	// source; a predictable salt is a real SNMPv3 privacy break, so fail
	// loudly.
	salt := make([]byte, 8)
	if _, err := usmPrivSaltRead(salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate DES salt: %w", err)
	}
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = salt[i] ^ preIV[i]
	}

	// Pad data to block size
	padded := s.padData(data, 8)

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// The IV is filled by crypto/rand above; gosec's flow analysis
	// doesn't trace the usmPrivSaltRead fill, so the slice literal here
	// trips G407 as if it were hardcoded.
	// #nosec G407 -- IV is random (see usmPrivSaltRead above)
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	// privParams carries the SALT, not the IV.
	return encrypted, salt, nil
}

// encryptAES128At builds the RFC 3826 §3.1.2.1 IV from the boots and time the
// message advertises. See encryptScopedPDUAt for why they are passed in.
func (s *SNMPServer) encryptAES128At(data []byte, boots, engineTime int) ([]byte, []byte, error) {
	// The localized PRIVACY key, derived with the AUTH protocol's hash from the
	// privacy password (nl6#624). It was the auth password hashed with SHA1
	// whatever the configuration said, so a conforming manager derived a
	// different key and decryption never had a chance.
	usm := s.usmState()
	aesKey := usm.privKey
	if len(aesKey) < 16 {
		return nil, nil, fmt.Errorf("SNMPv3 privacy is configured but no localized key is available; " +
			"check that a password or priv_password is set")
	}
	aesKey = aesKey[:16]

	// Create AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// For SNMPv3 AES, create IV from engine boots/time + salt
	iv := make([]byte, aes.BlockSize)

	// First 8 bytes: the engine boots and engine time this message ADVERTISES
	// (RFC 3826 §3.1.2.1). Both were hardcoded before nl6#624, against a
	// msgAuthoritativeEngineTime that said something else, so a peer building
	// the IV from the values nl6 itself sent decrypted garbage.
	iv[0], iv[1], iv[2], iv[3] = byte(boots>>24), byte(boots>>16), byte(boots>>8), byte(boots)
	iv[4], iv[5], iv[6], iv[7] = byte(engineTime>>24), byte(engineTime>>16), byte(engineTime>>8), byte(engineTime)

	// Last 8 bytes: random salt (privacy parameters)
	salt := make([]byte, 8)
	if _, err := usmPrivSaltRead(salt); err != nil {
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

// decryptAES128At decrypts against the engine boots and time the SENDER
// declared, which is what RFC 3826 §3.1.2.1 builds the IV from.
//
// The declared values are used rather than this engine's own because a manager
// keeps its own estimate of our engine time and the two drift by seconds. An IV
// is an exact input, not a windowed one, so decrypting with our current reading
// fails as soon as they differ. nl6 hardcoded the prefix entirely before
// nl6#624, which made the question moot and the result wrong.
func (s *SNMPServer) decryptAES128At(encrypted, privParams []byte, boots, engineTime int) ([]byte, error) {
	if len(privParams) != 8 {
		return nil, fmt.Errorf("invalid AES salt length: expected 8, got %d", len(privParams))
	}

	// In SNMPv3 AES, the IV is constructed from:
	// - First 8 bytes: engine boots (4) + engine time (4)
	// - Last 8 bytes: privacy parameters (salt)
	iv := make([]byte, aes.BlockSize)

	iv[0], iv[1], iv[2], iv[3] = byte(boots>>24), byte(boots>>16), byte(boots>>8), byte(boots)
	iv[4], iv[5], iv[6], iv[7] = byte(engineTime>>24), byte(engineTime>>16), byte(engineTime>>8), byte(engineTime)

	// Privacy parameters for last 8 bytes
	copy(iv[8:16], privParams)

	usm := s.usmState()
	if len(usm.privKey) < 16 {
		return nil, fmt.Errorf("SNMPv3 privacy is configured but no localized key is available")
	}
	block, err := aes.NewCipher(usm.privKey[:16])
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
