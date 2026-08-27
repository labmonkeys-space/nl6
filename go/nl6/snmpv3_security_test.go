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
	"testing"
)

// TestIsSNMPv3Request_TruncatedVersionByte verifies that isSNMPv3Request
// does not panic when the version byte is missing after a valid version
// length declaration. This is the primary classifier vulnerability from
// the pentest finding.
func TestIsSNMPv3Request_TruncatedVersionByte(t *testing.T) {
	// Minimal valid-prefix packet: outer SEQUENCE + INTEGER tag + length=1,
	// but the declared version byte is absent.
	// Structure: [SEQUENCE][length=4][INTEGER][length=1]
	malformed := []byte{0x30, 0x04, 0x02, 0x01}

	// Should return false without panicking
	result := isSNMPv3Request(malformed)
	if result {
		t.Error("isSNMPv3Request should return false for truncated packet")
	}
}

// TestIsSNMPv3Request_ValidSNMPv3 verifies that valid SNMPv3 packets
// are still correctly identified after the bounds-checking fix.
func TestIsSNMPv3Request_ValidSNMPv3(t *testing.T) {
	// Minimal valid SNMPv3 packet structure:
	// [SEQUENCE][length][INTEGER][length=1][version=3][SEQUENCE]...
	validV3 := []byte{
		0x30, 0x0A,       // SEQUENCE, length 10
		0x02, 0x01, 0x03, // INTEGER, length 1, value 3 (SNMPv3)
		0x30, 0x05,       // SEQUENCE (global data)
		0x02, 0x01, 0x00, // msgID
		0x00, 0x00,       // padding
	}

	result := isSNMPv3Request(validV3)
	if !result {
		t.Error("isSNMPv3Request should return true for valid SNMPv3 packet")
	}
}

// TestIsSNMPv3Request_SNMPv2c verifies that SNMPv2c packets are correctly
// rejected (version != 3).
func TestIsSNMPv3Request_SNMPv2c(t *testing.T) {
	// SNMPv2c packet (version = 1)
	v2cPacket := []byte{
		0x30, 0x0A,       // SEQUENCE, length 10
		0x02, 0x01, 0x01, // INTEGER, length 1, value 1 (SNMPv2c)
		0x04, 0x06,       // OCTET STRING (community)
		0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // "public"
	}

	result := isSNMPv3Request(v2cPacket)
	if result {
		t.Error("isSNMPv3Request should return false for SNMPv2c packet")
	}
}

// TestParseSNMPv3Message_NegativeScopedPDULength verifies that
// parseSNMPv3Message rejects packets with malformed (negative) scoped PDU
// lengths returned by parseLength.
func TestParseSNMPv3Message_NegativeScopedPDULength(t *testing.T) {
	server := &SNMPServer{
		v3Config: &SNMPv3Config{
			Enabled: true,
		},
	}

	// Craft a packet with a malformed long-form length that parseLength
	// will reject (return -1). This uses an invalid long-form encoding.
	// Structure: valid headers up to scopedPDU, then invalid length encoding
	malformed := []byte{
		0x30, 0x30,       // SEQUENCE, length 48
		0x02, 0x01, 0x03, // INTEGER, version 3
		0x30, 0x0C,       // SEQUENCE, global data
		0x02, 0x01, 0x01, // msgID = 1
		0x02, 0x02, 0x05, 0xDC, // msgMaxSize = 1500
		0x04, 0x01, 0x00, // msgFlags = 0
		0x02, 0x01, 0x03, // msgSecurityModel = 3 (USM)
		0x04, 0x00,       // msgSecurityParameters (empty)
		0x30,             // SEQUENCE tag for scopedPDU
		0x85, 0x00, 0x00, 0x00, 0x00, 0x00, // Invalid long-form: 5 length bytes (> 4)
	}

	_, err := server.parseSNMPv3Message(malformed)
	if err == nil {
		t.Error("parseSNMPv3Message should reject packet with invalid scoped PDU length")
	}
}

// TestExtractOIDAndTypeFromScopedPDU_NegativeContextEngineIDLength verifies
// that extractOIDAndTypeFromScopedPDU rejects scoped PDUs with negative
// contextEngineID lengths.
func TestExtractOIDAndTypeFromScopedPDU_NegativeContextEngineIDLength(t *testing.T) {
	server := &SNMPServer{}

	// Scoped PDU with invalid long-form length for contextEngineID
	malformed := []byte{
		0x04,             // OCTET STRING tag
		0x85, 0x00, 0x00, 0x00, 0x00, 0x00, // Invalid: 5 length bytes
	}

	_, _, err := server.extractOIDAndTypeFromScopedPDU(malformed)
	if err == nil {
		t.Error("extractOIDAndTypeFromScopedPDU should reject negative contextEngineID length")
	}
}

// TestExtractOIDAndTypeFromScopedPDU_NegativeContextNameLength verifies
// that extractOIDAndTypeFromScopedPDU rejects scoped PDUs with negative
// contextName lengths.
func TestExtractOIDAndTypeFromScopedPDU_NegativeContextNameLength(t *testing.T) {
	server := &SNMPServer{}

	// Scoped PDU with valid contextEngineID but invalid contextName length
	malformed := []byte{
		0x04, 0x00,       // contextEngineID: OCTET STRING, length 0
		0x04,             // contextName: OCTET STRING tag
		0x85, 0x00, 0x00, 0x00, 0x00, 0x00, // Invalid: 5 length bytes
	}

	_, _, err := server.extractOIDAndTypeFromScopedPDU(malformed)
	if err == nil {
		t.Error("extractOIDAndTypeFromScopedPDU should reject negative contextName length")
	}
}

// TestExtractOIDAndTypeFromScopedPDU_NegativeOIDLength verifies that
// extractOIDAndTypeFromScopedPDU rejects scoped PDUs with negative OID lengths.
func TestExtractOIDAndTypeFromScopedPDU_NegativeOIDLength(t *testing.T) {
	server := &SNMPServer{}

	// Scoped PDU with valid structure up to OID, then invalid OID length
	malformed := []byte{
		0x04, 0x00,       // contextEngineID: OCTET STRING, length 0
		0x04, 0x00,       // contextName: OCTET STRING, length 0
		0xA0, 0x20,       // GetRequest PDU, length 32
		0x02, 0x01, 0x01, // request-id = 1
		0x02, 0x01, 0x00, // error-status = 0
		0x02, 0x01, 0x00, // error-index = 0
		0x30, 0x12,       // variable bindings SEQUENCE, length 18
		0x30, 0x10,       // first varbind SEQUENCE, length 16
		0x06,             // OID tag
		0x85, 0x00, 0x00, 0x00, 0x00, 0x00, // Invalid: 5 length bytes
	}

	_, _, err := server.extractOIDAndTypeFromScopedPDU(malformed)
	if err == nil {
		t.Error("extractOIDAndTypeFromScopedPDU should reject negative OID length")
	}
}

// TestHandleSingleRequest_PanicRecovery verifies that handleSingleRequest
// recovers from panics and does not terminate the process.
func TestHandleSingleRequest_PanicRecovery(t *testing.T) {
	// Create a minimal SNMPServer
	server := &SNMPServer{
		v3Config: &SNMPv3Config{
			Enabled: true,
		},
	}

	// Use the truncated packet that would have caused a panic
	malformed := []byte{0x30, 0x04, 0x02, 0x01}

	// This should not panic - the defer recover() should catch it
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("handleSingleRequest panicked despite recovery boundary: %v", r)
		}
	}()

	// Call handleSingleRequest with nil clientAddr (we're not testing UDP send)
	server.handleSingleRequest(malformed, nil)

	// If we reach here, the panic was caught successfully
}

// TestExtractOIDAndTypeFromScopedPDU_ValidPacket verifies that valid
// scoped PDUs are still correctly parsed after the bounds-checking fixes.
func TestExtractOIDAndTypeFromScopedPDU_ValidPacket(t *testing.T) {
	server := &SNMPServer{}

	// Valid scoped PDU with a simple GetRequest for sysDescr.0
	validScopedPDU := []byte{
		0x04, 0x00,       // contextEngineID: OCTET STRING, length 0
		0x04, 0x00,       // contextName: OCTET STRING, length 0
		0xA0, 0x1A,       // GetRequest PDU, length 26
		0x02, 0x01, 0x01, // request-id = 1
		0x02, 0x01, 0x00, // error-status = 0
		0x02, 0x01, 0x00, // error-index = 0
		0x30, 0x0F,       // variable bindings SEQUENCE, length 15
		0x30, 0x0D,       // first varbind SEQUENCE, length 13
		0x06, 0x08,       // OID tag, length 8
		0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: 1.3.6.1.2.1.1.1.0
		0x05, 0x00,       // NULL value
	}

	oid, pduType, err := server.extractOIDAndTypeFromScopedPDU(validScopedPDU)
	if err != nil {
		t.Errorf("extractOIDAndTypeFromScopedPDU failed on valid packet: %v", err)
	}
	if pduType != ASN1_GET_REQUEST {
		t.Errorf("Expected PDU type 0x%02X, got 0x%02X", ASN1_GET_REQUEST, pduType)
	}
	if oid != ".1.3.6.1.2.1.1.1.0" {
		t.Errorf("Expected OID .1.3.6.1.2.1.1.1.0, got %s", oid)
	}
}

// TestParseLength_BoundsChecking verifies that parseLength correctly
// handles various edge cases and malformed inputs.
func TestParseLength_BoundsChecking(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		pos      int
		wantLen  int
		wantPos  int
	}{
		{
			name:    "short form valid",
			data:    []byte{0x05, 0x00},
			pos:     0,
			wantLen: 5,
			wantPos: 1,
		},
		{
			name:    "long form valid (2 bytes)",
			data:    []byte{0x82, 0x01, 0x00},
			pos:     0,
			wantLen: 256,
			wantPos: 3,
		},
		{
			name:    "pos beyond data",
			data:    []byte{0x05},
			pos:     5,
			wantLen: -1,
			wantPos: 5,
		},
		{
			name:    "long form truncated",
			data:    []byte{0x82, 0x01}, // Claims 2 length bytes, only 1 present
			pos:     0,
			wantLen: -1,
			wantPos: 0,
		},
		{
			name:    "long form too many bytes",
			data:    []byte{0x85, 0x00, 0x00, 0x00, 0x00, 0x00}, // 5 length bytes
			pos:     0,
			wantLen: -1,
			wantPos: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLen, gotPos := parseLength(tt.data, tt.pos)
			if gotLen != tt.wantLen {
				t.Errorf("parseLength() length = %d, want %d", gotLen, tt.wantLen)
			}
			if gotPos != tt.wantPos {
				t.Errorf("parseLength() pos = %d, want %d", gotPos, tt.wantPos)
			}
		})
	}
}
