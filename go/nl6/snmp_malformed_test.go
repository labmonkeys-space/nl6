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
	"net"
	"testing"
)

// TestMalformedSNMPPacketDoesNotPanic verifies that malformed SNMP packets
// with out-of-bounds BER encodings do not cause a process-wide panic.
// This test covers the security issue where a malformed packet could position
// an OCTET STRING tag at the end of the datagram, causing getPDUType to
// attempt an out-of-bounds array access.
func TestMalformedSNMPPacketDoesNotPanic(t *testing.T) {
	s := &SNMPServer{
		device: &DeviceSimulator{
			ID: "test-device",
		},
	}

	// Test case 1: The concrete exploit packet from the security report
	// 30 08 02 84 00 00 00 00 00 04
	// This packet has a malformed long-form length (0x84) that causes skipLength
	// to advance the cursor so the final byte (0x04 = OCTET STRING tag) is
	// positioned where getPDUType tries to read the community length.
	exploitPacket := []byte{0x30, 0x08, 0x02, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}

	// Test case 2: OCTET STRING tag at the very end with no length byte
	shortPacket := []byte{0x30, 0x05, 0x02, 0x01, 0x00, 0x04}

	// Test case 3: Truncated packet with malformed length encoding
	truncatedPacket := []byte{0x30, 0x82, 0x00, 0x10, 0x02, 0x01, 0x00, 0x04}

	// Test case 4: Empty packet
	emptyPacket := []byte{}

	// Test case 5: Single byte packet
	singleByte := []byte{0x30}

	testCases := []struct {
		name   string
		packet []byte
	}{
		{"exploit packet from security report", exploitPacket},
		{"OCTET STRING at end", shortPacket},
		{"truncated with malformed length", truncatedPacket},
		{"empty packet", emptyPacket},
		{"single byte", singleByte},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// The test passes if handleSingleRequest does not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("handleSingleRequest panicked on malformed packet: %v", r)
				}
			}()

			// Call handleSingleRequest with the malformed packet
			// It should recover from any panic internally and not crash
			clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
			s.handleSingleRequest(tc.packet, clientAddr)
		})
	}
}

// TestGetPDUTypeWithMalformedPackets verifies that getPDUType handles
// malformed packets gracefully without panicking or accessing out-of-bounds memory.
func TestGetPDUTypeWithMalformedPackets(t *testing.T) {
	s := &SNMPServer{
		device: &DeviceSimulator{
			ID: "test-device",
		},
	}

	testCases := []struct {
		name           string
		packet         []byte
		expectedPDUType byte
	}{
		{
			name:           "exploit packet",
			packet:         []byte{0x30, 0x08, 0x02, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
			expectedPDUType: ASN1_GET_REQUEST, // Should return default
		},
		{
			name:           "OCTET STRING at end",
			packet:         []byte{0x30, 0x05, 0x02, 0x01, 0x00, 0x04},
			expectedPDUType: ASN1_GET_REQUEST, // Should return default
		},
		{
			name:           "too short packet",
			packet:         []byte{0x30, 0x05},
			expectedPDUType: ASN1_GET_REQUEST, // Should return default
		},
		{
			name:           "empty packet",
			packet:         []byte{},
			expectedPDUType: ASN1_GET_REQUEST, // Should return default
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("getPDUType panicked on malformed packet: %v", r)
				}
			}()

			pduType := s.getPDUType(tc.packet)
			if pduType != tc.expectedPDUType {
				t.Errorf("getPDUType returned 0x%02X, expected 0x%02X", pduType, tc.expectedPDUType)
			}
		})
	}
}

// TestParseIncomingRequestWithMalformedPackets verifies that parseIncomingRequest
// handles malformed packets gracefully without panicking.
func TestParseIncomingRequestWithMalformedPackets(t *testing.T) {
	s := &SNMPServer{
		device: &DeviceSimulator{
			ID: "test-device",
		},
	}

	testCases := []struct {
		name   string
		packet []byte
	}{
		{
			name:   "exploit packet",
			packet: []byte{0x30, 0x08, 0x02, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
		},
		{
			name:   "OCTET STRING at end",
			packet: []byte{0x30, 0x05, 0x02, 0x01, 0x00, 0x04},
		},
		{
			name:   "truncated packet",
			packet: []byte{0x30, 0x82, 0x00, 0x10, 0x02, 0x01, 0x00, 0x04},
		},
		{
			name:   "empty packet",
			packet: []byte{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseIncomingRequest panicked on malformed packet: %v", r)
				}
			}()

			// Should return default values without panicking
			req := s.parseIncomingRequest(tc.packet)
			
			// Verify we got a valid request structure (with defaults)
			if req.Community == "" {
				t.Error("parseIncomingRequest returned empty community")
			}
			if req.RequestID == 0 {
				t.Error("parseIncomingRequest returned zero request ID")
			}
		})
	}
}
