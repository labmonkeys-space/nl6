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
	"log"
	"net"
	"sync"
)

// Pool for SNMP read buffers to avoid per-request allocation
var snmpBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 1024) },
}

// Helper function for minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// snmpSocketBufSize is the kernel socket buffer size for SNMP UDP sockets.
// SNMP packets are small (typically 200-1500 bytes), so 64KB is more than enough.
// Without this, each socket inherits net.core.rmem_default (often 4MB),
// and 30K sockets × 4MB = 120GB of kernel socket buffer memory.
const snmpSocketBufSize = 65536

// SNMP Server implementation
func (s *SNMPServer) Start() error {
	addr := &net.UDPAddr{
		IP:   s.device.IP,
		Port: s.device.SNMPPort,
	}

	var listener *net.UDPConn
	var err error

	if s.device.netNamespace != nil {
		listener, err = s.device.netNamespace.ListenUDPInNamespace(addr)
	} else {
		listener, err = net.ListenUDP("udp", addr)
	}
	if err != nil {
		return err
	}

	// Shrink kernel socket buffers from the system default (often 4MB) to 64KB.
	// At 30K devices this reduces kernel memory from ~240GB to ~3.8GB.
	listener.SetReadBuffer(snmpSocketBufSize)
	listener.SetWriteBuffer(snmpSocketBufSize)

	s.listener = listener
	s.running = true

	go s.handleRequests()
	return nil
}

func (s *SNMPServer) Stop() error {
	if s.listener != nil {
		s.running = false
		return s.listener.Close()
	}
	return nil
}

func (s *SNMPServer) handleRequests() {
	for {
		if !s.running || s.listener == nil {
			break
		}

		buffer := snmpBufPool.Get().([]byte)
		n, clientAddr, err := s.listener.ReadFromUDP(buffer)
		if err != nil {
			snmpBufPool.Put(buffer)
			if s.running {
				log.Printf("SNMP server error reading UDP: %v", err)
			}
			continue
		}

		// Process inline — SNMP is stateless UDP, handler is CPU-only.
		// The UDP listener is per-device, so there's no cross-device contention.
		s.handleSingleRequest(buffer[:n], clientAddr)
		snmpBufPool.Put(buffer)
	}
}

// handleSingleRequest processes a single SNMP request in its own goroutine
func (s *SNMPServer) handleSingleRequest(requestData []byte, clientAddr *net.UDPAddr) {
	var responsePacket []byte

	// Check if this is SNMPv3 request
	if isSNMPv3Request(requestData) {
		responsePacket = s.handleSNMPv3Request(requestData)
	} else {
		responsePacket = s.handleSNMPv2cRequest(requestData)
	}

	// Send response
	if len(responsePacket) > 0 {
		if s.listener != nil {
			_, err := s.listener.WriteToUDP(responsePacket, clientAddr)
			if err != nil {
				log.Printf("Error sending SNMP response: %v", err)
			}
		}
	}
}

// handleSNMPv2cRequest handles traditional SNMP v1/v2c requests
func (s *SNMPServer) handleSNMPv2cRequest(requestData []byte) []byte {
	// Parse SNMP request to get OID and request type
	req := s.parseIncomingRequest(requestData)
	oid := req.OID
	var response string
	var responseOID string

	// Determine PDU type from request data
	pduType := s.getPDUType(requestData)
	// log.Printf("SNMP %s: Detected PDU type: 0x%02X for OID: %s", s.device.ID, pduType, oid)

	if pduType == ASN1_GET_NEXT {
		// Handle GetNext request for SNMP walk
		responseOID, response = s.findNextOID(oid)
		if responseOID == "" {
			// End of MIB view - use a special response
			responseOID = oid
			response = "endOfMibView"
		}
		// log.Printf("SNMP %s: GetNext %s -> %s = %s", s.device.ID, oid, responseOID, response)
	} else if pduType == ASN1_GET_BULK {
		// Handle GetBulk request - return multiple OIDs
		// log.Printf("SNMP %s: Processing GetBulk request for OID: %s", s.device.ID, oid)
		return s.handleGetBulk(oid, requestData)
	} else {
		// Handle regular Get request
		responseOID = oid
		response = s.findResponse(oid)
		// log.Printf("SNMP %s: Get %s -> %s", s.device.ID, oid, response)
	}

	// Create proper SNMP response (pass the request data)
	responseBytes := s.createSNMPResponse(responseOID, response, requestData)
	// log.Printf("SNMP %s: Created response for %s, length: %d bytes", s.device.ID, responseOID, len(responseBytes))
	return responseBytes
}

// Extract PDU type from SNMP request
func (s *SNMPServer) getPDUType(data []byte) byte {
	if len(data) < 10 {
		return ASN1_GET_REQUEST // Default
	}

	pos := 0

	// Skip SEQUENCE tag and length
	if data[pos] != ASN1_SEQUENCE {
		return ASN1_GET_REQUEST
	}
	pos++
	pos += s.skipLength(data[pos:])

	// Skip version
	if pos < len(data) && data[pos] == ASN1_INTEGER {
		pos++
		pos += s.skipLength(data[pos:])
		pos++ // skip version value
	}

	// Skip community
	if pos < len(data) && data[pos] == ASN1_OCTET_STRING {
		pos++
		communityLen := int(data[pos])
		pos++
		pos += communityLen
	}

	// Get PDU type
	if pos < len(data) {
		return data[pos]
	}

	return ASN1_GET_REQUEST
}

// Helper to skip length bytes
func (s *SNMPServer) skipLength(data []byte) int {
	if len(data) == 0 {
		return 0
	}

	if data[0] < 0x80 {
		return 1
	}

	lengthBytes := int(data[0] & 0x7f)
	return 1 + lengthBytes
}
