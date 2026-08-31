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

// Pool for SNMP read buffers to avoid per-request allocation.
// `sync.Pool` is documented to perform best with pointer-typed values —
// non-pointer slice headers cost an extra allocation per Get/Put pair
// (staticcheck SA6002), so we wrap in `*[]byte`.
// snmpReadBufferBytes is how much of a request datagram the listener reads.
//
// It is also the only thing bounding how many variable bindings — GETBULK
// COLUMNS — one request can name, since the smallest encodable binding is
// minVarbindSize bytes. The v3 GETBULK repeater walk is bounded regardless
// (clampBulkWalk divides its ceiling by the column count), but the
// non-repeater loop is one walk step per column with no other bound, so
// raising this raises that work linearly. TestReadBufferBoundsTheColumnCount
// pins the coupling (nl6#535 review R12).
const snmpReadBufferBytes = 1024

var snmpBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, snmpReadBufferBytes)
		return &buf
	},
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

		bufPtr := snmpBufPool.Get().(*[]byte)
		n, clientAddr, err := s.listener.ReadFromUDP(*bufPtr)
		if err != nil {
			snmpBufPool.Put(bufPtr)
			if s.running {
				log.Printf("SNMP server error reading UDP: %v", err)
			}
			continue
		}

		// Process inline — SNMP is stateless UDP, handler is CPU-only.
		// The UDP listener is per-device, so there's no cross-device contention.
		s.handleSingleRequest((*bufPtr)[:n], clientAddr)
		snmpBufPool.Put(bufPtr)
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

// maxCounter64SkipSteps bounds the SNMPv1 Counter64 skip loop. The real run is
// (8 HC columns x interfaces), so this is far above any legitimate walk.
//
// It does NOT exist to catch a non-advancing oidNextMap: the non-advance check
// in the loop already does that, and a strictly increasing sequence over a
// finite map cannot run forever. It backs up the comparison itself, so a defect
// in compareOIDs (or a successor that is neither greater nor "") still cannot
// wedge the shared UDP handler.
const maxCounter64SkipSteps = 100000

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
		// A variable-bindings list that is not a valid ASN.1 encoding makes
		// the PDU malformed, and the datagram is discarded (nl6#537; see the
		// GET branch below). GETNEXT needs its own gate because it answers
		// from req.OID, and parseIncomingRequest leaves that at its sysDescr.0
		// DEFAULT when the name fails to decode, so without this a malformed
		// GETNEXT was answered as a walk restart from an OID nobody sent.
		if _, ok := s.parseAllOIDsFromRequest(requestData); !ok {
			s.logFirstMalformedList(pduType)
			return nil
		}

		// Handle GetNext request for SNMP walk. The LLDP served-OID snapshot
		// is taken ONCE here (generation-cached, so this is a pointer load in
		// steady state) and shared with the v1 Counter64 skip loop below, so
		// the first step and the skip run see the same ifAlias/LLDP view even
		// if the topology generation changes mid-request.
		served := s.lldpServedOIDs()
		responseOID, response = s.findNextOIDWithServed(oid, served)

		// SNMPv1 has no Counter64, and RFC 3584 §4.2.2.1 wants a GETNEXT to
		// SKIP such an object and carry on to the next lexicographic
		// successor. That is the opposite of the GET path, which answers noSuchName
		// (createVarbindResponse). The asymmetry is the point: a GETNEXT names
		// a position rather than an object, so erroring would stop a v1 walk
		// dead at the first ifHC* column and truncate the table with no signal.
		//
		// Walk order is column-major, so the Counter64 columns form one
		// contiguous run of (HC columns x interfaces). The ONE served-OID
		// snapshot taken above covers the first step and the whole run via
		// findNextOIDWithServed, because calling findNextOID per step rebuilds
		// the device's whole LLDP/ifAlias view each time, the O(steps x links)
		// hot path that function exists to avoid.
		//
		// Coverage is bounded by oidTypeTable, which lists exactly the eight
		// ifXTable ifHC* columns. A 64-bit counter served from a resource file
		// under any other OID (a vendor HC column, ipIfStatsHC*, dot3HC*) is
		// absent from that table, so snmpTypeTag does not report Counter64 and
		// v1 still receives tag 0x46 for it. The table is hand-maintained.
		//
		// The version test comes FIRST and is free: req was already parsed at
		// the top of this function. snmpTypeTag is NOT cheap, it is a linear
		// scan of the ~50-row type table that concatenates a string per row,
		// so a v2c fleet must never reach it here. Reversing these two
		// operands puts that scan on every GETNEXT of every version, on the
		// walk path this repo already has a CPU incident on.
		//
		// The loop is bounded twice over. It relies on findNextOIDWithServed
		// returning a strictly greater OID or "", an invariant driven by
		// operator-supplied resource files via oidNextMap, and this loop runs
		// INLINE in the shared UDP handler with no recover() on the path: a
		// non-advancing entry would wedge every device, where before this
		// change it was only the manager's problem. So a non-advance ends the
		// walk, and a step cap backs that up. Either exit is a data defect, so
		// it is logged once per device (the manager only sees a walk that
		// ends early, indistinguishable from a short table) and answered as
		// end-of-MIB. compareOIDs is the comparator the walk itself orders by.
		if req.Version == snmpVersion1 && responseOID != "" &&
			snmpTypeTag(responseOID) == ASN1_COUNTER64 {
			for steps := 0; responseOID != "" && snmpTypeTag(responseOID) == ASN1_COUNTER64; steps++ {
				if steps >= maxCounter64SkipSteps {
					s.logFirstSkipAbort("step cap reached", responseOID)
					responseOID = ""
					break
				}
				prev := responseOID
				responseOID, response = s.findNextOIDWithServed(responseOID, served)
				if responseOID != "" && compareOIDs(responseOID, prev) <= 0 {
					s.logFirstSkipAbort("successor "+responseOID+" does not advance", prev)
					responseOID = ""
					break
				}
			}
		}

		if responseOID == "" {
			// End of MIB view - use a special response. Under v1 the sentinel
			// is diverted to noSuchName by createSNMPResponse, which is also
			// where a v1 walk that skipped its way past the last non-Counter64
			// OID terminates.
			responseOID = oid
			response = valueEndOfMibView
		}
		// log.Printf("SNMP %s: GetNext %s -> %s = %s", s.device.ID, oid, responseOID, response)
	} else if pduType == ASN1_GET_BULK {
		// Handle GetBulk request - return multiple OIDs
		// log.Printf("SNMP %s: Processing GetBulk request for OID: %s", s.device.ID, oid)
		return s.handleGetBulk(oid, requestData)
	} else {
		// Handle regular Get request — answer EVERY requested varbind, not
		// just the first (RFC 3416 §4.2.1). A single-varbind response breaks
		// multi-OID getters: OpenNMS Enlinkd's LldpLocPortGetter bundles
		// lldpLocPortIdSubtype/Id/Desc in one GET; with only the first binding
		// returned, lldpLocPortId is absent → snmp4j yields a null value →
		// LldpSnmpUtils "cannot convert Null to a HexString", lldpPortId is
		// stored empty, and the discovered topology has no edges (issue #176).
		// Reuse the multi-varbind parser + GetResponse encoder (as GETBULK);
		// responses are returned per OID, in request order.
		oids, ok := s.parseAllOIDsFromRequest(requestData)
		if !ok {
			// A variable-bindings list that is not a valid ASN.1 encoding
			// makes the PDU malformed. RFC 1157 §4.1 step 1 and RFC 3412 §7.2
			// discard such a datagram rather than answering it, and returning
			// nothing here means handleSingleRequest sends no datagram at all
			// (nl6#537).
			//
			// Distinct from the zero case below: that one is a PDU whose
			// envelope could not be read as far as a list, or whose list is
			// empty, which the single parsed OID still covers.
			s.logFirstMalformedList(pduType)
			return nil
		}
		if len(oids) == 0 {
			oids = []string{oid} // fallback for an unparseable varbind list
		}
		return s.handleGetRequestVarbinds(oids, requestData)
	}

	// GETNEXT: single next-OID per request.
	responseBytes := s.createSNMPResponse(responseOID, response, requestData)
	// log.Printf("SNMP %s: Created response for %s, length: %d bytes", s.device.ID, responseOID, len(responseBytes))
	return responseBytes
}

// logFirstSkipAbort emits at most one log line per device when the SNMPv1
// Counter64 skip loop ends on one of its safety bounds rather than on a
// non-Counter64 successor. Same gate as logFirstEncodeErr on the trap path:
// the condition is a resource-file defect present from load, so ungated it
// would repeat on every v1 walk of every device sharing the profile.
func (s *SNMPServer) logFirstSkipAbort(why, at string) {
	s.firstSkipAbort.Do(func() {
		log.Printf("SNMP %s: v1 Counter64 skip aborted at %s (%s); answering end-of-MIB (further aborts suppressed for this device)",
			s.device.ID, at, why)
	})
}

// logFirstMalformedList emits at most one log line per device when a datagram
// is discarded because its variable-bindings list is not a valid ASN.1
// encoding (nl6#537). RFC 3412 §7.2 counts these in snmpInASNParseErrs; nl6
// serves no such counter, and without any trace a discard is
// indistinguishable from a network drop, which is the property the no-recover()
// rule on this path exists to avoid. Gated like logFirstSkipAbort: a manager
// that sends one malformed request tends to send it every poll.
func (s *SNMPServer) logFirstMalformedList(pduType byte) {
	s.firstMalformedList.Do(func() {
		log.Printf("SNMP %s: discarded PDU 0x%02X whose varbind list is not a valid ASN.1 encoding (further discards suppressed for this device)",
			s.device.ID, pduType)
	})
}

// logFirstMalformedV3 emits at most one line per device when an SNMPv3 scoped
// PDU is discarded as malformed. Same gate as logFirstMalformedList: the
// condition is attacker-controlled, so ungated it is a log-flood primitive.
func (s *SNMPServer) logFirstMalformedV3(err error) {
	s.firstMalformedV3.Do(func() {
		log.Printf("SNMP %s: discarded an SNMPv3 request whose scoped PDU does not parse: %v (further discards suppressed for this device)",
			s.device.ID, err)
	})
}

// logFirstMalformedV3List emits at most one line per device when an SNMPv3
// GETBULK is discarded because its variable-bindings list — or a container
// length on the way to it — is not a valid ASN.1 encoding.
//
// Separate from logFirstMalformedV3 on purpose: that gate covers the scoped
// PDU's first binding and its PDU type, this one covers the rest of the list,
// and one sync.Once across both means whichever fault arrives first hides the
// other for the device's lifetime. The v1/v2c side keeps the same two apart
// and names the PDU tag; this names the fault.
func (s *SNMPServer) logFirstMalformedV3List(err error) {
	s.firstMalformedV3List.Do(func() {
		log.Printf("SNMP %s: discarded an SNMPv3 GETBULK: %v (further discards of this fault suppressed for this device)",
			s.device.ID, err)
	})
}

// Extract PDU type from SNMP request
func (s *SNMPServer) getPDUType(data []byte) byte {
	if len(data) < 10 {
		return ASN1_GET_REQUEST // Default
	}

	pos := 0

	// Skip SEQUENCE tag and length. Read it with parseLength rather than
	// skipLength: skipLength has NO failure signal (it answers a malformed
	// long-form length with `1 + lengthBytes`, a plausible-looking skip
	// computed from a length it could not read), so a datagram whose outer
	// length is unreadable used to be walked from a cursor nobody chose. The
	// three envelope readers now agree here too — parseGetBulkParams already
	// bailed, and having this one step over it instead was a divergence
	// introduced by nl6#560, in the very field family this change exists to
	// align.
	if data[pos] != ASN1_SEQUENCE {
		return ASN1_GET_REQUEST
	}
	pos++
	outerLen, newPos := parseLength(data, pos)
	if outerLen < 0 {
		return ASN1_GET_REQUEST
	}
	pos = newPos

	// Skip version. Step over the number of content octets the INTEGER
	// DECLARES, not one: SNMP is BER, not DER, so `02 02 00 01` is a legal
	// encoding of version 1. The bare `pos++` this replaces assumed exactly
	// one content octet, so a non-minimal version left the cursor SHORT, the
	// byte read as the PDU tag was the version's own content octet, and
	// handleSNMPv2cRequest dispatches on it — a GETNEXT or GETBULK answered
	// from the GET branch (nl6#559).
	//
	// `02 00` is a DIFFERENT case and it is NOT legal BER: X.690 §8.3.1 says
	// an INTEGER's contents octets shall consist of one or more octets. It is
	// handled leniently anyway — every reader steps over zero octets, so all
	// four agree on where the PDU begins and the datagram is served — rather
	// than discarded under RFC 3412 §7.2, which would also be defensible.
	// Leniency is the choice this parser family already makes for a
	// structurally readable envelope (the strict reader for the part that
	// must be exact is parseAllOIDsFromRequest, nl6#537). Its consequence is
	// stated where it is felt: parseIncomingRequest reads no value, so the
	// request is answered as v2c. Before this fix the bare `pos++` stepped one
	// octet too FAR on it, onto the community's length octet.
	//
	// The `versionLen > 0` arm is both halves of the fix: it advances by the
	// declared length, and it is the `n < 0` guard parseLength's -1 failure
	// signal requires (nl6#513) — `pos += -1` would walk the cursor backward.
	// It is deliberately byte-for-byte the shape parseIncomingRequest uses at
	// snmp_response.go, because these two must agree about where the PDU
	// begins and the cheapest way to guarantee that is to read it the same way.
	if pos < len(data) && data[pos] == ASN1_INTEGER {
		pos++
		versionLen, newPos := parseLength(data, pos)
		pos = newPos
		if versionLen > 0 {
			pos += versionLen
		}
	}

	// Skip community. Read the length through parseLength rather than as a
	// raw byte: the raw read runs off the end when the OCTET STRING tag is
	// the last byte of the datagram, and it also mis-reads a long-form
	// length, which a community string of 128 bytes or more encodes as.
	//
	// This is byte-for-byte parseIncomingRequest's community read, and the
	// equality is the point. Bailing here on an unreadable length — which is
	// what nl6#559's first cut did — reproduced nl6#559 ONE FIELD LATER:
	// parseIncomingRequest does not bail, it leaves the cursor at the length
	// octet and carries on, so `30 xx 02 01 01 04 80 a1 …` had it decoding a
	// GETNEXT with real varbind names while getPDUType answered its GET bail
	// and handleSNMPv2cRequest dispatched the GET branch. Same symptom, same
	// cause: the two readers walking one field differently. Committed as the
	// seed repro559CommunityLengthUnreadable.
	if pos < len(data) && data[pos] == ASN1_OCTET_STRING {
		pos++
		communityLen, newPos := parseLength(data, pos)
		pos = newPos
		if communityLen >= 0 && pos+communityLen <= len(data) {
			pos += communityLen
		}
	}

	// Get PDU type
	if pos < len(data) {
		return data[pos]
	}

	return ASN1_GET_REQUEST
}

// Helper to skip length bytes.
//
// Two callers remain, both inside parseIncomingRequest's variable-bindings
// walk, and both deliberate: this function cannot report failure (it answers a
// malformed long-form length with a plausible-looking `1 + lengthBytes`), so
// every reader of an ENVELOPE field — outer SEQUENCE, version, community, PDU
// — was moved to parseLength by nl6#559/#560. The two survivors sit below a
// PDU tag the reader has already recognised, and the strict reader for that
// part of the datagram is parseAllOIDsFromRequest (nl6#537), whose verdict the
// dispatcher gates on. Do not add a third caller on an envelope field.
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
