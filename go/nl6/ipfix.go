/*
 * © 2025 Labmonkeys Space
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
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// IPFIX wire constants (RFC 7011).
const (
	ipfixVersion       = 10  // IPFIX version number
	ipfixTemplateID    = 256 // first valid data template ID (≥256)
	ipfixSetIDTemplate = 2   // Template Set ID (RFC 7011 §3.4.1)

	// IANA Information Element IDs (RFC 7012 / IANA IPFIX IE registry).
	// These map 1-to-1 with the NF9 field IDs 1–17; the timestamp fields
	// use absolute epoch milliseconds (IEs 152/153) instead of NF9's
	// uptime-relative FIRST_SWITCHED/LAST_SWITCHED.
	ipfixOctetDeltaCount          = 1   // octetDeltaCount       (≈ NF9 IN_BYTES)
	ipfixPacketDeltaCount         = 2   // packetDeltaCount      (≈ NF9 IN_PKTS)
	ipfixProtocolIdentifier       = 4   // protocolIdentifier    (≈ NF9 PROTOCOL)
	ipfixIPClassOfService         = 5   // ipClassOfService      (≈ NF9 SRC_TOS)
	ipfixTCPControlBits           = 6   // tcpControlBits        (≈ NF9 TCP_FLAGS)
	ipfixSourceTransportPort      = 7   // sourceTransportPort   (≈ NF9 L4_SRC_PORT)
	ipfixSourceIPv4Address        = 8   // sourceIPv4Address     (≈ NF9 IPV4_SRC_ADDR)
	ipfixSourceIPv4PrefixLength   = 9   // sourceIPv4PrefixLength(≈ NF9 SRC_MASK)
	ipfixIngressInterface         = 10  // ingressInterface      (≈ NF9 INPUT_SNMP)
	ipfixDestinationTransportPort = 11  // destinationTransportPort (≈ NF9 L4_DST_PORT)
	ipfixDestinationIPv4Address   = 12  // destinationIPv4Address(≈ NF9 IPV4_DST_ADDR)
	ipfixDestIPv4PrefixLength     = 13  // destinationIPv4PrefixLength (≈ NF9 DST_MASK)
	ipfixEgressInterface          = 14  // egressInterface       (≈ NF9 OUTPUT_SNMP)
	ipfixIPNextHopIPv4Address     = 15  // ipNextHopIPv4Address  (≈ NF9 IPV4_NEXT_HOP)
	ipfixBGPSourceAsNumber        = 16  // bgpSourceAsNumber     (≈ NF9 SRC_AS)
	ipfixBGPDestinationAsNumber   = 17  // bgpDestinationAsNumber(≈ NF9 DST_AS)
	ipfixFlowStartMilliseconds    = 152 // flowStartMilliseconds (absolute epoch ms, 8B)
	ipfixFlowEndMilliseconds      = 153 // flowEndMilliseconds   (absolute epoch ms, 8B)

	// Derived sizes.
	ipfixHeaderSize   = 16 // bytes — IPFIX Message Header (RFC 7011 §3.1)
	ipfixRecordSize   = 53 // bytes — one data record with the 18-field template below
	ipfixTemplSetSize = 80 // bytes — Template Set (4 set-hdr + 4 tmpl-hdr + 18×4 fields)
)

// ipfixFields is the ordered list of (ieID, ieLength) pairs that define the
// single template used for all simulated device IPFIX exports.
// Changing this list requires updating ipfixRecordSize and ipfixTemplSetSize.
var ipfixFields = [][2]uint16{
	{ipfixOctetDeltaCount, 4},
	{ipfixPacketDeltaCount, 4},
	{ipfixProtocolIdentifier, 1},
	{ipfixIPClassOfService, 1},
	{ipfixTCPControlBits, 1},
	{ipfixSourceTransportPort, 2},
	{ipfixSourceIPv4Address, 4},
	{ipfixSourceIPv4PrefixLength, 1},
	{ipfixIngressInterface, 2},
	{ipfixDestinationTransportPort, 2},
	{ipfixDestinationIPv4Address, 4},
	{ipfixDestIPv4PrefixLength, 1},
	{ipfixEgressInterface, 2},
	{ipfixIPNextHopIPv4Address, 4},
	{ipfixBGPSourceAsNumber, 2},
	{ipfixBGPDestinationAsNumber, 2},
	{ipfixFlowStartMilliseconds, 8},
	{ipfixFlowEndMilliseconds, 8},
}

// ipfixTemplateSetBytes is the pre-encoded Template Set, built once at init.
// It is read-only after init and safe to reference from any goroutine.
var ipfixTemplateSetBytes []byte

func init() {
	ipfixTemplateSetBytes = buildIPFIXTemplateSet()
}

// buildIPFIXTemplateSet encodes the Template Set for ipfixFields.
// Layout (80 bytes):
//
//	Set Header:      set_id=2 (2B), length=80 (2B)
//	Template Header: template_id=256 (2B), field_count=18 (2B)
//	18 × (IE_id 2B + IE_length 2B)
func buildIPFIXTemplateSet() []byte {
	fieldCount := len(ipfixFields)
	length := 4 + 4 + fieldCount*4 // set hdr + tmpl hdr + fields
	buf := make([]byte, length)
	pos := 0

	binary.BigEndian.PutUint16(buf[pos:], ipfixSetIDTemplate) // Set ID = 2
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(length)) // Set Length
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], ipfixTemplateID) // Template ID
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(fieldCount)) // Field Count
	pos += 2

	for _, f := range ipfixFields {
		binary.BigEndian.PutUint16(buf[pos:], f[0]) // IE ID
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], f[1]) // IE Length
		pos += 2
	}
	return buf
}

// IPFIXEncoder encodes FlowRecords into IPFIX UDP payloads (RFC 7011).
// It is stateless; all variable state is passed by the caller so the encoder
// can be shared across goroutines without locking.
//
// Key differences from NetFlow9Encoder:
//   - Message header is 16 bytes (no SysUptime field; uses Export Time instead)
//   - Template Set uses Set ID 2 (NF9 uses 0)
//   - Timestamps are absolute epoch milliseconds (IE 152/153, 8 bytes each)
//     rather than device-uptime-relative milliseconds
//   - The Length header field covers the entire message in bytes (NF9 uses FlowSet count)
type IPFIXEncoder struct{}

// PacketSizes returns the IPFIX per-packet overhead, template set size, and
// per-record size. Used by Tick() to compute protocol-correct batch capacity.
func (IPFIXEncoder) PacketSizes() (int, int, int) {
	return ipfixHeaderSize + 4, ipfixTemplSetSize, ipfixRecordSize
}

// SeqIncrement returns 1 because IPFIX's header sequence number is defined
// (RFC 7011 §3.1) as the incremental count of IPFIX Messages sent on this
// SCTP stream / UDP flow, not of data records — it advances once per message.
func (IPFIXEncoder) SeqIncrement(_ int) int {
	return 1
}

// MaxRecordSize returns 0 because IPFIX records are fixed-size under this
// simulator's single 18-field template; Tick paginates by PacketSizes()'s
// recordSize in that case.
func (IPFIXEncoder) MaxRecordSize() int { return 0 }

// EncodePacket serialises a complete IPFIX UDP payload into buf and returns
// the number of bytes written.
//
// Parameters:
//
//	domainID        — ObservationDomainID (RFC 7011 §3.1); encode the device
//	                  IPv4 address as uint32 for per-device identity at the collector.
//	seqNo           — per-domain sequence number (monotonically increasing).
//	uptimeMs        — device system uptime in milliseconds at export time; used
//	                  to convert per-flow uptime-relative StartMs/EndMs to absolute
//	                  epoch milliseconds for flowStartMilliseconds/flowEndMilliseconds.
//	records         — flow records to include in the Data Set.
//	includeTemplate — when true, a Template Set is prepended; send on the first
//	                  packet and every templateInterval thereafter.
//	buf             — caller-supplied output buffer; must be ≥ 1500 bytes.
//
// Returns an error if buf is too small to hold even a single record.
func (IPFIXEncoder) EncodePacket(
	domainID uint32,
	seqNo uint32,
	uptimeMs uint32,
	records []FlowRecord,
	includeTemplate bool,
	buf []byte,
) (int, error) {
	if len(records) == 0 && !includeTemplate {
		return 0, nil
	}

	// Compute absolute device-start epoch so per-record uptime-relative times
	// can be converted to absolute epoch milliseconds for the IPFIX wire format.
	// Clamp to zero to guard against a negative result if uptimeMs exceeds nowMs
	// (e.g. NTP step-back or synthetic clock in tests), which would otherwise
	// wrap via uint64 cast to a timestamp in year ~584 million CE.
	nowMs := time.Now().UnixMilli()
	deviceStartMs := nowMs - int64(uptimeMs)
	if deviceStartMs < 0 {
		deviceStartMs = 0
	}

	// Minimum required buffer size.
	overhead := ipfixHeaderSize + 4 // msg header + data Set header
	if includeTemplate {
		overhead += ipfixTemplSetSize
	}
	if len(buf) < overhead {
		return 0, fmt.Errorf("ipfix: buffer too small (%d bytes), need at least %d", len(buf), overhead)
	}
	if len(buf) < overhead+ipfixRecordSize && len(records) > 0 {
		return 0, fmt.Errorf("ipfix: buffer too small (%d bytes), need at least %d", len(buf), overhead+ipfixRecordSize)
	}

	// Cap records to what fits in buf.
	available := len(buf) - overhead
	maxRecords := available / ipfixRecordSize
	if maxRecords < len(records) {
		records = records[:maxRecords]
	}

	pos := 0

	// ── Message Header (16 bytes, RFC 7011 §3.1) ──────────────────────────────
	binary.BigEndian.PutUint16(buf[pos:], ipfixVersion) // Version = 10
	pos += 2
	// Total length placeholder — filled in after all sets are encoded.
	lengthOffset := pos
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], uint32(nowMs/1000)) // Export Time (unix_secs)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], seqNo) // Sequence Number
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], domainID) // Observation Domain ID
	pos += 4

	// ── Template Set (optional, 80 bytes) ─────────────────────────────────────
	if includeTemplate {
		copy(buf[pos:], ipfixTemplateSetBytes)
		pos += len(ipfixTemplateSetBytes)
	}

	if len(records) == 0 {
		binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(pos))
		return pos, nil
	}

	// ── Data Set ──────────────────────────────────────────────────────────────
	dataSetStart := pos
	binary.BigEndian.PutUint16(buf[pos:], ipfixTemplateID) // Set ID = template ID
	pos += 2
	// Data Set length placeholder — filled in after writing records.
	dataLenOffset := pos
	pos += 2

	for _, r := range records {
		pos = encodeIPFIXRecord(buf, pos, r, deviceStartMs)
	}

	// Pad to 4-byte boundary (RFC 7011 §3.3.1).
	dataLen := pos - dataSetStart
	if rem := dataLen % 4; rem != 0 {
		padBytes := 4 - rem
		for i := 0; i < padBytes; i++ {
			buf[pos] = 0
			pos++
		}
		dataLen += padBytes
	}
	binary.BigEndian.PutUint16(buf[dataLenOffset:], uint16(dataLen))

	// Fill total message length.
	binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(pos))

	return pos, nil
}

// encodeIPFIXRecord writes a single flow record into buf at pos, following
// the field order defined in ipfixFields. Returns the new position.
func encodeIPFIXRecord(buf []byte, pos int, r FlowRecord, deviceStartMs int64) int {
	// octetDeltaCount (4) — clamp uint64 to avoid silent wrap for large flows.
	inBytes := r.Bytes
	if inBytes > math.MaxUint32 {
		inBytes = math.MaxUint32
	}
	binary.BigEndian.PutUint32(buf[pos:], uint32(inBytes))
	pos += 4
	// packetDeltaCount (4)
	binary.BigEndian.PutUint32(buf[pos:], r.Packets)
	pos += 4
	// protocolIdentifier (1)
	buf[pos] = r.Protocol
	pos++
	// ipClassOfService (1)
	buf[pos] = r.ToS
	pos++
	// tcpControlBits (1)
	buf[pos] = r.TCPFlags
	pos++
	// sourceTransportPort (2)
	binary.BigEndian.PutUint16(buf[pos:], r.SrcPort)
	pos += 2
	// sourceIPv4Address (4)
	src := r.SrcIP.To4()
	if src == nil {
		src = []byte{0, 0, 0, 0}
	}
	copy(buf[pos:], src)
	pos += 4
	// sourceIPv4PrefixLength (1)
	buf[pos] = r.SrcMask
	pos++
	// ingressInterface (2)
	binary.BigEndian.PutUint16(buf[pos:], r.InIface)
	pos += 2
	// destinationTransportPort (2)
	binary.BigEndian.PutUint16(buf[pos:], r.DstPort)
	pos += 2
	// destinationIPv4Address (4)
	dst := r.DstIP.To4()
	if dst == nil {
		dst = []byte{0, 0, 0, 0}
	}
	copy(buf[pos:], dst)
	pos += 4
	// destinationIPv4PrefixLength (1)
	buf[pos] = r.DstMask
	pos++
	// egressInterface (2)
	binary.BigEndian.PutUint16(buf[pos:], r.OutIface)
	pos += 2
	// ipNextHopIPv4Address (4)
	nh := r.NextHop.To4()
	if nh == nil {
		nh = []byte{0, 0, 0, 0}
	}
	copy(buf[pos:], nh)
	pos += 4
	// bgpSourceAsNumber (2)
	binary.BigEndian.PutUint16(buf[pos:], r.SrcAS)
	pos += 2
	// bgpDestinationAsNumber (2)
	binary.BigEndian.PutUint16(buf[pos:], r.DstAS)
	pos += 2
	// flowStartMilliseconds (8) — absolute epoch ms
	binary.BigEndian.PutUint64(buf[pos:], uint64(deviceStartMs+int64(r.StartMs)))
	pos += 8
	// flowEndMilliseconds (8) — absolute epoch ms
	binary.BigEndian.PutUint64(buf[pos:], uint64(deviceStartMs+int64(r.EndMs)))
	pos += 8
	return pos
}
