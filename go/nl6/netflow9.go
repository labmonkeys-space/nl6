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

// NetFlow v9 wire constants (RFC 3954).
const (
	nf9Version    = 9
	nf9TemplateID = 256 // first valid data template ID

	// Field type IDs (RFC 3954, Appendix A)
	nf9InBytes      = 1
	nf9InPkts       = 2
	nf9Protocol     = 4
	nf9SrcTOS       = 5
	nf9TCPFlags     = 6
	nf9L4SrcPort    = 7
	nf9IPv4SrcAddr  = 8
	nf9SrcMask      = 9
	nf9InputSNMP    = 10
	nf9L4DstPort    = 11
	nf9IPv4DstAddr  = 12
	nf9DstMask      = 13
	nf9OutputSNMP   = 14
	nf9IPv4NextHop  = 15
	nf9SrcAS        = 16
	nf9DstAS        = 17
	nf9LastSwitched = 21
	nf9FirstSwitched = 22

	// Derived sizes.
	nf9HeaderSize   = 20 // bytes — Packet Header (RFC 3954 §5)
	nf9RecordSize   = 45 // bytes — one data record with the 18-field template below
	nf9TemplFlowSetSize = 80 // bytes — Template FlowSet (4 hdr + 4 tmpl hdr + 18×4 fields)
)

// nf9Fields is the ordered list of (fieldType, fieldLength) pairs that define
// the single template used for all simulated device flow exports.
// Changing this list requires updating nf9RecordSize and nf9TemplFlowSetSize.
var nf9Fields = [][2]uint16{
	{nf9InBytes, 4},
	{nf9InPkts, 4},
	{nf9Protocol, 1},
	{nf9SrcTOS, 1},
	{nf9TCPFlags, 1},
	{nf9L4SrcPort, 2},
	{nf9IPv4SrcAddr, 4},
	{nf9SrcMask, 1},
	{nf9InputSNMP, 2},
	{nf9L4DstPort, 2},
	{nf9IPv4DstAddr, 4},
	{nf9DstMask, 1},
	{nf9OutputSNMP, 2},
	{nf9IPv4NextHop, 4},
	{nf9SrcAS, 2},
	{nf9DstAS, 2},
	{nf9LastSwitched, 4},
	{nf9FirstSwitched, 4},
}

// nf9TemplatBytes is the pre-encoded Template FlowSet, built once at init.
// It is read-only after init and safe to reference from any goroutine.
var nf9TemplateBytes []byte

func init() {
	nf9TemplateBytes = buildNF9Template()
}

// buildNF9Template encodes the Template FlowSet for nf9Fields.
// Layout (80 bytes):
//   FlowSet Header: flowset_id=0 (2B), length=80 (2B)
//   Template Header: template_id=256 (2B), field_count=18 (2B)
//   18 × (field_type 2B + field_length 2B)
func buildNF9Template() []byte {
	fieldCount := len(nf9Fields)
	length := 4 + 4 + fieldCount*4 // flowset hdr + tmpl hdr + fields
	buf := make([]byte, length)
	pos := 0

	binary.BigEndian.PutUint16(buf[pos:], 0)          // FlowSet ID = 0 (Template)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(length)) // FlowSet Length
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], nf9TemplateID)  // Template ID
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(fieldCount)) // Field Count
	pos += 2

	for _, f := range nf9Fields {
		binary.BigEndian.PutUint16(buf[pos:], f[0]) // field type
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], f[1]) // field length
		pos += 2
	}
	return buf
}

// NetFlow9Encoder encodes FlowRecords into NetFlow v9 UDP payloads (RFC 3954).
// It is stateless; all variable state (sequence number, uptime) is passed by
// the caller so the encoder can be shared across goroutines without locking.
type NetFlow9Encoder struct{}

// PacketSizes returns the NF9 per-packet overhead, template flowset size, and
// per-record size. Used by Tick() to compute protocol-correct batch capacity.
func (NetFlow9Encoder) PacketSizes() (int, int, int) {
	return nf9HeaderSize + 4, nf9TemplFlowSetSize, nf9RecordSize
}

// SeqIncrement returns 1 because NetFlow v9's header sequence number is the
// "incremental sequence counter of all export packets" (RFC 3954 §5.1) — it
// advances by one per packet regardless of how many records the packet carries.
func (NetFlow9Encoder) SeqIncrement(_ int) int {
	return 1
}

// MaxRecordSize returns 0 because NetFlow v9 records are fixed-size; Tick
// paginates by PacketSizes()'s recordSize in that case.
func (NetFlow9Encoder) MaxRecordSize() int { return 0 }

// EncodePacket serialises a complete NetFlow v9 UDP payload into buf and
// returns the number of bytes written.
//
// Parameters:
//   domainID        — ObservationDomainID (source_id in v9 header); use the
//                     device IPv4 address as uint32 for per-device identity.
//   seqNo           — per-domain sequence number (monotonically increasing).
//   uptimeMs        — device system uptime in milliseconds at export time.
//   records         — flow records to include in the Data FlowSet.
//   includeTemplate — when true, a Template FlowSet is prepended; send on the
//                     first packet and every templateInterval thereafter.
//   buf             — caller-supplied output buffer; must be >= 1500 bytes.
//
// Returns an error if buf is too small to hold even a single record.
func (NetFlow9Encoder) EncodePacket(
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

	// Determine how many records actually fit.
	// Minimum buffer: header + (template if requested) + data FlowSet header
	overhead := nf9HeaderSize + 4 // hdr + data flowset hdr
	if includeTemplate {
		overhead += nf9TemplFlowSetSize
	}
	if len(buf) < overhead {
		return 0, fmt.Errorf("netflow9: buffer too small (%d bytes), need at least %d", len(buf), overhead)
	}
	if len(buf) < overhead+nf9RecordSize && len(records) > 0 {
		return 0, fmt.Errorf("netflow9: buffer too small (%d bytes), need at least %d", len(buf), overhead+nf9RecordSize)
	}

	// Cap records to what fits in buf.
	available := len(buf) - overhead
	maxRecords := available / nf9RecordSize
	if maxRecords < len(records) {
		records = records[:maxRecords]
	}

	// Count field in header = template records (1 if included) + data records.
	count := len(records)
	if includeTemplate {
		count++ // one template "record"
	}

	pos := 0

	// ── Packet Header (20 bytes) ─────────────────────────────────────
	binary.BigEndian.PutUint16(buf[pos:], nf9Version) // Version = 9
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(count)) // Count
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], uptimeMs) // SysUptime (ms)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], uint32(time.Now().Unix())) // unix_secs
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], seqNo) // SequenceNumber
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], domainID) // SourceId
	pos += 4

	// ── Template FlowSet (optional, 80 bytes) ────────────────────────
	if includeTemplate {
		copy(buf[pos:], nf9TemplateBytes)
		pos += len(nf9TemplateBytes)
	}

	if len(records) == 0 {
		return pos, nil
	}

	// ── Data FlowSet ─────────────────────────────────────────────────
	dataFlowSetStart := pos
	binary.BigEndian.PutUint16(buf[pos:], nf9TemplateID) // FlowSet ID = template ID
	pos += 2
	// Length placeholder — filled in after writing records.
	lengthOffset := pos
	pos += 2

	for _, r := range records {
		pos = encodeNF9Record(buf, pos, r)
	}

	// Pad to 4-byte boundary (RFC 3954 §5.3).
	dataLen := pos - dataFlowSetStart
	if rem := dataLen % 4; rem != 0 {
		padBytes := 4 - rem
		for i := 0; i < padBytes; i++ {
			buf[pos] = 0
			pos++
		}
		dataLen += padBytes
	}
	binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(dataLen))

	return pos, nil
}

// encodeNF9Record writes a single flow record into buf at pos, following the
// field order defined in nf9Fields. Returns the new position.
func encodeNF9Record(buf []byte, pos int, r FlowRecord) int {
	// IN_BYTES (4) — NetFlow v9 field is 4 bytes; clamp to avoid silent wrap for
	// large flows (GPU/Storage profiles can exceed 4 GB per flow).
	inBytes := r.Bytes
	if inBytes > math.MaxUint32 {
		inBytes = math.MaxUint32
	}
	binary.BigEndian.PutUint32(buf[pos:], uint32(inBytes))
	pos += 4
	// IN_PKTS (4)
	binary.BigEndian.PutUint32(buf[pos:], r.Packets)
	pos += 4
	// PROTOCOL (1)
	buf[pos] = r.Protocol
	pos++
	// SRC_TOS (1)
	buf[pos] = r.ToS
	pos++
	// TCP_FLAGS (1)
	buf[pos] = r.TCPFlags
	pos++
	// L4_SRC_PORT (2)
	binary.BigEndian.PutUint16(buf[pos:], r.SrcPort)
	pos += 2
	// IPV4_SRC_ADDR (4)
	src := r.SrcIP.To4()
	if src == nil {
		src = []byte{0, 0, 0, 0}
	}
	copy(buf[pos:], src)
	pos += 4
	// SRC_MASK (1)
	buf[pos] = r.SrcMask
	pos++
	// INPUT_SNMP (2)
	binary.BigEndian.PutUint16(buf[pos:], r.InIface)
	pos += 2
	// L4_DST_PORT (2)
	binary.BigEndian.PutUint16(buf[pos:], r.DstPort)
	pos += 2
	// IPV4_DST_ADDR (4)
	dst := r.DstIP.To4()
	if dst == nil {
		dst = []byte{0, 0, 0, 0}
	}
	copy(buf[pos:], dst)
	pos += 4
	// DST_MASK (1)
	buf[pos] = r.DstMask
	pos++
	// OUTPUT_SNMP (2)
	binary.BigEndian.PutUint16(buf[pos:], r.OutIface)
	pos += 2
	// IPV4_NEXT_HOP (4)
	nh := r.NextHop.To4()
	if nh == nil {
		nh = []byte{0, 0, 0, 0}
	}
	copy(buf[pos:], nh)
	pos += 4
	// SRC_AS (2)
	binary.BigEndian.PutUint16(buf[pos:], r.SrcAS)
	pos += 2
	// DST_AS (2)
	binary.BigEndian.PutUint16(buf[pos:], r.DstAS)
	pos += 2
	// LAST_SWITCHED (4)
	binary.BigEndian.PutUint32(buf[pos:], r.EndMs)
	pos += 4
	// FIRST_SWITCHED (4)
	binary.BigEndian.PutUint32(buf[pos:], r.StartMs)
	pos += 4
	return pos
}
