/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
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
	nf9InBytes       = 1
	nf9InPkts        = 2
	nf9Protocol      = 4
	nf9SrcTOS        = 5
	nf9TCPFlags      = 6
	nf9L4SrcPort     = 7
	nf9IPv4SrcAddr   = 8
	nf9SrcMask       = 9
	nf9InputSNMP     = 10
	nf9L4DstPort     = 11
	nf9IPv4DstAddr   = 12
	nf9DstMask       = 13
	nf9OutputSNMP    = 14
	nf9IPv4NextHop   = 15
	nf9SrcAS         = 16
	nf9DstAS         = 17
	nf9LastSwitched  = 21
	nf9FirstSwitched = 22
	nf9Direction     = 61 // DIRECTION: 0x00 = ingress, 0x01 = egress

	// Derived sizes.
	nf9HeaderSize         = 20 // bytes — Packet Header (RFC 3954 §5)
	nf9DataFlowSetHdrSize = 4  // bytes — data FlowSet header (FlowSet ID + length)
	nf9RecordSize         = 46 // bytes — one data record with the 19-field template below
	nf9TemplFlowSetSize   = 84 // bytes — Template FlowSet (4 hdr + 4 tmpl hdr + 19×4 fields)

	// Interface option-table wire constants ("option interface-table",
	// RFC 3954 §6.1). Template ID 257 sits beside the data template's 256 —
	// a future second data template must pick a different ID.
	nf9OptionsFlowSetID  = 1   // Options Template FlowSet ID (RFC 3954)
	nf9OptionsTemplateID = 257 // options template / option data FlowSet ID
	nf9ScopeSystem       = 1   // scope field type System
	nf9ScopeInterface    = 2   // scope field type Interface
	nf9IfName            = 82  // interfaceName field type
	nf9IfDesc            = 83  // interfaceDescription field type

	// Option data record sizes per shape (both 4-byte aligned — no padding).
	nf9OptionRecSizeIfScoped     = 4 + 2*flowOptionStringLen   // scope ifIndex + name + description
	nf9OptionRecSizeSystemScoped = 4 + 4 + flowOptionStringLen // scope system + ifIndex + description
)

// nf9OptionShapes is the per-shape descriptor table: options template,
// record size, and record encoder live in ONE entry per shape so they
// cannot drift apart. Adding a shape = adding one entry here (plus the
// Validate enum and the IPFIX table). Built at init, read-only after.
var nf9OptionShapes map[string]flowOptionShapeDesc

// buildNF9OptionsTemplate encodes an Options Template FlowSet (RFC 3954 §6.1):
//
//	FlowSet Header:  flowset_id=1 (2B), length (2B)
//	Template Header: template_id=257 (2B), option_scope_length (2B, bytes),
//	                 option_length (2B, bytes)
//	scope field specifiers (type 2B + length 2B)…
//	option field specifiers (type 2B + length 2B)…
//	padding to a 4-byte boundary
func buildNF9OptionsTemplate(scope [2]uint16, options [][2]uint16) []byte {
	scopeLen := 4              // one scope specifier
	optLen := len(options) * 4 // option specifiers
	length := 4 + 6 + scopeLen + optLen
	if rem := length % 4; rem != 0 {
		length += 4 - rem
	}
	buf := make([]byte, length)
	pos := 0
	binary.BigEndian.PutUint16(buf[pos:], nf9OptionsFlowSetID)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(length))
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], nf9OptionsTemplateID)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(scopeLen))
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(optLen))
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], scope[0])
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], scope[1])
	pos += 2
	for _, f := range options {
		binary.BigEndian.PutUint16(buf[pos:], f[0])
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], f[1])
		pos += 2
	}
	return buf
}

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
	{nf9Direction, 1},
}

// nf9TemplatBytes is the pre-encoded Template FlowSet, built once at init.
// It is read-only after init and safe to reference from any goroutine.
var nf9TemplateBytes []byte

func init() {
	nf9TemplateBytes = buildNF9Template()
	nf9OptionShapes = map[string]flowOptionShapeDesc{
		flowOptionShapeIfScoped: {
			templ: buildNF9OptionsTemplate(
				[2]uint16{nf9ScopeInterface, 4},
				[][2]uint16{{nf9IfName, flowOptionStringLen}, {nf9IfDesc, flowOptionStringLen}}),
			recSize: nf9OptionRecSizeIfScoped,
			encodeRecord: func(buf []byte, pos int, _ uint32, ifc flowOptionIface) int {
				binary.BigEndian.PutUint32(buf[pos:], ifc.ifIndex) // scope: ifIndex
				pos += 4
				pos = putPaddedString(buf, pos, ifc.name) // interfaceName(82)
				pos = putPaddedString(buf, pos, ifc.name) // interfaceDescription(83)
				return pos
			},
		},
		flowOptionShapeSystemScoped: {
			templ: buildNF9OptionsTemplate(
				[2]uint16{nf9ScopeSystem, 4},
				[][2]uint16{{nf9InputSNMP, 4}, {nf9IfDesc, flowOptionStringLen}}),
			recSize: nf9OptionRecSizeSystemScoped,
			encodeRecord: func(buf []byte, pos int, _ uint32, ifc flowOptionIface) int {
				binary.BigEndian.PutUint32(buf[pos:], 0) // scope: system (value ignored by collectors)
				pos += 4
				binary.BigEndian.PutUint32(buf[pos:], ifc.ifIndex) // INPUT_SNMP(10): ifIndex as option field
				pos += 4
				pos = putPaddedString(buf, pos, ifc.name) // interfaceDescription(83)
				return pos
			},
		},
	}
}

// buildNF9Template encodes the Template FlowSet for nf9Fields.
// Layout (84 bytes):
//
//	FlowSet Header: flowset_id=0 (2B), length=84 (2B)
//	Template Header: template_id=256 (2B), field_count=19 (2B)
//	19 × (field_type 2B + field_length 2B)
func buildNF9Template() []byte {
	fieldCount := len(nf9Fields)
	length := 4 + 4 + fieldCount*4 // flowset hdr + tmpl hdr + fields
	buf := make([]byte, length)
	pos := 0

	binary.BigEndian.PutUint16(buf[pos:], 0) // FlowSet ID = 0 (Template)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(length)) // FlowSet Length
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], nf9TemplateID) // Template ID
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

// nf9DataPadBytes returns the padding the data FlowSet needs to reach a 4-byte
// boundary (RFC 3954 §5.3) when carrying n records. Records are 46 bytes and
// the FlowSet header is 4, so an odd record count needs 2 bytes of pad and an
// even count needs none — which is why dropping a single record is always
// enough to make an over-budget packet fit.
//
// The pad is written AFTER the records, so record-capacity arithmetic has to
// budget it. `available / nf9RecordSize` alone overflows the buffer whenever
// the leftover bytes are fewer than the pad an odd record count needs: a
// 70-byte buffer (exactly overhead + one record) admits one record, then pads
// two bytes past the end.
//
// Not a theoretical edge. At the IPv6 datagram budget a full NetFlow v9 packet
// lands on exactly len(buf) with zero bytes spare, so any later shift in
// linkMTU or the header constants would turn a clean size error into an
// index-out-of-range panic inside the shared flow-ticker goroutine, taking the
// process down with it.
func nf9DataPadBytes(n int) int {
	if rem := (nf9DataFlowSetHdrSize + n*nf9RecordSize) % 4; rem != 0 {
		return 4 - rem
	}
	return 0
}

// MaxRecordsPerDatagram returns 0: NetFlow v9 has no record-count cap, only
// the datagram budget.
func (NetFlow9Encoder) MaxRecordsPerDatagram() int { return 0 }

// TrailingPadBytes reports the data-FlowSet pad for n records so Tick's
// pagination and EncodePacket's record cap use the same formula.
func (NetFlow9Encoder) TrailingPadBytes(n int) int { return nf9DataPadBytes(n) }

// MaxRecordSize returns 0 because NetFlow v9 records are fixed-size; Tick
// paginates by PacketSizes()'s recordSize in that case.
func (NetFlow9Encoder) MaxRecordSize() int { return 0 }

// EncodePacket serialises a complete NetFlow v9 UDP payload into buf and
// returns the number of bytes written.
//
// Parameters:
//
//	domainID        — ObservationDomainID (source_id in v9 header); use the
//	                  device IPv4 address as uint32 for per-device identity.
//	seqNo           — per-domain sequence number (monotonically increasing).
//	uptimeMs        — device system uptime in milliseconds at export time.
//	records         — flow records to include in the Data FlowSet.
//	includeTemplate — when true, a Template FlowSet is prepended; send on the
//	                  first packet and every templateInterval thereafter.
//	buf             — caller-supplied output buffer. The encoder writes at most
//	                  len(buf) bytes, so the caller's slice length IS the
//	                  datagram payload budget: Tick passes a buffer already
//	                  capped to flowPayloadBudget so the frame fits the MTU.
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
	if minOne := overhead + nf9RecordSize + nf9DataPadBytes(1); len(buf) < minOne && len(records) > 0 {
		return 0, fmt.Errorf("netflow9: buffer too small (%d bytes), need at least %d", len(buf), minOne)
	}

	// Cap records to what fits in buf, INCLUDING the trailing pad. Dropping one
	// record flips the pad parity (see nf9DataPadBytes), so a single decrement
	// always suffices — no loop needed.
	available := len(buf) - overhead
	maxRecords := available / nf9RecordSize
	if maxRecords > 0 && overhead+maxRecords*nf9RecordSize+nf9DataPadBytes(maxRecords) > len(buf) {
		maxRecords--
	}
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

	// ── Template FlowSet (optional, 84 bytes) ────────────────────────
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

// EncodeOptionsDatagram serialises a self-contained "option interface-table"
// NetFlow v9 datagram into buf: packet header + Options Template FlowSet
// (FlowSet ID 1, template ID 257) + one option data record per interface
// (data FlowSet ID 257). It is NOT part of the FlowEncoder interface — the
// exporter reaches it via type-assert, like sFlow's datagram methods.
//
// Returns (bytesWritten, ifacesConsumed, err). consumed < len(ifaces) means
// the buffer filled up; the caller re-invokes with the remainder (each
// datagram re-carries the options template, so every datagram is
// self-describing). Returns (0, 0, nil) on empty input — an options set with
// zero records is an invalid packet to collectors, so the caller must skip
// emission entirely for an empty interface universe.
func (NetFlow9Encoder) EncodeOptionsDatagram(
	domainID uint32,
	seqNo uint32,
	uptimeMs uint32,
	shape string,
	ifaces []flowOptionIface,
	buf []byte,
) (int, int, error) {
	if len(ifaces) == 0 {
		return 0, 0, nil
	}
	desc, ok := nf9OptionShapes[shape]
	if !ok {
		return 0, 0, fmt.Errorf("netflow9: unknown options shape %q", shape)
	}
	overhead := nf9HeaderSize + len(desc.templ) + 4 // pkt hdr + options template + data flowset hdr
	if len(buf) < overhead+desc.recSize {
		return 0, 0, fmt.Errorf("netflow9: buffer too small (%d bytes) for an options datagram, need at least %d", len(buf), overhead+desc.recSize)
	}

	pos := 0
	// ── Packet Header — count backfilled once the record count is known ──
	binary.BigEndian.PutUint16(buf[pos:], nf9Version)
	pos += 2
	countOffset := pos
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], uptimeMs)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], uint32(time.Now().Unix()))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], seqNo)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], domainID)
	pos += 4

	// ── Options Template FlowSet ──────────────────────────────────────
	copy(buf[pos:], desc.templ)
	pos += len(desc.templ)

	// ── Option Data FlowSet (shared pagination + record writer) ───────
	pos, consumed := encodeOptionRecords(buf, pos, nf9OptionsTemplateID, desc, domainID, ifaces)
	if consumed == 0 {
		// Unreachable given the size check above; defensive.
		return 0, 0, fmt.Errorf("netflow9: buffer too small (%d bytes) for an options record", len(buf))
	}
	// count = 1 template record + data records.
	binary.BigEndian.PutUint16(buf[countOffset:], uint16(1+consumed))
	return pos, consumed, nil
}

// Compile-time guard: NetFlow9Encoder emits interface option tables.
var _ flowOptionsEncoder = NetFlow9Encoder{}

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
	// DIRECTION (1) — constant ingress; matches an `ip flow ingress` exporter
	buf[pos] = 0x00
	pos++
	return pos
}
