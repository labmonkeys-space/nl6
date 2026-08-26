/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"fmt"
	"log"
)

// sFlow v5 wire constants (sflow_version_5.txt).
const (
	sflowVersion     = 5
	sflowAddrTypeIP4 = 1

	// Sample-type format tags (enterprise 0 = standard).
	sflowSampleTypeFlow     = 1 // flow_sample
	sflowSampleTypeCounters = 2 // counters_sample

	// Flow-record format tags (enterprise 0).
	sflowFlowFmtSampledHeader = 1 // sampled_header

	// Counter-record format tags (enterprise 0).
	sflowCtrFmtGeneric   = 1 // if_counters (generic interface)
	sflowCtrFmtProcessor = 1001

	// header_protocol enum values we emit (sflow_version_5.txt §5.3).
	sflowHdrProtoIPv4 = 11

	// Datagram header on the wire, when agent_address_type is IPv4.
	//   version(4) + address_type(4) + agent_address(4) + sub_agent_id(4)
	//   + sequence_number(4) + uptime(4) + num_samples(4) = 28 bytes.
	sflowDatagramHeaderSize = 28

	// sflowCountersSampleHeaderSize is the on-wire byte overhead of a single
	// counters_sample wrapper: sample_type(4) + sample_length(4) +
	// sequence_number(4) + source_id(4) + num_counter_records(4) = 20 bytes.
	// flow_exporter.go uses this to compute pagination capacity so the
	// overhead arithmetic isn't an unlabelled magic number at the call site.
	sflowCountersSampleHeaderSize = 20

	// Conservative worst-case size for a single flow_sample carrying one
	// sampled_header record with a synthesized IPv4+UDP/TCP packet header.
	//   flow_sample body (8 u32) + one flow_record hdr (8B) + header body
	//   (protocol+frame_length+stripped+length = 16B) + sampled bytes (up
	//   to 40B for IPv4+TCP + XDR 4B padding).
	// 32 + 8 + 16 + 44 = 100 bytes. We round up to 128 for safety.
	sflowMaxFlowSampleSize = 128

	// Conservative worst-case size for a counters_sample carrying a single
	// if_counters record. if_counters body is 88 bytes; header + record
	// header + body + padding gives ~128 bytes. Multiple interfaces are
	// split across datagrams by Tick's MaxRecordSize pagination.
	sflowMaxCountersSampleSize = 256

	// SyntheticSamplingRateMultiplier is the fixed multiplier applied to
	// FlowProfile.ConcurrentFlows when synthesizing a sampling rate for
	// emitted FLOW_SAMPLE records. The value is documented as synthetic
	// in README.md and CLAUDE.md — collectors that extrapolate volume from
	// sampling_rate will produce numbers shaped like real device output
	// but not reflective of any real traffic.
	SyntheticSamplingRateMultiplier = 10
)

// SFlowEncoder encodes FlowRecords into sFlow v5 UDP datagrams.
//
// It implements the FlowEncoder interface. Unlike NetFlow/IPFIX, sFlow records
// are variable-length and self-describing, so MaxRecordSize returns a non-zero
// worst-case bound and PacketSizes' recordSize is advisory only — FlowExporter
// consults MaxRecordSize to paginate.
//
// The encoder is stateless; agent identity, uptime, and sequence numbers are
// passed in by Tick through FlowEncoder.EncodePacket arguments. A single
// encoder instance is shared across all devices.
//
// Phase 1 emits FLOW_SAMPLE records only. Phase 2 additionally emits
// COUNTERS_SAMPLE records for interface, CPU, and memory counters via
// EncodeDatagram (see flow_exporter.go sFlow code path).
type SFlowEncoder struct{}

// PacketSizes returns a conservative upper bound on the datagram header and
// per-record overhead. recordSize is advisory — MaxRecordSize drives Tick's
// pagination for variable-length protocols.
func (SFlowEncoder) PacketSizes() (int, int, int) {
	return sflowDatagramHeaderSize, 0, sflowMaxFlowSampleSize
}

// TrailingPadBytes returns 0: sFlow pads each sampled_header inside the sample
// it belongs to, so there is no trailing pad after the record set for Tick to
// budget.
func (SFlowEncoder) TrailingPadBytes(int) int { return 0 }

// MaxRecordSize returns the worst-case byte size of a single flow_sample on
// the wire. FlowExporter.Tick uses this to bound the number of flow records
// per datagram so no datagram payload exceeds len(buf) — which Tick has
// already capped to flowPayloadBudget, i.e. the MTU minus the IP and UDP
// headers. The bound is the on-wire FRAME, not the buffer: sizing to the
// buffer alone is what fragmented NetFlow v9 and IPFIX exports (nl6#485).
func (SFlowEncoder) MaxRecordSize() int { return sflowMaxFlowSampleSize }

// SeqIncrement returns 1 because sFlow v5's datagram sequence_number is the
// monotonic count of datagrams sent by this agent (sflow_version_5.txt §5.1),
// advancing once per datagram regardless of sample count.
func (SFlowEncoder) SeqIncrement(_ int) int { return 1 }

// EncodePacket serialises an sFlow v5 UDP datagram into buf and returns the
// number of bytes written. It is the FlowEncoder-interface entry point, whose
// fixed signature carries no per-device config: it delegates to
// EncodeFlowDatagram with sub_agent_id 0 and a conservative sampling_rate of
// 1, so there is a single encode path that cannot drift. In-tree sFlow ticks
// go through EncodeFlowDatagram directly with the device's configured
// SubAgentID and profile-aware rate (see flow_exporter.go).
//
// The includeTemplate parameter is ignored under sFlow (records are
// self-describing). Returns (0, nil) when records is empty. Returns an error
// if buf is too small to hold the datagram header plus a single flow sample.
func (e SFlowEncoder) EncodePacket(
	domainID uint32,
	seqNo uint32,
	uptimeMs uint32,
	records []FlowRecord,
	_ bool,
	buf []byte,
) (int, error) {
	return e.EncodeFlowDatagram(domainID, 0, seqNo, uptimeMs, records, 1, buf)
}

// EncodeFlowDatagram is the sFlow-specific, profile-aware equivalent of
// EncodePacket. It is called by FlowExporter.Tick when the active protocol is
// sFlow, so the synthesized sampling_rate can reflect the device's FlowProfile
// (rate = SyntheticSamplingRateMultiplier × profile.ConcurrentFlows).
//
// The FlowEncoder.EncodePacket entry point still works for out-of-tree callers
// and tests that don't care about rate, but in-tree ticks go through here so
// the sampling_rate matches the spec's synthetic-rate contract.
func (SFlowEncoder) EncodeFlowDatagram(
	domainID uint32,
	subAgentID uint32,
	seqNo uint32,
	uptimeMs uint32,
	records []FlowRecord,
	samplingRate uint32,
	buf []byte,
) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	if len(buf) < sflowDatagramHeaderSize+sflowMaxFlowSampleSize {
		return 0, fmt.Errorf("sflow: buffer too small (%d bytes)", len(buf))
	}
	maxRecs := (len(buf) - sflowDatagramHeaderSize) / sflowMaxFlowSampleSize
	if maxRecs < 1 {
		return 0, fmt.Errorf("sflow: buffer %d too small for a single flow sample", len(buf))
	}
	if len(records) > maxRecs {
		records = records[:maxRecs]
	}

	pos := encodeDatagramHeader(buf, domainID, subAgentID, seqNo, uptimeMs, uint32(len(records)))
	samplePool := uint32(0)
	for _, r := range records {
		pos = encodeFlowSample(buf, pos, r, samplePool, samplingRate)
		samplePool += r.Packets
	}
	return pos, nil
}

// encodeDatagramHeader writes the sFlow v5 datagram header into buf starting
// at offset 0 and returns the post-header position.
//
// Layout (28 bytes, sflow_version_5.txt §5.1):
//
//	uint32 version            = 5
//	uint32 agent_address_type = 1 (IPv4)
//	4-byte agent_address      = device IPv4 (big-endian)
//	uint32 sub_agent_id       = per-device flowConfig.SubAgentID (default 0)
//	uint32 sequence_number
//	uint32 uptime             (milliseconds since agent start)
//	uint32 num_samples
func encodeDatagramHeader(buf []byte, agentIPv4 uint32, subAgentID, seqNo, uptimeMs, numSamples uint32) int {
	binary.BigEndian.PutUint32(buf[0:], sflowVersion)
	binary.BigEndian.PutUint32(buf[4:], sflowAddrTypeIP4)
	binary.BigEndian.PutUint32(buf[8:], agentIPv4)
	binary.BigEndian.PutUint32(buf[12:], subAgentID) // sub_agent_id
	binary.BigEndian.PutUint32(buf[16:], seqNo)
	binary.BigEndian.PutUint32(buf[20:], uptimeMs)
	binary.BigEndian.PutUint32(buf[24:], numSamples)
	return sflowDatagramHeaderSize
}

// encodeFlowSample writes one flow_sample record (sample_type=1) containing a
// single sampled_header flow_record. Returns the new position.
//
// We emit the compact flow_sample format (not flow_sample_expanded) because
// the simulator's single-agent / low-ifIndex topology fits the 24-bit ds_index
// and 31-bit input/output encoding comfortably. Collectors that don't support
// flow_sample (OpenNMS Telemetryd does) can be addressed in a follow-up by
// switching to flow_sample_expanded (format 3).
//
// Layout of sample_data for flow_sample (sflow_version_5.txt §5.3):
//
//	u32 sample_length       (bytes of body that follow; filled in last)
//	u32 sequence_number     (per-instance; we use domain seqNo for simplicity)
//	u32 source_id           (ds_class<<24 | ds_index; we emit 0 for interface 0)
//	u32 sampling_rate
//	u32 sample_pool
//	u32 drops
//	u32 input               (ifIndex of ingress)
//	u32 output              (ifIndex of egress)
//	u32 num_flow_records    (= 1 — one sampled_header)
//	...flow_records...
func encodeFlowSample(buf []byte, pos int, r FlowRecord, samplePool, samplingRate uint32) int {
	// sample_type + sample_length header: uint32 sample_type, uint32 length.
	// The length is filled in after encoding the body so we can walk variable
	// records without a second pass for counter-sample cases.
	binary.BigEndian.PutUint32(buf[pos:], sflowSampleTypeFlow)
	sampleLenOffset := pos + 4
	// length placeholder
	binary.BigEndian.PutUint32(buf[sampleLenOffset:], 0)
	bodyStart := pos + 8
	p := bodyStart

	// flow_sample body — 8 u32 fields then the flow_records array.
	binary.BigEndian.PutUint32(buf[p:], 0) // sequence_number (local; 0 is valid)
	p += 4
	binary.BigEndian.PutUint32(buf[p:], uint32(r.InIface)) // source_id = ds_class(0)<<24 | ds_index
	p += 4
	binary.BigEndian.PutUint32(buf[p:], samplingRate)
	p += 4
	binary.BigEndian.PutUint32(buf[p:], samplePool)
	p += 4
	binary.BigEndian.PutUint32(buf[p:], 0) // drops
	p += 4
	binary.BigEndian.PutUint32(buf[p:], uint32(r.InIface))
	p += 4
	binary.BigEndian.PutUint32(buf[p:], uint32(r.OutIface))
	p += 4
	binary.BigEndian.PutUint32(buf[p:], 1) // num_flow_records
	p += 4

	p = encodeSampledHeader(buf, p, r)

	// Fill in sample_length (body bytes, not including the sample_type/length
	// header itself).
	binary.BigEndian.PutUint32(buf[sampleLenOffset:], uint32(p-bodyStart))
	return p
}

// encodeSampledHeader writes one sampled_header flow_record (format=1) with a
// synthesized IPv4+UDP (or IPv4+TCP) packet header derived from r's 5-tuple.
// Returns the new position.
//
// Layout (sflow_version_5.txt §5.3 "sampled_header"):
//
//	u32 flow_record_format = 1 (sampled_header)
//	u32 flow_record_length (bytes of body; filled last)
//	u32 header_protocol    = 11 (IPv4) — we skip L2 framing
//	u32 frame_length       (original "on-wire" packet length; we use r.Bytes
//	                        clamped to uint32, or a synthesized per-packet size)
//	u32 stripped           = 0
//	opaque header<>        — XDR opaque: u32 length then header bytes then
//	                        zero-padding to 4-byte boundary.
func encodeSampledHeader(buf []byte, pos int, r FlowRecord) int {
	// flow_record header: format + length placeholder.
	binary.BigEndian.PutUint32(buf[pos:], sflowFlowFmtSampledHeader)
	lenOffset := pos + 4
	binary.BigEndian.PutUint32(buf[lenOffset:], 0)
	bodyStart := pos + 8
	p := bodyStart

	binary.BigEndian.PutUint32(buf[p:], sflowHdrProtoIPv4)
	p += 4

	// frame_length: clamp the flow's total octets to uint32 and reuse as the
	// "original packet length". This is synthetic — real sampled_header frames
	// carry the length of the single captured packet, not a flow-wide total.
	frameLen := r.Bytes
	if frameLen > 0xFFFFFFFF {
		frameLen = 0xFFFFFFFF
	}
	if frameLen == 0 {
		frameLen = 20 + 8 // minimal IPv4+UDP synthesized header below
	}
	binary.BigEndian.PutUint32(buf[p:], uint32(frameLen))
	p += 4

	binary.BigEndian.PutUint32(buf[p:], 0) // stripped bytes
	p += 4

	// opaque header<> — 4-byte length prefix, bytes, then zero pad to 4B.
	headerStart := p + 4 // skip the opaque length field; fill in after.
	hdrLen := encodeIPv4Header(buf, headerStart, r)
	binary.BigEndian.PutUint32(buf[p:], uint32(hdrLen))
	p = headerStart + hdrLen
	// Pad header bytes to 4-byte boundary.
	if rem := hdrLen % 4; rem != 0 {
		padBytes := 4 - rem
		for i := 0; i < padBytes; i++ {
			buf[p] = 0
			p++
		}
	}

	// Fill in flow_record_length (bytes of body that follow the length field).
	binary.BigEndian.PutUint32(buf[lenOffset:], uint32(p-bodyStart))
	return p
}

// encodeIPv4Header writes a minimal synthetic IPv4 header followed by a bare
// UDP or TCP transport header into buf at pos and returns the number of bytes
// written.
//
// For protocols other than TCP/UDP (e.g. ICMP) only the IPv4 header is written.
// This matches the spec's sampled_header expectation of a parseable IPv4 packet
// while keeping the synthetic payload minimal.
func encodeIPv4Header(buf []byte, pos int, r FlowRecord) int {
	start := pos

	src := r.SrcIP.To4()
	if src == nil {
		src = []byte{0, 0, 0, 0}
	}
	dst := r.DstIP.To4()
	if dst == nil {
		dst = []byte{0, 0, 0, 0}
	}

	// IPv4 header (20 bytes, no options).
	buf[pos] = 0x45 // version 4, ihl 5
	pos++
	buf[pos] = r.ToS
	pos++

	// total_length placeholder (2B) — filled after transport header.
	totalLenOffset := pos
	pos += 2

	// identification (2B), flags+frag_offset (2B), ttl (1B), protocol (1B).
	binary.BigEndian.PutUint16(buf[pos:], 0)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], 0x4000) // DF set
	pos += 2
	buf[pos] = 64 // ttl
	pos++
	buf[pos] = r.Protocol
	pos++

	// header_checksum placeholder — 0, not computed (synthetic header).
	binary.BigEndian.PutUint16(buf[pos:], 0)
	pos += 2

	copy(buf[pos:], src)
	pos += 4
	copy(buf[pos:], dst)
	pos += 4

	// Transport header.
	switch r.Protocol {
	case 17: // UDP (8 bytes)
		binary.BigEndian.PutUint16(buf[pos:], r.SrcPort)
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], r.DstPort)
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], 8) // UDP length (header-only)
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], 0) // checksum (0 = unused for IPv4 UDP)
		pos += 2
	case 6: // TCP (20 bytes, no options)
		binary.BigEndian.PutUint16(buf[pos:], r.SrcPort)
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], r.DstPort)
		pos += 2
		binary.BigEndian.PutUint32(buf[pos:], 0) // seq
		pos += 4
		binary.BigEndian.PutUint32(buf[pos:], 0) // ack
		pos += 4
		buf[pos] = 0x50 // data offset 5<<4, reserved 0
		pos++
		buf[pos] = r.TCPFlags
		pos++
		binary.BigEndian.PutUint16(buf[pos:], 0xFFFF) // window
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], 0) // checksum (synthetic header)
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], 0) // urgent
		pos += 2
	}

	total := pos - start
	binary.BigEndian.PutUint16(buf[totalLenOffset:], uint16(total))
	return total
}

// EncodeCounterDatagram writes an sFlow v5 datagram containing one or more
// counters_sample records sourced from the provided CounterRecord slices.
//
// Records are grouped into counters_sample wrappers by SourceID. This matters
// for collectors such as OpenNMS Telemetryd that key if_counters records by
// ds_index: per-interface records (SourceID = ifIndex) appear under their own
// counters_sample and device-wide records (SourceID = 0, e.g.
// processor_information) appear under a separate counters_sample with
// source_id=0. Records sharing a SourceID remain in input order within their
// group.
//
// The caller is expected to have already bounded the number of records so the
// datagram fits in a single UDP buffer. Records that would overflow the
// buffer are dropped with a log.Printf warning so silent loss is visible.
// Returns (0, nil) on empty input.
func (SFlowEncoder) EncodeCounterDatagram(
	domainID uint32,
	subAgentID uint32,
	seqNo uint32,
	uptimeMs uint32,
	records []CounterRecord,
	buf []byte,
) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	if len(buf) < sflowDatagramHeaderSize+sflowMaxCountersSampleSize {
		return 0, fmt.Errorf("sflow: buffer too small for counter sample (%d bytes)", len(buf))
	}

	// Group by SourceID while preserving input order: both the order of first
	// appearance of each SourceID and the order of records within a group.
	groupOrder := make([]uint32, 0, 4)
	groups := make(map[uint32][]CounterRecord, 4)
	for _, rec := range records {
		if _, seen := groups[rec.SourceID]; !seen {
			groupOrder = append(groupOrder, rec.SourceID)
		}
		groups[rec.SourceID] = append(groups[rec.SourceID], rec)
	}

	// Reserve datagram-header space; num_samples is filled once the number of
	// samples actually emitted is known (a group may be skipped if the buffer
	// can't hold even its fixed-size header).
	pos := sflowDatagramHeaderSize
	dropped := 0
	samplesEmitted := uint32(0)

	for _, sourceID := range groupOrder {
		recs := groups[sourceID]
		// Conservative check: counters_sample wrapper itself needs 20 bytes.
		if len(buf)-pos < sflowCountersSampleHeaderSize {
			dropped += len(recs)
			continue
		}

		// counters_sample header: sample_type(4) + sample_length(4).
		// Then body: sequence_number(4) + source_id(4) + num_counter_records(4)
		// followed by the counter_records themselves.
		binary.BigEndian.PutUint32(buf[pos:], sflowSampleTypeCounters)
		sampleLenOffset := pos + 4
		binary.BigEndian.PutUint32(buf[sampleLenOffset:], 0)
		bodyStart := pos + 8
		p := bodyStart

		binary.BigEndian.PutUint32(buf[p:], seqNo) // sequence_number
		p += 4
		binary.BigEndian.PutUint32(buf[p:], sourceID) // source_id (ds_class=0, ds_index=sourceID)
		p += 4
		// num_counter_records — placeholder; backfilled after emitting records
		// so partial overflow shrinks the count instead of lying to the decoder.
		numRecsOffset := p
		binary.BigEndian.PutUint32(buf[p:], 0)
		p += 4

		emitted := uint32(0)
		for _, rec := range recs {
			padded := len(rec.Body)
			if rem := padded % 4; rem != 0 {
				padded += 4 - rem
			}
			// 8B record header (format + length) + padded body.
			if len(buf)-p < 8+padded {
				dropped++
				continue
			}
			binary.BigEndian.PutUint32(buf[p:], rec.Format)
			p += 4
			binary.BigEndian.PutUint32(buf[p:], uint32(len(rec.Body)))
			p += 4
			copy(buf[p:], rec.Body)
			p += len(rec.Body)
			// Pad to 4-byte boundary.
			if rem := len(rec.Body) % 4; rem != 0 {
				padBytes := 4 - rem
				for i := 0; i < padBytes; i++ {
					buf[p] = 0
					p++
				}
			}
			emitted++
		}

		// Skip empty samples — if every record in this group overflowed we
		// shouldn't emit a header with num_counter_records=0.
		if emitted == 0 {
			// Rewind the sample wrapper we started writing.
			continue
		}

		// Backfill sample_length (body bytes after the sample_type/length
		// header itself) and num_counter_records.
		binary.BigEndian.PutUint32(buf[sampleLenOffset:], uint32(p-bodyStart))
		binary.BigEndian.PutUint32(buf[numRecsOffset:], emitted)

		pos = p
		samplesEmitted++
	}

	if samplesEmitted == 0 {
		// Nothing fit; surface the drop without writing a half-formed datagram.
		if dropped > 0 {
			log.Printf("sflow: dropping %d counter records that don't fit in datagram", dropped)
		}
		return 0, nil
	}

	// Backfill the datagram header — encodeDatagramHeader writes 7 u32 fields
	// including num_samples at offset 24.
	encodeDatagramHeader(buf, domainID, subAgentID, seqNo, uptimeMs, samplesEmitted)

	if dropped > 0 {
		log.Printf("sflow: dropping %d counter records that don't fit in datagram", dropped)
	}
	return pos, nil
}

// _ compile-time guard that SFlowEncoder satisfies FlowEncoder.
var _ FlowEncoder = SFlowEncoder{}
