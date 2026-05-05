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
	"net"
	"testing"
	"time"
)

// ── Inline sFlow v5 XDR decoder (test oracle) ────────────────────────────────
//
// Minimal parser for the subset of sFlow v5 emitted by SFlowEncoder. Validates
// that datagrams round-trip through an independent decoder, proving we produce
// wire-compliant XDR without introducing an external dependency.

type sflowDatagramHdr struct {
	Version    uint32
	AddrType   uint32
	AgentIPv4  [4]byte
	SubAgentID uint32
	SequenceNo uint32
	Uptime     uint32
	NumSamples uint32
}

type sflowSampledHeader struct {
	HeaderProtocol uint32
	FrameLength    uint32
	Stripped       uint32
	Header         []byte
}

type sflowFlowRecord struct {
	Format        uint32
	Length        uint32
	SampledHeader *sflowSampledHeader // populated when Format == 1
}

type sflowFlowSample struct {
	SequenceNumber uint32
	SourceID       uint32
	SamplingRate   uint32
	SamplePool     uint32
	Drops          uint32
	Input          uint32
	Output         uint32
	NumFlowRecords uint32
	Records        []sflowFlowRecord
}

type sflowCounterRecord struct {
	Format uint32
	Length uint32
	Body   []byte
}

type sflowCountersSample struct {
	SequenceNumber uint32
	SourceID       uint32
	NumRecords     uint32
	Records        []sflowCounterRecord
}

type sflowSample struct {
	Type        uint32
	Length      uint32
	FlowSample  *sflowFlowSample     // populated when Type == 1
	CounterSmpl *sflowCountersSample // populated when Type == 2
}

type sflowDatagram struct {
	Header  sflowDatagramHdr
	Samples []sflowSample
}

func decodeSFlow(t *testing.T, data []byte) *sflowDatagram {
	t.Helper()
	if len(data) < sflowDatagramHeaderSize {
		t.Fatalf("sflow: datagram too short: %d bytes", len(data))
	}
	dg := &sflowDatagram{}
	dg.Header.Version = binary.BigEndian.Uint32(data[0:])
	dg.Header.AddrType = binary.BigEndian.Uint32(data[4:])
	copy(dg.Header.AgentIPv4[:], data[8:12])
	dg.Header.SubAgentID = binary.BigEndian.Uint32(data[12:])
	dg.Header.SequenceNo = binary.BigEndian.Uint32(data[16:])
	dg.Header.Uptime = binary.BigEndian.Uint32(data[20:])
	dg.Header.NumSamples = binary.BigEndian.Uint32(data[24:])

	pos := sflowDatagramHeaderSize
	for i := uint32(0); i < dg.Header.NumSamples && pos+8 <= len(data); i++ {
		var s sflowSample
		s.Type = binary.BigEndian.Uint32(data[pos:])
		s.Length = binary.BigEndian.Uint32(data[pos+4:])
		if pos+8+int(s.Length) > len(data) {
			t.Fatalf("sflow: sample length %d overruns datagram at offset %d", s.Length, pos)
		}
		bodyStart := pos + 8
		bodyEnd := bodyStart + int(s.Length)

		switch s.Type {
		case sflowSampleTypeFlow:
			fs := decodeFlowSample(t, data[bodyStart:bodyEnd])
			s.FlowSample = fs
		case sflowSampleTypeCounters:
			cs := decodeCountersSample(t, data[bodyStart:bodyEnd])
			s.CounterSmpl = cs
		default:
			// Unknown sample type — skip body.
		}
		dg.Samples = append(dg.Samples, s)
		pos = bodyEnd
	}
	return dg
}

func decodeFlowSample(t *testing.T, b []byte) *sflowFlowSample {
	t.Helper()
	if len(b) < 32 {
		t.Fatalf("sflow: flow_sample body too short: %d", len(b))
	}
	fs := &sflowFlowSample{}
	fs.SequenceNumber = binary.BigEndian.Uint32(b[0:])
	fs.SourceID = binary.BigEndian.Uint32(b[4:])
	fs.SamplingRate = binary.BigEndian.Uint32(b[8:])
	fs.SamplePool = binary.BigEndian.Uint32(b[12:])
	fs.Drops = binary.BigEndian.Uint32(b[16:])
	fs.Input = binary.BigEndian.Uint32(b[20:])
	fs.Output = binary.BigEndian.Uint32(b[24:])
	fs.NumFlowRecords = binary.BigEndian.Uint32(b[28:])

	pos := 32
	for i := uint32(0); i < fs.NumFlowRecords && pos+8 <= len(b); i++ {
		var fr sflowFlowRecord
		fr.Format = binary.BigEndian.Uint32(b[pos:])
		fr.Length = binary.BigEndian.Uint32(b[pos+4:])
		recBodyStart := pos + 8
		recBodyEnd := recBodyStart + int(fr.Length)
		if recBodyEnd > len(b) {
			t.Fatalf("sflow: flow_record length %d overruns flow_sample at offset %d", fr.Length, pos)
		}
		if fr.Format == sflowFlowFmtSampledHeader {
			fr.SampledHeader = decodeSampledHeader(t, b[recBodyStart:recBodyEnd])
		}
		fs.Records = append(fs.Records, fr)
		pos = recBodyEnd
	}
	return fs
}

func decodeSampledHeader(t *testing.T, b []byte) *sflowSampledHeader {
	t.Helper()
	if len(b) < 12+4 {
		t.Fatalf("sflow: sampled_header body too short: %d", len(b))
	}
	sh := &sflowSampledHeader{}
	sh.HeaderProtocol = binary.BigEndian.Uint32(b[0:])
	sh.FrameLength = binary.BigEndian.Uint32(b[4:])
	sh.Stripped = binary.BigEndian.Uint32(b[8:])
	hdrLen := binary.BigEndian.Uint32(b[12:])
	if 16+int(hdrLen) > len(b) {
		t.Fatalf("sflow: sampled_header header length %d overruns body of len %d", hdrLen, len(b))
	}
	sh.Header = append([]byte{}, b[16:16+int(hdrLen)]...)
	return sh
}

func decodeCountersSample(t *testing.T, b []byte) *sflowCountersSample {
	t.Helper()
	if len(b) < 12 {
		t.Fatalf("sflow: counters_sample body too short: %d", len(b))
	}
	cs := &sflowCountersSample{}
	cs.SequenceNumber = binary.BigEndian.Uint32(b[0:])
	cs.SourceID = binary.BigEndian.Uint32(b[4:])
	cs.NumRecords = binary.BigEndian.Uint32(b[8:])
	pos := 12
	for i := uint32(0); i < cs.NumRecords && pos+8 <= len(b); i++ {
		var rec sflowCounterRecord
		rec.Format = binary.BigEndian.Uint32(b[pos:])
		rec.Length = binary.BigEndian.Uint32(b[pos+4:])
		bodyStart := pos + 8
		bodyEnd := bodyStart + int(rec.Length)
		if bodyEnd > len(b) {
			t.Fatalf("sflow: counter_record length %d overruns counters_sample at offset %d", rec.Length, pos)
		}
		rec.Body = append([]byte{}, b[bodyStart:bodyEnd]...)
		cs.Records = append(cs.Records, rec)
		// Skip 4-byte XDR padding for non-aligned bodies.
		pad := (4 - (int(rec.Length) % 4)) % 4
		pos = bodyEnd + pad
	}
	return cs
}

// parseIPv4 returns (srcIP, dstIP, protocol, srcPort, dstPort) extracted from
// the first 20 bytes + transport header of a synthesized IPv4 packet emitted
// by encodeIPv4Header.
func parseIPv4(t *testing.T, hdr []byte) (net.IP, net.IP, uint8, uint16, uint16) {
	t.Helper()
	if len(hdr) < 20 {
		t.Fatalf("parseIPv4: header too short: %d", len(hdr))
	}
	if hdr[0] != 0x45 {
		t.Errorf("parseIPv4: version/ihl = %#x, want 0x45", hdr[0])
	}
	proto := hdr[9]
	src := net.IP(append([]byte{}, hdr[12:16]...))
	dst := net.IP(append([]byte{}, hdr[16:20]...))
	var sp, dp uint16
	switch proto {
	case 6, 17:
		if len(hdr) < 24 {
			t.Fatalf("parseIPv4: transport truncated: %d", len(hdr))
		}
		sp = binary.BigEndian.Uint16(hdr[20:])
		dp = binary.BigEndian.Uint16(hdr[22:])
	}
	return src, dst, proto, sp, dp
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestSFlowFlowEncoderInterface(t *testing.T) {
	// Compile-time assertion: SFlowEncoder implements FlowEncoder.
	var _ FlowEncoder = SFlowEncoder{}

	enc := SFlowEncoder{}
	if got := enc.MaxRecordSize(); got == 0 {
		t.Errorf("SFlowEncoder.MaxRecordSize() = 0, want non-zero for variable-length opt-in")
	}
}

func TestSFlowDatagramHeader(t *testing.T) {
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)
	r := makeRecord("10.0.1.1", "10.0.2.2", 50000, 443, 6)

	n, err := enc.EncodeFlowDatagram(0xC0A80101, 42, 5000, []FlowRecord{r}, 1280, buf)
	if err != nil {
		t.Fatalf("EncodeFlowDatagram error: %v", err)
	}
	if n == 0 {
		t.Fatal("EncodeFlowDatagram returned 0 bytes")
	}

	dg := decodeSFlow(t, buf[:n])
	if dg.Header.Version != 5 {
		t.Errorf("version = %d, want 5", dg.Header.Version)
	}
	if dg.Header.AddrType != sflowAddrTypeIP4 {
		t.Errorf("address_type = %d, want 1 (IPv4)", dg.Header.AddrType)
	}
	want := [4]byte{0xC0, 0xA8, 0x01, 0x01}
	if dg.Header.AgentIPv4 != want {
		t.Errorf("agent_address = %v, want %v", dg.Header.AgentIPv4, want)
	}
	if dg.Header.SubAgentID != 0 {
		t.Errorf("sub_agent_id = %d, want 0", dg.Header.SubAgentID)
	}
	if dg.Header.SequenceNo != 42 {
		t.Errorf("sequence_number = %d, want 42", dg.Header.SequenceNo)
	}
	if dg.Header.Uptime != 5000 {
		t.Errorf("uptime = %d, want 5000", dg.Header.Uptime)
	}
	if dg.Header.NumSamples != 1 {
		t.Errorf("num_samples = %d, want 1", dg.Header.NumSamples)
	}
}

func TestSFlowFlowSampleTuple(t *testing.T) {
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)

	src := net.ParseIP("192.168.1.10").To4()
	dst := net.ParseIP("10.20.30.40").To4()
	r := FlowRecord{
		SrcIP:    src,
		DstIP:    dst,
		NextHop:  net.IPv4(0, 0, 0, 0).To4(),
		SrcPort:  54321,
		DstPort:  443,
		Protocol: 6, // TCP
		TCPFlags: 0x18,
		Bytes:    9876,
		Packets:  7,
		StartMs:  1000,
		EndMs:    2500,
		InIface:  3,
		OutIface: 4,
	}

	n, err := enc.EncodeFlowDatagram(0xC0A8010A, 1, 1000, []FlowRecord{r}, 2000, buf)
	if err != nil {
		t.Fatalf("EncodeFlowDatagram error: %v", err)
	}
	dg := decodeSFlow(t, buf[:n])
	if len(dg.Samples) != 1 {
		t.Fatalf("samples = %d, want 1", len(dg.Samples))
	}
	if dg.Samples[0].Type != sflowSampleTypeFlow {
		t.Errorf("sample type = %d, want %d (flow_sample)", dg.Samples[0].Type, sflowSampleTypeFlow)
	}
	fs := dg.Samples[0].FlowSample
	if fs == nil {
		t.Fatal("flow sample not decoded")
	}
	if fs.SamplingRate != 2000 {
		t.Errorf("sampling_rate = %d, want 2000", fs.SamplingRate)
	}
	if fs.Input != 3 {
		t.Errorf("input = %d, want 3", fs.Input)
	}
	if fs.Output != 4 {
		t.Errorf("output = %d, want 4", fs.Output)
	}
	if fs.NumFlowRecords != 1 {
		t.Fatalf("num_flow_records = %d, want 1", fs.NumFlowRecords)
	}

	rec := fs.Records[0]
	if rec.Format != sflowFlowFmtSampledHeader {
		t.Errorf("flow_record format = %d, want %d (sampled_header)", rec.Format, sflowFlowFmtSampledHeader)
	}
	sh := rec.SampledHeader
	if sh == nil {
		t.Fatal("sampled_header not decoded")
	}
	if sh.HeaderProtocol != sflowHdrProtoIPv4 {
		t.Errorf("header_protocol = %d, want %d (IPv4)", sh.HeaderProtocol, sflowHdrProtoIPv4)
	}
	if sh.FrameLength != 9876 {
		t.Errorf("frame_length = %d, want 9876", sh.FrameLength)
	}
	if sh.Stripped != 0 {
		t.Errorf("stripped = %d, want 0", sh.Stripped)
	}

	gotSrc, gotDst, proto, sp, dp := parseIPv4(t, sh.Header)
	if !gotSrc.Equal(src) {
		t.Errorf("sampled IPv4 src = %v, want %v", gotSrc, src)
	}
	if !gotDst.Equal(dst) {
		t.Errorf("sampled IPv4 dst = %v, want %v", gotDst, dst)
	}
	if proto != 6 {
		t.Errorf("sampled IPv4 protocol = %d, want 6 (TCP)", proto)
	}
	if sp != 54321 {
		t.Errorf("sampled TCP src port = %d, want 54321", sp)
	}
	if dp != 443 {
		t.Errorf("sampled TCP dst port = %d, want 443", dp)
	}
}

func TestSFlowFlowSampleUDP(t *testing.T) {
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)
	r := makeRecord("10.0.0.1", "10.0.0.2", 55000, 53, 17) // UDP DNS
	r.Bytes = 128

	n, err := enc.EncodeFlowDatagram(0x0A000001, 2, 2000, []FlowRecord{r}, 100, buf)
	if err != nil {
		t.Fatalf("EncodeFlowDatagram error: %v", err)
	}
	dg := decodeSFlow(t, buf[:n])
	sh := dg.Samples[0].FlowSample.Records[0].SampledHeader
	_, _, proto, sp, dp := parseIPv4(t, sh.Header)
	if proto != 17 {
		t.Errorf("sampled UDP protocol = %d, want 17", proto)
	}
	if sp != 55000 {
		t.Errorf("sampled UDP src port = %d, want 55000", sp)
	}
	if dp != 53 {
		t.Errorf("sampled UDP dst port = %d, want 53", dp)
	}
}

func TestSFlowSequenceIncrements(t *testing.T) {
	// Two encode calls with consecutive seqNo values should round-trip to
	// sequence_numbers differing by exactly one.
	enc := SFlowEncoder{}
	buf1 := make([]byte, 1500)
	buf2 := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 1000, 443, 6)}

	n1, err := enc.EncodeFlowDatagram(0x0A000001, 100, 1000, records, 1, buf1)
	if err != nil {
		t.Fatalf("pkt 1 error: %v", err)
	}
	n2, err := enc.EncodeFlowDatagram(0x0A000001, 101, 1100, records, 1, buf2)
	if err != nil {
		t.Fatalf("pkt 2 error: %v", err)
	}
	d1 := decodeSFlow(t, buf1[:n1])
	d2 := decodeSFlow(t, buf2[:n2])
	if d2.Header.SequenceNo-d1.Header.SequenceNo != 1 {
		t.Errorf("sequence diff = %d, want 1", d2.Header.SequenceNo-d1.Header.SequenceNo)
	}
}

func TestSFlowMultipleRecords(t *testing.T) {
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{
		makeRecord("10.0.0.1", "10.0.0.2", 1001, 443, 6),
		makeRecord("10.0.0.3", "10.0.0.4", 1002, 80, 6),
		makeRecord("10.0.0.5", "10.0.0.6", 1003, 53, 17),
	}
	n, err := enc.EncodeFlowDatagram(1, 5, 1000, records, 42, buf)
	if err != nil {
		t.Fatalf("EncodeFlowDatagram error: %v", err)
	}
	dg := decodeSFlow(t, buf[:n])
	if int(dg.Header.NumSamples) != len(records) {
		t.Errorf("num_samples = %d, want %d", dg.Header.NumSamples, len(records))
	}
	if len(dg.Samples) != len(records) {
		t.Fatalf("decoded samples = %d, want %d", len(dg.Samples), len(records))
	}
	// All samples should carry samplingRate = 42
	for i, s := range dg.Samples {
		if s.FlowSample.SamplingRate != 42 {
			t.Errorf("sample[%d] sampling_rate = %d, want 42", i, s.FlowSample.SamplingRate)
		}
	}
}

func TestSFlowMTUBound(t *testing.T) {
	// With 20 records and 1500-byte buffer, worst-case 128B/record says at
	// most 11 fit (1500-28)/128 = 11. EncodeFlowDatagram should cap at that
	// number and not overflow. Two successive calls with the remainder drain
	// the queue without exceeding MTU.
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)
	records := make([]FlowRecord, 20)
	for i := range records {
		records[i] = makeRecord("10.0.0.1", "10.0.0.2", uint16(2000+i), 443, 6)
	}
	n, err := enc.EncodeFlowDatagram(1, 1, 1000, records, 100, buf)
	if err != nil {
		t.Fatalf("EncodeFlowDatagram error: %v", err)
	}
	if n > 1500 {
		t.Errorf("datagram size = %d, exceeds 1500-byte MTU", n)
	}
	dg := decodeSFlow(t, buf[:n])
	if int(dg.Header.NumSamples) > 11 {
		t.Errorf("samples in one datagram = %d, want <= 11 (MTU cap)", dg.Header.NumSamples)
	}
	if dg.Header.NumSamples == 0 {
		t.Error("expected at least one sample in datagram")
	}
}

func TestSFlowSyntheticSamplingRateConstant(t *testing.T) {
	// The design mandates rate = 10 × ConcurrentFlows. This test guards the
	// named constant used by the Tick-level integration path.
	if SyntheticSamplingRateMultiplier != 10 {
		t.Errorf("SyntheticSamplingRateMultiplier = %d, want 10 (design §D3)", SyntheticSamplingRateMultiplier)
	}
}

func TestSFlowEncodePacketIsAFlowEncoderEntryPoint(t *testing.T) {
	// EncodePacket (the FlowEncoder entry point) should produce a valid
	// datagram even without a profile-derived sampling rate. This keeps
	// out-of-tree callers working.
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 1001, 443, 6)}
	n, err := enc.EncodePacket(0x0A000001, 1, 1000, records, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	if n == 0 {
		t.Fatal("EncodePacket returned 0 bytes")
	}
	dg := decodeSFlow(t, buf[:n])
	if dg.Header.Version != 5 {
		t.Errorf("version = %d, want 5", dg.Header.Version)
	}
	if dg.Samples[0].FlowSample.SamplingRate != 1 {
		t.Errorf("default sampling_rate = %d, want 1 (EncodePacket fallback)", dg.Samples[0].FlowSample.SamplingRate)
	}
}

func TestSFlowEncodePacketEmptyReturnsZero(t *testing.T) {
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodePacket(1, 0, 0, nil, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	if n != 0 {
		t.Errorf("empty call = %d bytes, want 0", n)
	}
}

func TestSFlowEncodePacketBufferTooSmall(t *testing.T) {
	enc := SFlowEncoder{}
	tiny := make([]byte, 10)
	_, err := enc.EncodePacket(1, 0, 0,
		[]FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 1000, 443, 6)}, false, tiny)
	if err == nil {
		t.Error("expected error for too-small buffer, got nil")
	}
}

func TestSFlowIPv4ProtocolTagAndICMP(t *testing.T) {
	// ICMP (protocol 1) should be emitted with an IPv4 header but no transport
	// ports. The decoder parses protocol bytes from the IPv4 header alone.
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)
	r := makeRecord("10.0.0.1", "10.0.0.2", 0, 0, 1)
	r.Bytes = 64

	n, err := enc.EncodeFlowDatagram(0x0A000001, 1, 1000, []FlowRecord{r}, 1, buf)
	if err != nil {
		t.Fatalf("EncodeFlowDatagram error: %v", err)
	}
	dg := decodeSFlow(t, buf[:n])
	sh := dg.Samples[0].FlowSample.Records[0].SampledHeader
	if len(sh.Header) < 20 {
		t.Fatalf("ICMP sampled header too short: %d", len(sh.Header))
	}
	if sh.Header[9] != 1 {
		t.Errorf("protocol byte = %d, want 1 (ICMP)", sh.Header[9])
	}
}

// ── Counter sample round-trip (Phase 2) ──────────────────────────────────────

func TestSFlowCounterDatagramInterfaceCounters(t *testing.T) {
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)

	// (ifIndex, speedBps, inOctets, inUcast, inMcast, inBcast, inDisc, inErr,
	//  outOctets, outUcast, outMcast, outBcast, outDisc, outErr)
	body := encodeIfCountersBody(
		3, 1_000_000_000,
		12345678, 100, 10, 5, 0, 0,
		23456789, 200, 20, 10, 0, 0,
	)
	recs := []CounterRecord{{Format: sflowCtrFmtGeneric, Body: body}}

	n, err := enc.EncodeCounterDatagram(0xC0A80102, 7, 500, recs, buf)
	if err != nil {
		t.Fatalf("EncodeCounterDatagram error: %v", err)
	}
	dg := decodeSFlow(t, buf[:n])

	if dg.Header.Version != 5 {
		t.Errorf("version = %d, want 5", dg.Header.Version)
	}
	if dg.Header.NumSamples != 1 {
		t.Fatalf("num_samples = %d, want 1", dg.Header.NumSamples)
	}
	s := dg.Samples[0]
	if s.Type != sflowSampleTypeCounters {
		t.Errorf("sample type = %d, want %d (counters_sample)", s.Type, sflowSampleTypeCounters)
	}
	cs := s.CounterSmpl
	if cs == nil {
		t.Fatal("counter sample not decoded")
	}
	if cs.NumRecords != 1 || len(cs.Records) != 1 {
		t.Fatalf("records = %d, want 1", cs.NumRecords)
	}
	rec := cs.Records[0]
	if rec.Format != sflowCtrFmtGeneric {
		t.Errorf("counter record format = %d, want %d", rec.Format, sflowCtrFmtGeneric)
	}
	if len(rec.Body) != 88 {
		t.Fatalf("if_counters body length = %d, want 88", len(rec.Body))
	}
	// Sanity-check ifIndex and octet totals.
	if ifIdx := binary.BigEndian.Uint32(rec.Body[0:]); ifIdx != 3 {
		t.Errorf("decoded ifIndex = %d, want 3", ifIdx)
	}
	if speed := binary.BigEndian.Uint64(rec.Body[8:]); speed != 1_000_000_000 {
		t.Errorf("decoded ifSpeed = %d, want 1_000_000_000", speed)
	}
	if inOct := binary.BigEndian.Uint64(rec.Body[24:]); inOct != 12345678 {
		t.Errorf("decoded ifInOctets = %d, want 12345678", inOct)
	}
	if outOct := binary.BigEndian.Uint64(rec.Body[56:]); outOct != 23456789 {
		t.Errorf("decoded ifOutOctets = %d, want 23456789", outOct)
	}
}

func TestSFlowCounterDatagramEmpty(t *testing.T) {
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodeCounterDatagram(1, 1, 0, nil, buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("empty records call returned %d bytes, want 0", n)
	}
}

// TestSFlowTickSyntheticRate end-to-ends through FlowExporter.Tick to prove
// the spec's synthetic-rate scenario: the sFlow flow_sample on the wire
// carries sampling_rate = 10 × profile.ConcurrentFlows. This is the scenario
// "Synthetic sampling rate is consistent and documented".
func TestSFlowTickSyntheticRate(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	// Use a short inactive timeout so at least one flow expires inside the
	// single Tick we run. Active timeout is much longer so Expire is driven
	// by inactivity, not age.
	profile := &FlowProfile{
		TCPWeight:       1.0,
		DstPorts:        []PortWeight{{Port: 443, Weight: 1.0}},
		SrcPortMin:      1024,
		SrcPortMax:      65535,
		BytesMin:        512,
		BytesMax:        1024,
		PktsMin:         1,
		PktsMax:         10,
		DurationMinMs:   100,
		DurationMaxMs:   500,
		ConcurrentFlows: 5, // rate should end up 5 × 10 = 50
		MaxFlows:        256,
	}

	fe := newTestFlowExporter(testDevice("10.9.8.7"), profile,
		1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)

	// Run two ticks 10ms apart so the inactive timeout fires.
	tickWithEncoder(fe, time.Now(), SFlowEncoder{}, conn, collectorAddr, testPool())
	time.Sleep(15 * time.Millisecond)
	tickWithEncoder(fe, time.Now(), SFlowEncoder{}, conn, collectorAddr, testPool())

	// Drain any datagrams produced. Look for the first one that actually
	// carries a flow_sample (as opposed to a counter-only tick).
	var samplingRate uint32
	for {
		pkt := receivePacket(ch)
		if pkt == nil {
			break
		}
		dg := decodeSFlow(t, pkt)
		if len(dg.Samples) > 0 && dg.Samples[0].Type == sflowSampleTypeFlow {
			samplingRate = dg.Samples[0].FlowSample.SamplingRate
			break
		}
	}
	want := uint32(profile.ConcurrentFlows * SyntheticSamplingRateMultiplier)
	if samplingRate != want {
		t.Errorf("sFlow flow_sample sampling_rate = %d, want %d (10 × ConcurrentFlows)", samplingRate, want)
	}
}

func TestSFlowCounterDatagramMTU(t *testing.T) {
	// A device with many interfaces can produce an if_counters payload that
	// would exceed the 1500-byte MTU in a single datagram. EncodeCounterDatagram
	// writes best-effort: it encodes as many records as fit and returns. The
	// FlowExporter.Tick sFlow code path then re-invokes with the remainder.
	// This test verifies the encoder never overruns the buffer and that the
	// resulting datagram parses cleanly.
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)

	// Create 32 if_counters records; each body is 88 bytes + 8-byte XDR
	// record header = 96 bytes, so 32 records ≈ 3072 bytes, well over 1500.
	recs := make([]CounterRecord, 32)
	for i := range recs {
		recs[i] = CounterRecord{
			Format: sflowCtrFmtGeneric,
			Body:   encodeIfCountersBody(uint32(i+1), 1_000_000_000, uint64(i)*1000, uint32(i), 0, 0, 0, 0, uint64(i)*2000, uint32(i)*2, 0, 0, 0, 0),
		}
	}

	n, err := enc.EncodeCounterDatagram(1, 1, 100, recs, buf)
	if err != nil {
		t.Fatalf("EncodeCounterDatagram error: %v", err)
	}
	if n > 1500 {
		t.Errorf("datagram size = %d, exceeds 1500-byte MTU", n)
	}
	dg := decodeSFlow(t, buf[:n])
	if dg.Header.NumSamples == 0 {
		t.Fatal("expected at least one sample in datagram")
	}
	if got := dg.Samples[0].CounterSmpl.NumRecords; got == 0 {
		t.Fatal("expected at least one counter record in sample")
	}
}

// TestSFlowCounterDatagramGroupsBySourceID verifies the PR #47 review fix for
// counter-sample source_id grouping: collectors such as OpenNMS Telemetryd key
// if_counters records by ds_index (ifIndex) and misattribute metrics when all
// records are packed into a single counters_sample with source_id=0. The
// encoder SHALL emit one counters_sample per distinct SourceID, so N per-
// interface records plus one device-wide record (SourceID=0) yield N+1
// samples in the datagram.
func TestSFlowCounterDatagramGroupsBySourceID(t *testing.T) {
	enc := SFlowEncoder{}
	buf := make([]byte, 1500)

	// Three interfaces (ifIndex 1, 2, 3) plus one device-wide processor
	// record. Expected: 4 counters_samples with source_id = 1, 2, 3, 0.
	recs := []CounterRecord{
		{
			Format:   sflowCtrFmtGeneric,
			SourceID: 1,
			Body:     encodeIfCountersBody(1, 1_000_000_000, 100, 1, 0, 0, 0, 0, 200, 2, 0, 0, 0, 0),
		},
		{
			Format:   sflowCtrFmtGeneric,
			SourceID: 2,
			Body:     encodeIfCountersBody(2, 1_000_000_000, 300, 3, 0, 0, 0, 0, 400, 4, 0, 0, 0, 0),
		},
		{
			Format:   sflowCtrFmtGeneric,
			SourceID: 3,
			Body:     encodeIfCountersBody(3, 1_000_000_000, 500, 5, 0, 0, 0, 0, 600, 6, 0, 0, 0, 0),
		},
		{
			Format:   sflowCtrFmtProcessor,
			SourceID: 0,
			Body:     make([]byte, 28), // processor_information fixed body
		},
	}

	n, err := enc.EncodeCounterDatagram(0x0A000001, 7, 1000, recs, buf)
	if err != nil {
		t.Fatalf("EncodeCounterDatagram error: %v", err)
	}
	dg := decodeSFlow(t, buf[:n])

	if got := int(dg.Header.NumSamples); got != 4 {
		t.Fatalf("num_samples = %d, want 4 (one per source_id, including device-wide)", got)
	}
	if len(dg.Samples) != 4 {
		t.Fatalf("decoded samples = %d, want 4", len(dg.Samples))
	}

	wantSourceIDs := []uint32{1, 2, 3, 0}
	for i, s := range dg.Samples {
		if s.Type != sflowSampleTypeCounters {
			t.Errorf("sample[%d] type = %d, want %d (counters_sample)", i, s.Type, sflowSampleTypeCounters)
			continue
		}
		if s.CounterSmpl == nil {
			t.Errorf("sample[%d] counter sample not decoded", i)
			continue
		}
		if s.CounterSmpl.SourceID != wantSourceIDs[i] {
			t.Errorf("sample[%d] source_id = %d, want %d", i, s.CounterSmpl.SourceID, wantSourceIDs[i])
		}
		if s.CounterSmpl.NumRecords != 1 {
			t.Errorf("sample[%d] num_counter_records = %d, want 1", i, s.CounterSmpl.NumRecords)
		}
	}
}

// TestSFlowInterfaceCounterSource_OneSamplePerIfIndex exercises the end-to-end
// path: InterfaceCounterSource produces one record per interface, and when
// those records are passed through EncodeCounterDatagram the output has one
// counters_sample per interface with source_id = ifIndex. This is the
// spec scenario "counters_sample source_id keyed by ds_index".
func TestSFlowInterfaceCounterSource_OneSamplePerIfIndex(t *testing.T) {
	const gbps = 1_000_000_000
	res := buildTestResources(t, []uint64{gbps, gbps, gbps})

	c := &MetricsCycler{}
	c.InitIfCounters(res, 9999)
	ic := c.ifCounters.Load()
	if ic == nil {
		t.Fatal("InitIfCounters did not create ifCounters")
	}

	adapter := NewInterfaceCounterSource(ic)
	recs := adapter.Snapshot(time.Now())
	if len(recs) != 3 {
		t.Fatalf("Snapshot returned %d records, want 3", len(recs))
	}

	// Each adapter-produced record must carry SourceID = ifIndex (1, 2, 3).
	gotIDs := map[uint32]bool{}
	for _, r := range recs {
		gotIDs[r.SourceID] = true
	}
	for want := uint32(1); want <= 3; want++ {
		if !gotIDs[want] {
			t.Errorf("adapter missing CounterRecord with SourceID=%d", want)
		}
	}

	enc := SFlowEncoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodeCounterDatagram(0x0A000001, 1, 1000, recs, buf)
	if err != nil {
		t.Fatalf("EncodeCounterDatagram error: %v", err)
	}
	dg := decodeSFlow(t, buf[:n])
	if got := int(dg.Header.NumSamples); got != 3 {
		t.Errorf("num_samples = %d, want 3 (one per ifIndex)", got)
	}
	// Every sample should be counters_sample with source_id matching an ifIndex.
	for i, s := range dg.Samples {
		if s.Type != sflowSampleTypeCounters {
			t.Errorf("sample[%d] type = %d, want %d", i, s.Type, sflowSampleTypeCounters)
			continue
		}
		if s.CounterSmpl.SourceID < 1 || s.CounterSmpl.SourceID > 3 {
			t.Errorf("sample[%d] source_id = %d, want in [1,3]", i, s.CounterSmpl.SourceID)
		}
	}
}
