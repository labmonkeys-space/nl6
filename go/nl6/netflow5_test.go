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
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// ── Inline NetFlow v5 decoder (test oracle) ──────────────────────────────────
//
// This minimal parser validates that NetFlow5Encoder.EncodePacket produces
// the correct Cisco-v5 wire bytes without introducing any external test
// dependency.

type netFlow5Header struct {
	Version          uint16
	Count            uint16
	SysUptime        uint32
	UnixSecs         uint32
	UnixNsecs        uint32
	FlowSequence     uint32
	EngineType       uint8
	EngineID         uint8
	SamplingInterval uint16
}

type netFlow5WireRecord struct {
	SrcAddr  net.IP
	DstAddr  net.IP
	NextHop  net.IP
	Input    uint16
	Output   uint16
	DPkts    uint32
	DOctets  uint32
	First    uint32
	Last     uint32
	SrcPort  uint16
	DstPort  uint16
	Pad1     uint8
	TCPFlags uint8
	Protocol uint8
	ToS      uint8
	SrcAS    uint16
	DstAS    uint16
	SrcMask  uint8
	DstMask  uint8
	Pad2     uint16
}

func decodeNetFlow5(t *testing.T, data []byte) (netFlow5Header, []netFlow5WireRecord) {
	t.Helper()
	if len(data) < netFlow5HeaderLen {
		t.Fatalf("netflow5: packet too short: %d bytes", len(data))
	}

	var h netFlow5Header
	h.Version = binary.BigEndian.Uint16(data[0:])
	h.Count = binary.BigEndian.Uint16(data[2:])
	h.SysUptime = binary.BigEndian.Uint32(data[4:])
	h.UnixSecs = binary.BigEndian.Uint32(data[8:])
	h.UnixNsecs = binary.BigEndian.Uint32(data[12:])
	h.FlowSequence = binary.BigEndian.Uint32(data[16:])
	h.EngineType = data[20]
	h.EngineID = data[21]
	h.SamplingInterval = binary.BigEndian.Uint16(data[22:])

	expected := netFlow5HeaderLen + int(h.Count)*netFlow5RecordLen
	if len(data) < expected {
		t.Fatalf("netflow5: packet length %d < expected %d (header count=%d)", len(data), expected, h.Count)
	}

	records := make([]netFlow5WireRecord, 0, h.Count)
	pos := netFlow5HeaderLen
	for i := uint16(0); i < h.Count; i++ {
		var r netFlow5WireRecord
		r.SrcAddr = net.IP(append([]byte{}, data[pos:pos+4]...))
		r.DstAddr = net.IP(append([]byte{}, data[pos+4:pos+8]...))
		r.NextHop = net.IP(append([]byte{}, data[pos+8:pos+12]...))
		r.Input = binary.BigEndian.Uint16(data[pos+12:])
		r.Output = binary.BigEndian.Uint16(data[pos+14:])
		r.DPkts = binary.BigEndian.Uint32(data[pos+16:])
		r.DOctets = binary.BigEndian.Uint32(data[pos+20:])
		r.First = binary.BigEndian.Uint32(data[pos+24:])
		r.Last = binary.BigEndian.Uint32(data[pos+28:])
		r.SrcPort = binary.BigEndian.Uint16(data[pos+32:])
		r.DstPort = binary.BigEndian.Uint16(data[pos+34:])
		r.Pad1 = data[pos+36]
		r.TCPFlags = data[pos+37]
		r.Protocol = data[pos+38]
		r.ToS = data[pos+39]
		r.SrcAS = binary.BigEndian.Uint16(data[pos+40:])
		r.DstAS = binary.BigEndian.Uint16(data[pos+42:])
		r.SrcMask = data[pos+44]
		r.DstMask = data[pos+45]
		r.Pad2 = binary.BigEndian.Uint16(data[pos+46:])
		records = append(records, r)
		pos += netFlow5RecordLen
	}
	return h, records
}

// captureLog redirects the standard logger to a buffer for the duration of fn
// and returns whatever was written. Used to assert one-shot warning behaviour.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	flags := log.Flags()
	prefix := log.Prefix()
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(orig)
		log.SetFlags(flags)
		log.SetPrefix(prefix)
	}()
	fn()
	return buf.String()
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestNetFlow5PacketSizes(t *testing.T) {
	enc := &NetFlow5Encoder{}
	base, tmpl, rec := enc.PacketSizes()
	if base != 24 || tmpl != 0 || rec != 48 {
		t.Errorf("PacketSizes() = (%d, %d, %d), want (24, 0, 48)", base, tmpl, rec)
	}
}

func TestNetFlow5Header(t *testing.T) {
	enc := &NetFlow5Encoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.1.1", "10.0.2.2", 50000, 443, 6)}

	beforeSecs := uint32(time.Now().Unix())
	n, err := enc.EncodePacket(0xC0A80101, 42, 5000, records, false, buf)
	afterSecs := uint32(time.Now().Unix())
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	if n != netFlow5HeaderLen+netFlow5RecordLen {
		t.Fatalf("bytes written = %d, want %d", n, netFlow5HeaderLen+netFlow5RecordLen)
	}

	h, recs := decodeNetFlow5(t, buf[:n])
	if h.Version != 5 {
		t.Errorf("version = %d, want 5", h.Version)
	}
	if h.Count != 1 {
		t.Errorf("count = %d, want 1", h.Count)
	}
	if h.SysUptime != 5000 {
		t.Errorf("sys_uptime = %d, want 5000", h.SysUptime)
	}
	if h.UnixSecs < beforeSecs-1 || h.UnixSecs > afterSecs+1 {
		t.Errorf("unix_secs %d outside [%d, %d]", h.UnixSecs, beforeSecs, afterSecs)
	}
	if h.UnixNsecs >= 1_000_000_000 {
		t.Errorf("unix_nsecs %d ≥ 1e9", h.UnixNsecs)
	}
	if h.FlowSequence != 42 {
		t.Errorf("flow_sequence = %d, want 42", h.FlowSequence)
	}
	if h.EngineType != 0 {
		t.Errorf("engine_type = %d, want 0", h.EngineType)
	}
	if h.EngineID != 0 {
		t.Errorf("engine_id = %d, want 0", h.EngineID)
	}
	if h.SamplingInterval != 0 {
		t.Errorf("sampling_interval = %d, want 0", h.SamplingInterval)
	}
	if len(recs) != 1 {
		t.Fatalf("decoded record count = %d, want 1", len(recs))
	}
}

func TestNetFlow5RecordRoundtrip(t *testing.T) {
	enc := &NetFlow5Encoder{}
	buf := make([]byte, 1500)

	src := net.ParseIP("192.168.1.10").To4()
	dst := net.ParseIP("10.20.30.40").To4()
	nh := net.ParseIP("172.16.0.1").To4()
	r := FlowRecord{
		SrcIP:    src,
		DstIP:    dst,
		NextHop:  nh,
		SrcPort:  54321,
		DstPort:  443,
		Protocol: 6,
		TCPFlags: 0x18,
		ToS:      0xB8,
		Bytes:    9876,
		Packets:  7,
		StartMs:  1000,
		EndMs:    2500,
		InIface:  3,
		OutIface: 4,
		SrcAS:    65001,
		DstAS:    65002,
		SrcMask:  24,
		DstMask:  16,
	}

	n, err := enc.EncodePacket(0xC0A8010A, 99, 3000, []FlowRecord{r}, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}

	_, recs := decodeNetFlow5(t, buf[:n])
	if len(recs) != 1 {
		t.Fatalf("decoded record count = %d, want 1", len(recs))
	}
	got := recs[0]

	check := func(field string, got, want interface{}) {
		t.Helper()
		if got != want {
			t.Errorf("%s: got %v, want %v", field, got, want)
		}
	}

	if !got.SrcAddr.Equal(src) {
		t.Errorf("srcaddr: got %v, want %v", got.SrcAddr, src)
	}
	if !got.DstAddr.Equal(dst) {
		t.Errorf("dstaddr: got %v, want %v", got.DstAddr, dst)
	}
	if !got.NextHop.Equal(nh) {
		t.Errorf("nexthop: got %v, want %v", got.NextHop, nh)
	}
	check("input", got.Input, uint16(3))
	check("output", got.Output, uint16(4))
	check("dPkts", got.DPkts, uint32(7))
	check("dOctets", got.DOctets, uint32(9876))
	check("first", got.First, uint32(1000))
	check("last", got.Last, uint32(2500))
	check("srcport", got.SrcPort, uint16(54321))
	check("dstport", got.DstPort, uint16(443))
	check("pad1", got.Pad1, uint8(0))
	check("tcp_flags", got.TCPFlags, uint8(0x18))
	check("prot", got.Protocol, uint8(6))
	check("tos", got.ToS, uint8(0xB8))
	check("src_as", got.SrcAS, uint16(65001))
	check("dst_as", got.DstAS, uint16(65002))
	check("src_mask", got.SrcMask, uint8(24))
	check("dst_mask", got.DstMask, uint8(16))
	check("pad2", got.Pad2, uint16(0))
}

func TestNetFlow5MultiPacketPagination(t *testing.T) {
	// Simulates the ticker behaviour: 45 records batched by the caller into
	// a 30-record call followed by a 15-record call, with seqNo advancing by
	// the record count of each packet.
	enc := &NetFlow5Encoder{}
	buf := make([]byte, 1500)

	records := make([]FlowRecord, 45)
	for i := range records {
		records[i] = makeRecord("10.0.0.1", "10.0.0.2", uint16(10000+i), 443, 6)
	}

	// First datagram: first 30 records, seqNo=100.
	n1, err := enc.EncodePacket(1, 100, 1000, records[:30], false, buf)
	if err != nil {
		t.Fatalf("packet 1 error: %v", err)
	}
	h1, recs1 := decodeNetFlow5(t, buf[:n1])
	if h1.Count != 30 {
		t.Errorf("packet 1 count = %d, want 30", h1.Count)
	}
	if len(recs1) != 30 {
		t.Errorf("packet 1 decoded records = %d, want 30", len(recs1))
	}
	if h1.FlowSequence != 100 {
		t.Errorf("packet 1 flow_sequence = %d, want 100", h1.FlowSequence)
	}

	// Second datagram: remaining 15 records, seqNo advanced by 30.
	buf2 := make([]byte, 1500)
	n2, err := enc.EncodePacket(1, 130, 1010, records[30:], false, buf2)
	if err != nil {
		t.Fatalf("packet 2 error: %v", err)
	}
	h2, recs2 := decodeNetFlow5(t, buf2[:n2])
	if h2.Count != 15 {
		t.Errorf("packet 2 count = %d, want 15", h2.Count)
	}
	if len(recs2) != 15 {
		t.Errorf("packet 2 decoded records = %d, want 15", len(recs2))
	}
	if h2.FlowSequence != 130 {
		t.Errorf("packet 2 flow_sequence = %d, want 130", h2.FlowSequence)
	}
}

func TestNetFlow5ThirtyRecordCap(t *testing.T) {
	enc := &NetFlow5Encoder{}
	buf := make([]byte, 1500)

	records := make([]FlowRecord, 31)
	for i := range records {
		records[i] = makeRecord("10.0.0.1", "10.0.0.2", uint16(20000+i), 443, 6)
	}

	n, err := enc.EncodePacket(1, 0, 1000, records, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	const wantBytes = 24 + 30*48
	if n != wantBytes {
		t.Errorf("bytes = %d, want %d", n, wantBytes)
	}
	h, recs := decodeNetFlow5(t, buf[:n])
	if h.Count != 30 {
		t.Errorf("count = %d, want 30", h.Count)
	}
	if len(recs) != 30 {
		t.Errorf("decoded records = %d, want 30", len(recs))
	}
}

func TestNetFlow5IPv4OnlyFiltering(t *testing.T) {
	enc := &NetFlow5Encoder{}
	buf := make([]byte, 1500)

	v6Src := FlowRecord{
		SrcIP:   net.ParseIP("2001:db8::1"),
		DstIP:   net.ParseIP("10.0.0.2").To4(),
		NextHop: net.IPv4(0, 0, 0, 0).To4(),
		SrcPort: 1000, DstPort: 443, Protocol: 6,
		Bytes: 100, Packets: 1,
		StartMs: 500, EndMs: 600,
		InIface: 1, OutIface: 2, SrcMask: 24, DstMask: 24,
	}
	v4 := makeRecord("10.0.0.1", "10.0.0.2", 2000, 443, 6)
	v6Dst := FlowRecord{
		SrcIP:   net.ParseIP("10.0.0.1").To4(),
		DstIP:   net.ParseIP("2001:db8::2"),
		NextHop: net.IPv4(0, 0, 0, 0).To4(),
		SrcPort: 3000, DstPort: 80, Protocol: 6,
		Bytes: 200, Packets: 2,
		StartMs: 700, EndMs: 800,
		InIface: 1, OutIface: 2, SrcMask: 24, DstMask: 24,
	}

	var n int
	var err error
	logs := captureLog(t, func() {
		n, err = enc.EncodePacket(0x0A000001, 1, 1000, []FlowRecord{v6Src, v4, v6Dst}, false, buf)
	})
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}

	h, recs := decodeNetFlow5(t, buf[:n])
	if h.Count != 1 {
		t.Errorf("count = %d, want 1 (IPv6 records filtered)", h.Count)
	}
	if len(recs) != 1 {
		t.Fatalf("decoded records = %d, want 1", len(recs))
	}
	if recs[0].SrcPort != 2000 {
		t.Errorf("surviving record srcport = %d, want 2000", recs[0].SrcPort)
	}

	// One-shot warning log: exactly one netflow5-prefixed "skipping" line.
	// The encoder is shared across the whole simulator, so the warning is
	// deliberately fleet-wide and does NOT name a specific device (that
	// would just be whoever lost the CAS race on the first IPv6 record).
	warnCount := strings.Count(logs, "netflow5: skipping non-IPv4")
	if warnCount != 1 {
		t.Errorf("expected exactly 1 netflow5 warning log, got %d (logs=%q)", warnCount, logs)
	}
	if strings.Contains(logs, "device ") {
		t.Errorf("warning log should not include a device identity, got %q", logs)
	}

	// A second call with another IPv6 record must NOT emit another warning
	// (fleet-wide one-shot — the encoder's atomic.Bool is sticky).
	logs2 := captureLog(t, func() {
		_, _ = enc.EncodePacket(0x0A000001, 2, 2000, []FlowRecord{v6Src, v4}, false, buf)
	})
	if strings.Contains(logs2, "netflow5:") {
		t.Errorf("expected no additional warnings on second call, got %q", logs2)
	}
}

func TestNetFlow5NextHopCoercion(t *testing.T) {
	enc := &NetFlow5Encoder{}
	buf := make([]byte, 1500)

	r := FlowRecord{
		SrcIP:   net.ParseIP("10.0.0.1").To4(),
		DstIP:   net.ParseIP("10.0.0.2").To4(),
		NextHop: net.ParseIP("2001:db8::feed"), // IPv6 nexthop
		SrcPort: 1000, DstPort: 443, Protocol: 6,
		Bytes: 100, Packets: 1,
		StartMs: 500, EndMs: 600,
		InIface: 1, OutIface: 2, SrcMask: 24, DstMask: 24,
	}

	n, err := enc.EncodePacket(1, 0, 1000, []FlowRecord{r}, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	h, recs := decodeNetFlow5(t, buf[:n])
	if h.Count != 1 {
		t.Fatalf("count = %d, want 1 (record should be encoded, not skipped)", h.Count)
	}
	if !recs[0].NextHop.Equal(net.IPv4(0, 0, 0, 0).To4()) {
		t.Errorf("nexthop = %v, want 0.0.0.0", recs[0].NextHop)
	}
}

func TestNetFlow5TemplateFlagIgnored(t *testing.T) {
	enc := &NetFlow5Encoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 1000, 443, 6)}

	n, err := enc.EncodePacket(1, 1, 1000, records, true, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	if n != netFlow5HeaderLen+netFlow5RecordLen {
		t.Errorf("bytes = %d, want %d (no template should be prepended)",
			n, netFlow5HeaderLen+netFlow5RecordLen)
	}
	h, _ := decodeNetFlow5(t, buf[:n])
	if h.Count != 1 {
		t.Errorf("count = %d, want 1", h.Count)
	}
}

// TestNetFlow5ASNClamp exercises the clamp branch directly. FlowRecord.SrcAS
// is uint16 today, so we call the clampASN method with a 32-bit value to
// verify the wire value and the one-shot log. If the schema is ever widened
// to uint32, swap this for a full EncodePacket round-trip with SrcAS set to
// 0x00100000 on the FlowRecord.
//
// The expected clamp value is AS_TRANS (23456 / 0x5BA0) per RFC 6793 §2, NOT
// 0xFFFF — 0xFFFF is a reserved ASN but is not AS_TRANS and has different
// meaning on the wire to compliant collectors.
func TestNetFlow5ASNClamp(t *testing.T) {
	enc := &NetFlow5Encoder{}

	// uint16 values should pass through unchanged and not log.
	logs := captureLog(t, func() {
		if got := enc.clampASN(65001); got != 65001 {
			t.Errorf("clampASN(65001) = %d, want 65001", got)
		}
	})
	if strings.Contains(logs, "clamping") {
		t.Errorf("unexpected clamp log for in-range ASN: %q", logs)
	}

	// First 32-bit overflow clamps to AS_TRANS (23456) and emits exactly one log.
	logs = captureLog(t, func() {
		if got := enc.clampASN(0x00100000); got != 23456 {
			t.Errorf("clampASN(0x00100000) = %d, want 23456 (AS_TRANS)", got)
		}
	})
	warnCount := strings.Count(logs, "clamping 32-bit ASN")
	if warnCount != 1 {
		t.Errorf("expected exactly 1 clamp warning, got %d (logs=%q)", warnCount, logs)
	}

	// Subsequent overflows clamp but do NOT log again.
	logs = captureLog(t, func() {
		if got := enc.clampASN(0x00200000); got != 23456 {
			t.Errorf("clampASN(0x00200000) = %d, want 23456 (AS_TRANS)", got)
		}
	})
	if strings.Contains(logs, "clamping") {
		t.Errorf("expected no additional clamp warning, got %q", logs)
	}
}

func TestNetFlow5EmptyRecordsReturnsZero(t *testing.T) {
	enc := &NetFlow5Encoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodePacket(1, 0, 0, nil, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	if n != 0 {
		t.Errorf("empty call = %d bytes, want 0 (no header-only datagram for v5)", n)
	}
}

func TestNetFlow5BufferTooSmall(t *testing.T) {
	enc := &NetFlow5Encoder{}
	tiny := make([]byte, 10)
	_, err := enc.EncodePacket(1, 0, 0,
		[]FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 5001, 443, 6)}, false, tiny)
	if err == nil {
		t.Error("expected error for too-small buffer, got nil")
	}
}

// TestNetFlow5SeqIncrement locks in the per-protocol flow_sequence semantics
// expected by FlowExporter.Tick: NetFlow v5 advances by the packet's record
// count (Cisco "sequence counter of total flows seen"), NetFlow v9 and IPFIX
// advance by 1 per packet. A regression here would cause Tick to emit wrong
// flow_sequence values under one protocol once >1 records-per-packet occur.
func TestNetFlow5SeqIncrement(t *testing.T) {
	nf5 := &NetFlow5Encoder{}
	if got := nf5.SeqIncrement(30); got != 30 {
		t.Errorf("NetFlow5.SeqIncrement(30) = %d, want 30 (record-count semantics)", got)
	}
	if got := nf5.SeqIncrement(0); got != 0 {
		t.Errorf("NetFlow5.SeqIncrement(0) = %d, want 0", got)
	}

	var nf9 NetFlow9Encoder
	if got := nf9.SeqIncrement(30); got != 1 {
		t.Errorf("NetFlow9.SeqIncrement(30) = %d, want 1 (per-packet semantics)", got)
	}

	var ipfix IPFIXEncoder
	if got := ipfix.SeqIncrement(30); got != 1 {
		t.Errorf("IPFIX.SeqIncrement(30) = %d, want 1 (per-message semantics)", got)
	}
}

// TestNetFlow5GoldenBytes pins one fully-specified FlowRecord against a
// hand-constructed 72-byte expected payload (24-byte header + 48-byte record).
// This is the independent oracle that a mirrored decoder in the same file
// cannot provide — a 2-byte offset error in pad2 would round-trip cleanly
// through decodeNetFlow5 but would diverge here.
//
// Header timestamp fields (unix_secs / unix_nsecs) are deliberately NOT
// compared — they come from time.Now() inside EncodePacket. Everything else
// is fixed by the inputs.
func TestNetFlow5GoldenBytes(t *testing.T) {
	enc := &NetFlow5Encoder{}
	buf := make([]byte, netFlow5HeaderLen+netFlow5RecordLen)

	r := FlowRecord{
		SrcIP:    net.ParseIP("192.168.1.10").To4(),
		DstIP:    net.ParseIP("10.20.30.40").To4(),
		NextHop:  net.ParseIP("172.16.0.1").To4(),
		SrcPort:  54321,
		DstPort:  443,
		Protocol: 6,
		TCPFlags: 0x18,
		ToS:      0xB8,
		Bytes:    9876,
		Packets:  7,
		StartMs:  1000,
		EndMs:    2500,
		InIface:  3,
		OutIface: 4,
		SrcAS:    65001,
		DstAS:    65002,
		SrcMask:  24,
		DstMask:  16,
	}

	n, err := enc.EncodePacket(0xC0A8010A, 0xDEADBEEF, 0x000003E8, []FlowRecord{r}, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	if n != 72 {
		t.Fatalf("wrote %d bytes, want 72", n)
	}

	// Expected header (24 bytes). unix_secs (bytes 8:12) and unix_nsecs
	// (bytes 12:16) are zero in the expected slice and masked out of the
	// comparison below.
	expected := []byte{
		// version=5, count=1
		0x00, 0x05, 0x00, 0x01,
		// sys_uptime = 1000
		0x00, 0x00, 0x03, 0xE8,
		// unix_secs (placeholder — masked before compare)
		0x00, 0x00, 0x00, 0x00,
		// unix_nsecs (placeholder — masked before compare)
		0x00, 0x00, 0x00, 0x00,
		// flow_sequence = 0xDEADBEEF
		0xDE, 0xAD, 0xBE, 0xEF,
		// engine_type, engine_id
		0x00, 0x00,
		// sampling_interval
		0x00, 0x00,

		// Record (48 bytes).
		// srcaddr 192.168.1.10
		0xC0, 0xA8, 0x01, 0x0A,
		// dstaddr 10.20.30.40
		0x0A, 0x14, 0x1E, 0x28,
		// nexthop 172.16.0.1
		0xAC, 0x10, 0x00, 0x01,
		// input ifIndex = 3
		0x00, 0x03,
		// output ifIndex = 4
		0x00, 0x04,
		// dPkts = 7
		0x00, 0x00, 0x00, 0x07,
		// dOctets = 9876
		0x00, 0x00, 0x26, 0x94,
		// first = 1000
		0x00, 0x00, 0x03, 0xE8,
		// last = 2500
		0x00, 0x00, 0x09, 0xC4,
		// srcport = 54321
		0xD4, 0x31,
		// dstport = 443
		0x01, 0xBB,
		// pad1, tcp_flags=0x18, prot=6, tos=0xB8
		0x00, 0x18, 0x06, 0xB8,
		// src_as = 65001 (0xFDE9), dst_as = 65002 (0xFDEA)
		0xFD, 0xE9, 0xFD, 0xEA,
		// src_mask=24, dst_mask=16
		0x18, 0x10,
		// pad2
		0x00, 0x00,
	}

	// Mask the two timestamp fields before comparison.
	got := make([]byte, len(buf))
	copy(got, buf)
	for i := 8; i < 16; i++ {
		got[i] = 0
	}

	if !bytes.Equal(got, expected) {
		t.Errorf("golden-bytes mismatch\ngot:  % X\nwant: % X", got, expected)
	}
}

// TestNetFlow5Tick_FlowSequenceCumulative drives FlowExporter.Tick end-to-end
// with the NetFlow v5 encoder and asserts flow_sequence on each emitted
// datagram matches the cumulative record count. This is the integration
// anchor for the SeqIncrement contract: if Tick ever reverts to `fe.seqNo++`
// the first multi-packet tick breaks this test.
func TestNetFlow5Tick_FlowSequenceCumulative(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()

	conn := testSender(t)
	defer conn.Close()

	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	// Large MaxFlows so 80 records fit; short timeouts so everything expires.
	profile := &FlowProfile{
		TCPWeight: 1.0, UDPWeight: 0, ICMPWeight: 0,
		DstPorts:   []PortWeight{{443, 1.0}},
		SrcPortMin: 1024, SrcPortMax: 65535,
		BytesMin: 100, BytesMax: 200,
		PktsMin: 1, PktsMax: 2,
		DurationMinMs: 100, DurationMaxMs: 200,
		ConcurrentFlows: 100,
		MaxFlows:        256,
	}

	fe := newTestFlowExporter(testDevice("10.5.6.7"), profile,
		1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)

	// Insert 80 pre-expired IPv4 flows.
	past := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 80; i++ {
		fe.cache.Add(FlowRecord{
			SrcIP:    net.ParseIP("10.0.0.1").To4(),
			DstIP:    net.ParseIP("10.0.0.2").To4(),
			NextHop:  net.IPv4(0, 0, 0, 0).To4(),
			SrcPort:  uint16(1024 + i),
			DstPort:  443,
			Protocol: 6,
			Bytes:    100,
			Packets:  1,
		}, past)
	}

	enc := &NetFlow5Encoder{}
	tickWithEncoder(fe, time.Now(), enc, conn, collectorAddr, testPool())

	// Collect all packets emitted by this single Tick.
	var packets [][]byte
	for {
		pkt := receivePacket(ch)
		if pkt == nil {
			break
		}
		packets = append(packets, pkt)
	}

	// 80 records / 30 per packet = 3 packets (30 + 30 + 20).
	if len(packets) < 2 {
		t.Fatalf("expected multiple packets for 80 records, got %d", len(packets))
	}

	// Verify each packet's flow_sequence equals the cumulative record count
	// BEFORE that packet — i.e. pkt[0].seq=0, pkt[1].seq=count(pkt[0]),
	// pkt[2].seq=count(pkt[0])+count(pkt[1]), …
	var cumulative uint32
	totalRecords := 0
	for i, pkt := range packets {
		h, recs := decodeNetFlow5(t, pkt)
		if h.FlowSequence != cumulative {
			t.Errorf("packet %d: flow_sequence = %d, want %d (cumulative record count)",
				i, h.FlowSequence, cumulative)
		}
		cumulative += uint32(len(recs))
		totalRecords += len(recs)
	}
	if totalRecords != 80 {
		t.Errorf("total records across packets = %d, want 80", totalRecords)
	}

	// After Tick completes, fe.seqNo must equal the cumulative count.
	if fe.seqNo != cumulative {
		t.Errorf("fe.seqNo after Tick = %d, want %d (cumulative count)", fe.seqNo, cumulative)
	}
}
