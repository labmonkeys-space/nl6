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
)

// ── Inline NetFlow v9 decoder (test oracle) ──────────────────────────────────
//
// This minimal parser validates that EncodePacket produces correctly-structured
// RFC 3954 wire bytes without introducing any external test dependency.

type nf9PacketHeader struct {
	Version    uint16
	Count      uint16
	SysUptime  uint32
	UnixSecs   uint32
	SequenceNo uint32
	SourceID   uint32
}

type nf9TemplateField struct {
	FieldType   uint16
	FieldLength uint16
}

type nf9DecodedTemplate struct {
	TemplateID uint16
	Fields     []nf9TemplateField
}

type nf9DecodedRecord struct {
	Bytes     uint32
	Packets   uint32
	Protocol  uint8
	ToS       uint8
	TCPFlags  uint8
	SrcPort   uint16
	SrcIP     net.IP
	SrcMask   uint8
	InIface   uint16
	DstPort   uint16
	DstIP     net.IP
	DstMask   uint8
	OutIface  uint16
	NextHop   net.IP
	SrcAS     uint16
	DstAS     uint16
	LastSw    uint32
	FirstSw   uint32
}

type nf9Packet struct {
	Header    nf9PacketHeader
	Templates []nf9DecodedTemplate
	Records   []nf9DecodedRecord
}

// decodeNF9Packet parses the given bytes into a nf9Packet, returning an error
// string on any structural violation.
func decodeNF9Packet(t *testing.T, data []byte) *nf9Packet {
	t.Helper()
	if len(data) < nf9HeaderSize {
		t.Fatalf("packet too short: %d bytes", len(data))
	}

	pkt := &nf9Packet{}
	pkt.Header.Version    = binary.BigEndian.Uint16(data[0:])
	pkt.Header.Count      = binary.BigEndian.Uint16(data[2:])
	pkt.Header.SysUptime  = binary.BigEndian.Uint32(data[4:])
	pkt.Header.UnixSecs   = binary.BigEndian.Uint32(data[8:])
	pkt.Header.SequenceNo = binary.BigEndian.Uint32(data[12:])
	pkt.Header.SourceID   = binary.BigEndian.Uint32(data[16:])

	pos := nf9HeaderSize
	for pos < len(data) {
		if pos+4 > len(data) {
			break
		}
		fsID := binary.BigEndian.Uint16(data[pos:])
		fsLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		if fsLen < 4 || pos+fsLen > len(data) {
			t.Fatalf("invalid FlowSet length %d at offset %d", fsLen, pos)
		}
		fsData := data[pos : pos+fsLen]
		pos += fsLen

		switch {
		case fsID == 0: // Template FlowSet
			tmplPos := 4 // skip flowset header
			for tmplPos+4 <= len(fsData) {
				tmplID := binary.BigEndian.Uint16(fsData[tmplPos:])
				fieldCount := int(binary.BigEndian.Uint16(fsData[tmplPos+2:]))
				tmplPos += 4
				tmpl := nf9DecodedTemplate{TemplateID: tmplID}
				for i := 0; i < fieldCount && tmplPos+4 <= len(fsData); i++ {
					ft := binary.BigEndian.Uint16(fsData[tmplPos:])
					fl := binary.BigEndian.Uint16(fsData[tmplPos+2:])
					tmpl.Fields = append(tmpl.Fields, nf9TemplateField{ft, fl})
					tmplPos += 4
				}
				pkt.Templates = append(pkt.Templates, tmpl)
			}

		case fsID >= 256: // Data FlowSet
			recPos := 4 // skip flowset header
			for recPos+nf9RecordSize <= fsLen {
				r := nf9DecodedRecord{}
				r.Bytes    = binary.BigEndian.Uint32(fsData[recPos:])
				r.Packets  = binary.BigEndian.Uint32(fsData[recPos+4:])
				r.Protocol = fsData[recPos+8]
				r.ToS      = fsData[recPos+9]
				r.TCPFlags = fsData[recPos+10]
				r.SrcPort  = binary.BigEndian.Uint16(fsData[recPos+11:])
				r.SrcIP    = net.IP(append([]byte{}, fsData[recPos+13:recPos+17]...))
				r.SrcMask  = fsData[recPos+17]
				r.InIface  = binary.BigEndian.Uint16(fsData[recPos+18:])
				r.DstPort  = binary.BigEndian.Uint16(fsData[recPos+20:])
				r.DstIP    = net.IP(append([]byte{}, fsData[recPos+22:recPos+26]...))
				r.DstMask  = fsData[recPos+26]
				r.OutIface = binary.BigEndian.Uint16(fsData[recPos+27:])
				r.NextHop  = net.IP(append([]byte{}, fsData[recPos+29:recPos+33]...))
				r.SrcAS    = binary.BigEndian.Uint16(fsData[recPos+33:])
				r.DstAS    = binary.BigEndian.Uint16(fsData[recPos+35:])
				r.LastSw   = binary.BigEndian.Uint32(fsData[recPos+37:])
				r.FirstSw  = binary.BigEndian.Uint32(fsData[recPos+41:])
				pkt.Records = append(pkt.Records, r)
				recPos += nf9RecordSize
			}
		}
	}
	return pkt
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestNF9Template_BuildSize(t *testing.T) {
	if got := len(nf9TemplateBytes); got != nf9TemplFlowSetSize {
		t.Errorf("template size = %d, want %d", got, nf9TemplFlowSetSize)
	}
}

func TestNF9Template_FieldCount(t *testing.T) {
	if len(nf9Fields) != 18 {
		t.Errorf("expected 18 fields, got %d", len(nf9Fields))
	}
	// Sum of field lengths must equal nf9RecordSize.
	total := 0
	for _, f := range nf9Fields {
		total += int(f[1])
	}
	if total != nf9RecordSize {
		t.Errorf("sum of field lengths = %d, want %d (nf9RecordSize)", total, nf9RecordSize)
	}
}

func TestNF9EncodePacket_HeaderFields(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.1.1", "10.0.2.2", 50000, 443, 6)}

	n, err := enc.EncodePacket(0xC0A80101, 42, 5000, records, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	if n == 0 {
		t.Fatal("EncodePacket returned 0 bytes")
	}

	pkt := decodeNF9Packet(t, buf[:n])

	if pkt.Header.Version != 9 {
		t.Errorf("version = %d, want 9", pkt.Header.Version)
	}
	if pkt.Header.SequenceNo != 42 {
		t.Errorf("sequence = %d, want 42", pkt.Header.SequenceNo)
	}
	if pkt.Header.SysUptime != 5000 {
		t.Errorf("uptime = %d, want 5000", pkt.Header.SysUptime)
	}
	if pkt.Header.SourceID != 0xC0A80101 {
		t.Errorf("sourceID = %08x, want c0a80101", pkt.Header.SourceID)
	}
}

func TestNF9EncodePacket_WithTemplate(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.1.1", "10.0.2.2", 50001, 443, 6)}

	n, err := enc.EncodePacket(1, 1, 1000, records, true, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}

	pkt := decodeNF9Packet(t, buf[:n])

	if len(pkt.Templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(pkt.Templates))
	}
	tmpl := pkt.Templates[0]
	if tmpl.TemplateID != nf9TemplateID {
		t.Errorf("template ID = %d, want %d", tmpl.TemplateID, nf9TemplateID)
	}
	if len(tmpl.Fields) != 18 {
		t.Errorf("template field count = %d, want 18", len(tmpl.Fields))
	}
	// Verify first and last field IDs match the nf9Fields table.
	if tmpl.Fields[0].FieldType != nf9InBytes {
		t.Errorf("first field type = %d, want %d (IN_BYTES)", tmpl.Fields[0].FieldType, nf9InBytes)
	}
	if tmpl.Fields[17].FieldType != nf9FirstSwitched {
		t.Errorf("last field type = %d, want %d (FIRST_SWITCHED)", tmpl.Fields[17].FieldType, nf9FirstSwitched)
	}
}

func TestNF9EncodePacket_RecordValues(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf := make([]byte, 1500)

	src := net.ParseIP("192.168.1.10").To4()
	dst := net.ParseIP("10.20.30.40").To4()
	r := FlowRecord{
		SrcIP:    src,
		DstIP:    dst,
		NextHop:  net.IPv4(0, 0, 0, 0).To4(),
		SrcPort:  54321,
		DstPort:  443,
		Protocol: 6,
		TCPFlags: 0x18,
		ToS:      0,
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

	pkt := decodeNF9Packet(t, buf[:n])

	if len(pkt.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(pkt.Records))
	}
	got := pkt.Records[0]

	check := func(field string, got, want interface{}) {
		t.Helper()
		if got != want {
			t.Errorf("%s: got %v, want %v", field, got, want)
		}
	}

	check("Bytes",    got.Bytes,    uint32(9876))
	check("Packets",  got.Packets,  uint32(7))
	check("Protocol", got.Protocol, uint8(6))
	check("TCPFlags", got.TCPFlags, uint8(0x18))
	check("SrcPort",  got.SrcPort,  uint16(54321))
	check("DstPort",  got.DstPort,  uint16(443))
	check("InIface",  got.InIface,  uint16(3))
	check("OutIface", got.OutIface, uint16(4))
	check("SrcAS",    got.SrcAS,    uint16(65001))
	check("DstAS",    got.DstAS,    uint16(65002))
	check("SrcMask",  got.SrcMask,  uint8(24))
	check("DstMask",  got.DstMask,  uint8(16))
	check("FirstSw",  got.FirstSw,  uint32(1000))
	check("LastSw",   got.LastSw,   uint32(2500))

	if !got.SrcIP.Equal(src) {
		t.Errorf("SrcIP: got %v, want %v", got.SrcIP, src)
	}
	if !got.DstIP.Equal(dst) {
		t.Errorf("DstIP: got %v, want %v", got.DstIP, dst)
	}
}

func TestNF9EncodePacket_MultipleRecords(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{
		makeRecord("10.0.0.1", "10.0.0.2", 1001, 443, 6),
		makeRecord("10.0.0.3", "10.0.0.4", 1002, 80, 6),
		makeRecord("10.0.0.5", "10.0.0.6", 1003, 53, 17),
	}

	n, err := enc.EncodePacket(1, 5, 1000, records, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}

	pkt := decodeNF9Packet(t, buf[:n])
	if len(pkt.Records) != 3 {
		t.Errorf("expected 3 records, got %d", len(pkt.Records))
	}
	if pkt.Records[2].Protocol != 17 {
		t.Errorf("record[2] protocol = %d, want 17 (UDP)", pkt.Records[2].Protocol)
	}
}

func TestNF9EncodePacket_SequenceNumber(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 2000, 443, 6)}

	for seqNo := uint32(0); seqNo < 5; seqNo++ {
		n, err := enc.EncodePacket(1, seqNo, 1000, records, false, buf)
		if err != nil {
			t.Fatalf("seq %d: EncodePacket error: %v", seqNo, err)
		}
		pkt := decodeNF9Packet(t, buf[:n])
		if pkt.Header.SequenceNo != seqNo {
			t.Errorf("seq %d: decoded sequence = %d", seqNo, pkt.Header.SequenceNo)
		}
	}
}

func TestNF9EncodePacket_Count(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf := make([]byte, 1500)

	// Without template: count = number of data records.
	records := []FlowRecord{
		makeRecord("10.0.0.1", "10.0.0.2", 3001, 443, 6),
		makeRecord("10.0.0.3", "10.0.0.4", 3002, 80, 6),
	}
	n, _ := enc.EncodePacket(1, 1, 1000, records, false, buf)
	pkt := decodeNF9Packet(t, buf[:n])
	if pkt.Header.Count != 2 {
		t.Errorf("count without template = %d, want 2", pkt.Header.Count)
	}

	// With template: count = 1 (template) + data records.
	n, _ = enc.EncodePacket(1, 2, 1000, records, true, buf)
	pkt = decodeNF9Packet(t, buf[:n])
	if pkt.Header.Count != 3 {
		t.Errorf("count with template = %d, want 3", pkt.Header.Count)
	}
}

func TestNF9EncodePacket_Alignment(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf := make([]byte, 1500)
	// A single 45-byte record: data FlowSet body = 4+45 = 49 bytes, must pad to 52.
	records := []FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 4001, 443, 6)}
	n, err := enc.EncodePacket(1, 1, 1000, records, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	// Total = header(20) + data FlowSet padded(52) = 72 bytes, divisible by 4.
	if n%4 != 0 {
		t.Errorf("packet length %d is not 4-byte aligned", n)
	}
}

func TestNF9EncodePacket_EmptyRecordsTemplateOnly(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodePacket(1, 0, 0, nil, true, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	// Should produce header + template only.
	want := nf9HeaderSize + nf9TemplFlowSetSize
	if n != want {
		t.Errorf("template-only packet size = %d, want %d", n, want)
	}
}

func TestNF9EncodePacket_BufferTooSmall(t *testing.T) {
	enc := NetFlow9Encoder{}
	tiny := make([]byte, 10) // far too small
	_, err := enc.EncodePacket(1, 0, 0, []FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 5001, 443, 6)}, false, tiny)
	if err == nil {
		t.Error("expected error for too-small buffer, got nil")
	}
}

func TestNF9EncodePacket_DomainIDDistinguishesDevices(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 6001, 443, 6)}

	domainA := uint32(0x0A000001) // 10.0.0.1
	domainB := uint32(0x0A000002) // 10.0.0.2

	nA, _ := enc.EncodePacket(domainA, 1, 1000, records, false, buf)
	pktA := decodeNF9Packet(t, buf[:nA])

	nB, _ := enc.EncodePacket(domainB, 1, 1000, records, false, buf)
	pktB := decodeNF9Packet(t, buf[:nB])

	if pktA.Header.SourceID == pktB.Header.SourceID {
		t.Errorf("expected different SourceIDs (%08x vs %08x)", domainA, domainB)
	}
}
