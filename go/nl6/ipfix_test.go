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

// ── Inline IPFIX decoder (test oracle) ──────────────────────────────────────
//
// This minimal parser validates that IPFIXEncoder.EncodePacket produces
// correctly-structured RFC 7011 wire bytes without introducing any external
// test dependency.

type ipfixMsgHeader struct {
	Version          uint16
	Length           uint16
	ExportTime       uint32
	SequenceNumber   uint32
	ObsDomainID      uint32
}

type ipfixTemplateField struct {
	IEID     uint16
	IELength uint16
}

type ipfixDecodedTemplate struct {
	TemplateID uint16
	Fields     []ipfixTemplateField
}

type ipfixDecodedRecord struct {
	Bytes    uint32
	Packets  uint32
	Protocol uint8
	ToS      uint8
	TCPFlags uint8
	SrcPort  uint16
	SrcIP    net.IP
	SrcMask  uint8
	InIface  uint16
	DstPort  uint16
	DstIP    net.IP
	DstMask  uint8
	OutIface uint16
	NextHop  net.IP
	SrcAS    uint16
	DstAS    uint16
	StartMs  uint64 // absolute epoch ms
	EndMs    uint64 // absolute epoch ms
}

type ipfixPacket struct {
	Header    ipfixMsgHeader
	Templates []ipfixDecodedTemplate
	Records   []ipfixDecodedRecord
}

// decodeIPFIXPacket parses the given bytes into an ipfixPacket using only the
// single 18-field template defined in ipfixFields.
func decodeIPFIXPacket(t *testing.T, data []byte) *ipfixPacket {
	t.Helper()
	if len(data) < ipfixHeaderSize {
		t.Fatalf("ipfix: packet too short: %d bytes", len(data))
	}

	pkt := &ipfixPacket{}
	pkt.Header.Version        = binary.BigEndian.Uint16(data[0:])
	pkt.Header.Length         = binary.BigEndian.Uint16(data[2:])
	pkt.Header.ExportTime     = binary.BigEndian.Uint32(data[4:])
	pkt.Header.SequenceNumber = binary.BigEndian.Uint32(data[8:])
	pkt.Header.ObsDomainID    = binary.BigEndian.Uint32(data[12:])

	pos := ipfixHeaderSize
	for pos < len(data) {
		if pos+4 > len(data) {
			break
		}
		setID  := binary.BigEndian.Uint16(data[pos:])
		setLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		if setLen < 4 || pos+setLen > len(data) {
			t.Fatalf("ipfix: invalid Set length %d at offset %d", setLen, pos)
		}
		setData := data[pos : pos+setLen]
		pos += setLen

		switch {
		case setID == ipfixSetIDTemplate: // Template Set
			tmplPos := 4 // skip Set header
			for tmplPos+4 <= len(setData) {
				tmplID     := binary.BigEndian.Uint16(setData[tmplPos:])
				fieldCount := int(binary.BigEndian.Uint16(setData[tmplPos+2:]))
				tmplPos += 4
				tmpl := ipfixDecodedTemplate{TemplateID: tmplID}
				for i := 0; i < fieldCount && tmplPos+4 <= len(setData); i++ {
					ieID  := binary.BigEndian.Uint16(setData[tmplPos:])
					ieLen := binary.BigEndian.Uint16(setData[tmplPos+2:])
					tmpl.Fields = append(tmpl.Fields, ipfixTemplateField{ieID, ieLen})
					tmplPos += 4
				}
				pkt.Templates = append(pkt.Templates, tmpl)
			}

		case setID >= 256: // Data Set
			recPos := 4 // skip Set header
			for recPos+ipfixRecordSize <= setLen {
				r := ipfixDecodedRecord{}
				r.Bytes    = binary.BigEndian.Uint32(setData[recPos:])
				r.Packets  = binary.BigEndian.Uint32(setData[recPos+4:])
				r.Protocol = setData[recPos+8]
				r.ToS      = setData[recPos+9]
				r.TCPFlags = setData[recPos+10]
				r.SrcPort  = binary.BigEndian.Uint16(setData[recPos+11:])
				r.SrcIP    = net.IP(append([]byte{}, setData[recPos+13:recPos+17]...))
				r.SrcMask  = setData[recPos+17]
				r.InIface  = binary.BigEndian.Uint16(setData[recPos+18:])
				r.DstPort  = binary.BigEndian.Uint16(setData[recPos+20:])
				r.DstIP    = net.IP(append([]byte{}, setData[recPos+22:recPos+26]...))
				r.DstMask  = setData[recPos+26]
				r.OutIface = binary.BigEndian.Uint16(setData[recPos+27:])
				r.NextHop  = net.IP(append([]byte{}, setData[recPos+29:recPos+33]...))
				r.SrcAS    = binary.BigEndian.Uint16(setData[recPos+33:])
				r.DstAS    = binary.BigEndian.Uint16(setData[recPos+35:])
				r.StartMs  = binary.BigEndian.Uint64(setData[recPos+37:])
				r.EndMs    = binary.BigEndian.Uint64(setData[recPos+45:])
				pkt.Records = append(pkt.Records, r)
				recPos += ipfixRecordSize
			}
		}
	}
	return pkt
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestIPFIXTemplate_BuildSize(t *testing.T) {
	if got := len(ipfixTemplateSetBytes); got != ipfixTemplSetSize {
		t.Errorf("template set size = %d, want %d", got, ipfixTemplSetSize)
	}
}

func TestIPFIXTemplate_FieldCount(t *testing.T) {
	if len(ipfixFields) != 18 {
		t.Errorf("expected 18 fields, got %d", len(ipfixFields))
	}
	// Sum of field lengths must equal ipfixRecordSize.
	total := 0
	for _, f := range ipfixFields {
		total += int(f[1])
	}
	if total != ipfixRecordSize {
		t.Errorf("sum of IE lengths = %d, want %d (ipfixRecordSize)", total, ipfixRecordSize)
	}
}

func TestIPFIXEncodePacket_HeaderFields(t *testing.T) {
	enc := IPFIXEncoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.1.1", "10.0.2.2", 50000, 443, 6)}

	n, err := enc.EncodePacket(0xC0A80101, 42, 5000, records, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	if n == 0 {
		t.Fatal("EncodePacket returned 0 bytes")
	}

	pkt := decodeIPFIXPacket(t, buf[:n])

	if pkt.Header.Version != 10 {
		t.Errorf("version = %d, want 10", pkt.Header.Version)
	}
	if pkt.Header.SequenceNumber != 42 {
		t.Errorf("sequence = %d, want 42", pkt.Header.SequenceNumber)
	}
	if pkt.Header.ObsDomainID != 0xC0A80101 {
		t.Errorf("observationDomainID = %08x, want c0a80101", pkt.Header.ObsDomainID)
	}
	// Length must equal n.
	if int(pkt.Header.Length) != n {
		t.Errorf("message length field = %d, want %d", pkt.Header.Length, n)
	}
	// Export time must be a recent unix timestamp (within ±5 seconds of now).
	nowSecs := uint32(time.Now().Unix())
	if pkt.Header.ExportTime < nowSecs-5 || pkt.Header.ExportTime > nowSecs+5 {
		t.Errorf("export time %d is not close to current unix_secs %d", pkt.Header.ExportTime, nowSecs)
	}
}

func TestIPFIXEncodePacket_WithTemplate(t *testing.T) {
	enc := IPFIXEncoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.1.1", "10.0.2.2", 50001, 443, 6)}

	n, err := enc.EncodePacket(1, 1, 1000, records, true, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}

	pkt := decodeIPFIXPacket(t, buf[:n])

	if len(pkt.Templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(pkt.Templates))
	}
	tmpl := pkt.Templates[0]
	if tmpl.TemplateID != ipfixTemplateID {
		t.Errorf("template ID = %d, want %d", tmpl.TemplateID, ipfixTemplateID)
	}
	if len(tmpl.Fields) != 18 {
		t.Errorf("template field count = %d, want 18", len(tmpl.Fields))
	}
	// Verify first and last IE IDs.
	if tmpl.Fields[0].IEID != ipfixOctetDeltaCount {
		t.Errorf("first IE ID = %d, want %d (octetDeltaCount)", tmpl.Fields[0].IEID, ipfixOctetDeltaCount)
	}
	if tmpl.Fields[17].IEID != ipfixFlowEndMilliseconds {
		t.Errorf("last IE ID = %d, want %d (flowEndMilliseconds)", tmpl.Fields[17].IEID, ipfixFlowEndMilliseconds)
	}
}

func TestIPFIXEncodePacket_SetID(t *testing.T) {
	enc := IPFIXEncoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodePacket(1, 0, 0, nil, true, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	// First Set after the 16-byte header must be a Template Set (ID=2).
	if len(buf[:n]) < ipfixHeaderSize+2 {
		t.Fatal("packet too short to read first Set ID")
	}
	setID := binary.BigEndian.Uint16(buf[ipfixHeaderSize:])
	if setID != ipfixSetIDTemplate {
		t.Errorf("first Set ID = %d, want %d (Template Set)", setID, ipfixSetIDTemplate)
	}
}

func TestIPFIXEncodePacket_RecordValues(t *testing.T) {
	enc := IPFIXEncoder{}
	buf := make([]byte, 1500)

	src := net.ParseIP("192.168.1.10").To4()
	dst := net.ParseIP("10.20.30.40").To4()
	const uptimeMs = uint32(60000) // 60 seconds of simulated uptime
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

	n, err := enc.EncodePacket(0xC0A8010A, 99, uptimeMs, []FlowRecord{r}, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}

	pkt := decodeIPFIXPacket(t, buf[:n])

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

	if !got.SrcIP.Equal(src) {
		t.Errorf("SrcIP: got %v, want %v", got.SrcIP, src)
	}
	if !got.DstIP.Equal(dst) {
		t.Errorf("DstIP: got %v, want %v", got.DstIP, dst)
	}
}

func TestIPFIXEncodePacket_AbsoluteTimestamps(t *testing.T) {
	enc := IPFIXEncoder{}
	buf := make([]byte, 1500)

	const uptimeMs = uint32(30000) // 30 seconds of simulated uptime
	r := FlowRecord{
		SrcIP:    net.ParseIP("10.0.0.1").To4(),
		DstIP:    net.ParseIP("10.0.0.2").To4(),
		NextHop:  net.IPv4(0, 0, 0, 0).To4(),
		SrcPort:  1000, DstPort: 443, Protocol: 6,
		Bytes: 500, Packets: 5,
		StartMs: 1000,  // 1000 ms after device start
		EndMs:   5000,  // 5000 ms after device start
	}

	beforeMs := time.Now().UnixMilli()
	n, err := enc.EncodePacket(1, 0, uptimeMs, []FlowRecord{r}, false, buf)
	afterMs := time.Now().UnixMilli()

	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}

	pkt := decodeIPFIXPacket(t, buf[:n])
	if len(pkt.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(pkt.Records))
	}
	rec := pkt.Records[0]

	// Compute expected epoch range for flowStartMilliseconds.
	// deviceStartMs = [beforeMs..afterMs] - uptimeMs
	// flowStartMs   = deviceStartMs + r.StartMs
	loStart := uint64(beforeMs-int64(uptimeMs)) + uint64(r.StartMs)
	hiStart := uint64(afterMs-int64(uptimeMs)) + uint64(r.StartMs)
	if rec.StartMs < loStart || rec.StartMs > hiStart {
		t.Errorf("flowStartMilliseconds %d outside expected range [%d, %d]",
			rec.StartMs, loStart, hiStart)
	}

	loEnd := uint64(beforeMs-int64(uptimeMs)) + uint64(r.EndMs)
	hiEnd := uint64(afterMs-int64(uptimeMs)) + uint64(r.EndMs)
	if rec.EndMs < loEnd || rec.EndMs > hiEnd {
		t.Errorf("flowEndMilliseconds %d outside expected range [%d, %d]",
			rec.EndMs, loEnd, hiEnd)
	}

	// Sanity check: timestamps must be in year 2020+ (epoch ms > 1.58×10¹²)
	const year2020Ms = uint64(1577836800000)
	if rec.StartMs < year2020Ms {
		t.Errorf("flowStartMilliseconds %d predates 2020-01-01 — looks like relative uptime, not absolute epoch", rec.StartMs)
	}
	if rec.EndMs <= rec.StartMs {
		t.Errorf("flowEndMilliseconds %d ≤ flowStartMilliseconds %d", rec.EndMs, rec.StartMs)
	}
}

func TestIPFIXEncodePacket_MultipleRecords(t *testing.T) {
	enc := IPFIXEncoder{}
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

	pkt := decodeIPFIXPacket(t, buf[:n])
	if len(pkt.Records) != 3 {
		t.Errorf("expected 3 records, got %d", len(pkt.Records))
	}
	if pkt.Records[2].Protocol != 17 {
		t.Errorf("record[2] protocol = %d, want 17 (UDP)", pkt.Records[2].Protocol)
	}
}

func TestIPFIXEncodePacket_Alignment(t *testing.T) {
	enc := IPFIXEncoder{}
	buf := make([]byte, 1500)
	// A single 53-byte record: data Set body = 4+53 = 57 bytes, must pad to 60.
	records := []FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 4001, 443, 6)}
	n, err := enc.EncodePacket(1, 1, 1000, records, false, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	if n%4 != 0 {
		t.Errorf("packet length %d is not 4-byte aligned", n)
	}
}

func TestIPFIXEncodePacket_EmptyRecordsTemplateOnly(t *testing.T) {
	enc := IPFIXEncoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodePacket(1, 0, 0, nil, true, buf)
	if err != nil {
		t.Fatalf("EncodePacket error: %v", err)
	}
	// Should produce header + template set only.
	want := ipfixHeaderSize + ipfixTemplSetSize
	if n != want {
		t.Errorf("template-only packet size = %d, want %d", n, want)
	}
}

func TestIPFIXEncodePacket_BufferTooSmall(t *testing.T) {
	enc := IPFIXEncoder{}
	tiny := make([]byte, 10)
	_, err := enc.EncodePacket(1, 0, 0, []FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 5001, 443, 6)}, false, tiny)
	if err == nil {
		t.Error("expected error for too-small buffer, got nil")
	}
}

func TestIPFIXEncodePacket_DomainIDDistinguishesDevices(t *testing.T) {
	enc := IPFIXEncoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{makeRecord("10.0.0.1", "10.0.0.2", 6001, 443, 6)}

	domainA := uint32(0x0A000001) // 10.0.0.1
	domainB := uint32(0x0A000002) // 10.0.0.2

	nA, _ := enc.EncodePacket(domainA, 1, 1000, records, false, buf)
	pktA := decodeIPFIXPacket(t, buf[:nA])

	nB, _ := enc.EncodePacket(domainB, 1, 1000, records, false, buf)
	pktB := decodeIPFIXPacket(t, buf[:nB])

	if pktA.Header.ObsDomainID == pktB.Header.ObsDomainID {
		t.Errorf("expected different ObservationDomainIDs (%08x vs %08x)", domainA, domainB)
	}
}

func TestIPFIXEncodePacket_LengthFieldMatchesPayload(t *testing.T) {
	enc := IPFIXEncoder{}
	buf := make([]byte, 1500)
	records := []FlowRecord{
		makeRecord("10.0.0.1", "10.0.0.2", 1001, 443, 6),
		makeRecord("10.0.0.3", "10.0.0.4", 1002, 80, 6),
	}

	for _, includeTempl := range []bool{false, true} {
		n, err := enc.EncodePacket(1, 1, 1000, records, includeTempl, buf)
		if err != nil {
			t.Fatalf("EncodePacket error: %v", err)
		}
		msgLen := int(binary.BigEndian.Uint16(buf[2:]))
		if msgLen != n {
			t.Errorf("includeTemplate=%v: Length field %d != actual bytes %d", includeTempl, msgLen, n)
		}
	}
}
