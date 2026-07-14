/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// ── Options-datagram test oracle ─────────────────────────────────────────────
//
// The nf9/ipfix flow-packet decoders in netflow9_test.go / ipfix_test.go
// assume data FlowSets carry 18-field flow records, so options datagrams get
// their own minimal decoder mirroring how a collector parses them: options
// template (scope + option field specifiers) first, then fixed-size option
// data records interpreted through that template.

type optTemplateField struct {
	Type   uint16
	Length uint16
}

type optDecodedTemplate struct {
	TemplateID uint16
	Scopes     []optTemplateField
	Options    []optTemplateField
}

type optDecodedRecord struct {
	// Raw per-field values in template order (scopes then options); string
	// fields are NUL/whitespace-trimmed like a collector would.
	ScopeVals  []uint32
	OptionU32s map[uint16]uint32 // numeric option fields by field type / IE
	OptionStrs map[uint16]string // string option fields by field type / IE
}

type optDatagram struct {
	SequenceNo uint32
	DomainID   uint32
	Count      uint16 // v9 only: header count field
	Template   *optDecodedTemplate
	Records    []optDecodedRecord
}

// decodeOptRecords interprets a data set's payload through the decoded
// options template. Shared by the v9 and IPFIX oracle paths.
func decodeOptRecords(t *testing.T, tmpl *optDecodedTemplate, data []byte) []optDecodedRecord {
	t.Helper()
	recSize := 0
	for _, f := range tmpl.Scopes {
		recSize += int(f.Length)
	}
	for _, f := range tmpl.Options {
		recSize += int(f.Length)
	}
	var recs []optDecodedRecord
	for pos := 0; pos+recSize <= len(data); pos += recSize {
		r := optDecodedRecord{OptionU32s: map[uint16]uint32{}, OptionStrs: map[uint16]string{}}
		p := pos
		for _, f := range tmpl.Scopes {
			if f.Length != 4 {
				t.Fatalf("oracle only handles 4-byte scope fields, got %d", f.Length)
			}
			r.ScopeVals = append(r.ScopeVals, binary.BigEndian.Uint32(data[p:]))
			p += int(f.Length)
		}
		for _, f := range tmpl.Options {
			switch f.Length {
			case 4:
				r.OptionU32s[f.Type] = binary.BigEndian.Uint32(data[p:])
			default: // string field
				raw := data[p : p+int(f.Length)]
				r.OptionStrs[f.Type] = strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", ""))
			}
			p += int(f.Length)
		}
		recs = append(recs, r)
	}
	return recs
}

// decodeNF9OptionsDatagram parses a v9 options datagram: packet header,
// Options Template FlowSet (ID 1), option data FlowSet (ID >= 256).
func decodeNF9OptionsDatagram(t *testing.T, data []byte) *optDatagram {
	t.Helper()
	if len(data) < nf9HeaderSize {
		t.Fatalf("datagram too short: %d", len(data))
	}
	if v := binary.BigEndian.Uint16(data[0:]); v != nf9Version {
		t.Fatalf("version = %d, want 9", v)
	}
	dg := &optDatagram{
		Count:      binary.BigEndian.Uint16(data[2:]),
		SequenceNo: binary.BigEndian.Uint32(data[12:]),
		DomainID:   binary.BigEndian.Uint32(data[16:]),
	}
	pos := nf9HeaderSize
	for pos+4 <= len(data) {
		fsID := binary.BigEndian.Uint16(data[pos:])
		fsLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		if fsLen < 4 || pos+fsLen > len(data) {
			t.Fatalf("invalid FlowSet length %d at offset %d", fsLen, pos)
		}
		fs := data[pos+4 : pos+fsLen]
		switch {
		case fsID == nf9OptionsFlowSetID:
			tmpl := &optDecodedTemplate{TemplateID: binary.BigEndian.Uint16(fs[0:])}
			scopeLen := int(binary.BigEndian.Uint16(fs[2:])) // bytes
			optLen := int(binary.BigEndian.Uint16(fs[4:]))   // bytes
			p := 6
			for i := 0; i < scopeLen; i += 4 {
				tmpl.Scopes = append(tmpl.Scopes, optTemplateField{binary.BigEndian.Uint16(fs[p:]), binary.BigEndian.Uint16(fs[p+2:])})
				p += 4
			}
			for i := 0; i < optLen; i += 4 {
				tmpl.Options = append(tmpl.Options, optTemplateField{binary.BigEndian.Uint16(fs[p:]), binary.BigEndian.Uint16(fs[p+2:])})
				p += 4
			}
			dg.Template = tmpl
		case fsID >= 256:
			if dg.Template == nil || fsID != dg.Template.TemplateID {
				t.Fatalf("data FlowSet %d without matching options template", fsID)
			}
			dg.Records = decodeOptRecords(t, dg.Template, fs)
		default:
			t.Fatalf("unexpected FlowSet ID %d in options datagram", fsID)
		}
		pos += fsLen
	}
	return dg
}

// decodeIPFIXOptionsDatagram parses an IPFIX options message: message header,
// Options Template Set (ID 3), option data Set (ID >= 256).
func decodeIPFIXOptionsDatagram(t *testing.T, data []byte) *optDatagram {
	t.Helper()
	if len(data) < ipfixHeaderSize {
		t.Fatalf("message too short: %d", len(data))
	}
	if v := binary.BigEndian.Uint16(data[0:]); v != ipfixVersion {
		t.Fatalf("version = %d, want 10", v)
	}
	if l := int(binary.BigEndian.Uint16(data[2:])); l != len(data) {
		t.Fatalf("message length field = %d, datagram is %d bytes", l, len(data))
	}
	dg := &optDatagram{
		SequenceNo: binary.BigEndian.Uint32(data[8:]),
		DomainID:   binary.BigEndian.Uint32(data[12:]),
	}
	pos := ipfixHeaderSize
	for pos+4 <= len(data) {
		setID := binary.BigEndian.Uint16(data[pos:])
		setLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		if setLen < 4 || pos+setLen > len(data) {
			t.Fatalf("invalid Set length %d at offset %d", setLen, pos)
		}
		set := data[pos+4 : pos+setLen]
		switch {
		case setID == ipfixSetIDOptionsTemplate:
			tmpl := &optDecodedTemplate{TemplateID: binary.BigEndian.Uint16(set[0:])}
			fieldCount := int(binary.BigEndian.Uint16(set[2:]))
			scopeCount := int(binary.BigEndian.Uint16(set[4:]))
			p := 6
			for i := 0; i < fieldCount; i++ {
				f := optTemplateField{binary.BigEndian.Uint16(set[p:]), binary.BigEndian.Uint16(set[p+2:])}
				if i < scopeCount {
					tmpl.Scopes = append(tmpl.Scopes, f)
				} else {
					tmpl.Options = append(tmpl.Options, f)
				}
				p += 4
			}
			dg.Template = tmpl
		case setID >= 256:
			if dg.Template == nil || setID != dg.Template.TemplateID {
				t.Fatalf("data Set %d without matching options template", setID)
			}
			dg.Records = decodeOptRecords(t, dg.Template, set)
		default:
			t.Fatalf("unexpected Set ID %d in options message", setID)
		}
		pos += setLen
	}
	return dg
}

// ── Encoder round-trips ──────────────────────────────────────────────────────

func testOptionIfaces() []flowOptionIface {
	return []flowOptionIface{
		{ifIndex: 1, name: "eth0"},
		{ifIndex: 2, name: "GigabitEthernet0/2"},
	}
}

func TestNF9OptionsIfScopedRoundTrip(t *testing.T) {
	buf := make([]byte, 1500)
	n, consumed, err := NetFlow9Encoder{}.EncodeOptionsDatagram(0x0A2A0001, 7, 1000, flowOptionShapeIfScoped, testOptionIfaces(), buf)
	if err != nil {
		t.Fatalf("EncodeOptionsDatagram: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("consumed = %d, want 2", consumed)
	}
	dg := decodeNF9OptionsDatagram(t, buf[:n])
	if dg.Count != 3 { // 1 template record + 2 data records
		t.Errorf("header count = %d, want 3", dg.Count)
	}
	tmpl := dg.Template
	if tmpl.TemplateID != nf9OptionsTemplateID {
		t.Errorf("template ID = %d, want %d", tmpl.TemplateID, nf9OptionsTemplateID)
	}
	if len(tmpl.Scopes) != 1 || tmpl.Scopes[0] != (optTemplateField{nf9ScopeInterface, 4}) {
		t.Errorf("scopes = %v, want [(2,4)]", tmpl.Scopes)
	}
	want := []optTemplateField{{nf9IfName, flowOptionStringLen}, {nf9IfDesc, flowOptionStringLen}}
	if len(tmpl.Options) != 2 || tmpl.Options[0] != want[0] || tmpl.Options[1] != want[1] {
		t.Errorf("options = %v, want %v", tmpl.Options, want)
	}
	if len(dg.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(dg.Records))
	}
	if dg.Records[0].ScopeVals[0] != 1 {
		t.Errorf("record 0 scope ifIndex = %d, want 1", dg.Records[0].ScopeVals[0])
	}
	if got := dg.Records[0].OptionStrs[nf9IfName]; got != "eth0" {
		t.Errorf("record 0 interfaceName = %q, want %q", got, "eth0")
	}
	if got := dg.Records[1].OptionStrs[nf9IfDesc]; got != "GigabitEthernet0/2" {
		t.Errorf("record 1 interfaceDescription = %q, want %q", got, "GigabitEthernet0/2")
	}
}

func TestNF9OptionsSystemScopedRoundTrip(t *testing.T) {
	buf := make([]byte, 1500)
	n, consumed, err := NetFlow9Encoder{}.EncodeOptionsDatagram(0x0A2A0001, 9, 1000, flowOptionShapeSystemScoped, testOptionIfaces(), buf)
	if err != nil {
		t.Fatalf("EncodeOptionsDatagram: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("consumed = %d, want 2", consumed)
	}
	dg := decodeNF9OptionsDatagram(t, buf[:n])
	tmpl := dg.Template
	if len(tmpl.Scopes) != 1 || tmpl.Scopes[0].Type != nf9ScopeSystem {
		t.Errorf("scopes = %v, want system (1)", tmpl.Scopes)
	}
	for _, f := range tmpl.Options {
		if f.Type == nf9IfName {
			t.Errorf("system-scoped template must NOT declare interfaceName(82)")
		}
	}
	want := []optTemplateField{{nf9InputSNMP, 4}, {nf9IfDesc, flowOptionStringLen}}
	if len(tmpl.Options) != 2 || tmpl.Options[0] != want[0] || tmpl.Options[1] != want[1] {
		t.Errorf("options = %v, want %v", tmpl.Options, want)
	}
	// ifIndex travels as option field 10 — the collector's field-fallback path.
	if got := dg.Records[1].OptionU32s[nf9InputSNMP]; got != 2 {
		t.Errorf("record 1 INPUT_SNMP = %d, want 2", got)
	}
	if got := dg.Records[0].OptionStrs[nf9IfDesc]; got != "eth0" {
		t.Errorf("record 0 interfaceDescription = %q, want %q", got, "eth0")
	}
}

func TestIPFIXOptionsIfScopedRoundTrip(t *testing.T) {
	buf := make([]byte, 1500)
	n, consumed, err := IPFIXEncoder{}.EncodeOptionsDatagram(0x0A2A0002, 3, 0, flowOptionShapeIfScoped, testOptionIfaces(), buf)
	if err != nil {
		t.Fatalf("EncodeOptionsDatagram: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("consumed = %d, want 2", consumed)
	}
	dg := decodeIPFIXOptionsDatagram(t, buf[:n])
	tmpl := dg.Template
	if tmpl.TemplateID != ipfixOptionsTemplateID {
		t.Errorf("template ID = %d, want %d", tmpl.TemplateID, ipfixOptionsTemplateID)
	}
	if len(tmpl.Scopes) != 1 || tmpl.Scopes[0] != (optTemplateField{ipfixIngressInterface, 4}) {
		t.Errorf("scope IEs = %v, want [(10,4)]", tmpl.Scopes)
	}
	if dg.Records[0].ScopeVals[0] != 1 || dg.Records[1].ScopeVals[0] != 2 {
		t.Errorf("scope ifIndexes = %d,%d, want 1,2", dg.Records[0].ScopeVals[0], dg.Records[1].ScopeVals[0])
	}
	if got := dg.Records[0].OptionStrs[ipfixInterfaceName]; got != "eth0" {
		t.Errorf("record 0 interfaceName = %q, want %q", got, "eth0")
	}
}

func TestIPFIXOptionsSystemScopedRoundTrip(t *testing.T) {
	buf := make([]byte, 1500)
	const domainID = 0x0A2A0002
	n, consumed, err := IPFIXEncoder{}.EncodeOptionsDatagram(domainID, 3, 0, flowOptionShapeSystemScoped, testOptionIfaces(), buf)
	if err != nil {
		t.Fatalf("EncodeOptionsDatagram: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("consumed = %d, want 2", consumed)
	}
	dg := decodeIPFIXOptionsDatagram(t, buf[:n])
	tmpl := dg.Template
	// Scope IE must NOT be an interface IE — that's what forces the
	// collector's field-fallback resolution.
	if len(tmpl.Scopes) != 1 || tmpl.Scopes[0].Type == ipfixIngressInterface || tmpl.Scopes[0].Type == ipfixEgressInterface {
		t.Errorf("scope IEs = %v, want a single non-interface scope", tmpl.Scopes)
	}
	if tmpl.Scopes[0].Type != ipfixObservationDomainID {
		t.Errorf("scope IE = %d, want observationDomainId (149)", tmpl.Scopes[0].Type)
	}
	if got := dg.Records[0].OptionU32s[ipfixIngressInterface]; got != 1 {
		t.Errorf("record 0 ingressInterface field = %d, want 1", got)
	}
	for _, r := range dg.Records {
		if _, has := r.OptionStrs[ipfixInterfaceName]; has {
			t.Errorf("system-scoped record must not carry interfaceName(82)")
		}
	}
}

// ── String encoding ──────────────────────────────────────────────────────────

func TestPutPaddedString(t *testing.T) {
	buf := make([]byte, 64)
	// Short value: NUL-padded to the full field.
	pos := putPaddedString(buf, 0, "eth0")
	if pos != flowOptionStringLen {
		t.Fatalf("pos = %d, want %d", pos, flowOptionStringLen)
	}
	if !bytes.Equal(buf[0:4], []byte("eth0")) {
		t.Errorf("payload = %q", buf[0:4])
	}
	for i := 4; i < flowOptionStringLen; i++ {
		if buf[i] != 0 {
			t.Fatalf("byte %d = %#x, want NUL padding", i, buf[i])
		}
	}
	// Long value: truncated at exactly the field size.
	long := strings.Repeat("x", 40)
	pos = putPaddedString(buf, 0, long)
	if pos != flowOptionStringLen {
		t.Fatalf("pos = %d, want %d", pos, flowOptionStringLen)
	}
	if !bytes.Equal(buf[:flowOptionStringLen], []byte(long[:flowOptionStringLen])) {
		t.Errorf("truncated payload mismatch")
	}
}

// ── Tick-level emission ──────────────────────────────────────────────────────

// optionsTickHarness runs one Tick against a live UDP listener and returns
// the received datagrams partitioned into flow packets and options datagrams
// (recognised by FlowSet/Set ID 1 or 3 right after the header).
func optionsTickHarness(t *testing.T, enc FlowEncoder, shape string, ifaces []flowOptionIface) (fe *FlowExporter, tick func() (flowPkts, optPkts [][]byte)) {
	t.Helper()
	ln, ch := testUDPListener(t)
	t.Cleanup(func() { ln.Close() })
	conn := testSender(t)
	t.Cleanup(func() { conn.Close() })
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	fe = newTestFlowExporter(testDevice("10.42.0.9"), sflowTickTestProfile(),
		1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)
	fe.optionShape = shape
	fe.optionIfaces = ifaces

	tick = func() ([][]byte, [][]byte) {
		tickWithEncoder(fe, time.Now(), enc, conn, collectorAddr, testPool())
		var flows, opts [][]byte
		for {
			pkt := receivePacket(ch)
			if pkt == nil {
				break
			}
			// Both protocols: first set/flowset header sits right after the
			// packet header; options datagrams open with the options
			// template (v9 FlowSet ID 1 / IPFIX Set ID 3).
			hdr := nf9HeaderSize
			if binary.BigEndian.Uint16(pkt[0:]) == ipfixVersion {
				hdr = ipfixHeaderSize
			}
			firstSet := binary.BigEndian.Uint16(pkt[hdr:])
			if firstSet == nf9OptionsFlowSetID || firstSet == ipfixSetIDOptionsTemplate {
				opts = append(opts, pkt)
			} else {
				flows = append(flows, pkt)
			}
		}
		return flows, opts
	}
	return fe, tick
}

func TestFlowOptionsTickEmission(t *testing.T) {
	_, tick := optionsTickHarness(t, NetFlow9Encoder{}, flowOptionShapeIfScoped, testOptionIfaces())

	// First tick: seqNo==0 forces the template-refresh condition → exactly
	// one options datagram alongside the flow packet(s).
	flows, opts := tick()
	if len(opts) != 1 {
		t.Fatalf("options datagrams on refresh tick = %d, want 1", len(opts))
	}
	if len(flows) == 0 {
		t.Fatal("no flow packet on first tick")
	}
	dg := decodeNF9OptionsDatagram(t, opts[0])
	if len(dg.Records) != 2 {
		t.Errorf("option records = %d, want 2", len(dg.Records))
	}

	// Second tick inside the 10-minute template interval: no options traffic.
	time.Sleep(15 * time.Millisecond)
	_, opts = tick()
	if len(opts) != 0 {
		t.Errorf("options datagrams between refreshes = %d, want 0", len(opts))
	}
}

func TestFlowOptionsTickEmptyUniverse(t *testing.T) {
	// Shape set but no interfaces: never emit an options set with zero
	// records — the datagram is skipped entirely.
	_, tick := optionsTickHarness(t, NetFlow9Encoder{}, flowOptionShapeIfScoped, nil)
	_, opts := tick()
	if len(opts) != 0 {
		t.Errorf("options datagrams with empty universe = %d, want 0", len(opts))
	}
}

func TestFlowOptionsTickDisabledUnchanged(t *testing.T) {
	// No shape: wire output carries no options FlowSets at all.
	_, tick := optionsTickHarness(t, NetFlow9Encoder{}, "", nil)
	flows, opts := tick()
	if len(opts) != 0 {
		t.Errorf("options datagrams while disabled = %d, want 0", len(opts))
	}
	if len(flows) == 0 {
		t.Fatal("no flow packet emitted")
	}
	// The flow packet still decodes under the regular flow oracle (template
	// ID 256, no FlowSet 1/257) — structure unchanged from pre-feature.
	pkt := decodeNF9Packet(t, flows[0])
	for _, tmpl := range pkt.Templates {
		if tmpl.TemplateID != nf9TemplateID {
			t.Errorf("unexpected template ID %d in flow packet", tmpl.TemplateID)
		}
	}
}

func TestFlowOptionsSequenceConsecutive(t *testing.T) {
	fe, tick := optionsTickHarness(t, NetFlow9Encoder{}, flowOptionShapeSystemScoped, testOptionIfaces())
	flows, opts := tick()
	if len(flows) == 0 || len(opts) != 1 {
		t.Fatalf("flows = %d, opts = %d, want >=1 and 1", len(flows), len(opts))
	}
	lastFlowSeq := decodeNF9Packet(t, flows[len(flows)-1]).Header.SequenceNo
	optSeq := decodeNF9OptionsDatagram(t, opts[0]).SequenceNo
	if optSeq != lastFlowSeq+1 {
		t.Errorf("options seq = %d, want last flow seq %d + 1", optSeq, lastFlowSeq)
	}
	// The next packet the exporter would emit continues after the options
	// datagram — the counter advanced by exactly 1 for it.
	if fe.seqNo != optSeq+1 {
		t.Errorf("fe.seqNo = %d, want %d (options datagram + 1)", fe.seqNo, optSeq+1)
	}
}

func TestFlowOptionsIPFIXSequencePlusOne(t *testing.T) {
	fe, tick := optionsTickHarness(t, IPFIXEncoder{}, flowOptionShapeIfScoped, testOptionIfaces())
	flows, opts := tick()
	if len(flows) == 0 || len(opts) != 1 {
		t.Fatalf("flows = %d, opts = %d, want >=1 and 1", len(flows), len(opts))
	}
	lastFlowSeq := decodeIPFIXPacket(t, flows[len(flows)-1]).Header.SequenceNumber
	dg := decodeIPFIXOptionsDatagram(t, opts[0])
	if dg.SequenceNo != lastFlowSeq+1 {
		t.Errorf("options seq = %d, want %d", dg.SequenceNo, lastFlowSeq+1)
	}
	// Message-counting interpretation: +1 for the whole options message,
	// regardless of the 2 option data records it carries (design D7).
	if fe.seqNo != dg.SequenceNo+1 {
		t.Errorf("fe.seqNo = %d, want %d", fe.seqNo, dg.SequenceNo+1)
	}
}

// ── Registration (interface universe capture) ────────────────────────────────

func TestRegisterFlowOptionInterfaces(t *testing.T) {
	device := testDevice("10.42.0.7")
	device.flowConfig = &DeviceFlowConfig{Collector: "127.0.0.1:2055", Protocol: "netflow9", OptionsInterfaceTable: flowOptionShapeIfScoped}
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	device.flowExporter = NewFlowExporter(device, sflowTickTestProfile(),
		time.Second, time.Second, time.Minute, "127.0.0.1:0", addr, "netflow9", NetFlow9Encoder{}, 0)
	device.metricsCycler = &MetricsCycler{}
	// Unsorted universe with a defensive 0 — 0 must be skipped, output sorted.
	device.metricsCycler.ifCounters.Store(&IfCounterCycler{ifIndexList: []int{2, 0, 1}})

	(&SimulatorManager{}).registerFlowOptionInterfaces(device)

	fe := device.flowExporter
	if fe.optionShape != flowOptionShapeIfScoped {
		t.Errorf("optionShape = %q", fe.optionShape)
	}
	if len(fe.optionIfaces) != 2 {
		t.Fatalf("optionIfaces = %v, want 2 entries (ifIndex 0 skipped)", fe.optionIfaces)
	}
	if fe.optionIfaces[0].ifIndex != 1 || fe.optionIfaces[1].ifIndex != 2 {
		t.Errorf("ifIndexes = %d,%d, want sorted 1,2", fe.optionIfaces[0].ifIndex, fe.optionIfaces[1].ifIndex)
	}
	// No device resources → synthIfName fallback.
	if fe.optionIfaces[0].name != "GigabitEthernet0/1" {
		t.Errorf("name = %q, want synthesised fallback", fe.optionIfaces[0].name)
	}
}
