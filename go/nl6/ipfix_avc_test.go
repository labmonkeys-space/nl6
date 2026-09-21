/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The encoder's IE table is DERIVED from testdata/cisco-avc/elements.tsv
// (spec section 1): a constant that disagrees with the extract fails by
// name here. This test cannot show the extract is right; it shows the code
// did not drift from it.
func TestIPFIXAVCConstantsMatchEvidence(t *testing.T) {
	_, elements := loadCiscoAVCExtract(t)
	want := map[string]struct {
		pen, id int
		got     int
	}{
		"applicationId":          {0, 95, ipfixApplicationID},
		"applicationName":        {0, 96, ipfixApplicationName},
		"applicationDescription": {0, 94, ipfixApplicationDescription},
		"HTTP Host":              {9, 12235, ciscoHTTPHost},
		"HTTP URI statistics":    {9, 9357, ciscoHTTPURIStatistics},
	}
	seen := map[string]bool{}
	for _, e := range elements {
		w, ok := want[e.Name]
		if !ok {
			continue
		}
		seen[e.Name] = true
		pen, _ := strconv.Atoi(e.PEN)
		id, _ := strconv.Atoi(e.ID)
		if pen != w.pen || id != w.id {
			t.Fatalf("test table for %q says pen=%d id=%d, extract says pen=%d id=%d: fix the test table only if the extract changed", e.Name, w.pen, w.id, pen, id)
		}
		if w.got != id {
			t.Errorf("constant for %q = %d, extract says %d", e.Name, w.got, id)
		}
		if e.Status == "unresolved" {
			t.Errorf("%q is unresolved in the extract and must not be encoded", e.Name)
		}
		switch e.Name {
		case "applicationName":
			if n, _ := strconv.Atoi(e.Length); n != ipfixApplicationNameLen {
				t.Errorf("applicationName length constant = %d, extract says %d", ipfixApplicationNameLen, n)
			}
		case "applicationDescription":
			if n, _ := strconv.Atoi(e.Length); n != ipfixApplicationDescriptionLen {
				t.Errorf("applicationDescription length constant = %d, extract says %d", ipfixApplicationDescriptionLen, n)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("extract has no row named %q", name)
		}
	}
	if ciscoPEN != 9 {
		t.Errorf("ciscoPEN = %d, want 9", ciscoPEN)
	}
	if ipfixAVCTemplateID != 258 || ipfixAppTableTemplateID != 259 {
		t.Errorf("template ids = %d/%d, want 258/259 (plan A global constraint)", ipfixAVCTemplateID, ipfixAppTableTemplateID)
	}
	if ciscoHTTPHostWireSpecifier != ipfixEnterpriseBit|ciscoHTTPHost {
		t.Errorf("ciscoHTTPHostWireSpecifier = %d, want ipfixEnterpriseBit|ciscoHTTPHost = %d (45003 = 0x8000|12235)", ciscoHTTPHostWireSpecifier, ipfixEnterpriseBit|ciscoHTTPHost)
	}
	if ciscoHTTPURIStatisticsWireSpecifier != ipfixEnterpriseBit|ciscoHTTPURIStatistics {
		t.Errorf("ciscoHTTPURIStatisticsWireSpecifier = %d, want ipfixEnterpriseBit|ciscoHTTPURIStatistics = %d (42125 = 0x8000|9357)", ciscoHTTPURIStatisticsWireSpecifier, ipfixEnterpriseBit|ciscoHTTPURIStatistics)
	}
}

// RFC 7011 section 7: a value shorter than 255 bytes carries a 1-byte length;
// otherwise the byte 255 then a 2-byte big-endian length. 254, 255 and 256
// are the boundary where variable-length encoders break.
func TestIPFIXVarLenBoundary(t *testing.T) {
	for _, n := range []int{0, 1, 254, 255, 256, 1000} {
		v := make([]byte, n)
		for i := range v {
			v[i] = byte('a' + i%26)
		}
		buf := make([]byte, n+3)
		pos, ok := putIPFIXVarLen(buf, 0, v)
		if !ok {
			t.Fatalf("n=%d: did not fit in %d bytes", n, len(buf))
		}
		if pos != ipfixVarLenSize(n) {
			t.Fatalf("n=%d: wrote %d bytes, ipfixVarLenSize says %d", n, pos, ipfixVarLenSize(n))
		}
		var gotLen, hdr int
		if buf[0] < 255 {
			gotLen, hdr = int(buf[0]), 1
		} else {
			gotLen, hdr = int(buf[1])<<8|int(buf[2]), 3
		}
		if n < 255 && hdr != 1 || n >= 255 && hdr != 3 {
			t.Fatalf("n=%d: header form %d bytes", n, hdr)
		}
		if gotLen != n || string(buf[hdr:pos]) != string(v) {
			t.Fatalf("n=%d: decoded length %d, payload mismatch=%v", n, gotLen, string(buf[hdr:pos]) != string(v))
		}
	}
	// Does not fit, one byte short in each length form: 253 bytes need 254;
	// 255 bytes need 258.
	if _, ok := putIPFIXVarLen(make([]byte, 253), 0, make([]byte, 253)); ok {
		t.Fatal("253-byte value needs 254 bytes and must not fit in 253")
	}
	if _, ok := putIPFIXVarLen(make([]byte, 257), 0, make([]byte, 255)); ok {
		t.Fatal("255-byte value needs 258 bytes and must not fit in 257")
	}
	// Too long to represent at all.
	if _, ok := putIPFIXVarLen(make([]byte, 70000), 0, make([]byte, 65536)); ok {
		t.Fatal("65536-byte value cannot be represented in a 2-byte length")
	}
}

func testAVCCatalog() *avcCatalog {
	return newAVCCatalog([]avcApplication{
		{ID: avcApplicationID(13, 80), Name: "http", Description: "HTTP", Proto: 6, DstPort: 80,
			Hosts: []string{"www.example.com", "cdn.example.net"}, URIs: []string{"/index.html", "/api/v1/items"}},
		{ID: avcApplicationID(13, 443), Name: "ssl", Description: "Secure Socket Layer", Proto: 6, DstPort: 443},
		{ID: avcApplicationID(3, 53), Name: "dns", Description: "Domain Name System", Proto: 17, DstPort: 53},
	})
}

func TestAVCCatalogIndexing(t *testing.T) {
	c := testAVCCatalog()
	if c.Len() != 3 {
		t.Fatalf("Len = %d, want 3", c.Len())
	}
	if _, ok := c.App(0); ok {
		t.Fatal("index 0 must mean absent")
	}
	if _, ok := c.App(4); ok {
		t.Fatal("index past the end must be absent")
	}
	app, ok := c.App(1)
	if !ok || app.Name != "http" {
		t.Fatalf("App(1) = %+v ok=%v, want http", app, ok)
	}
	if got := avcApplicationID(13, 80); got != 13<<24|80 {
		t.Fatalf("avcApplicationID(13,80) = %#x, want %#x", got, 13<<24|80)
	}
	// An even engine is load-bearing here: with an odd engine (13) the
	// selector's out-of-range bit 24 collides with a bit the engine already
	// sets, so an unmasked implementation would pass this assertion too.
	if got := avcApplicationID(12, 0x1FFFFFF); got&0xFFFFFF != 0xFFFFFF || got>>24 != 12 {
		t.Fatalf("selector must be masked to 24 bits (engine must stay 12), got %#x", got)
	}
	var r FlowRecord
	if r.AVC != (avcRef{}) {
		t.Fatal("zero FlowRecord must carry no application")
	}
}

// The AVC template is the 19 existing IEs, then applicationId, then the two
// PEN 9 layer-7 fields as variable-length enterprise specifiers. Enterprise
// specifiers are 8 bytes (RFC 7011 section 3.2), so the set length is
// computed, not the plain template's 84.
func TestIPFIXAVCTemplateSet(t *testing.T) {
	set := buildIPFIXAVCTemplateSet()
	wantLen := 4 + 4 + 20*4 + 2*8
	if len(set) != wantLen {
		t.Fatalf("template set length = %d, want %d", len(set), wantLen)
	}
	if got := int(set[2])<<8 | int(set[3]); got != wantLen {
		t.Fatalf("declared set length = %d, want %d", got, wantLen)
	}
	msg := append([]byte{0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, set...)
	msg[2], msg[3] = byte(len(msg)>>8), byte(len(msg))
	pkt := decodeIPFIXPacket(t, msg)
	if len(pkt.Templates) != 1 || pkt.Templates[0].TemplateID != ipfixAVCTemplateID {
		t.Fatalf("templates = %+v", pkt.Templates)
	}
	f := pkt.Templates[0].Fields
	if len(f) != 22 {
		t.Fatalf("field count = %d, want 22", len(f))
	}
	for i := 0; i < 19; i++ {
		if f[i].IEID != ipfixFields[i][0] || f[i].IELength != ipfixFields[i][1] || f[i].PEN != 0 {
			t.Fatalf("field %d = %+v, want the plain template's %v", i, f[i], ipfixFields[i])
		}
	}
	if f[19] != (ipfixTemplateField{IEID: ipfixApplicationID, IELength: 4}) {
		t.Fatalf("field 19 = %+v, want applicationId/4", f[19])
	}
	if f[20] != (ipfixTemplateField{IEID: ciscoHTTPHost, IELength: ipfixVarLen, PEN: ciscoPEN}) {
		t.Fatalf("field 20 = %+v, want httpHost var PEN 9", f[20])
	}
	if f[21] != (ipfixTemplateField{IEID: ciscoHTTPURIStatistics, IELength: ipfixVarLen, PEN: ciscoPEN}) {
		t.Fatalf("field 21 = %+v, want httpUriStatistics var PEN 9", f[21])
	}
}

func avcRecord(app, host, uri uint16, srcPort uint16) FlowRecord {
	return FlowRecord{
		SrcIP: net.ParseIP("10.0.0.1").To4(), DstIP: net.ParseIP("10.0.0.2").To4(),
		NextHop: net.IPv4(0, 0, 0, 0).To4(), SrcPort: srcPort, DstPort: 80, Protocol: 6,
		Bytes: 100, Packets: 1, AVC: avcRef{App: app, Host: host, URI: uri},
	}
}

// Round trip through the test decoder: template + records; applicationId,
// host and URI statistics come back as written. IE 12235 is Cisco's
// six-byte prefix then the host (nl6#679); a record with no host, and a
// record with no application at all, carry exactly the prefix and a
// zero-length URI field. The field is never empty: the IOS-XE capture shows
// the prefix on DNS flows too (TestCiscoAVCCapture_HTTPHostCarriesConstantPrefix).
func TestIPFIXAVCEncodeRoundTrip(t *testing.T) {
	enc := NewIPFIXAVCEncoder(testAVCCatalog())
	buf := make([]byte, 1472)
	recs := []FlowRecord{avcRecord(1, 2, 1, 50000), avcRecord(2, 0, 0, 50001), avcRecord(0, 0, 0, 50002)}
	n, consumed, dropped, err := enc.EncodeMeasured(1, 7, 1000, recs, true, buf)
	if err != nil || consumed != 3 || dropped != 0 {
		t.Fatalf("n=%d consumed=%d dropped=%d err=%v", n, consumed, dropped, err)
	}
	pkt := decodeIPFIXPacket(t, buf[:n])
	if len(pkt.Templates) != 1 || pkt.Templates[0].TemplateID != ipfixAVCTemplateID {
		t.Fatalf("templates = %+v", pkt.Templates)
	}
	if pkt.Header.SequenceNumber != 7 || int(pkt.Header.Length) != n {
		t.Fatalf("header = %+v, n=%d", pkt.Header, n)
	}
	got := decodeIPFIXAVCRecords(t, pkt.RawSets[ipfixAVCTemplateID])
	if len(got) != 3 {
		t.Fatalf("decoded %d records, want 3", len(got))
	}
	if got[0].AppID != avcApplicationID(13, 80) || got[0].Host != "cdn.example.net" {
		t.Fatalf("record 0 = %+v", got[0])
	}
	if want := append([]byte{0x03, 0x00, 0x00, 0x50, 0x34, 0x02}, "cdn.example.net"...); !bytes.Equal(got[0].HostField, want) {
		t.Fatalf("record 0 IE 12235 = %x, want %x (applicationId http, sub-application id 0x3402, host)", got[0].HostField, want)
	}
	want := append([]byte("/index.html\x00"), 0, 1)
	if string(got[0].URIStats) != string(want) {
		t.Fatalf("record 0 uri stats = %q, want %q (URI, NUL, uint16 BE count 1)", got[0].URIStats, want)
	}
	if got[1].AppID != avcApplicationID(13, 443) || got[1].Host != "" || len(got[1].URIStats) != 0 {
		t.Fatalf("record 1 (ssl, no host) = %+v", got[1])
	}
	if !bytes.Equal(got[1].HostField, avcHostPrefix) || len(got[1].HostField) != 6 {
		t.Fatalf("record 1 (ssl, no host) IE 12235 = %x, want exactly the six-byte prefix", got[1].HostField)
	}
	if got[2].AppID != 0 || got[2].Host != "" || got[2].Base.SrcPort != 50002 {
		t.Fatalf("record 2 (no application) = %+v", got[2])
	}
	if !bytes.Equal(got[2].HostField, avcHostPrefix) {
		t.Fatalf("record 2 (no application) IE 12235 = %x, want the prefix: the field is never empty", got[2].HostField)
	}
	if n%4 != 0 {
		t.Fatalf("message length %d is not 4-byte aligned", n)
	}
}

// Field lengths at the RFC 7011 section 7 boundary survive the round trip.
// The boundary is on the WHOLE IE 12235 value, prefix included, so a
// 249-byte host is the last one-byte-length field (255) and a 250-byte host
// the first three-byte-length field (256); the length form is read off the
// wire, not inferred from the decode.
func TestIPFIXAVCEncodeHostLengthBoundary(t *testing.T) {
	for _, hl := range []int{0, 1, 248, 249, 250, 300} {
		cat := newAVCCatalog([]avcApplication{{ID: avcApplicationID(13, 80), Name: "http", Hosts: []string{strings.Repeat("h", hl)}}})
		enc := NewIPFIXAVCEncoder(cat)
		buf := make([]byte, 1472)
		n, consumed, _, err := enc.EncodeMeasured(1, 0, 0, []FlowRecord{avcRecord(1, 1, 0, 1)}, false, buf)
		if err != nil || consumed != 1 {
			t.Fatalf("hl=%d: consumed=%d err=%v", hl, consumed, err)
		}
		set := decodeIPFIXPacket(t, buf[:n]).RawSets[ipfixAVCTemplateID]
		got := decodeIPFIXAVCRecords(t, set)
		if len(got) != 1 || len(got[0].Host) != hl || len(got[0].HostField) != hl+6 {
			t.Fatalf("hl=%d: decoded host length %d, field length %d", hl, len(got[0].Host), len(got[0].HostField))
		}
		lenByte := set[ipfixRecordSize+4]
		switch total := hl + 6; {
		case total < 255 && int(lenByte) != total:
			t.Fatalf("hl=%d: length byte %d, want the one-byte form %d", hl, lenByte, total)
		case total >= 255 && (lenByte != 255 || int(binary.BigEndian.Uint16(set[ipfixRecordSize+5:])) != total):
			t.Fatalf("hl=%d: length bytes %x, want the three-byte form 255,%04x", hl, set[ipfixRecordSize+4:ipfixRecordSize+7], total)
		}
	}
}

// Measured pagination: with a small budget the encoder consumes only what
// fits, and the count it reports is exactly the number of records on the
// wire. Then a record that fits no empty datagram is dropped and reported.
func TestIPFIXAVCEncodeMeasuredConsumesWhatFits(t *testing.T) {
	enc := NewIPFIXAVCEncoder(testAVCCatalog())
	recs := make([]FlowRecord, 10)
	for i := range recs {
		recs[i] = avcRecord(1, 1, 1, uint16(50000+i))
	}
	// Each record is 54 + 4 + (1+6+15) + (1+14) = 95 bytes (the host field
	// carries avcHostPrefix before the 15-byte host); header 16 + set 4.
	// +3 (not +2): EncodeMeasured reserves a 3-byte worst-case pad margin
	// (limit := len(buf)-3) while probing whether a record fits, so exactly
	// 3*95 bytes of headroom beyond the base overhead is required for the
	// third record's last write to land inside that margin.
	const recSize = ipfixRecordSize + 4 + (1 + 6 + 15) + (1 + 14)
	buf := make([]byte, 20+recSize*3+3)
	n, consumed, dropped, err := enc.EncodeMeasured(1, 0, 0, recs, false, buf)
	if err != nil || dropped != 0 {
		t.Fatalf("err=%v dropped=%d", err, dropped)
	}
	if consumed != 3 {
		t.Fatalf("consumed = %d, want 3", consumed)
	}
	if got := len(decodeIPFIXAVCRecords(t, decodeIPFIXPacket(t, buf[:n]).RawSets[ipfixAVCTemplateID])); got != consumed {
		t.Fatalf("%d records on the wire, consumed reports %d", got, consumed)
	}
	// Too small for even one record: dropped=1, consumed=1, nothing written.
	tiny := make([]byte, 20+50)
	n, consumed, dropped, err = enc.EncodeMeasured(1, 0, 0, recs[:1], false, tiny)
	if err != nil || n != 0 || consumed != 1 || dropped != 1 {
		t.Fatalf("oversize: n=%d consumed=%d dropped=%d err=%v; want 0,1,1,nil", n, consumed, dropped, err)
	}
	// Template-only message when nothing is given.
	n, consumed, dropped, err = enc.EncodeMeasured(1, 0, 0, nil, true, buf)
	if err != nil || consumed != 0 || dropped != 0 || n != 16+len(ipfixAVCTemplateSetBytes) {
		t.Fatalf("template-only: n=%d consumed=%d dropped=%d err=%v", n, consumed, dropped, err)
	}
}

// A template-carrying message with no room for even one record sends the
// template alone and reports nothing consumed and nothing dropped: the
// record is retried in the next, data-only datagram, which has more room.
func TestIPFIXAVCEncodeTemplateWhenNoRoom(t *testing.T) {
	enc := NewIPFIXAVCEncoder(testAVCCatalog())
	buf := make([]byte, 16+len(ipfixAVCTemplateSetBytes)+20) // room for the set header, not a record
	n, consumed, dropped, err := enc.EncodeMeasured(1, 9, 0, []FlowRecord{avcRecord(1, 1, 1, 50000)}, true, buf)
	if err != nil {
		t.Fatal(err)
	}
	if want := 16 + len(ipfixAVCTemplateSetBytes); n != want || consumed != 0 || dropped != 0 {
		t.Fatalf("n=%d consumed=%d dropped=%d, want %d, 0, 0", n, consumed, dropped, want)
	}
	pkt := decodeIPFIXPacket(t, buf[:n])
	if len(pkt.Templates) != 1 || int(pkt.Header.Length) != n || pkt.Header.SequenceNumber != 9 {
		t.Fatalf("template-only message decoded as %+v", pkt.Header)
	}
	if len(pkt.RawSets) != 0 {
		t.Fatalf("template-only message must carry no data set, got %v", pkt.RawSets)
	}
}

// Through the real Tick: 120 AVC records with varied host lengths paginate
// across several datagrams, every record reaches the wire exactly once,
// RecordsSent equals the wire count, and the sequence numbers are the
// running record count (RFC 7011 section 3.1).
func TestIPFIXAVCTickRequeuesOnConsumed(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	cat := newAVCCatalog([]avcApplication{{ID: avcApplicationID(13, 80), Name: "http",
		Hosts: []string{"a.example", strings.Repeat("b", 200), strings.Repeat("c", 300)}, URIs: []string{"/x"}}})
	enc := NewIPFIXAVCEncoder(cat)
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.50"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	past := time.Now().Add(-time.Hour)
	for i := 0; i < 120; i++ {
		fe.cache.Add(avcRecord(1, uint16(i%3+1), 1, uint16(49152+i)), past)
	}
	stats := tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())
	if stats.PacketsSent < 3 {
		t.Fatalf("expected several datagrams, got %d", stats.PacketsSent)
	}
	seen := map[uint16]bool{}
	var running uint32
	for i := 0; i < int(stats.PacketsSent); i++ {
		pkt := receivePacket(ch)
		if pkt == nil {
			t.Fatalf("datagram %d missing", i)
		}
		if len(pkt) > maxFlowPayloadIPv4 {
			t.Fatalf("datagram %d is %d bytes, over the %d budget", i, len(pkt), maxFlowPayloadIPv4)
		}
		dec := decodeIPFIXPacket(t, pkt)
		if dec.Header.SequenceNumber != running {
			t.Fatalf("datagram %d sequence %d, want %d", i, dec.Header.SequenceNumber, running)
		}
		recs := decodeIPFIXAVCRecords(t, dec.RawSets[ipfixAVCTemplateID])
		for _, r := range recs {
			if seen[r.Base.SrcPort] {
				t.Fatalf("record with src port %d arrived twice", r.Base.SrcPort)
			}
			seen[r.Base.SrcPort] = true
		}
		running += uint32(len(recs))
	}
	// fe.seqNo is 121, not 120: IPFIXAVCEncoder now also implements
	// appTableEncoder (Task 7), so this catalog's one application rides an
	// application-table datagram on the same refresh tick and advances the
	// sequence by one more Data Record (RFC 7011 section 3.1). That extra
	// datagram is not an AVC flow record, so it does not appear in `seen`
	// or move RecordsSent — decodeIPFIXAVCRecords returns nothing for it
	// (dec.RawSets[ipfixAVCTemplateID] is unset), leaving `running`
	// unaffected too.
	if len(seen) != 120 || stats.RecordsSent != 120 || fe.seqNo != 121 {
		t.Fatalf("wire=%d RecordsSent=%d seqNo=%d, want 120, 120, 121", len(seen), stats.RecordsSent, fe.seqNo)
	}
	if stats.SendFailures != 0 {
		t.Fatalf("SendFailures = %d, want 0", stats.SendFailures)
	}
}

// A record that fits no datagram is dropped once, counted once, and does
// not block the records behind it.
func TestIPFIXAVCTickDropsUnsendableRecord(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	cat := newAVCCatalog([]avcApplication{{ID: avcApplicationID(13, 80), Name: "http",
		Hosts: []string{"ok.example", strings.Repeat("z", 1500)}}})
	enc := NewIPFIXAVCEncoder(cat)
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.51"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	fe.lastTempl = time.Now() // data-only tick
	past := time.Now().Add(-time.Hour)
	fe.cache.Add(avcRecord(1, 2, 0, 49152), past) // 1500-byte host: never fits
	fe.cache.Add(avcRecord(1, 1, 0, 49153), past)
	stats := tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())
	if stats.SendFailures != 1 || stats.RecordsSent != 1 || stats.PacketsSent != 1 {
		t.Fatalf("stats = %+v, want SendFailures 1, RecordsSent 1, PacketsSent 1", stats)
	}
	pkt := receivePacket(ch)
	if pkt == nil {
		t.Fatal("the sendable record never arrived")
	}
	recs := decodeIPFIXAVCRecords(t, decodeIPFIXPacket(t, pkt).RawSets[ipfixAVCTemplateID])
	if len(recs) != 1 || recs[0].Host != "ok.example" {
		t.Fatalf("wire records = %+v", recs)
	}
	if fe.seqNo != 1 {
		t.Fatalf("seqNo = %d, want 1 (dropped record never counted as sent)", fe.seqNo)
	}
}

// Under the divisor-based pagination this catalog's worst case (a ~1400-byte
// host) exceeds the template tick's budget on its own, so cap computed from
// MaxRecordSize() was 0, the fixed-size loop broke immediately, and all ten
// queued records were lost without a single counter moving. The measured
// path must not predict capacity from the worst case in the catalog at all:
// it measures per record, so short-host records in the same catalog as one
// oversized host still get sent.
func TestIPFIXAVCTickSendsWhenWorstCaseExceedsBudget(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	cat := newAVCCatalog([]avcApplication{{ID: avcApplicationID(13, 80), Name: "http",
		Hosts: []string{"short.example", strings.Repeat("w", 1400)}}})
	enc := NewIPFIXAVCEncoder(cat)
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.52"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	// lastTempl left at its zero value: the first tick carries the template.
	past := time.Now().Add(-time.Hour)
	for i := 0; i < 10; i++ {
		fe.cache.Add(avcRecord(1, 1, 0, uint16(49152+i)), past) // all use the SHORT host
	}
	stats := tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())
	if stats.PacketsSent < 1 {
		t.Fatalf("expected at least one datagram, got %d", stats.PacketsSent)
	}
	if stats.RecordsSent != 10 {
		t.Fatalf("RecordsSent = %d, want 10", stats.RecordsSent)
	}
	if stats.SendFailures != 0 {
		t.Fatalf("SendFailures = %d, want 0", stats.SendFailures)
	}
	var got []ipfixDecodedAVCRecord
	sawTemplate := false
	for i := 0; i < int(stats.PacketsSent); i++ {
		pkt := receivePacket(ch)
		if pkt == nil {
			t.Fatalf("datagram %d missing", i)
		}
		dec := decodeIPFIXPacket(t, pkt)
		if i == 0 && len(dec.Templates) == 1 {
			sawTemplate = true
		}
		got = append(got, decodeIPFIXAVCRecords(t, dec.RawSets[ipfixAVCTemplateID])...)
	}
	if !sawTemplate {
		t.Fatal("first datagram must carry the template")
	}
	if len(got) != 10 {
		t.Fatalf("decoded %d records across all datagrams, want 10", len(got))
	}
	for _, r := range got {
		if r.Host != "short.example" {
			t.Fatalf("record host = %q, want %q", r.Host, "short.example")
		}
	}
}

// The application table is an Options Template (Set ID 3, template 259)
// with scope applicationId and non-scope applicationName (24 bytes) and
// applicationDescription (55 bytes), per RFC 6759 section 4.3 and Cisco's
// option application-table lengths. Records are 83 bytes, so the set pads.
func TestIPFIXAVCAppTableDatagram(t *testing.T) {
	cat := testAVCCatalog()
	enc := NewIPFIXAVCEncoder(cat)
	buf := make([]byte, 1472)
	n, consumed, err := enc.EncodeAppTableDatagram(1, 42, enc.Applications(), buf)
	if err != nil || consumed != 3 {
		t.Fatalf("n=%d consumed=%d err=%v", n, consumed, err)
	}
	if n%4 != 0 {
		t.Fatalf("message length %d not 4-byte aligned", n)
	}
	dg := decodeIPFIXOptionsDatagram(t, buf[:n])
	if dg.SequenceNo != 42 || dg.Template == nil || dg.Template.TemplateID != ipfixAppTableTemplateID {
		t.Fatalf("datagram = %+v", dg)
	}
	if dg.Template.ScopeCount != 1 || len(dg.Template.Fields) != 3 {
		t.Fatalf("template = %+v", dg.Template)
	}
	if f := dg.Template.Fields; f[0].IEID != ipfixApplicationID || f[0].IELength != 4 ||
		f[1].IEID != ipfixApplicationName || f[1].IELength != ipfixApplicationNameLen ||
		f[2].IEID != ipfixApplicationDescription || f[2].IELength != ipfixApplicationDescriptionLen {
		t.Fatalf("template fields = %+v", f)
	}
	if len(dg.Records) != 3 {
		t.Fatalf("records = %d, want 3", len(dg.Records))
	}
	if dg.Records[0].Scope != avcApplicationID(13, 80) || dg.Records[0].Strings[0] != "http" || dg.Records[0].Strings[1] != "HTTP" {
		t.Fatalf("record 0 = %+v", dg.Records[0])
	}
	// Pagination: a buffer holding two records consumes two.
	small := make([]byte, 16+len(ipfixAppTableTemplateSetBytes)+4+2*ipfixAppTableRecSize+3)
	_, consumed, err = enc.EncodeAppTableDatagram(1, 0, enc.Applications(), small)
	if err != nil || consumed != 2 {
		t.Fatalf("small buffer: consumed=%d err=%v, want 2", consumed, err)
	}
}

// Through Tick: on a template-refresh tick an AVC device emits the data
// template, the interface option table (257) AND the application table
// (259); the two options tables coexist and the application table advances
// the sequence by its record count. IPFIXAVCEncoder now also implements
// flowOptionsEncoder (delegating to IPFIXEncoder — the interface option
// table's message is identical regardless of which flow template a device
// otherwise uses), so both options tables fire from the one encoder.
func TestIPFIXAVCTickEmitsApplicationTable(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	enc := NewIPFIXAVCEncoder(testAVCCatalog())
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.52"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	fe.optionShape = flowOptionShapeIfScoped
	fe.optionIfaces = []flowOptionIface{{ifIndex: 1, name: "Gi0/1"}}
	fe.cache.Add(avcRecord(1, 1, 1, 49152), time.Now().Add(-time.Hour))
	stats := tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())
	if stats.PacketsSent != 3 || stats.RecordsSent != 1 {
		t.Fatalf("stats = %+v, want 3 datagrams (data, if-options, app-table) and 1 record", stats)
	}
	var seqs []uint32
	templates := map[uint16]bool{}
	for i := 0; i < 3; i++ {
		pkt := receivePacket(ch)
		if pkt == nil {
			t.Fatalf("datagram %d missing", i)
		}
		seqs = append(seqs, binary.BigEndian.Uint32(pkt[8:]))
		templates[binary.BigEndian.Uint16(pkt[20:])] = true // template id follows the 4-byte set header at offset 16, for a Template Set and an Options Template Set alike
	}
	for _, id := range []uint16{ipfixAVCTemplateID, ipfixOptionsTemplateID, ipfixAppTableTemplateID} {
		if !templates[id] {
			t.Fatalf("template %d not seen; saw %v", id, templates)
		}
	}
	// data (1 record) at 0; interface options (1 record) at 1; app table (3 records) at 2; final 5.
	if seqs[0] != 0 || seqs[1] != 1 || seqs[2] != 2 || fe.seqNo != 5 {
		t.Fatalf("sequences = %v, seqNo = %d; want [0 1 2] and 5", seqs, fe.seqNo)
	}
}

// TestIPFIXAVCTickDropCountsInScenarioLedger is the scenario-participant arm
// of TestIPFIXAVCTickDropsUnsendableRecord: with a running scenario installed
// on the exporter, a record dropped because it fits no datagram must still be
// counted in the scenario ledger (emitted + sendFailures), not just in the
// plain FlowTickStats. Two records are queued: one whose host is too large to
// ever fit a datagram, one that fits.
func TestIPFIXAVCTickDropCountsInScenarioLedger(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	cat := newAVCCatalog([]avcApplication{{ID: avcApplicationID(13, 80), Name: "http",
		Hosts: []string{"ok.example", strings.Repeat("z", 1500)}}})
	enc := NewIPFIXAVCEncoder(cat)
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.53"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	fe.lastTempl = time.Now() // data-only tick
	past := time.Now().Add(-time.Hour)
	fe.cache.Add(avcRecord(1, 2, 0, 49152), past) // 1500-byte host: never fits
	fe.cache.Add(avcRecord(1, 1, 0, 49153), past)

	now := time.Now()
	gate := &atomic.Pointer[gateState]{}
	gate.Store(&gateState{phase: phaseRunning, t0: now.Add(-time.Minute), t1: now.Add(time.Hour)})
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now, owner: "test"}
	fe.scenPart.Store(part)

	stats := tickWithEncoder(fe, now, enc, conn, addr, testPool())
	if stats.SendFailures != 1 || stats.RecordsSent != 1 || stats.PacketsSent != 1 {
		t.Fatalf("stats = %+v, want SendFailures 1, RecordsSent 1, PacketsSent 1", stats)
	}
	if pkt := receivePacket(ch); pkt == nil {
		t.Fatal("the sendable record never arrived")
	}

	if got := led.emitted.Load(); got != 2 {
		t.Fatalf("ledger emitted = %d, want 2 (both records generated, one dropped, one sent)", got)
	}
	if got := led.sendFailures.Load(); got != 1 {
		t.Fatalf("ledger sendFailures = %d, want 1", got)
	}
	if got := led.inWindow.Load(); got != 1 {
		t.Fatalf("ledger inWindow = %d, want 1 (only the sent record counts as in-window traffic)", got)
	}
}

// TestFlowOptionsWriteFailureCountsSendFailure is the write-failure arm of
// Tick's options datagrams (Task 4 of the final review): a refused write on
// the interface option table or the application table must count as a send
// failure, must NOT count toward PacketsSent/BytesSent, and must still
// advance fe.seqNo/the remainder as though the datagram had been sent
// (nl6#491's rule, now applied at these two sites too). Driven on a
// template-refresh tick of an AVC exporter with an if-scoped interface
// option table, so all three datagrams (data, interface options, app table)
// are attempted and all three writes are made to fail via writeOverride.
func TestFlowOptionsWriteFailureCountsSendFailure(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn := testSender(t)
	defer conn.Close()

	enc := NewIPFIXAVCEncoder(testAVCCatalog())
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.54"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	fe.optionShape = flowOptionShapeIfScoped
	fe.optionIfaces = []flowOptionIface{{ifIndex: 1, name: "Gi0/1"}}
	fe.cache.Add(avcRecord(1, 1, 1, 49152), time.Now().Add(-time.Hour))
	// lastTempl left at zero: this is the first, template-refresh tick, so
	// the data template, the interface option table AND the application
	// table are all attempted.
	failEverything := errors.New("induced write failure")
	fe.writeOverride = func([]byte) error { return failEverything }

	stats := tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())

	// Three datagrams are attempted on this tick: data (1 record), interface
	// options (1 record), application table (3 records, all of testAVCCatalog).
	// Every write fails, so nothing was ever handed to the kernel.
	if stats.PacketsSent != 0 {
		t.Fatalf("PacketsSent = %d, want 0 (every write failed)", stats.PacketsSent)
	}
	if stats.SendFailures != 3 {
		t.Fatalf("SendFailures = %d, want 3 (data, interface options, application table)", stats.SendFailures)
	}
	// The sequence still advances as though every datagram had been sent
	// successfully: data (1) + interface options (1) + app table (3) = 5,
	// matching TestIPFIXAVCTickEmitsApplicationTable's success-path total.
	if fe.seqNo != 5 {
		t.Fatalf("seqNo = %d, want 5 (advances on a failed write, nl6#491)", fe.seqNo)
	}
}

// TestIPFIXAVCEncodeBufferTooSmall pins the Data Set header write added to
// close Minor 6: EncodeMeasured must check room for the 4-byte Data Set
// header before writing it, the same way it already checks room for the
// message header. Without the guard a buffer that fits the message header
// (and template) but not four more bytes panics on the header write instead
// of returning nl6's usual "buffer too small" error.
func TestIPFIXAVCEncodeBufferTooSmall(t *testing.T) {
	enc := NewIPFIXAVCEncoder(testAVCCatalog())
	rec := []FlowRecord{avcRecord(1, 1, 1, 49152)}

	// Shorter than the message header: the existing top-of-function guard.
	tooShortForHeader := make([]byte, ipfixHeaderSize-1)
	if _, _, _, err := enc.EncodeMeasured(1, 0, 0, rec, false, tooShortForHeader); err == nil {
		t.Fatal("buffer shorter than the message header must error, got nil")
	}

	// Room for the message header but not the 4-byte Data Set header: [16, 20).
	for n := ipfixHeaderSize; n < ipfixHeaderSize+ipfixDataSetHdrSize; n++ {
		buf := make([]byte, n)
		if _, _, _, err := enc.EncodeMeasured(1, 0, 0, rec, false, buf); err == nil {
			t.Fatalf("n=%d: buffer with no room for the Data Set header must error, got nil", n)
		}
	}

	// buf == overhead, no records, includeTemplate=true: a template-only
	// message that needs no Data Set header at all.
	overhead := ipfixHeaderSize + len(ipfixAVCTemplateSetBytes)
	buf := make([]byte, overhead)
	n, consumed, dropped, err := enc.EncodeMeasured(1, 0, 0, nil, true, buf)
	if err != nil || n != overhead || consumed != 0 || dropped != 0 {
		t.Fatalf("template-only at buf==overhead: n=%d consumed=%d dropped=%d err=%v, want %d,0,0,nil", n, consumed, dropped, err, overhead)
	}
}
