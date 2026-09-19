/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"strconv"
	"strings"
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
// host and URI statistics come back as written; a record with no
// application carries applicationId 0 and two zero-length fields.
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
	want := append([]byte("/index.html\x00"), 0, 1)
	if string(got[0].URIStats) != string(want) {
		t.Fatalf("record 0 uri stats = %q, want %q (URI, NUL, uint16 BE count 1)", got[0].URIStats, want)
	}
	if got[1].AppID != avcApplicationID(13, 443) || got[1].Host != "" || len(got[1].URIStats) != 0 {
		t.Fatalf("record 1 (ssl, no host) = %+v", got[1])
	}
	if got[2].AppID != 0 || got[2].Host != "" || got[2].Base.SrcPort != 50002 {
		t.Fatalf("record 2 (no application) = %+v", got[2])
	}
	if n%4 != 0 {
		t.Fatalf("message length %d is not 4-byte aligned", n)
	}
}

// Host lengths at the RFC 7011 section 7 boundary survive the round trip.
func TestIPFIXAVCEncodeHostLengthBoundary(t *testing.T) {
	for _, hl := range []int{1, 254, 255, 256} {
		cat := newAVCCatalog([]avcApplication{{ID: avcApplicationID(13, 80), Name: "http", Hosts: []string{strings.Repeat("h", hl)}}})
		enc := NewIPFIXAVCEncoder(cat)
		buf := make([]byte, 1472)
		n, consumed, _, err := enc.EncodeMeasured(1, 0, 0, []FlowRecord{avcRecord(1, 1, 0, 1)}, false, buf)
		if err != nil || consumed != 1 {
			t.Fatalf("hl=%d: consumed=%d err=%v", hl, consumed, err)
		}
		got := decodeIPFIXAVCRecords(t, decodeIPFIXPacket(t, buf[:n]).RawSets[ipfixAVCTemplateID])
		if len(got) != 1 || len(got[0].Host) != hl {
			t.Fatalf("hl=%d: decoded host length %d", hl, len(got[0].Host))
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
	// Each record is 54 + 4 + (1+15) + (1+14) = 89 bytes; header 16 + set 4.
	// +3 (not +2): EncodeMeasured reserves a 3-byte worst-case pad margin
	// (limit := len(buf)-3) while probing whether a record fits, so exactly
	// 3*89 bytes of headroom beyond the base overhead is required for the
	// third record's last write to land inside that margin.
	buf := make([]byte, 20+89*3+3)
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
	if len(seen) != 120 || stats.RecordsSent != 120 || fe.seqNo != 120 {
		t.Fatalf("wire=%d RecordsSent=%d seqNo=%d, want 120 each", len(seen), stats.RecordsSent, fe.seqNo)
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
