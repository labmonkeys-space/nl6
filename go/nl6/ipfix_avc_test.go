/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strconv"
	"testing"
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
