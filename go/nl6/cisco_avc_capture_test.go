/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// The reference capture (testdata/cisco-avc/capture/) is IPFIX exported by a
// REAL IOS-XE 26.01.02, the first Cisco-originated bytes this evidence base
// has. These tests read the facts out of it with an independent template
// parser written here, not with nl6's encoders or test decoders, so a shared
// misreading cannot make them agree. Each test pins one fact NOTES.md quotes.
//
// Two of the facts were the residuals the design spec left open: the IE 9357
// layout (nl6's two encoder decisions are confirmed) and the IE 12235 host
// layout (the router prefixes the host with six constant bytes; nl6 emits
// them since nl6#679). Both are checked against the PRODUCTION encoder, not
// against a copy of its constants, so the capture and the encoder cannot
// drift apart. The remaining structural differences are the decision in
// nl6#680.

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ciscoAVCCapturePath = "testdata/cisco-avc/capture/c8000v-26.01.02-avc.pcap"

type captureField struct {
	id, pen, length uint16 // length 0xFFFF = variable
}

type captureTemplate struct {
	fields []captureField
	scope  uint16 // scope field count; 0 for a data template
}

type captureRecord struct {
	odid   uint32
	tid    uint16
	values map[captureField][]byte
}

// pcapUDPPayloads walks a libpcap file (Ethernet or Linux cooked link type)
// and yields IPv4/UDP payloads with the IP datagram length.
func pcapUDPPayloads(t *testing.T, path string) (payloads [][]byte, ipLens []int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(raw) < 24 {
		t.Fatalf("%s: too short for a pcap header", path)
	}
	var order binary.ByteOrder
	switch binary.LittleEndian.Uint32(raw[:4]) {
	case 0xA1B2C3D4, 0xA1B23C4D:
		order = binary.LittleEndian
	case 0xD4C3B2A1, 0x4D3CB2A1:
		order = binary.BigEndian
	default:
		t.Fatalf("%s: not a libpcap file (magic %x)", path, raw[:4])
	}
	linkType := order.Uint32(raw[20:24])
	pos := 24
	for pos+16 <= len(raw) {
		incl := int(order.Uint32(raw[pos+8 : pos+12]))
		pos += 16
		if pos+incl > len(raw) {
			t.Fatalf("%s: truncated packet at %d", path, pos)
		}
		pkt := raw[pos : pos+incl]
		pos += incl
		var ipOff int
		switch linkType {
		case 1: // Ethernet
			if len(pkt) < 14 || pkt[12] != 0x08 || pkt[13] != 0x00 {
				continue
			}
			ipOff = 14
		case 113: // Linux cooked
			ipOff = 16
		default:
			t.Fatalf("%s: unsupported link type %d", path, linkType)
		}
		ip := pkt[ipOff:]
		if len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != 17 {
			continue
		}
		ihl := int(ip[0]&0x0F) * 4
		ipLen := int(binary.BigEndian.Uint16(ip[2:4]))
		udp := ip[ihl:]
		if len(udp) < 8 {
			continue
		}
		ulen := int(binary.BigEndian.Uint16(udp[4:6]))
		if ulen < 8 || ulen > len(udp) {
			continue
		}
		payloads = append(payloads, udp[8:ulen])
		ipLens = append(ipLens, ipLen)
	}
	return payloads, ipLens
}

// decodeCapture parses every IPFIX message, learning templates per domain and
// decoding data and option data records against them. Records whose template
// has not been seen yet (the capture starts mid-stream) are counted, not
// failed, because RFC 7011 lets a template arrive later.
func decodeCapture(t *testing.T) (templates map[[2]uint32]captureTemplate, records []captureRecord, orphanRecords int, maxIPLen int, messages int) {
	t.Helper()
	payloads, ipLens := pcapUDPPayloads(t, ciscoAVCCapturePath)
	templates = map[[2]uint32]captureTemplate{}
	for i, p := range payloads {
		if len(p) < 16 || binary.BigEndian.Uint16(p[:2]) != 10 {
			continue
		}
		messages++
		if ipLens[i] > maxIPLen {
			maxIPLen = ipLens[i]
		}
		msgLen := int(binary.BigEndian.Uint16(p[2:4]))
		if msgLen > len(p) {
			t.Fatalf("message %d declares %d bytes, payload is %d", messages, msgLen, len(p))
		}
		odid := binary.BigEndian.Uint32(p[12:16])
		pos := 16
		for pos+4 <= msgLen {
			setID := binary.BigEndian.Uint16(p[pos : pos+2])
			setLen := int(binary.BigEndian.Uint16(p[pos+2 : pos+4]))
			if setLen < 4 || pos+setLen > msgLen {
				t.Fatalf("message %d: set %d length %d overruns the message", messages, setID, setLen)
			}
			body := p[pos+4 : pos+setLen]
			switch {
			case setID == 2 || setID == 3:
				parseCaptureTemplateSet(t, templates, odid, setID, body)
			case setID >= 256:
				tpl, ok := templates[[2]uint32{odid, uint32(setID)}]
				if !ok {
					orphanRecords++
					break
				}
				records = append(records, decodeCaptureRecords(t, odid, setID, tpl, body)...)
			}
			pos += setLen
		}
	}
	return templates, records, orphanRecords, maxIPLen, messages
}

func parseCaptureTemplateSet(t *testing.T, templates map[[2]uint32]captureTemplate, odid uint32, setID uint16, body []byte) {
	t.Helper()
	pos := 0
	for pos+4 <= len(body) {
		tid := binary.BigEndian.Uint16(body[pos : pos+2])
		count := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if tid == 0 { // padding
			return
		}
		var scope uint16
		if setID == 3 {
			scope = binary.BigEndian.Uint16(body[pos : pos+2])
			pos += 2
		}
		tpl := captureTemplate{scope: scope}
		for i := 0; i < count; i++ {
			id := binary.BigEndian.Uint16(body[pos : pos+2])
			length := binary.BigEndian.Uint16(body[pos+2 : pos+4])
			pos += 4
			var pen uint32
			if id&0x8000 != 0 {
				pen = binary.BigEndian.Uint32(body[pos : pos+4])
				pos += 4
				id &= 0x7FFF
			}
			tpl.fields = append(tpl.fields, captureField{id: id, pen: uint16(pen), length: length})
		}
		key := [2]uint32{odid, uint32(tid)}
		if prev, seen := templates[key]; seen && (prev.scope != tpl.scope || !equalCaptureFields(prev.fields, tpl.fields)) {
			t.Fatalf("odid %d template %d was re-sent with a different definition", odid, tid)
		}
		templates[key] = tpl
	}
}

func equalCaptureFields(a, b []captureField) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func decodeCaptureRecords(t *testing.T, odid uint32, tid uint16, tpl captureTemplate, body []byte) []captureRecord {
	t.Helper()
	minLen := 0
	for _, f := range tpl.fields {
		if f.length == 0xFFFF {
			minLen++
		} else {
			minLen += int(f.length)
		}
	}
	var out []captureRecord
	pos := 0
	for pos+minLen <= len(body) {
		rec := captureRecord{odid: odid, tid: tid, values: map[captureField][]byte{}}
		for _, f := range tpl.fields {
			var v []byte
			if f.length == 0xFFFF {
				n := int(body[pos])
				pos++
				if n == 255 {
					n = int(binary.BigEndian.Uint16(body[pos : pos+2]))
					pos += 2
				}
				v = body[pos : pos+n]
				pos += n
			} else {
				v = body[pos : pos+int(f.length)]
				pos += int(f.length)
			}
			rec.values[f] = v
		}
		out = append(out, rec)
	}
	return out
}

func captureDataRecords(t *testing.T) (records []captureRecord, tpl captureTemplate) {
	t.Helper()
	templates, all, _, _, _ := decodeCapture(t)
	var found bool
	for key, cand := range templates {
		if key[1] == 258 {
			tpl, found = cand, true
		}
	}
	if !found {
		t.Fatal("capture carries no template 258")
	}
	for _, r := range all {
		if r.tid == 258 {
			records = append(records, r)
		}
	}
	if len(records) != 1302 {
		t.Fatalf("capture carries %d AVC data records, README says 1302", len(records))
	}
	return records, tpl
}

// The router's AVC data template, in wire order. Match fields first, the two
// variable-length fields BEFORE the counters, URI statistics before host,
// and a connection id (PEN 9 IE 12242) IOS-XE would not bind the monitor
// without. nl6's template 258 differs on every one of those points (nl6#680).
func TestCiscoAVCCapture_DataTemplateFieldOrder(t *testing.T) {
	_, tpl := captureDataRecords(t)
	want := []captureField{
		{8, 0, 4}, {12, 0, 4}, {60, 0, 1}, {4, 0, 1}, {7, 0, 2}, {11, 0, 2}, {10, 0, 4},
		{12242, 9, 4}, {95, 0, 4}, {14, 0, 4}, {61, 0, 1},
		{9357, 9, 0xFFFF}, {12235, 9, 0xFFFF},
		{1, 0, 8}, {2, 0, 8}, {152, 0, 8}, {153, 0, 8},
	}
	if tpl.scope != 0 || !equalCaptureFields(tpl.fields, want) {
		t.Fatalf("template 258:\n got %v\nwant %v", tpl.fields, want)
	}
}

// Every IE 12235 value starts with the six-byte prefix; a record without a
// host carries the prefix and nothing else; the field is never empty. This is
// the fact nl6#679 fixes against.
func TestCiscoAVCCapture_HTTPHostCarriesConstantPrefix(t *testing.T) {
	records, _ := captureDataRecords(t)
	hostField := captureField{12235, 9, 0xFFFF}
	hosts := map[string]int{}
	for _, r := range records {
		v := r.values[hostField]
		if !bytes.HasPrefix(v, avcHostPrefix) {
			t.Fatalf("IE 12235 value %x does not start with %x", v, avcHostPrefix)
		}
		if name := string(v[len(avcHostPrefix):]); name != "" {
			hosts[name]++
		}
	}
	wantHosts := map[string]int{"www.example.com": 80, "api.example.com": 80, "cdn.example.net": 80, "login.example.org": 80, "static.example.com": 80}
	for name, n := range wantHosts {
		if hosts[name] != n {
			t.Fatalf("host %q seen %d times, want %d (traffic.sh: 4 URIs x 20 rounds); all: %v", name, hosts[name], n, hosts)
		}
	}
	if len(hosts) != len(wantHosts) {
		t.Fatalf("unexpected hosts: %v", hosts)
	}
}

// IE 9357 is `URI` NUL then a 2-byte BIG-ENDIAN hit count with NO trailing
// delimiter, which confirms both encoder decisions at uriStatsValue; the URI
// is the FIRST PATH SEGMENT only. Checked against nl6's encoder by value.
func TestCiscoAVCCapture_URIStatisticsLayout(t *testing.T) {
	records, _ := captureDataRecords(t)
	uriField := captureField{9357, 9, 0xFFFF}
	uris := map[string]int{}
	for _, r := range records {
		v := r.values[uriField]
		if len(v) == 0 {
			continue
		}
		nul := bytes.IndexByte(v, 0)
		if nul < 0 || len(v) != nul+3 {
			t.Fatalf("IE 9357 value %x is not URI NUL count16", v)
		}
		if count := binary.BigEndian.Uint16(v[nul+1:]); count != 1 {
			t.Fatalf("IE 9357 value %x: big-endian count %d, want 1 (one request per connection)", v, count)
		}
		uri := string(v[:nul])
		if strings.Count(uri, "/") != 1 {
			t.Fatalf("IE 9357 URI %q is not a single path segment", uri)
		}
		uris[uri]++
		if got := uriStatsValue(uri, 1); !bytes.Equal(got, v) {
			t.Fatalf("nl6 uriStatsValue(%q, 1) = %x, router emitted %x", uri, got, v)
		}
	}
	// traffic.sh requests /, /api/v1, /static/app.js and /api/login: the
	// router keeps the first segment, so /api carries two of the four.
	want := map[string]int{"/": 100, "/api": 200, "/static": 100}
	for k, n := range want {
		if uris[k] != n {
			t.Fatalf("URI %q seen %d times, want %d; all: %v", k, uris[k], n, uris)
		}
	}
	if len(uris) != len(want) {
		t.Fatalf("unexpected URIs: %v", uris)
	}
}

// Host and URI ride only the ingress-direction record of an http-classified
// request; the reverse-direction record and every non-http record carry the
// bare prefix and an empty URI field. Also pins the http applicationId as
// engine 3 / selector 80, the engine nl6's port-based entries use.
func TestCiscoAVCCapture_LayerSevenValuesAreIngressHTTPOnly(t *testing.T) {
	records, _ := captureDataRecords(t)
	appField := captureField{95, 0, 4}
	dirField := captureField{61, 0, 1}
	hostField := captureField{12235, 9, 0xFFFF}
	uriField := captureField{9357, 9, 0xFFFF}
	const httpID = 0x03000050
	var withL7, httpIngress uint64
	for _, r := range records {
		app := binary.BigEndian.Uint32(r.values[appField])
		ingress := r.values[dirField][0] == 0
		hasHost := len(r.values[hostField]) > len(avcHostPrefix)
		hasURI := len(r.values[uriField]) > 0
		if hasHost != hasURI {
			t.Fatalf("record app=%08x dir=%d has host=%v uri=%v; the router sets both or neither", app, r.values[dirField][0], hasHost, hasURI)
		}
		if hasHost {
			withL7++
			if app != httpID || !ingress {
				t.Fatalf("layer-7 values on app=%08x ingress=%v; want http (%08x) ingress only", app, ingress, httpID)
			}
		}
		if app == httpID && ingress {
			httpIngress++
		}
	}
	if withL7 != 400 || httpIngress != 400 {
		t.Fatalf("records with host+URI = %d, http ingress records = %d; want 400 and 400", withL7, httpIngress)
	}
}

// The options templates: the application table matches nl6's string lengths
// exactly (24 / 55); the interface table does not (33 / 65 plus an
// egressInterface, where nl6 sends 32 / 32). Cisco numbers them 256 and 257,
// with the data template at 258.
func TestCiscoAVCCapture_OptionsTemplates(t *testing.T) {
	templates, records, _, _, _ := decodeCapture(t)
	get := func(tid uint32) captureTemplate {
		for key, tpl := range templates {
			if key[1] == tid {
				return tpl
			}
		}
		t.Fatalf("no template %d in the capture", tid)
		return captureTemplate{}
	}
	iface := get(256)
	wantIface := []captureField{{10, 0, 4}, {82, 0, 33}, {83, 0, 65}, {14, 0, 4}}
	if iface.scope != 1 || !equalCaptureFields(iface.fields, wantIface) {
		t.Fatalf("interface options template 256: scope %d fields %v, want scope 1 %v", iface.scope, iface.fields, wantIface)
	}
	app := get(257)
	wantApp := []captureField{{95, 0, 4}, {96, 0, ipfixApplicationNameLen}, {94, 0, ipfixApplicationDescriptionLen}}
	if app.scope != 1 || !equalCaptureFields(app.fields, wantApp) {
		t.Fatalf("application table options template 257: scope %d fields %v, want scope 1 %v", app.scope, app.fields, wantApp)
	}
	names := map[uint32]string{}
	engines := map[byte]int{}
	for _, r := range records {
		if r.tid != 257 {
			continue
		}
		id := binary.BigEndian.Uint32(r.values[captureField{95, 0, 4}])
		name := string(bytes.TrimRight(r.values[captureField{96, 0, 24}], "\x00"))
		if prev, ok := names[id]; ok && prev != name {
			t.Fatalf("applicationId %08x named %q and %q", id, prev, name)
		}
		if _, ok := names[id]; !ok {
			engines[byte(id>>24)]++
		}
		names[id] = name
	}
	if len(names) != 1560 || engines[1] != 127 || engines[3] != 748 || engines[13] != 685 {
		t.Fatalf("application table: %d ids, engines %v; want 1560 across 1:127 3:748 13:685", len(names), engines)
	}
	for id, want := range map[uint32]string{0x03000050: "http", 0x03000035: "dns", 0x03000016: "ssh", 0x01000001: "icmp", 0x0d000001: "unknown", 0x0d0001af: "binary-over-http", 0x0d0001df: "ping"} {
		if names[id] != want {
			t.Fatalf("applicationId %08x is %q in the table, want %q", id, names[id], want)
		}
	}
}

// Message-level facts nl6 already matches: no datagram above the 1500-byte
// frame, and the sequence number counts data records including option data
// records (a message's sequence equals the previous message's plus its
// record count, per domain, once the stream is established).
func TestCiscoAVCCapture_MessageShape(t *testing.T) {
	_, _, orphans, maxIPLen, messages := decodeCapture(t)
	if messages < 300 || maxIPLen > 1500 || maxIPLen < 1400 {
		t.Fatalf("messages=%d maxIPLen=%d; README says 395 messages and a 1420-byte maximum", messages, maxIPLen)
	}
	if orphans > 1 {
		t.Fatalf("%d records arrived before their template; the capture starts mid-stream so at most one set may", orphans)
	}
	payloads, _ := pcapUDPPayloads(t, ciscoAVCCapturePath)
	type msg struct {
		seq   uint32
		count uint32
	}
	last := map[uint32]msg{}
	checked, gaps := 0, 0
	templates := map[[2]uint32]captureTemplate{}
	for _, p := range payloads {
		if len(p) < 16 || binary.BigEndian.Uint16(p[:2]) != 10 {
			continue
		}
		odid := binary.BigEndian.Uint32(p[12:16])
		seq := binary.BigEndian.Uint32(p[8:12])
		msgLen := int(binary.BigEndian.Uint16(p[2:4]))
		var count uint32
		complete := true
		for pos := 16; pos+4 <= msgLen; {
			setID := binary.BigEndian.Uint16(p[pos : pos+2])
			setLen := int(binary.BigEndian.Uint16(p[pos+2 : pos+4]))
			body := p[pos+4 : pos+setLen]
			if setID == 2 || setID == 3 {
				parseCaptureTemplateSet(t, templates, odid, setID, body)
			} else if setID >= 256 {
				tpl, ok := templates[[2]uint32{odid, uint32(setID)}]
				if !ok {
					complete = false
				} else {
					count += uint32(len(decodeCaptureRecords(t, odid, setID, tpl, body)))
				}
			}
			pos += setLen
		}
		if prev, ok := last[odid]; ok && complete {
			checked++
			if seq != prev.seq+prev.count {
				gaps++
			}
		}
		last[odid] = msg{seq, count}
	}
	if checked < 300 || gaps > 1 {
		t.Fatalf("sequence rule checked on %d messages with %d gaps; want hundreds and at most the capture-start gap", checked, gaps)
	}
}

func TestCiscoAVCCapture_FilesArePresent(t *testing.T) {
	dir := filepath.Dir(ciscoAVCCapturePath)
	for _, f := range []string{"README.md", "avc.clab.yml", "r1.cfg", "r1-running.cfg", "traffic.sh"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v (the capture must stay regenerable)", f, err)
		}
	}
}
