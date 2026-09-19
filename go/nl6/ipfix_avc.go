/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Cisco AVC (NBAR2) export over IPFIX. Every number below is DERIVED from
// testdata/cisco-avc/elements.tsv and pinned by TestIPFIXAVCConstantsMatchEvidence;
// the provenance of each row is in testdata/cisco-avc/NOTES.md. Do not add an
// IE here without a row there.
const (
	// ciscoPEN is Cisco's IANA Private Enterprise Number.
	ciscoPEN = 9

	// IANA-registered application identity IEs (RFC 6759 sections 7.1.1 to 7.1.3).
	ipfixApplicationID          = 95 // applicationId: engine id (8 bits) + selector (24 bits)
	ipfixApplicationName        = 96 // applicationName, fixed 24 bytes in Cisco's option application-table
	ipfixApplicationDescription = 94 // applicationDescription, fixed 55 bytes in Cisco's option application-table

	// Cisco enterprise-specific layer-7 IEs (PEN 9), IPFIX only. The IE id is
	// the low 15 bits, RFC 7011 section 3.2's "Information Element
	// identifier"; ciscoHTTPHost = 12235 and ciscoHTTPURIStatistics = 9357
	// are those 15-bit ids, matching libfds. Cisco's 2015 AVC guide instead
	// quotes the field specifier as it appears on the wire in a template,
	// enterprise bit already set (45003 = 0x8000|12235, 42125 = 0x8000|9357);
	// that wire-level specifier is not a second IE number, and a decoder
	// reports the IE id (12235 / 9357) beside PEN 9, never the specifier.
	ciscoHTTPHost          = 12235 // collect application http host; variable-length string
	ciscoHTTPURIStatistics = 9357  // collect application http uri statistics; see ipfixURIStatsLayout

	// ciscoHTTPHostWireSpecifier and ciscoHTTPURIStatisticsWireSpecifier are
	// the wire-level field specifiers Cisco's guide quotes (enterprise bit
	// included); ciscoHTTPHostWireSpecifier == ipfixEnterpriseBit|ciscoHTTPHost
	// and likewise for the URI statistics pair. Kept as named constants so a
	// reader checking the guide's own numbers against this file does not
	// have to compute the OR by hand.
	ciscoHTTPHostWireSpecifier          = 45003
	ciscoHTTPURIStatisticsWireSpecifier = 42125

	// Fixed lengths Cisco's 2015 AVC guide gives for option application-table.
	ipfixApplicationNameLen        = 24
	ipfixApplicationDescriptionLen = 55

	// Template ids. 256 is the plain data template and 257 the interface
	// option table (both existing); the AVC pair sits beside them so one
	// device can carry all four.
	ipfixAVCTemplateID      = 258
	ipfixAppTableTemplateID = 259

	// ipfixEnterpriseBit marks an enterprise-specific IE in a template field
	// specifier (RFC 7011 section 3.2); the 4-byte PEN follows the length.
	ipfixEnterpriseBit = 0x8000

	// ipfixVarLen is the template length that declares a variable-length
	// field (RFC 7011 section 7).
	ipfixVarLen = 0xFFFF
)

// ipfixURIStatsLayout documents the two decisions unit 1 left to the encoder
// for IE 42125 (testdata/cisco-avc/NOTES.md, "HTTP URI statistics (42125)
// layout"). Cisco's text gives "NULL (\0) is the delimiter." and the encoding
// example {URI\0countURI\0count}; it states no byte order and its prose
// format line shows a trailing delimiter its encoding example does not.
//
// Decision 1: the 2-byte hit count is BIG-ENDIAN, RFC 7011 section 6.1.1's
// network byte order for integers. Decision 2: the encoding example governs,
// so a record is `URI\0` + count, repeated, with NO trailing delimiter.
// Neither is Cisco-sourced; a capture from a real IOS-XE box would settle
// both, and the spec's fidelity exit rule applies to them until then.
const ipfixURIStatsLayout = "URI\\0 + uint16 big-endian count, repeated, no trailing delimiter"

// ipfixVarLenSize is the on-wire size of an n-byte variable-length value
// including its RFC 7011 section 7 length prefix.
func ipfixVarLenSize(n int) int {
	if n < 255 {
		return 1 + n
	}
	return 3 + n
}

// putIPFIXVarLen writes v at pos as an RFC 7011 section 7 variable-length
// field and returns the new position. ok is false, and buf is untouched,
// when the value does not fit; the caller decides what a non-fit means.
// Values longer than 65535 bytes cannot be represented and never fit.
func putIPFIXVarLen(buf []byte, pos int, v []byte) (int, bool) {
	n := len(v)
	if n > 0xFFFF || pos+ipfixVarLenSize(n) > len(buf) {
		return pos, false
	}
	if n < 255 {
		buf[pos] = byte(n)
		pos++
	} else {
		buf[pos] = 255
		binary.BigEndian.PutUint16(buf[pos+1:], uint16(n))
		pos += 3
	}
	copy(buf[pos:], v)
	return pos + n, true
}

// avcApplication is one NBAR2 application as the encoder needs it. Plan B's
// catalog loader produces these; here they are constructed directly.
type avcApplication struct {
	ID          uint32
	Name        string
	Description string
	Proto       uint8
	DstPort     uint16
	Hosts       []string
	URIs        []string
}

// avcCatalog is an immutable, 1-based indexed set of applications. Index 0
// means "no application" so a zero avcRef on a FlowRecord is a plain record.
// FlowRecords carry INDICES into this catalog rather than strings (spec
// section 3): at 30k devices x 256 flows the strings would cost ~300 MB.
type avcCatalog struct {
	apps []avcApplication
}

func newAVCCatalog(apps []avcApplication) *avcCatalog {
	c := &avcCatalog{apps: make([]avcApplication, len(apps))}
	copy(c.apps, apps)
	return c
}

// App returns the application at 1-based idx, or false for 0 or out of range.
func (c *avcCatalog) App(idx uint16) (*avcApplication, bool) {
	if c == nil || idx == 0 || int(idx) > len(c.apps) {
		return nil, false
	}
	return &c.apps[idx-1], true
}

func (c *avcCatalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.apps)
}

// avcApplicationID packs RFC 6759 section 4.1's applicationId: the
// classification engine id in the top 8 bits and the selector in the low 24.
func avcApplicationID(engine uint8, selector uint32) uint32 {
	return uint32(engine)<<24 | selector&0xFFFFFF
}

// avcRef is the per-record application reference: 1-based indices into the
// device's avcCatalog (App) and into that application's Hosts and URIs
// slices. 0 means absent. Six bytes per record, resolved at encode time.
type avcRef struct {
	App, Host, URI uint16
}

// ipfixFieldSpec is one template field specifier; pen 0 means IANA.
type ipfixFieldSpec struct {
	id, length uint16
	pen        uint32
}

// ipfixAVCFields is the AVC data template: the plain template's 19 IEs in
// the same order, then applicationId, then the two Cisco layer-7 fields.
// Keeping the plain prefix identical means a collector's decoder for 256
// reads the first 54 bytes of a 258 record unchanged.
var ipfixAVCFields = func() []ipfixFieldSpec {
	out := make([]ipfixFieldSpec, 0, len(ipfixFields)+3)
	for _, f := range ipfixFields {
		out = append(out, ipfixFieldSpec{id: f[0], length: f[1]})
	}
	return append(out,
		ipfixFieldSpec{id: ipfixApplicationID, length: 4},
		ipfixFieldSpec{id: ciscoHTTPHost, length: ipfixVarLen, pen: ciscoPEN},
		ipfixFieldSpec{id: ciscoHTTPURIStatistics, length: ipfixVarLen, pen: ciscoPEN},
	)
}()

// ipfixAVCTemplateSetBytes is the pre-encoded AVC Template Set, read-only
// after init.
var ipfixAVCTemplateSetBytes = buildIPFIXAVCTemplateSet()

// buildIPFIXAVCTemplateSet encodes the Template Set for ipfixAVCFields. An
// enterprise specifier is id|0x8000 (2) + length (2) + PEN (4), so the set
// length is computed from the field list rather than fixed.
func buildIPFIXAVCTemplateSet() []byte {
	length := 4 + 4
	for _, f := range ipfixAVCFields {
		if f.pen != 0 {
			length += 8
		} else {
			length += 4
		}
	}
	buf := make([]byte, length)
	pos := 0
	binary.BigEndian.PutUint16(buf[pos:], ipfixSetIDTemplate)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(length))
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], ipfixAVCTemplateID)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(len(ipfixAVCFields)))
	pos += 2
	for _, f := range ipfixAVCFields {
		id := f.id
		if f.pen != 0 {
			id |= ipfixEnterpriseBit
		}
		binary.BigEndian.PutUint16(buf[pos:], id)
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], f.length)
		pos += 2
		if f.pen != 0 {
			binary.BigEndian.PutUint32(buf[pos:], f.pen)
			pos += 4
		}
	}
	return buf
}

// IPFIXAVCEncoder emits the AVC data template (258) and records that
// resolve their avcRef against ONE catalog. It is constructed per catalog,
// not shared fleet-wide like IPFIXEncoder, because the record's indices
// are meaningless without the catalog they were drawn from (spec section 3).
// The catalog is immutable, so one encoder is still safe across goroutines.
type IPFIXAVCEncoder struct {
	cat *avcCatalog
}

func NewIPFIXAVCEncoder(cat *avcCatalog) *IPFIXAVCEncoder {
	return &IPFIXAVCEncoder{cat: cat}
}

// measuredFlowEncoder is the seam for encoders whose record size is not
// fixed. Tick hands it the whole expired slice and takes back how many
// records it emitted; the rest ride the next datagram. dropped is 1 when the
// first record could not fit an otherwise empty datagram: it is skipped,
// counted in consumed so the caller cannot retry it forever, and the caller
// counts it as a send failure. Like flowOptionsEncoder it is reached by
// type assertion, so fixed-size encoders are untouched.
type measuredFlowEncoder interface {
	EncodeMeasured(domainID, seqNo, uptimeMs uint32, records []FlowRecord, includeTemplate bool, buf []byte) (n, consumed, dropped int, err error)
}

func (e *IPFIXAVCEncoder) PacketSizes() (int, int, int) {
	return ipfixHeaderSize + ipfixDataSetHdrSize, len(ipfixAVCTemplateSetBytes), 0
}
func (e *IPFIXAVCEncoder) SeqIncrement(n int) int     { return n }
func (e *IPFIXAVCEncoder) TrailingPadBytes(int) int   { return 0 }
func (e *IPFIXAVCEncoder) MaxRecordsPerDatagram() int { return 0 }

// MaxRecordSize is the worst case over the catalog: the fixed prefix plus the
// longest host and the longest single-URI statistics value. Tick uses it only
// as a sanity bound; pagination is measured in EncodeMeasured.
func (e *IPFIXAVCEncoder) MaxRecordSize() int {
	maxHost, maxURI := 0, 0
	for i := 0; i < e.cat.Len(); i++ {
		app, _ := e.cat.App(uint16(i + 1))
		for _, h := range app.Hosts {
			if len(h) > maxHost {
				maxHost = len(h)
			}
		}
		for _, u := range app.URIs {
			if len(u)+3 > maxURI {
				maxURI = len(u) + 3 // URI + NUL + uint16 count
			}
		}
	}
	return ipfixRecordSize + 4 + ipfixVarLenSize(maxHost) + ipfixVarLenSize(maxURI)
}

// EncodePacket satisfies FlowEncoder for callers that do not use the measured
// seam; consumed is discarded, which is why Tick must use EncodeMeasured.
func (e *IPFIXAVCEncoder) EncodePacket(domainID, seqNo, uptimeMs uint32, records []FlowRecord, includeTemplate bool, buf []byte) (int, error) {
	n, _, _, err := e.EncodeMeasured(domainID, seqNo, uptimeMs, records, includeTemplate, buf)
	return n, err
}

// EncodeMeasured writes the message header, the AVC template when asked, and
// as many leading records as fit, padding the data Set to 4 bytes. Sizing is
// measured per record, never predicted: every bug in this family was a
// predicted size disagreeing with an emitted one.
func (e *IPFIXAVCEncoder) EncodeMeasured(domainID, seqNo, uptimeMs uint32, records []FlowRecord, includeTemplate bool, buf []byte) (int, int, int, error) {
	if len(records) == 0 && !includeTemplate {
		return 0, 0, 0, nil
	}
	nowMs := time.Now().UnixMilli()
	deviceStartMs := nowMs - int64(uptimeMs)
	if deviceStartMs < 0 {
		deviceStartMs = 0
	}
	overhead := ipfixHeaderSize
	if includeTemplate {
		overhead += len(ipfixAVCTemplateSetBytes)
	}
	if len(buf) < overhead {
		return 0, 0, 0, fmt.Errorf("ipfix avc: buffer too small (%d bytes), need at least %d", len(buf), overhead)
	}
	pos := 0
	binary.BigEndian.PutUint16(buf[pos:], ipfixVersion)
	pos += 2
	lengthOffset := pos
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], uint32(nowMs/1000))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], seqNo)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], domainID)
	pos += 4
	if includeTemplate {
		copy(buf[pos:], ipfixAVCTemplateSetBytes)
		pos += len(ipfixAVCTemplateSetBytes)
	}
	if len(records) == 0 {
		binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(pos))
		return pos, 0, 0, nil
	}
	// Data Set: header now, length backfilled. A record is written into the
	// remaining space minus the worst-case pad (3 bytes); if it does not fit,
	// the write position is rewound and the loop stops.
	setStart := pos
	binary.BigEndian.PutUint16(buf[pos:], ipfixAVCTemplateID)
	binary.BigEndian.PutUint16(buf[pos+2:], 0)
	pos += 4
	consumed := 0
	for _, r := range records {
		limit := len(buf) - 3
		if limit < pos {
			break
		}
		next, ok := e.encodeRecord(buf[:limit], pos, r, deviceStartMs)
		if !ok {
			break
		}
		pos = next
		consumed++
	}
	if consumed == 0 {
		// Nothing fit. If the datagram was otherwise empty this record can
		// never be sent: report it dropped and consumed so the caller moves on.
		if !includeTemplate {
			return 0, 1, 1, nil
		}
		// Template-carrying message with no room for a record: send the
		// template alone and let the caller retry the record in a data-only
		// datagram, which has more room.
		binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(setStart))
		return setStart, 0, 0, nil
	}
	if rem := (pos - setStart) % 4; rem != 0 {
		for i := 0; i < 4-rem; i++ {
			buf[pos] = 0
			pos++
		}
	}
	binary.BigEndian.PutUint16(buf[setStart+2:], uint16(pos-setStart))
	binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(pos))
	return pos, consumed, 0, nil
}

// encodeRecord writes the plain 54-byte prefix (reusing encodeIPFIXRecord so
// the two templates cannot drift), then applicationId and the two
// variable-length fields. Returns false, with nothing counted, when the
// record does not fit in buf.
func (e *IPFIXAVCEncoder) encodeRecord(buf []byte, pos int, r FlowRecord, deviceStartMs int64) (int, bool) {
	if pos+ipfixRecordSize+4 > len(buf) {
		return pos, false
	}
	start := pos
	pos = encodeIPFIXRecord(buf, pos, r, deviceStartMs)
	var appID uint32
	var host, uriStats []byte
	if app, ok := e.cat.App(r.AVC.App); ok {
		appID = app.ID
		if h := int(r.AVC.Host); h > 0 && h <= len(app.Hosts) {
			host = []byte(app.Hosts[h-1])
		}
		if u := int(r.AVC.URI); u > 0 && u <= len(app.URIs) {
			uriStats = uriStatsValue(app.URIs[u-1], 1)
		}
	}
	binary.BigEndian.PutUint32(buf[pos:], appID)
	pos += 4
	var ok bool
	if pos, ok = putIPFIXVarLen(buf, pos, host); !ok {
		return start, false
	}
	if pos, ok = putIPFIXVarLen(buf, pos, uriStats); !ok {
		return start, false
	}
	return pos, true
}

// uriStatsValue renders one IE 42125 entry per ipfixURIStatsLayout: the URI,
// a NUL, then the hit count as uint16 big-endian, with no trailing delimiter.
// count is clamped to Cisco's stated maximum of 65535.
func uriStatsValue(uri string, count uint32) []byte {
	if count > math.MaxUint16 {
		count = math.MaxUint16
	}
	out := make([]byte, 0, len(uri)+3)
	out = append(out, uri...)
	out = append(out, 0, byte(count>>8), byte(count))
	return out
}

var _ FlowEncoder = (*IPFIXAVCEncoder)(nil)
var _ measuredFlowEncoder = (*IPFIXAVCEncoder)(nil)

// ipfixAppTableRecSize is one application-table option data record: the
// 4-byte applicationId scope, then the two fixed-width strings Cisco's
// option application-table emits.
const ipfixAppTableRecSize = 4 + ipfixApplicationNameLen + ipfixApplicationDescriptionLen

// ipfixAppTableTemplateSetBytes is the RFC 6759 section 4.3 options
// template: scope applicationId, non-scope applicationName and
// applicationDescription, at Cisco's fixed lengths. Built once, read-only.
var ipfixAppTableTemplateSetBytes = buildIPFIXAppTableTemplateSet()

func buildIPFIXAppTableTemplateSet() []byte {
	length := 4 + 6 + 3*4 // set hdr + (id, field count, scope count) + 3 specifiers = 22
	if rem := length % 4; rem != 0 {
		length += 4 - rem
	}
	buf := make([]byte, length)
	pos := 0
	binary.BigEndian.PutUint16(buf[pos:], ipfixSetIDOptionsTemplate)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(length))
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], ipfixAppTableTemplateID)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], 3) // field count incl. scope
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], 1) // scope field count
	pos += 2
	for _, f := range [][2]uint16{
		{ipfixApplicationID, 4},
		{ipfixApplicationName, ipfixApplicationNameLen},
		{ipfixApplicationDescription, ipfixApplicationDescriptionLen},
	} {
		binary.BigEndian.PutUint16(buf[pos:], f[0])
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], f[1])
		pos += 2
	}
	return buf
}

// appTableEncoder is the seam Tick uses to emit the application table on
// the template-refresh cadence, beside the interface option table.
type appTableEncoder interface {
	Applications() []avcApplication
	EncodeAppTableDatagram(domainID, seqNo uint32, apps []avcApplication, buf []byte) (n, consumed int, err error)
}

// Applications returns the catalog's applications in index order. The slice
// is the catalog's own and must not be modified.
func (e *IPFIXAVCEncoder) Applications() []avcApplication { return e.cat.apps }

// EncodeAppTableDatagram writes a self-contained message: header, the
// options template, and as many application records as fit. consumed <
// len(apps) means the caller re-invokes with the remainder. The set is padded
// to 4 bytes because 83-byte records are not aligned.
func (e *IPFIXAVCEncoder) EncodeAppTableDatagram(domainID, seqNo uint32, apps []avcApplication, buf []byte) (int, int, error) {
	if len(apps) == 0 {
		return 0, 0, nil
	}
	overhead := ipfixHeaderSize + len(ipfixAppTableTemplateSetBytes) + ipfixDataSetHdrSize
	if len(buf) < overhead+ipfixAppTableRecSize+3 {
		return 0, 0, fmt.Errorf("ipfix avc: buffer too small (%d bytes) for an application-table datagram, need at least %d", len(buf), overhead+ipfixAppTableRecSize+3)
	}
	pos := 0
	binary.BigEndian.PutUint16(buf[pos:], ipfixVersion)
	pos += 2
	lengthOffset := pos
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], uint32(time.Now().Unix()))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], seqNo)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], domainID)
	pos += 4
	copy(buf[pos:], ipfixAppTableTemplateSetBytes)
	pos += len(ipfixAppTableTemplateSetBytes)

	setStart := pos
	binary.BigEndian.PutUint16(buf[pos:], ipfixAppTableTemplateID)
	pos += 4
	maxFit := (len(buf) - pos - 3) / ipfixAppTableRecSize
	consumed := len(apps)
	if consumed > maxFit {
		consumed = maxFit
	}
	for _, app := range apps[:consumed] {
		binary.BigEndian.PutUint32(buf[pos:], app.ID)
		pos += 4
		pos = putFixedString(buf, pos, app.Name, ipfixApplicationNameLen)
		pos = putFixedString(buf, pos, app.Description, ipfixApplicationDescriptionLen)
	}
	if rem := (pos - setStart) % 4; rem != 0 {
		for i := 0; i < 4-rem; i++ {
			buf[pos] = 0
			pos++
		}
	}
	binary.BigEndian.PutUint16(buf[setStart+2:], uint16(pos-setStart))
	binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(pos))
	return pos, consumed, nil
}

// putFixedString writes s into a fixed-width NUL-padded field of n bytes,
// truncating at n, and returns the new position. putPaddedString is the
// 32-byte special case used by the interface option table.
func putFixedString(buf []byte, pos int, s string, n int) int {
	c := copy(buf[pos:pos+n], s)
	for i := pos + c; i < pos+n; i++ {
		buf[i] = 0
	}
	return pos + n
}

var _ appTableEncoder = (*IPFIXAVCEncoder)(nil)
