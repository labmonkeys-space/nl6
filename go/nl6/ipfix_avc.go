/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "encoding/binary"

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
