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

	// Cisco enterprise-specific layer-7 IEs (PEN 9), IPFIX only.
	ciscoHTTPHost          = 45003 // collect application http host; variable-length string
	ciscoHTTPURIStatistics = 42125 // collect application http uri statistics; see ipfixURIStatsLayout

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
