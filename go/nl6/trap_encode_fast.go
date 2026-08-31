/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Allocation-free SNMPv2c notification assembly for the trap fire hot path.
//
// This is a PARALLEL path to encodeV2cNotification in trap_v2c.go, not a
// replacement. The legacy encoder stays because it is the readable reference
// and because the shared BER primitives in snmp_encoding.go (encodeOID and
// friends) are also on the SNMP *polling* path, which has different pressures
// and its own test suite. Nothing here touches them.
//
// Why it exists: at saturation the trap scheduler goroutine spent ~17 % of all
// CPU in EncodeTrap and ~19 % in the GC servicing ~2.2 KB of garbage per trap,
// most of it intermediate []byte returned by encodeSequence / encodeOID /
// encodeInteger on their way to being appended into a parent slice. This file
// builds the whole message into one caller-supplied buffer instead.
//
// Two techniques do the work:
//
//  1. Reserve-and-patch nesting. BER needs a length before its contents, so the
//     legacy encoder builds innermost-first into separate slices. Here each
//     constructed TLV reserves a 4-byte header, appends its contents, then
//     writes the minimal-form header back and shifts the contents down if the
//     header came out shorter. The shift is a few hundred bytes of memmove and
//     costs far less than the allocations it removes. Length encoding stays
//     minimal-form (DER-compatible) — a non-minimal long form would be legal
//     BER but is not worth the interop risk against arbitrary collectors.
//
//  2. Pre-encoded constants (see trap_precompute.go). A catalog entry's trap
//     OID, enterprise OID and any non-templated varbind OID are fixed for the
//     life of the process, so their BER is built once at catalog load and
//     memcpy'd per fire.
//
// Correctness contract: for every input, this must produce output BYTE-FOR-BYTE
// identical to encodeV2cNotification. TestFastEncoderMatchesLegacy asserts that
// across every shipped catalog entry and a table of type/boundary cases. If you
// change either encoder, that test is the one that must stay green.

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// maxTrapPDU bounds an assembled notification so the resulting UDP datagram
// FRAME fits the link, not so the payload fills it.
//
// It was previously a literal 1500, justified as "matches the 1500-byte buffer
// the legacy path allocated" — the same buffer-versus-frame conflation that put
// NetFlow v9 at 1524 bytes on the wire (nl6#485). A notification at that bound
// produced a 1528-byte frame and fragmented. See nl6#487.
//
// Derived, not literal, so it tracks `-datagram-mtu`: a hardcoded value would
// silently ignore the flag and re-break on exactly the lower-MTU paths the flag
// exists to serve. Refreshed by recomputeDatagramBudgets (datagram_budget.go).
//
// No address-family branch, unlike flow's budget: trap collectors resolve as
// `udp4` only (trap_manager.go), so IPv6 headers never apply here.
//
// Read at three sites that must stay in agreement — the trapBufPool allocation
// and the reference-encoder scratch clamp (both trap_exporter.go) and the
// encode guard below. All read it lazily at fire time, so a startup-set value
// propagates; the clamp in particular exists to stop the reference encoder
// overrunning a pooled buffer and has to keep matching the pool.
var maxTrapPDU = defaultLinkMTU - ipv4HeaderBytes - udpHeaderBytes

// pduTooLargeError reports an assembled notification that exceeded the bound,
// carrying the size it reached.
//
// Typed rather than a bare fmt.Errorf because the size is the only actionable
// part of the message and callers need it programmatically: the catalog's
// load-time check reports "over budget by N" to the operator, and it cannot
// recover the size from len(dst) — a failed encode returns a nil slice, and the
// check's budget equals maxTrapPDU in production, so this guard always fires
// first (nl6#487 review).
type pduTooLargeError struct {
	size  int
	limit int
}

func (e *pduTooLargeError) Error() string {
	return fmt.Sprintf("encoded PDU (%d bytes) exceeds buffer (%d)", e.size, e.limit)
}

// tlvHdrReserve is the placeholder written when a TLV is opened. Four bytes
// covers tag + the 0x82 long form, which is enough for any content length below
// 65536 — and maxTrapPDU keeps us two orders of magnitude below that.
const tlvHdrReserve = 4

// beginTLV opens a TLV by reserving space for its header. The returned mark is
// passed to endTLV once the contents have been appended.
func beginTLV(dst []byte) ([]byte, int) {
	mark := len(dst)
	return append(dst, 0, 0, 0, 0), mark
}

// endTLV writes the tag and minimal-form length for the TLV opened at mark,
// shifting the contents down when the real header is shorter than the reserved
// four bytes.
func endTLV(dst []byte, mark int, tag byte) []byte {
	contentLen := len(dst) - mark - tlvHdrReserve
	var hdr [tlvHdrReserve]byte
	hdr[0] = tag
	n := 0
	switch {
	case contentLen < 0x80:
		hdr[1] = byte(contentLen)
		n = 2
	case contentLen < 0x100:
		hdr[1] = 0x81
		hdr[2] = byte(contentLen)
		n = 3
	default:
		hdr[1] = 0x82
		hdr[2] = byte(contentLen >> 8)
		hdr[3] = byte(contentLen)
		n = 4
	}
	if n < tlvHdrReserve {
		copy(dst[mark+n:], dst[mark+tlvHdrReserve:])
		dst = dst[:len(dst)-(tlvHdrReserve-n)]
	}
	copy(dst[mark:], hdr[:n])
	return dst
}

// appendLength appends a minimal-form BER length. Mirrors encodeLength.
func appendLength(dst []byte, length int) []byte {
	if length < 0x80 {
		return append(dst, byte(length))
	}
	var tmp [8]byte
	i := len(tmp)
	for length > 0 {
		i--
		tmp[i] = byte(length & 0xff)
		length >>= 8
	}
	dst = append(dst, byte(0x80|(len(tmp)-i)))
	return append(dst, tmp[i:]...)
}

// appendInteger appends a BER INTEGER. Mirrors encodeInteger, including its
// two's-complement handling of negative values.
func appendInteger(dst []byte, value int) []byte {
	var tmp [9]byte
	var body []byte
	switch {
	case value == 0:
		body = []byte{0x00}
	case value > 0:
		// Fixed-offset form: tmp[0] is a permanent 0x00 sign pad and the value
		// fills tmp[1:9] big-endian, so every index below is provably in
		// [0,8] — the previous reverse-fill loop was flagged by gosec (G602)
		// because its in-boundedness rested on int64's value range rather
		// than on anything a static analyser can see.
		binary.BigEndian.PutUint64(tmp[1:9], uint64(value))
		start := 1
		for start < 8 && tmp[start] == 0 {
			start++ // strip leading zeros; value > 0 guarantees a nonzero byte
		}
		if tmp[start]&0x80 != 0 {
			start-- // pull in the pad byte so the value stays positive
		}
		body = tmp[start:]
	default:
		u := uint64(value)
		switch {
		case value >= -128:
			tmp[0] = byte(u)
			body = tmp[:1]
		case value >= -32768:
			tmp[0], tmp[1] = byte(u>>8), byte(u)
			body = tmp[:2]
		case value >= -8388608:
			tmp[0], tmp[1], tmp[2] = byte(u>>16), byte(u>>8), byte(u)
			body = tmp[:3]
		default:
			tmp[0], tmp[1], tmp[2], tmp[3] = byte(u>>24), byte(u>>16), byte(u>>8), byte(u)
			body = tmp[:4]
		}
		if body[0]&0x80 == 0 {
			// Legacy encoder prefixes 0xFF to keep the value negative.
			dst = append(dst, ASN1_INTEGER)
			dst = appendLength(dst, len(body)+1)
			dst = append(dst, 0xFF)
			return append(dst, body...)
		}
	}
	dst = append(dst, ASN1_INTEGER)
	dst = appendLength(dst, len(body))
	return append(dst, body...)
}

// appendUnsigned32 appends an APPLICATION-tagged unsigned (Counter32, Gauge32,
// TimeTicks) with leading zero bytes stripped. Mirrors encodeUnsigned32 — note
// it does NOT add a positive-sign pad byte, because these types are unsigned.
func appendUnsigned32(dst []byte, tag byte, value uint32) []byte {
	var b [4]byte
	b[0], b[1], b[2], b[3] = byte(value>>24), byte(value>>16), byte(value>>8), byte(value)
	start := 0
	for start < 3 && b[start] == 0 {
		start++
	}
	dst = append(dst, tag)
	dst = appendLength(dst, 4-start)
	return append(dst, b[start:]...)
}

// appendOctetString appends a BER OCTET STRING. Mirrors encodeOctetString.
func appendOctetString(dst []byte, value string) []byte {
	dst = append(dst, ASN1_OCTET_STRING)
	dst = appendLength(dst, len(value))
	return append(dst, value...)
}

// appendOID appends a BER OBJECT IDENTIFIER parsed from dotted-decimal form.
// Mirrors encodeOID, including its degenerate "fewer than two components"
// case, which emits an empty OID rather than failing.
func appendOID(dst []byte, oid string) []byte {
	if len(oid) > 0 && oid[0] == '.' {
		oid = oid[1:]
	}
	// Component count mirrors strings.Split, including the empty components a
	// leading/trailing/doubled dot produces. encodeOID treats "fewer than two"
	// as a degenerate empty OID rather than an error, and so must this.
	nComp := 1
	for i := 0; i < len(oid); i++ {
		if oid[i] == '.' {
			nComp++
		}
	}
	if nComp < 2 {
		return append(dst, ASN1_OID, 0x00)
	}

	dst = append(dst, ASN1_OID)
	lenMark := len(dst)
	dst = append(dst, 0) // single-byte length placeholder; see the guard below
	bodyStart := len(dst)

	// The FIRST sub-identifier carries 40*first+second and is a base-128
	// varint like every other one (X.690 §8.19.4); emitting it as a single
	// byte fabricated OIDs (nl6#529). strconv errors are NOT swallowed here or
	// in encodeOID: yielding 0 for a non-numeric component was the second
	// route into the same fabrication ("1.3.x.7" became .1.3.0.7).
	idx, start, first := 0, 0, 0
	for i := 0; i <= len(oid); i++ {
		if i != len(oid) && oid[i] != '.' {
			continue
		}
		v, convErr := strconv.Atoi(oid[start:i])
		if convErr != nil || v < 0 {
			return append(dst[:lenMark-1], ASN1_OID, 0x00)
		}
		// idx 0 and 1 are bounded together by legalOIDArcPair below, on the
		// COMBINED value; only later arcs are bounded individually. Bounding
		// the raw second arc here instead made this encoder reject inputs
		// encodeOID accepted (FuzzOIDRoundTrip found "2.7000000000").
		if idx >= 2 && v > maxOIDSubIdentifier {
			return append(dst[:lenMark-1], ASN1_OID, 0x00)
		}
		switch idx {
		case 0:
			first = v
		case 1:
			// Varint, matching encodeOID: the first two arcs share one
			// sub-identifier and it is not always one byte (nl6#529).
			// An arc pair X.690 cannot represent takes encodeOID's degenerate
			// path, or the two encoders stop agreeing byte for byte.
			if !legalOIDArcPair(first, v) {
				return append(dst[:lenMark-1], ASN1_OID, 0x00)
			}
			dst = appendOIDComponent(dst, 40*first+v)
		default:
			dst = appendOIDComponent(dst, v)
		}
		idx++
		start = i + 1
	}

	bodyLen := len(dst) - bodyStart
	if bodyLen > maxOIDBodyBytes {
		// Matches encodeOID: past this the length needs a third octet, which
		// the rewrite below does not write, and the two encoders would differ.
		return append(dst[:lenMark-1], ASN1_OID, 0x00)
	}
	if bodyLen < 0x80 {
		dst[lenMark] = byte(bodyLen)
		return dst
	}
	// Long-form length needed: make room and rewrite. OIDs this long do not
	// occur in the shipped catalogs, so this path is cold by construction —
	// correctness matters, speed does not. Two length bytes cover bodyLen up
	// to 65535; a longer body cannot fit maxTrapPDU, so both encoders reject
	// the message before a wider length form could ever reach the wire.
	extra := 1 // length bytes beyond the single reserved one
	if bodyLen >= 0x100 {
		extra = 2
	}
	for i := 0; i < extra; i++ {
		dst = append(dst, 0)
	}
	copy(dst[lenMark+1+extra:], dst[lenMark+1:len(dst)-extra])
	if extra == 1 {
		dst[lenMark] = 0x81
		dst[lenMark+1] = byte(bodyLen)
	} else {
		dst[lenMark] = 0x82
		dst[lenMark+1] = byte(bodyLen >> 8)
		dst[lenMark+2] = byte(bodyLen)
	}
	return dst
}

// appendOIDComponent appends one base-128 varint OID component.
//
// tmp is 10 bytes, which is enough for any int, but nothing that reaches here
// needs more than FIVE chunks: since nl6#532 every caller has already bounded
// the arc at maxOIDSubIdentifier (2^32-1), individually from index 2 up and
// through legalOIDArcPair on the combined first pair, so ceil(32/7) = 5 is the
// real width. The comment here used to justify the array with a 63-bit arc
// arriving from a REST varbindOverrides value as a full-width int; that path is
// gone — an over-wide arc is now refused by appendOID before this function is
// called, and the request fails rather than encoding (nl6#542 item 5). The
// slack is kept because it costs nothing and removes the need to re-derive the
// bound if the arc limit ever moves.
func appendOIDComponent(dst []byte, value int) []byte {
	if value < 0x80 {
		return append(dst, byte(value))
	}
	var tmp [10]byte
	i := len(tmp)
	i--
	tmp[i] = byte(value & 0x7f)
	value >>= 7
	for value > 0 {
		i--
		tmp[i] = byte(value&0x7f) | 0x80
		value >>= 7
	}
	return append(dst, tmp[i:]...)
}

// appendVarbindValue appends the value half of a resolved varbind, dispatching
// on Type exactly as encodeVarbindTyped does.
func appendVarbindValue(dst []byte, vb Varbind) ([]byte, error) {
	switch vb.Type {
	case TrapVTInteger:
		n, err := strconv.ParseInt(vb.Value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("integer: %q not parseable as Integer32: %w", vb.Value, err)
		}
		return appendInteger(dst, int(n)), nil

	case TrapVTOctetString:
		return appendOctetString(dst, vb.Value), nil

	case TrapVTOID:
		// The VALUE slot can carry an unencodable OID by the same rendered-
		// template / REST-override route as a varbind NAME, and parity between
		// the encoders cannot catch it because both would agree (nl6#540).
		if !encodableAsOID(vb.Value) {
			return nil, fmt.Errorf("oid: value %q is not one the encoder can represent", vb.Value)
		}
		return appendOID(dst, vb.Value), nil

	case TrapVTCounter32:
		n, err := strconv.ParseUint(vb.Value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("counter32: %q not parseable: %w", vb.Value, err)
		}
		return appendUnsigned32(dst, ASN1_COUNTER32, uint32(n)), nil

	case TrapVTGauge32:
		n, err := strconv.ParseUint(vb.Value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("gauge32: %q not parseable: %w", vb.Value, err)
		}
		return appendUnsigned32(dst, ASN1_GAUGE32, uint32(n)), nil

	case TrapVTTimeTicks:
		n, err := strconv.ParseUint(vb.Value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("timeticks: %q not parseable: %w", vb.Value, err)
		}
		return appendUnsigned32(dst, ASN1_TIMETICKS, uint32(n)), nil

	case TrapVTCounter64:
		n, err := strconv.ParseUint(vb.Value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("counter64: %q not parseable: %w", vb.Value, err)
		}
		// Counter64 and IpAddress are rare enough in catalogs that reusing the
		// allocating primitive keeps one implementation of their edge cases.
		return append(dst, encodeCounter64(n)...), nil

	case TrapVTIPAddress:
		if ip := net.ParseIP(vb.Value); ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("ipaddress: %q not a valid IPv4", vb.Value)
		}
		return append(dst, encodeIPAddress(vb.Value)...), nil

	default:
		return nil, fmt.Errorf("unknown varbind type %q", vb.Type)
	}
}

// encodeV2cNotificationFast assembles a complete SNMPv2c TRAP or INFORM message
// into dst (which should be a pooled, already-capacious buffer) and returns the
// extended slice. dst is truncated to zero length first; the caller keeps the
// returned slice to preserve the grown capacity for the next fire.
//
// pre supplies the entry's pre-encoded constants and MUST correspond to the
// same catalog entry that produced varbinds. A nil pre is legal and falls back
// to encoding every OID inline, which is what the on-demand HTTP path and the
// tests use.
func encodeV2cNotificationFast(dst []byte, pduTag byte, community string, reqID uint32,
	pre *preEncodedEntry, trapOID, enterpriseOID string,
	uptimeHundredths uint32, varbinds []Varbind) ([]byte, error) {

	dst = dst[:0]
	dst, outerMark := beginTLV(dst)
	dst = appendInteger(dst, 1) // version: v2c = 1
	dst = appendOctetString(dst, community)

	dst, pduMark := beginTLV(dst)
	dst = appendInteger(dst, int(reqID))
	dst = appendInteger(dst, 0) // error-status
	dst = appendInteger(dst, 0) // error-index

	dst, vbMark := beginTLV(dst)

	// Mandatory varbind 1: sysUpTime.0. The OID is constant, the TimeTicks
	// value is not.
	dst, m := beginTLV(dst)
	if pre != nil {
		dst = append(dst, pre.sysUpTimeOID...)
	} else {
		dst = appendOID(dst, oidSysUpTime0)
	}
	dst = appendUnsigned32(dst, ASN1_TIMETICKS, uptimeHundredths)
	dst = endTLV(dst, m, ASN1_SEQUENCE)

	// Mandatory varbind 2: snmpTrapOID.0. Entirely constant per catalog entry.
	// The slot is nil when precomputeEntry refused an unencodable trapOID
	// (nl6#540), so an empty slot must fall through to the checked branch —
	// appending nothing would silently drop the mandatory varbind instead.
	if pre != nil && len(pre.trapOIDVB) > 0 {
		dst = append(dst, pre.trapOIDVB...)
	} else {
		// Validated at catalog load since nl6#539; checked again here because
		// this encoder is also reachable with a caller-supplied trapOID, and
		// the identity varbind is the worst place to emit a degenerate OID.
		if !encodableAsOID(trapOID) {
			return nil, fmt.Errorf("snmpTrapOID %q is not one the encoder can represent", trapOID)
		}
		dst, m = beginTLV(dst)
		dst = appendOID(dst, oidSnmpTrapOID0)
		dst = appendOID(dst, trapOID)
		dst = endTLV(dst, m, ASN1_SEQUENCE)
	}

	// Optional varbind 3: snmpTrapEnterprise.0, in the RFC 3584 §4.1 position.
	// A nil slot with a non-empty enterpriseOID means precomputeEntry refused
	// it (nl6#540); falling through to the checked branch turns that into an
	// error instead of silently omitting the varbind the legacy path refuses.
	if pre != nil && pre.enterpriseVB != nil {
		dst = append(dst, pre.enterpriseVB...)
	} else if enterpriseOID != "" {
		if !encodableAsOID(enterpriseOID) {
			return nil, fmt.Errorf("snmpTrapEnterprise %q is not one the encoder can represent", enterpriseOID)
		}
		dst, m = beginTLV(dst)
		dst = appendOID(dst, oidSnmpTrapEnterprise0)
		dst = appendOID(dst, enterpriseOID)
		dst = endTLV(dst, m, ASN1_SEQUENCE)
	}

	// Body varbinds.
	for i, vb := range varbinds {
		dst, m = beginTLV(dst)
		if pre != nil && i < len(pre.varbindOID) && pre.varbindOID[i] != nil {
			dst = append(dst, pre.varbindOID[i]...)
		} else {
			// This branch carries a RENDERED templated OID. nl6#539 validates
			// literal catalog OIDs at load, but a template cannot be decided
			// until it renders, and a REST varbindOverrides value can make it
			// unencodable at that point whatever the catalog said.
			//
			// Refuse rather than emitting the degenerate 06 00 (nl6#540).
			// appendOID would silently produce an empty NAME, and a binding no
			// manager can match went on the wire with nothing recorded: no log
			// line, no counter, diagnosable only from a packet capture.
			// Returning an error here routes it to the exporter's existing
			// logFirstEncodeErr and sendFailures, so the signal already has
			// somewhere to go.
			if !encodableAsOID(vb.OID) {
				return nil, fmt.Errorf("varbind %d: OID %q is not one the encoder can represent "+
					"(rendered from a templated catalog OID or a REST override)", i, vb.OID)
			}
			dst = appendOID(dst, vb.OID)
		}
		var err error
		dst, err = appendVarbindValue(dst, vb)
		if err != nil {
			return nil, fmt.Errorf("varbind %d (%s): %w", i, vb.OID, err)
		}
		dst = endTLV(dst, m, ASN1_SEQUENCE)
	}

	dst = endTLV(dst, vbMark, ASN1_SEQUENCE)
	dst = endTLV(dst, pduMark, pduTag)
	dst = endTLV(dst, outerMark, ASN1_SEQUENCE)

	if len(dst) > maxTrapPDU {
		return nil, &pduTooLargeError{size: len(dst), limit: maxTrapPDU}
	}
	return dst, nil
}
