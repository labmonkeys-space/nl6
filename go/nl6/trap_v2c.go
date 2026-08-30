/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// SNMPv2c TRAP and INFORM PDU encoder, plus INFORM-ack parser.
//
// Wire format (RFC 3416 §4.2.6, §4.2.7):
//
//   Message := SEQUENCE {
//       version        INTEGER (1)             -- v2c = 1
//       community      OCTET STRING
//       data           SNMPv2-Trap-PDU | InformRequest-PDU
//   }
//
//   SNMPv2-Trap-PDU ::= [7] IMPLICIT PDU (tag 0xA7)
//   InformRequest-PDU ::= [6] IMPLICIT PDU (tag 0xA6)
//   PDU := SEQUENCE {
//       request-id     INTEGER
//       error-status   INTEGER (0)
//       error-index    INTEGER (0)
//       variable-bindings SEQUENCE OF VarBind
//   }
//
// The first two varbinds of every SNMPv2 notification are mandatory (RFC 3416
// §4.2.6): sysUpTime.0 (TimeTicks) and snmpTrapOID.0 (OID). This encoder
// prepends them automatically from the uptimeHundredths and trapOID arguments.
// Catalog authors supply only body varbinds; the loader rejects entries that
// list the two reserved OIDs explicitly (see trap_catalog.go validateVarbindOID).
//
// ParseAck decodes a GetResponse-PDU (tag 0xA2) which is the collector's
// acknowledgement of an INFORM. It reuses the BER primitives from
// snmp_encoding.go and shares the structural parser shape with
// extractOIDFromSNMPPacket.

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// TrapEncoder is the protocol-agnostic surface used by TrapExporter. Phase 1
// ships a single implementation (SNMPv2cEncoder); SNMPv1 and SNMPv3 encoders
// can layer in later without changing the exporter or scheduler (design §D9).
type TrapEncoder interface {
	// EncodeTrap writes an SNMPv2-Trap-PDU wrapped in an SNMPv2c message into
	// buf and returns the byte length written. trapOID is the dotted-decimal
	// OID that becomes snmpTrapOID.0 in the PDU. enterpriseOID, when non-
	// empty, causes the encoder to emit an additional `snmpTrapEnterprise.0`
	// varbind (OID 1.3.6.1.6.3.1.1.4.3.0) with that OID as its value — per
	// SNMPv2-MIB §10 this OPTIONAL varbind aids v1↔v2c cross-compatibility
	// handling on the receiving side. varbinds are the catalog-body varbinds;
	// the encoder prepends sysUpTime.0 and snmpTrapOID.0 unconditionally.
	EncodeTrap(community string, reqID uint32, trapOID, enterpriseOID string,
		uptimeHundredths uint32, varbinds []Varbind, buf []byte) (int, error)

	// EncodeInform is identical to EncodeTrap but uses the InformRequest-PDU
	// tag (0xA6). The receiving collector replies with a GetResponse-PDU
	// (0xA2) that ParseAck decodes.
	EncodeInform(community string, reqID uint32, trapOID, enterpriseOID string,
		uptimeHundredths uint32, varbinds []Varbind, buf []byte) (int, error)

	// ParseAck decodes a collector-side acknowledgement datagram. Returns the
	// request-id, whether error-status == 0 (ok), and any parse error. Callers
	// match reqID against their pending-inform map; a false ok but nil err
	// means "collector received but reports an error".
	ParseAck(pkt []byte) (reqID uint32, ok bool, err error)
}

// fastTrapEncoder is the optional allocation-free companion to TrapEncoder.
// It is a SEPARATE interface rather than extra TrapEncoder methods so that
// test doubles and any future encoder can implement the readable surface
// alone; TrapExporter type-asserts for it once at construction and falls back
// to EncodeTrap/EncodeInform when it is absent.
//
// EncodeNotificationFast appends into dst (truncating it first) and returns the
// extended slice, so a pooled buffer keeps its grown capacity across fires. The
// returned slice aliases dst and is only valid until the next call.
type fastTrapEncoder interface {
	EncodeNotificationFast(dst []byte, mode TrapMode, community string, reqID uint32,
		pre *preEncodedEntry, trapOID, enterpriseOID string,
		uptimeHundredths uint32, varbinds []Varbind) ([]byte, error)
}

// SNMPv2cEncoder is the community-string-authenticated SNMPv2c trap/inform
// encoder. Stateless and safe for concurrent use.
type SNMPv2cEncoder struct{}

// EncodeNotificationFast — see fastTrapEncoder. Produces output byte-for-byte
// identical to EncodeTrap / EncodeInform; TestFastEncoderMatchesLegacy pins it.
func (SNMPv2cEncoder) EncodeNotificationFast(dst []byte, mode TrapMode, community string, reqID uint32,
	pre *preEncodedEntry, trapOID, enterpriseOID string,
	uptimeHundredths uint32, varbinds []Varbind) ([]byte, error) {
	tag := byte(ASN1_TRAP_V2C)
	if mode == TrapModeInform {
		tag = ASN1_INFORM_REQUEST
	}
	return encodeV2cNotificationFast(dst, tag, community, reqID, pre, trapOID, enterpriseOID,
		uptimeHundredths, varbinds)
}

// EncodeTrap — see TrapEncoder.
func (SNMPv2cEncoder) EncodeTrap(community string, reqID uint32, trapOID, enterpriseOID string,
	uptimeHundredths uint32, varbinds []Varbind, buf []byte) (int, error) {
	return encodeV2cNotification(ASN1_TRAP_V2C, community, reqID, trapOID, enterpriseOID, uptimeHundredths, varbinds, buf)
}

// EncodeInform — see TrapEncoder.
func (SNMPv2cEncoder) EncodeInform(community string, reqID uint32, trapOID, enterpriseOID string,
	uptimeHundredths uint32, varbinds []Varbind, buf []byte) (int, error) {
	return encodeV2cNotification(ASN1_INFORM_REQUEST, community, reqID, trapOID, enterpriseOID, uptimeHundredths, varbinds, buf)
}

// ParseAck — see TrapEncoder.
func (SNMPv2cEncoder) ParseAck(pkt []byte) (uint32, bool, error) {
	return parseV2cAck(pkt)
}

// encodeV2cNotification is the shared body of EncodeTrap and EncodeInform; the
// only difference between TRAP and INFORM on the wire is the PDU tag byte.
func encodeV2cNotification(pduTag byte, community string, reqID uint32, trapOID, enterpriseOID string,
	uptimeHundredths uint32, varbinds []Varbind, buf []byte) (int, error) {
	// Build the PDU inner SEQUENCE contents:
	//   request-id / error-status / error-index / variable-bindings
	pduContents := make([]byte, 0, 128+len(varbinds)*32)
	pduContents = append(pduContents, encodeInteger(int(reqID))...)
	pduContents = append(pduContents, encodeInteger(0)...) // error-status
	pduContents = append(pduContents, encodeInteger(0)...) // error-index

	// variable-bindings SEQUENCE:
	//   1. sysUpTime.0 (TimeTicks)
	//   2. snmpTrapOID.0 (OID = trapOID)
	//   3. snmpTrapEnterprise.0 (OID = enterpriseOID) — only when non-empty.
	//      RFC 3584 §4.1 (the SNMPv1↔v2c proxy translation spec) places
	//      snmpTrapEnterprise.0 as the third element of variable-bindings,
	//      after sysUpTime.0 and snmpTrapOID.0 and before any additional
	//      varbinds. SNMPv2-MIB §10 makes this additional-info varbind
	//      optional on native v2c notifications; when catalog authors set it
	//      we emit it in the same position RFC 3584 pins.
	//   N. body varbinds
	// An OID this encoder cannot represent is REFUSED rather than emitted as
	// the degenerate 06 00 (nl6#540). The checks sit at the same positions as
	// encodeV2cNotificationFast's: the two must agree byte for byte AND fault
	// for fault, or TestFastEncoderMatchesLegacy_* passes while one ships a
	// message the other refuses. That parity test caught exactly this when
	// only the fast path was changed. (It compares which inputs error, not
	// the error text; the shared wording is a courtesy, not test-enforced.)
	if !encodableAsOID(trapOID) {
		return 0, fmt.Errorf("snmpTrapOID %q is not one the encoder can represent", trapOID)
	}
	if enterpriseOID != "" && !encodableAsOID(enterpriseOID) {
		return 0, fmt.Errorf("snmpTrapEnterprise %q is not one the encoder can represent", enterpriseOID)
	}

	vbContents := make([]byte, 0, 64+len(varbinds)*32)
	vbContents = append(vbContents, encodeVarbindTimeTicks(oidSysUpTime0, uptimeHundredths)...)
	vbContents = append(vbContents, encodeVarbindOID(oidSnmpTrapOID0, trapOID)...)
	if enterpriseOID != "" {
		vbContents = append(vbContents, encodeVarbindOID(oidSnmpTrapEnterprise0, enterpriseOID)...)
	}
	for i, vb := range varbinds {
		if !encodableAsOID(vb.OID) {
			return 0, fmt.Errorf("varbind %d: OID %q is not one the encoder can represent "+
				"(rendered from a templated catalog OID or a REST override)", i, vb.OID)
		}
		enc, err := encodeVarbindTyped(vb)
		if err != nil {
			return 0, fmt.Errorf("varbind %d (%s): %w", i, vb.OID, err)
		}
		vbContents = append(vbContents, enc...)
	}
	pduContents = append(pduContents, encodeSequence(vbContents)...)

	// Wrap the PDU body in the implicit-tagged PDU envelope.
	pdu := make([]byte, 0, len(pduContents)+4)
	pdu = append(pdu, pduTag)
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	// Outer message SEQUENCE: version INTEGER + community OCTET STRING + PDU.
	outer := make([]byte, 0, len(pdu)+16+len(community))
	outer = append(outer, encodeInteger(1)...) // v2c = 1
	outer = append(outer, encodeOctetString(community)...)
	outer = append(outer, pdu...)
	envelope := encodeSequence(outer)

	if len(envelope) > len(buf) {
		return 0, fmt.Errorf("encoded PDU (%d bytes) exceeds buffer (%d)", len(envelope), len(buf))
	}
	n := copy(buf, envelope)
	return n, nil
}

// encodeVarbindTimeTicks builds one VarBind of type TimeTicks (tag 0x43).
func encodeVarbindTimeTicks(oid string, value uint32) []byte {
	vb := make([]byte, 0, 32)
	vb = append(vb, encodeOID(oid)...)
	vb = append(vb, encodeUnsigned32(ASN1_TIMETICKS, value)...)
	return encodeSequence(vb)
}

// encodeVarbindOID builds one VarBind whose value is an OID (tag 0x06).
func encodeVarbindOID(oid, value string) []byte {
	vb := make([]byte, 0, 48)
	vb = append(vb, encodeOID(oid)...)
	vb = append(vb, encodeOID(value)...)
	return encodeSequence(vb)
}

// encodeVarbindTyped builds one VarBind from a resolved catalog Varbind,
// dispatching on Type to pick the right BER application tag.
func encodeVarbindTyped(vb Varbind) ([]byte, error) {
	body := make([]byte, 0, 32)
	body = append(body, encodeOID(vb.OID)...)

	switch vb.Type {
	case TrapVTInteger:
		// SNMP INTEGER is Integer32 (RFC 2578 §7.1.1) — parse at 32-bit
		// width so out-of-range catalog values error out instead of
		// truncating on the wire.
		n, err := strconv.ParseInt(vb.Value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("integer: %q not parseable as Integer32: %w", vb.Value, err)
		}
		body = append(body, encodeInteger(int(n))...)

	case TrapVTOctetString:
		body = append(body, encodeOctetString(vb.Value)...)

	case TrapVTOID:
		// Same refusal as appendVarbindValue's, wording included (nl6#540).
		if !encodableAsOID(vb.Value) {
			return nil, fmt.Errorf("oid: value %q is not one the encoder can represent", vb.Value)
		}
		body = append(body, encodeOID(vb.Value)...)

	case TrapVTCounter32:
		n, err := strconv.ParseUint(vb.Value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("counter32: %q not parseable: %w", vb.Value, err)
		}
		body = append(body, encodeUnsigned32(ASN1_COUNTER32, uint32(n))...)

	case TrapVTGauge32:
		n, err := strconv.ParseUint(vb.Value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("gauge32: %q not parseable: %w", vb.Value, err)
		}
		body = append(body, encodeUnsigned32(ASN1_GAUGE32, uint32(n))...)

	case TrapVTTimeTicks:
		n, err := strconv.ParseUint(vb.Value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("timeticks: %q not parseable: %w", vb.Value, err)
		}
		body = append(body, encodeUnsigned32(ASN1_TIMETICKS, uint32(n))...)

	case TrapVTCounter64:
		n, err := strconv.ParseUint(vb.Value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("counter64: %q not parseable: %w", vb.Value, err)
		}
		body = append(body, encodeCounter64(n)...)

	case TrapVTIPAddress:
		if ip := net.ParseIP(vb.Value); ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("ipaddress: %q not a valid IPv4", vb.Value)
		}
		body = append(body, encodeIPAddress(vb.Value)...)

	default:
		return nil, fmt.Errorf("unknown varbind type %q", vb.Type)
	}
	return encodeSequence(body), nil
}

// parseV2cAck decodes an SNMPv2c GetResponse-PDU arriving in response to an
// INFORM. Returns the request-id, whether error-status == 0, and an error on
// malformed input or unexpected PDU tag.
//
// Structural match mirrors extractOIDFromSNMPPacket in snmp_encoding.go — we
// walk the outer SEQUENCE / version / community / PDU envelope, then parse
// request-id and error-status.
func parseV2cAck(data []byte) (uint32, bool, error) {
	pos := 0

	// Outer SEQUENCE
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return 0, false, fmt.Errorf("not a SEQUENCE at offset 0")
	}
	pos++
	outerLen, np := parseLength(data, pos)
	if outerLen < 0 {
		return 0, false, fmt.Errorf("bad outer length")
	}
	pos = np
	if pos+outerLen > len(data) {
		return 0, false, fmt.Errorf("outer length %d exceeds packet %d", outerLen, len(data))
	}

	// version INTEGER (must be 1 for v2c)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return 0, false, fmt.Errorf("expected version INTEGER")
	}
	pos++
	verLen, np := parseLength(data, pos)
	if verLen < 0 || np+verLen > len(data) {
		return 0, false, fmt.Errorf("bad version length")
	}
	version := parseUintBE(data[np : np+verLen])
	if version != 1 {
		return 0, false, fmt.Errorf("expected v2c (version=1), got version=%d", version)
	}
	pos = np + verLen

	// community OCTET STRING
	if pos >= len(data) || data[pos] != ASN1_OCTET_STRING {
		return 0, false, fmt.Errorf("expected community OCTET STRING")
	}
	pos++
	commLen, np := parseLength(data, pos)
	if commLen < 0 || np+commLen > len(data) {
		return 0, false, fmt.Errorf("bad community length")
	}
	pos = np + commLen

	// PDU — must be GetResponse-PDU (0xA2) for an inform ack
	if pos >= len(data) {
		return 0, false, fmt.Errorf("packet truncated at PDU")
	}
	pduTag := data[pos]
	if pduTag != ASN1_GET_RESPONSE {
		return 0, false, fmt.Errorf("expected GetResponse-PDU (0xA2), got 0x%02X", pduTag)
	}
	pos++
	pduLen, np := parseLength(data, pos)
	if pduLen < 0 || np+pduLen > len(data) {
		return 0, false, fmt.Errorf("bad PDU length")
	}
	pos = np

	// request-id INTEGER
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return 0, false, fmt.Errorf("expected request-id INTEGER")
	}
	pos++
	ridLen, np := parseLength(data, pos)
	if ridLen < 0 || np+ridLen > len(data) {
		return 0, false, fmt.Errorf("bad request-id length")
	}
	reqID := parseUintBE(data[np : np+ridLen])
	pos = np + ridLen

	// error-status INTEGER
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return 0, false, fmt.Errorf("expected error-status INTEGER")
	}
	pos++
	esLen, np := parseLength(data, pos)
	if esLen < 0 || np+esLen > len(data) {
		return 0, false, fmt.Errorf("bad error-status length")
	}
	errorStatus := parseIntBE(data[np : np+esLen])

	return uint32(reqID), errorStatus == 0, nil
}

// parseUintBE decodes a big-endian unsigned integer from BER INTEGER contents.
// BER encodes integers with a leading 0x00 when the high bit would otherwise
// make the value appear negative; we tolerate that. Max 8 bytes.
func parseUintBE(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	// Pad to 8 bytes big-endian.
	var tmp [8]byte
	copy(tmp[8-len(b):], b)
	return binary.BigEndian.Uint64(tmp[:])
}

// parseIntBE decodes a BER INTEGER as a signed int64 (two's complement).
// Used for error-status where negative wouldn't actually be valid, but we
// decode truthfully so a non-zero error-status is reported regardless of sign.
func parseIntBE(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	// Truncate oversized INTEGERs to prevent negative slice bounds. BER permits
	// arbitrarily long INTEGERs; an attacker-controlled 9+ byte value would
	// otherwise cause copy(tmp[8-len(b):], b) to panic. We take the least
	// significant 8 bytes, matching parseUintBE's truncation strategy.
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	// Sign-extend from the most significant byte.
	negative := b[0]&0x80 != 0
	var tmp [8]byte
	if negative {
		for i := range tmp {
			tmp[i] = 0xFF
		}
	}
	copy(tmp[8-len(b):], b)
	return int64(binary.BigEndian.Uint64(tmp[:]))
}
