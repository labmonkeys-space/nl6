/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// trap_v1.go — the SNMPv1 Trap-PDU (RFC 1157 §4.1.6, tag 0xA4) encoder, and the
// RFC 3584 §3.2 mapping that derives a v1 notification's identity from the
// SNMPv2c catalog entries nl6 already ships (nl6#97).
//
// WHY THERE IS NO CATALOG SCHEMA CHANGE. nl6#97 proposed adding enterprise,
// generic-trap and specific-trap fields per entry. Measured against the shipped
// corpus, none is needed: of 23 entries, 5 are standard traps (all in _common)
// and 18 are enterprise-specific, and RFC 3584 §3.2 derives every field of the
// v1 identity from the snmpTrapOID those entries already carry. Hand-writing
// three more fields on 23 entries would be 23 chances to disagree with the OID
// beside them.
//
// THE DECLARED snmpTrapEnterprise IS NOT AN OVERRIDE, and this is the one place
// the mapping surprises. RFC 3584 §3.2 honours it ONLY when snmpTrapOID is one
// of the standard traps; for a non-standard trap the enterprise is ALWAYS
// derived from snmpTrapOID. Since no shipped standard-trap entry declares one
// and every vendor entry does, the declared value is used by the v1 path in
// ZERO shipped cases. It is still emitted as a varbind by the v2c path, which
// is unchanged. An earlier draft of this change had it backwards, and reading
// the RFC rather than recalling it is what caught that.
//
// A v1 PDU carries NONE of the three varbinds the v2c encoder prepends:
// sysUpTime.0 becomes the PDU's time-stamp, snmpTrapOID.0 becomes the
// (enterprise, generic-trap, specific-trap) identity, and snmpTrapEnterprise.0
// becomes the enterprise field. Emitting them as varbinds would produce a trap
// no real agent sends.

// snmpTrapsOID is `snmpTraps` (RFC 3418), the enterprise RFC 3584 §3.2 assigns
// to a standard trap that carries no snmpTrapEnterprise.
//
// NOT recalled: it is the common prefix of the five standard trap OIDs the
// shipped _common catalog already uses, and TestSnmpTrapsOIDIsTheStandardTrapPrefix
// re-derives it from the corpus rather than trusting this line.
const snmpTrapsOID = "1.3.6.1.6.3.1.1.5"

// SNMPv1 generic-trap values (RFC 1157 §4.1.6). enterpriseSpecific is the
// catch-all every vendor notification maps to.
const (
	v1GenericColdStart = iota
	v1GenericWarmStart
	v1GenericLinkDown
	v1GenericLinkUp
	v1GenericAuthFailure
	v1GenericEGPNeighborLoss
	v1GenericEnterpriseSpecific
)

// v1TrapPDUTag is the Trap-PDU's implicit context tag, [4].
const v1TrapPDUTag = 0xA4

// v1Identity is the (enterprise, generic-trap, specific-trap) triple a v1 trap
// carries in place of v2c's snmpTrapOID.0.
type v1Identity struct {
	Enterprise string
	Generic    int
	Specific   int
}

// mapV2cToV1Identity applies RFC 3584 §3.2 to a catalog entry's snmpTrapOID and
// optional snmpTrapEnterprise.
//
// Standard trap: generic-trap is its index under snmpTraps, specific-trap is 0,
// and the enterprise is the declared snmpTrapEnterprise when present, else
// snmpTraps.
//
// Anything else: generic-trap is enterpriseSpecific(6), specific-trap is the
// LAST sub-identifier of snmpTrapOID, and the enterprise is snmpTrapOID with
// its last two sub-identifiers removed when the next-to-last is zero, else with
// its last one removed. The declared snmpTrapEnterprise is deliberately IGNORED
// here; see the file header.
func mapV2cToV1Identity(trapOID, declaredEnterprise string) (v1Identity, error) {
	oid := strings.TrimPrefix(trapOID, ".")
	if oid == "" {
		return v1Identity{}, fmt.Errorf("empty snmpTrapOID has no SNMPv1 identity")
	}
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return v1Identity{}, fmt.Errorf("snmpTrapOID %q has too few sub-identifiers for an SNMPv1 identity", trapOID)
	}

	if prefix := strings.Join(parts[:len(parts)-1], "."); prefix == snmpTrapsOID {
		last, err := strconv.Atoi(parts[len(parts)-1])
		if err != nil {
			return v1Identity{}, fmt.Errorf("snmpTrapOID %q: unparseable final sub-identifier: %w", trapOID, err)
		}
		// snmpTraps.1 is coldStart(0), so the generic value is one less. Values
		// outside 1..6 sit under snmpTraps but are not standard traps, so they
		// fall through to the enterprise-specific branch below.
		if last >= 1 && last <= v1GenericEGPNeighborLoss+1 {
			ent := strings.TrimPrefix(declaredEnterprise, ".")
			if ent == "" {
				ent = snmpTrapsOID
			}
			return v1Identity{Enterprise: ent, Generic: last - 1, Specific: 0}, nil
		}
	}

	specific, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return v1Identity{}, fmt.Errorf("snmpTrapOID %q: unparseable final sub-identifier: %w", trapOID, err)
	}
	drop := 1
	if parts[len(parts)-2] == "0" {
		drop = 2
	}
	if len(parts)-drop < 2 {
		return v1Identity{}, fmt.Errorf("snmpTrapOID %q leaves no enterprise after removing %d sub-identifier(s)", trapOID, drop)
	}
	return v1Identity{
		Enterprise: strings.Join(parts[:len(parts)-drop], "."),
		Generic:    v1GenericEnterpriseSpecific,
		Specific:   specific,
	}, nil
}

// SNMPv1Encoder emits RFC 1157 Trap-PDUs.
//
// It carries the agent address, so unlike SNMPv2cEncoder it is PER DEVICE
// rather than shared. That is deliberate: agent-addr is the notification
// originator's own IP, which is per-device state and not a property of a single
// call, and modelling it as state leaves the TrapEncoder interface untouched.
// Widening the interface would have added a parameter meaningless to v2c, on
// the path this change must leave byte-identical.
type SNMPv1Encoder struct {
	// AgentAddr is the device's IPv4 in dotted-quad form. RFC 3584 §3.2 sets
	// agent-addr to the originating entity's address; an empty value encodes as
	// 0.0.0.0, which is what the RFC prescribes when no address is available.
	AgentAddr string
}

// EncodeTrap writes an SNMPv1 message carrying a Trap-PDU into buf.
//
// enterpriseOID is the catalog's declared snmpTrapEnterprise. It reaches the
// mapping, which uses it only for a standard trap; see the file header.
func (e SNMPv1Encoder) EncodeTrap(community string, _ uint32, trapOID, enterpriseOID string,
	uptimeHundredths uint32, varbinds []Varbind, buf []byte) (int, error) {
	// The request-id is unused: a v1 Trap-PDU has no such field. v2c's
	// signature carries one because INFORM needs it to match acks.
	id, err := mapV2cToV1Identity(trapOID, enterpriseOID)
	if err != nil {
		return 0, err
	}
	// Same refusal as the v2c path (nl6#540): an OID the encoder cannot
	// represent is refused rather than emitted as the degenerate 06 00.
	if !encodableAsOID(id.Enterprise) {
		return 0, fmt.Errorf("derived SNMPv1 enterprise %q is not one the encoder can represent", id.Enterprise)
	}

	pduContents := make([]byte, 0, 128+len(varbinds)*32)
	pduContents = append(pduContents, encodeOID(id.Enterprise)...)
	pduContents = append(pduContents, encodeIPAddress(e.agentAddrOrUnspecified())...)
	pduContents = append(pduContents, encodeInteger(id.Generic)...)
	pduContents = append(pduContents, encodeInteger(id.Specific)...)
	pduContents = append(pduContents, encodeUnsigned32(ASN1_TIMETICKS, uptimeHundredths)...)

	// BODY VARBINDS ONLY. sysUpTime.0, snmpTrapOID.0 and snmpTrapEnterprise.0
	// are v2c constructs that became PDU fields above.
	vbContents := make([]byte, 0, 64+len(varbinds)*32)
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

	pdu := make([]byte, 0, len(pduContents)+4)
	pdu = append(pdu, v1TrapPDUTag)
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	outer := make([]byte, 0, len(pdu)+16+len(community))
	outer = append(outer, encodeInteger(0)...) // version: SNMPv1 = 0
	outer = append(outer, encodeOctetString(community)...)
	outer = append(outer, pdu...)
	envelope := encodeSequence(outer)

	if len(envelope) > len(buf) {
		return 0, fmt.Errorf("encoded PDU (%d bytes) exceeds buffer (%d)", len(envelope), len(buf))
	}
	return copy(buf, envelope), nil
}

// agentAddrOrUnspecified is the RFC 3584 §3.2 fallback: an originator with no
// known address sends 0.0.0.0 rather than omitting the field, which the PDU
// shape does not allow.
func (e SNMPv1Encoder) agentAddrOrUnspecified() string {
	if e.AgentAddr == "" {
		return "0.0.0.0"
	}
	return e.AgentAddr
}

// EncodeInform always fails. RFC 1157 defines no acknowledged notification, so
// there is nothing to encode and nothing a collector would answer.
//
// Startup refuses the flag combination that would reach here, so this is the
// backstop rather than the diagnosis (see ParseTrapSNMPVersion's validation).
func (SNMPv1Encoder) EncodeInform(string, uint32, string, string, uint32, []Varbind, []byte) (int, error) {
	return 0, fmt.Errorf("SNMPv1 has no InformRequest-PDU: RFC 1157 defines no acknowledged " +
		"notification, so -trap-mode inform cannot be served by -trap-snmp-version v1")
}

// ParseAck always fails, for the same reason as EncodeInform: nothing ever
// acknowledges an SNMPv1 trap, so a datagram arriving on the trap socket in v1
// mode is not an ack.
func (SNMPv1Encoder) ParseAck([]byte) (uint32, bool, error) {
	return 0, false, fmt.Errorf("SNMPv1 traps are never acknowledged; there is no ack to parse")
}
