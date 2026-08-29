/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"testing"
)

// A variable-bindings list that is not a valid ASN.1 encoding is an ASN.1
// error. RFC 1157 §4.1 step 1 and RFC 3412 §7.2 discard such a datagram and
// perform no further actions; they do not answer it partially.
//
// Before nl6#537 a malformed binding was silently DROPPED and the response
// came back with fewer bindings than the request carried, against RFC 3416's
// correspondence requirement. The drop was near-unreachable until nl6#529 made
// decodeOID refuse malformed input rather than invent a value for it.

// unterminatedOIDName is a varbind name whose content is not a valid OBJECT
// IDENTIFIER: 0x2b 0xff is a sub-identifier whose final octet still sets the
// continuation bit, so the OID is truncated.
var unterminatedOIDName = []byte{ASN1_OID, 0x02, 0x2b, 0xff}

// requestWithVarbinds builds a v1/v2c message of the given PDU tag and version
// around a RAW variable-bindings list, so a test can put any bytes where the
// bindings go. Everything outside the list is well formed. For a GETBULK tag
// the two integers after request-id are non-repeaters=0 and max-repetitions=10.
func requestWithVarbinds(pduTag byte, version int, vbs []byte) []byte {
	var body []byte
	body = append(body, encodeInteger(42)...)
	body = append(body, encodeInteger(0)...)
	if pduTag == ASN1_GET_BULK {
		body = append(body, encodeInteger(10)...)
	} else {
		body = append(body, encodeInteger(0)...)
	}
	body = append(body, encodeSequence(vbs)...)
	pdu := append([]byte{pduTag}, append(encodeLength(len(body)), body...)...)

	var msg []byte
	msg = append(msg, encodeInteger(version)...)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// malformedNameRequest builds a request carrying `count` bindings, with the one
// at badIndex given the unterminated OID name. The PDU is structurally fine and
// only that one name's content is bad.
func malformedNameRequest(pduTag byte, version, count, badIndex int) []byte {
	var vbs []byte
	for i := 0; i < count; i++ {
		if i == badIndex {
			vbs = append(vbs, encodeSequence(append(unterminatedOIDName, encodeNull()...))...)
			continue
		}
		vbs = append(vbs, encodeVarBind(".1.3.6.1.2.1.1.1.0", encodeNull())...)
	}
	return requestWithVarbinds(pduTag, version, vbs)
}

// TestMalformedVarbindNameDiscardsTheDatagram drives every v1/v2c PDU type
// through the dispatcher. GETNEXT is in the table because it is the one branch
// that does NOT consume parseAllOIDsFromRequest's list: it answers from
// parseIncomingRequest's OID, which defaults to sysDescr.0 when the name fails
// to decode, so before the GETNEXT gate a malformed name was answered as a walk
// restart from an OID nobody sent.
func TestMalformedVarbindNameDiscardsTheDatagram(t *testing.T) {
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})

	for _, tc := range []struct {
		name            string
		pduTag          byte
		version         int
		count, badIndex int
	}{
		{"v2c GET, second of three", ASN1_GET_REQUEST, snmpVersion2c, 3, 1},
		{"v2c GET, first of two", ASN1_GET_REQUEST, snmpVersion2c, 2, 0},
		{"v2c GET, only binding", ASN1_GET_REQUEST, snmpVersion2c, 1, 0},
		{"v1 GET, second of three", ASN1_GET_REQUEST, snmpVersion1, 3, 1},
		{"v1 GET, only binding", ASN1_GET_REQUEST, snmpVersion1, 1, 0},
		{"v2c GETNEXT, only binding", ASN1_GET_NEXT, snmpVersion2c, 1, 0},
		{"v2c GETNEXT, second of two", ASN1_GET_NEXT, snmpVersion2c, 2, 1},
		{"v1 GETNEXT, only binding", ASN1_GET_NEXT, snmpVersion1, 1, 0},
		{"v2c GETBULK, only binding", ASN1_GET_BULK, snmpVersion2c, 1, 0},
		{"v2c GETBULK, second of two", ASN1_GET_BULK, snmpVersion2c, 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := malformedNameRequest(tc.pduTag, tc.version, tc.count, tc.badIndex)

			// An empty response is what handleSingleRequest gates the send on,
			// so this is a genuine discard rather than a zero-length datagram.
			if resp := s.handleSNMPv2cRequest(req); len(resp) != 0 {
				n := countVarbinds(t, resp)
				t.Errorf("a malformed varbind name was answered with a %d-byte response carrying "+
					"%d bindings; the request carried %d. RFC 1157 discards a datagram that fails "+
					"ASN.1 parsing", len(resp), n, tc.count)
			}
		})
	}
}

// TestStructurallyBrokenVarbindListDiscardsTheDatagram covers the failures
// that are not a bad OID CONTENT but a bad list SHAPE. Each of these used to
// skip the binding or break out of the loop with a partial list, which is the
// same short-response defect by a different route.
func TestStructurallyBrokenVarbindListDiscardsTheDatagram(t *testing.T) {
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})
	good := encodeVarBind(".1.3.6.1.2.1.1.1.0", encodeNull())

	for _, tc := range []struct {
		name string
		vbs  []byte
	}{
		// Name field carries a NULL tag where an OBJECT IDENTIFIER belongs.
		{"name tag is not OID", concat(good, encodeSequence(append(encodeNull(), encodeNull()...)))},
		// Name declares 40 bytes of content but the datagram ends after 2.
		{"name length overruns the datagram", concat(good, encodeSequence([]byte{ASN1_OID, 0x28, 0x2b, 0x06}))},
		// Empty name: 06 00 is never a legitimate OID (it has at least two arcs).
		{"zero-length name", concat(good, encodeSequence(append([]byte{ASN1_OID, 0x00}, encodeNull()...)))},
		// A second VarBind that is not a SEQUENCE.
		{"later varbind has wrong tag", concat(good, []byte{ASN1_INTEGER, 0x01, 0x00})},
		// A second VarBind whose length claims to extend past the list.
		{"later varbind overruns the list", concat(good, []byte{ASN1_SEQUENCE, 0x7f})},
		// An empty VarBind SEQUENCE.
		{"empty varbind", concat(good, []byte{ASN1_SEQUENCE, 0x00})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := requestWithVarbinds(ASN1_GET_REQUEST, snmpVersion2c, tc.vbs)
			if resp := s.handleSNMPv2cRequest(req); len(resp) != 0 {
				t.Errorf("a structurally broken varbind list was answered with a %d-byte response "+
					"carrying %d bindings; the request's list held 2 entries", len(resp), countVarbinds(t, resp))
			}
			if oids, ok := s.parseAllOIDsFromRequest(req); ok {
				t.Errorf("parser reported the list as parseable, returning %v", oids)
			}
		})
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestWellFormedMultiVarbindStillAnswered is the positive control. Without it,
// a change that discarded every request would pass the tests above.
func TestWellFormedMultiVarbindStillAnswered(t *testing.T) {
	s := newTestServer(map[string]string{
		".1.3.6.1.2.1.1.1.0":     "dev",
		".1.3.6.1.2.1.2.2.1.2.1": "Gi0/1",
	})
	oids := []string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.2.2.1.2.1", ".1.3.6.1.2.1.1.1.0"}

	// GET answers every binding, so its count is asserted. GETNEXT answers a
	// single successor and a GETBULK built by snmpRequestAt asks for zero
	// repetitions, so for those the check is only that a datagram comes back.
	for _, tc := range []struct {
		name   string
		pduTag byte
		count  bool
	}{
		{"GET", ASN1_GET_REQUEST, true},
		{"GETNEXT", ASN1_GET_NEXT, false},
		{"GETBULK", ASN1_GET_BULK, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := s.handleSNMPv2cRequest(snmpRequestAt(tc.pduTag, snmpVersion2c, oids))
			if len(resp) == 0 {
				t.Fatal("a well-formed multi-varbind request was discarded")
			}
			if tc.count {
				if got := countVarbinds(t, resp); got != len(oids) {
					t.Errorf("response carries %d bindings, request carried %d: RFC 3416 wants them to correspond",
						got, len(oids))
				}
			}
		})
	}
}

// TestEmptyVarbindListStillAnswered pins the distinction the bool exists for.
// A PDU whose variable-bindings list is empty is NOT the same as one carrying
// a malformed binding: the former is answered from the single parsed OID, the
// latter is discarded.
func TestEmptyVarbindListStillAnswered(t *testing.T) {
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})

	req := requestWithVarbinds(ASN1_GET_REQUEST, snmpVersion2c, nil)
	if resp := s.handleSNMPv2cRequest(req); len(resp) == 0 {
		t.Error("a PDU with an empty varbind list was discarded; only a MALFORMED list should be")
	}
}

// TestParseAllOIDsSignalsMalformedVsAbsent pins the two zero cases apart at the
// parser, since that distinction is the whole reason for the bool.
func TestParseAllOIDsSignalsMalformedVsAbsent(t *testing.T) {
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})

	oids, ok := s.parseAllOIDsFromRequest(malformedNameRequest(ASN1_GET_REQUEST, snmpVersion2c, 2, 1))
	if ok {
		t.Errorf("malformed name reported as parseable, returning %v", oids)
	}

	if _, ok := s.parseAllOIDsFromRequest([]byte{0x00, 0x01, 0x02}); !ok {
		t.Error("an unreadable envelope should report true (absent), not false (malformed): " +
			"reporting malformed there would discard datagrams the server used to answer")
	}
	if _, ok := s.parseAllOIDsFromRequest(nil); !ok {
		t.Error("nil input should report absent, not malformed")
	}
	if _, ok := s.parseAllOIDsFromRequest(requestWithVarbinds(ASN1_GET_REQUEST, snmpVersion2c, nil)); !ok {
		t.Error("an empty varbind list should report absent, not malformed")
	}
}
