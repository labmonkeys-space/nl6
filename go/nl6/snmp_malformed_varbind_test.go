/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"testing"
)

// A varbind name whose content is not a valid OBJECT IDENTIFIER encoding is an
// ASN.1 error. RFC 1157 and RFC 3412 discard such a datagram and perform no
// further actions; they do not answer it partially.
//
// Before nl6#537 the malformed binding was silently DROPPED and the response
// came back with fewer bindings than the request carried, against RFC 3416's
// correspondence requirement. The drop was near-unreachable until nl6#529 made
// decodeOID refuse malformed input rather than invent a value for it.

// malformedNameRequest builds a GET carrying `count` bindings, with the one at
// badIndex given an unterminated-varint OID name. Everything else is well
// formed, so the PDU is structurally fine and only the OID content is bad.
func malformedNameRequest(t *testing.T, version, count, badIndex int) []byte {
	t.Helper()

	var vbs []byte
	for i := 0; i < count; i++ {
		if i == badIndex {
			// 0x2b 0xff: a sub-identifier whose final octet still sets the
			// continuation bit, so the OID is truncated.
			name := []byte{ASN1_OID, 0x02, 0x2b, 0xff}
			vbs = append(vbs, encodeSequence(append(name, encodeNull()...))...)
			continue
		}
		vbs = append(vbs, encodeVarBind(".1.3.6.1.2.1.1.1.0", encodeNull())...)
	}

	var body []byte
	body = append(body, encodeInteger(42)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeSequence(vbs)...)
	pdu := append([]byte{ASN1_GET_REQUEST}, append(encodeLength(len(body)), body...)...)

	var msg []byte
	msg = append(msg, encodeInteger(version)...)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

func TestMalformedVarbindNameDiscardsTheDatagram(t *testing.T) {
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})

	for _, tc := range []struct {
		name            string
		version         int
		count, badIndex int
	}{
		{"v2c, second of three", snmpVersion2c, 3, 1},
		{"v2c, first of two", snmpVersion2c, 2, 0},
		{"v2c, only binding", snmpVersion2c, 1, 0},
		{"v1, second of three", snmpVersion1, 3, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := malformedNameRequest(t, tc.version, tc.count, tc.badIndex)

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

// TestWellFormedMultiVarbindStillAnswered is the positive control. Without it,
// a change that discarded every request would pass the test above.
func TestWellFormedMultiVarbindStillAnswered(t *testing.T) {
	s := newTestServer(map[string]string{
		".1.3.6.1.2.1.1.1.0":     "dev",
		".1.3.6.1.2.1.2.2.1.2.1": "Gi0/1",
	})

	oids := []string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.2.2.1.2.1", ".1.3.6.1.2.1.1.1.0"}
	resp := s.handleSNMPv2cRequest(snmpRequestAt(ASN1_GET_REQUEST, snmpVersion2c, oids))
	if len(resp) == 0 {
		t.Fatal("a well-formed multi-varbind GET was discarded")
	}
	if got := countVarbinds(t, resp); got != len(oids) {
		t.Errorf("response carries %d bindings, request carried %d: RFC 3416 wants them to correspond",
			got, len(oids))
	}
}

// TestEmptyVarbindListStillAnswered pins the distinction the bool exists for.
// A PDU whose variable-bindings list is absent or unreadable is NOT the same as
// one carrying a malformed name: the former is answered from the single parsed
// OID, the latter is discarded.
func TestEmptyVarbindListStillAnswered(t *testing.T) {
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})

	var body []byte
	body = append(body, encodeInteger(42)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeSequence(nil)...) // empty variable-bindings
	pdu := append([]byte{ASN1_GET_REQUEST}, append(encodeLength(len(body)), body...)...)
	var msg []byte
	msg = append(msg, encodeInteger(snmpVersion2c)...)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)

	if resp := s.handleSNMPv2cRequest(encodeSequence(msg)); len(resp) == 0 {
		t.Error("a PDU with an empty varbind list was discarded; only a MALFORMED name should be")
	}
}

// TestParseAllOIDsSignalsMalformedVsAbsent pins the two zero cases apart at the
// parser, since that distinction is the whole reason for the bool.
func TestParseAllOIDsSignalsMalformedVsAbsent(t *testing.T) {
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})

	oids, ok := s.parseAllOIDsFromRequest(malformedNameRequest(t, snmpVersion2c, 2, 1))
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
}

// TestMalformedVarbindNameDiscardsGetBulk covers the other consumer.
func TestMalformedVarbindNameDiscardsGetBulk(t *testing.T) {
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "dev"})

	name := []byte{ASN1_OID, 0x02, 0x2b, 0xff}
	vbs := encodeSequence(append(name, encodeNull()...))
	var body []byte
	body = append(body, encodeInteger(42)...)
	body = append(body, encodeInteger(0)...)
	body = append(body, encodeInteger(10)...)
	body = append(body, encodeSequence(vbs)...)
	pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)
	var msg []byte
	msg = append(msg, encodeInteger(snmpVersion2c)...)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)

	if resp := s.handleGetBulk(".1.3.6.1.2.1.1.1.0", encodeSequence(msg)); len(resp) != 0 {
		t.Errorf("GETBULK with a malformed varbind name was answered with %d bytes", len(resp))
	}
}

// countVarbinds decodes a v2c GetResponse and returns its binding count.
func countVarbinds(t *testing.T, resp []byte) int {
	t.Helper()
	body := expectSeq(t, resp, "message")
	pos := skipTLV(t, body, 0, "version")
	pos = skipTLV(t, body, pos, "community")
	if pos >= len(body) {
		t.Fatal("no PDU")
	}
	n, after := parseLength(body, pos+1)
	if n < 0 || after+n > len(body) {
		t.Fatal("bad PDU length")
	}
	pdu := body[after : after+n]
	pp := 0
	_, pp = expectInt(t, pdu, pp, "request-id")
	_, pp = expectInt(t, pdu, pp, "error-status")
	_, pp = expectInt(t, pdu, pp, "error-index")
	vbl := expectSeq(t, pdu[pp:], "variable-bindings")

	count := 0
	for vp := 0; vp < len(vbl); {
		expectSeq(t, vbl[vp:], "varbind")
		n2, after2 := parseLength(vbl, vp+1)
		if n2 < 0 || after2+n2 > len(vbl) {
			t.Fatal("bad varbind length")
		}
		vp = after2 + n2
		count++
	}
	return count
}
