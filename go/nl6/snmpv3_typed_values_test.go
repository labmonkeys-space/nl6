/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"testing"
)

// v3TestServer is newTestServer with SNMPv3 enabled. Privacy is off so
// the scoped PDU stays in the clear and its bytes can be asserted directly.
func v3TestServer(oidValues map[string]string) *SNMPServer {
	s := newTestServer(oidValues)
	s.v3Config = &SNMPv3Config{
		Enabled:      true,
		EngineID:     "0x80001234",
		Username:     "testuser",
		Password:     "s3cret",
		AuthProtocol: SNMPV3_AUTH_NONE,
		PrivProtocol: SNMPV3_PRIV_NONE,
	}
	return s
}

// TestSNMPv3_ScopedPDUMatchesV2cTypes is the invariant nl6#518 violated: the
// same OID and value must carry the same ASN.1 type whichever protocol version
// answered. Before the fix, v3 encoded everything as INTEGER or OCTET STRING;
// a collector validated against nl6 over v3 was being validated against types
// no real agent emits.
//
// Each row is checked three ways. The value TLV is read out of the varbind at
// its position (not searched for with bytes.Contains, which a short encoding
// such as `02 01 3e` can satisfy elsewhere in the message). Its tag is compared
// with the literal ASN.1 tag the MIB assigns, so a wrong oidTypeTable entry
// fails here rather than passing on both paths. And it is compared with the
// bytes the v2c GetResponse carries for the same request, which is the parity
// the issue asks for.
func TestSNMPv3_ScopedPDUMatchesV2cTypes(t *testing.T) {
	tests := []struct {
		name  string
		oid   string
		value string
		tag   byte
	}{
		{"Counter32 ifInOctets", ".1.3.6.1.2.1.2.2.1.10.1", "4294967290", ASN1_COUNTER32},
		{"Counter64 ifHCInOctets", ".1.3.6.1.2.1.31.1.1.1.6.1", "18446744073709551610", ASN1_COUNTER64},
		{"Gauge32 ifSpeed", ".1.3.6.1.2.1.2.2.1.5.1", "1000000000", ASN1_GAUGE32},
		{"TimeTicks sysUpTime", ".1.3.6.1.2.1.1.3.0", "123456", ASN1_TIMETICKS},
		{"IpAddress ipAdEntAddr", ".1.3.6.1.2.1.4.20.1.1.10.42.0.1", "10.42.0.1", ASN1_IPADDRESS},
		{"OBJECT IDENTIFIER sysObjectID", ".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.9.1.1404", ASN1_OID},
		{"OCTET STRING sysDescr", ".1.3.6.1.2.1.1.1.0", "a device", ASN1_OCTET_STRING},
		{"plain INTEGER", ".1.3.6.1.4.1.9.2.1.56.0", "62", ASN1_INTEGER},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := v3TestServer(map[string]string{tt.oid: tt.value})

			scoped, err := s.createScopedPDU(tt.oid, tt.value, &SNMPv3Message{})
			if err != nil {
				t.Fatalf("createScopedPDU: %v", err)
			}
			_, v3Value := decodeScopedPDUFirstVarbind(t, scoped[expectTag(t, scoped, 0, ASN1_SEQUENCE):])

			if v3Value[0] != tt.tag {
				t.Errorf("v3 value tag = 0x%02X, want 0x%02X (value bytes % x)", v3Value[0], tt.tag, v3Value)
			}

			v2c := decodeResponseHeader(t, s.createSNMPResponse(tt.oid, tt.value, v2cGetRequest(tt.oid)))
			_, v2cValue := decodeFirstVarbind(t, v2c.varbinds)
			if !bytes.Equal(v3Value, v2cValue) {
				t.Errorf("v3 and v2c disagree on the value encoding.\n v3:  % x\n v2c: % x", v3Value, v2cValue)
			}
		})
	}
}

// TestSNMPv3_EndOfMibViewIsAnException covers the encoder half of nl6#518 at
// the seam: hand the sentinels to createScopedPDU and read the value TLV back.
// Before the fix v3 put the TEXT "endOfMibView" on the wire as an octet string.
func TestSNMPv3_EndOfMibViewIsAnException(t *testing.T) {
	s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "a device"})

	for _, tc := range []struct {
		name  string
		value string
		want  []byte
	}{
		{"endOfMibView", valueEndOfMibView, wireEndOfMibView},
		{"noSuchObject", valueNoSuchObject, wireNoSuchObject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scoped, err := s.createScopedPDU(".1.3.6.1.2.1.1.1.0", tc.value, &SNMPv3Message{})
			if err != nil {
				t.Fatalf("createScopedPDU: %v", err)
			}

			_, got := decodeScopedPDUFirstVarbind(t, scoped[expectTag(t, scoped, 0, ASN1_SEQUENCE):])
			if !bytes.Equal(got, tc.want) {
				t.Errorf("value TLV = % x, want %s % x", got, tc.name, tc.want)
			}
			if bytes.Contains(scoped, []byte(tc.value)) {
				t.Errorf("scoped PDU carries %q as text rather than as a tag:\n% x", tc.value, scoped)
			}
		})
	}
}

// TestSNMPv3_GetNextPastEndTerminatesWalk drives the walk-termination half of
// nl6#518 end to end: a noAuthNoPriv GETNEXT for the last OID goes through
// handleSNMPv3Request, findNextOID and createSNMPv3Response, and the final
// varbind must come back as the endOfMibView exception with the request's own
// name and request-id. snmp4j stops a walk on Null.isExceptionSyntax (syntax
// >= 128), which the pre-fix octet string never satisfied.
//
// This covers GETNEXT only. handleSNMPv3GetBulk drops the sentinel before it
// reaches the encoder, so a GETBULK-driven v3 walk still does not terminate on
// the exception; that is a separate, pre-existing defect.
func TestSNMPv3_GetNextPastEndTerminatesWalk(t *testing.T) {
	// findNextOID always serves sysName.0 and sysLocation.0 dynamically, so the
	// walk's last OID has to sort after .1.3.6.1.2.1.1.6.0 for the GETNEXT to
	// run off the end of the view.
	const last = ".1.3.6.1.4.1.9.2.1.56.0"
	const requestID = 4242
	s := v3TestServer(map[string]string{last: "62"})

	resp := s.handleSNMPv3Request(v3GetNextRequest(t, s, requestID, last))
	if len(resp) == 0 {
		t.Fatal("handleSNMPv3Request returned an empty response")
	}
	msg, err := s.parseSNMPv3Message(resp)
	if err != nil {
		t.Fatalf("response does not parse as SNMPv3: %v", err)
	}

	gotID, oid, value := decodeScopedPDU(t, msg.ScopedPDU)
	if gotID != requestID {
		t.Errorf("response request-id = %d, want %d", gotID, requestID)
	}
	if oid != last {
		t.Errorf("response OID = %s, want the request's own name %s", oid, last)
	}
	if !bytes.Equal(value, wireEndOfMibView) {
		t.Errorf("value TLV = % x, want endOfMibView % x", value, wireEndOfMibView)
	}
	if bytes.Contains(resp, []byte(valueEndOfMibView)) {
		t.Errorf("response carries %q as text:\n% x", valueEndOfMibView, resp)
	}
}

// v3GetNextRequest builds a noAuthNoPriv SNMPv3 GETNEXT for oid, addressed to
// the server's engine and user, using the package's own encoders. A
// request-shaping helper, not a golden fixture.
func v3GetNextRequest(t *testing.T, s *SNMPServer, requestID int, oid string) []byte {
	t.Helper()

	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(requestID)...)
	pduBody = append(pduBody, encodeInteger(0)...) // error-status
	pduBody = append(pduBody, encodeInteger(0)...) // error-index
	pduBody = append(pduBody, encodeSequence(encodeVarBind(oid, encodeNull()))...)

	pdu := []byte{ASN1_GET_NEXT}
	pdu = append(pdu, encodeLength(len(pduBody))...)
	pdu = append(pdu, pduBody...)

	var scoped []byte
	scoped = append(scoped, encodeOctetString(s.v3Config.EngineID)...) // contextEngineID
	scoped = append(scoped, encodeOctetString("")...)                  // contextName
	scoped = append(scoped, pdu...)

	usm, err := s.encodeUSMSecurityParameters(&SNMPv3SecurityParams{
		AuthoritativeEngineID: s.v3Config.EngineID,
		UserName:              s.v3Config.Username,
	})
	if err != nil {
		t.Fatalf("encodeUSMSecurityParameters: %v", err)
	}
	req, err := s.encodeSNMPv3Message(&SNMPv3Message{
		Version: SNMPV3_VERSION,
		GlobalData: SNMPv3GlobalData{
			MsgID:            7,
			MsgMaxSize:       65507,
			MsgSecurityModel: SNMPV3_SECURITY_MODEL_USM,
		},
		ScopedPDU: encodeSequence(scoped),
	}, usm)
	if err != nil {
		t.Fatalf("encodeSNMPv3Message: %v", err)
	}
	return req
}

// decodeScopedPDU reads a plaintext scoped-PDU body (the contents of its outer
// SEQUENCE, as parseSNMPv3Message returns it) and yields the request-id plus
// the first varbind's OID and value TLV.
func decodeScopedPDU(t *testing.T, body []byte) (requestID int, oid string, value []byte) {
	t.Helper()
	var err error

	pos := 0
	for _, field := range []string{"contextEngineID", "contextName"} {
		if _, pos, err = parseOctetString(body, pos); err != nil {
			t.Fatalf("%s: %v", field, err)
		}
	}
	pos = expectTag(t, body, pos, ASN1_GET_RESPONSE)
	if requestID, pos, err = parseInteger(body, pos); err != nil {
		t.Fatalf("request-id: %v", err)
	}
	for _, field := range []string{"error-status", "error-index"} {
		if _, pos, err = parseInteger(body, pos); err != nil {
			t.Fatalf("%s: %v", field, err)
		}
	}
	pos = expectTag(t, body, pos, ASN1_SEQUENCE) // VarBindList
	oid, value = decodeFirstVarbind(t, body[pos:])
	return requestID, oid, value
}

// decodeScopedPDUFirstVarbind is decodeScopedPDU without the request-id.
func decodeScopedPDUFirstVarbind(t *testing.T, body []byte) (string, []byte) {
	t.Helper()
	_, oid, value := decodeScopedPDU(t, body)
	return oid, value
}

// decodeFirstVarbind reads the first VarBind out of VarBindList contents and
// returns its OID and its value TLV (tag, length and contents).
func decodeFirstVarbind(t *testing.T, varbinds []byte) (string, []byte) {
	t.Helper()
	pos := expectTag(t, varbinds, 0, ASN1_SEQUENCE)
	oidStart := expectTag(t, varbinds, pos, ASN1_OID)
	oidLen, _ := parseLength(varbinds, pos+1)
	oid := decodeOID(varbinds[oidStart : oidStart+oidLen])
	pos = oidStart + oidLen
	if pos >= len(varbinds) {
		t.Fatalf("varbind has no value at %d", pos)
	}
	n, next := parseLength(varbinds, pos+1)
	if n < 0 || next+n > len(varbinds) {
		t.Fatalf("bad value length at %d", pos)
	}
	return oid, varbinds[pos : next+n]
}
