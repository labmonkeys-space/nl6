/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"testing"
)

// RFC 3416 exceptions occupy the varbind's value position as context-specific,
// primitive, zero-length tags. These are the byte sequences OpenNMS decodes via
// SnmpValue.SNMP_NO_SUCH_OBJECT (0x80) and SNMP_END_OF_MIB (0x82), and snmp4j
// via Null.isExceptionSyntax.
var (
	wireNoSuchObject = []byte{0x80, 0x00}
	wireEndOfMibView = []byte{0x82, 0x00}
)

func TestEncodeTypedValue_Exceptions(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []byte
	}{
		{"noSuchObject", valueNoSuchObject, wireNoSuchObject},
		{"endOfMibView", valueEndOfMibView, wireEndOfMibView},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The OID is a Counter32 column, so a value-typed encoding would
			// produce an application tag rather than the exception. This
			// asserts the exception wins over the OID's declared type.
			got := encodeTypedValue(".1.3.6.1.2.1.2.2.1.10.1", tt.value)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("encodeTypedValue(%q) = % x, want % x", tt.value, got, tt.want)
			}
		})
	}
}

// TestFindResponse_UnknownOIDYieldsException pins the source of the sentinel.
// Before nl6#517 this returned the octet string "OID not supported", which a
// manager receives as data.
func TestFindResponse_UnknownOIDYieldsException(t *testing.T) {
	s := exceptionTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "a device"})

	if got := s.findResponse(".1.3.6.1.4.1.9.2.1.46.0"); got != valueNoSuchObject {
		t.Errorf("findResponse(unknown) = %q, want %q", got, valueNoSuchObject)
	}
	if got := s.findResponse(".1.3.6.1.2.1.1.1.0"); got != "a device" {
		t.Errorf("findResponse(known) = %q, want the stored value", got)
	}
}

// TestGetResponse_UnknownOIDCarriesNoSuchObject asserts the exception survives
// into an assembled v2c GetResponse, with error-status left at noError — the
// response is a success and the exception is per-varbind (RFC 3416 §4.2.1).
func TestGetResponse_UnknownOIDCarriesNoSuchObject(t *testing.T) {
	s := exceptionTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "a device"})

	const unknown = ".1.3.6.1.4.1.9.2.1.46.0"
	resp := s.createSNMPResponse(unknown, s.findResponse(unknown), v2cGetRequest(unknown))

	if !bytes.Contains(resp, wireNoSuchObject) {
		t.Errorf("response does not carry the noSuchObject tag % x:\n% x", wireNoSuchObject, resp)
	}
	// The string must be gone entirely — a manager seeing it would treat the
	// unimplemented OID as data.
	if bytes.Contains(resp, []byte("OID not supported")) || bytes.Contains(resp, []byte(valueNoSuchObject)) {
		t.Errorf("response carries the sentinel as text rather than as a tag:\n% x", resp)
	}
	hdr := decodeResponseHeader(t, resp)
	if hdr.errStatus != snmpErrNoError || hdr.errIndex != 0 {
		t.Errorf("v2c exception response has error-status=%d error-index=%d, want noError/0", hdr.errStatus, hdr.errIndex)
	}
}

// TestGetResponse_SNMPv1MapsExceptionToNoSuchName covers the half of nl6#517
// the issue did not report. SNMPv1 has no exception values, so RFC 3584
// §4.2.2.2 requires the noSuchName error-status instead, with error-index at
// the offending varbind (§4.2.2.2.1 noSuchObject, §4.2.2.2.2 endOfMibView).
// Emitting 0x80 or 0x82 to a v1 manager is itself a violation — and nl6
// already did that for endOfMibView.
func TestGetResponse_SNMPv1MapsExceptionToNoSuchName(t *testing.T) {
	s := exceptionTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "a device"})

	const unknown = ".1.3.6.1.4.1.9.2.1.46.0"

	for _, value := range []string{valueNoSuchObject, valueEndOfMibView} {
		t.Run(value, func(t *testing.T) {
			resp := s.createSNMPResponse(unknown, value, v1GetRequest(unknown))
			assertNoExceptionTags(t, resp)

			hdr := decodeResponseHeader(t, resp)
			if hdr.version != snmpVersion1 {
				t.Errorf("version = %d, want %d", hdr.version, snmpVersion1)
			}
			if hdr.errStatus != snmpErrNoSuchName || hdr.errIndex != 1 {
				t.Errorf("error-status=%d error-index=%d, want noSuchName(%d)/1", hdr.errStatus, hdr.errIndex, snmpErrNoSuchName)
			}
		})
	}
}

// TestGetResponse_SNMPv1MultiVarbindErrorIndex exercises the diversion in
// createVarbindResponse, which is the path a real v1 snmpget reaches through
// handleGetRequestVarbinds. error-index must point at the FIRST offending
// binding, 1-based, and every requested name must be echoed with a NULL value
// (RFC 1157 §4.1.3: the response's variable-bindings are the request's).
func TestGetResponse_SNMPv1MultiVarbindErrorIndex(t *testing.T) {
	const known, known2 = ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.5.0"
	const unknown, unknown2 = ".1.3.6.1.4.1.9.2.1.46.0", ".1.3.6.1.4.1.9.2.1.47.0"
	s := exceptionTestServer(map[string]string{known: "a device", known2: "host"})

	tests := []struct {
		name      string
		oids      []string
		wantIndex int
	}{
		{"second of two", []string{known, unknown}, 2},
		{"third of three", []string{known, known2, unknown}, 3},
		{"first of two exceptions", []string{known, unknown, unknown2}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := s.handleGetRequestVarbinds(tt.oids, getRequestAtVersionMulti(snmpVersion1, tt.oids))
			assertNoExceptionTags(t, resp)

			hdr := decodeResponseHeader(t, resp)
			if hdr.errStatus != snmpErrNoSuchName || hdr.errIndex != tt.wantIndex {
				t.Errorf("error-status=%d error-index=%d, want noSuchName/%d", hdr.errStatus, hdr.errIndex, tt.wantIndex)
			}
			var wantVarbinds []byte
			for _, o := range tt.oids {
				wantVarbinds = append(wantVarbinds, encodeVarBind(o, encodeNull())...)
			}
			if !bytes.Equal(hdr.varbinds, wantVarbinds) {
				t.Errorf("varbinds are not the request echoed with NULL values:\n got % x\nwant % x", hdr.varbinds, wantVarbinds)
			}
		})
	}
}

// TestGetResponse_SNMPv1KnownOIDUnaffected pins that the diversion is keyed on
// the sentinel, not on the version: a v1 GET for an implemented OID is a
// normal noError response carrying the value.
func TestGetResponse_SNMPv1KnownOIDUnaffected(t *testing.T) {
	const known = ".1.3.6.1.2.1.1.1.0"
	s := exceptionTestServer(map[string]string{known: "a device"})

	resp := s.handleGetRequestVarbinds([]string{known}, v1GetRequest(known))
	hdr := decodeResponseHeader(t, resp)
	if hdr.errStatus != snmpErrNoError || hdr.errIndex != 0 {
		t.Errorf("v1 GET of a known OID: error-status=%d error-index=%d, want noError/0", hdr.errStatus, hdr.errIndex)
	}
	if !bytes.Contains(hdr.varbinds, encodeOctetString("a device")) {
		t.Errorf("v1 GET of a known OID does not carry the value:\n% x", hdr.varbinds)
	}
}

// TestGetBulkResponse_SNMPv1NotDiverted pins the rule gate. GETBULK does not
// exist in SNMPv1, so a version-0 GETBULK is malformed and is answered as it
// always was: its OIDs are walked, not requested, so the noSuchName echo would
// be neither the RFC 1157 request echo nor bounded by the datagram budget.
func TestGetBulkResponse_SNMPv1NotDiverted(t *testing.T) {
	const known = ".1.3.6.1.2.1.1.1.0"
	s := exceptionTestServer(map[string]string{known: "a device"})

	oids := []string{known, known}
	resp := s.createGetBulkResponse(oids, []string{"a device", valueEndOfMibView}, getRequestAtVersionMulti(snmpVersion1, oids))
	hdr := decodeResponseHeader(t, resp)
	if hdr.errStatus != snmpErrNoError {
		t.Errorf("v1 GETBULK was diverted: error-status=%d, want noError", hdr.errStatus)
	}
	if !bytes.Contains(hdr.varbinds, wireEndOfMibView) {
		t.Errorf("v1 GETBULK lost its endOfMibView binding:\n% x", hdr.varbinds)
	}
}

func assertNoExceptionTags(t *testing.T, resp []byte) {
	t.Helper()
	for _, tag := range [][]byte{wireNoSuchObject, wireEndOfMibView} {
		if bytes.Contains(resp, tag) {
			t.Errorf("v1 response carries exception tag % x; v1 has no exceptions:\n% x", tag, resp)
		}
	}
}

// responseHeader is the decoded fixed part of a GetResponse message. The
// fields are read at their positions, not searched for: a bytes.Contains on
// `02 01 02` would also match a request-id of 2.
type responseHeader struct {
	version, requestID, errStatus, errIndex int
	varbinds                                []byte // contents of the VarBindList SEQUENCE
}

func decodeResponseHeader(t *testing.T, resp []byte) responseHeader {
	t.Helper()
	var h responseHeader
	var err error

	pos := expectTag(t, resp, 0, ASN1_SEQUENCE)
	if h.version, pos, err = parseInteger(resp, pos); err != nil {
		t.Fatalf("version: %v", err)
	}
	if _, pos, err = parseOctetString(resp, pos); err != nil {
		t.Fatalf("community: %v", err)
	}
	pos = expectTag(t, resp, pos, SNMP_GET_RESPONSE)
	if h.requestID, pos, err = parseInteger(resp, pos); err != nil {
		t.Fatalf("request-id: %v", err)
	}
	if h.errStatus, pos, err = parseInteger(resp, pos); err != nil {
		t.Fatalf("error-status: %v", err)
	}
	if h.errIndex, pos, err = parseInteger(resp, pos); err != nil {
		t.Fatalf("error-index: %v", err)
	}
	if pos >= len(resp) || resp[pos] != ASN1_SEQUENCE {
		t.Fatalf("expected VarBindList SEQUENCE at %d", pos)
	}
	n, start := parseLength(resp, pos+1)
	if n < 0 || start+n != len(resp) {
		t.Fatalf("VarBindList length %d at %d does not end the message (len %d)", n, start, len(resp))
	}
	h.varbinds = resp[start : start+n]
	return h
}

// expectTag checks the tag byte at pos and skips its length, returning the
// position of the contents.
func expectTag(t *testing.T, data []byte, pos int, tag byte) int {
	t.Helper()
	if pos >= len(data) || data[pos] != tag {
		t.Fatalf("expected tag 0x%02X at %d", tag, pos)
	}
	n, next := parseLength(data, pos+1)
	if n < 0 || next+n > len(data) {
		t.Fatalf("bad length after tag 0x%02X at %d", tag, pos)
	}
	return next
}

// exceptionTestServer builds an SNMPServer over the supplied OID→value map.
//
// It duplicates snmp_getbulk_test.go's newTestServer rather than calling it:
// that file carries //go:build linux, so its helper is invisible on macOS and
// a test depending on it cannot be run during local development — it would
// only ever be exercised in CI.
func exceptionTestServer(oidValues map[string]string) *SNMPServer {
	res := &DeviceResources{SNMP: make([]SNMPResource, 0, len(oidValues))}
	for oid, val := range oidValues {
		res.SNMP = append(res.SNMP, SNMPResource{OID: oid, Response: val})
	}
	(&SimulatorManager{}).buildResourceIndexes(res)
	return &SNMPServer{device: &DeviceSimulator{resources: res}}
}

// v2cGetRequest and v1GetRequest build a minimal GET for the given OID at the
// given version, using the package's own encoders. These are request-shaping
// helpers, not golden fixtures — the wire-verified client captures live in
// snmp_golden_packets_test.go.
func v2cGetRequest(oid string) []byte { return getRequestAtVersion(snmpVersion2c, oid) }
func v1GetRequest(oid string) []byte  { return getRequestAtVersion(snmpVersion1, oid) }

func getRequestAtVersion(version int, oid string) []byte {
	return getRequestAtVersionMulti(version, []string{oid})
}

func getRequestAtVersionMulti(version int, oids []string) []byte {
	var varbinds []byte
	for _, oid := range oids {
		varbinds = append(varbinds, encodeVarBind(oid, encodeNull())...)
	}

	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(42)...) // request-id
	pduBody = append(pduBody, encodeInteger(0)...)  // error-status
	pduBody = append(pduBody, encodeInteger(0)...)  // error-index
	pduBody = append(pduBody, encodeSequence(varbinds)...)

	pdu := []byte{ASN1_GET_REQUEST}
	pdu = append(pdu, encodeLength(len(pduBody))...)
	pdu = append(pdu, pduBody...)

	var msg []byte
	msg = append(msg, encodeInteger(version)...)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}
