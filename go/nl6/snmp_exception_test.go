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
}

// TestGetResponse_SNMPv1MapsExceptionToNoSuchName covers the half of nl6#517
// the issue did not report. SNMPv1 has no exception values, so RFC 3584
// §4.2.2.2.1 requires the noSuchName error-status instead, with error-index at
// the offending varbind. Emitting 0x80 or 0x82 to a v1 manager is itself a
// violation — and nl6 already did that for endOfMibView.
func TestGetResponse_SNMPv1MapsExceptionToNoSuchName(t *testing.T) {
	s := exceptionTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "a device"})

	const unknown = ".1.3.6.1.4.1.9.2.1.46.0"

	for _, value := range []string{valueNoSuchObject, valueEndOfMibView} {
		t.Run(value, func(t *testing.T) {
			resp := s.createSNMPResponse(unknown, value, v1GetRequest(unknown))

			for _, tag := range [][]byte{wireNoSuchObject, wireEndOfMibView} {
				if bytes.Contains(resp, tag) {
					t.Errorf("v1 response carries exception tag % x; v1 has no exceptions:\n% x", tag, resp)
				}
			}

			// error-status = noSuchName(2), error-index = 1. Both are 1-byte
			// INTEGERs, so they appear as 02 01 02 followed by 02 01 01.
			want := []byte{0x02, 0x01, snmpErrNoSuchName, 0x02, 0x01, 0x01}
			if !bytes.Contains(resp, want) {
				t.Errorf("v1 response lacks error-status noSuchName + error-index 1 (% x):\n% x", want, resp)
			}
		})
	}
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
func v2cGetRequest(oid string) []byte { return getRequestAtVersion(1, oid) }
func v1GetRequest(oid string) []byte  { return getRequestAtVersion(snmpVersion1, oid) }

func getRequestAtVersion(version int, oid string) []byte {
	varbind := encodeVarBind(oid, encodeNull())

	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(42)...) // request-id
	pduBody = append(pduBody, encodeInteger(0)...)  // error-status
	pduBody = append(pduBody, encodeInteger(0)...)  // error-index
	pduBody = append(pduBody, encodeSequence(varbind)...)

	pdu := []byte{ASN1_GET_REQUEST}
	pdu = append(pdu, encodeLength(len(pduBody))...)
	pdu = append(pdu, pduBody...)

	var msg []byte
	msg = append(msg, encodeInteger(version)...)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}
