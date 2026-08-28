/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"testing"
)

// v3TestServer builds an SNMPv3-enabled server over the supplied OID→value
// map. Privacy is off so the scoped PDU stays in the clear and its bytes can
// be asserted directly.
func v3TestServer(oidValues map[string]string) *SNMPServer {
	res := &DeviceResources{SNMP: make([]SNMPResource, 0, len(oidValues))}
	for oid, val := range oidValues {
		res.SNMP = append(res.SNMP, SNMPResource{OID: oid, Response: val})
	}
	(&SimulatorManager{}).buildResourceIndexes(res)

	return &SNMPServer{
		device: &DeviceSimulator{resources: res},
		v3Config: &SNMPv3Config{
			Enabled:      true,
			EngineID:     "0x80001234",
			Username:     "testuser",
			Password:     "s3cret",
			AuthProtocol: SNMPV3_AUTH_NONE,
			PrivProtocol: SNMPV3_PRIV_NONE,
		},
	}
}

// TestSNMPv3_ScopedPDUMatchesV2cTypes is the invariant nl6#518 violated: the
// same OID and value must carry the same ASN.1 type whichever protocol version
// answered. Before the fix, v3 encoded everything as INTEGER or OCTET STRING —
// a collector validated against nl6 over v3 was being validated against types
// no real agent emits.
//
// The comparison is on the encoded value, not the whole message: v2c and v3
// wrap it differently, but the varbind's value bytes must be identical.
func TestSNMPv3_ScopedPDUMatchesV2cTypes(t *testing.T) {
	tests := []struct {
		name  string
		oid   string
		value string
	}{
		{"Counter32 ifInOctets", ".1.3.6.1.2.1.2.2.1.10.1", "4294967290"},
		{"Gauge32 ifSpeed", ".1.3.6.1.2.1.2.2.1.5.1", "1000000000"},
		{"TimeTicks sysUpTime", ".1.3.6.1.2.1.1.3.0", "123456"},
		{"OBJECT IDENTIFIER sysObjectID", ".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.9.1.1404"},
		{"OCTET STRING sysDescr", ".1.3.6.1.2.1.1.1.0", "a device"},
		{"plain INTEGER", ".1.3.6.1.4.1.9.2.1.56.0", "62"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := v3TestServer(map[string]string{tt.oid: tt.value})

			scoped, err := s.createScopedPDU(tt.oid, tt.value, &SNMPv3Message{})
			if err != nil {
				t.Fatalf("createScopedPDU: %v", err)
			}

			want := encodeTypedValue(tt.oid, tt.value)
			if !bytes.Contains(scoped, want) {
				t.Errorf("v3 scoped PDU does not carry the v2c encoding.\n want value bytes: % x\n scoped PDU:      % x", want, scoped)
			}
		})
	}
}

// TestSNMPv3_EndOfMibViewIsAnException covers the walk-termination half of
// nl6#518. findNextOID returns the sentinel string, and before the fix v3 put
// the TEXT "endOfMibView" on the wire as an octet string. snmp4j terminates a
// walk on Null.isExceptionSyntax (syntax >= 128), which a string never
// satisfies, so a v3 walk did not stop where the protocol says it should.
func TestSNMPv3_EndOfMibViewIsAnException(t *testing.T) {
	s := v3TestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "a device"})

	for _, tc := range []struct {
		name  string
		value string
		tag   []byte
	}{
		{"endOfMibView", valueEndOfMibView, []byte{0x82, 0x00}},
		{"noSuchObject", valueNoSuchObject, []byte{0x80, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scoped, err := s.createScopedPDU(".1.3.6.1.2.1.1.1.0", tc.value, &SNMPv3Message{})
			if err != nil {
				t.Fatalf("createScopedPDU: %v", err)
			}

			if !bytes.Contains(scoped, tc.tag) {
				t.Errorf("scoped PDU lacks the %s tag % x:\n% x", tc.name, tc.tag, scoped)
			}
			if bytes.Contains(scoped, []byte(tc.value)) {
				t.Errorf("scoped PDU carries %q as text rather than as a tag:\n% x", tc.value, scoped)
			}
		})
	}
}
