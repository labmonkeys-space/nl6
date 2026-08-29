/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
)

// Test helpers shared across the SNMP suites. This file is deliberately
// UNTAGGED: some SNMP suites carry //go:build linux (the list lives in
// CLAUDE.md, "SNMP test helpers are split by build tag"), so a helper defined
// in one of those is invisible to the untagged suites and cannot be exercised
// during local development on macOS, only in CI. Keeping the constructors here
// is what lets one definition serve both halves.
//
// New shared SNMP test helpers belong here, not in a suite-specific file.

// newTestServer returns an SNMPServer backed by the supplied OID→value map.
// Indexes are built via buildResourceIndexes so findNextOID works correctly.
//
// The server is deliberately minimal, and what it does NOT have matters as
// much as what it does. The DeviceSimulator is zero-valued: no IP, no
// sysName/sysLocation, no metricsCycler (so no ifCounters/InterfaceState),
// and no v3Config (see v3TestServer). It also assumes the package globals are
// at their defaults, which every test that sets them restores in t.Cleanup:
// manager == nil and ifStateConfig.Scenario == IfScenarioAllNormal.
// Consequences in findResponse: the CPU/memory and IF-MIB dispatch is skipped
// (metricsCycler == nil), the interface-state override is inert (AllNormal),
// and the LLDP provider returns "" (lldpManager() == nil), so every OID
// resolves against the static index. This constructor is for the static OID
// lookup, encoding and walk paths.
//
// One trap: buildResourceIndexes drops sysName (.1.3.6.1.2.1.1.5.0) and
// sysLocation (.1.3.6.1.2.1.1.6.0) because findResponse serves them from the
// device fields instead. Passing either here would NOT make it a known OID:
// findResponse would return the zero-valued device's "", which is neither
// the supplied value nor an exception sentinel, and a test would assert
// against that silently. The constructor therefore panics on them, matching
// with or without the leading dot as buildResourceIndexes does; pick a
// different value-bearing OID (sysContact .1.3.6.1.2.1.1.4.0 is a safe
// DisplayString). The guard cannot cover the walk side: findNextOID always
// injects sysName.0 and sysLocation.0 as candidates, so a GETNEXT/GETBULK
// through the system group yields two empty-valued bindings the caller never
// supplied (see TestSNMPv3_GetNextPastEndTerminatesWalk for the workaround).
func newTestServer(oidValues map[string]string) *SNMPServer {
	res := &DeviceResources{
		SNMP: make([]SNMPResource, 0, len(oidValues)),
	}
	for oid, val := range oidValues {
		if norm := strings.TrimPrefix(oid, "."); norm == "1.3.6.1.2.1.1.5.0" || norm == "1.3.6.1.2.1.1.6.0" {
			panic("newTestServer: " + oid + " is served from device fields, not the OID index; use another OID")
		}
		res.SNMP = append(res.SNMP, SNMPResource{OID: oid, Response: val})
	}
	sm := &SimulatorManager{}
	sm.buildResourceIndexes(res)

	device := &DeviceSimulator{resources: res}
	return &SNMPServer{device: device}
}

// v3TestServer is newTestServer with SNMPv3 enabled at noAuthNoPriv: no
// HMAC to compute and the scoped PDU stays in the clear, so the response
// bytes can be asserted directly.
func v3TestServer(oidValues map[string]string) *SNMPServer {
	s := newTestServer(oidValues)
	s.v3Config = &SNMPv3Config{
		Enabled:      true,
		EngineID:     "0x80001234",
		Username:     "testuser",
		Password:     "s3cret", // inert: no auth, no priv
		AuthProtocol: SNMPV3_AUTH_NONE,
		PrivProtocol: SNMPV3_PRIV_NONE,
	}
	return s
}

// snmpRequestAt builds a minimal SNMP request message with the given PDU tag,
// version and variable-binding names, each encoded with a NULL value the way a
// manager sends them.
//
// The PDU tag is a parameter because before nl6#524 every builder in the
// package hardcoded ASN1_GET_REQUEST, so no suite could construct a GETNEXT at
// a chosen version, and the v1 GETNEXT skip had no way to be tested at the
// wire level.
func snmpRequestAt(pduTag byte, version int, oids []string) []byte {
	var varbinds []byte
	for _, oid := range oids {
		varbinds = append(varbinds, encodeVarBind(oid, encodeNull())...)
	}

	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(42)...) // request-id
	// For a GETBULK tag these two integers are non-repeaters and
	// max-repetitions (RFC 3416 §4.2.3), not error-status and error-index, so
	// a GETBULK built here asks for ZERO repetitions. That is enough for the
	// tests that only need a version-0/version-1 GETBULK to parse; a test that
	// needs real repetitions must build its own PDU.
	pduBody = append(pduBody, encodeInteger(0)...) // error-status (GETBULK: non-repeaters)
	pduBody = append(pduBody, encodeInteger(0)...) // error-index  (GETBULK: max-repetitions)
	pduBody = append(pduBody, encodeSequence(varbinds)...)

	pdu := []byte{pduTag}
	pdu = append(pdu, encodeLength(len(pduBody))...)
	pdu = append(pdu, pduBody...)

	var msg []byte
	msg = append(msg, encodeInteger(version)...)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// countVarbinds decodes a v1/v2c GetResponse and returns its binding count.
// Lives here rather than beside countResponseVarbinds because that one sits in
// the linux-tagged snmp_getbulk_test.go family and is invisible to the
// untagged suites (see the build-tag note in CLAUDE.md).
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
