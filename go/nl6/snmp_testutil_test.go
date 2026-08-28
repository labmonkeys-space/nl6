/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

// Test helpers shared across the SNMP suites. This file is deliberately
// UNTAGGED: snmp_getbulk_test.go and snmp_response_size_test.go carry
// //go:build linux, so a helper defined in either of them is invisible to the
// untagged suites and cannot be exercised during local development on macOS —
// only in CI. Keeping the constructor here is what lets one definition serve
// both halves; before this, the exception suite carried its own copy of it.
//
// New shared SNMP test helpers belong here, not in a suite-specific file.

// newTestServer returns an SNMPServer backed by the supplied OID→value map.
// Indexes are built via buildResourceIndexes so findNextOID works correctly.
//
// The server is deliberately minimal, and what it does NOT have matters as
// much as what it does. There is no device IP, no ifCounters/InterfaceState,
// no v3Config (see v3TestServer in snmpv3_typed_values_test.go), and no global
// manager installed. Anything reaching the dynamic IF-MIB dispatcher, the LLDP
// provider or the gNMI paths — all of which read per-device engines or the
// global manager — will therefore nil-path or serve zeros. This constructor is
// for the static OID lookup, encoding and walk paths.
//
// One trap: buildResourceIndexes drops sysName (.1.3.6.1.2.1.1.5.0) and
// sysLocation (.1.3.6.1.2.1.1.6.0) because live devices serve them from
// elsewhere. Passing either here does NOT make it a known OID — findResponse
// returns "" for it, which is neither the supplied value nor an exception
// sentinel. Pick a different OID when a test needs a value-bearing one.
func newTestServer(oidValues map[string]string) *SNMPServer {
	res := &DeviceResources{
		SNMP: make([]SNMPResource, 0, len(oidValues)),
	}
	for oid, val := range oidValues {
		res.SNMP = append(res.SNMP, SNMPResource{OID: oid, Response: val})
	}
	sm := &SimulatorManager{}
	sm.buildResourceIndexes(res)

	device := &DeviceSimulator{resources: res}
	return &SNMPServer{device: device}
}
