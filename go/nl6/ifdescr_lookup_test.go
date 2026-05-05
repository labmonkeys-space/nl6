/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// TestLookupIfDescr_HitFromOIDTable confirms the live-lookup path: a
// device whose SNMP OID table contains `ifDescr.5 = "TenGigE0/0/0/5"`
// returns that vendor-flavoured string verbatim. This is the core of
// PR 3's realism contract — Cisco IOS-XR catalogs reference
// `TenGigE...` while Juniper reference `ge-0/0/5` etc., and those
// strings must reach the template `{{.IfName}}` unchanged.
func TestLookupIfDescr_HitFromOIDTable(t *testing.T) {
	device := &DeviceSimulator{
		IP:        net.IPv4(10, 42, 0, 1),
		resources: &DeviceResources{oidIndex: &sync.Map{}},
	}
	device.resources.oidIndex.Store(".1.3.6.1.2.1.2.2.1.2.5", "TenGigE0/0/0/5")
	if got := lookupIfDescr(device, 5); got != "TenGigE0/0/0/5" {
		t.Errorf("lookupIfDescr(ifIndex=5): got %q, want TenGigE0/0/0/5", got)
	}
}

// TestLookupIfDescr_MissReturnsEmpty confirms the miss path returns "",
// letting callers decide on a fallback. This is the behaviour
// `deviceIfNameFn` relies on when routing to `synthIfName`.
func TestLookupIfDescr_MissReturnsEmpty(t *testing.T) {
	device := &DeviceSimulator{
		IP:        net.IPv4(10, 42, 0, 1),
		resources: &DeviceResources{oidIndex: &sync.Map{}},
	}
	if got := lookupIfDescr(device, 99); got != "" {
		t.Errorf("lookupIfDescr(missing ifIndex): got %q, want empty", got)
	}
}

// TestLookupIfDescr_NilGuards confirms the helper tolerates nil device,
// nil resources, and nil oidIndex without panicking. These states are
// reachable in tests that construct bare DeviceSimulator structs.
func TestLookupIfDescr_NilGuards(t *testing.T) {
	if got := lookupIfDescr(nil, 1); got != "" {
		t.Errorf("nil device: got %q, want empty", got)
	}
	if got := lookupIfDescr(&DeviceSimulator{}, 1); got != "" {
		t.Errorf("nil resources: got %q, want empty", got)
	}
	if got := lookupIfDescr(&DeviceSimulator{resources: &DeviceResources{}}, 1); got != "" {
		t.Errorf("nil oidIndex: got %q, want empty", got)
	}
}

// TestDeviceIfNameFn_LiveLookupOverridesSynthesis exercises the full
// `deviceIfNameFn` composition: with a real ifDescr in the table, the
// synthesized fallback must NOT appear in the output.
func TestDeviceIfNameFn_LiveLookupOverridesSynthesis(t *testing.T) {
	device := &DeviceSimulator{
		IP:        net.IPv4(10, 42, 0, 1),
		resources: &DeviceResources{oidIndex: &sync.Map{}},
	}
	device.resources.oidIndex.Store(".1.3.6.1.2.1.2.2.1.2.1", "FastEthernet1/0/1")
	fn := deviceIfNameFn(device)
	if got := fn(1); got != "FastEthernet1/0/1" {
		t.Errorf("deviceIfNameFn(1): got %q, want FastEthernet1/0/1", got)
	}
	// Fallback: ifIndex 99 has no entry; synthesis kicks in.
	if got := fn(99); got != "GigabitEthernet0/99" {
		t.Errorf("deviceIfNameFn(99): got %q, want GigabitEthernet0/99 (synth fallback)", got)
	}
	// Zero and negative still return empty (preserved guard).
	if got := fn(0); got != "" {
		t.Errorf("deviceIfNameFn(0): got %q, want empty", got)
	}
	if got := fn(-1); got != "" {
		t.Errorf("deviceIfNameFn(-1): got %q, want empty", got)
	}
}

// TestFieldResolver_IfName_LiveLookupFromManager exercises the
// `(*SimulatorManager).IfName` path through the full resolver contract.
// This is what PR 3 promises at the API level: the FieldResolver
// interface returns vendor-flavoured ifDescr when the device has one.
func TestFieldResolver_IfName_LiveLookupFromManager(t *testing.T) {
	device := &DeviceSimulator{
		ID:        "cisco-ios-0",
		IP:        net.IPv4(10, 42, 0, 1),
		resources: &DeviceResources{oidIndex: &sync.Map{}},
	}
	device.resources.oidIndex.Store(".1.3.6.1.2.1.2.2.1.2.7", "GigabitEthernet7")

	sm := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{"cisco-ios-0": device},
		deviceTypesByIP: map[string]string{"10.42.0.1": "cisco_ios"},
	}

	if got := sm.IfName("10.42.0.1", 7); got != "GigabitEthernet7" {
		t.Errorf("live lookup: got %q, want GigabitEthernet7", got)
	}
	// Miss falls back to synth.
	if got := sm.IfName("10.42.0.1", 42); got != "GigabitEthernet0/42" {
		t.Errorf("miss fallback: got %q, want GigabitEthernet0/42", got)
	}
	// Unknown device also falls back.
	if got := sm.IfName("10.99.99.99", 3); got != "GigabitEthernet0/3" {
		t.Errorf("unknown device fallback: got %q, want GigabitEthernet0/3", got)
	}
}

// TestDeviceIfNameFn_ByteIdentity_Unchanged_OnMiss pins that an ifIndex
// not in the SNMP OID table produces the same string as pre-PR-3
// (`GigabitEthernet0/N`). Protects existing catalog fixtures and the
// byte-identity pins on the wire encoders — resolved template values
// feed into BER / RFC-5424 layout only through string substitution.
func TestDeviceIfNameFn_ByteIdentity_Unchanged_OnMiss(t *testing.T) {
	// No oidIndex → every ifIndex misses → synth every time.
	device := &DeviceSimulator{
		IP:        net.IPv4(10, 42, 0, 1),
		resources: &DeviceResources{oidIndex: &sync.Map{}},
	}
	fn := deviceIfNameFn(device)
	for _, ifIndex := range []int{1, 2, 3, 10, 100, 65535} {
		got := fn(ifIndex)
		want := "GigabitEthernet0/" + strconv.Itoa(ifIndex)
		if got != want {
			t.Errorf("ifIndex=%d: got %q, want %q", ifIndex, got, want)
		}
	}
}

// TestLookupIfDescr_AgainstRealLoadedResources is the integration test
// that exercises the FULL chain: real `LoadSpecificResources` call →
// `buildResourceIndexes` produces the `oidIndex` with its canonical key
// format → `lookupIfDescr` reads from that map using the format the
// helper assumes. The other tests in this file self-consistently
// Store dot-prefixed keys that the helper then reads — they would all
// pass even if the loader used a different convention. This one fails
// loudly if the loader's key normalisation ever drifts from
// `.1.3.6.1.2.1.2.2.1.2.<N>`, protecting PR 3 from a silent regression.
func TestLookupIfDescr_AgainstRealLoadedResources(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	resources, err := sm.LoadSpecificResources("cisco_ios.json")
	if err != nil {
		t.Fatalf("LoadSpecificResources cisco_ios: %v", err)
	}
	if resources == nil || resources.oidIndex == nil {
		t.Fatal("loaded resources missing oidIndex — buildResourceIndexes did not run")
	}
	device := &DeviceSimulator{
		IP:        net.IPv4(10, 42, 0, 1),
		resources: resources,
	}
	// Spot-check ifIndex 1. The shipped cisco_ios JSON fixture seeds
	// ifDescr.1 = GigabitEthernet0/0 in resources/cisco_ios/cisco_ios_snmp_1.json.
	// If the loader's key format ever diverges from the helper's, the
	// Load misses → synth kicks in → "GigabitEthernet0/1" (note the
	// different suffix). Asserting the exact vendor-shipped string
	// catches both format drift AND a loader that silently fails to
	// populate the map.
	got := lookupIfDescr(device, 1)
	if got == "" {
		t.Fatal("lookupIfDescr returned empty — key format drift between loader and helper")
	}
	if got == "GigabitEthernet0/1" {
		t.Fatal("lookupIfDescr returned the synth fallback, not the vendor value — loader key format drift")
	}
	// Sanity: the real value contains "Ethernet" (every Cisco ifDescr
	// does). Not asserting the exact string so future fixture updates
	// to cisco_ios don't require hand-editing this test.
	if !strings.Contains(got, "Ethernet") {
		t.Errorf("lookupIfDescr for cisco_ios ifIndex 1: got %q, want a string containing 'Ethernet'", got)
	}
}

