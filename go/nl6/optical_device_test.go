/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
)

const opticalResourceFile = "ciena_waveserver5.json"

// TestOpticalDeviceTypeRegistered covers the sync-required tables that no
// compiler checks: a miss in any of them compiles clean and fails (or
// worse, silently degrades) at runtime.
func TestOpticalDeviceTypeRegistered(t *testing.T) {
	prof, ok := deviceProfileMap[opticalResourceFile]
	if !ok {
		t.Fatalf("deviceProfileMap has no entry for %s", opticalResourceFile)
	}
	if prof.Optical == nil {
		t.Fatal("optical device profile must carry a non-nil OpticalProfile — it is the canonical is-optical test")
	}
	if prof.Optical.ChannelCount <= 0 {
		t.Errorf("OpticalProfile.ChannelCount = %d, want > 0", prof.Optical.ChannelCount)
	}
	if !IsOpticalDeviceType(opticalResourceFile) {
		t.Error("IsOpticalDeviceType returned false for the optical type")
	}
	if IsOpticalDeviceType("asr9k.json") {
		t.Error("IsOpticalDeviceType returned true for a packet device type")
	}

	if got := getDeviceTypeFromName("ciena_waveserver5"); got != "Ciena Waveserver 5" {
		t.Errorf("getDeviceTypeFromName = %q, want %q", got, "Ciena Waveserver 5")
	}
	if got := getDeviceCategoryFromName("ciena_waveserver5"); got != "Optical Transport" {
		t.Errorf("getDeviceCategoryFromName = %q, want %q", got, "Optical Transport")
	}

	// {{.Model}} in trap/syslog templates resolves through deviceTypeLabels.
	if got := modelLabelForSlug("ciena_waveserver5"); got != "Ciena Waveserver 5" {
		t.Errorf("modelLabelForSlug = %q, want %q", got, "Ciena Waveserver 5")
	}
}

// TestOpticalTypeAppendedToRoundRobin guards the ordering contract:
// assignment is deviceIndex % len(list), so appending preserves the type
// of every position BELOW the old length. It does not preserve positions
// at or above it — growing 28→29 necessarily moves device #29 from index
// 0 to index 28 — so this asserts the prefix invariant only, which is the
// most the data structure can offer.
func TestOpticalTypeAppendedToRoundRobin(t *testing.T) {
	idx := -1
	for i, rf := range RoundRobinDeviceTypes {
		if rf == opticalResourceFile {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("%s missing from RoundRobinDeviceTypes", opticalResourceFile)
	}
	if idx != len(RoundRobinDeviceTypes)-1 {
		t.Errorf("optical type at index %d of %d: it must be appended (last), not inserted — "+
			"inserting would remap every position after it", idx, len(RoundRobinDeviceTypes))
	}

	// The prefix invariant that appending actually buys: positions below
	// the pre-existing length keep their type.
	prior := RoundRobinDeviceTypes[:len(RoundRobinDeviceTypes)-1]
	for i := range prior {
		if got := RoundRobinDeviceTypes[i%len(RoundRobinDeviceTypes)]; got != prior[i%len(prior)] {
			t.Errorf("position %d: type changed to %s after the append (was %s)", i, got, prior[i%len(prior)])
		}
	}
}

// TestOpticalTypeHasNoFlowCapability is the false-pass guard: a layer-1
// transport platform observes no flows, and GetFlowProfile's edge-router
// fallback means absence has to be implemented rather than omitted.
func TestOpticalTypeHasNoFlowCapability(t *testing.T) {
	if SupportsFlowExport(opticalResourceFile) {
		t.Error("optical transport must not support flow export — it performs no L3/L4 inspection")
	}
	for _, rf := range []string{"asr9k.json", "cisco_ios.json", "arista_7280r3.json", "netapp_ontap.json"} {
		if !SupportsFlowExport(rf) {
			t.Errorf("SupportsFlowExport(%s) = false, want true", rf)
		}
	}
	// The fallback that makes omission dangerous is still in place, which
	// is exactly why SupportsFlowExport must be consulted separately.
	if GetFlowProfile(opticalResourceFile) == nil {
		t.Error("GetFlowProfile must keep its non-nil contract so existing call sites cannot nil-panic")
	}
}

// TestFlowIncapableRequest covers the 400 guard, including the path that
// names no resource file: a category-filtered round-robin batch resolves
// to flow-incapable types only, and would otherwise be accepted while
// every device silently lost its flow config.
func TestFlowIncapableRequest(t *testing.T) {
	tests := []struct {
		name   string
		req    CreateDevicesRequest
		reject bool
	}{
		{"explicit optical type", CreateDevicesRequest{ResourceFile: opticalResourceFile}, true},
		{"explicit packet type", CreateDevicesRequest{ResourceFile: "asr9k.json"}, false},
		{"category-filtered round robin, optical only",
			CreateDevicesRequest{RoundRobin: true, Category: "Optical Transport"}, true},
		{"category-filtered round robin, packet category",
			CreateDevicesRequest{RoundRobin: true, Category: "Network Devices"}, false},
		{"mixed round robin is allowed — capable devices still export",
			CreateDevicesRequest{RoundRobin: true}, false},
		{"unknown category falls back to the full list, so mixed",
			CreateDevicesRequest{RoundRobin: true, Category: "No Such Category"}, false},
		{"neither round robin nor a resource file", CreateDevicesRequest{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rf, got := flowIncapableRequest(tc.req)
			if got != tc.reject {
				t.Fatalf("flowIncapableRequest = %v (%q), want %v", got, rf, tc.reject)
			}
			if got && rf == "" {
				t.Error("rejection must name the offending resource file")
			}
		})
	}
}

// TestRoundRobinTypesForCategory pins the resolution used by the flow
// guard to the filter in CreateDevicesWithOptions, including its
// fallback-to-unfiltered behaviour on an empty match.
func TestRoundRobinTypesForCategory(t *testing.T) {
	if got := roundRobinTypesForCategory(""); len(got) != len(RoundRobinDeviceTypes) {
		t.Errorf("empty category should return the full list, got %d", len(got))
	}
	optical := roundRobinTypesForCategory("Optical Transport")
	if len(optical) != 1 || optical[0] != opticalResourceFile {
		t.Errorf("Optical Transport category = %v, want [%s]", optical, opticalResourceFile)
	}
	if got := roundRobinTypesForCategory("No Such Category"); len(got) != len(RoundRobinDeviceTypes) {
		t.Errorf("unmatched category must fall back to the full list (mirroring device.go), got %d", len(got))
	}
}

// TestValidateOpticalInventory covers the guard that makes a silently
// discarded inventory impossible. The resource decoder is not strict, so
// a wrong key or shape yields a zero-valued struct with no error.
func TestValidateOpticalInventory(t *testing.T) {
	tests := []struct {
		name         string
		resourceFile string
		res          *DeviceResources
		wantErr      string
	}{{
		name:         "packet type is unaffected",
		resourceFile: "asr9k.json",
		res:          &DeviceResources{},
	}, {
		name:         "optical type with channels passes",
		resourceFile: opticalResourceFile,
		res: &DeviceResources{Optical: []OpticalChannel{
			{Name: "OCH-1-1"}, {Name: "OCH-1-2"},
		}},
	}, {
		name:         "optical type with no inventory fails loudly",
		resourceFile: opticalResourceFile,
		res:          &DeviceResources{},
		wantErr:      "loaded no optical channels",
	}, {
		name:         "nil resources fails loudly",
		resourceFile: opticalResourceFile,
		res:          nil,
		wantErr:      "loaded no optical channels",
	}, {
		name:         "empty channel name is rejected",
		resourceFile: opticalResourceFile,
		res: &DeviceResources{Optical: []OpticalChannel{
			{Name: "OCH-1-1"}, {Name: ""},
		}},
		wantErr: "empty name",
	}, {
		name:         "channel count must match the device profile",
		resourceFile: opticalResourceFile,
		res:          &DeviceResources{Optical: []OpticalChannel{{Name: "OCH-1-1"}}},
		wantErr:      "declares 2 optical channel(s)",
	}, {
		name:         "duplicate channel name is rejected",
		resourceFile: opticalResourceFile,
		res: &DeviceResources{Optical: []OpticalChannel{
			{Name: "OCH-1-1"}, {Name: "OCH-1-1"},
		}},
		wantErr: "duplicate optical channel name",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOpticalInventory(tc.resourceFile, tc.res)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestResourceFileForDir(t *testing.T) {
	for in, want := range map[string]string{
		"resources/ciena_waveserver5":  "ciena_waveserver5.json",
		"resources/ciena_waveserver5/": "ciena_waveserver5.json",
		"/abs/path/resources/asr9k":    "asr9k.json",
		"ciena_waveserver5":            "ciena_waveserver5.json",
		"./resources/nvidia_dgx_a100":  "nvidia_dgx_a100.json",
	} {
		if got := resourceFileForDir(in); got != want {
			t.Errorf("resourceFileForDir(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestOpticalResourceDirLoads exercises the real shipped resource files
// end to end: the OCH inventory must survive both the non-strict decoder
// and the merge, and the IF-MIB parts must carry the ifHCInOctets entries
// the counter engine keys on.
func TestOpticalResourceDirLoads(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}

	res, err := sm.loadSpecificResourcesFromDir("resources/ciena_waveserver5", opticalResourceFile)
	if err != nil {
		t.Fatalf("loading the optical resource dir failed: %v", err)
	}
	if len(res.Optical) == 0 {
		t.Fatal("OCH inventory is empty — the optical part was silently discarded by the loader")
	}
	if want := deviceProfileMap[opticalResourceFile].Optical.ChannelCount; len(res.Optical) != want {
		t.Errorf("loaded %d optical channels, profile declares %d", len(res.Optical), want)
	}
	for _, ch := range res.Optical {
		if ch.Name == "" {
			t.Error("loaded channel with empty name")
		}
		if ch.FrequencyMHz == 0 {
			t.Errorf("channel %s has zero frequency", ch.Name)
		}
		if ch.LinePort == "" {
			t.Errorf("channel %s has no line port", ch.Name)
		}
	}
	if len(res.SNMP) == 0 || len(res.SSH) == 0 {
		t.Errorf("expected SNMP and SSH parts to load too (got %d/%d)", len(res.SNMP), len(res.SSH))
	}

	// The counter engine discovers interfaces via ifHCInOctets; without
	// these the device would come up with no dynamic IF-MIB counters.
	var hcIn int
	for _, r := range res.SNMP {
		if strings.HasPrefix(r.OID, "1.3.6.1.2.1.31.1.1.1.6.") {
			hcIn++
		}
	}
	if hcIn == 0 {
		t.Error("no ifHCInOctets entries — the IF-MIB counter engine would find no interfaces")
	}
}
