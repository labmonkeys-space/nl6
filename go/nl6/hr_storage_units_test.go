/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestHrStorageSizeAndUsedFitTheirUnits pins nl6#1056's units change on every
// shipped profile whose metric map serves hrStorageSize.1 or hrStorageUsed.1:
// at every point of the curve both fit Integer32 (0..2147483647), used never
// exceeds size, and size is the profile's memory expressed in the profile's own
// hrStorageAllocationUnits.1. Before the change the engine served KB whatever
// the row said, so nvidia_dgx_h100 and nvidia_hgx_h200 answered a GET of
// hrStorageSize.1 with 2147483648, one over Integer32, in units of 1 MiB: 2 PiB.
func TestHrStorageSizeAndUsedFitTheirUnits(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	wantSize := map[string]int64{
		// hrStorageSize.1 as the row a collector reads describes it.
		"nvidia_dgx_a100.json":     1073741824, // 1 TiB in units of 1024
		"nvidia_dgx_h100.json":     2097152,    // 2 TiB in units of 1048576
		"nvidia_hgx_h200.json":     2097152,    // 2 TiB in units of 1048576
		"dell_poweredge_r750.json": 33554432,   // 32 GiB in units of 1024
		"arista_7280r3.json":       16777216,   // 16 GiB, no units row: 1024
	}
	checked := 0
	for _, profile := range shippedProfileNames(t) {
		m := GetMetricOIDs(profile)
		_, size := m[hrStorageSize1OID]
		_, used := m[hrStorageUsed1OID]
		if !size && !used {
			continue
		}
		checked++
		s := bootedShippedDevice(t, profile, boot, nil)
		units := s.device.hrStorageUnits
		dp := GetDeviceProfile(profile)
		if got, want := mustInt(t, profile, s.findResponseAt(hrStorageSize1OID, 0)), dp.MemTotalKB*1024/units; got != want {
			t.Errorf("%s hrStorageSize.1 = %d, want MemTotalKB %d in units of %d = %d", profile, got, dp.MemTotalKB, units, want)
		}
		if want, ok := wantSize[profile]; !ok {
			t.Errorf("%s serves hrStorageSize.1 from the engine but has no expected value here", profile)
		} else if got := mustInt(t, profile, s.findResponseAt(hrStorageSize1OID, 0)); got != want {
			t.Errorf("%s hrStorageSize.1 = %d, want %d", profile, got, want)
		}
		for p := 0; p < numDataPoints; p++ {
			sz := mustInt(t, profile, s.findResponseAt(hrStorageSize1OID, p))
			us := mustInt(t, profile, s.findResponseAt(hrStorageUsed1OID, p))
			if sz < 0 || sz > math.MaxInt32 || us < 0 || us > math.MaxInt32 {
				t.Fatalf("%s point %d: hrStorageSize.1 = %d, hrStorageUsed.1 = %d, want both in 0..%d", profile, p, sz, us, math.MaxInt32)
			}
			if us > sz {
				t.Fatalf("%s point %d: hrStorageUsed.1 = %d exceeds hrStorageSize.1 = %d", profile, p, us, sz)
			}
		}
	}
	if checked != len(wantSize) {
		t.Errorf("checked %d profiles that serve hrStorage row 1 from the engine, want %d", checked, len(wantSize))
	}
}

// TestVendorMemoryOIDsStayInKB: the conversion applies to hrStorageSize.1 and
// hrStorageUsed.1 only. A vendor OID that shares MetricMemTotal keeps serving
// KB, here dell_poweredge_r750's iDRAC memory total. dell ships units of 1024,
// where KB and units are the same number, so the device is given units of
// 1 MiB: a conversion applied to the vendor OID would then show, and the
// control proves the units took effect on hrStorageSize.1.
func TestVendorMemoryOIDsStayInKB(t *testing.T) {
	const dellMemTotalOID = ".1.3.6.1.4.1.674.10892.5.4.700.20.1.8.1.1"
	if GetMetricOIDs("dell_poweredge_r750.json")[dellMemTotalOID] != MetricMemTotal {
		t.Fatalf("fixture: %s is not MetricMemTotal on dell_poweredge_r750", dellMemTotalOID)
	}
	s := bootedShippedDevice(t, "dell_poweredge_r750.json", time.Now().Add(-time.Hour), nil)
	s.device.hrStorageUnits = 1048576
	kb := GetDeviceProfile("dell_poweredge_r750.json").MemTotalKB
	if got := mustInt(t, "dell_poweredge_r750.json", s.findResponseAt(dellMemTotalOID, 0)); got != kb {
		t.Errorf("iDRAC memory total = %d, want %d KB whatever hrStorageAllocationUnits.1 says", got, kb)
	}
	if got := mustInt(t, "dell_poweredge_r750.json", s.findResponseAt(hrStorageSize1OID, 0)); got != kb/1024 {
		t.Errorf("control: hrStorageSize.1 = %d with units of 1 MiB, want %d", got, kb/1024)
	}
}

// TestHrStorageAllocationUnitsFallsBackTo1024: a profile without the row, or
// with a value that is not a positive integer, gets the KBytes unit.
func TestHrStorageAllocationUnitsFallsBackTo1024(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  *DeviceResources
		want int64
	}{
		{"no resources", nil, 1024},
		{"no row", guardIndexed(), 1024},
		{"zero", guardIndexed([2]string{hrStorageAllocUnits1OID, "0"}), 1024},
		{"prose", guardIndexed([2]string{hrStorageAllocUnits1OID, "1 KiB"}), 1024},
		{"the row", guardIndexed([2]string{hrStorageAllocUnits1OID, "1048576"}), 1048576},
	} {
		if got := hrStorageAllocationUnits(tc.res); got != tc.want {
			t.Errorf("%s: units = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func guardIndexed(pairs ...[2]string) *DeviceResources {
	res := guardResources(pairs...)
	sm := &SimulatorManager{}
	sm.buildResourceIndexes(res)
	return res
}

func mustInt(t *testing.T, profile, v string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		t.Fatalf("%s: %q is not an integer: %v", profile, v, err)
	}
	return n
}
