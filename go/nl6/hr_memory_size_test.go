/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math"
	"testing"
	"time"
)

// TestHrMemorySizeIsTheProfileMemoryInKBytes pins nl6#1088 on every shipped
// profile whose metric map serves hrMemorySize.0: at every point of the curve
// the value is the profile's MemTotalKB, clamped to the KBytes range
// (Integer32, 0..2147483647). Before the change the three NVIDIA profiles
// served a static row 1024 times smaller than their own physical memory.
// h100 and h200 hold 2 TiB, which is 2147483648 KB, one over the range.
func TestHrMemorySizeIsTheProfileMemoryInKBytes(t *testing.T) {
	want := map[string]int64{
		"nvidia_dgx_a100.json": 1073741824, // 1 TiB
		"nvidia_dgx_h100.json": 2147483647, // 2 TiB, clamped
		"nvidia_hgx_h200.json": 2147483647, // 2 TiB, clamped
	}
	boot := time.Now().Add(-time.Hour)
	checked := 0
	for _, profile := range shippedProfileNames(t) {
		if _, ok := GetMetricOIDs(profile)[hrMemorySizeOID]; !ok {
			continue
		}
		checked++
		w, ok := want[profile]
		if !ok {
			t.Errorf("%s serves hrMemorySize.0 from the engine but has no expected value here", profile)
			continue
		}
		s := bootedShippedDevice(t, profile, boot, nil)
		for p := 0; p < numDataPoints; p++ {
			if got := mustInt(t, profile, s.findResponseAt(hrMemorySizeOID, p)); got != w {
				t.Fatalf("%s point %d: hrMemorySize.0 = %d, want %d", profile, p, got, w)
			}
		}
	}
	if checked != len(want) {
		t.Errorf("checked %d profiles that serve hrMemorySize.0 from the engine, want %d", checked, len(want))
	}
}

// TestHrMemorySizeClampsAtTheKBytesRange drives the clamp on both sides of the
// boundary. The value is never above 2147483647 and never changed below it.
func TestHrMemorySizeClampsAtTheKBytesRange(t *testing.T) {
	s := bootedShippedDevice(t, "nvidia_dgx_a100.json", time.Now().Add(-time.Hour), nil)
	for _, tc := range []struct{ kb, want int64 }{
		{math.MaxInt32 - 1, math.MaxInt32 - 1},
		{math.MaxInt32, math.MaxInt32},
		{math.MaxInt32 + 1, math.MaxInt32},
		{4 * 1024 * 1024 * 1024, math.MaxInt32},
	} {
		s.device.metricsCycler.memTotal = tc.kb
		if got := mustInt(t, "nvidia_dgx_a100.json", s.findResponseAt(hrMemorySizeOID, 0)); got != tc.want {
			t.Errorf("MemTotalKB %d: hrMemorySize.0 = %d, want %d", tc.kb, got, tc.want)
		}
	}
}

// TestVendorMemoryTotalIsNotClamped: the clamp belongs to hrMemorySize.0 alone.
// A vendor OID of type MetricMemTotal keeps serving the KB value whole, here
// dell_poweredge_r750's iDRAC memory total, given 2 TiB.
func TestVendorMemoryTotalIsNotClamped(t *testing.T) {
	const dellMemTotalOID = ".1.3.6.1.4.1.674.10892.5.4.700.20.1.8.1.1"
	if GetMetricOIDs("dell_poweredge_r750.json")[dellMemTotalOID] != MetricMemTotal {
		t.Fatalf("fixture: %s is not MetricMemTotal on dell_poweredge_r750", dellMemTotalOID)
	}
	s := bootedShippedDevice(t, "dell_poweredge_r750.json", time.Now().Add(-time.Hour), nil)
	s.device.metricsCycler.memTotal = math.MaxInt32 + 1
	if got := mustInt(t, "dell_poweredge_r750.json", s.findResponseAt(dellMemTotalOID, 0)); got != math.MaxInt32+1 {
		t.Errorf("iDRAC memory total = %d, want %d unclamped", got, int64(math.MaxInt32)+1)
	}
}
