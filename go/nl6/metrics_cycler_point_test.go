/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// atPoint moves a cycler's origin so that point k is served now, half an
// interval from either boundary, which leaves 30 s for a test's reads to stay
// on one point.
func atPoint(mc *MetricsCycler, k int) {
	mc.startTime = time.Now().Add(-(time.Duration(k)*metricsPointInterval + metricsPointInterval/2))
}

func TestMetricsPointFollowsElapsedTime(t *testing.T) {
	for _, tc := range []struct {
		elapsed time.Duration
		want    int
	}{
		{-time.Second, 0},
		{0, 0},
		{metricsPointInterval - time.Nanosecond, 0},
		{metricsPointInterval, 1},
		{99 * metricsPointInterval, 99},
		{100 * metricsPointInterval, 0},
		{250*metricsPointInterval + metricsPointInterval/2, 50},
	} {
		if got := metricsPointAt(tc.elapsed); got != tc.want {
			t.Errorf("metricsPointAt(%v) = %d, want %d", tc.elapsed, got, tc.want)
		}
	}
}

// Every shipped profile that serves both memory used and memory free must answer
// a pair that sums to the total, whichever of the two is read first. Each read
// used to advance one shared cursor, so the second read came from the next
// point and the pair never summed to the total (nl6#970).
func TestMemoryUsedPlusFreeIsTotalOnEveryShippedProfile(t *testing.T) {
	profiles := make([]string, 0, len(vendorOIDs))
	for rf := range vendorOIDs {
		profiles = append(profiles, rf)
	}
	sort.Strings(profiles)

	checked := 0
	for _, rf := range profiles {
		var usedOID, freeOID string
		for oid, typ := range GetMetricOIDs(rf) {
			switch typ {
			case MetricMemUsed:
				usedOID = oid
			case MetricMemFree:
				freeOID = oid
			}
		}
		if usedOID == "" || freeOID == "" {
			continue
		}
		checked++

		srv := deviceForProfileWithMetrics(t, rf)
		mc := srv.device.metricsCycler
		for _, k := range []int{0, 37, 99} {
			atPoint(mc, k)
			usedFirst, freeSecond := srv.findResponse(usedOID), srv.findResponse(freeOID)
			freeFirst, usedSecond := srv.findResponse(freeOID), srv.findResponse(usedOID)
			for _, pair := range [][2]string{{usedFirst, freeSecond}, {usedSecond, freeFirst}} {
				var used, free int64
				if _, err := fmt.Sscan(pair[0], &used); err != nil {
					t.Fatalf("%s: used %s = %q: %v", rf, usedOID, pair[0], err)
				}
				if _, err := fmt.Sscan(pair[1], &free); err != nil {
					t.Fatalf("%s: free %s = %q: %v", rf, freeOID, pair[1], err)
				}
				if used+free != mc.memTotal {
					t.Errorf("%s at point %d: used %d + free %d = %d, want the total %d", rf, k, used, free, used+free, mc.memTotal)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no shipped profile maps both memory used and memory free, so this test checked nothing")
	}
	t.Logf("%d profiles serve both memory used and memory free", checked)
}

// Reading a metric OID must not move the curve: a second collector, or a GETNEXT
// that evaluates a metric OID as a candidate without returning it, used to
// advance the cursor every other reader shares.
func TestMetricReadsDoNotAdvanceTheCurve(t *testing.T) {
	const rf = "cisco_ios.json"
	srv := deviceForProfileWithMetrics(t, rf)
	mc := srv.device.metricsCycler
	var cpuOID, tempOID string
	for oid, typ := range GetMetricOIDs(rf) {
		switch typ {
		case MetricCPUPercent:
			cpuOID = oid
		case MetricTemperature:
			tempOID = oid
		}
	}
	if cpuOID == "" || tempOID == "" {
		t.Fatalf("%s maps no CPU or no temperature OID", rf)
	}

	const k = 42
	atPoint(mc, k)
	wantCPU, wantTemp := fmt.Sprint(mc.cpuPoints[k]), fmt.Sprint(mc.tempPoints[k])
	for i := 0; i < 10; i++ {
		if got := srv.findResponse(cpuOID); got != wantCPU {
			t.Fatalf("read %d of %s = %s, want %s (point %d)", i, cpuOID, got, wantCPU, k)
		}
		if got := srv.findResponse(tempOID); got != wantTemp {
			t.Fatalf("read %d of %s = %s, want %s (point %d)", i, tempOID, got, wantTemp, k)
		}
	}
}

// The curves of one GPU are derived from one another point by point (power from
// utilization, temperature correlated with it, the clocks from it), so every
// OID of a GPU must be answered from one point, however unevenly they are read.
// Each metric used to have its own cursor, and reading utilization twice made
// power answer from a different point than utilization.
func TestGPUMetricsOfOneGPUAnswerFromOnePoint(t *testing.T) {
	const rf = "nvidia_dgx_h100.json"
	srv := gpuDeviceForProfile(t, rf)
	mc := srv.device.metricsCycler
	const k = 63
	atPoint(mc, k)

	g := mc.gpuMetrics[0]
	want := map[int]int64{
		5:  int64(g.gpuUtil[k]),
		6:  g.gpuMemUsed[k],
		8:  int64(g.gpuTemp[k]),
		9:  int64(g.gpuPower[k]),
		10: int64(g.gpuFanSpeed[k]),
		11: int64(g.gpuClockSM[k]),
		12: int64(g.gpuClockMem[k]),
	}
	// Utilization is read three times before the others, the uneven reading a
	// collector polling it more often produces.
	for _, metric := range []int{5, 5, 5, 9, 8, 11, 12, 10, 6} {
		oid := fmt.Sprintf("%s.%d.0", nvidiaGPUMetricPrefix, metric)
		if got := srv.findResponse(oid); got != fmt.Sprint(want[metric]) {
			t.Errorf("%s = %s, want %d (point %d of GPU 0)", oid, got, want[metric], k)
		}
	}
}
