/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// movingFrom gives a cycler a clock that starts half an interval into point k
// and moves one point forward on every read. A request that reads the clock
// once is answered from point k; one that reads it per binding spreads its
// bindings over k, k+1, ... (nl6#975).
func movingFrom(mc *MetricsCycler, k int) {
	reads := 0
	mc.now = func() time.Time {
		at := mc.startTime.Add(time.Duration(k+reads)*metricsPointInterval + metricsPointInterval/2)
		reads++
		return at
	}
}

// assertOnePointPerRequest serves one request with a clock that moves on every
// read and requires the answer to equal the one served with the clock frozen at
// the request's first point. It picks a point whose successor answers
// differently, so a handler that reads the clock twice cannot pass by luck.
func assertOnePointPerRequest(t *testing.T, mc *MetricsCycler, serve func() []byte) {
	t.Helper()
	for k := 0; k < numDataPoints-1; k++ {
		atPoint(mc, k)
		want := serve()
		atPoint(mc, k+1)
		if bytes.Equal(want, serve()) {
			continue // points k and k+1 answer alike, so k cannot catch a split
		}
		movingFrom(mc, k)
		if got := serve(); !bytes.Equal(got, want) {
			t.Fatalf("a request answered across a point change differs from the answer at point %d:\n got % x\nwant % x", k, got, want)
		}
		return
	}
	t.Fatal("no two adjacent points answer differently, so this test checked nothing")
}

func metricOIDOf(t *testing.T, rf string, want MetricOIDType) string {
	t.Helper()
	for oid, typ := range GetMetricOIDs(rf) {
		if typ == want {
			return oid
		}
	}
	t.Fatalf("%s maps no OID of metric type %v", rf, want)
	return ""
}

// One GET carrying memory used and memory free is answered from one point, so
// the pair sums to the total (TestMemoryUsedPlusFreeIsTotalOnEveryShippedProfile
// pins that for a frozen point).
func TestGetOfMemoryUsedAndFreeIsOnePoint(t *testing.T) {
	const rf = "cisco_ios.json"
	srv := deviceForProfileWithMetrics(t, rf)
	oids := []string{metricOIDOf(t, rf, MetricMemUsed), metricOIDOf(t, rf, MetricMemFree)}
	req := getRequestAtVersionMulti(snmpVersion2c, oids)
	assertOnePointPerRequest(t, srv.device.metricsCycler, func() []byte {
		return srv.handleGetRequestVarbinds(oids, req)
	})
}

func TestGetOfGPUUtilizationAndPowerIsOnePoint(t *testing.T) {
	srv := gpuDeviceForProfile(t, "nvidia_dgx_h100.json")
	oids := []string{nvidiaGPUMetricPrefix + ".5.0", nvidiaGPUMetricPrefix + ".9.0"}
	req := getRequestAtVersionMulti(snmpVersion2c, oids)
	assertOnePointPerRequest(t, srv.device.metricsCycler, func() []byte {
		return srv.handleGetRequestVarbinds(oids, req)
	})
}

func TestGetNextOverGPUMetricsIsOnePoint(t *testing.T) {
	srv := gpuDeviceForProfile(t, "nvidia_dgx_h100.json")
	oids := []string{nvidiaGPUMetricPrefix + ".5", nvidiaGPUMetricPrefix + ".9"}
	assertOnePointPerRequest(t, srv.device.metricsCycler, func() []byte {
		respOIDs, respVals := srv.getNextBindingsForRequest(oids, srv.lldpServedOIDs(), snmpVersion2c,
			newCounter64SkipBudget())
		for i, o := range respOIDs {
			if want := oids[i] + ".0"; o != want {
				t.Fatalf("GETNEXT of %s returned %s, want %s", oids[i], o, want)
			}
		}
		return []byte(strings.Join(respVals, " "))
	})
}

func TestGetBulkOverGPUMetricsIsOnePoint(t *testing.T) {
	srv := gpuDeviceForProfile(t, "nvidia_dgx_h100.json")
	cols := []string{nvidiaGPUMetricPrefix + ".5", nvidiaGPUMetricPrefix + ".9"}
	req := v2cGetBulkRequest(0, 8, cols)
	assertOnePointPerRequest(t, srv.device.metricsCycler, func() []byte {
		return srv.handleGetBulk(cols[0], req)
	})
}

func TestV3GetBulkOverGPUMetricsIsOnePoint(t *testing.T) {
	srv := gpuDeviceForProfile(t, "nvidia_dgx_h100.json")
	srv.v3Config = v3TestServer(nil).v3Config
	cols := []string{nvidiaGPUMetricPrefix + ".5", nvidiaGPUMetricPrefix + ".9"}
	assertOnePointPerRequest(t, srv.device.metricsCycler, func() []byte {
		return []byte(fmt.Sprint(v3Bulk(t, srv, 0, 8, cols).varbinds))
	})
}

// Separate requests each read the clock, so the cadence of nl6#971 holds.
func TestSeparateRequestsFollowTheClock(t *testing.T) {
	const rf = "cisco_ios.json"
	srv := deviceForProfileWithMetrics(t, rf)
	mc := srv.device.metricsCycler
	oid := metricOIDOf(t, rf, MetricCPUPercent)
	for k := 0; k < numDataPoints-1; k++ {
		if mc.cpuPoints[k] == mc.cpuPoints[k+1] {
			continue
		}
		movingFrom(mc, k)
		first, second := srv.findResponse(oid), srv.findResponse(oid)
		if first != fmt.Sprint(mc.cpuPoints[k]) || second != fmt.Sprint(mc.cpuPoints[k+1]) {
			t.Fatalf("two requests in points %d and %d = %s, %s, want %d, %d",
				k, k+1, first, second, mc.cpuPoints[k], mc.cpuPoints[k+1])
		}
		return
	}
	t.Fatal("no two adjacent CPU points differ, so this test checked nothing")
}
