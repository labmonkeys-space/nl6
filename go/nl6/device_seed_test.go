/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"testing"
)

// seededDevice builds a device through initDeviceCyclers, the code both
// production creation paths run, so the seed under test is the one a created
// device gets.
func seededDevice(t *testing.T, sm *SimulatorManager, profile, ip string) *SNMPServer {
	t.Helper()
	res, err := sm.LoadSpecificResources(profile)
	if err != nil {
		t.Fatalf("LoadSpecificResources(%s): %v", profile, err)
	}
	dev := &DeviceSimulator{ID: "seed", IP: net.ParseIP(ip).To4(), resources: res, resourceFile: profile}
	initDeviceCyclers(dev)
	return &SNMPServer{device: dev}
}

// nvidiaGPUMetrics are the dynamic GPU columns under nvidiaGPUMetricPrefix.
var nvidiaGPUMetrics = []int{5, 6, 8, 9, 10, 11, 12}

// servedBySeed reads every value a device's seed decides, keyed by subsystem
// and then by reading: the CPU, memory and temperature OIDs at each of the
// numDataPoints points, the same for every GPU, every dial-derived interface
// column at fixed instants, and the optical leaves at fixed instants.
func servedBySeed(t *testing.T, srv *SNMPServer) map[string]map[string]string {
	t.Helper()
	mc := srv.device.metricsCycler
	got := map[string]map[string]string{}
	put := func(subsystem, key, value string) {
		if got[subsystem] == nil {
			got[subsystem] = map[string]string{}
		}
		got[subsystem][key] = value
	}

	metricOIDs := make([]string, 0)
	for oid := range GetMetricOIDs(srv.device.resourceFile) {
		metricOIDs = append(metricOIDs, oid)
	}
	sort.Strings(metricOIDs)
	for k := 0; k < numDataPoints; k++ {
		atPoint(mc, k)
		for _, oid := range metricOIDs {
			put("metrics", fmt.Sprintf("%s@%d", oid, k), srv.findResponse(oid))
		}
		for g := range mc.gpuMetrics {
			for _, m := range nvidiaGPUMetrics {
				oid := fmt.Sprintf("%s.%d.%d", nvidiaGPUMetricPrefix, m, g)
				put("gpu", fmt.Sprintf("%s@%d", oid, k), srv.findResponse(oid))
			}
		}
	}

	if ic := mc.ifCounters.Load(); ic != nil {
		for _, i := range ic.sortedIfIndexes {
			for _, c := range ifCyclerColumns {
				if isStateCol(c.col, c.prefix) {
					continue
				}
				oid := c.prefix + strconv.Itoa(c.col) + "." + strconv.Itoa(i)
				for _, at := range []float64{0, 600, 3600} {
					put("interfaces", fmt.Sprintf("%s@%g", oid, at), ic.GetDynamicAt(oid, at))
				}
			}
		}
	}

	if oc := mc.OpticalCyclerOf(); oc != nil {
		leaves := []string{
			OpticalLeafInputPower + "/" + OpticalStatInstant,
			OpticalLeafOSNR + "/" + OpticalStatInstant,
			OpticalLeafLaserBias + "/" + OpticalStatInstant,
			OpticalLeafUncorrBlock,
		}
		for _, comp := range oc.Components() {
			for _, leaf := range leaves {
				for _, at := range []float64{0, 600} {
					v, ok := oc.GetDynamicAt(comp, leaf, at)
					if !ok {
						t.Fatalf("%s %s: no value", comp, leaf)
					}
					put("optical", fmt.Sprintf("%s %s@%g", comp, leaf, at), fmt.Sprint(v))
				}
			}
		}
	}
	return got
}

// firstDifference names one reading on which a and b disagree, or "".
func firstDifference(a, b map[string]string) string {
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if a[k] != b[k] {
			return fmt.Sprintf("%s: %s vs %s", k, a[k], b[k])
		}
	}
	if len(a) != len(b) {
		return fmt.Sprintf("%d readings vs %d", len(a), len(b))
	}
	return ""
}

// A device built twice from the same IP, as a restart or a second request for
// the same address does, must serve the same values on every subsystem. The
// interface dials used to be drawn while ranging a map, so the same seed gave
// each interface a different draw on every build (nl6#989).
func TestSameIPServesTheSameValuesOnEverySubsystem(t *testing.T) {
	withIfScenario(t, IfScenarioAllNormal, 0)
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}

	checked := map[string]int{}
	for _, profile := range shippedProfileNames(t) {
		a := servedBySeed(t, seededDevice(t, sm, profile, "10.42.0.3"))
		b := servedBySeed(t, seededDevice(t, sm, profile, "10.42.0.3"))
		for subsystem, readings := range a {
			checked[subsystem]++
			if diff := firstDifference(readings, b[subsystem]); diff != "" {
				t.Errorf("%s %s: two builds from one IP differ at %s", profile, subsystem, diff)
			}
		}
	}
	for _, subsystem := range []string{"metrics", "gpu", "interfaces", "optical"} {
		if checked[subsystem] == 0 {
			t.Errorf("no shipped profile serves %s, so this test checked nothing there", subsystem)
		}
	}
	t.Logf("profiles checked per subsystem: %v", checked)
}

// Two devices of one type must serve different values on every seeded
// subsystem. 10.42.0.3 and 10.42.0.11 are the addresses of the first device of
// two separate requests in the nl6#989 reproduction: seeded by their index
// within the request, both were device 0 and served identical CPU, memory and
// interface counter values.
func TestDifferentIPsServeDifferentValuesOnEverySubsystem(t *testing.T) {
	withIfScenario(t, IfScenarioAllNormal, 0)
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}

	checked := map[string]int{}
	for _, profile := range shippedProfileNames(t) {
		a := servedBySeed(t, seededDevice(t, sm, profile, "10.42.0.3"))
		b := servedBySeed(t, seededDevice(t, sm, profile, "10.42.0.11"))
		for subsystem, readings := range a {
			checked[subsystem]++
			if firstDifference(readings, b[subsystem]) == "" {
				t.Errorf("%s %s: 10.42.0.3 and 10.42.0.11 serve identical values (%d readings)", profile, subsystem, len(readings))
			}
		}
	}
	for _, subsystem := range []string{"metrics", "gpu", "interfaces", "optical"} {
		if checked[subsystem] == 0 {
			t.Errorf("no shipped profile serves %s, so this test checked nothing there", subsystem)
		}
	}
	t.Logf("profiles checked per subsystem: %v", checked)
}

// No GPU of one device may share its curves with a GPU of another. GPU k used
// to be seeded base+17*k, so GPU 1 of a device was GPU 0 of the device whose
// seed was 17 higher. Seeds 17 apart are the case that collided.
func TestGPUsOfTwoDevicesNeverShareACurve(t *testing.T) {
	const profile = "nvidia_dgx_h100.json"
	dp := GetDeviceProfile(profile)
	if dp.GPU == nil || dp.GPU.GPUCount < 2 {
		t.Fatalf("%s needs at least two GPUs for this test", profile)
	}
	curve := func(g *GPUMetrics) string {
		return fmt.Sprint(g.gpuUtil, g.gpuMemUsed, g.gpuTemp, g.gpuPower)
	}
	for _, base := range []int64{0, 1, deviceSeed(net.ParseIP("10.42.0.3"))} {
		a, b := NewMetricsCycler(base, dp), NewMetricsCycler(base+17, dp)
		a.InitGPUMetrics(base, dp.GPU)
		b.InitGPUMetrics(base+17, dp.GPU)
		seen := map[string]string{}
		for name, mc := range map[string]*MetricsCycler{"a": a, "b": b} {
			for k, g := range mc.gpuMetrics {
				who := fmt.Sprintf("GPU %d of %s", k, name)
				if other, dup := seen[curve(g)]; dup {
					t.Errorf("seeds %d and %d: %s serves the curves of %s", base, base+17, who, other)
				}
				seen[curve(g)] = who
			}
		}
	}
}

// Seeds that agree modulo 2^31-1 must still draw different curves. math/rand
// reduces every seed modulo that prime, which left about two billion distinct
// streams for 64-bit hashed seeds.
func TestSeedsEqualModuloMathRandPrimeDrawDifferentCurves(t *testing.T) {
	const mathRandPrime = 1<<31 - 1
	profile := GetDeviceProfile("cisco_ios.json")
	for _, s := range []int64{1, deviceSeed(net.ParseIP("10.42.0.3"))} {
		a, b := NewMetricsCycler(s, profile), NewMetricsCycler(s+mathRandPrime, profile)
		if a.cpuPoints == b.cpuPoints && a.memUsed == b.memUsed && a.tempPoints == b.tempPoints {
			t.Errorf("seeds %d and %d draw identical CPU, memory and temperature curves", s, s+mathRandPrime)
		}
	}
}
