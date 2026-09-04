/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"
	"time"

	"github.com/grafana/pyroscope-go"
)

// profiling_gc_bench_test.go — the measurement behind -profiling-force-gc's
// default (nl6#635).
//
// The pyroscope-go SDK forces a runtime.GC() before each heap snapshot when no
// GC ran during the upload interval, so the heap profile it uploads is fresh.
// On a 30,000-device fleet that GC walks a large live heap on a process whose
// CPU is spoken for. The rule, pre-registered in the spec so the number could
// not be picked after the fact: build a heap from N TUN-less devices, time one
// runtime.GC(), extrapolate linearly to 30,000, and if that exceeds 150 ms
// (1% of one core per 15 s upload window) the default is false.
//
// This is an IN-PROCESS PROXY: the devices carry their value engines and
// resource pointers but no sockets, TUN or namespace, so the real fleet's
// heap is larger. The fleet-scale VM measurement is the follow-up recorded
// under docs/ops/profiling.md#follow-ups.

// benchFleetSizes are the device counts measured. Override with
// NL6_GC_BENCH_DEVICES=<n> to measure one size.
var benchFleetSizes = []int{1000, 5000}

// buildTUNFreeFleet constructs n devices the way CreateDevicesWithOptions
// does, minus everything that needs a network device: the shared resource
// profile, a metrics cycler with GPU, interface-counter and optical engines,
// and the per-device identity strings.
func buildTUNFreeFleet(tb testing.TB, n int) []*DeviceSimulator {
	tb.Helper()
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	const profile = "asr9k.json" // the default fleet profile
	res, err := sm.LoadSpecificResources(profile)
	if err != nil {
		tb.Fatalf("LoadSpecificResources(%s): %v", profile, err)
	}
	dp := GetDeviceProfile(profile)
	fleet := make([]*DeviceSimulator, 0, n)
	for i := 0; i < n; i++ {
		ip := net.IPv4(10, 42, byte(i>>8), byte(i))
		d := &DeviceSimulator{
			ID:           fmt.Sprintf("device-%d", i+1),
			IP:           ip,
			SNMPPort:     161,
			resources:    res,
			resourceFile: profile,
			sysName:      fmt.Sprintf("asr9k-%05d", i+1),
			sysLocation:  "Bench, Nowhere",
		}
		d.metricsCycler = NewMetricsCycler(int64(i), dp)
		d.metricsCycler.InitGPUMetrics(int64(i), dp.GPU)
		d.metricsCycler.InitIfCountersWithScenario(res, int64(i)^0x4843_0000, IfErrorClean)
		d.metricsCycler.InitOpticalCycler(res, int64(i), opticalBandFor(OpticalClean))
		fleet = append(fleet, d)
	}
	return fleet
}

// BenchmarkForcedGCOnFleetHeap reports the wall time of one runtime.GC() on
// a heap holding N devices, and the live heap it walked.
//
//	cd go && go test ./nl6/ -run '^$' -bench BenchmarkForcedGCOnFleetHeap -benchtime=5x
func BenchmarkForcedGCOnFleetHeap(b *testing.B) {
	sizes := benchFleetSizes
	if v := os.Getenv("NL6_GC_BENCH_DEVICES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 65535 {
			// The IP derivation below packs the index into the low two octets.
			b.Fatalf("NL6_GC_BENCH_DEVICES=%q: want an integer in 1..65535", v)
		}
		sizes = []int{n}
	}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("devices=%d", n), func(b *testing.B) {
			fleet := buildTUNFreeFleet(b, n)
			runtime.GC() // settle the heap before timing
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)

			b.ResetTimer()
			var total time.Duration
			for i := 0; i < b.N; i++ {
				start := time.Now()
				runtime.GC()
				total += time.Since(start)
			}
			b.StopTimer()
			// Both metrics after the loop: the testing package resets the
			// extra-metric map per run, so one reported before the loop is
			// dropped on the final (printed) run.
			b.ReportMetric(float64(total.Microseconds())/float64(b.N)/1000, "ms/gc")
			b.ReportMetric(float64(ms.HeapAlloc)/(1<<20), "live-heap-MiB")
			// Keep the fleet reachable through the timed loop.
			runtime.KeepAlive(fleet)
		})
	}
}

// TestProfilerForcesGCOnlyWhenConfigured pins the knob's wiring to the SDK:
// with DisableGCRuns following -profiling-force-gc, a heap snapshot forces a
// GC iff the flag is true. NumForcedGC counts explicit runtime.GC calls only,
// so for the false half a background collection cannot stand in for a forced
// one and automatic GC is left alone. The TRUE half is the reverse: the SDK
// forces a collection only when none ran during the interval, and in a test
// binary one usually does (observed: the half failed with automatic GC on),
// so automatic GC is paused for that half alone.
func TestProfilerForcesGCOnlyWhenConfigured(t *testing.T) {
	srv, _ := fakePyroscope(t)

	for _, forceGC := range []bool{true, false} {
		t.Run(fmt.Sprintf("force-gc=%v", forceGC), func(t *testing.T) {
			saved := profilingForceGC
			profilingForceGC = forceGC
			t.Cleanup(func() { profilingForceGC = saved })
			if forceGC {
				prev := debug.SetGCPercent(-1)
				t.Cleanup(func() { debug.SetGCPercent(prev) })
			}

			cfg := newProfilerConfig(srv.URL)
			cfg.UploadRate = time.Second
			if cfg.DisableGCRuns != !forceGC {
				t.Fatalf("DisableGCRuns=%v for force-gc=%v; the flag is not wired to the SDK", cfg.DisableGCRuns, forceGC)
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			p, err := pyroscope.Start(cfg)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(2500 * time.Millisecond) // two snapshot intervals
			_ = p.Stop()
			runtime.ReadMemStats(&after)
			forced := after.NumForcedGC - before.NumForcedGC
			if forceGC && forced == 0 {
				t.Errorf("force-gc=true: no forced GC across two heap snapshots")
			}
			if !forceGC && forced != 0 {
				t.Errorf("force-gc=false: %d forced GC(s) across two heap snapshots", forced)
			}
		})
	}
}
