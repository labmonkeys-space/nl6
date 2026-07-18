/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"testing"
)

// BenchmarkScenarioReportBuild measures report serialization at fleet scale
// (NFR-P2 evidence, story 1.5 AC3): the ≤5 s target must hold at 30k
// participants. Reported as ns/op so a regression is visible in benchstat.
func BenchmarkScenarioReportBuild(b *testing.B) {
	const N = 30000
	sm, ips := buildBenchScaleManager(N)
	c := newScenarioController(sm, nil)
	c.id, c.spec, c.configSHA = "s-000001", &Scenario{Protocol: "syslog", Seed: 1}, "deadbeef"
	res := &ScenarioResult{ID: "s-000001", Phase: phaseStopped, PerDevice: make(map[string]ledgerSnapshot, N)}
	for _, ip := range ips {
		res.PerDevice[ip] = ledgerSnapshot{Emitted: 10, InWindow: 10}
	}
	c.result = res

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if rep := buildScenarioReport(sm, c); rep == nil || len(rep.Counters) != N {
			b.Fatalf("report built %d counters, want %d", len(rep.Counters), N)
		}
	}
}

// buildBenchScaleManager is the benchmark-side (no *testing.T) counterpart of
// scaleManager: n devices with syslog configs, no exporters fired.
func buildBenchScaleManager(n int) (*SimulatorManager, []string) {
	sm := &SimulatorManager{
		devices:     make(map[string]*DeviceSimulator, n),
		deviceIPs:   make(map[string]struct{}, n),
		devicesByIP: make(map[string]*DeviceSimulator, n),
	}
	ips := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		ip := scaleIP(i)
		dev := &DeviceSimulator{ID: "device-" + ip.String(), IP: ip,
			syslogConfig: &DeviceSyslogConfig{Collector: "10.0.0.9:514"}}
		sm.devices[dev.ID] = dev
		sm.deviceIPs[ip.String()] = struct{}{}
		sm.devicesByIP[ip.String()] = dev
		ips = append(ips, ip.String())
	}
	return sm, ips
}
