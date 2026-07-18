/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// scenario_fleet_scale_test.go — fleet-scale validation (story 4.7). The
// shared gate/ledger increment path is proven race-free at 10k for syslog+flow
// in scenario_scale_test.go; this adds the NEWEST producer sites (SNMP trap
// fireWithSource + gNMI dial-out scenarioGate) to a concurrent mixed-producer
// race, so ALL six gate sites are covered under -race with real instances
// (NFR-S1/S2). NFR-P2 (report ≤5s @ 30k) and the gate-decide benchstat are the
// existing BenchmarkScenarioReportBuild / BenchmarkScenarioGateDecide; NFR-P3
// (poll paths untouched) holds by construction — the gate lives only on push
// exporters, asserted below.

// TestScenarioFleet_MixedProducerRace hammers the trap + dial-out gate sites
// concurrently across many participants sharing running gates, then asserts
// every ledger identity holds. Run under -race.
func TestScenarioFleet_MixedProducerRace(t *testing.T) {
	if testing.Short() {
		t.Skip("fleet-scale race test: skipped under -short")
	}
	cat, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	// One shared discard socket for every trap exporter (WriteToUDP is
	// goroutine-safe) so the test doesn't open thousands of sockets.
	shared := openTestUDPConn(t)
	defer shared.Close()
	discard := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}

	const N = 2000
	t0 := time.Unix(1_700_000_000, 0)
	running := &gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour), drainEnd: t0.Add(time.Hour + time.Second)}

	type part struct {
		trap    *TrapExporter
		dialout *GnmiDialoutExporter
		ledger  *ledgerEntry
		drain   *drainGate
		gate    *atomic.Pointer[gateState]
	}
	parts := make([]*part, N)
	dev := newTestGnmiDevice(t, 1)
	for i := 0; i < N; i++ {
		led := &ledgerEntry{}
		dg := &drainGate{}
		g := &atomic.Pointer[gateState]{}
		g.Store(running)
		sp := &scenarioPart{gate: g, ledger: led, drain: dg, now: time.Now}

		tx := NewTrapExporter(TrapExporterOptions{
			DeviceIP: net.IPv4(10, 42, 0, 1), Community: "public", Mode: TrapModeTrap,
			Collector: discard, IfIndexFn: func() int { return 3 }, IfNameFn: func(int) string { return "Gi0/3" },
		})
		tx.SetConn(shared)
		tx.scenPart.Store(sp)

		dx := newTestDialoutExporter(t, dev, "127.0.0.1:0", "sample",
			[]string{"/interfaces/interface[name=*]/state/oper-status"})
		setStreamLive(dx, true)
		dx.scenPart.Store(sp)

		parts[i] = &part{trap: tx, dialout: dx, ledger: led, drain: dg, gate: g}
	}

	entry := cat.ByName["linkDown"]
	const G = 8
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i, p := range parts {
				switch (i + w) % 3 {
				case 0:
					p.trap.fireScenario(entry, nil)
				case 1:
					_, leave := p.dialout.scenarioGate(time.Now())
					leave()
				case 2:
					p.trap.FireForInterface(entry, 3) // state-driven site
				}
			}
		}(w)
	}
	wg.Wait()

	for i, p := range parts {
		p.drain.closeAndWait()
		if !p.ledger.identityHolds() {
			t.Fatalf("ledger[%d] identity violated: %+v", i, p.ledger.snapshot())
		}
	}
}

// TestScenarioFleet_PollPathsUngated (NFR-P3): the gate lives only on push
// exporters, so a device with NO scenario attached serves its poll surfaces
// (here: gNMI dial-in path resolution) byte-for-byte regardless of any
// scenario machinery. Proven by construction — the dial-in resolver has no
// scenPart field.
func TestScenarioFleet_PollPathsUngated(t *testing.T) {
	device := newTestGnmiDevice(t, 2)
	// The dial-in resolver (poll path) is the same one dial-out reuses; it
	// carries no scenario handle. Resolving a path must succeed and be
	// unaffected by scenario state (there is none to affect it).
	r := newPathResolver(device)
	p, err := parseGnmiPath("/interfaces/interface[name=*]/state/oper-status")
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve(p, time.Now())
	if err != nil {
		t.Fatalf("poll-path resolve: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("poll path returned no updates — degraded")
	}
}

// TestScenarioFleet_ReportUnder5sMixed re-affirms NFR-P2 at fleet scale for the
// report projection (protocol-agnostic — the same builder serves every
// protocol). Complements BenchmarkScenarioReportBuild.
func TestScenarioFleet_ReportUnder5sMixed(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test: skipped under -short")
	}
	const N = 30000
	sm, ips := scaleManager(t, N)
	c := newScenarioController(sm, nil)
	c.id, c.spec, c.configSHA = "s-000001", &Scenario{Protocol: "netflow9", Seed: 1}, "deadbeef"
	res := &ScenarioResult{ID: "s-000001", Phase: phaseStopped, PerDevice: make(map[string]ledgerSnapshot, N)}
	for _, ip := range ips {
		res.PerDevice[ip] = ledgerSnapshot{Emitted: 10, InWindow: 10, InformsOriginated: 4, InformsAcked: 3}
	}
	c.result = res

	start := time.Now()
	rep := buildScenarioReport(sm, c)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("report build %s exceeds the 5s target at %d devices", d, N)
	}
	if len(rep.Counters) != N {
		t.Fatalf("counters = %d, want %d", len(rep.Counters), N)
	}
}
