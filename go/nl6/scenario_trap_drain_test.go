/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Finalize-vs-emission-pool drain tests (#409 / await-trap-emission-drain).
//
// The contract: for an snmp-trap scenario, finalize waits for the scenario
// emission pool to fully drain (trapTickerDone) before snapshotting ledgers,
// so no queued fire mutates counters concurrently with — or after — the
// snapshot, and the report's ledger identity holds even for a run stopped
// while saturated.
//
// Real time, not synctest: the emission pool's workers and the UDP-backed
// exporters would not be durably-blocked inside a synctest bubble.

package main

import (
	"context"
	"net"
	"testing"
	"time"
)

// scenarioTrapTestManager mirrors scenarioTestManager but with trap-capable
// devices: each has a TrapExporter with a real UDP conn to a throwaway
// collector, and the manager carries the universal trap catalog so
// CatalogFor resolves.
func scenarioTrapTestManager(t *testing.T, n int) *SimulatorManager {
	t.Helper()
	cat, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	mc := newMockCollector(t, false)
	t.Cleanup(mc.Close)

	sm := &SimulatorManager{
		devices:            make(map[string]*DeviceSimulator),
		deviceIPs:          make(map[string]struct{}),
		deviceTypesByIP:    make(map[string]string),
		devicesByIP:        make(map[string]*DeviceSimulator),
		trapCatalog:        cat,
		trapCatalogsByType: map[string]*Catalog{universalCatalogKey: cat},
	}
	for i := 1; i <= n; i++ {
		ip := net.IPv4(10, 42, 0, byte(i))
		exp := NewTrapExporter(TrapExporterOptions{
			DeviceIP:  ip,
			Community: "public",
			Mode:      TrapModeTrap,
			Collector: mc.addr,
			IfIndexFn: func() int { return 3 },
			IfNameFn:  func(int) string { return "Gi0/3" },
		})
		exp.SetConn(openTestUDPConn(t))
		dev := &DeviceSimulator{ID: "device-" + ip.String(), IP: ip, trapExporter: exp}
		sm.devices[dev.ID] = dev
		sm.deviceIPs[ip.String()] = struct{}{}
		sm.devicesByIP[ip.String()] = dev
	}
	return sm
}

// TestScenarioTrapFinalize_LedgerIdentityUnderSaturation stops a saturated
// snmp-trap scenario mid-window and asserts (repeatedly, for flake
// resistance) that the ledger identity holds in the report and that no
// counter moves after the snapshot — the #409 symptom was late queued fires
// mutating counters post-snapshot.
func TestScenarioTrapFinalize_LedgerIdentityUnderSaturation(t *testing.T) {
	for round := 0; round < 3; round++ {
		sm := scenarioTrapTestManager(t, 3)
		ips := []string{"10.42.0.1", "10.42.0.2", "10.42.0.3"}
		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: ips,
			Protocol:     "snmp-trap",
			Rate:         500, // per device: 1500 fires/s demand across the fleet
			Window:       2 * time.Second,
			Drain:        200 * time.Millisecond,
			Seed:         int64(round + 1),
		}
		if err := c.Submit(spec, "s-00040"+string(rune('0'+round))); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}

		// Stop mid-window while the emission pool is under full demand, so
		// the worker queue is as full as it gets at the moment of finalize.
		time.Sleep(150 * time.Millisecond)
		res, err := c.Stop()
		if err != nil {
			if res = c.Result(); res == nil {
				t.Fatalf("round %d: stop: %v", round, err)
			}
		}

		for ip, snap := range res.PerDevice {
			sent := snap.InWindow + snap.Drain
			if snap.Emitted != sent+snap.SendFailures+snap.Dropped+snap.SuppressedPreWindow {
				t.Fatalf("round %d: ledger identity violated for %s: %+v", round, ip, snap)
			}
		}

		// No counter may move after the snapshot: re-snapshot the live
		// ledgers after a grace period and require equality with the report.
		// Pre-fix, queued pool fires kept mutating for up to a queue's worth
		// of sends past finalize.
		time.Sleep(100 * time.Millisecond)
		for ip, led := range c.ledgers {
			if again := led.snapshot(); again != res.PerDevice[ip] {
				t.Fatalf("round %d: ledger for %s moved after finalize:\n report=%+v\n later =%+v",
					round, ip, res.PerDevice[ip], again)
			}
		}
	}
}
