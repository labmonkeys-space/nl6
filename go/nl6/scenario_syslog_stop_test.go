/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Finalize-vs-scheduler stop test for syslog scenarios (#410 /
// await-syslog-emission-stop): finalize's existing c.sched.Stop() call is now
// an awaited barrier, so no inline scenario fire can mutate ledger counters
// concurrently with — or after — the snapshot. Syslog mirror of
// TestScenarioTrapFinalize_LedgerIdentityUnderSaturation.
//
// Real time, not synctest: the slow write override below simulates in-flight
// wire writes, which would not be durably-blocked in a synctest bubble.

package main

import (
	"context"
	"testing"
	"time"
)

func TestScenarioSyslogFinalize_LedgerIdentityUnderLoad(t *testing.T) {
	for round := 0; round < 3; round++ {
		sm, _ := scenarioTestManager(t, 3)
		ips := []string{"10.42.0.1", "10.42.0.2", "10.42.0.3"}

		// Slow the wire down so a fire is very likely in flight inside the
		// scheduler's inline Run loop at the moment Stop is called — that
		// in-flight fire is exactly the #410 window.
		for _, dev := range sm.devicesByIP {
			dev.syslogExporter.writeOverride = func(_ []byte) error {
				time.Sleep(2 * time.Millisecond)
				return nil
			}
		}

		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: ips,
			Protocol:     "syslog",
			Rate:         200, // per device; well above what 2ms writes sustain
			Window:       2 * time.Second,
			Seed:         int64(round + 1),
		}
		if err := c.Submit(spec, "s-00041"+string(rune('0'+round))); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}

		// Stop mid-window while fires are in flight.
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

		// No counter may move after the snapshot; pre-fix, one in-flight
		// inline fire could still land post-finalize.
		time.Sleep(100 * time.Millisecond)
		for ip, led := range c.ledgers {
			if again := led.snapshot(); again != res.PerDevice[ip] {
				t.Fatalf("round %d: ledger for %s moved after finalize:\n report=%+v\n later =%+v",
					round, ip, res.PerDevice[ip], again)
			}
		}
	}
}
