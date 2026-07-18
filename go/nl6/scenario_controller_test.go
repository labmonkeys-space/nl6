/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// scenarioTestManager builds a manager with `n` syslog-capable devices
// (10.42.0.1..n) whose exporters write into per-device in-memory sinks. No
// UDP, no background scheduler running. Returns the manager and the shared
// wire-write counter.
func scenarioTestManager(t *testing.T, n int) (*SimulatorManager, *atomic.Uint64) {
	t.Helper()
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	sm := &SimulatorManager{
		devices:         make(map[string]*DeviceSimulator),
		deviceIPs:       make(map[string]struct{}),
		deviceTypesByIP: make(map[string]string),
		devicesByIP:     make(map[string]*DeviceSimulator),
		syslogCatalog:   cat,
	}
	var wire atomic.Uint64
	for i := 1; i <= n; i++ {
		ip := net.IPv4(10, 42, 0, byte(i))
		exp := NewSyslogExporter(SyslogExporterOptions{
			DeviceIP:  ip,
			Encoder:   &RFC5424Encoder{},
			Collector: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 514},
			SysName:   "dev",
			IfIndexFn: func() int { return 3 },
			IfNameFn:  func(int) string { return "Gi0/3" },
		})
		exp.writeOverride = func(_ []byte) error { wire.Add(1); return nil }
		dev := &DeviceSimulator{ID: "device-" + ip.String(), IP: ip, syslogExporter: exp}
		sm.devices[dev.ID] = dev
		sm.deviceIPs[ip.String()] = struct{}{}
		sm.devicesByIP[ip.String()] = dev
	}
	return sm, &wire
}

// AC4/AC5: fixed-rate determinism + exact count. Under synctest fake time,
// a fixed-seed constant-rate scenario emits exactly rate×window records,
// byte-identical across runs; the ledger identity holds.
func TestScenarioController_FixedRateExactCount(t *testing.T) {
	run := func() ledgerSnapshot {
		var snap ledgerSnapshot
		synctest.Test(t, func(t *testing.T) {
			sm, _ := scenarioTestManager(t, 1)
			c := newScenarioController(sm, nil) // bubble time
			spec := &Scenario{
				Participants: []string{"10.42.0.1"},
				Protocol:     "syslog",
				Rate:         10, // 10/s → 100ms interval
				Window:       time.Second,
				Drain:        500 * time.Millisecond,
				Seed:         42,
			}
			if err := c.Submit(spec, "s-000001"); err != nil {
				t.Fatal(err)
			}
			armed, _, err := c.Arm()
			if err != nil || armed != 1 {
				t.Fatalf("Arm: armed=%d err=%v", armed, err)
			}
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			// The window self-closes at T1 (auto-stop). Advance past T1 +
			// drain; synctest advances fake time while the scheduler
			// goroutine sleeps between fires, then the auto-stop timer fires
			// and finalizes. Do NOT call Stop() — that would double-stop.
			time.Sleep(spec.Window + spec.drainOrDefault() + 100*time.Millisecond)
			synctest.Wait()
			res := c.Result()
			if res == nil {
				t.Fatal("scenario did not auto-finalize at T1")
			}
			if res.Phase != phaseStopped {
				t.Fatalf("phase = %s, want stopped", res.Phase)
			}
			snap = res.PerDevice["10.42.0.1"]
		})
		return snap
	}

	a := run()
	b := run()

	// 10/s over a 1s half-open window, first fire at T0 → exactly 10.
	if a.InWindow != 10 {
		t.Errorf("in_window = %d, want 10 (rate×window)", a.InWindow)
	}
	// The SENT/identity buckets are the determinism contract. The demand
	// counter `requested` is counted at scheduler pop, so the fire that lands
	// exactly on the T1 boundary races the auto-stop and may be popped (11) or
	// not (10) — it is gate-suppressed either way, so it never affects sent.
	// Exclude the boundary-racy demand counters from strict equality.
	a.Requested, a.Deferred = 0, 0
	b.Requested, b.Deferred = 0, 0
	if a != b {
		t.Errorf("non-deterministic ledger across runs:\n a=%+v\n b=%+v", a, b)
	}
	sent := a.InWindow + a.Drain
	if a.Emitted != sent+a.SendFailures+a.Dropped+a.SuppressedPreWindow {
		t.Errorf("ledger identity violated: %+v", a)
	}
}

// AC6: the transition table rejects illegal edges, is idempotent, flips the
// freeze on running and clears it at finalize.
func TestScenarioController_Transitions(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, nil)
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "syslog", Rate: 1, Window: time.Second, Seed: 1}

	// Cannot start before arm.
	if err := c.Start(context.Background()); !errors.Is(err, errInvalidTransition) {
		t.Errorf("Start before arm: err=%v, want invalid-transition", err)
	}
	if err := c.Submit(spec, "s-000042"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	// Idempotent re-arm returns nil.
	if _, _, err := c.Arm(); err != nil {
		t.Errorf("idempotent re-Arm: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Freeze is set while running.
	if err := sm.fleetFreezeCheck(); err == nil {
		t.Error("fleet should be frozen while scenario running")
	}
	// Cannot cancel a running scenario.
	if err := c.Cancel(); !errors.Is(err, errInvalidTransition) {
		t.Errorf("Cancel while running: err=%v, want invalid-transition", err)
	}
	if _, err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	// Freeze cleared at finalize; participation detached.
	if err := sm.fleetFreezeCheck(); err != nil {
		t.Errorf("fleet should be unfrozen after stop: %v", err)
	}
	if sm.devicesByIP["10.42.0.1"].syslogExporter.scenPart.Load() != nil {
		t.Error("participation handle should be nil-swapped after stop")
	}
	// Cannot stop twice (terminal).
	if _, err := c.Stop(); !errors.Is(err, errInvalidTransition) {
		t.Errorf("double Stop: err=%v, want invalid-transition", err)
	}
}

// FR9: unknown participants land in the excluded set with a reason, and arm
// still succeeds for the known ones.
func TestScenarioController_ArmExcludesUnknown(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, nil)
	spec := &Scenario{
		Participants: []string{"10.42.0.1", "10.42.0.99"},
		Protocol:     "syslog", Rate: 1, Window: time.Second, Seed: 1,
	}
	if err := c.Submit(spec, "s-000007"); err != nil {
		t.Fatal(err)
	}
	armed, excluded, err := c.Arm()
	if err != nil {
		t.Fatal(err)
	}
	if armed != 1 {
		t.Errorf("armed = %d, want 1", armed)
	}
	if len(excluded) != 1 || excluded[0].Device != "10.42.0.99" {
		t.Fatalf("excluded = %+v, want one entry for 10.42.0.99", excluded)
	}
	if excluded[0].Reason == "" || excluded[0].RemediationHint == "" {
		t.Error("excluded entry must carry reason + remediation_hint (readiness contract)")
	}
}

// FR39: cancel an armed-but-unstarted scenario releases participation with
// no measurement report.
func TestScenarioController_CancelFromArmed(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, nil)
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "syslog", Rate: 1, Window: time.Second, Seed: 1}
	if err := c.Submit(spec, "s-000009"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	if err := c.Cancel(); err != nil {
		t.Fatal(err)
	}
	if sm.devicesByIP["10.42.0.1"].syslogExporter.scenPart.Load() != nil {
		t.Error("participation handle should be detached after cancel")
	}
	if c.result != nil {
		t.Error("cancel must not produce a measurement result")
	}
	// Fleet was never frozen (freeze happens at start).
	if err := sm.fleetFreezeCheck(); err != nil {
		t.Errorf("fleet should not be frozen after cancel-from-armed: %v", err)
	}
}
