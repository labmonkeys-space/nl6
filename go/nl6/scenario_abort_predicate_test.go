/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// scenario_abort_predicate_test.go — self-aborting runaway scenarios (story
// 3.4, FR7): a predicate over a mid-run ledger metric aborts the run through
// the standard running→aborted pipeline once its threshold holds past the
// grace period.

// failingSyslogManager builds n devices whose every write fails, so a run
// accumulates send_failures (a "drowning collector" signal).
func failingSyslogManager(t *testing.T, n int) (*SimulatorManager, []string) {
	t.Helper()
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	sm := &SimulatorManager{
		devices: map[string]*DeviceSimulator{}, deviceIPs: map[string]struct{}{},
		deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{}, syslogCatalog: cat,
	}
	ips := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		ip := scaleIP(i)
		exp := NewSyslogExporter(SyslogExporterOptions{
			DeviceIP: ip, Encoder: &RFC5424Encoder{}, Collector: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 514},
			SysName: "dev", IfIndexFn: func() int { return 3 }, IfNameFn: func(int) string { return "Gi0/3" },
		})
		exp.writeOverride = func([]byte) error { return fmt.Errorf("induced write failure") }
		dev := &DeviceSimulator{ID: "device-" + ip.String(), IP: ip, syslogExporter: exp,
			syslogConfig: &DeviceSyslogConfig{Collector: "10.0.0.9:514"}}
		sm.devices[dev.ID] = dev
		sm.deviceIPs[ip.String()] = struct{}{}
		sm.devicesByIP[ip.String()] = dev
		ips = append(ips, ip.String())
	}
	return sm, ips
}

// TestScenarioAbortPredicate_Triggers (FR7): send_failures crossing the
// threshold for the grace period aborts the run well before its window ends,
// through the standard pipeline (phase aborted + report).
func TestScenarioAbortPredicate_Triggers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, ips := failingSyslogManager(t, 2)
		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: ips, Protocol: "syslog", Rate: 10, Window: 30 * time.Second, Drain: time.Second, Seed: 1,
			// 20 failures/s (2 devices × 10/s) crosses 20 within ~1–2s; abort 3s later.
			AbortPredicate: &AbortPredicateSpec{Metric: "send_failures", Threshold: 20, Grace: "3s"},
		}
		if err := c.Submit(spec, "s-000001"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}

		// Well before the 30s window: the predicate must have aborted.
		time.Sleep(8 * time.Second)
		synctest.Wait()

		if c.Phase() != phaseAborted {
			t.Fatalf("phase = %s, want aborted (predicate should have fired)", c.Phase())
		}
		res := c.Result()
		if res == nil || res.Phase != phaseAborted {
			t.Fatalf("no aborted result: %+v", res)
		}
		// The abort truncated the window well short of 30s.
		if d := res.T1Actual.Sub(res.T0Actual); d >= 30*time.Second {
			t.Fatalf("window not truncated by abort: %s", d)
		}
		// Standard pipeline: the transition log ends at aborted.
		trs := c.Transitions()
		if trs[len(trs)-1].Phase != phaseAborted {
			t.Fatalf("transition log does not end aborted: %+v", trs)
		}
	})
}

// TestScenarioAbortPredicate_DoesNotTrigger: a threshold the run never reaches
// leaves the scenario to complete normally (stopped at T1).
func TestScenarioAbortPredicate_DoesNotTrigger(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, ips := failingSyslogManager(t, 2)
		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: ips, Protocol: "syslog", Rate: 10, Window: 2 * time.Second, Drain: 200 * time.Millisecond, Seed: 1,
			AbortPredicate: &AbortPredicateSpec{Metric: "send_failures", Threshold: 1_000_000, Grace: "1s"},
		}
		if err := c.Submit(spec, "s-000001"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Second)
		synctest.Wait()
		res := c.Result()
		if res == nil || res.Phase != phaseStopped {
			t.Fatalf("expected clean stop, got %+v", res)
		}
	})
}

// TestBuildAbortPredicate_Validation covers spec resolution + rejections.
func TestBuildAbortPredicate_Validation(t *testing.T) {
	if p, err := buildAbortPredicate(nil); err != nil || p != nil {
		t.Fatalf("nil spec: p=%v err=%v", p, err)
	}
	if _, err := buildAbortPredicate(&AbortPredicateSpec{Metric: "send_failures", Threshold: 10, Grace: "5s"}); err != nil {
		t.Fatalf("valid predicate rejected: %v", err)
	}
	for _, bad := range []*AbortPredicateSpec{
		{Metric: "cpu", Threshold: 10},                 // unknown metric
		{Metric: "sent", Threshold: 0},                 // zero threshold
		{Metric: "sent", Threshold: 10, Grace: "nope"}, // bad grace
	} {
		if _, err := buildAbortPredicate(bad); err == nil {
			t.Fatalf("expected rejection for %+v", bad)
		}
	}
}
