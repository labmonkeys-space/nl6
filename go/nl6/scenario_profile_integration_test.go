/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/time/rate"
)

// scenario_profile_integration_test.go — λ(t) end-to-end (story 3.1): a
// time-varying profile drives real scenario emission through the NHPP path,
// determinism holds (golden counts under synctest), the emission is time-
// weighted per λ(t), and the shared global limiter still governs an over-cap
// profile.

// profileSink counts fires and, using the injected fake clock, splits them
// into the first vs second half of the window relative to a captured T0.
type profileSink struct {
	t0       atomic.Int64 // unix nanos of window open
	windowNs int64
	first    atomic.Uint64
	second   atomic.Uint64
	now      func() time.Time
}

func (s *profileSink) write([]byte) error {
	if t0 := s.t0.Load(); t0 != 0 {
		if s.now().UnixNano()-t0 < s.windowNs/2 {
			s.first.Add(1)
		} else {
			s.second.Add(1)
		}
	}
	return nil
}

func profileManager(t *testing.T, n int, window time.Duration, now func() time.Time) (*SimulatorManager, []string, *profileSink) {
	t.Helper()
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	sink := &profileSink{windowNs: window.Nanoseconds(), now: now}
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
		exp.writeOverride = sink.write
		dev := &DeviceSimulator{ID: "device-" + ip.String(), IP: ip, syslogExporter: exp,
			syslogConfig: &DeviceSyslogConfig{Collector: "10.0.0.9:514"}}
		sm.devices[dev.ID] = dev
		sm.deviceIPs[ip.String()] = struct{}{}
		sm.devicesByIP[ip.String()] = dev
		ips = append(ips, ip.String())
	}
	return sm, ips, sink
}

// runLinearProfile runs a rising linear-profile scenario under synctest and
// returns (in-window count, first-half fires, second-half fires).
func runLinearProfile(t *testing.T, seed int64) (uint64, uint64, uint64) {
	t.Helper()
	var inWindow, first, second uint64
	synctest.Test(t, func(t *testing.T) {
		const window = 10 * time.Second
		sm, ips, sink := profileManager(t, 5, window, time.Now)
		sink.t0.Store(time.Now().UnixNano())
		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: ips, Protocol: "syslog", Rate: 10, Window: window, Seed: seed,
			RateProfile: &RateProfileSpec{Kind: "linear", StartRate: 5, EndRate: 50}, // rising 5→50/s
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
		time.Sleep(window + time.Second + 100*time.Millisecond)
		synctest.Wait()
		res := c.Result()
		if res == nil {
			t.Fatal("scenario did not finalize")
		}
		for _, snap := range res.PerDevice {
			inWindow += snap.InWindow
		}
		first, second = sink.first.Load(), sink.second.Load()
	})
	return inWindow, first, second
}

// TestScenarioProfile_LinearDeterministicAndWeighted (FR5): a rising λ(t)
// yields a deterministic golden count under synctest and clearly more load in
// the back half of the window than the front.
func TestScenarioProfile_LinearDeterministicAndWeighted(t *testing.T) {
	inA, firstA, secondA := runLinearProfile(t, 42)
	inB, _, _ := runLinearProfile(t, 42)

	if inA == 0 {
		t.Fatal("no in-window emission")
	}
	// Determinism: same seed+profile → identical golden count.
	if inA != inB {
		t.Fatalf("non-deterministic count across runs: %d vs %d", inA, inB)
	}
	// Rising λ (5→50): the second half must carry clearly more load.
	if secondA <= firstA {
		t.Fatalf("emission not front-to-back weighted: first=%d second=%d (want second > first)", firstA, secondA)
	}
	if secondA < 2*firstA {
		t.Fatalf("weighting too weak for 5→50 rise: first=%d second=%d", firstA, secondA)
	}
	// Sanity: total ≈ Λ(window)×devices = (5+50)/2·10·5 = 1375, within ±15%.
	total := firstA + secondA
	if total < 1150 || total > 1600 {
		t.Fatalf("total fires %d far from expected Λ≈1375", total)
	}
	t.Logf("linear 5→50: in_window=%d first=%d second=%d", inA, firstA, secondA)
}

// TestScenarioProfile_OverCapGoverned: an over-cap profile is throttled by the
// SHARED global limiter, so the emitted count is bounded by the cap, not the
// profile's demand (FR36). Real time (the limiter uses the wall clock).
func TestScenarioProfile_OverCapGoverned(t *testing.T) {
	const window = 1 * time.Second
	const capTPS = 40
	sm, ips, _ := profileManager(t, 3, window, time.Now)

	// Publish a background scheduler carrying the shared cap; the scenario
	// scheduler must reuse its limiter rather than build a second one.
	shared := rate.NewLimiter(rate.Limit(capTPS), capTPS)
	bg := NewSyslogScheduler(SyslogSchedulerOptions{
		CatalogFor: func(net.IP) *SyslogCatalog { return sm.syslogCatalog }, MeanInterval: time.Second,
		SharedLimiter: shared,
	})
	sm.syslogScheduler.Store(bg)

	c := newScenarioController(sm, nil)
	// Demand far above the cap: constant-high would use fixed-interval, so use
	// a staged profile (NHPP) that wants ~300/device/s across 3 devices.
	spec := &Scenario{
		Participants: ips, Protocol: "syslog", Rate: 100, Window: window, Seed: 1,
		RateProfile: &RateProfileSpec{Kind: "staged", Stages: []ProfileStage{{Duration: "1s", Rate: 300}}},
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
	time.Sleep(window + 400*time.Millisecond)
	res, err := c.Stop()
	if err != nil {
		if res = c.Result(); res == nil {
			t.Fatalf("stop: %v", err)
		}
	}

	var sent uint64
	for _, snap := range res.PerDevice {
		sent += snap.InWindow + snap.Drain
	}
	// Demand was ~900 (300/s × 3 devices × 1s). The shared cap (40 tps + 40
	// burst) bounds the total; allow generous slack for scheduling but assert
	// it is FAR below demand — the cap governs.
	if sent > 150 {
		t.Fatalf("emitted %d exceeds what the %d-tps shared cap allows — cap not governing", sent, capTPS)
	}
	if sent == 0 {
		t.Fatal("cap starved the scenario entirely")
	}
	t.Logf("over-cap staged(300/s×3) under %d-tps shared cap: sent=%d", capTPS, sent)
}
