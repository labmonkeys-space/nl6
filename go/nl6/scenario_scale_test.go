/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// scenario_scale_test.go — ground-truth proof at fleet scale (story 1.5):
// the increment path is race-free with all sources concurrent over ≥10k
// participants (AC1), the ledger equals the wire ±0 at volume (AC2), and
// the report builds within the ≤5 s target at 30k devices (AC3).

// scaleIP maps a 0-based index to a unique 10.42.x.y management IP, so the
// builder scales past the 255-device ceiling of net.IPv4(10,42,0,byte(i)).
func scaleIP(i int) net.IP { return net.IPv4(10, 42, byte(i>>8), byte(i&0xff)) }

// scaleManager builds n syslog-capable devices with in-memory write sinks
// (no UDP, no scheduler running) and returns the manager plus the ordered
// participant IP list.
func scaleManager(t *testing.T, n int) (*SimulatorManager, []string) {
	t.Helper()
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	sm := &SimulatorManager{
		devices:         make(map[string]*DeviceSimulator, n),
		deviceIPs:       make(map[string]struct{}, n),
		deviceTypesByIP: make(map[string]string, n),
		devicesByIP:     make(map[string]*DeviceSimulator, n),
		syslogCatalog:   cat,
	}
	ips := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		ip := scaleIP(i)
		exp := NewSyslogExporter(SyslogExporterOptions{
			DeviceIP: ip, Encoder: &RFC5424Encoder{}, Collector: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 514},
			SysName: "dev", IfIndexFn: func() int { return 3 }, IfNameFn: func(int) string { return "Gi0/3" },
		})
		exp.writeOverride = func([]byte) error { return nil } // in-memory: isolate the increment path
		dev := &DeviceSimulator{ID: "device-" + ip.String(), IP: ip, syslogExporter: exp,
			syslogConfig: &DeviceSyslogConfig{Collector: "10.0.0.9:514"}}
		sm.devices[dev.ID] = dev
		sm.deviceIPs[ip.String()] = struct{}{}
		sm.devicesByIP[ip.String()] = dev
		ips = append(ips, ip.String())
	}
	return sm, ips
}

// TestScenarioScale_ConcurrentIncrementRace (AC1/NFR-A1): with ≥10k armed
// participants and every fire source hammering the ledger concurrently, the
// increment path is race-free (run under -race) and every ledger identity
// holds. Uses a manually-published running gate so the workers — not the
// scheduler — drive volume, isolating the shared increment path.
func TestScenarioScale_ConcurrentIncrementRace(t *testing.T) {
	if testing.Short() {
		t.Skip("scale/race test: skipped under -short")
	}
	const N = 10000
	sm, ips := scaleManager(t, N)
	entry := sm.syslogCatalog.Entries[0]

	c := newScenarioController(sm, nil)
	spec := &Scenario{Participants: ips, Protocol: "syslog", Rate: 1, Window: time.Hour, Seed: 1}
	if err := c.Submit(spec, "s-000001"); err != nil {
		t.Fatal(err)
	}
	armed, _, err := c.Arm()
	if err != nil || armed != N {
		t.Fatalf("Arm: armed=%d err=%v, want %d", armed, err, N)
	}
	// Publish a running gate directly (skip the scheduler): the window is
	// wide open so every worker fire in it is admitted and counted.
	now := c.now()
	c.gate.Store(&gateState{phase: phaseRunning, t0: now, t1: now.Add(time.Hour)})

	// For EVERY device, fire all four sources as four concurrent goroutines
	// hitting the SAME exporter + ledger at once — this is what forces the
	// race detector to inspect concurrent same-ledger access (a staggered
	// per-worker sweep would only collide incidentally). A semaphore bounds
	// the live goroutine count so 10k devices don't spawn 40k at once.
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	fireAllSources := func(exp *SyslogExporter) {
		defer wg.Done()
		var inner sync.WaitGroup
		sources := []func(){
			func() { _ = exp.Fire(entry, nil) },           // on-demand
			func() { _ = exp.FireForInterface(entry, 3) }, // state-driven
			func() { _ = exp.fireBackground(entry, nil) }, // background (suppressed)
			func() { _ = exp.fireScenario(entry, nil) },   // scenario
		}
		for _, fn := range sources {
			inner.Add(1)
			go func(fn func()) { defer inner.Done(); fn() }(fn)
		}
		inner.Wait()
		<-sem
	}
	for _, ip := range ips {
		sem <- struct{}{}
		wg.Add(1)
		go fireAllSources(sm.devicesByIP[ip].syslogExporter)
	}
	wg.Wait()

	// Close admission and drain, then assert every ledger identity holds.
	c.drain.closeAndWait()
	for ip, led := range c.ledgers {
		if !led.identityHolds() {
			t.Fatalf("ledger identity violated for %s: %+v", ip, led.snapshot())
		}
	}
}

// TestScenarioScale_LedgerEqualsWire (AC2/NFR-R1): a moderate-volume run
// across many devices to ONE loopback collector reconciles exactly — the
// summed report `sent` equals the datagrams the collector received, and the
// ledger identity holds at scale.
func TestScenarioScale_LedgerEqualsWire(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test: skipped under -short")
	}
	mc := newMockCollector(t, false)
	defer mc.Close()

	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	const N = 25
	sm := &SimulatorManager{
		devices: map[string]*DeviceSimulator{}, deviceIPs: map[string]struct{}{},
		deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{}, syslogCatalog: cat,
	}
	socks := make([]*net.UDPConn, 0, N)
	ips := make([]string, 0, N)
	for i := 1; i <= N; i++ {
		ip := scaleIP(i)
		shared, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		socks = append(socks, shared)
		exp := NewSyslogExporter(SyslogExporterOptions{
			DeviceIP: ip, Encoder: &RFC5424Encoder{}, Collector: mc.addr, SharedConn: shared,
			SysName: "dev", IfIndexFn: func() int { return 3 }, IfNameFn: func(int) string { return "Gi0/3" },
		})
		dev := &DeviceSimulator{ID: "device-" + ip.String(), IP: ip, syslogExporter: exp,
			syslogConfig: &DeviceSyslogConfig{Collector: mc.addr.String()}}
		sm.devices[dev.ID] = dev
		sm.deviceIPs[ip.String()] = struct{}{}
		sm.devicesByIP[ip.String()] = dev
		ips = append(ips, ip.String())
	}
	defer func() {
		for _, s := range socks {
			s.Close()
		}
	}()

	c := newScenarioController(sm, nil)
	spec := &Scenario{Participants: ips, Protocol: "syslog", Rate: 10, Window: 300 * time.Millisecond, Seed: 5}
	if err := c.Submit(spec, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 200ms of real-time slack on a 300ms window (see the note in
	// TestScenarioAcceptance_SentEqualsReceived): wall-clock test, loaded CI.
	time.Sleep(spec.Window + 200*time.Millisecond)
	res, err := c.Stop()
	if err != nil {
		if res = c.Result(); res == nil {
			t.Fatalf("Stop: %v", err)
		}
	}

	// Same drain-tail assertion as the acceptance test, at 50 devices
	// (nl6#500): a transport parking writes past T1 would show up here first.
	assertDrainTailIsBounded(t, res)

	var sent uint64
	for _, snap := range res.PerDevice {
		sent += snap.InWindow + snap.Drain
		if snap.Emitted != snap.InWindow+snap.Drain+snap.SendFailures+snap.Dropped+snap.SuppressedPreWindow {
			t.Fatalf("ledger identity violated at scale: %+v", snap)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && mc.received.Load() < sent {
		time.Sleep(20 * time.Millisecond)
	}
	if got := mc.received.Load(); got != sent {
		t.Fatalf("collector received %d, report sent %d — must reconcile ±0", got, sent)
	}
	if sent == 0 {
		t.Fatal("no datagrams sent")
	}
}

// TestScenarioScale_ReportBuildUnder5s (AC3/NFR-P2): building the report from
// a 30k-device finalized result completes well within the ≤5 s target.
func TestScenarioScale_ReportBuildUnder5s(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test: skipped under -short")
	}
	const N = 30000
	sm, ips := scaleManager(t, N)
	c := newScenarioController(sm, nil)
	c.id, c.spec, c.configSHA = "s-000001", &Scenario{Protocol: "syslog", Seed: 1}, "deadbeef"
	res := &ScenarioResult{ID: "s-000001", Phase: phaseStopped, PerDevice: make(map[string]ledgerSnapshot, N)}
	for _, ip := range ips {
		res.PerDevice[ip] = ledgerSnapshot{Emitted: 10, InWindow: 10}
	}
	c.result = res

	start := time.Now()
	rep := buildScenarioReport(sm, c)
	elapsed := time.Since(start)
	if rep == nil || len(rep.Counters) != N {
		t.Fatalf("report built %d counters, want %d", len(rep.Counters), N)
	}
	if rep.Summary.InWindow != uint64(N)*10 {
		t.Fatalf("summary in_window = %d, want %d", rep.Summary.InWindow, N*10)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("report build took %s, exceeds the 5s target", elapsed)
	}
	t.Logf("report build for %d devices: %s", N, elapsed)
}
