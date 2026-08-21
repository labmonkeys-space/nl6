/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Awaited-Stop contract tests for the scenario-owned flow ticker. Companion to
// syslog_scheduler_stop_test.go (#415) and the trap drain suite (#409): flow
// was the fourth emission architecture and the only one whose ticker finalize
// cancelled without joining.
//
// The contract is asserted directly — "the goroutine has returned by the time
// Stop returns" — rather than through its symptom. Without the join the ticker
// is parked on its interval timer when Stop returns, so its done channel is
// definitively still open; with the join it is definitively closed. That is
// deterministic in both directions, which a counter-watching test alone could
// not be: forcing a straggler mid-pass would need a write seam FlowExporter
// does not have, and participant visit order is map-random.

package main

import (
	"context"
	"net"
	"testing"
	"time"
)

// flowTickerFixture builds a one-device netflow9 manager whose exporter can
// actually TICK, not merely arm. Two things armFixtureFlow omits, because it
// exists for handle-installation tests:
//
//   - sm.flowBufPool.New — supplied in production by the flow subsystem's
//     start (flow_exporter.go), which no unit fixture runs. Without it Tick
//     panics on the pool's type assertion.
//   - a real collector socket and a SHORT template interval, so every tick
//     puts bytes on the wire. Templates keep flowing while data records are
//     gate-suppressed, and that is what makes a leaked ticker observable —
//     with a 10-minute interval only the first tick emits, and the "nothing
//     ticked after Stop" assertion would pass vacuously.
func flowTickerFixture(t *testing.T) (*SimulatorManager, *FlowExporter) {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	dev := testDevice("10.42.0.1")
	dev.ID = "device-10.42.0.1"
	dev.IP = net.ParseIP("10.42.0.1").To4()
	fe := newTestFlowExporter(dev, zeroGenFlowProfile(), time.Millisecond, time.Millisecond, time.Millisecond)
	fe.collectorAddr = ln.LocalAddr().(*net.UDPAddr)
	fe.collectorStr = ln.LocalAddr().String()
	fe.protocol = "netflow9"
	dev.flowExporter = fe

	sm := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{dev.ID: dev},
		deviceIPs:       map[string]struct{}{"10.42.0.1": {}},
		deviceTypesByIP: map[string]string{},
		devicesByIP:     map[string]*DeviceSimulator{"10.42.0.1": dev},
	}
	sm.flowBufPool.New = func() any { b := make([]byte, 1500); return &b }
	return sm, fe
}

// startedFlowScenario submits, arms and starts a netflow9 scenario at a 5 ms
// cadence so the ticker is provably live during the run.
func startedFlowScenario(t *testing.T, sm *SimulatorManager) *ScenarioController {
	t.Helper()
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(&Scenario{
		Participants: []string{"10.42.0.1"},
		Protocol:     "netflow9",
		Rate:         200,
		Window:       time.Minute,
	}, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if armed, _, err := c.Arm(); err != nil || armed != 1 {
		t.Fatalf("arm: armed=%d err=%v", armed, err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestScenarioFlowTicker_StopJoinsTicker pins the join. A cancelled goroutine
// is not a stopped one, and the difference is observable: a straggler tick at a
// terminal gate still reaches ledger.backgroundSuppressed after the drain
// barrier has closed, and — once a device can be claimed by a successor
// scenario — would load that successor's handle and be admitted to its drain as
// an indistinguishable legitimate send.
func TestScenarioFlowTicker_StopJoinsTicker(t *testing.T) {
	sm, fe := flowTickerFixture(t)
	c := startedFlowScenario(t, sm)

	// The flow path must be the one under test: a scenario-driven exporter is
	// marked so the fleet ticker yields. If this goes false the ticker never
	// started and everything below is vacuous.
	if !fe.scenDriven.Load() {
		t.Fatal("precondition: participant should be scenario-driven while running")
	}
	c.mu.Lock()
	done := c.flowTickerDone
	c.mu.Unlock()
	if done == nil {
		t.Fatal("precondition: a flow scenario must start a flow ticker")
	}
	select {
	case <-done:
		t.Fatal("precondition: the ticker should still be running mid-scenario")
	default:
	}

	if _, err := c.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// The contract. No sleep, no polling: if finalize joined the goroutine this
	// channel is closed the instant Stop returns.
	select {
	case <-done:
	default:
		t.Fatal("Stop returned while the scenario flow ticker was still running: " +
			"cancelling it is not the same as joining it")
	}

	// And the handle is released, so a successor could claim this device with
	// no straggler able to reach it.
	if fe.scenPart.Load() != nil {
		t.Error("participation handle survived finalize")
	}
	if fe.scenDriven.Load() {
		t.Error("scenDriven survived finalize; the fleet ticker would keep yielding")
	}
}

// TestScenarioFlowTicker_StopIsFinal is the behavioural companion: once Stop
// returns, nothing this scenario owns puts bytes on the wire again. The fixture
// deliberately runs no fleet ticker — after finalize clears scenDriven the
// fleet ticker legitimately resumes these devices, so this assertion holds only
// while the scenario ticker is the sole driver.
func TestScenarioFlowTicker_StopIsFinal(t *testing.T) {
	sm, fe := flowTickerFixture(t)
	c := startedFlowScenario(t, sm)

	type snap struct{ packets, bytes, records uint64 }
	read := func() snap {
		return snap{fe.statPackets.Load(), fe.statBytes.Load(), fe.statRecords.Load()}
	}

	// Prove the counters MOVE while running, or "unchanged after Stop" says
	// nothing. This is the non-vacuity guard the fixture's short template
	// interval exists for.
	deadline := time.Now().Add(2 * time.Second)
	for read().packets == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no flow emission observed during the run; the negative assertion below would be vacuous")
		}
		time.Sleep(2 * time.Millisecond)
	}

	if _, err := c.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	before := read()
	time.Sleep(50 * time.Millisecond) // ~10 cadences, generous failsafe
	if after := read(); after != before {
		t.Errorf("exporter kept ticking after Stop returned:\n  before %+v\n  after  %+v", before, after)
	}
}
