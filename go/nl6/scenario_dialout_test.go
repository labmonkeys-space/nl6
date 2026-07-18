/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// scenario_dialout_test.go — gated, counted gNMI dial-out (story 4.3): both
// producers (pushSnapshot / pushChange, via scenarioGate) are gated; no
// updates flow pre-T0; in-window notifications count `sent` when the Publish
// stream is live, else `send_failures`; arm surfaces a down collector.

// setStreamLive forces the exporter's "a stream is up" predicate on/off.
func setStreamLive(e *GnmiDialoutExporter, live bool) {
	if live {
		cc, _ := grpc.NewClient("passthrough:///127.0.0.1:0", grpc.WithTransportCredentials(insecure.NewCredentials()))
		e.conn.Store(cc)
		atomic.StoreInt64(&e.statStreamsActive, 1)
	} else {
		e.conn.Store(nil)
		atomic.StoreInt64(&e.statStreamsActive, 0)
	}
}

// TestScenarioDialout_GateCounting exercises scenarioGate (shared by both
// producers) across the lifecycle: suppressed pre-T0/post-window, sent when
// in-window on a live stream, send_failures when the stream is down.
func TestScenarioDialout_GateCounting(t *testing.T) {
	device := newTestGnmiDevice(t, 2)
	e := newTestDialoutExporter(t, device, "127.0.0.1:0", "sample",
		[]string{"/interfaces/interface[name=*]/state/oper-status"})

	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now}
	e.scenPart.Store(part)
	t0 := time.Unix(1_700_000_000, 0)

	do := func(now time.Time) bool {
		enq, leave := e.scenarioGate(now)
		leave()
		return enq
	}

	// ARMED / pre-T0: suppressed, no update flows.
	setStreamLive(e, true) // stream established silently
	gate.Store(&gateState{phase: phaseArmed})
	if do(t0.Add(-time.Second)) {
		t.Fatal("pre-T0 must not enqueue")
	}
	if led.backgroundSuppressed.Load() != 1 || led.emitted.Load() != 0 {
		t.Fatalf("pre-T0: bg=%d emitted=%d, want 1/0", led.backgroundSuppressed.Load(), led.emitted.Load())
	}

	// RUNNING + live stream: sent.
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour), drainEnd: t0.Add(time.Hour + time.Second)})
	if !do(t0.Add(time.Minute)) {
		t.Fatal("in-window on a live stream must enqueue")
	}
	if led.inWindow.Load() != 1 || led.emitted.Load() != 1 {
		t.Fatalf("in-window: in_window=%d emitted=%d, want 1/1", led.inWindow.Load(), led.emitted.Load())
	}

	// RUNNING + stream down: send_failures (blip visible, never masked).
	setStreamLive(e, false)
	if do(t0.Add(2 * time.Minute)) {
		t.Fatal("a down stream must not enqueue")
	}
	if led.sendFailures.Load() != 1 || led.emitted.Load() != 2 {
		t.Fatalf("blip: send_failures=%d emitted=%d, want 1/2", led.sendFailures.Load(), led.emitted.Load())
	}

	// STOPPED / post-window: suppressed again.
	setStreamLive(e, true)
	gate.Store(&gateState{phase: phaseStopped, t0: t0, t1: t0.Add(time.Hour), drainEnd: t0.Add(time.Hour + time.Second)})
	if do(t0.Add(2 * time.Hour)) {
		t.Fatal("post-window must not enqueue")
	}

	if !led.identityHolds() {
		t.Fatalf("ledger identity violated: %+v", led.snapshot())
	}
	if led.inWindow.Load() != 1 {
		t.Fatalf("sent = %d, want exactly 1 (written to a live stream)", led.inWindow.Load())
	}
}

// TestScenarioDialout_ArmReadinessStreamDown: arming a dial-out scenario when
// the collector is unreachable (no live stream) excludes the device with a
// connect-refusal reason (FR16 stream arming).
func TestScenarioDialout_ArmReadinessStreamDown(t *testing.T) {
	device := newTestGnmiDevice(t, 1)
	device.ID = "device-10.42.0.1"
	device.IP = net.ParseIP("10.42.0.1").To4()
	e := newTestDialoutExporter(t, device, "127.0.0.1:65535", "sample",
		[]string{"/interfaces/interface[name=*]/state/oper-status"})
	device.gnmiDialoutExporter = e // NOT started → no live stream

	sm := &SimulatorManager{
		devices: map[string]*DeviceSimulator{device.ID: device}, deviceIPs: map[string]struct{}{"10.42.0.1": {}},
		deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{"10.42.0.1": device},
	}
	c := newScenarioController(sm, nil)
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "gnmi-dialout", Rate: 1, Window: time.Minute, Seed: 1}
	if err := c.Submit(spec, "s-000001"); err != nil {
		t.Fatal(err)
	}
	armed, excluded, err := c.Arm()
	if err != nil {
		t.Fatal(err)
	}
	if armed != 0 || len(excluded) != 1 {
		t.Fatalf("armed=%d excluded=%d, want 0/1", armed, len(excluded))
	}
	if excluded[0].Reason == "" || excluded[0].RemediationHint == "" {
		t.Fatalf("excluded entry incomplete: %+v", excluded[0])
	}
}

// TestScenarioDialout_SilentArmingEndToEnd: with a live collector, arming
// establishes the Publish stream but NO updates flow until T0; flipping the
// gate to running lets updates flow and be received.
func TestScenarioDialout_SilentArmingEndToEnd(t *testing.T) {
	col, addr, stop := startTestDialoutCollector(t, "127.0.0.1:0")
	defer stop()

	device := newTestGnmiDevice(t, 2)
	e := newTestDialoutExporter(t, device, addr, "sample",
		[]string{"/interfaces/interface[name=*]/state/oper-status"})

	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now}
	gate.Store(&gateState{phase: phaseArmed}) // armed before the exporter starts
	e.scenPart.Store(part)

	e.Start()
	defer e.Close()

	// Let the stream establish and several suppressed sample ticks pass.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !e.streamLive() {
		time.Sleep(50 * time.Millisecond)
	}
	if !e.streamLive() {
		t.Fatal("dial-out stream never established")
	}
	time.Sleep(1500 * time.Millisecond) // ≥1 sample tick, all suppressed
	if got := col.snapshot(); len(got) != 0 {
		t.Fatalf("collector received %d updates pre-T0, want 0 (silent arming)", len(got))
	}

	// Open the window: updates now flow and are received + counted.
	t0 := time.Now()
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour), drainEnd: t0.Add(time.Hour + time.Second)})
	waitForResponses(t, col, 1, 5*time.Second)
	if led.inWindow.Load() == 0 {
		t.Fatal("in-window updates not counted as sent")
	}
}
