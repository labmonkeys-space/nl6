/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ypFailConn refuses writes while fail is set. It runs onWrite, when set,
// before each write.
type ypFailConn struct {
	net.Conn
	fail    *atomic.Bool
	onWrite *atomic.Pointer[func()]
}

func (c ypFailConn) Write(b []byte) (int, error) {
	if h := c.onWrite.Load(); h != nil {
		(*h)()
	}
	if c.fail.Load() {
		return 0, errors.New("write refused")
	}
	return c.Conn.Write(b)
}

// ypScen is one exporter with a hand-built scenario part, as the controller
// would install it.
type ypScen struct {
	e    *YangPushExporter
	fc   *ypFakeClock
	c    *ypCollector
	st   *InterfaceState
	dev  *DeviceSimulator
	gate *atomic.Pointer[gateState]
	led  *ledgerEntry
	part *scenarioPart
	fail *atomic.Bool
	// onWrite runs on the run goroutine before each socket write.
	onWrite *atomic.Pointer[func()]
}

// newYPScen starts an exporter. With claimed set, the part is installed
// before the run loop starts, so the device has not announced anything.
// Otherwise the device announces its subscriptions first and the caller
// installs s.part itself.
func newYPScen(t *testing.T, claimed bool, phase scenarioPhase) *ypScen {
	t.Helper()
	dev, st := newYangPushTestDevice(t)
	c := newYPCollector(t)
	fc := &ypFakeClock{now: ypTestStart()}
	e, err := NewYangPushExporter(dev, &DeviceYangPushConfig{Collector: c.addr(), SegmentSize: defaultYangPushSegmentSize}, fc.Now)
	if err != nil {
		t.Fatalf("NewYangPushExporter: %v", err)
	}
	e.newTimer = fc.NewTimer
	s := &ypScen{e: e, fc: fc, c: c, st: st, dev: dev, gate: &atomic.Pointer[gateState]{}, led: &ledgerEntry{}, fail: &atomic.Bool{}, onWrite: &atomic.Pointer[func()]{}}
	e.conn = ypFailConn{Conn: e.conn, fail: s.fail, onWrite: s.onWrite}
	s.part = &scenarioPart{gate: s.gate, ledger: s.led, drain: &drainGate{}, now: fc.Now, owner: "scn-test"}
	s.setPhase(phase)
	if claimed {
		e.scenPart.Store(s.part)
	}
	t.Cleanup(func() { _ = e.Close() })
	e.Start()
	if !claimed {
		readStart(t, c)
	}
	waitArmed(t, fc)
	return s
}

// setPhase publishes a gate. A running window spans ten minutes from now.
func (s *ypScen) setPhase(phase scenarioPhase) {
	now := s.fc.Now()
	s.gate.Store(&gateState{phase: phase, t0: now, t1: now.Add(10 * time.Minute)})
}

// tick advances the fake clock and waits until the run loop re-armed.
func (s *ypScen) tick(t *testing.T, d time.Duration) {
	t.Helper()
	s.fc.Advance(d)
	waitArmed(t, s.fc)
}

func (s *ypScen) quiet(t *testing.T) {
	t.Helper()
	if m, ok := s.c.next(t, 50*time.Millisecond); ok {
		t.Fatalf("received %s id %d msg %d, want silence", m.Kind, m.SubID, m.MsgID)
	}
}

func ypLedgerIdentity(t *testing.T, led *ledgerEntry) {
	t.Helper()
	sum := led.inWindow.Load() + led.drain.Load() + led.sendFailures.Load() + led.dropped.Load() + led.suppressedPreWindow.Load()
	if led.emitted.Load() != sum {
		t.Errorf("ledger identity: emitted %d, in_window %d + drain %d + send_failures %d + dropped %d + pre_window %d = %d",
			led.emitted.Load(), led.inWindow.Load(), led.drain.Load(), led.sendFailures.Load(), led.dropped.Load(),
			led.suppressedPreWindow.Load(), sum)
	}
}

// The first sub-8 tick is 50 s after ypTestStart, the sub-9 tick 3 s later.
const ypFirstTick = 50 * time.Second

func TestYangPushScenarioSilentOutsideWindow(t *testing.T) {
	s := newYPScen(t, true, phaseArmed)
	s.tick(t, ypFirstTick)
	s.tick(t, 3*time.Second)
	s.quiet(t)
	if bg, em := s.led.backgroundSuppressed.Load(), s.led.emitted.Load(); bg != 2 || em != 0 {
		t.Errorf("background_suppressed %d emitted %d, want 2 and 0", bg, em)
	}
	if n := s.e.messagesSent.Load(); n != 0 {
		t.Errorf("messages_sent = %d, want 0", n)
	}
	if n := s.e.fidelitySuppressed.Load(); n != 0 {
		t.Errorf("fidelity_suppressed = %d for a claimed device, want 0", n)
	}
}

// A device that never spoke announces its subscriptions at its first activity
// inside the window. The tick suppressed before T0 consumed no message ID.
func TestYangPushScenarioFreshDeviceInWindow(t *testing.T) {
	s := newYPScen(t, true, phaseArmed)
	s.tick(t, ypFirstTick) // suppressed
	s.setPhase(phaseRunning)
	s.tick(t, 3*time.Second)
	want := []struct {
		kind string
		sub  uint32
	}{
		{"ietf-subscribed-notifications:subscription-started", 8},
		{"ietf-subscribed-notifications:subscription-started", 9},
		{"ietf-subscribed-notifications:subscription-started", 10},
		{"ietf-yang-push:push-update", 10},
		{"ietf-yang-push:push-update", 9},
	}
	for i, w := range want {
		m := s.c.mustNext(t)
		if m.Kind != w.kind || m.SubID != w.sub || m.MsgID != uint32(i+1) || m.Seq != uint64(i+1) {
			t.Fatalf("message %d = %s id %d msg %d seq %d, want %s id %d msg %d", i, m.Kind, m.SubID, m.MsgID, m.Seq, w.kind, w.sub, i+1)
		}
	}
	if em, in := s.led.emitted.Load(), s.led.inWindow.Load(); em != 5 || in != 5 {
		t.Errorf("emitted %d in_window %d, want 5 and 5", em, in)
	}
	ypLedgerIdentity(t, s.led)
}

// A device claimed after it announced its subscriptions does not announce
// them again, and streams as before once it is released.
func TestYangPushScenarioClaimedAfterAnnounce(t *testing.T) {
	s := newYPScen(t, false, phaseRunning)
	s.e.scenPart.Store(s.part)
	s.tick(t, ypFirstTick)
	if m := s.c.mustNext(t); m.Kind != "ietf-yang-push:push-update" || m.SubID != 8 || m.MsgID != 5 {
		t.Fatalf("got %s id %d msg %d, want push-update 8 msg 5", m.Kind, m.SubID, m.MsgID)
	}
	s.e.scenPart.Store(nil)
	s.tick(t, 3*time.Second)
	if m := s.c.mustNext(t); m.Kind != "ietf-yang-push:push-update" || m.SubID != 9 || m.MsgID != 6 {
		t.Fatalf("after release got %s id %d msg %d, want push-update 9 msg 6", m.Kind, m.SubID, m.MsgID)
	}
	if em := s.led.emitted.Load(); em != 1 {
		t.Errorf("emitted = %d after release, want 1", em)
	}
}

func TestYangPushScenarioAfterT1(t *testing.T) {
	s := newYPScen(t, false, phaseRunning)
	now := s.fc.Now()
	s.gate.Store(&gateState{phase: phaseRunning, t0: now.Add(-2 * time.Minute), t1: now.Add(-time.Minute)})
	s.e.scenPart.Store(s.part)
	s.tick(t, ypFirstTick)
	s.quiet(t)
	if bg, em := s.led.backgroundSuppressed.Load(), s.led.emitted.Load(); bg != 1 || em != 0 {
		t.Errorf("background_suppressed %d emitted %d, want 1 and 0", bg, em)
	}
}

// A message admitted before T1 whose write returns after T1 is drain.
func TestYangPushScenarioDrainBucket(t *testing.T) {
	s := newYPScen(t, false, phaseRunning)
	s.part.now = func() time.Time { return s.fc.Now().Add(time.Hour) }
	s.e.scenPart.Store(s.part)
	s.tick(t, ypFirstTick)
	s.c.mustNext(t)
	if dr, in := s.led.drain.Load(), s.led.inWindow.Load(); dr != 1 || in != 0 {
		t.Errorf("drain %d in_window %d, want 1 and 0", dr, in)
	}
	ypLedgerIdentity(t, s.led)
}

func TestYangPushScenarioSendFailure(t *testing.T) {
	s := newYPScen(t, false, phaseRunning)
	s.e.scenPart.Store(s.part)
	s.fail.Store(true)
	s.tick(t, ypFirstTick)
	s.quiet(t)
	if em, sf, in := s.led.emitted.Load(), s.led.sendFailures.Load(), s.led.inWindow.Load(); em != 1 || sf != 1 || in != 0 {
		t.Errorf("emitted %d send_failures %d in_window %d, want 1, 1 and 0", em, sf, in)
	}
	if n := s.e.sendFailures.Load(); n != 1 {
		t.Errorf("exporter send_failures = %d, want 1", n)
	}
	// The failed message consumed its ID, as outside a scenario.
	s.fail.Store(false)
	s.tick(t, 3*time.Second)
	if m := s.c.mustNext(t); m.MsgID != 6 {
		t.Errorf("message id after a failure = %d, want 6", m.MsgID)
	}
}

func TestYangPushScenarioDrainClosed(t *testing.T) {
	s := newYPScen(t, false, phaseRunning)
	s.e.scenPart.Store(s.part)
	s.part.drain.closeAndWait("test")
	s.tick(t, ypFirstTick)
	s.quiet(t)
	if em, dr := s.led.emitted.Load(), s.led.dropped.Load(); em != 1 || dr != 1 {
		t.Errorf("emitted %d dropped %d, want 1 and 1", em, dr)
	}
	if n := s.e.messagesSent.Load(); n != 4 {
		t.Errorf("messages_sent = %d, want the 4 start messages only", n)
	}
	ypLedgerIdentity(t, s.led)
}

// A device whose announcement is refused by a closed drain barrier announces
// at its next activity instead of never.
func TestYangPushScenarioAnnounceRefusedIsRetried(t *testing.T) {
	s := newYPScen(t, true, phaseArmed)
	s.part.drain.closeAndWait("test")
	s.setPhase(phaseRunning)
	s.tick(t, ypFirstTick)
	s.quiet(t)
	if em, dr := s.led.emitted.Load(), s.led.dropped.Load(); em != 2 || dr != 2 {
		t.Errorf("emitted %d dropped %d, want 2 and 2: one refused announcement, one refused push-update", em, dr)
	}
	s.e.scenPart.Store(nil)
	s.tick(t, 3*time.Second)
	if m := s.c.mustNext(t); m.Kind != "ietf-subscribed-notifications:subscription-started" || m.MsgID != 1 {
		t.Fatalf("after release got %s msg %d, want subscription-started msg 1", m.Kind, m.MsgID)
	}
	ypLedgerIdentity(t, s.led)
}

// A device whose announcement is cut short announces all of it again at its
// next chance. Here the scenario ends while the first subscription-started is
// on the wire, so the other three messages are refused.
func TestYangPushScenarioPartialAnnounceIsRepeated(t *testing.T) {
	s := newYPScen(t, true, phaseArmed)
	s.setPhase(phaseRunning)
	var once sync.Once
	end := func() { once.Do(func() { s.setPhase(phaseStopped) }) }
	s.onWrite.Store(&end)
	s.tick(t, ypFirstTick)
	if m := s.c.mustNext(t); m.Kind != "ietf-subscribed-notifications:subscription-started" || m.SubID != 8 || m.MsgID != 1 {
		t.Fatalf("got %s id %d msg %d, want subscription-started 8 msg 1", m.Kind, m.SubID, m.MsgID)
	}
	s.quiet(t)
	if em, in := s.led.emitted.Load(), s.led.inWindow.Load(); em != 1 || in != 1 {
		t.Errorf("emitted %d in_window %d, want 1 and 1", em, in)
	}
	ypLedgerIdentity(t, s.led)

	s.e.scenPart.Store(nil)
	s.tick(t, 3*time.Second)
	want := []struct {
		kind string
		sub  uint32
	}{
		{"ietf-subscribed-notifications:subscription-started", 8},
		{"ietf-subscribed-notifications:subscription-started", 9},
		{"ietf-subscribed-notifications:subscription-started", 10},
		{"ietf-yang-push:push-update", 10},
		{"ietf-yang-push:push-update", 9},
	}
	for i, w := range want {
		m := s.c.mustNext(t)
		if m.Kind != w.kind || m.SubID != w.sub || m.MsgID != uint32(i+2) {
			t.Fatalf("after release message %d = %s id %d msg %d, want %s id %d msg %d", i, m.Kind, m.SubID, m.MsgID, w.kind, w.sub, i+2)
		}
	}
}

// A state change before T0 is dropped. It must not go out inside the window
// with an old state.
func TestYangPushScenarioChangeBeforeT0Dropped(t *testing.T) {
	s := newYPScen(t, true, phaseArmed)
	idx := s.dev.metricsCycler.ifCounters.Load().IfIndices()[0]
	ypSetLink(s.st, idx, OperDown)
	deadline := time.Now().Add(3 * time.Second)
	for s.led.backgroundSuppressed.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the state change was not suppressed")
		}
		time.Sleep(time.Millisecond)
	}
	s.setPhase(phaseRunning)
	s.tick(t, ypDampening)
	s.quiet(t)
	if em := s.led.emitted.Load(); em != 0 {
		t.Errorf("emitted = %d, want 0", em)
	}
}

func TestYangPushScenarioChangeInWindow(t *testing.T) {
	s := newYPScen(t, false, phaseRunning)
	s.e.scenPart.Store(s.part)
	var up int
	for _, idx := range s.dev.metricsCycler.ifCounters.Load().IfIndices() {
		if s.st.OperStatus(idx) == OperUp {
			up = idx
			break
		}
	}
	if up == 0 {
		t.Fatal("no interface is up")
	}
	ypSetLink(s.st, up, OperDown)
	if m := s.c.mustNext(t); m.Kind != "ietf-yang-push:push-change-update" || m.SubID != 10 || m.MsgID != 5 {
		t.Fatalf("got %s id %d msg %d, want push-change-update 10 msg 5", m.Kind, m.SubID, m.MsgID)
	}
	waitArmedN(t, s.fc, 3)
	if em, in := s.led.emitted.Load(), s.led.inWindow.Load(); em != 1 || in != 1 {
		t.Errorf("emitted %d in_window %d, want 1 and 1", em, in)
	}
}

func TestYangPushScenarioLedgerIdentity(t *testing.T) {
	s := newYPScen(t, true, phaseRunning)
	s.tick(t, ypFirstTick)
	for range 5 {
		s.c.mustNext(t)
	}
	s.fail.Store(true)
	s.tick(t, 3*time.Second)
	if em, in, sf := s.led.emitted.Load(), s.led.inWindow.Load(), s.led.sendFailures.Load(); em != 6 || in != 5 || sf != 1 {
		t.Errorf("emitted %d in_window %d send_failures %d, want 6, 5 and 1", em, in, sf)
	}
	ypLedgerIdentity(t, s.led)
}

// A state change that arrives before T0 while a dampening period is open is
// dropped at collection. The period was opened by a change sent before the
// device was claimed.
func TestYangPushScenarioChangeBeforeT0DroppedWhileDampening(t *testing.T) {
	s := newYPScen(t, false, phaseArmed)
	var up []int
	for _, idx := range s.dev.metricsCycler.ifCounters.Load().IfIndices() {
		if s.st.OperStatus(idx) == OperUp && len(up) < 2 {
			up = append(up, idx)
		}
	}
	if len(up) < 2 {
		t.Fatal("fewer than two interfaces are up")
	}
	ypSetLink(s.st, up[0], OperDown)
	if m := s.c.mustNext(t); m.Kind != "ietf-yang-push:push-change-update" || m.MsgID != 5 {
		t.Fatalf("got %s msg %d, want push-change-update msg 5", m.Kind, m.MsgID)
	}
	waitArmedN(t, s.fc, 3) // the dampening period is open

	s.e.scenPart.Store(s.part)
	ypSetLink(s.st, up[1], OperDown)
	deadline := time.Now().Add(3 * time.Second)
	for s.led.backgroundSuppressed.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the state change before T0 was not dropped at collection")
		}
		time.Sleep(time.Millisecond)
	}
	s.setPhase(phaseRunning)
	s.fc.Advance(ypDampening)
	waitArmed(t, s.fc)
	s.quiet(t)
	if em, bg := s.led.emitted.Load(), s.led.backgroundSuppressed.Load(); em != 0 || bg != 1 {
		t.Errorf("emitted %d background_suppressed %d, want 0 and 1", em, bg)
	}
}

// The report states T1 in milliseconds and the envelope event-time has
// milliseconds too. A message in the last partial millisecond before T1 would
// carry an event-time equal to the reported T1, and a receiver selecting
// [T0,T1) would not count it. The gate therefore closes at the millisecond.
func TestYangPushScenarioLastPartialMillisecondIsOutside(t *testing.T) {
	s := newYPScen(t, false, phaseRunning)
	base := s.fc.Now().Truncate(time.Millisecond)
	s.gate.Store(&gateState{phase: phaseRunning, t0: base.Add(-time.Minute), t1: base.Add(500 * time.Microsecond)})
	s.e.scenPart.Store(s.part)
	if s.e.speaks(base.Add(100 * time.Microsecond)) {
		t.Error("speaks in the last partial millisecond before T1")
	}
	if ok, _ := s.e.gate(base.Add(100 * time.Microsecond)); ok {
		t.Error("gate let a message out whose event-time equals the reported T1")
	}
	if s.e.gateEvent(base.Add(100 * time.Microsecond)) {
		t.Error("gateEvent collected a change in the last partial millisecond before T1")
	}
	if ok, done := s.e.gate(base.Add(-time.Microsecond)); !ok {
		t.Error("gate refused a message one millisecond before the reported T1")
	} else {
		done(true)
	}
	if em, bg := s.led.emitted.Load(), s.led.backgroundSuppressed.Load(); em != 1 || bg != 2 {
		t.Errorf("emitted %d background_suppressed %d, want 1 and 2", em, bg)
	}
}

// The gate has a lower bound too. A caller that read the clock before Start
// published the window must not send with an event-time before the reported
// T0. The bound is the millisecond the report prints for T0.
func TestYangPushScenarioBeforeT0MillisecondIsOutside(t *testing.T) {
	s := newYPScen(t, false, phaseRunning)
	base := s.fc.Now().Truncate(time.Millisecond)
	s.gate.Store(&gateState{phase: phaseRunning, t0: base.Add(500 * time.Microsecond), t1: base.Add(time.Minute)})
	s.e.scenPart.Store(s.part)
	if s.e.speaks(base.Add(-time.Microsecond)) {
		t.Error("speaks in the millisecond before the reported T0")
	}
	if ok, _ := s.e.gate(base.Add(-time.Microsecond)); ok {
		t.Error("gate let a message out whose event-time is before the reported T0")
	}
	if ok, done := s.e.gate(base.Add(100 * time.Microsecond)); !ok {
		t.Error("gate refused a message whose event-time equals the reported T0")
	} else {
		done(true)
	}
	if em, bg := s.led.emitted.Load(), s.led.backgroundSuppressed.Load(); em != 1 || bg != 1 {
		t.Errorf("emitted %d background_suppressed %d, want 1 and 1", em, bg)
	}
}
