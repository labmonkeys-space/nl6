/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// nl6#618. THE JOINS AHEAD OF THE BARRIER ARE BOUNDED TOO.
//
// nl6#567 bounded the drain barrier and stopped there, and that turned out to
// close the defect for the uncommon case only. finish() joins the scenario
// scheduler and the trap and flow tickers BEFORE it reaches the barrier, and
// every one of those was a bare channel receive. The syslog and trap schedulers
// fire INLINE, so a stalled scheduler-driven write parked the run loop and
// finish() blocked joining it with the ceiling never armed.
//
// That was found when a controller-driven nl6#567 test hung for five minutes,
// and it is why these tests exist: each parks a write on ONE of the paths that
// sits ahead of the barrier and requires finalize to return anyway.
//
// GIVING UP DOES NOT CANCEL THE GOROUTINE. Nothing can, it is in a write. The
// report says so via incomplete_joins, exactly as drain_stragglers says it for
// the barrier.

// TestFinalizeIsBoundedWhenTheSchedulerStalls is the common case nl6#567 missed:
// an ordinary scheduler-driven fire whose write never returns.
//
// Before nl6#618 this test hangs rather than fails, which is the shape the
// defect had in the first place.
func TestFinalizeIsBoundedWhenTheSchedulerStalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, _ := scenarioTestManager(t, 1)
		dev := sm.devicesByIP["10.42.0.1"]
		dev.syslogConfig = &DeviceSyslogConfig{Collector: "10.0.0.9:514"}

		// Parks the scheduler's OWN fire, which is the whole point: this is the
		// path that blocks c.sched.Stop().
		release := make(chan struct{})
		dev.syslogExporter.writeOverride = func([]byte) error { <-release; return nil }

		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: []string{"10.42.0.1"}, Protocol: "syslog",
			Rate: 1, Window: time.Second, Seed: 1,
		}
		if err := c.Submit(spec, "s-000618"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // the scheduler's fire is admitted and parked in its write

		time.Sleep(spec.Window) // T1: finalize begins and blocks joining the scheduler
		synctest.Wait()

		time.Sleep(finalizeBudget) // the budget expires
		synctest.Wait()

		res := c.Result()
		if res == nil {
			t.Fatal("finalize did not return within the budget with the scheduler parked in a write.\n" +
				"This is the nl6#618 defect: c.sched.Stop() joins a run loop that fires INLINE, so a " +
				"stalled write holds finalize with nl6#567's barrier ceiling never armed")
		}
		if len(res.IncompleteJoins) == 0 {
			t.Error("finalize returned but reported no incomplete join. A give-up that says nothing " +
				"is indistinguishable from a clean finalize, which is the whole reason the field exists")
		}
		if !containsString(res.IncompleteJoins, "syslog-scheduler") {
			t.Errorf("incomplete joins = %v, want the syslog scheduler named. An operator needs to "+
				"know WHICH wait was abandoned, since each leaves a different goroutine running",
				res.IncompleteJoins)
		}

		close(release)
		synctest.Wait()
	})
}

// TestFinalizeIsBoundedWhenAFlowTickStalls covers the other join ahead of the
// barrier, on the path that had no test seam at all until nl6#618 added
// FlowExporter.writeOverride. The flow ticker join runs under c.mu, so before
// this a parked Tick write blocked Phase/Result/LiveCounts as well as finalize.
//
// It builds its own flow exporter rather than reaching for the shared fixture,
// which provides none: an earlier cut skipped when it found none, and a skipping
// test asserts nothing while looking like coverage.
func TestFinalizeIsBoundedWhenAFlowTickStalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// NO real listener, and no reader goroutine: synctest can only advance its
		// clock once every goroutine is durably blocked, and a goroutine parked on
		// a real socket read never is, so a listener here hangs the bubble rather
		// than failing. writeOverride replaces WriteTo, so nothing is ever sent.
		conn := testSender(t)
		defer conn.Close()

		dev := testDevice("10.42.0.1")
		dev.ID = "device-10.42.0.1"
		fe := newTestFlowExporter(dev, zeroGenFlowProfile(), time.Millisecond, time.Millisecond, 10*time.Minute)
		fe.collectorAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2055}
		fe.collectorStr = "127.0.0.1:2055"
		// A non-nil write conn, or Tick returns before it writes anything.
		fe.conn.Store(conn)
		dev.flowExporter = fe

		// Parks the FIRST datagram this exporter writes and lets every later one
		// through, so exactly one Tick is held and the ticker goroutine cannot
		// reach its `defer close(done)`.
		release := make(chan struct{})
		var parked atomic.Bool
		fe.writeOverride = func([]byte) error {
			if parked.CompareAndSwap(false, true) {
				<-release
			}
			return nil
		}

		sm := &SimulatorManager{
			devices: map[string]*DeviceSimulator{dev.ID: dev}, deviceIPs: map[string]struct{}{"10.42.0.1": {}},
			deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{"10.42.0.1": dev},
		}
		// tickFlowExporter takes buffers from the manager's pool; a bare
		// SimulatorManager has none and Tick panics on the nil assertion.
		sm.flowBufPool.New = func() interface{} {
			buf := make([]byte, flowBufSize)
			return &buf
		}

		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: []string{"10.42.0.1"}, Protocol: "netflow9",
			Rate: 1, Window: time.Second, Seed: 1,
		}
		if err := c.Submit(spec, "s-000618b"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		// Something for the tick to export, or it writes nothing and parks nothing.
		injectExpiredFlows(fe, 5, time.Now())
		synctest.Wait()

		time.Sleep(spec.Window) // T1: finalize begins
		synctest.Wait()
		time.Sleep(finalizeBudget)
		synctest.Wait()

		res := c.Result()
		if res == nil {
			t.Fatal("finalize did not return within the budget with a flow Tick write parked.\n" +
				"That join runs under c.mu, so before nl6#618 it blocked Phase/Result/LiveCounts too, " +
				"and nl6#567's barrier ceiling sat behind it unreachable")
		}
		if !parked.Load() {
			t.Fatal("no flow datagram was ever written, so nothing was parked and this test proved " +
				"nothing about the join")
		}

		close(release)
		synctest.Wait()
	})
}

// TestJoinWithinReturnsImmediatelyOnAClosedChannel pins the fast path: a healthy
// finalize must not pay a timer per join. It also pins the nil case, which is
// every scenario that runs no ticker for a protocol it does not use.
func TestJoinWithinReturnsImmediatelyOnAClosedChannel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		close(done)

		start := time.Now()
		if !joinWithin("test", "already finished", done, time.Now().Add(finalizeBudget)) {
			t.Error("joinWithin reported an already-closed channel as incomplete")
		}
		if !joinWithin("test", "never started", nil, time.Now().Add(finalizeBudget)) {
			t.Error("joinWithin reported a nil channel as incomplete; a scenario that runs no ticker " +
				"for a protocol it does not use has nothing to join and must not be flagged")
		}
		if elapsed := time.Since(start); elapsed != 0 {
			t.Errorf("a healthy join cost %s, want 0", elapsed)
		}

		// And a deadline already spent gives up rather than blocking, which is
		// what makes the shared budget a real total: the barrier must not get a
		// fresh ceiling after the joins have spent it.
		blocked := make(chan struct{})
		if joinWithin("test", "stalled", blocked, time.Now().Add(-time.Second)) {
			t.Error("joinWithin waited on a deadline that had already passed. The finalize budget is " +
				"shared, so a wait reached after it is spent must return at once")
		}
	})
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return strings.Contains(strings.Join(hay, ","), needle)
}
