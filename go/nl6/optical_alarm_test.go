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

// optical_alarm_test.go — SD/SF threshold detection (#347, tasks 6.2-6.4).

// TestOpticalAlarmThresholdsMatchTheCascade pins the invariant that keeps the
// alarm surface and the counter surface from contradicting each other: SF is
// the SAME threshold that gates fec-uncorrectable-blocks. If these two ever
// drift apart, a channel can be "service-affecting" with a still counter, or
// accrue blocks with no SF raised, and a collector cannot tell which surface
// to believe.
func TestOpticalAlarmThresholdsMatchTheCascade(t *testing.T) {
	if opticalSFThresholdDB() != osnrThresholdDB() {
		t.Errorf("SF threshold %.4f dB != block-counter threshold %.4f dB; the alarm and the counter must agree",
			opticalSFThresholdDB(), osnrThresholdDB())
	}
	// SD must be strictly predictive: it fires while FEC is still coping.
	if opticalSDThresholdDB() <= opticalSFThresholdDB() {
		t.Errorf("SD threshold %.2f dB must sit ABOVE SF %.2f dB (it is the earlier warning)",
			opticalSDThresholdDB(), opticalSFThresholdDB())
	}
}

// TestOpticalAlarmTierMapping: the shipped health bands must land where the
// tier names promise. `degraded` is the interesting one — visibly elevated
// BER that FEC still corrects is exactly what a predictive alarm is for, so
// it must raise SD and NOT SF.
func TestOpticalAlarmTierMapping(t *testing.T) {
	tests := []struct {
		tier   OpticalScenario
		sd, sf bool
	}{
		{OpticalClean, false, false},
		{OpticalTypical, false, false},
		{OpticalDegraded, true, false},
		{OpticalFailing, true, true},
	}
	for _, tc := range tests {
		b := opticalBandFor(tc.tier)
		osnr := b.pInMeanDBm - b.nAseMeanDBm
		if got := osnr < opticalSDThresholdDB(); got != tc.sd {
			t.Errorf("%s (osnr %.2f): SD=%v, want %v", tc.tier, osnr, got, tc.sd)
		}
		if got := osnr < opticalSFThresholdDB(); got != tc.sf {
			t.Errorf("%s (osnr %.2f): SF=%v, want %v", tc.tier, osnr, got, tc.sf)
		}
	}
}

// TestAlarmLatchHysteresisDeadBand is the anti-flap guard at unit level. A
// channel sitting between the raise threshold and threshold+margin must not
// publish anything, in either direction, however long it sits there.
func TestAlarmLatchHysteresisDeadBand(t *testing.T) {
	const thr = 13.0
	base := time.Unix(1_700_000_000, 0)
	var l alarmLatch

	// Well below: raises after the soak.
	if l.evaluate(thr-2, thr, base, time.Minute) {
		t.Fatal("published before the soak elapsed")
	}
	if !l.evaluate(thr-2, thr, base.Add(2*time.Minute), time.Minute) {
		t.Fatal("did not raise after the soak")
	}
	if !l.raised {
		t.Fatal("latch not marked raised")
	}

	// Inside the dead band (above the threshold, below threshold+margin): the
	// raise must HOLD. This is the case that would otherwise flap.
	for i := 0; i < 50; i++ {
		at := base.Add(time.Duration(3+i) * time.Minute)
		if l.evaluate(thr+opticalAlarmHysteresisDB/2, thr, at, time.Minute) {
			t.Fatalf("published a transition from inside the dead band at step %d", i)
		}
		if !l.raised {
			t.Fatalf("alarm dropped inside the dead band at step %d", i)
		}
	}

	// Recovered past the margin: clears after the soak.
	rec := base.Add(time.Hour)
	if l.evaluate(thr+opticalAlarmHysteresisDB+1, thr, rec, time.Minute) {
		t.Fatal("cleared before the soak elapsed")
	}
	if !l.evaluate(thr+opticalAlarmHysteresisDB+1, thr, rec.Add(2*time.Minute), time.Minute) {
		t.Fatal("did not clear after the soak")
	}
	if l.raised {
		t.Fatal("latch still raised after clear")
	}
}

// TestAlarmLatchSoakSwallowsBriefExcursion: a dip that recovers before the
// soak elapses must publish nothing at all. Hysteresis handles a channel
// resting on the line; soak handles one passing through it.
func TestAlarmLatchSoakSwallowsBriefExcursion(t *testing.T) {
	const thr = 13.0
	base := time.Unix(1_700_000_000, 0)
	var l alarmLatch

	if l.evaluate(thr-3, thr, base, time.Minute) {
		t.Fatal("published immediately")
	}
	// Recovered 10s later, well inside the 60s soak.
	if l.evaluate(thr+5, thr, base.Add(10*time.Second), time.Minute) {
		t.Fatal("published on recovery of an unpublished candidate")
	}
	if l.raised {
		t.Fatal("a brief excursion raised an alarm")
	}
	// And the abandoned candidate must not let a LATER dip publish early by
	// reusing the old timestamp.
	if l.evaluate(thr-3, thr, base.Add(time.Hour), time.Minute) {
		t.Fatal("second dip published immediately; the soak clock was not restarted")
	}
}

// TestOpticalAlarmEscalationOrder: crossing both thresholds in one step must
// emit SD before SF, and recovery must clear SF before SD. A collector
// watching the pair should see a coherent escalation, not an arbitrary order.
func TestOpticalAlarmEscalationOrder(t *testing.T) {
	oc := newOpticalCycler(t, 41, opticalBandFor(OpticalClean))
	entry := &opticalAlarmEntry{
		deviceIP: net.IPv4(10, 42, 0, 1), component: "OCH-1-1", oc: oc,
	}
	now := oc.StartTime()

	// Straight past both thresholds, with zero soak so the step is visible.
	degradeAt(oc, "OCH-1-1", 0, 3600, 0, 12)
	evs := entry.evaluateAt(now.Add(time.Second), 0)
	if len(evs) != 2 {
		t.Fatalf("got %d events, want 2 (SD then SF): %+v", len(evs), evs)
	}
	if evs[0].Condition != opticalCondSD || !evs[0].Raised {
		t.Errorf("first event = %v raised=%v, want SD raised", evs[0].Condition, evs[0].Raised)
	}
	if evs[1].Condition != opticalCondSF || !evs[1].Raised {
		t.Errorf("second event = %v raised=%v, want SF raised", evs[1].Condition, evs[1].Raised)
	}

	// Recovery: clear SF first, then SD.
	oc.episodes[oc.slot["OCH-1-1"]].Store(&opticalEpisodeLog{})
	evs = entry.evaluateAt(now.Add(2*time.Second), 0)
	if len(evs) != 2 {
		t.Fatalf("got %d events on recovery, want 2 (SF then SD): %+v", len(evs), evs)
	}
	if evs[0].Condition != opticalCondSF || evs[0].Raised {
		t.Errorf("first clear = %v raised=%v, want SF cleared", evs[0].Condition, evs[0].Raised)
	}
	if evs[1].Condition != opticalCondSD || evs[1].Raised {
		t.Errorf("second clear = %v raised=%v, want SD cleared", evs[1].Condition, evs[1].Raised)
	}
}

// TestOpticalAlarmClearIsItsOwnEvent: a clear must be published as an event
// carrying Raised=false, not signalled by the absence of further raises. A
// collector cannot infer a clear from silence.
func TestOpticalAlarmClearIsItsOwnEvent(t *testing.T) {
	oc := newOpticalCycler(t, 42, opticalBandFor(OpticalClean))
	entry := &opticalAlarmEntry{deviceIP: net.IPv4(10, 42, 0, 1), component: "OCH-1-1", oc: oc}
	now := oc.StartTime()

	// Assert the invariant rather than a fixed count: whatever set of
	// conditions a degradation raises, recovery must publish a clear for
	// exactly that set. Pinning "one SD event" would instead pin the
	// instantaneous OSNR of a particular seed, which the sine dial moves.
	degradeAt(oc, "OCH-1-1", 0, 3600, 0, 6)
	raises := entry.evaluateAt(now.Add(time.Second), 0)
	if len(raises) == 0 {
		t.Fatal("degradation raised nothing")
	}
	raised := map[opticalCondition]bool{}
	for _, e := range raises {
		if !e.Raised {
			t.Errorf("%v published as a clear during degradation", e.Condition)
		}
		raised[e.Condition] = true
	}

	oc.episodes[oc.slot["OCH-1-1"]].Store(&opticalEpisodeLog{})
	clears := entry.evaluateAt(now.Add(2*time.Second), 0)
	if len(clears) != len(raised) {
		t.Fatalf("got %d clear events for %d raised conditions; a clear must be its own event, "+
			"never inferred from silence: %+v", len(clears), len(raised), clears)
	}
	for _, e := range clears {
		if e.Raised {
			t.Errorf("%v clear event has Raised=true", e.Condition)
		}
		if !raised[e.Condition] {
			t.Errorf("cleared %v which was never raised", e.Condition)
		}
		// The OSNR that triggered it must ride along for the description varbind.
		if e.OSNRdB == 0 {
			t.Errorf("%v clear carries no OSNR value", e.Condition)
		}
		delete(raised, e.Condition)
	}
	if len(raised) != 0 {
		t.Errorf("conditions raised but never cleared: %v", raised)
	}
}

// TestOpticalAlarmEvaluatorRunsWithoutPolling is the point of having a
// goroutine at all: a threshold crossing must be noticed with nobody reading
// gNMI or SNMP. Nothing in this test touches a value surface.
func TestOpticalAlarmEvaluatorRunsWithoutPolling(t *testing.T) {
	oc := newOpticalCycler(t, 43, opticalBandFor(OpticalClean))
	degradeAt(oc, "OCH-1-1", 0, 3600, 0, 12) // past both thresholds

	var mu sync.Mutex
	var got []OpticalAlarmEvent
	ev := NewOpticalAlarmEvaluator(OpticalAlarmEvaluatorOptions{
		Interval: 5 * time.Millisecond,
		Soak:     10 * time.Millisecond,
		Notify: func(e OpticalAlarmEvent) {
			mu.Lock()
			got = append(got, e)
			mu.Unlock()
		},
	})
	ev.Register(net.IPv4(10, 42, 0, 1), oc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ev.Run(ctx)
	defer ev.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) < 2 {
		t.Fatalf("evaluator published %d events, want SD and SF raised without any polling", len(got))
	}
	if got[0].Condition != opticalCondSD || got[1].Condition != opticalCondSF {
		t.Errorf("event order = %v, %v; want SD then SF", got[0].Condition, got[1].Condition)
	}
	sd, sf, ok := ev.ActiveAlarms("10.42.0.1", "OCH-1-1")
	if !ok || !sd || !sf {
		t.Errorf("ActiveAlarms = (sd=%v sf=%v ok=%v), want both raised", sd, sf, ok)
	}
}

// TestOpticalAlarmEvaluatorRegisterDeregister: enrolment is idempotent per
// channel (so a re-register cannot replay alarms a collector already saw) and
// deregistration actually removes the channels.
func TestOpticalAlarmEvaluatorRegisterDeregister(t *testing.T) {
	oc := newOpticalCycler(t, 44, opticalBandFor(OpticalClean))
	ev := NewOpticalAlarmEvaluator(OpticalAlarmEvaluatorOptions{})
	ip := net.IPv4(10, 42, 0, 1)

	ev.Register(ip, oc)
	ev.Register(ip, oc) // idempotent
	ev.mu.Lock()
	n := len(ev.byKey)
	heapLen := ev.heap.Len()
	ev.mu.Unlock()
	if n != 2 || heapLen != 2 {
		t.Errorf("after double Register: %d keys / %d heap entries, want 2/2", n, heapLen)
	}

	ev.Deregister(ip)
	ev.mu.Lock()
	n, heapLen = len(ev.byKey), ev.heap.Len()
	ev.mu.Unlock()
	if n != 0 || heapLen != 0 {
		t.Errorf("after Deregister: %d keys / %d heap entries, want 0/0", n, heapLen)
	}
	if _, _, ok := ev.ActiveAlarms("10.42.0.1", "OCH-1-1"); ok {
		t.Error("ActiveAlarms still reports a deregistered channel")
	}
}

// TestOpticalAlarmDegradeEndpointDrivesFullCycle joins this to #334: the REST
// degrade endpoint with a duration must produce raise then clear across the
// window's own expiry, with no explicit revert call.
func TestOpticalAlarmDegradeEndpointDrivesFullCycle(t *testing.T) {
	oc := newOpticalCycler(t, 45, opticalBandFor(OpticalClean))
	entry := &opticalAlarmEntry{deviceIP: net.IPv4(10, 42, 0, 1), component: "OCH-1-1", oc: oc}
	start := oc.StartTime()

	// A bounded episode, exactly what the endpoint publishes.
	degradeAt(oc, "OCH-1-1", 10, 100, 0, 12)

	if evs := entry.evaluateAt(start.Add(50*time.Second), 0); len(evs) != 2 {
		t.Fatalf("mid-window: got %d events, want SD+SF raised", len(evs))
	}
	// After the window closes the channel is back in band by arithmetic alone.
	evs := entry.evaluateAt(start.Add(200*time.Second), 0)
	if len(evs) != 2 {
		t.Fatalf("post-window: got %d events, want SF+SD cleared: %+v", len(evs), evs)
	}
	for _, e := range evs {
		if e.Raised {
			t.Errorf("%v still raised after the degradation window expired", e.Condition)
		}
	}
}
