/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// nl6#567. THE DRAIN BARRIER HAS A CEILING.
//
// closeAndWait was a bare wg.Wait() with nothing capping it, and
// abortActiveScenario calls it on the graceful-shutdown path, so one admitted
// fire that never returned held FINALIZE open forever. Two reachable causes: a
// stream transport whose write sets no deadline, and an admitted fire that never
// calls leave() at all (a panic on a write path, a dropped callback). No
// per-transport write deadline could ever fix that second case, which is why the
// BARRIER is what got bounded rather than the transports.
//
// The stragglers are NOT cancelled. Nothing here can interrupt a write parked in
// the kernel. So the barrier stops waiting, counts what was still outstanding,
// and the report says so; see drain_stragglers.
//
// TestScenarioDrain_BarrierWaitsForInflight (scenario_drain_test.go) is the
// other half of this contract and must keep passing: BELOW the ceiling the
// barrier still outlasts every in-flight fire. A change that made the barrier
// return early would satisfy every test here and break that one.
//
// WHAT THE CEILING DOES NOT REACH. finish() joins the scheduler and the
// trap/flow tickers BEFORE the barrier, and all three joins are unbounded, so a
// stalled SCHEDULER-DRIVEN write parks finalize ahead of the ceiling and the
// ceiling is never armed. What it reaches is a fire admitted outside the
// scheduler: REST on-demand and state-driven link notifications. Do not read
// these tests as saying shutdown is bounded in general.

// TestScenarioDrain_CeilingBoundsAStalledWrite is the defect nl6#567 names: a
// transport write that never returns must not outlast the BARRIER.
//
// Driven through the real exporter fire path (newSinkExporter with a blocking
// write), not by calling admit() directly, so the ceiling is proven against the
// same route a scenario participant actually takes.
func TestScenarioDrain_CeilingBoundsAStalledWrite(t *testing.T) {
	// The log lines are emitted from closeAndWait's goroutine inside the bubble,
	// so the capture wraps the whole bubble and is asserted after it completes.
	out := captureLog(t, func() {
		synctest.Test(t, func(t *testing.T) {
			entry := mustEntry(t)
			t0 := time.Now()
			t1 := t0.Add(time.Second)
			gate := &atomic.Pointer[gateState]{}
			gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1})
			led := &ledgerEntry{}
			d := &drainGate{}

			// Released only at the very end. Until then this write is parked
			// exactly as a stalled transport would be.
			blockWrite := make(chan struct{})
			exp := newSinkExporter(t, net.IPv4(10, 42, 0, 1), func(_ []byte) error { <-blockWrite; return nil })
			exp.scenPart.Store(&scenarioPart{gate: gate, ledger: led, drain: d, now: time.Now})

			go func() { _ = exp.fireScenario(entry, nil) }()
			synctest.Wait() // fire admitted into the barrier, blocked in its write

			if got := d.inflight.Load(); got != 1 {
				t.Fatalf("inflight = %d after one admitted fire, want 1; the straggler count cannot be "+
					"right if the counter does not track admission", got)
			}

			started := time.Now()
			var stragglers int64
			returned := make(chan struct{})
			go func() { stragglers = d.closeAndWait("test"); close(returned) }()

			synctest.Wait()
			select {
			case <-returned:
				t.Fatal("closeAndWait returned while a fire was still in flight and the ceiling had not " +
					"expired. Below the ceiling the barrier must still outlast every admitted fire, or " +
					"the ledger is read while it is still moving")
			default:
			}

			// The bubble is idle, so the fake clock runs to the next timer: the
			// watchdog tick, then the ceiling.
			<-returned

			if elapsed := time.Since(started); elapsed != drainBarrierTimeout {
				t.Errorf("barrier returned after %s, want exactly %s. Under synctest the clock only "+
					"advances to a timer, so an inexact value means it returned on something other than "+
					"the ceiling", elapsed, drainBarrierTimeout)
			}
			if stragglers != 1 {
				t.Errorf("closeAndWait reported %d stragglers, want 1. The count is what tells a report "+
					"reader the snapshot was taken over a set that was still moving", stragglers)
			}

			// The straggler must NOT have been laundered into a loss bucket. Its
			// outcome is unknown: this write may yet succeed.
			if got := led.dropped.Load(); got != 0 {
				t.Errorf("dropped = %d, want 0. A straggler is not a dropped fire. It was admitted, it "+
					"is still running, and it may still reach the collector. Folding it into `dropped` "+
					"asserts an outcome nothing observed", got)
			}

			// Release the write. Its leave() lands long after the barrier gave up,
			// which is the ordinary end state for a straggler and must be harmless.
			close(blockWrite)
			synctest.Wait()
			if got := d.inflight.Load(); got != 0 {
				t.Errorf("inflight = %d after the straggler completed, want 0; a late leave() must still "+
					"balance its admit()", got)
			}
		})
	})

	if !strings.Contains(out, "gave up") {
		t.Errorf("the give-up was not logged. An operator whose shutdown was truncated has no other "+
			"signal at the moment it happens.\nlog:\n%s", out)
	}
	if !strings.Contains(out, "still waiting") {
		t.Errorf("the watchdog line did not precede the give-up. The ceiling sits above the watchdog "+
			"cadence so the log reads as an escalation rather than a surprise.\nlog:\n%s", out)
	}
}

// TestScenarioDrain_CeilingBoundsAFireThatNeverLeaves covers the half of nl6#567
// that no per-transport write deadline could reach: an admitted fire whose
// leave() is never called at all, because the write path panicked or a callback
// was dropped. There is nothing to time out except the barrier itself.
func TestScenarioDrain_CeilingBoundsAFireThatNeverLeaves(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &drainGate{}
		if !d.admit() {
			t.Fatal("admit must succeed on a fresh gate")
		}
		// Deliberately no leave() before the barrier: that IS the scenario.

		started := time.Now()
		stragglers := d.closeAndWait("test")

		if elapsed := time.Since(started); elapsed != drainBarrierTimeout {
			t.Errorf("barrier returned after %s, want exactly %s", elapsed, drainBarrierTimeout)
		}
		if stragglers != 1 {
			t.Errorf("closeAndWait reported %d stragglers, want 1", stragglers)
		}

		// The abandoned wg.Wait() goroutine is still parked. Release it, or the
		// synctest bubble cannot finish. That is also the honest statement of the
		// production cost: a truncated finalize leaves one goroutine waiting until
		// its last straggler returns, or forever if one never does.
		d.leave()
	})
}

// TestScenarioDrain_HealthyDrainReportsNoStragglers pins the other side. The
// ceiling must be invisible on every run that drains normally: same timing, no
// straggler count, nothing for a report reader to interpret.
//
// Without this, a barrier that simply returned immediately would satisfy both
// tests above.
func TestScenarioDrain_HealthyDrainReportsNoStragglers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entry := mustEntry(t)
		t0 := time.Now()
		t1 := t0.Add(time.Second)
		gate := &atomic.Pointer[gateState]{}
		gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1})
		led := &ledgerEntry{}
		d := &drainGate{}

		exp := newSinkExporter(t, net.IPv4(10, 42, 0, 2), func(_ []byte) error { return nil })
		exp.scenPart.Store(&scenarioPart{gate: gate, ledger: led, drain: d, now: time.Now})

		go func() { _ = exp.fireScenario(entry, nil) }()
		synctest.Wait() // the fire completes; nothing is in flight

		started := time.Now()
		stragglers := d.closeAndWait("test")

		if elapsed := time.Since(started); elapsed != 0 {
			t.Errorf("a healthy barrier took %s, want 0. The ceiling must cost a normal run nothing", elapsed)
		}
		if stragglers != 0 {
			t.Errorf("a healthy drain reported %d stragglers, want 0", stragglers)
		}
		if !led.identityHolds() {
			t.Errorf("identity violated on a clean drain: %+v", led.snapshot())
		}
	})
}

// TestScenarioReport_DrainStragglersIsItsOwnFieldAndOmittedWhenZero pins the
// wire shape. Two properties, and both are decisions rather than accidents: the
// count is its OWN field (never a participant's `dropped`, whose meaning is an
// observed outcome), and it is ABSENT on a healthy run, so every report produced
// before this ceiling existed still round-trips unchanged.
func TestScenarioReport_DrainStragglersIsItsOwnFieldAndOmittedWhenZero(t *testing.T) {
	encode := func(n int64) map[string]any {
		t.Helper()
		raw, err := json.Marshal(reportMetadata{DrainEnd: "2026-09-02T00:00:00.000Z", DrainStragglers: n})
		if err != nil {
			t.Fatalf("marshal reportMetadata: %v", err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return got
	}

	if _, present := encode(0)["drain_stragglers"]; present {
		t.Error("drain_stragglers is serialized on a healthy run. It must be omitempty, or every " +
			"clean report changes shape for a field that has nothing to say")
	}
	got := encode(3)
	if v, present := got["drain_stragglers"]; !present || v != float64(3) {
		t.Errorf("drain_stragglers = %v (present=%v), want 3", v, present)
	}
	if _, present := got["dropped"]; present {
		t.Error("metadata carries a `dropped` key. The straggler count must never be folded into a " +
			"loss bucket: its outcome is unknown and it may still have reached the collector")
	}
}

// TestScenarioReportCarriesTheStragglerCount pins the plumbing between the two
// halves above, through the PRODUCTION projection rather than by restating the
// assignment. The count has to survive ScenarioResult -> buildScenarioReport ->
// metadata; a test that merely copied the field between two structs could not
// fail, which is the shape this repo treats as coverage that guards nothing.
func TestScenarioReportCarriesTheStragglerCount(t *testing.T) {
	sm := &SimulatorManager{}
	c := newScenarioController(sm, func() time.Time { return time.Unix(1_700_000_000, 0) })
	c.spec = &Scenario{Protocol: "syslog", Window: time.Minute}
	c.result = &ScenarioResult{
		ID:              "scn-straggler",
		Phase:           phaseAborted,
		DrainStragglers: 7,
		PerDevice:       map[string]ledgerSnapshot{},
	}

	rep := buildScenarioReport(sm, c)
	if rep == nil {
		t.Fatal("buildScenarioReport returned nil for a finalized result")
	}
	if got := rep.Summary.Metadata.DrainStragglers; got != 7 {
		t.Errorf("report metadata drain_stragglers = %d, want 7. The count is produced by "+
			"closeAndWait and consumed by a report reader; if the projection drops it, a truncated "+
			"finalize is indistinguishable from a clean one", got)
	}
}

// TestScenarioFinishCarriesTheStragglerCount drives the REAL controller through
// finish(), which is the one hop nothing else covers and the one most likely to
// be dropped.
//
// The nl6#567 review demonstrated the gap rather than asserting it: replacing
// `stragglers := c.drain.closeAndWait(c.id)` with `_ = c.drain.closeAndWait(...)`
// and hard-coding `DrainStragglers: 0` left the ENTIRE package green. The
// drainGate tests read closeAndWait's return directly, and the projection test
// writes the field by hand, so both flank this hop without crossing it.
//
// THE STRAGGLER IS AN OUT-OF-BAND FIRE, AND THAT IS NOT AN ARBITRARY CHOICE.
// finish() joins the scheduler and the trap/flow tickers BEFORE the barrier, and
// the syslog scheduler fires INLINE, so a stalled scheduler-driven write parks
// the scheduler goroutine and c.sched.Stop() blocks joining it: the ceiling is
// never armed. Written with a scheduler-driven straggler this test hangs, which
// is how that was found. What the ceiling actually reaches is a fire admitted
// outside the scheduler (REST on-demand, state-driven link notifications), and
// that is what this exercises. See nl6#567 follow-up.
func TestScenarioFinishCarriesTheStragglerCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, _ := scenarioTestManager(t, 1)
		dev := sm.devicesByIP["10.42.0.1"]
		dev.syslogConfig = &DeviceSyslogConfig{Collector: "10.0.0.9:514"}

		// Blocks only once armed, so the scheduler's own fires complete and
		// c.sched.Stop() can join. Only the out-of-band fire below is parked.
		var blocking atomic.Bool
		release := make(chan struct{})
		var once sync.Once
		dev.syslogExporter.writeOverride = func([]byte) error {
			if blocking.Load() {
				once.Do(func() { <-release })
			}
			return nil
		}

		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: []string{"10.42.0.1"}, Protocol: "syslog",
			Rate: 1, Window: time.Second, Seed: 1,
		}
		if err := c.Submit(spec, "s-000567"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()

		// An out-of-band fire, admitted to the controller's real drain gate but
		// owned by no scheduler, parked from here on.
		blocking.Store(true)
		go func() { _ = dev.syslogExporter.fireScenario(mustEntry(t), nil) }()
		synctest.Wait()

		time.Sleep(spec.Window) // T1: finalize begins
		synctest.Wait()

		time.Sleep(drainBarrierTimeout) // the ceiling expires and finalize gives up
		synctest.Wait()

		res := c.Result()
		if res == nil {
			t.Fatal("no result after the ceiling expired: finalize did not return, so the ceiling did " +
				"not bound the barrier on the real controller path")
		}
		if res.DrainStragglers != 1 {
			t.Errorf("ScenarioResult.DrainStragglers = %d, want 1.\nfinish() is the ONLY production "+
				"site that turns closeAndWait's return into report data. Discarding it leaves every "+
				"other test in this file green while a truncated finalize reports as clean",
				res.DrainStragglers)
		}

		// And end to end, because the field only matters if a report reader sees it.
		rep := buildScenarioReport(sm, c)
		if rep == nil {
			t.Fatal("buildScenarioReport returned nil for a finalized result")
		}
		raw, err := json.Marshal(rep.Summary.Metadata)
		if err != nil {
			t.Fatalf("marshal metadata: %v", err)
		}
		if !strings.Contains(string(raw), `"drain_stragglers":1`) {
			t.Errorf("the report of a truncated run does not carry drain_stragglers:1.\ngot: %s", raw)
		}

		close(release) // let the straggler finish so the bubble can end
		synctest.Wait()
	})
}

// TestScenarioDrain_BelowTheCeilingReportsNoStragglers covers the whole interval
// the two ceiling tests skip. They park a write forever and the barrier test
// releases immediately, so nothing exercised a write that takes a long time and
// still returns in good order.
func TestScenarioDrain_BelowTheCeilingReportsNoStragglers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, _ := scenarioTestManager(t, 1)
		dev := sm.devicesByIP["10.42.0.1"]
		dev.syslogConfig = &DeviceSyslogConfig{Collector: "10.0.0.9:514"}

		release := make(chan struct{})
		var once sync.Once
		dev.syslogExporter.writeOverride = func([]byte) error {
			once.Do(func() { <-release })
			return nil
		}

		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: []string{"10.42.0.1"}, Protocol: "syslog",
			Rate: 1, Window: time.Second, Seed: 1,
		}
		if err := c.Submit(spec, "s-000567b"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()

		time.Sleep(spec.Window)
		synctest.Wait()

		// A write that is slow but returns with a second to spare must finalize
		// exactly as a fast one does.
		time.Sleep(drainBarrierTimeout - time.Second)
		close(release)
		synctest.Wait()

		res := c.Result()
		if res == nil {
			t.Fatal("no result after the write returned below the ceiling")
		}
		if res.DrainStragglers != 0 {
			t.Errorf("DrainStragglers = %d, want 0. A write that returns before the ceiling is not a "+
				"straggler however long it took, or the field reports slowness rather than truncation",
				res.DrainStragglers)
		}
	})
}

// TestDrainBarrierCeilingClearsItsInputs pins the relationships the ceiling's own
// comment reasons about. An earlier cut DERIVED the ceiling from the watchdog
// cadence, which coupled them in the wrong direction: lowering the watchdog to
// see the log sooner silently shortened the ceiling, and at a 5s watchdog it
// would have fallen to 10s, below the write timeout it has to clear. The
// constants are independent now, so the relationship needs an assertion.
func TestDrainBarrierCeilingClearsItsInputs(t *testing.T) {
	if drainBarrierTimeout <= drainWatchdogInterval {
		t.Errorf("drainBarrierTimeout (%s) must exceed drainWatchdogInterval (%s), or the barrier "+
			"gives up before it has said once that it is waiting", drainBarrierTimeout, drainWatchdogInterval)
	}
	if drainBarrierTimeout <= syslogTCPWriteTimeout {
		t.Errorf("drainBarrierTimeout (%s) must exceed syslogTCPWriteTimeout (%s), the longest "+
			"legitimate single write in the tree, or a healthy syslog TCP write is reported as a "+
			"straggler", drainBarrierTimeout, syslogTCPWriteTimeout)
	}
	// The documented figure: how many queued syslog TCP writes the ceiling covers
	// on one device, since tcpTransport.Send serialises them behind writeMu.
	if got := drainBarrierTimeout / syslogTCPWriteTimeout; got != 30 {
		t.Errorf("the ceiling covers %d queued syslog TCP writes; the comment on drainBarrierTimeout "+
			"says roughly 30. Move the comment or the constant, but do not leave them disagreeing", got)
	}
}

// TestIdentityHoldsIsAssertedOnlyInTests pins the claim the whole straggler
// design rests on.
//
// closeAndWait's comment, CLAUDE.md and the schema doc all argue that a
// truncated finalize is SAFE because production never checks the ledger
// identity: a straggler can leave a participant's buckets not adding up, and
// nothing fails. That is true today, and nothing kept it true. A future
// production caller of identityHolds would turn every truncated finalize into a
// live failure, which is exactly the kind of prose-only claim this repo pins
// with a scan rather than trusting.
func TestIdentityHoldsIsAssertedOnlyInTests(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var offenders []string
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			// The declaration itself is not a call site.
			if strings.Contains(line, "identityHolds(") && !strings.Contains(line, "func (l *ledgerEntry)") {
				offenders = append(offenders, fmt.Sprintf("%s:%d: %s", name, i+1, strings.TrimSpace(line)))
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no production files, so this guard proves nothing")
	}
	if len(offenders) != 0 {
		t.Errorf("identityHolds is called from production code:\n  %s\n\nThe nl6#567 straggler design "+
			"argues a truncated finalize cannot fail a live simulator BECAUSE only tests assert the "+
			"identity. A production caller makes every give-up a runtime failure and invalidates that "+
			"reasoning in closeAndWait's comment, CLAUDE.md and the report schema doc",
			strings.Join(offenders, "\n  "))
	}
	t.Logf("scanned %d production files; identityHolds has no production call site", scanned)
}

// TestScenarioDrain_StragglerMovesCountersAfterTheSnapshot demonstrates the
// hazard every doc paragraph rests on, rather than only asserting it in prose:
// a straggler released after the give-up still moves the ledger, so a snapshot
// taken at the give-up is a lower bound over a set that was still moving.
func TestScenarioDrain_StragglerMovesCountersAfterTheSnapshot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entry := mustEntry(t)
		t0 := time.Now()
		t1 := t0.Add(time.Second)
		gate := &atomic.Pointer[gateState]{}
		gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1})
		led := &ledgerEntry{}
		d := &drainGate{}

		blockWrite := make(chan struct{})
		exp := newSinkExporter(t, net.IPv4(10, 42, 0, 3), func(_ []byte) error { <-blockWrite; return nil })
		exp.scenPart.Store(&scenarioPart{gate: gate, ledger: led, drain: d, now: time.Now})

		go func() { _ = exp.fireScenario(entry, nil) }()
		synctest.Wait()

		var stragglers int64
		returned := make(chan struct{})
		go func() { stragglers = d.closeAndWait("test"); close(returned) }()
		<-returned
		if stragglers != 1 {
			t.Fatalf("stragglers = %d, want 1", stragglers)
		}

		// The snapshot a report would be built from, taken at the give-up.
		atGiveUp := led.snapshot()
		if atGiveUp.Emitted == 0 {
			t.Fatal("the straggler was not counted as emitted at the give-up, so this test cannot " +
				"demonstrate the drift it exists to demonstrate")
		}

		close(blockWrite) // the straggler completes AFTER the snapshot
		synctest.Wait()

		after := led.snapshot()
		if after == atGiveUp {
			t.Error("the straggler completed and the ledger did not move. Every doc paragraph on " +
				"drain_stragglers says a truncated report is a lower bound over a still-moving set; " +
				"if nothing moves, that caveat is wrong and should be deleted rather than documented")
		}
		if atGiveUp.Emitted == atGiveUp.InWindow+atGiveUp.Drain+atGiveUp.SendFailures+
			atGiveUp.Dropped+atGiveUp.SuppressedPreWindow {
			t.Error("the give-up snapshot satisfied the ledger identity, so the documented hazard did " +
				"not occur here. emitted is incremented at GENERATION and sent at the write's RETURN, " +
				"so a straggler must sit between the two")
		}
	})
}

// TestDrainGiveUpNeverReportsZeroStragglers pins the floor, which is the fix
// that actually protects the report.
//
// Two narrow races can make the shadow counter read LOW at the give-up instant:
// leave() decrementing it between wg.Done() and the ceiling firing, and select
// choosing the ceiling when done is also ready. The ordering in leave() and the
// done-preference in closeAndWait narrow both, but neither can be closed and
// neither can be triggered deterministically by a test. The floor is what makes
// the outcome safe regardless, and unlike the two orderings it IS testable, by
// forcing the low read directly.
//
// The floor is an invariant, not a fudge: reaching the ceiling branch means done
// was not closed, so at least one fire has not called wg.Done().
func TestDrainGiveUpNeverReportsZeroStragglers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &drainGate{}
		if !d.admit() {
			t.Fatal("admit must succeed on a fresh gate")
		}
		// Force the low read the races would produce, without needing to hit a
		// window a nanosecond wide.
		d.inflight.Store(0)

		if got := d.closeAndWait("test"); got != 1 {
			t.Errorf("a give-up reported %d stragglers, want at least 1.\nThe ceiling branch is only "+
				"reached when done is NOT closed, so a fire is outstanding by construction. Reporting "+
				"0 drops drain_stragglers via omitempty and makes a truncated finalize "+
				"indistinguishable from a clean one, which is the exact outcome the field exists to "+
				"prevent", got)
		}
		d.leave() // release the parked waiter so the bubble can finish
	})
}
