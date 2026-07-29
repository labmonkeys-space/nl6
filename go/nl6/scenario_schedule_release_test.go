/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

// scenario_schedule_release_test.go — a pending absolute-T0 start must never
// leave the scenario in a state an operator cannot get out of.
//
// Two ways the old code did exactly that. Both ended identically: phase `armed`,
// a `scheduled_start` in the past, `ScheduleStart` refusing a replacement
// because startTimer was still non-nil, and no log line saying why.
//
//  1. Every armed participant is deleted before T0. Start rolls back to `armed`
//     and returns an error the timer discarded.
//  2. A re-arm drops the participant set (to 0/N, or just to a different set)
//     while the timer keeps pointing at the old authorisation.

// TestScheduleRelease_FailedFireReleasesSchedule covers path 1 and needs no
// re-arm: it is reachable on any build with an absolute-T0 start.
func TestScheduleRelease_FailedFireReleasesSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := scenarioAPIManager(t, 1)
		id := submitOK(t, router, `{"participants":["10.42.0.1"],"protocol":"syslog","rate":10,"window":"1s","seed":5}`)
		mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
		ctrl, err := manager.scenarioByID(id)
		if err != nil {
			t.Fatal(err)
		}

		at := time.Now().Add(5 * time.Second)
		mustPostBody(t, router, "/api/v1/scenarios/"+id+"/start",
			fmt.Sprintf(`{"at":%q}`, at.Format(time.RFC3339)))
		if ctrl.ScheduledStart().IsZero() {
			t.Fatal("schedule was not recorded")
		}

		// Retire the only participant before T0, so the fire cannot succeed.
		// Under manager.mu, like the real delete path (manager.go): a live start
		// timer reads this map under RLock, so an unsynchronised test mutation is
		// a genuine data race, not just untidiness.
		manager.mu.Lock()
		dev := manager.devicesByIP["10.42.0.1"]
		dev.syslogExporter = nil
		delete(manager.devicesByIP, "10.42.0.1")
		delete(manager.devices, dev.ID)
		delete(manager.deviceIPs, "10.42.0.1")
		manager.mu.Unlock()

		time.Sleep(8 * time.Second)
		synctest.Wait()

		// The fire failed, so the scenario stays armed — but the schedule must be
		// released rather than left pinned.
		if p := ctrl.Phase(); p != phaseArmed {
			t.Fatalf("phase after failed scheduled start = %s, want armed", p)
		}
		if got := ctrl.ScheduledStart(); !got.IsZero() {
			t.Fatalf("schedule still pinned at %s after a failed fire", got.Format(time.RFC3339))
		}
		// Status must not advertise a start that will never happen.
		w := doReq(t, router, http.MethodGet, "/api/v1/scenarios/"+id, "")
		var st statusResponse
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		if st.ScheduledStart != "" {
			t.Fatalf("status still reports scheduled_start = %q", st.ScheduledStart)
		}

		// And the operator can recover: recreate the fleet, re-arm, reschedule.
		// Previously ScheduleStart refused forever ("already has a scheduled
		// start"), with DELETE the only way out.
		sm, _ := scenarioTestManager(t, 1)
		manager.mu.Lock()
		for ip, d := range sm.devicesByIP {
			manager.devicesByIP[ip] = d
			manager.devices[d.ID] = d
			manager.deviceIPs[ip] = struct{}{}
		}
		manager.mu.Unlock()
		aw := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
		if aw.Code != http.StatusOK {
			t.Fatalf("re-arm after failed fire = %d (body %s)", aw.Code, aw.Body.String())
		}
		next := time.Now().Add(5 * time.Second).Format(time.RFC3339)
		sw := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/start", fmt.Sprintf(`{"at":%q}`, next))
		if sw.Code != http.StatusOK {
			t.Fatalf("reschedule after failed fire = %d (body %s), want 200", sw.Code, sw.Body.String())
		}
	})
}

// TestScheduleRelease_ReplacementScheduleSurvives is the end-to-end shape:
// schedule A, withdraw it by re-arming, schedule B, and confirm A's instant
// passing disturbs neither the phase nor B. Here timer.Stop() does the work,
// because A had not fired yet — the harder case, where A has already fired and
// is blocked on the mutex, is TestScheduleRelease_FiredButWithdrawnDoesNotRun.
func TestScheduleRelease_ReplacementScheduleSurvives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := scenarioAPIManager(t, 1)
		id := submitOK(t, router, `{"participants":["10.42.0.1"],"protocol":"syslog","rate":10,"window":"1s","seed":11}`)
		mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
		ctrl, err := manager.scenarioByID(id)
		if err != nil {
			t.Fatal(err)
		}

		// Schedule A at T+5, then withdraw it by re-arming.
		mustPostBody(t, router, "/api/v1/scenarios/"+id+"/start",
			fmt.Sprintf(`{"at":%q}`, time.Now().Add(5*time.Second).Format(time.RFC3339)))
		mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")

		// Schedule B, further out than A.
		bAt := time.Now().Add(20 * time.Second)
		mustPostBody(t, router, "/api/v1/scenarios/"+id+"/start",
			fmt.Sprintf(`{"at":%q}`, bAt.Format(time.RFC3339)))

		// Walk past A's instant. A is superseded, so it must do nothing at all.
		time.Sleep(8 * time.Second)
		synctest.Wait()
		if p := ctrl.Phase(); p != phaseArmed {
			t.Fatalf("phase after the superseded instant = %s, want armed (A started the scenario)", p)
		}
		if got := ctrl.ScheduledStart(); got.IsZero() {
			t.Fatal("the superseded fire blanked the live schedule B")
		} else if !got.Equal(bAt) {
			t.Fatalf("scheduled_start = %s, want B at %s", got.Format(time.RFC3339), bAt.Format(time.RFC3339))
		}

		// B still fires on time.
		time.Sleep(15 * time.Second)
		synctest.Wait()
		if p := ctrl.Phase(); p == phaseArmed {
			t.Fatal("schedule B never fired")
		}
	})
}

// TestScheduleRelease_FiredButWithdrawnDoesNotRun pins the generation guard,
// which covers the one window `timer.Stop()` cannot: the timer has ALREADY fired
// and its goroutine is queued on c.mu, so Stop() reports nothing useful and a
// withdrawal recorded meanwhile must still be honoured.
//
// Driven by invoking the fire directly with the generation it captured, rather
// than by racing a real timer: the guard lives inside the lock, so the state is
// unreachable on demand from the REST surface, and trying to hold c.mu across a
// synctest clock advance simply deadlocks the bubble.
func TestScheduleRelease_FiredButWithdrawnDoesNotRun(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, nil)
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "syslog",
		Rate: 1, Window: time.Second, Seed: 17}
	if err := c.Submit(spec, "s-000200"); err != nil {
		t.Fatal(err)
	}
	if armed, _, err := c.Arm(); err != nil || armed != 1 {
		t.Fatalf("arm: armed=%d err=%v", armed, err)
	}
	ctx := context.Background()
	t.Cleanup(func() { _ = c.Cancel() }) // stop whatever timer is left pending

	// Grant schedule A and capture the generation its fire carries.
	if err := c.ScheduleStart(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	genA := c.scheduleGen
	c.mu.Unlock()

	// Withdraw A (this is what a re-arm does), then grant B in its place.
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	bAt := time.Now().Add(2 * time.Hour)
	if err := c.ScheduleStart(ctx, bAt); err != nil {
		t.Fatalf("schedule B after withdrawing A: %v", err)
	}

	// A's fire had already left the gate when the withdrawal landed. It must do
	// nothing: not start the scenario, and not blank B.
	c.startScheduled(ctx, genA)

	if p := c.Phase(); p != phaseArmed {
		t.Errorf("phase = %s, want armed: a withdrawn fire started the scenario against a membership the operator never approved", p)
	}
	if got := c.ScheduledStart(); got.IsZero() {
		t.Error("the withdrawn fire blanked the live schedule B (a pending timer with no scheduled_start in status)")
	} else if !got.Equal(bAt) {
		t.Errorf("scheduled_start = %s, want B at %s", got.Format(time.RFC3339), bAt.Format(time.RFC3339))
	}
}

// TestScheduleRelease_FinishStopsPendingTimer: an operator may schedule an
// absolute T0 and then start manually. The completed run must leave no stale
// fire behind — previously finish() stopped only the auto-close timer, so the
// scheduled one woke up afterwards and logged a spurious failure.
func TestScheduleRelease_FinishStopsPendingTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := scenarioAPIManager(t, 1)
		id := submitOK(t, router, `{"participants":["10.42.0.1"],"protocol":"syslog","rate":10,"window":"1s","drain":"100ms","seed":13}`)
		mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
		ctrl, err := manager.scenarioByID(id)
		if err != nil {
			t.Fatal(err)
		}

		mustPostBody(t, router, "/api/v1/scenarios/"+id+"/start",
			fmt.Sprintf(`{"at":%q}`, time.Now().Add(30*time.Second).Format(time.RFC3339)))
		// Start immediately instead, and let the window self-close.
		mustPost(t, router, "/api/v1/scenarios/"+id+"/start")
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if p := ctrl.Phase(); p != phaseStopped {
			t.Fatalf("phase after the window = %s, want stopped", p)
		}
		if got := ctrl.ScheduledStart(); !got.IsZero() {
			t.Errorf("finished run still advertises scheduled_start = %s", got.Format(time.RFC3339))
		}

		// Walk past the abandoned instant: nothing may stir.
		time.Sleep(35 * time.Second)
		synctest.Wait()
		if p := ctrl.Phase(); p != phaseStopped {
			t.Fatalf("phase after the abandoned instant = %s, want stopped", p)
		}
	})
}

// TestScheduleRelease_ReArmCancelsSchedule covers path 2: a re-arm withdraws the
// authorisation the schedule was granted against, and says so in the readiness
// response rather than only in a log line.
func TestScheduleRelease_ReArmCancelsSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := scenarioAPIManager(t, 2)
		id := submitOK(t, router, `{"participants":["10.42.0.1","10.42.0.2"],"protocol":"syslog","rate":10,"window":"1s","seed":7}`)
		mustPost(t, router, "/api/v1/scenarios/"+id+"/arm")
		ctrl, err := manager.scenarioByID(id)
		if err != nil {
			t.Fatal(err)
		}

		mustPostBody(t, router, "/api/v1/scenarios/"+id+"/start",
			fmt.Sprintf(`{"at":%q}`, time.Now().Add(5*time.Second).Format(time.RFC3339)))

		// Re-arm while the start is pending.
		w := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
		if w.Code != http.StatusOK {
			t.Fatalf("re-arm = %d (body %s)", w.Code, w.Body.String())
		}
		var rd readinessResponse
		if err := json.Unmarshal(w.Body.Bytes(), &rd); err != nil {
			t.Fatal(err)
		}
		if !rd.ScheduledStartCancelled {
			t.Error("re-arm cancelled the schedule without reporting scheduled_start_cancelled")
		}
		if got := ctrl.ScheduledStart(); !got.IsZero() {
			t.Fatalf("schedule survived a re-arm: %s", got.Format(time.RFC3339))
		}

		// The cancelled timer must not fire: T0 passes with the scenario armed.
		time.Sleep(8 * time.Second)
		synctest.Wait()
		if p := ctrl.Phase(); p != phaseArmed {
			t.Fatalf("phase after the cancelled T0 = %s, want armed", p)
		}

		// An arm with nothing scheduled must not claim a cancellation.
		w2 := doReq(t, router, http.MethodPost, "/api/v1/scenarios/"+id+"/arm", "")
		var rd2 readinessResponse
		if err := json.Unmarshal(w2.Body.Bytes(), &rd2); err != nil {
			t.Fatal(err)
		}
		if rd2.ScheduledStartCancelled {
			t.Error("arm reported scheduled_start_cancelled with nothing scheduled")
		}
		// Rescheduling still works, and this time it fires.
		mustPostBody(t, router, "/api/v1/scenarios/"+id+"/start",
			fmt.Sprintf(`{"at":%q}`, time.Now().Add(2*time.Second).Format(time.RFC3339)))
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if p := ctrl.Phase(); p == phaseArmed {
			t.Fatal("the rescheduled start never fired")
		}
	})
}
