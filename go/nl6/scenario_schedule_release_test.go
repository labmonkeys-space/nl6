/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
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
