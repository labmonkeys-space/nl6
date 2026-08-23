/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// withFidelity restores both the in-force value and any pending timer, so a
// test cannot leak simulator-wide state into its neighbours.
func withFidelity(t *testing.T, silent bool) {
	t.Helper()
	prevSilent := fidelitySilent.Load()
	prevFlag := fidelityStartupFlag.Load()
	t.Cleanup(func() {
		cancelFidelityRevert()
		fidelitySilent.Store(prevSilent)
		fidelityStartupFlag.Store(prevFlag)
	})
	cancelFidelityRevert()
	fidelitySilent.Store(silent)
}

func postFidelity(t *testing.T, body string) (*httptest.ResponseRecorder, FidelityStatus) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/fidelity", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	fidelityToggleHandler(w, r)
	var resp struct {
		Data FidelityStatus `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp.Data
}

// TestFidelityToggle_RuntimeChange is the whole point of the change: silencing
// a fleet must not require a restart, because restarting destroys every
// REST-created device and the measurement setup with them.
func TestFidelityToggle_RuntimeChange(t *testing.T) {
	withFidelity(t, false)

	w, st := postFidelity(t, `{"silent":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if !st.InForce {
		t.Error("response reports silent=false after enabling it")
	}
	if !fidelitySilent.Load() {
		t.Error("the flag the exporters actually read was not updated")
	}

	if _, st = postFidelity(t, `{"silent":false}`); st.InForce {
		t.Error("toggling back did not take effect")
	}
	if fidelitySilent.Load() {
		t.Error("exporters still see silent after it was turned off")
	}
}

// TestFidelityStatus_ReportsInForceAndStartupFlag guards the trap this change
// could most easily have walked into.
//
// Once the value is mutable, `-fidelity` is a DEFAULT rather than a fact. A
// surface reporting only the flag would assert something the engine may have
// stopped honouring, which is the nl6#445 defect (a value accepted, echoed and
// ignored) reappearing in the change built to be honest about exactly that.
func TestFidelityStatus_ReportsInForceAndStartupFlag(t *testing.T) {
	withFidelity(t, false)
	fidelityStartupFlag.Store(false) // process started WITHOUT -fidelity

	postFidelity(t, `{"silent":true}`)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/fidelity", nil)
	w := httptest.NewRecorder()
	fidelityStatusHandler(w, r)

	var resp struct {
		Data FidelityStatus `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Data.InForce {
		t.Error("in-force value not reported as silent")
	}
	if resp.Data.StartupFlag {
		t.Error("startup flag reported as true; the process started without -fidelity")
	}
	if resp.Data.InForce == resp.Data.StartupFlag {
		t.Error("the two values are indistinguishable here, so a reader cannot see the divergence " +
			"that makes the runtime value trustworthy")
	}
}

// TestFidelityToggle_TimedRevert covers the auto-revert half of the
// interface-state convention.
func TestFidelityToggle_TimedRevert(t *testing.T) {
	withFidelity(t, false)

	w, st := postFidelity(t, `{"silent":true,"duration":"120ms"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if !st.RevertPending || st.RevertAt == "" {
		t.Errorf("timed toggle did not report a pending revert: %+v", st)
	}
	if !fidelitySilent.Load() {
		t.Fatal("silence not applied")
	}

	deadline := time.Now().Add(2 * time.Second)
	for fidelitySilent.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fidelitySilent.Load() {
		t.Error("value did not revert after the duration elapsed")
	}
}

// TestFidelityToggle_LaterRequestSupersedes pins the "one timer, not a stack"
// rule.
//
// The obvious version of this test cannot detect stacking: `timer` is a single
// field, so an implementation that assigns a new timer WITHOUT stopping the old
// one still nils the field and still reverts on schedule, and assertions on
// "did it revert" and "is timer nil" both pass. It also orphaned a 10s timer
// that would later fire inside whatever other test was running, flipping a
// process global.
//
// So: both durations are short, and the test watches PAST the first deadline
// for a second, unexplained transition. A surviving timer would revert again.
func TestFidelityToggle_LaterRequestSupersedes(t *testing.T) {
	withFidelity(t, false)

	postFidelity(t, `{"silent":true,"duration":"400ms"}`) // superseded
	postFidelity(t, `{"silent":true,"duration":"80ms"}`)  // wins

	// The winner reverts to false.
	deadline := time.Now().Add(2 * time.Second)
	for fidelitySilent.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fidelitySilent.Load() {
		t.Fatal("the second timer did not fire")
	}

	// Re-silence, then wait past the FIRST timer's deadline. If it survived, it
	// fires here and drags the value back to false.
	fidelitySilent.Store(true)
	time.Sleep(600 * time.Millisecond)
	if !fidelitySilent.Load() {
		t.Error("a superseded timer fired after its own deadline; timers stacked instead of " +
			"superseding, and the fleet changed state with no request behind it")
	}
}

// TestFidelityToggle_RejectsBadDuration covers the 400 paths, including the
// 24h cap that keeps auto-revert from being an unbounded goroutine.
func TestFidelityToggle_RejectsBadDuration(t *testing.T) {
	withFidelity(t, false)

	for _, tc := range []struct{ name, body string }{
		{"over cap", `{"silent":true,"duration":"25h"}`},
		{"unparseable", `{"silent":true,"duration":"soon"}`},
		{"negative", `{"silent":true,"duration":"-5s"}`},
		{"unknown field", `{"silent":true,"quiet":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := fidelitySilent.Load()
			w, _ := postFidelity(t, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 for %s", w.Code, tc.name)
			}
			if fidelitySilent.Load() != before {
				t.Error("a rejected request changed the value in force")
			}
		})
	}
}

// TestFidelityMute_AppliesToBackgroundNotOnDemand pins the predicate's
// semantics: fidelity mutes autonomous noise, and an explicit operator fire is
// a deliberate action rather than fleet chatter.
func TestFidelityMute_AppliesToBackgroundNotOnDemand(t *testing.T) {
	withFidelity(t, true)

	for _, tc := range []struct {
		src   fireSource
		muted bool
	}{
		{sourceBackground, true},
		{sourceStateDriven, true},
		{sourceOnDemand, false},
	} {
		if got := fidelityMutesBackground(tc.src); got != tc.muted {
			t.Errorf("fidelityMutesBackground(%v) = %v, want %v", tc.src, got, tc.muted)
		}
	}

	withFidelity(t, false)
	if fidelityMutesBackground(sourceBackground) {
		t.Error("background muted while fidelity is off")
	}
}

// TestFidelityMute_ObservesRuntimeChange is why section 1 of this change was a
// prerequisite rather than cleanup.
//
// All four push subsystems consult fidelity through this one predicate, so a
// runtime toggle is observed identically by every one of them. Before the
// consolidation, flow and gNMI dial-out read the flag directly and could not
// express the on-demand exemption at all.
func TestFidelityMute_ObservesRuntimeChange(t *testing.T) {
	withFidelity(t, false)

	if fidelityMutesBackground(sourceBackground) {
		t.Fatal("muted before any toggle")
	}
	postFidelity(t, `{"silent":true}`)
	if !fidelityMutesBackground(sourceBackground) {
		t.Error("the shared predicate did not observe the runtime toggle")
	}
	postFidelity(t, `{"silent":false}`)
	if fidelityMutesBackground(sourceBackground) {
		t.Error("the shared predicate did not observe the toggle back")
	}
}

// TestFidelity_SingleConsultPoint is a source-level guard on the single
// consult point.
//
// SCOPE, stated honestly: it catches a subsystem going back to reading
// `fidelitySilent` directly, which would lose the fireSource distinction and
// start muting on-demand operator fires. It does NOT catch caching
// `fidelityMutesBackground(...)` at exporter construction — that keeps the
// identifier absent and passes cleanly. A grep cannot see that, so fidelity.go
// now says what this enforces rather than claiming more.
//
// The floor assertions matter as much as the check: filepath.Glob returns
// (nil, nil) on no match, so without them any change to the test binary's
// working directory would silently disable the guard while it kept reporting
// PASS.
func TestFidelity_SingleConsultPoint(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) < 50 {
		t.Fatalf("scanned only %d files; this package has hundreds, so the guard is not "+
			"looking where it thinks it is and would pass vacuously", len(files))
	}

	allowed := map[string]bool{
		"fidelity.go":     true, // defines the flag and the predicate
		"fidelity_api.go": true, // the runtime setter
		"simulator.go":    true, // records the startup flag
	}
	// The four push subsystems must actually have been among the files read,
	// or "no direct reads found" says nothing about them.
	mustScan := map[string]bool{
		"syslog_exporter.go": false, "trap_exporter.go": false,
		"flow_exporter.go": false, "gnmi_dialout_exporter.go": false,
	}
	for _, f := range files {
		if _, ok := mustScan[f]; ok {
			mustScan[f] = true
		}
		if allowed[f] || strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// Needle includes the dot so it matches the atomic's accessors
		// (`fidelitySilent.Load()` / `.Store()`) and not identifiers that
		// merely start with the same letters, such as the report's
		// `fidelitySilentAtStart` field. The looser form produced false
		// positives on this package's own disclosure code.
		if bytes.Contains(src, []byte("fidelitySilent.")) {
			t.Errorf("%s reads fidelitySilent directly; consult fidelityMutesBackground instead, "+
				"or the fireSource distinction is lost and on-demand fires get muted", f)
		}
	}
	for f, seen := range mustScan {
		if !seen {
			t.Errorf("%s was never scanned, so this guard says nothing about it", f)
		}
	}
}

// TestFidelityToggle_ChainedTimedTogglesRevertToOriginal is the regression
// guard for a bug this test suite caught during implementation.
//
// The obvious implementation captures "the value in force" as the revert
// target on every request. Chain two timed toggles and the second captures what
// the FIRST had just set, so the revert restores the temporary state and the
// fleet stays silent permanently. Shortening a measurement window is an
// ordinary thing to do, so this was a stuck-silent fleet from two normal
// requests.
//
// The revert target is the state from before the CHAIN began.
func TestFidelityToggle_ChainedTimedTogglesRevertToOriginal(t *testing.T) {
	withFidelity(t, false) // fleet is emitting

	postFidelity(t, `{"silent":true,"duration":"10s"}`)   // silence for a while
	postFidelity(t, `{"silent":true,"duration":"120ms"}`) // actually, make it short

	deadline := time.Now().Add(3 * time.Second)
	for fidelitySilent.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fidelitySilent.Load() {
		t.Fatal("fleet is still silent after the shortened window: the revert restored the " +
			"temporary state instead of the state before the chain, so silence is permanent")
	}
}

// TestFidelityToggle_UntimedTogglePinsTheNewState checks the other half: an
// untimed toggle is a standing change, so a LATER timed toggle must return to
// it rather than to something older.
func TestFidelityToggle_UntimedTogglePinsTheNewState(t *testing.T) {
	withFidelity(t, false)

	postFidelity(t, `{"silent":true}`)                     // standing: fleet silent
	postFidelity(t, `{"silent":false,"duration":"120ms"}`) // briefly un-silence

	deadline := time.Now().Add(3 * time.Second)
	for !fidelitySilent.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !fidelitySilent.Load() {
		t.Error("did not return to the standing silent state after the temporary window")
	}
}

// TestFidelityToggle_FiredCallbackCannotClobber is the regression guard for a
// race review found before this shipped.
//
// time.Timer.Stop() cannot recall a callback that has ALREADY fired. Such a
// callback can be blocked on the mutex while an operator's standing toggle
// commits, and would then store its stale captured value over the operator's
// change: a 200 response, and a fleet doing the opposite of what was asked,
// with the "clean measurement window" silently contaminated.
//
// The ordering has to be forced, not hoped for. Holding the mutex across the
// deadline parks the callback; mutating state while still holding it is
// exactly "the operator's toggle committed first"; releasing then lets the
// stale callback try to act. A first version of this test did the mutation
// AFTER releasing, so the callback had already completed and the test passed
// against the bug it was written to catch.
func TestFidelityToggle_FiredCallbackCannotClobber(t *testing.T) {
	withFidelity(t, false)

	// Arm a revert back to false, due almost immediately.
	postFidelity(t, `{"silent":true,"duration":"60ms"}`)

	fidelityRevert.mu.Lock()
	time.Sleep(150 * time.Millisecond) // the callback has fired and is now parked on the mutex

	// Simulate a standing toggle winning the lock: this is precisely what
	// setFidelity(silent=true, 0) does to the shared state.
	cancelFidelityRevertLocked() // supersedes the parked callback
	fidelityRevert.restore = true
	fidelitySilent.Store(true)
	fidelityRevert.mu.Unlock()

	// Let the parked callback run and attempt its stale store.
	time.Sleep(150 * time.Millisecond)

	if !fidelitySilent.Load() {
		t.Fatal("a fired-but-superseded revert clobbered the operator's standing toggle; " +
			"the fleet is emitting when it was explicitly silenced")
	}
}

// TestFidelityStatus_ReportsRevertDeadline covers the field's own contract.
// An operator who armed a window in one shell polls GET from another, and
// "a revert is pending" without "when" does not answer their question.
func TestFidelityStatus_ReportsRevertDeadline(t *testing.T) {
	withFidelity(t, false)
	postFidelity(t, `{"silent":true,"duration":"10s"}`)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/fidelity", nil)
	w := httptest.NewRecorder()
	fidelityStatusHandler(w, r)
	var resp struct {
		Data FidelityStatus `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Data.RevertPending {
		t.Fatal("GET does not report the pending revert")
	}
	if resp.Data.RevertAt == "" {
		t.Error("GET reports a pending revert with no deadline, so an operator cannot tell " +
			"when the window ends")
	}
	if _, err := time.Parse(time.RFC3339, resp.Data.RevertAt); err != nil {
		t.Errorf("revert_at %q is not RFC3339: %v", resp.Data.RevertAt, err)
	}
}

// TestFidelityToggle_OppositeDirectionChainDoesNotDiscardTheWindow is the
// regression guard for the HIGH review found.
//
// `restore` used to be preserved whenever a timer was pending, with no
// direction check — the comment said "shortens or extends the window", which
// was the only case reasoned about. So: silence for an hour, peek for two
// minutes, and the peek's revert restored the PRE-SILENCE value. The fleet then
// emitted for the remaining 58 minutes with GET reporting nothing pending, and
// nothing anywhere indicating the window had been dropped.
//
// A direction change starts a new chain, so the peek reverts to silent.
func TestFidelityToggle_OppositeDirectionChainDoesNotDiscardTheWindow(t *testing.T) {
	withFidelity(t, false) // fleet emitting

	postFidelity(t, `{"silent":true,"duration":"10s"}`)    // silence the measurement
	postFidelity(t, `{"silent":false,"duration":"100ms"}`) // peek at background traffic

	deadline := time.Now().Add(3 * time.Second)
	for !fidelitySilent.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !fidelitySilent.Load() {
		t.Fatal("after the peek the fleet is EMITTING; the outer silence window was silently " +
			"discarded and the measurement it protected is contaminated")
	}
}

// TestFidelityToggle_RequiresSilentField pins the presence check.
//
// As a bare bool, `{"duration":"30m"}` — the natural shorthand for "keep it as
// it is for another 30 minutes" — decoded to false and un-muted the whole fleet
// immediately, returning 200.
func TestFidelityToggle_RequiresSilentField(t *testing.T) {
	withFidelity(t, true) // fleet is silent for a measurement

	w, _ := postFidelity(t, `{"duration":"30m"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when `silent` is omitted", w.Code)
	}
	if !fidelitySilent.Load() {
		t.Error("omitting `silent` un-muted the fleet; a measurement in progress is now contaminated")
	}
}

// TestFidelityToggle_TimedThenUntimedCancels covers the likeliest operator
// sequence, which had no test: arm a window, then decide to make it permanent.
//
// Guarding the cancel behind `if d > 0` would ship green without this, and the
// standing silence would evaporate when the old timer fired.
func TestFidelityToggle_TimedThenUntimedCancels(t *testing.T) {
	withFidelity(t, false)

	postFidelity(t, `{"silent":true,"duration":"150ms"}`) // temporary
	postFidelity(t, `{"silent":true}`)                    // actually, make it permanent

	// Wait past the original deadline. A surviving timer reverts to false.
	time.Sleep(400 * time.Millisecond)
	if !fidelitySilent.Load() {
		t.Error("the standing silence evaporated when the superseded timer fired; the operator's " +
			"permanent change was undone with no request behind it")
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/fidelity", nil)
	w := httptest.NewRecorder()
	fidelityStatusHandler(w, r)
	var resp struct {
		Data FidelityStatus `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Data.RevertPending {
		t.Error("GET still advertises a pending revert after an untimed toggle cleared it")
	}
}

// TestFidelityStatus_ReportsRevertTarget covers the field that makes the chain
// semantics legible. The target is the pre-chain value, NOT the negation of the
// value in force, so an operator cannot infer it.
func TestFidelityStatus_ReportsRevertTarget(t *testing.T) {
	withFidelity(t, false)
	postFidelity(t, `{"silent":true,"duration":"10s"}`)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/fidelity", nil)
	w := httptest.NewRecorder()
	fidelityStatusHandler(w, r)
	var resp struct {
		Data FidelityStatus `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.RevertTo == nil {
		t.Fatal("GET reports a pending revert without saying what it reverts TO")
	}
	if *resp.Data.RevertTo {
		t.Errorf("revert_to = true, want false (the value before the chain began)")
	}
}

// TestFidelityToggle_RejectsTrailingContent: a handler that sets
// DisallowUnknownFields so a typo is a 400 should not silently drop a whole
// second object.
func TestFidelityToggle_RejectsTrailingContent(t *testing.T) {
	withFidelity(t, false)
	w, _ := postFidelity(t, `{"silent":true}{"silent":false}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for trailing content", w.Code)
	}
}

// TestFidelityRoutes_RegisteredOnTheRouter exercises the endpoints through
// setupRoutes() rather than by calling the handlers directly, following the
// interface-state convention. Every other test in this file invokes the
// handler functions, so a wrong path, a missing method, or a handler wired to
// the wrong verb would pass all of them while the feature is unreachable over
// HTTP.
func TestFidelityRoutes_RegisteredOnTheRouter(t *testing.T) {
	withFidelity(t, false)
	router := setupRoutes()

	post := httptest.NewRequest(http.MethodPost, "/api/v1/fidelity",
		bytes.NewReader([]byte(`{"silent":true}`)))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, post)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/fidelity via router: got %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	if !fidelitySilent.Load() {
		t.Fatal("POST routed to a handler that did not change the in-force value")
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v1/fidelity", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, get)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/fidelity via router: got %d, want 200", rr.Code)
	}
	var resp struct {
		Data FidelityStatus `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GET body is not the documented envelope: %v (body %q)", err, rr.Body.String())
	}
	if !resp.Data.InForce {
		t.Error("GET routed to a handler that did not report the value POST just set")
	}

	// The two verbs are registered separately; a GET must not reach the
	// mutating handler.
	bad := httptest.NewRequest(http.MethodDelete, "/api/v1/fidelity", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, bad)
	if rr.Code == http.StatusOK {
		t.Error("DELETE /api/v1/fidelity returned 200; only GET and POST are registered")
	}
}

// TestFidelityToggle_MidScenarioDoesNotDisturbTheRun covers the claim task 5.1
// originally cited the wrong evidence for: TestFidelity_ScenarioStillEmits
// stores silence BEFORE Submit/Arm/Start and never mutates it, so it pins
// "silent at T0", not a transition during the window. Here the fleet starts
// emitting and is silenced mid-window, which is the case an operator actually
// hits when they quiet the fleet after a run is already going.
func TestFidelityToggle_MidScenarioDoesNotDisturbTheRun(t *testing.T) {
	withFidelity(t, false) // fleet NOT silent at T0

	synctest.Test(t, func(t *testing.T) {
		sm, _ := scenarioTestManager(t, 1)
		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: []string{"10.42.0.1"}, Protocol: "syslog",
			Rate: 20, Window: 2 * time.Second, Drain: 200 * time.Millisecond, Seed: 42,
		}
		if err := c.Submit(spec, "s-000042"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}

		// Silence the fleet mid-window, through the real handler.
		time.Sleep(spec.Window / 2)
		if w, _ := postFidelity(t, `{"silent":true}`); w.Code != http.StatusOK {
			t.Fatalf("mid-scenario toggle: got %d", w.Code)
		}

		time.Sleep(spec.Window + spec.drainOrDefault() + 100*time.Millisecond)
		synctest.Wait()

		res := c.Result()
		if res == nil {
			t.Fatal("scenario did not finalize")
		}
		var sent uint64
		for _, s := range res.PerDevice {
			sent += s.InWindow + s.Drain
		}
		if sent == 0 {
			t.Fatal("participant stopped emitting when the fleet was silenced mid-run; " +
				"the mute must stay in the non-participant branch")
		}

		// The disclosure is the operator-visible half: without it an archived
		// report cannot say the fleet went quiet partway through.
		rep := buildScenarioReport(sm, c)
		if rep == nil {
			t.Fatal("no report built")
		}
		fid := rep.Summary.Metadata.Fidelity
		if fid.SilentAtStart {
			t.Error("silent_at_start should record the value at T0 (false), not the value at finalize")
		}
		if !fid.ChangedDuringWindow {
			t.Error("changed_during_window must record the mid-run toggle; " +
				"a clean-looking ledger over a mixed window is exactly what this field exists to flag")
		}
	})
}
