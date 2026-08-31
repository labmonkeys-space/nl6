/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// scenario_drain_knob_test.go — nl6#500: the scenario `drain` duration
// configured nothing (the post-window phase is a barrier, not a duration), so
// it is REJECTED at submit rather than accepted, echoed and ignored — the
// nl6#445 rule. These tests pin the BEHAVIOUR (finalize ends when the admitted
// writes return, never on a deadline), the rejection, the fingerprint
// consequence for an old run being re-submitted, and — as a cheap second net
// only — the absence of the old identifiers.

// TestScenarioDrainEnd_IsTheReleaseInstantNotADeadline is the primary
// regression stop, and it is a BEHAVIOURAL one on purpose.
//
// A reviewer defeated the name-based test by rebuilding the whole knob under a
// different name (`Grace` on the spec, a `grace` DTO key, `time.Sleep` in
// finish) with the entire suite green. Nothing that inspects identifiers can
// catch that. What no reintroduction can hide is the OBSERVABLE: `drain_end`
// must be the instant the last admitted write returned, so any post-window
// sleep, deadline or held-open gate — whatever it is called — moves it.
//
// The fire is released 10ms after T1, which is shorter than any plausible
// grace (the removed knob defaulted to 2s), so a reintroduced one shows up as
// a drain_end later than the release.
//
// One caveat, verified by running the reviewer's `Grace` mutation against this
// test: a reintroduction that sleeps INSIDE finish (which holds c.mu) can wedge
// the synctest bubble instead of reaching the assertion, so it surfaces here as
// a test timeout rather than a message. That is still a red test, and the
// legible failure for that shape comes from assertDrainTailIsBounded on the two
// real-time runs ("drain_end − t1 = 2.0025765s, want 0..750ms"). Both nets are
// therefore load-bearing; neither alone is enough.
func TestScenarioDrainEnd_IsTheReleaseInstantNotADeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, _ := scenarioTestManager(t, 1)
		dev := sm.devicesByIP["10.42.0.1"]
		dev.syslogConfig = &DeviceSyslogConfig{Collector: "10.0.0.9:514"}

		// The first write blocks until released; it is admitted to the barrier
		// before T1, so finalize cannot complete until it returns.
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
		if err := c.Submit(spec, "s-000500"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // first fire admitted, blocked in its write

		// Reach T1: the auto-close timer finalizes, which blocks in the
		// barrier behind that write.
		time.Sleep(spec.Window)
		synctest.Wait()
		// emitting flips false only AFTER closeAndWait returns, and it is an
		// atomic — Result() would deadlock here, since finish() holds c.mu for
		// the whole barrier wait.
		if !c.emitting.Load() {
			t.Fatal("finalize completed while an admitted write was still blocked — the barrier did not hold")
		}

		const held = 10 * time.Millisecond
		time.Sleep(held)
		releasedAt := time.Now()
		close(release)
		synctest.Wait()

		res := c.Result()
		if res == nil {
			t.Fatal("no result after the in-flight write returned")
		}
		// Exact equality is available and is the point: synctest's clock only
		// advances when every goroutine is blocked, so with no sleep left in
		// finalize, drain_end IS the release instant. Any added wait fails
		// here regardless of what the added field is called.
		if !res.DrainEnd.Equal(releasedAt) {
			t.Errorf("drain_end = %s, want the release instant %s (+%s): the post-window phase must "+
				"end when the admitted writes return, not on a deadline (nl6#500)",
				res.DrainEnd, releasedAt, res.DrainEnd.Sub(releasedAt))
		}
		// The released write returned after T1, so it buckets `drain` — the
		// tail exists as an observed consequence, which is what makes the
		// barrier (rather than a duration) the honest mechanism.
		if got := res.PerDevice["10.42.0.1"].Drain; got != 1 {
			t.Errorf("drain = %d, want 1 (the write released after T1)", got)
		}
	})
}

// drainTailSlack bounds how long after T1 a healthy real-time run may take to
// finalize. It is deliberately loose — a wall-clock test on loaded CI — and
// still an order of magnitude below the removed knob's 2s default, so it fails
// a reintroduced grace of any realistic size. The exact statement lives in
// TestScenarioDrainEnd_IsTheReleaseInstantNotADeadline under synctest.
const drainTailSlack = 750 * time.Millisecond

// assertDrainTailIsBounded pins the claim four documents now rest on: the drain
// tail is bounded by the work admitted before T1 (one write per device on the
// syslog path), not by a duration. Called from the two tests that finalize a
// real run, where it costs nothing and would catch a transport that started
// parking writes past T1 (nl6#500 R8).
func assertDrainTailIsBounded(t *testing.T, res *ScenarioResult) {
	t.Helper()
	if held := res.DrainEnd.Sub(res.T1Actual); held < 0 || held > drainTailSlack {
		t.Errorf("drain_end − t1 = %s, want 0..%s: the barrier returns when the admitted "+
			"writes return (nl6#500)", held, drainTailSlack)
	}
	for ip, snap := range res.PerDevice {
		// At most ONE write per device can be in flight at T1: the scenario
		// syslog scheduler fires inline per participant.
		if snap.Drain > 1 {
			t.Errorf("%s: drain = %d, want <= 1 — the tail is bounded by the write admitted "+
				"before T1, not by a grace period (nl6#500)", ip, snap.Drain)
		}
	}
}

// TestScenarioAPI_DrainIsRejected: a submit carrying `drain` is a 400
// attributed to the `drain` field, and the message says the barrier is
// automatic AND what to do about it. The message is what makes the rejection
// actionable — an operator who had a drain configured needs to be told their
// grace period never existed, not that their JSON key is unwelcome.
//
// Every row is a separate subtest, so one failing shape cannot hide the
// others — the empty/null rows are the ones that regressed.
func TestScenarioAPI_DrainIsRejected(t *testing.T) {
	router := scenarioAPIManager(t, 1)
	const head = `{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"1s"`
	for _, tc := range []struct{ name, body string }{
		{"duration", head + `,"drain":"2s","seed":42}`},
		// The refusal keys on the KEY's presence, never on its value: an
		// explicit empty or null drain is the accepted-and-ignored shape
		// nl6#445 forbids, and a string field could see neither.
		{"empty_string", head + `,"drain":""}`},
		{"null", head + `,"drain":null}`},
		{"zero", head + `,"drain":"0s"}`},
		{"unparseable", head + `,"drain":"xx"}`},
		// A non-string value must reach the same actionable message instead of
		// the decoder's "cannot unmarshal number into … of type string".
		{"number", head + `,"drain":30}`},
		{"object", head + `,"drain":{"after":"2s"}}`},
		// A bad window AND a drain: the schema change must be reported, not
		// the value error, or the operator meets it only on the second try.
		{"bad_window_too", `{"participants":["10.42.0.1"],"protocol":"syslog","rate":5,"window":"nope","drain":"2s"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("submit with drain = %d, want 400 (body %s)", w.Code, w.Body.String())
			}
			var resp struct {
				Error string `json:"error"`
				Field string `json:"field"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("400 body: %v (%s)", err, w.Body.String())
			}
			if resp.Field != "drain" {
				t.Errorf("field = %q, want %q (body %s)", resp.Field, "drain", w.Body.String())
			}
			// Both halves: the diagnosis AND the instruction. A rewrite that
			// keeps "not supported" but drops the remedy leaves the operator
			// with no next step.
			for _, want := range []string{"not supported", "automatic", "no grace period to configure", "remove the field"} {
				if !strings.Contains(resp.Error, want) {
					t.Errorf("message must contain %q, got %q", want, resp.Error)
				}
			}
		})
	}
}

// TestScenarioFingerprint_DrainFreeBodyKeepsItsDigest is the reproduce-from-
// fingerprint decision (nl6#500 Block If). A recorded fingerprint is a SHA-256
// of the submit body and carries no drain of its own, so replaying a run means
// a human re-submitting that body. Two outcomes had to be explicit:
//
//   - a body that CARRIED a drain no longer submits at all (400, above) — an
//     error the operator reads, never a silent replay of something different;
//   - a body that omitted it must hash EXACTLY as before, or every baseline
//     taken before this change would read as a different configuration.
//
// The digest below was computed on main@44ef67f, BEFORE the field stopped being
// honoured — not re-derived from the current code, which would prove nothing.
// The body is submitted THROUGH the handler and the digest read off the 202
// response, so this pins the end-to-end property an operator observes rather
// than the hash helper in isolation.
func TestScenarioFingerprint_DrainFreeBodyKeepsItsDigest(t *testing.T) {
	const (
		body                = `{"participants":["10.42.0.1","10.42.0.2"],"protocol":"syslog","rate":10,"window":"1s","seed":42}`
		wantPreChangeDigest = "57cd3804ceee6b8a0b9143c497f40693cb6f6918270d0beb7974aee67333c1a6"
	)
	router := scenarioAPIManager(t, 2)
	w := doReq(t, router, http.MethodPost, "/api/v1/scenarios", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit = %d, want 202 (body %s)", w.Code, w.Body.String())
	}
	var resp struct {
		ConfigSHA256 string `json:"config_sha256"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ConfigSHA256 != wantPreChangeDigest {
		t.Fatalf("config_sha256 = %s, want %s (pre-change digest from main@44ef67f — a submit "+
			"that reproduced a run before nl6#500 must reproduce it after)", resp.ConfigSHA256, wantPreChangeDigest)
	}
}

// TestNoProductionCodeConfiguresADrain is the SECOND net, not the first. It
// catches a re-add that reuses the old vocabulary, which is cheap to check and
// worth having; it does NOT catch a reintroduction under a new name, and a
// reviewer demonstrated exactly that (`Grace`, `defaultDrainGrace`,
// `drainGraceFor`) passing this test with the suite green. The behavioural stop
// is TestScenarioDrainEnd_IsTheReleaseInstantNotADeadline; if you are here
// because this test failed, read that one too.
//
// The `drain` ledger bucket, the `drain_end` timestamp and the drainGate are
// deliberately NOT in scope: those are observed, not configured.
func TestNoProductionCodeConfiguresADrain(t *testing.T) {
	for _, st := range []struct {
		name string
		typ  reflect.Type
	}{
		{"Scenario", reflect.TypeOf(Scenario{})},
		{"gateState", reflect.TypeOf(gateState{})},
	} {
		for i := 0; i < st.typ.NumField(); i++ {
			if strings.Contains(strings.ToLower(st.typ.Field(i).Name), "drain") {
				t.Errorf("%s regained a drain field (%s): the post-window phase is a "+
					"barrier, not a duration (nl6#500)", st.name, st.typ.Field(i).Name)
			}
		}
	}

	// Word-boundary match, and CASE-SENSITIVE. `DrainEnd` / `drain_end` are
	// legitimate — an observed timestamp on the report — while `drainEnd` was
	// the dead gate field, so the two differ only in case and a
	// case-insensitive scan would fail the suite on the shipped report struct.
	// Prose containing "drainEnd" would also trip this; that is the accepted
	// cost of the cheap net, and the fix is to write "the dead gate field"
	// instead of spelling the identifier.
	banned := regexp.MustCompile(`\b(drainOrDefault|defaultScenarioDrain|drainEnd)\b`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sawAPIFile := false
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		if f == "scenario_api.go" {
			sawAPIFile = true
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := banned.FindString(string(b)); m != "" {
			t.Errorf("%s mentions %s: a configured drain duration is gone (nl6#500) — "+
				"the barrier ends when the writes admitted before T1 return", f, m)
		}
	}
	// Positive control: a glob that matched nothing, or only test files, would
	// pass silently. Naming the file the rejection lives in beats a magic
	// count, which fails in the wrong direction when files are removed.
	if !sawAPIFile {
		t.Fatal("scan never reached scenario_api.go — the glob is not covering the package")
	}
}
