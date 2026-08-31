/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// nl6#538: a resource-file rejection must be FATAL, CLASSIFIABLE and
// PANIC-FREE. These tests pin the three properties as one contract, because
// each is individually satisfiable by code that gets the other two wrong:
// a loader that returns an error for everything is classifiable but useless,
// and one that never panics because it never publishes is fatal but silent.
//
// None of these tests may run in parallel: they chdir (t.Chdir), and other
// tests in this package resolve resources/ relative to the working directory.

const (
	// The sentinel-colliding value from nl6#523. Exactly this string, since
	// the guard's test is exact.
	rejectedEntry = `{"oid":"1.3.6.1.2.1.1.1.0","response":"noSuchObject"}`
	cleanEntry    = `{"oid":"1.3.6.1.2.1.1.1.0","response":"a clean sysDescr"}`
)

// classifyFixture chdirs into a temp tree with a resources/ directory and
// returns a manager wired the way the real loaders expect one.
func classifyFixture(t *testing.T) *SimulatorManager {
	t.Helper()
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("resources", 0o755); err != nil {
		t.Fatalf("mkdir resources: %v", err)
	}
	return &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
}

func writeResourceFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// assertNoPathDisclosure is the single definition of the no-path guarantee.
//
// Checking for the literal "resources/" prefix was too weak twice over: the
// fixtures live under t.TempDir(), so an absolute /var/folders/... leak went
// undetected, and any path spelling other than that one prefix passed. This
// asserts on the separator itself plus the absolute fixture root.
func assertNoPathDisclosure(t *testing.T, body string) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// The JSON envelope has no separators of its own; any that appear came
	// from a rendered path.
	if strings.Contains(body, "/") || strings.Contains(body, `\/`) {
		t.Errorf("body %q discloses a path separator", body)
	}
	if strings.Contains(body, cwd) {
		t.Errorf("body %q discloses the absolute fixture root %q", body, cwd)
	}
}

// assertInvalid asserts the error is classified as invalid CONTENT and not as
// an absent file. Both directions matter: the two sentinels drive opposite
// round-robin behaviour, so an error that answers true to both is as broken as
// one that answers false to both.
func assertInvalid(t *testing.T, err error) *resourceFileError {
	t.Helper()
	if err == nil {
		t.Fatal("want an invalid-content error, got nil")
	}
	if !errors.Is(err, errResourceInvalid) {
		t.Errorf("error %q is not classified errResourceInvalid", err)
	}
	if errors.Is(err, errResourceNotFound) {
		t.Errorf("error %q is classified errResourceNotFound as well as invalid; "+
			"round-robin would carry on past content that is wrong", err)
	}
	var rerr *resourceFileError
	if !errors.As(err, &rerr) {
		t.Fatalf("error %q does not carry a *resourceFileError; the 400 body "+
			"cannot be rendered with the file's base name only", err)
	}
	return rerr
}

func assertNotFound(t *testing.T, err error) *resourceFileError {
	t.Helper()
	if err == nil {
		t.Fatal("want a not-found error, got nil")
	}
	if !errors.Is(err, errResourceNotFound) {
		t.Errorf("error %q is not classified errResourceNotFound", err)
	}
	if errors.Is(err, errResourceInvalid) {
		t.Errorf("error %q is classified invalid as well as not-found", err)
	}
	var rerr *resourceFileError
	if !errors.As(err, &rerr) {
		t.Fatalf("error %q does not carry a *resourceFileError", err)
	}
	return rerr
}

// ── matrix row: null single file ───────────────────────────────────────────

// A resource file containing the literal `null` decoded into a *DeviceResources
// field and left it nil; validateSNMPResourceValues returns nil for nil input,
// so buildResourceIndexes then dereferenced it and PANICKED.
func TestNullResourceFileIsRejectedNotDereferenced(t *testing.T) {
	sm := classifyFixture(t)
	before := &DeviceResources{SNMP: []SNMPResource{{OID: "1.3.6.1.2.1.1.1.0", Response: "previous"}}}
	sm.deviceResources = before

	writeResourceFile(t, filepath.Join("resources", "nulltype.json"), "null")

	err := sm.LoadResources(filepath.Join("resources", "nulltype.json"))
	rerr := assertInvalid(t, err)
	if !strings.Contains(rerr.Error(), "nulltype.json") {
		t.Errorf("error %q does not name the offending file", err)
	}
	if sm.deviceResources != before {
		t.Errorf("a failed load replaced sm.deviceResources; it must keep the previous set")
	}
}

// The REST-reachable loader decoded into a VALUE, so `null` yielded a zero
// DeviceResources that passed the guard, was CACHED, and produced devices
// answering no OID at all — no error, no warning. The acceptance bullet is
// unqualified, so it must hold on this loader too.
func TestNullResourceFileRejectedByRESTLoader(t *testing.T) {
	sm := classifyFixture(t)
	writeResourceFile(t, filepath.Join("resources", "nullprof.json"), "null")

	res, err := sm.LoadSpecificResources("nullprof.json")
	if err == nil {
		t.Fatalf("a null resource file loaded as an empty set (%+v); every device "+
			"created from it would answer no OID", res)
	}
	rerr := assertInvalid(t, err)
	if !strings.Contains(rerr.Error(), "nullprof.json") {
		t.Errorf("error %q does not name the offending file", err)
	}
	if _, cached := sm.cachedResources("nullprof.json"); cached {
		t.Error("a rejected resource file was cached")
	}
}

// A directory PART containing `null` decodes into a value, so it is an empty
// part rather than a nil pointer. It must not panic and must not fail the
// load: a part legitimately carries only some sections.
func TestNullDirectoryPartLoadsAsEmpty(t *testing.T) {
	sm := classifyFixture(t)
	dir := filepath.Join("resources", "nullpart")
	writeResourceFile(t, filepath.Join(dir, "a_null.json"), "null")
	writeResourceFile(t, filepath.Join(dir, "b_snmp.json"), `{"snmp":[`+cleanEntry+`]}`)

	if err := sm.LoadResources(filepath.Join("resources", "nullpart.json")); err != nil {
		t.Fatalf("a null directory part failed the load: %v", err)
	}
	if n := len(sm.deviceResources.SNMP); n != 1 {
		t.Errorf("loaded %d SNMP entries, want 1 (the sibling part)", n)
	}
}

// ── matrix row: JSON syntax error ──────────────────────────────────────────

// The cause must stay reachable: Unwrap returns the sentinel AND the
// underlying error, so errors.As can still reach a *json.SyntaxError and
// errors.Is a sentinel like io.ErrUnexpectedEOF. Returning only the
// classification made the cause unrecoverable.
//
// Both JSON fault shapes are exercised because they surface as different
// types: a truncated document is io.ErrUnexpectedEOF, a bad byte is a
// *json.SyntaxError.
func TestMalformedJSONIsClassifiedInvalid(t *testing.T) {
	for _, layout := range []string{"single-file", "directory"} {
		for _, shape := range []struct {
			name, body string
			check      func(t *testing.T, err error)
		}{
			{"truncated", `{"snmp":[`, func(t *testing.T, err error) {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Errorf("error %q does not carry io.ErrUnexpectedEOF; Unwrap dropped the cause", err)
				}
			}},
			{"bad-byte", `{"snmp":[}]}`, func(t *testing.T, err error) {
				var syn *json.SyntaxError
				if !errors.As(err, &syn) {
					t.Errorf("error %q does not carry a *json.SyntaxError; Unwrap dropped the cause", err)
				}
			}},
		} {
			t.Run(layout+"/"+shape.name, func(t *testing.T) {
				sm := classifyFixture(t)
				switch layout {
				case "single-file":
					writeResourceFile(t, filepath.Join("resources", "brokenjson.json"), shape.body)
				case "directory":
					writeResourceFile(t, filepath.Join("resources", "brokenjson", "p_snmp.json"), shape.body)
				}
				_, err := sm.LoadSpecificResources("brokenjson.json")
				_ = assertInvalid(t, err)
				shape.check(t, err)
			})
		}
	}
}

// ── matrix row: partial set on error ───────────────────────────────────────

// A directory whose third part is invalid must leave sm.deviceResources at its
// previous value. Before nl6#538 the loader assigned the manager's field up
// front and returned mid-merge, publishing a partial, unindexed set.
func TestFailedDirectoryLoadLeavesPreviousSetIntact(t *testing.T) {
	sm := classifyFixture(t)
	before := &DeviceResources{SNMP: []SNMPResource{{OID: "1.3.6.1.2.1.1.1.0", Response: "previous"}}}
	sm.deviceResources = before

	dir := filepath.Join("resources", "partialtype")
	writeResourceFile(t, filepath.Join(dir, "a_snmp.json"), `{"snmp":[{"oid":"1.3.6.1.2.1.1.4.0","response":"one"}]}`)
	writeResourceFile(t, filepath.Join(dir, "b_snmp.json"), `{"snmp":[{"oid":"1.3.6.1.2.1.1.5.0","response":"two"}]}`)
	writeResourceFile(t, filepath.Join(dir, "c_snmp.json"), `{"snmp":[`+rejectedEntry+`]}`)

	err := sm.LoadResources(filepath.Join("resources", "partialtype.json"))
	rerr := assertInvalid(t, err)
	if !strings.Contains(rerr.Error(), "c_snmp.json") {
		t.Errorf("error %q does not name the offending PART", err)
	}
	if sm.deviceResources != before {
		t.Fatalf("sm.deviceResources was replaced by a failed load: got %+v", sm.deviceResources.SNMP)
	}
}

// An EXISTING directory holding no .json part published an empty set and
// returned nil — the one surviving route by which a good in-memory set was
// replaced with nothing.
func TestEmptyDeviceTypeDirectoryIsInvalid(t *testing.T) {
	t.Run("LoadResources", func(t *testing.T) {
		sm := classifyFixture(t)
		before := &DeviceResources{SNMP: []SNMPResource{{OID: "1.3.6.1.2.1.1.1.0", Response: "previous"}}}
		sm.deviceResources = before
		if err := os.MkdirAll(filepath.Join("resources", "emptytype"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		err := sm.LoadResources(filepath.Join("resources", "emptytype.json"))
		_ = assertInvalid(t, err)
		if sm.deviceResources != before {
			t.Fatalf("an empty directory replaced the loaded set with %d entries",
				len(sm.deviceResources.SNMP))
		}
	})

	t.Run("LoadSpecificResources", func(t *testing.T) {
		sm := classifyFixture(t)
		if err := os.MkdirAll(filepath.Join("resources", "emptytype"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		res, err := sm.LoadSpecificResources("emptytype.json")
		if err == nil {
			t.Fatalf("an empty directory loaded and would be cached as a device type: %+v", res)
		}
		_ = assertInvalid(t, err)
		if _, cached := sm.cachedResources("emptytype.json"); cached {
			t.Error("an empty directory was cached")
		}
	})
}

// ── matrix rows: startup ───────────────────────────────────────────────────

// An INVALID default resource file is fatal: loadDefaultResources returns an
// error rather than substituting the cisco_ios profile.
func TestStartupLoadDoesNotSubstituteOnInvalid(t *testing.T) {
	sm := classifyFixture(t)
	writeResourceFile(t, filepath.Join("resources", "asr9k.json"), `{"snmp":[`+rejectedEntry+`]}`)
	writeResourceFile(t, filepath.Join("resources", "cisco_ios.json"), `{"snmp":[`+cleanEntry+`]}`)

	err := loadDefaultResources(sm)
	rerr := assertInvalid(t, err)
	if !strings.Contains(rerr.Error(), "asr9k.json") {
		t.Errorf("error %q does not name the offending file", err)
	}
	if sm.deviceResources != nil {
		t.Fatalf("startup fell back to a substituted profile on an INVALID asr9k.json "+
			"(%d entries loaded); it must exit instead", len(sm.deviceResources.SNMP))
	}
}

// An ABSENT asr9k.json does NOT reach the cisco_ios arm: LoadResources
// SYNTHESISES a default file for it and returns nil. That is pre-existing
// behaviour and this test pins it, so nobody reads the cisco_ios arm as the
// answer to "asr9k.json is missing".
func TestAbsentDefaultResourceIsSynthesisedNotFallenBackTo(t *testing.T) {
	sm := classifyFixture(t)
	writeResourceFile(t, filepath.Join("resources", "cisco_ios.json"), `{"snmp":[`+cleanEntry+`]}`)

	if err := loadDefaultResources(sm); err != nil {
		t.Fatalf("an absent asr9k.json was made fatal: %v", err)
	}
	if _, err := os.Stat(filepath.Join("resources", "asr9k.json")); err != nil {
		t.Fatalf("asr9k.json was not synthesised: %v", err)
	}
	// The compiled-in default, not the cisco_ios fixture (one entry).
	if n := len(sm.deviceResources.SNMP); n < 2 {
		t.Fatalf("loaded %d SNMP entries; the synthesised default has ~30, the "+
			"cisco_ios fixture has 1 — this looks like the fallback arm ran", n)
	}
}

// The cisco_ios arm is only REACHABLE when the synthesised default cannot be
// written. This drives it for real and asserts the loaded set is the cisco_ios
// FIXTURE, not the compiled-in default.
//
// The lever is an unwritable resources/ directory, which root ignores, so the
// test PROBES that os.Create actually fails and skips with an explanation if
// it does not. That means the arm is unpinned on a root test runner; it is the
// only portable lever available, since every other route to this branch is
// also a route to a different branch.
func TestStartupFallsBackToCiscoIOSWhenDefaultCannotBeSynthesised(t *testing.T) {
	sm := classifyFixture(t)
	const marker = "cisco-ios-fixture-marker"
	writeResourceFile(t, filepath.Join("resources", "cisco_ios.json"),
		`{"snmp":[{"oid":"1.3.6.1.2.1.1.1.0","response":"`+marker+`"}]}`)

	if err := os.Chmod("resources", 0o555); err != nil {
		t.Fatalf("chmod resources: %v", err)
	}
	// Restore write permission so t.TempDir's cleanup can remove the tree.
	t.Cleanup(func() { _ = os.Chmod("resources", 0o755) })

	// Probe: on a root runner the mode bits are advisory.
	probe := filepath.Join("resources", "zz_probe.json")
	if f, err := os.Create(probe); err == nil {
		f.Close()
		_ = os.Remove(probe)
		t.Skip("resources/ is writable despite mode 0555 (running as root?); " +
			"the cisco_ios fallback arm cannot be reached portably here")
	}

	if err := loadDefaultResources(sm); err != nil {
		t.Fatalf("the cisco_ios fallback arm did not run: %v", err)
	}
	if sm.deviceResources == nil || len(sm.deviceResources.SNMP) != 1 {
		t.Fatalf("loaded %+v; want exactly the one-entry cisco_ios fixture", sm.deviceResources)
	}
	if got := sm.deviceResources.SNMP[0].Response; got != marker {
		t.Fatalf("loaded response %q, want %q — the fallback loaded something "+
			"other than the cisco_ios fixture", got, marker)
	}
}

// The absent-file classification itself, independent of which arm consumes it.
func TestAbsentDefaultResourceIsClassifiedNotFound(t *testing.T) {
	sm := classifyFixture(t)
	err := sm.LoadResources(filepath.Join("resources", "nosuchdir", "absent.json"))
	_ = assertNotFound(t, err)
}

// ── matrix rows: round robin ───────────────────────────────────────────────

// withRoundRobinTypes swaps the package-level type list for the duration of a
// test. Safe only because these tests never run in parallel.
func withRoundRobinTypes(t *testing.T, types []string) {
	t.Helper()
	saved := RoundRobinDeviceTypes
	RoundRobinDeviceTypes = types
	t.Cleanup(func() { RoundRobinDeviceTypes = saved })
}

// An INVALID round-robin type fails the call. Skipping it would silently
// change the device-type MIX the caller asked for.
func TestRoundRobinFailsOnInvalidType(t *testing.T) {
	sm := classifyFixture(t)
	withRoundRobinTypes(t, []string{"rrgood.json", "rrbad.json"})
	writeResourceFile(t, filepath.Join("resources", "rrgood.json"), `{"snmp":[`+cleanEntry+`]}`)
	writeResourceFile(t, filepath.Join("resources", "rrbad.json"), `{"snmp":[`+rejectedEntry+`]}`)

	_, _, _, err := sm.resolveCreateResources(true, "", "")
	rerr := assertInvalid(t, err)
	if !strings.Contains(rerr.Error(), "rrbad.json") {
		t.Errorf("error %q does not name the offending type", err)
	}
}

// An ABSENT round-robin type is still skipped, and the remaining types load.
// This is the consumer that makes the not-found sentinel worth having, since
// the REST boundary now answers both kinds 400.
func TestRoundRobinSkipsAbsentType(t *testing.T) {
	sm := classifyFixture(t)
	withRoundRobinTypes(t, []string{"rrgood.json", "rrmissing.json"})
	writeResourceFile(t, filepath.Join("resources", "rrgood.json"), `{"snmp":[`+cleanEntry+`]}`)

	_, rrRes, rrFiles, err := sm.resolveCreateResources(true, "", "")
	if err != nil {
		t.Fatalf("an absent round-robin type was made fatal: %v", err)
	}
	if len(rrRes) != 1 || len(rrFiles) != 1 || rrFiles[0] != "rrgood.json" {
		t.Fatalf("want the one present type loaded, got files %v", rrFiles)
	}
}

// An UNREADABLE round-robin type is neither invalid nor absent, and aborts the
// batch. That is a deliberate widening of the old warn-and-skip: an unreadable
// file is not evidence that the type is unshipped, and skipping it changes the
// device-type mix silently.
func TestRoundRobinAbortsOnUnreadableType(t *testing.T) {
	sm := classifyFixture(t)
	withRoundRobinTypes(t, []string{"rrgood.json", "rrlocked.json"})
	writeResourceFile(t, filepath.Join("resources", "rrgood.json"), `{"snmp":[`+cleanEntry+`]}`)
	locked := filepath.Join("resources", "rrlocked.json")
	writeResourceFile(t, locked, `{"snmp":[`+cleanEntry+`]}`)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	if f, err := os.Open(locked); err == nil {
		f.Close()
		t.Skip("mode 0000 is readable (running as root?); cannot stage an unreadable file")
	}

	_, _, _, err := sm.resolveCreateResources(true, "", "")
	if err == nil {
		t.Fatal("an unreadable round-robin type was skipped; the batch must abort")
	}
	if errors.Is(err, errResourceInvalid) || errors.Is(err, errResourceNotFound) {
		t.Errorf("error %q is classified; an unreadable file is neither kind, and "+
			"this test exists to pin the un-classified abort", err)
	}
	if !strings.Contains(err.Error(), "rrlocked.json") {
		t.Errorf("error %q does not name the offending type", err)
	}
}

// ── the REST boundary ──────────────────────────────────────────────────────

// The handler, end to end. Driving createDevicesErrorResponse alone left the
// handler's own line unpinned: reverting it to a 500 kept the suite green.
//
// Reaching it required hoisting resource resolution above the root check in
// CreateDevicesWithOptions, which is the correct order anyway — caller data is
// wrong whether or not the process is root.
func TestCreateDevicesHandlerRejectsBadResourceFile(t *testing.T) {
	sm := classifyFixture(t)
	t.Cleanup(swapGlobalManager(sm))
	router := setupRoutes()

	dir := filepath.Join("resources", "restbad")
	writeResourceFile(t, filepath.Join(dir, "restbad_snmp.json"), `{"snmp":[`+rejectedEntry+`]}`)
	writeResourceFile(t, filepath.Join("resources", "restgood.json"), `{"snmp":[`+cleanEntry+`]}`)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	t.Run("invalid-content-is-400", func(t *testing.T) {
		rr := post(`{"start_ip":"10.42.0.1","device_count":1,"netmask":"16","resource_file":"restbad.json"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		for _, want := range []string{"restbad_snmp.json", "1.3.6.1.2.1.1.1.0", "noSuchObject"} {
			if !strings.Contains(body, want) {
				t.Errorf("body %q does not mention %q", body, want)
			}
		}
		assertNoPathDisclosure(t, body)
	})

	t.Run("absent-device-type-is-400", func(t *testing.T) {
		rr := post(`{"start_ip":"10.42.0.1","device_count":1,"netmask":"16","resource_file":"nosuchtype.json"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if !strings.Contains(body, "nosuchtype") {
			t.Errorf("body %q does not name the device type", body)
		}
		// The docs promise the 400 body never contains a directory path; the
		// original not-found message interpolated resources/<slug> twice.
		assertNoPathDisclosure(t, body)
	})

	t.Run("bad-file-name-is-400-without-a-path", func(t *testing.T) {
		const submitted = "../../etc/passwd"
		rr := post(`{"start_ip":"10.42.0.1","device_count":1,"netmask":"16","resource_file":"` + submitted + `"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		// Positive, not a conjunction of absences: `!(has "/" && has "..")`
		// passed for a body echoing the traversal with either character
		// dropped. The submitted string must not survive at all, and the base
		// name must be what identifies the fault.
		if strings.Contains(body, submitted) {
			t.Errorf("body %q echoes the submitted traversal path back", body)
		}
		if !strings.Contains(body, "passwd") {
			t.Errorf("body %q does not name the base name of the rejected file", body)
		}
		assertNoPathDisclosure(t, body)
	})

	// A VALID resource file gets past resolution and hits the root check,
	// which is the pre-existing 500. Without this row a handler that answered
	// 400 for everything would pass.
	t.Run("valid-request-still-reports-the-root-requirement", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: the privilege check does not fire")
		}
		rr := post(`{"start_ip":"10.42.0.1","device_count":1,"netmask":"16","resource_file":"restgood.json"}`)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "root privileges") {
			t.Errorf("body %q is not the root-privileges error", rr.Body.String())
		}
	})
}

// The mapping itself, over an error produced by the real loader chain. This is
// the test that catches a %v anywhere on that chain: %v flattens it, errors.As
// returns false, and the status silently reverts to 500.
func TestRESTRejectionIs400WithBaseNameOnly(t *testing.T) {
	sm := classifyFixture(t)
	dir := filepath.Join("resources", "restbad")
	writeResourceFile(t, filepath.Join(dir, "restbad_snmp.json"), `{"snmp":[`+rejectedEntry+`]}`)

	_, _, _, err := sm.resolveCreateResources(false, "", "restbad.json")
	if err == nil {
		t.Fatal("a rejected resource file loaded")
	}

	msg, status := createDevicesErrorResponse(err)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d. A flattened error chain (%%v instead of %%w) "+
			"is the usual cause", status, http.StatusBadRequest)
	}
	for _, want := range []string{"restbad_snmp.json", "1.3.6.1.2.1.1.1.0", "noSuchObject"} {
		if !strings.Contains(msg, want) {
			t.Errorf("400 body %q does not mention %q", msg, want)
		}
	}
	assertNoPathDisclosure(t, msg)
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error %q lost the full path; the log needs it", err)
	}
}

// One sentinel, two consumers that must not be collapsed: the REST boundary
// answers not-found 400 (an unknown device type is an unsatisfiable request),
// while round-robin carries on past it. TestRoundRobinSkipsAbsentType is the
// other half.
func TestAbsentIs400AtRESTOnly(t *testing.T) {
	msg, status := createDevicesErrorResponse(notFoundResource("x.json", "no such device type"))
	if status != http.StatusBadRequest {
		t.Errorf("absent-file status = %d, want 400", status)
	}
	if !strings.Contains(msg, "x.json") {
		t.Errorf("body %q does not name the file", msg)
	}
}

// An UNCLASSIFIED error keeps its 500: telling the caller its request was
// malformed when the server could not read a file is a lie.
func TestUnclassifiedErrorKeeps500(t *testing.T) {
	msg, status := createDevicesErrorResponse(errors.New("root privileges required to create TUN interfaces"))
	if status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", status)
	}
	if msg == "" {
		t.Error("empty body")
	}
}

// ── validateOpticalInventory is classified too ─────────────────────────────

// Its four faults are the same class of caller-data fault as a guard
// rejection. The existing TestValidateOpticalInventory only substring-matches
// message text, which is unchanged, so it survives a revert to fmt.Errorf.
func TestOpticalInventoryFaultsAreClassifiedInvalid(t *testing.T) {
	const optType = "ciena_waveserver5"
	prof := OpticalProfileFor(optType + ".json")
	if prof == nil {
		t.Fatalf("%s has no optical profile; pick another optical type", optType)
	}

	t.Run("through-the-directory-loader", func(t *testing.T) {
		sm := classifyFixture(t)
		dir := filepath.Join("resources", optType)
		writeResourceFile(t, filepath.Join(dir, optType+"_snmp.json"), `{"snmp":[`+cleanEntry+`]}`)
		// Exactly one channel where the profile declares prof.ChannelCount.
		writeResourceFile(t, filepath.Join(dir, optType+"_optical.json"),
			`{"optical":[{"name":"OCH-1-1"}]}`)

		_, err := sm.LoadSpecificResources(optType + ".json")
		if prof.ChannelCount == 1 {
			t.Skipf("%s declares 1 channel; the fixture cannot disagree", optType)
		}
		rerr := assertInvalid(t, err)
		if !strings.Contains(rerr.Error(), optType) {
			t.Errorf("error %q does not name the device type", err)
		}
	})

	// The other three faults, directly: missing inventory, empty name,
	// duplicate name.
	for _, tc := range []struct {
		name string
		res  *DeviceResources
	}{
		{"no-inventory", &DeviceResources{}},
		{"empty-channel-name", &DeviceResources{Optical: []OpticalChannel{{Name: ""}}}},
		{"duplicate-channel-name", &DeviceResources{Optical: []OpticalChannel{{Name: "OCH-1-1"}, {Name: "OCH-1-1"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOpticalInventory(optType+".json", tc.res)
			_ = assertInvalid(t, err)
		})
	}
}

// ── the typed error's two renderings ───────────────────────────────────────

func TestResourceFileErrorRendersTwice(t *testing.T) {
	e := &resourceFileError{
		File: filepath.Join("resources", "some_type", "some_type_snmp.json"),
		Msg:  `OID 1.3.6.1.2.1.1.1.0 has value "noSuchObject", which collides`,
		kind: errResourceInvalid,
	}
	if !strings.Contains(e.Error(), filepath.Join("resources", "some_type")) {
		t.Errorf("Error() = %q, want the full path", e.Error())
	}
	if strings.Contains(e.PublicMessage(), string(os.PathSeparator)) {
		t.Errorf("PublicMessage() = %q, want the base name only", e.PublicMessage())
	}
	if !strings.Contains(e.PublicMessage(), "some_type_snmp.json") {
		t.Errorf("PublicMessage() = %q, want the base name", e.PublicMessage())
	}
	if !errors.Is(e, errResourceInvalid) {
		t.Error("the typed error does not carry the sentinel")
	}
}

// Hostile input reaches both renderings: File comes from a REST field and Msg
// quotes file CONTENT.
func TestResourceFileErrorSanitisesHostileInput(t *testing.T) {
	t.Run("newlines-are-not-log-injection", func(t *testing.T) {
		e := &resourceFileError{
			File: "a.json\nFATAL: everything is fine",
			Msg:  "bad\r\nvalue",
			kind: errResourceInvalid,
		}
		for _, got := range []string{e.Error(), e.PublicMessage()} {
			if strings.ContainsAny(got, "\n\r") {
				t.Errorf("rendering %q still contains a line break", got)
			}
		}
	})

	t.Run("empty-name-is-not-a-bare-dot", func(t *testing.T) {
		e := &resourceFileError{File: "", Msg: "something", kind: errResourceInvalid}
		if strings.Contains(e.PublicMessage(), "resource .:") {
			t.Errorf("PublicMessage() = %q; filepath.Base(\"\") leaked its bare dot", e.PublicMessage())
		}
		if strings.Contains(e.Error(), "resource :") {
			t.Errorf("Error() = %q; want a placeholder for the empty name", e.Error())
		}
	})

	t.Run("c1-and-line-separators-are-stripped", func(t *testing.T) {
		e := &resourceFileError{
			File: "a.json\u0085NEL header",
			Msg:  "bad\u2028line\u2029break\u009bCSI",
			kind: errResourceInvalid,
		}
		for _, got := range []string{e.Error(), e.PublicMessage()} {
			for _, r := range []rune{'\u0085', '\u2028', '\u2029', '\u009b'} {
				if strings.ContainsRune(got, r) {
					t.Errorf("rendering %q still contains U+%04X", got, r)
				}
			}
		}
	})

	t.Run("truncation-lands-on-a-rune-boundary", func(t *testing.T) {
		// The prefix "resource a.json: " is 17 bytes, so the cap falls an odd
		// number of bytes into a run of 2-byte runes — exactly the mid-rune
		// cut a byte-slicing truncation ships as invalid UTF-8. Sized from
		// the constant, not from a literal, so raising the cap cannot make
		// this silently stop exercising truncation at all.
		e := &resourceFileError{File: "a.json", Msg: strings.Repeat("ü", maxResourceMessageBytes), kind: errResourceInvalid}
		got := e.PublicMessage()
		if !utf8.ValidString(got) {
			t.Errorf("PublicMessage() is not valid UTF-8: %q", got)
		}
		if !strings.HasSuffix(got, "(truncated)") {
			t.Errorf("PublicMessage() = %q; the oversized message was not truncated", got)
		}
	})

	t.Run("length-is-capped", func(t *testing.T) {
		e := &resourceFileError{File: "a.json", Msg: strings.Repeat("x", 100000), kind: errResourceInvalid}
		if n := len(e.PublicMessage()); n > maxResourceMessageBytes+32 {
			t.Errorf("PublicMessage() is %d bytes; a multi-megabyte resource value "+
				"must not become a multi-megabyte HTTP body", n)
		}
	})
}

// ── matrix row: startup on an UNCLASSIFIED fault ───────────────────────────

// An asr9k.json that exists but cannot be READ is neither invalid content nor
// absent, and must be fatal: the round-robin twin of this rule has
// TestRoundRobinAbortsOnUnreadableType, and without this test the startup
// guard `!errors.Is(err, errResourceNotFound)` could quietly narrow to
// `errors.Is(err, errResourceInvalid)` — every other startup test stays green
// while an I/O fault silently substitutes the cisco_ios profile again.
func TestStartupIsFatalOnUnclassifiedLoadFailure(t *testing.T) {
	sm := classifyFixture(t)
	locked := filepath.Join("resources", "asr9k.json")
	writeResourceFile(t, locked, `{"snmp":[`+cleanEntry+`]}`)
	writeResourceFile(t, filepath.Join("resources", "cisco_ios.json"), `{"snmp":[`+cleanEntry+`]}`)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	if f, err := os.Open(locked); err == nil {
		f.Close()
		t.Skip("mode 0000 is readable (running as root?); cannot stage an unreadable file")
	}

	err := loadDefaultResources(sm)
	if err == nil {
		t.Fatal("an unreadable asr9k.json fell back; it must be fatal")
	}
	if errors.Is(err, errResourceInvalid) || errors.Is(err, errResourceNotFound) {
		t.Errorf("error %q is classified; an unreadable file is neither kind, and "+
			"this test exists to pin the fatal UNCLASSIFIED arm", err)
	}
	if sm.deviceResources != nil {
		t.Fatalf("startup published %d entries from a fallback profile on an "+
			"unreadable asr9k.json; it must exit instead", len(sm.deviceResources.SNMP))
	}
}

// ── matrix row: zero-entry single file ─────────────────────────────────────

// A single file containing `{}` (or only empty arrays) is the sibling of the
// null document: it decodes cleanly, passes the guard, and publishes or caches
// a set from which every device answers no OID at all. Directory parts stay
// exempt — a part legitimately carries only some sections
// (TestNullDirectoryPartLoadsAsEmpty pins that half).
func TestZeroEntrySingleFileIsInvalid(t *testing.T) {
	for _, body := range []string{`{}`, `{"snmp":[],"ssh":[]}`} {
		t.Run(body, func(t *testing.T) {
			t.Run("LoadResources", func(t *testing.T) {
				sm := classifyFixture(t)
				before := &DeviceResources{SNMP: []SNMPResource{{OID: "1.3.6.1.2.1.1.1.0", Response: "previous"}}}
				sm.deviceResources = before
				writeResourceFile(t, filepath.Join("resources", "hollow.json"), body)

				err := sm.LoadResources(filepath.Join("resources", "hollow.json"))
				_ = assertInvalid(t, err)
				if sm.deviceResources != before {
					t.Error("a zero-entry file replaced the loaded set")
				}
			})
			t.Run("LoadSpecificResources", func(t *testing.T) {
				sm := classifyFixture(t)
				writeResourceFile(t, filepath.Join("resources", "hollow.json"), body)

				res, err := sm.LoadSpecificResources("hollow.json")
				if err == nil {
					t.Fatalf("a zero-entry file loaded and would be cached: %+v", res)
				}
				_ = assertInvalid(t, err)
				if _, cached := sm.cachedResources("hollow.json"); cached {
					t.Error("a zero-entry file was cached")
				}
			})
		})
	}
}

// ── matrix row: trailing data after the document ───────────────────────────

// json.Decoder reads ONE value and stops, so a half-broken file used to load
// silently as whatever its first value happened to be. All four decode sites
// carry the check; the two loaders here reach all of them between them.
func TestTrailingDataIsInvalid(t *testing.T) {
	const goodDoc = `{"snmp":[` + cleanEntry + `]}`
	for _, shape := range []struct{ name, body string }{
		{"second-document", goodDoc + `{"snmp":[]}`},
		{"stray-bracket", goodDoc + `]`},
	} {
		for _, layout := range []string{"single-file", "directory"} {
			t.Run(shape.name+"/"+layout, func(t *testing.T) {
				sm := classifyFixture(t)
				switch layout {
				case "single-file":
					writeResourceFile(t, filepath.Join("resources", "trailing.json"), shape.body)
				case "directory":
					writeResourceFile(t, filepath.Join("resources", "trailing", "p_snmp.json"), shape.body)
				}
				_, err := sm.LoadSpecificResources("trailing.json")
				_ = assertInvalid(t, err)

				sm2 := classifyFixture(t)
				switch layout {
				case "single-file":
					writeResourceFile(t, filepath.Join("resources", "trailing.json"), shape.body)
				case "directory":
					writeResourceFile(t, filepath.Join("resources", "trailing", "p_snmp.json"), shape.body)
				}
				_ = assertInvalid(t, sm2.LoadResources(filepath.Join("resources", "trailing.json")))
			})
		}
	}
}

// ── R1: the zero-entry rule is a property of the SET, not of the layout ────

// The directory twin of TestZeroEntrySingleFileIsInvalid. Counting .json FILES
// left this open: a directory whose only part is `{}` reaches parts == 1,
// passes that guard, and publishes or caches a set from which every device
// answers no OID at all — verbatim the outcome the single-file rule exists to
// prevent. A part that is individually empty is still fine; what is refused is
// a merged set with nothing in it.
func TestZeroEntryDirectoryIsInvalid(t *testing.T) {
	for _, shape := range []struct {
		name  string
		parts []string
	}{
		{"one-empty-part", []string{`{}`}},
		{"empty-arrays", []string{`{"snmp":[],"ssh":[]}`}},
		{"several-empty-parts", []string{`{}`, `{"snmp":[]}`, `null`}},
	} {
		write := func(t *testing.T) {
			t.Helper()
			for i, body := range shape.parts {
				writeResourceFile(t, filepath.Join("resources", "hollowdir",
					fmt.Sprintf("p%d_snmp.json", i)), body)
			}
		}

		t.Run(shape.name+"/LoadResources", func(t *testing.T) {
			sm := classifyFixture(t)
			before := &DeviceResources{SNMP: []SNMPResource{{OID: "1.3.6.1.2.1.1.1.0", Response: "previous"}}}
			sm.deviceResources = before
			write(t)

			err := sm.LoadResources(filepath.Join("resources", "hollowdir.json"))
			_ = assertInvalid(t, err)
			if sm.deviceResources != before {
				t.Errorf("a zero-entry directory replaced the loaded set with %d entries",
					len(sm.deviceResources.SNMP))
			}
		})

		t.Run(shape.name+"/LoadSpecificResources", func(t *testing.T) {
			sm := classifyFixture(t)
			write(t)

			res, err := sm.LoadSpecificResources("hollowdir.json")
			if err == nil {
				t.Fatalf("a zero-entry directory loaded and would be cached: %+v", res)
			}
			_ = assertInvalid(t, err)
			if _, cached := sm.cachedResources("hollowdir.json"); cached {
				t.Error("a zero-entry directory was cached")
			}
		})
	}

	// The two emptinesses keep distinct messages, because the remedies differ:
	// one directory needs a part, the other needs entries in the parts it has.
	t.Run("messages-are-distinct", func(t *testing.T) {
		sm := classifyFixture(t)
		if err := os.MkdirAll(filepath.Join("resources", "nopart"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		writeResourceFile(t, filepath.Join("resources", "noentry", "p_snmp.json"), `{}`)

		_, noPart := sm.LoadSpecificResources("nopart.json")
		_, noEntry := sm.LoadSpecificResources("noentry.json")
		if noPart == nil || noEntry == nil {
			t.Fatalf("both must fail: %v / %v", noPart, noEntry)
		}
		if noPart.Error() == noEntry.Error() {
			t.Fatalf("both emptinesses report the same message %q", noPart)
		}
		if !strings.Contains(noPart.Error(), "no .json resource part") {
			t.Errorf("no-part message %q does not say a part is missing", noPart)
		}
		if !strings.Contains(noEntry.Error(), "no resource entries") {
			t.Errorf("no-entry message %q does not say entries are missing", noEntry)
		}
	})
}

// ── R11: positive controls ─────────────────────────────────────────────────

// Three tests assert the cache is ABSENT after a rejection, and a loader that
// stopped caching entirely would pass all three. This is the control: a good
// single file IS cached, and the second call is served from that cache.
//
// It doubles as the single-file happy path the four refusals above need. Every
// other positive control in this package uses the DIRECTORY layout (the
// shipped tree has no single-file device type), so a regression that rejected
// every valid single file would otherwise go unnoticed.
func TestValidSingleFileLoadsAndIsCached(t *testing.T) {
	sm := classifyFixture(t)
	writeResourceFile(t, filepath.Join("resources", "goodsingle.json"),
		`{"snmp":[`+cleanEntry+`],"ssh":[{"command":"show version","response":"ok"}]}`)

	res, err := sm.LoadSpecificResources("goodsingle.json")
	if err != nil {
		t.Fatalf("a valid single-file resource was rejected: %v", err)
	}
	if len(res.SNMP) != 1 || len(res.SSH) != 1 {
		t.Fatalf("loaded %d SNMP and %d SSH entries, want 1 and 1", len(res.SNMP), len(res.SSH))
	}
	cached, ok := sm.cachedResources("goodsingle.json")
	if !ok {
		t.Fatal("a valid single file was NOT cached; the no-cache assertions " +
			"elsewhere would pass on a loader that never caches")
	}
	if cached != res {
		t.Error("the cached pointer is not the returned one")
	}
	if again, err := sm.LoadSpecificResources("goodsingle.json"); err != nil || again != res {
		t.Errorf("second call did not come from the cache: %v / %p vs %p", err, again, res)
	}

	// ...and it is a cache hit in the strong sense: no disk is touched. Proved
	// by deleting the file first — a loader that re-read would now fail
	// not-found. This also pins that the guarded read in cachedResources still
	// SERVES from the cache rather than falling through, which a mis-scoped
	// lock could break without any race detector noticing (nl6#555).
	if err := os.Remove(filepath.Join("resources", "goodsingle.json")); err != nil {
		t.Fatalf("remove fixture: %v", err)
	}
	if afterDelete, err := sm.LoadSpecificResources("goodsingle.json"); err != nil {
		t.Errorf("a cache hit re-read the disk instead of the cache: %v", err)
	} else if afterDelete != res {
		t.Errorf("cache hit returned %p, want the cached %p", afterDelete, res)
	}

	// The startup loader accepts it too, and publishes it.
	sm2 := classifyFixture(t)
	writeResourceFile(t, filepath.Join("resources", "goodsingle.json"),
		`{"snmp":[`+cleanEntry+`]}`)
	if err := sm2.LoadResources(filepath.Join("resources", "goodsingle.json")); err != nil {
		t.Fatalf("LoadResources rejected a valid single file: %v", err)
	}
	if sm2.deviceResources == nil || len(sm2.deviceResources.SNMP) != 1 {
		t.Fatalf("LoadResources published %+v", sm2.deviceResources)
	}
}

// ── R2: an all-absent round-robin batch ────────────────────────────────────

// Every INDIVIDUAL absent type is a not-found fault the REST boundary answers
// 400. A batch in which they are ALL absent — a trimmed resource tree, or a
// category matching only unshipped types — is the same fault and must get the
// same status; it used to return a bare fmt.Errorf that errors.As missed, so
// the caller got an opaque 500. TestRoundRobinSkipsAbsentType always leaves
// one type present, so nothing covered this.
func TestRoundRobinAllAbsentIsClassifiedNotFound(t *testing.T) {
	sm := classifyFixture(t)
	withRoundRobinTypes(t, []string{"rrgone1.json", "rrgone2.json"})

	_, _, _, err := sm.resolveCreateResources(true, "", "")
	_ = assertNotFound(t, err)

	msg, status := createDevicesErrorResponse(err)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — the same status a single absent type gets", status)
	}
	assertNoPathDisclosure(t, msg)
}

// ── R6: an unknown category must not substitute the full type list ─────────

// `if len(filtered) > 0 { rrTypes = filtered }` meant a typo'd category built
// the batch from EVERY device type in the fleet, and the log line printed the
// requested category beside the unfiltered count, so the substitution was
// invisible there too. That is the same "silently changes the device-type mix
// the caller asked for" failure that makes an invalid type abort.
func TestUnknownCategoryIsRejectedNotSubstituted(t *testing.T) {
	sm := classifyFixture(t)
	withRoundRobinTypes(t, []string{"rrgood.json"})
	writeResourceFile(t, filepath.Join("resources", "rrgood.json"), `{"snmp":[`+cleanEntry+`]}`)

	_, rrRes, _, err := sm.resolveCreateResources(true, "No Such Category", "")
	if err == nil {
		t.Fatalf("an unknown category loaded %d device type(s) instead of being rejected", len(rrRes))
	}
	_ = assertInvalid(t, err)
	if !strings.Contains(err.Error(), "No Such Category") {
		t.Errorf("error %q does not name the rejected category", err)
	}
	if _, status := createDevicesErrorResponse(err); status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}

	// Positive control: a category that DOES match still filters.
	sm2 := classifyFixture(t)
	real := RoundRobinDeviceTypes
	if len(real) == 0 {
		t.Skip("no shipped round-robin types")
	}
	cat := getDeviceCategoryFromName(strings.TrimSuffix(real[0], ".json"))
	if cat == "" {
		t.Skip("first round-robin type has no category")
	}
	if _, _, _, err := sm2.resolveCreateResources(true, cat, ""); err == nil {
		t.Errorf("expected the empty fixture tree to fail, but a real category was rejected outright")
	} else if !errors.Is(err, errResourceNotFound) {
		t.Errorf("a matching category failed as %v; want the not-found "+
			"all-absent fault, proving the filter itself matched", err)
	}
}

// ── R3: the full path must reach the log ───────────────────────────────────

// The spec's Always clause is that the 400 body names the base name and the
// full path stays in the error "and therefore in logs". sendErrorResponse
// writes only the HTTP body, so before this the error rendered twice and only
// the public rendering was ever emitted: the path reached nobody.
func TestRejectionLogsTheFullPath(t *testing.T) {
	sm := classifyFixture(t)
	t.Cleanup(swapGlobalManager(sm))
	router := setupRoutes()

	dir := filepath.Join("resources", "logbad")
	writeResourceFile(t, filepath.Join(dir, "logbad_snmp.json"), `{"snmp":[`+rejectedEntry+`]}`)

	var logged strings.Builder
	restore := captureLogOutput(t, &logged)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices",
		strings.NewReader(`{"start_ip":"10.42.0.1","device_count":1,"netmask":"16","resource_file":"logbad.json"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	restore()

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	want := filepath.Join(dir, "logbad_snmp.json")
	if !strings.Contains(logged.String(), want) {
		t.Fatalf("the server log does not contain the full path %q.\nlog was: %s", want, logged.String())
	}
	// And the body still does not.
	assertNoPathDisclosure(t, rr.Body.String())
}

// captureLogOutput redirects the standard logger for the duration of a call.
func captureLogOutput(t *testing.T, into *strings.Builder) (restore func()) {
	t.Helper()
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(into)
	log.SetFlags(0)
	done := false
	restore = func() {
		if done {
			return
		}
		done = true
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}
	t.Cleanup(restore)
	return restore
}

// ── R5: a path reaching the body through Msg ───────────────────────────────

// PublicMessage base-names e.File, but messages INTERPOLATE causes:
// json.Decoder.Decode returns the underlying read error unwrapped, and the
// startup fallback interpolates an *os.PathError. The guarantee therefore has
// to be enforced at the rendering, not per call site.
func TestPublicMessageRedactsPathsInsideTheMessage(t *testing.T) {
	for _, tc := range []struct{ name, msg, wantAbsent, wantPresent string }{
		{
			name:        "unwrapped-read-error",
			msg:         "failed to parse: read resources/cisco_ios/snmp_system.json: input/output error",
			wantAbsent:  "resources/cisco_ios",
			wantPresent: "snmp_system.json",
		},
		{
			name:        "os-PathError",
			msg:         `not found, and default resources could not be created: open resources/asr9k.json: permission denied`,
			wantAbsent:  "resources/asr9k.json",
			wantPresent: "asr9k.json",
		},
		{
			name:        "absolute-path",
			msg:         "failed to parse: read /var/folders/xy/T/abc/resources/p.json: bad file descriptor",
			wantAbsent:  "/var/folders",
			wantPresent: "p.json",
		},
		{
			name:        "quoted-path",
			msg:         `cannot stat "resources/some_type": permission denied`,
			wantAbsent:  "resources/some_type",
			wantPresent: "some_type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &resourceFileError{File: "x.json", Msg: tc.msg, kind: errResourceInvalid}
			got := e.PublicMessage()
			if strings.Contains(got, tc.wantAbsent) {
				t.Errorf("PublicMessage() = %q still contains the path %q", got, tc.wantAbsent)
			}
			if !strings.Contains(got, tc.wantPresent) {
				t.Errorf("PublicMessage() = %q dropped the base name %q", got, tc.wantPresent)
			}
			// Error() keeps the whole thing, for the log.
			if !strings.Contains(e.Error(), tc.wantAbsent) {
				t.Errorf("Error() = %q lost the full path; the log needs it", e.Error())
			}
		})
	}

	// An OID is dotted-numeric with no separator and must survive intact — the
	// guard messages quote OIDs, and redaction that ate them would destroy the
	// diagnosis this whole feature exists to deliver.
	t.Run("an-OID-is-not-a-path", func(t *testing.T) {
		e := &resourceFileError{
			File: "x.json",
			Msg:  `OID 1.3.6.1.2.1.1.1.0 has value "noSuchObject", which collides`,
			kind: errResourceInvalid,
		}
		if !strings.Contains(e.PublicMessage(), "1.3.6.1.2.1.1.1.0") {
			t.Errorf("PublicMessage() = %q mangled the OID", e.PublicMessage())
		}
	})
}

// ── R12: an unreadable device-type directory ───────────────────────────────

// os.Stat failing with permission-denied rather than IsNotExist used to fall
// through to the single-file branch and end as not-found, so round-robin
// SKIPPED the type and the device mix changed silently.
func TestUnreadableDirectoryIsInvalidNotNotFound(t *testing.T) {
	sm := classifyFixture(t)
	// A directory that cannot be stat'd: put it under a parent with no
	// execute permission.
	parent := filepath.Join("resources", "locked")
	if err := os.MkdirAll(filepath.Join(parent, "inner"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	if _, err := os.Stat(filepath.Join(parent, "inner")); err == nil || os.IsNotExist(err) {
		t.Skip("cannot stage an unstattable directory (running as root?)")
	}

	// LoadResources takes the same branch.
	err := sm.LoadResources(filepath.Join(parent, "inner.json"))
	if err == nil {
		t.Fatal("an unstattable device-type directory loaded")
	}
	if errors.Is(err, errResourceNotFound) {
		t.Errorf("error %q is classified not-found; round-robin would SKIP the "+
			"type and change the device mix silently", err)
	}
	_ = assertInvalid(t, err)

	// And the REST-reachable loader, which is the one round-robin calls. It
	// resolves resources/<slug> itself, so the unstattable directory has to be
	// staged by making resources/ non-traversable.
	t.Run("LoadSpecificResources", func(t *testing.T) {
		sm2 := classifyFixture(t)
		if err := os.MkdirAll(filepath.Join("resources", "inner"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod("resources", 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod("resources", 0o755) })
		if _, err := os.Stat(filepath.Join("resources", "inner")); err == nil || os.IsNotExist(err) {
			t.Skip("cannot stage an unstattable directory (running as root?)")
		}

		_, err := sm2.LoadSpecificResources("inner.json")
		if err == nil {
			t.Fatal("an unstattable device-type directory loaded")
		}
		if errors.Is(err, errResourceNotFound) {
			t.Fatalf("error %q is classified not-found, so resolveCreateResources "+
				"would SKIP this type in a round-robin batch and change the "+
				"device mix silently", err)
		}
		_ = assertInvalid(t, err)
	})
}

// ── R4: checkSingleDocument must not call an I/O fault "trailing data" ─────

// Testing `err != io.EOF` collapsed four outcomes into two: any non-EOF result,
// INCLUDING a read failure on the underlying file, was reported to the operator
// as trailing data — pointing at content that is fine — and classified as
// caller data, which is fatal at startup and 400 at REST. That is exactly the
// classification distinction this work exists to draw.
//
// Driven directly, because a real mid-read I/O fault cannot be staged portably.
func TestCheckSingleDocumentSeparatesIOFromTrailingData(t *testing.T) {
	readErr := errors.New("simulated disk failure")

	t.Run("io-fault-is-not-classified", func(t *testing.T) {
		dec := json.NewDecoder(io.MultiReader(
			strings.NewReader(`{"snmp":[]} `),
			&errReader{err: readErr},
		))
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("the document itself must decode: %v", err)
		}

		err := checkSingleDocument("resources/x.json", dec)
		if err == nil {
			t.Fatal("a read failure after the document was ignored")
		}
		if !errors.Is(err, readErr) {
			t.Errorf("error %q does not carry the underlying read error", err)
		}
		if errors.Is(err, errResourceInvalid) {
			t.Errorf("a read FAILURE was classified as invalid content (%q); it would "+
				"be fatal at startup and 400 at REST, and would blame content "+
				"that is fine", err)
		}
		if strings.Contains(err.Error(), "trailing data") {
			t.Errorf("error %q calls a read failure trailing data", err)
		}
	})

	// The controls: both genuine trailing-data shapes stay invalid content.
	t.Run("a-second-document-is-invalid-content", func(t *testing.T) {
		dec := json.NewDecoder(strings.NewReader(`{"snmp":[]} {"snmp":[]}`))
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("decode: %v", err)
		}
		_ = assertInvalid(t, checkSingleDocument("resources/x.json", dec))
	})

	t.Run("trailing-garbage-is-invalid-content", func(t *testing.T) {
		dec := json.NewDecoder(strings.NewReader(`{"snmp":[]} ]`))
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("decode: %v", err)
		}
		err := checkSingleDocument("resources/x.json", dec)
		_ = assertInvalid(t, err)
		var syn *json.SyntaxError
		if !errors.As(err, &syn) {
			t.Errorf("error %q does not carry the syntax error as its cause", err)
		}
	})

	t.Run("a-clean-document-passes", func(t *testing.T) {
		dec := json.NewDecoder(strings.NewReader(`{"snmp":[]}`))
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if err := checkSingleDocument("resources/x.json", dec); err != nil {
			t.Errorf("a single clean document was rejected: %v", err)
		}
	})
}

// errReader fails every read with a fixed error, standing in for a mid-file
// I/O fault that cannot be staged portably.
type errReader struct{ err error }

func (r *errReader) Read([]byte) (int, error) { return 0, r.err }

// ── R13: bidi and zero-width runes, and the raised cap ─────────────────────

func TestSanitiseStripsBidiAndZeroWidthRunes(t *testing.T) {
	// Every rune that can restructure a rendered line without changing what
	// the bytes say. U+202E RIGHT-TO-LEFT OVERRIDE is the sharp one: it
	// reorders the VISIBLE text, so a crafted file name makes a log line or a
	// 400 body read as a different file from the one that failed.
	formatting := []rune{
		'\u200b', '\u200c', '\u200d', '\ufeff', // zero-width
		'\u200e', '\u200f', // LRM / RLM
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', // embedding / override
		'\u2066', '\u2067', '\u2068', '\u2069', // isolates
	}
	var hostile strings.Builder
	hostile.WriteString("a")
	for _, r := range formatting {
		hostile.WriteRune(r)
		hostile.WriteString("b")
	}

	e := &resourceFileError{File: hostile.String() + ".json", Msg: "bad" + hostile.String() + "value", kind: errResourceInvalid}
	for name, got := range map[string]string{"Error()": e.Error(), "PublicMessage()": e.PublicMessage()} {
		for _, r := range formatting {
			if strings.ContainsRune(got, r) {
				t.Errorf("%s = %q still contains formatting rune %U", name, got, r)
			}
		}
	}
	// Positive control: ordinary non-ASCII text is NOT mangled, so the
	// stripping cannot be a blanket "drop everything above 0x7f".
	keep := &resourceFileError{File: "ciena-wavelänge.json", Msg: "naïve", kind: errResourceInvalid}
	if !strings.Contains(keep.PublicMessage(), "wavelänge") || !strings.Contains(keep.PublicMessage(), "naïve") {
		t.Errorf("PublicMessage() = %q mangled ordinary non-ASCII text", keep.PublicMessage())
	}
}

// The cap must not cut the remediation off a realistic guard message. The
// sentinel message puts the quoted value early and "change the value" last.
func TestRealisticGuardMessageSurvivesTheCap(t *testing.T) {
	sm := classifyFixture(t)
	longValue := strings.Repeat("x", 90)
	dir := filepath.Join("resources", "capcheck")
	writeResourceFile(t, filepath.Join(dir, "capcheck_snmp_interfaces_and_more.json"),
		`{"snmp":[{"oid":"1.3.6.1.2.1.1.2.0","response":"`+longValue+`"}]}`)

	_, err := sm.LoadSpecificResources("capcheck.json")
	rerr := assertInvalid(t, err)
	msg := rerr.PublicMessage()
	if strings.Contains(msg, "(truncated)") {
		t.Errorf("a realistic guard message was truncated at %d bytes: %q", maxResourceMessageBytes, msg)
	}
	// The remediation is the tail, and it is the half that says how to fix it.
	if !strings.Contains(msg, "Correct the value") {
		t.Errorf("message %q lost its remediation tail", msg)
	}
}
