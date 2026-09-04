/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nl6#519: device profiles were read into resourcesCache at first use and never
// again, so verifying a one-line profile fix cost a container restart and a
// fleet rebuild. POST /api/v1/resources/reload EVICTS cache entries so the next
// creation reads the file as it is now. It never mutates a cached set: a
// running device holds a pointer to the *DeviceResources it was built with and
// serves from indexes built ON that struct, so rewriting it would change what
// every device of that type answers mid-walk.
//
// The two rows that matter most are TestReloadedProfileIsServedByTheNextDevice
// (pre-evict device keeps the OLD value through a real findResponse, post-evict
// device serves the NEW one, in BOTH resource layouts) and
// TestReloadDuringABatchIs409 (proved INSIDE a real batch through
// createBatchStageProbe, never against a mirror of the gate).
//
// Every test here uses classifyFixture, which chdirs, so none may t.Parallel.

const sysDescrOID = ".1.3.6.1.2.1.1.1.0"

// writeTypeDirWith is writeTypeDir with a caller-chosen sysDescr, so a test can
// edit a profile on disk between two loads and tell the two apart.
func writeTypeDirWith(t *testing.T, slug, sysDescr string) {
	t.Helper()
	writeResourceFile(t, filepath.Join("resources", slug, "system.json"),
		`{"snmp":[{"oid":"1.3.6.1.2.1.1.1.0","response":`+jsonString(sysDescr)+`}]}`)
}

// writeTypeFileWith is the single-file twin of writeTypeDirWith. Every reload
// test that only wrote directories left LoadSpecificResources' own publish
// site (the single-file layout) pinned by nothing — the nl6#555 lesson.
func writeTypeFileWith(t *testing.T, slug, sysDescr string) {
	t.Helper()
	writeResourceFile(t, filepath.Join("resources", slug+".json"),
		`{"snmp":[{"oid":"1.3.6.1.2.1.1.1.0","response":`+jsonString(sysDescr)+`}]}`)
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// mustLoad loads a type through the production loader and fails the test on
// any error.
func mustLoad(t *testing.T, sm *SimulatorManager, key string) *DeviceResources {
	t.Helper()
	res, err := sm.LoadSpecificResources(key)
	if err != nil {
		t.Fatalf("LoadSpecificResources(%s): %v", key, err)
	}
	return res
}

// mustReload runs a reload and fails the test on any error.
func mustReload(t *testing.T, sm *SimulatorManager, key string) ReloadReport {
	t.Helper()
	report, err := sm.ReloadResources(key)
	if err != nil {
		t.Fatalf("ReloadResources(%q): %v", key, err)
	}
	return report
}

// deviceOn builds the smallest device that serves from a resource set, the way
// the octet-shadow tests do, so a test can ask the REAL findResponse what a
// device answers rather than reading the struct's fields.
func deviceOn(res *DeviceResources) *SNMPServer {
	return &SNMPServer{device: &DeviceSimulator{resources: res}}
}

// cachedKeys reads the cache's key set under its own lock.
func cachedKeys(sm *SimulatorManager) []string {
	sm.resourcesCacheMu.RLock()
	defer sm.resourcesCacheMu.RUnlock()
	keys := make([]string, 0, len(sm.resourcesCache))
	for k := range sm.resourcesCache {
		keys = append(keys, k)
	}
	return keys
}

// Matrix row: evict all. Every cached key is reported, sorted, and the cache is
// empty afterwards.
func TestReloadEvictsEveryCachedKey(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	for _, slug := range []string{"reload_b", "reload_a", "reload_c"} {
		writeTypeDir(t, slug)
		mustLoad(t, sm, slug+".json")
	}

	report := mustReload(t, sm, "")
	want := []string{"reload_a.json", "reload_b.json", "reload_c.json"}
	if strings.Join(report.Evicted, ",") != strings.Join(want, ",") {
		t.Errorf("evicted = %v, want %v (sorted)", report.Evicted, want)
	}
	for _, key := range want {
		if n, ok := report.DevicesOnOldSnapshot[key]; !ok || n != 0 {
			t.Errorf("devices_on_old_snapshot[%s] = %d (present=%v), want 0 for a fleet with no devices", key, n, ok)
		}
		if present, ok := report.PresentOnDisk[key]; !ok || !present {
			t.Errorf("present_on_disk[%s] = %v (present=%v), want true", key, present, ok)
		}
	}
	if report.Note != reloadNote {
		t.Error("the report carries a note other than reloadNote; a caller must be told existing " +
			"devices keep their snapshot and that catalogs are not reloaded")
	}
	if keys := cachedKeys(sm); len(keys) != 0 {
		t.Errorf("cache still holds %v after an evict-all", keys)
	}
}

// Matrix row: evict one. Only the named key goes; the others are untouched,
// pointer-identical to what they were.
func TestReloadEvictsOneKeyOnly(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	writeTypeDir(t, "keep_me")
	writeTypeDir(t, "drop_me")
	keep := mustLoad(t, sm, "keep_me.json")
	mustLoad(t, sm, "drop_me.json")

	report := mustReload(t, sm, "drop_me.json")
	if len(report.Evicted) != 1 || report.Evicted[0] != "drop_me.json" {
		t.Errorf("evicted = %v, want [drop_me.json]", report.Evicted)
	}
	if _, listed := report.DevicesOnOldSnapshot["keep_me.json"]; listed {
		t.Error("the report counts devices for a key it did not evict")
	}
	still, ok := sm.cachedResources("keep_me.json")
	if !ok || still != keep {
		t.Errorf("keep_me.json: cached=%v pointer=%p want the original %p; a single-key evict touched another key", ok, still, keep)
	}
	if _, ok := sm.cachedResources("drop_me.json"); ok {
		t.Error("drop_me.json is still cached after being evicted")
	}
}

// Matrix row: unknown key, which is TWO answers and not one. A profile that is
// shipped but never loaded is refused with the not-cached sentinel (404) and
// told the next creation reads from disk anyway — true. A name that is NOT
// shipped (a typo) is errResourceNotFound (400), the classification
// LoadSpecificResources gives it, because "the next creation reads from disk"
// would be false advice about a type that does not exist. A malformed name is
// errResourceInvalid (400) and never reaches the filesystem.
func TestReloadUnknownKeyIsRefused(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	writeTypeDir(t, "present")
	writeTypeDir(t, "shipped_uncached")
	writeTypeFile(t, "shipped_uncached_file")
	mustLoad(t, sm, "present.json")

	for _, key := range []string{"shipped_uncached.json", "shipped_uncached_file.json"} {
		_, err := sm.ReloadResources(key)
		if !errors.Is(err, errResourceNotCached) {
			t.Fatalf("%s: error = %v, want errResourceNotCached", key, err)
		}
		if !strings.Contains(err.Error(), key) {
			t.Errorf("refusal %q does not name the key", err)
		}
	}

	_, err := sm.ReloadResources("nope.json")
	if !errors.Is(err, errResourceNotFound) {
		t.Fatalf("unshipped name: error = %v, want errResourceNotFound (400)", err)
	}
	if errors.Is(err, errResourceNotCached) {
		t.Fatal("an unshipped name was classified not-cached; it would be told the next creation reads it from disk")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("refusal %q does not name the type", err)
	}
	if _, ok := sm.cachedResources("present.json"); !ok {
		t.Error("a refused single-key reload evicted an unrelated key")
	}

	_, err = sm.ReloadResources("../etc/passwd")
	if !errors.Is(err, errResourceInvalid) {
		t.Fatalf("malformed name: error = %v, want errResourceInvalid (400)", err)
	}
}

// Matrix row: nothing cached. 200 with an EMPTY list, which must serialise as
// `[]` and not `null` — a client iterating the field must not have to
// special-case the empty fleet.
func TestReloadWithNothingCachedIsEmptyNotNull(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)

	report := mustReload(t, sm, "")
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"evicted":[]`, `"devices_on_old_snapshot":{}`, `"present_on_disk":{}`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body %s does not carry %s", body, want)
		}
	}
}

// The two rows that matter most, in one test because they are one scenario:
// a device built from profile P, P edited on disk, reload, a second device
// created. The first still serves the pre-edit value THROUGH findResponse and
// still holds its original pointer; the second serves the post-edit value from
// a different object. Run in BOTH layouts, because each publishes from a
// different write site.
//
// Pointer identity AND the served value are both asserted because they catch
// different mutations. An evict that REWROTE the cached struct in place from
// disk would keep the pointer and change the old device's answer (the value
// assertion catches it). An evict that zeroed the struct and kept the key would
// hand the next load the zeroed set (the new device's value catches it).
func TestReloadedProfileIsServedByTheNextDevice(t *testing.T) {
	run := func(t *testing.T, slug string, write func(t *testing.T, slug, sysDescr string)) {
		silenceCreateGateLogs(t)
		sm := classifyFixture(t)
		write(t, slug, "before the edit")
		key := slug + ".json"
		before := mustLoad(t, sm, key)
		oldDevice := deviceOn(before)
		if got := oldDevice.findResponse(sysDescrOID); got != "before the edit" {
			t.Fatalf("pre-edit device answers %q, want the pre-edit value", got)
		}

		// Edit the profile on disk, then reload. Order does not matter for
		// the contract (the cache is keyed, not watched), but this is the
		// operator's order.
		write(t, slug, "after the edit")
		report := mustReload(t, sm, key)
		if len(report.Evicted) != 1 {
			t.Fatalf("evicted = %v, want exactly the edited key", report.Evicted)
		}

		after := mustLoad(t, sm, key)
		if after == before {
			t.Fatal("the load after the reload returned the SAME pointer: nothing was evicted, so the " +
				"next device would serve the pre-edit profile")
		}
		newDevice := deviceOn(after)
		if got := newDevice.findResponse(sysDescrOID); got != "after the edit" {
			t.Errorf("post-reload device answers %q, want the edited value", got)
		}
		if got := oldDevice.findResponse(sysDescrOID); got != "before the edit" {
			t.Errorf("pre-reload device answers %q after the reload, want the value it was built "+
				"with; the cached struct was mutated in place", got)
		}
		if oldDevice.device.resources != before {
			t.Error("the pre-reload device's pointer moved; a device must never be re-pointed by a reload")
		}
		if cached, _ := sm.cachedResources(key); cached != after {
			t.Errorf("cache holds %p after the second load, want the freshly loaded %p", cached, after)
		}
	}
	t.Run("directory-layout", func(t *testing.T) { run(t, "edited_dir", writeTypeDirWith) })
	t.Run("single-file-layout", func(t *testing.T) { run(t, "edited_file", writeTypeFileWith) })
}

// devices_on_old_snapshot counts per KEY, not per evicted pointer. Across two
// generations a pointer comparison UNDER-COUNTS: devices A and B from gen1,
// reload, device C from gen2, reload again — A and B are still on a
// pre-reload snapshot but hold a pointer no longer in the cache, so comparing
// against the pointer evicted NOW reports 1 where 3 is the truth. Also: a
// device of another type is not counted, and a device with NO resource_file
// is attributed to defaultResourceKey.
func TestReloadCountsDevicesOnTheOldSnapshotAcrossGenerations(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	sm.devices = make(map[string]*DeviceSimulator)
	writeTypeDir(t, "counted")
	writeTypeDir(t, "other")
	writeTypeDir(t, "asr9k")
	gen1 := mustLoad(t, sm, "counted.json")
	other := mustLoad(t, sm, "other.json")
	dflt := mustLoad(t, sm, "asr9k.json")
	sm.defaultResourceKey = "asr9k.json"
	sm.deviceResources = dflt

	sm.devices["A"] = &DeviceSimulator{resources: gen1, resourceFile: "counted.json"}
	sm.devices["B"] = &DeviceSimulator{resources: gen1, resourceFile: "counted.json"}
	sm.devices["O"] = &DeviceSimulator{resources: other, resourceFile: "other.json"}
	sm.devices["D"] = &DeviceSimulator{resources: dflt, resourceFile: ""} // a plain create

	report := mustReload(t, sm, "counted.json")
	if got := report.DevicesOnOldSnapshot["counted.json"]; got != 2 {
		t.Errorf("gen1: devices_on_old_snapshot[counted.json] = %d, want 2", got)
	}
	if len(report.DevicesOnOldSnapshot) != 1 {
		t.Errorf("report counts %v; only the evicted key belongs there", report.DevicesOnOldSnapshot)
	}

	gen2 := mustLoad(t, sm, "counted.json")
	if gen2 == gen1 {
		t.Fatal("gen2 is gen1; the evict did not happen")
	}
	sm.devices["C"] = &DeviceSimulator{resources: gen2, resourceFile: "counted.json"}

	report = mustReload(t, sm, "counted.json")
	if got := report.DevicesOnOldSnapshot["counted.json"]; got != 3 {
		t.Errorf("gen2: devices_on_old_snapshot[counted.json] = %d, want 3 — A and B are still on a "+
			"pre-reload snapshot even though the pointer evicted NOW is gen2's", got)
	}

	// Evict-all: `other` and the default are left. The plain-create device
	// counts under the default's key.
	report = mustReload(t, sm, "")
	if strings.Join(report.Evicted, ",") != "asr9k.json,other.json" {
		t.Errorf("evicted = %v, want [asr9k.json other.json]", report.Evicted)
	}
	if got := report.DevicesOnOldSnapshot["other.json"]; got != 1 {
		t.Errorf("devices_on_old_snapshot[other.json] = %d, want 1", got)
	}
	if got := report.DevicesOnOldSnapshot["asr9k.json"]; got != 1 {
		t.Errorf("devices_on_old_snapshot[asr9k.json] = %d, want 1: the device created with no "+
			"resource_file resolved through the default key and must be attributed to it", got)
	}
	// The startup pointer itself is never written by a reload.
	if sm.deviceResources != dflt || sm.devices["D"].resources != dflt {
		t.Error("a reload touched sm.deviceResources or the device serving from it")
	}
}

// The default profile goes THROUGH the cache (nl6#519, renegotiated): a create
// naming "asr9k.json" and one naming nothing resolve to ONE object, so a reload
// of that key covers the whole -auto-start-ip fleet's profile. Pinned at
// resolveCreateResources, the production resolver both creation paths use,
// because the constructor below it cannot run without a listener bind.
func TestDefaultProfileResolvesThroughTheCache(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	writeTypeDirWith(t, "asr9k", "the default before")
	if err := loadDefaultResources(sm); err != nil {
		t.Fatal(err)
	}
	if sm.defaultResourceKey != "asr9k.json" {
		t.Fatalf("defaultResourceKey = %q, want asr9k.json", sm.defaultResourceKey)
	}
	cached, ok := sm.cachedResources("asr9k.json")
	if !ok || cached != sm.deviceResources {
		t.Fatalf("startup default is not the cached object (cached=%v %p, deviceResources=%p)", ok, cached, sm.deviceResources)
	}

	named, _, _, err := sm.resolveCreateResources(false, "", "asr9k.json")
	if err != nil {
		t.Fatal(err)
	}
	plain, _, _, err := sm.resolveCreateResources(false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if named != plain || named != cached {
		t.Fatalf("explicit asr9k.json resolves to %p, no resource_file to %p, cache holds %p; want ONE object", named, plain, cached)
	}

	// Edit, reload, and the plain create serves the edit.
	writeTypeDirWith(t, "asr9k", "the default after")
	report := mustReload(t, sm, "asr9k.json")
	if len(report.Evicted) != 1 {
		t.Fatalf("evicted = %v", report.Evicted)
	}
	plain2, _, _, err := sm.resolveCreateResources(false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if plain2 == plain {
		t.Fatal("a plain create after the reload still resolves to the pre-reload object")
	}
	if got := deviceOn(plain2).findResponse(sysDescrOID); got != "the default after" {
		t.Errorf("plain create after the reload answers %q, want the edited default", got)
	}
	if got := deviceOn(plain).findResponse(sysDescrOID); got != "the default before" {
		t.Errorf("the pre-reload default set now answers %q; it was mutated", got)
	}
}

// The compiled-in fallback (no asr9k directory or file anywhere, so
// LoadResources synthesises the file) stays OUT of the cache: defaultResourceKey
// is empty, a plain create reads sm.deviceResources, and a reload of everything
// evicts nothing and never touches it.
func TestSynthesisedDefaultStaysOutOfTheCache(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	if err := loadDefaultResources(sm); err != nil {
		t.Fatal(err)
	}
	if sm.defaultResourceKey != "" {
		t.Fatalf("defaultResourceKey = %q, want empty for the synthesised default", sm.defaultResourceKey)
	}
	if keys := cachedKeys(sm); len(keys) != 0 {
		t.Fatalf("the synthesised default was cached under %v", keys)
	}
	plain, _, _, err := sm.resolveCreateResources(false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if plain != sm.deviceResources {
		t.Fatal("a plain create did not resolve to sm.deviceResources on the synthesised path")
	}
	report := mustReload(t, sm, "")
	if len(report.Evicted) != 0 || sm.deviceResources != plain {
		t.Errorf("a reload evicted %v or moved sm.deviceResources", report.Evicted)
	}
}

// Matrix row: batch in progress. Proved INSIDE a real batch through
// createBatchStageProbe: at every stage the reload is refused with the nl6#565
// sentinel and the cache is unchanged, and once the batch has returned the
// same reload succeeds. Standing inside the batch is what makes this a pin on
// the gate ACQUISITION rather than on a mirror of it — a reload that skipped
// the gate would succeed mid-batch, which is the stale-republish hazard the
// gate exists to make impossible.
func TestReloadDuringABatchIs409(t *testing.T) {
	silenceCreateGateLogs(t)
	withFakeEuid(t, 0)

	sm := newCreateGateRESTManager(t)
	t.Cleanup(sm.CleanupPreAllocatedInterfaces)
	loaded := mustLoad(t, sm, "gategood.json")

	var refusals int
	withCreateBatchProbe(t, func(stage createBatchStage) error {
		_, err := sm.ReloadResources("")
		if !errors.Is(err, errCreateBatchInProgress) {
			t.Errorf("at stage %s a reload was answered %v, want errCreateBatchInProgress", stage, err)
		} else {
			refusals++
			// The BATCH is named, not a reload: the holder kind is diagnosed.
			if !strings.Contains(err.Error(), "batch #") || strings.Contains(err.Error(), "profile reload") {
				t.Errorf("at stage %s the refusal %q does not name the running batch", stage, err)
			}
		}
		if cached, ok := sm.cachedResources("gategood.json"); !ok || cached != loaded {
			t.Errorf("at stage %s the cache changed under a refused reload (cached=%v %p, want %p)",
				stage, ok, cached, loaded)
		}
		if stage == stageBeforeIPWalk {
			return &probeAbortError{stage: stage, cursor: snapshotCursor(sm)}
		}
		return nil
	})

	_, err := sm.CreateDevicesWithOptions("10.42.0.1", 1, "16", "gategood.json", nil, false, 0, false, "", 161, nil)
	var abort *probeAbortError
	if !errors.As(err, &abort) {
		t.Fatalf("error = %v, want the probe's abort; the batch never reached the IP walk", err)
	}
	if refusals != 3 {
		t.Fatalf("the reload was refused at %d stages, want all 3", refusals)
	}

	report := mustReload(t, sm, "")
	if len(report.Evicted) != 1 || report.Evicted[0] != "gategood.json" {
		t.Errorf("evicted = %v after the batch, want [gategood.json]", report.Evicted)
	}
	if held, err := gateIsHeld(sm); err != nil {
		t.Fatal(err)
	} else if held {
		t.Fatal("the gate is still held after a successful reload")
	}
}

// The invalid-name check runs BEFORE the gate: with a batch holding it, a
// malformed name is still the 400, never the 409. Moving the name check below
// the TryLock passed every other test.
func TestReloadInvalidNameIsRefusedBeforeTheGate(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	release, err := sm.tryEnterCreateBatch(7)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	_, err = sm.ReloadResources("../x")
	if !errors.Is(err, errResourceInvalid) {
		t.Fatalf("error = %v, want errResourceInvalid: the name check sits below the gate", err)
	}
	if errors.Is(err, errCreateBatchInProgress) {
		t.Fatal("a malformed name was answered with the batch sentinel")
	}
}

// The gate is held for the WHOLE evict, and the CREATE side of the exclusion
// is observed: while a reload is in progress, tryEnterCreateBatch is refused
// and its message names a RELOAD, not a batch. Replacing the deferred unlock
// with an immediate one after the TryLock left every other test green, so the
// observation is made THROUGH reloadWalkProbe, which fires after the last
// evict and before the device walk — the end of the evict loop.
func TestReloadHoldsTheGateThroughTheEvictAndRefusesACreate(t *testing.T) {
	silenceCreateGateLogs(t)
	classifyFixture(t)
	// newCreateGateManager: GetStatus reads the atomic.Value fields, which the
	// bare classifyFixture manager never stores.
	sm := newCreateGateManager()
	writeTypeDir(t, "spanned")
	mustLoad(t, sm, "spanned.json")

	var observed bool
	var createErr error
	var held bool
	var batchDuring *createBatchInfo
	var statusDuring ManagerStatus
	withReloadWalkProbe(t, func() {
		observed = true
		held, _ = gateIsHeld(sm)
		_, createErr = sm.tryEnterCreateBatch(3)
		batchDuring = sm.createBatch.Load()
		statusDuring = sm.GetStatus()
	})

	mustReload(t, sm, "spanned.json")
	if !observed {
		t.Fatal("the probe did not fire")
	}
	if !held {
		t.Fatal("the gate is NOT held at the end of the evict loop")
	}
	if !errors.Is(createErr, errCreateBatchInProgress) {
		t.Fatalf("a create during a reload was answered %v, want the batch sentinel", createErr)
	}
	if !strings.Contains(createErr.Error(), "profile reload") || strings.Contains(createErr.Error(), "shared cursor") {
		t.Errorf("refusal %q does not diagnose a RELOAD holder; a create was told a batch is running", createErr)
	}
	// A reload must not publish a 0-device batch, and the status surface
	// must still show that the gate is held.
	if batchDuring != nil {
		t.Errorf("createBatch = %+v during a reload, want nil: a reload is not a batch", batchDuring)
	}
	if statusDuring.CreateBatchInProgress {
		t.Error("create_batch_in_progress read true during a reload")
	}
	if !statusDuring.ResourceReloadInProgress {
		t.Error("resource_reload_in_progress read false during a reload; a 409'd client polling status could not see the holder")
	}
	if sm.resourceReload.Load() != nil || sm.GetStatus().ResourceReloadInProgress {
		t.Error("the reload token is still published after the reload returned")
	}
	if held, _ := gateIsHeld(sm); held {
		t.Fatal("the gate is still held after the reload returned")
	}
}

// withReloadWalkProbe installs the reload's stage probe for the test. Set
// before the reload and cleared after it returns, so the var itself is never
// accessed concurrently.
func withReloadWalkProbe(t *testing.T, probe func()) {
	t.Helper()
	prev := reloadWalkProbe
	reloadWalkProbe = probe
	t.Cleanup(func() { reloadWalkProbe = prev })
}

// Matrix row: bad file after evict. The next creation fails with the nl6#538
// classification and caches nothing — a rejection is never cached, so fixing
// the file and creating again works without another reload.
func TestBadFileAfterEvictIsRejectedAndNotCached(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	writeTypeDir(t, "breakme")
	mustLoad(t, sm, "breakme.json")
	mustReload(t, sm, "breakme.json")

	writeResourceFile(t, filepath.Join("resources", "breakme", "system.json"), `{"snmp":[`+rejectedEntry+`]}`)
	if _, err := sm.LoadSpecificResources("breakme.json"); !errors.Is(err, errResourceInvalid) {
		t.Fatalf("load after evict: error = %v, want errResourceInvalid", err)
	}
	if _, cached := sm.cachedResources("breakme.json"); cached {
		t.Fatal("the rejected profile was cached")
	}

	writeTypeDir(t, "breakme")
	if _, err := sm.LoadSpecificResources("breakme.json"); err != nil {
		t.Fatalf("load after the fix: %v; the rejection was cached, so the fix is invisible", err)
	}
}

// present_on_disk reports a profile removed since it was loaded NOW, not at
// the next create.
func TestReloadReportsAProfileRemovedFromDisk(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	writeTypeDir(t, "gone")
	writeTypeDir(t, "stays")
	mustLoad(t, sm, "gone.json")
	mustLoad(t, sm, "stays.json")
	if err := os.RemoveAll(filepath.Join("resources", "gone")); err != nil {
		t.Fatal(err)
	}
	report := mustReload(t, sm, "")
	if report.PresentOnDisk["gone.json"] || !report.PresentOnDisk["stays.json"] {
		t.Errorf("present_on_disk = %v, want gone:false stays:true", report.PresentOnDisk)
	}
	if len(report.Evicted) != 2 {
		t.Errorf("evicted = %v; a profile missing from disk is still evicted", report.Evicted)
	}
}

// The REST surface, every status in the matrix: 200 for all and for one, 404
// for a shipped-but-uncached key, 400 for an unshipped one, 409 with
// Retry-After during a batch, 400 for a malformed body, an unknown field, a
// trailing second object and an explicit empty resource_file, 413 for an
// over-long body.
func TestReloadResourcesHandler(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	t.Cleanup(swapGlobalManager(sm))
	router := setupRoutes()

	post := func(body string) *httptest.ResponseRecorder {
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(http.MethodPost, "/api/v1/resources/reload", nil)
		} else {
			r = httptest.NewRequest(http.MethodPost, "/api/v1/resources/reload", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, r)
		return rr
	}
	decode := func(t *testing.T, rr *httptest.ResponseRecorder) ReloadReport {
		t.Helper()
		var env struct {
			Success bool         `json:"success"`
			Data    ReloadReport `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode %s: %v", rr.Body.String(), err)
		}
		if !env.Success {
			t.Fatalf("success=false in %s", rr.Body.String())
		}
		return env.Data
	}

	t.Run("no-body-evicts-all", func(t *testing.T) {
		writeTypeDir(t, "h_one")
		writeTypeDir(t, "h_two")
		mustLoad(t, sm, "h_one.json")
		mustLoad(t, sm, "h_two.json")
		rr := post("")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		report := decode(t, rr)
		if strings.Join(report.Evicted, ",") != "h_one.json,h_two.json" {
			t.Errorf("evicted = %v", report.Evicted)
		}
		// Pinned by identity, not by a substring of prose.
		if report.Note != reloadNote {
			t.Errorf("note = %q, want reloadNote", report.Note)
		}
	})

	t.Run("one-key", func(t *testing.T) {
		writeTypeDir(t, "h_one")
		writeTypeDir(t, "h_two")
		mustLoad(t, sm, "h_one.json")
		mustLoad(t, sm, "h_two.json")
		rr := post(`{"resource_file":"h_one.json"}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		if report := decode(t, rr); strings.Join(report.Evicted, ",") != "h_one.json" {
			t.Errorf("evicted = %v, want [h_one.json]", report.Evicted)
		}
		if _, ok := sm.cachedResources("h_two.json"); !ok {
			t.Error("h_two.json was evicted by a single-key request")
		}
	})

	t.Run("shipped-but-uncached-is-404", func(t *testing.T) {
		writeTypeDir(t, "h_uncached")
		rr := post(`{"resource_file":"h_uncached.json"}`)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "h_uncached.json") {
			t.Errorf("body %s does not name the key", rr.Body.String())
		}
	})

	t.Run("unshipped-is-400", func(t *testing.T) {
		rr := post(`{"resource_file":"nope.json"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "nope") {
			t.Errorf("body %s does not name the type", rr.Body.String())
		}
		assertNoPathDisclosure(t, rr.Body.String())
	})

	t.Run("empty-cache-is-200-with-empty-list", func(t *testing.T) {
		mustReload(t, sm, "")
		rr := post(`{}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"evicted":[]`) {
			t.Errorf("body %s does not carry evicted:[]", rr.Body.String())
		}
	})

	t.Run("batch-in-progress-is-409-with-retry-after", func(t *testing.T) {
		writeTypeDir(t, "h_held")
		held := mustLoad(t, sm, "h_held.json")
		release, err := sm.tryEnterCreateBatch(4242)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		rr := post("")
		if rr.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409; body=%s", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("Retry-After"); got != createConflictRetryAfterSeconds {
			t.Errorf("Retry-After = %q, want %q", got, createConflictRetryAfterSeconds)
		}
		if !strings.Contains(rr.Body.String(), "4242") {
			t.Errorf("body %s does not name the running batch", rr.Body.String())
		}
		if cached, ok := sm.cachedResources("h_held.json"); !ok || cached != held {
			t.Error("a 409'd reload changed the cache")
		}
		// A malformed name under a held gate is still the 400 (name check
		// precedes the gate).
		if rr := post(`{"resource_file":"../x"}`); rr.Code != http.StatusBadRequest {
			t.Errorf("malformed name under a held gate: status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("malformed-bodies-are-400", func(t *testing.T) {
		for _, body := range []string{`{`, `{"resource_fil":"x.json"}`, `{"resource_file":"a.json"}{"resource_file":"b.json"}`, `{"resource_file":"../x"}`, `{"resource_file":""}`} {
			rr := post(body)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("body %s: status = %d, want 400; response=%s", body, rr.Code, rr.Body.String())
			}
		}
	})

	t.Run("oversized-body-is-413", func(t *testing.T) {
		rr := post(`{"resource_file":"` + strings.Repeat("a", 5<<10) + `.json"}`)
		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// TestResourceIsShippedRefusesAnUnvalidatedName pins that the stat helper is
// SELF-GUARDING. ReloadResources validates the name before calling it, but a
// free function that builds a filesystem path from a string must refuse a bad
// one itself: a future caller that skips the check would otherwise stat
// "resources/../x" -- the go/path-injection class CodeQL flagged here (#634).
// Asserted on the helper directly, since the handler path is already covered
// by the caller's own check and could not see this regression.
func TestResourceIsShippedRefusesAnUnvalidatedName(t *testing.T) {
	for _, bad := range []string{"../etc.json", "a/b.json", "x.json.json/../y.json", "", "nojson"} {
		shipped, err := resourceIsShipped(bad)
		if err == nil || shipped {
			t.Errorf("resourceIsShipped(%q) = (%v, %v), want (false, error): the helper trusted "+
				"its caller to have validated the name and built a path from it", bad, shipped, err)
		}
		if err != nil && !errors.Is(err, errResourceInvalid) {
			t.Errorf("resourceIsShipped(%q) error is not errResourceInvalid: %v", bad, err)
		}
	}
}
