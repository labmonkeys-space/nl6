/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// nl6#555: LoadSpecificResources runs on the net/http handler goroutine (via
// resolveCreateResources), so two concurrent POST /api/v1/devices naming
// different device types hit sm.resourcesCache at the same time. An unguarded
// map answers that with a runtime throw(), which recover() cannot catch — the
// whole simulator dies, not the one request.
//
// These tests must be run under -race to be worth anything; CI gates on
// `make test-race`. Without the guard they report a data race deterministically
// under -race, and usually (not always — the runtime's concurrent-write
// detection is best-effort) a `fatal error: concurrent map writes` without it.
//
// THERE ARE TWO WRITE SITES and they are reached by different layouts: a
// device type shipped as a DIRECTORY publishes from loadSpecificResourcesFromDir,
// one shipped as a SINGLE FILE publishes from LoadSpecificResources itself.
// Every test here that only wrote directories left the single-file lock pinned
// by nothing — deleting it kept the suite green. Hence writeTypeFile and the
// mixed row below.
//
// Like the rest of the classification suite these use classifyFixture, which
// chdirs, so none of them may call t.Parallel.

// writeTypeDir writes a minimal, valid device-type DIRECTORY (the shipped
// layout) with one SNMP entry whose response names the type, so a caller can
// tell the loaded sets apart. Loads of it publish from
// loadSpecificResourcesFromDir.
func writeTypeDir(t *testing.T, slug string) {
	t.Helper()
	writeResourceFile(t, filepath.Join("resources", slug, "system.json"),
		fmt.Sprintf(`{"snmp":[{"oid":"1.3.6.1.2.1.1.1.0","response":%q}]}`, typeMarker(slug)))
}

// writeTypeFile writes the same content in the legacy SINGLE-FILE layout,
// which LoadSpecificResources takes whenever resources/<slug> does not exist.
// Loads of it publish from LoadSpecificResources' own write site.
func writeTypeFile(t *testing.T, slug string) {
	t.Helper()
	writeResourceFile(t, filepath.Join("resources", slug+".json"),
		fmt.Sprintf(`{"snmp":[{"oid":"1.3.6.1.2.1.1.1.0","response":%q}]}`, typeMarker(slug)))
}

// typeMarker is the per-type sysDescr, so a test can prove a load returned its
// OWN type's resources and not another's.
func typeMarker(slug string) string { return "sysDescr for " + slug }

// concurrently runs fn(i) on n goroutines that all start together. The
// ready-barrier matters: with only `close(start)` after the launch loop, a
// late goroutine can reach the channel after an early one has finished its
// whole load, and a green run is then weak evidence of anything. Every
// goroutine signals ready and only then blocks, so the accesses interleave.
func concurrently(n int, fn func(i int)) {
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(n)
	done.Add(n)
	for i := range n {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			fn(i)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
}

// assertLoaded is the per-goroutine result check shared by the rows below.
func assertLoaded(t *testing.T, slug string, res *DeviceResources, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("concurrent load of %s failed: %v", slug, err)
		return
	}
	if res == nil || len(res.SNMP) != 1 {
		t.Errorf("%s loaded %+v, want one SNMP entry", slug, res)
		return
	}
	if got, want := res.SNMP[0].Response, typeMarker(slug); got != want {
		t.Errorf("%s got response %q, want %q — a load returned another type's resources",
			slug, got, want)
	}
}

// Matrix row 1: N goroutines, N different types, in the DIRECTORY layout.
// This exercises the loadSpecificResourcesFromDir write site.
func TestConcurrentDistinctTypeLoads(t *testing.T) {
	sm := classifyFixture(t)

	const n = 16
	slugs := make([]string, n)
	for i := range slugs {
		slugs[i] = fmt.Sprintf("racedir_%02d", i)
		writeTypeDir(t, slugs[i])
	}

	got := make([]*DeviceResources, n)
	errs := make([]error, n)
	concurrently(n, func(i int) {
		got[i], errs[i] = sm.LoadSpecificResources(slugs[i] + ".json")
	})

	for i, slug := range slugs {
		assertLoaded(t, slug, got[i], errs[i])
	}
	assertCachedExactly(t, sm, slugs, got)
}

// Matrix row 1b: the same N-goroutine pattern over the SINGLE-FILE layout,
// which reaches the OTHER write site. Without this row, deleting the lock
// around LoadSpecificResources' own map write left every test in this file
// green under -race, so a fleet using single-file device types kept the
// nl6#555 throw() with CI reporting nothing.
func TestConcurrentDistinctSingleFileTypeLoads(t *testing.T) {
	sm := classifyFixture(t)

	const n = 16
	slugs := make([]string, n)
	for i := range slugs {
		slugs[i] = fmt.Sprintf("racefile_%02d", i)
		writeTypeFile(t, slugs[i])
	}

	got := make([]*DeviceResources, n)
	errs := make([]error, n)
	concurrently(n, func(i int) {
		got[i], errs[i] = sm.LoadSpecificResources(slugs[i] + ".json")
	})

	for i, slug := range slugs {
		assertLoaded(t, slug, got[i], errs[i])
	}
	assertCachedExactly(t, sm, slugs, got)
}

// Matrix row 1c: MIXED layouts. This is the shape that writes ONE map from
// TWO different code paths at the same time, which neither single-layout row
// above can produce, and it is what makes removing EITHER write lock fail.
func TestConcurrentMixedLayoutTypeLoads(t *testing.T) {
	sm := classifyFixture(t)

	const n = 16
	slugs := make([]string, n)
	for i := range slugs {
		if i%2 == 0 {
			slugs[i] = fmt.Sprintf("mixdir_%02d", i)
			writeTypeDir(t, slugs[i])
		} else {
			slugs[i] = fmt.Sprintf("mixfile_%02d", i)
			writeTypeFile(t, slugs[i])
		}
	}

	got := make([]*DeviceResources, n)
	errs := make([]error, n)
	concurrently(n, func(i int) {
		got[i], errs[i] = sm.LoadSpecificResources(slugs[i] + ".json")
	})

	for i, slug := range slugs {
		assertLoaded(t, slug, got[i], errs[i])
	}
	assertCachedExactly(t, sm, slugs, got)
}

// assertCachedExactly pins that every type is cached exactly once, under the
// pointer each caller was handed, and that the cache holds nothing else.
func assertCachedExactly(t *testing.T, sm *SimulatorManager, slugs []string, got []*DeviceResources) {
	t.Helper()
	sm.resourcesCacheMu.RLock()
	defer sm.resourcesCacheMu.RUnlock()
	if len(sm.resourcesCache) != len(slugs) {
		t.Fatalf("cache holds %d entries, want %d", len(sm.resourcesCache), len(slugs))
	}
	for i, slug := range slugs {
		cached, ok := sm.resourcesCache[slug+".json"]
		if !ok {
			t.Errorf("%s was not cached", slug)
			continue
		}
		if got[i] != nil && cached != got[i] {
			t.Errorf("%s: caller holds %p but the cache holds %p", slug, got[i], cached)
		}
	}
}

// Matrix row 2: N goroutines, ONE type. The lock is deliberately not held
// across the file I/O, so two goroutines may both miss and both build a set —
// one redundant load, accepted. What must NOT happen is both sets surviving:
// publishResources re-checks under the write lock, so every caller ends up
// holding the same object.
//
// The old closing assertion here was `len(cache) != 1`, which is true whatever
// the locking — sixteen goroutines writing one key can only make one entry, so
// it could not fail. Pointer identity across all sixteen callers is the
// property this row is actually for.
func TestConcurrentSameTypeLoads(t *testing.T) {
	sm := classifyFixture(t)
	writeTypeDir(t, "sametype")

	const n = 16
	got := make([]*DeviceResources, n)
	errs := make([]error, n)
	concurrently(n, func(i int) {
		got[i], errs[i] = sm.LoadSpecificResources("sametype.json")
	})

	for i := range n {
		assertLoaded(t, "sametype", got[i], errs[i])
	}
	for i := 1; i < n; i++ {
		if got[i] != got[0] {
			t.Fatalf("goroutine %d holds %p but goroutine 0 holds %p; two full "+
				"resource sets survived for one device type, so two devices of "+
				"that type would serve from different objects", i, got[i], got[0])
		}
	}
	assertCachedExactly(t, sm, []string{"sametype"}, got[:1])
}

// The same, in the single-file layout: publishResources is shared, but only
// this row proves the single-file branch actually routes through it rather
// than writing the map directly.
func TestConcurrentSameSingleFileTypeLoads(t *testing.T) {
	sm := classifyFixture(t)
	writeTypeFile(t, "samefile")

	const n = 16
	got := make([]*DeviceResources, n)
	errs := make([]error, n)
	concurrently(n, func(i int) {
		got[i], errs[i] = sm.LoadSpecificResources("samefile.json")
	})

	for i := range n {
		assertLoaded(t, "samefile", got[i], errs[i])
	}
	for i := 1; i < n; i++ {
		if got[i] != got[0] {
			t.Fatalf("goroutine %d holds %p but goroutine 0 holds %p", i, got[i], got[0])
		}
	}
	assertCachedExactly(t, sm, []string{"samefile"}, got[:1])
}

// Matrix row 3: a valid load and a rejected one racing. The rejection stays
// classified errResourceInvalid (nl6#538) and caches nothing — a lock that
// accidentally moved the write earlier would cache the invalid type.
//
// The absence of a cache entry is deliberate and not merely incidental: a
// rejected type is NOT negatively cached, so it stays re-triable once the
// operator fixes the file, without restarting the simulator. Caching the
// rejection would make a fixed file invisible for the life of the process.
// That is also why every goroutine below sees the SAME error rather than one
// rejection and fifteen cache hits.
func TestConcurrentLoadAndRejection(t *testing.T) {
	sm := classifyFixture(t)
	writeTypeDir(t, "goodtype")
	// A sentinel-colliding value: rejected by validateSNMPResourceValues
	// (nl6#523), which runs per part inside the directory loader.
	writeResourceFile(t, filepath.Join("resources", "badtype", "system.json"),
		`{"snmp":[`+rejectedEntry+`]}`)

	const n = 8
	goodErrs := make([]error, n)
	badErrs := make([]error, n)
	concurrently(2*n, func(i int) {
		if i%2 == 0 {
			_, goodErrs[i/2] = sm.LoadSpecificResources("goodtype.json")
		} else {
			_, badErrs[i/2] = sm.LoadSpecificResources("badtype.json")
		}
	})

	for i := range n {
		if goodErrs[i] != nil {
			t.Errorf("valid load %d failed: %v", i, goodErrs[i])
		}
		if !errors.Is(badErrs[i], errResourceInvalid) {
			t.Errorf("rejection %d is %v, not classified errResourceInvalid", i, badErrs[i])
		}
		if errors.Is(badErrs[i], errResourceNotFound) {
			t.Errorf("rejection %d is classified not-found as well as invalid: %v", i, badErrs[i])
		}
	}

	sm.resourcesCacheMu.RLock()
	defer sm.resourcesCacheMu.RUnlock()
	if _, cached := sm.resourcesCache["badtype.json"]; cached {
		t.Error("the rejected type was CACHED; a rejection must cache nothing so " +
			"the type stays re-triable after the operator fixes the file")
	}
	if _, cached := sm.resourcesCache["goodtype.json"]; !cached {
		t.Error("the valid type was not cached")
	}
}

// Matrix row 4 (nl6#519): the evict is the THIRD sibling of the seam, and it
// takes the same lock. N goroutines load distinct types while N others evict
// everything; without resourcesCacheMu around the delete this is a concurrent
// map write against the publish. A RACE-DETECTOR pin: it fails only under
// -race (or by the runtime's best-effort concurrent-write throw).
//
// The evicts contend for createBatchGate too, so some are refused with the
// nl6#565 sentinel; that is the contract (a reload borrows the gate, so two
// reloads exclude each other as well) and not a failure. What must hold is
// that every load returns its own type's set and every reload that ran left
// the cache holding only sets that were loaded, never a half-written map.
//
// Every contender LOOPS, and the cache is PRE-LOADED. A first cut ran one
// load and one reload per goroutine from a cold cache, and the lock could be
// deleted from the evict with the row green three runs out of three: the
// reloads all ran while the loads were still in their file I/O, found an
// empty cache, and deleted nothing — so no delete ever overlapped a publish
// and the detector had nothing to pair (the nl6#556 lesson, again).
func TestConcurrentEvictAndLoad(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)

	const (
		n     = 16
		loops = 40
	)
	// MIXED layouts, so both publish sites race the evict (the nl6#555
	// lesson: a directory-only row leaves LoadSpecificResources' own write
	// site pinned by nothing).
	slugs := make([]string, n)
	for i := range slugs {
		if i%2 == 0 {
			slugs[i] = fmt.Sprintf("evictracedir_%02d", i)
			writeTypeDir(t, slugs[i])
		} else {
			slugs[i] = fmt.Sprintf("evictracefile_%02d", i)
			writeTypeFile(t, slugs[i])
		}
		if _, err := sm.LoadSpecificResources(slugs[i] + ".json"); err != nil {
			t.Fatal(err)
		}
	}

	got := make([]*DeviceResources, n)
	errs := make([]error, n)
	reloadErrs := make([]error, n)
	concurrently(2*n, func(i int) {
		for range loops {
			if i%2 == 0 {
				got[i/2], errs[i/2] = sm.LoadSpecificResources(slugs[i/2] + ".json")
				if errs[i/2] != nil {
					return
				}
			} else {
				if _, err := sm.ReloadResources(""); err != nil && !errors.Is(err, errCreateBatchInProgress) {
					reloadErrs[i/2] = err
					return
				}
			}
		}
	})

	for i, slug := range slugs {
		assertLoaded(t, slug, got[i], errs[i])
	}
	for i, err := range reloadErrs {
		if err != nil {
			t.Errorf("reload %d failed with %v; the only refusal a reload may hear is the batch sentinel", i, err)
		}
	}
	sm.resourcesCacheMu.RLock()
	defer sm.resourcesCacheMu.RUnlock()
	for key, cached := range sm.resourcesCache {
		if cached == nil || len(cached.SNMP) != 1 {
			t.Errorf("cache holds a half-built set under %s: %+v", key, cached)
		}
	}
}

// Matrix row 5 (nl6#519): the device walk that counts who still holds an
// evicted set reads sm.devices, which DeleteDevice writes without the batch
// gate. The walk must run under sm.mu.RLock. A RACE-DETECTOR pin: a spinning
// goroutine churns the device map under sm.mu.Lock while reloads walk it, and
// dropping the RLock around the walk is reported deterministically under
// -race. The churner spins rather than running a bounded loop so it is still
// writing when the walks happen (the nl6#556 lesson).
func TestConcurrentReloadAndDeviceChurn(t *testing.T) {
	silenceCreateGateLogs(t)
	sm := classifyFixture(t)
	sm.devices = make(map[string]*DeviceSimulator)
	writeTypeDir(t, "churn")
	res, err := sm.LoadSpecificResources("churn.json")
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	running := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(running)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			key := fmt.Sprintf("10.42.%d.%d", (i/256)%256, i%256)
			sm.mu.Lock()
			if _, exists := sm.devices[key]; exists {
				delete(sm.devices, key)
			} else {
				sm.devices[key] = &DeviceSimulator{resources: res}
			}
			sm.mu.Unlock()
		}
	}()
	<-running

	for i := 0; i < 200; i++ {
		if _, err := sm.LoadSpecificResources("churn.json"); err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		if _, err := sm.ReloadResources("churn.json"); err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
	}
	close(stop)
	<-done
}
