/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// nl6#565: device IP allocation is a shared cursor, not a reservation, because
// CreateDevicesWithOptions rewinds currentIP to the batch start after
// pre-allocation. Two overlapping batches therefore hand out overlapping
// addresses, and the deviceIPs collision check absorbs the overlap as "already
// exists" — so the second batch silently creates fewer devices than requested
// and reports success. The fix admits one batch at a time and refuses the
// second with 409 Conflict.
//
// Which kind of pin each test here is, since the two are not interchangeable:
//
//   - VALUE pins (fail on an assertion, with or without -race):
//     TestCreateBatchGateAdmitsExactlyOneBatch,
//     TestConcurrentCreateIsRefusedWithTheSentinel,
//     TestCreateDevicesHandlerAnswers409ForAConcurrentBatch,
//     TestCreateBatchGateIsReleasedOnEveryExitPath,
//     TestGatedBatchesNeverOverlapOnDeviceIPs,
//     TestGateSpansThePreAllocationWindow,
//     TestCreateBatchSentinelIsClassified409.
//   - RACE-DETECTOR support: every concurrent test above also runs the real
//     locked fields under -race, but none of them RELIES on the detector: the
//     defect this closes is a wrong VALUE (an overlapping IP range), not an
//     unsynchronised access — nl6#556 already locked the fields.
//
// Not covered, and deliberately: driving a real batch to completion needs root
// and a Linux TUN device. TestGateSpansThePreAllocationWindow gets as far as a
// non-root process can — it observes a real batch inside its pre-allocation and
// requires a concurrent create to be refused there — and
// TestGatedBatchesNeverOverlapOnDeviceIPs mirrors the rest of the window
// (rewind + walk) with the production functions in production order.

// silenceCreateGateLogs keeps the pre-allocation path's ~20 log lines per batch
// out of the test output. Restored on cleanup.
func silenceCreateGateLogs(t *testing.T) {
	t.Helper()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })
}

// TestCreateBatchGateAdmitsExactlyOneBatch is the gate's own pin: with N
// contenders arriving together, exactly one is admitted and every other gets
// the sentinel.
//
// The admitted goroutine HOLDS until every contender has resolved, which is the
// point: a bounded set of take-and-release calls would serialise happily even
// with no exclusion at all, and the count of admissions would be N.
func TestCreateBatchGateAdmitsExactlyOneBatch(t *testing.T) {
	const contenders = 8

	sm := newPreallocLockTestManager()

	var admitted, refused, resolved atomic.Int64
	begin := make(chan struct{})
	holdUntil := make(chan struct{})

	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-begin
			release, err := sm.tryEnterCreateBatch()
			if err != nil {
				if !errors.Is(err, errCreateBatchInProgress) {
					t.Errorf("refusal %q is not classified errCreateBatchInProgress", err)
				}
				refused.Add(1)
				resolved.Add(1)
				return
			}
			admitted.Add(1)
			resolved.Add(1)
			<-holdUntil
			release()
		}()
	}

	close(begin)

	deadline := time.Now().Add(10 * time.Second)
	for resolved.Load() < contenders {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d contenders resolved: the gate blocks instead of refusing",
				resolved.Load(), contenders)
		}
		time.Sleep(200 * time.Microsecond)
	}

	if got := admitted.Load(); got != 1 {
		t.Errorf("%d contenders were admitted at once, want exactly 1", got)
	}
	if got := refused.Load(); got != contenders-1 {
		t.Errorf("%d contenders were refused, want %d", got, contenders-1)
	}

	close(holdUntil)
	wg.Wait()

	// And the gate is free again once the holder released.
	release, err := sm.tryEnterCreateBatch()
	if err != nil {
		t.Fatalf("gate still held after the admitted batch released: %v", err)
	}
	release()
}

// TestConcurrentCreateIsRefusedWithTheSentinel pins the gate to the entry of
// CreateDevicesWithOptions itself.
//
// It runs unprivileged, and that is what makes it a wiring test rather than a
// tautology: the root-privileges check is INSIDE the batch, so an answer that
// is the sentinel and not "root privileges required" proves the refusal happened
// at entry, above the freeze check and above nl6#538's resource resolution.
func TestConcurrentCreateIsRefusedWithTheSentinel(t *testing.T) {
	sm := newPreallocLockTestManager()
	sm.deviceCreateTotal.Store(4242)
	sm.deviceCreateProgress.Store(17)

	// Stand in for the batch in flight.
	if !sm.createBatchGate.TryLock() {
		t.Fatal("a fresh manager's create gate is already held")
	}
	defer sm.createBatchGate.Unlock()

	created, err := sm.CreateDevicesWithOptions("10.42.0.1", 1, "16", "", nil, true, 0, false, "", 161, nil)
	if err == nil {
		t.Fatal("a second batch was admitted while one was in flight")
	}
	if created != 0 {
		t.Errorf("refused batch reports %d devices created, want 0", created)
	}
	if !errors.Is(err, errCreateBatchInProgress) {
		t.Fatalf("error %q is not classified errCreateBatchInProgress", err)
	}
	if strings.Contains(err.Error(), "root privileges") {
		t.Errorf("error %q is the root-privileges answer: the gate is below the privilege check, "+
			"so it does not cover the whole batch", err)
	}

	// The message has to be actionable: the batch in the way, and the remedy.
	for _, want := range []string{"4242", "17", "retry"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not mention %q", err, want)
		}
	}
}

// TestCreateBatchSentinelIsClassified409 pins the boundary mapping. Without it
// the refusal renders as a 500 — an unclassified server fault — which tells a
// client to open a bug rather than to retry.
func TestCreateBatchSentinelIsClassified409(t *testing.T) {
	sm := newPreallocLockTestManager()
	if !sm.createBatchGate.TryLock() {
		t.Fatal("a fresh manager's create gate is already held")
	}
	defer sm.createBatchGate.Unlock()

	_, err := sm.tryEnterCreateBatch()
	if err == nil {
		t.Fatal("tryEnterCreateBatch admitted a second batch")
	}

	msg, status := createDevicesErrorResponse(err)
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409. A concurrent batch is neither caller data that is wrong (400) "+
			"nor a server fault (500)", status)
	}
	if !strings.Contains(msg, "already in progress") {
		t.Errorf("409 body %q does not say what is in progress", msg)
	}
}

// TestCreateDevicesHandlerAnswers409ForAConcurrentBatch is the HTTP boundary end
// to end. Driving createDevicesErrorResponse alone leaves the handler's own line
// unpinned — the nl6#538 lesson, where reverting it to a 500 kept the suite
// green.
//
// The second subtest is the non-root row of the matrix: with the gate FREE the
// pre-existing root-privileges answer must be exactly what it was, so the gate
// cannot be masking it.
func TestCreateDevicesHandlerAnswers409ForAConcurrentBatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the request would create real devices")
	}
	silenceCreateGateLogs(t)

	sm := classifyFixture(t)
	sm.devices = make(map[string]*DeviceSimulator)
	sm.deviceIPs = make(map[string]struct{})
	sm.tunInterfacePool = make(map[string]*TunInterface)
	sm.isPreAllocating.Store(false)
	sm.isCreatingDevices.Store(false)
	sm.deviceCreateProgress.Store(0)
	sm.deviceCreateTotal.Store(0)
	t.Cleanup(swapGlobalManager(sm))
	router := setupRoutes()

	writeResourceFile(t, filepath.Join("resources", "gategood.json"), `{"snmp":[`+cleanEntry+`]}`)
	const body = `{"start_ip":"10.42.0.1","device_count":1,"netmask":"16","resource_file":"gategood.json"}`

	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	t.Run("batch-in-flight-is-409", func(t *testing.T) {
		if !sm.createBatchGate.TryLock() {
			t.Fatal("the fixture manager's create gate is already held")
		}
		defer sm.createBatchGate.Unlock()

		rr := post()
		if rr.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409; body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "retry") {
			t.Errorf("409 body %q does not tell the caller to retry", rr.Body.String())
		}
	})

	t.Run("gate-free-still-reports-the-root-requirement", func(t *testing.T) {
		rr := post()
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want the pre-existing 500; body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "root privileges") {
			t.Errorf("body %q is not the root-privileges error", rr.Body.String())
		}
	})
}

// TestCreateBatchGateIsReleasedOnEveryExitPath: a batch that fails must not
// wedge the gate for the life of the process. The three exits a batch has that a
// test can drive are the freeze rejection, the privilege rejection, and a panic.
func TestCreateBatchGateIsReleasedOnEveryExitPath(t *testing.T) {
	silenceCreateGateLogs(t)

	assertFree := func(t *testing.T, sm *SimulatorManager) {
		t.Helper()
		release, err := sm.tryEnterCreateBatch()
		if err != nil {
			t.Fatalf("gate still held after the batch returned: %v", err)
		}
		release()
	}

	t.Run("freeze-rejection", func(t *testing.T) {
		sm := newPreallocLockTestManager()
		sm.fleetFrozenBy = map[string]struct{}{"s-000001": {}}

		_, err := sm.CreateDevicesWithOptions("10.42.0.1", 1, "16", "", nil, true, 0, false, "", 161, nil)
		if err == nil || !strings.Contains(err.Error(), "frozen") {
			t.Fatalf("error = %v, want the fleet-freeze rejection (unchanged from today)", err)
		}
		if errors.Is(err, errCreateBatchInProgress) {
			t.Error("the freeze rejection is classified as a concurrent batch")
		}
		assertFree(t, sm)
	})

	t.Run("privilege-rejection", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: the privilege check does not fire")
		}
		sm := classifyFixture(t)
		sm.devices = make(map[string]*DeviceSimulator)
		sm.deviceIPs = make(map[string]struct{})
		sm.tunInterfacePool = make(map[string]*TunInterface)
		sm.isPreAllocating.Store(false)
		sm.isCreatingDevices.Store(false)
		sm.deviceCreateProgress.Store(0)
		sm.deviceCreateTotal.Store(0)
		writeResourceFile(t, filepath.Join("resources", "gategood.json"), `{"snmp":[`+cleanEntry+`]}`)

		_, err := sm.CreateDevicesWithOptions("10.42.0.1", 1, "16", "gategood.json", nil, true, 0, false, "", 161, nil)
		if err == nil || !strings.Contains(err.Error(), "root privileges") {
			t.Fatalf("error = %v, want the root-privileges rejection", err)
		}
		assertFree(t, sm)
	})

	t.Run("panic", func(t *testing.T) {
		sm := newPreallocLockTestManager()

		func() {
			defer func() {
				if recover() == nil {
					t.Error("the panicking batch did not panic")
				}
			}()
			release, err := sm.tryEnterCreateBatch()
			if err != nil {
				t.Fatalf("tryEnterCreateBatch: %v", err)
			}
			defer release()
			panic("batch blew up")
		}()

		assertFree(t, sm)
	})
}

// gatedBatchWindow mirrors, with the production functions and in production
// order, the part of createDevicesWithOptionsLocked that consumes the shared IP
// cursor: the pre-allocation reservation (which commits currentIP to the batch
// END), the rewind back to the batch START, and the walk createDevicesParallel
// does from the cursor. It goes through the REAL gate.
//
// The mirror exists because the real function needs root and a Linux TUN device
// to reach its walk. What it does NOT pin is the release POINT inside the real
// function — see the file header.
func gatedBatchWindow(sm *SimulatorManager, start net.IP, count int, mask string, hold time.Duration) ([]string, error) {
	release, err := sm.tryEnterCreateBatch()
	if err != nil {
		return nil, err
	}
	defer release()

	// The reservation half. Commits currentIP = start + count.
	if err := sm.PreAllocateTunInterfaces(count, 4, start, mask); err != nil {
		return nil, err
	}

	// The rewind, verbatim from createDevicesWithOptionsLocked: the devices must
	// land on the addresses the pool carries.
	rewound := make(net.IP, len(start))
	copy(rewound, start)
	sm.mu.Lock()
	sm.currentIP = rewound
	sm.mu.Unlock()

	// The window the gate has to span. In the real batch it is the summary log
	// lines, the worker launch and every device's Start(); here it is a sleep,
	// which is what puts an ungated second batch's rewind inside it.
	time.Sleep(hold)

	// The walk, as createDevicesParallel does it: snapshot the cursor under the
	// read lock, then precompute the batch's addresses from the snapshot.
	sm.mu.RLock()
	startingIP := make(net.IP, len(sm.currentIP))
	copy(startingIP, sm.currentIP)
	sm.mu.RUnlock()

	ips, _ := preAllocBatchIPs(startingIP, parsePrefix(mask), count)
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out, nil
}

// TestGatedBatchesNeverOverlapOnDeviceIPs is the pin for the defect itself.
//
// Two batches with DIFFERENT start addresses race. Ungated, both rewind the
// shared cursor and then walk it, so the loser's walk returns the WINNER's
// range: every device of one batch lands on the other's addresses, the deviceIPs
// check absorbs them as "already exists", and the batch reports success having
// created almost nothing. Gated, the second is refused, retries, and gets its
// own range.
//
// Both assertions are load-bearing and neither implies the other: each batch
// must walk its OWN requested range, and the union of the two ranges must have
// no repetition. A run of rounds, because a single interleaving proves nothing.
func TestGatedBatchesNeverOverlapOnDeviceIPs(t *testing.T) {
	silenceCreateGateLogs(t)

	const (
		rounds = 8
		count  = 8
		mask   = "16"
	)
	starts := []string{"10.42.0.1", "10.42.1.1"}

	for round := 0; round < rounds; round++ {
		sm := newPreallocLockTestManager()
		t.Cleanup(sm.CleanupPreAllocatedInterfaces)

		results := make([][]string, len(starts))
		begin := make(chan struct{})
		var wg sync.WaitGroup

		for i := range starts {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				start := net.ParseIP(starts[i]).To4()
				<-begin
				deadline := time.Now().Add(10 * time.Second)
				for {
					ips, err := gatedBatchWindow(sm, start, count, mask, 2*time.Millisecond)
					if err == nil {
						results[i] = ips
						return
					}
					if !errors.Is(err, errCreateBatchInProgress) {
						t.Errorf("batch %s failed: %v", starts[i], err)
						return
					}
					if time.Now().After(deadline) {
						t.Errorf("batch %s never got in", starts[i])
						return
					}
					time.Sleep(200 * time.Microsecond)
				}
			}(i)
		}
		close(begin)
		wg.Wait()

		seen := map[string]string{}
		for i, start := range starts {
			// Every batch walks the range it asked for, computed independently.
			walk := net.ParseIP(start).To4()
			want := make([]string, count)
			for j := 0; j < count; j++ {
				want[j] = walk.String()
				walk = nextHost(walk, parsePrefix(mask))
			}
			if len(results[i]) != count {
				t.Fatalf("round %d: batch %s produced %d addresses, want %d", round, start, len(results[i]), count)
			}
			for j := range want {
				if results[i][j] != want[j] {
					t.Fatalf("round %d: batch %s device %d is %s, want %s — the batch walked another batch's range",
						round, start, j, results[i][j], want[j])
				}
			}
			for _, ip := range results[i] {
				if other, dup := seen[ip]; dup {
					t.Fatalf("round %d: %s is issued to both batch %s and batch %s", round, ip, other, start)
				}
				seen[ip] = start
			}
		}
	}
}

// TestGateSpansThePreAllocationWindow is the one test that observes the REAL
// CreateDevicesWithOptions holding the gate past its entry, which is what a
// release placed before the IP walk would break.
//
// isPreAllocating is the production flag whose whole lifetime lies inside the
// batch, so while it is set the gate must be held. The prober therefore attempts
// a create whenever it sees the flag, and only calls an admission a failure if
// the flag is STILL set on the far side of the attempt — otherwise the batch
// legitimately finished mid-attempt and a sequential create is allowed.
//
// Unprivileged only: as root the pre-allocation would create real TUN links.
func TestGateSpansThePreAllocationWindow(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: pre-allocation would create real TUN interfaces")
	}
	silenceCreateGateLogs(t)

	sm := newPreallocLockTestManager()
	t.Cleanup(sm.CleanupPreAllocatedInterfaces)

	var batchDone atomic.Bool
	go func() {
		defer batchDone.Store(true)
		// count >= 10 selects the pre-allocation path; 2000 makes its window
		// wide enough to probe. Every worker fails fast without /dev/net/tun,
		// so nothing is created and the batch ends at the privilege check.
		_, _ = sm.CreateDevicesWithOptions("10.43.0.1", 2000, "16", "", nil, true, 100, false, "", 161, nil)
	}()

	probes, refusals := 0, 0
	deadline := time.Now().Add(30 * time.Second)
	for !batchDone.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the batch never finished")
		}
		if inPreAlloc, _ := sm.isPreAllocating.Load().(bool); !inPreAlloc {
			time.Sleep(100 * time.Microsecond)
			continue
		}
		probes++
		release, err := sm.tryEnterCreateBatch()
		if err == nil {
			stillInPreAlloc, _ := sm.isPreAllocating.Load().(bool)
			release()
			if stillInPreAlloc {
				t.Fatal("a second batch was admitted while a batch was mid-pre-allocation: " +
					"the gate does not span the reservation, so it cannot span the IP walk either")
			}
			continue
		}
		if !errors.Is(err, errCreateBatchInProgress) {
			t.Fatalf("refusal %q is not classified errCreateBatchInProgress", err)
		}
		refusals++
	}

	if probes == 0 {
		t.Fatal("never observed the batch inside pre-allocation: the probe window was too short " +
			"to assert anything")
	}
	if refusals == 0 {
		t.Fatalf("%d probes inside pre-allocation, none refused", probes)
	}
	t.Logf("probed %d times inside pre-allocation, %d refused", probes, refusals)
}
