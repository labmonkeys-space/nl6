/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"fmt"
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
// addresses, the deviceIPs collision check absorbs the overlap as "already
// exists", and the second batch silently creates fewer devices than requested
// while reporting success. The fix admits one batch at a time and refuses the
// second with 409 Conflict.
//
// EVERY test here observes the REAL CreateDevicesWithOptions, and that is the
// whole point of the shape they have. The first cut of this file pinned a
// hand-written MIRROR of the gated body: deleting the gate from
// CreateDevicesWithOptions left three of six tests green (review R1). Two
// production seams make the real function reachable, both nil/no-op in
// production and both documented at their definitions in device.go:
//
//   - `geteuid`, because the privilege check sits ABOVE the currentIP rewind, so
//     an unprivileged process returns before the half of the window this change
//     is about. Faked in BOTH directions, so the privilege-rejection path is
//     exercised on a root CI container too instead of skipping (review R5).
//   - `createBatchStageProbe`, so a test can stand at a named point INSIDE a
//     real batch — entry, past the reservation, and the instant before the IP
//     walk — and ask whether the gate is held. The walk is the half that
//     consumes currentIP, so it is the half a claim about this gate has to
//     cover; a probe keyed on isPreAllocating does NOT cover it, which is how
//     the first cut's headline claim came to be false (review R2).
//
// Which kind of pin each test is, since the two are not interchangeable:
//
//   - VALUE pins (fail on an assertion, with or without -race): all of them.
//     The defect is a wrong VALUE — an overlapping IP range — not an
//     unsynchronised access; nl6#556 already locked the fields.
//   - The race detector adds coverage for the concurrent tests but no test
//     RELIES on it.
//
// What no test here covers: a batch driven to COMPLETION, which needs root and
// a Linux TUN device. Every probe-driven test aborts the batch at a stage before
// any device is created, so the walk's own loop and createDevicesParallel are
// out of scope, as they were before this change.

// silenceCreateGateLogs keeps the creation path's log lines out of the test
// output. Restored on cleanup.
func silenceCreateGateLogs(t *testing.T) {
	t.Helper()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })
}

// newCreateGateManager is the smallest manager the gate and creation paths need.
func newCreateGateManager() *SimulatorManager {
	sm := &SimulatorManager{
		devices:          make(map[string]*DeviceSimulator),
		deviceIPs:        make(map[string]struct{}),
		tunInterfacePool: make(map[string]*TunInterface),
		resourcesCache:   make(map[string]*DeviceResources),
	}
	sm.isPreAllocating.Store(false)
	sm.isCreatingDevices.Store(false)
	sm.deviceCreateProgress.Store(0)
	sm.deviceCreateTotal.Store(0)
	return sm
}

// newCreateGateRESTManager is newCreateGateManager plus the on-disk resource
// fixture the REST path resolves against, and a good device type to name.
// (Extracted: the reset block was duplicated verbatim between two tests —
// review R11.)
func newCreateGateRESTManager(t *testing.T) *SimulatorManager {
	t.Helper()
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("resources", 0o755); err != nil {
		t.Fatalf("mkdir resources: %v", err)
	}
	writeResourceFile(t, filepath.Join("resources", "gategood.json"), `{"snmp":[`+cleanEntry+`]}`)
	return newCreateGateManager()
}

// withFakeEuid drives the batch's privilege check, in either direction, on any
// host. See the `geteuid` comment in device.go.
func withFakeEuid(t *testing.T, uid int) {
	t.Helper()
	prev := geteuid
	geteuid = func() int { return uid }
	t.Cleanup(func() { geteuid = prev })
}

// probeAbortError is how a probe stops a batch: an ordinary error return, so the
// wrapper's deferred release runs exactly as it does on any other failure. It
// carries the stage and the cursor the probe observed, which is how a
// per-goroutine observation gets back to the goroutine that made the call — the
// probe runs ON the caller's goroutine, but the global probe func has no way to
// tell two callers apart.
type probeAbortError struct {
	stage  createBatchStage
	cursor string
}

func (e *probeAbortError) Error() string {
	return fmt.Sprintf("probe aborted the batch at %s (cursor %s)", e.stage, e.cursor)
}

// withCreateBatchProbe installs a stage probe for the duration of the test. Set
// before the batch starts and cleared after it has returned, so there is no
// unsynchronised access to the var itself.
func withCreateBatchProbe(t *testing.T, probe func(createBatchStage) error) {
	t.Helper()
	prev := createBatchStageProbe
	createBatchStageProbe = probe
	t.Cleanup(func() { createBatchStageProbe = prev })
}

// gateIsHeld reports whether the gate is currently taken, WITHOUT taking it: the
// accessor is the only thing tests use, so a test cannot pass by reaching around
// a wrapper whose gate is gone (review R11).
func gateIsHeld(sm *SimulatorManager) (bool, error) {
	release, err := sm.tryEnterCreateBatch(1)
	if err != nil {
		if !errors.Is(err, errCreateBatchInProgress) {
			return true, fmt.Errorf("refusal %q is not classified errCreateBatchInProgress", err)
		}
		return true, nil
	}
	release()
	return false, nil
}

// snapshotCursor reads the allocation cursor the way createDevicesParallel reads
// it at the start of the IP walk: one copy under the read lock.
func snapshotCursor(sm *SimulatorManager) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	cur := make(net.IP, len(sm.currentIP))
	copy(cur, sm.currentIP)
	return cur.String()
}

// TestCreateBatchGateAdmitsExactlyOneBatch is the gate's own pin: with N
// contenders arriving together, exactly one is admitted and every other gets the
// sentinel.
//
// The admitted goroutine HOLDS until every contender has resolved, which is the
// point: a bounded set of take-and-release calls would serialise happily with no
// exclusion at all and the admission count would be N.
func TestCreateBatchGateAdmitsExactlyOneBatch(t *testing.T) {
	const contenders = 8

	sm := newCreateGateManager()

	var admitted, refused, resolved atomic.Int64
	begin := make(chan struct{})
	holdUntil := make(chan struct{})

	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-begin
			release, err := sm.tryEnterCreateBatch(10)
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

	if held, err := gateIsHeld(sm); err != nil {
		t.Fatal(err)
	} else if held {
		t.Fatal("gate still held after the admitted batch released")
	}
}

// TestReleaseIsIdempotentAndTheRefusalReleaseIsSafe (review R8). A second
// Unlock of a sync.Mutex is `fatal error: unlock of unlocked mutex`, which no
// recover() catches: it takes the whole simulator down, on a path whose doc
// comment hands the caller a func to call.
func TestReleaseIsIdempotentAndTheRefusalReleaseIsSafe(t *testing.T) {
	sm := newCreateGateManager()

	release, err := sm.tryEnterCreateBatch(3)
	if err != nil {
		t.Fatalf("tryEnterCreateBatch: %v", err)
	}
	release()
	release() // must be a no-op, not a fatal double unlock

	if held, err := gateIsHeld(sm); err != nil {
		t.Fatal(err)
	} else if held {
		t.Fatal("gate held after an idempotent double release")
	}

	// The refusal path hands back a callable no-op, so a caller that ignores the
	// error does not nil-panic.
	hold, err := sm.tryEnterCreateBatch(3)
	if err != nil {
		t.Fatalf("tryEnterCreateBatch: %v", err)
	}
	defer hold()

	noop, err := sm.tryEnterCreateBatch(1)
	if err == nil {
		t.Fatal("a second batch was admitted")
	}
	if noop == nil {
		t.Fatal("the refusal path returned a nil release func; a caller that ignores the error nil-panics")
	}
	noop()
	if held, _ := gateIsHeld(sm); !held {
		t.Fatal("calling the refusal's no-op released the running batch's gate")
	}
}

// TestConcurrentCreateIsRefusedWithTheSentinel pins the gate to the entry of
// CreateDevicesWithOptions itself.
//
// The privilege check is faked to non-root, and the answer must be the sentinel
// rather than the privilege error: that is what proves the refusal happens at
// entry, above the freeze check and above nl6#538's resource resolution.
func TestConcurrentCreateIsRefusedWithTheSentinel(t *testing.T) {
	silenceCreateGateLogs(t)
	withFakeEuid(t, 1000)

	sm := newCreateGateManager()

	// Stand in for the batch in flight, through the accessor.
	hold, err := sm.tryEnterCreateBatch(4242)
	if err != nil {
		t.Fatalf("tryEnterCreateBatch: %v", err)
	}
	defer hold()

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
		t.Errorf("error %q is the privilege answer: the gate sits below the privilege check, "+
			"so it does not cover the whole batch", err)
	}

	// Actionable: the batch in the way, its size, and the remedy. The size comes
	// from the RUNNING batch's own token, never from deviceCreateTotal (review
	// R7) — so a stale counter is proved not to be the source.
	sm.deviceCreateTotal.Store(999999)
	sm.deviceCreateProgress.Store(888888)
	_, err2 := sm.tryEnterCreateBatch(1)
	if err2 == nil {
		t.Fatal("a second batch was admitted")
	}
	for _, want := range []string{"batch #", "4242", "retry"} {
		if !strings.Contains(err2.Error(), want) {
			t.Errorf("refusal %q does not mention %q", err2, want)
		}
	}
	for _, unwanted := range []string{"999999", "888888"} {
		if strings.Contains(err2.Error(), unwanted) {
			t.Errorf("refusal %q reports deviceCreate* counters, which belong to whatever batch "+
				"wrote them last, not to the running batch", err2)
		}
	}
}

// TestRefusedBatchTouchesNoCreationState (review R3): a refused request must
// leave the running batch's state alone.
//
// Move the gate one line BELOW the isCreatingDevices / deviceCreateTotal /
// deviceCreateProgress stores and a refused request clobbers the running batch's
// counters AND its deferred Store(false) clears the running batch's
// freeze-interlock flag — with nothing else in the suite failing. Same lesson as
// nl6#538's "allocated the pool and then answered 400", in a new place.
func TestRefusedBatchTouchesNoCreationState(t *testing.T) {
	silenceCreateGateLogs(t)
	withFakeEuid(t, 1000)

	sm := newCreateGateManager()

	// State as a running batch would have left it.
	hold, err := sm.tryEnterCreateBatch(4242)
	if err != nil {
		t.Fatalf("tryEnterCreateBatch: %v", err)
	}
	defer hold()
	sm.isCreatingDevices.Store(true)
	sm.deviceCreateTotal.Store(4242)
	sm.deviceCreateProgress.Store(17)
	sm.mu.Lock()
	sm.tunPoolSize = 7
	sm.maxWorkers = 33
	sm.nextTunIndex = 11
	sm.currentIP = net.ParseIP("10.42.9.9").To4()
	sm.mu.Unlock()

	if _, err := sm.CreateDevicesWithOptions("10.42.0.1", 99, "16", "", nil, true, 0, false, "", 161, nil); !errors.Is(err, errCreateBatchInProgress) {
		t.Fatalf("error = %v, want the concurrency sentinel", err)
	}

	if creating, _ := sm.isCreatingDevices.Load().(bool); !creating {
		t.Error("the refused request cleared isCreatingDevices — the running batch's " +
			"FR35/FR38 freeze interlock is now open mid-batch")
	}
	if got, _ := sm.deviceCreateTotal.Load().(int); got != 4242 {
		t.Errorf("deviceCreateTotal = %d, want the running batch's 4242", got)
	}
	if got, _ := sm.deviceCreateProgress.Load().(int); got != 17 {
		t.Errorf("deviceCreateProgress = %d, want the running batch's 17", got)
	}
	sm.mu.RLock()
	poolSize, workers, idx, cursor := sm.tunPoolSize, sm.maxWorkers, sm.nextTunIndex, sm.currentIP.String()
	devices, ips := len(sm.devices), len(sm.deviceIPs)
	sm.mu.RUnlock()
	if poolSize != 7 || workers != 33 || idx != 11 || cursor != "10.42.9.9" {
		t.Errorf("allocation state moved: tunPoolSize=%d maxWorkers=%d nextTunIndex=%d currentIP=%s, "+
			"want 7/33/11/10.42.9.9", poolSize, workers, idx, cursor)
	}
	if devices != 0 || ips != 0 {
		t.Errorf("the refused request created state: %d devices, %d IPs", devices, ips)
	}
}

// TestGateIsHeldAtEveryStageOfTheBatch is the pin the first cut of this change
// did not have (review R1, R2): the gate must still be held at the instant the
// IP walk begins, and the only evidence that counts is taken INSIDE a real
// batch.
//
// The three stages are entry, the far side of the pre-allocation reservation,
// and immediately after the currentIP rewind, which is where the walk starts
// reading. A release moved anywhere inside the body — above pre-allocation,
// between the reservation and the rewind, anywhere before the walk — fails here.
// It also asserts the gate is FREE once the batch returns (review R5).
func TestGateIsHeldAtEveryStageOfTheBatch(t *testing.T) {
	run := func(t *testing.T, count int, preAllocate bool) {
		silenceCreateGateLogs(t)
		withFakeEuid(t, 0) // reach past the privilege check on any host

		sm := newCreateGateManager()
		t.Cleanup(sm.CleanupPreAllocatedInterfaces)

		var seen []createBatchStage
		withCreateBatchProbe(t, func(stage createBatchStage) error {
			held, err := gateIsHeld(sm)
			if err != nil {
				t.Error(err)
			} else if !held {
				t.Errorf("the gate is NOT held at stage %s of a running batch", stage)
			}
			seen = append(seen, stage)
			if stage == stageBeforeIPWalk {
				// Stop before any device is created: this test must be safe to
				// run as root.
				return &probeAbortError{stage: stage, cursor: snapshotCursor(sm)}
			}
			return nil
		})

		_, err := sm.CreateDevicesWithOptions("10.42.0.1", count, "16", "", nil, preAllocate, 4, false, "", 161, nil)
		var abort *probeAbortError
		if !errors.As(err, &abort) {
			t.Fatalf("error = %v, want the probe's abort at the IP walk. The batch never reached it.", err)
		}
		if abort.cursor != "10.42.0.1" {
			t.Errorf("cursor at the walk = %s, want the batch start 10.42.0.1", abort.cursor)
		}

		want := []createBatchStage{stageBatchEntered, stageAfterReservation, stageBeforeIPWalk}
		if len(seen) != len(want) {
			t.Fatalf("stages seen = %v, want %v", seen, want)
		}
		for i := range want {
			if seen[i] != want[i] {
				t.Fatalf("stages seen = %v, want %v", seen, want)
			}
		}

		if held, err := gateIsHeld(sm); err != nil {
			t.Fatal(err)
		} else if held {
			t.Fatal("the gate is still held after the batch returned")
		}
	}

	// No pre-allocation: creates nothing on any host, so this arm runs
	// everywhere, root included.
	t.Run("without-pre-allocation", func(t *testing.T) { run(t, 1, false) })

	// With a REAL reservation. Unprivileged only: as root the pre-allocator
	// creates real TUN links, and this test's value is the gate observation, not
	// the links.
	t.Run("with-a-real-reservation", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: pre-allocation would create real TUN interfaces")
		}
		run(t, 12, true)
	})
}

// TestGatedBatchesNeverOverlapOnDeviceIPs is the pin for the defect itself, and
// it drives the REAL function: two batches with DIFFERENT start addresses race,
// and each observes the cursor at the instant its own IP walk would read it.
//
// Ungated, both rewind the shared cursor and then walk it, so the loser's walk
// starts from the WINNER's address: every device of one batch lands on the
// other's addresses, the deviceIPs check absorbs them as "already exists", and
// the batch reports success having created almost nothing. Gated, the second is
// refused, retries, and gets its own range.
//
// Both assertions are load-bearing and neither implies the other: each batch
// must walk its OWN requested range, and the union of the two ranges must have
// no repetition. Rounds, because a single interleaving proves nothing.
func TestGatedBatchesNeverOverlapOnDeviceIPs(t *testing.T) {
	silenceCreateGateLogs(t)
	withFakeEuid(t, 0)

	const (
		rounds = 8
		count  = 4
		mask   = "16"
	)
	starts := []string{"10.42.0.1", "10.42.1.1"}

	// The probe runs on the batch's own goroutine and takes no argument, so the
	// manager under test is handed to it through this pointer, written once per
	// round while no batch is running.
	var current atomic.Pointer[SimulatorManager]

	// The sleep widens the window the gate has to span: in a real batch this is
	// the summary log lines, the worker launch and every device's Start().
	withCreateBatchProbe(t, func(stage createBatchStage) error {
		if stage != stageBeforeIPWalk {
			return nil
		}
		time.Sleep(2 * time.Millisecond)
		return &probeAbortError{stage: stage, cursor: snapshotCursor(current.Load())}
	})

	for round := 0; round < rounds; round++ {
		sm := newCreateGateManager()
		current.Store(sm)

		observed := make([]string, len(starts))
		begin := make(chan struct{})
		var wg sync.WaitGroup

		for i := range starts {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-begin
				deadline := time.Now().Add(10 * time.Second)
				for {
					_, err := sm.CreateDevicesWithOptions(starts[i], count, mask, "", nil, false, 0, false, "", 161, nil)
					var abort *probeAbortError
					if errors.As(err, &abort) {
						observed[i] = abort.cursor
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
			if observed[i] != start {
				t.Fatalf("round %d: batch %s begins its IP walk at %s — it walks another batch's range",
					round, start, observed[i])
			}
			// The walk from that cursor, computed independently, must not
			// intersect the other batch's.
			walk := net.ParseIP(observed[i]).To4()
			for j := 0; j < count; j++ {
				ip := walk.String()
				if other, dup := seen[ip]; dup {
					t.Fatalf("round %d: %s is issued to both batch %s and batch %s", round, ip, other, start)
				}
				seen[ip] = start
				walk = nextHost(walk, parsePrefix(mask))
			}
		}
	}
}

// TestCreateBatchGateIsReleasedOnEveryExitPath: a batch that fails must not
// wedge the gate for the life of the process.
//
// Every subtest observes the gate WHILE the batch runs (through the entry probe)
// and again after it returns, because "free afterwards" alone is satisfied
// trivially by a batch that never took the gate — which is exactly how the first
// cut of this test passed with the gate deleted (review R1).
func TestCreateBatchGateIsReleasedOnEveryExitPath(t *testing.T) {
	silenceCreateGateLogs(t)

	// installEntryWitness asserts the gate is held at entry and records that the
	// batch really got that far.
	installEntryWitness := func(t *testing.T, sm *SimulatorManager, fired *bool) {
		withCreateBatchProbe(t, func(stage createBatchStage) error {
			if stage != stageBatchEntered {
				return nil
			}
			*fired = true
			held, err := gateIsHeld(sm)
			if err != nil {
				t.Error(err)
			} else if !held {
				t.Error("the gate is not held at the entry of a running batch")
			}
			return nil
		})
	}

	assertReleased := func(t *testing.T, sm *SimulatorManager, fired bool) {
		t.Helper()
		if !fired {
			t.Fatal("the batch never entered the gated body; this test asserted nothing")
		}
		if held, err := gateIsHeld(sm); err != nil {
			t.Fatal(err)
		} else if held {
			t.Fatal("gate still held after the batch returned")
		}
	}

	t.Run("freeze-rejection", func(t *testing.T) {
		sm := newCreateGateManager()
		sm.fleetFrozenBy = map[string]struct{}{"s-000001": {}}
		fired := false
		installEntryWitness(t, sm, &fired)

		_, err := sm.CreateDevicesWithOptions("10.42.0.1", 1, "16", "", nil, true, 0, false, "", 161, nil)
		if err == nil || !strings.Contains(err.Error(), "frozen") {
			t.Fatalf("error = %v, want the fleet-freeze rejection (unchanged from today)", err)
		}
		if errors.Is(err, errCreateBatchInProgress) {
			t.Error("the freeze rejection is classified as a concurrent batch")
		}
		assertReleased(t, sm, fired)
	})

	t.Run("privilege-rejection", func(t *testing.T) {
		withFakeEuid(t, 1000) // exercised on a root host too (review R5)
		sm := newCreateGateRESTManager(t)
		fired := false
		installEntryWitness(t, sm, &fired)

		_, err := sm.CreateDevicesWithOptions("10.42.0.1", 1, "16", "gategood.json", nil, true, 0, false, "", 161, nil)
		if err == nil || !strings.Contains(err.Error(), "root privileges") {
			t.Fatalf("error = %v, want the root-privileges rejection", err)
		}
		assertReleased(t, sm, fired)
	})

	t.Run("abort-mid-batch", func(t *testing.T) {
		withFakeEuid(t, 0)
		sm := newCreateGateManager()
		fired := false
		withCreateBatchProbe(t, func(stage createBatchStage) error {
			if stage == stageBatchEntered {
				fired = true
			}
			if stage != stageBeforeIPWalk {
				return nil
			}
			return &probeAbortError{stage: stage, cursor: snapshotCursor(sm)}
		})

		_, err := sm.CreateDevicesWithOptions("10.42.0.1", 1, "16", "", nil, false, 0, false, "", 161, nil)
		var abort *probeAbortError
		if !errors.As(err, &abort) {
			t.Fatalf("error = %v, want the probe abort", err)
		}
		assertReleased(t, sm, fired)
	})

	t.Run("panic-mid-batch", func(t *testing.T) {
		withFakeEuid(t, 0)
		sm := newCreateGateManager()
		fired := false
		withCreateBatchProbe(t, func(stage createBatchStage) error {
			if stage == stageBatchEntered {
				fired = true
			}
			if stage == stageBeforeIPWalk {
				panic("batch blew up mid-walk")
			}
			return nil
		})

		func() {
			defer func() {
				if recover() == nil {
					t.Error("the panicking batch did not panic")
				}
			}()
			_, _ = sm.CreateDevicesWithOptions("10.42.0.1", 1, "16", "", nil, false, 0, false, "", 161, nil)
		}()

		// This is what makes the wrapper's `defer release()` load-bearing: a
		// release called at the end of the wrapper instead would be skipped by
		// the panic and wedge the gate for the life of the process.
		assertReleased(t, sm, fired)
	})
}

// TestCreateBatchSentinelIsClassified409 pins the boundary mapping. Without it
// the refusal renders as a 500 — an unclassified server fault — which tells a
// client to open a bug rather than to retry.
func TestCreateBatchSentinelIsClassified409(t *testing.T) {
	sm := newCreateGateManager()
	hold, err := sm.tryEnterCreateBatch(12)
	if err != nil {
		t.Fatalf("tryEnterCreateBatch: %v", err)
	}
	defer hold()

	_, err = sm.tryEnterCreateBatch(1)
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
// pre-existing privilege answer must be exactly what it was, so the gate cannot
// be masking it. The privilege check is faked, so both rows run on any host.
func TestCreateDevicesHandlerAnswers409ForAConcurrentBatch(t *testing.T) {
	silenceCreateGateLogs(t)
	withFakeEuid(t, 1000)

	sm := newCreateGateRESTManager(t)
	t.Cleanup(swapGlobalManager(sm))
	router := setupRoutes()

	const body = `{"start_ip":"10.42.0.1","device_count":1,"netmask":"16","resource_file":"gategood.json"}`
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	t.Run("batch-in-flight-is-409", func(t *testing.T) {
		hold, err := sm.tryEnterCreateBatch(2000)
		if err != nil {
			t.Fatalf("tryEnterCreateBatch: %v", err)
		}
		defer hold()

		rr := post()
		if rr.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409; body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "retry") {
			t.Errorf("409 body %q does not tell the caller to retry", rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "2000") {
			t.Errorf("409 body %q does not name the batch in the way", rr.Body.String())
		}
		// Machine-actionable, not only prose (review R10).
		if got := rr.Header().Get("Retry-After"); got != createConflictRetryAfterSeconds {
			t.Errorf("Retry-After = %q, want %q", got, createConflictRetryAfterSeconds)
		}
	})

	t.Run("gate-free-still-reports-the-privilege-requirement", func(t *testing.T) {
		rr := post()
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want the pre-existing 500; body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "root privileges") {
			t.Errorf("body %q is not the root-privileges error", rr.Body.String())
		}
		if rr.Header().Get("Retry-After") != "" {
			t.Errorf("Retry-After set on a %d answer", rr.Code)
		}
	})
}

// TestStatusReportsTheCreateGate (review R10): a client told to retry needs a
// way to know when. is_creating_devices is a proxy — published after the gate is
// taken, cleared before it is released — so the gate itself is reported.
func TestStatusReportsTheCreateGate(t *testing.T) {
	sm := newCreateGateManager()

	if st := sm.GetStatus(); st.CreateBatchInProgress || st.CreateBatchRequested != 0 {
		t.Fatalf("idle status reports in_progress=%v requested=%d", st.CreateBatchInProgress, st.CreateBatchRequested)
	}

	hold, err := sm.tryEnterCreateBatch(1234)
	if err != nil {
		t.Fatalf("tryEnterCreateBatch: %v", err)
	}
	st := sm.GetStatus()
	if !st.CreateBatchInProgress {
		t.Error("create_batch_in_progress is false while a batch holds the gate")
	}
	if st.CreateBatchRequested != 1234 {
		t.Errorf("create_batch_requested = %d, want 1234", st.CreateBatchRequested)
	}
	// The proxy is deliberately NOT the gate: nothing published it here.
	if creating, _ := sm.isCreatingDevices.Load().(bool); creating {
		t.Error("isCreatingDevices is set by tryEnterCreateBatch; it must stay the batch body's flag")
	}

	hold()
	if st := sm.GetStatus(); st.CreateBatchInProgress || st.CreateBatchRequested != 0 {
		t.Fatalf("status after release reports in_progress=%v requested=%d", st.CreateBatchInProgress, st.CreateBatchRequested)
	}
}
