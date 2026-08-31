/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

// nl6#556: four SimulatorManager fields on the device-creation path
// (nextTunIndex, currentIP, tunPoolSize, maxWorkers) were read and written bare
// in prealloc.go while the same fields were locked elsewhere.
//
// Which kind of pin each test is, since the two are not interchangeable:
//
//   - RACE-DETECTOR pins (only fail under -race, and only because the detector
//     pairs an unsynchronised read with a write):
//     TestPreAllocWorkersDoNotReadTheSharedTunIndex,
//     TestPreAllocSnapshotIsRaceFree,
//     TestCleanupClearsPoolSizeUnderTheFleetLock.
//   - VALUE pins (fail on an assertion, with or without -race; no lock is
//     involved in the ones about the counter, since a load-then-store on an
//     atomic is not a data race — it just loses updates):
//     TestPreAllocReservationNeverYieldsADuplicateTunName (duplicate names),
//     TestPreAllocReservationAdvancesIndexAndIPTogether (torn pair),
//     TestPreAllocProgress* , TestPreAllocBatchIPs*, TestPreAllocCommits*.
//
// TestPreAllocReservationNeverYieldsADuplicateTunName is deliberately BOTH: its
// own duplicate check has to be load-bearing, not merely backed by the detector.

// newPreallocLockTestManager builds the smallest manager the pre-allocation and
// status paths need. No namespace, so the workers take the plain
// createTunInterface path.
func newPreallocLockTestManager() *SimulatorManager {
	sm := &SimulatorManager{
		devices:          make(map[string]*DeviceSimulator),
		deviceIPs:        make(map[string]struct{}),
		tunInterfacePool: make(map[string]*TunInterface),
	}
	sm.isPreAllocating.Store(false)
	sm.isCreatingDevices.Store(false)
	sm.deviceCreateProgress.Store(0)
	sm.deviceCreateTotal.Store(0)
	return sm
}

// tunNamesForBatch expands a reserved base index into the names that batch owns.
func tunNamesForBatch(base, poolSize int) []string {
	names := make([]string, poolSize)
	for i := range names {
		names[i] = fmt.Sprintf("%s%d", TUN_DEVICE_PREFIX, base+i)
	}
	return names
}

// TestPreAllocReservationNeverYieldsADuplicateTunName is the pin for the
// duplicate-name defect: overlapping batches plus a stream of on-demand
// getNextTunName calls must between them produce a set of names with no
// repetition, and nextTunIndex must end up advanced by the sum.
//
// The contention is deliberately heavy (8 reservers × 100 reservations, plus a
// spinning on-demand writer). With a handful of reservations the DUPLICATE check
// almost never fires when the reservation lock is removed — the two reservers
// have to read the same base — and the test passes its own assertions while
// being saved by the race detector alone. This test's own assertion has to be
// the pin.
func TestPreAllocReservationNeverYieldsADuplicateTunName(t *testing.T) {
	const (
		reservers = 8
		rounds    = 100
		poolSize  = 4
	)

	sm := newPreallocLockTestManager()
	startIP := net.ParseIP("10.42.0.10").To4()

	var mu sync.Mutex
	names := make([]string, 0, reservers*rounds*poolSize+4096)
	record := func(n ...string) {
		mu.Lock()
		names = append(names, n...)
		mu.Unlock()
	}

	stop := make(chan struct{})
	running := make(chan struct{}, 1)
	var handedOut atomic.Int64

	// On-demand namer, spinning for the whole run — exactly how the creation
	// path calls it (device.go), under sm.mu.
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		first := true
		for {
			select {
			case <-stop:
				return
			default:
			}
			sm.mu.Lock()
			name := sm.getNextTunName()
			sm.mu.Unlock()
			handedOut.Add(1)
			record(name)
			if first {
				running <- struct{}{}
				first = false
			}
		}
	}()
	<-running

	var wg sync.WaitGroup
	for r := 0; r < reservers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				base := sm.reservePreAllocBatch(poolSize, 100, startIP)
				record(tunNamesForBatch(base, poolSize)...)
			}
		}()
	}
	wg.Wait()
	close(stop)
	writerWG.Wait()

	want := reservers*rounds*poolSize + int(handedOut.Load())
	if len(names) != want {
		t.Fatalf("collected %d names, want %d", len(names), want)
	}
	seen := make(map[string]int, len(names))
	for _, n := range names {
		seen[n]++
	}
	if len(seen) != want {
		dupes := make([]string, 0, 4)
		for n, c := range seen {
			if c > 1 {
				dupes = append(dupes, fmt.Sprintf("%s×%d", n, c))
			}
			if len(dupes) == 4 {
				break
			}
		}
		t.Fatalf("duplicate TUN names computed: %d distinct of %d (e.g. %v)", len(seen), want, dupes)
	}

	sm.mu.RLock()
	got := sm.nextTunIndex
	sm.mu.RUnlock()
	if got != want {
		t.Fatalf("nextTunIndex = %d, want %d (sum of every reservation and hand-out)", got, want)
	}
}

// TestPreAllocReservationAdvancesIndexAndIPTogether asserts the pair invariant:
// a reader must never observe nextTunIndex advanced by k batches while
// currentIP is still at batch k-1's end, which is what separate bare writes
// allowed.
func TestPreAllocReservationAdvancesIndexAndIPTogether(t *testing.T) {
	const (
		batches  = 1000
		poolSize = 2 // > 1, so the "whole number of batches" arm below is live
		prefix   = 16
		readers  = 2
	)

	sm := newPreallocLockTestManager()
	start := net.ParseIP("10.42.0.1").To4()

	// The end IP after k reservations. Every reserver walks from the previous
	// batch's end, so these are exactly the (index, IP) pairs a reader may
	// legitimately observe: index k*poolSize pairs with endIPs[k], nothing else.
	endIPs := make([]string, batches+1)
	walk := make(net.IP, len(start))
	copy(walk, start)
	endIPs[0] = walk.String()
	for k := 1; k <= batches; k++ {
		for i := 0; i < poolSize; i++ {
			walk = nextHost(walk, prefix)
		}
		endIPs[k] = walk.String()
	}

	stop := make(chan struct{})
	running := make(chan struct{}, readers)
	var readerWG sync.WaitGroup
	for r := 0; r < readers; r++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			first := true
			for {
				select {
				case <-stop:
					return
				default:
				}
				sm.mu.RLock()
				idx := sm.nextTunIndex
				ip := sm.currentIP.String()
				sm.mu.RUnlock()
				if first {
					// Only start reserving once a reader is actually spinning,
					// otherwise the whole loop below can finish before this
					// goroutine is ever scheduled.
					running <- struct{}{}
					first = false
				}
				if idx == 0 {
					continue // nothing reserved yet; currentIP is still nil
				}
				if idx%poolSize != 0 || idx/poolSize > batches {
					t.Errorf("observed nextTunIndex = %d, not a whole number of batches", idx)
					return
				}
				if ip != endIPs[idx/poolSize] {
					t.Errorf("torn pair: nextTunIndex = %d but currentIP = %s, want %s", idx, ip, endIPs[idx/poolSize])
					return
				}
			}
		}()
	}
	for r := 0; r < readers; r++ {
		<-running
	}

	for k := 1; k <= batches; k++ {
		sm.reservePreAllocBatch(poolSize, 100, net.ParseIP(endIPs[k]).To4())
	}
	close(stop)
	readerWG.Wait()

	sm.mu.RLock()
	idx, ip := sm.nextTunIndex, sm.currentIP.String()
	sm.mu.RUnlock()
	if idx != batches*poolSize || ip != endIPs[batches] {
		t.Fatalf("final state (%d, %s), want (%d, %s)", idx, ip, batches*poolSize, endIPs[batches])
	}
}

// TestPreAllocWorkersDoNotReadTheSharedTunIndex drives the real
// PreAllocateTunInterfaces while another goroutine hands out on-demand names.
// The workers must build their names from the reserved base, never from
// sm.nextTunIndex — under -race, a worker reading the field is a data race
// against getNextTunName's increment.
//
// The on-demand writer SPINS until the batch is done and hands over a `running`
// handshake first. A bounded loop of hand-outs does not work: it completes
// during the ~10 log.Printf lines and the IP precompute that run before the
// first worker goroutine launches, the two never overlap, and the detector has
// nothing to pair — measured at 37/40 clean runs with the defect restored.
//
// TWO MODES, both intended. Unprivileged (any OS) or non-Linux: every
// createTunInterface fails immediately and what runs is the name COMPUTATION,
// which is the part under test. As root on Linux (the scale box, a privileged
// CI container): 40 real sim<N> links are created, so t.Cleanup deletes them —
// a no-op in the first mode, where the pool stays empty.
func TestPreAllocWorkersDoNotReadTheSharedTunIndex(t *testing.T) {
	const poolSize = 40

	sm := newPreallocLockTestManager()
	t.Cleanup(sm.CleanupPreAllocatedInterfaces)

	stop := make(chan struct{})
	running := make(chan struct{}, 1)
	var handedOut atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		first := true
		for {
			select {
			case <-stop:
				return
			default:
			}
			sm.mu.Lock()
			_ = sm.getNextTunName()
			sm.mu.Unlock()
			handedOut.Add(1)
			if first {
				running <- struct{}{}
				first = false
			}
		}
	}()
	<-running

	// Only the 5-minute timeout can make this return an error — interface
	// creation failures are logged and counted, not returned — so this asserts
	// the batch completed, nothing about the interfaces.
	if err := sm.PreAllocateTunInterfaces(poolSize, 8, net.ParseIP("10.42.1.1").To4(), "16"); err != nil {
		t.Fatalf("PreAllocateTunInterfaces: %v", err)
	}
	close(stop)
	wg.Wait()

	sm.mu.RLock()
	idx, poolSizeField, workers := sm.nextTunIndex, sm.tunPoolSize, sm.maxWorkers
	sm.mu.RUnlock()

	if want := poolSize + int(handedOut.Load()); idx != want {
		t.Fatalf("nextTunIndex = %d, want %d (pool %d + on-demand %d)", idx, want, poolSize, handedOut.Load())
	}
	if poolSizeField != poolSize || workers != 8 {
		t.Fatalf("tunPoolSize/maxWorkers = %d/%d, want %d/8", poolSizeField, workers, poolSize)
	}
}

// TestPreAllocBatchIPsWalksFromTheStartAddress pins the up-front IP precompute.
// An off-by-one (advancing before recording) is invisible on a test host — it
// addresses every interface one host high, makes every device create miss the
// pool, and presents as a performance regression — so the walk is asserted
// directly: element 0 IS the start address, element i is nextHost applied i
// times, and the returned end IP is nextHost applied poolSize times.
func TestPreAllocBatchIPsWalksFromTheStartAddress(t *testing.T) {
	cases := []struct {
		start  string
		mask   string
		pool   int
		expect []string // spot-check of the first few, spelled out
	}{
		{"10.42.0.1", "16", 4, []string{"10.42.0.1", "10.42.0.2", "10.42.0.3", "10.42.0.4"}},
		{"10.42.0.254", "24", 3, []string{"10.42.0.254", "10.42.1.1", "10.42.1.2"}},
		{"10.0.0.1", "8", 2, []string{"10.0.0.1", "10.0.0.2"}},
	}

	for _, tc := range cases {
		t.Run(tc.start+"/"+tc.mask, func(t *testing.T) {
			start := net.ParseIP(tc.start).To4()
			prefix := parsePrefix(tc.mask)

			ips, endIP := preAllocBatchIPs(start, prefix, tc.pool)
			if len(ips) != tc.pool {
				t.Fatalf("got %d IPs, want %d", len(ips), tc.pool)
			}
			if !ips[0].Equal(start) {
				t.Fatalf("first interface IP = %s, want the start address %s", ips[0], start)
			}
			for i, want := range tc.expect {
				if got := ips[i].String(); got != want {
					t.Fatalf("interface %d IP = %s, want %s", i, got, want)
				}
			}

			// nextHost applied i times, independently of the precompute.
			walk := make(net.IP, len(start))
			copy(walk, start)
			for i := 0; i < tc.pool; i++ {
				if !ips[i].Equal(walk) {
					t.Fatalf("interface %d IP = %s, want nextHost^%d(%s) = %s", i, ips[i], i, start, walk)
				}
				walk = nextHost(walk, prefix)
			}
			if !endIP.Equal(walk) {
				t.Fatalf("end IP = %s, want nextHost^%d(%s) = %s", endIP, tc.pool, start, walk)
			}

			// The start address must not have been mutated by the walk.
			if got := start.String(); got != tc.start {
				t.Fatalf("startIP mutated to %s", got)
			}
		})
	}
}

// TestPreAllocCommitsTheBatchEndIP pins the same walk THROUGH the real entry
// point: after a batch, the manager's currentIP is nextHost applied poolSize
// times to the start address.
func TestPreAllocCommitsTheBatchEndIP(t *testing.T) {
	const (
		poolSize = 8
		mask     = "24"
	)

	sm := newPreallocLockTestManager()
	t.Cleanup(sm.CleanupPreAllocatedInterfaces)
	start := net.ParseIP("10.42.7.1").To4()

	if err := sm.PreAllocateTunInterfaces(poolSize, 4, start, mask); err != nil {
		t.Fatalf("PreAllocateTunInterfaces: %v", err)
	}

	want := make(net.IP, len(start))
	copy(want, start)
	for i := 0; i < poolSize; i++ {
		want = nextHost(want, parsePrefix(mask))
	}

	sm.mu.RLock()
	got := sm.currentIP.String()
	sm.mu.RUnlock()
	if got != want.String() {
		t.Fatalf("currentIP = %s after a batch of %d from %s, want %s", got, poolSize, start, want)
	}
}

// TestPreAllocRejectsANonIPv4Start: nextHost returns its input unchanged for
// anything that is not IPv4, so without the guard every interface in the batch
// gets the SAME address and the committed currentIP never advances.
func TestPreAllocRejectsANonIPv4Start(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip   net.IP
	}{
		{"nil", nil},
		{"ipv6", net.ParseIP("2001:db8::1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm := newPreallocLockTestManager()
			if err := sm.PreAllocateTunInterfaces(4, 2, tc.ip, "16"); err == nil {
				t.Fatal("PreAllocateTunInterfaces accepted a non-IPv4 start address")
			}
			sm.mu.RLock()
			idx, pool := sm.nextTunIndex, sm.tunPoolSize
			sm.mu.RUnlock()
			if idx != 0 || pool != 0 {
				t.Fatalf("refused batch still reserved state: nextTunIndex=%d tunPoolSize=%d", idx, pool)
			}
		})
	}
}

// TestPreAllocSnapshotIsRaceFree races the accessor device creation uses
// against a batch reservation. Without it the device path read tunPoolSize and
// maxWorkers bare — and no existing test reaches those lines, since
// CreateDevicesWithOptions returns on the root check first and
// createDevicesParallel has no test caller.
func TestPreAllocSnapshotIsRaceFree(t *testing.T) {
	const reservations = 500

	sm := newPreallocLockTestManager()
	endIP := net.ParseIP("10.42.0.1").To4()

	stop := make(chan struct{})
	running := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		first := true
		for {
			select {
			case <-stop:
				return
			default:
			}
			poolSize, workers := sm.preAllocSnapshot()
			if poolSize != 0 && workers == 0 {
				t.Errorf("snapshot (%d, %d): pool size set with no workers", poolSize, workers)
				return
			}
			if first {
				running <- struct{}{}
				first = false
			}
		}
	}()
	<-running

	for i := 0; i < reservations; i++ {
		sm.reservePreAllocBatch(16, 100, endIP)
	}
	close(stop)
	wg.Wait()
}

// TestPreAllocProgressCounterLosesNoUpdates pins the progress counter as a
// genuine atomic read-modify-write. A load-then-store (what this was before
// nl6#556) undercounts from N goroutines. A VALUE pin, not a race pin: a
// load-then-store on an atomic is not a data race.
func TestPreAllocProgressCounterLosesNoUpdates(t *testing.T) {
	const (
		goroutines = 64
		perG       = 200
	)

	sm := newPreallocLockTestManager()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				sm.bumpPreAllocProgress()
			}
		}()
	}
	wg.Wait()

	if got := int(sm.preAllocProgress.Load()); got != goroutines*perG {
		t.Fatalf("preAllocProgress = %d, want %d (lost updates)", got, goroutines*perG)
	}
}

// TestPreAllocProgressSurvivesAConcurrentBatchStart: a batch beginning while
// another batch's workers are still counting must not zero their count. The old
// Store(0) at the top of PreAllocateTunInterfaces both wiped the running batch
// and raced its Add calls, which is the fault the atomic counter exists to
// prevent, one line further up.
func TestPreAllocProgressSurvivesAConcurrentBatchStart(t *testing.T) {
	const (
		workers = 32
		perW    = 200
	)

	sm := newPreallocLockTestManager()

	// The batch-start goroutine SPINS for the whole run, with a handshake
	// before the counting starts. A bounded number of starts is caught on only
	// 19 of 20 runs: they can all land before the first worker increments.
	stop := make(chan struct{})
	running := make(chan struct{}, 1)
	var starter sync.WaitGroup
	starter.Add(1)
	go func() {
		defer starter.Done()
		first := true
		for {
			select {
			case <-stop:
				return
			default:
			}
			sm.beginPreAllocProgress()
			if first {
				running <- struct{}{}
				first = false
			}
		}
	}()
	<-running

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perW; i++ {
				sm.bumpPreAllocProgress()
			}
		}()
	}
	wg.Wait()
	close(stop)
	starter.Wait()

	if got := int(sm.preAllocProgress.Load()); got != workers*perW {
		t.Fatalf("preAllocProgress = %d, want %d (a batch start lost another batch's count)", got, workers*perW)
	}
}

// TestPreAllocProgressForIsBatchRelative pins the status arithmetic, including
// the clamp: a batch publishing its baseline after the counter was read must not
// report a negative count.
func TestPreAllocProgressForIsBatchRelative(t *testing.T) {
	cases := []struct {
		progress, base int64
		want           int
	}{
		{0, 0, 0},
		{7, 0, 7},
		{107, 100, 7},
		{100, 107, 0}, // baseline published after the read; clamped
	}
	for _, tc := range cases {
		if got := preAllocProgressFor(tc.progress, tc.base); got != tc.want {
			t.Fatalf("preAllocProgressFor(%d, %d) = %d, want %d", tc.progress, tc.base, got, tc.want)
		}
	}
}

// TestCleanupClearsPoolSizeUnderTheFleetLock pins the cleanup path's locking:
// tunPoolSize is an sm.mu field (GetStatus reads it under sm.mu.RLock) and was
// written bare, and the tunInterfacePool reassignment must stay under the mutex
// that guards the CONTENTS while the lock boundaries move around it.
//
// (The reassignment was already covered on the baseline — the function held the
// mutex for its whole body. The faults that were actually here were the bare
// tunPoolSize write and the lock held across the bulk `ip` delete. This asserts
// the invariant prospectively, not a fixed bug.)
func TestCleanupClearsPoolSizeUnderTheFleetLock(t *testing.T) {
	sm := newPreallocLockTestManager()
	sm.preAllocProgress.Store(7)
	sm.mu.Lock()
	sm.tunPoolSize = 42
	sm.mu.Unlock()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// A status reader, as the web console polls it.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = sm.GetStatus()
		}
	}()

	// Pre-allocation workers writing the pool's CONTENTS while cleanup replaces
	// the map. Several of them, and many cleanup rounds: with one writer and 50
	// rounds, moving the reassignment out from under the mutex was caught on
	// only 17 of 20 runs.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				sm.tunPoolMutex.Lock()
				sm.tunInterfacePool[fmt.Sprintf("10.42.%d.%d", w, i%250)] = &TunInterface{Name: "nl6-x", PreAllocated: false}
				sm.tunPoolMutex.Unlock()
			}
		}(w)
	}

	for i := 0; i < 300; i++ {
		sm.CleanupPreAllocatedInterfaces()
	}
	close(stop)
	wg.Wait()

	sm.mu.RLock()
	got := sm.tunPoolSize
	sm.mu.RUnlock()
	if got != 0 {
		t.Fatalf("tunPoolSize = %d after cleanup, want 0", got)
	}
}
