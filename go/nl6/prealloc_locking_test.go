/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

// nl6#556: the four SimulatorManager fields on the device-creation path
// (nextTunIndex, currentIP, tunPoolSize, maxWorkers) were read and written bare
// in prealloc.go while the same fields were locked elsewhere. Every test here
// is meant to be run under -race; several of them assert an invariant that no
// amount of single-goroutine testing can see.

// newPreallocLockTestManager builds the smallest manager the pre-allocation and
// status paths need. No namespace, so the workers take the plain
// createTunInterface path (which fails without root / off Linux — the name
// COMPUTATION is what these tests exercise, not the interface).
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
// duplicate-name defect: two overlapping batches plus a stream of on-demand
// getNextTunName calls must between them produce a set of names with no
// repetition, and nextTunIndex must end up advanced by the sum.
func TestPreAllocReservationNeverYieldsADuplicateTunName(t *testing.T) {
	const (
		batches   = 4
		poolSize  = 64
		onDemands = 200
	)

	sm := newPreallocLockTestManager()
	startIP := net.ParseIP("10.42.0.10").To4()

	var mu sync.Mutex
	var names []string
	record := func(n ...string) {
		mu.Lock()
		names = append(names, n...)
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for b := 0; b < batches; b++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			base := sm.reservePreAllocBatch(poolSize, 100, startIP)
			record(tunNamesForBatch(base, poolSize)...)
		}()
	}
	for i := 0; i < onDemands; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Exactly how the creation path calls it (device.go).
			sm.mu.Lock()
			name := sm.getNextTunName()
			sm.mu.Unlock()
			record(name)
		}()
	}
	wg.Wait()

	want := batches*poolSize + onDemands
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
		t.Fatalf("nextTunIndex = %d, want %d (sum of every reservation)", got, want)
	}
}

// TestPreAllocReservationAdvancesIndexAndIPTogether asserts the pair invariant:
// a reader must never observe nextTunIndex advanced by k batches while
// currentIP is still at batch k-1's end, which is what separate bare writes
// allowed.
func TestPreAllocReservationAdvancesIndexAndIPTogether(t *testing.T) {
	const (
		batches  = 2000
		poolSize = 1
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
// Interface creation itself fails here (no root, or not Linux); that is
// deliberate — the failure path still computes the name, which is the part
// under test.
func TestPreAllocWorkersDoNotReadTheSharedTunIndex(t *testing.T) {
	const (
		poolSize  = 40
		onDemands = 100
	)

	sm := newPreallocLockTestManager()

	stop := make(chan struct{})
	var handedOut int
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < onDemands; i++ {
			select {
			case <-stop:
				return
			default:
			}
			sm.mu.Lock()
			_ = sm.getNextTunName()
			sm.mu.Unlock()
			handedOut++
		}
	}()

	if err := sm.PreAllocateTunInterfaces(poolSize, 8, net.ParseIP("10.42.1.1").To4(), "16"); err != nil {
		t.Fatalf("PreAllocateTunInterfaces: %v", err)
	}
	close(stop)
	wg.Wait()

	sm.mu.RLock()
	idx, poolSizeField, workers := sm.nextTunIndex, sm.tunPoolSize, sm.maxWorkers
	sm.mu.RUnlock()

	if idx != poolSize+handedOut {
		t.Fatalf("nextTunIndex = %d, want %d (pool %d + on-demand %d)", idx, poolSize+handedOut, poolSize, handedOut)
	}
	if poolSizeField != poolSize || workers != 8 {
		t.Fatalf("tunPoolSize/maxWorkers = %d/%d, want %d/8", poolSizeField, workers, poolSize)
	}
}

// TestPreAllocProgressCounterLosesNoUpdates pins the progress counter as a
// genuine atomic read-modify-write. A load-then-store (what this was before
// nl6#556) undercounts from N goroutines.
func TestPreAllocProgressCounterLosesNoUpdates(t *testing.T) {
	const (
		goroutines = 64
		perG       = 200
	)

	sm := newPreallocLockTestManager()
	sm.preAllocProgress.Store(0)

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

// TestCleanupClearsPoolSizeUnderTheFleetLock pins the two locking faults on the
// cleanup path: tunPoolSize (an sm.mu field, read by GetStatus under
// sm.mu.RLock) and the tunInterfacePool REASSIGNMENT, which must take the same
// mutex the pre-allocation workers take for the contents.
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

	// A pre-allocation worker writing the pool's CONTENTS while cleanup
	// replaces the map.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			sm.tunPoolMutex.Lock()
			sm.tunInterfacePool[fmt.Sprintf("10.42.9.%d", i%250)] = &TunInterface{Name: "nl6-x", PreAllocated: false}
			sm.tunPoolMutex.Unlock()
		}
	}()

	for i := 0; i < 50; i++ {
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
