/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// PreAllocateTunInterfaces creates a pool of TUN interfaces in parallel for faster device creation
func (sm *SimulatorManager) PreAllocateTunInterfaces(poolSize int, maxWorkers int, startIP net.IP, netmask string) error {
	if poolSize <= 0 {
		return nil // No pre-allocation requested
	}

	// nextHost returns its input unchanged for anything that is not IPv4, so a
	// nil or IPv6 startIP would give every interface in the batch the SAME
	// address and leave the committed currentIP where it started. Refuse
	// instead of pre-allocating a pool of duplicates (nl6#556 review).
	if startIP.To4() == nil {
		return fmt.Errorf("pre-allocation requires an IPv4 start address, got %q", startIP.String())
	}

	// Clamp workers to a sane band: the upper bound prevents resource
	// exhaustion, the lower bound prevents make(chan, n) panicking on a
	// negative request-supplied value (CodeQL go/uncontrolled-allocation-size).
	if maxWorkers > 500 {
		maxWorkers = 500
		log.Printf("WARNING: Limiting workers to 500 to prevent resource exhaustion")
	}
	if maxWorkers < 1 {
		maxWorkers = 100
	}

	// Set pre-allocation status. The progress counter is NOT zeroed here: a
	// Store racing the workers' Add loses exactly the updates the atomic
	// counter exists to keep, and zeroing it would also wipe a concurrent
	// batch's live count. beginPreAllocProgress publishes the batch's baseline
	// instead, and everything downstream is relative to it (nl6#556 review).
	sm.isPreAllocating.Store(true)
	progressBase := sm.beginPreAllocProgress()
	defer sm.isPreAllocating.Store(false)

	log.Printf("Pre-allocating %d TUN interfaces with %d workers...", poolSize, maxWorkers)
	log.Printf("Test Parameters:")
	log.Printf("   - Pool Size: %d interfaces", poolSize)
	log.Printf("   - Workers: %d parallel workers", maxWorkers)
	log.Printf("   - Start IP: %s/%s", startIP.String(), netmask)
	log.Printf("   - Test Started: %s", time.Now().Format("2006-01-02 15:04:05.000"))
	log.Println()

	startTime := time.Now()
	log.Printf("PRE-ALLOCATION START TIME: %v", startTime.Format("15:04:05.000"))

	// Walk the batch's IPs up front, in one pass. Precomputing is what lets the
	// reservation below commit the index base and the end IP together.
	prefix := parsePrefix(netmask)
	interfaceIPs, endIP := preAllocBatchIPs(startIP, prefix, poolSize)

	// Reserve everything this batch takes from the manager's shared allocation
	// state in ONE critical section, BEFORE any worker starts (nl6#556).
	baseTunIndex := sm.reservePreAllocBatch(poolSize, maxWorkers, endIP)

	// Worker pool for parallel interface creation
	sem := make(chan struct{}, maxWorkers) // Limit concurrent workers
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	for i := 0; i < poolSize; i++ {
		interfaceIP := interfaceIPs[i]

		wg.Add(1)
		go func(interfaceIndex int, ip net.IP) {
			defer wg.Done()

			// Acquire worker slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Generate unique interface name from the base index this batch
			// RESERVED before the workers started. Reading sm.nextTunIndex
			// here (as this did before nl6#556) let a concurrent
			// getNextTunName move the base mid-batch, so two workers of the
			// SAME batch could compute the same name.
			tunName := fmt.Sprintf("%s%d", TUN_DEVICE_PREFIX, baseTunIndex+interfaceIndex)

			// Create TUN interface (in namespace if enabled)
			var tunIface *TunInterface
			var err error
			if sm.useNamespace && sm.netNamespace != nil {
				tunIface, err = createTunInterfaceInNamespaceViaExec(sm.netNamespace.Name, tunName, ip, netmask)
			} else {
				tunIface, err = createTunInterface(tunName, ip, netmask)
			}
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("failed to create interface %s: %v", tunName, err))
				mu.Unlock()
				return
			}

			// Mark as pre-allocated
			tunIface.PreAllocated = true

			// Store interface in the pool indexed by IP
			sm.tunPoolMutex.Lock()
			sm.tunInterfacePool[ip.String()] = tunIface
			sm.tunPoolMutex.Unlock()

			// Update progress counter. Batch-relative, since the manager's
			// counter is Add-only and shared with any concurrent batch.
			newCurrent := sm.bumpPreAllocProgress() - progressBase

			// Log progress every 50 interfaces. (The old condition OR'd in
			// == 100, == 200 and == 250, all three of which are already
			// multiples of 50.)
			if newCurrent%50 == 0 {
				elapsed := time.Since(startTime)
				rate := float64(newCurrent) / elapsed.Seconds()
				log.Printf("Progress: %d/%d interfaces created (%.1f interfaces/sec, %v elapsed)",
					newCurrent, poolSize, rate, elapsed.Round(time.Millisecond))
			}

		}(i, interfaceIP)
	}

	// Wait for all workers to complete with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All workers completed successfully
	case <-time.After(5 * time.Minute):
		// Pre-existing and NOT fixed here: the workers are detached, not
		// cancelled. They keep creating interfaces and writing the pool after
		// the caller has fallen back to on-demand creation, and they keep
		// adding to the progress counter, so the summary above is never
		// reached for this batch. The reservation is what makes that merely
		// wasteful rather than corrupting — the names and the index range are
		// already committed, so a fallback create cannot collide with a
		// straggler. Cancelling them needs a context through
		// createTunInterface*, which is out of nl6#556's scope.
		log.Printf("WARNING: Pre-allocation timed out after 5 minutes")
		return fmt.Errorf("pre-allocation timed out")
	}

	elapsed := time.Since(startTime)
	created := int(sm.preAllocProgress.Load()) - progressBase

	log.Printf("PRE-ALLOCATION END TIME: %v", time.Now().Format("15:04:05.000"))
	log.Println()

	log.Printf("PERFORMANCE RESULTS:")
	log.Printf("   Total interfaces created: %d/%d", created, poolSize)
	log.Printf("   Total time: %v", elapsed)
	if created > 0 {
		// Guard the divisions: a batch in which every interface failed used to
		// print +Inf / NaN here.
		log.Printf("   Average time per interface: %.3f ms", float64(elapsed.Nanoseconds())/float64(created*1e6))
		log.Printf("   Interfaces per second: %.2f", float64(created)/elapsed.Seconds())
	}
	log.Printf("   Workers used: %d", maxWorkers)

	if len(errors) > 0 {
		log.Printf("   Errors encountered: %d", len(errors))
		log.Printf("   Success rate: %.1f%%", float64(created)/float64(poolSize)*100.0)
		log.Println()
		log.Printf("First few errors for debugging:")
		for i, err := range errors {
			if i >= 5 { // Limit error output
				log.Printf("... and %d more errors", len(errors)-5)
				break
			}
			log.Printf("   Error %d: %v", i+1, err)
		}
	} else {
		log.Printf("   Success rate: 100%%")
	}

	// nextTunIndex and currentIP were advanced by reservePreAllocBatch before
	// the workers started — deliberately not here. Advancing the INDEX at the
	// end left the whole batch window in which a concurrent getNextTunName
	// handed out a name this batch was already using, and left the index
	// un-advanced on the timeout return above while workers had already
	// created interfaces from that range.
	//
	// The IP half is NOT a reservation, and this must not be read as one: the
	// batch's only production caller (CreateDevicesWithOptions) rewinds
	// currentIP to the batch START immediately after this returns, because the
	// devices have to land on the addresses the pool was created with. IP
	// allocation is therefore still a single shared cursor — two overlapping
	// batches can still hand out overlapping device IPs — and nl6#556 does not
	// close that. currentIP is committed here only so that no reader can
	// observe the index advanced against a stale IP.
	return nil
}

// reservePreAllocBatch commits, in ONE sm.mu critical section, everything a
// pre-allocation batch takes from the manager's shared allocation state, and
// returns the TUN index base the batch owns: names TUN_DEVICE_PREFIX+base ..
// base+poolSize-1 are reserved for it and no other caller can compute them.
//
// One critical section, not four, because nextTunIndex and currentIP advance
// together: a reader must never see the index advanced against a stale IP.
// `endIP` is the first host AFTER the batch.
//
// Only the TUN index is genuinely RESERVED (no other caller can compute a name
// in the batch's range). The IP is a shared cursor that this batch's caller
// rewinds — see the note at the end of PreAllocateTunInterfaces.
//
// tunPoolSize and maxWorkers are last-writer-wins across concurrent batches;
// per-field locking makes them race-free, not correct. See the CLAUDE.md note.
//
// The lock covers the FIELD ACCESSES ONLY. No interface is created and no exec
// runs under it — the 500-worker pre-allocator depends on that.
func (sm *SimulatorManager) reservePreAllocBatch(poolSize int, maxWorkers int, endIP net.IP) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Pool size tells device creation that pre-allocation was done.
	sm.tunPoolSize = poolSize
	sm.maxWorkers = maxWorkers

	base := sm.nextTunIndex
	sm.nextTunIndex += poolSize

	sm.currentIP = make(net.IP, len(endIP))
	copy(sm.currentIP, endIP)

	return base
}

// preAllocBatchIPs walks the poolSize addresses a batch will use, starting at
// startIP, and returns them together with the first host AFTER the batch (what
// currentIP advances to). Pure: same nextHost rule, same order and same
// per-interface allocation the launch loop used to do inline, hoisted so the
// reservation can commit the index base and the end IP together — and so the
// walk is testable without root or a manager.
//
// The i-th element is nextHost applied i times to startIP, and the returned end
// IP is nextHost applied poolSize times. An off-by-one here is invisible on a
// unit-test host: it would address every interface one host high, make every
// device create miss the pool and fall back to on-demand creation, and present
// as a performance regression rather than a bug.
//
// The slice is request-sized (poolSize comes from a REST `count`), which is not
// a new exposure: the loop it replaces already allocated one net.IP AND started
// one goroutine per element, so the pool size has always been the bound. Unlike
// maxWorkers there is no CodeQL go/uncontrolled-allocation-size concern to
// answer — a caller asking for a fleet of N genuinely needs N interfaces, and
// poolSize <= 0 is refused above.
func preAllocBatchIPs(startIP net.IP, prefix int, poolSize int) ([]net.IP, net.IP) {
	ips := make([]net.IP, poolSize)
	walk := make(net.IP, len(startIP))
	copy(walk, startIP)
	for i := 0; i < poolSize; i++ {
		ips[i] = make(net.IP, len(walk))
		copy(ips[i], walk)
		walk = nextHost(walk, prefix)
	}
	return ips, walk
}

// preAllocSnapshot reads the two pre-allocation settings under the lock that
// owns them, as one pair. Device creation needs both and must not read either
// bare: a concurrent batch's reservePreAllocBatch writes them.
func (sm *SimulatorManager) preAllocSnapshot() (poolSize int, maxWorkers int) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.tunPoolSize, sm.maxWorkers
}

// beginPreAllocProgress publishes the calling batch's baseline for the shared
// progress counter and returns it. Everything the batch reports is relative to
// that baseline.
//
// The counter is Add-ONLY. It used to be zeroed at the top of every batch,
// which (a) raced the workers' increments — a Store landing between a worker's
// Add and another's loses updates, the very fault bumpPreAllocProgress exists
// to prevent — and (b) wiped a concurrent batch's live count. Two overlapping
// batches still SHARE the gauge, so GetStatus reports whichever baseline was
// published last; that is a display limitation, not a lost count, and fixing it
// properly means per-batch status records rather than one manager-global pair.
func (sm *SimulatorManager) beginPreAllocProgress() int {
	base := int(sm.preAllocProgress.Load())
	sm.preAllocProgressBase.Store(int64(base))
	return base
}

// preAllocProgressFor turns the Add-only counter and a batch baseline into the
// batch-relative progress GetStatus reports. Clamped at zero: a batch that
// published its baseline after the read would otherwise show a negative count.
func preAllocProgressFor(progress, base int64) int {
	if progress < base {
		return 0
	}
	return int(progress - base)
}

// bumpPreAllocProgress increments the pre-allocation progress counter and
// returns the new absolute value.
//
// This is an atomic read-modify-write, not the load-then-store it used to be.
// The counter is progress only, so a lost update is not a correctness fault. It
// is fixed anyway because the summary log's "Total interfaces created: %d/%d"
// and per-interface timings are computed from it, and an undercount there is
// indistinguishable from failed interfaces.
func (sm *SimulatorManager) bumpPreAllocProgress() int {
	return int(sm.preAllocProgress.Add(1))
}

// bulkDeleteTunInterfaces deletes multiple TUN interfaces efficiently using batch commands
func (sm *SimulatorManager) bulkDeleteTunInterfaces(interfaceNames []string) error {
	if len(interfaceNames) == 0 {
		return nil
	}

	log.Printf("Bulk deleting %d TUN interfaces...", len(interfaceNames))
	startTime := time.Now()

	// Method 1: Use iproute2 batch mode for maximum efficiency
	if err := sm.deleteTunInterfacesBatch(interfaceNames); err == nil {
		elapsed := time.Since(startTime)
		log.Printf("Bulk deleted %d TUN interfaces in %v (%.3f ms per interface)",
			len(interfaceNames), elapsed, float64(elapsed.Nanoseconds())/float64(len(interfaceNames)*1e6))
		return nil
	}

	// Method 2: Fallback to parallel deletion if batch fails
	log.Printf("Batch deletion failed, falling back to parallel deletion")
	return sm.deleteTunInterfacesParallel(interfaceNames)
}

// deleteTunInterfacesBatch uses iproute2 batch mode for optimal performance
func (sm *SimulatorManager) deleteTunInterfacesBatch(interfaceNames []string) error {
	// Create a temporary batch file with deletion commands
	batchFile, err := os.CreateTemp("", "tun_delete_batch_*.txt")
	if err != nil {
		return fmt.Errorf("failed to create batch file: %v", err)
	}
	defer os.Remove(batchFile.Name())
	defer batchFile.Close()

	// Write all deletion commands to the batch file
	for _, ifName := range interfaceNames {
		if _, err := fmt.Fprintf(batchFile, "link delete %s\n", ifName); err != nil {
			return fmt.Errorf("failed to write to batch file: %v", err)
		}
	}
	batchFile.Sync()

	// Execute the batch file with ip command
	cmd := exec.Command("ip", "-batch", batchFile.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("batch deletion failed: %v, output: %s", err, string(output))
	}

	return nil
}

// deleteTunInterfacesParallel deletes interfaces in parallel as fallback
func (sm *SimulatorManager) deleteTunInterfacesParallel(interfaceNames []string) error {
	const maxWorkers = 50 // Limit concurrent deletions to avoid overwhelming the system
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []string

	// Worker pool for parallel deletion
	sem := make(chan struct{}, maxWorkers)

	for _, ifName := range interfaceNames {
		wg.Add(1)
		go func(interfaceName string) {
			defer wg.Done()

			// Acquire worker slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Delete the interface
			cmd := exec.Command("ip", "link", "delete", interfaceName)
			if err := cmd.Run(); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("%s: %v", interfaceName, err))
				mu.Unlock()
			}
		}(ifName)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("parallel deletion errors: %s", strings.Join(errors, ", "))
	}
	return nil
}

// CleanupPreAllocatedInterfaces destroys all pre-allocated TUN interfaces.
//
// Shutdown-only in practice (Shutdown's no-namespace path is the only caller),
// same contract as StopTrapExport / StopSyslogExport: it is not safe to race
// concurrent device creation, which can hold a pointer to a pooled interface it
// took under tunPoolMutex and then have it destroyed underneath.
func (sm *SimulatorManager) CleanupPreAllocatedInterfaces() {
	// tunPoolSize belongs to sm.mu (GetStatus reads it under sm.mu.RLock).
	// Cleared FIRST, before the pool lock is taken: doing it last left a
	// GetStatus poller reporting PreAllocTotal against an already-empty pool
	// for the whole duration of the bulk `ip -batch` delete, which is seconds
	// to minutes at fleet scale. Sequential, not nested — the documented order
	// is sm.mu -> tunPoolMutex (shutdownFast establishes it), and taking the
	// two the other way round would invert it.
	sm.mu.Lock()
	sm.tunPoolSize = 0
	sm.mu.Unlock()

	sm.tunPoolMutex.Lock()

	var interfaceNames []string

	// Collect interface names for bulk deletion
	for _, tunIface := range sm.tunInterfacePool {
		if tunIface != nil && tunIface.PreAllocated {
			interfaceNames = append(interfaceNames, tunIface.Name)
			tunIface.destroy() // Close file descriptors
		}
	}

	// Clear the pool under tunPoolMutex. The reassignment was already covered
	// on this path before nl6#556 (the function held the mutex for its whole
	// body); it is kept explicit here because a mutex that guards a map's
	// ENTRIES does not guard replacing the map, and the shape is easy to break
	// while moving the lock boundaries — which this change does.
	//
	// The two faults that WERE here: the bare sm.tunPoolSize write (now above)
	// and holding the pool lock across the bulk `ip` delete. Clearing the map
	// before that delete is what releases the lock: `interfaceNames` is local
	// by then, and a device create that races this misses the pool and creates
	// its interface on demand, which is the right answer for an interface that
	// is being deleted.
	sm.tunInterfacePool = make(map[string]*TunInterface)
	sm.tunPoolMutex.Unlock()

	// Bulk delete the interfaces
	if len(interfaceNames) > 0 {
		var err error
		if sm.useNamespace && sm.netNamespace != nil {
			err = sm.bulkDeleteTunInterfacesInNamespace(interfaceNames)
		} else {
			err = sm.bulkDeleteTunInterfaces(interfaceNames)
		}
		if err != nil {
			log.Printf("Warning: bulk cleanup failed, some interfaces may remain: %v", err)
		}
	}

	log.Printf("Cleaned up all %d pre-allocated interfaces", len(interfaceNames))
}

// bulkDeleteTunInterfacesInNamespace deletes TUN interfaces inside the network namespace
func (sm *SimulatorManager) bulkDeleteTunInterfacesInNamespace(interfaceNames []string) error {
	if len(interfaceNames) == 0 {
		return nil
	}

	if sm.netNamespace == nil {
		return fmt.Errorf("no namespace available")
	}

	log.Printf("Bulk deleting %d TUN interfaces in namespace '%s'...", len(interfaceNames), sm.netNamespace.Name)
	startTime := time.Now()

	// Method 1: Use ip netns exec with batch file
	batchFile, err := os.CreateTemp("", "tun_delete_ns_batch_*.txt")
	if err != nil {
		return sm.deleteTunInterfacesInNamespaceParallel(interfaceNames)
	}
	defer os.Remove(batchFile.Name())
	defer batchFile.Close()

	// Write all deletion commands to the batch file
	for _, ifName := range interfaceNames {
		if _, err := fmt.Fprintf(batchFile, "link delete %s\n", ifName); err != nil {
			return sm.deleteTunInterfacesInNamespaceParallel(interfaceNames)
		}
	}
	batchFile.Sync()

	// Execute the batch file inside the namespace
	cmd := exec.Command("ip", "netns", "exec", sm.netNamespace.Name, "ip", "-batch", batchFile.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Batch deletion in namespace failed: %v, output: %s", err, string(output))
		return sm.deleteTunInterfacesInNamespaceParallel(interfaceNames)
	}

	elapsed := time.Since(startTime)
	log.Printf("Bulk deleted %d TUN interfaces in namespace in %v", len(interfaceNames), elapsed)
	return nil
}

// deleteTunInterfacesInNamespaceParallel deletes interfaces in namespace in parallel
func (sm *SimulatorManager) deleteTunInterfacesInNamespaceParallel(interfaceNames []string) error {
	const maxWorkers = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []string

	sem := make(chan struct{}, maxWorkers)

	for _, ifName := range interfaceNames {
		wg.Add(1)
		go func(interfaceName string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			cmd := exec.Command("ip", "netns", "exec", sm.netNamespace.Name, "ip", "link", "delete", interfaceName)
			if err := cmd.Run(); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("%s: %v", interfaceName, err))
				mu.Unlock()
			}
		}(ifName)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("parallel deletion errors in namespace: %s", strings.Join(errors, ", "))
	}
	return nil
}
