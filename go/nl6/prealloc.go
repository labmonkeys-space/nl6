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

	// Set pre-allocation status
	sm.isPreAllocating.Store(true)
	sm.preAllocProgress.Store(0)
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

	// Walk the batch's IPs up front, in one pass, exactly as the launch loop
	// used to walk them (same nextHost rule, same order). `walkIP` ends on the
	// first host AFTER the batch, which is what the manager's currentIP has to
	// advance to. Precomputing is what lets the reservation below commit the
	// index base and the end IP together — the same O(n) precompute
	// createDevicesParallel already does for device IPs.
	prefix := parsePrefix(netmask)
	interfaceIPs := make([]net.IP, poolSize)
	walkIP := make(net.IP, len(startIP))
	copy(walkIP, startIP)
	for i := 0; i < poolSize; i++ {
		interfaceIPs[i] = make(net.IP, len(walkIP))
		copy(interfaceIPs[i], walkIP)
		walkIP = nextHost(walkIP, prefix)
	}

	// Reserve everything this batch takes from the manager's shared allocation
	// state in ONE critical section, BEFORE any worker starts (nl6#556).
	baseTunIndex := sm.reservePreAllocBatch(poolSize, maxWorkers, walkIP)

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

			// Update progress counter
			newCurrent := sm.bumpPreAllocProgress()

			// Log progress every 50 interfaces or for milestones
			if newCurrent%50 == 0 || newCurrent == 100 || newCurrent == 200 || newCurrent == 250 {
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
		log.Printf("WARNING: Pre-allocation timed out after 5 minutes")
		return fmt.Errorf("pre-allocation timed out")
	}

	elapsed := time.Since(startTime)
	created := int(sm.preAllocProgress.Load())

	log.Printf("PRE-ALLOCATION END TIME: %v", time.Now().Format("15:04:05.000"))
	log.Println()

	log.Printf("PERFORMANCE RESULTS:")
	log.Printf("   Total interfaces created: %d/%d", created, poolSize)
	log.Printf("   Total time: %v", elapsed)
	log.Printf("   Average time per interface: %.3f ms", float64(elapsed.Nanoseconds())/float64(created*1e6))
	log.Printf("   Interfaces per second: %.2f", float64(created)/elapsed.Seconds())
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
	// the workers started — deliberately not here. Advancing them at the end
	// left the whole batch window in which a concurrent getNextTunName handed
	// out a name this batch was already using, and a concurrent device create
	// handed out an IP inside the pool's range. It also meant the timeout
	// return above left both fields un-advanced while workers had already
	// created interfaces from that range.
	return nil
}

// reservePreAllocBatch commits, in ONE sm.mu critical section, everything a
// pre-allocation batch takes from the manager's shared allocation state, and
// returns the TUN index base the batch owns: names TUN_DEVICE_PREFIX+base ..
// base+poolSize-1 are reserved for it and no other caller can compute them.
//
// One critical section, not four, because nextTunIndex and currentIP advance
// together: a reader must never see the index advanced and the IP not, or two
// devices land on one address. `endIP` is the first host AFTER the batch.
//
// The lock covers the FIELD ACCESSES ONLY. No interface is created, no exec
// runs and no per-interface I/O happens under it — the 500-worker pre-allocator
// depends on that.
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

// bumpPreAllocProgress increments the pre-allocation progress counter and
// returns the new value.
//
// This is an atomic read-modify-write, not the load-then-store it used to be.
// The counter is progress only — GetStatus reports it and the summary log
// divides by it — so a lost update is not a correctness fault. It is fixed
// anyway because `preAllocProgress` is the field the summary's
// "Total interfaces created: %d/%d" and per-interface timings are computed
// from, and an undercount there is indistinguishable from failed interfaces:
// the cheapest possible fix (atomic.Int64.Add) buys an honest number, whereas
// documenting the loss would leave a misleading log line behind.
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

// CleanupPreAllocatedInterfaces destroys all pre-allocated TUN interfaces
func (sm *SimulatorManager) CleanupPreAllocatedInterfaces() {
	sm.tunPoolMutex.Lock()

	var interfaceNames []string

	// Collect interface names for bulk deletion
	for _, tunIface := range sm.tunInterfacePool {
		if tunIface != nil && tunIface.PreAllocated {
			interfaceNames = append(interfaceNames, tunIface.Name)
			tunIface.destroy() // Close file descriptors
		}
	}

	// Clear the pool. The REASSIGNMENT takes the same mutex the pre-allocation
	// workers take for the CONTENTS — a mutex that guards a map's entries does
	// not guard replacing the map (nl6#556).
	//
	// Cleared BEFORE the deletion below so no lock is held across the `ip`
	// exec. `interfaceNames` is local by then, and a device create that races
	// this misses the pool and creates its interface on demand, which is the
	// right answer for an interface that is being deleted.
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

	// tunPoolSize belongs to sm.mu (GetStatus reads it under sm.mu.RLock), and
	// it is written AFTER releasing tunPoolMutex on purpose: shutdownFast takes
	// tunPoolMutex while holding sm.mu, so the only safe order on this path is
	// sm.mu → tunPoolMutex. Taking sm.mu here while holding tunPoolMutex would
	// invert it and deadlock.
	sm.mu.Lock()
	sm.tunPoolSize = 0
	sm.mu.Unlock()

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
