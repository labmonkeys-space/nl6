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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var deleteDeviceTunInterfaces = func(sm *SimulatorManager, interfaceNames []string) error {
	return sm.bulkDeleteTunInterfaces(interfaceNames)
}

var deleteDeviceTunInterfacesInNamespace = func(sm *SimulatorManager, interfaceNames []string) error {
	return sm.bulkDeleteTunInterfacesInNamespace(interfaceNames)
}

// NewSimulatorManagerWithOptions creates a manager with configurable namespace isolation
func NewSimulatorManagerWithOptions(useNamespace bool) *SimulatorManager {
	// Go 1.20+ auto-seeds the math/rand package, so an explicit Seed call
	// would be a no-op (and is deprecated).

	sm := &SimulatorManager{
		devices:          make(map[string]*DeviceSimulator),
		deviceIPs:        make(map[string]struct{}),
		deviceTypesByIP:  make(map[string]string),
		devicesByIP:      make(map[string]*DeviceSimulator),
		topology:         NewTopology(),
		nextTunIndex:     0,
		resourcesCache:   make(map[string]*DeviceResources),
		tunInterfacePool: make(map[string]*TunInterface),
		useNamespace:     useNamespace,
	}
	// Initialize atomic values
	sm.isPreAllocating.Store(false)
	sm.preAllocProgress.Store(0)
	sm.isCreatingDevices.Store(false)
	sm.deviceCreateProgress.Store(0)
	sm.deviceCreateTotal.Store(0)

	// Initialize network namespace for device isolation
	if useNamespace {
		ns, err := CreateNetNamespace()
		if err != nil {
			log.Printf("WARNING: Failed to create network namespace: %v", err)
			log.Printf("Falling back to root namespace (systemd-networkd may consume resources)")
			sm.useNamespace = false
		} else {
			sm.netNamespace = ns
			log.Printf("Network namespace '%s' active - devices isolated from systemd-networkd", NETNS_NAME)
		}
	}

	// Pre-generate shared SSH host key for all devices
	sm.generateSharedSSHKey()

	// Pre-generate shared TLS certificate for all API servers
	sm.generateSharedTLSCert()

	// Bring up the always-on flow-export infrastructure (buf pool + ticker
	// goroutine + stop channel). No-op at startup when no device has
	// flowConfig; per-device attach via attachFlowExporter enables export
	// later. Phase 3 of per-device-export-config.
	sm.initFlowSubsystem()

	return sm
}

func (sm *SimulatorManager) getNextTunName() string {
	name := fmt.Sprintf("%s%d", TUN_DEVICE_PREFIX, sm.nextTunIndex)
	sm.nextTunIndex++
	return name
}

// generateSharedSSHKey generates a single RSA key to be shared by all devices
func (sm *SimulatorManager) generateSharedSSHKey() {
	log.Println("Generating shared SSH host key for all devices...")
	startTime := time.Now()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("WARNING: Failed to generate shared SSH key: %v", err)
		return
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		log.Printf("WARNING: Failed to parse shared SSH key: %v", err)
		return
	}

	sm.sharedSSHSigner = signer
	elapsed := time.Since(startTime)
	log.Printf("Shared SSH host key generated in %v", elapsed)
}

// generateSharedTLSCert generates a single TLS certificate to be shared by all API servers.
// This avoids expensive per-device 4096-bit RSA key generation (~10-20s each).
func (sm *SimulatorManager) generateSharedTLSCert() {
	log.Println("Generating shared TLS certificate for all API servers...")
	startTime := time.Now()

	// Generate a 2048-bit CA key (sufficient for simulation, ~10x faster than 4096-bit)
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("WARNING: Failed to generate shared TLS CA key: %v", err)
		return
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2025),
		Subject: pkix.Name{
			CommonName:   "nl6-ca",
			Organization: []string{"nl6"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		log.Printf("WARNING: Failed to create shared TLS CA: %v", err)
		return
	}

	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		log.Printf("WARNING: Failed to parse shared TLS CA: %v", err)
		return
	}

	// Generate a server certificate signed by the CA
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("WARNING: Failed to generate shared TLS server key: %v", err)
		return
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "nl6-device",
			Organization: []string{"nl6"},
		},
		// Use wildcard-style: accept any IP by including 0.0.0.0
		IPAddresses: []net.IP{net.IPv4zero, net.IPv6zero},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		log.Printf("WARNING: Failed to create shared TLS cert: %v", err)
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Printf("WARNING: Failed to load shared TLS cert: %v", err)
		return
	}

	sm.sharedTLSCert = &tlsCert
	elapsed := time.Since(startTime)
	log.Printf("Shared TLS certificate generated in %v", elapsed)
}

func (sm *SimulatorManager) ListDevices() []DeviceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Resolve the simulator-wide cadences ONCE. They are identical for every
	// device, so doing it per device meant 3xN Duration.String() calls inside
	// this read lock on the fleet-list path.
	effSnap := sm.snapshotEffectiveIntervals()

	var devices []DeviceInfo
	for _, device := range sm.devices {
		info := DeviceInfo{
			ID:           device.ID,
			IP:           device.IP.String(),
			SNMPPort:     device.SNMPPort,
			SSHPort:      device.SSHPort,
			Running:      device.running,
			ResourceFile: device.resourceFile,
			DeviceType:   getDeviceTypeFromResourceFile(device.resourceFile),
		}
		if device.tunIface != nil {
			info.Interface = device.tunIface.Name
		}
		// Echo the per-device export config blocks verbatim (phase 3 task
		// 3.9), so a GET block stays a valid POST block. The cadence that is
		// actually in effect rides alongside in EffectiveIntervals rather than
		// inside these blocks — nesting it there broke every read-modify-write
		// client, the repo's own scripts/fleet.sh included.
		//
		// The echo* helpers hide an interval the caller never supplied: the
		// stored value is then just whatever ApplyDefaults stamped, and echoing
		// it both reports a choice nobody made and makes a re-POST of this body
		// (scripts/fleet.sh import) warn about an interval the simulator
		// invented. They return the original pointer when nothing needs hiding.
		info.Flow = echoFlowConfig(device.flowConfig)
		info.Traps = echoTrapConfig(device.trapConfig)
		info.Syslog = echoSyslogConfig(device.syslogConfig)
		info.GnmiDialout = device.gnmiDialoutConfig
		info.EffectiveIntervals = buildEffectiveIntervals(device, effSnap)
		// Emit scenario on GET only when non-default, so clean-mode
		// devices (the common case) don't clutter the response. Matches
		// the omitempty pattern used by the export blocks.
		if device.OpticalScenario != "" && device.OpticalScenario != string(OpticalClean) {
			info.OpticalScenario = device.OpticalScenario
		}
		if device.IfErrorScenario != "" && device.IfErrorScenario != string(IfErrorClean) {
			info.IfErrorScenario = device.IfErrorScenario
		}
		if device.IfFlapScenario != "" && device.IfFlapScenario != string(IfFlapClean) {
			info.IfFlapScenario = device.IfFlapScenario
		}
		// Geolocation: the assigned world-city string plus coordinates.
		// Coordinates are emitted only when a location resolved (Name
		// non-empty) so an unset location omits the pair rather than
		// reporting 0,0.
		if loc, ok := device.cachedLocation.Load().(WorldCity); ok && loc.Name != "" {
			info.Location = loc.Name
			// The unknown sentinel has no real coordinates; emit the pair
			// only for a genuinely resolved location.
			if loc.Name != unknownLocationName {
				lat, lng := loc.Latitude, loc.Longitude
				info.Latitude = &lat
				info.Longitude = &lng
			}
		}
		devices = append(devices, info)
	}

	return devices
}

func (sm *SimulatorManager) GetStatus() ManagerStatus {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	totalDevices := len(sm.devices)
	runningDevices := 0
	for _, device := range sm.devices {
		if device.running {
			runningDevices++
		}
	}

	return ManagerStatus{
		IsPreAllocating:      sm.isPreAllocating.Load().(bool),
		PreAllocProgress:     sm.preAllocProgress.Load().(int),
		PreAllocTotal:        sm.tunPoolSize,
		IsCreatingDevices:    sm.isCreatingDevices.Load().(bool),
		DeviceCreateProgress: sm.deviceCreateProgress.Load().(int),
		DeviceCreateTotal:    sm.deviceCreateTotal.Load().(int),
		TotalDevices:         totalDevices,
		RunningDevices:       runningDevices,
	}
}

// freezeFleet marks fleet membership immutable on behalf of the named
// scenario: device create/delete is rejected until unfreezeFleet. Part of
// the scenario PR0 mechanism (FR35/FR38); inert until the scenario
// controller (story 1.2) calls it.
//
// Refuses while a creation batch is in flight: batches publish
// isCreatingDevices BEFORE their freeze check, so whichever side commits
// first wins and the other observes it — a freeze can never land mid-batch
// and a batch can never start mid-freeze (review interlock).
func (sm *SimulatorManager) freezeFleet(scenarioID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if creating, ok := sm.isCreatingDevices.Load().(bool); ok && creating {
		return fmt.Errorf("cannot freeze fleet for scenario %s: a device-creation batch is in progress; retry after it completes", scenarioID)
	}
	if sm.fleetFrozenBy == nil {
		sm.fleetFrozenBy = make(map[string]struct{}, 1)
	}
	sm.fleetFrozenBy[scenarioID] = struct{}{}
	return nil
}

// unfreezeFleet releases ONE scenario's hold. The freeze lifts only when the
// last holder leaves.
//
// Per-scenario rather than a single clear (#392): with several scenarios able
// to run at once, a single slot meant the first to finish unfroze the fleet
// while its peers were still running, re-opening the arm/start membership
// TOCTOU the freeze exists to close — and every rollback path would have done
// the same. Passing the ID makes releasing someone else's hold impossible
// rather than merely unlikely.
func (sm *SimulatorManager) unfreezeFleet(scenarioID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.fleetFrozenBy, scenarioID)
}

// fleetFreezeCheck returns an error naming the freezing scenarios when the
// fleet is frozen, nil otherwise. The error text carries the scenario IDs so
// the REST layer can map the rejection to 409 with actionable context.
func (sm *SimulatorManager) fleetFreezeCheck() error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.fleetFreezeCheckLocked()
}

// fleetFreezeCheckLocked is fleetFreezeCheck for callers already holding
// sm.mu (read or write).
func (sm *SimulatorManager) fleetFreezeCheckLocked() error {
	if len(sm.fleetFrozenBy) == 0 {
		return nil
	}
	holders := make([]string, 0, len(sm.fleetFrozenBy))
	for id := range sm.fleetFrozenBy {
		holders = append(holders, id)
	}
	// By sequence, not bytes: %06d is a minimum width, so past the millionth
	// submit s-1000000 would sort before s-999999 — the same trap
	// compareScenarioID exists to close for the scenario listing. This is the
	// other place multiple scenario IDs are rendered for an operator.
	slices.SortFunc(holders, compareScenarioID)
	return fmt.Errorf("fleet membership is frozen by running scenario(s) %s: device create/delete is rejected until they finish",
		strings.Join(holders, ", "))
}

func (sm *SimulatorManager) DeleteDevice(deviceID string) error {
	// Drop the device's optical channels from the shared SD/SF evaluator —
	// but only once the delete has actually COMMITTED. The first cut
	// deregistered up front, so a freeze-rejected delete (scenario running,
	// FR35) permanently silenced a device that stayed alive and serving.
	//
	// Mechanics: deregisterOpticalIP is set at the commit point below, and
	// this deferred hook runs AFTER the write lock is released (defers are
	// LIFO; the Unlock defer is registered later, so it fires first) —
	// required because DeregisterOpticalDevice takes sm.mu itself and Go's
	// RWMutex is not reentrant.
	var deregisterOpticalIP net.IP
	defer func() {
		if deregisterOpticalIP != nil {
			sm.DeregisterOpticalDevice(deregisterOpticalIP)
		}
	}()
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Freeze check precedes the existence lookup: a frozen fleet rejects
	// the operation categorically (FR35), regardless of the target.
	if err := sm.fleetFreezeCheckLocked(); err != nil {
		return err
	}

	device, exists := sm.devices[deviceID]
	if !exists {
		return fmt.Errorf("device %s not found", deviceID)
	}

	// Capture TUN interface identity BEFORE Stop runs. device.Stop()
	// nils d.tunIface for non-preallocated interfaces as of the partial-
	// startup cleanup fix; reading device.tunIface after Stop would then
	// miss the bulk-delete for those devices and silently leak the
	// kernel netdev — defeating the purpose of deleting it here.
	var (
		hasTun        bool
		interfaceName string
		preAllocated  bool
	)
	if device.tunIface != nil {
		hasTun = true
		interfaceName = device.tunIface.Name
		preAllocated = device.tunIface.PreAllocated
	}

	// Stop and cleanup device. Errors during teardown are non-fatal
	// (the device is being deleted regardless); ignore intentionally.
	_ = device.Stop()

	var tunErr error
	if hasTun {
		// Pre-allocated interfaces keep their FD open through Stop;
		// close it here before asking netlink to remove the link. For
		// non-preallocated interfaces, Stop already ran destroy() and
		// nilled d.tunIface — we use the captured name / flag instead.
		if preAllocated && device.tunIface != nil {
			device.tunIface.destroy()
		}

		if sm.useNamespace && sm.netNamespace != nil {
			tunErr = deleteDeviceTunInterfacesInNamespace(sm, []string{interfaceName})
		} else {
			tunErr = deleteDeviceTunInterfaces(sm, []string{interfaceName})
		}

		if preAllocated {
			sm.tunPoolMutex.Lock()
			delete(sm.tunInterfacePool, device.IP.String())
			sm.tunPoolMutex.Unlock()
		}
	}

	// Always remove from maps — even if netlink delete failed. The
	// device is already Stop'd, FDs are closed, and leaving it in the
	// maps would create a ghost that reports as a device but is dead.
	// Matches DeleteAllDevices's log-and-continue behaviour. The tun
	// delete error is still surfaced to the caller below.
	delete(sm.devices, deviceID)
	deregisterOpticalIP = device.IP // committed: safe to drop alarm enrolment
	delete(sm.deviceIPs, device.IP.String())
	delete(sm.deviceTypesByIP, device.IP.String())
	delete(sm.devicesByIP, device.IP.String())

	// Prune any topology edges referencing this device so a deleted
	// device leaves no dangling links (which would otherwise surface a
	// stale neighbor row or a malformed `to__` ifAlias on the peer).
	if sm.topology != nil {
		sm.topology.PruneDevice(device.IP.String())
	}

	// Republish DNS zones now the device is gone (debounced; no-op if DNS off).
	sm.markDNSDirty()

	if tunErr != nil {
		return fmt.Errorf("delete TUN interface %s: %w", interfaceName, tunErr)
	}
	return nil
}

func (sm *SimulatorManager) DeleteAllDevices() error {
	// Snapshot the device set and clear all registries under the lock, then
	// release it BEFORE the slow per-device teardown. Holding sm.mu across
	// Stop() for every device (each tears down 4 protocol servers + 3
	// exporters + TUN) blocked every reader — /status, /devices, /system-stats
	// — for the whole teardown, so the console froze ("nothing happens") at
	// fabric scale. Clearing the maps up front also makes a concurrent second
	// call idempotent: it snapshots an empty map and tears down nothing, so a
	// double-click can't double-free.
	sm.mu.Lock()
	// Freeze check (FR35): delete-all is the biggest membership hammer and
	// must respect a running scenario like single-device delete does. The
	// graceful-shutdown path is unaffected in practice: the scenario
	// controller aborts (and unfreezes) before manager.Shutdown runs (D7).
	if err := sm.fleetFreezeCheckLocked(); err != nil {
		sm.mu.Unlock()
		return err
	}
	devices := make([]*DeviceSimulator, 0, len(sm.devices))
	deviceIDs := make([]string, 0, len(sm.devices))
	for deviceID, device := range sm.devices {
		devices = append(devices, device)
		deviceIDs = append(deviceIDs, deviceID)
	}
	sm.devices = make(map[string]*DeviceSimulator)
	sm.deviceIPs = make(map[string]struct{})
	sm.deviceTypesByIP = make(map[string]string)
	sm.devicesByIP = make(map[string]*DeviceSimulator)
	sm.tunPoolMutex.Lock()
	sm.tunInterfacePool = make(map[string]*TunInterface)
	sm.tunPoolMutex.Unlock()
	// Every device is gone, so every topology edge is now dangling —
	// drop them all (matches the per-device prune in DeleteDevice).
	if sm.topology != nil {
		sm.topology.Clear()
	}
	sm.mu.Unlock()

	// The fleet reset must also empty the alarm evaluator: DeleteAllDevices
	// bypasses DeleteDevice, and without this every optical channel stayed
	// enrolled forever — evaluated each cycle against a dead cycler, and
	// (via Register's keyed idempotency) shadowing any re-created device on
	// the same IP with the old device's band and start time.
	for _, device := range devices {
		sm.DeregisterOpticalDevice(device.IP)
	}

	// Tear down outside the lock. The snapshot is private to this call, so the
	// API stays responsive throughout.
	var errors []string
	var tunInterfaces []string
	for i, device := range devices {
		if err := device.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", deviceIDs[i], err))
		}
		if device.tunIface != nil {
			// Always close FD on deletion regardless of PreAllocated status
			if device.tunIface.PreAllocated {
				device.tunIface.destroy()
			}
			tunInterfaces = append(tunInterfaces, device.tunIface.Name)
		}
	}

	// Bulk delete TUN interfaces for better performance
	if len(tunInterfaces) > 0 {
		if sm.useNamespace && sm.netNamespace != nil {
			// Delete interfaces in namespace
			if err := sm.bulkDeleteTunInterfacesInNamespace(tunInterfaces); err != nil {
				errors = append(errors, fmt.Sprintf("bulk TUN deletion in namespace: %v", err))
			}
		} else {
			if err := sm.bulkDeleteTunInterfaces(tunInterfaces); err != nil {
				errors = append(errors, fmt.Sprintf("bulk TUN deletion: %v", err))
			}
		}
	}

	// Republish DNS zones now the fleet is empty (debounced; no-op if DNS off).
	sm.markDNSDirty()

	if len(errors) > 0 {
		return fmt.Errorf("errors deleting devices: %s", strings.Join(errors, ", "))
	}
	return nil
}

// Shutdown cleans up all resources including the network namespace
func (sm *SimulatorManager) Shutdown() error {
	log.Println("Shutting down simulator manager...")
	startTime := time.Now()

	// Stop any pending fidelity auto-revert.
	//
	// NOT because it would "fire into a torn-down manager" — the callback
	// touches only package globals and a log, never manager state — so the
	// placement here is not load-bearing and a later reader should not
	// preserve it as if it were. It is here so a pending timer does not
	// outlive the process's intent.
	//
	// Note this DROPS the revert rather than applying it, leaving the value at
	// whatever the temporary toggle set. Inert today: Shutdown has one caller,
	// the signal handler, which exits immediately afterwards. It becomes a real
	// bug if Shutdown is ever made non-terminal.
	cancelFidelityRevert()

	// D7: abort a running load-test scenario FIRST — before the export
	// subsystems tear down — so the scenario finalizes its report while
	// participant exporters still exist, and the fleet freeze is released.
	// Bounded by the drain grace, so shutdown cannot hang.
	sm.abortActiveScenario()

	// Stop the flow ticker goroutine and close every pooled shared socket.
	// Per the per-device-export-config refactor the subsystem is always-on
	// (design §D9); flowStopOnce ensures close(flowStopCh) is idempotent.
	// flowWg.Wait() guarantees the ticker has exited before we close pooled
	// sockets so Tick never races WriteTo against Close. Per-device sockets
	// are closed when each device's flowExporter.Close() runs.
	if sm.flowStopCh != nil {
		sm.flowStopOnce.Do(func() { close(sm.flowStopCh) })
		sm.flowWg.Wait()
	}
	sm.closeFlowConnPool()

	// Stop the trap subsystem (scheduler goroutine + per-device exporters +
	// shared fallback socket). Safe to call when trap export was never started.
	sm.StopTrapExport()

	// Stop the syslog subsystem (same shape as trap). Safe to call when
	// syslog export was never started.
	sm.StopSyslogExport()

	// Stop the gNMI subsystem. Walks every device and gracefully stops
	// its per-device gRPC server. Safe to call when never started.
	sm.StopGnmiSubsystem()

	// Stop the gNMI dial-out subsystem (per-device push exporters: cancel
	// each run loop and close its ClientConn). Safe to call when never started.
	sm.StopGnmiDialout()

	// Stop the shared optical SD/SF alarm evaluator alongside its peer
	// subsystems. Without this it is the one goroutine Shutdown leaves
	// running, firing state-driven traps into torn-down exporters.
	sm.mu.RLock()
	oa := sm.opticalAlarms
	sm.mu.RUnlock()
	if oa != nil {
		oa.Stop()
	}

	// Stop the DNS service-discovery subsystem (debounce worker + listeners).
	// Safe to call when never started.
	sm.StopDnsSubsystem()

	// Stop the flap scheduler (state-engine mutator goroutine). Safe to
	// call when never started. Cancels the Run context so the goroutine
	// unwinds even when blocked in `limiter.Wait`.
	sm.StopFlapSubsystem()

	// Cancel every pending REST auto-revert timer (POST .../oper-status
	// with a `duration` field). Without this, in-flight timers would
	// keep their goroutines alive across Shutdown, mutating an
	// effectively-dead state engine.
	sm.cancelAllAutoReverts()

	if sm.useNamespace && sm.netNamespace != nil {
		// Fast path: when using a namespace, deleting it instantly destroys all
		// TUN interfaces inside it. No need to delete them one by one.
		// Just close file descriptors and stop listeners in-process, then nuke the namespace.
		sm.shutdownFast()
	} else {
		// Slow path: no namespace, must delete interfaces individually
		if err := sm.DeleteAllDevices(); err != nil {
			log.Printf("Warning: errors deleting devices during shutdown: %v", err)
		}
		sm.CleanupPreAllocatedInterfaces()
	}

	// Cleanup network namespace (deletes all interfaces inside it)
	if sm.netNamespace != nil {
		if err := sm.netNamespace.Close(); err != nil {
			log.Printf("Warning: failed to close network namespace: %v", err)
		}
		sm.netNamespace = nil
	}

	elapsed := time.Since(startTime)
	log.Printf("Simulator manager shutdown complete in %v", elapsed)
	return nil
}

// shutdownFast stops all device listeners and closes FDs without deleting TUN interfaces.
// The caller is responsible for deleting the namespace, which destroys all interfaces at once.
func (sm *SimulatorManager) shutdownFast() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	deviceCount := len(sm.devices)
	log.Printf("Fast shutdown: closing %d devices (namespace deletion will clean up TUN interfaces)...", deviceCount)

	// Stop all device services (closes UDP/TCP listeners and TUN FDs)
	for _, device := range sm.devices {
		device.stopListenersOnly()
	}

	// Clear maps. The IP-keyed companion maps are cleared alongside
	// `devices` so that a subsequent Startup cycle starts from a clean
	// slate (previously these were leaked, letting stale IP→slug mappings
	// bleed into the next run and mis-resolving per-type catalogs).
	sm.devices = make(map[string]*DeviceSimulator)
	sm.deviceIPs = make(map[string]struct{})
	sm.deviceTypesByIP = make(map[string]string)
	sm.devicesByIP = make(map[string]*DeviceSimulator)
	sm.tunPoolMutex.Lock()
	// Close pre-allocated TUN FDs
	for _, tunIface := range sm.tunInterfacePool {
		if tunIface != nil {
			tunIface.destroy()
		}
	}
	sm.tunInterfacePool = make(map[string]*TunInterface)
	sm.tunPoolMutex.Unlock()

	log.Printf("Fast shutdown: all %d device listeners closed", deviceCount)
}

// SetupRoutesForDevices adds host routes to make devices accessible from external machines
func (sm *SimulatorManager) SetupRoutesForDevices(startIP string, count int, netmask string) error {
	if !sm.useNamespace || sm.netNamespace == nil {
		// No namespace, routes not needed (interfaces are in root namespace)
		return nil
	}

	return sm.netNamespace.AddRouteForDevices(startIP, count, netmask)
}

// SetupRoutesFromDevices adds host routes based on actual device IPs rather than
// calculating from startIP + count, ensuring no subnets are missed.
func (sm *SimulatorManager) SetupRoutesFromDevices(netmask string) error {
	if !sm.useNamespace || sm.netNamespace == nil {
		return nil
	}

	// Collect unique networks at the batch prefix — one /16 for the flat
	// management plane, per-/24 for an explicit /24 batch (see ipalloc.go).
	prefix := parsePrefix(netmask)
	sm.mu.RLock()
	subnets := make(map[string]bool)
	for _, device := range sm.devices {
		if cidr := networkCIDR(device.IP, prefix); cidr != "" {
			subnets[cidr] = true
		}
	}
	sm.mu.RUnlock()

	for subnet := range subnets {
		if err := sm.netNamespace.addHostRoute(subnet); err != nil {
			log.Printf("Warning: failed to add route for %s: %v", subnet, err)
		}
	}

	return nil
}

// ensureAllSubnetRoutes adds host routes covering every subnet between startIP
// and currentIP at the batch prefix — a single /16 for the flat management
// plane, or per-/24 for an explicit /24 batch (see ipalloc.go).
func (sm *SimulatorManager) ensureAllSubnetRoutes(startIP net.IP, netmask string) {
	if sm.netNamespace == nil {
		return
	}

	start := startIP.To4()
	if start == nil {
		return
	}

	sm.mu.RLock()
	end := sm.currentIP.To4()
	if end == nil {
		sm.mu.RUnlock()
		return
	}
	endCopy := make(net.IP, 4)
	copy(endCopy, end)
	sm.mu.RUnlock()

	routes := networkRoutesBetween(start, endCopy, parsePrefix(netmask))
	for _, cidr := range routes {
		sm.netNamespace.addHostRoute(cidr)
	}
	log.Printf("ensureAllSubnetRoutes: added %d route(s) covering %s - %s",
		len(routes), start.String(), endCopy.String())
}
