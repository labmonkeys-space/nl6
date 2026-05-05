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
	"strings"
	"sync"
	"time"
)

// makeDeviceID builds a device ID from an IP and an optional device-type slug.
// When slug is empty the ID is just the IP; otherwise it is "<slug>-<ip>"
// (e.g. "cisco-catalyst-9500-10.0.0.1"). The "device-" prefix is intentionally
// omitted so the ID reflects the device identity directly.
func makeDeviceID(ip net.IP, typeSlug string) string {
	if typeSlug == "" {
		return ip.String()
	}
	return fmt.Sprintf("%s-%s", typeSlug, ip.String())
}

func (sm *SimulatorManager) CreateDevices(startIP string, count int, netmask string, resourceFile string, v3Config *SNMPv3Config, roundRobin bool, category string, snmpPort int, seed *ExportSeed) error {
	return sm.CreateDevicesWithOptions(startIP, count, netmask, resourceFile, v3Config, true, 0, roundRobin, category, snmpPort, seed)
}

// CreateDevicesWithOptions creates devices with optional pre-allocation control.
// `seed`, when non-nil, populates every created device's `flowConfig` /
// `trapConfig` / `syslogConfig` pointer fields with a copy of the seed's
// non-nil blocks (per-device-export-config phase 3).
func (sm *SimulatorManager) CreateDevicesWithOptions(startIP string, count int, netmask string, resourceFile string, v3Config *SNMPv3Config, preAllocate bool, maxWorkers int, roundRobin bool, category string, snmpPort int, seed *ExportSeed) error {
	if snmpPort == 0 {
		snmpPort = DEFAULT_SNMP_PORT
	}

	// Set device creation status
	sm.isCreatingDevices.Store(true)
	sm.deviceCreateProgress.Store(0)
	sm.deviceCreateTotal.Store(count)
	defer sm.isCreatingDevices.Store(false)

	// Automatically pre-allocate TUN interfaces if creating many devices
	// Pre-allocate by default for 10+ devices unless explicitly disabled
	shouldPreAllocate := preAllocate && count >= 10

	if shouldPreAllocate {
		ip := net.ParseIP(startIP)
		if ip != nil {
			// Use provided maxWorkers or determine optimal count based on device count
			if maxWorkers == 0 {
				if count >= 1000 {
					maxWorkers = 200
				} else if count >= 500 {
					maxWorkers = 150
				} else {
					maxWorkers = 100
				}
			}

			log.Printf("Pre-allocating %d TUN interfaces with %d workers for faster device creation...", count, maxWorkers)
			err := sm.PreAllocateTunInterfaces(count, maxWorkers, ip, netmask)
			if err != nil {
				log.Printf("WARNING: Pre-allocation failed: %v. Falling back to on-demand creation.", err)
				// Continue with device creation even if pre-allocation fails
			}
		}
	}

	log.Printf("DEVICE STARTUP TEST: Creating %d devices starting from %s/%s", count, startIP, netmask)
	log.Printf("Device Creation Parameters:")
	log.Printf("   - Device Count: %d", count)
	log.Printf("   - Start IP: %s/%s", startIP, netmask)
	log.Printf("   - Resource File: %s", resourceFile)
	log.Printf("   - Round Robin: %t", roundRobin)
	log.Printf("   - SNMPv3 Enabled: %t", v3Config != nil && v3Config.Enabled)
	log.Printf("   - Test Started: %s", time.Now().Format("2006-01-02 15:04:05.000"))
	log.Println()

	deviceStartTime := time.Now()
	log.Printf("DEVICE CREATION START TIME: %v", deviceStartTime.Format("15:04:05.000"))

	// Check for root privileges for TUN interface creation
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required to create TUN interfaces")
	}

	ip := net.ParseIP(startIP)
	if ip == nil {
		return fmt.Errorf("invalid start IP address: %s", startIP)
	}

	// Initialize with a write lock, then release it for the loop
	sm.mu.Lock()
	sm.currentIP = ip
	sm.mu.Unlock()

	successCount := 0

	// Pre-load round robin resource files if round robin is enabled
	var roundRobinResources []*DeviceResources
	var roundRobinResourceFiles []string
	if roundRobin {
		// Filter device types by category if specified
		rrTypes := RoundRobinDeviceTypes
		if category != "" {
			var filtered []string
			for _, rrFile := range RoundRobinDeviceTypes {
				name := strings.TrimSuffix(rrFile, ".json")
				if getDeviceCategoryFromName(name) == category {
					filtered = append(filtered, rrFile)
				}
			}
			if len(filtered) > 0 {
				rrTypes = filtered
			}
			log.Printf("Round Robin mode enabled for category %q - %d device types", category, len(rrTypes))
		} else {
			log.Printf("Round Robin mode enabled - loading %d device type resources...", len(rrTypes))
		}
		for _, rrFile := range rrTypes {
			res, err := sm.LoadSpecificResources(rrFile)
			if err != nil {
				log.Printf("WARNING: Failed to load round robin resource %s: %v", rrFile, err)
				continue
			}
			roundRobinResources = append(roundRobinResources, res)
			roundRobinResourceFiles = append(roundRobinResourceFiles, rrFile)
		}
		if len(roundRobinResources) == 0 {
			return fmt.Errorf("failed to load any round robin resource files")
		}
		log.Printf("Loaded %d round robin device types", len(roundRobinResources))
	}

	// Load the specified resource file if provided (for non-round-robin mode)
	var resources *DeviceResources
	if !roundRobin {
		if resourceFile != "" {
			var err error
			resources, err = sm.LoadSpecificResources(resourceFile)
			if err != nil {
				return fmt.Errorf("failed to load resource file %s: %v", resourceFile, err)
			}
		} else {
			// Use default resources
			resources = sm.deviceResources
		}
	}

	if sm.tunPoolSize > 0 {
		// Pre-allocation was done - create devices in parallel
		sm.createDevicesParallel(count, netmask, resourceFile, resources, v3Config, &successCount, roundRobin, roundRobinResources, roundRobinResourceFiles, snmpPort, seed)
	} else {
		// No pre-allocation - create devices sequentially (original logic)
		for i := 0; i < count; i++ {
			// Select resources first so the device-type slug is available for the device ID
			deviceResources := resources
			deviceResourceFile := resourceFile
			if roundRobin && len(roundRobinResources) > 0 {
				rrIndex := i % len(roundRobinResources)
				deviceResources = roundRobinResources[rrIndex]
				deviceResourceFile = roundRobinResourceFiles[rrIndex]
			}
			typeSlug := slugifyDeviceType(deviceResourceFile)

			// Get current IP with a read lock
			sm.mu.RLock()
			currentIP := make(net.IP, len(sm.currentIP))
			copy(currentIP, sm.currentIP)
			deviceID := makeDeviceID(currentIP, typeSlug)

			// Check IP (not deviceID) so re-invocations with a different
			// resource file still detect the collision.
			_, exists := sm.deviceIPs[currentIP.String()]
			sm.mu.RUnlock()

			if exists {
				// log.Printf("Device %s already exists, skipping", deviceID)
				sm.mu.Lock()
				sm.incrementIP()
				sm.mu.Unlock()
				continue
			}

			// Get or create TUN interface
			var tunIface *TunInterface
			var err error

			// Check if we have a pre-allocated interface for this IP
			sm.tunPoolMutex.RLock()
			preAllocated, exists := sm.tunInterfacePool[currentIP.String()]
			sm.tunPoolMutex.RUnlock()

			if exists && preAllocated != nil {
				// Use pre-allocated interface - it already has IP configured
				tunIface = preAllocated
				// log.Printf("Reusing pre-allocated interface %s for IP %s", tunIface.Name, currentIP.String())
			} else {
				// No pre-allocation or not found, create TUN interface on-demand
				sm.mu.Lock()
				tunName := sm.getNextTunName()
				sm.mu.Unlock()

				tunIP := make(net.IP, len(currentIP))
				copy(tunIP, currentIP)

				// Create TUN interface (in namespace if enabled)
				if sm.useNamespace && sm.netNamespace != nil {
					tunIface, err = createTunInterfaceInNamespaceViaExec(sm.netNamespace.Name, tunName, tunIP, netmask)
				} else {
					tunIface, err = createTunInterface(tunName, tunIP, netmask)
				}
				if err != nil {
					log.Printf("Failed to create TUN interface %s for %s: %v", tunName, deviceID, err)
					sm.mu.Lock()
					sm.incrementIP()
					sm.mu.Unlock()
					continue
				}
			}

			// Create device with default ports (use the copied IP)
			deviceIP := make(net.IP, len(currentIP))
			copy(deviceIP, currentIP)

			sysLocationValue := getRandomCity()
			sysNameValue := getRandomDeviceName(typeSlug)

			device := &DeviceSimulator{
				ID:           deviceID,
				IP:           deviceIP,
				SNMPPort:     snmpPort,
				SSHPort:      DEFAULT_SSH_PORT,
				APIPort:      DEFAULT_API_PORT,
				tunIface:     tunIface,
				resources:    deviceResources,
				resourceFile: deviceResourceFile,
				sysLocation:  sysLocationValue,
				sysName:      sysNameValue,
			}

			// Set namespace reference if using namespace isolation
			if sm.useNamespace && sm.netNamespace != nil {
				device.netNamespace = sm.netNamespace
			}

			// Initialize per-device metrics cycler for dynamic CPU/memory values
			profile := GetDeviceProfile(deviceResourceFile)
			device.metricsCycler = NewMetricsCycler(int64(i), profile)
			device.metricsCycler.InitGPUMetrics(int64(i), profile.GPU)

			// Apply the batch-level export seed BEFORE InitIfCounters so
			// device.IfErrorScenario is populated in time for the cycler
			// to draw scenario-banded ppms.
			applyExportSeed(device, seed)

			scenario, _ := ParseIfErrorScenario(device.IfErrorScenario)
			device.IfErrorScenario = string(scenario) // canonicalise for GET /api/v1/devices
			device.metricsCycler.InitIfCountersWithScenario(deviceResources, int64(i)^0x4843_0000, scenario)

			// Initialize flow exporter if this device has flow config.
			if device.flowConfig != nil {
				flowProfile := GetFlowProfile(deviceResourceFile)
				if err := sm.attachFlowExporter(device, flowProfile); err != nil {
					log.Printf("flow export: skipping device %s: %v", device.IP, err)
					// Nil out flowConfig so ListDevices doesn't show
					// config that has no live exporter (review fix P5).
					device.flowConfig = nil
				}
			}

			// Register device type BEFORE starting exporters. startDevice*Exporter
			// calls scheduler.Register which puts the device on the fire heap;
			// any fire that lands before deviceTypesByIP is populated would
			// resolve via CatalogFor → miss → fall through to _universal,
			// silently skipping any per-type overlay for the first fires.
			sm.mu.Lock()
			sm.deviceTypesByIP[currentIP.String()] = resourceDirName(deviceResourceFile)
			sm.mu.Unlock()

			// Initialize SNMP trap exporter if this device has trap
			// config (set by applyExportSeed). In INFORM mode a
			// per-device bind failure is fatal for this device (but
			// not for the simulator as a whole — we log and clear
			// trapConfig so ListDevices doesn't expose a ghost entry).
			if device.trapConfig != nil {
				if err := sm.startDeviceTrapExporter(device); err != nil {
					log.Printf("trap export: skipping device %s: %v", device.IP, err)
					device.mu.Lock()
					device.trapConfig = nil
					device.mu.Unlock()
				}
			}

			// Initialize UDP syslog exporter if this device has syslog
			// config (set by applyExportSeed). Per-device bind failure
			// is non-fatal for syslog — exporter falls back to the
			// shared-pool socket with an in-function warning log. Other
			// errors (bad format, unresolvable collector) nil the config
			// so ListDevices doesn't show a ghost entry.
			if device.syslogConfig != nil {
				if err := sm.startDeviceSyslogExporter(device); err != nil {
					log.Printf("syslog export: skipping device %s: %v", device.IP, err)
					device.mu.Lock()
					device.syslogConfig = nil
					device.mu.Unlock()
				}
			}

			// Cache the dynamic values using atomic for lock-free access
			device.cachedSysName.Store(sysNameValue)
			device.cachedSysLocation.Store(sysLocationValue)

			// Create servers with SNMPv3 configuration
			device.snmpServer = &SNMPServer{
				device:   device,
				v3Config: v3Config,
			}
			device.sshServer = &SSHServer{device: device, signer: sm.sharedSSHSigner}
			device.apiServer = &APIServer{device: device, sharedTLSCert: sm.sharedTLSCert}

			// Start device services
			if err := device.Start(); err != nil {
				log.Printf("Failed to start device %s: %v", deviceID, err)
				device.Stop() // Clean up
				sm.mu.Lock()
				sm.incrementIP()
				sm.mu.Unlock()
				continue
			}

			// Add device to map with a write lock. deviceTypesByIP was
			// populated earlier (before exporter registration) to avoid a
			// fire-timing race; repeated write here is idempotent.
			sm.mu.Lock()
			sm.devices[deviceID] = device
			sm.deviceIPs[currentIP.String()] = struct{}{}
			sm.incrementIP()
			sm.mu.Unlock()

			successCount++

			// Update progress counter
			sm.deviceCreateProgress.Store(successCount)

			// log.Printf("Created device: %s on IP %s (interface: %s)", deviceID, currentIP.String(), tunName)
		}

	}

	deviceElapsed := time.Since(deviceStartTime)
	deviceEndTime := time.Now()

	log.Printf("DEVICE CREATION END TIME: %v", deviceEndTime.Format("15:04:05.000"))
	log.Println()

	log.Printf("DEVICE CREATION RESULTS:")
	log.Printf("   Total devices created: %d/%d", successCount, count)
	log.Printf("   Total device creation time: %v", deviceElapsed)
	log.Printf("   Average time per device: %.3f ms", float64(deviceElapsed.Nanoseconds())/float64(successCount*1e6))
	log.Printf("   Devices created per second: %.2f", float64(successCount)/deviceElapsed.Seconds())
	if sm.tunPoolSize > 0 {
		log.Printf("   Mode: Parallel creation with pre-allocated interfaces")
		log.Printf("   Workers used: %d", sm.maxWorkers)
	} else {
		log.Printf("   Mode: Sequential creation with on-demand interfaces")
	}

	if successCount < count {
		log.Printf("   Failed devices: %d", count-successCount)
		log.Printf("   Success rate: %.1f%%", float64(successCount)/float64(count)*100.0)
	} else {
		log.Printf("   Success rate: 100%%")
	}

	log.Printf("Successfully created %d out of %d requested devices", successCount, count)

	// Setup host routes for external access if using namespace
	if sm.useNamespace && sm.netNamespace != nil && successCount > 0 {
		log.Printf("Setting up host routes for external access...")
		if err := sm.SetupRoutesFromDevices(netmask); err != nil {
			log.Printf("Warning: failed to setup some routes: %v", err)
		}
		// Ensure all subnets between startIP and currentIP have routes
		sm.ensureAllSubnetRoutes(ip, netmask)
	}

	return nil
}

// createDevicesParallel creates devices in parallel when pre-allocation was done.
// `seed` is propagated verbatim to every worker; each worker passes it into
// `createSingleDevice` which copies per-device.
func (sm *SimulatorManager) createDevicesParallel(count int, netmask string, resourceFile string, resources *DeviceResources, v3Config *SNMPv3Config, successCount *int, roundRobin bool, roundRobinResources []*DeviceResources, roundRobinResourceFiles []string, snmpPort int, seed *ExportSeed) {
	// Worker pool for parallel device creation
	sem := make(chan struct{}, sm.maxWorkers) // Limit concurrent workers
	var wg sync.WaitGroup
	var mu sync.Mutex

	log.Printf("Creating %d devices in parallel with %d workers...", count, sm.maxWorkers)
	parallelStartTime := time.Now()
	log.Printf("PARALLEL DEVICE START TIME: %v", parallelStartTime.Format("15:04:05.000"))

	// Get starting IP with read lock
	sm.mu.RLock()
	startingIP := make(net.IP, len(sm.currentIP))
	copy(startingIP, sm.currentIP)
	sm.mu.RUnlock()

	// Pre-compute all device IPs in O(n) instead of O(n²)
	deviceIPs := make([]net.IP, count)
	currentDevIP := make(net.IP, len(startingIP))
	copy(currentDevIP, startingIP)
	for i := 0; i < count; i++ {
		deviceIPs[i] = make(net.IP, len(currentDevIP))
		copy(deviceIPs[i], currentDevIP)
		if i < count-1 {
			sm.incrementIPAddress(currentDevIP)
		}
	}

	for i := 0; i < count; i++ {
		deviceIP := deviceIPs[i]

		// Select resources first so the device-type slug is available for the device ID
		deviceResources := resources
		deviceResourceFile := resourceFile
		if roundRobin && len(roundRobinResources) > 0 {
			rrIndex := i % len(roundRobinResources)
			deviceResources = roundRobinResources[rrIndex]
			deviceResourceFile = roundRobinResourceFiles[rrIndex]
		}
		deviceID := makeDeviceID(deviceIP, slugifyDeviceType(deviceResourceFile))

		// Check IP (not deviceID) so the duplicate check stays robust against
		// the device-ID format including a resource-type slug.
		sm.mu.RLock()
		_, exists := sm.deviceIPs[deviceIP.String()]
		sm.mu.RUnlock()

		if exists {
			continue
		}

		wg.Add(1)
		go func(deviceIndex int, ip net.IP, devID string, devResources *DeviceResources, devResourceFile string) {
			defer wg.Done()

			// Acquire worker slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Create device in parallel
			if sm.createSingleDevice(deviceIndex, ip, devID, netmask, devResourceFile, devResources, v3Config, snmpPort, seed) {
				mu.Lock()
				(*successCount)++
				progress := *successCount
				mu.Unlock()

				// Update progress counter
				sm.deviceCreateProgress.Store(progress)
			}

		}(i, deviceIP, deviceID, deviceResources, deviceResourceFile)
	}

	// Wait for all workers to complete
	wg.Wait()

	parallelElapsed := time.Since(parallelStartTime)
	parallelEndTime := time.Now()
	log.Printf("PARALLEL DEVICE END TIME: %v", parallelEndTime.Format("15:04:05.000"))
	log.Printf("Parallel device creation completed: %d devices in %v (%.3f ms per device)",
		*successCount, parallelElapsed, float64(parallelElapsed.Nanoseconds())/float64(*successCount*1e6))
	log.Printf("Parallel creation rate: %.2f devices/second", float64(*successCount)/parallelElapsed.Seconds())
}

// createSingleDevice creates a single device - used by parallel device creation.
// `seed` propagates the batch-level export configuration (phase 3).
func (sm *SimulatorManager) createSingleDevice(deviceIndex int, deviceIP net.IP, deviceID string, netmask string, resourceFile string, resources *DeviceResources, v3Config *SNMPv3Config, snmpPort int, seed *ExportSeed) bool {
	// Check if we have a pre-allocated interface for this IP
	var tunIface *TunInterface

	sm.tunPoolMutex.RLock()
	preAllocated, exists := sm.tunInterfacePool[deviceIP.String()]
	sm.tunPoolMutex.RUnlock()

	if exists && preAllocated != nil {
		// Use pre-allocated interface - it already has IP configured
		tunIface = preAllocated
	} else {
		// No pre-allocated interface found, create on-demand
		// Use getNextTunName to ensure unique interface names
		sm.mu.Lock()
		tunName := sm.getNextTunName()
		sm.mu.Unlock()
		var err error
		// Create TUN interface (in namespace if enabled)
		if sm.useNamespace && sm.netNamespace != nil {
			tunIface, err = createTunInterfaceInNamespaceViaExec(sm.netNamespace.Name, tunName, deviceIP, netmask)
		} else {
			tunIface, err = createTunInterface(tunName, deviceIP, netmask)
		}
		if err != nil {
			log.Printf("Failed to create TUN interface %s for device %s: %v", tunName, deviceID, err)
			return false
		}
	}

	sysLocationValue := getRandomCity()
	sysNameValue := getRandomDeviceName(slugifyDeviceType(resourceFile))

	device := &DeviceSimulator{
		ID:           deviceID,
		IP:           make(net.IP, len(deviceIP)),
		SNMPPort:     snmpPort,
		SSHPort:      DEFAULT_SSH_PORT,
		APIPort:      DEFAULT_API_PORT,
		tunIface:     tunIface,
		resources:    resources,
		resourceFile: resourceFile,
		sysLocation:  sysLocationValue,
		sysName:      sysNameValue,
	}
	copy(device.IP, deviceIP)

	// Set namespace reference if using namespace isolation
	if sm.useNamespace && sm.netNamespace != nil {
		device.netNamespace = sm.netNamespace
	}

	// Initialize per-device metrics cycler for dynamic CPU/memory values
	profile := GetDeviceProfile(resourceFile)
	device.metricsCycler = NewMetricsCycler(int64(deviceIndex), profile)
	device.metricsCycler.InitGPUMetrics(int64(deviceIndex), profile.GPU)

	// Apply the batch-level export seed BEFORE InitIfCounters so the
	// scenario is known when the cycler draws its ppm bands.
	applyExportSeed(device, seed)

	scenario, _ := ParseIfErrorScenario(device.IfErrorScenario)
	device.IfErrorScenario = string(scenario)
	device.metricsCycler.InitIfCountersWithScenario(resources, int64(deviceIndex)^0x4843_0000, scenario)

	// Initialize flow exporter if this device has flow config.
	if device.flowConfig != nil {
		flowProfile := GetFlowProfile(resourceFile)
		if err := sm.attachFlowExporter(device, flowProfile); err != nil {
			log.Printf("flow export: skipping device %s: %v", device.IP, err)
			// Nil out flowConfig so ListDevices doesn't show config
			// that has no live exporter (review fix P5).
			device.flowConfig = nil
		}
	}

	// Register device type BEFORE starting exporters so scheduler fires
	// resolve the correct per-type catalog from the first pick onward.
	sm.mu.Lock()
	sm.deviceTypesByIP[deviceIP.String()] = resourceDirName(resourceFile)
	sm.mu.Unlock()

	// Initialize SNMP trap exporter if this device has trap config.
	if device.trapConfig != nil {
		if err := sm.startDeviceTrapExporter(device); err != nil {
			log.Printf("trap export: skipping device %s: %v", device.IP, err)
			device.mu.Lock()
			device.trapConfig = nil
			device.mu.Unlock()
		}
	}

	// Initialize UDP syslog exporter if this device has syslog config.
	if device.syslogConfig != nil {
		if err := sm.startDeviceSyslogExporter(device); err != nil {
			log.Printf("syslog export: skipping device %s: %v", device.IP, err)
			device.mu.Lock()
			device.syslogConfig = nil
			device.mu.Unlock()
		}
	}

	// Cache the dynamic values using atomic for lock-free access
	device.cachedSysName.Store(sysNameValue)
	device.cachedSysLocation.Store(sysLocationValue)

	// Create servers with SNMPv3 configuration
	device.snmpServer = &SNMPServer{
		device:   device,
		v3Config: v3Config,
	}
	device.sshServer = &SSHServer{device: device, signer: sm.sharedSSHSigner}
	device.apiServer = &APIServer{device: device, sharedTLSCert: sm.sharedTLSCert}

	// Start device services
	if err := device.Start(); err != nil {
		log.Printf("Failed to start device %s: %v", deviceID, err)
		device.Stop() // Clean up
		return false
	}

	// Add device to map with a write lock. deviceTypesByIP was populated
	// earlier (before exporter registration) to avoid a fire-timing race.
	sm.mu.Lock()
	sm.devices[deviceID] = device
	sm.deviceIPs[deviceIP.String()] = struct{}{}
	sm.mu.Unlock()

	return true
}

func (sm *SimulatorManager) incrementIP() {
	ip := sm.currentIP.To4()
	if ip == nil {
		return // Only support IPv4 for now
	}

	// Create a copy to avoid modifying the original IP
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	// Increment the last octet
	newIP[3]++

	// Handle overflow or reaching 255 (move to next subnet)
	if newIP[3] == 0 || newIP[3] == 255 {
		newIP[2]++
		newIP[3] = 1 // Start from .1 in the new subnet
		if newIP[2] == 0 {
			newIP[1]++
			newIP[3] = 1 // Start from .1 in the new subnet
			if newIP[1] == 0 {
				newIP[0]++
				newIP[3] = 1 // Start from .1 in the new subnet
			}
		}
	}

	sm.currentIP = newIP
}

// DeviceSimulator implementation
func (d *DeviceSimulator) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return nil
	}

	var errors []string

	// Start SNMP server
	if err := d.snmpServer.Start(); err != nil {
		errors = append(errors, fmt.Sprintf("SNMP: %v", err))
	}

	// Start SSH server
	if err := d.sshServer.Start(); err != nil {
		errors = append(errors, fmt.Sprintf("SSH: %v", err))
	}

	// Start API server (if device has API resources)
	if d.apiServer != nil && len(d.resources.API) > 0 {
		if err := d.apiServer.Start(); err != nil {
			errors = append(errors, fmt.Sprintf("API: %v", err))
		}
	}

	if len(errors) > 0 {
		// Stop any services that did start
		d.snmpServer.Stop()
		d.sshServer.Stop()
		if d.apiServer != nil {
			d.apiServer.Stop()
		}
		return fmt.Errorf("failed to start services: %s", strings.Join(errors, ", "))
	}

	d.running = true
	// log.Printf("Device %s started on %s (interface: %s, SNMP:%d, SSH:%d)",
	//	d.ID, d.IP.String(), d.tunIface.Name, d.SNMPPort, d.SSHPort)

	return nil
}

func (d *DeviceSimulator) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	wasRunning := d.running
	if !wasRunning &&
		d.snmpServer == nil &&
		d.sshServer == nil &&
		d.apiServer == nil &&
		d.flowExporter == nil &&
		d.trapExporter == nil &&
		d.syslogExporter == nil &&
		d.tunIface == nil {
		return nil
	}

	var errors []string

	if d.snmpServer != nil {
		if err := d.snmpServer.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("SNMP: %v", err))
		}
		d.snmpServer = nil
	}

	if d.sshServer != nil {
		if err := d.sshServer.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("SSH: %v", err))
		}
		d.sshServer = nil
	}

	if d.apiServer != nil {
		if err := d.apiServer.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("API: %v", err))
		}
		d.apiServer = nil
	}

	if d.flowExporter != nil {
		// Persist cumulative counters into the simulator-wide
		// per-collector aggregate (review decision D1.b) BEFORE closing
		// the exporter so /flows/status reports monotonic totals. The
		// outer `if !d.running` guard above makes this single-shot for
		// running devices; partially-started devices skip persistence.
		if wasRunning && manager != nil {
			manager.persistFlowCounters(d.flowExporter)
		}
		d.flowExporter.Close() //nolint:errcheck
		d.flowExporter = nil
	}

	if d.trapExporter != nil {
		// Persist cumulative counters into the simulator-wide
		// per-(collector, mode) aggregate (review decision D1.b) BEFORE
		// closing the exporter so /traps/status reports monotonic totals.
		// The running-state gate above makes this single-shot for started
		// devices; partially-started devices skip persistence.
		if wasRunning && manager != nil {
			manager.persistTrapCounters(d.trapExporter)
		}
		_ = d.trapExporter.Close()
		// Snapshot the scheduler under manager.mu so the nil-check and
		// the Deregister call can't split across a concurrent Stop*Export
		// that nils the field (phase-5 review D3).
		if sched := getTrapScheduler(manager); sched != nil {
			sched.Deregister(d.IP)
		}
		d.trapExporter = nil
	}

	if d.syslogExporter != nil {
		// Persist counters into the simulator-wide per-(collector,
		// format) aggregate so /syslog/status reports monotonic totals
		// across device churn. sync.Once-gated so it's single-shot even
		// if StopSyslogExport also persists the same exporter. Partially
		// started devices skip persistence because they never exported.
		if wasRunning && manager != nil {
			manager.persistSyslogCounters(d.syslogExporter)
		}
		_ = d.syslogExporter.Close()
		if sched := getSyslogScheduler(manager); sched != nil {
			sched.Deregister(d.IP)
		}
		d.syslogExporter = nil
	}

	// Only destroy TUN interface if it's not pre-allocated and not part of bulk deletion
	// Individual device stops will close the file descriptor but not delete the interface
	// Bulk deletion handles the actual interface removal
	if d.tunIface != nil && !d.tunIface.PreAllocated {
		d.tunIface.destroy() // Only closes the file descriptor
		d.tunIface = nil
	}
	// Pre-allocated interfaces remain available for reuse

	d.running = false
	// log.Printf("Device %s stopped", d.ID)

	if len(errors) > 0 {
		return fmt.Errorf("errors stopping services: %s", strings.Join(errors, ", "))
	}
	return nil
}

// stopListenersOnly closes all network listeners and TUN FDs without deleting TUN interfaces.
// Used during fast shutdown when the namespace will be deleted to clean up all interfaces at once.
func (d *DeviceSimulator) stopListenersOnly() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return
	}

	if d.snmpServer != nil {
		d.snmpServer.Stop()
	}
	if d.sshServer != nil {
		d.sshServer.Stop()
	}
	if d.apiServer != nil {
		d.apiServer.Stop()
	}
	if d.flowExporter != nil {
		// Persist counters before Close (review decision D1.b). The
		// `if !d.running` early-return above makes this single-shot.
		if manager != nil {
			manager.persistFlowCounters(d.flowExporter)
		}
		d.flowExporter.Close() //nolint:errcheck
	}
	if d.trapExporter != nil {
		// Persist counters before Close (review decision D1.b).
		if manager != nil {
			manager.persistTrapCounters(d.trapExporter)
		}
		_ = d.trapExporter.Close()
		d.trapExporter = nil
	}
	if d.syslogExporter != nil {
		// Persist counters before Close (sync.Once-gated).
		if manager != nil {
			manager.persistSyslogCounters(d.syslogExporter)
		}
		_ = d.syslogExporter.Close()
		d.syslogExporter = nil
	}
	if d.tunIface != nil {
		d.tunIface.destroy() // Close FD only, no ip link delete
	}
	d.running = false
}
