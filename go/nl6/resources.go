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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
)

func (sm *SimulatorManager) LoadResources(filename string) error {
	// Extract directory name from filename (e.g., "resources/asr9k.json" -> "resources/asr9k")
	dirPath := strings.TrimSuffix(filename, ".json")

	// Check if directory exists (new structure)
	if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
		return sm.loadResourcesFromDir(dirPath)
	}

	// Fallback to old single-file format for backwards compatibility
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Printf("Resources file %s not found, creating default resources...", filename)
		return sm.createDefaultResources(filename)
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&sm.deviceResources); err != nil {
		return err
	}

	// Build indexes for loaded default resources
	sm.buildResourceIndexes(sm.deviceResources)

	log.Printf("Loaded %d SNMP and %d SSH resources with indexes", len(sm.deviceResources.SNMP), len(sm.deviceResources.SSH))
	return nil
}

// loadResourcesFromDir loads and merges all JSON files from a directory
func (sm *SimulatorManager) loadResourcesFromDir(dirPath string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %v", dirPath, err)
	}

	sm.deviceResources = &DeviceResources{
		SNMP: make([]SNMPResource, 0),
		SSH:  make([]SSHResource, 0),
		API:  make([]APIResource, 0),
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := fmt.Sprintf("%s/%s", dirPath, entry.Name())
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open %s: %v", filePath, err)
		}

		var partResources DeviceResources
		if err := json.NewDecoder(file).Decode(&partResources); err != nil {
			file.Close()
			return fmt.Errorf("failed to parse %s: %v", filePath, err)
		}
		file.Close()

		sm.deviceResources.SNMP = append(sm.deviceResources.SNMP, partResources.SNMP...)
		sm.deviceResources.SSH = append(sm.deviceResources.SSH, partResources.SSH...)
		sm.deviceResources.API = append(sm.deviceResources.API, partResources.API...)
	}

	// Build indexes for loaded default resources
	sm.buildResourceIndexes(sm.deviceResources)

	log.Printf("Loaded %d SNMP and %d SSH resources from directory %s",
		len(sm.deviceResources.SNMP), len(sm.deviceResources.SSH), dirPath)
	return nil
}

func (sm *SimulatorManager) createDefaultResources(filename string) error {
	defaultResources := &DeviceResources{
		SNMP: []SNMPResource{
			{OID: "1.3.6.1.2.1.1.1.0", Response: "Cisco IOS Software, Router Version 15.1"},
			{OID: "1.3.6.1.2.1.1.2.0", Response: "1.3.6.1.4.1.9.1.1"},
			{OID: "1.3.6.1.2.1.1.3.0", Response: "123456789"},
			{OID: "1.3.6.1.2.1.1.4.0", Response: "Network Administrator"},
			{OID: "1.3.6.1.2.1.1.5.0", Response: "Router-Simulator"},
			{OID: "1.3.6.1.2.1.1.6.0", Response: "Simulation Lab"},
			{OID: "1.3.6.1.2.1.2.1.0", Response: "4"},
			{OID: "1.3.6.1.2.1.2.2.1.1.1", Response: "1"},
			{OID: "1.3.6.1.2.1.2.2.1.2.1", Response: "FastEthernet0/0"},
			{OID: "1.3.6.1.2.1.2.2.1.3.1", Response: "6"},
			{OID: "1.3.6.1.2.1.2.2.1.5.1", Response: "1000000000"},
			{OID: "1.3.6.1.2.1.2.2.1.7.1", Response: "1"},
			{OID: "1.3.6.1.2.1.2.2.1.8.1", Response: "1"},
			{OID: "1.3.6.1.2.1.2.2.1.10.1", Response: "1000000"},
			{OID: "1.3.6.1.2.1.2.2.1.16.1", Response: "500000"},
			{OID: "1.3.6.1.2.1.4.1.0", Response: "1"},
			{OID: "1.3.6.1.2.1.4.2.0", Response: "64"},
			{OID: "1.3.6.1.2.1.4.3.0", Response: "100"},
			{OID: "1.3.6.1.2.1.4.4.0", Response: "0"},
			{OID: "1.3.6.1.2.1.4.5.0", Response: "10"},
			{OID: "1.3.6.1.2.1.6.1.0", Response: "1"},
			{OID: "1.3.6.1.2.1.6.2.0", Response: "60"},
			{OID: "1.3.6.1.2.1.6.4.0", Response: "2"},
			{OID: "1.3.6.1.2.1.6.5.0", Response: "1000"},
			{OID: "1.3.6.1.2.1.6.6.0", Response: "500"},
			{OID: "1.3.6.1.2.1.6.8.0", Response: "200"},
			{OID: "1.3.6.1.2.1.6.9.0", Response: "100"},
			{OID: "1.3.6.1.2.1.7.1.0", Response: "1"},
			{OID: "1.3.6.1.2.1.7.2.0", Response: "1000"},
			{OID: "1.3.6.1.2.1.7.3.0", Response: "500"},
		},
		SSH: []SSHResource{
			{Command: "show version", Response: "Cisco IOS Software, Router Version 15.1\nDevice Simulator v1.0\nUptime: 1 day, 2 hours, 30 minutes"},
			{Command: "show interfaces", Response: "FastEthernet0/0 is up, line protocol is up\n  Hardware is FastEthernet, address is 0011.2233.4455\n  Internet address is 192.168.1.1/24\n  MTU 1500 bytes, BW 100000 Kbit/sec"},
			{Command: "show ip route", Response: "Codes: L - local, C - connected, S - static\nGateway of last resort is 192.168.1.254 to network 0.0.0.0\nC    192.168.1.0/24 is directly connected, FastEthernet0/0"},
			{Command: "show running-config", Response: "version 15.1\nhostname Router-Simulator\ninterface FastEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown"},
			{Command: "show processes cpu", Response: "CPU utilization for five seconds: 2%/0%; one minute: 3%; five minutes: 4%\nPID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process\n  1        1000       10000        100  0.5%   0.6%   0.7%   0 Init"},
			{Command: "show memory", Response: "Head    Total(b)     Used(b)     Free(b)   Lowest(b)  Largest(b)\nProcessor  67108864    33554432    33554432   30000000   30000000\n I/O     16777216     8388608     8388608    8000000    8000000"},
			{Command: "ping 8.8.8.8", Response: "Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to 8.8.8.8, timeout is 2 seconds:\n!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms"},
			{Command: "traceroute 8.8.8.8", Response: "Type escape sequence to abort.\nTracing the route to 8.8.8.8\n  1 192.168.1.254 4 msec 2 msec 4 msec\n  2 * * *\n  3 8.8.8.8 20 msec 18 msec 20 msec"},
		},
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(defaultResources); err != nil {
		return err
	}

	// Build indexes for default resources too
	sm.buildResourceIndexes(defaultResources)

	sm.deviceResources = defaultResources
	log.Printf("Created default resources file %s with %d SNMP and %d SSH resources",
		filename, len(defaultResources.SNMP), len(defaultResources.SSH))

	return nil
}

// LoadSpecificResources loads resources from a directory in the resources folder
func (sm *SimulatorManager) LoadSpecificResources(filename string) (*DeviceResources, error) {
	// Check cache first
	if cached, exists := sm.resourcesCache[filename]; exists {
		return cached, nil
	}

	// Extract directory name (e.g., "cisco_catalyst_9500.json" -> "cisco_catalyst_9500")
	dirName := strings.TrimSuffix(filename, ".json")
	dirPath := fmt.Sprintf("resources/%s", dirName)

	// Check if directory exists (new structure)
	if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
		return sm.loadSpecificResourcesFromDir(dirPath, filename)
	}

	// Fallback to old single-file format for backwards compatibility
	resourcePath := fmt.Sprintf("resources/%s", filename)
	if _, err := os.Stat(resourcePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("resource directory or file %s not found", filename)
	}

	file, err := os.Open(resourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open resource file %s: %v", resourcePath, err)
	}
	defer file.Close()

	var resources DeviceResources
	if err := json.NewDecoder(file).Decode(&resources); err != nil {
		return nil, fmt.Errorf("failed to parse resource file %s: %v", resourcePath, err)
	}

	// Build performance indexes for fast lookups (also sorts by OID after normalizing)
	sm.buildResourceIndexes(&resources)

	// Cache the loaded resources with indexes
	sm.resourcesCache[filename] = &resources

	return &resources, nil
}

// loadSpecificResourcesFromDir loads and merges all JSON files from a resource directory
func (sm *SimulatorManager) loadSpecificResourcesFromDir(dirPath string, cacheKey string) (*DeviceResources, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %v", dirPath, err)
	}

	resources := &DeviceResources{
		SNMP: make([]SNMPResource, 0),
		SSH:  make([]SSHResource, 0),
		API:  make([]APIResource, 0),
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := fmt.Sprintf("%s/%s", dirPath, entry.Name())
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %v", filePath, err)
		}

		var partResources DeviceResources
		if err := json.NewDecoder(file).Decode(&partResources); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to parse %s: %v", filePath, err)
		}
		file.Close()

		resources.SNMP = append(resources.SNMP, partResources.SNMP...)
		resources.SSH = append(resources.SSH, partResources.SSH...)
		resources.API = append(resources.API, partResources.API...)
	}

	// Build performance indexes for fast lookups (also sorts by OID after normalizing)
	sm.buildResourceIndexes(resources)

	// Cache the loaded resources with indexes
	sm.resourcesCache[cacheKey] = resources

	return resources, nil
}

// buildResourceIndexes builds performance optimization indexes for fast OID lookups
func (sm *SimulatorManager) buildResourceIndexes(resources *DeviceResources) {
	// Sort SNMP resources by OID numerically so that SNMP walks return OIDs in
	// strictly increasing order (column-major table ordering). JSON files store
	// OIDs in row-major order, so without this sort the oidNextMap produces an
	// "OID not increasing" error when snmpwalk crosses row boundaries.
	sort.Slice(resources.SNMP, func(i, j int) bool {
		return compareOIDsLexicographically(resources.SNMP[i].OID, resources.SNMP[j].OID) < 0
	})

	// Initialize lock-free sync.Map for O(1) OID lookups
	resources.oidIndex = &sync.Map{}

	// Initialize sorted OID slice for binary search in GetNext operations
	resources.sortedOIDs = make([]string, 0, len(resources.SNMP))

	// Initialize next OID map for pre-computed walk paths
	resources.oidNextMap = &sync.Map{}

	// Build oidIndex and sortedOIDs, skipping dynamic OIDs handled elsewhere.
	// Normalize OIDs from JSON to always use a leading dot.
	for _, resource := range resources.SNMP {
		oid := resource.OID
		if len(oid) > 0 && oid[0] != '.' {
			oid = "." + oid
		}
		if oid == ".1.3.6.1.2.1.1.5.0" || oid == ".1.3.6.1.2.1.1.6.0" {
			continue
		}
		resources.oidIndex.Store(oid, resource.Response)
		resources.sortedOIDs = append(resources.sortedOIDs, oid)
	}

	// Sort OIDs into lexicographic order. Resource JSON files group OIDs by
	// interface (all columns for interface 1, then interface 2, etc.), not by
	// column, so the raw order is not lexicographic. Binary search in
	// findNextOID and the oidNextMap both require lexicographic ordering.
	sort.Slice(resources.sortedOIDs, func(i, j int) bool {
		return compareOIDsLexicographically(resources.sortedOIDs[i], resources.sortedOIDs[j]) < 0
	})

	// Build oidNextMap from sortedOIDs rather than from the raw SNMP slice.
	// The old loop used SNMP[i+1] which could land on a skipped special OID
	// (sysName/sysLocation). Those OIDs are absent from oidIndex, so the fast
	// path in findNextOID silently fell back to binary search for every OID
	// immediately preceding a special OID.
	for i := 0; i < len(resources.sortedOIDs)-1; i++ {
		resources.oidNextMap.Store(resources.sortedOIDs[i], resources.sortedOIDs[i+1])
	}
}

// ListAvailableResources lists all available resource directories in the resources directory
func (sm *SimulatorManager) ListAvailableResources() []ResourceInfo {
	var resources []ResourceInfo

	resourceDir := "resources"
	entries, err := os.ReadDir(resourceDir)
	if err != nil {
		log.Printf("Failed to read resources directory: %v", err)
		return resources
	}

	for _, entry := range entries {
		// Look for directories (new structure) containing JSON files
		if entry.IsDir() {
			name := entry.Name()
			deviceType := getDeviceTypeFromName(name)

			// Verify directory contains at least one JSON file
			dirPath := fmt.Sprintf("%s/%s", resourceDir, name)
			subEntries, err := os.ReadDir(dirPath)
			if err != nil {
				continue
			}

			hasJSON := false
			for _, subEntry := range subEntries {
				if !subEntry.IsDir() && strings.HasSuffix(subEntry.Name(), ".json") {
					hasJSON = true
					break
				}
			}

			if hasJSON {
				resources = append(resources, ResourceInfo{
					Filename: name + ".json", // Keep .json suffix for API compatibility
					Name:     name,
					Type:     deviceType,
					Category: getDeviceCategoryFromName(name),
				})
			}
		}
	}

	return resources
}

// getDeviceTypeFromName determines the device type from a resource name
func getDeviceTypeFromName(name string) string {
	nameLower := strings.ToLower(name)

	if strings.Contains(nameLower, "asr9k") {
		return "Cisco ASR9K"
	} else if strings.Contains(nameLower, "cisco") && strings.Contains(nameLower, "ios") {
		return "Cisco IOS"
	} else if strings.Contains(nameLower, "cisco") {
		return "Cisco Router/Switch"
	} else if strings.Contains(nameLower, "juniper") {
		return "Juniper"
	} else if strings.Contains(nameLower, "nexus") {
		return "Cisco Nexus"
	} else if strings.Contains(nameLower, "arista") {
		return "Arista"
	} else if strings.Contains(nameLower, "fortinet") {
		return "Fortinet"
	} else if strings.Contains(nameLower, "palo") {
		return "Palo Alto"
	} else if strings.Contains(nameLower, "check_point") {
		return "Check Point"
	} else if strings.Contains(nameLower, "dell") {
		return "Dell"
	} else if strings.Contains(nameLower, "hpe") || strings.Contains(nameLower, "hp") {
		return "HPE"
	} else if strings.Contains(nameLower, "huawei") {
		return "Huawei"
	} else if strings.Contains(nameLower, "nokia") {
		return "Nokia"
	} else if strings.Contains(nameLower, "extreme") {
		return "Extreme Networks"
	} else if strings.Contains(nameLower, "dlink") || strings.Contains(nameLower, "d-link") {
		return "D-Link"
	} else if strings.Contains(nameLower, "sonicwall") {
		return "SonicWall"
	} else if strings.Contains(nameLower, "nec") {
		return "NEC"
	} else if strings.Contains(nameLower, "ibm") {
		return "IBM"
	} else if strings.Contains(nameLower, "netapp") {
		return "NetApp"
	} else if strings.Contains(nameLower, "pure") {
		return "Pure Storage"
	} else if strings.Contains(nameLower, "aws") {
		return "AWS"
	} else if strings.Contains(nameLower, "linux") {
		return "Linux Server"
	} else if strings.Contains(nameLower, "nvidia") || strings.Contains(nameLower, "dgx") || strings.Contains(nameLower, "hgx") {
		return "NVIDIA GPU Server"
	}

	// Capitalize first letter of name as fallback
	if len(name) > 0 {
		return strings.ToUpper(name[:1]) + name[1:]
	}
	return "Unknown"
}

// getDeviceCategoryFromName determines the device category from a resource name.
func getDeviceCategoryFromName(name string) string {
	nameLower := strings.ToLower(name)

	// Network Devices (routers, switches, firewalls)
	if strings.Contains(nameLower, "asr9k") || strings.Contains(nameLower, "crs") ||
		strings.Contains(nameLower, "mx240") || strings.Contains(nameLower, "mx960") ||
		strings.Contains(nameLower, "ne8000") || strings.Contains(nameLower, "7750") ||
		strings.Contains(nameLower, "nec") || (strings.Contains(nameLower, "cisco") && strings.Contains(nameLower, "ios")) ||
		strings.Contains(nameLower, "catalyst") || strings.Contains(nameLower, "nexus") ||
		strings.Contains(nameLower, "arista") || strings.Contains(nameLower, "extreme") ||
		strings.Contains(nameLower, "dlink") || strings.Contains(nameLower, "d-link") ||
		strings.Contains(nameLower, "palo") || strings.Contains(nameLower, "fortinet") ||
		strings.Contains(nameLower, "fortigate") || strings.Contains(nameLower, "check_point") ||
		strings.Contains(nameLower, "sonicwall") || strings.Contains(nameLower, "nokia") ||
		strings.Contains(nameLower, "huawei") || strings.Contains(nameLower, "juniper") {
		return "Network Devices"
	}

	// GPU Servers
	if strings.Contains(nameLower, "nvidia") || strings.Contains(nameLower, "dgx") ||
		strings.Contains(nameLower, "hgx") {
		return "GPU Servers"
	}

	// Storage
	if strings.Contains(nameLower, "netapp") || strings.Contains(nameLower, "pure") ||
		strings.Contains(nameLower, "dell_emc") || strings.Contains(nameLower, "aws") {
		return "Storage"
	}

	// Servers
	if strings.Contains(nameLower, "dell") || strings.Contains(nameLower, "hpe") ||
		strings.Contains(nameLower, "hp") || strings.Contains(nameLower, "ibm") ||
		strings.Contains(nameLower, "linux") || strings.Contains(nameLower, "poweredge") ||
		strings.Contains(nameLower, "proliant") || strings.Contains(nameLower, "power_s") {
		return "Servers"
	}

	return "Other"
}

// getDeviceTypeFromResourceFile determines the device type from a resource filename
func getDeviceTypeFromResourceFile(filename string) string {
	if filename == "" {
		return "Default"
	}

	name := strings.TrimSuffix(filename, ".json")
	return getDeviceTypeFromName(name)
}
