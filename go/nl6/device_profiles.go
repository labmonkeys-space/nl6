/*
 * Copyright 2025 Sharon Aicler (saichler@gmail.com)
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

// DeviceProfile defines CPU/memory/temperature metric parameters for a device category.
type DeviceProfile struct {
	CPUBaseMin  int   // Minimum base CPU% (e.g., 10)
	CPUBaseMax  int   // Maximum base CPU% (e.g., 40)
	CPUSpike    int   // Max amplitude of sine wave spikes
	MemTotalKB  int64 // Total memory in KB
	MemBaseMin  int   // Minimum base memory utilization %
	MemBaseMax  int   // Maximum base memory utilization %
	MemVariance int   // Memory fluctuation range %
	TempBaseMin int   // Minimum base temperature in Celsius
	TempBaseMax int   // Maximum base temperature in Celsius
	TempSpike   int   // Max amplitude of temperature spikes
	GPU         *GPUProfile // Non-nil for GPU server devices
}

// GPUProfile defines per-GPU metric generation parameters for NVIDIA DCGM devices.
type GPUProfile struct {
	GPUCount        int   // Number of GPUs (e.g., 8 for DGX/HGX)
	VRAMPerGPUMB    int64 // VRAM per GPU in MB
	GPUUtilMin      int   // Min GPU utilization %
	GPUUtilMax      int   // Max GPU utilization %
	GPUUtilSpike    int   // Utilization spike amplitude
	GPUTempMin      int   // Min GPU temperature (Celsius)
	GPUTempMax      int   // Max GPU temperature (Celsius)
	GPUTempSpike    int   // Temperature spike amplitude
	GPUPowerMin     int   // Min power draw (Watts)
	GPUPowerMax     int   // Max power draw (Watts)
	GPUPowerSpike   int   // Power spike amplitude
	GPUClockSMBase  int   // Base SM clock (MHz)
	GPUClockMemBase int   // Base memory clock (MHz)
}

var profileCoreRouter = DeviceProfile{
	CPUBaseMin: 15, CPUBaseMax: 45, CPUSpike: 20,
	MemTotalKB: 16 * 1024 * 1024, // 16 GB
	MemBaseMin: 50, MemBaseMax: 80, MemVariance: 10,
	TempBaseMin: 38, TempBaseMax: 52, TempSpike: 6,
}

var profileEdgeRouter = DeviceProfile{
	CPUBaseMin: 10, CPUBaseMax: 35, CPUSpike: 18,
	MemTotalKB: 8 * 1024 * 1024, // 8 GB
	MemBaseMin: 40, MemBaseMax: 70, MemVariance: 10,
	TempBaseMin: 32, TempBaseMax: 44, TempSpike: 5,
}

var profileDCSwitch = DeviceProfile{
	CPUBaseMin: 8, CPUBaseMax: 30, CPUSpike: 15,
	MemTotalKB: 16 * 1024 * 1024, // 16 GB
	MemBaseMin: 45, MemBaseMax: 75, MemVariance: 8,
	TempBaseMin: 28, TempBaseMax: 40, TempSpike: 4,
}

var profileCampusSwitch = DeviceProfile{
	CPUBaseMin: 5, CPUBaseMax: 25, CPUSpike: 12,
	MemTotalKB: 4 * 1024 * 1024, // 4 GB
	MemBaseMin: 35, MemBaseMax: 65, MemVariance: 8,
	TempBaseMin: 26, TempBaseMax: 38, TempSpike: 4,
}

var profileFirewall = DeviceProfile{
	CPUBaseMin: 25, CPUBaseMax: 60, CPUSpike: 25,
	MemTotalKB: 8 * 1024 * 1024, // 8 GB
	MemBaseMin: 55, MemBaseMax: 85, MemVariance: 10,
	TempBaseMin: 36, TempBaseMax: 54, TempSpike: 7,
}

var profileServer = DeviceProfile{
	CPUBaseMin: 20, CPUBaseMax: 50, CPUSpike: 22,
	MemTotalKB: 32 * 1024 * 1024, // 32 GB
	MemBaseMin: 50, MemBaseMax: 80, MemVariance: 10,
	TempBaseMin: 30, TempBaseMax: 55, TempSpike: 8,
}

// GPU server profiles
var profileGPUServerA100 = DeviceProfile{
	CPUBaseMin: 20, CPUBaseMax: 55, CPUSpike: 25,
	MemTotalKB:  1024 * 1024 * 1024, // 1 TB system RAM
	MemBaseMin:  40, MemBaseMax: 75, MemVariance: 12,
	TempBaseMin: 32, TempBaseMax: 48, TempSpike: 6,
	GPU: &GPUProfile{
		GPUCount: 8, VRAMPerGPUMB: 81920,
		GPUUtilMin: 15, GPUUtilMax: 85, GPUUtilSpike: 30,
		GPUTempMin: 35, GPUTempMax: 75, GPUTempSpike: 12,
		GPUPowerMin: 100, GPUPowerMax: 400, GPUPowerSpike: 80,
		GPUClockSMBase: 1410, GPUClockMemBase: 1512,
	},
}

var profileGPUServerH100 = DeviceProfile{
	CPUBaseMin: 25, CPUBaseMax: 60, CPUSpike: 28,
	MemTotalKB:  2 * 1024 * 1024 * 1024, // 2 TB system RAM
	MemBaseMin:  45, MemBaseMax: 80, MemVariance: 12,
	TempBaseMin: 34, TempBaseMax: 50, TempSpike: 7,
	GPU: &GPUProfile{
		GPUCount: 8, VRAMPerGPUMB: 81920,
		GPUUtilMin: 20, GPUUtilMax: 90, GPUUtilSpike: 30,
		GPUTempMin: 35, GPUTempMax: 80, GPUTempSpike: 14,
		GPUPowerMin: 150, GPUPowerMax: 700, GPUPowerSpike: 120,
		GPUClockSMBase: 1980, GPUClockMemBase: 2619,
	},
}

var profileGPUServerH200 = DeviceProfile{
	CPUBaseMin: 25, CPUBaseMax: 60, CPUSpike: 28,
	MemTotalKB:  2 * 1024 * 1024 * 1024, // 2 TB system RAM
	MemBaseMin:  45, MemBaseMax: 80, MemVariance: 12,
	TempBaseMin: 34, TempBaseMax: 50, TempSpike: 7,
	GPU: &GPUProfile{
		GPUCount: 8, VRAMPerGPUMB: 144384,
		GPUUtilMin: 20, GPUUtilMax: 90, GPUUtilSpike: 30,
		GPUTempMin: 35, GPUTempMax: 78, GPUTempSpike: 13,
		GPUPowerMin: 150, GPUPowerMax: 700, GPUPowerSpike: 120,
		GPUClockSMBase: 1980, GPUClockMemBase: 2619,
	},
}

// deviceProfileMap maps resource file names to their device profiles.
var deviceProfileMap = map[string]DeviceProfile{
	// Core Routers
	"asr9k.json":            profileCoreRouter,
	"cisco_crs_x.json":      profileCoreRouter,
	"huawei_ne8000.json":    profileCoreRouter,
	"nokia_7750_sr12.json":  profileCoreRouter,
	"juniper_mx960.json":    profileCoreRouter,

	// Edge Routers
	"juniper_mx240.json": profileEdgeRouter,
	"nec_ix3315.json":    profileEdgeRouter,
	"cisco_ios.json":     profileEdgeRouter,

	// Data Center Switches
	"cisco_nexus_9500.json": profileDCSwitch,
	"arista_7280r3.json":    profileDCSwitch,

	// Campus Switches
	"cisco_catalyst_9500.json": profileCampusSwitch,
	"extreme_vsp4450.json":     profileCampusSwitch,
	"dlink_dgs3630.json":       profileCampusSwitch,

	// Firewalls
	"palo_alto_pa3220.json":       profileFirewall,
	"fortinet_fortigate_600e.json": profileFirewall,
	"sonicwall_nsa6700.json":      profileFirewall,
	"check_point_15600.json":      profileFirewall,

	// Servers / BMC
	"dell_poweredge_r750.json": profileServer,
	"hpe_proliant_dl380.json":  profileServer,
	"ibm_power_s922.json":      profileServer,

	// NVIDIA GPU Servers
	"nvidia_dgx_a100.json": profileGPUServerA100,
	"nvidia_dgx_h100.json": profileGPUServerH100,
	"nvidia_hgx_h200.json": profileGPUServerH200,
}

// GetDeviceProfile returns the metric profile for a given resource file.
// Falls back to edge router profile if the file is unknown.
func GetDeviceProfile(resourceFile string) DeviceProfile {
	if p, ok := deviceProfileMap[resourceFile]; ok {
		return p
	}
	return profileEdgeRouter
}
