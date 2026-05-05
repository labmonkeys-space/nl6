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

import "fmt"

// MetricOIDType identifies which cycling metric an OID maps to.
type MetricOIDType int

const (
	MetricCPUPercent    MetricOIDType = iota // CPU utilization %
	MetricMemUsed                           // Memory used (KB)
	MetricMemFree                           // Memory free (KB)
	MetricMemTotal                          // Memory total (KB, constant)
	MetricMemUsedPct                        // Memory used % (for vendors that report %)
	MetricTemperature                       // Temperature in Celsius

	// GPU-specific metric types (NVIDIA DCGM)
	MetricGPUUtil     MetricOIDType = iota + 10 // GPU compute utilization %
	MetricGPUMemUsed                             // GPU VRAM used (MB)
	MetricGPUMemTotal                            // GPU VRAM total (MB, constant)
	MetricGPUTemp                                // GPU temperature (Celsius)
	MetricGPUPower                               // GPU power draw (Watts)
	MetricGPUFanSpeed                            // GPU fan speed %
	MetricGPUClockSM                             // GPU SM clock (MHz)
	MetricGPUClockMem                            // GPU memory clock (MHz)
)

// vendorOIDs maps resource file names to their vendor-specific metric OIDs.
var vendorOIDs = map[string]map[string]MetricOIDType{

	// --- Cisco devices ---
	"cisco_ios.json": {
		".1.3.6.1.4.1.9.9.109.1.1.1.1.5.1": MetricCPUPercent,
		".1.3.6.1.4.1.9.9.48.1.1.1.5.1":    MetricMemUsed,
		".1.3.6.1.4.1.9.9.48.1.1.1.6.1":    MetricMemFree,
		".1.3.6.1.4.1.9.9.13.1.3.1.3.1":    MetricTemperature, // ciscoEnvMonTemperatureStatusValue
	},
	"cisco_catalyst_9500.json": {
		".1.3.6.1.4.1.9.9.109.1.1.1.1.5.1": MetricCPUPercent,
		".1.3.6.1.4.1.9.9.48.1.1.1.5.1":    MetricMemUsed,
		".1.3.6.1.4.1.9.9.48.1.1.1.6.1":    MetricMemFree,
		".1.3.6.1.4.1.9.9.13.1.3.1.3.1":    MetricTemperature,
	},
	"cisco_nexus_9500.json": {
		".1.3.6.1.4.1.9.9.109.1.1.1.1.5.1": MetricCPUPercent,
		".1.3.6.1.4.1.9.9.48.1.1.1.5.1":    MetricMemUsed,
		".1.3.6.1.4.1.9.9.48.1.1.1.6.1":    MetricMemFree,
		".1.3.6.1.4.1.9.9.13.1.3.1.3.1":    MetricTemperature,
	},
	"asr9k.json": {
		".1.3.6.1.4.1.9.9.109.1.1.1.1.5.1": MetricCPUPercent,
		".1.3.6.1.4.1.9.9.48.1.1.1.5.1":    MetricMemUsed,
		".1.3.6.1.4.1.9.9.48.1.1.1.6.1":    MetricMemFree,
		".1.3.6.1.4.1.9.9.13.1.3.1.3.1":    MetricTemperature,
	},
	"cisco_crs_x.json": {
		".1.3.6.1.4.1.9.9.109.1.1.1.1.5.1": MetricCPUPercent,
		".1.3.6.1.4.1.9.9.48.1.1.1.5.1":    MetricMemUsed,
		".1.3.6.1.4.1.9.9.48.1.1.1.6.1":    MetricMemFree,
		".1.3.6.1.4.1.9.9.13.1.3.1.3.1":    MetricTemperature,
	},

	// --- Juniper devices ---
	"juniper_mx960.json": {
		".1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0":  MetricCPUPercent,
		".1.3.6.1.4.1.2636.3.1.13.1.11.9.1.0.0": MetricMemUsedPct,
		".1.3.6.1.4.1.2636.3.1.13.1.7.9.1.0.0":  MetricTemperature, // jnxOperatingTemp
	},
	"juniper_mx240.json": {
		".1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0":  MetricCPUPercent,
		".1.3.6.1.4.1.2636.3.1.13.1.11.9.1.0.0": MetricMemUsedPct,
		".1.3.6.1.4.1.2636.3.1.13.1.7.9.1.0.0":  MetricTemperature,
	},

	// --- Palo Alto ---
	"palo_alto_pa3220.json": {
		".1.3.6.1.4.1.25461.2.1.2.1.2.0": MetricCPUPercent,
		".1.3.6.1.4.1.25461.2.1.2.3.1.0": MetricMemTotal,
		".1.3.6.1.4.1.25461.2.1.2.3.2.0": MetricMemFree,
		".1.3.6.1.4.1.25461.2.1.2.3.8.0": MetricTemperature, // panSysTemperature
	},

	// --- Fortinet ---
	"fortinet_fortigate_600e.json": {
		".1.3.6.1.4.1.12356.101.4.1.3.0": MetricCPUPercent,
		".1.3.6.1.4.1.12356.101.4.1.4.0": MetricMemUsedPct,
		".1.3.6.1.4.1.12356.101.4.1.5.0": MetricMemTotal,
		".1.3.6.1.4.1.12356.101.4.3.1.0": MetricTemperature, // fgHwSensorEntValue (temp)
	},

	// --- Huawei ---
	"huawei_ne8000.json": {
		".1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.0":  MetricCPUPercent,
		".1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7.0":  MetricMemUsedPct,
		".1.3.6.1.4.1.2011.5.25.31.1.1.1.1.8.0":  MetricMemTotal,
		".1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11.0": MetricTemperature, // hwEntityTemperature
	},

	// --- Nokia ---
	"nokia_7750_sr12.json": {
		".1.3.6.1.4.1.6527.3.1.2.1.1.1.1.5.1":  MetricCPUPercent,
		".1.3.6.1.4.1.6527.3.1.2.1.1.1.1.10.1": MetricMemUsed,
		".1.3.6.1.4.1.6527.3.1.2.1.1.1.1.11.1": MetricMemFree,
		".1.3.6.1.4.1.6527.3.1.2.1.1.1.1.7.1":  MetricTemperature, // tmnxHwTemperature
	},

	// --- Arista (uses standard Host Resources MIB) ---
	"arista_7280r3.json": {
		".1.3.6.1.2.1.25.3.3.1.2.1":      MetricCPUPercent,
		".1.3.6.1.2.1.25.2.3.1.5.1":      MetricMemTotal,
		".1.3.6.1.2.1.25.2.3.1.6.1":      MetricMemUsed,
		".1.3.6.1.2.1.99.1.1.1.4.100006": MetricTemperature, // entPhySensorValue (temp)
	},

	// --- Check Point ---
	"check_point_15600.json": {
		".1.3.6.1.4.1.2620.1.6.7.2.7.0":     MetricCPUPercent,
		".1.3.6.1.4.1.2620.1.6.7.4.1.0":     MetricMemTotal,
		".1.3.6.1.4.1.2620.1.6.7.4.3.0":     MetricMemUsed,
		".1.3.6.1.4.1.2620.1.6.7.4.4.0":     MetricMemFree,
		".1.3.6.1.4.1.2620.1.6.7.8.1.1.3.0": MetricTemperature, // temperatureSensorValue
	},

	// --- SonicWall ---
	"sonicwall_nsa6700.json": {
		".1.3.6.1.4.1.8714.2.1.3.1.1.0": MetricCPUPercent,
		".1.3.6.1.4.1.8714.2.1.3.1.2.0": MetricMemFree,
		".1.3.6.1.4.1.8714.2.1.3.1.3.0": MetricMemTotal,
		".1.3.6.1.4.1.8714.2.1.3.1.4.0": MetricTemperature, // sonicTemperature
	},

	// --- Dell iDRAC ---
	"dell_poweredge_r750.json": {
		".1.3.6.1.4.1.674.10892.5.4.200.10.1.12.1.1": MetricCPUPercent,
		".1.3.6.1.4.1.674.10892.5.4.700.20.1.8.1.1":  MetricMemTotal,
		".1.3.6.1.4.1.674.10892.5.4.700.20.1.6.1.1":  MetricTemperature, // systemBoardInletTemp
		".1.3.6.1.2.1.25.2.3.1.5.1":                   MetricMemTotal,    // hrStorageSize (physical memory)
		".1.3.6.1.2.1.25.2.3.1.6.1":                   MetricMemUsed,     // hrStorageUsed (physical memory)
	},

	// --- HPE iLO ---
	"hpe_proliant_dl380.json": {
		".1.3.6.1.4.1.232.11.2.3.1.1.3.0":  MetricCPUPercent,
		".1.3.6.1.4.1.232.11.2.13.1.0":     MetricMemUsed,
		".1.3.6.1.4.1.232.11.2.13.2.0":     MetricMemFree,
		".1.3.6.1.4.1.232.6.2.6.8.1.4.0.1": MetricTemperature, // cpqHeTemperatureCelsius
	},

	// --- IBM Power ---
	"ibm_power_s922.json": {
		".1.3.6.1.4.1.2.6.220.2.1.1.1.5.0": MetricCPUPercent,
		".1.3.6.1.4.1.2.6.220.2.1.2.1.4.0": MetricMemTotal,
		".1.3.6.1.4.1.2.6.220.2.1.2.1.5.0": MetricMemUsed,
		".1.3.6.1.4.1.2.6.220.2.1.2.1.6.0": MetricMemFree,
		".1.3.6.1.4.1.2.6.220.2.1.3.1.4.0": MetricTemperature, // ibmSystemTemperature
	},

	// --- NEC ---
	"nec_ix3315.json": {
		".1.3.6.1.4.1.119.2.3.84.3.1.0": MetricCPUPercent,
		".1.3.6.1.4.1.119.2.3.84.3.2.0": MetricMemTotal,
		".1.3.6.1.4.1.119.2.3.84.3.3.0": MetricMemUsed,
		".1.3.6.1.4.1.119.2.3.84.3.4.0": MetricMemFree,
		".1.3.6.1.4.1.119.2.3.84.3.5.0": MetricTemperature, // necTemperature
	},

	// --- Extreme ---
	"extreme_vsp4450.json": {
		".1.3.6.1.4.1.1916.1.32.1.4.1.5.1": MetricCPUPercent,
		".1.3.6.1.4.1.1916.1.32.2.2.1.2.1": MetricMemTotal,
		".1.3.6.1.4.1.1916.1.32.2.2.1.3.1": MetricMemFree,
		".1.3.6.1.4.1.1916.1.1.1.8.0":      MetricTemperature, // extremeCurrentTemperature
	},

	// --- D-Link ---
	"dlink_dgs3630.json": {
		".1.3.6.1.4.1.171.12.1.1.6.1.0":  MetricCPUPercent,
		".1.3.6.1.4.1.171.12.1.1.9.2.0":  MetricMemTotal,
		".1.3.6.1.4.1.171.12.1.1.9.4.0":  MetricMemUsedPct,
		".1.3.6.1.4.1.171.12.11.1.1.6.1": MetricTemperature, // dLinkTemperature
	},
}

// nvidiaGPUOIDs builds per-GPU dynamic metric OID mappings for NVIDIA DCGM devices.
// OID schema: .1.3.6.1.4.1.53246.1.1.1.1.{metric}.{gpuIndex}
//
//	metric 5=GPUUtil, 6=GPUMemUsed, 7=GPUMemTotal, 8=GPUTemp,
//	9=GPUPower, 10=GPUFanSpeed, 11=GPUClockSM, 12=GPUClockMem
//	gpuIndex 0-7
func nvidiaGPUOIDs(gpuCount int) map[string]MetricOIDType {
	prefix := ".1.3.6.1.4.1.53246.1.1.1.1"
	metrics := []struct {
		suffix int
		typ    MetricOIDType
	}{
		{5, MetricGPUUtil},
		{6, MetricGPUMemUsed},
		{7, MetricGPUMemTotal},
		{8, MetricGPUTemp},
		{9, MetricGPUPower},
		{10, MetricGPUFanSpeed},
		{11, MetricGPUClockSM},
		{12, MetricGPUClockMem},
	}
	m := make(map[string]MetricOIDType, gpuCount*len(metrics))
	for gpu := 0; gpu < gpuCount; gpu++ {
		for _, mt := range metrics {
			oid := fmt.Sprintf("%s.%d.%d", prefix, mt.suffix, gpu)
			m[oid] = mt.typ
		}
	}
	// Also include host-level CPU/memory/temperature via standard Host Resources MIB
	m[".1.3.6.1.2.1.25.3.3.1.2.1"] = MetricCPUPercent
	m[".1.3.6.1.2.1.25.2.3.1.5.1"] = MetricMemTotal
	m[".1.3.6.1.2.1.25.2.3.1.6.1"] = MetricMemUsed
	return m
}

func init() {
	vendorOIDs["nvidia_dgx_a100.json"] = nvidiaGPUOIDs(8)
	vendorOIDs["nvidia_dgx_h100.json"] = nvidiaGPUOIDs(8)
	vendorOIDs["nvidia_hgx_h200.json"] = nvidiaGPUOIDs(8)
}

// GetMetricOIDs returns the OID-to-metric-type mapping for a device type.
// Returns nil if the device type has no dynamic metric OIDs.
func GetMetricOIDs(resourceFile string) map[string]MetricOIDType {
	if m, ok := vendorOIDs[resourceFile]; ok {
		return m
	}
	return nil
}

// cachedSortedMetricOIDs stores pre-sorted metric OID slices per device type.
// Computed once at init time to avoid repeated allocation and O(n²) sorting.
var cachedSortedMetricOIDs = map[string][]string{}

func init() {
	for resourceFile, m := range vendorOIDs {
		oids := make([]string, 0, len(m))
		for oid := range m {
			oids = append(oids, oid)
		}
		// Sort OIDs using bubble sort (small slices, done once at startup)
		for i := 0; i < len(oids); i++ {
			for j := i + 1; j < len(oids); j++ {
				if compareOIDs(oids[i], oids[j]) > 0 {
					oids[i], oids[j] = oids[j], oids[i]
				}
			}
		}
		cachedSortedMetricOIDs[resourceFile] = oids
	}
}

// GetSortedMetricOIDs returns a pre-sorted list of metric OID strings
// for a given device type. The result is cached at init time.
func GetSortedMetricOIDs(resourceFile string) []string {
	return cachedSortedMetricOIDs[resourceFile]
}
