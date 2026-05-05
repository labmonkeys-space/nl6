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
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// SystemStats contains system resource statistics
type SystemStats struct {
	// Simulator process memory
	SimulatorMemoryMB float64 `json:"simulator_memory_mb"`
	SimulatorMemoryGB float64 `json:"simulator_memory_gb"`

	// System memory
	TotalMemoryMB uint64 `json:"total_memory_mb"`
	TotalMemoryGB float64 `json:"total_memory_gb"`
	UsedMemoryMB  uint64 `json:"used_memory_mb"`
	UsedMemoryGB  float64 `json:"used_memory_gb"`
	FreeMemoryMB  uint64 `json:"free_memory_mb"`
	FreeMemoryGB  float64 `json:"free_memory_gb"`
	MemoryUsagePercent float64 `json:"memory_usage_percent"`

	// CPU
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	NumCPU          int     `json:"num_cpu"`

	// Load average
	LoadAvg1  float64 `json:"load_avg_1"`
	LoadAvg5  float64 `json:"load_avg_5"`
	LoadAvg15 float64 `json:"load_avg_15"`
}

// GetSystemStats collects and returns current system statistics
func GetSystemStats() SystemStats {
	stats := SystemStats{
		NumCPU: runtime.NumCPU(),
	}

	// Get simulator process memory
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	stats.SimulatorMemoryMB = float64(memStats.Alloc) / 1024 / 1024
	stats.SimulatorMemoryGB = stats.SimulatorMemoryMB / 1024

	// Get system memory from /proc/meminfo
	getSystemMemory(&stats)

	// Get CPU usage from /proc/stat
	stats.CPUUsagePercent = getCPUUsage()

	// Get load average from /proc/loadavg
	getLoadAverage(&stats)

	return stats
}

// getSystemMemory reads memory info from /proc/meminfo
func getSystemMemory(stats *SystemStats) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer file.Close()

	var totalKB, freeKB, availableKB, buffersKB, cachedKB uint64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		switch fields[0] {
		case "MemTotal:":
			totalKB = value
		case "MemFree:":
			freeKB = value
		case "MemAvailable:":
			availableKB = value
		case "Buffers:":
			buffersKB = value
		case "Cached:":
			cachedKB = value
		}
	}

	stats.TotalMemoryMB = totalKB / 1024
	stats.TotalMemoryGB = float64(totalKB) / 1024 / 1024

	// Use MemAvailable if present, otherwise calculate from free + buffers + cached
	if availableKB > 0 {
		stats.FreeMemoryMB = availableKB / 1024
	} else {
		stats.FreeMemoryMB = (freeKB + buffersKB + cachedKB) / 1024
	}
	stats.FreeMemoryGB = float64(stats.FreeMemoryMB) / 1024

	stats.UsedMemoryMB = stats.TotalMemoryMB - stats.FreeMemoryMB
	stats.UsedMemoryGB = float64(stats.UsedMemoryMB) / 1024

	if stats.TotalMemoryMB > 0 {
		stats.MemoryUsagePercent = float64(stats.UsedMemoryMB) / float64(stats.TotalMemoryMB) * 100
	}
}

// getCPUUsage calculates CPU usage percentage
// This is a simplified version that reads current CPU stats
func getCPUUsage() float64 {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0
			}

			user, _ := strconv.ParseUint(fields[1], 10, 64)
			nice, _ := strconv.ParseUint(fields[2], 10, 64)
			system, _ := strconv.ParseUint(fields[3], 10, 64)
			idle, _ := strconv.ParseUint(fields[4], 10, 64)
			iowait := uint64(0)
			if len(fields) > 5 {
				iowait, _ = strconv.ParseUint(fields[5], 10, 64)
			}

			total := user + nice + system + idle + iowait
			busy := user + nice + system

			if total > 0 {
				return float64(busy) / float64(total) * 100
			}
			break
		}
	}
	return 0
}

// getLoadAverage reads load average from /proc/loadavg
func getLoadAverage(stats *SystemStats) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}

	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		stats.LoadAvg1, _ = strconv.ParseFloat(fields[0], 64)
		stats.LoadAvg5, _ = strconv.ParseFloat(fields[1], 64)
		stats.LoadAvg15, _ = strconv.ParseFloat(fields[2], 64)
	}
}
