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

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"
)

const numDataPoints = 100

// metricsPointInterval is how long each pre-generated point is served, so a
// full cycle of numDataPoints lasts 100 minutes. A collector polling every
// minute reads every point; one polling every five minutes reads every fifth.
const metricsPointInterval = time.Minute

// MetricsCycler holds 100 pre-generated CPU, memory, and temperature data points per device.
// The point served is a function of the time since the cycler was built, never
// of how often it is read (nl6#970). Every metric of a device, its GPUs
// included, reads the same point at the same instant: memory used + free is the
// total, a GPU's power follows its utilization, and a second collector or a
// GETNEXT that evaluates a metric OID without returning it moves nothing.
type MetricsCycler struct {
	cpuPoints  [numDataPoints]int   // CPU utilization % (0-100)
	memUsed    [numDataPoints]int64 // Memory used in KB
	tempPoints [numDataPoints]int   // Temperature in Celsius
	memTotal   int64                // Total memory in KB (constant)
	startTime  time.Time            // origin of the served point, set by NewMetricsCycler
	now        func() time.Time     // clock of the point, nil reads time.Now; unsynchronised, set before sharing
	gpuMetrics []*GPUMetrics        // Per-GPU cycling metrics (nil for non-GPU devices)
	// ifCounters holds the per-interface HC counter cycler (nil if no HC OIDs).
	//
	// The pointer is stored atomically. The pointed-to IfCounterCycler is
	// immutable after Store — re-initialisation means building a fresh
	// instance and calling Store again with the new pointer. All readers
	// must call Load() at the top of the function and operate on the
	// captured local. This makes a future runtime reset / rescenario
	// control plane safe to drop in without racing the SNMP hot path.
	ifCounters atomic.Pointer[IfCounterCycler]
	// optical holds the per-channel coherent optical value engine (nil
	// for every packet device type). Same discipline as ifCounters: the
	// pointer is stored atomically and the pointed-to OpticalCycler is
	// immutable after Store, so readers capture it once with Load() and
	// operate on the local.
	optical atomic.Pointer[OpticalCycler]
}

// NewMetricsCycler creates a cycler with 100 data points generated from the
// given seed and device profile. Each device gets a unique curve.
func NewMetricsCycler(seed int64, profile DeviceProfile) *MetricsCycler {
	c := &MetricsCycler{
		memTotal:  profile.MemTotalKB,
		startTime: time.Now(),
	}

	rng := newSeededRand(seed)

	// Generate CPU curve: overlapping sine waves + jitter
	cpuBase := profile.CPUBaseMin + rng.IntN(profile.CPUBaseMax-profile.CPUBaseMin+1)
	// Random phase offsets for sine waves
	phase1 := rng.Float64() * 2 * math.Pi
	phase2 := rng.Float64() * 2 * math.Pi
	phase3 := rng.Float64() * 2 * math.Pi

	for i := 0; i < numDataPoints; i++ {
		t := float64(i) / float64(numDataPoints) * 2 * math.Pi
		// Three sine waves at different frequencies for realistic variation
		wave1 := math.Sin(t+phase1) * float64(profile.CPUSpike) * 0.5
		wave2 := math.Sin(t*2.7+phase2) * float64(profile.CPUSpike) * 0.25
		wave3 := math.Sin(t*5.3+phase3) * float64(profile.CPUSpike) * 0.1
		jitter := float64(rng.IntN(5) - 2) // -2 to +2

		cpu := float64(cpuBase) + wave1 + wave2 + wave3 + jitter
		c.cpuPoints[i] = clampInt(int(math.Round(cpu)), 1, 100)
	}

	// Generate memory curve: higher base, lower variance than CPU
	memBasePercent := profile.MemBaseMin + rng.IntN(profile.MemBaseMax-profile.MemBaseMin+1)
	memPhase1 := rng.Float64() * 2 * math.Pi
	memPhase2 := rng.Float64() * 2 * math.Pi

	for i := 0; i < numDataPoints; i++ {
		t := float64(i) / float64(numDataPoints) * 2 * math.Pi
		wave1 := math.Sin(t*0.8+memPhase1) * float64(profile.MemVariance) * 0.6
		wave2 := math.Sin(t*2.1+memPhase2) * float64(profile.MemVariance) * 0.3
		jitter := float64(rng.IntN(3) - 1) // -1 to +1

		memPct := float64(memBasePercent) + wave1 + wave2 + jitter
		memPct = math.Max(1, math.Min(99, memPct))
		c.memUsed[i] = int64(memPct / 100.0 * float64(profile.MemTotalKB))
	}

	// Generate temperature curve: slow sine wave with small jitter
	tempBase := profile.TempBaseMin + rng.IntN(profile.TempBaseMax-profile.TempBaseMin+1)
	tempPhase1 := rng.Float64() * 2 * math.Pi
	tempPhase2 := rng.Float64() * 2 * math.Pi

	for i := 0; i < numDataPoints; i++ {
		t := float64(i) / float64(numDataPoints) * 2 * math.Pi
		wave1 := math.Sin(t*0.6+tempPhase1) * float64(profile.TempSpike) * 0.6
		wave2 := math.Sin(t*1.9+tempPhase2) * float64(profile.TempSpike) * 0.3
		jitter := float64(rng.IntN(3) - 1) // -1 to +1

		temp := float64(tempBase) + wave1 + wave2 + jitter
		c.tempPoints[i] = clampInt(int(math.Round(temp)), 15, 95)
	}

	return c
}

// point is the index of the data point served now. A request reads it once and
// passes it to every getter, so all its variable bindings come from one point
// even when the request straddles a minute boundary (nl6#975).
func (c *MetricsCycler) point() int {
	now := c.now
	if now == nil {
		now = time.Now
	}
	return metricsPointAt(now().Sub(c.startTime))
}

// metricsPointAt is the index served at elapsed time since startTime. A cycler
// built without NewMetricsCycler has a zero startTime; Sub saturates for it, so
// it still yields a valid index. A clock that reads before startTime, which
// only an injected one can, serves point 0 instead of a negative index.
func metricsPointAt(elapsed time.Duration) int {
	if elapsed < 0 {
		elapsed = 0
	}
	return int((elapsed / metricsPointInterval) % numDataPoints)
}

// GetCPUPercent returns the CPU% at point p as a string.
func (c *MetricsCycler) GetCPUPercent(p int) string {
	return fmt.Sprintf("%d", c.cpuPoints[p])
}

// GetMemUsed returns the memory used in KB at point p as a string.
func (c *MetricsCycler) GetMemUsed(p int) string {
	return fmt.Sprintf("%d", c.memUsed[p])
}

// GetMemFree returns total - used in KB at point p as a string, so it sums to
// GetMemTotal with GetMemUsed at the same point.
func (c *MetricsCycler) GetMemFree(p int) string {
	used := c.memUsed[p]
	free := c.memTotal - used
	if free < 0 {
		free = 0
	}
	return fmt.Sprintf("%d", free)
}

// GetMemTotal returns the constant total memory in KB as a string.
func (c *MetricsCycler) GetMemTotal() string {
	return fmt.Sprintf("%d", c.memTotal)
}

// GetMemUsedPercent returns memory utilization at point p as a percentage string.
func (c *MetricsCycler) GetMemUsedPercent(p int) string {
	used := c.memUsed[p]
	pct := float64(used) / float64(c.memTotal) * 100
	return fmt.Sprintf("%d", int(math.Round(pct)))
}

// GetTemperature returns the temperature in Celsius at point p as a string.
func (c *MetricsCycler) GetTemperature(p int) string {
	return fmt.Sprintf("%d", c.tempPoints[p])
}

func clampInt(val, min, max int) int {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}
