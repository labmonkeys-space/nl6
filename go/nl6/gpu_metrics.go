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
	"strconv"
	"strings"
)

// GPUMetrics holds cycling data points for a single GPU.
type GPUMetrics struct {
	gpuUtil     [numDataPoints]int   // GPU utilization % (0-100)
	gpuMemUsed  [numDataPoints]int64 // GPU VRAM used (MB)
	gpuMemTotal int64                // GPU VRAM total (MB, constant)
	gpuTemp     [numDataPoints]int   // GPU temperature (Celsius)
	gpuPower    [numDataPoints]int   // GPU power draw (Watts)
	gpuFanSpeed [numDataPoints]int   // GPU fan speed % (0-100)
	gpuClockSM  [numDataPoints]int   // SM clock MHz
	gpuClockMem [numDataPoints]int   // Memory clock MHz
}

// InitGPUMetrics initializes GPU metric arrays on the MetricsCycler for devices
// with a GPUProfile. Each GPU gets its own seed, gpuSeed(baseSeed, k), for different
// but correlated curves.
func (c *MetricsCycler) InitGPUMetrics(baseSeed int64, gpuProfile *GPUProfile) {
	if gpuProfile == nil {
		return
	}
	c.gpuMetrics = make([]*GPUMetrics, gpuProfile.GPUCount)
	for i := 0; i < gpuProfile.GPUCount; i++ {
		c.gpuMetrics[i] = newGPUMetrics(gpuSeed(baseSeed, i), gpuProfile)
	}
}

func newGPUMetrics(seed int64, p *GPUProfile) *GPUMetrics {
	g := &GPUMetrics{gpuMemTotal: p.VRAMPerGPUMB}
	rng := newSeededRand(seed)

	// GPU utilization curve
	utilBase := p.GPUUtilMin + rng.IntN(p.GPUUtilMax-p.GPUUtilMin+1)
	ph1 := rng.Float64() * 2 * math.Pi
	ph2 := rng.Float64() * 2 * math.Pi
	ph3 := rng.Float64() * 2 * math.Pi
	for i := 0; i < numDataPoints; i++ {
		t := float64(i) / float64(numDataPoints) * 2 * math.Pi
		w1 := math.Sin(t+ph1) * float64(p.GPUUtilSpike) * 0.5
		w2 := math.Sin(t*2.3+ph2) * float64(p.GPUUtilSpike) * 0.25
		w3 := math.Sin(t*4.7+ph3) * float64(p.GPUUtilSpike) * 0.1
		jitter := float64(rng.IntN(7) - 3)
		g.gpuUtil[i] = clampInt(int(math.Round(float64(utilBase)+w1+w2+w3+jitter)), 0, 100)
	}

	// GPU memory usage (correlated with utilization)
	for i := 0; i < numDataPoints; i++ {
		utilPct := float64(g.gpuUtil[i]) / 100.0
		// Memory roughly follows utilization with some lag and noise
		memPct := utilPct*0.85 + rng.Float64()*0.1
		memPct = math.Max(0.05, math.Min(0.98, memPct))
		g.gpuMemUsed[i] = int64(memPct * float64(p.VRAMPerGPUMB))
	}

	// GPU temperature (correlated with power/utilization)
	tempBase := p.GPUTempMin + rng.IntN(p.GPUTempMax-p.GPUTempMin+1)
	tph1 := rng.Float64() * 2 * math.Pi
	tph2 := rng.Float64() * 2 * math.Pi
	for i := 0; i < numDataPoints; i++ {
		t := float64(i) / float64(numDataPoints) * 2 * math.Pi
		w1 := math.Sin(t*0.7+tph1) * float64(p.GPUTempSpike) * 0.6
		w2 := math.Sin(t*1.8+tph2) * float64(p.GPUTempSpike) * 0.3
		// Add correlation with utilization
		utilCorrelation := float64(g.gpuUtil[i]-50) * 0.15
		jitter := float64(rng.IntN(3) - 1)
		g.gpuTemp[i] = clampInt(int(math.Round(float64(tempBase)+w1+w2+utilCorrelation+jitter)), 25, 95)
	}

	// GPU power draw (strongly correlated with utilization)
	for i := 0; i < numDataPoints; i++ {
		utilPct := float64(g.gpuUtil[i]) / 100.0
		powerRange := float64(p.GPUPowerMax - p.GPUPowerMin)
		power := float64(p.GPUPowerMin) + utilPct*powerRange*0.85
		power += float64(rng.IntN(p.GPUPowerSpike) - p.GPUPowerSpike/2)
		g.gpuPower[i] = clampInt(int(math.Round(power)), p.GPUPowerMin, p.GPUPowerMax)
	}

	// Fan speed (correlated with temperature, 0 for liquid-cooled DGX/HGX)
	// DGX/HGX systems use liquid cooling so fan reports 0; but include small values for realism
	for i := 0; i < numDataPoints; i++ {
		if g.gpuTemp[i] > 70 {
			g.gpuFanSpeed[i] = clampInt(rng.IntN(15)+5, 0, 100)
		} else {
			g.gpuFanSpeed[i] = 0
		}
	}

	// SM clock (varies with P-state, correlated with utilization)
	for i := 0; i < numDataPoints; i++ {
		utilPct := float64(g.gpuUtil[i]) / 100.0
		// Higher utilization -> closer to base clock; idle -> throttled
		clockPct := 0.6 + utilPct*0.4
		g.gpuClockSM[i] = int(float64(p.GPUClockSMBase) * clockPct)
	}

	// Memory clock (relatively stable at full speed under load)
	for i := 0; i < numDataPoints; i++ {
		utilPct := float64(g.gpuUtil[i]) / 100.0
		clockPct := 0.7 + utilPct*0.3
		g.gpuClockMem[i] = int(float64(p.GPUClockMemBase) * clockPct)
	}

	return g
}

// GPU metric getter methods on MetricsCycler. p is the point the request
// serves, read once per request (nl6#975).

func (c *MetricsCycler) GetGPUUtil(gpuIndex, p int) string {
	if gpuIndex < 0 || gpuIndex >= len(c.gpuMetrics) {
		return "0"
	}
	return fmt.Sprintf("%d", c.gpuMetrics[gpuIndex].gpuUtil[p])
}

func (c *MetricsCycler) GetGPUMemUsed(gpuIndex, p int) string {
	if gpuIndex < 0 || gpuIndex >= len(c.gpuMetrics) {
		return "0"
	}
	return fmt.Sprintf("%d", c.gpuMetrics[gpuIndex].gpuMemUsed[p])
}

func (c *MetricsCycler) GetGPUMemTotal(gpuIndex int) string {
	if gpuIndex < 0 || gpuIndex >= len(c.gpuMetrics) {
		return "0"
	}
	return fmt.Sprintf("%d", c.gpuMetrics[gpuIndex].gpuMemTotal)
}

func (c *MetricsCycler) GetGPUTemp(gpuIndex, p int) string {
	if gpuIndex < 0 || gpuIndex >= len(c.gpuMetrics) {
		return "0"
	}
	return fmt.Sprintf("%d", c.gpuMetrics[gpuIndex].gpuTemp[p])
}

func (c *MetricsCycler) GetGPUPower(gpuIndex, p int) string {
	if gpuIndex < 0 || gpuIndex >= len(c.gpuMetrics) {
		return "0"
	}
	return fmt.Sprintf("%d", c.gpuMetrics[gpuIndex].gpuPower[p])
}

func (c *MetricsCycler) GetGPUFanSpeed(gpuIndex, p int) string {
	if gpuIndex < 0 || gpuIndex >= len(c.gpuMetrics) {
		return "0"
	}
	return fmt.Sprintf("%d", c.gpuMetrics[gpuIndex].gpuFanSpeed[p])
}

func (c *MetricsCycler) GetGPUClockSM(gpuIndex, p int) string {
	if gpuIndex < 0 || gpuIndex >= len(c.gpuMetrics) {
		return "0"
	}
	return fmt.Sprintf("%d", c.gpuMetrics[gpuIndex].gpuClockSM[p])
}

func (c *MetricsCycler) GetGPUClockMem(gpuIndex, p int) string {
	if gpuIndex < 0 || gpuIndex >= len(c.gpuMetrics) {
		return "0"
	}
	return fmt.Sprintf("%d", c.gpuMetrics[gpuIndex].gpuClockMem[p])
}

// parseGPUIndexFromOID extracts the GPU index from the last component of an NVIDIA OID.
// OID format: 1.3.6.1.4.1.5703.1.1.1.1.{metric}.{gpuIndex} (nvidiaGPUMetricPrefix)
func parseGPUIndexFromOID(oid string) int {
	parts := strings.Split(oid, ".")
	if len(parts) == 0 {
		return 0
	}
	idx, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return 0
	}
	return idx
}
