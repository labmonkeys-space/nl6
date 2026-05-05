/*
 * © 2025 Labmonkeys Space
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

import "math/rand"

// FlowProfile defines synthetic traffic characteristics for a device category.
// It drives 5-tuple generation (src/dst IP, src/dst port, protocol) and the
// byte/packet sizing of FlowRecord entries produced by FlowCache.GenerateFlows.
type FlowProfile struct {
	// Protocol distribution — values must sum to 1.0.
	TCPWeight  float64
	UDPWeight  float64
	ICMPWeight float64

	// Destination port distribution (TCP/UDP). Weights must sum to 1.0.
	DstPorts []PortWeight

	// Ephemeral source port range (inclusive).
	SrcPortMin uint16
	SrcPortMax uint16

	// Bytes per flow — sampled uniformly from [BytesMin, BytesMax).
	BytesMin int64
	BytesMax int64

	// Packets per flow — sampled uniformly from [PktsMin, PktsMax).
	PktsMin int32
	PktsMax int32

	// Flow duration in milliseconds — sampled uniformly from [DurationMinMs, DurationMaxMs).
	DurationMinMs int64
	DurationMaxMs int64

	// Target number of concurrently active flows for this device.
	ConcurrentFlows int

	// Hard cap on active flows in the cache (mirrors real router behaviour).
	MaxFlows int
}

// PortWeight pairs a destination port number with a sampling weight.
type PortWeight struct {
	Port   uint16
	Weight float64
}

// SampleProtocol returns 6 (TCP), 17 (UDP), or 1 (ICMP) based on the
// profile's distribution, using r as the random source.
func (fp *FlowProfile) SampleProtocol(r *rand.Rand) uint8 {
	v := r.Float64()
	if v < fp.TCPWeight {
		return 6
	}
	if v < fp.TCPWeight+fp.UDPWeight {
		return 17
	}
	return 1
}

// SampleDstPort returns a destination port sampled from DstPorts.
// Falls back to 443 if the distribution is empty.
func (fp *FlowProfile) SampleDstPort(r *rand.Rand) uint16 {
	if len(fp.DstPorts) == 0 {
		return 443
	}
	v := r.Float64()
	cumulative := 0.0
	for _, pw := range fp.DstPorts {
		cumulative += pw.Weight
		if v < cumulative {
			return pw.Port
		}
	}
	return fp.DstPorts[len(fp.DstPorts)-1].Port
}

// SampleBytes returns a byte count sampled uniformly from [BytesMin, BytesMax).
func (fp *FlowProfile) SampleBytes(r *rand.Rand) int64 {
	if fp.BytesMax <= fp.BytesMin {
		return fp.BytesMin
	}
	return fp.BytesMin + r.Int63n(fp.BytesMax-fp.BytesMin)
}

// SamplePkts returns a packet count sampled uniformly from [PktsMin, PktsMax).
func (fp *FlowProfile) SamplePkts(r *rand.Rand) int32 {
	if fp.PktsMax <= fp.PktsMin {
		return fp.PktsMin
	}
	return fp.PktsMin + r.Int31n(fp.PktsMax-fp.PktsMin)
}

// SampleDurationMs returns a flow duration in milliseconds.
func (fp *FlowProfile) SampleDurationMs(r *rand.Rand) int64 {
	if fp.DurationMaxMs <= fp.DurationMinMs {
		return fp.DurationMinMs
	}
	return fp.DurationMinMs + r.Int63n(fp.DurationMaxMs-fp.DurationMinMs)
}

// ---- Per-category profiles ----------------------------------------

var flowProfileCoreRouter = &FlowProfile{
	TCPWeight: 0.65, UDPWeight: 0.30, ICMPWeight: 0.05,
	DstPorts: []PortWeight{
		{443, 0.35}, {80, 0.15}, {179, 0.15}, {53, 0.15}, {22, 0.10}, {8080, 0.10},
	},
	SrcPortMin:      1024,
	SrcPortMax:      65535,
	BytesMin:        512,
	BytesMax:        1_500_000,
	PktsMin:         1,
	PktsMax:         1000,
	DurationMinMs:   500,
	DurationMaxMs:   300_000,
	ConcurrentFlows: 200,
	MaxFlows:        256,
}

var flowProfileEdgeRouter = &FlowProfile{
	TCPWeight: 0.70, UDPWeight: 0.25, ICMPWeight: 0.05,
	DstPorts: []PortWeight{
		{443, 0.50}, {80, 0.20}, {53, 0.15}, {22, 0.10}, {25, 0.05},
	},
	SrcPortMin:      1024,
	SrcPortMax:      65535,
	BytesMin:        256,
	BytesMax:        500_000,
	PktsMin:         1,
	PktsMax:         500,
	DurationMinMs:   200,
	DurationMaxMs:   120_000,
	ConcurrentFlows: 128,
	MaxFlows:        256,
}

var flowProfileDCSwitch = &FlowProfile{
	TCPWeight: 0.80, UDPWeight: 0.18, ICMPWeight: 0.02,
	DstPorts: []PortWeight{
		{3260, 0.30}, {2049, 0.25}, {443, 0.20}, {4789, 0.15}, {445, 0.10},
	},
	SrcPortMin:      1024,
	SrcPortMax:      65535,
	BytesMin:        4_096,
	BytesMax:        10_000_000,
	PktsMin:         4,
	PktsMax:         8000,
	DurationMinMs:   100,
	DurationMaxMs:   60_000,
	ConcurrentFlows: 128,
	MaxFlows:        256,
}

var flowProfileCampusSwitch = &FlowProfile{
	TCPWeight: 0.65, UDPWeight: 0.30, ICMPWeight: 0.05,
	DstPorts: []PortWeight{
		{443, 0.40}, {80, 0.20}, {53, 0.20}, {67, 0.10}, {389, 0.10},
	},
	SrcPortMin:      1024,
	SrcPortMax:      65535,
	BytesMin:        64,
	BytesMax:        300_000,
	PktsMin:         1,
	PktsMax:         300,
	DurationMinMs:   100,
	DurationMaxMs:   30_000,
	ConcurrentFlows: 64,
	MaxFlows:        256,
}

var flowProfileFirewall = &FlowProfile{
	TCPWeight: 0.60, UDPWeight: 0.30, ICMPWeight: 0.10,
	DstPorts: []PortWeight{
		{443, 0.35}, {80, 0.20}, {53, 0.20}, {22, 0.15}, {3389, 0.10},
	},
	SrcPortMin:      1024,
	SrcPortMax:      65535,
	BytesMin:        0, // blocked flows carry 0 bytes
	BytesMax:        200_000,
	PktsMin:         0,
	PktsMax:         200,
	DurationMinMs:   50,
	DurationMaxMs:   60_000,
	ConcurrentFlows: 64,
	MaxFlows:        256,
}

var flowProfileServer = &FlowProfile{
	TCPWeight: 0.85, UDPWeight: 0.13, ICMPWeight: 0.02,
	DstPorts: []PortWeight{
		{443, 0.40}, {22, 0.25}, {161, 0.20}, {80, 0.15},
	},
	SrcPortMin:      1024,
	SrcPortMax:      65535,
	BytesMin:        512,
	BytesMax:        100_000,
	PktsMin:         1,
	PktsMax:         200,
	DurationMinMs:   1_000,
	DurationMaxMs:   60_000,
	ConcurrentFlows: 32,
	MaxFlows:        256,
}

var flowProfileGPUServer = &FlowProfile{
	TCPWeight: 0.30, UDPWeight: 0.68, ICMPWeight: 0.02,
	DstPorts: []PortWeight{
		{4791, 0.60}, {443, 0.20}, {22, 0.10}, {8080, 0.10},
	},
	SrcPortMin:      1024,
	SrcPortMax:      65535,
	BytesMin:        1_000_000,
	BytesMax:        10_000_000_000, // 10 GB — large RDMA/NCCL transfers
	PktsMin:         1000,
	PktsMax:         8_000_000,
	DurationMinMs:   10_000,
	DurationMaxMs:   600_000,
	ConcurrentFlows: 8, // few but very large flows
	MaxFlows:        256,
}

var flowProfileStorage = &FlowProfile{
	TCPWeight: 0.85, UDPWeight: 0.14, ICMPWeight: 0.01,
	DstPorts: []PortWeight{
		{2049, 0.30}, {3260, 0.30}, {443, 0.25}, {445, 0.15},
	},
	SrcPortMin:      1024,
	SrcPortMax:      65535,
	BytesMin:        65_536,
	BytesMax:        5_000_000_000, // 5 GB
	PktsMin:         64,
	PktsMax:         4_000_000,
	DurationMinMs:   5_000,
	DurationMaxMs:   300_000,
	ConcurrentFlows: 32,
	MaxFlows:        256,
}

// flowProfileMap mirrors deviceProfileMap, mapping resource file names to
// their corresponding FlowProfile. Must stay in sync with RoundRobinDeviceTypes.
var flowProfileMap = map[string]*FlowProfile{
	// Core Routers
	"asr9k.json":           flowProfileCoreRouter,
	"cisco_crs_x.json":     flowProfileCoreRouter,
	"nokia_7750_sr12.json": flowProfileCoreRouter,
	"juniper_mx960.json":   flowProfileCoreRouter,

	// Edge Routers
	"juniper_mx240.json":  flowProfileEdgeRouter,
	"nec_ix3315.json":     flowProfileEdgeRouter,
	"cisco_ios.json":      flowProfileEdgeRouter,
	"huawei_ne8000.json":  flowProfileEdgeRouter,

	// Data Center Switches
	"cisco_nexus_9500.json": flowProfileDCSwitch,
	"arista_7280r3.json":    flowProfileDCSwitch,

	// Campus Switches
	"cisco_catalyst_9500.json": flowProfileCampusSwitch,
	"extreme_vsp4450.json":     flowProfileCampusSwitch,
	"dlink_dgs3630.json":       flowProfileCampusSwitch,

	// Firewalls
	"palo_alto_pa3220.json":        flowProfileFirewall,
	"fortinet_fortigate_600e.json": flowProfileFirewall,
	"sonicwall_nsa6700.json":       flowProfileFirewall,
	"check_point_15600.json":       flowProfileFirewall,

	// Servers
	"dell_poweredge_r750.json": flowProfileServer,
	"hpe_proliant_dl380.json":  flowProfileServer,
	"ibm_power_s922.json":      flowProfileServer,
	"linux_server.json":        flowProfileServer,

	// GPU Servers
	"nvidia_dgx_a100.json": flowProfileGPUServer,
	"nvidia_dgx_h100.json": flowProfileGPUServer,
	"nvidia_hgx_h200.json": flowProfileGPUServer,

	// Storage Systems
	"netapp_ontap.json":            flowProfileStorage,
	"pure_storage_flasharray.json": flowProfileStorage,
	"dell_emc_unity.json":          flowProfileStorage,
	"aws_s3_storage.json":          flowProfileStorage,
}

// GetFlowProfile returns the FlowProfile for the given resource file name.
// Falls back to flowProfileEdgeRouter if the file is not in the map.
func GetFlowProfile(resourceFile string) *FlowProfile {
	if p, ok := flowProfileMap[resourceFile]; ok {
		return p
	}
	return flowProfileEdgeRouter
}
