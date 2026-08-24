/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"log"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"
)

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

	// Ephemeral source port range (inclusive). Shipped profiles floor this
	// at 49152 (IANA dynamic/private range) so a random source port can
	// never match a registered-port application-classification rule on a
	// downstream collector (scenario-app-traffic ground-truth contract).
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
	SrcPortMin:      49152,
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
	SrcPortMin:      49152,
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
	SrcPortMin:      49152,
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
	SrcPortMin:      49152,
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
	SrcPortMin:      49152,
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
	SrcPortMin:      49152,
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
	SrcPortMin:      49152,
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
	SrcPortMin:      49152,
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
	"juniper_mx240.json": flowProfileEdgeRouter,
	"nec_ix3315.json":    flowProfileEdgeRouter,
	"cisco_ios.json":     flowProfileEdgeRouter,
	"huawei_ne8000.json": flowProfileEdgeRouter,

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

// flowIncapableTypes lists device types that natively export no flow
// records at all, so nl6 must not either.
//
// This exists because absence has to be *implemented*, not merely
// omitted: GetFlowProfile falls back to flowProfileEdgeRouter for any
// unmapped type, so simply leaving a device out of flowProfileMap would
// hand it edge-router flow ground truth. For a layer-1 optical transport
// platform — which performs no layer-3/4 inspection and cannot observe
// flows — that would emit plausible but entirely fictional NetFlow, and
// a monitoring team could build on data that never appears in
// production.
//
// Callers MUST consult SupportsFlowExport before attaching a flow
// exporter; GetFlowProfile deliberately keeps its non-nil contract so
// existing call sites cannot nil-panic.
var flowIncapableTypes = map[string]struct{}{
	"ciena_waveserver5.json": {},
}

// SupportsFlowExport reports whether a device type natively exports flow
// records. False for layer-1 transport platforms.
func SupportsFlowExport(resourceFile string) bool {
	_, incapable := flowIncapableTypes[resourceFile]
	return !incapable
}

// roundRobinTypesForCategory resolves the device types a round-robin
// batch will actually draw from, mirroring the filter in
// CreateDevicesWithOptions — including its "empty filter means no filter"
// fallback. Kept next to SupportsFlowExport because the flow-capability
// check is its only caller today; if the filter logic in device.go
// changes, this must change with it.
func roundRobinTypesForCategory(category string) []string {
	if category == "" {
		return RoundRobinDeviceTypes
	}
	var filtered []string
	for _, rrFile := range RoundRobinDeviceTypes {
		if getDeviceCategoryFromName(strings.TrimSuffix(rrFile, ".json")) == category {
			filtered = append(filtered, rrFile)
		}
	}
	if len(filtered) == 0 {
		// device.go falls back to the unfiltered list in this case.
		return RoundRobinDeviceTypes
	}
	return filtered
}

// flowIncapableRequest reports whether a device-creation request asks for
// flow export on a set of device types that can never provide it. It
// returns the offending resource file so the caller can name it.
//
// Only a request whose *entire* resolved type set is flow-incapable is
// rejected: a mixed round-robin batch is legitimate, since the capable
// devices export and the rest are skipped.
func flowIncapableRequest(req CreateDevicesRequest) (string, bool) {
	if req.ResourceFile != "" {
		if !SupportsFlowExport(req.ResourceFile) {
			return req.ResourceFile, true
		}
		return "", false
	}
	if !req.RoundRobin {
		return "", false
	}
	types := roundRobinTypesForCategory(req.Category)
	for _, rf := range types {
		if SupportsFlowExport(rf) {
			return "", false // at least one type can export — allow the batch
		}
	}
	if len(types) == 0 {
		return "", false
	}
	return types[0], true
}

// opticalIncapableRequest is the inverse-capability mirror of
// flowIncapableRequest, for `optical_scenario`. It reports whether a
// device-creation request asks for an optical health band on a set of
// device types that carry no coherent-optical inventory, returning the
// offending resource file so the caller can name it.
//
// The asymmetry it removes: InitOpticalCycler no-ops without OCH
// inventory, so without this check a request pairing `cisco_ios` with
// `optical_scenario: failing` returns 201 and then echoes `failing` back
// on GET /api/v1/devices for a device where the band does nothing —
// exactly the "plausible but fictional telemetry" failure the flow
// capability check exists to prevent, in the opposite direction.
//
// Same shape as the flow rule for the same reasons: only a request whose
// ENTIRE resolved type set is optically incapable is rejected, so a mixed
// round-robin batch stays usable (the optical devices get the band, the
// rest ignore it), and clean is always allowed since it is the default
// every device already has.
func opticalIncapableRequest(req CreateDevicesRequest, scenario OpticalScenario) (string, bool) {
	if scenario == OpticalClean {
		return "", false
	}
	if req.ResourceFile != "" {
		if !IsOpticalDeviceType(req.ResourceFile) {
			return req.ResourceFile, true
		}
		return "", false
	}
	if !req.RoundRobin {
		return "", false
	}
	types := roundRobinTypesForCategory(req.Category)
	for _, rf := range types {
		if IsOpticalDeviceType(rf) {
			return "", false // at least one type carries OCH inventory
		}
	}
	if len(types) == 0 {
		return "", false
	}
	return types[0], true
}

// opticalScenarioFieldFor returns the value to store in
// DeviceSimulator.OpticalScenario — the canonicalised scenario for a type
// with optical channels, and the empty string for every other type.
//
// Empty rather than "clean" because the field is `omitempty`: surfacing
// `optical_scenario: clean` on the 28 device types that have no OCH
// inventory would advertise a knob that does nothing there. A packet
// switch does not have a coherent-optical health band, and saying it has
// a clean one is a claim about hardware that does not exist.
//
// Both device-creation paths call this, so they cannot disagree about what
// GET /api/v1/devices reports.
func opticalScenarioFieldFor(resourceFile string, scenario OpticalScenario) string {
	if !IsOpticalDeviceType(resourceFile) {
		return ""
	}
	return string(scenario)
}

// GetFlowProfile returns the FlowProfile for the given resource file name.
// Falls back to flowProfileEdgeRouter if the file is not in the map.
//
// A non-nil result does NOT mean the device type should export flow —
// check SupportsFlowExport first. The fallback is a convenience for
// mapped-but-unlisted packet types, not a capability assertion.
func GetFlowProfile(resourceFile string) *FlowProfile {
	if p, ok := flowProfileMap[resourceFile]; ok {
		return p
	}
	// Reachable only for OPERATOR-SUPPLIED resource files dropped into the
	// resources directory at runtime — for repo types the completeness test
	// (TestFlowCapabilityCompleteness) guarantees a map hit or an explicit
	// incapable listing. The maps are compiled in, so a custom type cannot
	// declare its flow story; edge-router ground truth is the least-wrong
	// default, but the choice must be visible rather than silent (#364).
	if _, seen := flowFallbackLogged.LoadOrStore(resourceFile, struct{}{}); !seen {
		log.Printf("flow: device type %q is not in flowProfileMap; using the edge-router "+
			"flow profile as ground truth (custom type? see issue #364)", resourceFile)
	}
	return flowProfileEdgeRouter
}

// flowFallbackLogged gates the fallback warning to once per type per process.
var flowFallbackLogged sync.Map

// MeanFlowLifetime is the expected time a synthetic flow stays cached before it
// is exported: E[min(active, D + inactive)] where D is the profile's sampled
// duration. It is the constant relating cache population to export rate,
//
//	records/s  ~=  ConcurrentFlows / MeanFlowLifetime
//
// which is what lets a scenario pace a device by sizing its cache.
//
// Computed from the profile rather than assumed: the shipped profiles' duration
// ranges span 50ms to 600s, so a single hardcoded value would be right for one
// of them and wrong for the other seven. Measured against the emission engine
// across all eight, the identity holds to within 4.3% (worst case), and across
// cache sizes from 4 to 256 to within 0.2%.
//
// D is uniform on [DurationMinMs, DurationMaxMs], so D+inactive is uniform on
// [a+I, b+I] and the expectation of its min with `active` is piecewise closed
// form.
func MeanFlowLifetime(p *FlowProfile, active, inactive time.Duration) time.Duration {
	a := float64(p.DurationMinMs) / 1000
	b := float64(p.DurationMaxMs) / 1000
	act := active.Seconds()
	inact := inactive.Seconds()
	lo, hi := a+inact, b+inact

	var mean float64
	switch {
	case hi <= lo: // degenerate duration range: D is a point mass
		mean = math.Min(act, lo)
	case act <= lo: // the cap always binds first
		mean = act
	case act >= hi: // the cap never binds
		mean = (a+b)/2 + inact
	default: // split at act
		mean = ((act*act-lo*lo)/2 + act*(hi-act)) / (hi - lo)
	}
	if mean <= 0 {
		return 0
	}
	return time.Duration(mean * float64(time.Second))
}
