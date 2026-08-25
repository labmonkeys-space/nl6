/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"math/rand"
	"net"
	"sync"
	"time"
)

// FlowKey is the 5-tuple that uniquely identifies a flow in the cache.
// Using a fixed-size array type (not slices) allows it to be a map key.
type FlowKey struct {
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// FlowRecord is the canonical in-memory representation of a single flow.
// It maps 1:1 to the NetFlow v9 / IPFIX template fields used by this
// simulator, except flowDirection(61), which the encoders emit as a constant
// (ingress). All byte/packet counts are cumulative for the flow lifetime.
type FlowRecord struct {
	SrcIP    net.IP
	DstIP    net.IP
	NextHop  net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	TCPFlags uint8
	ToS      uint8
	Bytes    uint64
	Packets  uint32
	StartMs  uint32 // ms since device uptime epoch (SysUptime at flow start)
	EndMs    uint32 // ms since device uptime epoch (SysUptime at last packet)
	InIface  uint16 // SNMP ifIndex of ingress interface
	OutIface uint16 // SNMP ifIndex of egress interface
	SrcAS    uint16
	DstAS    uint16
	SrcMask  uint8
	DstMask  uint8
}

// flowEntry wraps a FlowRecord with metadata used by the aging engine.
type flowEntry struct {
	record     FlowRecord
	lastSeenAt time.Time
	// activeDeadline is when this flow hits the active timeout: its creation
	// instant plus the configured timeout plus a per-flow jitter.
	//
	// It is stored rather than derived, and the entry no longer keeps its
	// creation time at all, because the whole
	// point is that it is NOT a fixed offset. A deterministic deadline makes
	// expiry a pure delay of creation, and since creation refills exactly what
	// expired, the creation profile is then replayed every timeout period
	// forever with nothing to damp it.
	activeDeadline time.Time
}

// FlowCache maintains the set of active synthetic flows for a single device.
//
// Flows are inserted via GenerateFlows (the only production path) and aged out
// by Expire. Add is retained for direct insertion and is currently exercised
// only by tests. Callers should call
// GenerateFlows periodically to keep the cache at the target concurrency level,
// then call Expire to harvest records ready for export.
//
// All public methods are safe for concurrent use.
type FlowCache struct {
	flows           map[FlowKey]*flowEntry
	activeTimeout   time.Duration
	inactiveTimeout time.Duration
	maxFlows        int
	// expiredActive / expiredInactive tally which timeout retired each flow.
	// Totals alone cannot show that both paths are live — before nl6#446 the
	// active path was unreachable and the totals still looked healthy.
	expiredActive   uint64
	expiredInactive uint64
	// warmed records whether the first fill has happened. That fill starts the
	// cache COLD — every flow created at one instant — and the active timeout
	// is a fixed offset from creation, so the whole cohort would then expire on
	// one tick and keep doing so forever. Sampled durations alone do not fix
	// it: they stagger only the minority of flows that leave by the inactive
	// timeout. See warmStartOffset.
	warmed bool
	// activeJitterFraction defaults to flowActiveJitterFraction. It is a field
	// rather than a direct read of the constant so a test can construct an
	// UNDAMPED cache and measure the echo it is supposed to remove — the
	// damping assertion is relative to that baseline, not to a threshold
	// someone would later tune to fit.
	activeJitterFraction float64
	mu                   sync.Mutex
}

// NewFlowCache creates a FlowCache with the given timeout values and maximum
// number of concurrent flows.
func NewFlowCache(activeTimeout, inactiveTimeout time.Duration, maxFlows int) *FlowCache {
	return &FlowCache{
		flows:                make(map[FlowKey]*flowEntry),
		activeTimeout:        activeTimeout,
		activeJitterFraction: flowActiveJitterFraction,
		inactiveTimeout:      inactiveTimeout,
		maxFlows:             maxFlows,
	}
}

// Add inserts r into the cache or accumulates bytes/packets into an existing
// entry. New entries are silently dropped when the cache is at capacity,
// mirroring real router behaviour under high flow load.
//
// NOTE ON lastSeenAt, because this deliberately differs from GenerateFlows and
// the difference looks like the nl6#446 defect at a glance.
//
// Add is a PACKET-ARRIVAL api: `now` IS the moment of the flow's latest packet,
// so `lastSeenAt = now` is correct, and a caller that keeps calling Add keeps
// the flow alive until the active timeout caps it. GenerateFlows is not that —
// it synthesises an entire flow in one call from a duration the profile
// sampled, so its last packet lies in the FUTURE and pinning lastSeenAt to the
// creation instant made every synthetic flow look idle from birth. That was
// nl6#446; it is not a defect here.
//
// A review of nl6#446 proposed "fixing" this the same way. Making the change
// breaks TestFlowCache_InactiveTimeout and TestFlowCache_InactiveReset, which
// pin exactly the contract above — the inactive timer must reset on a fresh
// packet. Those tests are the specification; do not reconcile the two paths.
//
// Add has no production caller today (GenerateFlows is the only insertion path
// used by FlowExporter). It is retained as the ingest seam and exercised by
// tests.
func (fc *FlowCache) Add(r FlowRecord, now time.Time) {
	key := recordKey(r)
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if e, ok := fc.flows[key]; ok {
		// Accumulate into existing flow.
		e.record.Bytes += r.Bytes
		e.record.Packets += r.Packets
		e.record.TCPFlags |= r.TCPFlags
		e.record.EndMs = r.EndMs
		e.lastSeenAt = now
		return
	}
	if len(fc.flows) >= fc.maxFlows {
		return // cache full — drop silently
	}
	fc.flows[key] = &flowEntry{
		record:     r,
		lastSeenAt: now,
		// No jitter on the ingest path: jitter exists to break the
		// expiry-drives-creation loop, and a caller feeding Add drives creation
		// itself. Its arrivals already carry whatever variance its traffic has.
		activeDeadline: now.Add(fc.activeTimeout),
	}
}

// Expire removes and returns all flows that have crossed either the active or
// inactive timeout boundary. The returned records are ready for export.
func (fc *FlowCache) Expire(now time.Time) []FlowRecord {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	var expired []FlowRecord
	for key, e := range fc.flows {
		byActive := !now.Before(e.activeDeadline)
		byInactive := now.Sub(e.lastSeenAt) >= fc.inactiveTimeout
		if !byActive && !byInactive {
			continue
		}
		// Attribute to the active timeout when both apply: a flow still within
		// its modelled duration is capped, not idle.
		if byActive {
			fc.expiredActive++
		} else {
			fc.expiredInactive++
		}
		expired = append(expired, e.record)
		delete(fc.flows, key)
	}
	return expired
}

// ExpiryReasons returns cumulative counts of flows retired by the active and
// inactive timeouts. Exposed so a test can assert that BOTH paths are live;
// a total record count cannot distinguish a healthy split from a collapsed
// model where only one timeout can ever fire.
func (fc *FlowCache) ExpiryReasons() (active, inactive uint64) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.expiredActive, fc.expiredInactive
}

// TrimTo drops flows until the cache holds at most target, and reports how many
// it dropped. Called BEFORE Expire on each tick, so a cache being resized
// downward converges in one tick instead of draining over a flow lifetime.
//
// Ordering matters. Trimming AFTER Expire lets the surplus population have one
// last harvest: measured at rate 0.5 from a warm cache, that single tick put
// the run 47% over its target across a 60s window, because ~22 flows of the old
// 128 came due before the trim reached them. Trimming first drops them unsent.
//
// Dropping is accounting-safe: a flow is counted only when EXPORTED, so a
// trimmed flow has never reached a ledger, a wire, or a collector.
//
// Eviction follows map-iteration order, deliberately NOT age. Evicting newest
// first would leave a uniformly OLD survivor set that expires within a short
// span — re-creating the synchronised cohort burst nl6#446 removed. Arbitrary
// eviction preserves the age spread that keeps emission continuous.
func (fc *FlowCache) TrimTo(target int) int {
	if target < 0 {
		target = 0
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	dropped := 0
	for key := range fc.flows {
		if len(fc.flows) <= target {
			break
		}
		delete(fc.flows, key)
		dropped++
	}
	return dropped
}

// Len returns the current number of active flows in the cache.
func (fc *FlowCache) Len() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return len(fc.flows)
}

// GenerateFlows synthesises new FlowRecords from profile and adds them until
// the cache reaches `target`. startUptimeMs is the device's current uptime in
// milliseconds, used to anchor flow start/end timestamps.
//
// GenerateFlows takes the target population EXPLICITLY rather than reading
// profile.ConcurrentFlows. FlowProfile values are shared package-level pointers
// held by every exporter of a device type, so a caller that wanted a different
// population for ONE device and set it on the profile would change it for the
// whole fleet. Passing the target makes that mistake impossible to express
// here: the only way to vary it is per call site, which is per exporter.
func (fc *FlowCache) GenerateFlows(profile *FlowProfile, target int, deviceIP net.IP, rng *rand.Rand, now time.Time, startUptimeMs uint32) {
	fc.mu.Lock()
	need := target - len(fc.flows)
	fc.mu.Unlock()
	if need <= 0 {
		return
	}

	// Generate synthetic records outside the lock (pure CPU, no shared state).
	//
	// The active-timeout jitter is drawn HERE, one per record, alongside the
	// record itself — unconditionally, before anything can skip it. Drawing it
	// later (only for flows that will take the active branch, say) would make
	// the number of RNG draws depend on the flow, desynchronising the stream and
	// changing every subsequent flow on this device. A seeded run has to
	// reproduce exactly: scenario ground truth reconciles against it.
	batch := make([]FlowRecord, need)
	jitters := make([]time.Duration, need)
	for i := range batch {
		batch[i] = syntheticFlow(profile, deviceIP, rng, startUptimeMs)
		jitters[i] = activeTimeoutJitter(fc.activeTimeout, fc.activeJitterFraction, rng)
	}

	// Insert the whole batch under a single lock acquisition to avoid TOCTOU
	// between the need-check and the individual Add calls.
	fc.mu.Lock()
	defer fc.mu.Unlock()
	// Mark warmed AFTER this batch: only the first fill is backdated.
	defer func() { fc.warmed = true }()
	for i, r := range batch {
		if len(fc.flows) >= fc.maxFlows {
			break
		}
		key := recordKey(r)
		if _, ok := fc.flows[key]; !ok {
			deadline := fc.activeTimeout + jitters[i]
			createdAt := now
			if !fc.warmed {
				// Offset drawn from this flow's OWN lifetime, which now includes
				// its jitter — otherwise a flow whose jitter shortened its
				// deadline could be born already expired.
				createdAt = now.Add(-fc.warmStartOffset(r, deadline, rng))
			}
			// lastSeenAt is the time of the flow's LAST PACKET, which for a
			// synthetic flow is its creation plus the duration the profile
			// already sampled (carried on the record as EndMs-StartMs). It is
			// normally in the FUTURE, and that is the point: the inactive
			// timeout must not start counting until the flow has actually
			// stopped sending.
			//
			// Setting it to `now` — as this did before — made every flow look
			// idle from birth. Expiry then collapsed to
			// min(active, inactive), the active timeout became unreachable
			// under the shipped defaults, and because a refill creates its
			// whole batch at one instant the entire cache expired on a single
			// tick, producing a burst-then-silence sawtooth no real exporter
			// emits.
			//
			// With the modelled end, expiry falls out of the UNCHANGED
			// condition in Expire as min(active, duration+inactive): a flow
			// still running at the cap leaves by the active timeout, one that
			// ended and went idle leaves by the inactive one. Independently
			// sampled durations also stagger the cohort for free.
			fc.flows[key] = &flowEntry{
				record:         r,
				lastSeenAt:     createdAt.Add(recordDuration(r)),
				activeDeadline: createdAt.Add(deadline),
			}
		}
	}
}

// warmStartOffset returns how far into its own life a flow should already be at
// the first fill, so the cache starts as a running router's would: holding
// flows of every age rather than a cohort born together.
//
// The offset is drawn from the flow's OWN lifetime — min(active, duration +
// inactive) — rather than from the active timeout, so a warm flow can never be
// born already expired and produce a spurious burst on the first tick.
//
// Only the first fill needs this. Afterwards expiries are spread, so each tick
// refills a few flows at its own instant and the spread sustains itself.
func (fc *FlowCache) warmStartOffset(r FlowRecord, activeDeadline time.Duration, rng *rand.Rand) time.Duration {
	lifetime := recordDuration(r) + fc.inactiveTimeout
	if activeDeadline < lifetime {
		lifetime = activeDeadline
	}
	if lifetime <= 0 {
		return 0
	}
	return time.Duration(rng.Int63n(int64(lifetime)))
}

// flowActiveJitterFraction is the half-width of the active-timeout jitter, as a
// fraction of the timeout: a 30 s timeout yields deadlines spread over
// [22.5 s, 37.5 s].
//
// 0.25 is the SMALLEST swept value that brings the one-lifetime emission
// autocorrelation below 0.25 on every shipped profile. Measured on a re-pacing
// disturbance (edge / GPU / campus), r at one lifetime:
//
//	fraction   0.00   0.10   0.15   0.20   0.25   0.30
//	edge      +0.87  +0.51  +0.50  +0.37  +0.23  +0.06
//	gpu       +0.96  +0.50  +0.45  +0.26  +0.17  +0.07
//	campus    +0.54  +0.24  +0.26  +0.23  +0.20  +0.08
//
// Below 0.20 the echo is halved but plainly still there. Above it the returns
// are small and the cost is not: the jitter is a spread on a user-facing
// timeout, and at 0.50 the deadline lands anywhere in [15 s, 45 s], which
// empties `-flow-active-timeout` of meaning and drives the correlation
// NEGATIVE (-0.12 on edge) — an artifact of its own, not a quieter emitter.
//
// TestFlowEmission_EchoIsDamped asserts the property this value buys, relative
// to an undamped baseline it computes itself, so the number is not load-bearing
// for the test passing.
const flowActiveJitterFraction = 0.25

// activeTimeoutJitter returns a zero-mean offset to apply to one flow's active
// deadline, uniform on ±flowActiveJitterFraction of the timeout.
//
// Zero-mean in the DEADLINE. That is not the same as zero-mean in the lifetime:
// a flow's lifetime is min(deadline, duration+inactive), and a minimum is
// concave, so symmetric jitter lowers the expectation. MeanFlowLifetime is what
// scenario pacing calibrates against, so the size of that shift is measured
// rather than assumed.
func activeTimeoutJitter(active time.Duration, fraction float64, rng *rand.Rand) time.Duration {
	if active <= 0 || fraction <= 0 {
		return 0
	}
	span := float64(active) * fraction
	return time.Duration((rng.Float64()*2 - 1) * span)
}

// recordDuration is the flow's modelled lifetime, taken from the uptime-
// relative timestamps the profile already sampled. Clamped at zero so a record
// whose EndMs wrapped (the ~49-day uptime guard in syntheticFlow) cannot
// produce a lastSeenAt before createdAt and expire the flow instantly.
func recordDuration(r FlowRecord) time.Duration {
	if r.EndMs <= r.StartMs {
		return 0
	}
	return time.Duration(r.EndMs-r.StartMs) * time.Millisecond
}

// recordKey derives a FlowKey from a FlowRecord's 5-tuple.
func recordKey(r FlowRecord) FlowKey {
	var k FlowKey
	if ip4 := r.SrcIP.To4(); ip4 != nil {
		copy(k.SrcIP[:], ip4)
	}
	if ip4 := r.DstIP.To4(); ip4 != nil {
		copy(k.DstIP[:], ip4)
	}
	k.SrcPort = r.SrcPort
	k.DstPort = r.DstPort
	k.Protocol = r.Protocol
	return k
}

// syntheticFlow constructs a single realistic FlowRecord for the given device.
// Destination IPs are drawn from the 10.0.0.0/8 range; source IP is always
// the device's own address (as a router or server would appear in exports).
func syntheticFlow(profile *FlowProfile, deviceIP net.IP, rng *rand.Rand, startUptimeMs uint32) FlowRecord {
	proto := profile.SampleProtocol(rng)
	dstPort := profile.SampleDstPort(rng)

	var srcPort uint16
	spread := int(profile.SrcPortMax) - int(profile.SrcPortMin)
	if spread > 0 {
		srcPort = profile.SrcPortMin + uint16(rng.Intn(spread))
	} else {
		srcPort = profile.SrcPortMin
	}
	// ICMP has no transport ports; real exporters carry 0 (or type/code)
	// in the port fields, never a sampled service port. Zeroing both keeps
	// the wire honest and the per-application ground truth free of
	// fabricated (icmp, 443)-style rows. rng draws above are kept so the
	// per-protocol rng stream stays aligned across protocols for a seed.
	if proto == 1 {
		srcPort, dstPort = 0, 0
	}

	// Random destination in 10.0.0.1–10.255.255.254 (exclude network/broadcast).
	var dstRaw [4]byte
	binary.BigEndian.PutUint32(dstRaw[:], 0x0A000000|uint32(rng.Intn(0x00FFFFFE)+1))
	dstIP := net.IP(append([]byte{}, dstRaw[:]...))

	durationMs := uint32(profile.SampleDurationMs(rng))
	endMs := startUptimeMs + durationMs
	if endMs < startUptimeMs { // uint32 overflow guard (~49-day uptime wrap)
		endMs = startUptimeMs
	}

	var tcpFlags uint8
	if proto == 6 {
		tcpFlags = 0x18 // ACK + PSH — normal established-session data
	}

	bytes := profile.SampleBytes(rng)
	if bytes < 0 {
		bytes = 0
	}
	pkts := profile.SamplePkts(rng)
	if pkts < 0 {
		pkts = 0
	}

	return FlowRecord{
		SrcIP:    deviceIP.To4(),
		DstIP:    dstIP,
		NextHop:  net.IPv4(0, 0, 0, 0).To4(),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: proto,
		TCPFlags: tcpFlags,
		ToS:      0,
		Bytes:    uint64(bytes),
		Packets:  uint32(pkts),
		StartMs:  startUptimeMs,
		EndMs:    endMs,
		InIface:  1,
		OutIface: 2,
		SrcAS:    0,
		DstAS:    0,
		SrcMask:  24,
		DstMask:  24,
	}
}
