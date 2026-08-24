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
	createdAt  time.Time
	lastSeenAt time.Time
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
	mu     sync.Mutex
}

// NewFlowCache creates a FlowCache with the given timeout values and maximum
// number of concurrent flows.
func NewFlowCache(activeTimeout, inactiveTimeout time.Duration, maxFlows int) *FlowCache {
	return &FlowCache{
		flows:           make(map[FlowKey]*flowEntry),
		activeTimeout:   activeTimeout,
		inactiveTimeout: inactiveTimeout,
		maxFlows:        maxFlows,
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
		createdAt:  now,
		lastSeenAt: now,
	}
}

// Expire removes and returns all flows that have crossed either the active or
// inactive timeout boundary. The returned records are ready for export.
func (fc *FlowCache) Expire(now time.Time) []FlowRecord {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	var expired []FlowRecord
	for key, e := range fc.flows {
		byActive := now.Sub(e.createdAt) >= fc.activeTimeout
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

// Len returns the current number of active flows in the cache.
func (fc *FlowCache) Len() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return len(fc.flows)
}

// GenerateFlows synthesises new FlowRecords from profile and adds them until
// the cache reaches profile.ConcurrentFlows. startUptimeMs is the device's
// current uptime in milliseconds, used to anchor flow start/end timestamps.
func (fc *FlowCache) GenerateFlows(profile *FlowProfile, deviceIP net.IP, rng *rand.Rand, now time.Time, startUptimeMs uint32) {
	fc.mu.Lock()
	need := profile.ConcurrentFlows - len(fc.flows)
	fc.mu.Unlock()
	if need <= 0 {
		return
	}

	// Generate synthetic records outside the lock (pure CPU, no shared state).
	batch := make([]FlowRecord, need)
	for i := range batch {
		batch[i] = syntheticFlow(profile, deviceIP, rng, startUptimeMs)
	}

	// Insert the whole batch under a single lock acquisition to avoid TOCTOU
	// between the need-check and the individual Add calls.
	fc.mu.Lock()
	defer fc.mu.Unlock()
	// Mark warmed AFTER this batch: only the first fill is backdated.
	defer func() { fc.warmed = true }()
	for _, r := range batch {
		if len(fc.flows) >= fc.maxFlows {
			break
		}
		key := recordKey(r)
		if _, ok := fc.flows[key]; !ok {
			createdAt := now
			if !fc.warmed {
				createdAt = now.Add(-fc.warmStartOffset(r, rng))
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
				record:     r,
				createdAt:  createdAt,
				lastSeenAt: createdAt.Add(recordDuration(r)),
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
func (fc *FlowCache) warmStartOffset(r FlowRecord, rng *rand.Rand) time.Duration {
	lifetime := recordDuration(r) + fc.inactiveTimeout
	if fc.activeTimeout < lifetime {
		lifetime = fc.activeTimeout
	}
	if lifetime <= 0 {
		return 0
	}
	return time.Duration(rng.Int63n(int64(lifetime)))
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
