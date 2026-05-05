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
// It maps 1:1 to the 18 fields in the NetFlow v9 / IPFIX template used by
// this simulator. All byte/packet counts are cumulative for the flow lifetime.
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
// Flows are inserted via Add and aged out by Expire. Callers should call
// GenerateFlows periodically to keep the cache at the target concurrency level,
// then call Expire to harvest records ready for export.
//
// All public methods are safe for concurrent use.
type FlowCache struct {
	flows           map[FlowKey]*flowEntry
	activeTimeout   time.Duration
	inactiveTimeout time.Duration
	maxFlows        int
	mu              sync.Mutex
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
		if now.Sub(e.createdAt) >= fc.activeTimeout ||
			now.Sub(e.lastSeenAt) >= fc.inactiveTimeout {
			expired = append(expired, e.record)
			delete(fc.flows, key)
		}
	}
	return expired
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
	for _, r := range batch {
		if len(fc.flows) >= fc.maxFlows {
			break
		}
		key := recordKey(r)
		if _, ok := fc.flows[key]; !ok {
			fc.flows[key] = &flowEntry{record: r, createdAt: now, lastSeenAt: now}
		}
	}
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
