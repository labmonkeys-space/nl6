/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FlowEncoder is the protocol-agnostic interface satisfied by the NetFlow v5,
// NetFlow v9, IPFIX, and sFlow encoders. uptimeMs is the device uptime in
// milliseconds at export time; IPFIX encoders may use it to compute absolute
// timestamps.
type FlowEncoder interface {
	EncodePacket(domainID uint32, seqNo uint32, uptimeMs uint32,
		records []FlowRecord, includeTemplate bool, buf []byte) (int, error)
	// PacketSizes returns the three per-packet size constants that Tick() needs
	// to compute batch capacity correctly for fixed-size record protocols:
	//   baseOverhead — message/packet header + data-set/flowset header (bytes)
	//   templateSize — template set/flowset byte length
	//   recordSize   — bytes per flow record on the wire
	//
	// For encoders that produce variable-length records (e.g. sFlow), recordSize
	// is advisory — Tick() consults MaxRecordSize() to pick a safe worst-case
	// paginator bound instead of dividing buffer space by recordSize.
	PacketSizes() (baseOverhead int, templateSize int, recordSize int)
	// SeqIncrement returns how much to advance the flow-sequence counter after
	// a packet carrying packetRecordCount data records. NetFlow v9 and IPFIX
	// return 1 (RFC 3954 "sequence number of all export packets" / RFC 7011
	// "per-SCTP-stream message count"). NetFlow v5 returns packetRecordCount
	// because Cisco v5 defines flow_sequence as the cumulative count of
	// records, not packets.
	SeqIncrement(packetRecordCount int) int
	// MaxRecordSize returns the worst-case on-wire byte size of a single record
	// for variable-length protocols. Fixed-size encoders (NetFlow v5 / v9,
	// IPFIX) return 0 and keep the existing PacketSizes()-driven pagination.
	// A non-zero return opts into variable-length pagination in Tick().
	MaxRecordSize() int
	// TrailingPadBytes returns the bytes the encoder writes AFTER n records to
	// pad its data set to an alignment boundary (RFC 3954 §5.3, RFC 7011
	// §3.3.1). Encoders that never pad return 0.
	//
	// Tick must budget this or it silently loses records: Tick's own capacity
	// arithmetic decides how many records leave the expiry queue, and a batch
	// the encoder then truncates for want of pad room is already gone from
	// `expired` and already counted into RecordsSent and the scenario ledger.
	// That is a drop with no error, no dropped counter, and an over-reporting
	// ground truth — the worst shape a bug can take on this path.
	//
	// This exists so Tick and the encoder compute capacity from ONE formula.
	// They agree at today's constants, but NetFlow v9 at the IPv6 budget lands
	// on exactly len(buf), so the margin that keeps them agreeing is zero.
	TrailingPadBytes(recordCount int) int
	// MaxRecordsPerDatagram returns a protocol-imposed ceiling on records per
	// datagram that is INDEPENDENT of buffer space, or 0 when the only limit
	// is how much fits. NetFlow v5 returns 30 (the Cisco datagram cap);
	// everything else returns 0.
	//
	// Tick must honour this for the same reason it must honour
	// TrailingPadBytes: it advances `expired` by its own capacity before the
	// encoder sees the batch, so records the encoder then discards are gone
	// from the queue while still counted into RecordsSent, the scenario ledger
	// and the sequence counter. Under NetFlow v5 that also desynchronises
	// `flow_sequence`, which counts records rather than packets — a collector
	// reads the gap as lost flows.
	//
	// This was invisible while the datagram budget was fixed at 1472, where
	// `(1472-24)/48` happens to equal exactly 30. `-datagram-mtu` makes larger
	// buffers reachable and turns that coincidence into silent data loss:
	// measured at MTU 9000, 60 of 240 records reached the wire while
	// RecordsSent reported all 240.
	MaxRecordsPerDatagram() int
}

// Flow's own datagram ceilings, derived from the shared egress-path constants
// in datagram_budget.go. The inputs are shared because they are facts about
// the path; this budget is flow's own because it is a PACKING TARGET — Tick
// fills each datagram with as many records as fit, so every unused byte is
// throughput lost and the value must be exact. See datagram_budget.go for why
// the budgets are deliberately per-subsystem rather than one shared constant.
//
// NetFlow v5 and sFlow happened to fit even under the old (wrong) full-MTU
// budget, but by arithmetic accident rather than design: v5's 30-record
// protocol cap coincided with what the budget allowed, and sFlow's worst-case
// record size is conservative enough to leave slack. Neither was evidence the
// budget was right.
// These are variables rather than constants because `-datagram-mtu` sets
// linkMTU at startup and recomputeDatagramBudgets refreshes them; they are
// read-only afterwards. Anything that captures one at package-init time would
// keep the 1500-derived value and silently fragment on a lower-MTU path.
var (
	// maxFlowPayloadIPv4 / maxFlowPayloadIPv6 are the per-datagram payload
	// ceilings: 1472 and 1452 at the default MTU. Flow branches on address
	// family because an IPv6 collector is reachable through the shared
	// dual-stack socket.
	maxFlowPayloadIPv4 = defaultLinkMTU - ipv4HeaderBytes - udpHeaderBytes
	maxFlowPayloadIPv6 = defaultLinkMTU - ipv6HeaderBytes - udpHeaderBytes

	// flowBufSize is the pooled buffer size. It stays at the full MTU so a
	// pooled buffer is never smaller than a budget derived from it; Tick
	// reslices to the budget its own collector needs.
	flowBufSize = defaultLinkMTU
)

// flowPayloadBudget returns the datagram payload ceiling for a collector at
// addr. The IPv6 header costs 20 bytes more than IPv4, which is enough to
// change the record count per datagram, so the address family is resolved
// rather than assumed: attachFlowExporter resolves collectors with
// net.ResolveUDPAddr("udp", …) and an IPv6 collector is reachable through the
// shared (dual-stack) socket. A nil or family-less address takes the
// conservative IPv6 budget.
func flowPayloadBudget(addr *net.UDPAddr) int {
	if addr != nil && addr.IP.To4() != nil {
		return maxFlowPayloadIPv4
	}
	return maxFlowPayloadIPv6
}

// FlowTickStats holds per-tick export counters returned by Tick.
// tickAllFlowExporters sums these across all devices and adds them to the
// cumulative atomic counters on SimulatorManager.
type FlowTickStats struct {
	PacketsSent uint64
	BytesSent   uint64
	RecordsSent uint64
	// SendFailures counts datagrams the kernel refused. Kept separate from
	// PacketsSent rather than folded into it, so `sent` means "reached the
	// kernel" — the reading syslog already uses (syslog_exporter.go increments
	// SendFailures and returns; Sent only on the success path).
	//
	// Before nl6#491 all three counters incremented after a failed WriteTo, so
	// GET /api/v1/flows/status reported datagrams that never left the host and
	// a down collector was undetectable from it. That is also why nl6#488's
	// datagram gate cannot drive Tick through its probe socket: an EMSGSIZE
	// never reaches the return value.
	SendFailures   uint64
	LastTemplateMs int64 // unix ms of the most-recent template send this tick; 0 if none
}

// FlowExporter is owned by one DeviceSimulator. It ties the FlowCache and
// encoder together and is driven by the shared SimulatorManager ticker goroutine.
// It has no goroutines of its own — see SimulatorManager.startFlowTicker.
//
// The optional per-device conn (set by the device lifecycle when
// flowSourcePerDevice is enabled) lets each exporter send UDP packets with
// a source IP matching the simulated device, so collectors like OpenNMS
// Telemetryd can attribute flows to the correct node. When conn is nil,
// Tick falls back to the shared-socket pool (one entry per (collector,
// protocol) tuple) via `SimulatorManager.flowConnFor`.
//
// As of the per-device-export-config refactor, the exporter owns its
// protocol / encoder / collector address and cumulative stat counters
// instead of pulling them from the manager at tick time. That keeps
// heterogeneous fleets coherent: devices pointing at different collectors
// or using different protocols tick independently through the same
// goroutine.
type FlowExporter struct {
	cache   *FlowCache
	profile *FlowProfile
	// concurrentOverride replaces profile.ConcurrentFlows for THIS exporter when
	// positive. It exists so a scenario can pace one device without touching the
	// profile, which is a shared pointer held by every device of the same type:
	// writing through to it would resize the cache of the whole fleet, including
	// devices the scenario never armed, and would outlive the run if anything
	// went wrong. Zero means "use the profile".
	concurrentOverride atomic.Int64
	rng                *rand.Rand
	seqNo              uint32
	domainID           uint32    // device IPv4 as uint32 (RFC 7011 §3.1)
	subAgentID         uint32    // sFlow sub_agent_id (0 = single-agent default)
	startTime          time.Time // reference point for SysUptime
	lastTempl          time.Time // last template transmission time
	templateInterval   time.Duration

	// Per-device wire configuration (owned by the exporter, not the manager).
	// collectorStr keeps the human-readable "host:port" for status reporting;
	// collectorAddr is the resolved *net.UDPAddr used for WriteTo. protocol
	// is the canonicalised name ("netflow9" / "ipfix" / "netflow5" / "sflow").
	collectorStr  string
	collectorAddr *net.UDPAddr
	protocol      string
	encoder       FlowEncoder

	// Per-exporter cumulative counters. Summed at status-endpoint read
	// time and persisted into the simulator-wide per-collector aggregate
	// when the device is deleted, so /api/v1/flows/status exposes
	// monotonic totals even as devices come and go.
	statPackets  atomic.Uint64
	statFailures atomic.Uint64
	statBytes    atomic.Uint64
	statRecords  atomic.Uint64

	// firstWriteErr ensures we log at most one write-failure message per
	// exporter; silent swallowing of WriteTo errors was an observability
	// hole flagged in the phase 3 review (P6).
	firstWriteErr sync.Once
	// firstOptionsErr mirrors firstWriteErr for the option-datagram encode
	// path: an encoder error there would otherwise stop option emission
	// silently (review finding — unreachable today, but defensive).
	firstOptionsErr sync.Once
	// persistOnce makes persistFlowCounters idempotent per exporter. The
	// fold is reachable from two device-teardown paths (device.go Stop and
	// delete), and folding twice would double the persisted per-collector
	// aggregates (scenario PR0 prerequisite fix).
	persistOnce sync.Once

	// conn is the per-device UDP socket (nil = use shared pool). atomic.Pointer
	// so Tick (ticker goroutine) and Close (device-shutdown paths) can read and
	// clear it without racing. Callers must use Load/Store/Swap — never touch
	// the field by address.
	conn atomic.Pointer[net.UDPConn]
	// counterSources is consulted on each sFlow tick to emit COUNTERS_SAMPLE
	// records alongside FLOW_SAMPLEs. Written once at device init and read-only
	// thereafter, so no locking is required for the read path in Tick.
	// Under NetFlow/IPFIX exporters the slice is non-nil but ignored.
	counterSources []CounterSource

	// Interface option-table state ("option interface-table"). optionShape is
	// the canonical shape ("" = off); optionIfaces is the device's interface
	// universe with resolved names, captured once at attach time by
	// registerFlowOptionInterfaces and read-only thereafter (same discipline
	// as counterSources). Only ever set for netflow9/ipfix exporters —
	// Validate enforces the protocol compatibility.
	optionShape  string
	optionIfaces []flowOptionIface

	// scenPart is the load-test scenario participation handle (nil = not
	// participating → byte-for-byte legacy behaviour). When set, Tick gates
	// DATA emission through the scenario gate (FR15/FR17): pre-T0 and post-
	// window, data records are generation-suppressed (tick skip) while
	// TEMPLATES still flow so the collector is armed before T0; in-window,
	// data records count at datagram-write-return (templates excluded from
	// `sent`; a failed datagram moves its records to send_failures). Gate
	// decisions and bucketing use the tick's `now`.
	scenPart atomic.Pointer[scenarioPart]
	// scenDriven (FR: D1 flow-cadence adaptation): true while a RUNNING
	// scenario owns this exporter's emission cadence. The fleet flow ticker
	// skips it (the scenario's own ticker drives Tick at the scenario cadence
	// during [T0,T1)); flipped false at finalize. During ARM it stays false so
	// the fleet ticker still emits arming templates.
	scenDriven atomic.Bool
}

// flowOptionIface is one interface's option-record identity: its ifIndex and
// resolved name (used for both interfaceName(82) and interfaceDescription(83)
// — the same ifDescr-backed source the trap/syslog IfName path resolves).
type flowOptionIface struct {
	ifIndex uint32
	name    string
}

// Canonical option-table shape names (see DeviceFlowConfig.Validate). The
// names describe where the ifIndex lives on the wire, not a vendor:
// "system-scoped" matches the shape real Cisco IOS-XR exporters emit.
const (
	flowOptionShapeIfScoped     = "if-scoped"
	flowOptionShapeSystemScoped = "system-scoped"
	// flowOptionStringLen is the fixed on-wire size of option-record string
	// fields (82/83) in both protocols: NUL-padded, truncated at 32 bytes —
	// the fixed-width form collectors' v9 string handling expects.
	flowOptionStringLen = 32
)

// putPaddedString writes s into buf at pos as a fixed flowOptionStringLen-byte
// field: NUL-padded on the right, truncated at the field size. Returns the
// new position. Shared by the NF9 and IPFIX option-record encoders.
//
// Caller contract: pos+flowOptionStringLen must not exceed len(buf) — bounds
// are guaranteed one level up by encodeOptionRecords' defensive record cap,
// so record encoders never need per-field checks.
func putPaddedString(buf []byte, pos int, s string) int {
	n := copy(buf[pos:pos+flowOptionStringLen], s)
	for i := pos + n; i < pos+flowOptionStringLen; i++ {
		buf[i] = 0
	}
	return pos + flowOptionStringLen
}

// flowOptionShapeDesc bundles everything one option-table shape needs —
// pre-encoded options template, record size, and the record encoder — so a
// shape cannot be half-registered: template and record layout live in the
// same table entry and cannot drift apart (a review finding: shape knowledge
// spread across uncoupled switch sites risks template/data mismatch when a
// shape is added to some sites but not others). Each protocol owns a
// map[shape]flowOptionShapeDesc built in its init().
type flowOptionShapeDesc struct {
	templ   []byte // pre-encoded options template FlowSet/Set
	recSize int    // on-wire bytes of one option data record
	// encodeRecord writes one option data record at pos and returns the new
	// position. domainID feeds shapes whose scope value is the exporter
	// identity (IPFIX system-scoped); interface-scoped shapes ignore it.
	encodeRecord func(buf []byte, pos int, domainID uint32, ifc flowOptionIface) int
}

// encodeOptionRecords writes the option data FlowSet/Set: 4-byte set header
// (setID + length) followed by one record per interface, capped to what fits
// in buf. Returns (newPos, consumed). Shared by the NF9 and IPFIX option
// encoders so the pagination/set-length math exists exactly once.
//
// The record cap is re-derived here from len(buf) rather than trusted from
// the caller's overhead arithmetic — defense in depth so a drift in a
// caller's size constants degrades to fewer records per datagram instead of
// a slice-bounds panic in the shared ticker goroutine.
func encodeOptionRecords(buf []byte, pos int, setID uint16, desc flowOptionShapeDesc, domainID uint32, ifaces []flowOptionIface) (int, int) {
	maxFit := (len(buf) - pos - 4) / desc.recSize
	consumed := len(ifaces)
	if consumed > maxFit {
		consumed = maxFit
	}
	if consumed <= 0 {
		return pos, 0
	}
	binary.BigEndian.PutUint16(buf[pos:], setID)
	binary.BigEndian.PutUint16(buf[pos+2:], uint16(4+consumed*desc.recSize)) // records are 4B-aligned, no padding
	pos += 4
	for _, ifc := range ifaces[:consumed] {
		pos = desc.encodeRecord(buf, pos, domainID, ifc)
	}
	return pos, consumed
}

// flowOptionsEncoder is the seam for encoders that emit interface
// option-table datagrams (NetFlow v9 and IPFIX). Deliberately NOT part of
// FlowEncoder — netflow5/sflow cannot implement it, and Validate guarantees
// optionShape is only ever set for protocols whose encoder satisfies this.
// A future options-capable encoder satisfies it implicitly; nothing in
// Tick needs to enumerate concrete types.
type flowOptionsEncoder interface {
	EncodeOptionsDatagram(domainID, seqNo, uptimeMs uint32, shape string,
		ifaces []flowOptionIface, buf []byte) (n int, consumed int, err error)
}

// NewFlowExporter creates a FlowExporter for device, using profile to drive
// synthetic flow generation. The RNG is seeded from the device's domainID so
// each device produces distinct but deterministic traffic patterns.
//
// collectorStr is the "host:port" the device exports to; collectorAddr is the
// resolved form (the caller must pre-resolve so construction is cheap);
// protocol is the canonical protocol name; encoder is the matching encoder
// instance; subAgentID is the sFlow sub_agent_id (0 for non-sFlow or the
// single-agent default). Callers typically use
// `SimulatorManager.attachFlowExporter` rather than calling this constructor
// directly.
func NewFlowExporter(device *DeviceSimulator, profile *FlowProfile,
	activeTimeout, inactiveTimeout, templateInterval time.Duration,
	collectorStr string, collectorAddr *net.UDPAddr,
	protocol string, encoder FlowEncoder, subAgentID uint32) *FlowExporter {
	var domainID uint32
	if ip4 := device.IP.To4(); ip4 != nil {
		domainID = binary.BigEndian.Uint32(ip4)
	}
	return &FlowExporter{
		cache:            NewFlowCache(activeTimeout, inactiveTimeout, profile.MaxFlows),
		profile:          profile,
		rng:              rand.New(rand.NewSource(int64(domainID))),
		domainID:         domainID,
		subAgentID:       subAgentID,
		startTime:        time.Now(),
		templateInterval: templateInterval,
		collectorStr:     collectorStr,
		collectorAddr:    collectorAddr,
		protocol:         protocol,
		encoder:          encoder,
	}
}

// Close releases the per-device UDP socket, if one was opened. Safe to call
// on a nil or already-closed FlowExporter; safe to call multiple times and
// concurrently with Tick (Swap atomically claims the conn so only one caller
// ever observes it non-nil).
func (fe *FlowExporter) Close() error {
	if fe == nil {
		return nil
	}
	conn := fe.conn.Swap(nil)
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// logFirstWriteErr emits at most one log line per exporter on a failed
// WriteTo. Gated by fe.firstWriteErr so a down/misconfigured collector
// doesn't flood logs at tick cadence × device count.
func (fe *FlowExporter) logFirstWriteErr(err error) {
	if fe == nil {
		return
	}
	fe.firstWriteErr.Do(func() {
		log.Printf("flow export: device %s write to %s failed: %v (further errors suppressed for this exporter)",
			domainIDtoIP(fe.domainID), fe.collectorStr, err)
	})
}

// logFirstOptionsErr emits at most one log line per exporter when an
// option-datagram encode fails; option emission stops for the refresh tick
// but must not stop silently.
func (fe *FlowExporter) logFirstOptionsErr(err error) {
	if fe == nil {
		return
	}
	fe.firstOptionsErr.Do(func() {
		log.Printf("flow export: device %s option-datagram encode (shape %s) failed: %v (further errors suppressed for this exporter)",
			domainIDtoIP(fe.domainID), fe.optionShape, err)
	})
}

// effectiveFlowLifetime is how long a flow actually occupies the cache: the
// lifetime the profile and timeouts imply, PLUS half the sweep interval.
//
// Expiry is noticed by a periodic sweep, so a flow whose deadline falls between
// sweeps waits for the next one — on average half an interval. That delay is
// real residency and it belongs in the denominator: pacing divides a requested
// rate by this to get a cache size, and omitting the term sizes every cache
// short, so every paced run emits low.
//
// It was invisible until the active deadline gained jitter. Without jitter a
// flow created on a sweep boundary had a deadline exactly `active` later, which
// landed on another sweep boundary and cost nothing — an alignment artifact of
// synthetic timing, not a property of the exporter. Measured across a 10x range
// of sweep intervals, `MeanFlowLifetime + sweep/2` predicts the real residency
// to within 0.3%.
func effectiveFlowLifetime(fe *FlowExporter, sweep time.Duration) time.Duration {
	base := MeanFlowLifetime(fe.profile, fe.cache.activeTimeout, fe.cache.inactiveTimeout)
	if base <= 0 {
		return 0
	}
	if sweep > 0 {
		base += sweep / 2
	}
	return base
}

// flowRateReachable reports whether this exporter can be paced to `rate`.
//
// The cache cannot hold more than MaxFlows, so the reachable per-device rate is
// bounded by MaxFlows / mean-lifetime — about 8.6 to 9.7 records/second across
// the shipped profiles, which is lower than operators expect. Flow is not a
// protocol to drive hard per device: fleet throughput scales with participant
// count, per-device rate does not scale past the cache.
//
// Returning a reason rather than silently clamping is the point. Delivering 8.8
// against a requested 50 while the report names 50 as the target is the exact
// defect this change exists to remove.
func flowRateReachable(fe *FlowExporter, rate float64, sweep time.Duration) (reason, hint string, ok bool) {
	if rate <= 0 || fe == nil || fe.profile == nil || fe.cache == nil {
		return "", "", true // no rate to honor
	}
	lifetime := effectiveFlowLifetime(fe, sweep)
	if lifetime <= 0 {
		return "", "", true
	}
	ceiling := float64(fe.profile.MaxFlows) / lifetime.Seconds()
	if rate <= ceiling {
		return "", "", true
	}
	return fmt.Sprintf("requested rate %.2f/s exceeds this device's flow ceiling of %.2f/s "+
			"(cache holds at most %d flows, mean residency %.1fs = lifetime + half the %s sweep)",
			rate, ceiling, fe.profile.MaxFlows, lifetime.Seconds(), sweep),
		fmt.Sprintf("lower the per-device rate to %.2f/s or below, or add participants — "+
			"fleet throughput scales with participant count, per-device rate does not", ceiling),
		false
}

// flowPacingTarget is the cache population that makes this exporter emit at
// `rate` records/second, from the identity in MeanFlowLifetime. Returns 0 (no
// override, keep the profile's population) for a non-positive rate.
//
// Rounded to at least 1: a rate low enough to round to zero would otherwise
// silence the device entirely, which is not what a small rate means. Rates too
// LOW to express are floored here; rates too HIGH to reach are refused at
// submit instead, because silently under-delivering a requested rate is the
// defect this whole change exists to remove.
func flowPacingTarget(fe *FlowExporter, rate float64, sweep time.Duration) int {
	if rate <= 0 || fe == nil || fe.profile == nil || fe.cache == nil {
		return 0
	}
	// A profile with auto-generation disabled cannot be paced by this
	// mechanism: pacing works by setting the population GenerateFlows fills to,
	// and this profile asks it to fill to nothing. The cache holds only what a
	// caller injected through Add, which is not ours to resize.
	//
	// No shipped profile sets this — every one is 8..200 — so this guards the
	// inject-only path rather than a real device.
	if fe.profile.ConcurrentFlows <= 0 {
		return 0
	}
	// The timeouts live on the cache, which is what actually ages the flows —
	// reading them from anywhere else risks pacing against a value the engine
	// is not using.
	lifetime := effectiveFlowLifetime(fe, sweep)
	if lifetime <= 0 {
		return 0
	}
	target := int(math.Round(rate * lifetime.Seconds()))
	if target < 1 {
		target = 1
	}
	return target
}

// targetFlows is the cache population this exporter aims for: its scenario
// override when one is installed, otherwise its profile's value.
func (fe *FlowExporter) targetFlows() int {
	if n := fe.concurrentOverride.Load(); n > 0 {
		return int(n)
	}
	return fe.profile.ConcurrentFlows
}

// setConcurrentOverride installs (n > 0) or clears (n <= 0) this exporter's
// cache-population override. Clearing must happen on EVERY path that ends
// participation — finalize, abort, device teardown — or a device keeps emitting
// at a scenario's rate after the scenario is gone.
func (fe *FlowExporter) setConcurrentOverride(n int) {
	if n <= 0 {
		fe.concurrentOverride.Store(0)
		return
	}
	fe.concurrentOverride.Store(int64(n))
}

// Tick is called by the shared SimulatorManager ticker goroutine on every
// flowTickInterval. It replenishes the flow cache to ConcurrentFlows, expires
// aged records, and emits one or more UDP datagrams to `fe.collectorAddr`
// using `fe.encoder`.
//
// When fe.conn is non-nil (per-device mode) it is used for the WriteTo; the
// passed-in sharedConn is the shared-pool fallback (keyed by collector +
// protocol) used when the per-device socket could not be opened or
// per-device mode is disabled. sharedConn may be nil when the pool
// could not open a socket for this exporter's (collector, protocol) tuple.
//
// bufPool must supply []byte slices of at least flowBufSize bytes; Tick
// reslices them down to the collector's flowPayloadBudget.
// Write errors are ignored (best-effort delivery; collector may be down).
// The returned FlowTickStats are summed by tickAllFlowExporters into the
// per-exporter atomic counters and aggregated at status-endpoint read time.
func (fe *FlowExporter) Tick(now time.Time, sharedConn *net.UDPConn, bufPool *sync.Pool) FlowTickStats {
	uptimeMs := uint32(now.Sub(fe.startTime).Milliseconds())
	deviceIP := domainIDtoIP(fe.domainID)
	encoder := fe.encoder
	collectorAddr := fe.collectorAddr

	// Prefer the per-device socket (source IP = device IP) when set; fall back
	// to the shared-pool socket so callers that don't use per-device binding
	// (tests, ns-disabled deployments) still work.
	// atomic Load pairs with Swap in Close — Tick never observes a torn pointer.
	writeConn := fe.conn.Load()
	if writeConn == nil {
		writeConn = sharedConn
	}
	if writeConn == nil || collectorAddr == nil || encoder == nil {
		return FlowTickStats{}
	}

	// Trim BEFORE expiring: a cache being resized downward (a scenario pacing
	// this device below its profile population) must converge now, not over a
	// flow lifetime. Letting the surplus expire first gives it one last harvest
	// and puts a short run well over its target.
	//
	// ONLY when a scenario is pacing this device. Trimming unconditionally would
	// evict flows a caller injected through Add — the ingest seam, whose whole
	// point is that the cache holds what it was given rather than what the
	// generator would have produced. Nothing needs to converge when no override
	// is installed, so there is nothing to trim toward.
	target := fe.targetFlows()
	if fe.concurrentOverride.Load() > 0 {
		fe.cache.TrimTo(target)
	}

	// EXPIRE, then refill. A router frees the cache entry and then admits
	// new flows into the vacated slot; doing it the other way round means a
	// flow can never leave on the tick it was born, so the cache alternates
	// between full and empty once the tick period approaches the flow lifetime.
	// At -flow-tick-interval 30s with the 30s default active timeout that
	// produced a literal [0 128 0 128 ...] — the whole cache on one tick, then
	// a silent one, forever. Expiring first refills the vacated slots in the
	// same tick, so a coarse cadence yields big datagrams rather than
	// alternating bursts and silence.
	expired := fe.cache.Expire(now)

	// Replenish the cache to its target population.
	fe.cache.GenerateFlows(fe.profile, target, deviceIP, fe.rng, now, uptimeMs)

	sendTemplate := fe.seqNo == 0 || now.Sub(fe.lastTempl) >= fe.templateInterval
	if len(expired) == 0 && !sendTemplate {
		return FlowTickStats{}
	}
	// Scenario gate (FR15/FR17): pre-T0 and post-window, DATA records are
	// generation-suppressed (dropped from this tick) while TEMPLATES keep
	// flowing so the collector is armed before T0; in-window, admit the drain
	// barrier so Stop can outlast an in-flight tick. `scenCount` records the
	// per-datagram ledger accounting done at each write-return below.
	part := fe.scenPart.Load()
	// Fidelity mode: a non-participant device emits no autonomous flow at all
	// (not even templates) — the wire is silent until a scenario drives it.
	//
	// Routed through fidelityMutesBackground rather than reading the flag
	// directly so all four push subsystems observe fidelity through ONE rule.
	// A tick is autonomous by definition (flow has no on-demand endpoint), so
	// sourceBackground is the honest classification and this is behaviourally
	// identical to the previous raw read.
	if part == nil && fidelityMutesBackground(sourceBackground) {
		return FlowTickStats{}
	}
	scenActive := false
	if part != nil {
		switch part.decide(sourceScenario, now) {
		case gateSuppressSilent, gateSuppressCounted:
			// Suppress data this tick; disclose how many records we skipped.
			if len(expired) > 0 {
				part.ledger.backgroundSuppressed.Add(uint64(len(expired)))
			}
			expired = nil
			// Templates (NF9/IPFIX arming) and sFlow counters_sample (keepalive)
			// still flow while data is suppressed — only bail if there is truly
			// nothing left to send this tick.
			if !sendTemplate && len(fe.counterSources) == 0 {
				return FlowTickStats{}
			}
		default: // allow
			if part.drain.admit() {
				scenActive = true
				defer part.drain.leave()
			} else {
				// Window is closing: these records are dropped, not sent.
				if len(expired) > 0 {
					part.ledger.emitted.Add(uint64(len(expired)))
					part.ledger.dropped.Add(uint64(len(expired)))
				}
				expired = nil
				if !sendTemplate && len(fe.counterSources) == 0 {
					return FlowTickStats{}
				}
			}
		}
	}

	// Options datagrams ride the template-refresh cadence; capture the
	// condition now because the flow loop below consumes sendTemplate.
	emitOptions := sendTemplate && fe.optionShape != "" && len(fe.optionIfaces) > 0

	// `sync.Pool` stores `*[]byte` (SA6002). Deref once into a local
	// slice header — the backing array is shared, so writes via `buf`
	// land in the same memory the pointer references.
	//
	// Reslice to this collector's payload budget. Every sizing decision
	// below (the flow loop, the sFlow counters loop, and the options
	// encoders) derives from len(buf), so capping it here is the single
	// point that keeps all of them inside the MTU (nl6#485).
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr
	if budget := flowPayloadBudget(collectorAddr); budget < len(buf) {
		buf = buf[:budget]
	}

	var stats FlowTickStats

	// Paginate: send as many records as fit in one datagram payload (buf has
	// already been capped to the collector's flowPayloadBudget above).
	// Capacity depends on the active encoder's protocol (NF9: 46B/record,
	// IPFIX: 54B/record), so we ask the encoder for its sizes rather than
	// hard-coding NF9 constants here.
	//
	// Variable-length encoders (sFlow) return a non-zero MaxRecordSize and we
	// bound batches by that worst-case; fixed-size encoders return 0 and keep
	// the original (len(buf) - overhead) / recSize division unchanged so
	// existing NetFlow/IPFIX datagram framing is preserved byte-for-byte.
	baseOverhead, templSize, recSize := encoder.PacketSizes()
	maxRecSize := encoder.MaxRecordSize()
	for {
		overhead := baseOverhead
		if sendTemplate {
			overhead += templSize
		}
		var batch []FlowRecord
		perRec := recSize
		if maxRecSize > 0 {
			perRec = maxRecSize
		}
		if len(buf) >= overhead+perRec {
			cap := (len(buf) - overhead) / perRec
			// Match the encoder's own capacity exactly, pad included. Handing
			// it one record more than it will encode drops that record
			// silently while still counting it as sent (see TrailingPadBytes).
			// Dropping one record flips the pad parity, so one decrement is
			// always enough.
			if cap > 0 && overhead+cap*perRec+encoder.TrailingPadBytes(cap) > len(buf) {
				cap--
			}
			// Honour a protocol record-count ceiling that buffer arithmetic
			// cannot see (NetFlow v5's 30). The remainder stays in `expired`
			// and rides the next datagram, so nothing is lost.
			if m := encoder.MaxRecordsPerDatagram(); m > 0 && cap > m {
				cap = m
			}
			if cap >= len(expired) {
				batch = expired
				expired = nil
			} else {
				batch = expired[:cap]
				expired = expired[cap:]
			}
		}

		if len(batch) == 0 && !sendTemplate {
			break
		}

		var n int
		var err error
		if sfe, ok := encoder.(SFlowEncoder); ok {
			// sFlow routes through EncodeFlowDatagram so sampling_rate can be
			// derived from the device's FlowProfile — the FlowEncoder interface
			// doesn't carry the profile, and a shared encoder can't hold state.
			rate := uint32(fe.profile.ConcurrentFlows * SyntheticSamplingRateMultiplier)
			if rate == 0 {
				rate = 1
			}
			n, err = sfe.EncodeFlowDatagram(fe.domainID, fe.subAgentID, fe.seqNo, uptimeMs, batch, rate, buf)
		} else {
			n, err = encoder.EncodePacket(fe.domainID, fe.seqNo, uptimeMs, batch, sendTemplate, buf)
		}
		if err != nil || n == 0 {
			break
		}

		writeErr := false
		if _, err := writeConn.WriteTo(buf[:n], collectorAddr); err != nil {
			fe.logFirstWriteErr(err)
			writeErr = true
		}
		// Scenario ledger accounting (FR20/FR23): DATA records count at
		// datagram-write-return; templates are NOT counted in `sent`. A failed
		// datagram moves its records to send_failures. Whether the batch also
		// feeds the per-application ledger is the participant's countApps
		// flag, set at installScenPart (sflow excluded there — a conforming
		// sFlow collector derives bytes by sampling extrapolation).
		if scenActive && len(batch) > 0 {
			part.ledger.emitted.Add(uint64(len(batch)))
			if writeErr {
				part.ledger.sendFailures.Add(uint64(len(batch)))
			} else {
				part.bucketFlowBatch(now, batch)
			}
		}
		if writeErr {
			stats.SendFailures++
		} else {
			stats.PacketsSent++
			stats.BytesSent += uint64(n)
			stats.RecordsSent += uint64(len(batch))
		}
		// Advance flow_sequence per the protocol's semantics. NF9/IPFIX advance
		// by 1 per packet; NF5 advances by the record count of this packet.
		//
		// Advanced even on a failed write, deliberately and unchanged by
		// nl6#491. The alternative — reusing the sequence — would hide the loss
		// from the collector entirely, whereas advancing shows it as a gap.
		// Either is defensible; changing it would alter wire semantics, which
		// is a bigger question than the status counters this fixes.
		fe.seqNo += uint32(encoder.SeqIncrement(len(batch)))
		if sendTemplate {
			fe.lastTempl = now
			stats.LastTemplateMs = now.UnixMilli()
			sendTemplate = false
		}

		if len(expired) == 0 {
			break
		}
	}

	// Phase 2: after the flow-sample loop, sFlow emits one COUNTERS_SAMPLE
	// datagram per tick aggregating all registered CounterSources. Each source's
	// Snapshot is called once; records are concatenated into a single datagram
	// bounded by sflowMaxCountersSampleSize * recordCount. Datagrams that would
	// exceed the buffer are split — EncodeCounterDatagram is called repeatedly
	// with remaining records until the batch is drained.
	if sfe, ok := encoder.(SFlowEncoder); ok && len(fe.counterSources) > 0 {
		var allRecords []CounterRecord
		for _, src := range fe.counterSources {
			allRecords = append(allRecords, src.Snapshot(now)...)
		}
		for len(allRecords) > 0 {
			batch := allRecords
			// Pick the largest batch that fits in buf. Each record
			// occupies at most sflowMaxCountersSampleSize bytes once wrapped,
			// and each counters_sample wrapper contributes
			// sflowCountersSampleHeaderSize bytes of overhead on top of the
			// datagram header.
			maxBatch := (len(buf) - sflowDatagramHeaderSize - sflowCountersSampleHeaderSize) / sflowMaxCountersSampleSize
			if maxBatch < 1 {
				break
			}
			if len(batch) > maxBatch {
				batch = batch[:maxBatch]
				allRecords = allRecords[maxBatch:]
			} else {
				allRecords = nil
			}
			n, err := sfe.EncodeCounterDatagram(fe.domainID, fe.subAgentID, fe.seqNo, uptimeMs, batch, buf)
			if err != nil || n == 0 {
				break
			}
			if _, err := writeConn.WriteTo(buf[:n], collectorAddr); err != nil {
				fe.logFirstWriteErr(err)
			}
			stats.PacketsSent++
			stats.BytesSent += uint64(n)
			fe.seqNo++
		}
	}

	// Interface option-table datagrams ride the template-refresh cadence
	// (emitOptions captured before the flow loop consumed sendTemplate).
	// Each datagram is self-contained (options template + data records), so
	// pagination just re-invokes with the remainder. The datagram advances
	// fe.seqNo by 1 under both protocols (v9 counts export packets; IPFIX
	// keeps this simulator's message-counting interpretation — design D7).
	// Option data records are metadata, not flows: counted in packet/byte
	// stats but excluded from RecordsSent.
	//
	// optionShape is only ever set for netflow9/ipfix (Validate), whose
	// encoders satisfy flowOptionsEncoder — the assertion failing means a
	// wiring bug, not a config error, hence the log.
	if emitOptions {
		optEnc, ok := encoder.(flowOptionsEncoder)
		if !ok {
			fe.logFirstOptionsErr(fmt.Errorf("encoder %T does not implement EncodeOptionsDatagram", encoder))
		}
		remaining := fe.optionIfaces
		for ok && len(remaining) > 0 {
			n, consumed, err := optEnc.EncodeOptionsDatagram(fe.domainID, fe.seqNo, uptimeMs, fe.optionShape, remaining, buf)
			if err != nil {
				fe.logFirstOptionsErr(err)
				break
			}
			if n == 0 || consumed == 0 {
				break
			}
			if _, err := writeConn.WriteTo(buf[:n], collectorAddr); err != nil {
				fe.logFirstWriteErr(err)
			}
			stats.PacketsSent++
			stats.BytesSent += uint64(n)
			fe.seqNo++
			remaining = remaining[consumed:]
		}
	}

	return stats
}

// SetFlowSourcePerDevice toggles per-device UDP source IP binding. When true,
// each device opens its own UDP socket inside the nl6sim namespace bound to
// the device's IP, so collectors see per-device exporter IPs rather than the
// container host IP. Read at per-device attach time; call before the
// first call to `CreateDevices` that carries a flow seed.
func (sm *SimulatorManager) SetFlowSourcePerDevice(enabled bool) {
	sm.flowSourcePerDevice = enabled
}

// registerFlowOptionInterfaces captures the device's interface option-table
// state onto the FlowExporter when `options_interface_table` is enabled:
// the canonical shape plus the interface universe with names resolved once
// through the same ifDescr-backed path trap/syslog use (deviceIfNameFn).
// Both the universe (IfCounterCycler.knownIfIndexes) and ifDescr values are
// static after device init, so a one-time snapshot is exact. Indices are
// sorted ascending for deterministic wire output. ifIndex 0 (or negative)
// is never emitted — collectors treat a zero ifIndex as absent. A device
// with no interfaces gets an empty slice, which suppresses emission
// entirely (an options set with zero records is an invalid packet).
func (sm *SimulatorManager) registerFlowOptionInterfaces(device *DeviceSimulator) {
	fe := device.flowExporter
	cfg := device.flowConfig
	if fe == nil || cfg == nil || cfg.OptionsInterfaceTable == "" {
		return
	}
	var ifaces []flowOptionIface
	if device.metricsCycler != nil {
		if ic := device.metricsCycler.ifCounters.Load(); ic != nil {
			idxs := append([]int(nil), ic.IfIndices()...)
			sort.Ints(idxs)
			nameFn := deviceIfNameFn(device)
			for _, idx := range idxs {
				if idx <= 0 {
					continue
				}
				ifaces = append(ifaces, flowOptionIface{ifIndex: uint32(idx), name: nameFn(idx)})
			}
		}
	}
	fe.optionShape = cfg.OptionsInterfaceTable
	fe.optionIfaces = ifaces
}

// registerSFlowCounterSources wires per-device CounterSource instances onto
// the FlowExporter, but only when the device's protocol is sFlow. Under
// NetFlow/IPFIX/NF5 the sources are never consulted, so skipping registration
// avoids per-device allocations for the 30,000+ device workloads this
// simulator is built for.
func (sm *SimulatorManager) registerSFlowCounterSources(device *DeviceSimulator) {
	if device.flowExporter == nil || device.flowExporter.protocol != "sflow" {
		return
	}
	var sources []CounterSource
	if device.metricsCycler != nil {
		if ic := device.metricsCycler.ifCounters.Load(); ic != nil {
			if s := NewInterfaceCounterSource(ic); s != nil {
				sources = append(sources, s)
			}
		}
	}
	// CPUCounterSource's processor_information record already carries
	// total_memory and free_memory — a separate memory counter source would
	// emit a non-standard sFlow format ID that strict collectors drop.
	sources = append(sources, NewCPUCounterSource(device))
	device.flowExporter.counterSources = sources
}

// openFlowConnForDevice opens a per-device UDP socket bound to the device's
// IP (ephemeral source port) and assigns it to device.flowExporter.conn.
// Silently falls through to the shared-pool socket when:
//   - per-device mode is disabled,
//   - namespace isolation is off (device.netNamespace == nil),
//   - or the bind fails (typically because the nl6sim ns has no route to
//     the collector — see issue #36).
//
// Best-effort: a failed per-device bind logs once and the exporter keeps
// working via the shared-pool socket.
func (sm *SimulatorManager) openFlowConnForDevice(device *DeviceSimulator) {
	if !sm.flowSourcePerDevice || device.flowExporter == nil {
		return
	}
	if device.netNamespace == nil {
		return
	}
	addr := &net.UDPAddr{IP: device.IP, Port: 0}
	conn, err := device.netNamespace.ListenUDPInNamespace(addr)
	if err != nil {
		if device.flowExporter.protocol == "sflow" {
			log.Printf("flow export: device %s per-device bind failed, falling back to shared socket: %v (sFlow agent_address may not match UDP source IP observed by collector)", device.IP, err)
		} else {
			log.Printf("flow export: device %s per-device bind failed, falling back to shared socket: %v", device.IP, err)
		}
		return
	}
	conn.SetWriteBuffer(65536)
	device.flowExporter.conn.Store(conn)
}

// flowConnFor returns the shared-pool UDP socket for a (collector, protocol)
// tuple. First caller for a key opens the socket; subsequent callers reuse
// it. Returns nil if the socket can't be opened. Safe for concurrent use.
func (sm *SimulatorManager) flowConnFor(key flowConnKey) *net.UDPConn {
	if cached, ok := sm.flowConns.Load(key); ok {
		return cached.(*net.UDPConn)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		log.Printf("flow export: failed to open shared socket for %s/%s: %v", key.collector, key.protocol, err)
		return nil
	}
	actual, loaded := sm.flowConns.LoadOrStore(key, conn)
	if loaded {
		// Another goroutine opened a socket for this key first. Close ours.
		_ = conn.Close()
		return actual.(*net.UDPConn)
	}
	return conn
}

// closeFlowConnPool closes every pooled shared socket. Called from
// Shutdown after the ticker goroutine has exited. Does NOT reassign
// `sm.flowConns` — the manager is being torn down, the map value goes
// out of scope with it, and reassigning a concurrent sync.Map field is
// racy by itself.
func (sm *SimulatorManager) closeFlowConnPool() {
	sm.flowConns.Range(func(_, v interface{}) bool {
		if conn, ok := v.(*net.UDPConn); ok {
			_ = conn.Close()
		}
		return true
	})
}

// flowCollectorAggregate holds monotonic counters for a
// (collector, protocol) tuple that survive device deletion. Written
// by `persistFlowCounters` on device Stop; read by `GetFlowStatus` and
// merged with live-exporter counters to produce cumulative totals.
type flowCollectorAggregate struct {
	packets  atomic.Uint64
	bytes    atomic.Uint64
	records  atomic.Uint64
	failures atomic.Uint64
}

// persistFlowCounters snapshots a FlowExporter's cumulative counters
// into the simulator-wide per-collector aggregate so /flows/status
// reports monotonic totals even as devices come and go (review
// decision D1.b). Called from the device lifecycle immediately before
// `FlowExporter.Close()`. Safe to call with nil exporter; idempotent
// per exporter (`persistOnce`) — repeated calls after the first fold
// are no-ops, so the two teardown call sites can never double-count
// (scenario PR0 prerequisite fix).
func (sm *SimulatorManager) persistFlowCounters(fe *FlowExporter) {
	if fe == nil || fe.collectorStr == "" {
		return
	}
	fe.persistOnce.Do(func() {
		key := flowConnKey{collector: fe.collectorStr, protocol: fe.protocol}
		v, _ := sm.flowAggregates.LoadOrStore(key, &flowCollectorAggregate{})
		agg := v.(*flowCollectorAggregate)
		agg.packets.Add(fe.statPackets.Load())
		agg.failures.Add(fe.statFailures.Load())
		agg.bytes.Add(fe.statBytes.Load())
		agg.records.Add(fe.statRecords.Load())
	})
}

// buildFlowEncoder returns the encoder + canonical protocol name for a
// configured protocol string. Caller must have already canonicalised via
// `DeviceFlowConfig.Validate` — this function is strict and returns an
// error for anything it doesn't recognise. Centralised so the
// `attachFlowExporter` path and any future REST-validation path share one
// source of truth.
func buildFlowEncoder(protocol string) (FlowEncoder, string, error) {
	switch strings.ToLower(protocol) {
	case "netflow9", "nf9", "":
		return NetFlow9Encoder{}, "netflow9", nil
	case "ipfix", "ipfix10":
		return IPFIXEncoder{}, "ipfix", nil
	case "netflow5", "nf5":
		return &NetFlow5Encoder{}, "netflow5", nil
	case "sflow", "sflow5":
		return SFlowEncoder{}, "sflow", nil
	default:
		return nil, "", fmt.Errorf("unknown flow protocol %q (supported: netflow9, ipfix, netflow5, sflow)", protocol)
	}
}

// attachFlowExporter constructs and wires a FlowExporter for a device that
// already has `device.flowConfig` populated. Opens the per-device UDP
// socket if `flowSourcePerDevice` is enabled; registers sFlow counter
// sources if the device is exporting sFlow. On failure, logs and leaves
// `device.flowExporter == nil` so the device participates in the
// simulator but without flow export.
//
// The collector string stored on the exporter is the canonicalised form
// returned by `net.ResolveUDPAddr` so that devices configured with
// equivalent-but-different-spelling collectors (e.g. "localhost:2055"
// vs "127.0.0.1:2055") aggregate into one pool entry and one
// FlowCollectorStatus row (review fix P1).
func (sm *SimulatorManager) attachFlowExporter(device *DeviceSimulator, flowProfile *FlowProfile) error {
	cfg := device.flowConfig
	if cfg == nil {
		return nil
	}
	encoder, canonical, err := buildFlowEncoder(cfg.Protocol)
	if err != nil {
		return err
	}
	collectorAddr, err := net.ResolveUDPAddr("udp", cfg.Collector)
	if err != nil {
		return fmt.Errorf("resolve collector %q: %w", cfg.Collector, err)
	}
	canonicalCollector := collectorAddr.String()

	// Per-device TickInterval is stored on cfg but not honored: ONE
	// simulator-wide ticker drives every device.
	//
	// This is NOT the same debt as the syslog / trap Interval fields, though
	// the three are often described together. Those run on min-heap
	// schedulers with a per-entry nextFire, where a per-device cadence is a
	// field on the heap entry. Here it would mean restructuring the ticker.
	// Same symptom, materially different cost.
	//
	// The REST surface now discloses this to the caller who set the field
	// (see export_interval_disclosure.go), which is the fix that IS uniform
	// across all three, precisely because it is independent of the mechanism
	// underneath. Like its trap/syslog counterparts this log is CAS-gated to
	// one line per subsystem lifecycle; it used to warn per device and flooded
	// at fleet scale (review fix P2).
	// Disclose only when the CALLER actually set a tick interval. Gating on
	// `!= 0` was wrong twice over: ApplyDefaults always stamps 5s, so the
	// condition was permanently true, the one-shot CAS was burned by device #1
	// with the self-contradicting line "configured tick_interval=5s but every
	// device ticks at 5s", and a genuinely divergent device later logged
	// nothing at all.
	//
	// The effective value is the LATCHED period, the same reference the REST
	// disclosure uses, so the two channels cannot contradict each other.
	if cfg.TickIntervalWasSet() && sm.flowIntervalWarned.CompareAndSwap(false, true) {
		// Same text as the REST disclosure — see the syslog twin.
		if wrn := intervalDisclosure("flow.tick_interval", true,
			time.Duration(cfg.TickInterval), sm.effectiveFlowTickInterval()); wrn != nil {
			log.Printf("flow export: device %s: %s (further devices suppressed this lifecycle)",
				device.IP, wrn.Message)
		}
	}

	device.flowExporter = NewFlowExporter(device, flowProfile,
		time.Duration(cfg.ActiveTimeout),
		time.Duration(cfg.InactiveTimeout),
		sm.flowTemplateInterval,
		canonicalCollector, collectorAddr, canonical, encoder, cfg.SubAgentID)
	sm.openFlowConnForDevice(device)
	sm.registerSFlowCounterSources(device)
	sm.registerFlowOptionInterfaces(device)
	sm.flowFirstAttachLog.Do(func() {
		log.Printf("flow export: active; first device %s → %s (protocol=%s)",
			device.IP, canonicalCollector, canonical)
	})
	return nil
}

// domainIDtoIP converts a uint32 ObservationDomainID back to a net.IP.
func domainIDtoIP(id uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, id)
	return ip
}

// initFlowSubsystem sets up the simulator-wide flow export infrastructure
// that's always live: the flowBufSize buffer pool, the stop channel, and
// the ticker goroutine. After this runs, per-device attach via
// `attachFlowExporter` wires up individual exporters; the ticker walks
// them on every tick interval and no-ops when the list is empty.
//
// Called unconditionally from `NewSimulatorManagerWithOptions` (design
// §D9: always-on scheduler). The simulator-wide tick / template interval
// defaults are set here; operators override them via WithFlowTickInterval
// / SetFlowTemplateInterval before creating devices. Safe to call once.
func (sm *SimulatorManager) initFlowSubsystem() {
	// sync.Pool wants pointer-typed values to avoid the extra alloc on
	// every Get/Put pair (staticcheck SA6002); store `*[]byte`.
	sm.flowBufPool.New = func() interface{} {
		buf := make([]byte, flowBufSize)
		return &buf
	}
	sm.flowStopCh = make(chan struct{})
	sm.flowStopOnce = sync.Once{}
	if sm.flowTickInterval == 0 {
		sm.flowTickInterval = defaultFlowTickInterval
	}
	if sm.flowTemplateInterval == 0 {
		sm.flowTemplateInterval = 60 * time.Second
	}
	sm.startFlowTicker()
}

// The flow ticker cadence is configured at construction via
// WithFlowTickInterval, not by a setter. startFlowTicker latches the period, so
// a setter running after the constructor could only write a field nothing
// re-reads — which was nl6#446. The seam is an option deliberately, so the
// ordering cannot regress silently: an option applied too late is a compile-
// time call-site change, whereas a setter called too late looks correct.
//
// SetFlowTemplateInterval overrides the simulator-wide template refresh
// interval (applies to NetFlow v9 / IPFIX). Call before device creation.
// `template_interval` is global per design §D5.
func (sm *SimulatorManager) SetFlowTemplateInterval(d time.Duration) {
	if d > 0 {
		sm.flowTemplateInterval = d
	}
}

// startFlowTicker launches a single background goroutine that calls Tick on
// every active device's FlowExporter at flowTickInterval. The goroutine exits
// when flowStopCh is closed.
func (sm *SimulatorManager) startFlowTicker() {
	// Latch the period SYNCHRONOUSLY, before the goroutine starts, and record
	// it as the cadence the ticker is actually configured with.
	//
	// Two reasons, both still load-bearing after nl6#446 was fixed. First,
	// reading sm.flowTickInterval inside the goroutine would race any write to
	// it. Second, latching makes the reported cadence true BY CONSTRUCTION
	// rather than by the call ordering happening to be right — the report
	// describes what runs even if a future caller reintroduces a late write.
	period := sm.flowTickInterval
	// Floor the invariant HERE rather than trusting every writer of the field
	// to have applied it. time.NewTicker panics on a non-positive period, and
	// the callers that currently guarantee it (WithFlowTickInterval's d > 0
	// gate, initFlowSubsystem's defaulting) are not the only ones that could
	// exist tomorrow.
	if period <= 0 {
		period = defaultFlowTickInterval
	}
	sm.flowTickerPeriod.Store(int64(period))
	sm.flowWg.Add(1)
	go func() {
		defer sm.flowWg.Done()
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				sm.tickAllFlowExporters(now)
			case <-sm.flowStopCh:
				return
			}
		}
	}()
}

// tickAllFlowExporters calls Tick on every device that has a FlowExporter.
// Each exporter supplies its own encoder / collectorAddr; the manager
// supplies the shared-pool fallback socket (looked up by the exporter's
// (collector, protocol) key). Stats are accumulated per-exporter and
// aggregated at status-endpoint read time.
func (sm *SimulatorManager) tickAllFlowExporters(now time.Time) {
	sm.mu.RLock()
	exporters := make([]*FlowExporter, 0, len(sm.devices))
	for _, d := range sm.devices {
		if d.flowExporter != nil {
			exporters = append(exporters, d.flowExporter)
		}
	}
	sm.mu.RUnlock()

	var lastTemplMs int64
	for _, fe := range exporters {
		// D1 flow-cadence adaptation: skip exporters a running scenario owns —
		// its own ticker drives their cadence during [T0,T1). Non-participants
		// and armed-but-not-started participants stay on the fleet cadence.
		if fe.scenDriven.Load() {
			continue
		}
		s := sm.tickFlowExporter(fe, now)
		if s.LastTemplateMs > lastTemplMs {
			lastTemplMs = s.LastTemplateMs
		}
	}
	if lastTemplMs > 0 {
		sm.flowStatLastTmpl.Store(lastTemplMs)
	}
}

// tickFlowExporter ticks one exporter with the shared-pool fallback socket and
// folds its stats. Shared by the fleet ticker and the scenario-owned flow
// ticker (D1 cadence adaptation) so both take the identical wire path.
func (sm *SimulatorManager) tickFlowExporter(fe *FlowExporter, now time.Time) FlowTickStats {
	var sharedConn *net.UDPConn
	if fe.conn.Load() == nil {
		sharedConn = sm.flowConnFor(flowConnKey{collector: fe.collectorStr, protocol: fe.protocol})
	}
	s := fe.Tick(now, sharedConn, &sm.flowBufPool)
	// Unguarded: the old `if s.PacketsSent > 0` skip was harmless while every
	// tick that did anything incremented PacketsSent, but nl6#491 split
	// failures out — and on a tick where EVERY write failed, PacketsSent is 0,
	// so that guard would have swallowed the failure count too. A counter that
	// cannot record the thing it exists for is worse than no counter. Adding
	// zero is free.
	fe.statPackets.Add(s.PacketsSent)
	fe.statFailures.Add(s.SendFailures)
	fe.statBytes.Add(s.BytesSent)
	fe.statRecords.Add(s.RecordsSent)
	return s
}

// GetFlowStatus returns the aggregated flow-export snapshot. Devices
// sharing the same (collector, protocol) tuple collapse into one record
// in the `Collectors` array. Counters are MONOTONIC since simulator
// start: live exporters' per-tick counters are summed with the
// per-collector aggregates persisted when earlier devices were deleted
// (review decision D1.b), so Prometheus-style consumers never see
// counter resets mid-run.
//
// BREAKING (per-device-export-config phase 3): returns the new
// array-of-collectors shape. The legacy scalar fields are retired;
// callers detect "feature off" via `len(collectors) == 0`.
func (sm *SimulatorManager) GetFlowStatus() FlowStatus {
	agg := make(map[flowConnKey]*FlowCollectorStatus)

	sm.mu.RLock()
	for _, d := range sm.devices {
		fe := d.flowExporter
		if fe == nil {
			continue
		}
		k := flowConnKey{collector: fe.collectorStr, protocol: fe.protocol}
		rec, ok := agg[k]
		if !ok {
			rec = &FlowCollectorStatus{
				Collector: fe.collectorStr,
				Protocol:  fe.protocol,
			}
			agg[k] = rec
		}
		rec.Devices++
		rec.SentPackets += fe.statPackets.Load()
		rec.SendFailures += fe.statFailures.Load()
		rec.SentBytes += fe.statBytes.Load()
		rec.SentRecords += fe.statRecords.Load()
	}
	sm.mu.RUnlock()

	// Fold persisted counters for tuples whose devices have since been
	// deleted (or that have a live device AND historical deletions).
	// A tuple with no live exporters still shows up in the output with
	// Devices=0 so the monotonic totals remain visible.
	sm.flowAggregates.Range(func(k, v interface{}) bool {
		key := k.(flowConnKey)
		pers := v.(*flowCollectorAggregate)
		rec, ok := agg[key]
		if !ok {
			rec = &FlowCollectorStatus{
				Collector: key.collector,
				Protocol:  key.protocol,
			}
			agg[key] = rec
		}
		rec.SentPackets += pers.packets.Load()
		rec.SendFailures += pers.failures.Load()
		rec.SentBytes += pers.bytes.Load()
		rec.SentRecords += pers.records.Load()
		return true
	})

	collectors := make([]FlowCollectorStatus, 0, len(agg))
	totalDevices := 0
	for _, rec := range agg {
		collectors = append(collectors, *rec)
		totalDevices += rec.Devices
	}

	var lastTemplate string
	if ms := sm.flowStatLastTmpl.Load(); ms > 0 {
		lastTemplate = time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
	}

	return FlowStatus{
		Collectors:       collectors,
		DevicesExporting: totalDevices,
		LastTemplateSend: lastTemplate,
	}
}
