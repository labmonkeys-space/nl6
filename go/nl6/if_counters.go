/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IF-MIB prefixes for the dynamic counter dispatcher.
const (
	ifTablePrefix  = ".1.3.6.1.2.1.2.2.1."    // ifTable (RFC 2863)
	ifXTablePrefix = ".1.3.6.1.2.1.31.1.1.1." // ifXTable (RFC 2863)

	// Legacy HC-only prefixes — kept for GetHCOctets forwarding and
	// for out-of-package callers (counter_source.go) during the refactor.
	hcInOIDPrefix  = ifXTablePrefix + "6."
	hcOutOIDPrefix = ifXTablePrefix + "10."

	hcPeriodSec = 3600.0 // 1-hour sine-wave cycle

	// maxResourceIfIndex caps the largest ifIndex accepted from a
	// resource JSON file. NewInterfaceState allocates one
	// atomic.Uint64 per ifIndex up to maxIfIndex, so a corrupted file
	// listing e.g. .6.4000000000 would otherwise drive a ~32 GB
	// allocation. 65535 is comfortably above realistic device
	// interface counts.
	maxResourceIfIndex = 65535
)

// ifXTable and ifTable column numbers handled dynamically.
const (
	// ifXTable (.1.3.6.1.2.1.31.1.1.1.X)
	colIfInMulticastPkts    = 2
	colIfInBroadcastPkts    = 3
	colIfOutMulticastPkts   = 4
	colIfOutBroadcastPkts   = 5
	colIfHCInOctets         = 6
	colIfHCInUcastPkts      = 7
	colIfHCInMulticastPkts  = 8
	colIfHCInBroadcastPkts  = 9
	colIfHCOutOctets        = 10
	colIfHCOutUcastPkts     = 11
	colIfHCOutMulticastPkts = 12
	colIfHCOutBroadcastPkts = 13

	// ifTable (.1.3.6.1.2.1.2.2.1.X)
	colIfAdminStatus  = 7
	colIfOperStatus   = 8
	colIfLastChange   = 9
	colIfInOctets     = 10
	colIfInUcastPkts  = 11
	colIfInDiscards   = 13
	colIfInErrors     = 14
	colIfOutOctets    = 16
	colIfOutUcastPkts = 17
	colIfOutDiscards  = 19
	colIfOutErrors    = 20
)

// ifCyclerColumns lists every (table, column) pair the cycler owns, in
// strict MIB lex order. Walk enumeration (NextDynamicOID) iterates this
// list, and ordering must match compareOIDs — the 7th sub-identifier
// puts ifTable (2.2.1) strictly before ifXTable (31.1.1.1) numerically,
// and within each table the column numbers are ascending.
var ifCyclerColumns = []struct {
	prefix string
	col    int
}{
	{ifTablePrefix, colIfAdminStatus},         // .7  (state engine)
	{ifTablePrefix, colIfOperStatus},          // .8  (state engine)
	{ifTablePrefix, colIfLastChange},          // .9  (state engine)
	{ifTablePrefix, colIfInOctets},            // .10 (shadow of ifXTable .6)
	{ifTablePrefix, colIfInUcastPkts},         // .11
	{ifTablePrefix, colIfInDiscards},          // .13
	{ifTablePrefix, colIfInErrors},            // .14
	{ifTablePrefix, colIfOutOctets},           // .16 (shadow of ifXTable .10)
	{ifTablePrefix, colIfOutUcastPkts},        // .17
	{ifTablePrefix, colIfOutDiscards},         // .19
	{ifTablePrefix, colIfOutErrors},           // .20
	{ifXTablePrefix, colIfInMulticastPkts},    // .2
	{ifXTablePrefix, colIfInBroadcastPkts},    // .3
	{ifXTablePrefix, colIfOutMulticastPkts},   // .4
	{ifXTablePrefix, colIfOutBroadcastPkts},   // .5
	{ifXTablePrefix, colIfHCInOctets},         // .6
	{ifXTablePrefix, colIfHCInUcastPkts},      // .7
	{ifXTablePrefix, colIfHCInMulticastPkts},  // .8
	{ifXTablePrefix, colIfHCInBroadcastPkts},  // .9
	{ifXTablePrefix, colIfHCOutOctets},        // .10
	{ifXTablePrefix, colIfHCOutUcastPkts},     // .11
	{ifXTablePrefix, colIfHCOutMulticastPkts}, // .12
	{ifXTablePrefix, colIfHCOutBroadcastPkts}, // .13
}

// stateEnumStrings is a lookup table mapping IF-MIB integer enum values
// to their decimal-string SNMP wire encoding. Avoids per-call
// `strconv.Itoa` allocation on the hot read path. Index 0 is the
// uninitialised / out-of-range default ("0").
var stateEnumStrings = [8]string{"0", "1", "2", "3", "4", "5", "6", "7"}

// operEnumString converts an IF-MIB ifOperStatus value (legal range
// 1..7, RFC 2863) to its SNMP decimal string without allocating.
// Values outside the legal range render as `"0"` — wire-invalid, but
// matches the engine's "never emit out-of-range" contract: a
// regression that lets such a value escape OperStatus surfaces as a
// loud SNMP value of "0" rather than misencoding as an in-range enum.
func operEnumString(v uint8) string {
	if v < OperUp || v > OperLowerLayerDn {
		return "0"
	}
	return stateEnumStrings[v]
}

// adminEnumString converts an IF-MIB ifAdminStatus value (legal range
// 1..3, RFC 2863) to its SNMP decimal string without allocating.
// Values outside the legal admin range render as `"0"` even when they
// would have been valid as an ifOperStatus value (e.g. 4..7); the
// type-split prevents an oper-range value from being misencoded as
// admin if a future refactor crosses wires.
func adminEnumString(v uint8) string {
	if v < AdminUp || v > AdminTesting {
		return "0"
	}
	return stateEnumStrings[v]
}

// isStateCol returns true if (prefix, col) names one of the three
// state-engine-owned ifTable columns: ifAdminStatus (.7), ifOperStatus
// (.8), ifLastChange (.9). Used by NextDynamicOID to skip these
// columns in the rare test-harness path where the cycler was
// constructed without a state engine.
func isStateCol(col int, prefix string) bool {
	return prefix == ifTablePrefix && (col == colIfAdminStatus || col == colIfOperStatus || col == colIfLastChange)
}

// IfErrorScenario controls per-device error / discard counter behavior.
// Scenarios scale the errors-per-million (errPpm) and discards-per-million
// (discPpm) drawn for each interface at init time; other counter columns
// are unaffected.
type IfErrorScenario string

const (
	IfErrorClean    IfErrorScenario = "clean"
	IfErrorTypical  IfErrorScenario = "typical"
	IfErrorDegraded IfErrorScenario = "degraded"
	IfErrorFailing  IfErrorScenario = "failing"
)

// ParseIfErrorScenario canonicalises s (case-insensitive) to one of the
// four known scenarios. Empty input maps to IfErrorClean. Unknown values
// return an error naming the accepted scenarios so the validation
// message is self-service on both the CLI and the REST surface.
func ParseIfErrorScenario(s string) (IfErrorScenario, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(IfErrorClean):
		return IfErrorClean, nil
	case string(IfErrorTypical):
		return IfErrorTypical, nil
	case string(IfErrorDegraded):
		return IfErrorDegraded, nil
	case string(IfErrorFailing):
		return IfErrorFailing, nil
	default:
		return "", fmt.Errorf("invalid if_error_scenario %q (accepted: clean, typical, degraded, failing)", s)
	}
}

// scenarioBand returns the errors-per-million and discards-per-million
// ranges for a scenario. Each interface draws its per-direction ppm
// uniformly within the band at init time.
func scenarioBand(s IfErrorScenario) (errLo, errHi, discLo, discHi uint32) {
	switch s {
	case IfErrorTypical:
		return 10, 100, 20, 200
	case IfErrorDegraded:
		return 1_000, 10_000, 2_000, 20_000
	case IfErrorFailing:
		return 10_000, 100_000, 20_000, 200_000
	default: // IfErrorClean and any unknown value (defensive)
		return 0, 0, 0, 0
	}
}

// IfCounterCycler generates monotonically increasing counter values for
// the IF-MIB ifTable and ifXTable columns listed below, all derived
// analytically from a single per-direction sine wave so packet /
// multicast / broadcast / error / discard counters track link busyness.
//
// Counter64 HC columns (ifXTable):
//
//	.6  ifHCInOctets              ← master dial, inbound
//	.7  ifHCInUcastPkts
//	.8  ifHCInMulticastPkts
//	.9  ifHCInBroadcastPkts
//	.10 ifHCOutOctets              ← master dial, outbound
//	.11 ifHCOutUcastPkts
//	.12 ifHCOutMulticastPkts
//	.13 ifHCOutBroadcastPkts
//
// Counter32 shadow columns (ifXTable):
//
//	.2 ifInMulticastPkts      = low-32 of HC .8
//	.3 ifInBroadcastPkts      = low-32 of HC .9
//	.4 ifOutMulticastPkts     = low-32 of HC .12
//	.5 ifOutBroadcastPkts     = low-32 of HC .13
//
// Counter32 columns (ifTable):
//
//	.10 ifInOctets            = low-32 of HC .6   (de-facto shadow, nl6#570)
//	.11 ifInUcastPkts         = low-32 of HC .7
//	.13 ifInDiscards          = base + totalInPkts  × discPpmIn  / 1e6
//	.14 ifInErrors            = base + totalInPkts  × errPpmIn   / 1e6
//	.16 ifOutOctets           = low-32 of HC .10  (de-facto shadow, nl6#570)
//	.17 ifOutUcastPkts        = low-32 of HC .11
//	.19 ifOutDiscards         = base + totalOutPkts × discPpmOut / 1e6
//	.20 ifOutErrors           = base + totalOutPkts × errPpmOut  / 1e6
//
// Formula per interface i at time t seconds since device start:
//
//	octets_in(t)  = baseInOctets  + ifSpeed_Bps/8 × [0.8·t + (0.2·T/2π)·(cos(φᵢⁿ)  − cos(2π·t/T + φᵢⁿ))]
//	octets_out(t) = baseOutOctets + ifSpeed_Bps/8 × [0.8·t + (0.2·T/2π)·(cos(φᵢᵒᵘᵗ) − cos(2π·t/T + φᵢᵒᵘᵗ))]
//	totalInPkts(t)  = octets_in(t)  / pktSizeIn[i]
//	totalOutPkts(t) = octets_out(t) / pktSizeOut[i]
//
// where T = 3600 s and φᵢ is a per-interface random phase offset. The
// rate never falls below 60 % of capacity, so every derived counter is
// strictly monotonic.
//
// Thread safety: all fields are written once by InitIfCounters before
// the cycler is published via MetricsCycler.ifCounters.Store(ic), and
// the pointed-to IfCounterCycler is immutable after Store —
// re-initialisation means building a fresh instance and calling Store
// again with the new pointer. All readers must call
// MetricsCycler.ifCounters.Load() at the top of the function and
// operate on the captured local; the atomic Load/Store pair plus the
// immutable-after-Store contract means concurrent reads in GetDynamic
// are safe even across a future reset / rescenario control plane.
type IfCounterCycler struct {
	startTime      time.Time
	maxIfIndex     int              // upper bound for array indexing
	knownIfIndexes map[int]struct{} // exact set of ifIndex values present in oidIndex
	// ifIndexList caches knownIfIndexes as a slice so IfIndices is
	// allocation-free on the hot path (trap varbind template resolution
	// calls it per fire). Populated once in InitIfCounters; read-only after.
	ifIndexList []int
	// sortedIfIndexes is ifIndexList sorted ascending — required so
	// NextDynamicOID emits rows in MIB lex order during SNMP walks.
	sortedIfIndexes []int
	// firstDynOID / lastDynOID bracket the entire set of OIDs this
	// cycler owns. findNextOID uses them to decide whether the static
	// "next OID" fast path is safe without scanning every cycler row.
	firstDynOID string
	lastDynOID  string
	ifSpeedBps  []uint64 // per-interface link speed in bps (slot = ifIndex-1)

	// Octet-cycler dials (existing).
	baseInOctets  []uint64  // per-interface starting octet counter (in)
	baseOutOctets []uint64  // per-interface starting octet counter (out)
	phaseIn       []float64 // per-interface random phase offset in [0, 2π)
	phaseOut      []float64

	// Packet-derivation inputs, jittered per interface at init.
	pktSizeIn     []float64 // avg bytes/packet inbound (500 ±20%)
	pktSizeOut    []float64 // avg bytes/packet outbound
	ucastRatioIn  []float64 // 0..1; ucast+mcast+bcast = 1.0 per direction
	mcastRatioIn  []float64
	bcastRatioIn  []float64
	ucastRatioOut []float64
	mcastRatioOut []float64
	bcastRatioOut []float64

	// Pre-seeded bases for each packet-count column, so a fresh device
	// looks like it has been running ~24h on the first poll.
	baseInUcast  []uint64
	baseInMcast  []uint64
	baseInBcast  []uint64
	baseOutUcast []uint64
	baseOutMcast []uint64
	baseOutBcast []uint64

	// Scenario-driven error / discard rates (ppm of packets), plus bases.
	errPpmIn    []uint32
	errPpmOut   []uint32
	discPpmIn   []uint32
	discPpmOut  []uint32
	baseInErr   []uint64
	baseOutErr  []uint64
	baseInDisc  []uint64
	baseOutDisc []uint64

	// state is the interface state engine (oper-status, admin-status,
	// last-change per ifIndex). Source of truth for the three IF-MIB
	// state columns (.7, .8, .9) served via GetDynamicAt, and for the
	// gNMI `state/*` leaves. Set by InitIfCountersWithScenario.
	state *InterfaceState
}

// State returns the interface state engine owned by this cycler. May be
// nil for cyclers constructed outside InitIfCountersWithScenario (test
// harnesses); callers must nil-check.
func (ic *IfCounterCycler) State() *InterfaceState {
	if ic == nil {
		return nil
	}
	return ic.state
}

// IfIndices returns the cached slice of known ifIndex values for this
// device. Used by trap templating ({{.IfIndex}}) to pick a random
// interface per fire. Returns nil when the device has no indexed
// interfaces.
//
// The returned slice is a shared read-only view — callers must NOT
// mutate it. Indexing with `rand.Intn(len(slice))` is the intended usage.
func (ic *IfCounterCycler) IfIndices() []int {
	if ic == nil {
		return nil
	}
	return ic.ifIndexList
}

// GetDynamic returns the current dynamic counter value for any
// ifTable / ifXTable OID this cycler handles, or "" if the OID is not
// in the dynamic-counter set for a known interface index.
//
// Each call reads the wall-clock for a fresh evaluation instant — safe
// when the caller only needs one column. For multi-column coherence
// (e.g. the Counter32 shadow must equal uint32(Counter64HC & 0xFFFFFFFF)
// at the same moment; sFlow counter_sample must match a concurrent SNMP
// GET across 11 columns) use GetDynamicAt with a single captured t.
//
// Returned values are decimal strings — the SNMP encoder wraps them as
// the appropriate Counter32 or Counter64 based on oidTypeTable
// (snmp_encoding.go).
func (ic *IfCounterCycler) GetDynamic(oid string) string {
	if ic == nil {
		return ""
	}
	return ic.GetDynamicAt(oid, time.Since(ic.startTime).Seconds())
}

// GetDynamicAt evaluates the cycler at a caller-supplied t (seconds
// since the cycler's startTime). Callers that need a coherent snapshot
// across several columns capture t once with
// `time.Since(ic.startTime).Seconds()` and pass the same value to every
// lookup — guarantees shadow == low-32(HC) byte-for-byte, and makes
// sFlow counter_sample values match a concurrent SNMP GET exactly.
func (ic *IfCounterCycler) GetDynamicAt(oid string, t float64) string {
	if ic == nil {
		return ""
	}

	// Parse "<prefix><column>.<ifIndex>" → (column, ifIndex). The
	// prefix test is a single HasPrefix per table to avoid iterating
	// every column constant.
	var (
		suffix string
		ifX    bool
	)
	switch {
	case strings.HasPrefix(oid, ifXTablePrefix):
		suffix = oid[len(ifXTablePrefix):]
		ifX = true
	case strings.HasPrefix(oid, ifTablePrefix):
		suffix = oid[len(ifTablePrefix):]
	default:
		return ""
	}
	// suffix is "<column>.<ifIndex>"
	dot := strings.IndexByte(suffix, '.')
	if dot <= 0 || dot == len(suffix)-1 {
		return ""
	}
	col, err := strconv.Atoi(suffix[:dot])
	if err != nil {
		return ""
	}
	ifIndex, err := strconv.Atoi(suffix[dot+1:])
	if err != nil || ifIndex < 1 || ifIndex > ic.maxIfIndex {
		return ""
	}
	if _, known := ic.knownIfIndexes[ifIndex]; !known {
		return ""
	}
	slot := ifIndex - 1

	// State OIDs (.7 ifAdminStatus, .8 ifOperStatus, .9 ifLastChange)
	// are pure lookups against the state engine — skip the delta
	// computation below. The state engine is the single source of
	// truth; oidIndex retains the initial JSON values only as a
	// boot-time seed, never read on the hot path.
	//
	// **RFC-2863 caveat:** `ifLastChange` is specified as "value of
	// sysUpTime at the time the interface entered its current
	// operational state". We measure from the state-engine
	// construction time (`bootTimeUnixNs`), not the SNMP agent's
	// `sysUpTime`. Today `InitIfCountersWithScenario` runs exactly once
	// per device (guarded against re-init via panic) so the two
	// epochs coincide. If a future "reload scenario" feature is added,
	// the divergence must be re-examined.
	if !ifX && ic.state != nil {
		switch col {
		case colIfAdminStatus:
			return adminEnumString(ic.state.AdminStatus(ifIndex))
		case colIfOperStatus:
			return operEnumString(ic.state.OperStatus(ifIndex))
		case colIfLastChange:
			// TimeTicks (hundredths of a second since the state-engine
			// boot epoch). Pre-transition slots render as "0"; rewind-
			// sentinel slots also render as "0" (rewind is observable
			// elsewhere via the wallRelNs log + LastChangeRewindSentinel
			// in StateChange.LastChangeNs).
			lastUnixNs := ic.state.LastChangeNs(ifIndex)
			if lastUnixNs == LastChangeRewindSentinel || lastUnixNs <= ic.state.bootTimeUnixNs {
				return "0"
			}
			return strconv.FormatUint((lastUnixNs-ic.state.bootTimeUnixNs)/10_000_000, 10)
		}
	}

	// Live delta octets = octetsAt(t) − baseInOctets. We work in
	// delta-space for packet / error / discard derivations because the
	// pre-seed bases (baseInUcast, baseInErr, …) are themselves
	// derived from baseInOctets at init; adding another
	// ratio × baseInOctets here would double-count the pre-seed.
	inDelta := ic.deltaOctetsAt(slot, t, true)
	outDelta := ic.deltaOctetsAt(slot, t, false)

	// Dispatch by (table, column). Ordering below mirrors the MIB
	// column numbering so the intent is obvious when reading.
	if ifX {
		switch col {
		// Counter32 shadows of Counter64 HC packet columns.
		case colIfInMulticastPkts:
			return fmtU32(uint32(ic.packets(slot, inDelta, true, true, false, false) & 0xFFFFFFFF))
		case colIfInBroadcastPkts:
			return fmtU32(uint32(ic.packets(slot, inDelta, true, false, true, false) & 0xFFFFFFFF))
		case colIfOutMulticastPkts:
			return fmtU32(uint32(ic.packets(slot, outDelta, false, true, false, false) & 0xFFFFFFFF))
		case colIfOutBroadcastPkts:
			return fmtU32(uint32(ic.packets(slot, outDelta, false, false, true, false) & 0xFFFFFFFF))

		// Counter64 HC columns.
		case colIfHCInOctets:
			return fmtU64(ic.baseInOctets[slot] + inDelta)
		case colIfHCInUcastPkts:
			return fmtU64(ic.packets(slot, inDelta, true, false, false, true))
		case colIfHCInMulticastPkts:
			return fmtU64(ic.packets(slot, inDelta, true, true, false, false))
		case colIfHCInBroadcastPkts:
			return fmtU64(ic.packets(slot, inDelta, true, false, true, false))
		case colIfHCOutOctets:
			return fmtU64(ic.baseOutOctets[slot] + outDelta)
		case colIfHCOutUcastPkts:
			return fmtU64(ic.packets(slot, outDelta, false, false, false, true))
		case colIfHCOutMulticastPkts:
			return fmtU64(ic.packets(slot, outDelta, false, true, false, false))
		case colIfHCOutBroadcastPkts:
			return fmtU64(ic.packets(slot, outDelta, false, false, true, false))
		}
		return ""
	}
	// ifTable
	switch col {
	// Counter32 shadows of the two Counter64 HC octet columns
	// (nl6#570).
	//
	// RFC 2863 does NOT mandate the low-32 equality, and an earlier
	// version of this comment said it did. What the RFC says: the
	// ifXTable DESCRIPTION of ifHCInOctets calls it "a 64-bit version
	// of ifInOctets", and §3.1.6 mandates only which WIDTH to serve at
	// which speed (32-bit octet counters at or below 20 Mb/s, 64-bit
	// above). A conforming agent may hold the two counters
	// independently. Deriving one from the other is nl6's deliberate
	// choice, matching the de-facto convention every agent this
	// simulator stands in for follows, and it is what makes the two
	// columns impossible to contradict each other.
	//
	// Both are computed from the SAME inDelta / outDelta the HC column
	// uses — one evaluation of the dial at the caller's t, never stored
	// and never a second call to deltaOctetsAt. The identity therefore
	// holds exactly for a caller that passes ONE t across both columns
	// (GetDynamicAt: sFlow counter_sample, gNMI). It does NOT hold
	// across two GetDynamic calls, which read the clock separately —
	// see GetDynamic's own doc comment, and the caveat in
	// docs/reference/snmp.md about the per-OID SNMP path.
	//
	// The & 0xFFFFFFFF is redundant under the uint32 conversion and is
	// kept only to match the neighbouring shadow columns; the
	// conversion is what implements the wrap.
	case colIfInOctets:
		return fmtU32(uint32((ic.baseInOctets[slot] + inDelta) & 0xFFFFFFFF))
	case colIfOutOctets:
		return fmtU32(uint32((ic.baseOutOctets[slot] + outDelta) & 0xFFFFFFFF))
	case colIfInUcastPkts:
		return fmtU32(uint32(ic.packets(slot, inDelta, true, false, false, true) & 0xFFFFFFFF))
	case colIfOutUcastPkts:
		return fmtU32(uint32(ic.packets(slot, outDelta, false, false, false, true) & 0xFFFFFFFF))
	case colIfInErrors:
		// total live packets (ucast + mcast + bcast) = deltaOctets / pktSize.
		// Ratios sum to 1 per direction, so we can skip re-splitting.
		totalDeltaPkts := uint64(float64(inDelta) / safePktSize(ic.pktSizeIn[slot]))
		return fmtU32(uint32((ic.baseInErr[slot] + totalDeltaPkts*uint64(ic.errPpmIn[slot])/1_000_000) & 0xFFFFFFFF))
	case colIfInDiscards:
		totalDeltaPkts := uint64(float64(inDelta) / safePktSize(ic.pktSizeIn[slot]))
		return fmtU32(uint32((ic.baseInDisc[slot] + totalDeltaPkts*uint64(ic.discPpmIn[slot])/1_000_000) & 0xFFFFFFFF))
	case colIfOutErrors:
		totalDeltaPkts := uint64(float64(outDelta) / safePktSize(ic.pktSizeOut[slot]))
		return fmtU32(uint32((ic.baseOutErr[slot] + totalDeltaPkts*uint64(ic.errPpmOut[slot])/1_000_000) & 0xFFFFFFFF))
	case colIfOutDiscards:
		totalDeltaPkts := uint64(float64(outDelta) / safePktSize(ic.pktSizeOut[slot]))
		return fmtU32(uint32((ic.baseOutDisc[slot] + totalDeltaPkts*uint64(ic.discPpmOut[slot])/1_000_000) & 0xFFFFFFFF))
	}
	return ""
}

// FirstDynamicOID returns the smallest OID this cycler owns. Empty
// string when the cycler has no rows.
func (ic *IfCounterCycler) FirstDynamicOID() string {
	if ic == nil {
		return ""
	}
	return ic.firstDynOID
}

// LastDynamicOID returns the largest OID this cycler owns. Empty string
// when the cycler has no rows.
func (ic *IfCounterCycler) LastDynamicOID() string {
	if ic == nil {
		return ""
	}
	return ic.lastDynOID
}

// NextDynamicOID returns the next (oid, value) pair the cycler owns that
// is strictly greater than currentOID in MIB lex order. Returns ("", "")
// when currentOID is at or past the last dynamic row.
//
// This is the walk counterpart to GetDynamic — without it, snmpwalk on a
// column whose instances are not declared in the device's static JSON
// (e.g. ifHCInMulticastPkts on many device types) would skip the whole
// column because findNextOID only enumerates OIDs that already exist in
// oidIndex / sortedOIDs.
//
// Implementation is O(log N) in the number of interfaces: parse
// currentOID once into (table, col, ifIndex), locate the column
// position in `ifCyclerColumns` by linear scan (the slice is small
// and grows rarely; len-driven so additions are picked up
// automatically), and use sort.SearchInts on sortedIfIndexes to find
// the successor ifIndex. The previous O(cols × ifIndexes)
// implementation built and compared an OID string for every (col,
// ifIndex) pair on each GETNEXT step, which made walking a
// 1000-interface device ~18000 string allocations per step.
func (ic *IfCounterCycler) NextDynamicOID(currentOID string) (string, string) {
	if ic == nil || len(ic.sortedIfIndexes) == 0 {
		return "", ""
	}
	t := time.Since(ic.startTime).Seconds()

	// Parse currentOID into (isIfX, col, ifIndex). The two outcomes that
	// matter for routing are:
	//   - matched=true, haveCol=true:  search inside the cycler range
	//   - everything else:             jump to first owned OID if currentOID
	//                                  sorts before it, else end of walk
	var (
		suffix  string
		isIfX   bool
		matched bool
	)
	switch {
	case strings.HasPrefix(currentOID, ifXTablePrefix):
		suffix = currentOID[len(ifXTablePrefix):]
		isIfX = true
		matched = true
	case strings.HasPrefix(currentOID, ifTablePrefix):
		suffix = currentOID[len(ifTablePrefix):]
		matched = true
	}

	// stateNil short-circuits the state-engine-owned ifTable columns
	// (.7 ifAdminStatus, .8 ifOperStatus, .9 ifLastChange) when the
	// cycler was constructed without a state engine (test-harness path:
	// caller built IfCounterCycler directly, not via
	// InitIfCountersWithScenario). With stateNil the walk skips those
	// columns and starts at colIfInUcastPkts as it did pre-change.
	stateNil := ic.state == nil

	// emitFromColumn returns the (oid, value) for column at index colIdx in
	// ifCyclerColumns, at the supplied ifIndex. When the state engine is
	// nil and the column is one of the state cols (.7/.8/.9), advance to
	// the next non-state column rather than returning "" and bailing the
	// walk to end-of-walk prematurely.
	emitFromColumn := func(colIdx, ifIndex int) (string, string) {
		if stateNil {
			for colIdx < len(ifCyclerColumns) && isStateCol(ifCyclerColumns[colIdx].col, ifCyclerColumns[colIdx].prefix) {
				colIdx++
			}
			if colIdx >= len(ifCyclerColumns) {
				return "", ""
			}
		}
		c := ifCyclerColumns[colIdx]
		oid := c.prefix + strconv.Itoa(c.col) + "." + strconv.Itoa(ifIndex)
		val := ic.GetDynamicAt(oid, t)
		if val == "" {
			// Defensive: every (owned col, owned ifIndex) pair must
			// resolve. Falling through to "" here means a config /
			// init mismatch — surface as end-of-walk rather than
			// looping.
			return "", ""
		}
		return oid, val
	}

	if !matched {
		// currentOID is outside the cycler's prefix range. If it sorts
		// before our first OID, start at the first owned row; if it
		// sorts at or past our last OID, the walk is done.
		if compareOIDs(currentOID, ic.firstDynOID) < 0 {
			return emitFromColumn(0, ic.sortedIfIndexes[0])
		}
		return "", ""
	}

	// Parse the suffix into (col, ifIndex). Tolerate forms that lack an
	// ifIndex ("<col>" or "<col>.") by treating the missing ifIndex as 0
	// — successor lookup will then return the first owned ifIndex.
	var (
		col, ifIndex int
		haveCol      bool
		// pastCol means currentOID sits inside a column the cycler owns but
		// NOT at a row that can be ordered against that column's rows. The
		// successor must then be the next COLUMN: any row inside this one
		// might sort below currentOID, which is the nl6#526 class (a
		// non-increasing walk, which snmp4j reports as "OID not increasing"
		// or hangs on). Cheaper to skip a column than to emit below.
		pastCol bool
	)
	if dot := strings.IndexByte(suffix, '.'); dot > 0 {
		if c, err := strconv.Atoi(suffix[:dot]); err == nil {
			col, haveCol = c, true
			inst := suffix[dot+1:]
			// A request may name MORE sub-identifiers than the column's INDEX
			// needs — ".10.5.7" is a well-formed varbind name and reaches here
			// from the wire. It sits inside row .10.5, and the successor must be
			// strictly greater than ".10.5.7", so taking the FIRST component and
			// searching for ifIndex+1 is both correct and exactly what the
			// single-component case already does. Parsing "5.7" whole fails, and
			// a failed parse used to leave ifIndex at 0, which emitted .10.1 —
			// below currentOID.
			if extra := strings.IndexByte(inst, '.'); extra >= 0 {
				inst = inst[:extra]
			}
			switch idx, err := strconv.Atoi(inst); {
			case inst == "":
				// "<col>." — no instance at all. ifIndex stays 0, so the
				// successor search lands on the first owned row, which is
				// greater than the bare column prefix.
			case err != nil:
				// A non-numeric instance cannot be positioned among numeric
				// rows. Not reachable from the wire (decodeOID emits digits
				// only) but reachable from in-package callers.
				pastCol = true
			case idx < 0:
				// Likewise unorderable, and likewise unreachable from the wire:
				// decodeOID refuses a negative arc (nl6#529).
				pastCol = true
			default:
				ifIndex = idx
			}
		}
	} else if dot < 0 && suffix != "" {
		if c, err := strconv.Atoi(suffix); err == nil {
			col, haveCol = c, true
		}
	}

	if !haveCol {
		// Suffix was empty or unparseable — currentOID sits at the
		// table prefix itself (e.g. ".1.3.6.1.2.1.2.2.1."). Land on
		// the first owned column of the matching table.
		for i, tc := range ifCyclerColumns {
			entryIsIfX := tc.prefix == ifXTablePrefix
			if entryIsIfX == isIfX {
				return emitFromColumn(i, ic.sortedIfIndexes[0])
			}
		}
		return "", ""
	}

	// Locate the first ifCyclerColumns entry whose (table, col) is at
	// or after the parsed (isIfX, col). Linear scan is faster than
	// sort.Search on a slice this small.
	colIdx := -1
	for i, tc := range ifCyclerColumns {
		entryIsIfX := tc.prefix == ifXTablePrefix
		switch {
		case isIfX && !entryIsIfX:
			// currentOID is in ifXTable; skip ifTable entries.
			continue
		case !isIfX && entryIsIfX:
			// currentOID is in ifTable but col is past every owned
			// ifTable column — first ifXTable entry is the target.
			colIdx = i
		default:
			// Same table. Take the first owned col >= parsed col.
			if tc.col >= col {
				colIdx = i
			}
		}
		if colIdx >= 0 {
			break
		}
	}
	if colIdx < 0 {
		// Past every owned column — end of walk.
		return "", ""
	}

	chosen := ifCyclerColumns[colIdx]
	chosenIsIfX := chosen.prefix == ifXTablePrefix
	if chosenIsIfX == isIfX && chosen.col == col {
		// stateNil short-circuit: if the parsed col is a state col
		// (.7/.8/.9) and the cycler has no state engine, the column
		// is unowned. The correct successor is the first non-state
		// col at the first owned ifIndex — not ifIndex+1 on the
		// state col itself. emitFromColumn advances colIdx past the
		// state cols so the right (col, ifIndex) pair is emitted.
		if stateNil && isStateCol(chosen.col, chosen.prefix) {
			return emitFromColumn(colIdx, ic.sortedIfIndexes[0])
		}
		if pastCol {
			// currentOID is inside this column at an unorderable row, so no row
			// of this column is provably greater. The next column is.
			if colIdx+1 >= len(ifCyclerColumns) {
				return "", ""
			}
			return emitFromColumn(colIdx+1, ic.sortedIfIndexes[0])
		}
		// Same column as currentOID — find the successor ifIndex.
		pos := sort.SearchInts(ic.sortedIfIndexes, ifIndex+1)
		if pos < len(ic.sortedIfIndexes) {
			return emitFromColumn(colIdx, ic.sortedIfIndexes[pos])
		}
		// All ifIndexes in this column already walked — advance to the
		// next owned column at its first ifIndex.
		if colIdx+1 >= len(ifCyclerColumns) {
			return "", ""
		}
		return emitFromColumn(colIdx+1, ic.sortedIfIndexes[0])
	}
	// Advanced past currentOID's column — emit at first ifIndex.
	return emitFromColumn(colIdx, ic.sortedIfIndexes[0])
}

// safePktSize shields every pktSize-divided derivation from a zero or
// negative divisor. Init draws pktSize from [400, 600] so this is
// unreachable today, but widening the jitter or allowing an operator
// override would turn an unguarded division into a silent 0 / NaN /
// implementation-defined cast. Centralising the guard keeps future
// refactors from drifting behavior across branches.
func safePktSize(v float64) float64 {
	if v <= 0 {
		return 500
	}
	return v
}

// GetHCOctets is a backward-compatible forwarder to GetDynamic for the
// two HC octet OIDs.
//
// Deprecated: call GetDynamic directly. Kept for one release so
// out-of-package callers that still reference GetHCOctets keep working
// during the transition.
func (ic *IfCounterCycler) GetHCOctets(oid string) string {
	switch {
	case strings.HasPrefix(oid, hcInOIDPrefix), strings.HasPrefix(oid, hcOutOIDPrefix):
		return ic.GetDynamic(oid)
	}
	return ""
}

// deltaOctetsAt evaluates just the growth term of the sine-wave octet
// integral (octets added since device start at time t = 0). Clamps to
// zero for the t≈0 floating-point case where the integral's cosine
// difference can produce a tiny negative value. Callers wanting the
// total-octets value (base + delta) must add baseIn/baseOut themselves
// so all downstream derivations work in the same delta-space as the
// pre-seed bases.
func (ic *IfCounterCycler) deltaOctetsAt(slot int, t float64, inbound bool) uint64 {
	speedBytesPerSec := float64(ic.ifSpeedBps[slot]) / 8.0
	var phase float64
	if inbound {
		phase = ic.phaseIn[slot]
	} else {
		phase = ic.phaseOut[slot]
	}
	T := hcPeriodSec
	delta := speedBytesPerSec * (0.8*t + 0.2*(T/(2*math.Pi))*(math.Cos(phase)-math.Cos(2*math.Pi*t/T+phase)))
	if delta < 0 {
		delta = 0
	}
	return uint64(delta)
}

// packets returns a Counter64 value for a packet column: base + totalPkts × ratio.
// Exactly one of (mcast, bcast, ucast) must be true. Passing zero flags
// is a programmer error: the helper panics rather than silently
// returning 0, which would be indistinguishable from a genuine "no
// packets yet" answer and mask the miswiring.
//
// The `inbound` flag picks the correct pktSize + ratios + base tables.
// Returning 64-bit values lets callers either emit them as Counter64
// directly (HC columns) or truncate to Counter32 via `& 0xFFFFFFFF`
// (shadow columns) — Counter32 wrap is inherent, no discontinuity.
func (ic *IfCounterCycler) packets(slot int, octets uint64, inbound, mcast, bcast, ucast bool) uint64 {
	var (
		pktSize float64
		ratio   float64
		base    uint64
	)
	if !ucast && !mcast && !bcast {
		panic("IfCounterCycler.packets: exactly one of (ucast, mcast, bcast) must be true")
	}
	if inbound {
		pktSize = ic.pktSizeIn[slot]
		switch {
		case ucast:
			ratio = ic.ucastRatioIn[slot]
			base = ic.baseInUcast[slot]
		case mcast:
			ratio = ic.mcastRatioIn[slot]
			base = ic.baseInMcast[slot]
		case bcast:
			ratio = ic.bcastRatioIn[slot]
			base = ic.baseInBcast[slot]
		}
	} else {
		pktSize = ic.pktSizeOut[slot]
		switch {
		case ucast:
			ratio = ic.ucastRatioOut[slot]
			base = ic.baseOutUcast[slot]
		case mcast:
			ratio = ic.mcastRatioOut[slot]
			base = ic.baseOutMcast[slot]
		case bcast:
			ratio = ic.bcastRatioOut[slot]
			base = ic.baseOutBcast[slot]
		}
	}
	total := float64(octets) / safePktSize(pktSize)
	return base + uint64(total*ratio)
}

// fmtU64 / fmtU32 — decimal formatting helpers used by the dispatcher.
func fmtU64(v uint64) string { return strconv.FormatUint(v, 10) }
func fmtU32(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

// InitIfCounters sets up per-interface counter cycling for all dynamic
// IF-MIB columns under the `clean` error scenario. Backward-compatible
// forwarder to InitIfCountersWithScenario.
//
// Must be called after NewMetricsCycler and before device.Start() so
// goroutine creation provides the happens-before edge required for
// thread safety.
func (c *MetricsCycler) InitIfCounters(resources *DeviceResources, seed int64) {
	c.InitIfCountersWithScenario(resources, seed, IfErrorClean)
}

// InitIfCountersWithScenario sets up per-interface counter cycling for
// all dynamic IF-MIB columns with the given error scenario. Interface
// speeds are read from the device's oidIndex (ifHighSpeed in Mbps
// preferred; falls back to ifSpeed in bps).
//
// **Single-init only.** Calling this method twice on the same
// MetricsCycler panics — the second call would silently orphan any
// gNMI ON_CHANGE listeners and flap-scheduler entries already
// registered against the existing state engine. Any future
// "reload-scenario" feature must explicitly address listener migration
// before relaxing this guard.
func (c *MetricsCycler) InitIfCountersWithScenario(resources *DeviceResources, seed int64, scenario IfErrorScenario) {
	if resources == nil || resources.oidIndex == nil {
		return
	}
	if existing := c.ifCounters.Load(); existing != nil && existing.state != nil {
		panic("InitIfCountersWithScenario: re-init unsafe — state engine already published; orphaned listeners would silently miss every subsequent event")
	}

	// Collect the exact set of ifIndex values that have HC in-octets OIDs.
	// Reject ifIndex > maxResourceIfIndex to guard against a corrupted or
	// adversarial resource file that would otherwise force NewInterfaceState
	// into an O(maxIfIndex) atomic.Uint64 allocation (e.g. a single
	// .1.3.6.1.2.1.31.1.1.1.6.4000000000 entry → ~32 GB).
	knownIdxs := make(map[int]struct{})
	resources.oidIndex.Range(func(k, _ interface{}) bool {
		oid, ok := k.(string)
		if !ok {
			return true
		}
		if strings.HasPrefix(oid, hcInOIDPrefix) {
			if idx, err := strconv.Atoi(oid[len(hcInOIDPrefix):]); err == nil && idx > 0 {
				if idx > maxResourceIfIndex {
					log.Printf("if_counters: ifIndex %d from resource exceeds maxResourceIfIndex %d; skipped (resource file may be corrupted)", idx, maxResourceIfIndex)
					return true
				}
				knownIdxs[idx] = struct{}{}
			}
		}
		return true
	})
	if len(knownIdxs) == 0 {
		return // no HC counters for this device type
	}

	maxIdx := 0
	for idx := range knownIdxs {
		if idx > maxIdx {
			maxIdx = idx
		}
	}

	// Freeze the ifIndex set as a slice once so IfIndices returns a
	// cached read-only view (hot path: trap template resolution).
	indexList := make([]int, 0, len(knownIdxs))
	for idx := range knownIdxs {
		indexList = append(indexList, idx)
	}

	// Sorted copy used by walk enumeration — must be ascending so that
	// NextDynamicOID emits (col, ifIndex) rows in MIB lex order.
	sortedIndexList := make([]int, len(indexList))
	copy(sortedIndexList, indexList)
	sort.Ints(sortedIndexList)

	// Precompute the first/last OID the cycler owns so findNextOID can
	// cheaply decide whether a static-only fast path is safe.
	firstCol := ifCyclerColumns[0]
	lastCol := ifCyclerColumns[len(ifCyclerColumns)-1]
	firstDynOID := firstCol.prefix + strconv.Itoa(firstCol.col) + "." + strconv.Itoa(sortedIndexList[0])
	lastDynOID := lastCol.prefix + strconv.Itoa(lastCol.col) + "." + strconv.Itoa(sortedIndexList[len(sortedIndexList)-1])

	ic := &IfCounterCycler{
		startTime:       time.Now(),
		maxIfIndex:      maxIdx,
		knownIfIndexes:  knownIdxs,
		ifIndexList:     indexList,
		sortedIfIndexes: sortedIndexList,
		firstDynOID:     firstDynOID,
		lastDynOID:      lastDynOID,
		ifSpeedBps:      make([]uint64, maxIdx),
		baseInOctets:    make([]uint64, maxIdx),
		baseOutOctets:   make([]uint64, maxIdx),
		phaseIn:         make([]float64, maxIdx),
		phaseOut:        make([]float64, maxIdx),
		pktSizeIn:       make([]float64, maxIdx),
		pktSizeOut:      make([]float64, maxIdx),
		ucastRatioIn:    make([]float64, maxIdx),
		mcastRatioIn:    make([]float64, maxIdx),
		bcastRatioIn:    make([]float64, maxIdx),
		ucastRatioOut:   make([]float64, maxIdx),
		mcastRatioOut:   make([]float64, maxIdx),
		bcastRatioOut:   make([]float64, maxIdx),
		baseInUcast:     make([]uint64, maxIdx),
		baseInMcast:     make([]uint64, maxIdx),
		baseInBcast:     make([]uint64, maxIdx),
		baseOutUcast:    make([]uint64, maxIdx),
		baseOutMcast:    make([]uint64, maxIdx),
		baseOutBcast:    make([]uint64, maxIdx),
		errPpmIn:        make([]uint32, maxIdx),
		errPpmOut:       make([]uint32, maxIdx),
		discPpmIn:       make([]uint32, maxIdx),
		discPpmOut:      make([]uint32, maxIdx),
		baseInErr:       make([]uint64, maxIdx),
		baseOutErr:      make([]uint64, maxIdx),
		baseInDisc:      make([]uint64, maxIdx),
		baseOutDisc:     make([]uint64, maxIdx),
	}

	rng := rand.New(rand.NewSource(seed))
	errLo, errHi, discLo, discHi := scenarioBand(scenario)

	for idx := range knownIdxs {
		slot := idx - 1

		// Prefer ifHighSpeed (Mbps → bps) over ifSpeed (bps, capped ~4 Gbps).
		var speedBps uint64 = 1_000_000_000 // default 1 Gbps
		highSpeedOID := fmt.Sprintf(ifXTablePrefix+"15.%d", idx)
		if v, ok := resources.oidIndex.Load(highSpeedOID); ok {
			if s, ok := v.(string); ok {
				if mbps, err := strconv.ParseUint(s, 10, 64); err == nil && mbps > 0 {
					speedBps = mbps * 1_000_000
				}
			}
		} else {
			ifSpeedOID := fmt.Sprintf(ifTablePrefix+"5.%d", idx)
			if v, ok := resources.oidIndex.Load(ifSpeedOID); ok {
				if s, ok := v.(string); ok {
					if bps, err := strconv.ParseUint(s, 10, 64); err == nil && bps > 0 {
						speedBps = bps
					}
				}
			}
		}
		ic.ifSpeedBps[slot] = speedBps

		// Seed octet counters with ~24 h of 80 %-average traffic so they
		// look realistic from the first poll. Up to +5 % per-interface
		// jitter for variety.
		avg24h := uint64(float64(speedBps) / 8.0 * 0.8 * 86400.0)
		ic.baseInOctets[slot] = avg24h + uint64(rng.Float64()*float64(avg24h)*0.05)
		ic.baseOutOctets[slot] = avg24h + uint64(rng.Float64()*float64(avg24h)*0.05)

		// Random phase offsets so interfaces don't peak simultaneously.
		ic.phaseIn[slot] = rng.Float64() * 2 * math.Pi
		ic.phaseOut[slot] = rng.Float64() * 2 * math.Pi

		// Average packet size jittered per-interface ±20 % around 500 B.
		// Match the sFlow synthesis default so unified readers stay
		// numerically consistent when the divisor is 500.
		ic.pktSizeIn[slot] = 500.0 * (1.0 + (rng.Float64()-0.5)*0.4)
		ic.pktSizeOut[slot] = 500.0 * (1.0 + (rng.Float64()-0.5)*0.4)

		// Packet mix ratios, ±3 % jitter, normalized to sum 1.0 per direction.
		uIn, mIn, bIn := jitterAndNormalize(rng, 0.85, 0.10, 0.05, 0.03)
		uOut, mOut, bOut := jitterAndNormalize(rng, 0.90, 0.08, 0.02, 0.03)
		ic.ucastRatioIn[slot], ic.mcastRatioIn[slot], ic.bcastRatioIn[slot] = uIn, mIn, bIn
		ic.ucastRatioOut[slot], ic.mcastRatioOut[slot], ic.bcastRatioOut[slot] = uOut, mOut, bOut

		// Scenario-banded per-direction ppms. `clean` gives 0s via
		// scenarioBand — the pre-seeded bases below stay 0 too.
		ic.errPpmIn[slot] = drawPpm(rng, errLo, errHi)
		ic.errPpmOut[slot] = drawPpm(rng, errLo, errHi)
		ic.discPpmIn[slot] = drawPpm(rng, discLo, discHi)
		ic.discPpmOut[slot] = drawPpm(rng, discLo, discHi)

		// Pre-seed packet and error/discard counters with ~24 h of
		// accumulation so a fresh device doesn't look pristine.
		totalInPkts24h := uint64(float64(ic.baseInOctets[slot]) / ic.pktSizeIn[slot])
		totalOutPkts24h := uint64(float64(ic.baseOutOctets[slot]) / ic.pktSizeOut[slot])
		ic.baseInUcast[slot] = uint64(float64(totalInPkts24h) * ic.ucastRatioIn[slot])
		ic.baseInMcast[slot] = uint64(float64(totalInPkts24h) * ic.mcastRatioIn[slot])
		ic.baseInBcast[slot] = uint64(float64(totalInPkts24h) * ic.bcastRatioIn[slot])
		ic.baseOutUcast[slot] = uint64(float64(totalOutPkts24h) * ic.ucastRatioOut[slot])
		ic.baseOutMcast[slot] = uint64(float64(totalOutPkts24h) * ic.mcastRatioOut[slot])
		ic.baseOutBcast[slot] = uint64(float64(totalOutPkts24h) * ic.bcastRatioOut[slot])
		ic.baseInErr[slot] = totalInPkts24h * uint64(ic.errPpmIn[slot]) / 1_000_000
		ic.baseOutErr[slot] = totalOutPkts24h * uint64(ic.errPpmOut[slot]) / 1_000_000
		ic.baseInDisc[slot] = totalInPkts24h * uint64(ic.discPpmIn[slot]) / 1_000_000
		ic.baseOutDisc[slot] = totalOutPkts24h * uint64(ic.discPpmOut[slot]) / 1_000_000
	}

	// Build the interface state engine. Seed each slot from the static
	// ifAdminStatus.<N> / ifOperStatus.<N> JSON values so the initial
	// state matches what the resources declare; later mutations (flap
	// scenario, REST control plane) write to this engine directly.
	// Counter aggregates are wired in by SimulatorManager.StartGnmiSubsystem
	// once it owns the global counters (§D12).
	//
	// JSON values out of IF-MIB range fall back to UP and log a warning
	// so a typo in the resource file doesn't silently corrupt the seed.
	ic.state = NewInterfaceState(maxIdx, nil, nil)
	for idx := range knownIdxs {
		oper := OperUp
		admin := AdminUp
		operOID := ifTablePrefix + strconv.Itoa(colIfOperStatus) + "." + strconv.Itoa(idx)
		if v, ok := resources.oidIndex.Load(operOID); ok {
			if s, ok := v.(string); ok {
				if n, err := strconv.Atoi(s); err == nil {
					if n >= 1 && n <= 7 {
						oper = uint8(n)
					} else {
						log.Printf("if_counters: ifOperStatus.%d JSON value %q out of IF-MIB range 1..7; defaulting to UP", idx, s)
					}
				}
			}
		}
		adminOID := ifTablePrefix + strconv.Itoa(colIfAdminStatus) + "." + strconv.Itoa(idx)
		if v, ok := resources.oidIndex.Load(adminOID); ok {
			if s, ok := v.(string); ok {
				if n, err := strconv.Atoi(s); err == nil {
					if n >= 1 && n <= 3 {
						admin = uint8(n)
					} else {
						log.Printf("if_counters: ifAdminStatus.%d JSON value %q out of IF-MIB range 1..3; defaulting to UP", idx, s)
					}
				}
			}
		}
		ic.state.Seed(idx, oper, admin)
	}

	// ic is fully constructed before the Store, so concurrent readers
	// either see the complete new cycler or the previous pointer — never
	// a partially-initialised intermediate. This is the contract the
	// atomic.Pointer field on MetricsCycler depends on.
	c.ifCounters.Store(ic)
}

// jitterAndNormalize applies ±jitter (as a fraction) to each ratio
// independently and then normalizes so they sum to exactly 1.0.
// Normalization absorbs the floating-point rounding that would
// otherwise make `ucast + mcast + bcast != 1.0` and cause
// totalPkts-vs-sum-of-components to drift.
func jitterAndNormalize(rng *rand.Rand, u, m, b, jitter float64) (float64, float64, float64) {
	uj := u * (1.0 + (rng.Float64()-0.5)*2*jitter)
	mj := m * (1.0 + (rng.Float64()-0.5)*2*jitter)
	bj := b * (1.0 + (rng.Float64()-0.5)*2*jitter)
	sum := uj + mj + bj
	if sum <= 0 {
		return u, m, b
	}
	return uj / sum, mj / sum, bj / sum
}

// drawPpm uniformly samples ppm within [lo, hi]. Returns lo when hi==lo
// (inclusive of the clean-scenario [0, 0] case — no error growth).
func drawPpm(rng *rand.Rand, lo, hi uint32) uint32 {
	if hi <= lo {
		return lo
	}
	return lo + uint32(rng.Intn(int(hi-lo)+1))
}
