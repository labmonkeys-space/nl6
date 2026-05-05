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
	"fmt"
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
	colIfInUcastPkts  = 11
	colIfInDiscards   = 13
	colIfInErrors     = 14
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
	{ifTablePrefix, colIfInUcastPkts},         // .11
	{ifTablePrefix, colIfInDiscards},          // .13
	{ifTablePrefix, colIfInErrors},            // .14
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
//	.11 ifInUcastPkts         = low-32 of HC .7
//	.13 ifInDiscards          = base + totalInPkts  × discPpmIn  / 1e6
//	.14 ifInErrors            = base + totalInPkts  × errPpmIn   / 1e6
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
// currentOID once into (table, col, ifIndex), locate the column position
// in ifCyclerColumns by linear scan over its 18 entries, and use
// sort.SearchInts on sortedIfIndexes to find the successor ifIndex.
// The previous O(cols × ifIndexes) implementation built and compared an
// OID string for every (col, ifIndex) pair on each GETNEXT step, which
// made walking a 1000-interface device ~18000 string allocations per
// step.
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

	// emitFromColumn returns the (oid, value) for column at index colIdx in
	// ifCyclerColumns, at the supplied ifIndex.
	emitFromColumn := func(colIdx, ifIndex int) (string, string) {
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
	)
	if dot := strings.IndexByte(suffix, '.'); dot > 0 {
		if c, err := strconv.Atoi(suffix[:dot]); err == nil {
			col, haveCol = c, true
			if idx, err := strconv.Atoi(suffix[dot+1:]); err == nil {
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

	// Locate the first ifCyclerColumns entry whose (table, col) is at or
	// after the parsed (isIfX, col). 18-entry list — linear scan is
	// faster than sort.Search on a slice this small.
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
func (c *MetricsCycler) InitIfCountersWithScenario(resources *DeviceResources, seed int64, scenario IfErrorScenario) {
	if resources == nil || resources.oidIndex == nil {
		return
	}

	// Collect the exact set of ifIndex values that have HC in-octets OIDs.
	knownIdxs := make(map[int]struct{})
	resources.oidIndex.Range(func(k, _ interface{}) bool {
		oid, ok := k.(string)
		if !ok {
			return true
		}
		if strings.HasPrefix(oid, hcInOIDPrefix) {
			if idx, err := strconv.Atoi(oid[len(hcInOIDPrefix):]); err == nil && idx > 0 {
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
