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
	"strings"
)

func (s *SNMPServer) findResponse(oid string) string {
	// Handle dynamic sysLocation OID - lock-free access
	if oid == ".1.3.6.1.2.1.1.6.0" {
		if val := s.device.cachedSysLocation.Load(); val != nil {
			return val.(string)
		}
		return s.device.sysLocation // Fallback
	}

	// Handle dynamic sysName OID - lock-free access
	if oid == ".1.3.6.1.2.1.1.5.0" {
		if val := s.device.cachedSysName.Load(); val != nil {
			return val.(string)
		}
		return s.device.sysName // Fallback
	}

	// Handle dynamic CPU/memory metric OIDs - per-device cycling values
	if s.device.metricsCycler != nil {
		if val := s.getMetricValue(oid); val != "" {
			return val
		}
		// Handle all dynamic IF-MIB counter OIDs (ifTable + ifXTable):
		// octets, HC packets, Counter32 shadows, error / discard. The
		// cycler returns "" for OIDs it doesn't own — fall through to
		// the static oidIndex lookup in that case.
		if ic := s.device.metricsCycler.ifCounters.Load(); ic != nil {
			if val := ic.GetDynamic(oid); val != "" {
				return val
			}
		}
	}

	// Interface state scenario override (admin/oper status)
	if override := getIfStateOverride(oid); override != "" {
		return override
	}

	// LLDP-MIB neighbor / local-system tables and the ifAlias link label
	// are served by the topology-driven dynamic provider. Checked before
	// the static oidIndex so the dynamic ifAlias wins over any static .18
	// entry shipped in the device resources.
	if isLLDPOID(oid) || isIfAliasOID(oid) {
		if val := s.lldpGet(oid); val != "" {
			return val
		}
	}

	// Fast O(1) lookup using lock-free sync.Map
	if s.device.resources.oidIndex != nil {
		if response, exists := s.device.resources.oidIndex.Load(oid); exists {
			return response.(string)
		}
	}
	// Not in this device's MIB view. RFC 3416 §4.2.1 requires a noSuchObject
	// exception, not a value — answering with an octet string makes an
	// unimplemented OID look like data, and a collector typing the OID per its
	// MIB fails to convert it (nl6#517).
	return valueNoSuchObject
}

// Compare two OIDs lexicographically
// compareOIDs compares two dotted OIDs numerically, segment by segment,
// without allocating. It is on the GETBULK walk hot path (binary search, the
// LLDP sort comparator, and the lldpNextFromServed scan), so the previous
// strings.Split + strconv.Atoi implementation dominated CPU during fabric-wide
// Enlinkd walks. Semantics are identical to that implementation: a single
// leading "." is ignored; a missing segment counts as 0 for value comparison
// but a longer OID with an otherwise-equal prefix sorts after a shorter one; a
// non-numeric or empty segment parses as 0. Equivalence is pinned by a
// differential fuzz test against the reference in compareoids_test.go.
//
// Equivalence holds for every value SNMP can emit: sub-identifiers are 32-bit,
// so each segment fits well within int. A pathological segment of >18 digits
// would wrap in the accumulator below (the old strconv.Atoi clamped to MaxInt),
// but such an OID is malformed and never produced by a real agent or walk; the
// only consequence would be cosmetic mis-ordering, never a panic.
func compareOIDs(oid1, oid2 string) int {
	c1 := newOIDCursor(oid1)
	c2 := newOIDCursor(oid2)
	for {
		v1, ok1 := c1.next()
		v2, ok2 := c2.next()
		if !ok1 && !ok2 {
			return 0
		}
		if v1 != v2 {
			if v1 < v2 {
				return -1
			}
			return 1
		}
		// Values equal (a missing segment yields 0); if one OID has run out
		// the shorter one sorts first. Any later non-zero segment on the
		// longer side would point the same direction, so deciding here is safe.
		if ok1 != ok2 {
			if !ok1 {
				return -1
			}
			return 1
		}
	}
}

// oidCursor yields the numeric value of successive OID segments without
// allocating. It mirrors strings.Split semantics exactly, including trailing
// empty segments (e.g. "1." yields {1, 0}).
type oidCursor struct {
	s    string
	i    int
	done bool
}

func newOIDCursor(oid string) oidCursor {
	// Drop a single leading dot (matches strings.TrimPrefix(oid, ".")).
	if len(oid) > 0 && oid[0] == '.' {
		oid = oid[1:]
	}
	// An empty (trimmed) OID has zero segments.
	return oidCursor{s: oid, done: oid == ""}
}

// next returns the value of the next segment and whether a segment was present.
// Exhausted cursors return (0, false), so missing segments compare as 0.
func (c *oidCursor) next() (int, bool) {
	if c.done {
		return 0, false
	}
	val := 0
	numeric := true
	start := c.i
	for c.i < len(c.s) && c.s[c.i] != '.' {
		ch := c.s[c.i]
		if ch >= '0' && ch <= '9' {
			val = val*10 + int(ch-'0')
		} else {
			numeric = false
		}
		c.i++
	}
	if !numeric || c.i == start {
		val = 0 // strconv.Atoi failure (non-digit) or empty segment → 0
	}
	if c.i < len(c.s) {
		c.i++ // consume the '.'; another segment follows (possibly empty)
	} else {
		c.done = true
	}
	return val, true
}

// Find the next OID in lexicographic order for SNMP GetNext requests.
// Builds the LLDP served-OID set for this single lookup. GETBULK callers
// that issue many lookups per request should instead build the set once and
// call findNextOIDWithServed to avoid rebuilding it per repetition.
func (s *SNMPServer) findNextOID(currentOID string) (string, string) {
	return s.findNextOIDWithServed(currentOID, s.lldpServedOIDs())
}

// findNextOIDWithServed is findNextOID with the LLDP served-OID set supplied
// by the caller. The set is a sorted (oid,value) snapshot; passing it lets a
// multi-repetition GETBULK reuse one snapshot across every repetition instead
// of recomputing the device's entire LLDP/ifAlias view on each walk step —
// the original hot path that turned a fabric-wide Enlinkd walk into O(steps ×
// links). nil/empty is valid (device serves no LLDP).
func (s *SNMPServer) findNextOIDWithServed(currentOID string, lldpServed []kvOID) (string, string) {
	// Try pre-computed next OID map first (O(1) lookup)
	var precomputedNextOID string
	var precomputedNextResp string
	if s.device.resources.oidNextMap != nil {
		if nextOID, exists := s.device.resources.oidNextMap.Load(currentOID); exists {
			if response, exists := s.device.resources.oidIndex.Load(nextOID); exists {
				precomputedNextOID = nextOID.(string)
				precomputedNextResp = response.(string)
			}
		}
	}

	// Resolve dynamic sources up front so both fast-path and slow-path
	// candidate assembly can see them.
	sortedMetricOIDs := GetSortedMetricOIDs(s.device.resourceFile)
	var ifCycler *IfCounterCycler
	if s.device.metricsCycler != nil {
		ifCycler = s.device.metricsCycler.ifCounters.Load()
	}
	ifCyclerHasRows := ifCycler != nil && len(ifCycler.sortedIfIndexes) > 0

	// Resolve the next LLDP / ifAlias OID up front. The LLDP provider owns
	// two disjoint ranges (the 1.0.8802 subtree, which sorts BEFORE every
	// static OID, and ifXTable .18, which sorts mid-ifXTable), so a single
	// first/last bracket cannot describe it — lldpNextFromServed does the work
	// and the fast-path clearance below is derived from its result.
	lldpNextLLDP, lldpNextVal := lldpNextFromServed(lldpServed, currentOID)
	lldpHas := lldpNextLLDP != ""

	// Fast path: precomputedNextOID is safe to return immediately iff no
	// dynamic source can emit a candidate in (currentOID, precomputedNextOID].
	// For each source that condition is: source is empty, OR its first
	// owned OID is at/after precomputedNextOID, OR currentOID is at/after
	// its last owned OID.
	if precomputedNextOID != "" {
		metricsClear := len(sortedMetricOIDs) == 0 ||
			compareOIDs(precomputedNextOID, sortedMetricOIDs[0]) <= 0 ||
			compareOIDs(currentOID, sortedMetricOIDs[len(sortedMetricOIDs)-1]) >= 0
		ifCyclerClear := !ifCyclerHasRows ||
			compareOIDs(precomputedNextOID, ifCycler.firstDynOID) <= 0 ||
			compareOIDs(currentOID, ifCycler.lastDynOID) >= 0
		// LLDP is clear iff it has no candidate at or before precomputedNextOID.
		// Without this term the static next is returned and the 1.0.8802
		// subtree (which sorts before all statics) is silently skipped.
		lldpClear := !lldpHas || compareOIDs(lldpNextLLDP, precomputedNextOID) > 0
		if metricsClear && ifCyclerClear && lldpClear {
			val := s.overrideIfHC(ifCycler, precomputedNextOID, precomputedNextResp)
			return precomputedNextOID, s.overrideLLDP(precomputedNextOID, val)
		}
	}

	// Slow path: need to consider dynamic metric OIDs as candidates.
	// Dynamic OIDs - check these with lock-free access
	sysNameOID := ".1.3.6.1.2.1.1.5.0"
	sysLocationOID := ".1.3.6.1.2.1.1.6.0"

	var nextOID string
	var response string

	// Get cached dynamic values (lock-free)
	var cachedSysName, cachedSysLocation string
	if val := s.device.cachedSysName.Load(); val != nil {
		cachedSysName = val.(string)
	} else {
		cachedSysName = s.device.sysName
	}
	if val := s.device.cachedSysLocation.Load(); val != nil {
		cachedSysLocation = val.(string)
	} else {
		cachedSysLocation = s.device.sysLocation
	}

	// Use binary search on pre-sorted OIDs for O(log n) performance
	sortedOIDs := s.device.resources.sortedOIDs
	if len(sortedOIDs) == 0 {
		// Fallback to checking only dynamic OIDs (sysName/sysLocation + LLDP).
		best, bestVal := "", ""
		consider := func(o, v string) {
			if compareOIDs(o, currentOID) > 0 && (best == "" || compareOIDs(o, best) < 0) {
				best, bestVal = o, v
			}
		}
		consider(sysNameOID, cachedSysName)
		consider(sysLocationOID, cachedSysLocation)
		if lldpHas {
			consider(lldpNextLLDP, lldpNextVal)
		}
		if best == "" {
			return "", "endOfMibView"
		}
		return best, s.overrideLLDP(best, bestVal)
	}

	// Find first OID greater than currentOID using binary search
	left, right := 0, len(sortedOIDs)
	for left < right {
		mid := (left + right) / 2
		if compareOIDs(sortedOIDs[mid], currentOID) <= 0 {
			left = mid + 1
		} else {
			right = mid
		}
	}

	// Check candidates: next static OID, dynamic sysName/sysLocation, and metric OIDs
	candidates := make([]struct{ oid, resp string }, 0, 8)

	// Add pre-computed next static OID if available
	if precomputedNextOID != "" {
		candidates = append(candidates, struct{ oid, resp string }{
			oid:  precomputedNextOID,
			resp: precomputedNextResp,
		})
	} else if left < len(sortedOIDs) {
		// Fallback to binary search result
		staticOID := sortedOIDs[left]
		// Skip dynamic OIDs that might be in the sorted list
		if staticOID != sysNameOID && staticOID != sysLocationOID {
			if respVal, exists := s.device.resources.oidIndex.Load(staticOID); exists {
				candidates = append(candidates, struct{ oid, resp string }{
					oid:  staticOID,
					resp: respVal.(string),
				})
			}
		}
	}

	// Add dynamic OIDs if they're greater than currentOID
	if compareOIDs(sysNameOID, currentOID) > 0 {
		candidates = append(candidates, struct{ oid, resp string }{
			oid:  sysNameOID,
			resp: cachedSysName,
		})
	}
	if compareOIDs(sysLocationOID, currentOID) > 0 {
		candidates = append(candidates, struct{ oid, resp string }{
			oid:  sysLocationOID,
			resp: cachedSysLocation,
		})
	}

	// Add dynamic metric OIDs as candidates for walks (uses cached sorted slice)
	if s.device.metricsCycler != nil && len(sortedMetricOIDs) > 0 {
		for _, mOID := range sortedMetricOIDs {
			if compareOIDs(mOID, currentOID) > 0 {
				val := s.getMetricValue(mOID)
				if val != "" {
					candidates = append(candidates, struct{ oid, resp string }{
						oid:  mOID,
						resp: val,
					})
					break // Only need the first (smallest) metric OID greater than current
				}
			}
		}
	}

	// Add the next dynamic ifTable/ifXTable counter row as a candidate.
	// Columns served analytically by IfCounterCycler (e.g.
	// ifHCInMulticastPkts) frequently have no static-JSON instance rows,
	// so without this a walk would skip the whole column even though GET
	// on a specific instance works.
	if ifCyclerHasRows {
		if nextOID, val := ifCycler.NextDynamicOID(currentOID); nextOID != "" {
			candidates = append(candidates, struct{ oid, resp string }{
				oid:  nextOID,
				resp: val,
			})
		}
	}

	// Add the next LLDP / ifAlias OID as a candidate. The 1.0.8802 rows
	// have no static-JSON instance, and a linked port's ifAlias may be
	// dynamic-only, so without this a walk would skip them.
	if lldpHas {
		candidates = append(candidates, struct{ oid, resp string }{
			oid:  lldpNextLLDP,
			resp: lldpNextVal,
		})
	}

	if len(candidates) == 0 {
		return "", "endOfMibView"
	}

	// Find lexicographically smallest candidate
	nextOID = candidates[0].oid
	response = candidates[0].resp
	for i := 1; i < len(candidates); i++ {
		if compareOIDs(candidates[i].oid, nextOID) < 0 {
			nextOID = candidates[i].oid
			response = candidates[i].resp
		}
	}

	// overrideLLDP after overrideIfHC so the dynamic LLDP/ifAlias value wins
	// even when the chosen candidate originated from the static oidIndex
	// (e.g. a statically-shipped ifAlias .18.N on a linked port).
	response = s.overrideIfHC(ifCycler, nextOID, response)
	response = s.overrideLLDP(nextOID, response)
	return nextOID, response
}

// handleGetBulk processes SNMP GetBulk requests
// handleGetBulk implements RFC 3416 §4.2.3 GetBulk processing.
//
// A GETBULK request carries multiple OIDs in its variable-bindings list:
//   - The first nonRepeaters OIDs are treated like GETNEXT (one result each).
//   - The remaining OIDs are "repeater" columns: for each repetition the
//     response contains one GETNEXT result per column, interleaved in order.
//
// Previous implementation only processed the first OID, so OpenNMS's
// multi-column GETBULK requests only ever returned values for the first
// requested column, leaving ifDescr/ifName/ifAlias/ifSpeed as N/A.
func (s *SNMPServer) handleGetBulk(startOID string, requestData []byte) []byte {
	nonRepeaters, maxRepetitions := s.parseGetBulkParams(requestData)
	// Defence in depth. parseGetBulkParams already rejects negatives, but the
	// consequence of one slipping through is a slice-bounds panic that takes
	// the whole simulator down from a single malformed UDP packet — there is no
	// recover() on the serve path. Two guards is the right price for that.
	if nonRepeaters < 0 {
		nonRepeaters = 0
	}
	if maxRepetitions < 0 {
		maxRepetitions = 0
	}

	// Parse every OID from the variable-bindings list.
	allOIDs := s.parseAllOIDsFromRequest(requestData)
	if len(allOIDs) == 0 {
		// Fallback: use the single OID extracted by the general request parser.
		allOIDs = []string{startOID}
	}

	var responseOIDs []string
	var responseValues []string

	// Build the LLDP served-OID snapshot ONCE for the whole request. A
	// GETBULK issues nonRepeaters + repeaterCols × maxRepetitions GETNEXT
	// lookups; rebuilding the device's entire LLDP/ifAlias view on each was
	// the dominant cost of an Enlinkd fabric walk. One snapshot per request
	// is also more consistent (a single view of link/oper state).
	lldpServed := s.lldpServedOIDs()

	// ── Non-repeater section (GETNEXT semantics) ──────────────────────────
	cap := nonRepeaters
	if cap > len(allOIDs) {
		cap = len(allOIDs)
	}
	for i := 0; i < cap; i++ {
		nextOID, nextVal := s.findNextOIDWithServed(allOIDs[i], lldpServed)
		if nextOID == "" {
			nextOID = allOIDs[i]
			nextVal = "endOfMibView"
		}
		responseOIDs = append(responseOIDs, nextOID)
		responseValues = append(responseValues, nextVal)
	}

	// ── Repeater section (multi-column GETNEXT × maxRepetitions) ──────────
	repeaterCols := allOIDs[cap:] // columns to repeat
	if len(repeaterCols) == 0 || maxRepetitions == 0 {
		return s.createGetBulkResponse(responseOIDs, responseValues, requestData)
	}

	// Bound the WALK, not just the response.
	//
	// Truncation at encode time is what makes the response correct; this is a
	// CPU guard. Without it a request for max-repetitions 1000 across 10 columns
	// walks 10,000 MIB steps to emit the ~60 variable bindings that fit, and a
	// walk step is not cheap here — ~29 SNMP req/s already saturates the cores
	// on the LLDP path.
	//
	// Clamped rather than estimated: minVarbindSize is a floor on what any
	// binding can encode to, so budget/minVarbindSize is a hard ceiling on how
	// many could ever fit. The +1 keeps it from ever under-walking; the encode
	// bound trims whatever is left over, so being generous here costs nothing
	// but being tight would under-fill datagrams.
	// No outer `maxRepetitions > maxFit` test: it made the clamp inert for
	// everything below ~98, so 30 columns x 98 repetitions still walked 2940
	// steps to emit the ~60 bindings that fit — precisely the amplification
	// this guard exists to stop (nl6#489 review).
	if perRep := maxSNMPResponseSize/minVarbindSize/len(repeaterCols) + 1; maxRepetitions > perRep {
		maxRepetitions = perRep
	}

	// currentOIDs tracks the "cursor" position in each column.
	currentOIDs := make([]string, len(repeaterCols))
	copy(currentOIDs, repeaterCols)

	// endOfMib[i] == true once column i has exhausted the MIB.
	endOfMib := make([]bool, len(repeaterCols))

	for rep := 0; rep < maxRepetitions; rep++ {
		for col, startCol := range repeaterCols {
			if endOfMib[col] {
				// RFC 3416: pad with the ORIGINAL requested OID + endOfMibView.
				responseOIDs = append(responseOIDs, startCol)
				responseValues = append(responseValues, "endOfMibView")
				continue
			}
			nextOID, nextVal := s.findNextOIDWithServed(currentOIDs[col], lldpServed)
			if nextOID == "" || nextVal == "endOfMibView" {
				endOfMib[col] = true
				responseOIDs = append(responseOIDs, startCol)
				responseValues = append(responseValues, "endOfMibView")
			} else {
				responseOIDs = append(responseOIDs, nextOID)
				responseValues = append(responseValues, nextVal)
				currentOIDs[col] = nextOID
			}
		}
	}

	return s.createGetBulkResponse(responseOIDs, responseValues, requestData)
}

// handleGetRequestVarbinds answers a multi-variable-binding GET.
//
// It uses the tooBig overflow rule, NOT truncation: RFC 3416 §4.2.1 requires a
// GET response to carry every requested binding or none. Unlike a GETBULK walk,
// the requester has no resume point, so a partial response is a wrong answer it
// cannot detect (nl6#489, design D3).
//
// Multi-binding GET support itself is load-bearing: OpenNMS Enlinkd's
// LldpLocPortGetter bundles lldpLocPortIdSubtype/Id/Desc in one GET, and
// answering only the first binding leaves the discovered topology with no edges
// (nl6#176).
func (s *SNMPServer) handleGetRequestVarbinds(oids []string, requestData []byte) []byte {
	responses := make([]string, len(oids))
	for i, o := range oids {
		responses[i] = s.findResponse(o)
	}
	return s.createGetResponse(oids, responses, requestData)
}

// parseAllOIDsFromRequest extracts every OID from the variable-bindings list
// of an SNMP PDU (GET, GETNEXT, or GETBULK). For GETBULK this returns all
// column starters; for GET/GETNEXT it returns the single requested OID.
func (s *SNMPServer) parseAllOIDsFromRequest(data []byte) []string {
	var oids []string

	pos := 0

	// Outer SEQUENCE
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return oids
	}
	pos++
	outerLen, newPos := parseLength(data, pos)
	if outerLen < 0 {
		return oids
	}
	pos = newPos

	// Version (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return oids
	}
	pos++
	verLen, newPos := parseLength(data, pos)
	if verLen < 0 {
		return oids
	}
	pos = newPos + verLen

	// Community (OCTET STRING)
	if pos >= len(data) || data[pos] != ASN1_OCTET_STRING {
		return oids
	}
	pos++
	commLen, newPos := parseLength(data, pos)
	if commLen < 0 {
		return oids
	}
	pos = newPos + commLen

	// PDU tag (any: GET / GETNEXT / GETBULK / …)
	if pos >= len(data) {
		return oids
	}
	pos++ // consume PDU type byte
	pduLen, newPos := parseLength(data, pos)
	if pduLen < 0 {
		return oids
	}
	pos = newPos

	// Request-ID (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return oids
	}
	pos++
	reqIDLen, newPos := parseLength(data, pos)
	if reqIDLen < 0 {
		return oids
	}
	pos = newPos + reqIDLen

	// error-status / non-repeaters (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return oids
	}
	pos++
	f1Len, newPos := parseLength(data, pos)
	if f1Len < 0 {
		return oids
	}
	pos = newPos + f1Len

	// error-index / max-repetitions (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return oids
	}
	pos++
	f2Len, newPos := parseLength(data, pos)
	if f2Len < 0 {
		return oids
	}
	pos = newPos + f2Len

	// VarBindList (SEQUENCE)
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return oids
	}
	pos++
	vbListLen, newPos := parseLength(data, pos)
	if vbListLen < 0 {
		return oids
	}
	pos = newPos
	end := pos + vbListLen

	// Walk every VarBind
	for pos < end && pos < len(data) {
		if data[pos] != ASN1_SEQUENCE {
			break
		}
		pos++
		vbLen, newPos := parseLength(data, pos)
		if vbLen < 0 {
			break
		}
		pos = newPos
		nextVarBind := pos + vbLen
		if nextVarBind > end {
			break // VarBind claims to extend beyond declared VarBindList boundary
		}

		// OID inside VarBind
		if pos < len(data) && data[pos] == ASN1_OID {
			pos++
			oidLen, newPos := parseLength(data, pos)
			if oidLen >= 0 && newPos+oidLen <= len(data) {
				if oid := decodeOID(data[newPos : newPos+oidLen]); oid != "" {
					oids = append(oids, oid)
				}
			}
		}

		pos = nextVarBind
	}

	return oids
}

// parseGetBulkParams extracts non-repeaters and max-repetitions from GetBulk request
func (s *SNMPServer) parseGetBulkParams(data []byte) (int, int) {
	// Default values
	nonRepeaters := 0
	maxRepetitions := 10

	// Find the GetBulk PDU in the message
	// Structure: [SEQUENCE][version][community][GetBulk PDU]
	// GetBulk PDU: [PDU Type][Length][Request-ID][Non-Repeaters][Max-Repetitions][Variable Bindings]

	pos := 0
	// Skip outer SEQUENCE
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return nonRepeaters, maxRepetitions
	}
	pos++
	_, newPos := parseLength(data, pos)
	pos = newPos

	// Skip version
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	verLen, newPos := parseLength(data, pos)
	pos = newPos + verLen

	// Skip community
	if pos >= len(data) || data[pos] != ASN1_OCTET_STRING {
		return nonRepeaters, maxRepetitions
	}
	pos++
	commLen, newPos := parseLength(data, pos)
	pos = newPos + commLen

	// Now we're at the GetBulk PDU
	if pos >= len(data) || data[pos] != ASN1_GET_BULK {
		return nonRepeaters, maxRepetitions
	}
	pos++
	_, newPos = parseLength(data, pos)
	pos = newPos

	// Skip request-id
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	reqIdLen, newPos := parseLength(data, pos)
	pos = newPos + reqIdLen

	// Parse non-repeaters
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	nonRepLen, newPos := parseLength(data, pos)
	pos = newPos
	if v, ok := parseBERInt(data, pos, nonRepLen); ok && v >= 0 {
		// Clamped HERE, not after the parse: six early returns follow, and a
		// negative reaching handleGetBulk becomes `allOIDs[cap:]` with a
		// negative index — a slice-bounds panic on the inline serve path, with
		// no recover() anywhere, from one malformed packet (nl6#489 review).
		nonRepeaters = v
	}
	pos += nonRepLen

	// Parse max-repetitions
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	maxRepLen, newPos := parseLength(data, pos)
	pos = newPos
	// RFC 3416 §4.2.3 defines max-repetitions as non-negative; a negative value
	// is rejected at the parse site for the same reason as non-repeaters above.
	if v, ok := parseBERInt(data, pos, maxRepLen); ok && v >= 0 {
		maxRepetitions = v
	}

	// log.Printf("SNMP %s: GetBulk parsed parameters - nonRepeaters: %d, maxRepetitions: %d",
	//	s.device.ID, nonRepeaters, maxRepetitions)

	return nonRepeaters, maxRepetitions
}

// minVarbindSize is a floor on the encoded size of one variable binding:
// SEQUENCE header (2) + the shortest plausible OID TLV (2 + ~8) + the shortest
// value TLV (2 + 1). Deliberately an UNDER-estimate — it is used only to cap
// how far the GETBULK walk runs, and under-estimating means walking slightly
// too far, which the encode-time bound then trims. Over-estimating would stop
// the walk early and under-fill datagrams.
const minVarbindSize = 15

// parseBERInt decodes a BER INTEGER's content octets (two's complement,
// big-endian) at `pos` for `length` bytes.
//
// The previous implementation read only single-byte content, which looks like a
// 255 ceiling but is actually a 127 one: BER encodes any value >= 128 in two
// bytes, because the leading 0x00 is what keeps it positive. Everything above
// 127 therefore fell back to the default of 10 — silently, and right in the
// middle of the range operators tune `max-repetitions` to (nl6#489).
//
// That mattered beyond correctness: an operator testing max-repetitions=200 got
// 10, the collector performed 20x the round-trips, and the benchmark reported a
// plausible number describing a configuration nobody chose.
//
// Returns false when the content is absent, truncated, or wider than an int64
// can hold — callers keep their existing default in that case.
func parseBERInt(data []byte, pos, length int) (int, bool) {
	if length <= 0 || pos+length > len(data) {
		return 0, false
	}
	// Skip leading 0x00 padding before measuring width. Encoders that pad to a
	// fixed field width emit legal INTEGERs wider than 8 octets, and rejecting
	// those outright would make the caller keep its default — the same "value
	// silently replaced by a default" failure this function exists to remove.
	start, end := pos, pos+length
	for start < end-1 && data[start] == 0x00 && data[start+1]&0x80 == 0 {
		start++
	}
	if end-start > 8 {
		return 0, false
	}
	v := int64(int8(data[start])) // sign-extend from the first significant octet
	for i := start + 1; i < end; i++ {
		v = v<<8 | int64(data[i])
	}
	return int(v), true
}

// overrideIfHC replaces staticResp with the live cycler value for any ifTable
// or ifXTable OID the IfCounterCycler owns (octets, HC packets, Counter32
// shadows, errors, discards — see if_counters.go for the full column list).
// Returns staticResp unchanged for OIDs outside those trees, or for in-tree
// OIDs the cycler does not own (e.g. ifDescr). Used by findNextOID to return
// live counter values during walks where the candidate OID originated from
// the static oidIndex.
//
// The caller passes the *IfCounterCycler it already Load()ed at the top of
// its function so the whole GETNEXT step reads a single consistent cycler
// snapshot. A concurrent Store between the caller's Load and this call
// would otherwise make the candidate-selection decision and the value
// override disagree.
func (s *SNMPServer) overrideIfHC(ic *IfCounterCycler, oid, staticResp string) string {
	if ic == nil {
		return staticResp
	}
	// Fast pre-check: dynamic IF-MIB OIDs live under ifTable
	// (.1.3.6.1.2.1.2.2.1.) or ifXTable (.1.3.6.1.2.1.31.1.1.1.). Skip
	// the cycler dispatch for OIDs outside both trees (the vast
	// majority of the MIB).
	if !strings.HasPrefix(oid, ".1.3.6.1.2.1.2.2.1.") && !strings.HasPrefix(oid, ".1.3.6.1.2.1.31.1.1.1.") {
		return staticResp
	}
	if dynVal := ic.GetDynamic(oid); dynVal != "" {
		return dynVal
	}
	return staticResp
}

// getMetricValue returns the cycling metric value for a dynamic OID,
// or empty string if the OID is not a metric OID for this device.
func (s *SNMPServer) getMetricValue(oid string) string {
	metricOIDs := GetMetricOIDs(s.device.resourceFile)
	if metricOIDs == nil {
		return ""
	}
	metricType, exists := metricOIDs[oid]
	if !exists {
		return ""
	}
	switch metricType {
	case MetricCPUPercent:
		return s.device.metricsCycler.GetCPUPercent()
	case MetricMemUsed:
		return s.device.metricsCycler.GetMemUsed()
	case MetricMemFree:
		return s.device.metricsCycler.GetMemFree()
	case MetricMemTotal:
		return s.device.metricsCycler.GetMemTotal()
	case MetricMemUsedPct:
		return s.device.metricsCycler.GetMemUsedPercent()
	case MetricTemperature:
		return s.device.metricsCycler.GetTemperature()
	// GPU metric types (NVIDIA DCGM)
	case MetricGPUUtil:
		return s.device.metricsCycler.GetGPUUtil(parseGPUIndexFromOID(oid))
	case MetricGPUMemUsed:
		return s.device.metricsCycler.GetGPUMemUsed(parseGPUIndexFromOID(oid))
	case MetricGPUMemTotal:
		return s.device.metricsCycler.GetGPUMemTotal(parseGPUIndexFromOID(oid))
	case MetricGPUTemp:
		return s.device.metricsCycler.GetGPUTemp(parseGPUIndexFromOID(oid))
	case MetricGPUPower:
		return s.device.metricsCycler.GetGPUPower(parseGPUIndexFromOID(oid))
	case MetricGPUFanSpeed:
		return s.device.metricsCycler.GetGPUFanSpeed(parseGPUIndexFromOID(oid))
	case MetricGPUClockSM:
		return s.device.metricsCycler.GetGPUClockSM(parseGPUIndexFromOID(oid))
	case MetricGPUClockMem:
		return s.device.metricsCycler.GetGPUClockMem(parseGPUIndexFromOID(oid))
	}
	return ""
}
