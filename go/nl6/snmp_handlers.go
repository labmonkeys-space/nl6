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
	"strconv"
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

	// Fast O(1) lookup using lock-free sync.Map
	if s.device.resources.oidIndex != nil {
		if response, exists := s.device.resources.oidIndex.Load(oid); exists {
			return response.(string)
		}
	}
	return "OID not supported"
}

// Compare two OIDs lexicographically
func compareOIDs(oid1, oid2 string) int {
	var parts1, parts2 []string
	if s := strings.TrimPrefix(oid1, "."); s != "" {
		parts1 = strings.Split(s, ".")
	}
	if s := strings.TrimPrefix(oid2, "."); s != "" {
		parts2 = strings.Split(s, ".")
	}

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var val1, val2 int

		if i < len(parts1) {
			val1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			val2, _ = strconv.Atoi(parts2[i])
		}

		if val1 < val2 {
			return -1
		} else if val1 > val2 {
			return 1
		}
	}

	if len(parts1) < len(parts2) {
		return -1
	} else if len(parts1) > len(parts2) {
		return 1
	}

	return 0
}

// Find the next OID in lexicographic order for SNMP GetNext requests
func (s *SNMPServer) findNextOID(currentOID string) (string, string) {
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
		if metricsClear && ifCyclerClear {
			return precomputedNextOID, s.overrideIfHC(ifCycler, precomputedNextOID, precomputedNextResp)
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
		// Fallback to checking only dynamic OIDs
		if compareOIDs(sysNameOID, currentOID) > 0 {
			return sysNameOID, cachedSysName
		}
		if compareOIDs(sysLocationOID, currentOID) > 0 {
			return sysLocationOID, cachedSysLocation
		}
		return "", "endOfMibView"
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

	return nextOID, s.overrideIfHC(ifCycler, nextOID, response)
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

	// Parse every OID from the variable-bindings list.
	allOIDs := s.parseAllOIDsFromRequest(requestData)
	if len(allOIDs) == 0 {
		// Fallback: use the single OID extracted by the general request parser.
		allOIDs = []string{startOID}
	}

	var responseOIDs []string
	var responseValues []string

	// ── Non-repeater section (GETNEXT semantics) ──────────────────────────
	cap := nonRepeaters
	if cap > len(allOIDs) {
		cap = len(allOIDs)
	}
	for i := 0; i < cap; i++ {
		nextOID, nextVal := s.findNextOID(allOIDs[i])
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
			nextOID, nextVal := s.findNextOID(currentOIDs[col])
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
	if nonRepLen == 1 && pos < len(data) {
		nonRepeaters = int(data[pos])
	}
	pos += nonRepLen

	// Parse max-repetitions
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return nonRepeaters, maxRepetitions
	}
	pos++
	maxRepLen, newPos := parseLength(data, pos)
	pos = newPos
	if maxRepLen == 1 && pos < len(data) {
		maxRepetitions = int(data[pos])
	}

	// log.Printf("SNMP %s: GetBulk parsed parameters - nonRepeaters: %d, maxRepetitions: %d",
	//	s.device.ID, nonRepeaters, maxRepetitions)

	return nonRepeaters, maxRepetitions
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
