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
	"strconv"
	"testing"
	"time"
)

// parseU — test helper; t.Fatal on parse failure, 0-safe otherwise.
func parseU(t *testing.T, s string) uint64 {
	t.Helper()
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

// Every newly-dynamic IF-MIB column must strictly increase across polls.
// Covers spec Requirement 1 "HC packet counters grow monotonically across polls".
func TestGetDynamic_MonotonicAllColumns(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, 42, IfErrorTypical)
	ic := c.ifCounters.Load()

	cases := []struct {
		oid  string
		desc string
	}{
		// ifXTable Counter32 shadow columns
		{".1.3.6.1.2.1.31.1.1.1.2.1", "ifInMulticastPkts"},
		{".1.3.6.1.2.1.31.1.1.1.3.1", "ifInBroadcastPkts"},
		{".1.3.6.1.2.1.31.1.1.1.4.1", "ifOutMulticastPkts"},
		{".1.3.6.1.2.1.31.1.1.1.5.1", "ifOutBroadcastPkts"},
		// ifXTable Counter64 HC columns
		{".1.3.6.1.2.1.31.1.1.1.6.1", "ifHCInOctets"},
		{".1.3.6.1.2.1.31.1.1.1.7.1", "ifHCInUcastPkts"},
		{".1.3.6.1.2.1.31.1.1.1.8.1", "ifHCInMulticastPkts"},
		{".1.3.6.1.2.1.31.1.1.1.9.1", "ifHCInBroadcastPkts"},
		{".1.3.6.1.2.1.31.1.1.1.10.1", "ifHCOutOctets"},
		{".1.3.6.1.2.1.31.1.1.1.11.1", "ifHCOutUcastPkts"},
		{".1.3.6.1.2.1.31.1.1.1.12.1", "ifHCOutMulticastPkts"},
		{".1.3.6.1.2.1.31.1.1.1.13.1", "ifHCOutBroadcastPkts"},
		// ifTable Counter32 columns
		{".1.3.6.1.2.1.2.2.1.11.1", "ifInUcastPkts"},
		{".1.3.6.1.2.1.2.2.1.13.1", "ifInDiscards"},
		{".1.3.6.1.2.1.2.2.1.14.1", "ifInErrors"},
		{".1.3.6.1.2.1.2.2.1.17.1", "ifOutUcastPkts"},
		{".1.3.6.1.2.1.2.2.1.19.1", "ifOutDiscards"},
		{".1.3.6.1.2.1.2.2.1.20.1", "ifOutErrors"},
	}

	prev := make(map[string]uint64, len(cases))
	for poll := 0; poll < 5; poll++ {
		time.Sleep(5 * time.Millisecond)
		for _, tc := range cases {
			v := parseU(t, ic.GetDynamic(tc.oid))
			if poll > 0 && v < prev[tc.oid] {
				t.Errorf("poll %d: %s decreased %d → %d", poll, tc.desc, prev[tc.oid], v)
			}
			prev[tc.oid] = v
		}
	}
}

// HC packet columns sum to ≈ total packets derived from octets + pktSize.
// Covers spec Requirement 1 "Ratio decomposition matches total-packets identity".
func TestGetDynamic_RatiosSumToTotalPackets(t *testing.T) {
	res := buildTestResources(t, []uint64{10_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, 2026, IfErrorClean)
	ic := c.ifCounters.Load()

	// Advance time so the derived packet counts have meaningful magnitude
	// beyond the t≈0 floor.
	time.Sleep(15 * time.Millisecond)

	inUcast := parseU(t, ic.GetDynamic(".1.3.6.1.2.1.31.1.1.1.7.1"))
	inMcast := parseU(t, ic.GetDynamic(".1.3.6.1.2.1.31.1.1.1.8.1"))
	inBcast := parseU(t, ic.GetDynamic(".1.3.6.1.2.1.31.1.1.1.9.1"))
	inOctets := parseU(t, ic.GetDynamic(".1.3.6.1.2.1.31.1.1.1.6.1"))

	// totalInPkts(t) = inOctets / pktSizeIn  — approximate; ratio
	// rounding to uint64 at each call can drop fractional packets so
	// we allow 0.2 % tolerance.
	pktSize := ic.pktSizeIn[0]
	expectedTotal := float64(inOctets) / pktSize
	gotTotal := float64(inUcast + inMcast + inBcast)
	if expectedTotal == 0 {
		t.Fatalf("expected non-zero totalInPkts")
	}
	drift := math.Abs(gotTotal-expectedTotal) / expectedTotal
	if drift > 0.002 {
		t.Errorf("ucast+mcast+bcast=%.0f vs totalInPkts=%.0f (drift %.3f%%, want ≤ 0.2%%)",
			gotTotal, expectedTotal, drift*100)
	}
}

// Counter32 shadow = low-32 of matching Counter64 HC value.
// Covers spec Requirement 1 "Counter32 shadow equals low-32 of Counter64".
func TestGetDynamic_Counter32ShadowEqualsLow32(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, 99, IfErrorClean)
	ic := c.ifCounters.Load()

	// Check both directions for all three shadow pairs at t ≈ 0.
	pairs := []struct {
		hc     string
		shadow string
	}{
		// ifXTable mcast/bcast shadows
		{".1.3.6.1.2.1.31.1.1.1.8.1", ".1.3.6.1.2.1.31.1.1.1.2.1"}, // ifHCInMulticast / ifInMulticast
		{".1.3.6.1.2.1.31.1.1.1.9.1", ".1.3.6.1.2.1.31.1.1.1.3.1"}, // ifHCInBroadcast / ifInBroadcast
		{".1.3.6.1.2.1.31.1.1.1.12.1", ".1.3.6.1.2.1.31.1.1.1.4.1"},
		{".1.3.6.1.2.1.31.1.1.1.13.1", ".1.3.6.1.2.1.31.1.1.1.5.1"},
		// ifTable ucast shadows
		{".1.3.6.1.2.1.31.1.1.1.7.1", ".1.3.6.1.2.1.2.2.1.11.1"}, // ifHCInUcast / ifInUcast
		{".1.3.6.1.2.1.31.1.1.1.11.1", ".1.3.6.1.2.1.2.2.1.17.1"},
	}
	// Freeze a single evaluation instant so the shadow and HC columns
	// see the same t — the invariant "shadow == uint32(HC & 0xFFFFFFFF)"
	// is exact by construction of GetDynamicAt, not drift-tolerant.
	tSec := time.Since(ic.startTime).Seconds()
	for _, p := range pairs {
		hcVal := parseU(t, ic.GetDynamicAt(p.hc, tSec))
		shVal := parseU(t, ic.GetDynamicAt(p.shadow, tSec))
		want := hcVal & 0xFFFFFFFF
		if shVal != want {
			t.Errorf("%s=%d, want low-32 of %s (%d)=%d (must be exact at same t)",
				p.shadow, shVal, p.hc, hcVal, want)
		}
	}
}

// `clean` scenario produces zero error/discard growth between polls.
// Covers spec Requirement 2 "`clean` produces zero error growth".
func TestScenario_CleanHasZeroErrors(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, 1, IfErrorClean)
	ic := c.ifCounters.Load()

	oids := []string{
		".1.3.6.1.2.1.2.2.1.13.1", // ifInDiscards
		".1.3.6.1.2.1.2.2.1.14.1", // ifInErrors
		".1.3.6.1.2.1.2.2.1.19.1", // ifOutDiscards
		".1.3.6.1.2.1.2.2.1.20.1", // ifOutErrors
	}
	start := map[string]uint64{}
	for _, oid := range oids {
		start[oid] = parseU(t, ic.GetDynamic(oid))
	}
	time.Sleep(20 * time.Millisecond)
	for _, oid := range oids {
		got := parseU(t, ic.GetDynamic(oid))
		if got != start[oid] {
			t.Errorf("%s grew under clean scenario: %d → %d", oid, start[oid], got)
		}
	}
}

// `failing` scenario produces strictly non-zero growth under traffic.
// Covers spec Requirement 2 "`failing` produces aggressive error growth".
func TestScenario_FailingAccumulatesErrors(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, 1, IfErrorFailing)
	ic := c.ifCounters.Load()

	t0 := parseU(t, ic.GetDynamic(".1.3.6.1.2.1.2.2.1.14.1"))
	time.Sleep(50 * time.Millisecond)
	t1 := parseU(t, ic.GetDynamic(".1.3.6.1.2.1.2.2.1.14.1"))
	if t1 <= t0 {
		t.Errorf("failing scenario: ifInErrors did not grow across 50ms poll window (%d → %d)", t0, t1)
	}
}

// Two cyclers with different scenarios sharing the same resources
// produce independent error streams; one simulator hosting a mix of
// scenarios works correctly.
// Covers spec Requirement 2 "Two devices with different scenarios do not interact".
func TestScenario_PerDeviceIsolation(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})

	clean := &MetricsCycler{}
	clean.InitIfCountersWithScenario(res, 7, IfErrorClean)
	cleanIC := clean.ifCounters.Load()

	failing := &MetricsCycler{}
	failing.InitIfCountersWithScenario(res, 7, IfErrorFailing)
	failIC := failing.ifCounters.Load()

	cleanStart := parseU(t, cleanIC.GetDynamic(".1.3.6.1.2.1.2.2.1.14.1"))
	failStart := parseU(t, failIC.GetDynamic(".1.3.6.1.2.1.2.2.1.14.1"))
	if cleanStart != 0 {
		t.Errorf("clean device started with non-zero errors: %d", cleanStart)
	}
	if failStart == 0 {
		t.Error("failing device should have a non-zero error pre-seed (~24h × failing-ppm)")
	}

	time.Sleep(30 * time.Millisecond)

	cleanAfter := parseU(t, cleanIC.GetDynamic(".1.3.6.1.2.1.2.2.1.14.1"))
	failAfter := parseU(t, failIC.GetDynamic(".1.3.6.1.2.1.2.2.1.14.1"))
	if cleanAfter != cleanStart {
		t.Errorf("clean device grew errors despite sharing resources with failing: %d → %d", cleanStart, cleanAfter)
	}
	if failAfter <= failStart {
		t.Errorf("failing device did not grow errors: %d → %d", failStart, failAfter)
	}
}

// ParseIfErrorScenario accepts the four canonical values (case-
// insensitive), defaults empty to clean, and rejects unknowns.
// Covers spec Requirements 2/3/4 "Unknown scenario string is rejected".
func TestParseIfErrorScenario(t *testing.T) {
	valid := map[string]IfErrorScenario{
		"":         IfErrorClean,
		"clean":    IfErrorClean,
		"Clean":    IfErrorClean,
		"CLEAN":    IfErrorClean,
		"typical":  IfErrorTypical,
		"degraded": IfErrorDegraded,
		"failing":  IfErrorFailing,
	}
	for in, want := range valid {
		got, err := ParseIfErrorScenario(in)
		if err != nil {
			t.Errorf("ParseIfErrorScenario(%q) error = %v; want nil", in, err)
		}
		if got != want {
			t.Errorf("ParseIfErrorScenario(%q) = %q; want %q", in, got, want)
		}
	}
	for _, bad := range []string{"banana", "none", "off", "healthy"} {
		if _, err := ParseIfErrorScenario(bad); err == nil {
			t.Errorf("ParseIfErrorScenario(%q) error = nil; want non-nil", bad)
		}
	}
}

// sFlow counter_sample body carries the same values SNMP returns for
// the same counters at the same t.
// Covers spec Requirement 5 "sFlow counter_sample matches concurrent SNMP GET".
func TestSFlowSnapshotMatchesSNMPAtSameInstant(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, 555, IfErrorTypical)
	ic := c.ifCounters.Load()

	adapter := NewInterfaceCounterSource(ic)

	// Freeze a single evaluation instant. Snapshot honors the passed-in
	// time; the SNMP reads below use the same frozen tSec. This makes
	// the "sFlow counter_sample matches concurrent SNMP GET" invariant
	// a byte-for-byte equality (spec Requirement 5), not drift-tolerant.
	snapshotAt := time.Now()
	tSec := snapshotAt.Sub(ic.startTime).Seconds()

	recs := adapter.Snapshot(snapshotAt)
	if len(recs) != 1 {
		t.Fatalf("Snapshot returned %d records, want 1", len(recs))
	}

	// Extract Counter32 fields from the sFlow body by offset.
	// See encodeIfCountersBody for the layout.
	body := recs[0].Body
	readU32 := func(off int) uint32 {
		return uint32(body[off])<<24 | uint32(body[off+1])<<16 | uint32(body[off+2])<<8 | uint32(body[off+3])
	}

	snmpInUcast := uint32(parseU(t, ic.GetDynamicAt(".1.3.6.1.2.1.2.2.1.11.1", tSec)))
	snmpInErr := uint32(parseU(t, ic.GetDynamicAt(".1.3.6.1.2.1.2.2.1.14.1", tSec)))

	// Body layout (see encodeIfCountersBody):
	//   0..3   u32 ifIndex
	//   4..7   u32 ifType
	//   8..15  u64 ifSpeed
	//  16..19  u32 ifDirection
	//  20..23  u32 ifStatus
	//  24..31  u64 ifInOctets
	//  32..35  u32 ifInUcastPkts
	//  36..39  u32 ifInMulticastPkts
	//  40..43  u32 ifInBroadcastPkts
	//  44..47  u32 ifInDiscards
	//  48..51  u32 ifInErrors
	sflowInUcast := readU32(32)
	sflowInErr := readU32(48)

	if snmpInUcast != sflowInUcast {
		t.Errorf("ifInUcastPkts SNMP=%d sFlow=%d (must match exactly at same t)", snmpInUcast, sflowInUcast)
	}
	if snmpInErr != sflowInErr {
		t.Errorf("ifInErrors SNMP=%d sFlow=%d (must match exactly at same t)", snmpInErr, sflowInErr)
	}
}

// `clean` scenario at t ≈ 0 returns exactly 0 for error / discard
// counters (no pre-seed under clean because ppm bands are [0, 0]).
// Covers spec Requirement 6 "Fresh device has zero error baseline under clean".
func TestCleanScenario_ZeroPreSeed(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, 88, IfErrorClean)
	ic := c.ifCounters.Load()

	for _, col := range []string{"13", "14", "19", "20"} {
		oid := fmt.Sprintf(".1.3.6.1.2.1.2.2.1.%s.1", col)
		if v := parseU(t, ic.GetDynamic(oid)); v != 0 {
			t.Errorf("clean scenario %s = %d at t≈0; want 0", oid, v)
		}
	}
}

// `typical` scenario at t ≈ 0 returns non-zero bases for error /
// discard counters (24h pre-seed at typical ppm band).
// Covers spec Requirement 6 "Fresh device has non-zero error baseline under typical".
func TestTypicalScenario_NonZeroPreSeed(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, 88, IfErrorTypical)
	ic := c.ifCounters.Load()

	// ifInErrors / ifInDiscards should both be > 0 at t=0 — typical
	// ppm × 24h packet pre-seed is orders of magnitude above 0.
	for _, col := range []string{"13", "14", "19", "20"} {
		oid := fmt.Sprintf(".1.3.6.1.2.1.2.2.1.%s.1", col)
		if v := parseU(t, ic.GetDynamic(oid)); v == 0 {
			t.Errorf("typical scenario %s = 0 at t≈0; expected non-zero pre-seed", oid)
		}
	}
}

// GetDynamic returns "" for IF-MIB OIDs outside the dynamic set, so the
// SNMP handler falls through to static JSON values.
// Covers spec Requirement 1 "Unknown dynamic column falls through to static JSON".
func TestGetDynamic_UnknownColumnFallsThrough(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, 1, IfErrorClean)
	ic := c.ifCounters.Load()

	// ifType (.3), ifMtu (.4), ifAdminStatus (.7), ifOperStatus (.8)
	// — none of these columns are in the dynamic set.
	for _, oid := range []string{
		".1.3.6.1.2.1.2.2.1.3.1",
		".1.3.6.1.2.1.2.2.1.4.1",
		".1.3.6.1.2.1.2.2.1.7.1",
		".1.3.6.1.2.1.2.2.1.8.1",
	} {
		if v := ic.GetDynamic(oid); v != "" {
			t.Errorf("GetDynamic(%q) = %q; want empty (fall through to static JSON)", oid, v)
		}
	}
}

// Legacy GetHCOctets shim still works for the two HC octet OIDs.
// Protects existing out-of-package callers during the deprecation window.
func TestGetHCOctets_LegacyShim(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, 1, IfErrorClean)
	ic := c.ifCounters.Load()

	in := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.6.1")
	out := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.10.1")
	if in == "" || out == "" {
		t.Errorf("legacy GetHCOctets returned empty for HC octet OIDs: in=%q out=%q", in, out)
	}
	// Should return empty for non-HC-octet columns.
	if v := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.7.1"); v != "" {
		t.Errorf("legacy GetHCOctets returned %q for non-HC-octet OID; want empty", v)
	}
}
