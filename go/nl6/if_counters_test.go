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
	"strconv"
	"sync"
	"testing"
	"time"
)

// buildTestResources constructs a minimal DeviceResources with HC counter and
// speed OIDs for the given contiguous interface list (speeds in bps).
func buildTestResources(t *testing.T, speeds []uint64) *DeviceResources {
	t.Helper()
	res := &DeviceResources{
		oidIndex: &sync.Map{},
	}
	for i, spd := range speeds {
		ifIndex := i + 1
		// ifHighSpeed in Mbps
		res.oidIndex.Store(
			fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.15.%d", ifIndex),
			strconv.FormatUint(spd/1_000_000, 10),
		)
		// HC in/out placeholders (InitIfCounters only reads speed, not these values)
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.6.%d", ifIndex), "0")
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.10.%d", ifIndex), "0")
	}
	return res
}

// buildSparseTestResources constructs resources with HC OIDs only at the given
// ifIndex values (sparse, non-contiguous).
func buildSparseTestResources(t *testing.T, ifIndexes []int, speedBps uint64) *DeviceResources {
	t.Helper()
	res := &DeviceResources{oidIndex: &sync.Map{}}
	for _, idx := range ifIndexes {
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.15.%d", idx),
			strconv.FormatUint(speedBps/1_000_000, 10))
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.6.%d", idx), "0")
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.10.%d", idx), "0")
	}
	return res
}

func TestIfCounterCycler_Monotonic(t *testing.T) {
	const gbps = 1_000_000_000
	res := buildTestResources(t, []uint64{gbps, gbps})

	c := &MetricsCycler{}
	c.InitIfCounters(res, 42)

	ic := c.ifCounters.Load()
	if ic == nil {
		t.Fatal("InitIfCounters did not create ifCounters")
	}

	// Poll 5 times with small sleeps and verify strict monotonic increase.
	prev1, prev2 := uint64(0), uint64(0)
	for poll := 0; poll < 5; poll++ {
		time.Sleep(5 * time.Millisecond)

		v1str := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.6.1")
		v2str := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.6.2")
		v1, err1 := strconv.ParseUint(v1str, 10, 64)
		v2, err2 := strconv.ParseUint(v2str, 10, 64)
		if err1 != nil || err2 != nil {
			t.Fatalf("poll %d: non-numeric HC value (%q, %q)", poll, v1str, v2str)
		}
		if poll > 0 && v1 <= prev1 {
			t.Errorf("poll %d: ifHCInOctets.1 not increasing: %d -> %d", poll, prev1, v1)
		}
		if poll > 0 && v2 <= prev2 {
			t.Errorf("poll %d: ifHCInOctets.2 not increasing: %d -> %d", poll, prev2, v2)
		}
		prev1, prev2 = v1, v2
	}
}

func TestIfCounterCycler_NoWrapAtZero(t *testing.T) {
	// Read the counter immediately after init (t ≈ 0). The integral can be a
	// tiny negative float due to floating-point imprecision; if cast directly to
	// uint64 it wraps to ~2^64. The clamp-to-zero guard must prevent this.
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCounters(res, 99)

	ic := c.ifCounters.Load()
	vStr := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.6.1")
	v, err := strconv.ParseUint(vStr, 10, 64)
	if err != nil {
		t.Fatalf("non-numeric value at t≈0: %q", vStr)
	}

	// Must be a sane positive value (≥10 GB from 24h seeding) and well below
	// the uint64 wrap sentinel (> 2^63).
	const minExpected = uint64(1e10)     // 10 GB
	const wrapSentinel = uint64(1) << 63 // half of uint64 max
	if v < minExpected {
		t.Errorf("counter at t≈0 is %d, too small — base seeding failed or clamped to 0", v)
	}
	if v > wrapSentinel {
		t.Errorf("counter at t≈0 is %d, suspiciously large — uint64 wrap likely occurred", v)
	}
}

func TestIfCounterCycler_RateInRange(t *testing.T) {
	// Use a 10 Gbps interface and verify the byte-rate is within [60%, 100%] of capacity.
	const gbps10 = 10_000_000_000
	res := buildTestResources(t, []uint64{gbps10})

	c := &MetricsCycler{}
	c.InitIfCounters(res, 7)

	ic := c.ifCounters.Load()
	if ic == nil {
		t.Fatal("InitIfCounters did not create ifCounters")
	}

	// Sample over ~100 ms; compute average byte-rate.
	start := time.Now()
	v0str := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.6.1")
	v0, _ := strconv.ParseUint(v0str, 10, 64)

	time.Sleep(100 * time.Millisecond)

	v1str := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.6.1")
	v1, _ := strconv.ParseUint(v1str, 10, 64)
	elapsed := time.Since(start).Seconds()

	rate := float64(v1-v0) / elapsed // bytes/sec
	speedBytesPerSec := float64(gbps10) / 8.0

	minRate := speedBytesPerSec * 0.50 // allow 10% margin below 60%
	maxRate := speedBytesPerSec * 1.10 // allow 10% margin above 100%

	if rate < minRate || rate > maxRate {
		t.Errorf("byte-rate %.0f B/s out of expected range [%.0f, %.0f] B/s (%.1f%% of capacity)",
			rate, minRate, maxRate, rate/speedBytesPerSec*100)
	}
}

func TestIfCounterCycler_UnknownOID(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCounters(res, 1)

	ic := c.ifCounters.Load()
	// Wrong column — should return empty string
	if v := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.7.1"); v != "" {
		t.Errorf("expected empty for non-HC OID, got %q", v)
	}
	// Out-of-range interface index
	if v := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.6.99"); v != "" {
		t.Errorf("expected empty for out-of-range ifIndex, got %q", v)
	}
}

func TestIfCounterCycler_SparseIfIndex(t *testing.T) {
	// Device with ifIndex 1, 3, 5 only (gaps at 2 and 4).
	// GetHCOctets for the missing indices must return "".
	res := buildSparseTestResources(t, []int{1, 3, 5}, 1_000_000_000)
	c := &MetricsCycler{}
	c.InitIfCounters(res, 77)

	ic := c.ifCounters.Load()
	if ic == nil {
		t.Fatal("InitIfCounters did not create ifCounters")
	}

	time.Sleep(5 * time.Millisecond)

	// Known indices should return live values.
	for _, idx := range []int{1, 3, 5} {
		oid := fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.6.%d", idx)
		if v := ic.GetHCOctets(oid); v == "" {
			t.Errorf("expected non-empty for known ifIndex %d, got empty", idx)
		}
	}

	// Missing indices must not return a live counter.
	for _, idx := range []int{2, 4} {
		oid := fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.6.%d", idx)
		if v := ic.GetHCOctets(oid); v != "" {
			t.Errorf("expected empty for missing ifIndex %d, got %q", idx, v)
		}
	}
}

func TestIfCounterCycler_InOutDiffer(t *testing.T) {
	// In- and out-octets use independent phase offsets and bases; their values
	// should differ by a measurable amount after a brief interval.
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCounters(res, 123456)

	time.Sleep(10 * time.Millisecond)
	ic := c.ifCounters.Load()
	inStr := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.6.1")
	outStr := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.10.1")

	in, _ := strconv.ParseUint(inStr, 10, 64)
	out, _ := strconv.ParseUint(outStr, 10, 64)

	// The bases differ by up to ~5% of avg24h (~43 GB at 1 Gbps/80%/24h).
	// Require at least 1 MB difference, which is well within the expected jitter.
	const minDelta = uint64(1 << 20) // 1 MB
	var delta uint64
	if in > out {
		delta = in - out
	} else {
		delta = out - in
	}
	if delta < minDelta {
		t.Errorf("ifHCInOctets (%d) and ifHCOutOctets (%d) differ by only %d bytes — independent bases/phases may not be working", in, out, delta)
	}
}

func TestIfCounterCycler_NoHCOIDs(t *testing.T) {
	// A device with no HC OIDs in oidIndex must leave ifCounters nil.
	res := &DeviceResources{oidIndex: &sync.Map{}}
	res.oidIndex.Store(".1.3.6.1.2.1.1.1.0", "Linux 5.15")

	c := &MetricsCycler{}
	c.InitIfCounters(res, 1)

	if c.ifCounters.Load() != nil {
		t.Error("expected ifCounters to be nil for device with no HC OIDs")
	}
}

// TestInterfaceCounterSource_MatchesSNMPSurface is the regression gate for the
// sFlow Phase 2 CounterSource abstraction (openspec capability flow-export-sflow,
// "InterfaceCounterSource reuses IfCounterCycler state" scenario).
//
// The adapter exposes the same octet counters that ifHCInOctets / ifHCOutOctets
// return over SNMP, so a collector reading both surfaces for the same device
// at the same time sees identical values. Because GetHCOctets is time-driven,
// we compare the adapter body's octets against a snapshot taken within the
// same goroutine tick.
func TestInterfaceCounterSource_MatchesSNMPSurface(t *testing.T) {
	const gbps = 1_000_000_000
	res := buildTestResources(t, []uint64{gbps, gbps, gbps})

	c := &MetricsCycler{}
	c.InitIfCounters(res, 4242)
	ic := c.ifCounters.Load()
	if ic == nil {
		t.Fatal("InitIfCounters did not create ifCounters")
	}

	adapter := NewInterfaceCounterSource(ic)
	if adapter == nil {
		t.Fatal("NewInterfaceCounterSource returned nil")
	}
	recs := adapter.Snapshot(time.Now())
	if len(recs) != 3 {
		t.Fatalf("Snapshot returned %d records, want 3", len(recs))
	}
	// Build a map of ifIndex -> decoded (in, out) octets for each adapter record.
	decoded := make(map[uint32][2]uint64)
	for _, r := range recs {
		if len(r.Body) != 88 {
			t.Fatalf("if_counters body length = %d, want 88", len(r.Body))
		}
		ifIdx := uint32ByBigEndian(r.Body[0:])
		in := uint64ByBigEndian(r.Body[24:])
		out := uint64ByBigEndian(r.Body[56:])
		decoded[ifIdx] = [2]uint64{in, out}
	}
	// Read the SNMP-surface values as closely as possible to the adapter call
	// and assert the absolute difference is within a small tolerance (the
	// floating-point integral drifts with the time delta between the two
	// Snapshot / GetHCOctets calls).
	for ifIdx := uint32(1); ifIdx <= 3; ifIdx++ {
		pair, ok := decoded[ifIdx]
		if !ok {
			t.Errorf("adapter missing ifIndex %d", ifIdx)
			continue
		}
		inStr := ic.GetHCOctets(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.6.%d", ifIdx))
		outStr := ic.GetHCOctets(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.10.%d", ifIdx))
		snmpIn, _ := strconv.ParseUint(inStr, 10, 64)
		snmpOut, _ := strconv.ParseUint(outStr, 10, 64)

		// At 1 Gbps ≈ 125 MB/s, one millisecond of drift moves the counter by
		// up to 125 KB. Allow 2 MB slack for slow CI machines.
		const slack = uint64(2 << 20)
		adapterIn, adapterOut := pair[0], pair[1]
		if absDiff(adapterIn, snmpIn) > slack {
			t.Errorf("ifIndex %d in-octets adapter=%d vs SNMP=%d differ by more than slack %d",
				ifIdx, adapterIn, snmpIn, slack)
		}
		if absDiff(adapterOut, snmpOut) > slack {
			t.Errorf("ifIndex %d out-octets adapter=%d vs SNMP=%d differ by more than slack %d",
				ifIdx, adapterOut, snmpOut, slack)
		}
	}
}

// absDiff returns |a - b|.
func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// uint32ByBigEndian and uint64ByBigEndian avoid pulling encoding/binary into
// this test file just to parse 4- and 8-byte big-endian integers. Identical to
// binary.BigEndian.Uint32 / Uint64 at the byte level.
func uint32ByBigEndian(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint64ByBigEndian(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func TestIfCounterCycler_BaseIsPositive(t *testing.T) {
	// At t≈0, counter must equal approximately base (large positive number).
	res := buildTestResources(t, []uint64{1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCounters(res, 99)

	// Read immediately (t ≈ 0)
	ic := c.ifCounters.Load()
	vStr := ic.GetHCOctets(".1.3.6.1.2.1.31.1.1.1.6.1")
	v, _ := strconv.ParseUint(vStr, 10, 64)

	// ~24h of 80% traffic at 1 Gbps ≈ 8.64 TB; require at least 10 GB.
	const minExpected = uint64(1e10)
	if v < minExpected {
		t.Errorf("initial counter value %d is unexpectedly small (< %d); base seeding may have failed", v, minExpected)
	}
}

// TestIfCounterCycler_NextDynamicOID_WalksColumnWithoutStatic exercises the
// bug that `snmpwalk .1.3.6.1.2.1.31.1.1.1.8` reported "OID not supported"
// on devices whose JSON omits ifHCInMulticastPkts instances. The cycler
// must enumerate the column analytically so the walk machinery has
// instance rows to return.
func TestIfCounterCycler_NextDynamicOID_WalksColumnWithoutStatic(t *testing.T) {
	res := buildSparseTestResources(t, []int{1, 3, 5}, 1_000_000_000)
	c := &MetricsCycler{}
	c.InitIfCounters(res, 42)
	ic := c.ifCounters.Load()
	if ic == nil {
		t.Fatal("InitIfCounters did not create ifCounters")
	}

	// Starting from the bare ifHCInMulticastPkts column, the walk must
	// land on the smallest owned ifIndex (1), then step through 3 and 5,
	// then cross into column 9 (ifHCInBroadcastPkts) at ifIndex 1.
	want := []string{
		".1.3.6.1.2.1.31.1.1.1.8.1",
		".1.3.6.1.2.1.31.1.1.1.8.3",
		".1.3.6.1.2.1.31.1.1.1.8.5",
		".1.3.6.1.2.1.31.1.1.1.9.1",
	}
	cur := ".1.3.6.1.2.1.31.1.1.1.8"
	for i, exp := range want {
		next, val := ic.NextDynamicOID(cur)
		if next != exp {
			t.Fatalf("step %d: got next=%q, want %q", i, next, exp)
		}
		if val == "" {
			t.Fatalf("step %d: empty value for %s", i, next)
		}
		if _, err := strconv.ParseUint(val, 10, 64); err != nil {
			t.Fatalf("step %d: non-numeric value %q for %s: %v", i, val, next, err)
		}
		cur = next
	}
}

// TestIfCounterCycler_NextDynamicOID_OrderAndBounds pins the enumeration
// order: ifTable columns come before ifXTable, within each table columns
// are ascending, within each column ifIndexes are ascending, and walking
// past the last owned OID returns ("", "").
func TestIfCounterCycler_NextDynamicOID_OrderAndBounds(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000, 1_000_000_000})
	c := &MetricsCycler{}
	c.InitIfCounters(res, 7)
	ic := c.ifCounters.Load()
	if ic == nil {
		t.Fatal("InitIfCounters did not create ifCounters")
	}

	// Before the first dynamic row, walk must land on it.
	if got, _ := ic.NextDynamicOID(".1.3.6.1.2.1.2"); got != ic.FirstDynamicOID() {
		t.Errorf("pre-first: got %q, want FirstDynamicOID=%q", got, ic.FirstDynamicOID())
	}

	// First dynamic row must be ifTable column 11 ifIndex 1 (ifInUcastPkts.1).
	if got := ic.FirstDynamicOID(); got != ".1.3.6.1.2.1.2.2.1.11.1" {
		t.Errorf("FirstDynamicOID: got %q, want .1.3.6.1.2.1.2.2.1.11.1", got)
	}
	// Last dynamic row must be ifXTable column 13 at the largest ifIndex (2).
	if got := ic.LastDynamicOID(); got != ".1.3.6.1.2.1.31.1.1.1.13.2" {
		t.Errorf("LastDynamicOID: got %q, want .1.3.6.1.2.1.31.1.1.1.13.2", got)
	}

	// ifTable → ifXTable boundary: stepping past the last ifTable column
	// (.20.2) must cross into the first ifXTable column (.2.1).
	if got, _ := ic.NextDynamicOID(".1.3.6.1.2.1.2.2.1.20.2"); got != ".1.3.6.1.2.1.31.1.1.1.2.1" {
		t.Errorf("ifTable→ifXTable boundary: got %q, want .1.3.6.1.2.1.31.1.1.1.2.1", got)
	}

	// Past the last dynamic row → end of walk.
	if got, val := ic.NextDynamicOID(ic.LastDynamicOID()); got != "" || val != "" {
		t.Errorf("past-last: got (%q, %q), want empty", got, val)
	}
}
