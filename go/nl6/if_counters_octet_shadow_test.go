/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"
)

// nl6#570: ifTable .10 (ifInOctets) and .16 (ifOutOctets) are the RFC 2863
// Counter32 shadows of ifXTable .6 / .10, and until this change they were the
// only IF-MIB counter columns served frozen from static JSON while their HC
// column climbed from ifSpeed. A collector computing a rate from them got 0 bps
// forever; one cross-checking them against the HC columns — which the RFC
// relationship invites — saw them disagree completely.
//
// The tests below are one per row of the change's I/O matrix. The shadow
// identity and the WALK ORDER are the two that matter most and for opposite
// reasons: the identity is the contract, and the ordering is the part that can
// break with no value assertion able to see it (nl6#526's class — snmp4j
// reports "OID not increasing", or TreeUtils never terminates).

const (
	octetShadowInOID   = ifTablePrefix + "10."
	octetShadowOutOID  = ifTablePrefix + "16."
	octetShadowHCInOID = ifXTablePrefix + "6."
	octetShadowHCOut   = ifXTablePrefix + "10."
)

// newOctetShadowCycler builds a published cycler over the given per-interface
// speeds, with the state engine wired (the ordinary production path).
func newOctetShadowCycler(t *testing.T, speeds []uint64, seed int64) *IfCounterCycler {
	t.Helper()
	res := buildTestResources(t, speeds)
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, seed, IfErrorTypical)
	ic := c.ifCounters.Load()
	if ic == nil {
		t.Fatal("InitIfCountersWithScenario published no cycler")
	}
	return ic
}

func octetShadowU64(t *testing.T, s string) uint64 {
	t.Helper()
	if s == "" {
		t.Fatal("cycler returned an empty value where a counter was expected")
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("value %q does not parse as an unsigned integer: %v", s, err)
	}
	return v
}

// TestOctetShadowsEqualLow32OfTheirHCColumn is the RFC 2863 contract, in both
// directions, at ONE captured instant. The single t is the whole point: the
// shadow is derived, never stored, so it cannot drift from the HC column — and
// asserting it at two clock reads would test something weaker than what a
// collector cross-checking one GET response actually sees.
func TestOctetShadowsEqualLow32OfTheirHCColumn(t *testing.T) {
	const gbps = 1_000_000_000
	ic := newOctetShadowCycler(t, []uint64{gbps, 100 * gbps, 400 * gbps}, 570)

	// Several instants, because a single one can agree by accident when both
	// sides are small.
	for _, tSec := range []float64{0, 0.5, 7, 3599, 3601, 86400, 1_000_000} {
		for ifIndex := 1; ifIndex <= 3; ifIndex++ {
			idx := strconv.Itoa(ifIndex)
			for _, pair := range []struct {
				dir          string
				shadow, hcOI string
			}{
				{"in", octetShadowInOID + idx, octetShadowHCInOID + idx},
				{"out", octetShadowOutOID + idx, octetShadowHCOut + idx},
			} {
				shadow := octetShadowU64(t, ic.GetDynamicAt(pair.shadow, tSec))
				hc := octetShadowU64(t, ic.GetDynamicAt(pair.hcOI, tSec))
				if want := hc & 0xFFFFFFFF; shadow != want {
					t.Errorf("t=%g if%d %s: %s = %d, want uint32(%s=%d & 0xFFFFFFFF) = %d",
						tSec, ifIndex, pair.dir, pair.shadow, shadow, pair.hcOI, hc, want)
				}
				if shadow > math.MaxUint32 {
					t.Errorf("t=%g if%d %s: %s = %d exceeds Counter32",
						tSec, ifIndex, pair.dir, pair.shadow, shadow)
				}
			}
		}
	}
}

// TestOctetShadowsAdvance is the defect itself: both columns were frozen, so a
// rate computed from them was 0 bps forever.
func TestOctetShadowsAdvance(t *testing.T) {
	const gbps = 1_000_000_000
	ic := newOctetShadowCycler(t, []uint64{gbps}, 571)

	// The claim is MODULAR, not an inequality: 10 s at 1 Gbps is ~1.25e9 octets
	// against a 2^32 counter seeded as if the device had been up a day, so a
	// wrap inside the window is ordinary and an inequality would fail on it
	// (measured: it does). What must hold is that the column moved, and moved by
	// exactly the HC column's delta.
	for _, pair := range []struct{ shadow, hcOID string }{
		{octetShadowInOID + "1", octetShadowHCInOID + "1"},
		{octetShadowOutOID + "1", octetShadowHCOut + "1"},
	} {
		first := octetShadowU64(t, ic.GetDynamicAt(pair.shadow, 10))
		second := octetShadowU64(t, ic.GetDynamicAt(pair.shadow, 20))
		hcFirst := octetShadowU64(t, ic.GetDynamicAt(pair.hcOID, 10))
		hcSecond := octetShadowU64(t, ic.GetDynamicAt(pair.hcOID, 20))

		if hcSecond <= hcFirst {
			t.Fatalf("%s did not advance between t=10 s and t=20 s (%d -> %d); the premise of "+
				"this test is gone", pair.hcOID, hcFirst, hcSecond)
		}
		if first == second {
			t.Errorf("%s reads %d at both t=10 s and t=20 s — the column is frozen, which is the "+
				"0-bps-forever defect nl6#570 fixed", pair.shadow, first)
		}
		if want := (first + (hcSecond - hcFirst)) & 0xFFFFFFFF; second != want {
			t.Errorf("%s advanced %d -> %d, but its HC column advanced by %d, so the shadow "+
				"should read %d", pair.shadow, first, second, hcSecond-hcFirst, want)
		}
	}
}

// TestOctetShadowsWrapAndStayCounter32 covers the row the issue's own caveat
// names: at 400 Gbps a Counter32 wraps in ~86 ms, so wrapping is the NORMAL
// case for these columns, not an edge one. The shadow must wrap with the HC
// column and never leave the Counter32 range.
func TestOctetShadowsWrapAndStayCounter32(t *testing.T) {
	const gbps = 1_000_000_000
	ic := newOctetShadowCycler(t, []uint64{400 * gbps}, 572)

	// One hour at 400 Gbps is ~1.8e14 octets — tens of thousands of wraps.
	const tSec = 3600
	wrapped := 0
	for _, pair := range []struct{ shadow, hcOID string }{
		{octetShadowInOID + "1", octetShadowHCInOID + "1"},
		{octetShadowOutOID + "1", octetShadowHCOut + "1"},
	} {
		hc := octetShadowU64(t, ic.GetDynamicAt(pair.hcOID, tSec))
		if hc <= math.MaxUint32 {
			t.Fatalf("%s = %d has not passed 2^32 at t=%d s, so this test is not exercising a "+
				"wrap", pair.hcOID, hc, tSec)
		}
		wrapped++
		shadow := octetShadowU64(t, ic.GetDynamicAt(pair.shadow, tSec))
		if shadow != hc&0xFFFFFFFF {
			t.Errorf("%s = %d, want the wrapped low 32 bits of %d (= %d)",
				pair.shadow, shadow, hc, hc&0xFFFFFFFF)
		}
		if shadow > math.MaxUint32 {
			t.Errorf("%s = %d is not a legal Counter32", pair.shadow, shadow)
		}
	}
	if wrapped != 2 {
		t.Fatalf("only %d of 2 directions exercised a wrap", wrapped)
	}
}

// TestOctetShadowWalkOrderAndCompleteness is the ordering guard. It drives the
// real enumeration from before the cycler's first OID to the end of the walk and
// asserts three things a value assertion cannot see: every step strictly
// increases per compareOIDs, .10 lands between .9 and .11 (and .16 between .14
// and .17), and each new column appears exactly once per known ifIndex.
func TestOctetShadowWalkOrderAndCompleteness(t *testing.T) {
	const gbps = 1_000_000_000
	ifIndexes := []int{1, 2, 3}
	ic := newOctetShadowCycler(t, []uint64{gbps, gbps, gbps}, 573)

	var walked []string
	cur := ".1.3.6.1.2.1.2.2.1"
	for i := 0; ; i++ {
		if i > 10_000 {
			t.Fatal("walk did not terminate")
		}
		next, val := ic.NextDynamicOID(cur)
		if next == "" {
			break
		}
		if val == "" {
			t.Fatalf("step %d: %s has an empty value", i, next)
		}
		if compareOIDs(next, cur) <= 0 {
			t.Fatalf("step %d: %s does not increase on %s. A non-increasing walk is nl6#526's "+
				"class: snmp4j reports \"OID not increasing\" or TreeUtils never terminates",
				i, next, cur)
		}
		walked = append(walked, next)
		cur = next
	}

	seen := map[string]int{}
	for _, o := range walked {
		seen[o]++
	}
	for _, o := range walked {
		if seen[o] != 1 {
			t.Errorf("%s appears %d times in one walk", o, seen[o])
		}
	}
	for _, ifIndex := range ifIndexes {
		for _, oid := range []string{
			octetShadowInOID + strconv.Itoa(ifIndex),
			octetShadowOutOID + strconv.Itoa(ifIndex),
		} {
			if seen[oid] != 1 {
				t.Errorf("%s appears %d times in a full ifTable walk, want exactly once",
					oid, seen[oid])
			}
		}
	}

	// Position: the ifTable columns must come out .9 → .10 → .11 and
	// .14 → .16 → .17, each block covering every ifIndex before the next
	// column starts.
	wantPrefixSeq := []string{"9", "10", "11", "13", "14", "16", "17", "19", "20"}
	var gotSeq []string
	for _, o := range walked {
		if len(o) <= len(ifTablePrefix) || o[:len(ifTablePrefix)] != ifTablePrefix {
			continue
		}
		rest := o[len(ifTablePrefix):]
		col := rest[:len(rest)-len("."+strconv.Itoa(1))]
		// Column runs, collapsed: record a column the first time it appears.
		if len(gotSeq) == 0 || gotSeq[len(gotSeq)-1] != col {
			gotSeq = append(gotSeq, col)
		}
	}
	// The walk starts at .7 (the state cols); drop everything before .9.
	for len(gotSeq) > 0 && gotSeq[0] != "9" {
		gotSeq = gotSeq[1:]
	}
	if fmt.Sprint(gotSeq) != fmt.Sprint(wantPrefixSeq) {
		t.Errorf("ifTable column order in the walk = %v, want %v", gotSeq, wantPrefixSeq)
	}
}

// TestOctetShadowMatchesSFlowCounterSample is the cross-protocol row. The sFlow
// generic-interface-counters body carries ifInOctets / ifOutOctets as u64 taken
// from the HC columns, so at one instant the SNMP Counter32 shadow must be
// exactly their low 32 bits — the same identity, across two protocols, from one
// captured t.
func TestOctetShadowMatchesSFlowCounterSample(t *testing.T) {
	const gbps = 1_000_000_000
	ic := newOctetShadowCycler(t, []uint64{100 * gbps}, 574)

	snapshotAt := time.Now().Add(90 * time.Second)
	tSec := snapshotAt.Sub(ic.startTime).Seconds()

	recs := NewInterfaceCounterSource(ic).Snapshot(snapshotAt)
	if len(recs) != 1 {
		t.Fatalf("Snapshot returned %d records, want 1", len(recs))
	}
	body := recs[0].Body
	if len(body) != 88 {
		t.Fatalf("counter body is %d bytes, want 88", len(body))
	}
	// Offsets from encodeIfCountersBody: u64 ifInOctets at 24, u64 ifOutOctets
	// at 56.
	sflowIn := binary.BigEndian.Uint64(body[24:])
	sflowOut := binary.BigEndian.Uint64(body[56:])

	snmpIn := octetShadowU64(t, ic.GetDynamicAt(octetShadowInOID+"1", tSec))
	snmpOut := octetShadowU64(t, ic.GetDynamicAt(octetShadowOutOID+"1", tSec))

	if snmpIn != sflowIn&0xFFFFFFFF {
		t.Errorf("ifInOctets: SNMP %d, sFlow low-32 %d (sFlow u64 %d)",
			snmpIn, sflowIn&0xFFFFFFFF, sflowIn)
	}
	if snmpOut != sflowOut&0xFFFFFFFF {
		t.Errorf("ifOutOctets: SNMP %d, sFlow low-32 %d (sFlow u64 %d)",
			snmpOut, sflowOut&0xFFFFFFFF, sflowOut)
	}
}

// TestOctetShadowsEmitCounter32 pins the wire type. The cycler's values are
// decimal strings and the tag comes from oidTypeTable, so a column added to the
// cycler without a Counter32 declaration would go out as an INTEGER — the
// change's Block If.
func TestOctetShadowsEmitCounter32(t *testing.T) {
	for _, oid := range []string{ifTablePrefix + "10.1", ifTablePrefix + "16.1"} {
		// A value above Integer32 is deliberate: an untyped leaf would not
		// merely mistag it, it would encode it as a 5-byte INTEGER.
		enc := encodeTypedValue(oid, "4294967295")
		if len(enc) == 0 || enc[0] != ASN1_COUNTER32 {
			t.Errorf("%s encodes as % x, want a Counter32 (0x%02X) — the dynamic value would "+
				"otherwise reach the wire as an INTEGER", oid, enc, ASN1_COUNTER32)
		}
	}
}

// TestOctetShadowWithoutCyclerIsUnchanged covers the no-cycler row: a device
// built without a metricsCycler (every newTestServer-based suite) must keep
// answering both columns from the static map, with no panic. findResponse
// consults the cycler first, so this is the branch that says the fall-through
// still exists.
func TestOctetShadowWithoutCyclerIsUnchanged(t *testing.T) {
	s := newTestServer(map[string]string{
		"1.3.6.1.2.1.2.2.1.10.1": "1012345678",
		"1.3.6.1.2.1.2.2.1.16.1": "911111111",
	})
	if s.device.metricsCycler != nil {
		t.Fatal("newTestServer grew a metrics cycler; this test no longer covers the nil path")
	}
	for oid, want := range map[string]string{
		".1.3.6.1.2.1.2.2.1.10.1": "1012345678",
		".1.3.6.1.2.1.2.2.1.16.1": "911111111",
	} {
		if got := s.findResponse(oid); got != want {
			t.Errorf("findResponse(%s) = %q, want %q", oid, got, want)
		}
	}
}

// TestNoStaticOctetShadowEntriesShip is the corpus row. The cycler now serves
// both columns and findResponse consults it first, so any static entry for them
// is unreachable dead data — and dead data that looks authoritative is how the
// frozen-counter defect survived long enough to need an issue.
func TestNoStaticOctetShadowEntriesShip(t *testing.T) {
	offenders := 0
	for _, e := range shippedSNMPEntries(t) {
		for _, prefix := range []string{ifTablePrefix + "10.", ifTablePrefix + "16."} {
			if len(e.OID) > len(prefix) && e.OID[:len(prefix)] == prefix {
				offenders++
				t.Errorf("%s still serves %s = %q statically; the cycler shadows it, so the "+
					"entry is unreachable", e.Part, e.OID, e.Value)
			}
		}
	}
	if offenders == 0 {
		t.Logf("no shipped profile serves ifTable .10 / .16 statically (1322 entries deleted "+
			"across %d profiles)", len(shippedProfileNames(t)))
	}
}
