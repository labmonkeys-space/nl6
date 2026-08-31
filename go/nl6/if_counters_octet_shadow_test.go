/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// nl6#570: ifTable .10 (ifInOctets) and .16 (ifOutOctets) are served as the low
// 32 bits of ifXTable .6 / .10, and until this change they were the only IF-MIB
// counter columns served frozen from static JSON while their HC column climbed
// from ifSpeed. A collector computing a rate from them got 0 bps forever; one
// cross-checking them against the HC columns saw them disagree completely.
//
// The low-32 equality is a DE-FACTO convention, not an RFC 2863 mandate: the
// ifXTable DESCRIPTION calls ifHCInOctets "a 64-bit version of ifInOctets" and
// §3.1.6 mandates only which WIDTH to serve at which speed. Deriving one from
// the other is nl6's choice; see the dispatch comment in if_counters.go.
//
// SCOPE OF THE IDENTITY, which these tests assert and the docs now state: it
// holds for a caller passing ONE t to GetDynamicAt across both columns (sFlow
// counter_sample, gNMI). The per-OID SNMP path calls GetDynamic, which reads the
// clock per varbind, so a multi-varbind GET spanning .10 and ifXTable .6 samples
// two instants — pinned as a caveat by
// TestOctetShadowThroughGetDynamicReadsTheClockPerCall rather than papered over.
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

// TestOctetShadowsEqualLow32OfTheirHCColumn is the shadow contract, in both
// directions. WITHIN each comparison both columns are read at ONE shared t,
// which is the scope the identity actually has; the loop then repeats that
// comparison over several instants and three speeds, because a single instant
// can agree by accident when both sides are small. Those are not competing
// stories — one t per comparison, many comparisons (nl6#570 review, R11).
//
// The range check is on the ENCODED value, not on the parsed integer: having
// just asserted shadow == hc & 0xFFFFFFFF, a `shadow > MaxUint32` test cannot
// fire, and would read as Counter32 coverage while asserting nothing.
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
				raw := ic.GetDynamicAt(pair.shadow, tSec)
				shadow := octetShadowU64(t, raw)
				hc := octetShadowU64(t, ic.GetDynamicAt(pair.hcOI, tSec))
				if want := hc & 0xFFFFFFFF; shadow != want {
					t.Errorf("t=%g if%d %s: %s = %d, want uint32(%s=%d & 0xFFFFFFFF) = %d",
						tSec, ifIndex, pair.dir, pair.shadow, shadow, pair.hcOI, hc, want)
				}
				assertEncodesAsCounter32(t, pair.shadow, raw)
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

	// One hour at 400 Gbps is ~1.8e14 octets — tens of thousands of wraps. Each
	// row Fatalf's if its HC column has NOT passed 2^32, which is what makes
	// "this test exercised a wrap" true; the after-the-loop counter this
	// replaces could never fire, since the loop bailed before incrementing it
	// and incremented unconditionally otherwise (nl6#570 review, R11).
	const tSec = 3600
	for _, pair := range []struct{ shadow, hcOID string }{
		{octetShadowInOID + "1", octetShadowHCInOID + "1"},
		{octetShadowOutOID + "1", octetShadowHCOut + "1"},
	} {
		hc := octetShadowU64(t, ic.GetDynamicAt(pair.hcOID, tSec))
		if hc <= math.MaxUint32 {
			t.Fatalf("%s = %d has not passed 2^32 at t=%d s, so this test is not exercising a "+
				"wrap", pair.hcOID, hc, tSec)
		}
		raw := ic.GetDynamicAt(pair.shadow, tSec)
		shadow := octetShadowU64(t, raw)
		if shadow != hc&0xFFFFFFFF {
			t.Errorf("%s = %d, want the wrapped low 32 bits of %d (= %d)",
				pair.shadow, shadow, hc, hc&0xFFFFFFFF)
		}
		// The real range statement: what goes on the WIRE is a Counter32 and it
		// decodes back to the same number.
		assertEncodesAsCounter32(t, pair.shadow, raw)
	}
}

// TestOctetShadowWalkOrderAndCompleteness is the ordering guard. It drives the
// real enumeration from before the cycler's first OID to the end of the walk and
// asserts three things a value assertion cannot see: every step strictly
// increases per compareOIDs, .10 lands between .9 and .11 (and .16 between .14
// and .17), and each new column appears exactly once per known ifIndex.
func TestOctetShadowWalkOrderAndCompleteness(t *testing.T) {
	const gbps = 1_000_000_000
	// A MULTI-DIGIT ifIndex is deliberate: shipped profiles reach 144
	// interfaces, and the first cut of this test trimmed a hard-coded two
	// characters off each row suffix, so it could only ever run on 1..9 and the
	// most important test in the change could not be widened (nl6#570 review,
	// R3). The sparse set also exercises the successor search.
	ifIndexes := []int{1, 2, 12}
	ic := newSparseOctetShadowCycler(t, ifIndexes, gbps, 573)

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
		// Split at the LAST dot: the instance is 1..N digits wide, not one.
		dot := strings.LastIndexByte(rest, '.')
		if dot <= 0 {
			t.Fatalf("walked OID %q has no instance suffix", o)
		}
		col := rest[:dot]
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
	if len(body) != sflowIfCountersBodyLen {
		t.Fatalf("counter body is %d bytes, want %d", len(body), sflowIfCountersBodyLen)
	}
	// The offsets are the encoder's own named constants, pinned to it by
	// TestSFlowOctetOffsetsMatchTheEncoder, so a field insertion cannot
	// silently re-point this comparison at a different counter (review R12).
	sflowIn := binary.BigEndian.Uint64(body[sflowIfCountersInOctets:])
	sflowOut := binary.BigEndian.Uint64(body[sflowIfCountersOutOctet:])

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

// ── the corpus rows (R7, R10) ───────────────────────────────────────────────

// staticRowsOnCyclerOwnedIfTableColumns is the census of static entries that
// still ship on an ifTable column the cycler owns, counting only entries with
// exactly one instance sub-identifier. Measured mechanically over resources/.
//
// It exists because nl6#570 applies the dead-data rule to TWO columns and the
// class is wider than that (review R10). The three cases are different and the
// difference is the point:
//
//   - .10 / .16 — the columns this change took over. ZERO may remain: the
//     cycler answers them, so a static entry is unreachable.
//   - .7 ifAdminStatus / .8 ifOperStatus — LIVE data despite being
//     cycler-served. InitIfCountersWithScenario reads both out of oidIndex to
//     SEED the interface-state engine (if_counters.go, `ic.state.Seed`), so
//     deleting them would change every device's initial state. They are a
//     carve-out on evidence, not on assumption.
//   - .9 ifLastChange / .11 ifInUcastPkts / .17 ifOutUcastPkts — unreachable by
//     exactly this change's argument, and NOT fixed here (the change's Never
//     clause forbids touching the other shadows). .9 is not read by the seed
//     loop, which only looks at .7 and .8. Filed as follow-up; the numbers are
//     pinned so the class cannot grow while that is pending.
//
// Two further BARE `.8` entries (a column OID with no instance) ship as well.
// They are not counted here because they are not rows; they belong to
// bareColumnEntriesShipped and TestBareColumnCensusHasNotGrown.
var staticRowsOnCyclerOwnedIfTableColumns = map[int]int{
	colIfAdminStatus:  887, // live: seeds the state engine
	colIfOperStatus:   887, // live: seeds the state engine
	colIfLastChange:   646, // dead, out of scope, filed
	colIfInOctets:     0,   // nl6#570: must stay 0
	colIfInUcastPkts:  48,  // dead, out of scope, filed (asr9k)
	colIfInDiscards:   0,
	colIfInErrors:     0,
	colIfOutOctets:    0,  // nl6#570: must stay 0
	colIfOutUcastPkts: 48, // dead, out of scope, filed (asr9k)
	colIfOutDiscards:  0,
	colIfOutErrors:    0,
}

// stateSeedColumns are the two columns whose static rows are read at device
// construction to seed the interface-state engine, which is why they are
// exempt from the dead-data rule. Kept as a named set so the carve-out is
// visible in the failure message rather than implied by a magic number.
var stateSeedColumns = map[int]bool{colIfAdminStatus: true, colIfOperStatus: true}

// TestStaticRowsOnCyclerOwnedColumnsMatchTheCensus generalises the corpus row
// over ifCyclerColumns instead of over the two columns nl6#570 touched, so the
// scope of the dead-data rule is VISIBLE: which columns must be empty, which are
// exempt and why, and which are known-dead and merely pinned.
func TestStaticRowsOnCyclerOwnedIfTableColumnsMatchTheCensus(t *testing.T) {
	owned := map[int]bool{}
	for _, c := range ifCyclerColumns {
		if c.prefix == ifTablePrefix {
			owned[c.col] = true
		}
	}
	// The census must cover every owned ifTable column, or a column added to the
	// cycler later would escape the rule entirely.
	for col := range owned {
		if _, ok := staticRowsOnCyclerOwnedIfTableColumns[col]; !ok {
			t.Errorf("ifTable .%d is cycler-owned but absent from the census; add it (0 unless "+
				"its static rows are load-bearing, and say why if they are)", col)
		}
	}
	for col := range staticRowsOnCyclerOwnedIfTableColumns {
		if !owned[col] {
			t.Errorf("the census lists ifTable .%d, which the cycler does not own", col)
		}
	}

	got := map[int]int{}
	firstPart := map[int]string{}
	for _, e := range shippedSNMPEntries(t) {
		col, ok := ifTableRowColumn(e.OID)
		if !ok || !owned[col] {
			continue
		}
		got[col]++
		if firstPart[col] == "" {
			firstPart[col] = e.Part
		}
	}

	for col, want := range staticRowsOnCyclerOwnedIfTableColumns {
		switch {
		case got[col] == want:
			// on census
		case want == 0:
			t.Errorf("ifTable .%d ships %d static rows (e.g. %s) but the cycler answers that "+
				"column, so they are unreachable dead data; delete them and record the "+
				"transition in a ledger", col, got[col], firstPart[col])
		case stateSeedColumns[col]:
			t.Errorf("ifTable .%d ships %d static rows, census says %d. These rows are LIVE — "+
				"they seed the interface-state engine — so a change here changes device initial "+
				"state; re-census deliberately", col, got[col], want)
		default:
			t.Errorf("ifTable .%d ships %d static rows, census says %d. These are unreachable "+
				"dead data pinned pending a follow-up sweep: lowering the census is welcome, "+
				"raising it needs a reason", col, got[col], want)
		}
	}
	t.Logf("static rows on cycler-owned ifTable columns: %v (census %v)",
		got, staticRowsOnCyclerOwnedIfTableColumns)
}

// ifTableRowColumn parses an ifTable ROW OID into its column, rejecting a bare
// column OID (no instance) and anything with extra sub-identifiers — those are
// not rows and are counted elsewhere.
func ifTableRowColumn(oid string) (int, bool) {
	if !strings.HasPrefix(oid, ifTablePrefix) {
		return 0, false
	}
	rest := oid[len(ifTablePrefix):]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 {
		return 0, false
	}
	col, err := strconv.Atoi(rest[:dot])
	if err != nil {
		return 0, false
	}
	if _, err := strconv.Atoi(rest[dot+1:]); err != nil {
		return 0, false
	}
	return col, true
}

// TestNoStaticOctetShadowEntriesShip is the nl6#570 corpus row, and it now
// CHECKS THE PRECONDITION it used to assert (review R7). A static .10 / .16
// entry is unreachable only when the cycler knows that ifIndex, which requires
// the same profile to ship an ifXTable .6 row for it and the index to be within
// maxResourceIfIndex. Where that does not hold, the entry is still SERVED — and
// still frozen, which is the nl6#570 defect by another route — so both cases
// fail, with the message each one has actually established.
func TestNoStaticOctetShadowEntriesShip(t *testing.T) {
	hcRows := map[string]map[string]bool{} // profile -> ifIndex -> ships HC .6
	for _, e := range shippedSNMPEntries(t) {
		if idx, ok := hcSixInstance(e.OID); ok {
			if hcRows[e.Profile] == nil {
				hcRows[e.Profile] = map[string]bool{}
			}
			hcRows[e.Profile][idx] = true
		}
	}

	offenders := 0
	for _, e := range shippedSNMPEntries(t) {
		col, idx, ok := octetShadowRow(e.OID)
		if !ok {
			continue
		}
		offenders++
		n, convErr := strconv.Atoi(idx)
		switch {
		case hcRows[e.Profile][idx] && convErr == nil && n <= maxResourceIfIndex:
			t.Errorf("%s still serves ifTable .%d.%s = %q statically, and the profile ships "+
				"ifXTable .6.%s so the cycler answers that row first — the entry is unreachable "+
				"dead data", e.Part, col, idx, e.Value, idx)
		default:
			t.Errorf("%s still serves ifTable .%d.%s = %q statically, and the cycler does NOT "+
				"know that ifIndex (no ifXTable .6.%s row in this profile, or the index is above "+
				"maxResourceIfIndex=%d). So it is still served, and still frozen, which is the "+
				"nl6#570 defect itself — give the profile an HC row or drop the entry",
				e.Part, col, idx, e.Value, idx, maxResourceIfIndex)
		}
	}
	if offenders == 0 {
		t.Logf("no shipped profile serves ifTable .10 / .16 statically (%d entries deleted "+
			"across %d profiles)", len(nl6570DeletedOctetEntries), nl6570LedgerProfileCount())
	}
}

// octetShadowRow reports whether oid is a .10 or .16 ROW, with its column and
// instance.
func octetShadowRow(oid string) (col int, instance string, ok bool) {
	for _, c := range []int{colIfInOctets, colIfOutOctets} {
		prefix := ifTablePrefix + strconv.Itoa(c) + "."
		if strings.HasPrefix(oid, prefix) {
			return c, oid[len(prefix):], true
		}
	}
	return 0, "", false
}

// hcSixInstance reports whether oid is an ifXTable .6 (ifHCInOctets) row — the
// ONLY key InitIfCounters builds its ifIndex set from.
func hcSixInstance(oid string) (string, bool) {
	if strings.HasPrefix(oid, hcInOIDPrefix) {
		return oid[len(hcInOIDPrefix):], true
	}
	return "", false
}

// nl6570LedgerProfileCount is the number of profiles the deletion touched, taken
// from the ledger rather than from the profile enumeration. The first cut logged
// len(shippedProfileNames(t)) and so reported "across 29 profiles" where the
// census is 20 (review R7).
func nl6570LedgerProfileCount() int {
	seen := map[string]struct{}{}
	for _, d := range nl6570DeletedOctetEntries {
		seen[d.profile] = struct{}{}
	}
	return len(seen)
}

// ── helpers shared by the rows above and below ─────────────────────────────

// newSparseOctetShadowCycler publishes a cycler that knows exactly the given
// ifIndexes, so a fixture can carry a multi-digit or non-contiguous index.
func newSparseOctetShadowCycler(t *testing.T, ifIndexes []int, speedBps uint64, seed int64) *IfCounterCycler {
	t.Helper()
	res := buildSparseTestResources(t, ifIndexes, speedBps)
	c := &MetricsCycler{}
	c.InitIfCountersWithScenario(res, seed, IfErrorTypical)
	ic := c.ifCounters.Load()
	if ic == nil {
		t.Fatal("InitIfCountersWithScenario published no cycler")
	}
	return ic
}

// assertEncodesAsCounter32 is the range assertion with teeth: it takes the
// decimal string the cycler produced, encodes it the way the serve path will,
// and requires a Counter32 tag whose content decodes back to the same number.
// A value above 2^32-1 cannot satisfy both.
func assertEncodesAsCounter32(t *testing.T, oid, raw string) {
	t.Helper()
	enc := encodeTypedValue(oid, raw)
	if len(enc) < 2 || enc[0] != ASN1_COUNTER32 {
		t.Errorf("%s = %q encodes as % x, want a Counter32 (0x%02X)", oid, raw, enc, ASN1_COUNTER32)
		return
	}
	n, next := parseLength(enc, 1)
	if n < 0 || next+n != len(enc) {
		t.Errorf("%s = %q: malformed Counter32 encoding % x", oid, raw, enc)
		return
	}
	var got uint64
	for _, b := range enc[next : next+n] {
		got = got<<8 | uint64(b)
	}
	want := octetShadowU64(t, raw)
	if got != want {
		t.Errorf("%s = %q encodes to % x, which decodes to %d, not %d — the value does not fit "+
			"a Counter32", oid, raw, enc, got, want)
	}
	if want > math.MaxUint32 {
		t.Errorf("%s = %q exceeds Counter32", oid, raw)
	}
}

// newOctetShadowServer builds an SNMPServer whose device has BOTH a live cycler
// and a static OID map, which is the configuration the whole deletion rests on
// and which newTestServer cannot express (it has no cycler).
func newOctetShadowServer(t *testing.T, ifIndexes []int, speedBps uint64, static map[string]string) *SNMPServer {
	t.Helper()

	res := &DeviceResources{}
	for _, idx := range ifIndexes {
		res.SNMP = append(res.SNMP,
			SNMPResource{OID: fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.15.%d", idx),
				Response: strconv.FormatUint(speedBps/1_000_000, 10)},
			SNMPResource{OID: fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.6.%d", idx), Response: "0"},
			SNMPResource{OID: fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.10.%d", idx), Response: "0"},
		)
	}
	for oid, val := range static {
		res.SNMP = append(res.SNMP, SNMPResource{OID: oid, Response: val})
	}
	sm := &SimulatorManager{}
	sm.buildResourceIndexes(res)

	mc := &MetricsCycler{}
	mc.InitIfCountersWithScenario(res, 570, IfErrorTypical)
	if mc.ifCounters.Load() == nil {
		t.Fatal("fixture published no cycler")
	}
	return &SNMPServer{device: &DeviceSimulator{resources: res, metricsCycler: mc}}
}

// ── R4: the property the whole deletion rests on ───────────────────────────

// TestCyclerWinsOverAStaticOctetEntry is the premise of deleting 1322 rows:
// findResponse consults the cycler BEFORE the static map, so a static entry for
// a cycler-owned row is unreachable. Nothing pinned that — the only serve-path
// test was the nil-cycler one, which proves the opposite branch (review R4).
//
// The static values here are deliberately implausible as counters (1 and 2) so
// "the dynamic value won" cannot be satisfied by coincidence.
func TestCyclerWinsOverAStaticOctetEntry(t *testing.T) {
	const gbps = 1_000_000_000
	s := newOctetShadowServer(t, []int{1}, gbps, map[string]string{
		"1.3.6.1.2.1.2.2.1.10.1": "1",
		"1.3.6.1.2.1.2.2.1.16.1": "2",
	})

	for oid, static := range map[string]string{
		".1.3.6.1.2.1.2.2.1.10.1": "1",
		".1.3.6.1.2.1.2.2.1.16.1": "2",
	} {
		got := s.findResponse(oid)
		if got == static {
			t.Errorf("findResponse(%s) = %q, the STATIC value. The cycler must win, or the 1322 "+
				"deleted entries were not dead data and the deletion changed what devices "+
				"serve", oid, got)
		}
		if got == "" {
			t.Errorf("findResponse(%s) returned nothing", oid)
		}
		assertEncodesAsCounter32(t, oid, got)
	}
}

// TestOctetShadowsThroughTheDispatcher drives the real v2c dispatcher, because
// every other test in this file calls the cycler directly and would pass even if
// the serve path never reached it. GET, GETNEXT and GETBULK each have their own
// route to the columns; this repo pins at the dispatcher for exactly that reason
// (nl6#535, nl6#527).
func TestOctetShadowsThroughTheDispatcher(t *testing.T) {
	const gbps = 1_000_000_000
	s := newOctetShadowServer(t, []int{1, 2}, gbps, map[string]string{
		"1.3.6.1.2.1.2.2.1.10.1": "1", // static loser, as above
	})

	t.Run("GET", func(t *testing.T) {
		resp := s.handleSNMPv2cRequest(snmpRequestAt(ASN1_GET_REQUEST, snmpVersion2c,
			[]string{".1.3.6.1.2.1.2.2.1.10.1", ".1.3.6.1.2.1.2.2.1.16.1"}))
		hdr := decodeResponseHeader(t, resp)
		if hdr.errStatus != snmpErrNoError {
			t.Fatalf("error-status %d, want noError", hdr.errStatus)
		}
		if n := bytes.Count(hdr.varbinds, []byte{ASN1_COUNTER32}); n < 2 {
			t.Errorf("response carries %d Counter32 tags, want at least 2 (one per column):\n% x",
				n, hdr.varbinds)
		}
		// The static "1" must not be what came back. A Counter32 of 1 encodes
		// as 41 01 01.
		if bytes.Contains(hdr.varbinds, []byte{ASN1_COUNTER32, 0x01, 0x01}) {
			t.Errorf("the GET answered the STATIC value 1 for .10.1:\n% x", hdr.varbinds)
		}
	})

	t.Run("GETNEXT", func(t *testing.T) {
		// Walking from .9.2 (the last state column, second interface) must land
		// on .10.1 and carry a Counter32.
		resp := s.handleSNMPv2cRequest(snmpRequestAt(ASN1_GET_NEXT, snmpVersion2c,
			[]string{".1.3.6.1.2.1.2.2.1.9.2"}))
		hdr := decodeResponseHeader(t, resp)
		if hdr.errStatus != snmpErrNoError {
			t.Fatalf("error-status %d, want noError", hdr.errStatus)
		}
		if !bytes.Contains(hdr.varbinds, encodeOID(".1.3.6.1.2.1.2.2.1.10.1")) {
			t.Errorf("GETNEXT from .9.2 did not return .10.1:\n% x", hdr.varbinds)
		}
		if !bytes.Contains(hdr.varbinds, []byte{ASN1_COUNTER32}) {
			t.Errorf("GETNEXT of .10.1 carries no Counter32 tag:\n% x", hdr.varbinds)
		}
	})

	t.Run("GETBULK", func(t *testing.T) {
		// Four repetitions from .9.2 must cover .10.1, .10.2, .16.1 ... in
		// order, all Counter32.
		resp := s.handleSNMPv2cRequest(v2cGetBulkRequest(0, 4,
			[]string{".1.3.6.1.2.1.2.2.1.9.2"}))
		hdr := decodeResponseHeader(t, resp)
		if hdr.errStatus != snmpErrNoError {
			t.Fatalf("error-status %d, want noError", hdr.errStatus)
		}
		for _, oid := range []string{".1.3.6.1.2.1.2.2.1.10.1", ".1.3.6.1.2.1.2.2.1.10.2"} {
			if !bytes.Contains(hdr.varbinds, encodeOID(oid)) {
				t.Errorf("GETBULK from .9.2 with 4 repetitions omits %s:\n% x", oid, hdr.varbinds)
			}
		}
	})
}

// ── R5: an unorderable instance must not walk backwards ────────────────────

// TestOctetShadowWalkFromDeepInstanceIncreases covers the one ordering failure
// a newly-owned column can introduce that entering from a table prefix cannot
// see: a request naming a row with EXTRA sub-identifiers (".10.5.7" is a
// well-formed varbind name and reaches the walk from the wire), or with an
// instance that is not a number at all. Before the fix the instance parse failed
// and left ifIndex at 0, so the walk answered .10.1 — below the OID asked for,
// which is nl6#526's class.
//
// The fault is generic to NextDynamicOID rather than specific to .10 / .16, so
// the table covers an old column too.
func TestOctetShadowWalkFromDeepInstanceIncreases(t *testing.T) {
	const gbps = 1_000_000_000
	ic := newSparseOctetShadowCycler(t, []int{1, 2, 12}, gbps, 575)

	for _, cur := range []string{
		ifTablePrefix + "10.5.7",  // deep instance, mid-column
		ifTablePrefix + "10.1.1",  // deep instance on a known row
		ifTablePrefix + "10.12.9", // deep instance on the LAST known row
		ifTablePrefix + "16.5.7",
		ifTablePrefix + "16.12.9",
		ifTablePrefix + "11.5.7", // an older column: same parse, same hazard
		ifTablePrefix + "10.abc", // unorderable instance
		ifTablePrefix + "10.-1",  // ditto; unreachable from the wire
		ifTablePrefix + "10.",    // no instance at all
		ifXTablePrefix + "6.5.7",
	} {
		next, val := ic.NextDynamicOID(cur)
		if next == "" {
			continue // end of walk is always a legal answer
		}
		if val == "" {
			t.Errorf("NextDynamicOID(%s) = %s with an empty value", cur, next)
		}
		if compareOIDs(next, cur) <= 0 {
			t.Errorf("NextDynamicOID(%s) = %s, which does not increase. A walk that returns a "+
				"non-increasing OID is nl6#526's class: snmp4j reports \"OID not increasing\" "+
				"or TreeUtils never terminates", cur, next)
		}
	}
}

// ── R1: the identity's scope, stated as a test ─────────────────────────────

// TestOctetShadowThroughGetDynamicReadsTheClockPerCall pins the CAVEAT rather
// than the contract. findResponse calls GetDynamic, which takes its own clock
// reading, so a multi-varbind GET spanning .10 and ifXTable .6 evaluates the
// dial twice. At 400 Gbps that is ~5e7 octets per millisecond of drift, so
// "byte-for-byte" is true of GetDynamicAt with a shared t and false of the
// per-OID SNMP path (review R1).
//
// Asserting the drift directly would be timing-dependent, so the test asserts
// the MECHANISM: successive GetDynamic calls on the same OID move, which they
// can only do by re-reading the clock. It also covers the GetDynamic path for
// these two columns at all, which nothing else did (review R12).
func TestOctetShadowThroughGetDynamicReadsTheClockPerCall(t *testing.T) {
	const gbps = 1_000_000_000
	ic := newOctetShadowCycler(t, []uint64{400 * gbps}, 576)

	for _, oid := range []string{octetShadowInOID + "1", octetShadowOutOID + "1"} {
		first := ic.GetDynamic(oid)
		assertEncodesAsCounter32(t, oid, first)

		moved := false
		for i := 0; i < 1000 && !moved; i++ {
			if ic.GetDynamic(oid) != first {
				moved = true
			}
		}
		if !moved {
			t.Errorf("%s returned %q on 1001 successive GetDynamic calls at 400 Gbps. Either the "+
				"column stopped advancing, or GetDynamic no longer reads the clock per call — "+
				"the second would make the shared-t caveat in the docs wrong", oid, first)
		}
	}
}

// ── R12: the cases the deletion makes load-bearing ─────────────────────────

// TestStaticOctetEntryWithoutAnHCRowIsStillServed is the fall-through the
// narrowed corpus guard now reasons about: the cycler's ifIndex set comes only
// from ifXTable .6 keys, so a .10 row for an ifIndex with no HC row is NOT
// shadowed and the static map answers. Same for an index above maxIfIndex.
//
// No shipped profile is in that state — TestOctetShadowLedgerIsNotVacuous
// asserts it per row — but an operator resource file can be, and the guard's
// message depends on this being true.
func TestStaticOctetEntryWithoutAnHCRowIsStillServed(t *testing.T) {
	const gbps = 1_000_000_000
	// ifIndex 1 has an HC row (the fixture builds one); 7 does not.
	s := newOctetShadowServer(t, []int{1}, gbps, map[string]string{
		"1.3.6.1.2.1.2.2.1.10.7": "424242",
		"1.3.6.1.2.1.2.2.1.16.7": "434343",
	})

	for oid, want := range map[string]string{
		".1.3.6.1.2.1.2.2.1.10.7": "424242",
		".1.3.6.1.2.1.2.2.1.16.7": "434343",
	} {
		if got := s.findResponse(oid); got != want {
			t.Errorf("findResponse(%s) = %q, want the static %q: the cycler knows no ifIndex 7, "+
				"so nothing shadows this row", oid, got, want)
		}
	}

	// And an index above the cycler's bound behaves the same way.
	ic := s.device.metricsCycler.ifCounters.Load()
	above := fmt.Sprintf("%s%d", octetShadowInOID, ic.maxIfIndex+1)
	if got := ic.GetDynamicAt(above, 10); got != "" {
		t.Errorf("GetDynamicAt(%s) = %q, want \"\" for an ifIndex past maxIfIndex=%d",
			above, got, ic.maxIfIndex)
	}
}

// TestNewlyServedProfileAnswersTheOctetColumns covers the eight profiles that
// shipped ifXTable .6 rows but never a static .10 / .16, and therefore GAIN the
// two columns. They are the half of the fleet-visible change no ledger row
// mentions (review R9), so at least one is exercised end to end.
func TestNewlyServedProfileAnswersTheOctetColumns(t *testing.T) {
	const profile = "cisco_catalyst_9500.json"

	shipped := map[string]bool{}
	hcIdx := []string{}
	for _, e := range shippedSNMPEntries(t) {
		if e.Profile != profile {
			continue
		}
		shipped[e.OID] = true
		if idx, ok := hcSixInstance(e.OID); ok {
			hcIdx = append(hcIdx, idx)
		}
	}
	if len(hcIdx) == 0 {
		t.Fatalf("%s ships no ifXTable .6 rows, so it is not one of the profiles that gain the "+
			"columns; pick another", profile)
	}
	for _, col := range []int{colIfInOctets, colIfOutOctets} {
		oid := fmt.Sprintf("%s%d.%s", ifTablePrefix, col, hcIdx[0])
		if shipped[oid] {
			t.Errorf("%s ships %s statically, so it is not a NEWLY-served profile", profile, oid)
		}
	}

	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources(profile)
	if err != nil {
		t.Fatalf("load %s: %v", profile, err)
	}
	mc := &MetricsCycler{}
	mc.InitIfCountersWithScenario(res, 577, IfErrorClean)
	ic := mc.ifCounters.Load()
	if ic == nil {
		t.Fatal("no cycler for the profile")
	}
	for _, col := range []int{colIfInOctets, colIfOutOctets} {
		oid := fmt.Sprintf("%s%d.%s", ifTablePrefix, col, hcIdx[0])
		raw := ic.GetDynamicAt(oid, 60)
		if raw == "" {
			t.Errorf("%s: %s is not answered, so the profile gained nothing", profile, oid)
			continue
		}
		assertEncodesAsCounter32(t, oid, raw)
	}
}

// TestDefaultResourcesServeOctetsDynamically covers the compiled-in fallback
// profile, which had NO test at all and which nl6#570's first cut left serving
// two frozen octet counters (review B2).
//
// createDefaultResources is reached whenever a named resource file is absent
// (resources.go), so it is a production path, not a fixture. It used to ship
// static ifInOctets.1 = 1000000 / ifOutOctets.1 = 500000 and NO ifXTable .6
// row, so no cycler was published and both values were served frozen forever —
// the exact 0-bps-forever symptom this change removes, on the one profile the
// corpus guard cannot see because it reads only resources/. The first cut kept
// them and argued they were "the only source, not dead data"; that is true about
// deadness and beside the point about the defect.
//
// The fix gives the set its two HC rows instead, so a cycler IS published and
// all four octet columns are derived. This test asserts the whole chain on a
// device built from that set: the static rows are gone, the columns are
// answered, they are Counter32, they advance, and the shadow identity holds.
func TestDefaultResourcesServeOctetsDynamically(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll("resources", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	if err := sm.createDefaultResources("resources/zzdefault.json"); err != nil {
		t.Fatalf("createDefaultResources: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join("resources", "zzdefault.json"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var doc DeviceResources
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var hc, octets []string
	for _, r := range doc.SNMP {
		oid := normaliseResourceOID(r.OID)
		if _, ok := hcSixInstance(oid); ok {
			hc = append(hc, oid)
		}
		if _, _, ok := octetShadowRow(oid); ok {
			octets = append(octets, oid+"="+r.Response)
		}
	}
	if len(octets) != 0 {
		t.Errorf("createDefaultResources still ships static octet rows %v. On this path they are "+
			"served frozen forever, which is the defect nl6#570 removes, and the docs claim no "+
			"static octet rows exist anywhere", octets)
	}
	if len(hc) == 0 {
		t.Fatal("createDefaultResources ships no ifXTable .6 row, so no cycler is published and " +
			"the octet columns are not served at all — the fallback profile has no octet counters")
	}

	// Now the serve path, which is what actually matters: a device built off
	// this set must answer both columns dynamically.
	res, err := sm.LoadSpecificResources("zzdefault.json")
	if err != nil {
		t.Fatalf("load the default profile: %v", err)
	}
	mc := &MetricsCycler{}
	mc.InitIfCountersWithScenario(res, 578, IfErrorClean)
	ic := mc.ifCounters.Load()
	if ic == nil {
		t.Fatal("no cycler published for the default profile")
	}
	srv := &SNMPServer{device: &DeviceSimulator{resources: res, metricsCycler: mc}}

	for _, pair := range []struct{ shadow, hcOID string }{
		{octetShadowInOID + "1", octetShadowHCInOID + "1"},
		{octetShadowOutOID + "1", octetShadowHCOut + "1"},
	} {
		got := srv.findResponse(pair.shadow)
		if got == "" {
			t.Errorf("findResponse(%s) returned nothing on the default profile", pair.shadow)
			continue
		}
		assertEncodesAsCounter32(t, pair.shadow, got)

		// Derived, not frozen: the identity at a shared instant, and movement
		// between two instants.
		const t1, t2 = 30.0, 90.0
		shadow := octetShadowU64(t, ic.GetDynamicAt(pair.shadow, t1))
		hcVal := octetShadowU64(t, ic.GetDynamicAt(pair.hcOID, t1))
		if want := hcVal & 0xFFFFFFFF; shadow != want {
			t.Errorf("default profile %s = %d, want %d", pair.shadow, shadow, want)
		}
		if later := octetShadowU64(t, ic.GetDynamicAt(pair.shadow, t2)); later == shadow {
			t.Errorf("default profile %s reads %d at both t=%g and t=%g — still frozen",
				pair.shadow, shadow, t1, t2)
		}
	}
}

// TestSFlowOctetOffsetsMatchTheEncoder pins the two shared body offsets against
// the encoder with sentinel values, so a field insertion cannot silently
// re-point the cross-protocol test at a different counter (review R12).
func TestSFlowOctetOffsetsMatchTheEncoder(t *testing.T) {
	const (
		inSentinel  uint64 = 0x1122334455667788
		outSentinel uint64 = 0x8877665544332211
	)
	body := encodeIfCountersBody(1, 0, inSentinel, 0, 0, 0, 0, 0, outSentinel, 0, 0, 0, 0, 0)
	if len(body) != sflowIfCountersBodyLen {
		t.Fatalf("body is %d bytes, sflowIfCountersBodyLen says %d", len(body), sflowIfCountersBodyLen)
	}
	if got := binary.BigEndian.Uint64(body[sflowIfCountersInOctets:]); got != inSentinel {
		t.Errorf("offset %d holds %#x, want the ifInOctets sentinel %#x",
			sflowIfCountersInOctets, got, inSentinel)
	}
	if got := binary.BigEndian.Uint64(body[sflowIfCountersOutOctet:]); got != outSentinel {
		t.Errorf("offset %d holds %#x, want the ifOutOctets sentinel %#x",
			sflowIfCountersOutOctet, got, outSentinel)
	}
}

// ── B1: the guard whose failure mode does not destroy the evidence ─────────

// octetColumnsServedFloor is the number of (profile, column, ifIndex) octet
// answers the shipped corpus must produce. It is the 1322 rows nl6#570 deleted
// PLUS the 452 that no profile served before, because 28 profiles ship
// ifHCInOctets rows where only 20 shipped static octet entries.
//
// Both halves are load-bearing: the first says nothing regressed, the second
// says the eight newly-served profiles really are served. A floor rather than an
// equality so that adding interfaces to a profile is not a test failure —
// TestOctetShadowCoverageIsCompletePerProfile is what makes the number
// per-profile-exact.
const octetColumnsServedFloor = 1322 + 452

// TestEveryInterfaceAnswersBothOctetColumns is the corpus-level coverage guard.
//
// Why it exists (review B1): the ledger and the three corpus digests pin what
// was DELETED, and their documented remedy on failure is to re-pin. So a later
// profile edit that adds interface rows WITHOUT an ifHCInOctets row would drop
// ifInOctets / ifOutOctets for those interfaces, and the only tests that fired
// would tell the maintainer to absorb the change — while
// TestNoStaticOctetShadowEntriesShip forbids restoring the static rows that used
// to be the fallback. That is the nl6#541 glob hole again: a guard whose failure
// mode destroys the evidence.
//
// This test fires on the DEFECT instead. It walks every shipped profile, builds
// a real device with a live cycler, and requires findResponse — the production
// serve path, not the cycler directly — to answer both columns for every ifIndex
// the profile exposes, where "exposes" is taken from ifDescr rather than from
// ifHCInOctets, so a profile that grows interfaces without HC rows FAILS HERE
// rather than silently losing two columns.
func TestEveryInterfaceAnswersBothOctetColumns(t *testing.T) {
	served, missing := 0, 0
	for _, profile := range shippedProfileNames(t) {
		srv := deviceForProfile(t, profile)
		ifIndexes := profileIfIndexes(t, srv.device.resources)
		if len(ifIndexes) == 0 {
			continue // a profile with no interface table at all (aws_s3_storage)
		}
		for _, idx := range ifIndexes {
			for _, col := range []int{colIfInOctets, colIfOutOctets} {
				oid := fmt.Sprintf("%s%d.%d", ifTablePrefix, col, idx)
				got := srv.findResponse(oid)
				switch {
				case got == "":
					missing++
					t.Errorf("%s exposes ifIndex %d (it has an ifDescr row) but %s is answered "+
						"by nothing. The cycler's ifIndex set comes ONLY from ifXTable .6 rows, "+
						"so this profile is missing ifHCInOctets.%d — add it. Do NOT re-add a "+
						"static octet row, and do NOT re-pin a corpus digest to make this go "+
						"away: the columns are simply absent for that interface",
						profile, idx, oid, idx)
				case isSNMPExceptionValue(got):
					missing++
					t.Errorf("%s %s answers the exception %q", profile, oid, got)
				default:
					served++
					assertEncodesAsCounter32(t, oid, got)
				}
			}
		}
	}

	if served < octetColumnsServedFloor {
		t.Errorf("the shipped corpus answers %d octet-column instances, want at least %d "+
			"(1322 rows that used to be static + 452 newly served). A shortfall means interfaces "+
			"lost these columns rather than gaining them", served, octetColumnsServedFloor)
	}
	t.Logf("%d octet-column instances answered across the corpus, %d missing (floor %d)",
		served, missing, octetColumnsServedFloor)
}

// TestOctetShadowCoverageIsCompletePerProfile is the per-profile half: within a
// profile, the set of interfaces with an ifDescr row, the set with an
// ifHCInOctets row, and therefore the set answering the octet columns must be
// the SAME set. Equality per profile is what a fleet-wide floor cannot say.
func TestOctetShadowCoverageIsCompletePerProfile(t *testing.T) {
	for _, profile := range shippedProfileNames(t) {
		sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
		res, err := sm.LoadSpecificResources(profile)
		if err != nil {
			t.Fatalf("LoadSpecificResources(%s): %v", profile, err)
		}
		descr := map[int]bool{}
		for _, idx := range profileIfIndexes(t, res) {
			descr[idx] = true
		}
		hc := map[int]bool{}
		for _, r := range res.SNMP {
			if idx, ok := hcSixInstance(normaliseResourceOID(r.OID)); ok {
				if n, err := strconv.Atoi(idx); err == nil {
					hc[n] = true
				}
			}
		}
		for idx := range descr {
			if !hc[idx] {
				t.Errorf("%s: ifIndex %d has an ifDescr row but no ifHCInOctets row, so it serves "+
					"neither octet column", profile, idx)
			}
		}
		for idx := range hc {
			if !descr[idx] {
				t.Errorf("%s: ifIndex %d has an ifHCInOctets row but no ifDescr row — the octet "+
					"columns are served for an interface the ifTable does not describe",
					profile, idx)
			}
		}
	}
}

// profileIfIndexes returns every ifIndex the profile DESCRIBES, taken from
// ifDescr (ifTable .2) rows. Deliberately a different source from the cycler's
// own ifHCInOctets set: using the cycler's set would make the coverage test
// tautological, which is the whole failure B1 describes.
func profileIfIndexes(t *testing.T, res *DeviceResources) []int {
	t.Helper()
	const ifDescrPrefix = ifTablePrefix + "2."
	var out []int
	for _, r := range res.SNMP {
		oid := normaliseResourceOID(r.OID)
		if !strings.HasPrefix(oid, ifDescrPrefix) {
			continue
		}
		if n, err := strconv.Atoi(oid[len(ifDescrPrefix):]); err == nil && n >= 1 {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}
