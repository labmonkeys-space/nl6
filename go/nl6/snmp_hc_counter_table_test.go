/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// shippedTypedCorpus returns the distinct (profile, OID, emitted tag) triples
// the fleet would put on the wire, as sorted "profile\toid\ttag" lines, plus
// the number of entries inspected.
//
// The tag is the FIRST BYTE encodeTypedValue actually emits, not the tag
// oidTypeTable declares: this is a measurement of the wire, so it must come
// from the encoder.
//
// Keyed on the PROFILE as well as the OID (nl6#541 review). Keyed on the OID
// alone, a change that flips one profile's value is invisible whenever another
// profile already produces that (OID, tag) pair — measured: the 31 tag changes
// this very change made to shipped data show up as only 12 lost pairs in the
// fleet-wide view, and would vanish entirely if keyed by OID.
//
// What it remains blind to, deliberately: it hashes TAGS, not encoded bytes, so
// a value change within one type (42 -> 43 on a Counter32) does not move it.
// That is what keeps it stable across ordinary data edits, which is the whole
// point of a golden digest here; TestShippedOIDsUnchangedOnTheWire is the
// byte-level pin, for OIDs.
func shippedTypedCorpus(t *testing.T) (lines []string, entries int) {
	t.Helper()

	seen := make(map[string]struct{})
	for _, e := range shippedSNMPEntries(t) {
		emitted := encodeTypedValue(e.OID, e.Value)
		if len(emitted) == 0 {
			t.Fatalf("%s: encodeTypedValue(%s, %q) emitted nothing", e.Part, e.OID, e.Value)
		}
		seen[fmt.Sprintf("%s\t%s\t%02X", e.Profile, e.OID, emitted[0])] = struct{}{}
		entries++
	}
	lines = make([]string, 0, len(seen))
	for l := range seen {
		lines = append(lines, l)
	}
	sort.Strings(lines)
	return lines, entries
}

// shippedTagDigest is a SHA-256 over the sorted, distinct (profile, OID,
// emitted tag) triples of the whole shipped resource corpus.
//
// It was computed on the working tree of this change with the oidTypeTable
// widening of nl6#541 NOT YET APPLIED (the resource-data corrections of the
// same change already in place — those are pinned separately, and from the
// PARENT revision, by TestShippedDataEditsReproduceTheParentCorpus), and then
// re-run with the widening applied. Both runs produce this digest, which is the
// measurement behind the spec's Block If: widening the table changed the
// emitted tag of no OID any shipped profile serves. It is a measurement, not an
// argument, and it was NOT re-derived from the widened code.
//
// RE-PINNED TWICE. Both re-pins are CORPUS changes, and each is re-derived by a
// test rather than asserted here.
//
// The first was nl6#570, which deleted the 1322 shipped ifTable .10 / .16
// entries the cycler now serves. No surviving OID moved its tag;
// TestOctetShadowDeletionReproducesTheParentCorpus restores the deleted rows and
// requires the value this constant held before, byte for byte.
//
// The second is nl6#574 / nl6#571 / nl6#569, which deleted 829 entries (742 dead
// ifTable .9 / .11 / .17 rows, 57 bare column OIDs, 4 over-specified instances,
// 24 Palo Alto OIDs served by profiles that are not Palo Alto devices, and 2
// invalid PAN OIDs) and corrected 5 PAN values, 3 of which DO move a tag — a
// number where a DisplayString belongs was the defect.
// TestResourceDataDefectsReproduceTheParentCorpus reverses all of it and
// requires the value this constant held at ec4700f.
//
// The third is nl6#576, which re-homed the NVIDIA GPU telemetry arc from
// 1.3.6.1.4.1.53246 (IANA: Mailteck, S.A.) to 1.3.6.1.4.1.5703 (NVIDIA
// Corporation). No tag moved and no entry was added or removed — this digest is
// keyed on the OID STRING as well as the tag, which is the only reason a pure
// rename moves it. TestNvidiaArcRehomeReproducesTheParentCorpus reverses the 225
// recorded rows and requires the value this constant held at 1bca8e8, which is
// what makes the re-pin below a measurement rather than an acceptance of
// whatever the new code emits. That ledger, its tables and the pre-change value
// of this constant (shippedTagDigestBeforeNvidiaArcRehome) all live in
// snmp_shipped_nvidia_arc_ledger_test.go rather than beside this line.
//
// If a resource edit legitimately adds an OID or changes a value's TYPE, this
// digest must be re-pinned in the same commit, and the diff the failure prints
// is the review evidence for doing so. Re-pinning it to silence a failure
// caused by a new profile's own defect is the failure mode to watch for: it is
// how a Counter64 column on an untyped leaf would be absorbed rather than
// fixed. TestShippedBigValuesSitOnCounter64Leaves and
// TestShippedUntypedValuesFitInteger32 fire on the DEFECT rather than on the
// digest, and exist so that re-pinning is never the only route out.
const shippedTagDigest = "fa776c654f5b88fd1e429d1bcd0d2758613273ee80a22f0239d2c4097ac24bb2"

func TestShippedTagsUnchangedByTableWidening(t *testing.T) {
	lines, entries := shippedTypedCorpus(t)

	sum := sha256.New()
	for _, l := range lines {
		sum.Write([]byte(l))
		sum.Write([]byte{'\n'})
	}
	got := hex.EncodeToString(sum.Sum(nil))

	tags := map[string]int{}
	for _, l := range lines {
		tags[l[strings.LastIndexByte(l, '\t')+1:]]++
	}
	t.Logf("%d SNMP entries inspected, %d distinct (profile, OID, tag) triples; tag histogram: %v",
		entries, len(lines), tags)

	if got != shippedTagDigest {
		t.Errorf("shipped (OID, emitted tag) digest = %s, want %s.\n"+
			"Every OID a shipped profile serves must keep the tag it had: widening oidTypeTable "+
			"is a WIRE change, and this is the measurement that says whether it moved anything.",
			got, shippedTagDigest)
	}
}

// ── nl6#541 part 2: widened Counter64 recognition ──────────────────────────

// ipStatsC64Columns are the Counter64 columns of the two RFC 4293 IP statistics
// tables, which share a column layout. ipStatsColumnCount is the last assigned
// column in either.
//
// PROVENANCE: read out of the IP-MIB shipped with net-snmp, column by column,
// with `snmptranslate -Td .1.3.6.1.2.1.4.31.{1,3}.1.<c>`. A list recalled from
// memory during this change was wrong on every entry, which is why the numbers
// below are pinned against the non-HC columns too — an off-by-one row would
// declare Counter64 on a Counter32 column and change that column's tag on the
// wire.
//
// This list is an independent RESTATEMENT of oidTypeTable's rows, which catches
// an edit to either side but NOT a misreading shared by both — they were written
// in the same change from the same reading of the same MIB. That gap is closed
// separately, by TestOidTypeTableAgreesWithTheMIBs, which compares the table
// against MIB facts extracted with net-snmp and checked in under
// testdata/mibs/. Those fixtures are independent of this list and of the table;
// they are not independent of net-snmp, which is stated there rather than
// glossed over.
var ipStatsC64Columns = []int{4, 6, 13, 19, 21, 24, 31, 33, 35, 37, 39, 41, 43, 45}

const ipStatsColumnCount = 47

// dot3HCStatsColumns is every assigned column of the EtherLike-MIB
// dot3HCStatsTable (RFC 3635); all six are Counter64.
var dot3HCStatsColumns = []int{1, 2, 3, 4, 5, 6}

// TestWidenedTableDeclaresTheHCColumns pins part 2 of nl6#541 in BOTH
// directions: the HC columns must be declared Counter64, and every other
// assigned column of the same tables must NOT be — the latter is what catches
// a mistyped or off-by-one row, which is a wire change rather than a
// validation change.
func TestWidenedTableDeclaresTheHCColumns(t *testing.T) {
	c64 := map[int]bool{}
	for _, c := range ipStatsC64Columns {
		c64[c] = true
	}

	for _, tbl := range []struct{ name, prefix string }{
		{"ipSystemStatsTable", ".1.3.6.1.2.1.4.31.1.1"},
		{"ipIfStatsTable", ".1.3.6.1.2.1.4.31.3.1"},
	} {
		for col := 1; col <= ipStatsColumnCount; col++ {
			// An instance suffix, not necessarily THE index: ipSystemStatsTable
			// is indexed by ipSystemStatsIPVersion alone, ipIfStatsTable by
			// (IPVersion, ifIndex), so ".1.7" is one sub-identifier too long
			// for the first. Harmless for a prefix match, and both are probed
			// with the same suffix on purpose — what is being asserted is the
			// TYPE the table declares for the column, not the index shape.
			oid := fmt.Sprintf("%s.%d.1.7", tbl.prefix, col)
			got := snmpTypeTag(oid)
			if c64[col] && got != ASN1_COUNTER64 {
				t.Errorf("%s column %d (%s) declares 0x%02X, want Counter64: nl6#524's v1 divert "+
					"and GETNEXT skip cannot fire for it", tbl.name, col, oid, got)
			}
			if !c64[col] && got == ASN1_COUNTER64 {
				t.Errorf("%s column %d (%s) is declared Counter64 but is not an HC column; "+
					"that changes this column's tag on the wire", tbl.name, col, oid)
			}
		}
	}

	for _, col := range dot3HCStatsColumns {
		oid := fmt.Sprintf(".1.3.6.1.2.1.10.7.11.1.%d.3", col)
		if got := snmpTypeTag(oid); got != ASN1_COUNTER64 {
			t.Errorf("dot3HCStatsTable column %d (%s) declares 0x%02X, want Counter64", col, oid, got)
		}
	}
	// dot3StatsTable sits next door and is Counter32 throughout; the widened
	// rows must not have leaked onto it.
	if got := snmpTypeTag(".1.3.6.1.2.1.10.7.2.1.4.3"); got == ASN1_COUNTER64 {
		t.Errorf("dot3StatsAlignmentErrors is declared Counter64; the dot3HCStats rows have leaked")
	}
}

// TestShippedBigValuesSitOnCounter64Leaves is part 2's pin over the shipped
// corpus: a value that needs more than 32 bits must live on a leaf the table
// declares Counter64. Otherwise it reaches a manager as a 64-bit INTEGER (the
// encoder's default branch) or as an OCTET STRING, nl6#524's v1 divert and
// GETNEXT skip never fire for it, and no 32-bit SMI type can carry it.
//
// A profile adding a vendor or standard HC column must therefore either be
// covered by oidTypeTable or fail this test — which is exactly the point: the
// table is hand-maintained, so the failure is the reminder.
//
// Leaves the table declares OCTET STRING are exempt: a numeric serial number or
// a numeric ifAlias is a STRING on the wire whatever its magnitude, so the
// 64-bit question does not arise for them.
func TestShippedBigValuesSitOnCounter64Leaves(t *testing.T) {
	big, offending, exempt := 0, 0, 0
	for _, e := range shippedSNMPEntries(t) {
		v, perr := strconv.ParseUint(e.Value, 10, 64)
		if perr != nil || v <= 0xFFFFFFFF {
			continue
		}
		declared := snmpTypeTag(e.OID)
		if declared == ASN1_OCTET_STRING {
			exempt++
			continue
		}
		big++
		if declared != ASN1_COUNTER64 {
			offending++
			t.Errorf("%s: %s = %s needs 64 bits but its leaf is %s. Either the leaf is a 64-bit "+
				"counter and oidTypeTable needs the row (then re-pin shippedTagDigest), or the "+
				"value is wrong for the leaf's real MIB type and belongs in 32 bits",
				e.Part, e.OID, e.Value, declaredTypeForMessage(declared))
		}
	}
	if big == 0 {
		t.Fatal("no shipped value needs more than 32 bits, so this test asserted nothing about the corpus")
	}
	t.Logf("%d shipped values need more than 32 bits, %d of them off a Counter64 leaf (%d string-typed, exempt)",
		big, offending, exempt)

	// Positive control: the corpus being clean must not be mistaken for a test
	// that cannot fail. A vendor HC column with a 64-bit value is exactly the
	// case the check exists for, and the table does not type it.
	const vendorHC = ".1.3.6.1.4.1.9999.1.1.1.6.1"
	if snmpTypeTag(vendorHC) == ASN1_COUNTER64 {
		t.Fatalf("control fixture %s is typed by the table, so it no longer exercises the check", vendorHC)
	}
	if got := encodeTypedValue(vendorHC, "9876543210"); len(got) == 0 || got[0] == ASN1_COUNTER64 {
		t.Errorf("premise changed: an untyped vendor HC column now encodes as Counter64 (% x)", got)
	}
}

// TestShippedUntypedValuesFitInteger32 closes the gap the test above leaves
// open, and it is the test that would have caught the defect it was written for:
// an untyped leaf carrying 2147483648 — exactly one over Integer32's ceiling —
// shipped in two profiles, one row above an edit made in the same change, and
// the >2^32 threshold above walked straight past it.
//
// A leaf oidTypeTable does not type takes encodeTypedValue's default branch,
// which emits INTEGER via strconv.Atoi at the host's int width. RFC 2578 makes
// every SMI INTEGER an Integer32, so a value outside -2^31..2^31-1 is legal BER
// and illegal SMI: a manager parsing it into an Integer32 does not get the
// number the profile intended. Typed leaves are excluded because Counter32,
// Gauge32 and Counter64 legitimately exceed Integer32 — that is what they are
// for.
func TestShippedUntypedValuesFitInteger32(t *testing.T) {
	inspected, offending := 0, 0
	for _, e := range shippedSNMPEntries(t) {
		if snmpTypeTag(e.OID) != 0 {
			continue // typed leaves have their own width, checked by the load guard
		}
		v, perr := strconv.ParseInt(e.Value, 10, 64)
		if perr != nil {
			continue // not a number: the default branch emits an OCTET STRING
		}
		inspected++
		if v > math.MaxInt32 || v < math.MinInt32 {
			offending++
			t.Errorf("%s: %s = %s is on a leaf oidTypeTable does not type, so it is served as an "+
				"INTEGER, and RFC 2578 bounds an SMI INTEGER to Integer32 (%d..%d). Either the "+
				"value belongs in 32 bits — rescale its units, as hrStorageAllocationUnits exists "+
				"to allow — or the leaf is a 64-bit object and needs an oidTypeTable row",
				e.Part, e.OID, e.Value, math.MinInt32, math.MaxInt32)
		}
	}
	if inspected == 0 {
		t.Fatal("no untyped numeric value inspected, so this test asserted nothing")
	}
	t.Logf("%d untyped numeric values inspected, %d outside Integer32", inspected, offending)

	// Positive control, for the same reason as above: the check must be shown to
	// fire, since a clean corpus proves nothing about the assertion.
	const untyped = ".1.3.6.1.4.1.9999.2.1.0"
	if snmpTypeTag(untyped) != 0 {
		t.Fatalf("control fixture %s is typed, so it no longer exercises the check", untyped)
	}
	got := encodeTypedValue(untyped, "2147483648")
	if len(got) == 0 || got[0] != ASN1_INTEGER {
		t.Fatalf("premise changed: an untyped 2^31 value encodes as % x, not INTEGER", got)
	}
	if len(got) != 7 {
		t.Errorf("2147483648 encodes as % x (%d bytes); the point of the check is that it needs "+
			"5 content bytes and cannot be an Integer32", got, len(got))
	}
}

// declaredTypeForMessage names a declared tag for an operator-facing message,
// distinguishing "not in oidTypeTable" from a tag, because the remedy differs:
// an untyped leaf needs a table row or a smaller value, not a corrected type.
func declaredTypeForMessage(tag byte) string {
	if tag == 0 {
		return "not in oidTypeTable (served as INTEGER)"
	}
	return "declared " + snmpTypeName(tag)
}

// snmpTypeTagConcat is the form snmpTypeTag had before nl6#541: it concatenated
// prefix+"." for every row of every call. It is kept HERE, in the test file, so
// the A/B is reproducible (BenchmarkSnmpTypeTagAB) and the equivalence is
// pinned (TestSnmpTypeTagMatchesTheConcatenatingForm) without leaving a second
// implementation in production code.
func snmpTypeTagConcat(oid string) byte {
	for _, e := range oidTypeTable {
		if strings.HasPrefix(oid, e.prefix+".") || oid == e.prefix {
			return e.tag
		}
	}
	return 0
}

// TestSnmpTypeTagMatchesTheConcatenatingForm is the durable evidence for the
// rewrite. snmpTypeTag runs once per encoded value on every SNMP response of
// every version, so "algebraically equivalent" is not a claim to leave in a
// commit message: it is asserted here over generated input, in the shape this
// package already uses for encoder equivalence (FuzzOIDRoundTrip,
// TestOIDEncodingMatchesEncodingASN1).
//
// The generated set is built AROUND the table's own prefixes, because that is
// where the two forms could differ: at the boundary character, at exact
// equality, and on a digit-extension near-miss (".1" must not match ".10").
func TestSnmpTypeTagMatchesTheConcatenatingForm(t *testing.T) {
	var probes []string
	for _, e := range oidTypeTable {
		probes = append(probes,
			e.prefix,                          // exact equality
			e.prefix+".",                      // trailing separator, no instance
			e.prefix+".1",                     // ordinary instance
			e.prefix+".1.2.3",                 // deep instance
			e.prefix+"0",                      // digit extension: must NOT match
			e.prefix+"0.1",                    // digit extension with an instance
			e.prefix+"9.9",                    // ditto
			e.prefix+"x",                      // non-digit extension
			e.prefix[:len(e.prefix)-1],        // one character short
			strings.TrimPrefix(e.prefix, "."), // undotted spelling
		)
	}
	probes = append(probes,
		"", ".", "..", ".1", ".1.3", ".1.3.6.1.2.1", ".1.3.6.1.4.1.9999.1.2.3",
		".1.0.8802.1.1.2.1.3", "1.3.6.1.2.1.2.2.1.10.1", ".1.3.6.1.2.1.2.2.1.100.1",
	)

	for _, oid := range probes {
		if got, want := snmpTypeTag(oid), snmpTypeTagConcat(oid); got != want {
			t.Errorf("snmpTypeTag(%q) = 0x%02X, the concatenating form gives 0x%02X", oid, got, want)
		}
	}
	t.Logf("%d probes agree between the allocation-free and concatenating forms", len(probes))
}

// FuzzSnmpTypeTagFormsAgree extends the same property to arbitrary input, which
// is what makes it evidence rather than a table of cases the author thought of.
func FuzzSnmpTypeTagFormsAgree(f *testing.F) {
	for _, seed := range []string{
		"", ".", ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.2.2.1.10", ".1.3.6.1.2.1.2.2.1.100",
		".1.3.6.1.2.1.4.31.3.1.6.1.4", ".1.3.6.1.2.1.10.7.11.1.2.3", ".1.0.8802.1.1.2.1.4.1.1.10",
		"1.3.6.1.2.1.1.2", ".1.3.6.1.2.1.1.20",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, oid string) {
		if got, want := snmpTypeTag(oid), snmpTypeTagConcat(oid); got != want {
			t.Fatalf("snmpTypeTag(%q) = 0x%02X, concatenating form gives 0x%02X", oid, got, want)
		}
	})
}

// BenchmarkSnmpTypeTagAB is the A/B behind the claim that the rewrite paid for
// the widening. "new" is the shipped allocation-free comparison, "concat" the
// form it replaced, over the SAME (widened) table — so the difference is the
// comparison and nothing else. `miss` walks every row and is the number to
// quote; `hit-early` returns on row 2 and measures almost nothing.
//
// nl6#524 put this scan on the v1 GETNEXT path deliberately after a version
// compare, but that is not the only caller: encodeTypedValue calls it once per
// encoded value on every response of every version.
func BenchmarkSnmpTypeTagAB(b *testing.B) {
	cases := []struct{ name, oid string }{
		{"hit-early", ".1.3.6.1.2.1.1.3.0"},              // sysUpTime, row 2
		{"hit-widened", ".1.3.6.1.2.1.4.31.3.1.6.1.4"},   // ipIfStatsHCInOctets
		{"hit-late", ".1.0.8802.1.1.2.1.4.1.1.10.1.1.1"}, // lldpRemSysDesc, last row
		{"miss", ".1.3.6.1.4.1.9999.1.2.3.4.5"},          // walks the whole table
	}
	for _, tc := range cases {
		b.Run("new/"+tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = snmpTypeTag(tc.oid)
			}
		})
		b.Run("concat/"+tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = snmpTypeTagConcat(tc.oid)
			}
		})
	}
}

// ── nl6#524's v1 behaviour, now reachable for the widened columns ───────────

// Widened Counter64 columns, one per newly covered table, plus the Counter32
// neighbours a walk crosses on either side of each run.
const (
	ipIfHCInOctets  = ".1.3.6.1.2.1.4.31.3.1.6.1.4" // ipIfStatsHCInOctets, ipv4, ifIndex 4
	ipIfInOctets32  = ".1.3.6.1.2.1.4.31.3.1.5.1.4" // ipIfStatsInOctets, Counter32
	ipIfInHdrErrs32 = ".1.3.6.1.2.1.4.31.3.1.7.1.4" // ipIfStatsInHdrErrors, Counter32
	dot3HCFCSErrors = ".1.3.6.1.2.1.10.7.11.1.2.3"  // dot3HCStatsFCSErrors, ifIndex 3
	afterDot3Run    = ".1.3.6.1.2.1.11.1.0"         // snmpInPkts, the first OID past the run
)

// widenedFixture seeds one instance of each newly covered HC run with its
// Counter32 neighbours, so a v1 walk crosses a run and must come out the far
// side. dot3HCStatsTable is entirely Counter64, so its run is the whole table.
func widenedFixture() map[string]string {
	vals := map[string]string{
		ipIfInOctets32:  "12345",
		ipIfHCInOctets:  "9876543210",
		ipIfInHdrErrs32: "0",
		afterDot3Run:    "100",
	}
	for col := 1; col <= 6; col++ {
		vals[fmt.Sprintf(".1.3.6.1.2.1.10.7.11.1.%d.3", col)] = "9876543210"
	}
	return vals
}

// TestV1GetWidenedCounter64ReturnsNoSuchName is the matrix row: an
// ipIfStatsHC* or dot3HC* GET under v1 now diverts to noSuchName (RFC 3584
// §4.2.2.1), where before the widening it was answered with a value.
func TestV1GetWidenedCounter64ReturnsNoSuchName(t *testing.T) {
	s := newTestServer(widenedFixture())

	for _, oid := range []string{ipIfHCInOctets, dot3HCFCSErrors} {
		if snmpTypeTag(oid) != ASN1_COUNTER64 {
			t.Fatalf("precondition failed: %s is not declared Counter64", oid)
		}
		resp := s.handleGetRequestVarbinds([]string{oid}, snmpRequestAt(ASN1_GET_REQUEST, snmpVersion1, []string{oid}))
		hdr := decodeResponseHeader(t, resp)
		if hdr.errStatus != snmpErrNoSuchName || hdr.errIndex != 1 {
			t.Errorf("v1 GET %s: error-status=%d error-index=%d, want noSuchName/1",
				oid, hdr.errStatus, hdr.errIndex)
		}
		assertNoCounter64Tag(t, hdr.varbinds)
	}
}

// TestV1GetNextSkipsWidenedCounter64 is the other half of the matrix pair: a
// GETNEXT must SKIP the widened column and continue, never error, and it must
// stop at the FIRST non-Counter64 successor rather than over-skipping.
func TestV1GetNextSkipsWidenedCounter64(t *testing.T) {
	s := newTestServer(widenedFixture())

	for _, tc := range []struct{ name, from, want string }{
		{"ipIfStats HC run", ipIfInOctets32, ipIfInHdrErrs32},
		{"dot3HCStats whole table", ipIfInHdrErrs32, afterDot3Run},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next, _ := s.findNextOID(tc.from)
			if snmpTypeTag(next) != ASN1_COUNTER64 {
				t.Fatalf("precondition failed: successor of %s is %s, expected a Counter64", tc.from, next)
			}
			resp := s.handleSNMPv2cRequest(snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, []string{tc.from}))
			hdr := decodeResponseHeader(t, resp)
			if hdr.errStatus != 0 {
				t.Fatalf("v1 GETNEXT(%s) error-status=%d, want noError: a GETNEXT SKIPS a Counter64",
					tc.from, hdr.errStatus)
			}
			assertNoCounter64Tag(t, hdr.varbinds)
			if got := firstVarbindOID(t, hdr.varbinds); got != tc.want {
				t.Errorf("v1 GETNEXT(%s) returned %s, want %s: it must stop at the first "+
					"non-Counter64 successor, not over-skip", tc.from, got, tc.want)
			}
		})
	}
}

// TestV2cWidenedCounter64Unchanged pins that the widening did not move v2c:
// the tag was Counter64-shaped data before (encoded as INTEGER, since the
// table did not type the column) and is tag 0x46 now, which is the CORRECTION,
// so what must not change is that v2c still answers with a value.
func TestV2cWidenedCounter64Unchanged(t *testing.T) {
	s := newTestServer(widenedFixture())

	for _, oid := range []string{ipIfHCInOctets, dot3HCFCSErrors} {
		resp := s.handleGetRequestVarbinds([]string{oid}, snmpRequestAt(ASN1_GET_REQUEST, snmpVersion2c, []string{oid}))
		hdr := decodeResponseHeader(t, resp)
		if hdr.errStatus != 0 {
			t.Errorf("v2c GET %s: error-status=%d, want noError", oid, hdr.errStatus)
		}
		if !containsTagAtVarbindValue(hdr.varbinds, ASN1_COUNTER64) {
			t.Errorf("v2c GET %s no longer carries tag 0x46", oid)
		}
	}
}

// TestV1GetBulkWidenedCounter64Unchanged records the DECISION, not a
// preference: a version-0 GETBULK keeps answering as-is, tag 0x46 included,
// exactly as TestV1GetBulkStillReturnsCounter64 pins for ifXTable. The
// widening must not quietly change that for the newly covered columns.
func TestV1GetBulkWidenedCounter64Unchanged(t *testing.T) {
	s := newTestServer(widenedFixture())

	oids := []string{ipIfHCInOctets, dot3HCFCSErrors}
	responses := []string{"9876543210", "9876543210"}
	resp := s.createVarbindResponse(oids, responses,
		snmpRequestAt(ASN1_GET_BULK, snmpVersion1, []string{ipIfHCInOctets}),
		varbindResponseRules{overflow: overflowTruncate, v1Diversion: v1DivertNothing})

	hdr := decodeResponseHeader(t, resp)
	if hdr.errStatus != 0 {
		t.Fatalf("v1 GETBULK error-status=%d, want noError: the divert is GET-only", hdr.errStatus)
	}
	if !containsTagAtVarbindValue(hdr.varbinds, ASN1_COUNTER64) {
		t.Errorf("v1 GETBULK no longer carries tag 0x46 for a widened column")
	}
}

// TestOidTypeTableHasNoShadowedRows pins that every row of oidTypeTable can
// actually be reached. snmpTypeTag returns the FIRST match, so a row whose
// prefix is covered by an earlier row is inert: it looks like a declaration and
// declares nothing. That is a silent way to believe a column is typed when it is
// not, and this change added 34 rows in one go.
//
// A row is shadowed when an EARLIER row's prefix is a prefix of it (at a
// sub-identifier boundary), which is exactly the match snmpTypeTag performs.
func TestOidTypeTableHasNoShadowedRows(t *testing.T) {
	for i, e := range oidTypeTable {
		for j := 0; j < i; j++ {
			p := oidTypeTable[j].prefix
			if e.prefix == p || (strings.HasPrefix(e.prefix, p) && e.prefix[len(p)] == '.') {
				t.Errorf("row %d (%s -> %s) is shadowed by row %d (%s -> %s): snmpTypeTag returns "+
					"the first match, so the later row never applies",
					i, e.prefix, snmpTypeName(e.tag), j, p, snmpTypeName(oidTypeTable[j].tag))
			}
		}
		// And every row must be reachable through the real function.
		if got := snmpTypeTag(e.prefix + ".1"); got != e.tag {
			t.Errorf("row %d (%s -> %s) is not reachable: snmpTypeTag(%s.1) = 0x%02X",
				i, e.prefix, snmpTypeName(e.tag), e.prefix, got)
		}
	}
	t.Logf("%d oidTypeTable rows, all reachable", len(oidTypeTable))
}
