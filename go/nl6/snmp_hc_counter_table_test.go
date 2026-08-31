/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// shippedTypedCorpus walks every shipped resource part and returns the
// distinct (normalised OID, emitted tag) pairs the fleet would put on the wire,
// as sorted "oid\ttag" lines, plus the number of entries inspected.
//
// The tag is the FIRST BYTE encodeTypedValue actually emits, not the tag
// oidTypeTable declares: this is a measurement of the wire, so it must come
// from the encoder.
func shippedTypedCorpus(t *testing.T) (lines []string, entries int) {
	t.Helper()
	files, err := filepath.Glob("resources/*/*.json")
	if err != nil {
		t.Fatalf("glob resources: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no resource files found — has the layout changed?")
	}
	sort.Strings(files)

	seen := make(map[string]struct{})
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- test-only, path from a repo glob
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var doc DeviceResources
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: does not decode as a resource file: %v", f, err)
		}
		for _, r := range doc.SNMP {
			oid := normaliseResourceOID(r.OID)
			emitted := encodeTypedValue(oid, r.Response)
			if len(emitted) == 0 {
				t.Fatalf("%s: encodeTypedValue(%s, %q) emitted nothing", f, oid, r.Response)
			}
			seen[fmt.Sprintf("%s\t%02X", oid, emitted[0])] = struct{}{}
			entries++
		}
	}
	lines = make([]string, 0, len(seen))
	for l := range seen {
		lines = append(lines, l)
	}
	sort.Strings(lines)
	return lines, entries
}

// shippedTagDigest is a SHA-256 over the sorted, distinct (OID, emitted tag)
// pairs of the whole shipped resource corpus.
//
// It was computed on the working tree of this change with the oidTypeTable
// widening of nl6#541 NOT YET APPLIED (but with the resource-data corrections
// of the same change already in place, since those precede it), and then
// re-run with the widening applied. Both runs produce this digest, which is
// the measurement behind the spec's Block If: widening the table changed the
// emitted tag of no OID any shipped profile serves. It is a measurement, not
// an argument, and it was NOT re-derived from the widened code.
//
// If a resource edit legitimately adds an OID or changes a value's TYPE, this
// digest must be re-pinned in the same commit, and the diff the failure prints
// is the review evidence for doing so.
const shippedTagDigest = "7fe75d4a8f4cbc3aa1b00c87ce5ab4676aeccca50267f09fb03fe91c432138f5"

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
	t.Logf("%d SNMP entries inspected, %d distinct (OID, tag) pairs; tag histogram: %v",
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
			// A real instance OID: these tables are indexed by address family
			// (and ifIndex, in ipIfStatsTable).
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
func TestShippedBigValuesSitOnCounter64Leaves(t *testing.T) {
	files, err := filepath.Glob("resources/*/*.json")
	if err != nil {
		t.Fatalf("glob resources: %v", err)
	}
	sort.Strings(files)

	big, offending := 0, 0
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- test-only, path from a repo glob
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var doc DeviceResources
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: does not decode as a resource file: %v", f, err)
		}
		for _, r := range doc.SNMP {
			v, perr := strconv.ParseUint(r.Response, 10, 64)
			if perr != nil || v <= 0xFFFFFFFF {
				continue
			}
			big++
			oid := normaliseResourceOID(r.OID)
			if snmpTypeTag(oid) != ASN1_COUNTER64 {
				offending++
				t.Errorf("%s: %s = %s needs 64 bits but its leaf is declared %s. Either the leaf is a "+
					"64-bit counter and oidTypeTable needs the row (then re-pin shippedTagDigest), or "+
					"the value is wrong for the leaf's real MIB type and belongs in 32 bits",
					f, oid, r.Response, snmpTypeName(snmpTypeTag(oid)))
			}
		}
	}
	if big == 0 {
		t.Fatal("no shipped value needs more than 32 bits, so this test asserted nothing about the corpus")
	}
	t.Logf("%d shipped values need more than 32 bits, %d of them off a Counter64 leaf", big, offending)

	// Positive control: the corpus being clean must not be mistaken for a test
	// that cannot fail. A vendor HC column with a 64-bit value is exactly the
	// case the check exists for, and the table does not type it.
	const vendorHC = ".1.3.6.1.4.1.9999.1.1.1.6.1"
	if snmpTypeTag(vendorHC) == ASN1_COUNTER64 {
		t.Fatalf("control fixture %s is typed by the table, so it no longer exercises the check", vendorHC)
	}
	if got := encodeTypedValue(vendorHC, "9876543210"); got[0] == ASN1_COUNTER64 {
		t.Errorf("premise changed: an untyped vendor HC column now encodes as Counter64 (% x)", got)
	}
}

// BenchmarkSnmpTypeTag measures the linear scan nl6#524 deliberately put
// AFTER the SNMP version compare on the v1 GETNEXT path. The widening of
// nl6#541 lengthens the table, so the cost of the scan is measured rather than
// left implicit: `hit-early` and `miss` bracket it (a miss walks every row).
func BenchmarkSnmpTypeTag(b *testing.B) {
	for _, tc := range []struct{ name, oid string }{
		{"hit-early", ".1.3.6.1.2.1.1.3.0"},              // sysUpTime, row 2
		{"hit-widened", ".1.3.6.1.2.1.4.31.3.1.6.1.4"},   // ipIfStatsHCInOctets
		{"hit-late", ".1.0.8802.1.1.2.1.4.1.1.10.1.1.1"}, // lldpRemSysDesc, last row
		{"miss", ".1.3.6.1.4.1.9999.1.2.3.4.5"},          // walks the whole table
	} {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = snmpTypeTag(tc.oid)
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
