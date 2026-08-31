/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The nl6#541 review's standing objection: oidTypeTable's 34 new rows and the
// test-side lists that check them were written in the same change, from the same
// reading of the same MIBs, so a misreading shared by both passes every
// assertion in the package. Every other check here is nl6 verifying nl6.
//
// testdata/mibs/*.tsv is the independent side: MIB facts extracted with
// net-snmp, checked in with the command that produced them. Independent of the
// hand-written table, which is where the risk is; not independent of net-snmp,
// which is a limitation and not a pretence.
//
// The test READS the fixtures. It deliberately does NOT shell out to
// snmptranslate: no workflow installs net-snmp, so a tool-dependent test would
// t.Skip in CI and assert nothing.

type mibRow struct {
	oid    string
	name   string
	syntax string
}

// mibSyntaxTag maps a MIB SYNTAX clause to the ASN.1 application tag SNMP puts
// on the wire for it. A syntax nl6 has no application tag for (Integer32, an
// INTEGER enum) maps to 0, which means "oidTypeTable must not type it": those
// take encodeTypedValue's default INTEGER branch.
func mibSyntaxTag(syntax string) byte {
	switch {
	case syntax == "Counter64":
		return ASN1_COUNTER64
	case syntax == "Counter32":
		return ASN1_COUNTER32
	case syntax == "Gauge32" || syntax == "Unsigned32" || strings.HasPrefix(syntax, "Gauge32 "):
		return ASN1_GAUGE32
	case syntax == "TimeTicks" || syntax == "TimeStamp":
		return ASN1_TIMETICKS
	case syntax == "IpAddress":
		return ASN1_IPADDRESS
	case syntax == "OBJECT IDENTIFIER":
		return ASN1_OBJECT_ID
	case strings.HasPrefix(syntax, "OCTET STRING") ||
		strings.HasPrefix(syntax, "DisplayString") ||
		strings.HasPrefix(syntax, "SnmpAdminString") ||
		strings.HasPrefix(syntax, "PhysAddress"):
		return ASN1_OCTET_STRING
	default:
		return 0
	}
}

// loadMIBFixture reads one extracted fixture, returning the resolved rows and
// the number of unresolved ones. Unresolved rows are returned as a count rather
// than dropped, because "the MIB was not in the extraction set" and "the column
// does not exist" must not be able to hide a missing row.
func loadMIBFixture(t *testing.T, name string) (rows []mibRow, unresolvedOIDs []string) {
	t.Helper()
	path := filepath.Join("testdata", "mibs", name)
	f, err := os.Open(path) // #nosec G304 -- test-only, fixed repo path
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			t.Fatalf("%s: malformed row %q (want oid<TAB>name<TAB>syntax)", path, line)
		}
		if parts[1] == "-" {
			unresolvedOIDs = append(unresolvedOIDs, parts[0])
			continue
		}
		rows = append(rows, mibRow{oid: parts[0], name: parts[1], syntax: parts[2]})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s resolved no rows, so every assertion over it is vacuous", path)
	}
	return rows, unresolvedOIDs
}

// fixtureOIDs is every OID a fixture mentions, resolved or not. The tests below
// check a fixture's EXTENT with it, which is the hole two mutation checks found:
// both directions iterate the fixture, so a table row absent from the fixture,
// or a fixture row deleted, was invisible.
func fixtureOIDs(rows []mibRow, unresolved []string) map[string]struct{} {
	out := make(map[string]struct{}, len(rows)+len(unresolved))
	for _, r := range rows {
		out[r.oid] = struct{}{}
	}
	for _, o := range unresolved {
		out[o] = struct{}{}
	}
	return out
}

// TestOidTypeTableAgreesWithTheMIBs checks the whole table against extracted MIB
// facts, in both directions.
func TestOidTypeTableAgreesWithTheMIBs(t *testing.T) {
	// ── Direction 1: every typed row must carry the MIB's own type ──────────
	//
	// Covers the WHOLE table, not only the rows nl6#541 added.
	prefixes, prefixUnresolved := loadMIBFixture(t, "oidtypetable_prefixes.tsv")

	// EXTENT first: every oidTypeTable row must appear in the fixture, and the
	// fixture must mention nothing else. Without this the checks below iterate
	// the fixture and a row added to the table without regenerating it is
	// simply not looked at — which a mutation check confirmed.
	inFixture := fixtureOIDs(prefixes, prefixUnresolved)
	for _, e := range oidTypeTable {
		if _, ok := inFixture[e.prefix]; !ok {
			t.Errorf("oidTypeTable declares %s (%s) but testdata/mibs/oidtypetable_prefixes.tsv "+
				"does not mention it, so nothing checks it against a MIB. Regenerate the fixture "+
				"(its header carries the command)", e.prefix, snmpTypeName(e.tag))
		}
	}
	if len(inFixture) != len(oidTypeTable) {
		t.Errorf("the prefix fixture mentions %d OIDs but oidTypeTable has %d rows; the fixture "+
			"is stale in one direction or the other", len(inFixture), len(oidTypeTable))
	}

	for _, r := range prefixes {
		want := mibSyntaxTag(r.syntax)
		if want == 0 {
			t.Errorf("%s (%s) has SYNTAX %q, which nl6 has no application tag for, yet "+
				"oidTypeTable types it. Such an object belongs on the default INTEGER branch",
				r.oid, r.name, r.syntax)
			continue
		}
		// Probe through the real function, on an instance OID.
		if got := snmpTypeTag(r.oid + ".1"); got != want {
			t.Errorf("%s (%s): MIB SYNTAX is %q so the wire tag must be 0x%02X (%s), but "+
				"oidTypeTable declares 0x%02X (%s)",
				r.oid, r.name, r.syntax, want, snmpTypeName(want), got, snmpTypeName(got))
		}
	}

	// The unresolved rows are pinned so a NEW standard row cannot land in that
	// bucket unnoticed. All 12 are objects the extraction set does not define:
	// the usmStats SUBTREE prefix (not a column), OLD-CISCO-MEMORY-MIB freeMem,
	// and 10 LLDP-MIB columns.
	const wantPrefixUnresolved = 12
	if len(prefixUnresolved) != wantPrefixUnresolved {
		t.Errorf("%d oidTypeTable rows are unresolved against the extraction set, want %d. "+
			"A new row that no fixture can check must be a deliberate decision: either add the "+
			"MIB to the extraction set and regenerate, or raise this count and say which object "+
			"it is and why it cannot be checked", len(prefixUnresolved), wantPrefixUnresolved)
	}
	t.Logf("direction 1: %d oidTypeTable rows checked against MIB syntax, %d unresolved",
		len(prefixes), len(prefixUnresolved))

	// ── Direction 2: every 64-bit column of the widened tables must be typed ─
	//
	// This is the direction that catches an OMITTED or MISNUMBERED row, which
	// is what a shared misreading would produce. It is driven by the MIB's own
	// column enumeration, so it does not depend on ipStatsC64Columns being right.
	checked, c64 := 0, 0
	for _, fixture := range []struct {
		file           string
		wantUnresolved int
		// bases is the column enumeration the fixture must cover CONTIGUOUSLY,
		// as base prefix -> last column. Without it a DELETED fixture row is
		// invisible, because this loop iterates the fixture — mutation-confirmed.
		bases map[string]int
	}{
		// ipSystemStats column 2 and ipIfStats column 22 are unassigned.
		{"ip_mib_columns.tsv", 2, map[string]int{
			".1.3.6.1.2.1.4.31.1.1": 47,
			".1.3.6.1.2.1.4.31.3.1": 47,
		}},
		// dot3HCStatsTable assigns 1..6; 7..12 are probed to prove the table
		// ends where the rows say it does.
		{"etherlike_mib_columns.tsv", 6, map[string]int{
			".1.3.6.1.2.1.10.7.11.1": 12,
		}},
	} {
		rows, unresolved := loadMIBFixture(t, fixture.file)

		present := fixtureOIDs(rows, unresolved)
		wantRows := 0
		for base, last := range fixture.bases {
			wantRows += last
			for c := 1; c <= last; c++ {
				oid := fmt.Sprintf("%s.%d", base, c)
				if _, ok := present[oid]; !ok {
					t.Errorf("%s does not cover %s: the fixture must enumerate columns 1..%d of "+
						"%s contiguously, or a deleted row goes unnoticed",
						fixture.file, oid, last, base)
				}
			}
		}
		if len(present) != wantRows {
			t.Errorf("%s mentions %d OIDs, want %d (the contiguous enumeration); it carries rows "+
				"outside the tables it claims to cover", fixture.file, len(present), wantRows)
		}

		if len(unresolved) != fixture.wantUnresolved {
			t.Errorf("%s: %d unresolved columns, want %d — the MIB assigns a different set of "+
				"columns than when this was extracted, so the widened rows need re-checking",
				fixture.file, len(unresolved), fixture.wantUnresolved)
		}
		for _, r := range rows {
			checked++
			declared := snmpTypeTag(r.oid + ".1")
			want := mibSyntaxTag(r.syntax)

			if want == ASN1_COUNTER64 {
				c64++
				if declared != ASN1_COUNTER64 {
					t.Errorf("%s (%s) is Counter64 in the MIB but oidTypeTable declares 0x%02X "+
						"(%s): nl6#524's SNMPv1 divert and GETNEXT skip cannot fire for it",
						r.oid, r.name, declared, snmpTypeName(declared))
				}
				continue
			}
			if declared == ASN1_COUNTER64 {
				t.Errorf("%s (%s) has SYNTAX %q but oidTypeTable declares Counter64. That is a "+
					"WIRE change on a column that is not 64-bit, which is exactly what an "+
					"off-by-one row produces", r.oid, r.name, r.syntax)
			}
			// A column nl6 chooses not to type is fine; a column it types
			// WRONGLY is not.
			if declared != 0 && want != 0 && declared != want {
				t.Errorf("%s (%s): MIB SYNTAX %q wants tag 0x%02X (%s), oidTypeTable declares "+
					"0x%02X (%s)", r.oid, r.name, r.syntax, want, snmpTypeName(want),
					declared, snmpTypeName(declared))
			}
		}
	}
	if c64 == 0 {
		t.Fatal("no Counter64 column found in the fixtures, so direction 2 asserted nothing")
	}
	t.Logf("direction 2: %d MIB columns checked, %d of them Counter64", checked, c64)
}

// TestMIBFixturesCarryTheirProvenance pins the header contract. A fixture whose
// regeneration command is missing is a fixture nobody can re-derive, which is
// how extracted data turns back into hand-written data.
func TestMIBFixturesCarryTheirProvenance(t *testing.T) {
	for _, name := range []string{
		"oidtypetable_prefixes.tsv", "ip_mib_columns.tsv", "etherlike_mib_columns.tsv",
	} {
		path := filepath.Join("testdata", "mibs", name)
		b, err := os.ReadFile(path) // #nosec G304 -- test-only, fixed repo path
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		head := string(b)
		for _, want := range []string{"snmptranslate", "Extracted with:", "MIB path:", "Extracted on:"} {
			if !strings.Contains(head, want) {
				t.Errorf("%s does not record %q in its header, so it cannot be regenerated", name, want)
			}
		}
	}
}
