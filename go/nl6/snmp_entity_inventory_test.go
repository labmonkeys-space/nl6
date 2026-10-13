/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The chassis rows of most shipped profiles served the ENTITY-MIB inventory
// columns one place to the right: the manufacturer name at entPhysicalUris, a
// urn:clei: URI at entPhysicalUUID, and 14 ASCII hex characters at
// entPhysicalMfgDate. Four generated profiles had no entPhysicalMfgName on the
// chassis at all, and named "Simulation Vendor" on every port row. Every value
// encoded cleanly, so no load guard could see it.
//
// These guards check the SHAPE RFC 4133 and RFC 6933 give each column, and that
// a profile does not contradict itself about who made it. They do not check that
// a manufacturer name is the right one.

const (
	entPhysicalMfgNameCol = "12"
	entPhysicalMfgDateCol = "17"
	entPhysicalUrisCol    = "18"
	entPhysicalUUIDCol    = "19"
)

// entityInventoryFormatViolations returns one line per served entPhysicalMfgDate,
// entPhysicalUris or entPhysicalUUID value that the column cannot hold.
func entityInventoryFormatViolations(entries []shippedSNMPEntry) []string {
	var out []string
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.OID, entPhysicalEntryPrefix)
		if !ok {
			continue
		}
		col, _, _ := strings.Cut(rest, ".")
		var why string
		switch col {
		case entPhysicalMfgDateCol:
			// DateAndTime is 8 or 11 octets; '0000000000000000'H means unknown.
			if n := len(e.Value); n != 8 && n != 11 {
				why = fmt.Sprintf("entPhysicalMfgDate is %d octets, want 8 or 11", n)
			}
		case entPhysicalUrisCol:
			// Zero-length, or URIs separated by spaces.
			for tok := range strings.FieldsSeq(e.Value) {
				if u, err := url.Parse(tok); err != nil || u.Scheme == "" {
					why = fmt.Sprintf("entPhysicalUris token %q is not an absolute URI", tok)
					break
				}
			}
		case entPhysicalUUIDCol:
			// UUIDorZero: 16 octets, or zero-length.
			if n := len(e.Value); n != 0 && n != 16 {
				why = fmt.Sprintf("entPhysicalUUID is %d octets, want 0 or 16", n)
			}
		}
		if why != "" {
			out = append(out, fmt.Sprintf("%s: %s = %q: %s", e.Profile, e.OID, e.Value, why))
		}
	}
	sort.Strings(out)
	return out
}

// entityManufacturerViolations requires the root row (entPhysicalContainedIn 0)
// to name its manufacturer, and every other row to name the same one or none.
// A profile without exactly one root is entityRootViolations' finding, not this.
func entityManufacturerViolations(entries []shippedSNMPEntry) []string {
	type row struct {
		containedIn string
		mfg         *string
	}
	tables := map[string]map[string]*row{} // profile -> index -> row
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.OID, entPhysicalEntryPrefix)
		if !ok {
			continue
		}
		col, index, ok := strings.Cut(rest, ".")
		if !ok || strings.Contains(index, ".") {
			continue
		}
		if tables[e.Profile] == nil {
			tables[e.Profile] = map[string]*row{}
		}
		r := tables[e.Profile][index]
		if r == nil {
			r = &row{}
			tables[e.Profile][index] = r
		}
		switch col {
		case entPhysicalContainedInCol:
			r.containedIn = e.Value
		case entPhysicalMfgNameCol:
			v := e.Value
			r.mfg = &v
		}
	}

	var out []string
	for profile, rows := range tables {
		var rootIndex string
		roots := 0
		for index, r := range rows {
			if r.containedIn == "0" {
				rootIndex, roots = index, roots+1
			}
		}
		if roots != 1 {
			continue
		}
		root := rows[rootIndex]
		if root.mfg == nil || *root.mfg == "" {
			out = append(out, fmt.Sprintf("%s: root row %s names no entPhysicalMfgName", profile, rootIndex))
			continue
		}
		for index, r := range rows {
			if index == rootIndex || r.mfg == nil || *r.mfg == "" || *r.mfg == *root.mfg {
				continue
			}
			out = append(out, fmt.Sprintf("%s: row %s has entPhysicalMfgName %q, root row %s has %q",
				profile, index, *r.mfg, rootIndex, *root.mfg))
		}
	}
	sort.Strings(out)
	return out
}

func TestEntityInventoryColumnsAreWellFormedOrAbsent(t *testing.T) {
	t.Run("positive control", func(t *testing.T) { assertEntityInventoryDetectionWorks(t) })

	for _, v := range entityInventoryFormatViolations(shippedSNMPEntries(t)) {
		t.Error(v)
	}
}

func TestEntityManufacturerIsNamedAndConsistent(t *testing.T) {
	t.Run("positive control", func(t *testing.T) { assertEntityInventoryDetectionWorks(t) })

	for _, v := range entityManufacturerViolations(shippedSNMPEntries(t)) {
		t.Error(v)
	}
}

// assertEntityInventoryDetectionWorks plants a single-file profile with the
// shapes that shipped into a temp copy of resources/ and requires both guards
// to report exactly them. Scoped to the planted profiles, so a real violation
// elsewhere cannot make it pass or fail.
func assertEntityInventoryDetectionWorks(t *testing.T) {
	t.Helper()

	tmp := t.TempDir()
	if err := os.CopyFS(filepath.Join(tmp, "resources"), os.DirFS("resources")); err != nil {
		t.Fatalf("copy resources: %v", err)
	}
	// zzshifted: the chassis row of most profiles. zznomfg: the generated
	// family, no chassis manufacturer and a placeholder on the port.
	// zzcontra: a root that names one vendor and a port that names another.
	plants := map[string]string{
		"zzshifted.json": `{"snmp":[
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.4.1","response":"0"},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.12.1","response":"Cisco Systems, Inc."},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.17.1","response":"07E4060A000000"},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.18.1","response":"Cisco Systems, Inc."},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.19.1","response":"urn:clei:CMICAB5DAA"}]}`,
		"zznomfg.json": `{"snmp":[
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.4.1","response":"0"},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.4.1001","response":"1"},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.12.1001","response":"Simulation Vendor"}]}`,
		"zzcontra.json": `{"snmp":[
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.4.1","response":"0"},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.12.1","response":"Cisco Systems, Inc."},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.4.1001","response":"1"},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.12.1001","response":"Simulation Vendor"},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.4.1002","response":"1"},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.12.1002","response":""},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.18.1","response":"urn:clei:CMICAB5DAA http://example.com/x"},
			{"oid":"1.3.6.1.2.1.47.1.1.1.1.19.1","response":""}]}`,
	}
	for name, body := range plants {
		if err := os.WriteFile(filepath.Join(tmp, "resources", name), []byte(body), 0o644); err != nil {
			t.Fatalf("plant %s: %v", name, err)
		}
	}
	t.Chdir(tmp)

	entries := shippedSNMPEntries(t)
	planted := func(vs []string) string {
		var got []string
		for _, v := range vs {
			if strings.HasPrefix(v, "zz") {
				got = append(got, v)
			}
		}
		return strings.Join(got, "\n")
	}

	wantFormat := strings.Join([]string{
		`zzshifted.json: .1.3.6.1.2.1.47.1.1.1.1.17.1 = "07E4060A000000": entPhysicalMfgDate is 14 octets, want 8 or 11`,
		`zzshifted.json: .1.3.6.1.2.1.47.1.1.1.1.18.1 = "Cisco Systems, Inc.": entPhysicalUris token "Cisco" is not an absolute URI`,
		`zzshifted.json: .1.3.6.1.2.1.47.1.1.1.1.19.1 = "urn:clei:CMICAB5DAA": entPhysicalUUID is 19 octets, want 0 or 16`,
	}, "\n")
	if got := planted(entityInventoryFormatViolations(entries)); got != wantFormat {
		t.Errorf("the format guard reported\n%s\nfor the planted profiles, want\n%s", got, wantFormat)
	}

	wantMfg := strings.Join([]string{
		`zzcontra.json: row 1001 has entPhysicalMfgName "Simulation Vendor", root row 1 has "Cisco Systems, Inc."`,
		`zznomfg.json: root row 1 names no entPhysicalMfgName`,
	}, "\n")
	if got := planted(entityManufacturerViolations(entries)); got != wantMfg {
		t.Errorf("the manufacturer guard reported\n%s\nfor the planted profiles, want\n%s", got, wantMfg)
	}
}
