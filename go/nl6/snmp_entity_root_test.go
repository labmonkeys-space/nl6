/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// RFC 4133 requires one "overall" physical entity. That row is the root of the
// containment tree: its entPhysicalContainedIn is 0, its class is chassis(3),
// and its entPhysicalParentRelPos is -1. A collector builds an inventory tree by
// following entPhysicalContainedIn upward, so a root contained in an index
// nobody serves leaves the whole tree without one.
//
// Four profiles shipped exactly that: a chassis row of class other(1),
// contained in 39, 42, 41 or 55, none of which existed. Every other profile
// already had a correct root. The guard runs over the shared corpus walk, so it
// sees the single-file layout too.

const (
	entPhysicalEntryPrefix    = ".1.3.6.1.2.1.47.1.1.1.1."
	entPhysicalContainedInCol = "4"
	entPhysicalClassCol       = "5"
	entPhysicalParentRelPos   = "6"
	entPhysicalClassChassis   = "3"
)

// entityRootViolations checks every profile that serves entPhysicalTable and
// returns one line per defect, sorted, each naming the profile.
func entityRootViolations(entries []shippedSNMPEntry) []string {
	type row struct{ containedIn, class, relPos string }
	tables := map[string]map[string]*row{} // profile -> index -> row
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.OID, entPhysicalEntryPrefix)
		if !ok {
			continue
		}
		col, index, ok := strings.Cut(rest, ".")
		if !ok || strings.Contains(index, ".") {
			continue // a bare column or an over-specified name, not a row
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
		case entPhysicalClassCol:
			r.class = e.Value
		case entPhysicalParentRelPos:
			r.relPos = e.Value
		}
	}

	var out []string
	for profile, rows := range tables {
		var roots []string
		for index, r := range rows {
			switch {
			case r.containedIn == "0":
				roots = append(roots, index)
			case r.containedIn == "":
				out = append(out, fmt.Sprintf("%s: row %s serves no entPhysicalContainedIn", profile, index))
			case rows[r.containedIn] == nil:
				out = append(out, fmt.Sprintf("%s: row %s is contained in %s, which the profile does not serve",
					profile, index, r.containedIn))
			}
		}
		sort.Strings(roots)
		if len(roots) != 1 {
			out = append(out, fmt.Sprintf("%s: %d rows have entPhysicalContainedIn 0 %v, want exactly one",
				profile, len(roots), roots))
			continue
		}
		root := rows[roots[0]]
		if root.class != entPhysicalClassChassis {
			out = append(out, fmt.Sprintf("%s: root row %s has entPhysicalClass %q, want chassis(3)",
				profile, roots[0], root.class))
		}
		if root.relPos != "" && root.relPos != "-1" {
			out = append(out, fmt.Sprintf("%s: root row %s has entPhysicalParentRelPos %q, want -1",
				profile, roots[0], root.relPos))
		}
	}
	sort.Strings(out)
	return out
}

func TestEveryEntityTableHasOneChassisRoot(t *testing.T) {
	// The control runs first and in its own scope, because it t.Chdir()s.
	t.Run("positive control", func(t *testing.T) { assertEntityRootDetectionWorks(t) })

	for _, v := range entityRootViolations(shippedSNMPEntries(t)) {
		t.Error(v)
	}
}

// assertEntityRootDetectionWorks plants a single-file profile with the shape
// that shipped (a class-other root contained in a missing index) into a temp
// copy of resources/, and requires the guard to report it. Scoped to the
// planted profile, so a real violation elsewhere cannot make it pass or fail.
func assertEntityRootDetectionWorks(t *testing.T) {
	t.Helper()

	tmp := t.TempDir()
	if err := os.CopyFS(filepath.Join(tmp, "resources"), os.DirFS("resources")); err != nil {
		t.Fatalf("copy resources: %v", err)
	}
	planted := `{"snmp":[
		{"oid":"1.3.6.1.2.1.47.1.1.1.1.4.1","response":"39"},
		{"oid":"1.3.6.1.2.1.47.1.1.1.1.5.1","response":"1"},
		{"oid":"1.3.6.1.2.1.47.1.1.1.1.6.1","response":"1"},
		{"oid":"1.3.6.1.2.1.47.1.1.1.1.4.1001","response":"1"},
		{"oid":"1.3.6.1.2.1.47.1.1.1.1.5.1001","response":"10"}]}`
	if err := os.WriteFile(filepath.Join(tmp, "resources", "zzbadroot.json"), []byte(planted), 0o644); err != nil {
		t.Fatalf("plant single-file profile: %v", err)
	}
	t.Chdir(tmp)

	var got []string
	for _, v := range entityRootViolations(shippedSNMPEntries(t)) {
		if strings.HasPrefix(v, "zzbadroot.json:") {
			got = append(got, v)
		}
	}
	want := []string{
		"zzbadroot.json: 0 rows have entPhysicalContainedIn 0 [], want exactly one",
		"zzbadroot.json: row 1 is contained in 39, which the profile does not serve",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the guard reported\n%s\nfor the planted profile, want\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The root checks themselves, which the shipped shape never reaches because
	// it has no root at all.
	rootOnly := []shippedSNMPEntry{
		{Profile: "zzroot.json", OID: ".1.3.6.1.2.1.47.1.1.1.1.4.1", Value: "0"},
		{Profile: "zzroot.json", OID: ".1.3.6.1.2.1.47.1.1.1.1.5.1", Value: "1"},
		{Profile: "zzroot.json", OID: ".1.3.6.1.2.1.47.1.1.1.1.6.1", Value: "1"},
	}
	want = []string{
		`zzroot.json: root row 1 has entPhysicalClass "1", want chassis(3)`,
		`zzroot.json: root row 1 has entPhysicalParentRelPos "1", want -1`,
	}
	if got := entityRootViolations(rootOnly); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the guard reported\n%s\nfor a wrong root, want\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
