/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"strings"
	"testing"
)

// longestCounter64Run returns the length of the longest run of CONSECUTIVE
// entries in walk order whose declared type is Counter64, and the OID the run
// starts at.
//
// Walk order is what matters, not the count of Counter64 OIDs: the skip loop in
// getNextBinding steps once per consecutive Counter64 successor, so a profile
// with 500 HC columns scattered between Counter32 ones costs one step per
// binding, while 288 adjacent ones cost 288 on one binding. sortedOIDs is the
// order findNextOID walks, so it is the order this counts in.
func longestCounter64Run(sorted []string) (int, string) {
	best, bestAt := 0, ""
	cur, curAt := 0, ""
	for _, oid := range sorted {
		if snmpTypeTag(oid) == ASN1_COUNTER64 {
			if cur == 0 {
				curAt = oid
			}
			cur++
			if cur > best {
				best, bestAt = cur, curAt
			}
			continue
		}
		cur, curAt = 0, ""
	}
	return best, bestAt
}

// TestLongestCounter64RunAcrossShippedProfiles pins the figure that sizes
// nl6#524's Counter64 skip loop (nl6#542 item 4).
//
// CLAUDE.md and getNextBinding both cite the width of the widest contiguous
// Counter64 run across the shipped profiles. It was measured once by hand and
// re-checked by nothing, so a resource edit that widened it — another interface
// on cisco_crs_x, a ninth ifHC* column added to oidTypeTable — made the
// documented number stale silently. This recomputes it from the shipped set
// through the real loader and the real type table.
//
// Same shape and same reason as TestShippedResourcesLoadClean: every directory
// under resources/ except the _-prefixed ones, and the totals are asserted
// non-zero so a decode regression could not make it pass vacuously.
//
// It is deliberately an EQUALITY, not an upper bound. A run that got SHORTER is
// also a stale document, and the step cap is 100000 — three orders of magnitude
// above this — so an inequality would never fire for the reason the figure
// exists.
func TestLongestCounter64RunAcrossShippedProfiles(t *testing.T) {
	// The figure carried in CLAUDE.md and in getNextBinding's comment.
	const documentedRun = 288

	entries, err := os.ReadDir("resources")
	if err != nil {
		t.Fatalf("read resources dir: %v", err)
	}

	dirs, seenC64 := 0, 0
	worst, worstProfile, worstAt := 0, "", ""
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		name := e.Name() + ".json"
		sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
		res, err := sm.LoadSpecificResources(name)
		if err != nil {
			t.Errorf("LoadSpecificResources(%s): %v", name, err)
			continue
		}
		dirs++
		for _, oid := range res.sortedOIDs {
			if snmpTypeTag(oid) == ASN1_COUNTER64 {
				seenC64++
			}
		}
		if run, at := longestCounter64Run(res.sortedOIDs); run > worst {
			worst, worstProfile, worstAt = run, name, at
		}
	}

	if dirs == 0 {
		t.Fatal("no resource directories loaded. Is the test running from go/nl6?")
	}
	if seenC64 == 0 {
		t.Fatalf("loaded %d directories and found no Counter64 OID at all, so the "+
			"measurement would be vacuous: snmpTypeTag or the resource loader has changed", dirs)
	}

	if worst != documentedRun {
		t.Errorf("longest contiguous Counter64 run across %d shipped profiles is %d "+
			"(%s, starting at %s), but %d is documented in CLAUDE.md and in "+
			"getNextBinding's comment.\n"+
			"A v1 GETNEXT skips this many steps on one binding, inline in the shared UDP "+
			"handler. Update both places to %d, or explain the new width.",
			dirs, worst, worstProfile, worstAt, documentedRun, worst)
	}
	t.Logf("%d profiles, %d Counter64 OIDs, longest contiguous run %d (%s at %s)",
		dirs, seenC64, worst, worstProfile, worstAt)
}

// TestLongestCounter64RunCountsAdjacencyOnly tests longestCounter64Run directly,
// because the shipped set cannot distinguish it from a total.
//
// cisco_crs_x's Counter64 OIDs happen to be ONE contiguous block, and no other
// shipped profile has more Counter64 OIDs in total than that block is long, so
// deleting the run reset above leaves the measurement over the shipped set
// unchanged at 288. Adjacency is the whole point of the figure — the skip loop
// costs one step per CONSECUTIVE Counter64 successor — so it is asserted here on
// synthetic input where the two answers differ.
//
// The OIDs are real ifXTable columns, since snmpTypeTag decides the type and a
// made-up OID would report the wrong one. Precondition-checked, so a change to
// oidTypeTable fails loudly instead of making every row read "not a Counter64".
func TestLongestCounter64RunCountsAdjacencyOnly(t *testing.T) {
	// Two Counter64 columns and two that are not (Counter32 / Gauge32).
	c64a, c64b := ".1.3.6.1.2.1.31.1.1.1.6.1", ".1.3.6.1.2.1.31.1.1.1.10.1"
	plain, plain2 := ".1.3.6.1.2.1.31.1.1.1.5.1", ".1.3.6.1.2.1.31.1.1.1.15.1"
	for _, o := range []string{c64a, c64b} {
		if snmpTypeTag(o) != ASN1_COUNTER64 {
			t.Fatalf("precondition failed: %s is not typed Counter64 by oidTypeTable", o)
		}
	}
	for _, o := range []string{plain, plain2} {
		if snmpTypeTag(o) == ASN1_COUNTER64 {
			t.Fatalf("precondition failed: %s is typed Counter64 by oidTypeTable", o)
		}
	}

	tests := []struct {
		name   string
		sorted []string
		want   int
		wantAt string
	}{
		{"empty", nil, 0, ""},
		{"none", []string{plain, plain2}, 0, ""},
		{"one", []string{plain, c64a, plain2}, 1, c64a},
		{"adjacent pair", []string{plain, c64a, c64b, plain2}, 2, c64a},
		// The row the reset exists for: four Counter64 OIDs in total, none of
		// them adjacent to another, so the longest RUN is one.
		{"four split by non-counter64s", []string{c64a, plain, c64b, plain2, c64a, plain, c64b}, 1, c64a},
		{"trailing run", []string{plain, c64a, c64b}, 2, c64a},
		{"leading run beats later single", []string{c64a, c64b, plain, c64a}, 2, c64a},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, at := longestCounter64Run(tt.sorted)
			if got != tt.want || at != tt.wantAt {
				t.Errorf("longestCounter64Run = (%d, %q), want (%d, %q): the figure counts "+
					"CONSECUTIVE Counter64 entries in walk order, not the total",
					got, at, tt.want, tt.wantAt)
			}
		})
	}
}
