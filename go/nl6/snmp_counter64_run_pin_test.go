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

// longestCounter64RunThroughWalk returns the length of the longest run of
// CONSECUTIVE Counter64 objects a WALK crosses on this device, and the OID the
// run starts at.
//
// It walks findNextOIDWithServed — the function the skip loop itself calls — and
// NOT DeviceResources.sortedOIDs. That distinction is the entire point of this
// helper (nl6#542 review A1). The static index holds only the columns a
// profile's JSON ships rows for; the walk also offers
// ifCycler.NextDynamicOID, because IfCounterCycler serves the rest of ifXTable
// analytically. Measuring the index therefore under-counts the run by whatever
// share of the HC columns is analytic — 4x on cisco_crs_x — and the first
// version of this pin did exactly that, agreeing with the hand measurement it
// was written to check.
//
// Walk order is what matters, not the count of Counter64 OIDs: the skip loop
// steps once per CONSECUTIVE Counter64 successor, so 500 scattered ones cost
// one step each while 1152 adjacent ones cost 1152 on a single binding.
//
// steps is returned so a caller can assert the walk actually went somewhere; a
// walk that stopped immediately would report a run of 0 and look like a profile
// with no HC columns.
func longestCounter64RunThroughWalk(s *SNMPServer, maxSteps int) (run int, at string, steps int) {
	served := s.lldpServedOIDs()
	cur := ""
	cnt, cntAt := 0, ""
	for steps < maxSteps {
		next, _ := s.findNextOIDWithServed(cur, served)
		// Same termination conditions the walk itself uses: no successor, or one
		// that does not advance (a corrupt oidNextMap).
		if next == "" || (cur != "" && compareOIDs(next, cur) <= 0) {
			break
		}
		steps++
		if snmpTypeTag(next) == ASN1_COUNTER64 {
			if cnt == 0 {
				cntAt = next
			}
			cnt++
			if cnt > run {
				run, at = cnt, cntAt
			}
		} else {
			cnt, cntAt = 0, ""
		}
		cur = next
	}
	return run, at, steps
}

// deviceForProfile builds a device the way both production creation paths do:
// resources plus an initialised IfCounterCycler. Without the cycler the walk
// omits every analytically-served ifXTable column, which is the blind spot A1
// found.
func deviceForProfile(t *testing.T, profile string) *SNMPServer {
	t.Helper()
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources(profile)
	if err != nil {
		t.Fatalf("LoadSpecificResources(%s): %v", profile, err)
	}
	mc := &MetricsCycler{}
	mc.InitIfCounters(res, 1)
	return &SNMPServer{device: &DeviceSimulator{
		ID:            "pin",
		resources:     res,
		resourceFile:  profile,
		metricsCycler: mc,
	}}
}

// TestLongestCounter64RunAcrossShippedProfiles pins the figure that sizes
// nl6#524's Counter64 skip work (nl6#542 item 4).
//
// The value has ONE home, the production const longestShippedCounter64Run,
// which this test recomputes by WALKING every shipped profile on a device with
// a live counter cycler. Reading the const rather than restating it is
// deliberate (review R12): a test with its own copy of the number can only
// check itself.
//
// Same shape and same reason as TestShippedResourcesLoadClean: every directory
// under resources/ except the _-prefixed ones, and the totals are asserted
// non-zero so a decode regression could not make it pass vacuously.
//
// It is an EQUALITY, not an upper bound. A run that got SHORTER is also a stale
// document, and since nl6#542 review A1 the const is the NUMERATOR of the skip
// budget (counter64SkipBudgetSteps), so a shorter run means an oversized budget
// and a longer one means legitimate v1 tables truncate.
func TestLongestCounter64RunAcrossShippedProfiles(t *testing.T) {
	// Read from production, never restated here.
	const documentedRun = longestShippedCounter64Run

	entries, err := os.ReadDir("resources")
	if err != nil {
		t.Fatalf("read resources dir: %v", err)
	}

	dirs, totalSteps := 0, 0
	worst, worstProfile, worstAt := 0, "", ""
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		profile := e.Name() + ".json"
		s := deviceForProfile(t, profile)
		dirs++

		// Generous cap: the widest shipped profile walks ~6.5k steps.
		run, at, steps := longestCounter64RunThroughWalk(s, 400000)
		totalSteps += steps
		if steps == 0 {
			t.Errorf("%s: the walk returned nothing, so its measurement is vacuous", profile)
		}
		if run > worst {
			worst, worstProfile, worstAt = run, profile, at
		}
	}

	if dirs == 0 {
		t.Fatal("no resource directories loaded. Is the test running from go/nl6?")
	}
	if totalSteps == 0 {
		t.Fatalf("walked %d profiles and took zero steps", dirs)
	}

	if worst != documentedRun {
		t.Errorf("longest contiguous Counter64 run a WALK crosses, across %d shipped "+
			"profiles, is %d (%s, starting at %s), but longestShippedCounter64Run is %d.\n"+
			"A v1 GETNEXT skips this many steps on ONE binding, inline in the shared UDP "+
			"handler, and the const is the numerator of counter64SkipBudgetSteps(). Set the "+
			"const to %d (one edit, in snmp_server.go) or explain the new width.",
			dirs, worst, worstProfile, worstAt, documentedRun, worst)
	}
	t.Logf("%d profiles, %d walk steps total; longest contiguous Counter64 run %d (%s at %s)",
		dirs, totalSteps, worst, worstProfile, worstAt)
}

// TestStaticIndexUnderCountsTheCounter64Run is the regression test for the blind
// spot itself (nl6#542 review A1).
//
// It asserts that the static index and the walk DISAGREE on cisco_crs_x, which
// is what makes measuring the index the wrong method. If a future change made
// every ifXTable column statically present the two would converge and this
// would fail — at which point the pin above could be simplified, deliberately,
// rather than by a measurement quietly starting to agree again.
func TestStaticIndexUnderCountsTheCounter64Run(t *testing.T) {
	const profile = "cisco_crs_x.json"
	s := deviceForProfile(t, profile)

	staticRun, _ := longestCounter64Run(s.device.resources.sortedOIDs)
	walkRun, _, steps := longestCounter64RunThroughWalk(s, 400000)
	if steps == 0 {
		t.Fatal("the walk took no steps")
	}
	if staticRun >= walkRun {
		t.Errorf("the static index reports a run of %d and the walk %d on %s.\n"+
			"They are expected to DIFFER: the walk also offers ifCycler.NextDynamicOID for "+
			"the ifXTable columns this profile serves analytically. If they now agree, "+
			"longestCounter64RunThroughWalk can be simplified — but make that an explicit "+
			"decision, since a measurement agreeing with itself is what made 288 wrong.",
			staticRun, walkRun, profile)
	}
	t.Logf("%s: static index %d, walk %d (ratio %.1fx)", profile, staticRun, walkRun,
		float64(walkRun)/float64(staticRun))
}

// longestCounter64Run is the STATIC counterpart, kept only so
// TestStaticIndexUnderCountsTheCounter64Run can show the two disagreeing, and
// so the adjacency property below has a pure function to test.
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

// TestLongestCounter64RunCountsAdjacencyOnly tests the run counter directly,
// because no shipped profile can distinguish it from a total.
//
// cisco_crs_x's Counter64 OIDs are ONE contiguous block, and no other shipped
// profile has more Counter64 OIDs in total than that block is long, so deleting
// the run reset leaves the measurement over the shipped set unchanged.
// Adjacency is the whole point of the figure — the skip loop costs one step per
// CONSECUTIVE Counter64 successor — so it is asserted here on synthetic input
// where the two answers differ.
//
// The OIDs are real ifXTable columns, since snmpTypeTag decides the type and a
// made-up OID would report the wrong one. Precondition-checked, so a change to
// oidTypeTable fails loudly instead of making every row read "not a Counter64".
func TestLongestCounter64RunCountsAdjacencyOnly(t *testing.T) {
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
