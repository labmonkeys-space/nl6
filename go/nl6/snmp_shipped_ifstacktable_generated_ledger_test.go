/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strconv"
	"testing"
)

// The two generated profiles related their units and VLAN subinterfaces to
// the port beneath them only by name, so an SNMP-only collector had to parse
// ifDescr while gNMI nested each one under its parent. The chassis generators
// now render the ifStackTable: one ifStackStatus.<logical>.<parent> row per
// unit or subinterface, and the RFC 2863 markers 0.<I> for every interface
// nothing runs over and <I>.0 for every interface that runs over nothing, so
// each interface is in at least two rows. This change added those rows and
// nothing else. The OID NAME view is one set over the whole corpus, and
// nokia_7750_sr12 already shipped the same marker names for its own ifIndexes
// 1 to 73 (listed in logicalIfsAddedOIDNames), so the names this change
// introduced to the corpus are the rows below minus that overlap; the value
// view, keyed by profile, reverses every row.
//
// The index lists below are the data: a reader checks them against the model
// (xe-0/0/0 is ifIndex 1 and carries units 73 to 76; HundredGigE0/0/0/8 is 9
// under 55 and 56; Bundle-Ether1 is 51, over members 10 and 11 and under 57,
// so 9, 10, 11 and 51 have no 0.<I> row and 51, 55, 56, 57 no <I>.0 row).

// ifStackTableGeneratedParentRevision is main at branch time; the digests
// below were taken there and are NOT re-derived from the new tree.
const ifStackTableGeneratedParentRevision = "31237b50"

const (
	shippedTagDigestBeforeIfStackTableGenerated         = "ae463d5157810cbb2f78ad0d3a369f5a667e7eefd8cad994bda2fff83a77b1c1"
	shippedOIDEncodingDigestBeforeIfStackTableGenerated = "b954622c4a8acc1307ec9d88a1ca9d0ff43a7be0d81b2fc9b37c01aa6d016d76"
)

// stackRowSet names the ifStackStatus rows one profile gained: 0.<I> for
// each I in tops, <I>.0 for each I in bottoms, and <h>.<l> for each stacked
// pair. Ranges are inclusive.
type stackRowSet struct {
	tops, bottoms [][2]int
	stacked       [][2]int
}

func (s stackRowSet) names() []string {
	var out []string
	for _, r := range s.tops {
		for i := r[0]; i <= r[1]; i++ {
			out = append(out, "1.3.6.1.2.1.31.1.2.1.3.0."+strconv.Itoa(i))
		}
	}
	for _, r := range s.bottoms {
		for i := r[0]; i <= r[1]; i++ {
			out = append(out, "1.3.6.1.2.1.31.1.2.1.3."+strconv.Itoa(i)+".0")
		}
	}
	for _, p := range s.stacked {
		out = append(out, "1.3.6.1.2.1.31.1.2.1.3."+strconv.Itoa(p[0])+"."+strconv.Itoa(p[1]))
	}
	return out
}

func (s stackRowSet) edits() []profileRowEdit {
	var out []profileRowEdit
	for _, n := range s.names() {
		out = append(out, profileRowEdit{op: editAdd, oid: "." + n, after: "1"})
	}
	return out
}

var ifStackTableGeneratedRows = map[string]stackRowSet{
	ciscoAsr9902Profile: {
		tops:    [][2]int{{1, 8}, {12, 50}, {52, 57}},
		bottoms: [][2]int{{1, 50}, {52, 54}},
		stacked: [][2]int{{55, 9}, {56, 9}, {57, 51}},
	},
	juniperMx10004Profile: {
		tops:    [][2]int{{2, 76}},
		bottoms: [][2]int{{1, 72}},
		stacked: [][2]int{{73, 1}, {74, 1}, {75, 1}, {76, 1}},
	},
}

func restoreIfStackTableGenerated(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	for profile, rows := range ifStackTableGeneratedRows {
		reverseProfileEdits(t, cur, profile, "ifStackTable on the generated profiles", rows.edits())
	}
}

// ifStackTableGeneratedNewOIDNames is the rows minus the names the Nokia
// profile already carried, deduplicated across the two profiles.
func ifStackTableGeneratedNewOIDNames() []string {
	already := map[string]bool{}
	for _, n := range logicalIfsAddedOIDNames {
		already[n] = true
	}
	var added []string
	for _, profile := range []string{ciscoAsr9902Profile, juniperMx10004Profile} {
		for _, n := range ifStackTableGeneratedRows[profile].names() {
			if !already[n] {
				already[n] = true
				added = append(added, n)
			}
		}
	}
	return added
}

func ifStackTableGeneratedOIDNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return reverseOIDNameEdits(t, names, "ifStackTable on the generated profiles", ifStackTableGeneratedNewOIDNames(), nil)
}

func TestIfStackTableGeneratedNewNamesExcludeTheNokiaOverlap(t *testing.T) {
	// Nokia serves 74 interfaces with their markers and 73.1 (toWAN over
	// port 1/1/1), so the names the corpus set gains are the ones its table
	// cannot hold: the MX's 0.75, 0.76 and 75.1, 76.1, and the stacked rows
	// of the ASR 9902.
	got := map[string]bool{}
	for _, n := range ifStackTableGeneratedNewOIDNames() {
		got[n] = true
	}
	for _, n := range []string{"1.3.6.1.2.1.31.1.2.1.3.0.2", "1.3.6.1.2.1.31.1.2.1.3.18.0", "1.3.6.1.2.1.31.1.2.1.3.73.1"} {
		if got[n] {
			t.Errorf("%s is listed as new, but nokia_7750_sr12 shipped it before this change", n)
		}
	}
	for _, n := range []string{"1.3.6.1.2.1.31.1.2.1.3.0.75", "1.3.6.1.2.1.31.1.2.1.3.0.76", "1.3.6.1.2.1.31.1.2.1.3.57.51", "1.3.6.1.2.1.31.1.2.1.3.55.9", "1.3.6.1.2.1.31.1.2.1.3.75.1", "1.3.6.1.2.1.31.1.2.1.3.76.1"} {
		if !got[n] {
			t.Errorf("%s is new to the corpus but not listed", n)
		}
	}
}

func TestIfStackTableGeneratedRowCounts(t *testing.T) {
	// 109 rows on the ASR 9902 (57 interfaces, 4 without a top marker, 4
	// without a bottom one, 3 stacked) and 151 on the MX10004 (76
	// interfaces, 1 without a top marker, 4 without a bottom one, 4 stacked).
	for profile, want := range map[string]int{ciscoAsr9902Profile: 109, juniperMx10004Profile: 151} {
		if got := len(ifStackTableGeneratedRows[profile].names()); got != want {
			t.Errorf("%s: %d rows listed, want %d", profile, got, want)
		}
	}
}

func TestIfStackTableGeneratedReproducesTheParentCorpus(t *testing.T) {
	if got := corpusTagDigestAt(t, corpusValuesAt(t, ifStackTableGeneratedParentRevision), ifStackTableGeneratedParentRevision); got != shippedTagDigestBeforeIfStackTableGenerated {
		t.Errorf("reversing the ifStackTable change gives digest %s, want %s: another shipped row changed without being recorded",
			got, shippedTagDigestBeforeIfStackTableGenerated)
	}
}

func TestIfStackTableGeneratedRePinIsOnlyTheEdit(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), ifStackTableGeneratedParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeIfStackTableGenerated {
		t.Errorf("reversing the ifStackTable OID names gives digest %s, want %s", got, shippedOIDEncodingDigestBeforeIfStackTableGenerated)
	}
}
