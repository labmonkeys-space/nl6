/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The served-state digest over the shipped corpus.
//
// WHY THIS EXISTS. Before it, nothing observed the served VALUE of
// ifAdminStatus / ifOperStatus / ifLastChange across the shipped profiles. The
// two digests CLAUDE.md calls "the corpus digests" — shippedTagDigest and
// shippedOIDEncodingDigest — read the RESOURCE FILES: OIDs, declared types,
// emitted tags. These three leaves are served DYNAMICALLY from the interface
// state engine, so no resource-file digest can witness a change to them, and
// nl6#693's acceptance line ("the GET/GETNEXT/GETBULK response digest over the
// shipped corpus SHALL equal the digest taken before this change") named a
// measurement that did not exist.
//
// A test that asserts "nothing changed" by observing nothing passes for the
// wrong reason. This one observes 887 (profile, ifIndex) rows through the
// cycler's own serve path — the same GetDynamic that findResponse delegates to
// for .7/.8/.9 — and pins their concatenation.
//
// ifLastChange is in the tuple deliberately. A digest over the two status
// leaves alone would go green on a build where a masked flap still stamps
// last-change, which is exactly the regression nl6#694's derivation introduces
// the risk of.
//
// WHEN THIS FAILS. The failure prints the differing rows. Re-pinning is the
// right move ONLY for an intended wire change, and the diff is the review
// evidence for it. Re-pinning to silence a failure is how a defect gets
// absorbed — see the same warning on shippedTagDigest.
const shippedServedStateDigest = "182da76a7ef8109cf831a2bcc340031796f857be95906f324534ba07b3ca85b0"

// shippedServedStateDigestBeforeDerivation is the value this digest held on the
// parent revision, captured BEFORE nl6#694's derivation was written — which is
// the only order in which it has any detection power. Kept so the one intended
// wire change this repo has made to these leaves is reversible from the record
// rather than from memory.
//
// The two digests differ in EXACTLY 18 rows, all cisco_nexus_9500, ifIndex
// 33-40 and 51-60, each ifOperStatus moving 1 -> 2. Those rows ship
// ifAdminStatus = down(2) with ifOperStatus = up(1), which RFC 2863 forbids;
// under the derivation the admin value forces oper down. The resource files are
// NOT edited: read as a LINK seed, ifOperStatus = 1 on a shut port means the
// cable is good, so the port returns to up(1) when unshut.
//
// TestServedStateDigestMovedOnlyAtTheNexusRows pins the delta itself, so
// "unchanged except for these 18" is a comparison rather than an assertion.
const shippedServedStateDigestBeforeDerivation = "ac5f07eb914c77bf1a80a5590b59c9eecb771ca3218697e12cd322139ba74dc0"

// servedStateRow is one interface's three state leaves as the agent serves them.
type servedStateRow struct {
	Profile string
	IfIndex int
	Admin   string
	Oper    string
	LastChg string
	// Link is the STORED physical-layer state, read from the engine rather
	// than inferred. The delta test compares it against the served Oper to
	// decide whether a row is masked; inferring it from the expected set
	// instead would make that test compare the corpus with itself.
	Link string
}

func (r servedStateRow) String() string {
	return fmt.Sprintf("%s\t%d\tadmin=%s\toper=%s\tlastChange=%s",
		r.Profile, r.IfIndex, r.Admin, r.Oper, r.LastChg)
}

// shippedServedStateRows builds every device type the repo ships under the
// DEFAULT interface-state scenario and reads the three leaves back per ifIndex.
//
// The scenario is pinned to IfScenarioAllNormal explicitly rather than inherited
// from the process default: the digest is a statement about the DEFAULT fleet,
// and a test that silently picked up another scenario would pin the wrong thing.
func shippedServedStateRows(t *testing.T) []servedStateRow {
	t.Helper()
	withIfScenario(t, IfScenarioAllNormal, 0)

	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	var rows []servedStateRow
	for _, profile := range shippedProfileNames(t) {
		res, err := sm.LoadSpecificResources(profile)
		if err != nil {
			t.Fatalf("load %s: %v", profile, err)
		}
		mc := NewMetricsCycler(0, GetDeviceProfile(""))
		mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
		ic := mc.ifCounters.Load()
		if ic == nil {
			// A profile with no ifXTable .6 keys has no cycler and therefore no
			// state engine. That is legitimate (a storage profile may model no
			// interfaces); record it so the count is visible rather than silently
			// absent.
			rows = append(rows, servedStateRow{Profile: profile, IfIndex: -1,
				Admin: "none", Oper: "none", LastChg: "none"})
			continue
		}
		idx := ic.IfIndices()
		sort.Ints(idx)
		for _, i := range idx {
			rows = append(rows, servedStateRow{
				Profile: profile,
				IfIndex: i,
				Admin:   ic.GetDynamic(fmt.Sprintf("%s.%d", oidIfAdminStatus, i)),
				Oper:    ic.GetDynamic(fmt.Sprintf("%s.%d", oidIfOperStatus, i)),
				LastChg: ic.GetDynamic(fmt.Sprintf("%s.%d", oidIfLastChange, i)),
				Link:    strconv.Itoa(int(ic.State().LinkState(i))),
			})
		}
	}
	if len(rows) == 0 {
		t.Fatal("no served state rows collected. Is the test running from go/nl6?")
	}
	return rows
}

func servedStateDigest(rows []servedStateRow) (string, []string) {
	lines := make([]string, 0, len(rows))
	for _, r := range rows {
		lines = append(lines, r.String())
	}
	sort.Strings(lines)
	sum := sha256.New()
	for _, l := range lines {
		sum.Write([]byte(l))
		sum.Write([]byte{'\n'})
	}
	return hex.EncodeToString(sum.Sum(nil)), lines
}

// TestShippedServedStateDigest pins what every shipped profile serves for the
// three interface-state leaves under the default scenario.
func TestShippedServedStateDigest(t *testing.T) {
	rows := shippedServedStateRows(t)
	got, lines := servedStateDigest(rows)
	if got != shippedServedStateDigest {
		t.Errorf("served-state digest = %s, want %s\n"+
			"%d rows over %d profiles. Re-pin ONLY for an intended wire change, and say which rows moved and why.\n"+
			"First 5 rows:\n  %s",
			got, shippedServedStateDigest, len(rows), len(shippedProfileNames(t)),
			strings.Join(lines[:min(5, len(lines))], "\n  "))
	}
}

// TestShippedCorpusHasNoAdminDownOperUp is the DEFECT-shaped counterpart to the
// digest, so re-pinning is never the only route out (the shippedTagDigest
// lesson: a guard whose documented remedy is "re-pin" destroys its own
// evidence).
//
// It asserts the RFC 2863 invariant on SERVED values: ifAdminStatus = down(2)
// with ifOperStatus = up(1) is a state the MIB does not allow.
//
// It is EXPECTED TO FAIL on the parent revision — 18 cisco_nexus_9500
// interfaces ship exactly that pair and the pre-derivation engine serves it
// verbatim. That failure is the measurement nl6#694 was filed on, reproduced as
// a test. It passes once oper is derived.
func TestShippedCorpusHasNoAdminDownOperUp(t *testing.T) {
	var bad []string
	for _, r := range shippedServedStateRows(t) {
		if r.Admin == "2" && r.Oper == "1" {
			bad = append(bad, r.String())
		}
	}
	if len(bad) != 0 {
		t.Errorf("%d served interfaces report ifAdminStatus=down(2) with ifOperStatus=up(1), "+
			"which RFC 2863 does not allow (ifOperStatus: \"If ifAdminStatus is down(2) then "+
			"ifOperStatus should be down(2)\"):\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}
}

// nexusMaskedRows names every (profile, ifIndex) whose SHIPPED JSON pairs
// ifAdminStatus = down(2) with ifOperStatus = up(1). These are the rows — and
// under this change the ONLY rows — whose served ifOperStatus moved, from 1 to
// 2.
//
// The list is written out rather than derived so the test states a claim a
// reviewer can check against the JSON, instead of comparing the corpus with
// itself and passing whatever it finds.
var nexusMaskedRows = map[string][]int{
	"cisco_nexus_9500.json": {33, 34, 35, 36, 37, 38, 39, 40, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60},
}

// TestServedStateDigestMovedOnlyAtTheNexusRows is the delta half of the digest:
// it pins WHICH rows the derivation moved and WHY, so "unchanged except for
// these 18" is a checkable statement rather than a claim resting on a hash
// nobody can decompose.
//
// The reasoning it enforces, per (profile, ifIndex):
//
//   - the JSON declares ifAdminStatus = 2 and ifOperStatus = 1 (the RFC 2863
//     violation the corpus shipped);
//   - the engine seeds link = 1 from that oper row and admin = 2;
//   - the derivation therefore serves oper = 2 while the link stays up, so
//     unshutting the port returns it to 1 with no further mutation.
//
// Every OTHER served interface must have oper == link, i.e. the derivation is
// the identity on it, which is what makes the rest of the corpus byte-identical.
func TestServedStateDigestMovedOnlyAtTheNexusRows(t *testing.T) {
	// The JSON pairs, read straight from the resource files.
	jsonPairs := map[string]map[int][2]string{} // profile -> ifIndex -> (admin, oper)
	for _, e := range shippedSNMPEntries(t) {
		var leaf string
		switch {
		case strings.HasPrefix(e.OID, oidIfAdminStatus+"."):
			leaf = "admin"
		case strings.HasPrefix(e.OID, oidIfOperStatus+"."):
			leaf = "oper"
		default:
			continue
		}
		idx, err := strconv.Atoi(strings.TrimPrefix(e.OID, strings.TrimSuffix(e.OID, ".")+"."))
		if err != nil {
			// Recompute the instance suffix robustly rather than by trimming.
			parts := strings.Split(e.OID, ".")
			idx, err = strconv.Atoi(parts[len(parts)-1])
			if err != nil {
				continue
			}
		}
		if jsonPairs[e.Profile] == nil {
			jsonPairs[e.Profile] = map[int][2]string{}
		}
		p := jsonPairs[e.Profile][idx]
		if leaf == "admin" {
			p[0] = e.Value
		} else {
			p[1] = e.Value
		}
		jsonPairs[e.Profile][idx] = p
	}

	// Every interface whose JSON violates RFC 2863 must be in the expected set.
	got := map[string][]int{}
	for profile, byIdx := range jsonPairs {
		for idx, p := range byIdx {
			if p[0] == "2" && p[1] == "1" {
				got[profile] = append(got[profile], idx)
			}
		}
	}
	for profile := range got {
		sort.Ints(got[profile])
	}
	if !reflect.DeepEqual(got, nexusMaskedRows) {
		t.Errorf("shipped admin-down/oper-up rows = %v, want %v.\n"+
			"A new row here is a NEW corpus defect, not a reason to extend the list: "+
			"the derivation will mask it, which hides the bad data rather than fixing it.",
			got, nexusMaskedRows)
	}

	// Served: exactly those rows have oper != link; everywhere else the
	// derivation is the identity.
	for _, r := range shippedServedStateRows(t) {
		if r.IfIndex < 0 {
			continue
		}
		expectMasked := containsInt(nexusMaskedRows[r.Profile], r.IfIndex)
		masked := r.Oper != r.Link
		if masked != expectMasked {
			t.Errorf("%s ifIndex %d: masked=%v, want %v (admin=%s oper=%s)",
				r.Profile, r.IfIndex, masked, expectMasked, r.Admin, r.Oper)
		}
		if expectMasked && r.Oper != "2" {
			t.Errorf("%s ifIndex %d: served oper=%s, want 2 (admin-down forces it)",
				r.Profile, r.IfIndex, r.Oper)
		}
	}
}
