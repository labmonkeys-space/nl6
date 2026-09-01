/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Every change that edits shipped resource data commits a LEDGER: a table of what
// it changed, plus a test that reverses the table against today's corpus and
// requires the parent revision's golden digest byte for byte. Each ledger
// reconstructs the corpus at ITS OWN parent, so a ledger must first undo every
// change that landed AFTER it, newest first.
//
// That chaining used to be written by hand at every call site: eleven reversal
// functions invoked from 60 chained call sites across nine files, and adding a
// link meant editing all of them. THE FAILURE MODE IS WHAT MAKES THIS WORTH
// CENTRALISING:
// omitting one wiring produces a digest mismatch in an unrelated ledger whose
// documented remedy is to RE-PIN THE CONSTANT, i.e. to absorb the defect instead
// of reporting it. Four consecutive audits (nl6#576, nl6#590, nl6#591, nl6#590's
// Arista half) paid that tax.
//
// The registry below is the chain, written once. A ledger test asks for the
// corpus at its own parent revision and gets it; adding a link is ONE entry here
// and TestCorpusReversalRegistryCoversEveryLedgerFile fails by NAME if a new
// ledger file forgets to add it.

// corpusHeadRevision is the pseudo-revision naming the working tree, i.e. the
// corpus every reversal starts from. It is the newest entry's restoresFrom.
const corpusHeadRevision = "HEAD"

// corpusOldestRevision is the far end of the chain: the revision nl6#541's data
// edits forked from, and the oldest corpus state any test reconstructs. It reads
// the ledger's own constant rather than respelling the hash.
const corpusOldestRevision = dataEditsParentRevision

// corpusReversal is one link of the chain: everything needed to walk the corpus
// back across one change.
//
// TWO VIEWS, because two golden digests exist and neither can see the other.
// shippedTagDigest hashes (profile, OID, emitted tag) triples and is reversed
// through `values`, a (profile, OID) -> value map. shippedOIDEncodingDigest
// hashes each DISTINCT shipped OID NAME against its BER encoding and is reversed
// through `names`, a list rewrite. A change can move one, the other, or both.
//
// A VIEW MAY BE LEGITIMATELY ABSENT, and that must be distinguishable from a
// missed wiring — which is the whole point of this file. An absent view carries a
// non-empty reason and TestCorpusReversalAbsentViewsAreExplained requires it. An
// absent view is treated as the IDENTITY on that view, so the reason has to say
// why the change moved nothing there.
type corpusReversal struct {
	// name is how a failure names this link, e.g. "nl6#590 Arista arc".
	name string

	// file is the ledger test file that owns the tables and the reversal
	// functions. It is checked against the package directory, so a new ledger
	// that registers nothing fails by name rather than by digest.
	file string

	// restoresFrom is the revision whose corpus this reversal takes as INPUT.
	// For the newest entry that is corpusHeadRevision; for every other it is the
	// previous entry's parent, which is what makes the chain contiguous.
	//
	// It is the revision at which the corpus reached the state this reversal
	// undoes, which is NOT always the commit the change landed in: a branch forks
	// from whatever was on main at the time (often a release or a deps bump), and
	// what matters is that no resource file moved in between.
	restoresFrom string

	// parent is the revision whose corpus this reversal PRODUCES — the revision
	// the owning ledger's golden digests were taken at.
	parent string

	// values reverses the change against a (profile, OID) -> value map, in place.
	// nil means the change moved no tag; valuesAbsentReason must then say why.
	values func(t *testing.T, cur map[[2]string]string)

	// valuesAbsentReason explains a nil values view. Required when values is nil,
	// forbidden otherwise.
	valuesAbsentReason string

	// names reverses the change against the list of distinct shipped OID names
	// collectShippedOIDs gathers, returning the parent's list. nil means the
	// change moved no OID name and no OID-typed value; namesAbsentReason must
	// then say why.
	//
	// EVERY name view takes a *testing.T and is FATAL on disagreement, matching
	// the value views. Four of them used to be t-less pure functions, which meant
	// a rewrite that stopped matching degraded to a silent no-op — the one failure
	// this whole file exists to make impossible.
	names func(t *testing.T, names []string) []string

	// namesAbsentReason explains a nil names view. Required when names is nil,
	// forbidden otherwise.
	namesAbsentReason string
}

// newestFirstReversals is THE CHAIN. Index 0 is the most recent corpus-editing
// change; the last entry is the oldest. The reversals compose in this direction
// only, and TestCorpusReversalChainIsContiguous pins the order by revision so an
// entry inserted in the wrong place fails by name.
//
// To add a link: put the new entry at the TOP, set its restoresFrom to
// corpusHeadRevision and its parent to the revision your golden digests were
// taken at, and set the entry below it to restoresFrom = your parent. Nothing
// else changes — no ledger test has a chain of its own any more.
var newestFirstReversals = []corpusReversal{
	{
		name:         "nl6#590 Arista arc",
		file:         "snmp_shipped_arista_arc_ledger_test.go",
		restoresFrom: corpusHeadRevision,
		parent:       "2e16f91",
		values:       restoreNl6590AristaArc,
		names:        nl6590aristaOIDNamesBeforeAudit,
	},
	{
		name:         "nl6#591 writeMem removal",
		file:         "snmp_shipped_cisco_writeonly_ledger_test.go",
		restoresFrom: "2e16f91",
		parent:       "f47c85d",
		values:       restoreNl6591WriteMem,
		names:        nl6591OIDNamesBeforeWriteMemRemoval,
	},
	{
		name:         "nl6#590 Cisco arc",
		file:         "snmp_shipped_cisco_arc_ledger_test.go",
		restoresFrom: "f47c85d",
		parent:       "5bded6c",
		values:       restoreNl6590CiscoArc,
		names:        nl6590OIDNamesBeforeAudit,
	},
	{
		name:         "nl6#588 AWS PEN re-homing",
		file:         "snmp_shipped_aws_pen_ledger_test.go",
		restoresFrom: "5bded6c",
		parent:       "87c642d",
		values:       nil,
		valuesAbsentReason: "nl6#588 moved ONE OID-typed VALUE (aws_s3_storage's sysObjectID.0) and no " +
			"OID key and no type, so the emitted tag is ASN1_OBJECT_ID before and after and " +
			"shippedTagDigest does not move. Verified by running the package with the data edit " +
			"applied: every tag-digest test and every tag-digest reversal stayed green.",
		names: nl6588OIDNamesBeforeRehome,
	},
	{
		name:         "nl6#576 NVIDIA arc re-homing",
		file:         "snmp_shipped_nvidia_arc_ledger_test.go",
		restoresFrom: "87c642d",
		parent:       "1bca8e8",
		values:       restoreNl6576NvidiaArc,
		names:        nl6576OIDNamesBeforeRehome,
	},
	{
		name:         "nl6#574 / nl6#571 / nl6#569 resource-data defects",
		file:         "snmp_shipped_resource_defect_ledger_test.go",
		restoresFrom: "1bca8e8",
		parent:       "ec4700f",
		values:       restoreNl6574ResourceDefectEntries,
		names:        nl6574OIDNamesBeforeDefectSweep,
	},
	{
		name:         "nl6#570 octet-shadow deletion",
		file:         "snmp_shipped_octet_shadow_ledger_test.go",
		restoresFrom: "ec4700f",
		parent:       "3a69927",
		values:       restoreNl6570OctetEntries,
		names:        nl6570OIDNamesBeforeOctetShadowDeletion,
	},
	{
		name:         "nl6#541 typed-class data edits",
		file:         "snmp_shipped_data_ledger_test.go",
		restoresFrom: "3a69927",
		parent:       corpusOldestRevision,
		values:       restoreNl6541DataEdits,
		names:        nl6541OIDNamesBeforeDataEdits,
	},
}

// reversalIndexFor returns the index of the entry whose reversal lands the corpus
// at target. Unknown targets are fatal: a caller asking for a revision no ledger
// reconstructs is a wiring error, and returning "the whole chain" would answer it
// with a plausible-looking corpus at the wrong revision.
func reversalIndexFor(t *testing.T, target string) int {
	t.Helper()
	for i, r := range newestFirstReversals {
		if r.parent == target {
			return i
		}
	}
	var have []string
	for _, r := range newestFirstReversals {
		have = append(have, r.parent)
	}
	t.Fatalf("no registered corpus reversal restores the corpus to %q; the chain reconstructs %s. "+
		"Either the revision is wrong, or this ledger's link is missing from newestFirstReversals "+
		"in snmp_shipped_corpus_reversals_test.go", target, strings.Join(have, ", "))
	return 0
}

// restoreCorpusValuesTo walks a (profile, OID) -> value map of TODAY's corpus back
// to the corpus at target, applying every registered value-view reversal from the
// newest down to and including the one whose parent is target.
//
// It is in-place, like the reversals it calls, and returns nothing so a caller
// cannot accidentally use a stale copy — nl6#576's reversal RENAMES keys, so a
// merge-back over the old map would leave both spellings in the corpus.
func restoreCorpusValuesTo(t *testing.T, cur map[[2]string]string, target string) {
	t.Helper()
	last := reversalIndexFor(t, target)
	for i := 0; i <= last; i++ {
		r := newestFirstReversals[i]
		if r.values == nil {
			continue
		}
		r.values(t, cur)
	}
}

// restoreCorpusOIDNamesTo walks the list of distinct shipped OID names back to the
// set target shipped, applying every registered name-view reversal from the newest
// down to and including the one whose parent is target.
//
// The returned list is NOT sorted and NOT deduplicated: callers hash it after
// sorting, and multiplicity is load-bearing (a name appended twice hashes twice),
// which is why every reversal that appends is fatal when its name is already
// present.
func restoreCorpusOIDNamesTo(t *testing.T, names []string, target string) []string {
	t.Helper()
	last := reversalIndexFor(t, target)
	out := names
	for i := 0; i <= last; i++ {
		r := newestFirstReversals[i]
		if r.names == nil {
			continue
		}
		out = r.names(t, out)
	}
	return out
}

// appendVanishedOIDNames is the shared body of every name-view reversal whose
// change only DELETED names: put them back.
//
// It is fatal when the list is empty (a ledger that yields no vanished name has
// stopped reversing anything) and fatal when a name is already present (appending
// it would hash it twice and the parent digest could not come back). Both used to
// be unobservable: these were t-less pure functions, so either fault degraded them
// to a silent no-op whose only symptom was a digest mismatch elsewhere.
func appendVanishedOIDNames(t *testing.T, change string, names, vanished []string) []string {
	t.Helper()

	if len(vanished) == 0 {
		t.Fatalf("%s: the ledger yielded no vanished OID names, so its name-view reversal is a "+
			"no-op and every digest it chains into is being reconstructed at the wrong revision",
			change)
	}
	have := make(map[string]struct{}, len(names))
	for _, n := range names {
		have[n] = struct{}{}
	}
	for _, v := range vanished {
		if _, dup := have[v]; dup {
			t.Fatalf("%s: %s is shipped again, so this reversal would add a name the corpus already "+
				"has and the reconstruction is not the parent's set. Either restore the pre-change "+
				"digest or explain the new corpus", change, v)
		}
	}
	return append(append([]string{}, names...), vanished...)
}

// TestCorpusReversalRegistryCoversEveryLedgerFile is the guard that replaces
// care. Every *_ledger_test.go file in the package must contribute EXACTLY ONE
// entry to the chain.
//
// The file set is WALKED, not listed: hard-coding it would be the same
// hand-maintenance this registry removes, and the omission it is meant to catch
// is precisely the one a hand-kept list also forgets. A new ledger that registers
// nothing fails HERE, by name, instead of producing a digest mismatch in an
// unrelated test whose documented remedy is to re-pin the constant.
func TestCorpusReversalRegistryCoversEveryLedgerFile(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	onDisk := map[string]struct{}{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_ledger_test.go") {
			continue
		}
		onDisk[e.Name()] = struct{}{}
	}
	if len(onDisk) == 0 {
		t.Fatal("found no *_ledger_test.go files in the package directory, so this test proves " +
			"nothing; the walk is broken, not the registry")
	}

	registered := map[string]int{}
	for _, r := range newestFirstReversals {
		registered[r.file]++
	}

	for f := range onDisk {
		switch n := registered[f]; {
		case n == 0:
			t.Errorf("%s is a ledger file but contributes no entry to newestFirstReversals in "+
				"snmp_shipped_corpus_reversals_test.go. Every corpus-editing change has to join "+
				"the chain, or every OLDER ledger reconstructs its parent from a corpus this "+
				"change has already moved — and the only symptom is a digest mismatch whose "+
				"documented remedy is to re-pin the constant.", f)
		case n > 1:
			t.Errorf("%s contributes %d entries to newestFirstReversals, want exactly 1: one ledger "+
				"is one link of the chain", f, n)
		}
	}
	for f := range registered {
		if _, ok := onDisk[f]; !ok {
			t.Errorf("newestFirstReversals registers %q, which is not a *_ledger_test.go file in "+
				"this package", f)
		}
	}

	t.Logf("%d ledger files, %d registered reversals", len(onDisk), len(newestFirstReversals))
}

// TestCorpusReversalChainIsContiguous pins the ORDER, which is load-bearing: the
// reversals compose in one direction only, and applying them out of order
// reconstructs a corpus that is neither today's nor any parent's.
//
// Contiguity is the property that makes "apply everything down to my parent"
// sound: each entry's parent must be the next entry's restoresFrom, so the chain
// is a single walk from the working tree to corpusOldestRevision with no gap and
// no revision visited twice. Swapping two adjacent entries breaks it by name.
func TestCorpusReversalChainIsContiguous(t *testing.T) {
	if len(newestFirstReversals) < 2 {
		t.Fatal("the chain has fewer than two links, so ordering proves nothing")
	}

	if got := newestFirstReversals[0].restoresFrom; got != corpusHeadRevision {
		t.Errorf("the newest reversal (%s) starts from %q, want %q: index 0 is the change that has "+
			"nothing newer than it, so it reverses the working tree itself",
			newestFirstReversals[0].name, got, corpusHeadRevision)
	}

	for i := 0; i < len(newestFirstReversals)-1; i++ {
		cur, next := newestFirstReversals[i], newestFirstReversals[i+1]
		if cur.parent != next.restoresFrom {
			t.Errorf("chain breaks between %s and %s: %s restores the corpus to %q but %s expects "+
				"to start from %q. Either an entry is in the wrong place, or a link is missing "+
				"between them.", cur.name, next.name, cur.name, cur.parent, next.name, next.restoresFrom)
		}
	}

	last := newestFirstReversals[len(newestFirstReversals)-1]
	if last.parent != corpusOldestRevision {
		t.Errorf("the oldest reversal (%s) restores the corpus to %q, want %q: nothing in the "+
			"package reconstructs anything older, so the chain has to end there",
			last.name, last.parent, corpusOldestRevision)
	}

	seen := map[string]string{}
	for _, r := range newestFirstReversals {
		for _, rev := range []string{r.restoresFrom, r.parent} {
			if rev == "" {
				t.Errorf("%s leaves a revision blank; both ends of a link are what make the order "+
					"checkable", r.name)
			}
		}
		if prev, dup := seen[r.parent]; dup {
			t.Errorf("%s and %s both restore the corpus to %q; two links cannot land on one "+
				"revision", prev, r.name, r.parent)
		}
		seen[r.parent] = r.name
	}
}

// TestCorpusReversalAbsentViewsAreExplained keeps "absent because it does not
// apply" distinguishable from "absent because someone forgot".
//
// A nil view is treated as the identity by the walkers, so an unexplained nil is
// a silently skipped link — exactly the defect this file exists to stop, wearing
// the costume of a deliberate decision. ONE absence is legitimate today and it was
// verified rather than assumed (PR #599): nl6#588 has no value view because it
// moved one OID-typed VALUE and no tag.
//
// PR #599 also recorded nl6#541 as having no name view. That was true of the FILE,
// not of the change: the reversal existed, spelled inline in
// snmp_oid_roundtrip_test.go as a literal OID appended by hand. It is
// nl6541OIDNamesBeforeDataEdits now, derived from the removal ledger, and the two
// views of that ledger are symmetric again.
//
// A reason on a view that IS present is rejected too: it would be a claim about
// the code that the code contradicts.
func TestCorpusReversalAbsentViewsAreExplained(t *testing.T) {
	const minReason = 40

	for _, r := range newestFirstReversals {
		switch {
		case r.values == nil && strings.TrimSpace(r.valuesAbsentReason) == "":
			t.Errorf("%s has no value-view reversal and no valuesAbsentReason. A nil view is skipped "+
				"silently, so an unexplained one is a missing link: say why shippedTagDigest did "+
				"not move, or wire the reversal in.", r.name)
		case r.values == nil && len(strings.TrimSpace(r.valuesAbsentReason)) < minReason:
			t.Errorf("%s: valuesAbsentReason is %d characters, want at least %d — it has to say why "+
				"the change moved no tag, not merely that it did not", r.name,
				len(strings.TrimSpace(r.valuesAbsentReason)), minReason)
		case r.values != nil && r.valuesAbsentReason != "":
			t.Errorf("%s has a value-view reversal AND a valuesAbsentReason; the reason describes a "+
				"view that is not absent", r.name)
		}

		switch {
		case r.names == nil && strings.TrimSpace(r.namesAbsentReason) == "":
			t.Errorf("%s has no name-view reversal and no namesAbsentReason. A nil view is skipped "+
				"silently, so an unexplained one is a missing link: say why "+
				"shippedOIDEncodingDigest did not move, or wire the reversal in.", r.name)
		case r.names == nil && len(strings.TrimSpace(r.namesAbsentReason)) < minReason:
			t.Errorf("%s: namesAbsentReason is %d characters, want at least %d — it has to say why "+
				"no OID name and no OID-typed value moved", r.name,
				len(strings.TrimSpace(r.namesAbsentReason)), minReason)
		case r.names != nil && r.namesAbsentReason != "":
			t.Errorf("%s has a name-view reversal AND a namesAbsentReason; the reason describes a "+
				"view that is not absent", r.name)
		}
	}
}

// TestCorpusReversalWalkersStopAtTheirTarget pins the walkers themselves, which
// no ledger test can see: every one of them asks for its OWN parent and checks a
// digest, so a walker that applied one link too many or too few would fail those
// tests as an opaque digest mismatch — the failure shape this file exists to
// remove.
//
// It counts invocations through a stand-in chain rather than asserting on the
// corpus, because the property is "how far did it walk", not "what did it
// produce".
func TestCorpusReversalWalkersStopAtTheirTarget(t *testing.T) {
	saved := newestFirstReversals
	t.Cleanup(func() { newestFirstReversals = saved })

	var order []string
	link := func(name, from, to string, withValues, withNames bool) corpusReversal {
		r := corpusReversal{name: name, file: name + "_ledger_test.go", restoresFrom: from, parent: to}
		if withValues {
			r.values = func(*testing.T, map[[2]string]string) { order = append(order, "v:"+name) }
		} else {
			r.valuesAbsentReason = "stand-in"
		}
		if withNames {
			r.names = func(_ *testing.T, n []string) []string {
				order = append(order, "n:"+name)
				return n
			}
		} else {
			r.namesAbsentReason = "stand-in"
		}
		return r
	}
	newestFirstReversals = []corpusReversal{
		link("a", corpusHeadRevision, "r1", true, true),
		link("b", "r1", "r2", false, true),
		link("c", "r2", "r3", true, true),
	}

	for _, tc := range []struct {
		target string
		want   []string
	}{
		{"r1", []string{"v:a"}},
		{"r2", []string{"v:a"}},
		{"r3", []string{"v:a", "v:c"}},
	} {
		order = nil
		restoreCorpusValuesTo(t, map[[2]string]string{}, tc.target)
		if fmt.Sprint(order) != fmt.Sprint(tc.want) {
			t.Errorf("value walk to %s applied %v, want %v", tc.target, order, tc.want)
		}
	}

	for _, tc := range []struct {
		target string
		want   []string
	}{
		{"r1", []string{"n:a"}},
		{"r2", []string{"n:a", "n:b"}},
		{"r3", []string{"n:a", "n:b", "n:c"}},
	} {
		order = nil
		restoreCorpusOIDNamesTo(t, nil, tc.target)
		if fmt.Sprint(order) != fmt.Sprint(tc.want) {
			t.Errorf("name walk to %s applied %v, want %v", tc.target, order, tc.want)
		}
	}
}
