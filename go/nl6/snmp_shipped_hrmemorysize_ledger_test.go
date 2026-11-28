/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// nl6#1088 serves hrMemorySize.0 (1.3.6.1.2.1.25.2.2.0) from the metric
// engine, as the profile's MemTotalKB clamped to the KBytes range, on the three
// NVIDIA profiles. Their static rows were 1024 times smaller than the host's
// own physical memory (1 GiB and 2 GiB for hosts of 1 TiB and 2 TiB), and once
// the engine owns the OID a row there is dead data, so
// TestNoShippedStaticRowShadowsAMetricOID requires its deletion.
//
// DELETED, NOT CORRECTED, for the reason the nl6#1056 ledger gives: one source
// for physical memory, so hrMemorySize.0 and hrStorageSize.1 cannot drift
// apart again.
//
// Both golden digests move: three (profile, OID, tag) triples go, and no other
// shipped resource or catalog names 1.3.6.1.2.1.25.2.2.0, so the name leaves
// the corpus. TestHrMemorySizeNameLeftTheCorpus measures it.
//
// Every recorded oldValue was read OUT OF GIT at the parent revision with
// `git show <rev>:go/nl6/resources/<type>/<part>`, never retyped from the
// working tree, and TestHrMemorySizeLedgerValuesMatchTheParentRevision pins the
// table against a digest of that read (the nl6#573 lesson). The same procedure
// run at c7e4cb4 gives metricShadowValueDigestAtParent back.

// hrMemorySizeParentRevision is the revision this change was taken from, and
// the one its two golden digests below were taken at.
const hrMemorySizeParentRevision = "0366613"

// The two "before" digests are the values shippedTagDigest and
// shippedOIDEncodingDigest held at the parent, NOT re-derived from the edited
// tree.
const (
	shippedTagDigestBeforeHrMemorySize         = "a91aaf3a4449c844a9d37c39e715e658f9aafef9b9f2486e93c54fabe4bba1c2"
	shippedOIDEncodingDigestBeforeHrMemorySize = "d2f55d095d58498e9e7356846c92e6adc41d4ee6e96c8d3537c9e170f2e42799"
)

// hrMemorySizeDeletedEntries are the three rows this change removed, read out
// of git at the parent.
//
// DO NOT restore any row with a "better" number: the engine serves the OID on
// both paths, and a static row is dead data whatever it holds.
var hrMemorySizeDeletedEntries = []struct{ profile, oid, oldValue string }{
	{"nvidia_dgx_a100.json", hrMemorySizeOID, "1048576"},
	{"nvidia_dgx_h100.json", hrMemorySizeOID, "2097152"},
	{"nvidia_hgx_h200.json", hrMemorySizeOID, "2097152"},
}

// hrMemorySizeValueDigestAtParent is a SHA-256 over the sorted
// "profile\toid\toldValue" lines of the three rows as they existed at the
// parent, computed from `git ls-tree` and `git show` at that revision, never
// from the table above.
const hrMemorySizeValueDigestAtParent = "e7918771e87ee91a89c5a522ace95951455c01a639369f71be86eea880fdd4a9"

// restoreHrMemorySizeRows reverses this change against a (profile, OID) ->
// value map. Fatal on any row that still ships.
func restoreHrMemorySizeRows(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	for _, d := range hrMemorySizeDeletedEntries {
		reverseProfileEdits(t, cur, d.profile, "nl6#1088 hrMemorySize rows",
			[]profileRowEdit{{op: editDel, oid: d.oid, before: d.oldValue}})
	}
}

// hrMemorySizeVanishedOIDNames is the OID name this change removed from the
// corpus entirely, in the undotted spelling collectShippedOIDs gathers.
var hrMemorySizeVanishedOIDNames = []string{strings.TrimPrefix(hrMemorySizeOID, ".")}

// hrMemorySizeOIDNamesBefore is the name-view counterpart of
// restoreHrMemorySizeRows.
func hrMemorySizeOIDNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return appendVanishedOIDNames(t, "nl6#1088 hrMemorySize rows", names, hrMemorySizeVanishedOIDNames)
}

func TestHrMemorySizeDeletionReproducesTheParentCorpus(t *testing.T) {
	got := corpusTagDigestAt(t, corpusValuesAt(t, hrMemorySizeParentRevision), hrMemorySizeParentRevision)
	if got != shippedTagDigestBeforeHrMemorySize {
		t.Errorf("reversing the nl6#1088 deletion gives tag digest %s, want %s: another shipped row "+
			"changed without being recorded", got, shippedTagDigestBeforeHrMemorySize)
	}
}

func TestHrMemorySizeRePinIsOnlyTheDeletion(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), hrMemorySizeParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeHrMemorySize {
		t.Errorf("restoring the nl6#1088 name gives digest %s, want %s: the re-pin is NOT the deletion alone",
			got, shippedOIDEncodingDigestBeforeHrMemorySize)
	}
}

// TestHrMemorySizeLedgerValuesMatchTheParentRevision pins the recorded old
// values against the tree at the parent. If it fails after an edit to the
// table, the table is wrong: the parent revision cannot change.
func TestHrMemorySizeLedgerValuesMatchTheParentRevision(t *testing.T) {
	var lines []string
	for _, d := range hrMemorySizeDeletedEntries {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", d.profile, d.oid, d.oldValue))
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != hrMemorySizeValueDigestAtParent {
		t.Errorf("ledger value digest = %s, want %s (%d rows): the recorded rows no longer match what %s shipped",
			got, hrMemorySizeValueDigestAtParent, len(lines), hrMemorySizeParentRevision)
	}
	if len(hrMemorySizeDeletedEntries) != 3 {
		t.Errorf("nl6#1088 deleted entries: ledger has %d rows, want 3", len(hrMemorySizeDeletedEntries))
	}
}

// TestHrMemorySizeNameLeftTheCorpus makes "the name vanished entirely" a
// measurement.
func TestHrMemorySizeNameLeftTheCorpus(t *testing.T) {
	shipped := map[string]struct{}{}
	for _, o := range collectShippedOIDs(t) {
		shipped[strings.TrimPrefix(o, ".")] = struct{}{}
	}
	for _, o := range hrMemorySizeVanishedOIDNames {
		if _, ok := shipped[o]; ok {
			t.Errorf("%s is named by a shipped resource or catalog again", o)
		}
	}
}
