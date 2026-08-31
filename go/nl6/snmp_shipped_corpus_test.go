/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The shipped-corpus tests share ONE walk of resources/, because they used to
// have three and two of them could not see a whole supported layout.
//
// A device type ships either as a DIRECTORY of parts (resources/<slug>/*.json,
// the only layout in the tree today) or as a single resources/<slug>.json. Both
// are supported and both are exercised at all four loaders by
// TestGuardIsWiredIntoLoaders. The corpus walkers globbed "resources/*/*.json",
// which is exactly two path segments and therefore blind to the single-file
// layout: a vendor 64-bit column in resources/newvendor.json passed the sentinel
// guard, the tag digest and the Counter64 pin, and the only test that fired told
// the maintainer to re-pin a golden digest — which would have absorbed the
// defect entirely. That is worse than having no guard.
//
// shippedResourceParts is the recursive walk. shippedProfiles is the profile
// list the loader-driven tests use. They cross-check each other: every part
// found by the walk must belong to a profile the enumeration reports, so a
// layout one of them cannot see fails the suite instead of passing quietly.

// shippedResourceParts returns every shipped resource JSON part, at any depth,
// with `_`-prefixed directories excluded (they are not device types).
func shippedResourceParts(t *testing.T) []string {
	t.Helper()

	var parts []string
	err := filepath.Walk("resources", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel("resources", p)
		if relErr != nil {
			return relErr
		}
		if info.IsDir() {
			if rel != "." && strings.HasPrefix(filepath.Base(p), "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(p) == ".json" {
			parts = append(parts, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking resources: %v", err)
	}
	if len(parts) == 0 {
		t.Fatal("no resource parts found — has the layout changed, or is the test not running from go/nl6?")
	}
	sort.Strings(parts)

	// Cross-check: every part must belong to a profile the enumeration reports.
	// This is the assertion that fails when a layout is added that one of the
	// two views cannot see.
	known := make(map[string]struct{})
	for _, p := range shippedProfileNames(t) {
		known[p] = struct{}{}
	}
	for _, p := range parts {
		if _, ok := known[shippedProfileOf(p)]; !ok {
			t.Errorf("resource part %s belongs to profile %q, which the profile enumeration does "+
				"not report. One of the two views of resources/ is blind to a layout the loaders "+
				"support, so a corpus test would pass over it silently", p, shippedProfileOf(p))
		}
	}
	return parts
}

// shippedProfileOf maps a part path to the profile name the loaders use:
// "resources/asr9k/asr9k_snmp_1.json" and "resources/asr9k.json" both give
// "asr9k.json".
func shippedProfileOf(part string) string {
	rel, err := filepath.Rel("resources", part)
	if err != nil {
		return part
	}
	if dir := filepath.Dir(rel); dir != "." {
		// Only the top-level directory names a device type.
		return strings.SplitN(dir, string(filepath.Separator), 2)[0] + ".json"
	}
	return filepath.Base(rel)
}

// shippedProfileNames returns every shipped device-type profile, in BOTH
// layouts, as the "<slug>.json" name LoadSpecificResources takes.
func shippedProfileNames(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir("resources")
	if err != nil {
		t.Fatalf("read resources dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "_") {
			continue
		}
		switch {
		case e.IsDir():
			names = append(names, e.Name()+".json")
		case filepath.Ext(e.Name()) == ".json":
			// The single-file layout. None ship today, but the loaders accept
			// it and a corpus test that cannot see it is a hole, not a saving.
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("no resource profiles found. Is the test running from go/nl6?")
	}
	sort.Strings(names)
	return names
}

// shippedSNMPEntry is one resource entry with the profile it came from, which is
// what makes the tag digest per-profile rather than fleet-wide.
type shippedSNMPEntry struct {
	Profile string // "asr9k.json"
	Part    string // "resources/asr9k/asr9k_snmp_1.json"
	OID     string // normalised, leading dot
	Value   string
}

// shippedSNMPEntries decodes every part and returns its snmp entries.
func shippedSNMPEntries(t *testing.T) []shippedSNMPEntry {
	t.Helper()

	var out []shippedSNMPEntry
	for _, part := range shippedResourceParts(t) {
		raw, err := os.ReadFile(part) // #nosec G304 -- test-only, path from a repo walk
		if err != nil {
			t.Fatalf("read %s: %v", part, err)
		}
		var doc DeviceResources
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: does not decode as a resource file: %v", part, err)
		}
		for _, r := range doc.SNMP {
			out = append(out, shippedSNMPEntry{
				Profile: shippedProfileOf(part),
				Part:    part,
				OID:     normaliseResourceOID(r.OID),
				Value:   r.Response,
			})
		}
	}
	if len(out) == 0 {
		t.Fatal("no shipped SNMP entries collected")
	}
	return out
}

// TestShippedCorpusViewsAgree pins the cross-check itself, so the shared walk
// cannot be quietly narrowed back to a glob. It also asserts that a single-file
// profile dropped into resources/ is SEEN — the exact case the old
// "resources/*/*.json" glob missed — by planting one in a temp copy of the tree.
func TestShippedCorpusViewsAgree(t *testing.T) {
	base := len(shippedResourceParts(t))
	profiles := len(shippedProfileNames(t))
	t.Logf("%d resource parts across %d profiles", base, profiles)

	// A copy of resources/ plus one single-file profile, in a temp cwd.
	tmp := t.TempDir()
	if err := os.CopyFS(filepath.Join(tmp, "resources"), os.DirFS("resources")); err != nil {
		t.Fatalf("copy resources: %v", err)
	}
	planted := filepath.Join(tmp, "resources", "zzsinglefile.json")
	if err := os.WriteFile(planted,
		[]byte(`{"snmp":[{"oid":"1.3.6.1.2.1.1.1.0","response":"planted"}]}`), 0o644); err != nil {
		t.Fatalf("plant single-file profile: %v", err)
	}
	t.Chdir(tmp)

	parts := shippedResourceParts(t)
	if len(parts) != base+1 {
		t.Errorf("walk found %d parts after planting a single-file profile, want %d: the corpus "+
			"walk is blind to resources/<slug>.json, which every loader supports", len(parts), base+1)
	}
	var seen bool
	for _, p := range parts {
		if filepath.Base(p) == "zzsinglefile.json" {
			seen = true
		}
	}
	if !seen {
		t.Error("the planted single-file profile is not in the walk")
	}
	names := shippedProfileNames(t)
	if len(names) != profiles+1 {
		t.Errorf("profile enumeration found %d profiles, want %d", len(names), profiles+1)
	}
	if got := shippedProfileOf(filepath.Join("resources", "zzsinglefile.json")); got != "zzsinglefile.json" {
		t.Errorf("shippedProfileOf = %q, want zzsinglefile.json", got)
	}
}

// TestUnknownTopLevelKeysAreInert pins the convention the PAN profile now relies
// on: the resource decoder is non-strict, so a "_comment" key carries an
// unresolved-question note next to the data it is about without changing what
// loads. The note exists because JSON has no comments and the alternative was
// leaving an escalation only in a commit message (nl6#541 review, R4).
//
// It is a convention worth pinning rather than assuming: if the decoder ever
// becomes strict, this fails and points at the profiles carrying such a key,
// instead of every one of them failing to load with no explanation.
func TestUnknownTopLevelKeysAreInert(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll(filepath.Join("resources", "zzcomment"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const entry = `{"oid":"1.3.6.1.2.1.1.1.0","response":"a device"}`
	if err := os.WriteFile(filepath.Join("resources", "zzcomment", "zzcomment_snmp.json"),
		[]byte(`{"_comment":"an unresolved question about this data","snmp":[`+entry+`]}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("zzcomment.json")
	if err != nil {
		t.Fatalf("a profile carrying a _comment key must load: %v", err)
	}
	if len(res.SNMP) != 1 {
		t.Errorf("loaded %d SNMP entries, want 1: the comment key must not affect the data", len(res.SNMP))
	}

	// And the shipped profile that uses it really does carry one, so this test
	// is about live data rather than a hypothetical.
	found := 0
	for _, part := range shippedResourceParts(t) {
		raw, err := os.ReadFile(part) // #nosec G304 -- test-only, path from a repo walk
		if err != nil {
			t.Fatalf("read %s: %v", part, err)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			continue
		}
		if _, ok := doc["_comment"]; ok {
			found++
		}
	}
	t.Logf("%d shipped parts carry a _comment key", found)
}

// bareColumnEntriesShipped is the number of shipped entries whose OID is an
// INTERIOR node of the served tree — that is, some shipped OID has it as a
// proper prefix, which makes it a table column rather than an instance. A column
// with no instance sub-identifier is not a legal varbind name, so such an entry
// makes a walk emit a binding named with a column OID.
//
// nl6#541 deleted 14 of these (a bare ipRouteDest valued "1"), but only because
// the typed-class rule REFUSED them — that column is IpAddress-typed and "1" is
// not an address — not as a sweep of the class. nl6#571 swept the rest: 61
// entries across 15 distinct OIDs and 13 profiles (bare entPhysicalTable
// columns, bare ifDescr / ifMtu / ifSpeed / ifOperStatus, a Cisco environment
// column, a Juniper jnxOperatingTemp column, a PAN column and a bare
// hrStorageAllocationUnits column), recorded in
// snmp_shipped_resource_defect_ledger_test.go. The class is now CLOSED for the
// shipped set, which is why the number is zero rather than small.
//
// THE SCAN HAD TO BECOME CORPUS-WIDE BEFORE THE SWEEP COULD FIND THEM, AND THAT
// IS THE FIX TO THE GUARD ITSELF. It used to look for an extending sibling in
// the SAME profile only, and reported 41 — the number nl6#571 quotes. 20 further
// entries were bare columns whose instantiated sibling happened to live in a
// DIFFERENT profile: the bare hrStorageAllocationUnits column, a bare Juniper
// jnxOperatingTemp column carried by four CISCO profiles, and a bare PAN column
// carried by twelve NON-PAN profiles. The per-profile scan was structurally
// unable to see any of them, so deleting only the 41 would have driven this
// constant to 0 while 20 bare columns still shipped — a green suite over a
// half-done sweep.
//
// Legality is a property of the OID, not of which profile carries it. The
// per-profile form was simply the wrong question, in the same family as the
// nl6#541 resources/*/*.json glob: a guard whose blind spot is invisible from
// inside the guard. Do not narrow this scan back to one profile.
//
// The four bare hrStorageAllocationUnits entries were nl6#571's Block If — in
// each of those profiles the entry was the ONLY hrStorageTable row of any column,
// so deleting it empties the table rather than removing a duplicate. Decided as
// DELETE: a collector getting nothing is honest about a device type that models
// no storage, while a collector getting a binding named with a column OID is
// handed a name that is not a legal instance. Those profiles model no storage now
// and that is correct — do not restore the row to make the table non-empty.
//
// What this scan still cannot see: a bare column that NOTHING in the corpus
// extends. Without a MIB it is indistinguishable from a scalar.
//
// The count is pinned rather than left as prose so the class cannot re-open.
// Raising it needs a reason.
const bareColumnEntriesShipped = 0

// TestBareColumnCensusHasNotGrown pins the size of an ACKNOWLEDGED gap. It is
// not a fix and does not pretend to be one — the framing this replaces read as
// though bare columns were now impossible, which they are not.
func TestBareColumnCensusHasNotGrown(t *testing.T) {
	all := map[string]struct{}{}
	byProfile := map[[2]string]string{} // (profile, oid) -> part
	for _, e := range shippedSNMPEntries(t) {
		all[e.OID] = struct{}{}
		byProfile[[2]string{e.Profile, e.OID}] = e.Part
	}

	interior := 0
	profiles := map[string]struct{}{}
	for k, part := range byProfile {
		e := shippedSNMPEntry{Profile: k[0], Part: part, OID: k[1]}
		for other := range all {
			if other != e.OID && strings.HasPrefix(other, e.OID+".") {
				interior++
				profiles[e.Profile] = struct{}{}
				t.Logf("bare column: %s serves %s, which is a prefix of another shipped entry",
					e.Part, e.OID)
				break
			}
		}
	}

	if interior > bareColumnEntriesShipped {
		t.Errorf("%d bare-column entries ship, up from the recorded %d, across %d profiles. A "+
			"table column with no instance is not a legal varbind name: a walk emits a binding "+
			"named with a column OID. Give the entry an instance suffix, or delete it",
			interior, bareColumnEntriesShipped, len(profiles))
	}
	if interior < bareColumnEntriesShipped {
		t.Errorf("%d bare-column entries ship, down from the recorded %d — good, but lower "+
			"bareColumnEntriesShipped to %d so the pin keeps its grip",
			interior, bareColumnEntriesShipped, interior)
	}
	t.Logf("%d bare-column entries across %d profiles (recorded: %d)", interior, len(profiles), bareColumnEntriesShipped)
}
