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
// INTERIOR node of its own profile's served tree — that is, another entry in the
// same profile has it as a proper prefix. A table column with no instance is not
// a legal varbind name, so such an entry makes a walk emit a binding named with
// a column OID.
//
// nl6#541 deleted 14 of these (a bare ipRouteDest valued "1"), but it did so
// because the typed-class rule REFUSED them — that column is IpAddress-typed and
// "1" is not an address — not as a sweep of the class. 41 remain, across 6
// profiles, and they are NOT fixed here: bare entPhysicalTable columns, bare
// ifDescr / ifMtu / ifSpeed / ifOperStatus, and a Cisco environment column.
//
// The count is pinned rather than left as prose so the class cannot grow while
// the sweep is pending. Lowering it is always welcome; raising it needs a
// reason.
const bareColumnEntriesShipped = 41

// TestBareColumnCensusHasNotGrown pins the size of an ACKNOWLEDGED gap. It is
// not a fix and does not pretend to be one — the framing this replaces read as
// though bare columns were now impossible, which they are not.
func TestBareColumnCensusHasNotGrown(t *testing.T) {
	byProfile := map[string]map[string]string{} // profile -> oid -> part
	for _, e := range shippedSNMPEntries(t) {
		if byProfile[e.Profile] == nil {
			byProfile[e.Profile] = map[string]string{}
		}
		byProfile[e.Profile][e.OID] = e.Part
	}

	interior := 0
	profiles := map[string]struct{}{}
	for profile, oids := range byProfile {
		for oid, part := range oids {
			for other := range oids {
				if other != oid && strings.HasPrefix(other, oid+".") {
					interior++
					profiles[profile] = struct{}{}
					t.Logf("bare column: %s serves %s, which is a prefix of another entry", part, oid)
					break
				}
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
