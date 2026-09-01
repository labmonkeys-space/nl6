/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
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
	// THE REAL CORPUS IS COUNTED FIRST, BEFORE THE t.Chdir BELOW. It used to be
	// counted after, so the walk ran against the temp directory holding only the
	// synthetic fixture and the test logged "1 shipped parts carry a _comment
	// key" no matter what the corpus held — while CLAUDE.md cited that number as
	// the corpus census. A log line that reads the same on every tree is not
	// evidence (nl6#588 review, P5).
	shippedWithComment := countShippedPartsWithComment(t)

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

	// And the shipped profiles that use it really do carry one, so this test is
	// about live data rather than a hypothetical. The count came from the REAL
	// corpus above; it is asserted rather than only logged, because CLAUDE.md
	// quotes it.
	const wantShippedComments = 7
	if shippedWithComment != wantShippedComments {
		t.Errorf("%d shipped parts carry a _comment key, want %d (the _snmp_gpu and _snmp_system "+
			"parts of the three nvidia_* profiles from nl6#576, plus aws_s3_storage from nl6#588). "+
			"CLAUDE.md quotes this number, so move them together",
			shippedWithComment, wantShippedComments)
	}
	t.Logf("%d shipped parts carry a _comment key", shippedWithComment)
}

// countShippedPartsWithComment counts the real corpus's _comment keys. It is a
// helper so the count is taken BEFORE its caller changes directory — the whole
// point of nl6#588's P5 fix.
func countShippedPartsWithComment(t *testing.T) int {
	t.Helper()

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
	return found
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

// ── the shared bare-column detector, and the control that keeps it honest ───
//
// Both guards for this class — the JSON census below and the serve-path walk in
// TestNoShippedWalkEmitsABareColumnOID — go through bareColumnsAcrossProfiles and
// bareColumnCountViolation, and both begin by calling
// assertBareColumnDetectionIsCorpusWide. That is not tidiness. The fourth review
// layer of nl6#571 demonstrated that each guard could be narrowed back to a
// per-profile scan, with a real cross-profile bare column planted, and BOTH would
// pass reporting zero — reintroducing precisely the regression nl6#571 exists to
// fix, with a green suite, because a narrowing changes no shipped byte and
// therefore moves no digest and no ledger.
//
// The old controls could not catch it: the census had none at all, and the walk
// test's exercised the detector on a set holding a column and its instance
// TOGETHER, which a per-profile scan still finds. The control below is
// CROSS-PROFILE by construction — the column in profile A, its instance in
// profile B — so a narrowed detector fails it.

// bareColumnsAcrossProfiles returns every (profile, OID) pair whose OID is an
// INTERIOR node of the corpus-wide served set: some OID served by ANY profile has
// it as a proper prefix. The value is the extending OID, for the message.
//
// The union is taken across profiles deliberately and must stay that way.
// Legality is a property of the OID, not of which profile carries it: 20 of the 61
// entries nl6#571 deleted were bare columns whose only instantiated sibling lived
// in a different profile.
//
// WHAT IT CANNOT DECIDE, and this bit on first use (nl6#571 review R1). The test
// is "something extends it", which is a heuristic for "it is a column", and the
// heuristic inverts when the EXTENDING sibling is the malformed one. At
// ciscoImageString (1.3.6.1.4.1.9.9.25.1.1.1.2) all four Cisco profiles shipped
// .2.2 AND .2.2.1; ciscoImageEntry's INDEX is a single sub-identifier, so .2.2 is
// the LEGAL instance and .2.2.1 is over-specified — and this function reported
// .2.2, the legal one. Telling the two apart needs the table's INDEX arity, which
// means a MIB; nothing here has one. So a hit is a candidate to be checked against
// the MIB, never a verdict, and the corresponding ledger table records the arity
// finding per row (nl6571DeletedOverSpecifiedInstances).
func bareColumnsAcrossProfiles(perProfile map[string]map[string]struct{}) map[[2]string]string {
	union := map[string]struct{}{}
	for _, oids := range perProfile {
		for oid := range oids {
			union[oid] = struct{}{}
		}
	}
	// Walk each OID's own prefixes rather than comparing pairwise: at 42k OIDs
	// that is the difference between instant and 1.8e9 comparisons.
	columns := map[string]string{} // column -> an OID that extends it
	for oid := range union {
		for i := len(oid) - 1; i > 0; i-- {
			if oid[i] != '.' {
				continue
			}
			if _, ok := union[oid[:i]]; ok {
				columns[oid[:i]] = oid
			}
		}
	}
	out := map[[2]string]string{}
	for profile, oids := range perProfile {
		for oid := range oids {
			if ext, ok := columns[oid]; ok {
				out[[2]string{profile, oid}] = ext
			}
		}
	}
	return out
}

// bareColumnCountViolation is the comparison both guards make, as a pure
// function returning "" when the count is on census. It is a function so the
// control can require it to REPORT a violation, which an inline `if` cannot be
// asked to do.
func bareColumnCountViolation(got, want int) string {
	switch {
	case got > want:
		return fmt.Sprintf("%d bare-column entries ship, up from the recorded %d. A table column "+
			"with no instance sub-identifier is not a legal varbind name: a walk emits a binding "+
			"named with a column OID. Give the entry an instance suffix, or delete it — but check "+
			"the table's INDEX arity first, because the detector cannot tell a column from a legal "+
			"instance with an over-specified sibling", got, want)
	case got < want:
		return fmt.Sprintf("%d bare-column entries ship, down from the recorded %d — good, but "+
			"lower bareColumnEntriesShipped to %d so the pin keeps its grip", got, want, got)
	}
	return ""
}

// crossProfileBareColumnFixture is the shared positive control input: profile A
// serves the bare hrStorageAllocationUnits column, profile B serves an instance of
// it, and nobody serves both. A per-profile scan sees no bare column here; a
// corpus-wide one sees exactly the pair in profile A.
func crossProfileBareColumnFixture() map[string]map[string]struct{} {
	return map[string]map[string]struct{}{
		"zzprofile_a.json": {
			".1.3.6.1.2.1.25.2.3.1.4": {}, // the column, with no instance
			".1.3.6.1.2.1.1.1.0":      {}, // an ordinary leaf, must not be reported
		},
		"zzprofile_b.json": {
			".1.3.6.1.2.1.25.2.3.1.4.1": {}, // its instance, in ANOTHER profile
		},
	}
}

// assertBareColumnDetectionIsCorpusWide is the control every guard for this class
// runs first. It fails on the two mutations that would otherwise pass silently: a
// detector narrowed to one profile, and a comparison that no longer reports.
func assertBareColumnDetectionIsCorpusWide(t *testing.T) {
	t.Helper()

	found := bareColumnsAcrossProfiles(crossProfileBareColumnFixture())
	want := [2]string{"zzprofile_a.json", ".1.3.6.1.2.1.25.2.3.1.4"}
	if len(found) != 1 {
		t.Fatalf("the control fixture plants ONE bare column, in a different profile from its "+
			"instance, and the detector reported %d: %v.\nIf it reported none, the scan has been "+
			"narrowed to a single profile — which is exactly the blind spot nl6#571 was filed for, "+
			"and it makes the zero this test asserts meaningless. Keep the union corpus-wide.", len(found), found)
	}
	if _, ok := found[want]; !ok {
		t.Fatalf("the control found %v, want the planted column %v", found, want)
	}

	// A column and its instance in the SAME profile must still be found, or a
	// "fix" that only looked across profiles would pass the check above.
	same := bareColumnsAcrossProfiles(map[string]map[string]struct{}{
		"zzprofile_a.json": {
			".1.3.6.1.2.1.25.2.3.1.4":   {},
			".1.3.6.1.2.1.25.2.3.1.4.1": {},
		},
	})
	if len(same) != 1 {
		t.Fatalf("a bare column and its instance in ONE profile must still be detected, got %v", same)
	}

	// And the comparison must still speak up. Asserted by requiring a message,
	// so disabling the condition inside bareColumnCountViolation fails here
	// rather than silently making every zero-assertion vacuous.
	if bareColumnCountViolation(1, 0) == "" {
		t.Fatal("bareColumnCountViolation(1, 0) reports nothing: the comparison behind every " +
			"bare-column assertion has stopped working, so those assertions cannot fail")
	}
	if bareColumnCountViolation(0, 1) == "" {
		t.Fatal("bareColumnCountViolation(0, 1) reports nothing: a census that has become stale " +
			"low would no longer be reported")
	}
	if msg := bareColumnCountViolation(0, 0); msg != "" {
		t.Fatalf("bareColumnCountViolation(0, 0) reported %q, so the guard would fail on a clean "+
			"corpus", msg)
	}
}

// TestBareColumnCensusHasNotGrown is the JSON-side guard: it says what the corpus
// CONTAINS. TestNoShippedWalkEmitsABareColumnOID is the serve-path side and says
// what a walk EMITS. Two independent guards over one shared detector, so
// disabling one still leaves a real defect reported by the other.
func TestBareColumnCensusHasNotGrown(t *testing.T) {
	assertBareColumnDetectionIsCorpusWide(t)

	perProfile := map[string]map[string]struct{}{}
	part := map[[2]string]string{}
	for _, e := range shippedSNMPEntries(t) {
		if perProfile[e.Profile] == nil {
			perProfile[e.Profile] = map[string]struct{}{}
		}
		perProfile[e.Profile][e.OID] = struct{}{}
		part[[2]string{e.Profile, e.OID}] = e.Part
	}

	found := bareColumnsAcrossProfiles(perProfile)
	profiles := map[string]struct{}{}
	for k, ext := range found {
		profiles[k[0]] = struct{}{}
		t.Logf("bare column: %s serves %s, which %s extends", part[k], k[1], ext)
	}
	if msg := bareColumnCountViolation(len(found), bareColumnEntriesShipped); msg != "" {
		t.Errorf("%s (across %d profiles)", msg, len(profiles))
	}
	t.Logf("%d bare-column entries across %d profiles (recorded: %d)",
		len(found), len(profiles), bareColumnEntriesShipped)
}
