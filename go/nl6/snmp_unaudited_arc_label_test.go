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

// nl6#590. EVERY VENDOR ARC IS AUDITED, LABELLED, OR EXPLICITLY EXCLUDED.
//
// nl6#588's guard (TestEveryProfileServesOnlyItsOwnVendorArc) checks the NUMBER
// directly below 1.3.6.1.4.1 and stops there. Everything under that number is a
// separate question, and five arcs have now been read against a vendor MIB to
// answer it. The miss rate, counting distinct OIDs, was Palo Alto 8 of 11, Cisco
// 11 of 13, Arista 6 of 6, Ciena 0 of 1 and Juniper 13 of 15.
//
// nl6#590's scope measurement then found that of the arcs the corpus serves, only
// four have ANY consumer in this repository. No polling rule in pollaris.mdx, no
// trap varbind, no doc keys on the rest, and all four are audited. So the
// remaining fourteen were closed BY DECISION rather than by audit: each carries a
// _comment saying, in the file a reader opens, that nobody has checked the objects
// under its PEN.
//
// THIS TEST IS THE DURABLE HALF OF THAT DECISION. A label is a statement about
// today's corpus and nothing stops the corpus regrowing the problem, which is how
// it got here: a new device type may ship a vendor subtree, pass every existing
// guard, and imply a fidelity nobody checked. The rule below refuses that. For
// each (profile, PEN) pair the dual-position scan reports, EXACTLY ONE of three
// must hold:
//
//  1. the PEN is in auditedArcPENs, whose every row names the reading test that
//     covers it (and TestUnauditedArcRegistriesAreCurated requires that test to
//     EXIST in the package, so the citation is checkable rather than prose);
//  2. every part of that profile carrying an entry under that PEN marks it
//     unaudited;
//  3. the pair is in excludedArcPairs with a written reason.
//
// A profile that does none of the three fails BY NAME.
//
// FOUR THINGS ARE LOAD-BEARING.
//
//  1. THE MARKER IS A SENTINEL, NOT PROSE, AND IT CARRIES THE PEN. It is
//     "UNAUDITED-ARC(<pen>)" inside the part's _comment. Prose matching would make
//     the guard fail on a rewording and pass on a label that says nothing, and a
//     PEN-less marker would let a profile that gained a SECOND arc inherit the
//     first one's label silently. Binding the sentinel to the number means a
//     labelled 2620 does not excuse an unlabelled 1234 in the same file. The
//     spelling is a constant here and is what a `git grep` finds.
//
//  2. IT IS PER PART, NOT PER PROFILE. Five of the fourteen carry their arc in TWO
//     parts, and in each case the second part holds one vendor serial-number
//     object among a page of standard MIB rows. A per-profile marker would leave
//     that file looking checked. The label's whole value is that a reader who
//     opens the file sees it.
//
//  3. IT RUNS THE SAME SCAN AS THE PEN GUARD. scanArcPositions reads OID NAMES and
//     OID-TYPED VALUES, and the value half is the one vendor detection reads. A
//     second walk here would be a second place for that half to go missing, which
//     is the nl6#587/#588 blind spot exactly.
//
//  4. THE POSITIVE CONTROL PLANTS BOTH ARMS. A test asserting ZERO of something
//     cannot fail on its own. The control plants a synthetic profile serving an
//     UNLABELLED arc and requires it reported, and a second one serving a LABELLED
//     arc and requires it silent. A rule that reported every arc it saw would pass
//     the first arm alone, so the second arm is what makes the first one mean
//     something.
//
// WHAT IT DOES NOT DO: it does not check that a label is TRUE, and it cannot. A
// label is a claim that nobody read a MIB, and no test can read a MIB. Nor does it
// bound the trap and syslog catalogs, which are excluded from the scan for the
// same reason the corpus walkers exclude them.

// unauditedArcMarkerOpen is the sentinel's stable prefix. The full marker is
// unauditedArcSentinel(pen); the open form is what a stale-label scan looks for
// when it does not yet know which PEN a part claims.
const unauditedArcMarkerOpen = "UNAUDITED-ARC("

// unauditedArcSentinel is the exact substring a part's _comment must contain to
// mark one PEN unaudited.
func unauditedArcSentinel(pen string) string { return unauditedArcMarkerOpen + pen + ")" }

// auditedArc is one row of the audited set: a PEN somebody read a MIB for, and
// the test that records the reading.
type auditedArc struct {
	readingTest string // must exist in this package
	note        string
}

// auditedArcPENs is the first of the three dispositions: arcs that were audited
// against a vendor MIB, each naming the test that pins the reading.
//
// Every readingTest is required to EXIST by TestUnauditedArcRegistriesAreCurated.
// A citation nothing checks is how trap_catalog.go's validateDottedOID drifted
// from the encoder (nl6#539), and a renamed test would otherwise leave this map
// pointing at nothing while still excusing the arc.
var auditedArcPENs = map[string]auditedArc{
	"25461": {"TestPaloAltoPANSubtreeMatchesTheMIB",
		"nl6#569, the first audit. 8 of 11 distinct OIDs wrong: 5 answered a value of the wrong kind and 3 were not valid OIDs at all"},
	"9": {"TestCiscoEnvMonAndMemoryPoolMatchTheMIB",
		"nl6#590's first arc. 11 of 13 ciscoMgmt OIDs wrong. Seven OLD-CISCO OIDs remain unread and are recorded per OID in docs/reference/snmp.md rather than here, because a partial audit is still an audit for the purpose of this rule"},
	"30065": {"TestAristaArcMatchesTheMIB",
		"nl6#590's second arc and the worst result: 6 of 6 facts wrong. The profile now serves no OID name under its own PEN"},
	"1271": {"TestCienaArcMatchesTheMIB",
		"nl6#601, and the only audit that found nothing wrong: 0 of 1. It is why the corpus reads as SPLIT rather than as uniformly fabricated"},
	"2636": {"TestJuniperArcMatchesTheMIB",
		"nl6#602, 13 of 15 distinct OIDs wrong, and the source of the wrong-platform-inside-the-right-vendor subclass"},
	"5703": {"TestEveryNvidiaGPUOIDIsAnsweredAtTheNewArc",
		"NVIDIA is accounted for by a STRONGER statement than an audit, which is why it is here rather than in the labelled set: NVIDIA publishes no SNMP GPU MIB at all, so nl6#576/#587 recorded in the two _comments of each nvidia_* profile that every object below the PEN is nl6's own invention and unresolvable against any published module. There is nothing to audit it against, so an UNAUDITED-ARC label would understate what is known"},
}

// arcExclusion is one (profile, PEN) pair that is neither audited nor labelled,
// with the reason it is neither.
//
// scanVisible records whether the dual-position scan actually reports the pair.
// It is checked BOTH ways by TestUnauditedArcRegistriesAreCurated: a visible
// exclusion the scan does not report is stale, and an invisible one it DOES report
// means the position became visible and the row needs revisiting. Without it a
// row could sit here forever describing nothing.
type arcExclusion struct {
	reason      string
	scanVisible bool
}

// excludedArcPairs is the third disposition, and it is deliberately per PAIR
// rather than per PEN: an exclusion is a judgement about one profile serving one
// number, and a PEN-wide exclusion would let a second profile inherit it.
var excludedArcPairs = map[[2]string]arcExclusion{
	{"aws_s3_storage.json", "32473"}: {
		reason: "32473 is RFC 5612's Example Enterprise Number for Documentation Use, held by IANA. " +
			"nl6#588 chose it deliberately over Amazon's real numbers because this profile models a " +
			"CATEGORY with no manufacturer, and the choice is already documented in that profile's own " +
			"_comment and in docs/reference/snmp.md. There is no vendor MIB to audit it against and no " +
			"vendor claim to label as unchecked",
		scanVisible: true,
	},

	// PEN 0 is the entPhysicalVendorType placeholder, 208 responses across these
	// four profiles. It is NOT a vendor subtree: PEN 0 is Reserved in the registry,
	// held by IANA, so a collector reading one of these resolves nothing at all.
	// Already recorded as known-synthetic by nl6#588 and pinned by count in
	// entPhysicalVendorTypePlaceholders.
	//
	// scanVisible is FALSE on all four and that is the interesting half: oidTypeTable
	// does not type entPhysicalVendorType, so the production predicate this scan
	// shares with the wire reads those responses as OCTET STRINGs and skips them.
	// They are covered instead by assertEntPhysicalVendorTypeIsNotCrossVendor. If
	// oidTypeTable ever gains that row these four flip to visible, this test says so,
	// and the disposition has to be decided again rather than inherited.
	{"cisco_catalyst_9500.json", "0"}: {reason: entPhysicalVendorTypeExclusionReason},
	{"cisco_nexus_9500.json", "0"}:    {reason: entPhysicalVendorTypeExclusionReason},
	{"juniper_mx960.json", "0"}:       {reason: entPhysicalVendorTypeExclusionReason},
	{"palo_alto_pa3220.json", "0"}:    {reason: entPhysicalVendorTypeExclusionReason},
}

const entPhysicalVendorTypeExclusionReason = "the 1.3.6.1.4.1.0.0 entPhysicalVendorType placeholder. " +
	"PEN 0 is Reserved in the IANA registry and held by IANA, so this is not a vendor subtree and there " +
	"is no vendor MIB it could be audited against. Recorded as known-synthetic by nl6#588 and pinned by " +
	"count in entPhysicalVendorTypePlaceholders"

// ── the census, so the zero this test asserts cannot go vacuous ──────────────

// The corpus totals, RE-DERIVED by the test on every run. They are pinned because
// a rule that finds nothing to classify reports no violations either, and because
// the parts figure is the one a reader is most likely to get wrong: fourteen
// PROFILES carry an unaudited arc, but they carry it in NINETEEN parts.
const (
	unauditedArcLabelledPairs = 14
	unauditedArcLabelledParts = 19
	auditedArcPairsShipped    = 13
	excludedArcPairsShipped   = 1 // the scan-visible ones; the four PEN-0 rows are not scan-visible
)

// arcPairParts groups the scan's hits into (profile, PEN) -> the parts carrying
// them. It is the input shape of the rule, so the positive control can build one
// by hand without touching the filesystem twice.
func arcPairParts(hits []arcHit) map[[2]string][]string {
	seen := map[[2]string]map[string]struct{}{}
	for _, h := range hits {
		pen, ok := arcPENOf(normaliseOIDKey(h.text))
		if !ok {
			pen = penUnparseable
		}
		key := [2]string{h.profile, pen}
		if seen[key] == nil {
			seen[key] = map[string]struct{}{}
		}
		seen[key][h.part] = struct{}{}
	}
	out := map[[2]string][]string{}
	for key, parts := range seen {
		for p := range parts {
			out[key] = append(out[key], p)
		}
		sort.Strings(out[key])
	}
	return out
}

// partUnauditedMarks reads every resource part's _comment and returns, per part,
// the set of PENs it marks unaudited.
//
// It parses into map[string]json.RawMessage rather than DeviceResources for the
// reason TestUnknownTopLevelKeysAreInert exists: _comment is an unknown key the
// production decoder ignores, so the typed struct cannot see it at all.
func partUnauditedMarks(t *testing.T) map[string]map[string]bool {
	t.Helper()

	out := map[string]map[string]bool{}
	for _, part := range shippedResourceParts(t) {
		raw, err := os.ReadFile(part) // #nosec G304 -- test-only, path from a repo walk
		if err != nil {
			t.Fatalf("read %s: %v", part, err)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			continue
		}
		comment, ok := doc["_comment"]
		if !ok {
			continue
		}
		var text string
		if err := json.Unmarshal(comment, &text); err != nil {
			t.Errorf("%s: _comment is not a string: %v", part, err)
			continue
		}
		for _, pen := range unauditedArcMarksIn(text) {
			if out[part] == nil {
				out[part] = map[string]bool{}
			}
			out[part][pen] = true
		}
	}
	return out
}

// unauditedArcMarksIn extracts every PEN a comment marks unaudited. It is a pure
// function so the sentinel's parse is testable without a filesystem, and because
// a comment may in principle mark two arcs.
func unauditedArcMarksIn(comment string) []string {
	var pens []string
	rest := comment
	for {
		i := strings.Index(rest, unauditedArcMarkerOpen)
		if i < 0 {
			return pens
		}
		rest = rest[i+len(unauditedArcMarkerOpen):]
		j := strings.Index(rest, ")")
		if j < 0 {
			return pens
		}
		if pen := rest[:j]; pen != "" {
			pens = append(pens, pen)
		}
		rest = rest[j+1:]
	}
}

// arcLabelFinding is one (profile, PEN) pair that is not cleanly in exactly one
// of the three dispositions.
type arcLabelFinding struct {
	profile string
	pen     string
	kind    string // "unaccounted" | "double-classified" | "partially-labelled"
	detail  string
}

// arcLabelFindings is THE RULE, as a pure function over the scan's output, so the
// positive control can require it to REPORT rather than only to stay silent. An
// inline `if` inside the corpus test could not be asked to do that, which is the
// lesson bareColumnCountViolation records.
func arcLabelFindings(
	pairs map[[2]string][]string,
	marks map[string]map[string]bool,
	audited map[string]auditedArc,
	excluded map[[2]string]arcExclusion,
) []arcLabelFinding {
	var out []arcLabelFinding
	for key, parts := range pairs {
		profile, pen := key[0], key[1]

		labelled, unlabelled := 0, []string{}
		for _, p := range parts {
			if marks[p][pen] {
				labelled++
			} else {
				unlabelled = append(unlabelled, p)
			}
		}

		var classes []string
		if _, ok := audited[pen]; ok {
			classes = append(classes, "audited")
		}
		if labelled == len(parts) {
			classes = append(classes, "labelled")
		}
		if _, ok := excluded[key]; ok {
			classes = append(classes, "excluded")
		}

		switch {
		case len(classes) == 0:
			detail := fmt.Sprintf("no reading test claims PEN %s, no exclusion covers this pair, and "+
				"%d of %d parts carry the marker: %s", pen, labelled, len(parts), strings.Join(unlabelled, ", "))
			out = append(out, arcLabelFinding{profile, pen, "unaccounted", detail})
		case len(classes) > 1:
			out = append(out, arcLabelFinding{profile, pen, "double-classified",
				fmt.Sprintf("classified %s at once", strings.Join(classes, " and "))})
		case labelled > 0 && labelled < len(parts):
			// Reachable only alongside "audited" or "excluded", since a partial
			// label is not the "labelled" class. Still a defect: it means somebody
			// started labelling an arc that is already accounted for another way.
			out = append(out, arcLabelFinding{profile, pen, "partially-labelled",
				fmt.Sprintf("%d of %d parts marked; unmarked: %s",
					labelled, len(parts), strings.Join(unlabelled, ", "))})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].profile != out[j].profile {
			return out[i].profile < out[j].profile
		}
		return out[i].pen < out[j].pen
	})
	return out
}

// unlabelledArcPlants are the positive control's two synthetic profiles. BOTH arms
// matter: the first proves the rule reports, the second proves it is not simply
// reporting every arc it sees.
//
// The PENs are 99998 and 99999, which no shipped profile uses and which IANA has
// not allocated to anybody in the checked-in extract, so neither plant can
// accidentally match a real disposition.
func unlabelledArcPlants() []struct{ dir, file, body string } {
	return []struct{ dir, file, body string }{
		{"zzunlabelled", "zzunlabelled_snmp.json",
			`{"snmp":[{"oid":"1.3.6.1.4.1.99999.1.2.0","response":"a vendor object nobody checked"}]}`},
		{"zzlabelled", "zzlabelled_snmp.json",
			`{"_comment":"UNAUDITED-ARC(99998): nobody has read a MIB for this.",` +
				`"snmp":[{"oid":"1.3.6.1.4.1.99998.1.2.0","response":"a vendor object nobody checked"}]}`},
	}
}

// assertUnauditedArcDetectionWorks is the control the corpus guard runs first. It
// plants both arms into a temp copy of resources/ and requires the SAME scan and
// the SAME rule to report exactly one of them.
func assertUnauditedArcDetectionWorks(t *testing.T) {
	t.Helper()

	tmp := t.TempDir()
	if err := os.CopyFS(filepath.Join(tmp, "resources"), os.DirFS("resources")); err != nil {
		t.Fatalf("copy resources: %v", err)
	}
	for _, p := range unlabelledArcPlants() {
		if err := os.MkdirAll(filepath.Join(tmp, "resources", p.dir), 0o755); err != nil {
			t.Fatalf("plant a synthetic profile: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmp, "resources", p.dir, p.file),
			[]byte(p.body), 0o644); err != nil {
			t.Fatalf("plant a synthetic profile: %v", err)
		}
	}
	t.Chdir(tmp)

	found := arcLabelFindings(
		arcPairParts(scanArcPositions(t, underAnyEnterpriseArc)),
		partUnauditedMarks(t), auditedArcPENs, excludedArcPairs)

	// SCOPED TO THE PLANTED PROFILES, for the reason assertForeignArcDetectionWorks
	// gives: an exact corpus-wide total would make the control fail whenever a REAL
	// violation exists, which is precisely when the guard is doing its job and the
	// control still has to be trustworthy.
	byProfile := map[string][]arcLabelFinding{}
	for _, f := range found {
		byProfile[f.profile] = append(byProfile[f.profile], f)
	}

	reported := byProfile["zzunlabelled.json"]
	if len(reported) != 1 || reported[0].kind != "unaccounted" || reported[0].pen != "99999" {
		t.Fatalf("the control plants a synthetic profile serving an UNLABELLED arc under PEN 99999 "+
			"and the rule reported %+v.\nThe zero asserted below is therefore vacuous: a new device "+
			"type could ship a vendor subtree that nobody has audited and nobody has labelled, and "+
			"nothing would fail. That is the state nl6#590 exists to leave behind.", reported)
	}
	if stray := byProfile["zzlabelled.json"]; len(stray) != 0 {
		t.Fatalf("the control's SECOND arm plants a synthetic profile whose part carries "+
			"UNAUDITED-ARC(99998), and the rule reported it anyway: %+v.\nA rule that reports every "+
			"arc it sees passes the first arm and is worthless, so this arm is what makes the first "+
			"one mean something.", stray)
	}

	// And the sentinel's parse, directly, since a marker that binds to no PEN would
	// make every label match every arc.
	if got := unauditedArcMarksIn("UNAUDITED-ARC(2620): text"); len(got) != 1 || got[0] != "2620" {
		t.Fatalf("unauditedArcMarksIn read %v from a well-formed marker, want [2620]", got)
	}
	if got := unauditedArcMarksIn("no marker here"); len(got) != 0 {
		t.Fatalf("unauditedArcMarksIn read %v from a comment with no marker", got)
	}
	if got := unauditedArcMarksIn("UNAUDITED-ARC(674) and UNAUDITED-ARC(232)"); len(got) != 2 {
		t.Fatalf("unauditedArcMarksIn read %v from a comment marking two arcs", got)
	}
}

// TestEveryVendorArcIsAuditedLabelledOrExcluded is nl6#590's deliverable: the
// policy, enforced.
func TestEveryVendorArcIsAuditedLabelledOrExcluded(t *testing.T) {
	// The control runs first and in its own scope, because it t.Chdir()s.
	t.Run("positive control", func(t *testing.T) { assertUnauditedArcDetectionWorks(t) })

	pairs := arcPairParts(scanArcPositions(t, underAnyEnterpriseArc))
	marks := partUnauditedMarks(t)

	for _, f := range arcLabelFindings(pairs, marks, auditedArcPENs, excludedArcPairs) {
		switch f.kind {
		case "unaccounted":
			t.Errorf("%s serves an enterprise arc under PEN %s and is neither audited, labelled nor "+
				"excluded (%s).\nAn arc must be exactly one of the three. Pick one:\n"+
				"  AUDIT it.   Read the vendor's MIB, correct or delete the data, and add the PEN to "+
				"auditedArcPENs naming the reading test (see snmp_shipped_juniper_arc_ledger_test.go "+
				"for the shape);\n"+
				"  LABEL it.   Put %q in the _comment of EVERY part of the profile carrying an entry "+
				"under that PEN, saying that the objects below the number are unchecked. Five arcs "+
				"were audited and the miss rates were 8 of 11, 11 of 13, 6 of 6, 0 of 1 and 13 of 15 "+
				"distinct OIDs, so a reader needs to be told which kind of data this is;\n"+
				"  EXCLUDE it. Add the (profile, PEN) pair to excludedArcPairs with a written reason, "+
				"which is for arcs that are not vendor claims at all.\n"+
				"Doing none of the three is the state nl6#590 closed: a vendor subtree that reads as "+
				"checked because nothing says otherwise.",
				f.profile, f.pen, f.detail, unauditedArcSentinel(f.pen))
		case "double-classified":
			t.Errorf("%s / PEN %s is %s. Exactly one disposition must apply: an audited arc must not "+
				"also carry an unaudited label, and an excluded pair must not be labelled as a vendor "+
				"claim it is not", f.profile, f.pen, f.detail)
		case "partially-labelled":
			t.Errorf("%s / PEN %s: %s. The marker is per PART, not per profile: five of the fourteen "+
				"labelled profiles carry their arc in two parts, and the second is usually one vendor "+
				"serial-number object among a page of standard rows. A reader who opens the unmarked "+
				"file is told nothing", f.profile, f.pen, f.detail)
		}
	}

	// ── the census ──
	labelledPairs, labelledParts := 0, map[string]struct{}{}
	auditedPairs, excludedVisible := 0, 0
	var rows []string
	for key, parts := range pairs {
		profile, pen := key[0], key[1]
		// EVERY part must be marked, exactly as the rule requires. Testing only the
		// first one made the census log "labelled" for a profile the rule was
		// reporting as unaccounted, which is a log line contradicting the verdict
		// beside it.
		marked := 0
		for _, p := range parts {
			if marks[p][pen] {
				marked++
			}
		}

		disposition := "UNACCOUNTED"
		switch {
		case auditedArcPENs[pen].readingTest != "":
			disposition = "audited"
			auditedPairs++
		case marked == len(parts):
			disposition = "labelled"
			labelledPairs++
			for _, p := range parts {
				labelledParts[p] = struct{}{}
			}
		default:
			if _, ok := excludedArcPairs[key]; ok {
				disposition = "excluded"
				excludedVisible++
			}
		}
		rows = append(rows, fmt.Sprintf("%-30s PEN %-6s %-11s %d part(s)",
			profile, pen, disposition, len(parts)))
	}
	sort.Strings(rows)
	for _, r := range rows {
		t.Log(r)
	}

	if labelledPairs != unauditedArcLabelledPairs || len(labelledParts) != unauditedArcLabelledParts {
		t.Errorf("%d (profile, PEN) pairs are labelled unaudited across %d parts, recorded as %d and "+
			"%d. A count that FELL means an arc stopped being labelled without being audited, which is "+
			"how this guard goes quiet without failing; a count that ROSE needs the constants moved and "+
			"a reason in the commit", labelledPairs, len(labelledParts),
			unauditedArcLabelledPairs, unauditedArcLabelledParts)
	}
	if auditedPairs != auditedArcPairsShipped {
		t.Errorf("%d (profile, PEN) pairs are covered by an audited arc, recorded as %d",
			auditedPairs, auditedArcPairsShipped)
	}
	if excludedVisible != excludedArcPairsShipped {
		t.Errorf("%d scan-visible pairs are excluded, recorded as %d", excludedVisible, excludedArcPairsShipped)
	}
	t.Logf("%d (profile, PEN) pairs: %d audited, %d labelled unaudited across %d parts, %d excluded",
		len(pairs), auditedPairs, labelledPairs, len(labelledParts), excludedVisible)
}

// TestNoStaleUnauditedArcLabel is the mirror of the guard above: the guard says
// every arc is accounted for, this says every account describes something.
//
// A marker naming a PEN the part serves no entry under is stale, and stale is not
// harmless here: the label's claim is "these objects are unchecked", so a marker
// left behind after an audit tells a reader the opposite of the truth.
func TestNoStaleUnauditedArcLabel(t *testing.T) {
	pairs := arcPairParts(scanArcPositions(t, underAnyEnterpriseArc))
	served := map[[2]string]bool{} // (part, PEN) the corpus really serves
	for key, parts := range pairs {
		for _, p := range parts {
			served[[2]string{p, key[1]}] = true
		}
	}

	marked := 0
	for part, pens := range partUnauditedMarks(t) {
		for pen := range pens {
			marked++
			if !served[[2]string{part, pen}] {
				t.Errorf("%s marks PEN %s unaudited, but serves no entry under 1.3.6.1.4.1.%s. Either "+
					"the entry was deleted and the marker should go with it, or the marker names the "+
					"wrong number", part, pen, pen)
			}
			if a, ok := auditedArcPENs[pen]; ok {
				t.Errorf("%s marks PEN %s unaudited, but that arc IS audited: %s (%s). Remove the "+
					"marker rather than leaving a reader two contradictory statements",
					part, pen, a.readingTest, a.note)
			}
		}
	}
	if marked != unauditedArcLabelledParts {
		t.Errorf("%d parts carry an unaudited-arc marker, want %d", marked, unauditedArcLabelledParts)
	}
	t.Logf("%d unaudited-arc markers, all naming a PEN their own part serves", marked)
}

// TestUnauditedArcRegistriesAreCurated pins the two maps before anything uses
// them, in the shape TestOwnVendorPENMapIsCuratedAndComplete established.
//
// The reading-test citations are the half worth having: without this, renaming an
// audit's test would leave auditedArcPENs excusing an arc on the strength of a
// function that no longer exists, and nothing would fail.
func TestUnauditedArcRegistriesAreCurated(t *testing.T) {
	declared := declaredTestFuncs(t)
	for pen, a := range auditedArcPENs {
		if strings.TrimSpace(a.note) == "" {
			t.Errorf("audited PEN %s carries no note. Every row needs one: this map is the reason an "+
				"arc is exempt from labelling, so the exemption has to be readable", pen)
		}
		if !declared[a.readingTest] {
			t.Errorf("audited PEN %s cites %s, which this package does not declare. A citation nothing "+
				"checks is prose: rename the reference, or the arc is no longer covered by a reading",
				pen, a.readingTest)
			continue
		}
		t.Logf("PEN %-6s audited, pinned by %s", pen, a.readingTest)
	}

	// Every audited PEN must still be SERVED by some profile, or the row is stale.
	pairs := arcPairParts(scanArcPositions(t, underAnyEnterpriseArc))
	servedPENs := map[string]bool{}
	for key := range pairs {
		servedPENs[key[1]] = true
	}
	for pen := range auditedArcPENs {
		if !servedPENs[pen] {
			t.Errorf("auditedArcPENs names PEN %s, which no shipped profile serves. The row is stale", pen)
		}
	}

	// And the exclusions, both ways round. scanVisible is what makes a row that
	// describes nothing fail instead of sitting here forever.
	for key, ex := range excludedArcPairs {
		if strings.TrimSpace(ex.reason) == "" {
			t.Errorf("the exclusion for %s / PEN %s carries no reason", key[0], key[1])
		}
		_, visible := pairs[key]
		switch {
		case ex.scanVisible && !visible:
			t.Errorf("%s / PEN %s is recorded as visible to the dual-position scan and the scan does "+
				"not report it. The exclusion is stale", key[0], key[1])
		case !ex.scanVisible && visible:
			t.Errorf("%s / PEN %s is recorded as INVISIBLE to the dual-position scan and the scan now "+
				"reports it. That is a real change, not a bookkeeping one: the position became "+
				"readable (oidTypeTable gaining an OBJECT IDENTIFIER row would do it), so the "+
				"disposition has to be decided again rather than inherited", key[0], key[1])
		}
	}
	t.Logf("%d audited PENs, %d excluded pairs", len(auditedArcPENs), len(excludedArcPairs))
}

// declaredTestFuncs returns every `func Name(` this package's test files declare.
// It reads the sources as text rather than parsing them, which is enough to answer
// "does this identifier exist" and keeps the check free of a go/ast dependency for
// one string lookup.
func declaredTestFuncs(t *testing.T) map[string]bool {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(e.Name()) // #nosec G304 -- test-only, name from a package-dir read
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			rest, ok := strings.CutPrefix(line, "func ")
			if !ok {
				continue
			}
			if name, _, ok := strings.Cut(rest, "("); ok {
				out[name] = true
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no test functions found. Is the test running from go/nl6?")
	}
	return out
}
