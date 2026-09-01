/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// nl6#588 — THE PER-PROFILE OWN-VENDOR ENTERPRISE-OID GUARD.
//
// A vendor enterprise subtree is an IDENTITY CLAIM, not an approximation
// (nl6#569's wording, and the reason its 24 foreign Palo Alto entries were
// deleted rather than corrected). A profile may serve its own vendor's PEN and
// nothing else, in EITHER position an OID reaches the wire from.
//
// Four instances of the class shipped before this change and each was found
// separately, which is the argument for a general guard rather than a fifth
// single-arc one:
//
//   - nl6#569: twelve non-Palo-Alto profiles served the PAN subtree
//     (TestNoForeignPANOIDsShip, kept)
//   - nl6#576/#587: three nvidia_* profiles served GPU telemetry under 53246,
//     which IANA allocates to Mailteck, S.A.
//     (TestNoNvidiaOIDsShipUnderMailteck, kept)
//   - nl6#588: aws_s3_storage answered sysObjectID.0 with 1.3.6.1.4.1.9999,
//     allocated to Zerna, Koepper & Partner, a German engineering firm
//     (re-homed to 32473; see snmp_shipped_aws_pen_ledger_test.go)
//   - nl6#576, still open at the object layer: the bare Juniper jnxOperatingCPU
//     column four Cisco profiles carried, which nl6#571 deleted for a different
//     reason (it was a bare column) and which this guard would now also refuse
//
// FOUR THINGS ARE LOAD-BEARING, and each is a defect this repo has already
// shipped once:
//
//  1. IT READS OID-TYPED VALUES AS WELL AS NAMES. sysObjectID.0 is a RESPONSE and
//     it is the field a collector reads for vendor detection. A name-only scan is
//     structurally blind to it — that blind spot hid this very defect from the
//     nl6#587 research census, and nl6#587's own first-cut guard had it too. The
//     scan is scanArcPositions, shared with entriesTouchingArc, and the
//     is-it-an-OID test is the production one (snmpTypeTag(normaliseOIDKey(name))
//     == ASN1_OBJECT_ID), never a second predicate of this file's own — a second
//     predicate that agreed on the day it was written is how trap_catalog.go's
//     validateDottedOID drifted from the encoder (nl6#539).
//
//  2. THE POSITIVE CONTROL PLANTS ACROSS PROFILES. A test asserting ZERO of
//     something cannot fail on its own, and a control that plants and detects
//     inside ONE profile survives a narrowing of the scan — which is exactly the
//     regression nl6#571's fourth review layer demonstrated on the bare-column
//     census, with a green suite, because a narrowing changes no shipped byte and
//     therefore moves no digest and no ledger.
//
//  3. THE MAP IS CURATED, NEVER DERIVED FROM STRING SIMILARITY. Six shipped pairs
//     defeat name matching and are all correct; see ownVendorPENs.
//
//  4. THE PEN IS MATCHED ON A SUB-IDENTIFIER BOUNDARY. PEN 2 (IBM) is a string
//     prefix of 2011 (Huawei), 2620 (Check Point), 2636 (Juniper) and 25461
//     (Palo Alto), and all five ship. That is the same class of bug as the
//     `Contains "5703"` rule nl6#587's review found in pollaris.mdx.
//
// AND IT COVERS THE CODE-SERVED ARCS, NOT ONLY THE JSON. That was not in the
// first cut of this change and the omission was not theoretical: `vendorOIDs`
// (metrics_oids.go) served `sonicwall_nsa6700` four OIDs under PEN 8714 — iNOC,
// Inc. — where SonicWALL is 8741, a digit transposition that had never been read
// by any test in the package, while the same profile's resource files used 8741
// throughout. It answered live values and was enumerated into every walk. So
// there are THREE surfaces here, each with its own test and its own control:
// TestEveryProfileServesOnlyItsOwnVendorArc (the resource files),
// TestEveryCodeServedVendorOIDIsItsOwnVendorArc (vendorOIDs) and
// TestDefaultResourcesServeNoForeignVendorArc (the compiled-in fallback, which
// identified an unprofiled device as Cisco). All three run the SAME
// foreignArcViolations rule over the SAME ownVendorPENs map.

// enterpriseRoot is iso.org.dod.internet.private.enterprise — the node every
// vendor arc hangs from. A PEN is the ONE sub-identifier directly below it.
const enterpriseRoot = ".1.3.6.1.4.1"

// arcPENOf returns the private enterprise number a dotted OID sits under.
//
// IT SPLITS ON A SUB-IDENTIFIER BOUNDARY AND THAT IS THE WHOLE POINT. The obvious
// alternative — testing each known PEN with strings.HasPrefix — resolves
// .1.3.6.1.4.1.2011.2.239.1.1.1.1 (Huawei's NE8000 sysObjectID) to PEN 2 (IBM),
// because "1.3.6.1.4.1.2" is a prefix of "1.3.6.1.4.1.2011". FOUR shipped vendors
// sit behind that one trap — 2011 (Huawei), 2620 (Check Point), 2636 (Juniper)
// and 25461 (Palo Alto) — so the mistake is a false POSITIVE on all four, and,
// run the other way round, a false NEGATIVE that lets any of their OIDs pass
// inside the IBM profile. PEN 9 (Cisco) is likewise a prefix of 9999, the arc
// nl6#588 re-homed away from.
//
// The arc node itself (.1.3.6.1.4.1 with nothing below it) is not a vendor claim
// and reports no PEN. Nothing ships it; the branch exists so the parse cannot
// return an empty PEN that would then be compared against a profile's real one.
func arcPENOf(dottedOID string) (string, bool) {
	rest, ok := strings.CutPrefix(dottedOID, enterpriseRoot+".")
	if !ok {
		return "", false
	}
	pen, _, _ := strings.Cut(rest, ".")
	if pen == "" {
		return "", false
	}
	return pen, true
}

// ownVendorPEN is one curated row of the map below.
//
// `why` is MANDATORY for every profile, enforced by
// TestOwnVendorPENMapIsCuratedAndComplete. A bare slug-to-number table would look
// like something a script derived, and this map is precisely the thing a script
// must not derive: six of its rows are correct and would fail any name match.
// Writing the reason down is what makes a future edit reviewable.
type ownVendorPEN struct {
	pen string // "" means: this profile serves NO enterprise arc at all
	why string
}

// ownVendorPENs is the curated profile-to-PEN map: the ONE enterprise arc each
// shipped profile may serve, in an OID name or an OID-typed value.
//
// Every PEN here is looked up in testdata/iana/enterprise_numbers.tsv by
// TestOwnVendorPENMapIsCuratedAndComplete, so the map cannot name a number the
// registry extract does not carry, and the organisation string is on hand when
// one of these rows is questioned.
//
// It was VERIFIED against the corpus, not copied from the nl6#588 research
// digest: the census in that digest was re-derived here and agrees on all 29
// profiles, and TestEveryProfileServesOnlyItsOwnVendorArc re-derives it again on
// every run.
var ownVendorPENs = map[string]ownVendorPEN{
	"arista_7280r3.json":           {"30065", "Arista Networks, Inc. — registered as 'Arista Networks, Inc. (formerly Arastra, Inc.)'; the company renamed"},
	"asr9k.json":                   {"9", "ciscoSystems; the ASR 9000 is a Cisco platform"},
	"aws_s3_storage.json":          {"32473", "RFC 5612's documentation PEN, held by IANA. nl6#588 chose it over Amazon's real numbers (4843 Amazon.com Inc., 60099 Amazon Web Services Inc) DELIBERATELY: this profile models a CATEGORY — an S3-compatible object storage gateway, which MinIO, Ceph RGW and others implement — not a manufacturer, and AWS's own S3 is an HTTP service with no SNMP surface. Naming Amazon would trade one misattribution for a more plausible one. THIS IS A PER-PROFILE ALLOWANCE: 32473 must not become globally permitted, or any future profile could dodge this guard by claiming to be documentation"},
	"check_point_15600.json":       {"2620", "Check Point Software Technologies Ltd"},
	"ciena_waveserver5.json":       {"1271", "Ciena Corporation"},
	"cisco_catalyst_9500.json":     {"9", "ciscoSystems"},
	"cisco_crs_x.json":             {"9", "ciscoSystems"},
	"cisco_ios.json":               {"9", "ciscoSystems"},
	"cisco_nexus_9500.json":        {"9", "ciscoSystems"},
	"dell_emc_unity.json":          {"1139", "EMC Corp — Dell acquired EMC and Unity is the EMC line, so the slug says Dell and the registry says EMC. Dell's own PEN 674 is a different platform family (see dell_poweredge_r750)"},
	"dell_poweredge_r750.json":     {"674", "Dell Inc.; PowerEdge is Dell's own line"},
	"dlink_dgs3630.json":           {"171", "D-Link Systems, Inc."},
	"extreme_vsp4450.json":         {"1916", "Extreme Networks"},
	"fortinet_fortigate_600e.json": {"12356", "Fortinet, Inc."},
	"hpe_proliant_dl380.json":      {"232", "Compaq — HP acquired Compaq and ProLiant is the Compaq line, so the registry organisation shares no word with the slug. HPE's newer numbers are not what ProLiant hardware answers with"},
	"huawei_ne8000.json":           {"2011", "HUAWEI Technology Co.,Ltd. Note 2011 begins with '2', which is IBM's whole PEN — see arcPENOf"},
	"ibm_power_s922.json":          {"2", "IBM. A bare single-digit PEN, and a string prefix of three other shipped ones (2011, 2620, 2636); the boundary match in arcPENOf is what keeps those apart"},
	"juniper_mx240.json":           {"2636", "Juniper Networks, Inc."},
	"juniper_mx960.json":           {"2636", "Juniper Networks, Inc."},
	"linux_server.json":            {"", "A generic Linux host. It serves the standard MIB-II and HOST-RESOURCES trees and NO enterprise arc at all — not even net-snmp's 8072 — so the guard requires it to keep serving none. Giving it one would be an identity claim about a device that has no manufacturer"},
	"nec_ix3315.json":              {"119", "NEC Corporation"},
	"netapp_ontap.json":            {"789", "Network Appliance Corporation — NetApp's former legal name, which is what the registry still records"},
	"nokia_7750_sr12.json":         {"6527", "Nokia (formerly 'Alcatel-Lucent') — Nokia acquired Alcatel-Lucent and the 7750 SR is the ALU line"},
	"nvidia_dgx_a100.json":         {"5703", "NVIDIA Corporation (nl6#576 re-homed this arc off 53246, Mailteck, S.A.)"},
	"nvidia_dgx_h100.json":         {"5703", "NVIDIA Corporation (nl6#576)"},
	"nvidia_hgx_h200.json":         {"5703", "NVIDIA Corporation (nl6#576)"},
	"palo_alto_pa3220.json":        {"25461", "PALO ALTO NETWORKS. nl6#569 audited this subtree against PAN-COMMON-MIB and deleted the 24 entries twelve foreign profiles served under it"},
	"pure_storage_flasharray.json": {"40482", "Pure Storage"},
	"sonicwall_nsa6700.json":       {"8741", "SonicWALL, Inc."},
}

// penUnparseable marks a hit that is under the enterprise root but yields no
// private enterprise number. It is a sentinel, not a PEN, and no profile may be
// allowed it: ownVendorPENs holds digits or the empty string.
const penUnparseable = "<unparseable>"

// arcViolation is one shipped string sitting under a PEN its profile does not own.
type arcViolation struct {
	hit     arcHit
	pen     string // the PEN the string is actually under
	allowed string // the PEN the profile may serve; "" = none at all
}

// foreignArcViolations is the RULE, as a pure function over the scan's output, so
// the positive control can require it to REPORT rather than only to stay silent.
// An inline `if` inside the corpus test could not be asked to do that, which is
// the lesson bareColumnCountViolation records.
//
// A profile with no entry in `allowed` is reported for EVERY arc it touches: a
// new device type must be registered in ownVendorPENs before it may serve one,
// rather than defaulting to unguarded.
//
// A hit that sits under the enterprise root but yields NO PEN is reported too,
// as penUnparseable, not skipped. It is only reachable for a bare .1.3.6.1.4.1
// or a trailing empty sub-identifier, neither of which ships — but "the parse
// failed" is the one answer a guard must never turn into "nothing to see here",
// since that is a silent pass on exactly the malformed input it cannot reason
// about.
func foreignArcViolations(hits []arcHit, allowed map[string]ownVendorPEN) []arcViolation {
	var out []arcViolation
	for _, h := range hits {
		pen, ok := arcPENOf(normaliseOIDKey(h.text))
		if !ok {
			pen = penUnparseable
		}
		if own, registered := allowed[h.profile]; registered && own.pen == pen {
			continue
		}
		out = append(out, arcViolation{hit: h, pen: pen, allowed: allowed[h.profile].pen})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].hit.profile != out[j].hit.profile {
			return out[i].hit.profile < out[j].hit.profile
		}
		if out[i].hit.oid != out[j].hit.oid {
			return out[i].hit.oid < out[j].hit.oid
		}
		return out[i].hit.where < out[j].hit.where
	})
	return out
}

// underAnyEnterpriseArc is the scan predicate: every position under
// 1.3.6.1.4.1, whichever vendor it belongs to. entriesTouchingArc asks about ONE
// named arc; this guard has to see them all, or a foreign arc it has never heard
// of is exactly what it misses.
func underAnyEnterpriseArc(dottedOID string) bool {
	return underArc(dottedOID, enterpriseRoot)
}

// ── the census the guard is measured against ────────────────────────────────

// ownVendorArcNamesShipped and ownVendorArcValuesShipped are the corpus totals,
// RE-DERIVED here from the shipped tree and not copied from nl6#588's research
// digest (they happen to agree with it, which is the point of re-deriving).
//
// They are pinned so the zero this guard asserts cannot become vacuous by the
// corpus losing its enterprise arcs: a scan that found nothing would report no
// violations either. Raising or lowering them needs a reason in the commit.
//
// The name count fell from 343 to 335 in nl6#590, the first vendor-arc MIB audit:
// eight Cisco entries were deleted because the objects they named do not hold
// what the profile put in them (see snmp_shipped_cisco_arc_ledger_test.go). The
// VALUE count is unchanged, which is the half that matters here — no profile
// stopped identifying itself.
const (
	ownVendorArcNamesShipped  = 335
	ownVendorArcValuesShipped = 28
)

// TestOwnVendorPENMapIsCuratedAndComplete pins the map itself before anything
// uses it: it must name every shipped profile and no others, every PEN must
// resolve in the checked-in IANA extract, and every row must carry a reason.
//
// The completeness half is what makes a NEW device type fail loudly instead of
// arriving unguarded, and it is why the map lists linux_server with an empty PEN
// rather than omitting it — an omission and a deliberate "serves none" would
// otherwise be the same thing.
func TestOwnVendorPENMapIsCuratedAndComplete(t *testing.T) {
	byPEN := map[string]ianaPENEntry{}
	for _, e := range readIANAPENFixture(t) {
		if prev, dup := byPEN[e.pen]; dup {
			t.Fatalf("%s gives PEN %s twice (%q and %q)", ianaPENFixture, e.pen, prev.org, e.org)
		}
		byPEN[e.pen] = e
	}

	shipped := map[string]struct{}{}
	for _, p := range shippedProfileNames(t) {
		shipped[p] = struct{}{}
	}
	for p := range shipped {
		if _, ok := ownVendorPENs[p]; !ok {
			t.Errorf("profile %s is shipped but has no ownVendorPENs entry, so nothing constrains "+
				"which vendor's enterprise arc it may serve. Register it — with an empty PEN if it "+
				"serves none — and record which IANA row the number comes from", p)
		}
	}
	for p, v := range ownVendorPENs {
		if _, ok := shipped[p]; !ok {
			t.Errorf("ownVendorPENs names %s, which is not a shipped profile; the map is stale", p)
		}
		if strings.TrimSpace(v.why) == "" {
			t.Errorf("%s carries PEN %q with no reason. Every row needs one: six shipped pairs are "+
				"correct and share no word with their slug, so a bare number table would look like "+
				"something derived from name matching, which this map must never be", p, v.pen)
		}
		if v.pen == "" {
			continue
		}
		e, ok := byPEN[v.pen]
		if !ok {
			t.Errorf("%s claims PEN %s, which %s does not carry. Add the registry row (with its "+
				"line number and the fetch provenance) rather than asserting the number here",
				p, v.pen, ianaPENFixture)
			continue
		}
		t.Logf("%-30s PEN %-6s %s", p, v.pen, e.org)
	}

	// The documentation PEN is a PER-PROFILE allowance and must stay one. If a
	// second profile ever claims 32473 that is a decision to argue for, not a
	// default to inherit.
	var docPEN []string
	for p, v := range ownVendorPENs {
		if v.pen == "32473" {
			docPEN = append(docPEN, p)
		}
	}
	sort.Strings(docPEN)
	if len(docPEN) != 1 || docPEN[0] != "aws_s3_storage.json" {
		t.Errorf("profiles claiming the documentation PEN 32473: %v, want exactly "+
			"[aws_s3_storage.json]. 32473 is allowed for that one profile because it models a "+
			"category with no manufacturer (nl6#588). Making it generally available would give any "+
			"future profile a way to dodge this guard", docPEN)
	}
}

// TestArcPENOfMatchesOnASubIdentifierBoundary is the unit pin for requirement 4,
// and it exists because the corpus scan alone cannot state the property in so
// many words: with the map correct, a prefix-matching implementation and a
// boundary-matching one both report zero violations on a CLEAN corpus. The
// difference only shows on the mutations, so the rule is asserted directly.
func TestArcPENOfMatchesOnASubIdentifierBoundary(t *testing.T) {
	for _, tc := range []struct {
		oid, wantPEN string
		wantOK       bool
		why          string
	}{
		{".1.3.6.1.4.1.2.6.191.2.4.2.1", "2", true, "ibm_power_s922's sysObjectID; PEN 2 is a whole PEN, not a prefix of one"},
		{".1.3.6.1.4.1.2011.2.239.1.1.1.1", "2011", true, "huawei_ne8000's sysObjectID. A prefix match against PEN 2 resolves this to IBM"},
		{".1.3.6.1.4.1.2620.1.1.15600", "2620", true, "check_point_15600; also behind the PEN 2 prefix trap"},
		{".1.3.6.1.4.1.2636.1.1.1.2.29", "2636", true, "juniper_mx240; the third one behind it"},
		{".1.3.6.1.4.1.9.1.1", "9", true, "cisco_ios. PEN 9 is a prefix of 9999 (Zerna) and of 99, 999 ..."},
		{".1.3.6.1.4.1.9999", "9999", true, "the arc aws_s3_storage used to answer with; a prefix match against PEN 9 calls it Cisco"},
		{".1.3.6.1.4.1.32473.1.1", "32473", true, "aws_s3_storage today"},
		{".1.3.6.1.4.1.5703.1.2.1", "5703", true, "nvidia_dgx_a100"},
		{".1.3.6.1.4.1", "", false, "the enterprise node itself is not a vendor claim"},
		{".1.3.6.1.4.1.", "", false, "a trailing dot yields no sub-identifier"},
		{".1.3.6.1.2.1.1.2.0", "", false, "sysObjectID's own name is not under an enterprise arc"},
		{".1.3.6.1.4.10.1", "", false, "1.3.6.1.4.10 is not 1.3.6.1.4.1 — the boundary matters above the PEN too"},
		{"", "", false, "empty"},
	} {
		pen, ok := arcPENOf(tc.oid)
		if ok != tc.wantOK || pen != tc.wantPEN {
			t.Errorf("arcPENOf(%q) = (%q, %v), want (%q, %v) — %s",
				tc.oid, pen, ok, tc.wantPEN, tc.wantOK, tc.why)
		}
	}

	// And the rule stated as the property rather than as a table: no shipped PEN
	// may be reported for an OID that merely starts with its digits.
	seen := map[string]string{}
	for p, v := range ownVendorPENs {
		if v.pen == "" {
			continue
		}
		seen[v.pen] = p
	}
	for pen := range seen {
		for other := range seen {
			if other == pen || !strings.HasPrefix(other, pen) {
				continue
			}
			// `other` is a longer PEN whose digits start with `pen`. An OID under
			// `other` must never resolve to `pen`.
			oid := enterpriseRoot + "." + other + ".1"
			if got, _ := arcPENOf(oid); got != other {
				t.Errorf("arcPENOf(%q) = %q, want %q. PEN %s (%s) is a string prefix of PEN %s (%s), "+
					"so a prefix match reports the wrong vendor for every OID of the longer one",
					oid, got, other, pen, seen[pen], other, seen[other])
			}
		}
	}
}

// crossProfileForeignArcFixture is the positive control's plant, and every row of
// it sits in a DIFFERENT profile from the arc it names. Legality is a property of
// the (profile, OID) pair, so a control that plants a foreign arc and detects it
// inside ONE profile proves nothing about a scan that has been narrowed.
//
// Three plants, each covering a distinct way the guard can fail:
//
//  1. a foreign OID NAME — Juniper's 2636 inside cisco_ios (own PEN 9)
//  2. a foreign OID-TYPED VALUE — NVIDIA's 5703 as linux_server's sysObjectID.0,
//     in the profile that is registered as serving NO arc at all. Nothing about
//     the OID KEY (1.3.6.1.2.1.1.2.0, plain sysObjectID) gives this away, so a
//     name-only scan cannot see it — and this is the position vendor detection
//     actually reads.
//  3. THE PEN-2 PREFIX TRAP — Huawei's 2011 inside ibm_power_s922, whose own PEN
//     is 2. A guard matching "1.3.6.1.4.1.2" by string prefix admits this
//     silently.
func crossProfileForeignArcFixture() []struct{ dir, file, body string } {
	return []struct{ dir, file, body string }{
		{"cisco_ios", "zzplanted_foreign_name_snmp.json",
			`{"snmp":[{"oid":"1.3.6.1.4.1.2636.3.1.13.1.5.9.1.0.0","response":"42"}]}`},
		{"linux_server", "zzplanted_foreign_value_snmp.json",
			`{"snmp":[{"oid":"1.3.6.1.2.1.1.2.0","response":"1.3.6.1.4.1.5703.1.2.1"}]}`},
		{"ibm_power_s922", "zzplanted_prefix_trap_snmp.json",
			`{"snmp":[{"oid":"1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.1","response":"7"}]}`},
	}
}

// assertForeignArcDetectionWorks is the control every assertion in this file's
// corpus guard runs first. It plants the three rows above into a temp copy of
// resources/ and requires the SAME scan and the SAME rule to report all three.
func assertForeignArcDetectionWorks(t *testing.T) {
	t.Helper()

	tmp := t.TempDir()
	if err := os.CopyFS(filepath.Join(tmp, "resources"), os.DirFS("resources")); err != nil {
		t.Fatalf("copy resources: %v", err)
	}
	for _, p := range crossProfileForeignArcFixture() {
		if err := os.WriteFile(filepath.Join(tmp, "resources", p.dir, p.file),
			[]byte(p.body), 0o644); err != nil {
			t.Fatalf("plant a foreign-arc entry: %v", err)
		}
	}
	t.Chdir(tmp)

	// SCOPED TO THE PLANTED PROFILES, deliberately. An exact total over the whole
	// corpus would make this control fail whenever a REAL violation exists
	// elsewhere — which is precisely when the guard is doing its job and the
	// control still has to be trustworthy. Within the three planted profiles the
	// count IS exact, so a rule that reported every entry rather than the foreign
	// ones still fails here.
	want := map[string]struct{ pen, where string }{
		"cisco_ios.json":      {"2636", "name"},
		"linux_server.json":   {"5703", "value"},
		"ibm_power_s922.json": {"2011", "name"},
	}
	seen := map[string]arcViolation{}
	for _, v := range foreignArcViolations(scanArcPositions(t, underAnyEnterpriseArc), ownVendorPENs) {
		if _, planted := want[v.hit.profile]; !planted {
			continue
		}
		if prev, dup := seen[v.hit.profile]; dup {
			t.Fatalf("the control plants ONE foreign arc in %s and the guard reported two "+
				"(%+v, %+v): either the rule is reporting entries that are not foreign, or that "+
				"profile has acquired a REAL violation — in which case move the plant to a clean "+
				"profile, because a control must not share a profile with the defect it is "+
				"calibrating against", v.hit.profile, prev, v)
		}
		seen[v.hit.profile] = v
	}
	for profile, w := range want {
		v, ok := seen[profile]
		if !ok {
			t.Fatalf("the control planted a foreign PEN %s in the %s position of %s and the guard "+
				"did not report it.\nThe zero asserted below is therefore vacuous. If the VALUE "+
				"plant in linux_server is the missing one, the scan reads OID KEYS only — and "+
				"vendor detection reads the sysObjectID RESPONSE. If the PEN-2011 plant inside the "+
				"IBM profile (own PEN 2) is missing, the PEN is being matched by string prefix "+
				"rather than on a sub-identifier boundary.", w.pen, w.where, profile)
		}
		if v.pen != w.pen || v.hit.where != w.where {
			t.Fatalf("in %s the guard reported PEN %s in the %s position, want PEN %s in the %s "+
				"position", profile, v.pen, v.hit.where, w.pen, w.where)
		}
	}

	// And the rule must still report when a profile is not in the map at all,
	// which is how a NEW device type is caught before it may serve an arc.
	unregistered := foreignArcViolations(
		[]arcHit{{"zznew.json", ".1.3.6.1.4.1.9.1.1", "resources/zznew/x.json", "name", ".1.3.6.1.4.1.9.1.1"}},
		ownVendorPENs)
	if len(unregistered) != 1 {
		t.Fatalf("an arc served by a profile with no ownVendorPENs entry must be reported, got %v",
			unregistered)
	}
}

// TestEveryProfileServesOnlyItsOwnVendorArc is nl6#588's deliverable: the class
// nl6#569 and nl6#576 each closed one instance of, closed corpus-wide.
//
// The two single-arc guards stay. They say something this one does not: that
// 1.3.6.1.4.1.53246 and the PAN subtree must not come BACK, by name, with the
// specific history that made each a defect. This guard says every profile serves
// only its own vendor. Neither subsumes the other and both are cheap.
//
// WHAT IT STILL CANNOT SEE, stated rather than glossed:
//
//   - THE VALUE HALF SEES sysObjectID AND NOTHING ELSE, which is narrower than
//     "OID-typed values" sounds and was overstated in the first cut of this
//     comment. The gate is snmpTypeTag(...) == ASN1_OBJECT_ID and oidTypeTable
//     carries exactly ONE such row: sysObjectID. entPhysicalVendorType
//     (1.3.6.1.2.1.47.1.1.1.1.3.x) is an OBJECT IDENTIFIER in RFC 4133 and ships
//     with enterprise-arc responses in at least six profiles, and this guard
//     reads every one of them as an OCTET STRING and skips it. Nothing
//     cross-vendor sits there today (assertEntPhysicalVendorTypeIsNotCrossVendor
//     below checks that separately and cheaply), so this is a coverage gap and
//     not a live defect. Reusing the PRODUCTION predicate is still the right
//     boundary: nl6 encodes an untyped dotted-looking response as an OCTET
//     STRING, so it never reaches the wire as an OID, and a guard that judged
//     values by string shape would report entries no collector can read as an
//     identity. Widening this means adding a row to oidTypeTable, which is a wire
//     change and a separate decision.
//   - whether the objects BELOW a correct PEN mean what the vendor's MIB says
//     they mean. nl6#569's audit of one profile found 8 of 11 wrong, and the
//     other 28 have had no equivalent review. A profile can pass this guard while
//     every value under its own arc is invented (all three nvidia_* profiles do:
//     NVIDIA publishes no SNMP GPU MIB, so 5703.1.1.1.* names no published
//     object).
//   - a MISSING arc. Nothing here requires a profile to identify itself, only to
//     identify itself truthfully; the per-profile value count below is the
//     closest thing, and it is a census, not a rule.
//   - the trap catalogs' snmpTrapEnterprise values, gNMI and the REST surface.
//     The catalogs were audited by hand for nl6#588 and are clean; scanning them
//     was considered and deliberately not added.
func TestEveryProfileServesOnlyItsOwnVendorArc(t *testing.T) {
	// The control runs first and in its own scope, because it t.Chdir()s.
	t.Run("positive control", func(t *testing.T) { assertForeignArcDetectionWorks(t) })

	hits := scanArcPositions(t, underAnyEnterpriseArc)

	for _, v := range foreignArcViolations(hits, ownVendorPENs) {
		own, registered := ownVendorPENs[v.hit.profile]
		switch {
		case !registered:
			t.Errorf("%s: %s reaches the wire under PEN %s (as an OID %s: %s), and %s has no "+
				"ownVendorPENs entry at all. Register the profile before it serves an enterprise arc",
				v.hit.part, v.hit.oid, v.pen, v.hit.where, v.hit.text, v.hit.profile)
		case own.pen == "":
			t.Errorf("%s: %s reaches the wire under PEN %s (as an OID %s: %s), but %s is recorded as "+
				"serving NO enterprise arc: %s", v.hit.part, v.hit.oid, v.pen, v.hit.where,
				v.hit.text, v.hit.profile, own.why)
		default:
			t.Errorf("%s: %s reaches the wire under PEN %s (as an OID %s: %s), which is not %s's "+
				"own vendor. That profile may serve PEN %s only (%s). A vendor enterprise subtree is "+
				"an identity claim, not an approximation: a collector keyed on the other vendor's MIB "+
				"reads this device as their hardware. Delete the entry, or re-home it — and if the "+
				"profile's own PEN really did change, edit ownVendorPENs and say why",
				v.hit.part, v.hit.oid, v.pen, v.hit.where, v.hit.text, v.hit.profile, own.pen, own.why)
		}
	}

	// ── the census, so the zero above cannot go vacuous ──
	type census struct{ names, values int }
	per := map[string]*census{}
	for _, h := range hits {
		if per[h.profile] == nil {
			per[h.profile] = &census{}
		}
		if h.where == "name" {
			per[h.profile].names++
		} else {
			per[h.profile].values++
		}
	}
	names, values := 0, 0
	var rows []string
	for p, c := range per {
		names += c.names
		values += c.values
		rows = append(rows, fmt.Sprintf("%-30s PEN %-6s names=%-3d values=%d",
			p, ownVendorPENs[p].pen, c.names, c.values))
	}
	sort.Strings(rows)
	for _, r := range rows {
		t.Log(r)
	}

	if names != ownVendorArcNamesShipped || values != ownVendorArcValuesShipped {
		t.Errorf("the corpus serves %d enterprise-arc OID names and %d OID-typed values, recorded "+
			"as %d and %d. If a profile legitimately gained or lost vendor OIDs, update the two "+
			"constants and say so — but a value count that fell means a profile stopped identifying "+
			"itself, which is the way this guard goes quiet without failing",
			names, values, ownVendorArcNamesShipped, ownVendorArcValuesShipped)
	}

	// EVERY profile with a PEN must actually use it in the VALUE position. That
	// is the sysObjectID.0 vendor-detection surface, the one this whole class of
	// defect lives in, and asserting it per profile is what stops a single
	// profile going silent behind a healthy total.
	for p, v := range ownVendorPENs {
		c := per[p]
		switch {
		case v.pen == "":
			if c != nil {
				t.Errorf("%s is recorded as serving no enterprise arc but serves %d names and %d "+
					"values", p, c.names, c.values)
			}
		case c == nil || c.values == 0:
			t.Errorf("%s serves no OID-typed value under its own PEN %s. sysObjectID.0 is how a "+
				"collector identifies the device; a profile that answers none is not covered by "+
				"this guard at all", p, v.pen)
		}
	}
	t.Logf("%d enterprise-arc OID names and %d OID-typed values across %d profiles; none foreign",
		names, values, len(per))

	assertEntPhysicalVendorTypeIsNotCrossVendor(t)
}

// entPhysicalVendorTypePlaceholders is the number of shipped
// entPhysicalVendorType responses answering the synthetic 1.3.6.1.4.1.0.0.
//
// PEN 0 is "Reserved" in the registry, held by IANA — it is not a company, so
// these are not a misattribution the way 9999 or 8714 were, but they are not a
// vendor type either: a collector reading entPhysicalVendorType gets a value that
// resolves to nothing. Pinned so the count is a known quantity rather than
// something nobody has counted.
const entPhysicalVendorTypePlaceholders = 208

// assertEntPhysicalVendorTypeIsNotCrossVendor closes, by inspection, the gap the
// main guard's value half cannot reach.
//
// entPhysicalVendorType is an OBJECT IDENTIFIER in RFC 4133, but oidTypeTable
// does not type it, so scanArcPositions reads its responses as OCTET STRINGs and
// never tests them. That is the right boundary for the guard (see the exclusion
// list above) and it leaves a real question unanswered: are any of those values
// another vendor's arc? They are not, and this says so with a check rather than
// with a sentence.
//
// It reads the responses DIRECTLY rather than through scanArcPositions, precisely
// because the production predicate excludes them — routing it through the shared
// scan would either report nothing or require widening the scan, which is the
// wire change the exclusion list declines to make here.
func assertEntPhysicalVendorTypeIsNotCrossVendor(t *testing.T) {
	t.Helper()

	const entPhysicalVendorTypeCol = ".1.3.6.1.2.1.47.1.1.1.1.3."
	placeholders, checked := 0, 0
	for _, e := range shippedSNMPEntries(t) {
		if !strings.HasPrefix(e.OID, entPhysicalVendorTypeCol) {
			continue
		}
		pen, ok := arcPENOf(normaliseOIDKey(e.Value))
		if !ok {
			// Not under the enterprise root at all (eight entries answer a bare
			// "1"). Malformed as a vendor type, but not a vendor misattribution,
			// and out of scope here.
			continue
		}
		checked++
		if pen == "0" {
			placeholders++
			continue
		}
		if own := ownVendorPENs[e.Profile]; own.pen != pen {
			t.Errorf("%s: entPhysicalVendorType %s answers %q, which is under PEN %s, not %s's own "+
				"PEN %s. The main guard cannot see this position — oidTypeTable does not type "+
				"entPhysicalVendorType, so the response is encoded as an OCTET STRING — which is why "+
				"it is checked here instead", e.Part, e.OID, e.Value, pen, e.Profile, own.pen)
		}
	}
	if placeholders != entPhysicalVendorTypePlaceholders {
		t.Errorf("%d entPhysicalVendorType responses answer the synthetic 1.3.6.1.4.1.0.0, recorded "+
			"as %d. PEN 0 is 'Reserved' in the registry: these resolve to no vendor at all. The "+
			"count is pinned so it is a known quantity, not because it is right",
			placeholders, entPhysicalVendorTypePlaceholders)
	}
	t.Logf("%d entPhysicalVendorType values sit under an enterprise arc; %d are the reserved-PEN "+
		"placeholder, the rest are their own vendor's", checked, placeholders)
}

// ── the code-served surface (nl6#588 P2) ────────────────────────────────────

// codeServedVendorArcHits renders vendorOIDs into the same arcHit shape the
// resource scan produces, so the SAME rule can be run over it.
//
// vendorOIDs is keyed by the identical "<slug>.json" strings as ownVendorPENs, is
// answered on the wire by getMetricValue and enumerated into walks by
// GetSortedMetricOIDs — and until nl6#588 no test in the package read it at all.
// That is how four OIDs under iNOC, Inc.'s PEN 8714 shipped on a SonicWALL
// profile whose own resource files used 8741 throughout.
//
// Only the enterprise-rooted OIDs are rendered: the map also holds standard
// HOST-RESOURCES entries (hrProcessorLoad, hrStorageSize) which belong to no
// vendor.
func codeServedVendorArcHits() []arcHit {
	var out []arcHit
	for profile, m := range vendorOIDs {
		for oid := range m {
			dotted := normaliseOIDKey(oid)
			if !underAnyEnterpriseArc(dotted) {
				continue
			}
			out = append(out, arcHit{profile, dotted, "metrics_oids.go (vendorOIDs)", "name", dotted})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].profile != out[j].profile {
			return out[i].profile < out[j].profile
		}
		return out[i].oid < out[j].oid
	})
	return out
}

// codeServedVendorArcOIDs is the number of enterprise-rooted OIDs vendorOIDs
// serves, pinned so the zero below cannot go vacuous by the map emptying.
//
// MEASURED, not derived: 268 = 192 (the three nvidia_* profiles' 64 dynamic GPU
// OIDs each, which init() installs, so this pins the map AFTER package
// initialisation) + 76 spread over 19 other profiles at three to five each.
//
// codeServedVendorArcProfiles is 22, not len(vendorOIDs) = 23: arista_7280r3's
// entry is entirely standard-MIB (hrProcessorLoad, hrStorage, entPhySensorValue)
// and touches no enterprise arc at all, so it contributes nothing here. That is a
// real property of the map, recorded rather than smoothed over.
const (
	codeServedVendorArcOIDs     = 268
	codeServedVendorArcProfiles = 22
)

// TestEveryCodeServedVendorOIDIsItsOwnVendorArc is P2: the same rule as the
// resource-file guard, over the OIDs nl6 serves from Go code.
//
// It exists because fixing the SonicWALL transposition without it would leave
// nothing to stop the next one — and the transposition is the proof that "nobody
// would do that" is not an argument. Its positive control plants into a COPY of
// the map rather than mutating the package-level one, so it cannot leak into
// another test in the same binary.
func TestEveryCodeServedVendorOIDIsItsOwnVendorArc(t *testing.T) {
	// POSITIVE CONTROL, first: plant a Juniper OID on the Cisco IOS profile and
	// an unregistered-profile row, and require both reported. Same cross-profile
	// discipline as the resource-file control — the plant never shares a profile
	// with a real violation.
	planted := map[string]map[string]MetricOIDType{}
	for profile, m := range vendorOIDs {
		planted[profile] = m
	}
	planted["cisco_ios.json"] = map[string]MetricOIDType{
		".1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0": MetricCPUPercent, // Juniper's arc
		".1.3.6.1.4.1.9.9.109.1.1.1.1.5.1":     MetricCPUPercent, // Cisco's own, must NOT be reported
	}
	var control []arcHit
	for profile, m := range planted {
		for oid := range m {
			dotted := normaliseOIDKey(oid)
			if !underAnyEnterpriseArc(dotted) {
				continue
			}
			control = append(control, arcHit{profile, dotted, "planted", "name", dotted})
		}
	}
	reported := map[string]string{}
	for _, v := range foreignArcViolations(control, ownVendorPENs) {
		if v.hit.profile == "cisco_ios.json" {
			reported[v.hit.oid] = v.pen
		}
	}
	if len(reported) != 1 || reported[".1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0"] != "2636" {
		t.Fatalf("the control plants ONE foreign OID (Juniper's 2636) and one legitimate Cisco OID "+
			"into cisco_ios.json's code-served map, and the rule reported %v. The zero asserted "+
			"below is therefore vacuous", reported)
	}

	hits := codeServedVendorArcHits()
	for _, v := range foreignArcViolations(hits, ownVendorPENs) {
		own := ownVendorPENs[v.hit.profile]
		t.Errorf("metrics_oids.go: vendorOIDs[%q] serves %s, which is under PEN %s, not that "+
			"profile's own PEN %s (%s). This map is answered on the wire by getMetricValue and "+
			"enumerated into every walk by GetSortedMetricOIDs, so the device really does serve "+
			"another vendor's arc — which is exactly how PEN 8714 (iNOC, Inc.) shipped on the "+
			"SonicWALL profile until nl6#588. Fix the OID, preserving every sub-identifier below "+
			"the PEN", v.hit.profile, v.hit.oid, v.pen, own.pen, own.why)
	}

	if len(hits) != codeServedVendorArcOIDs {
		t.Errorf("vendorOIDs serves %d enterprise-rooted OIDs, recorded as %d. If a device type "+
			"legitimately gained or lost vendor metric OIDs, update the constant and say so — a "+
			"count that fell to zero would make this guard pass on an empty map",
			len(hits), codeServedVendorArcOIDs)
	}

	// And the SonicWALL row specifically, because it is the defect this test was
	// written for and a census total would absorb its return.
	sonic := map[string]struct{}{}
	for _, h := range hits {
		if h.profile == "sonicwall_nsa6700.json" {
			sonic[h.oid] = struct{}{}
		}
	}
	for _, oid := range []string{
		".1.3.6.1.4.1.8741.2.1.3.1.1.0", ".1.3.6.1.4.1.8741.2.1.3.1.2.0",
		".1.3.6.1.4.1.8741.2.1.3.1.3.0", ".1.3.6.1.4.1.8741.2.1.3.1.4.0",
	} {
		if _, ok := sonic[oid]; !ok {
			t.Errorf("vendorOIDs[sonicwall_nsa6700.json] no longer serves %s. nl6#588 re-homed "+
				"these four off PEN 8714 (iNOC, Inc.) to SonicWALL's 8741 preserving every "+
				"sub-identifier; they were not meant to disappear", oid)
		}
	}
	if len(sonic) != 4 {
		t.Errorf("vendorOIDs[sonicwall_nsa6700.json] serves %d enterprise OIDs, want 4", len(sonic))
	}

	withArc := map[string]struct{}{}
	for _, h := range hits {
		withArc[h.profile] = struct{}{}
	}
	if len(withArc) != codeServedVendorArcProfiles {
		t.Errorf("%d of vendorOIDs' %d profiles serve an enterprise arc, want %d. One profile "+
			"(arista_7280r3) is deliberately all standard-MIB; a second one going quiet would mean "+
			"a vendor's metrics stopped being served", len(withArc), len(vendorOIDs),
			codeServedVendorArcProfiles)
	}
	t.Logf("%d code-served enterprise OIDs across %d of vendorOIDs' %d profiles; none foreign",
		len(hits), len(withArc), len(vendorOIDs))
}

// TestDefaultResourcesServeNoForeignVendorArc is P3, and it is the only one of
// the three surfaces that is not a data table: createDefaultResources is the
// compiled-in fallback written whenever a named resource file is absent, so it is
// a PRODUCTION path that any misconfigured device lands on.
//
// It answered sysObjectID.0 with 1.3.6.1.4.1.9.1.1 — ciscoSystems — until
// nl6#588, so a device with no profile at all told every collector it was Cisco
// hardware. It now answers the documentation PEN, for the same reason
// aws_s3_storage does: a generic fallback models no manufacturer.
//
// It drives the REAL function into a temp directory rather than asserting against
// a literal, so a future edit to those compiled-in constants is covered.
func TestDefaultResourcesServeNoForeignVendorArc(t *testing.T) {
	t.Chdir(t.TempDir())

	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	if err := sm.createDefaultResources("zzdefault.json"); err != nil {
		t.Fatalf("createDefaultResources: %v", err)
	}
	res := sm.deviceResources
	if res == nil || len(res.SNMP) == 0 {
		t.Fatal("createDefaultResources produced no SNMP entries")
	}

	// The fallback is not a device TYPE, so it has no ownVendorPENs row. Its rule
	// is stricter: the documentation PEN, or nothing.
	checked := 0
	for _, e := range res.SNMP {
		oid := normaliseOIDKey(e.OID)
		for _, candidate := range []string{oid, normaliseOIDKey(e.Response)} {
			pen, ok := arcPENOf(candidate)
			if !ok {
				continue
			}
			checked++
			if pen != "32473" {
				t.Errorf("createDefaultResources serves %s under PEN %s (%q). This is the "+
					"compiled-in fallback for a device with NO resource file, so it must not claim "+
					"any manufacturer's identity: nl6#588 re-homed its sysObjectID off ciscoSystems "+
					"(1.3.6.1.4.1.9.1.1) to the documentation PEN 1.3.6.1.4.1.32473 for exactly that "+
					"reason", oid, pen, e.Response)
			}
		}
	}
	if checked == 0 {
		t.Error("no enterprise-rooted OID found in the default resources, so this guard asserted " +
			"nothing. It should find sysObjectID.0's response at minimum")
	}

	// And the value itself, read back through the serve path rather than off the
	// struct, since buildResourceIndexes is what a device actually answers from.
	srv := &SNMPServer{device: &DeviceSimulator{
		ID: "default-fallback-pin", resources: res, resourceFile: "zzdefault.json",
	}}
	if got, want := srv.findResponse(".1.3.6.1.2.1.1.2.0"), "1.3.6.1.4.1.32473.1.1"; got != want {
		t.Errorf("the fallback profile answers sysObjectID.0 with %q, want %q", got, want)
	}
	t.Logf("%d enterprise-rooted positions in the compiled-in fallback, all under the "+
		"documentation PEN", checked)
}
