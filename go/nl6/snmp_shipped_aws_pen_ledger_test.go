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

// nl6#588 re-homed aws_s3_storage's sysObjectID.0 from 1.3.6.1.4.1.9999 to
// 1.3.6.1.4.1.32473.1.1.
//
// 9999 is not Amazon's and not anybody's in storage. The IANA enterprise-numbers
// registry (fetched 2026-09-01, self-dated 2026-08-28, the same snapshot nl6#576
// used — the SHA-256 reproduces byte for byte) allocates it to:
//
//	9999   Zerna, Koepper & Partner   <cas&zkp.de>
//
// a German engineering consultancy with no connection to Amazon, to AWS, or to
// object storage. That made it the FOURTH instance of the nl6#576 defect class —
// structurally identical to 53246/Mailteck — and the last foreign arc in the
// corpus.
//
// ── WHY 32473 AND NOT AN AMAZON PEN, which is the decision in this change ────
//
// 32473 is RFC 5612's "Example Enterprise Number for Documentation Use",
// registered to IANA itself. Amazon holds two real numbers — 4843 (Amazon.com
// Inc.) and 60099 (Amazon Web Services Inc) — and neither was chosen, DELIBERATELY.
//
// The DGX precedent does not transfer. For nl6#576, 5703 made sysObjectID
// unambiguously CORRECT: NVIDIA genuinely manufactures DGX systems, so a
// collector doing vendor detection got the right answer. Here there is no such
// fact. "AWS S3 Compatible Object Storage Gateway" names a CATEGORY — MinIO,
// Ceph RGW and others implement it — not a manufacturer, and AWS's own S3 is an
// HTTP service with no SNMP surface at all. Re-homing to 60099 would assert
// "Amazon manufactured this device", trading one misattribution for a more
// plausible one. The documentation PEN says instead that this device has no
// manufacturer, which is the true statement.
//
// The cost is real and is accepted: vendor detection now resolves this profile to
// nothing. That is why 32473 is a PER-PROFILE allowance in ownVendorPENs and not
// a globally permitted number — see TestOwnVendorPENMapIsCuratedAndComplete.
// Deleting the arc entirely was the third option and was not taken: sysObjectID.0
// is a scalar every collector reads, and answering noSuchObject for it is a
// bigger behaviour change than this issue asked for.
//
// ── which digests moved, MEASURED rather than assumed ───────────────────────
//
// One row changed and only one of the two golden corpus digests moved. Both
// halves were measured against the tree, not reasoned about:
//
//   - shippedTagDigest is keyed on (profile, OID, emitted tag). The OID KEY here
//     is sysObjectID.0, unchanged, and its tag is ASN1_OBJECT_ID before and
//     after, so the digest does NOT move. Confirmed by running the package with
//     the data edit applied: every tag-digest test and every tag-digest reversal
//     stayed green.
//   - shippedOIDEncodingDigest hashes each DISTINCT shipped OID NAME against its
//     BER encoding, and collectShippedOIDs gathers OID-typed VALUES into that set
//     too — because an OID-typed response reaches encodeOID. So the string
//     1.3.6.1.4.1.9999 left the set and 1.3.6.1.4.1.32473.1.1 entered it, and the
//     digest DOES move. Five tests fired, all of them on that one constant and its
//     chained reversals.
//
// This is the first link in the chain that moves ONE digest rather than both,
// which is worth saying out loud: the reversal below is a name-list rewrite only,
// and there is deliberately no value-map reversal, because there is no
// value-keyed digest for it to reproduce. If a future change adds one, this row
// has to join it — restoreNl6576NvidiaArc's reconstruction claims to rebuild the
// parent corpus and, for this one value, no longer does.
//
// The recorded oldValue was read OUT OF GIT at 87c642d08e0fff79b92d6a2d580bf70238763d4e
// (the merge of nl6#587, the revision this branch forked from) rather than
// retyped from the new tree — TestAWSPENLedgerValuesMatchTheParentRevision pins
// that, so the table cannot be "fixed" into agreeing with itself. That is the
// nl6#573 lesson.
//
// This ledger is the NEWEST link in the chain. Every older reversal starts from
// today's corpus, so each now begins by undoing this re-homing as well: the chain
// reads today -> 87c642d -> 1bca8e8 -> ec4700f -> 3a69927 -> 44ef67f.

// nl6588RehomedSysObjectIDs is the whole transition: one row.
//
// (profile, oid, oldValue, newValue). oldValue came from
// `git show 87c642d:go/nl6/resources/aws_s3_storage/aws_s3_storage.json`.
var nl6588RehomedSysObjectIDs = []struct{ profile, oid, oldValue, newValue string }{
	{"aws_s3_storage.json", ".1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.9999", "1.3.6.1.4.1.32473.1.1"},
}

// zernaArcPrefix is the arc aws_s3_storage's sysObjectID used to name. Spelled
// out once so every assertion about "the old arc" reads the same string.
//
// What is ENFORCED is narrower than "the digits appear nowhere": the number is
// written down deliberately as historical context — the profile's _comment, this
// file, the docs — and 1.3.6.1.4.1.9999 is also used as a deliberately-unassigned
// arc by several unrelated unit tests that build synthetic profiles in temp
// directories (snmp_hc_counter_table_test.go, snmpv3_getbulk_multicolumn_test.go).
// What no SHIPPED string may do is name it, in an OID key or an OID-typed value.
const zernaArcPrefix = ".1.3.6.1.4.1.9999"

// documentationArcPrefix is RFC 5612's example PEN, held by IANA.
//
// It is a LITERAL here rather than derived from ownVendorPENs, for the reason
// nvidiaArcPrefix is one: a test whose expectation follows the production table
// reports nothing when the table is the thing that moved.
const documentationArcPrefix = ".1.3.6.1.4.1.32473"

// shippedOIDEncodingDigestBeforeAWSPENRehome is the OID-name-to-encoding digest
// of the corpus at 87c642d — the value shippedOIDEncodingDigest held before this
// change, NOT re-derived from the re-homed tree.
//
//	live value                  declared in                    reversed by
//	shippedOIDEncodingDigest    snmp_oid_roundtrip_test.go     TestAWSPENRePinIsOnlyTheRehoming
//
// shippedTagDigest is deliberately absent from that table: it did not move (see
// the header).
const shippedOIDEncodingDigestBeforeAWSPENRehome = "40e4b72d4b5563f70dd7eb9d668ba4b2e49cdc762ddd4cb6ea1b19f5111537a4"

// nl6588ValueDigestAtParent is a SHA-256 over the sorted
// "profile\toid\toldValue" lines of every row this ledger records, as it existed
// at 87c642d.
//
// It was computed by reading the resource part OUT OF GIT at that revision
// (`git show 87c642d:<path>`), never from the table above, so comparing the table
// against it compares it with the tree as it actually was. A digest derived from
// the table would only prove the table equal to itself — and the re-homing
// removed the old value from the tree, so nothing else in the package has
// anything left to compare against.
const nl6588ValueDigestAtParent = "be5f333460dd04e5c7136da4d4d15fa80dc7cbc4c7e19a2d7974b4ce7910dcdf"

// nl6588OIDNamesBeforeRehome maps a list of shipped OID NAMES back to the
// spelling they had at 87c642d. It is the reversal every chained digest test
// begins with, applied BEFORE nl6576OIDNamesBeforeRehome since this change is the
// newer one.
//
// It is an EXACT-STRING swap, not a prefix rewrite, because exactly one string
// moved and a prefix rewrite would silently catch a future 32473 string that this
// change did not put there. TestAWSPENLedgerIsNotVacuous requires every shipped
// 32473 string to be one this ledger records, which is what keeps that exactness
// honest rather than merely narrow.
//
// Names here carry no leading dot: that is the spelling collectShippedOIDs
// gathers, since it reads the raw JSON strings.
func nl6588OIDNamesBeforeRehome(names []string) []string {
	back := map[string]string{}
	for _, r := range nl6588RehomedSysObjectIDs {
		back[r.newValue] = r.oldValue
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if old, ok := back[n]; ok {
			n = old
		}
		out = append(out, n)
	}
	return out
}

// TestAWSPENRePinIsOnlyTheRehoming is the before/after pin for the OID-NAME
// digest: un-rehome this change against today's corpus and 87c642d's value must
// come back byte for byte. It can only come back if nothing else about what a
// shipped OID puts on the wire has changed.
func TestAWSPENRePinIsOnlyTheRehoming(t *testing.T) {
	restored := nl6588OIDNamesBeforeRehome(collectShippedOIDs(t))
	sort.Strings(restored)

	h := sha256.New()
	checked := 0
	for _, oid := range restored {
		if strings.Contains(oid, "{{") {
			continue
		}
		checked++
		// hash.Hash.Write never returns an error, but errcheck cannot know that.
		_, _ = fmt.Fprintf(h, "%s=%x\n", oid, encodeOID(oid))
	}
	got := hex.EncodeToString(h.Sum(nil))

	if got != shippedOIDEncodingDigestBeforeAWSPENRehome {
		t.Errorf("un-rehoming the AWS sysObjectID gives digest %s, want the pre-change value %s "+
			"over %d OIDs.\nSo the re-pin of shippedOIDEncodingDigest is NOT explained by this "+
			"re-homing alone: something else about what a shipped OID puts on the wire has changed.",
			got, shippedOIDEncodingDigestBeforeAWSPENRehome, checked)
	}
	t.Logf("%d shipped OID names with the AWS sysObjectID un-rehomed reproduce the pre-change digest",
		checked)
}

// TestAWSPENLedgerValuesMatchTheParentRevision pins the recorded oldValue against
// the tree at 87c642d. Without it that value is unfalsifiable: the re-homing
// removed it from the tree, so nothing else in the package has anything left to
// compare against.
//
// If it fails after an edit to the table, the TABLE is wrong — the parent
// revision cannot change.
func TestAWSPENLedgerValuesMatchTheParentRevision(t *testing.T) {
	var lines []string
	for _, r := range nl6588RehomedSysObjectIDs {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", r.profile, r.oid, r.oldValue))
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	got := hex.EncodeToString(h.Sum(nil))

	if got != nl6588ValueDigestAtParent {
		t.Errorf("ledger value digest = %s, want %s (%d rows).\n"+
			"The recorded (profile, OID, old value) triples no longer match what 87c642d shipped. "+
			"Re-derive with: git show 87c642d:go/nl6/resources/aws_s3_storage/aws_s3_storage.json, "+
			"take the rows this ledger names, and hash sorted \"profile\\tOID\\tvalue\" lines. Do "+
			"not re-pin this constant to match an edited table: the parent revision is fixed.",
			got, nl6588ValueDigestAtParent, len(lines))
	}
	t.Logf("all %d recorded values match the corpus at 87c642d", len(lines))
}

// TestAWSPENLedgerIsNotVacuous guards the guard. An emptied ledger would make the
// reversal above pass only if the corpus were untouched, so the census is pinned
// and the SHAPE of the row is checked against the claim made about it.
//
// It is also the SOUNDNESS PRECONDITION for nl6588OIDNamesBeforeRehome being
// applied blanket in the five digest reversals that call it (this ledger's own plus
// the four older ones): every 32473 string in the corpus
// must be one this change put there, and no 9999 string may remain.
func TestAWSPENLedgerIsNotVacuous(t *testing.T) {
	if got, want := len(nl6588RehomedSysObjectIDs), 1; got != want {
		t.Errorf("the ledger records %d rows, want %d — the count is the census quoted in the "+
			"commit body and the docs, so it moves with them or not at all", got, want)
	}

	for _, r := range nl6588RehomedSysObjectIDs {
		if r.oid != ".1.3.6.1.2.1.1.2.0" {
			t.Errorf("%s: the ledger records %s, which is not sysObjectID.0", r.profile, r.oid)
		}
		if !underArc(normaliseOIDKey(r.oldValue), zernaArcPrefix) {
			t.Errorf("%s: ledger oldValue %s is not under the Zerna arc %s",
				r.profile, r.oldValue, zernaArcPrefix)
		}
		if !underArc(normaliseOIDKey(r.newValue), documentationArcPrefix) {
			t.Errorf("%s: ledger newValue %s is not under the documentation arc %s",
				r.profile, r.newValue, documentationArcPrefix)
		}
		// A re-homing must not move a tag. Both sides go through the ENCODER
		// rather than being reasoned about from oidTypeTable, since the encoder is
		// what decides the wire byte — and it is the measurement behind this
		// change's claim that shippedTagDigest does not move.
		encB, encA := encodeTypedValue(r.oid, r.oldValue), encodeTypedValue(r.oid, r.newValue)
		if len(encB) == 0 || len(encA) == 0 || encB[0] != encA[0] {
			t.Errorf("%s: %s emits % x for %q and % x for %q; a re-homing must be tag-neutral, "+
				"and this is what makes the shippedTagDigest claim above a measurement",
				r.profile, r.oid, encB, r.oldValue, encA, r.newValue)
		}
	}

	// NOTHING WAS ADDED AND NOTHING WAS DROPPED: every shipped string under
	// either arc must be accounted for by a ledger row. Scanned in BOTH positions
	// — a sysObjectID response is not an OID key, and that position is the whole
	// reason this defect existed.
	ledger := map[[2]string]string{}
	for _, r := range nl6588RehomedSysObjectIDs {
		ledger[[2]string{r.profile, r.oid}] = r.newValue
	}
	for _, h := range entriesTouchingArc(t, zernaArcPrefix) {
		t.Errorf("%s: %s reaches the wire under %s (as an OID %s: %s). 1.3.6.1.4.1.9999 is "+
			"allocated to Zerna, Koepper & Partner, a German engineering firm: a collector doing "+
			"vendor detection resolves this device as that company", h.part, h.oid, zernaArcPrefix,
			h.where, h.text)
	}
	served := map[string]int{}
	for _, h := range entriesTouchingArc(t, documentationArcPrefix) {
		served[h.where]++
		if h.where != "value" {
			t.Errorf("%s: %s names the documentation arc %s as an OID KEY. This change re-homed a "+
				"sysObjectID VALUE; it did not add objects under 32473", h.part, h.oid,
				documentationArcPrefix)
			continue
		}
		if want, ok := ledger[[2]string{h.profile, h.oid}]; !ok || want != h.text {
			t.Errorf("%s: %s answers %q under the documentation arc, which the ledger does not "+
				"record. An unrecorded 32473 string makes nl6588OIDNamesBeforeRehome's rewrite "+
				"incomplete: the four OLDER chained reversals would each leave it in place", h.part, h.oid, h.text)
		}
	}
	if got, want := served["value"], len(nl6588RehomedSysObjectIDs); got != want {
		t.Errorf("%d OID-typed values sit under %s, want %d. The arc was re-homed, not deleted: "+
			"sysObjectID.0 is a scalar every collector reads", got, documentationArcPrefix, want)
	}

	// And the rewrite really does move it, which is what makes the claim about
	// nl6588OIDNamesBeforeRehome a statement about the FUNCTION rather than about
	// a table that happens to sit next to it.
	// underArc, not strings.HasPrefix, on BOTH sides. A bare HasPrefix on
	// "1.3.6.1.4.1.9999" counts a hypothetical 99991 as moved and inflates the
	// figure, and one on "1.3.6.1.4.1.32473." (with the dot) lets a bare 32473
	// value escape the paired check below it. Same sub-identifier-boundary rule
	// the guard's arcPENOf enforces — a ledger that measures the transition it
	// records must not measure it more loosely than the guard reads it.
	moved := 0
	for i, back := range nl6588OIDNamesBeforeRehome(collectShippedOIDs(t)) {
		if underArc(normaliseOIDKey(back), zernaArcPrefix) {
			moved++
		}
		if underArc(normaliseOIDKey(back), documentationArcPrefix) {
			t.Errorf("nl6588OIDNamesBeforeRehome left entry %d as %q, still under the documentation arc",
				i, back)
		}
	}
	if want := len(nl6588RehomedSysObjectIDs); moved != want {
		t.Errorf("the rewrite moved %d strings, want %d", moved, want)
	}
}

// TestAWSSysObjectIDIsAnsweredAtTheNewArc fires on the DEFECT rather than on a
// digest. The corpus digests' documented remedy is to RE-PIN, so a tree that
// edited the JSON in a way that stopped it loading — or that dropped the scalar
// altogether — would show up as "update the golden value" while the device
// answered nothing for sysObjectID.
//
// It also pins the profile's OTHER scalars, because the _comment key this change
// added sits at the top level of the same part and the decoder is non-strict: if
// that convention ever broke, the symptom would be a profile that loads with no
// data at all (TestUnknownTopLevelKeysAreInert is the general pin; this is the
// live one).
func TestAWSSysObjectIDIsAnsweredAtTheNewArc(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("aws_s3_storage.json")
	if err != nil {
		t.Fatalf("LoadSpecificResources(aws_s3_storage.json): %v", err)
	}
	srv := &SNMPServer{device: &DeviceSimulator{
		ID:           "aws-pen-pin",
		resources:    res,
		resourceFile: "aws_s3_storage.json",
	}}

	for _, r := range nl6588RehomedSysObjectIDs {
		switch got := srv.findResponse(r.oid); {
		case isSNMPExceptionValue(got):
			t.Errorf("%s: %s is unanswered (%q). The arc was re-homed here, not deleted; do NOT "+
				"re-pin a corpus digest to absorb this", r.profile, r.oid, got)
		case got != r.newValue:
			t.Errorf("%s: %s answers %q, want %q", r.profile, r.oid, got, r.newValue)
		}
	}

	// The rest of the part still loads, so the _comment key really is inert here
	// and not merely in a synthetic fixture.
	if got, want := srv.findResponse(".1.3.6.1.2.1.1.1.0"), "AWS S3 Compatible Object Storage Gateway"; got != want {
		t.Errorf("sysDescr.0 answers %q, want %q — the part carrying the new _comment no longer "+
			"loads its data", got, want)
	}
	// sysName.0 and sysLocation.0 are deliberately NOT read back here even though
	// the part ships both: they are served outside the resource map (the CSV
	// worldcities dataset and the generated device name), so findResponse answers
	// "" for them on a device built without that wiring. That is a property of the
	// serve path, not of this part loading.
}

// TestAWSPENArcsMatchTheIANARegistry is the premise, and it is the one assertion
// here that is about the WORLD rather than about the corpus: 9999 belongs to an
// uninvolved company and 32473 is the documentation number.
//
// Getting it backwards would fail nothing else in the package — the ledger would
// reverse cleanly, the digest would reproduce, the serve path would answer — and
// the fleet would go on identifying a simulated storage gateway as somebody's
// engineering consultancy. Same reasoning as
// TestArcPrefixesMatchTheIANARegistry, over the two rows this change turns on.
func TestAWSPENArcsMatchTheIANARegistry(t *testing.T) {
	const penRoot = ".1.3.6.1.4.1."

	byRole := map[string]ianaPENEntry{}
	for _, e := range readIANAPENFixture(t) {
		byRole[e.role] = e
	}

	for _, tc := range []struct {
		role, arc, wantOrg, why string
	}{
		{
			role: "zerna", arc: zernaArcPrefix,
			wantOrg: "Zerna, Koepper & Partner",
			why: "this is the arc aws_s3_storage's sysObjectID used to name, and the reason it " +
				"moved. If this row is not a company unrelated to Amazon and to storage, the defect " +
				"nl6#588 reports did not exist",
		},
		{
			role: "iana-doc", arc: documentationArcPrefix,
			wantOrg: "Example Enterprise Number for Documentation Use",
			why: "this is the arc the profile answers with now. It was chosen BECAUSE it belongs " +
				"to nobody in particular: the profile models a category, not a manufacturer. If it " +
				"turned out to be a real company's number, the re-homing would have repeated the " +
				"defect it fixes",
		},
	} {
		e, ok := byRole[tc.role]
		if !ok {
			t.Fatalf("%s carries no row with role %q", ianaPENFixture, tc.role)
		}
		if got := penRoot + e.pen; got != tc.arc {
			t.Errorf("the %s constant is %s, but the registry gives PEN %s for %s (%s). %s",
				tc.role, tc.arc, e.pen, e.org, got, tc.why)
		}
		if e.org != tc.wantOrg {
			t.Errorf("the registry gives PEN %s to %q, and this change was made on the reading that "+
				"it belongs to %q. Re-fetch the registry: %s", e.pen, e.org, tc.wantOrg, tc.why)
		}
	}

	// The two must be DIFFERENT owners, which is the defect in one line, and the
	// new one must be the number the profile actually claims.
	if byRole["zerna"].org == byRole["iana-doc"].org {
		t.Errorf("the fixture gives both PENs to %q, so there was nothing to re-home",
			byRole["zerna"].org)
	}
	if got := penRoot + ownVendorPENs["aws_s3_storage.json"].pen; got != documentationArcPrefix {
		t.Errorf("ownVendorPENs allows %s for aws_s3_storage.json, but this ledger re-homed it to "+
			"%s; the guard and the ledger disagree about what the profile serves",
			got, documentationArcPrefix)
	}
}
