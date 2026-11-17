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

// nl6#1031 serves sysUpTime.0 (1.3.6.1.2.1.1.3.0) LIVE from the device's boot
// instant: findResponseAt and findNextOIDWithServed answer it from
// liveSysUpTime (sysuptime.go) ahead of the static index on every device that
// has a boot instant, and initDeviceCyclers stamps one on every device both
// creation paths build. So the static sysUpTime.0 row 26 shipped profiles
// carried is DEAD DATA on every production device, exactly like the static
// ifTable .10 / .16 rows nl6#570 deleted once the cycler owned those columns:
// the live value always wins and the row is never read.
//
// DELETED, NOT CORRECTED. No static value is right for a clock: a constant
// sysUpTime.0 is a device that never ages, which is the defect nl6#1031 fixes,
// and replacing one constant with another would ship the same defect at a
// different number. Same reasoning that deleted writeMem in nl6#591. The
// compiled-in fallback in createDefaultResources lost its row for the same
// reason; it is not part of the shipped corpus, so it is not recorded here.
//
// hrSystemUptime.0 (1.3.6.1.2.1.25.1.1.0) is a different object (the host's
// uptime, not the agent's) and is out of scope: it still ships where it did.
//
// ── why there is a ledger at all ────────────────────────────────────────────
//
// Both golden corpus digests move, and WHICH ones move was MEASURED by applying
// the deletion and running the suite, not predicted:
//
//   - shippedTagDigest is keyed on (profile, OID, emitted tag). 26 triples are
//     removed outright, so it moves.
//   - shippedOIDEncodingDigest hashes each DISTINCT shipped OID NAME against its
//     BER encoding. 1.3.6.1.2.1.1.3.0 was served by these 26 profiles and by
//     nothing else in the corpus: no other profile, and no trap catalog names it
//     (the trap encoder PREPENDS sysUpTime.0, and the catalog loader refuses it
//     as a body varbind). So the name leaves entirely and this digest moves too,
//     which TestSysUpTimeNameLeftTheCorpus measures rather than assumes.
//
// Every recorded oldValue was read OUT OF GIT at 068e486 (the revision this
// branch forked from) with `git show 068e486:go/nl6/resources/<type>/<part>`,
// never retyped from the working tree, and TestSysUpTimeLedgerValuesMatchTheParentRevision
// pins the table against a digest of that read, so the table cannot be "fixed"
// into agreeing with itself. That is the nl6#573 lesson.
//
// 068e486 is the revision this branch FORKED FROM, not HEAD~1: the branch was
// later rebased onto 5a4b022, whose resource corpus is byte-identical to
// 068e486's (`git diff --quiet 068e486 5a4b022 -- go/nl6/resources`) and whose
// two corpus digests are the same values, so the ledger and its before-digests
// still describe the same transition.
//
// asr9k's recorded value is 272922827, the value nl6#541 rescaled it to from
// 4567890123 (which overflowed TimeTicks). This reversal runs BEFORE nl6#541's
// in the chain, so restoring it is what lets that older ledger still find its
// row.

// sysUpTimeDeletionParentRevision is the revision this change forked from and the
// one its two golden digests below were taken at. It is spelled once and read by
// both the tests here and this change's entry in newestFirstReversals.
const sysUpTimeDeletionParentRevision = "068e486"

// The two "before" digests are the values shippedTagDigest
// (snmp_hc_counter_table_test.go) and shippedOIDEncodingDigest
// (snmp_oid_roundtrip_test.go) held at 068e486, NOT re-derived from the edited
// tree. Reversed by TestSysUpTimeDeletionReproducesTheParentCorpus and
// TestSysUpTimeRePinIsOnlyTheDeletion respectively.
const (
	shippedTagDigestBeforeSysUpTimeDeletion         = "2af12a0da73bde2ed9228e45c0a23916d2d23904cd085a24fc1ae6fae5206238"
	shippedOIDEncodingDigestBeforeSysUpTimeDeletion = "1d1e3b7b6da9cf037b87599cd8e7a86553ce4dd79a1019312e35e45bf3225005"
)

// sysUpTimeDeletedEntries are the 26 shipped entries this change
// removed: one sysUpTime.0 row per profile, read out of git at 068e486.
//
// DO NOT restore any row with a "better" number: the value is served live, and
// a static row is dead data whatever it holds.
var sysUpTimeDeletedEntries = []struct{ profile, oid, oldValue string }{
	{"arista_7280r3.json", ".1.3.6.1.2.1.1.3.0", "663004100"},
	{"asr9k.json", ".1.3.6.1.2.1.1.3.0", "272922827"},
	{"check_point_15600.json", ".1.3.6.1.2.1.1.3.0", "0"},
	{"ciena_waveserver5.json", ".1.3.6.1.2.1.1.3.0", "418302700"},
	{"cisco_asr9902.json", ".1.3.6.1.2.1.1.3.0", "272922827"},
	{"cisco_catalyst_9500.json", ".1.3.6.1.2.1.1.3.0", "393084300"},
	{"cisco_crs_x.json", ".1.3.6.1.2.1.1.3.0", "1451548800"},
	{"cisco_ios.json", ".1.3.6.1.2.1.1.3.0", "123456789"},
	{"cisco_nexus_9500.json", ".1.3.6.1.2.1.1.3.0", "854932500"},
	{"dell_poweredge_r750.json", ".1.3.6.1.2.1.1.3.0", "755923600"},
	{"dlink_dgs3630.json", ".1.3.6.1.2.1.1.3.0", "673094400"},
	{"extreme_vsp4450.json", ".1.3.6.1.2.1.1.3.0", "1077732000"},
	{"fortinet_fortigate_600e.json", ".1.3.6.1.2.1.1.3.0", "394825200"},
	{"hpe_proliant_dl380.json", ".1.3.6.1.2.1.1.3.0", "295350000"},
	{"huawei_ne8000.json", ".1.3.6.1.2.1.1.3.0", "1755915800"},
	{"ibm_power_s922.json", ".1.3.6.1.2.1.1.3.0", "1257854600"},
	{"juniper_mx10004.json", ".1.3.6.1.2.1.1.3.0", "200149500"},
	{"juniper_mx240.json", ".1.3.6.1.2.1.1.3.0", "200149500"},
	{"juniper_mx960.json", ".1.3.6.1.2.1.1.3.0", "1348753300"},
	{"nec_ix3315.json", ".1.3.6.1.2.1.1.3.0", "1253724700"},
	{"nokia_7750_sr12.json", ".1.3.6.1.2.1.1.3.0", "769593300"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.2.1.1.3.0", "187654300"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.2.1.1.3.0", "234567800"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.2.1.1.3.0", "145678900"},
	{"palo_alto_pa3220.json", ".1.3.6.1.2.1.1.3.0", "1098064500"},
	{"sonicwall_nsa6700.json", ".1.3.6.1.2.1.1.3.0", "485547000"},
}

// sysUpTimeValueDigestAtParent is a SHA-256 over the sorted "profile\toid\toldValue"
// lines of every row this ledger records, as they existed at 068e486.
//
// It was computed by reading every resource part OUT OF GIT at that revision
// (`git ls-tree -r 068e486 go/nl6/resources` and `git show 068e486:<path>` per
// part, collecting each snmp row whose normalised OID is .1.3.6.1.2.1.1.3.0),
// never from the table above, so comparing the table against it compares it
// with the tree as it actually was. This change removed every row, so nothing
// else in the package has anything left to compare against.
const sysUpTimeValueDigestAtParent = "95ca7fa109c6c247f64940696d6483a67019cf435cb8077e0359e5c1c80a6593"

// restoreSysUpTimeDeletion reverses this change against a (profile, OID) ->
// value map, so the map afterwards is the corpus as 068e486 shipped it. Fatal
// on any row that still ships (reverseProfileEdits' editDel contract).
func restoreSysUpTimeDeletion(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	if len(sysUpTimeDeletedEntries) == 0 {
		t.Fatal("nl6#1031 sysUpTime deletion: empty ledger; a reversal that restores nothing is vacuous")
	}
	for _, d := range sysUpTimeDeletedEntries {
		reverseProfileEdits(t, cur, d.profile, "nl6#1031 sysUpTime deletion",
			[]profileRowEdit{{op: editDel, oid: d.oid, before: d.oldValue}})
	}
}

// sysUpTimeVanishedOIDNames are the OID names this change removed from the corpus
// ENTIRELY, in the undotted spelling collectShippedOIDs gathers. Derived from the
// deletion ledger, so the two views cannot drift, and pinned against the live
// corpus by TestSysUpTimeNameLeftTheCorpus.
func sysUpTimeVanishedOIDNames() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, d := range sysUpTimeDeletedEntries {
		o := strings.TrimPrefix(d.oid, ".")
		if _, dup := seen[o]; dup {
			continue
		}
		seen[o] = struct{}{}
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// sysUpTimeOIDNamesBeforeDeletion maps a list of shipped OID NAMES back to the
// set 068e486 shipped. It is the name-view counterpart of
// restoreSysUpTimeDeletion, registered as this change's link in
// newestFirstReversals.
func sysUpTimeOIDNamesBeforeDeletion(t *testing.T, names []string) []string {
	t.Helper()
	return appendVanishedOIDNames(t, "nl6#1031 sysUpTime deletion", names, sysUpTimeVanishedOIDNames())
}

// TestSysUpTimeDeletionReproducesTheParentCorpus is the before/after pin for the
// TAG digest: reverse the ledger against today's corpus and 068e486's value must
// come back.
func TestSysUpTimeDeletionReproducesTheParentCorpus(t *testing.T) {
	got := corpusTagDigestAt(t, corpusValuesAt(t, sysUpTimeDeletionParentRevision), sysUpTimeDeletionParentRevision)
	if got != shippedTagDigestBeforeSysUpTimeDeletion {
		t.Errorf("reversing the sysUpTime.0 deletion gives digest %s, want %s: another shipped row "+
			"changed without being recorded", got, shippedTagDigestBeforeSysUpTimeDeletion)
	}
}

// TestSysUpTimeRePinIsOnlyTheDeletion does the same job for the OID-NAME digest,
// which the tag digest cannot see.
func TestSysUpTimeRePinIsOnlyTheDeletion(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), sysUpTimeDeletionParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeSysUpTimeDeletion {
		t.Errorf("restoring the sysUpTime.0 OID name gives digest %s, want the pre-change value %s: "+
			"the re-pin of shippedOIDEncodingDigest is NOT explained by this deletion alone",
			got, shippedOIDEncodingDigestBeforeSysUpTimeDeletion)
	}
}

// TestSysUpTimeLedgerValuesMatchTheParentRevision pins the ledger's recorded old
// values against the tree at 068e486. If it fails after an edit to the table,
// the table is wrong: the parent revision cannot change.
func TestSysUpTimeLedgerValuesMatchTheParentRevision(t *testing.T) {
	var lines []string
	for _, d := range sysUpTimeDeletedEntries {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", d.profile, d.oid, d.oldValue))
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sysUpTimeValueDigestAtParent {
		t.Errorf("ledger value digest = %s, want %s (%d rows).\n"+
			"The recorded (profile, OID, old value) triples no longer match what 068e486 shipped. "+
			"Re-derive by reading every resource part with `git show 068e486:<path>`, collecting "+
			"the sysUpTime.0 rows, and hashing sorted \"profile\\tOID\\tvalue\" lines. Do not re-pin "+
			"this constant to match an edited table: the parent revision is fixed.",
			got, sysUpTimeValueDigestAtParent, len(lines))
	}
}

// TestSysUpTimeLedgerIsNotVacuous guards the guard: the census is pinned and the
// shape of every row is checked against the claim made about it.
func TestSysUpTimeLedgerIsNotVacuous(t *testing.T) {
	if got, want := len(sysUpTimeDeletedEntries), 26; got != want {
		t.Errorf("nl6#1031 deleted entries: ledger has %d rows, want %d", got, want)
	}
	if got, want := len(sysUpTimeVanishedOIDNames()), 1; got != want {
		t.Errorf("nl6#1031 names that vanished corpus-wide: %d, want %d", got, want)
	}
	seen := map[string]bool{}
	for _, d := range sysUpTimeDeletedEntries {
		if d.oid != sysUpTimeOID {
			t.Errorf("%s %s is in the nl6#1031 ledger but is not sysUpTime.0 (%s)", d.profile, d.oid, sysUpTimeOID)
		}
		if seen[d.profile] {
			t.Errorf("%s appears twice in the nl6#1031 ledger; each profile carried one row", d.profile)
		}
		seen[d.profile] = true
		// Every old value encoded as TimeTicks: the rows were dead, not
		// malformed, which is why the reason is liveness and not encodability.
		if enc := encodeTypedValue(d.oid, d.oldValue); len(enc) == 0 || enc[0] != ASN1_TIMETICKS {
			t.Errorf("%s %s: old value %q emits % x, want tag 0x%02X", d.profile, d.oid, d.oldValue, enc, ASN1_TIMETICKS)
		}
	}
}

// TestSysUpTimeNameLeftTheCorpus makes "the name vanished entirely" a
// measurement, and is also the guard against a static sysUpTime.0 row coming
// back: collectShippedOIDs walks every resource part and both catalogs, so any
// shipped file naming the OID fails here.
func TestSysUpTimeNameLeftTheCorpus(t *testing.T) {
	shipped := map[string]struct{}{}
	for _, o := range collectShippedOIDs(t) {
		shipped[strings.TrimPrefix(o, ".")] = struct{}{}
	}
	for _, o := range sysUpTimeVanishedOIDNames() {
		if _, ok := shipped[o]; ok {
			t.Errorf("%s is named by a shipped resource or catalog again. sysUpTime.0 is served live "+
				"from the device's boot instant (nl6#1031), so a static row is dead data; delete it "+
				"rather than re-pinning the corpus digests", o)
		}
	}
}
