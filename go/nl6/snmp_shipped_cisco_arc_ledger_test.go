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
	"strconv"
	"strings"
	"testing"
)

// nl6#590 is the first VENDOR-ARC MIB AUDIT: nl6#587 and nl6#589 closed the
// identity question (every profile serves only its own PEN), and this change
// starts on the harder one — whether the objects below a correct PEN exist and
// mean what the profile says they mean. The Cisco arc went first because it is
// the largest (39 resource OIDs across five profiles) and because Cisco's MIBs
// are the only ones obtainable anonymously and authoritatively, from Cisco's own
// github.com/cisco/cisco-mibs repository.
//
// ── what was read, and what was NOT ─────────────────────────────────────────
//
// Four modules were consulted, each cited by name and revision so the reading can
// be repeated: CISCO-ENVMON-MIB (201803210000Z), CISCO-MEMORY-POOL-MIB
// (201309180000Z), CISCO-IMAGE-MIB (9508150000Z), CISCO-SYSTEM-EXT-MIB
// (201606140000Z), with ciscoMgmt = 1.3.6.1.4.1.9.9 resolved out of CISCO-SMI.
//
// NO MIB FILE OR EXTRACTED FIXTURE IS CHECKED IN, and that is a decision rather
// than an omission. nl6#541's testdata/mibs/ fixtures are IETF standards-track
// modules; a vendor MIB is a different legal object. The nl6#590 obtainability
// research found no published redistribution grant for any of nineteen vendors —
// Cisco's own header asserts copyright and grants nothing — and LibreNMS, which
// has shipped vendor MIBs for years, classifies its own MIB tree as a
// GPL-non-compliant component rather than claiming the right. So each audit is
// recorded as a PINNED READING (TestCiscoEnvMonAndMemoryPoolMatchTheMIB below,
// the TestPaloAltoPANSubtreeMatchesTheMIB shape) and never as a live check. The
// asymmetry is the point: if the licensing question later resolves permissively a
// fixture can be added, and if it resolves restrictively nothing has to be
// removed.
//
// ── the audit's result ──────────────────────────────────────────────────────
//
// THE ARITHMETIC IS STATED IN TWO VIEWS BECAUSE MIXING THEM IS HOW THIS CHANGE
// FIRST GOT IT WRONG. A first cut reported "3 of 13" while counting
// ciscoEnvMonFanStatusDescr.1 twice, once as a deleted OID and once as a kept
// ENTRY. Both counts below are recomputed from the corpus by
// TestCiscoArcCensusMatchesTheCorpus rather than asserted here.
//
// DISTINCT OIDs. The parent revision shipped 21 distinct Cisco OID keys in
// resource snmp arrays. 13 sit under ciscoMgmt (1.3.6.1.4.1.9.9) and were
// audited; 8 sit on the OLD-CISCO arcs and were not (see below). Of the 13:
// TWO were right as shipped (ciscoImageString, cseSysCPUUtilization), FIVE were
// corrected and SIX were deleted. ciscoEnvMonFanStatusDescr.1 is counted ONCE,
// under corrected: it was deleted from cisco_catalyst_9500, where it named a
// supervisor module, and corrected in the three profiles that valued it "1".
// So 11 of 13 audited OIDs were wrong, against nl6#569's 8 of 11 on the Palo
// Alto subtree — like for like, both counting distinct OIDs, and the second
// measurement of how faithful an unaudited vendor subtree is.
//
// ENTRIES. 39 shipped entries name a Cisco OID; 23 of them sit on the 13 audited
// OIDs. 8 were deleted, 10 were corrected and 5 were left exactly as shipped (the
// four ciscoImageString rows and the one cseSysCPUUtilization row).
//
// UNAUDITED, and the reason differs per OID — an earlier draft of this file
// attributed all eight to one unobtainable module, which was wrong:
//
//   - 1.3.6.1.4.1.9.3.6.3.0 and .9.3.6.1.1.4.1.2.1, and .9.5.1.2.2.1.0 and
//     .9.5.1.3.1.1.5.1: genuinely unresolvable here. OLD-CISCO-CHASSIS-MIB was
//     not obtainable in this run.
//   - 1.3.6.1.4.1.9.2.1.56.0 and .58.0: RESOLVABLE and not audited. They are
//     busyPer and avgBusy5 in OLD-CISCO-CPU-MIB, which WAS obtained; both ship
//     plausible percentages and neither was checked further.
//   - 1.3.6.1.4.1.9.2.1.54.0: RESOLVABLE, and it was a live defect. It is
//     writeMem in OLD-CISCO-SYSTEM-MIB, ACCESS write-only — an action object that
//     saves the running configuration — and nl6 answered it with a large number.
//     Filed as nl6#591 rather than fixed here, and CLOSED there: both entries are
//     deleted and the reading lives in
//     snmp_shipped_cisco_writeonly_ledger_test.go. It is a different defect CLASS
//     from anything this ledger records, which is why it is a separate change.
//   - 1.3.6.1.4.1.9.2.1.8.0: not defined in the OLD-CISCO-SYSTEM-MIB copy
//     obtained (a v2 conversion that drops the deprecated memory objects).
//
// docs/reference/snmp.md carries the same split, so the gap is a recorded fact
// rather than an assumption that all eight were unexaminable.
//
// ── why there is a ledger at all ────────────────────────────────────────────
//
// Both golden corpus digests move, and each has to move for only the intended
// reason. Which ones move was MEASURED by applying the data edits and running the
// suite, not predicted:
//
//   - shippedTagDigest is keyed on (profile, OID, emitted tag). Eight triples are
//     removed outright and NINE of the ten corrections move a tag, so it moves.
//     Every one of those nine is the same defect: a bare number on a DisplayString
//     leaf, which encodeTypedValue emits as an INTEGER ("1100" on
//     ciscoMemoryPoolName, "1" on ciscoEnvMonFanStatusDescr and
//     ciscoEnvMonSupplyStatusDescr). Only the temperature-sensor description was
//     already an OCTET STRING and stays one.
//   - shippedOIDEncodingDigest hashes each DISTINCT shipped OID NAME against its
//     BER encoding. It moves too, but by FIVE names, not seven: two of the seven
//     deleted names still ship elsewhere in the corpus, which is the sort of thing
//     that has to be measured rather than reasoned about. See
//     nl6590SurvivingDeletedNames.
//
// Every recorded oldValue was read OUT OF GIT at 5bded6c (the revision this
// branch forked from) rather than retyped from the working tree —
// TestCiscoArcLedgerValuesMatchTheParentRevision pins that, so the table cannot
// be "fixed" into agreeing with itself. That is the nl6#573 lesson.
//
// This ledger WAS the newest link in the chain; nl6#591's writeMem removal
// (snmp_shipped_cisco_writeonly_ledger_test.go) has since taken that place, so
// every reversal here now begins by undoing THAT change first. Every older
// ledger reverses to its own parent starting from today's corpus, so each of them
// begins by undoing nl6#591 and then this change: the chain reads
// today -> f47c85d -> 5bded6c -> 87c642d -> 1bca8e8 -> ec4700f -> 3a69927 -> 44ef67f.

// nl6590DeletedCiscoEntries are the eight shipped entries this change removed.
// Seven distinct OIDs; ciscoEnvMonTemperatureStatusValue.1 was served by two
// profiles.
//
// The four ciscoEnvMonFanStatusTable rows were the ONLY rows of that table in
// cisco_catalyst_9500, so deleting them leaves the profile modelling no fans.
// That is correct and intended, exactly as nl6#571 left four profiles modelling
// no storage: a collector that gets nothing learns the truth about a profile that
// does not model fans, while a collector that gets "C9300-SUP-1" from
// ciscoEnvMonFanStatusDescr is told a supervisor module is a fan. DO NOT restore
// a row to make the table non-empty.
var nl6590DeletedCiscoEntries = []struct{ profile, oid, oldValue string }{
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.13.1.3.1.3.1", "CAT9500-001"},
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.13.1.4.1.2.1", "C9300-SUP-1"},
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.13.1.4.1.2.2", "C9300-48T"},
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.13.1.4.1.3.1", "Supervisor Module"},
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.13.1.4.1.3.2", "48-Port Gigabit Line Card"},
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.48.1.1.1.3.1", "PWR-C1-1100WAC"},
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.48.1.1.1.3.2", "PWR-C1-1100WAC"},
	{"cisco_nexus_9500.json", ".1.3.6.1.4.1.9.9.13.1.3.1.3.1", "39"},
}

// nl6590ValueCorrections are the ten entries that stayed but changed value.
// Nine move the emitted tag, which is why this table records tags and
// TestCiscoArcLedgerIsNotVacuous asserts them against the encoder rather than
// against oidTypeTable — a bare number on a DisplayString leaf is invisible until
// you ask the encoder what it emits.
var nl6590ValueCorrections = []struct {
	profile, oid, oldValue, newValue string
	oldTag, newTag                   byte
}{
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.13.1.3.1.2.1",
		"Catalyst 9500 Switch", "Chassis Inlet Temp Sensor", ASN1_OCTET_STRING, ASN1_OCTET_STRING},
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.48.1.1.1.2.1",
		"1100", "Processor", ASN1_INTEGER, ASN1_OCTET_STRING},
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.48.1.1.1.2.2",
		"1100", "I/O", ASN1_INTEGER, ASN1_OCTET_STRING},

	// The seven rows below are the same defect as the two above, found by the
	// nl6#590 review after the first cut of this change had decided to leave them
	// alone as "weak but legal". They are not legal. Both objects are
	// DisplayString (SIZE (0..32)) and both answered a bare "1", which
	// encodeTypedValue emits as tag 0x02 INTEGER — measured, not reasoned about,
	// which is the point: judging a value by whether it "looks like a string"
	// misses exactly this, and the first cut did.
	//
	// CORRECTED RATHER THAN DELETED, and for ciscoEnvMonSupplyStatusDescr the
	// evidence is inside the profile itself. resources/cisco_ios/traps.json fires
	// ciscoEnvMonSupplyStatusChangeNotif carrying
	//
	//	1.3.6.1.4.1.9.9.13.1.5.1.2.1  octet-string  "PWR-{{.Serial}}"
	//	1.3.6.1.4.1.9.9.13.1.5.1.3.1  integer       1
	//
	// so one profile modelled ONE OID as TWO TYPES depending on whether you polled
	// it or received its trap. Deleting the static row would leave a device sending
	// a trap that names an object it refuses to answer when polled, which is worse
	// than either state; correcting it is what makes poll and trap agree.
	//
	// THE TWO CALLS ARE NOT EQUALLY STRONG and the difference is recorded rather
	// than smoothed over. The SUPPLY correction is settled by that contradiction.
	// The FAN correction rests on consistency alone: no trap references any fan
	// object, so nothing independent says what ciscoEnvMonFanStatusDescr should
	// hold. It is corrected because splitting two sibling columns of the same MIB
	// family, both DisplayString, both valued "1", would need a principle and there
	// is none.
	//
	// The replacements are generic POSITIONAL descriptions, deliberately. A part
	// number or a model name would be the nl6#569 defect in the other direction
	// (inventing hardware the profile does not model), and the object describes the
	// component being instrumented, not its identity. The trap's own
	// "PWR-{{.Serial}}" is that profile's convention for the same object; a
	// positional description agrees with it in TYPE without copying a templated
	// serial into static data.
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.13.1.5.1.2.1",
		"1", "Power Supply 1", ASN1_INTEGER, ASN1_OCTET_STRING},
	{"cisco_crs_x.json", ".1.3.6.1.4.1.9.9.13.1.4.1.2.1",
		"1", "Fan 1", ASN1_INTEGER, ASN1_OCTET_STRING},
	{"cisco_crs_x.json", ".1.3.6.1.4.1.9.9.13.1.5.1.2.1",
		"1", "Power Supply 1", ASN1_INTEGER, ASN1_OCTET_STRING},
	{"cisco_ios.json", ".1.3.6.1.4.1.9.9.13.1.4.1.2.1",
		"1", "Fan 1", ASN1_INTEGER, ASN1_OCTET_STRING},
	{"cisco_ios.json", ".1.3.6.1.4.1.9.9.13.1.5.1.2.1",
		"1", "Power Supply 1", ASN1_INTEGER, ASN1_OCTET_STRING},
	{"cisco_nexus_9500.json", ".1.3.6.1.4.1.9.9.13.1.4.1.2.1",
		"1", "Fan 1", ASN1_INTEGER, ASN1_OCTET_STRING},
	{"cisco_nexus_9500.json", ".1.3.6.1.4.1.9.9.13.1.5.1.2.1",
		"1", "Power Supply 1", ASN1_INTEGER, ASN1_OCTET_STRING},
}

// nl6590SurvivingDeletedNames are the two deleted OID NAMES that are still
// somewhere in the corpus after this change, and therefore contribute nothing to
// the shippedOIDEncodingDigest reversal. Both survive for a different reason and
// neither is guessable from the deletion table, which is why they are written
// down and pinned against the live corpus by
// TestCiscoArcVanishedNamesAreMeasured:
//
//   - ciscoEnvMonFanStatusDescr.1 is deleted from cisco_catalyst_9500 only;
//     cisco_crs_x, cisco_ios and cisco_nexus_9500 still serve it (valued "1",
//     which is weak but a legal DisplayString — see the reading test).
//   - ciscoEnvMonTemperatureStatusValue.1 is deleted from BOTH profiles that
//     shipped it as a resource row, but resources/cisco_ios/traps.json names it
//     as a trap varbind, and collectShippedOIDs walks the trap catalogs too. In
//     the trap it is declared "gauge32" and valued "75", which is what the MIB
//     says it is; the defect was the RESOURCE rows, not the trap.
var nl6590SurvivingDeletedNames = map[string]string{
	"1.3.6.1.4.1.9.9.13.1.4.1.2.1": "still served by cisco_crs_x, cisco_ios and cisco_nexus_9500",
	"1.3.6.1.4.1.9.9.13.1.3.1.3.1": "still named as a trap varbind in resources/cisco_ios/traps.json",
}

// The two "before" digests live HERE rather than beside the live constants they
// chain onto, matching the nl6#576 ledger. The cross-reference is written down
// instead of left for a reader to discover:
//
//	live value                  declared in                       reversed by
//	shippedTagDigest            snmp_hc_counter_table_test.go     TestCiscoArcAuditReproducesTheParentCorpus
//	shippedOIDEncodingDigest    snmp_oid_roundtrip_test.go        TestCiscoArcRePinIsOnlyTheAudit
//
// Both live constants carry a comment naming this file and these two tests, so
// the chain can be followed from either end.

// shippedTagDigestBeforeCiscoArcAudit is the (profile, OID, emitted tag) digest
// of the corpus at 5bded6c — the value shippedTagDigest held before this change,
// NOT re-derived from the audited tree.
const shippedTagDigestBeforeCiscoArcAudit = "fa776c654f5b88fd1e429d1bcd0d2758613273ee80a22f0239d2c4097ac24bb2"

// shippedOIDEncodingDigestBeforeCiscoArcAudit is the OID-name-to-encoding digest
// at the same revision, and the same rule applies to it. It is also the newest
// entry in snmp_oid_roundtrip_test.go's historical run.
const shippedOIDEncodingDigestBeforeCiscoArcAudit = "dd5e1327b5f8dab9d30ca089bfe7309b903f53c4b02789e47ee85f6b56bedcbd"

// nl6590ValueDigestAtParent is a SHA-256 over the sorted "profile\toid\toldValue"
// lines of every row this ledger records, as they existed at 5bded6c.
//
// It was computed by reading the five resource parts OUT OF GIT at that revision
// (`git show 5bded6c:<path>`), never from the tables above, so comparing the
// tables against it compares them with the tree as it actually was. For the eight
// deleted rows nothing else in the package has anything left to compare against.
const nl6590ValueDigestAtParent = "d67b0cc657c7f7685d82856fb9878da2ecc6a20c3242f0493c891ef97925eb9c"

// restoreNl6590CiscoArc reverses this change against a (profile, OID) -> value
// map, so the map afterwards is the corpus as 5bded6c shipped it. Shared with
// every older ledger reversal, whose own starting point is the tree this one
// reconstructs.
//
// EVERY DISAGREEMENT IS FATAL, for the reason restoreNl6576NvidiaArc gives: a
// reversal that carries on past a corpus it does not recognise buries its own
// diagnosis under the caller's opaque digest mismatch.
func restoreNl6590CiscoArc(t *testing.T, cur map[[2]string]string) {
	t.Helper()

	for _, d := range nl6590DeletedCiscoEntries {
		k := [2]string{d.profile, d.oid}
		if got, ok := cur[k]; ok {
			t.Fatalf("%s %s is in the nl6#590 removal ledger but still ships, valued %q",
				d.profile, d.oid, got)
		}
		cur[k] = d.oldValue
	}
	for _, c := range nl6590ValueCorrections {
		k := [2]string{c.profile, c.oid}
		got, ok := cur[k]
		if !ok {
			t.Fatalf("%s %s is in the nl6#590 correction ledger but no longer ships",
				c.profile, c.oid)
		}
		if got != c.newValue {
			t.Fatalf("%s %s ships %q, but the ledger says this change set it to %q",
				c.profile, c.oid, got, c.newValue)
		}
		cur[k] = c.oldValue
	}
}

// nl6590VanishedCiscoOIDNames are the OID names this change removed from the
// corpus ENTIRELY, in the undotted spelling collectShippedOIDs gathers. Derived
// from the deletion ledger minus nl6590SurvivingDeletedNames, so the two views
// cannot drift, and pinned against the live corpus by
// TestCiscoArcVanishedNamesAreMeasured.
func nl6590VanishedCiscoOIDNames() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, d := range nl6590DeletedCiscoEntries {
		o := strings.TrimPrefix(d.oid, ".")
		if _, dup := seen[o]; dup {
			continue
		}
		seen[o] = struct{}{}
		if _, survives := nl6590SurvivingDeletedNames[o]; survives {
			continue
		}
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// nl6590OIDNamesBeforeAudit maps a list of shipped OID NAMES back to the set
// 5bded6c shipped. It is the name-view counterpart of restoreNl6590CiscoArc, and
// every reversal of shippedOIDEncodingDigest passes through it. It is no longer
// the innermost call: nl6#591 landed after this change, so
// nl6591OIDNamesBeforeWriteMemRemoval is undone first and this one wraps it.
func nl6590OIDNamesBeforeAudit(names []string) []string {
	return append(append([]string{}, names...), nl6590VanishedCiscoOIDNames()...)
}

// TestCiscoArcAuditReproducesTheParentCorpus is the before/after pin for the TAG
// digest: reverse the ledger against today's corpus and 5bded6c's value must come
// back. A missing row, an extra row, or any other edit to shipped data made
// without recording it here all fail.
func TestCiscoArcAuditReproducesTheParentCorpus(t *testing.T) {
	cur := map[[2]string]string{}
	for _, e := range shippedSNMPEntries(t) {
		k := [2]string{e.Profile, e.OID}
		if prev, dup := cur[k]; dup && prev != e.Value {
			t.Fatalf("%s serves %s twice with different values (%q, %q); the reconstruction "+
				"cannot be unambiguous", e.Profile, e.OID, prev, e.Value)
		}
		cur[k] = e.Value
	}

	// nl6#591 deleted the two writeMem entries after this change, so it is the
	// newest link of all and is undone first.
	restoreNl6591WriteMem(t, cur)
	restoreNl6590CiscoArc(t, cur)

	// Same line shape and hash as shippedTypedCorpus.
	seen := map[string]struct{}{}
	for k, v := range cur {
		enc := encodeTypedValue(k[1], v)
		if len(enc) == 0 {
			t.Fatalf("%s %s: encodeTypedValue(%q) emitted nothing", k[0], k[1], v)
		}
		seen[fmt.Sprintf("%s\t%s\t%02X", k[0], k[1], enc[0])] = struct{}{}
	}
	lines := make([]string, 0, len(seen))
	for l := range seen {
		lines = append(lines, l)
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	got := hex.EncodeToString(h.Sum(nil))

	t.Logf("restored %d deleted entries and reverted %d value corrections; %d (profile, OID, tag) "+
		"triples reconstructed", len(nl6590DeletedCiscoEntries), len(nl6590ValueCorrections),
		len(lines))

	if got != shippedTagDigestBeforeCiscoArcAudit {
		t.Errorf("reconstructed parent digest = %s, want %s.\n"+
			"The ledger no longer accounts for the difference between 5bded6c's shipped data and "+
			"this tree's. Either a row is missing from it, or shipped data changed without being "+
			"recorded.", got, shippedTagDigestBeforeCiscoArcAudit)
	}
}

// TestCiscoArcRePinIsOnlyTheAudit does the same job for the OID-NAME digest,
// which the tag digest cannot see: it hashes (profile, OID, tag) triples, so it
// says nothing about which distinct NAMES the corpus stopped shipping.
func TestCiscoArcRePinIsOnlyTheAudit(t *testing.T) {
	vanished := nl6590VanishedCiscoOIDNames()
	if len(vanished) == 0 {
		t.Fatal("the ledger yielded no vanished OID names")
	}

	// nl6#591 removed one more name after this change, so it is undone first.
	restored := nl6590OIDNamesBeforeAudit(
		nl6591OIDNamesBeforeWriteMemRemoval(collectShippedOIDs(t)))
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

	if got != shippedOIDEncodingDigestBeforeCiscoArcAudit {
		t.Errorf("restoring %d deleted OID names gives digest %s, want the pre-change value %s "+
			"over %d OIDs.\nSo the re-pin of shippedOIDEncodingDigest is NOT explained by this "+
			"audit alone: something else about what a shipped OID puts on the wire has changed.",
			len(vanished), got, shippedOIDEncodingDigestBeforeCiscoArcAudit, checked)
	}
	t.Logf("%d shipped OID names with %d deleted names restored reproduce the pre-change digest",
		checked, len(vanished))
}

// TestCiscoArcLedgerValuesMatchTheParentRevision pins the ledger's recorded old
// values against the tree at 5bded6c. Without it the eight deleted values are
// unfalsifiable: this change removed every one of them from the tree, so nothing
// else in the package has anything left to compare against.
//
// If it fails after an edit to the tables, the tables are wrong — the parent
// revision cannot change.
func TestCiscoArcLedgerValuesMatchTheParentRevision(t *testing.T) {
	var lines []string
	for _, d := range nl6590DeletedCiscoEntries {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", d.profile, d.oid, d.oldValue))
	}
	for _, c := range nl6590ValueCorrections {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", c.profile, c.oid, c.oldValue))
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	got := hex.EncodeToString(h.Sum(nil))

	if got != nl6590ValueDigestAtParent {
		t.Errorf("ledger value digest = %s, want %s (%d rows).\n"+
			"The recorded (profile, OID, old value) triples no longer match what 5bded6c shipped. "+
			"Re-derive with: git show 5bded6c:go/nl6/resources/cisco_catalyst_9500/"+
			"cisco_catalyst_9500_snmp_11.json and the cisco_nexus_9500 part, collect the rows this "+
			"ledger names, and hash sorted \"profile\\tOID\\tvalue\" lines. Do not re-pin this "+
			"constant to match an edited table: the parent revision is fixed.",
			got, nl6590ValueDigestAtParent, len(lines))
	}
	t.Logf("all %d recorded values match the corpus at 5bded6c", len(lines))
}

// TestCiscoArcLedgerIsNotVacuous guards the guard. An emptied ledger would make
// the reversals above pass only if the corpus were untouched, so the census is
// pinned and the SHAPE of every row is checked against the claim made about it.
func TestCiscoArcLedgerIsNotVacuous(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"nl6#590 deleted entries", len(nl6590DeletedCiscoEntries), 8},
		{"nl6#590 value corrections", len(nl6590ValueCorrections), 10},
		{"nl6#590 names that vanished corpus-wide", len(nl6590VanishedCiscoOIDNames()), 5},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: ledger has %d rows, want %d — the counts are the census quoted in the "+
				"commit body and the docs, so they move together or not at all",
				tc.name, tc.got, tc.want)
		}
	}

	// Every recorded row must be under the Cisco PEN. A row on another arc would
	// mean this ledger is reversing an edit that belongs to a different audit.
	const ciscoPEN = ".1.3.6.1.4.1.9."
	for _, d := range nl6590DeletedCiscoEntries {
		if !strings.HasPrefix(d.oid, ciscoPEN) {
			t.Errorf("%s %s is in the nl6#590 ledger but is not under Cisco's PEN", d.profile, d.oid)
		}
	}

	// The corrections' recorded tags are asserted through the ENCODER, not
	// reasoned about from oidTypeTable, because the encoder is what decides the
	// wire byte — and two of these three corrections MOVE it, which is half the
	// reason shippedTagDigest had to be re-pinned.
	for _, c := range nl6590ValueCorrections {
		if !strings.HasPrefix(c.oid, ciscoPEN) {
			t.Errorf("%s %s is in the nl6#590 correction ledger but is not under Cisco's PEN",
				c.profile, c.oid)
		}
		encOld := encodeTypedValue(c.oid, c.oldValue)
		encNew := encodeTypedValue(c.oid, c.newValue)
		if len(encOld) == 0 || encOld[0] != c.oldTag {
			t.Errorf("%s %s: old value %q emits % x, but the ledger records tag 0x%02X",
				c.profile, c.oid, c.oldValue, encOld, c.oldTag)
		}
		if len(encNew) == 0 || encNew[0] != c.newTag {
			t.Errorf("%s %s: new value %q emits % x, but the ledger records tag 0x%02X",
				c.profile, c.oid, c.newValue, encNew, c.newTag)
		}
	}
}

// TestCiscoArcVanishedNamesAreMeasured pins the split between the seven deleted
// OID names and the five that actually left the corpus. It is the assertion that
// makes nl6590SurvivingDeletedNames a measurement rather than a claim: without it
// a survivor added to that map by mistake would silently shrink the name-digest
// reversal, and the only test to fail would be one whose documented remedy is to
// re-pin a golden digest.
func TestCiscoArcVanishedNamesAreMeasured(t *testing.T) {
	shipped := map[string]struct{}{}
	for _, o := range collectShippedOIDs(t) {
		shipped[o] = struct{}{}
	}

	for _, o := range nl6590VanishedCiscoOIDNames() {
		if _, ok := shipped[o]; ok {
			t.Errorf("%s is recorded as having left the corpus but is still shipped somewhere; "+
				"the name-digest reversal would double-count it", o)
		}
	}
	for o, why := range nl6590SurvivingDeletedNames {
		if _, ok := shipped[o]; !ok {
			t.Errorf("%s is recorded as surviving (%s) but nothing in the corpus names it any "+
				"more, so the name-digest reversal is short by one name", o, why)
		}
	}

	// Every survivor must actually be one of the deleted names, or the map is
	// carrying an unrelated entry that quietly removes a name from the reversal.
	deleted := map[string]struct{}{}
	for _, d := range nl6590DeletedCiscoEntries {
		deleted[strings.TrimPrefix(d.oid, ".")] = struct{}{}
	}
	for o := range nl6590SurvivingDeletedNames {
		if _, ok := deleted[o]; !ok {
			t.Errorf("%s is in nl6590SurvivingDeletedNames but this change never deleted it", o)
		}
	}
	if got, want := len(deleted), 7; got != want {
		t.Errorf("the ledger names %d distinct OIDs, want %d", got, want)
	}
}

// TestCiscoArcCensusMatchesTheCorpus recomputes the audit's arithmetic from the
// shipped corpus plus the ledger, instead of leaving it as prose in a comment.
//
// It exists because the first cut of this change quoted "3 of 13" and that figure
// double-counted: ciscoEnvMonFanStatusDescr.1 was counted once as a deleted OID
// (it was deleted from cisco_catalyst_9500) and once as a kept ENTRY (it survives
// in three other profiles), so the number mixed distinct OIDs with per-profile
// entries and could not be compared with nl6#569's "8 of 11", which counts
// distinct OIDs on one profile.
//
// The two views are therefore computed separately here and the docs quote these
// numbers. A count nobody can recompute is not a measurement.
func TestCiscoArcCensusMatchesTheCorpus(t *testing.T) {
	const ciscoPrefix = ".1.3.6.1.4.1.9."
	const ciscoMgmtPrefix = ".1.3.6.1.4.1.9.9."

	// Today's corpus, then the ledger reversed over it, gives the parent's.
	parent := map[[2]string]string{}
	for _, e := range shippedSNMPEntries(t) {
		parent[[2]string{e.Profile, e.OID}] = e.Value
	}
	// nl6#591 deleted the two writeMem entries after this change, so it is the
	// newest link of all and is undone first. Without it the census below counts a
	// corpus that is neither today's nor 5bded6c's.
	restoreNl6591WriteMem(t, parent)
	restoreNl6590CiscoArc(t, parent)

	distinct, audited := map[string]struct{}{}, map[string]struct{}{}
	entries, auditedEntries := 0, 0
	for k := range parent {
		if !strings.HasPrefix(k[1], ciscoPrefix) {
			continue
		}
		entries++
		distinct[k[1]] = struct{}{}
		if strings.HasPrefix(k[1], ciscoMgmtPrefix) {
			auditedEntries++
			audited[k[1]] = struct{}{}
		}
	}

	// The distinct-OID view. "Wrong" is every audited OID this change touched;
	// an OID both deleted somewhere and corrected elsewhere counts ONCE, which is
	// the whole point of computing it from a set.
	touched := map[string]struct{}{}
	for _, d := range nl6590DeletedCiscoEntries {
		touched[d.oid] = struct{}{}
	}
	for _, c := range nl6590ValueCorrections {
		touched[c.oid] = struct{}{}
	}

	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"distinct Cisco OIDs shipped at the parent", len(distinct), 21},
		{"of those, audited (under ciscoMgmt)", len(audited), 13},
		{"of those, not audited (OLD-CISCO arcs)", len(distinct) - len(audited), 8},
		{"audited OIDs this change found wrong", len(touched), 11},
		{"audited OIDs right as shipped", len(audited) - len(touched), 2},
		{"Cisco entries shipped at the parent", entries, 39},
		{"of those, on an audited OID", auditedEntries, 23},
		{"entries deleted", len(nl6590DeletedCiscoEntries), 8},
		{"entries corrected", len(nl6590ValueCorrections), 10},
		{"entries left exactly as shipped",
			auditedEntries - len(nl6590DeletedCiscoEntries) - len(nl6590ValueCorrections), 5},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %d, want %d — this is the arithmetic quoted in the commit body, the "+
				"ledger header and docs/reference/snmp.md, so all of them move together",
				tc.name, tc.got, tc.want)
		}
	}

	// Every touched OID must be under ciscoMgmt, or the "13 audited" denominator
	// is describing a different set from the numerator.
	for o := range touched {
		if _, ok := audited[o]; !ok {
			t.Errorf("%s was edited by this change but is not one of the audited ciscoMgmt OIDs; "+
				"the hit rate's numerator and denominator have come apart", o)
		}
	}
}

// TestCiscoEnvMonAndMemoryPoolMatchTheMIB is the nl6#590 audit, committed as a
// test rather than left in an issue. It is the ONLY form of check available here:
// no load guard can see this defect, because every wrong value was a
// DisplayString-compatible string on an OID oidTypeTable does not type, so all
// three encodability rules passed the whole table (nl6#523, nl6#529, nl6#541).
//
// What it asserts is what a test CAN assert — the exact value served and the tag
// it goes out as, plus the absence of the OIDs that were deleted. It does not and
// cannot assert that the value is faithful to the MIB; that came from reading
// CISCO-ENVMON-MIB (201803210000Z), CISCO-MEMORY-POOL-MIB (201309180000Z),
// CISCO-IMAGE-MIB (9508150000Z) and CISCO-SYSTEM-EXT-MIB (201606140000Z) as
// published in github.com/cisco/cisco-mibs, and this table is the record of that
// reading. Read it as "these are the values nl6#590 resolved", never as "these
// are verified against a MIB by CI". NO MIB FILE IS CHECKED IN — see the licence
// note at the top of this file.
//
// The reading is qualified by REVISION, not stated as correctness: this profile
// matches those revisions of those modules. A device's shipped MIB need not.
func TestCiscoEnvMonAndMemoryPoolMatchTheMIB(t *testing.T) {
	catalyst := deviceForProfile(t, "cisco_catalyst_9500.json")

	// The values that survive the audit, with the object each one is.
	for _, tc := range []struct {
		profile, oid, object, want string
		tag                        byte
	}{
		// ciscoEnvMonTemperatureStatusDescr, DisplayString (SIZE (0..32)). It
		// describes the SENSOR, not the device: "Catalyst 9500 Switch" named the
		// chassis, which is what sysDescr is for.
		{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.13.1.3.1.2.1",
			"ciscoEnvMonTemperatureStatusDescr", "Chassis Inlet Temp Sensor", ASN1_OCTET_STRING},

		// ciscoMemoryPoolName, DisplayString. The INDEX is ciscoMemoryPoolType,
		// whose TC gives 1 = processor memory and 2 = i/o memory, so the two
		// instances are the two pools every IOS device reports — not, as the
		// profile had it, a wattage repeated twice.
		{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.48.1.1.1.2.1",
			"ciscoMemoryPoolName", "Processor", ASN1_OCTET_STRING},
		{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.48.1.1.1.2.2",
			"ciscoMemoryPoolName", "I/O", ASN1_OCTET_STRING},

		// Correct before the audit and left alone. ciscoImageString is a
		// DisplayString holding an arbitrary image-characteristic string, so a
		// version is the right KIND of value; the INDEX arity is one, so ".2" is
		// a legal instance (nl6#571 deleted the ".2.2.1" over-specified twins).
		{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.25.1.1.1.2.2",
			"ciscoImageString", "16.12.04", ASN1_OCTET_STRING},

		// ciscoEnvMonSupplyStatusDescr, DisplayString (SIZE (0..32)). The value
		// used to be a bare "1", which the first cut of this audit waved through
		// as "weak but a legal DisplayString". It was not legal: encodeTypedValue
		// emits a bare number as tag 0x02 INTEGER, so the row put an INTEGER on a
		// DisplayString leaf — the same defect as ciscoMemoryPoolName two rows up,
		// in the same profile, from the same reading. THE TAG ASSERTION IS WHY
		// THIS IS HERE: this was the one row in this function with no tag check,
		// which is exactly how it survived the first cut.
		{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.9.13.1.5.1.2.1",
			"ciscoEnvMonSupplyStatusDescr", "Power Supply 1", ASN1_OCTET_STRING},
	} {
		got := catalyst.findResponse(tc.oid)
		if got != tc.want {
			t.Errorf("%s %s (%s) answers %q, want %q", tc.profile, tc.oid, tc.object, got, tc.want)
			continue
		}
		if enc := encodeTypedValue(tc.oid, got); len(enc) == 0 || enc[0] != tc.tag {
			t.Errorf("%s %s (%s) = %q emits % x, want tag 0x%02X",
				tc.profile, tc.oid, tc.object, got, enc, tc.tag)
		}
	}

	// ciscoEnvMonTemperatureStatusDescr is bounded at 32 octets by the MIB, and a
	// correction that respected the type but not the size bound would still be
	// wrong. Asserted rather than eyeballed, since the value is prose.
	if v := catalyst.findResponse(".1.3.6.1.4.1.9.9.13.1.3.1.2.1"); len(v) > 32 {
		t.Errorf("ciscoEnvMonTemperatureStatusDescr answers %q (%d octets); the MIB declares "+
			"DisplayString (SIZE (0..32))", v, len(v))
	}

	// cseSysCPUUtilization, Gauge32 (0..100), on cisco_nexus_9500. Correct before
	// the audit and left alone; the range is asserted because it is the whole
	// reason the value is right.
	nexus := deviceForProfile(t, "cisco_nexus_9500.json")
	if got := nexus.findResponse(".1.3.6.1.4.1.9.9.305.1.1.1.0"); got != "28" {
		t.Errorf("cseSysCPUUtilization.0 answers %q, want 28", got)
	}

	// The deletions, as absences on cisco_catalyst_9500. findResponse answers a
	// miss with the valueNoSuchObject sentinel and never with "" (nl6#517), which
	// is the one spelling of absence this asserts.
	//
	// The eighth deleted entry, ciscoEnvMonTemperatureStatusValue.1, is NOT here
	// and cannot be: the metrics cycler answers that OID on all five Cisco
	// profiles, which is why it was deleted rather than corrected.
	// TestCiscoTemperatureStatusValueIsServedByTheCycler is its half of the pin.
	//
	// Worth carrying in the reading, since a pinned reading is what this file is
	// for: in CISCO-ENVMON-MIB 201803210000Z that object is STATUS deprecated, and
	// its DESCRIPTION names ciscoEnvMonTemperatureStatusValueRev1
	// (ciscoEnvMonTemperatureStatusEntry 7, Integer32, which also accommodates
	// negative temperatures) as the object to read instead. That does not change
	// the deletion — nl6 serves the deprecated column dynamically and no profile
	// serves Rev1 at all — but a collector written against the current MIB polls
	// .13.1.3.1.7.x, which nl6 answers with noSuchObject.
	for _, tc := range []struct{ oid, object, why string }{
		{".1.3.6.1.4.1.9.9.13.1.4.1.2.1",
			"ciscoEnvMonFanStatusDescr", "a supervisor part number is not a fan"},
		{".1.3.6.1.4.1.9.9.13.1.4.1.2.2",
			"ciscoEnvMonFanStatusDescr", "a line card is not a fan"},
		{".1.3.6.1.4.1.9.9.13.1.4.1.3.1",
			"ciscoEnvMonFanState", "SYNTAX CiscoEnvMonState, an INTEGER enum; a DisplayString is a type error"},
		{".1.3.6.1.4.1.9.9.13.1.4.1.3.2",
			"ciscoEnvMonFanState", "SYNTAX CiscoEnvMonState, an INTEGER enum; a DisplayString is a type error"},
		{".1.3.6.1.4.1.9.9.48.1.1.1.3.1",
			"ciscoMemoryPoolAlternate", "SYNTAX Integer32 (0..65535); a PSU part number is a string on an integer leaf"},
		{".1.3.6.1.4.1.9.9.48.1.1.1.3.2",
			"ciscoMemoryPoolAlternate", "SYNTAX Integer32 (0..65535); a PSU part number is a string on an integer leaf"},
	} {
		if got := catalyst.findResponse(tc.oid); !isSNMPExceptionValue(got) {
			t.Errorf("cisco_catalyst_9500.json %s (%s) still answers %q; it was deleted because %s",
				tc.oid, tc.object, got, tc.why)
		}
	}

	// ciscoEnvMonFanStatusDescr.1 survives on the other three Cisco profiles rather
	// than being deleted with cisco_catalyst_9500's copy, because there the value
	// was a supervisor part number and here it is a description of a fan. Both
	// objects are DisplayString (SIZE (0..32)) and both are checked for the TAG,
	// not only the string: a bare "1" satisfies "looks like a description" and
	// still goes out as an INTEGER, which is how the first cut of this audit left
	// seven of these in place.
	//
	// The replacements are generic and positional on purpose. Inventing a part
	// number would be nl6#569's defect in the other direction.
	for _, tc := range []struct{ profile, oid, object, want string }{
		{"cisco_crs_x.json", ".1.3.6.1.4.1.9.9.13.1.4.1.2.1", "ciscoEnvMonFanStatusDescr", "Fan 1"},
		{"cisco_ios.json", ".1.3.6.1.4.1.9.9.13.1.4.1.2.1", "ciscoEnvMonFanStatusDescr", "Fan 1"},
		{"cisco_nexus_9500.json", ".1.3.6.1.4.1.9.9.13.1.4.1.2.1", "ciscoEnvMonFanStatusDescr", "Fan 1"},
		{"cisco_crs_x.json", ".1.3.6.1.4.1.9.9.13.1.5.1.2.1", "ciscoEnvMonSupplyStatusDescr", "Power Supply 1"},
		{"cisco_ios.json", ".1.3.6.1.4.1.9.9.13.1.5.1.2.1", "ciscoEnvMonSupplyStatusDescr", "Power Supply 1"},
		{"cisco_nexus_9500.json", ".1.3.6.1.4.1.9.9.13.1.5.1.2.1", "ciscoEnvMonSupplyStatusDescr", "Power Supply 1"},
	} {
		got := deviceForProfile(t, tc.profile).findResponse(tc.oid)
		if got != tc.want {
			t.Errorf("%s %s (%s) answers %q, want %q", tc.profile, tc.oid, tc.object, got, tc.want)
			continue
		}
		if len(got) > 32 {
			t.Errorf("%s %s (%s) answers %q (%d octets); the MIB declares DisplayString "+
				"(SIZE (0..32))", tc.profile, tc.oid, tc.object, got, len(got))
		}
		if enc := encodeTypedValue(tc.oid, got); len(enc) == 0 || enc[0] != ASN1_OCTET_STRING {
			t.Errorf("%s %s (%s) = %q emits % x, want tag 0x%02X. A bare number on a "+
				"DisplayString leaf encodes as an INTEGER, which is the defect this row fixes",
				tc.profile, tc.oid, tc.object, got, enc, ASN1_OCTET_STRING)
		}
	}

	// RECORDED, NOT FIXED. Both tables now ship a DESCRIPTION column and no STATE
	// column: after this change no profile serves ciscoEnvMonFanState
	// (…13.1.4.1.3.x) or ciscoEnvMonSupplyState (…13.1.5.1.3.x) at all, so a
	// collector can discover that a fan or a supply exists and never read its
	// health. That is real and it is lesser than the wire-type error this change
	// fixed, and it must NOT be closed by inventing state values — that is the
	// nl6#569 defect. Asserted as an absence so the gap is visible and so
	// "completing the table" has to argue with a reading.
	//
	// Note the asymmetry with the trap catalog, which is the finding in its own
	// right: resources/cisco_ios/traps.json fires BOTH state columns
	// (…13.1.5.1.3.1 integer 1, …13.1.3.1.6.1 integer 2) that no resource file
	// serves.
	for _, tc := range []struct{ oid, object string }{
		{".1.3.6.1.4.1.9.9.13.1.4.1.3.1", "ciscoEnvMonFanState"},
		{".1.3.6.1.4.1.9.9.13.1.5.1.3.1", "ciscoEnvMonSupplyState"},
		{".1.3.6.1.4.1.9.9.13.1.3.1.6.1", "ciscoEnvMonTemperatureState"},
	} {
		for _, p := range []string{
			"cisco_catalyst_9500.json", "cisco_crs_x.json", "cisco_ios.json",
			"cisco_nexus_9500.json",
		} {
			if got := deviceForProfile(t, p).findResponse(tc.oid); !isSNMPExceptionValue(got) {
				t.Errorf("%s now answers %s (%s) with %q. If that is a deliberate improvement, "+
					"the value has to come from a reading of CiscoEnvMonState rather than from "+
					"a plausible-looking number, and this list has to shrink deliberately",
					p, tc.oid, tc.object, got)
			}
		}
	}
}

// TestCiscoTemperatureStatusValueIsServedByTheCycler pins what the two deleted
// ciscoEnvMonTemperatureStatusValue.1 rows actually did, and the first cut of
// this change got that wrong in a way worth writing down.
//
// THE ROWS WERE NOT DEAD, AND THE WALK IS WHAT THIS CHANGE MOVED. The claim they
// were "unreachable" was drawn from the GET path alone: metrics_oids.go maps the
// OID to MetricTemperature for all five Cisco profiles and findResponse consults
// getMetricValue BEFORE the static oidIndex, so a GET was already answered by the
// cycler. A WALK is a different path. findNextOIDWithServed assembles candidates
// and takes the lexicographically smallest with a STRICT less-than, so when the
// static row and the metric OID are the same OID the FIRST candidate wins — and
// the static one is appended first, from precomputedNextOID. Measured at the
// parent revision 5bded6c on a device with a live cycler:
//
//	findNextOID(".1.3.6.1.4.1.9.9.13.1.3.1.2.1")
//	  cisco_catalyst_9500 -> .13.1.3.1.3.1 = "CAT9500-001"   (findResponse: "30")
//	  cisco_nexus_9500    -> .13.1.3.1.3.1 = "39"            (findResponse: "31")
//
// So a GETNEXT or GETBULK across that table returned a chassis NAME on a Gauge32
// leaf, as an OCTET STRING, while a GET of the same OID on the same device
// returned a temperature. The deletion is still right — the static values were
// wrong on any path — but what it CHANGED is the walk, not the GET, and this is
// the surface the audit nearly shipped without a test.
//
// Hence the walk assertion below. No test in the package walks a Cisco profile at
// all; a mutation to GetSortedMetricOIDs' ordering makes this OID vanish from
// every Cisco walk while only the NVIDIA arc's walk test fires.
// TestNvidiaArcWalkIsStrictlyIncreasing is the shape this borrows.
//
// If the cycler ever stops owning this OID, the profiles need static rows back,
// with a value that is a temperature.
func TestCiscoTemperatureStatusValueIsServedByTheCycler(t *testing.T) {
	const descrOID = ".1.3.6.1.4.1.9.9.13.1.3.1.2.1"
	const tempOID = ".1.3.6.1.4.1.9.9.13.1.3.1.3.1"

	for _, profile := range []string{
		"asr9k.json", "cisco_catalyst_9500.json", "cisco_crs_x.json",
		"cisco_ios.json", "cisco_nexus_9500.json",
	} {
		if _, mapped := GetMetricOIDs(profile)[tempOID]; !mapped {
			t.Errorf("%s no longer maps %s to a metric; the two deleted static rows were deleted "+
				"BECAUSE the cycler owns this OID, so they have to come back", profile, tempOID)
			continue
		}
		srv := deviceForProfileWithMetrics(t, profile)

		// The GET path. Already true before this change; asserted so a
		// regression here is not mistaken for the walk regression below.
		got := srv.findResponse(tempOID)
		if isSNMPExceptionValue(got) || got == "" {
			t.Errorf("%s answers %q for %s; a live cycler must answer a temperature",
				profile, got, tempOID)
		}

		// The WALK path, which is the one this change moved. Driven through
		// findNextOIDWithServed, the same entry point the GETNEXT / GETBULK
		// handlers use, rather than through findResponse a second time.
		nextOID, nextVal := srv.findNextOIDWithServed(descrOID, srv.lldpServedOIDs())
		if nextOID != tempOID {
			t.Errorf("%s: walking from %s reaches %s, want %s — the cycler's metric OID is no "+
				"longer enumerated into the walk, so the column has gone missing from every "+
				"GETNEXT and GETBULK", profile, descrOID, nextOID, tempOID)
			continue
		}
		if _, err := strconv.Atoi(nextVal); err != nil {
			t.Errorf("%s: the walk answers %s with %q, which is not a number. This is the exact "+
				"defect nl6#590 deleted: at 5bded6c the walk returned a chassis name here on a "+
				"Gauge32 leaf while a GET of the same OID returned a temperature",
				profile, tempOID, nextVal)
		}
		if enc := encodeTypedValue(tempOID, nextVal); len(enc) == 0 || enc[0] != ASN1_INTEGER {
			t.Errorf("%s: the walk's value for %s emits % x, want an INTEGER-shaped tag 0x%02X",
				profile, tempOID, enc, ASN1_INTEGER)
		}
	}
}

// deviceForProfileWithMetrics is deviceForProfile plus a real MetricsCycler, so
// findResponse takes the getMetricValue branch. deviceForProfile builds a bare
// &MetricsCycler{}, which is enough for the interface counters but not for the
// CPU / memory / temperature patterns.
func deviceForProfileWithMetrics(t *testing.T, profile string) *SNMPServer {
	t.Helper()

	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources(profile)
	if err != nil {
		t.Fatalf("LoadSpecificResources(%s): %v", profile, err)
	}
	mc := NewMetricsCycler(1, GetDeviceProfile(profile))
	mc.InitIfCounters(res, 1)
	return &SNMPServer{device: &DeviceSimulator{
		ID:            "cisco-arc-pin",
		resources:     res,
		resourceFile:  profile,
		metricsCycler: mc,
	}}
}
