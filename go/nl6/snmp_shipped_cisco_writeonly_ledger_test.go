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

// nl6#591 is a NEW DEFECT CLASS, and that is the only reason it is a change of
// its own rather than two more rows in the nl6#590 ledger next door.
//
// Every resource defect found so far has been a wrong VALUE (nl6#569's PAN
// subtree), a wrong TYPE (nl6#590's bare "1" on a DisplayString leaf), a wrong
// NAME SHAPE (nl6#571's bare columns and over-specified instances) or a wrong
// VENDOR ARC (nl6#576, nl6#587, nl6#588, nl6#589). This one is a wrong ACCESS
// MODE: the object exists, the arc is right, the instance sub-identifier is
// right, and the value even encodes as the INTEGER the MIB declares. What is
// wrong is that the object is not readable at all.
//
//	writeMem OBJECT-TYPE
//	    SYNTAX  INTEGER
//	    ACCESS  write-only
//	    STATUS  mandatory
//	    DESCRIPTION
//	            "Write configuration into non-volatile memory
//	            / erase config memory if 0."
//	    ::= { lsystem 54 }
//
// A real Cisco device answers a GET of writeMem with an exception; nl6 answered
// 393084300 on cisco_catalyst_9500 and 1451548800 on cisco_crs_x. The object is
// also a COMMAND rather than a datum — writing to it saves the running
// configuration and writing 0 erases config memory — so a collector that
// discovers it as a readable integer has learned something false about the
// device in a way that is worse than a wrong number.
//
// DELETED, NOT CORRECTED. A write-only object has no correct readable value, so
// correction is not on the table. Same reasoning that deleted 3 of 11 OIDs in
// nl6#569 and the four ciscoEnvMonFanStatus rows in nl6#590.
//
// ── what was read ───────────────────────────────────────────────────────────
//
// OLD-CISCO-SYSTEM-MIB, as published in github.com/cisco/cisco-mibs. It is cited
// by NAME AND FORM rather than by revision, and the difference is not pedantry:
// the module is SMIv1 (it IMPORTS OBJECT-TYPE FROM RFC-1212 and spells access as
// `ACCESS write-only`, not `MAX-ACCESS`), so it carries NO MODULE-IDENTITY and
// therefore no LAST-UPDATED to quote. The only date in the copy read is its
// header line, "Copyright (c) 1994-1995 by cisco Systems, Inc." Where nl6#590
// could write "CISCO-ENVMON-MIB (201803210000Z)", the honest citation here is
// the module name, the SMIv1 form, and that copyright line. Claiming a revision
// string this module does not have would be the same failure the whole audit
// exists to stop.
//
// The arc was resolved rather than assumed: CISCO-SMI (201601150000Z, which DOES
// carry a MODULE-IDENTITY) puts `cisco` at `{ enterprises 9 }` and `local` at
// `{ cisco 2 }`, OLD-CISCO-SYSTEM-MIB puts `lsystem` at `{ local 1 }`, and
// writeMem at `{ lsystem 54 }` — so 1.3.6.1.4.1.9.2.1.54, and .0 for the scalar
// instance.
//
// NO MIB FILE OR EXTRACTED FIXTURE IS CHECKED IN. The reasoning is nl6#590's and
// is not restated here: no vendor grants redistribution, Cisco's own header
// asserts copyright and grants nothing, and LibreNMS files its own MIB tree as a
// GPL-non-compliant component rather than claiming the right. So this is a
// PINNED READING (TestCiscoWriteOnlyObjectsAreAbsent below, the
// TestCiscoEnvMonAndMemoryPoolMatchTheMIB / TestPaloAltoPANSubtreeMatchesTheMIB
// shape) and never a live check against a MIB.
//
// ── scope, and what stays open ──────────────────────────────────────────────
//
// This change closes ONE OBJECT, not the class. NO nl6 RULE MODELS MAX-ACCESS:
// the three load rules check encodability (nl6#523, nl6#529, nl6#541), the PEN
// guards check vendor identity (nl6#587, nl6#589), and nl6#590's reading tests
// check names, types and values. None of them can see an access mode, because an
// access mode is not a property of the OID or of the value — it is a property of
// the MIB, which nl6 does not have.
//
// The `not-accessible` half is the LARGER and unswept one: every SMIv2 table
// INDEX column is `not-accessible`, so a profile shipping an index column as a
// readable row makes exactly this mistake in the commonest possible place. It
// cannot be swept generically here for the same reason the rest of nl6#590 could
// not: the sweep needs the MIB, per arc, and only Cisco (partially) and Palo Alto
// have been read. It therefore advances WITH nl6#590 rather than being closed by
// this change. docs/reference/snmp.md carries the same statement.
//
// DELIBERATELY NOT TOUCHED, and recorded so the boundary is a decision rather
// than an oversight — TestCiscoWriteOnlyObjectsAreAbsent asserts they still
// ship, so removing one has to be a deliberate act:
//
//   - 1.3.6.1.4.1.9.2.1.56.0 (busyPer) and .58.0 (avgBusy5) resolve in
//     OLD-CISCO-CPU-MIB, are ACCESS read-only, and ship plausible percentages.
//     Plausible is not audited; neither was checked against its DESCRIPTION or
//     units.
//   - 1.3.6.1.4.1.9.2.1.8.0 is absent from the OLD-CISCO-SYSTEM-MIB copy read,
//     so it is unresolved rather than shown wrong.
//   - 1.3.6.1.4.1.9.3.6.* and 1.3.6.1.4.1.9.5.1.* are unresolved:
//     OLD-CISCO-CHASSIS-MIB was not obtainable in this run.
//
// All of those stay on nl6#590's unaudited list.
//
// ── why there is a ledger at all ────────────────────────────────────────────
//
// Both golden corpus digests move, and WHICH ones move was MEASURED by applying
// the deletions and running the suite, not predicted:
//
//   - shippedTagDigest is keyed on (profile, OID, emitted tag). Two triples are
//     removed outright, so it moves.
//   - shippedOIDEncodingDigest hashes each DISTINCT shipped OID NAME against its
//     BER encoding. 1.3.6.1.4.1.9.2.1.54.0 was served by these two profiles and
//     by nothing else in the corpus — no third profile, no trap catalog varbind —
//     so the name leaves entirely and this digest moves too. Contrast nl6#590,
//     where two of seven deleted names survived elsewhere; that is precisely why
//     the claim is checked against the live corpus by
//     TestWriteMemNameLeftTheCorpus rather than reasoned about.
//
// Every recorded oldValue was read OUT OF GIT at f47c85d (the revision this
// branch forked from) rather than retyped from the working tree —
// TestWriteMemLedgerValuesMatchTheParentRevision pins that, so the table cannot
// be "fixed" into agreeing with itself. That is the nl6#573 lesson.
//
// This ledger is the NEWEST link in the chain. Every older ledger reverses to its
// own parent starting from today's corpus, so each of them now begins by undoing
// this change: the chain reads
// today -> f47c85d -> 5bded6c -> 87c642d -> 1bca8e8 -> ec4700f -> 3a69927 -> 44ef67f.

// nl6591DeletedWriteOnlyEntries are the two shipped entries this change removed.
// One distinct OID, served by two profiles.
//
// Both were the ONLY lsystem write-only row in their profile, so after this
// change no profile answers any OLD-CISCO-SYSTEM-MIB write-only object. DO NOT
// restore either row with a "better" number: there is no readable value for a
// write-only object, which is the entire finding.
var nl6591DeletedWriteOnlyEntries = []struct{ profile, oid, oldValue string }{
	{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.2.1.54.0", "393084300"},
	{"cisco_crs_x.json", ".1.3.6.1.4.1.9.2.1.54.0", "1451548800"},
}

// The two "before" digests live HERE rather than beside the live constants they
// chain onto, matching the nl6#576 and nl6#590 ledgers. The cross-reference is
// written down instead of left for a reader to discover:
//
//	live value                  declared in                       reversed by
//	shippedTagDigest            snmp_hc_counter_table_test.go     TestWriteMemRemovalReproducesTheParentCorpus
//	shippedOIDEncodingDigest    snmp_oid_roundtrip_test.go        TestWriteMemRePinIsOnlyTheRemoval
//
// Both live constants carry a comment naming this file and these two tests, so
// the chain can be followed from either end.

// shippedTagDigestBeforeWriteMemRemoval is the (profile, OID, emitted tag) digest
// of the corpus at f47c85d — the value shippedTagDigest held before this change,
// NOT re-derived from the edited tree.
const shippedTagDigestBeforeWriteMemRemoval = "0ef1159118874de4fae3f89766d28034996775d7f10c91c1d1bc20ddaabd9e52"

// shippedOIDEncodingDigestBeforeWriteMemRemoval is the OID-name-to-encoding
// digest at the same revision, and the same rule applies to it. It is also the
// newest entry in snmp_oid_roundtrip_test.go's historical run.
const shippedOIDEncodingDigestBeforeWriteMemRemoval = "73ec7b1d6ec84991a4458b9e984ee1a33b3cf1f7c09d62334dee7bca9cc7f4ca"

// nl6591ValueDigestAtParent is a SHA-256 over the sorted "profile\toid\toldValue"
// lines of every row this ledger records, as they existed at f47c85d.
//
// It was computed by reading the two resource parts OUT OF GIT at that revision
// (`git show f47c85d:<path>`), never from the table above, so comparing the table
// against it compares it with the tree as it actually was. This change removed
// both rows, so nothing else in the package has anything left to compare against.
const nl6591ValueDigestAtParent = "374f15d236a077add4585b78c9da74a8fa3d638d99c9d59e0125afcabab9f0d0"

// restoreNl6591WriteMem reverses this change against a (profile, OID) -> value
// map, so the map afterwards is the corpus as f47c85d shipped it. Shared with
// every older ledger reversal, whose own starting point is the tree this one
// reconstructs.
//
// EVERY DISAGREEMENT IS FATAL, for the reason restoreNl6576NvidiaArc gives: a
// reversal that carries on past a corpus it does not recognise buries its own
// diagnosis under the caller's opaque digest mismatch.
func restoreNl6591WriteMem(t *testing.T, cur map[[2]string]string) {
	t.Helper()

	for _, d := range nl6591DeletedWriteOnlyEntries {
		k := [2]string{d.profile, d.oid}
		if got, ok := cur[k]; ok {
			t.Fatalf("%s %s is in the nl6#591 removal ledger but still ships, valued %q. "+
				"writeMem is ACCESS write-only; there is no readable value to restore",
				d.profile, d.oid, got)
		}
		cur[k] = d.oldValue
	}
}

// nl6591VanishedOIDNames are the OID names this change removed from the corpus
// ENTIRELY, in the undotted spelling collectShippedOIDs gathers. Derived from the
// deletion ledger, so the two views cannot drift, and pinned against the live
// corpus by TestWriteMemNameLeftTheCorpus.
//
// There is no survivors map here, unlike nl6#590's: the one deleted name was
// served by exactly these two profiles and nothing else. That is a MEASUREMENT,
// not an assumption — see TestWriteMemNameLeftTheCorpus.
func nl6591VanishedOIDNames() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, d := range nl6591DeletedWriteOnlyEntries {
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

// nl6591OIDNamesBeforeWriteMemRemoval maps a list of shipped OID NAMES back to
// the set f47c85d shipped. It is the name-view counterpart of
// restoreNl6591WriteMem, and every reversal of shippedOIDEncodingDigest now
// begins with it — this change is the newest link, so it is undone FIRST
// (innermost in the call chain).
func nl6591OIDNamesBeforeWriteMemRemoval(names []string) []string {
	return append(append([]string{}, names...), nl6591VanishedOIDNames()...)
}

// TestWriteMemRemovalReproducesTheParentCorpus is the before/after pin for the
// TAG digest: reverse the ledger against today's corpus and f47c85d's value must
// come back. A missing row, an extra row, or any other edit to shipped data made
// without recording it here all fail.
func TestWriteMemRemovalReproducesTheParentCorpus(t *testing.T) {
	cur := map[[2]string]string{}
	for _, e := range shippedSNMPEntries(t) {
		k := [2]string{e.Profile, e.OID}
		if prev, dup := cur[k]; dup && prev != e.Value {
			t.Fatalf("%s serves %s twice with different values (%q, %q); the reconstruction "+
				"cannot be unambiguous", e.Profile, e.OID, prev, e.Value)
		}
		cur[k] = e.Value
	}

	restoreNl6590AristaArc(t, cur)
	restoreNl6591WriteMem(t, cur)

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

	t.Logf("restored %d deleted entries; %d (profile, OID, tag) triples reconstructed",
		len(nl6591DeletedWriteOnlyEntries), len(lines))

	if got != shippedTagDigestBeforeWriteMemRemoval {
		t.Errorf("reconstructed parent digest = %s, want %s.\n"+
			"The ledger no longer accounts for the difference between f47c85d's shipped data and "+
			"this tree's. Either a row is missing from it, or shipped data changed without being "+
			"recorded.", got, shippedTagDigestBeforeWriteMemRemoval)
	}
}

// TestWriteMemRePinIsOnlyTheRemoval does the same job for the OID-NAME digest,
// which the tag digest cannot see: it hashes (profile, OID, tag) triples, so it
// says nothing about which distinct NAMES the corpus stopped shipping.
func TestWriteMemRePinIsOnlyTheRemoval(t *testing.T) {
	vanished := nl6591VanishedOIDNames()
	if len(vanished) == 0 {
		t.Fatal("the ledger yielded no vanished OID names")
	}

	restored := nl6591OIDNamesBeforeWriteMemRemoval(nl6590aristaOIDNamesBeforeAudit(t, collectShippedOIDs(t)))
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

	if got != shippedOIDEncodingDigestBeforeWriteMemRemoval {
		t.Errorf("restoring %d deleted OID names gives digest %s, want the pre-change value %s "+
			"over %d OIDs.\nSo the re-pin of shippedOIDEncodingDigest is NOT explained by this "+
			"removal alone: something else about what a shipped OID puts on the wire has changed.",
			len(vanished), got, shippedOIDEncodingDigestBeforeWriteMemRemoval, checked)
	}
	t.Logf("%d shipped OID names with %d deleted names restored reproduce the pre-change digest",
		checked, len(vanished))
}

// TestWriteMemLedgerValuesMatchTheParentRevision pins the ledger's recorded old
// values against the tree at f47c85d. Without it the two deleted values are
// unfalsifiable: this change removed both from the tree, so nothing else in the
// package has anything left to compare against.
//
// If it fails after an edit to the table, the table is wrong — the parent
// revision cannot change.
func TestWriteMemLedgerValuesMatchTheParentRevision(t *testing.T) {
	var lines []string
	for _, d := range nl6591DeletedWriteOnlyEntries {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", d.profile, d.oid, d.oldValue))
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	got := hex.EncodeToString(h.Sum(nil))

	if got != nl6591ValueDigestAtParent {
		t.Errorf("ledger value digest = %s, want %s (%d rows).\n"+
			"The recorded (profile, OID, old value) triples no longer match what f47c85d shipped. "+
			"Re-derive with: git show f47c85d:go/nl6/resources/cisco_catalyst_9500/"+
			"cisco_catalyst_9500_snmp_11.json and the cisco_crs_x part, collect the rows this "+
			"ledger names, and hash sorted \"profile\\tOID\\tvalue\" lines. Do not re-pin this "+
			"constant to match an edited table: the parent revision is fixed.",
			got, nl6591ValueDigestAtParent, len(lines))
	}
	t.Logf("all %d recorded values match the corpus at f47c85d", len(lines))
}

// TestWriteMemLedgerIsNotVacuous guards the guard. An emptied ledger would make
// the reversals above pass only if the corpus were untouched, so the census is
// pinned and the SHAPE of every row is checked against the claim made about it.
func TestWriteMemLedgerIsNotVacuous(t *testing.T) {
	if got, want := len(nl6591DeletedWriteOnlyEntries), 2; got != want {
		t.Errorf("nl6#591 deleted entries: ledger has %d rows, want %d — the count is the census "+
			"quoted in the commit body and the docs, so they move together or not at all",
			got, want)
	}
	if got, want := len(nl6591VanishedOIDNames()), 1; got != want {
		t.Errorf("nl6#591 names that vanished corpus-wide: %d, want %d", got, want)
	}

	// Every recorded row must be writeMem under the Cisco PEN. A row on another
	// OID would mean this ledger is reversing an edit that belongs elsewhere —
	// the two unaudited lsystem neighbours (.56, .58) sit one sub-identifier away
	// and are deliberately untouched.
	const writeMem = ".1.3.6.1.4.1.9.2.1.54.0"
	for _, d := range nl6591DeletedWriteOnlyEntries {
		if d.oid != writeMem {
			t.Errorf("%s %s is in the nl6#591 ledger but is not writeMem (%s)",
				d.profile, d.oid, writeMem)
		}

		// The recorded value's tag is asserted THROUGH THE ENCODER rather than
		// reasoned about, and this row is the reason the defect class is new: the
		// value encoded correctly. writeMem's SYNTAX is INTEGER, both old values
		// are plain decimals inside int32, and encodeTypedValue emits tag 0x02 for
		// them. Nothing about the wire bytes was wrong; the object was unreadable.
		enc := encodeTypedValue(d.oid, d.oldValue)
		if len(enc) == 0 || enc[0] != ASN1_INTEGER {
			t.Errorf("%s %s: old value %q emits % x, want tag 0x%02X. If this stops being an "+
				"INTEGER the class claim in this file's header is wrong: the point of nl6#591 is "+
				"that the ENCODING was fine and the ACCESS MODE was not",
				d.profile, d.oid, d.oldValue, enc, ASN1_INTEGER)
		}
	}
}

// TestWriteMemNameLeftTheCorpus is what makes "the name vanished entirely" a
// measurement rather than a claim. nl6#590 recorded seven deleted names of which
// only five actually left — one still shipped on three other profiles, one was
// still a trap varbind — so the same question has to be ASKED here, not inferred
// from a two-row table.
//
// collectShippedOIDs walks the trap and syslog catalogs as well as the resource
// parts, so a writeMem varbind hiding in a catalog would fail this.
func TestWriteMemNameLeftTheCorpus(t *testing.T) {
	shipped := map[string]struct{}{}
	for _, o := range collectShippedOIDs(t) {
		shipped[o] = struct{}{}
	}

	for _, o := range nl6591VanishedOIDNames() {
		if _, ok := shipped[o]; ok {
			t.Errorf("%s is recorded as having left the corpus but is still named somewhere "+
				"(a resource part or a catalog varbind); the name-digest reversal would "+
				"double-count it", o)
		}
	}
}

// TestCiscoWriteOnlyObjectsAreAbsent is the nl6#591 audit, committed as a test
// rather than left in an issue. It is the ONLY form of check available here: no
// load guard can see this defect, because the value was a decimal integer on an
// OID whose declared SYNTAX is INTEGER, so all three encodability rules passed it
// (nl6#523, nl6#529, nl6#541) and so does the numeric-leaf guard in
// resource_numeric_oids_test.go, which asks whether writeMem holds a NUMBER —
// the wrong question for an object that cannot be read at all.
//
// What it asserts is what a test CAN assert: the absence of an OID, and the
// continued presence of the neighbours this change deliberately left alone. It
// does not and cannot assert that an object is write-only; that came from reading
// OLD-CISCO-SYSTEM-MIB as published in github.com/cisco/cisco-mibs, and this
// function is the RECORD OF THAT READING. Read it as "this is what nl6#591
// resolved", never as "CI checks nl6 against a MIB". NO MIB FILE IS CHECKED IN —
// see the licence note at the top of this file.
//
// The module is SMIv1 and carries no MODULE-IDENTITY, so there is no revision
// string to qualify the reading with; the copy read is dated only by its own
// header, "Copyright (c) 1994-1995 by cisco Systems, Inc." A device's shipped MIB
// need not agree with it.
func TestCiscoWriteOnlyObjectsAreAbsent(t *testing.T) {
	// writeMem, ACCESS write-only. Deleted from both profiles that served it.
	// findResponse answers a miss with the valueNoSuchObject sentinel and never
	// with "" (nl6#517), which is the one spelling of absence this asserts.
	const writeMem = ".1.3.6.1.4.1.9.2.1.54.0"
	for _, profile := range []string{"cisco_catalyst_9500.json", "cisco_crs_x.json"} {
		if got := deviceForProfile(t, profile).findResponse(writeMem); !isSNMPExceptionValue(got) {
			t.Errorf("%s still answers %s (OLD-CISCO-SYSTEM-MIB::writeMem) with %q. That object "+
				"is ACCESS write-only: writing to it saves the running configuration and writing "+
				"0 erases config memory, so there is no readable value it can correctly answer. "+
				"A real device answers an exception here. Do not restore this row with a "+
				"different number", profile, writeMem, got)
		}
	}

	// The other write-only objects in the same group, asserted across EVERY Cisco
	// profile rather than only the two edited ones. None of them ships today and
	// none of them ever should; a profile that gained one would be repeating this
	// defect on a different sub-identifier, and nothing else in the package would
	// notice.
	for _, tc := range []struct{ oid, object, syntax string }{
		{".1.3.6.1.4.1.9.2.1.50.0", "netConfigSet",
			"DisplayString; loads a new network-confg file over TFTP"},
		{".1.3.6.1.4.1.9.2.1.53.0", "hostConfigSet",
			"DisplayString; loads a new host-confg file over TFTP"},
		{".1.3.6.1.4.1.9.2.1.55.0", "writeNet",
			"DisplayString; writes the configuration to a host over TFTP"},
	} {
		for _, profile := range []string{
			"asr9k.json", "cisco_catalyst_9500.json", "cisco_crs_x.json",
			"cisco_ios.json", "cisco_nexus_9500.json",
		} {
			if got := deviceForProfile(t, profile).findResponse(tc.oid); !isSNMPExceptionValue(got) {
				t.Errorf("%s answers %s (%s) with %q. Every one of these is ACCESS write-only in "+
					"OLD-CISCO-SYSTEM-MIB (%s) — an action, not a datum — so no value is a "+
					"correct answer", profile, tc.oid, tc.object, got, tc.syntax)
			}
		}
	}

	// RECORDED, NOT FIXED, and asserted as a PRESENCE so the scope boundary is a
	// measurement rather than a sentence in a comment. Every one of these sits in
	// the same lsystem group as writeMem — one, four and forty-six sub-identifiers
	// away — which is exactly why a sweep that "tidied the group up" would be a
	// different and unargued change.
	//
	// If a later audit deletes or corrects one, this list has to shrink
	// deliberately rather than a test quietly going green.
	for _, tc := range []struct{ profile, oid, object, why, want string }{
		{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.2.1.56.0", "busyPer",
			"resolves in OLD-CISCO-CPU-MIB, ACCESS read-only, plausible percentage, unaudited", "45"},
		{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.2.1.58.0", "avgBusy5",
			"resolves in OLD-CISCO-CPU-MIB, ACCESS read-only, plausible percentage, unaudited", "25"},
		{"cisco_catalyst_9500.json", ".1.3.6.1.4.1.9.2.1.8.0", "unresolved",
			"absent from the OLD-CISCO-SYSTEM-MIB copy read, so unresolved rather than shown wrong", "536870912"},
		{"cisco_crs_x.json", ".1.3.6.1.4.1.9.2.1.56.0", "busyPer",
			"resolves in OLD-CISCO-CPU-MIB, ACCESS read-only, plausible percentage, unaudited", "62"},
		{"cisco_crs_x.json", ".1.3.6.1.4.1.9.2.1.58.0", "avgBusy5",
			"resolves in OLD-CISCO-CPU-MIB, ACCESS read-only, plausible percentage, unaudited", "39"},
		{"cisco_crs_x.json", ".1.3.6.1.4.1.9.2.1.8.0", "unresolved",
			"absent from the OLD-CISCO-SYSTEM-MIB copy read, so unresolved rather than shown wrong", "1073741824"},
	} {
		got := deviceForProfile(t, tc.profile).findResponse(tc.oid)
		if got != tc.want {
			t.Errorf("%s %s (%s) answers %q, want %q — nl6#591 deleted writeMem from this "+
				"profile and deliberately left this neighbour alone (%s)",
				tc.profile, tc.oid, tc.object, got, tc.want, tc.why)
		}
	}
}
