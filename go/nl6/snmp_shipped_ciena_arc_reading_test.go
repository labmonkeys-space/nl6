/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// nl6#601, THIRD ARC of nl6#590. Cisco went first (nl6#592), Arista second
// (nl6#599), and this is Ciena's.
//
// THIS AUDIT FOUND NO DEFECTS. THERE IS NO DATA CHANGE, NO LEDGER AND NO
// REGISTRY ENTRY, AND THAT IS THE FINDING — not an omission and not an audit
// that was cut short. The file is named …_reading_test.go rather than
// …_ledger_test.go for a mechanical reason as well as an honest one: nl6#600's
// TestCorpusReversalRegistryCoversEveryLedgerFile requires every
// *_ledger_test.go to contribute exactly one reversal to newestFirstReversals,
// and a change that reverses nothing has nothing to register.
//
// ── the result, against the three that came before ──────────────────────────
//
// The series so far, quoted as a MISS rate the way docs/reference/snmp.md quotes
// every audit:
//
//	Palo Alto (nl6#569)   8 of 11 wrong
//	Cisco     (nl6#592)  11 of 13 wrong
//	Arista    (nl6#599)   6 of 6  wrong
//	Ciena     (nl6#601)   0 of 1  wrong
//
// The denominator here is 1 because that is all there was to check: the profile
// serves exactly ONE thing under 1.3.6.1.4.1.1271, the sysObjectID.0 VALUE, and
// zero OID names. It is correct.
//
// nl6#601 predicted the opposite in terms — "Set expectations from the base
// rate, not from hope: Palo Alto 8 of 11 wrong, Cisco 11 of 13, Arista 6 of 6.
// There is no reason to think this arc is better" — and told the implementer to
// plan for deletions. THAT EXPECTATION WAS WRONG, and the reason it was wrong is
// the useful part: this arc's data is the only one of the four that somebody had
// already read a MIB for. The trap catalog's own `comment` field cites the
// module, its LAST-UPDATED, the non-contiguous severity enum and an internal
// contradiction in the MIB, and every one of those claims re-checks out below.
// The corpus is not uniformly fabricated. It is split: what was read is right,
// what was guessed is mostly wrong, and the trap catalog is what a profile looks
// like when the reading happened before the data was written rather than years
// after it.
//
// ── what was read, and how to read the same bytes ───────────────────────────
//
// Two modules, fetched anonymously on 2026-09-01, cited by LAST-UPDATED and by
// the SHA-256 of the file read (the nl6#599 provenance convention — a revision
// string alone does not let a second reader confirm they read the same bytes):
//
//	CIENA-WS-MIB                201804270000Z  c7fe97de741c4334f23c4cf29644f604dd4bbedbac0bd51686c9ff2fa396ae78
//	CIENA-WS-NOTIFICATION-MIB   201611140000Z  821b50a6ebc7883e3ec3bbf9ababf9efb7e0970a0c774821c8acb38027a8af53
//
// Reproduce with:
//
//	curl -sS https://raw.githubusercontent.com/librenms/librenms/master/mibs/ciena/CIENA-WS-MIB | shasum -a 256
//	curl -sS https://raw.githubusercontent.com/kcsinclair/mibs/master/CIENA-WS-NOTIFICATION-MIB.mib | shasum -a 256
//
// BOTH COPIES ARE THIRD-PARTY MIRRORS AND THEIR PROVENANCE IS UNESTABLISHED.
// Ciena serves its MIBs from the myCiena portal, which is gated and was not
// tested. Neither mirrored file carries a copyright header at all — CIENA-WS-MIB
// opens straight into `CIENA-WS-MIB DEFINITIONS ::= BEGIN`, and the notification
// module into a bare `-- CIENA-WS-NOTIFICATION-MIB.my` comment. That may be how
// Ciena ships them or may be a header stripped in transit; nothing here can
// tell, so the reading is qualified by mirror as well as by revision. The trap
// catalog's own comment names the same kcsinclair mirror, so the notification
// module below is a RE-READING of the source that catalog was transcribed from,
// not an independent second source.
//
// NO MIB FILE OR EXTRACTED FIXTURE IS CHECKED IN, per the licensing finding
// recorded with nl6#592: no vendor grants redistribution, and LibreNMS files its
// own MIB tree as a GPL-non-compliant component rather than claiming the right.
// Licensing blocks the BYTES, not their DIGEST, which is what the table above is
// for. Everything below is a PINNED READING and never a live check — nothing in
// CI compares nl6 against a Ciena MIB.
//
// ── the arc, resolved rather than assumed ───────────────────────────────────
//
// From CIENA-WS-MIB, which is 72 lines long and defines nothing but structure:
//
//	ciena                  ::= { enterprises 1271 }   -- MODULE-IDENTITY
//	waveserver             ::= { ciena 3 }            -- "Root identifier for
//	                                                     Ciena's Waveserver product."
//	cienaWsConfigV1        ::= { waveserver 1 }       -- config, releases 1.0/1.1
//	cienaWsNotifications   ::= { waveserver 2 }
//	cienaWsStatistics      ::= { waveserver 3 }       -- STATUS obsolete
//	cienaWsConfig          ::= { waveserver 4 }       -- config, 1.2 and beyond
//	cienaWsPlatformConfig  ::= { waveserver 5 }       -- platform config, 1.2 and beyond
//
// EVERY CHILD OF waveserver IS A FUNCTIONAL AREA. The module defines NO
// model-specific product OID — there is no `waveserver5` node, no product
// registry, nothing that distinguishes a Waveserver 5 from a Waveserver Ai. So
// `waveserver` itself is the most specific identifier the MIB makes available,
// and answering sysObjectID.0 with it is right rather than lazy.
//
// ── the trap that this test exists to close ─────────────────────────────────
//
// `waveserver 5` IS cienaWsPlatformConfig. IT IS NOT "WAVESERVER 5 THE PRODUCT".
// The profile's slug is ciena_waveserver5 and the arc's fifth child is 5, and
// those two facts have nothing to do with each other. Anyone "correcting"
// sysObjectID.0 to 1.3.6.1.4.1.1271.3.5 to make it look more specific would
// point a collector's vendor detection at a CONFIGURATION SUBTREE — the same
// shape of plausible-looking invention nl6#599 found in Arista's sysObjectID,
// where 1.3.6.1.4.1.30065.1.3011.7280.3282.32.4 was well formed, under the right
// PEN, under the right sysObjectID root, and not a product. TestCienaArcMatchesTheMIB
// rejects 1271.3.5 BY NAME and says what it is.
//
// ── the trap catalog, and why it is part of this reading ────────────────────
//
// nl6#601 put this arc ahead of the other fifteen because of consumer coupling:
// 1.3.6.1.4.1.1271 carries 165 references from the trap catalogs, against
// Juniper's 31 and Cisco's 29, and every other unaudited arc has zero. So the
// catalog is where a wrong sub-identifier would do the most damage, and it is
// audited here alongside the polled data.
//
// It was already written from a MIB reading. resources/ciena_waveserver5/traps.json
// carries a `comment` recording the module, its LAST-UPDATED, the one-notification
// -type-with-state-varbinds model, the non-contiguous severity enum, and — the
// part worth keeping — that THE MIB CONTRADICTS ITSELF and which side the
// transcription took. Every one of those claims was re-verified against the two
// modules above, and every one holds. The tests below pin the facts a future
// tidy-up could silently break; TestOpticalTrapOverlayMatchesTheMIB
// (optical_alarm_manager_test.go, shipped with the profile) already pins the four
// entries' severities and condition flags, and this file deliberately does not
// restate those.
//
// ── what this audit did NOT close ───────────────────────────────────────────
//
//   - SEMANTIC faithfulness of the MIB-II and ifXTable rows. ciena_waveserver5
//     serves 86 shipped SNMP entries, 85 of them mib-2, and this reading says
//     nothing about any of them; the arc audits are scoped to enterprise arcs by
//     construction.
//   - The optical values themselves. They come from optical_cycler.go, not from
//     a resource file, and no Ciena MIB governs them — the served model is
//     OpenConfig (see gnmi_paths.go and TestOpticalPathManifest).
//   - Whether the mirrored modules are what Ciena ships. See the provenance note.

// cienaArcProfile is the one profile this reading is about.
const cienaArcProfile = "ciena_waveserver5.json"

// The arc, spelled once. cienaArcRoot is dotted because findNextOIDWithServed
// walks the dotted spelling; the rest are undotted because they appear in the
// VALUE position, which carries no leading dot.
const (
	cienaArcRoot = ".1.3.6.1.4.1.1271"

	// cienaWaveserverRoot is { ciena 3 }, "Root identifier for Ciena's
	// Waveserver product", and the value sysObjectID.0 answers.
	cienaWaveserverRoot = "1.3.6.1.4.1.1271.3"

	// cienaWsPlatformConfigOID is { waveserver 5 } — the near miss. Named as a
	// constant so the rejection below cannot degrade into a bare string a
	// reader mistakes for the right answer.
	cienaWsPlatformConfigOID = "1.3.6.1.4.1.1271.3.5"

	// cienaWsLinkStateNotifOID is wsLinkStateAlarmNotification, derived rather
	// than copied: { cienaWsNotifications 12 } where cienaWsNotifications is
	// { waveserver 2 }. Note the notification objects hang off
	// cienaWsNotifications DIRECTLY — the module identity cienaWsNotificationMIB
	// is { cienaWsNotifications 3 }, a sibling of the notifications rather than
	// their parent, which is unusual enough to write down.
	cienaWsLinkStateNotifOID = "1.3.6.1.4.1.1271.3.2.12"
)

// cienaWaveserverChildren is the reading of CIENA-WS-MIB 201804270000Z: every
// child of `waveserver`, and what each one is.
//
// THE POINT OF THE TABLE IS THAT NONE OF THEM IS A PRODUCT. It is transcribed,
// so it is a record of a reading and not a verification — but the arithmetic
// over it below (that 5 is a config subtree, that no entry is a product OID) is
// derived, which is what makes a mutation of any row fail rather than pass
// quietly.
var cienaWaveserverChildren = map[int]struct{ name, what string }{
	1: {"cienaWsConfigV1", "configuration for the Waveserver 1.0 and 1.1 releases"},
	2: {"cienaWsNotifications", "notifications; wsAlarmNotification and wsLinkStateAlarmNotification hang here"},
	3: {"cienaWsStatistics", "statistics — STATUS obsolete"},
	4: {"cienaWsConfig", "root object for the Waveserver API in 1.2 and beyond"},
	5: {"cienaWsPlatformConfig", "root object for the Waveserver PLATFORM API in 1.2 and beyond"},
}

// TestCienaArcMatchesTheMIB is the reading test, in the shape of
// TestAristaArcMatchesTheMIB. It is a RECORD OF A READING, never a live MIB
// check: what it asserts is the exact value served, the tag it goes out as, and
// the absence of any OID name under the arc. That the value is FAITHFUL comes
// from reading the two modules cited at the top of this file, and this function
// is the record of that reading.
//
// No load guard can see anything this test checks. The value encodes perfectly
// well (nl6#529's rule 2 asks whether an OID-typed value is ENCODABLE, never
// whether it RESOLVES), it is under the profile's own PEN (so nl6#588's vendor
// guard passes it by construction), and being a config subtree rather than a
// product is a property of a MIB, which nl6 does not have.
func TestCienaArcMatchesTheMIB(t *testing.T) {
	ciena := deviceForProfile(t, cienaArcProfile)

	// ── the one fact ──
	//
	// sysObjectID.0 is the vendor-detection surface: a collector resolves it
	// against the vendor's MIB tree, so the sub-identifiers are the value and
	// not decoration.
	const sysObjectID = ".1.3.6.1.2.1.1.2.0"
	got := ciena.findResponse(sysObjectID)

	if got == cienaWsPlatformConfigOID {
		t.Fatalf("sysObjectID.0 answers %s. THAT IS cienaWsPlatformConfig — { waveserver 5 } in "+
			"CIENA-WS-MIB 201804270000Z, \"Root object for the Waveserver Platform API in release "+
			"1.2 and beyond\" — NOT \"Waveserver 5 the product\". The profile slug is "+
			"ciena_waveserver5 and the arc's fifth child is 5, and those two facts are unrelated. "+
			"Pointing sysObjectID at it makes a collector's vendor detection resolve the node to a "+
			"CONFIGURATION SUBTREE. The correct answer is %s, waveserver itself: CIENA-WS-MIB "+
			"defines NO model-specific product OID, so the product root is the most specific "+
			"identifier available", got, cienaWaveserverRoot)
	}
	if got != cienaWaveserverRoot {
		t.Errorf("sysObjectID.0 answers %q, want %q. That is `waveserver`, { ciena 3 } in "+
			"CIENA-WS-MIB 201804270000Z, whose DESCRIPTION is \"Root identifier for Ciena's "+
			"Waveserver product.\" Every child of waveserver (1..5) is a FUNCTIONAL AREA — config, "+
			"notifications, obsolete statistics, config, platform config — and the module defines no "+
			"product registry at all, so there is nothing more specific to point at. A more specific "+
			"looking value here would be invented, which is the nl6#569 defect", got, cienaWaveserverRoot)
	}
	if enc := encodeTypedValue(sysObjectID, got); len(enc) == 0 || enc[0] != ASN1_OBJECT_ID {
		t.Errorf("sysObjectID.0 emits % x, want tag 0x%02X", enc, ASN1_OBJECT_ID)
	}

	// ── the children of waveserver, and what makes 1271.3.5 a trap ──
	//
	// Derived from the table rather than restated, so editing a row fails here
	// instead of leaving a comment that disagrees with the code below it.
	if len(cienaWaveserverChildren) != 5 {
		t.Errorf("the reading records %d children of waveserver, want 5 (1..5). CIENA-WS-MIB "+
			"201804270000Z defines exactly cienaWsConfigV1, cienaWsNotifications, "+
			"cienaWsStatistics, cienaWsConfig and cienaWsPlatformConfig",
			len(cienaWaveserverChildren))
	}
	for i := 1; i <= 5; i++ {
		c, ok := cienaWaveserverChildren[i]
		if !ok {
			t.Errorf("the reading has no entry for { waveserver %d }", i)
			continue
		}
		if !strings.HasPrefix(c.name, "cienaWs") {
			t.Errorf("{ waveserver %d } is recorded as %q, which is not a cienaWs* node; every "+
				"child of waveserver in CIENA-WS-MIB is one", i, c.name)
		}
	}
	if c := cienaWaveserverChildren[5]; c.name != "cienaWsPlatformConfig" {
		t.Errorf("{ waveserver 5 } is recorded as %q, want cienaWsPlatformConfig. That row is the "+
			"whole reason %s is rejected above: 5 is a configuration subtree, not a product",
			c.name, cienaWsPlatformConfigOID)
	}

	// ── the arc carries no OID NAME at all ──
	//
	// Asserted as a WALK from the PEN root rather than as named absences, so an
	// invented Ciena object added later fails here instead of arriving
	// unguarded. Same construction, and the same trap, as nl6#599's:
	// findNextOIDWithServed answers end-of-MIB with an EMPTY string, and OIDs
	// sort as strings, so 1.3.6.1.4.1.1271 sorts ABOVE every mib-2 OID this
	// profile serves and genuinely has no successor. An empty answer is the
	// CORRECT verdict, so "the successor is not under the arc" is also satisfied
	// by a walk that saw nothing — which is why the positive control below is
	// what makes the emptiness mean anything.
	t.Run("positive control: the walk can see an object in the arc", func(t *testing.T) {
		planted := deviceForProfileWithPlantedOID(t, cienaArcProfile,
			cienaWaveserverRoot+".4.99.0", "planted")
		next, _ := planted.findNextOIDWithServed(cienaArcRoot, planted.lldpServedOIDs())
		if !strings.HasPrefix(next, cienaArcRoot+".") {
			t.Fatalf("with an object planted at %s.4.99.0, walking from %s reaches %q — the walk "+
				"cannot see the Ciena arc at all, so the emptiness check in the parent test proves "+
				"nothing", cienaWaveserverRoot, cienaArcRoot, next)
		}
	})

	next, _ := ciena.findNextOIDWithServed(cienaArcRoot, ciena.lldpServedOIDs())
	if next != "" {
		t.Errorf("walking from %s reaches %s, so ciena_waveserver5 now serves an object under "+
			"Ciena's enterprise arc. It served none at the time of this reading, and CIENA-WS-MIB "+
			"201804270000Z defines no OBJECT-TYPE whatsoever — it is 72 lines of structure. Any "+
			"object added here needs a reading of the module that defines it, not a plausible "+
			"number", cienaArcRoot, next)
	}
}

// TestCienaArcIsExactlyOneFactInTheValuePosition is the dual-position scan, and
// it is what makes "0 of 1 wrong" a MEASUREMENT rather than a claim about
// whichever OIDs happened to be looked at.
//
// BOTH POSITIONS, because reading names only is the blind spot that hid the AWS
// defect in nl6#588 and the first cut of nl6#587's guard: an enterprise OID can
// be a varbind NAME or an OID-typed VALUE, and sysObjectID — the single most
// consequential one — is always a value. Here the count in the name position is
// ZERO and in the value position is ONE, so a scan that read names only would
// have reported this arc as absent from the corpus entirely.
func TestCienaArcIsExactlyOneFactInTheValuePosition(t *testing.T) {
	const bareArc = "1.3.6.1.4.1.1271"

	var names, values []string
	profileEntries := 0
	for _, e := range shippedSNMPEntries(t) {
		if e.Profile != cienaArcProfile {
			continue
		}
		profileEntries++
		if strings.HasPrefix(strings.TrimPrefix(e.OID, "."), bareArc) {
			names = append(names, e.OID)
		}
		// The VALUE position is gated by the PRODUCTION predicate, the same one
		// collectShippedOIDs uses, rather than by string shape: a value only
		// reaches the wire as an OID if snmpTypeTag says the leaf is one.
		if snmpTypeTag(e.OID) == ASN1_OBJECT_ID && strings.HasPrefix(e.Value, bareArc) {
			values = append(values, e.OID+" = "+e.Value)
		}
	}
	if profileEntries == 0 {
		t.Fatalf("no SNMP entries found for %s; the scan is looking at the wrong profile",
			cienaArcProfile)
	}
	sort.Strings(names)
	sort.Strings(values)

	if len(names) != 0 {
		t.Errorf("%s serves %d OID NAME(s) under %s: %v. It served none at the time of this "+
			"reading, and CIENA-WS-MIB 201804270000Z defines no OBJECT-TYPE at all, so any name "+
			"here answers an object that module does not define", cienaArcProfile, len(names),
			bareArc, names)
	}
	if len(values) != 1 {
		t.Fatalf("%s serves %d OID-typed VALUE(s) under %s, want exactly 1 (sysObjectID.0): %v. "+
			"That count is the denominator of this audit's \"0 of 1\" result, quoted in the header "+
			"of this file and in docs/reference/snmp.md", cienaArcProfile, len(values), bareArc,
			values)
	}
	if want := ".1.3.6.1.2.1.1.2.0 = " + cienaWaveserverRoot; values[0] != want {
		t.Errorf("the one Ciena-arc value is %q, want %q", values[0], want)
	}

	// The positive control: the scan must be able to SEE a name in the name
	// position, or "zero names" is also satisfied by a scan that reads nothing.
	// The two positions are gathered by different code, so both are controlled.
	t.Run("positive control", func(t *testing.T) {
		planted := shippedSNMPEntry{
			Profile: cienaArcProfile,
			OID:     ".1.3.6.1.4.1.1271.3.4.1.0",
			Value:   "planted",
		}
		if !strings.HasPrefix(strings.TrimPrefix(planted.OID, "."), bareArc) {
			t.Fatal("the name-position predicate does not match an OID under the Ciena arc")
		}
		if snmpTypeTag(".1.3.6.1.2.1.1.2.0") != ASN1_OBJECT_ID {
			t.Fatal("the value-position gate does not classify sysObjectID as OID-typed, so the " +
				"value scan above reads nothing")
		}
	})

	t.Logf("%d shipped entries on %s: %d names and %d OID-typed values under %s",
		profileEntries, cienaArcProfile, len(names), len(values), bareArc)
}

// ── the notification module ─────────────────────────────────────────────────

// cienaSeverityEnum is wsLinkStateAlarmNotificationSeverity's INTEGER enum, read
// out of CIENA-WS-NOTIFICATION-MIB 201611140000Z. wsAlarmNotificationSeverity
// carries the identical set.
//
// IT IS NON-CONTIGUOUS: 2 and 7 are not members. That is the fact a "tidy-up"
// destroys — renumbering to 1..6 looks like cleanup and silently changes what
// every shipped optical trap tells a collector, since a Waveserver's own
// severity mapping is what an alarm rule keys on.
var cienaSeverityEnum = map[string]int{
	"cleared":  1,
	"critical": 3,
	"major":    4,
	"minor":    5,
	"warning":  6,
	"info":     8,
}

// cienaEthObjectsClauseNames are the eight Ethernet-defect objects NAMED in
// wsLinkStateAlarmNotification's OBJECTS clause, in clause order.
//
// TWO OF THEM ARE NOT DEFINED ANYWHERE IN THE MODULE. See
// cienaEthDefinedObjects.
var cienaEthObjectsClauseNames = []string{
	"wsLinkStateAlarmNotificationEthFecLossSync",
	"wsLinkStateAlarmNotificationEthEBer",
	"wsLinkStateAlarmNotificationEthRsLf",
	"wsLinkStateAlarmNotificationEthRsRf",
	"wsLinkStateAlarmNotificationEthPcsLobl",
	"wsLinkStateAlarmNotificationEthPcsLoam",
	"wsLinkStateAlarmNotificationEthPcsLol",
	"wsLinkStateAlarmNotificationEthRsLinkDown",
}

// cienaEthDefinedObjects are the eight OBJECT-TYPEs actually DEFINED under
// wsLinkStateAlarmNotificationEthDefects ({ wsLinkStateAlarmNotification 11 }),
// keyed by sub-identifier.
//
// Two of these — EthPcsHighBer and EthPmaSool — appear in NO OBJECTS clause, and
// two clause names — EthEBer and EthPcsLol — have NO definition. The module
// contradicts itself, and the shipped catalog's `comment` records which side it
// took: the OBJECT-TYPE definitions, because those are what an agent can
// actually encode and what a manager can actually resolve. A name with no
// definition has no sub-identifier, so transcribing the clause was never an
// option — the choice was between the definitions and inventing two numbers.
var cienaEthDefinedObjects = map[int]string{
	1: "wsLinkStateAlarmNotificationEthPcsHighBer",
	2: "wsLinkStateAlarmNotificationEthPcsLoam",
	3: "wsLinkStateAlarmNotificationEthPcsLobl",
	4: "wsLinkStateAlarmNotificationEthRsLinkDown",
	5: "wsLinkStateAlarmNotificationEthRsLf",
	6: "wsLinkStateAlarmNotificationEthRsRf",
	7: "wsLinkStateAlarmNotificationEthFecLossSync",
	8: "wsLinkStateAlarmNotificationEthPmaSool",
}

// cienaNotifSubtreeWidths is the number of OBJECT-TYPE definitions under each of
// wsLinkStateAlarmNotification's four defect containers, keyed by the
// container's sub-identifier.
var cienaNotifSubtreeWidths = map[int]struct {
	container string
	width     int
}{
	10: {"wsLinkStateAlarmNotificationPtpDefects", 4},
	11: {"wsLinkStateAlarmNotificationEthDefects", 8},
	12: {"wsLinkStateAlarmNotificationOtuDefects", 8},
	13: {"wsLinkStateAlarmNotificationOduDefects", 10},
}

// cienaNotifScalarSubIDs are the scalar (non-container) objects of
// wsLinkStateAlarmNotification, by sub-identifier.
//
// 6 IS DELIBERATELY ABSENT AND THAT IS A READING, NOT A GAP. wsAlarmNotification
// — the OTHER notification in the module, at { cienaWsNotifications 11 } — has a
// TableId at .6. wsLinkStateAlarmNotification does not: its definitions run
// .1 .2 .3 .4 .5 then jump to .7. Emitting a `.6.0` varbind on a link-state
// notification would name an object that exists only on the sibling
// notification, which is exactly the cross-subtree contamination nl6#569 found
// on the Palo Alto profile, one arc deeper.
var cienaNotifScalarSubIDs = map[int]string{
	1:  "wsLinkStateAlarmNotificationSiteId",
	2:  "wsLinkStateAlarmNotificationGroupId",
	3:  "wsLinkStateAlarmNotificationMemberId",
	4:  "wsLinkStateAlarmNotificationInstanceId",
	5:  "wsLinkStateAlarmNotificationDateAndTime",
	7:  "wsLinkStateAlarmNotificationSeverity",
	8:  "wsLinkStateAlarmNotificationInstance",
	9:  "wsLinkStateAlarmNotificationDescription",
	14: "wsLinkStateAlarmNotificationEntityType",
}

// TestCienaNotificationMIBReadingIsSelfConsistent pins the READING of
// CIENA-WS-NOTIFICATION-MIB 201611140000Z that the shipped trap catalog was
// transcribed from — separately from the catalog, so a claim about the MIB and a
// claim about the JSON cannot be conflated.
//
// The tables above are transcribed and are therefore a record, not a
// verification. What this test adds is the ARITHMETIC over them, which is
// derived: the severity enum's non-contiguity, the exact shape of the module's
// self-contradiction, and the census the catalog's varbind count has to match.
// Mutating any row moves one of those, so a "tidy" edit fails here.
func TestCienaNotificationMIBReadingIsSelfConsistent(t *testing.T) {
	// ── the severity enum is non-contiguous ──
	seen := map[int]string{}
	for name, v := range cienaSeverityEnum {
		if prev, dup := seen[v]; dup {
			t.Errorf("severity %d is recorded twice, as %s and %s", v, prev, name)
		}
		seen[v] = name
	}
	if len(cienaSeverityEnum) != 6 {
		t.Errorf("the severity enum has %d members, want 6: cleared(1) critical(3) major(4) "+
			"minor(5) warning(6) info(8)", len(cienaSeverityEnum))
	}
	for _, gap := range []int{0, 2, 7} {
		if name, ok := seen[gap]; ok {
			t.Errorf("severity %d is recorded as %q, but wsLinkStateAlarmNotificationSeverity's "+
				"enum in CIENA-WS-NOTIFICATION-MIB 201611140000Z SKIPS %d. The enum is "+
				"cleared(1) critical(3) major(4) minor(5) warning(6) info(8) — renumbering it to a "+
				"contiguous 1..6 looks like cleanup and changes what every shipped optical trap "+
				"tells a collector", gap, name, gap)
		}
	}
	if max := 8; seen[max] != "info" {
		t.Errorf("severity 8 is %q, want info — 8 is the enum's top value and the reason it is "+
			"non-contiguous", seen[max])
	}

	// ── the module contradicts itself, and the shape of the contradiction ──
	//
	// This is the fact most at risk from a well-meaning edit: someone comparing
	// the OBJECTS clause with the definitions will find they disagree and may
	// "fix" one side. Pinning the disagreement as an exact arithmetic means such
	// an edit has to be a decision.
	defined := map[string]int{}
	for sub, name := range cienaEthDefinedObjects {
		if prev, dup := defined[name]; dup {
			t.Errorf("%s is recorded at both .%d and .%d", name, prev, sub)
		}
		defined[name] = sub
	}
	inClause := map[string]bool{}
	for _, n := range cienaEthObjectsClauseNames {
		inClause[n] = true
	}

	var namedButUndefined, definedButUnnamed []string
	for _, n := range cienaEthObjectsClauseNames {
		if _, ok := defined[n]; !ok {
			namedButUndefined = append(namedButUndefined, n)
		}
	}
	for _, n := range cienaEthDefinedObjects {
		if !inClause[n] {
			definedButUnnamed = append(definedButUnnamed, n)
		}
	}
	sort.Strings(namedButUndefined)
	sort.Strings(definedButUnnamed)

	wantNamedButUndefined := []string{
		"wsLinkStateAlarmNotificationEthEBer",
		"wsLinkStateAlarmNotificationEthPcsLol",
	}
	wantDefinedButUnnamed := []string{
		"wsLinkStateAlarmNotificationEthPcsHighBer",
		"wsLinkStateAlarmNotificationEthPmaSool",
	}
	if !slices.Equal(namedButUndefined, wantNamedButUndefined) {
		t.Errorf("the OBJECTS clause names %v with no OBJECT-TYPE definition, want %v. The "+
			"module's self-contradiction is the reason resources/ciena_waveserver5/traps.json "+
			"transcribes the DEFINITIONS and says so in its comment; changing which names are "+
			"undefined changes whether that choice was the right one",
			namedButUndefined, wantNamedButUndefined)
	}
	if !slices.Equal(definedButUnnamed, wantDefinedButUnnamed) {
		t.Errorf("%v are defined as OBJECT-TYPEs but named in no OBJECTS clause, want %v",
			definedButUnnamed, wantDefinedButUnnamed)
	}
	if len(cienaEthObjectsClauseNames) != len(cienaEthDefinedObjects) {
		t.Errorf("the clause names %d Ethernet objects and %d are defined; they disagree on "+
			"MEMBERSHIP, not on COUNT, and that distinction is what makes the sub-identifiers "+
			"1..8 usable at all", len(cienaEthObjectsClauseNames), len(cienaEthDefinedObjects))
	}

	// ── the census the catalog has to match ──
	//
	// RFC-style: the OBJECTS clause lists 39 objects, and the definitions add up
	// to the same 39 once the two contradicting pairs cancel. Derived from the
	// tables rather than asserted, so it moves when they do.
	total := len(cienaNotifScalarSubIDs)
	for _, c := range cienaNotifSubtreeWidths {
		total += c.width
	}
	if total != cienaNotifObjectCount {
		t.Errorf("the reading adds up to %d objects under wsLinkStateAlarmNotification, want %d "+
			"(9 scalars + 4 Ptp + 8 Eth + 8 Otu + 10 Odu). That total is what the shipped "+
			"catalog's varbind count is checked against", total, cienaNotifObjectCount)
	}
	if w := cienaNotifSubtreeWidths[11]; w.width != len(cienaEthDefinedObjects) {
		t.Errorf("the Eth container is recorded as %d wide but %d objects are enumerated under it",
			w.width, len(cienaEthDefinedObjects))
	}

	// ── .6 does not exist on THIS notification ──
	if name, ok := cienaNotifScalarSubIDs[6]; ok {
		t.Errorf("the reading records { wsLinkStateAlarmNotification 6 } as %q. It does not "+
			"exist: the definitions run .1 .2 .3 .4 .5 and jump to .7. The TableId at .6 belongs "+
			"to wsAlarmNotification, the SIBLING notification at { cienaWsNotifications 11 }, and "+
			"borrowing it would put an object from one notification into another's varbind list",
			name)
	}
	if _, ok := cienaNotifScalarSubIDs[7]; !ok {
		t.Error("the reading has no { wsLinkStateAlarmNotification 7 }; Severity is the object " +
			"immediately after the .6 gap and the whole point of recording the gap")
	}
}

// cienaNotifObjectCount is the number of objects wsLinkStateAlarmNotification's
// OBJECTS clause lists, and therefore the number of body varbinds a faithful
// transcription emits. Spelled once and read by both tests below.
const cienaNotifObjectCount = 39

// TestCienaTrapCatalogMatchesTheNotificationMIB checks the SHIPPED CATALOG
// against the reading above.
//
// The catalog was already written from a MIB reading — its `comment` cites the
// module, the revision, the severity enum and the self-contradiction — and this
// test is what keeps that reasoning from being tidied away by someone who reads
// the JSON and not the comment. It deliberately does NOT restate what
// TestOpticalTrapOverlayMatchesTheMIB already pins (the four entries' severities
// and their SD/SF condition flags); what it adds is the STRUCTURE those values
// sit in.
//
// Read against the JSON rather than the loaded catalog, for the reason
// TestOpticalTrapOverlayMatchesTheMIB gives: the loader compiles varbinds into
// templates and hides the raw OID, so it cannot answer a question about
// transcription. The catalog is also loaded, at the end, so a file that pins
// perfectly and does not load fails.
func TestCienaTrapCatalogMatchesTheNotificationMIB(t *testing.T) {
	const catalogPath = "resources/ciena_waveserver5/traps.json"
	raw, err := os.ReadFile(catalogPath)
	if err != nil {
		t.Fatalf("read %s: %v", catalogPath, err)
	}
	var doc struct {
		Comment string `json:"comment"`
		Traps   []struct {
			Name               string `json:"name"`
			SnmpTrapOID        string `json:"snmpTrapOID"`
			SnmpTrapEnterprise string `json:"snmpTrapEnterprise"`
			Varbinds           []struct {
				OID   string `json:"oid"`
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"varbinds"`
		} `json:"traps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", catalogPath, err)
	}
	if len(doc.Traps) == 0 {
		t.Fatalf("%s has no entries; every assertion below would be vacuous", catalogPath)
	}

	// THE COMMENT IS PART OF THE DATA. It is the only place the transcription's
	// reasoning lives, and it is what distinguishes this profile from the three
	// audited arcs that were wrong. A future edit that strips it should fail.
	for _, must := range []string{
		"CIENA-WS-NOTIFICATION-MIB",
		"201611140000Z",
		"cleared(1) critical(3) major(4) minor(5) warning(6) info(8)",
		"EthEBer/EthPcsLol",
		"EthPcsHighBer/EthPmaSool",
	} {
		if !strings.Contains(doc.Comment, must) {
			t.Errorf("%s's comment no longer records %q. That comment is the transcription's "+
				"provenance — module, revision, the non-contiguous severity enum, and the MIB's "+
				"own self-contradiction over which Ethernet defect objects exist. Every one of "+
				"those claims was re-verified in nl6#601 and holds; stripping them makes the "+
				"catalog indistinguishable from the invented data the other three arc audits "+
				"found", catalogPath, must)
		}
	}

	// Sub-identifiers the reading says a faithful varbind list uses. Built from
	// the reading's own tables, so a MIB-reading edit propagates here.
	wantSubIDs := map[string]string{}
	for sub, name := range cienaNotifScalarSubIDs {
		wantSubIDs[strconv.Itoa(sub)] = name
	}
	for container, c := range cienaNotifSubtreeWidths {
		for i := 1; i <= c.width; i++ {
			wantSubIDs[strconv.Itoa(container)+"."+strconv.Itoa(i)] = c.container + "." + strconv.Itoa(i)
		}
	}

	for _, e := range doc.Traps {
		if e.SnmpTrapOID != cienaWsLinkStateNotifOID {
			t.Errorf("%s: snmpTrapOID %q, want %q — wsLinkStateAlarmNotification, derived as "+
				"{ cienaWsNotifications 12 } with cienaWsNotifications = { waveserver 2 }",
				e.Name, e.SnmpTrapOID, cienaWsLinkStateNotifOID)
		}
		if e.SnmpTrapEnterprise != "1.3.6.1.4.1.1271" {
			t.Errorf("%s: snmpTrapEnterprise %q, want Ciena's PEN 1.3.6.1.4.1.1271",
				e.Name, e.SnmpTrapEnterprise)
		}
		if len(e.Varbinds) != cienaNotifObjectCount {
			t.Errorf("%s carries %d body varbinds, want %d — one per object in "+
				"wsLinkStateAlarmNotification's OBJECTS clause (9 scalars + 4 Ptp + 8 Eth + "+
				"8 Otu + 10 Odu)", e.Name, len(e.Varbinds), cienaNotifObjectCount)
		}

		var ethSubIDs []string
		for _, vb := range e.Varbinds {
			rest, ok := strings.CutPrefix(vb.OID, cienaWsLinkStateNotifOID+".")
			if !ok {
				t.Errorf("%s: varbind %s is not under %s", e.Name, vb.OID,
					cienaWsLinkStateNotifOID)
				continue
			}
			// Every varbind names an INSTANCE, so the trailing .0 comes off
			// before the object is resolved. A bare object OID would never match
			// a collector's instance-exact rule.
			sub, ok := strings.CutSuffix(rest, ".0")
			if !ok {
				t.Errorf("%s: varbind %s lacks the .0 instance sub-identifier", e.Name, vb.OID)
				continue
			}
			if _, ok := wantSubIDs[sub]; !ok {
				t.Errorf("%s: varbind %s resolves to { wsLinkStateAlarmNotification %s }, which "+
					"CIENA-WS-NOTIFICATION-MIB 201611140000Z does not define. If this is .6, note "+
					"that TableId belongs to the SIBLING notification wsAlarmNotification, not to "+
					"this one", e.Name, vb.OID, sub)
			}
			if strings.HasPrefix(sub, "11.") {
				ethSubIDs = append(ethSubIDs, strings.TrimPrefix(sub, "11."))
			}
		}

		// THE ETHERNET BLOCK IS THE CONTRADICTION MADE CONCRETE. It is emitted in
		// numeric sub-identifier order 1..8, which is the OBJECT-TYPE definitions'
		// order. The OBJECTS clause's order would be 7, ?, 5, 6, 3, 2, ?, 4 — with
		// two of the eight having no sub-identifier at all, because they have no
		// definition to take one from. So following the clause was never possible
		// without inventing two numbers, which is the choice the catalog's comment
		// records having declined.
		if want := []string{"1", "2", "3", "4", "5", "6", "7", "8"}; !slices.Equal(ethSubIDs, want) {
			t.Errorf("%s: the Ethernet defect block emits sub-identifiers %v, want %v in that "+
				"order. Numeric order IS the OBJECT-TYPE definitions' order; the OBJECTS clause "+
				"order (7, EthEBer, 5, 6, 3, 2, EthPcsLol, 4) cannot be followed at all, because "+
				"EthEBer and EthPcsLol have no definition and therefore no sub-identifier",
				e.Name, ethSubIDs, want)
		}

		// The severity value must be a MEMBER of the non-contiguous enum, and
		// resolve to the name the entry's own name implies. This is where a
		// renumbered cienaSeverityEnum fails.
		sev := ""
		for _, vb := range e.Varbinds {
			if vb.OID == cienaWsLinkStateNotifOID+".7.0" {
				sev = vb.Value
			}
		}
		wantSeverityName := "cleared"
		switch {
		case strings.HasSuffix(e.Name, "SdRaise"):
			wantSeverityName = "minor"
		case strings.HasSuffix(e.Name, "SfRaise"):
			wantSeverityName = "critical"
		}
		if got := cienaSeverityEnum[wantSeverityName]; strconv.Itoa(got) != sev {
			t.Errorf("%s: severity varbind = %q, but the reading gives %s(%d). A pre-FEC signal "+
				"DEGRADE is minor and a signal FAIL is critical; a clear is cleared(1). If this "+
				"fails after an edit to cienaSeverityEnum, the enum is what moved — "+
				"CIENA-WS-NOTIFICATION-MIB 201611140000Z skips 2 and 7", e.Name, sev,
				wantSeverityName, got)
		}
	}

	// And it must load through the production loader, roles intact.
	if _, err := LoadCatalogFromFile(catalogPath); err != nil {
		t.Fatalf("%s does not load: %v", catalogPath, err)
	}
}

// TestCienaTrapAndPolledDataAgreeOnEveryOID is nl6#593's class, checked
// explicitly here because nl6#601 asked for it: with 165 trap references against
// one profile's polled data, this arc is where a trap declaring a type that
// disagrees with what a GET answers is most likely. cisco_ios demonstrably
// violated it — its trap declared ciscoEnvMonSupplyStatusDescr as octet-string
// while a GET answered INTEGER.
//
// THE RESULT IS ZERO OVERLAP, AND THAT IS A MEASUREMENT, NOT AN ASSUMPTION. The
// profile's polled entries are entirely mib-2; every trap varbind is under
// wsLinkStateAlarmNotification. There is no shared OID, so there is nothing to
// disagree about — which is why this test asserts the disjointness rather than
// comparing types that do not exist.
func TestCienaTrapAndPolledDataAgreeOnEveryOID(t *testing.T) {
	polled := map[string]string{}
	for _, e := range shippedSNMPEntries(t) {
		if e.Profile != cienaArcProfile {
			continue
		}
		polled[strings.TrimPrefix(e.OID, ".")] = e.Value
	}
	if len(polled) == 0 {
		t.Fatalf("no polled entries for %s", cienaArcProfile)
	}

	cat, err := LoadCatalogFromFile("resources/ciena_waveserver5/traps.json")
	if err != nil {
		t.Fatalf("load ciena trap catalog: %v", err)
	}
	trapOIDs := map[string]TrapVarbindType{}
	for _, e := range cat.Entries {
		for _, vb := range e.Varbinds {
			// rawOID, not the compiled template: a templated OID has no fixed
			// spelling to compare against a polled one, and none of the shipped
			// Ciena varbinds templates its OID.
			if strings.Contains(vb.rawOID, "{{") {
				continue
			}
			trapOIDs[strings.TrimPrefix(vb.rawOID, ".")] = vb.Type
		}
	}
	if len(trapOIDs) == 0 {
		t.Fatal("no literal trap varbind OIDs collected; the disjointness below would be vacuous")
	}

	var shared []string
	for oid := range trapOIDs {
		if _, ok := polled[oid]; ok {
			shared = append(shared, oid)
		}
	}
	sort.Strings(shared)

	if len(shared) != 0 {
		// Not a hard failure by itself — a shared OID is legal. What is not legal
		// is the two surfaces disagreeing about its type, and once one exists this
		// test has to be extended to compare them rather than to assert away the
		// overlap.
		t.Errorf("%s now shares %d OID(s) between its trap catalog and its polled data: %v. That "+
			"is legal, but nl6#593's defect lives exactly there — cisco_ios declared "+
			"ciscoEnvMonSupplyStatusDescr as octet-string in a trap while a GET answered INTEGER. "+
			"This test asserted DISJOINTNESS because there was nothing to compare; extend it to "+
			"compare snmpTypeTag against the varbind's declared type instead of relaxing it",
			cienaArcProfile, len(shared), shared)
	}

	t.Logf("%d polled OIDs and %d literal trap varbind OIDs on %s, sharing none",
		len(polled), len(trapOIDs), cienaArcProfile)
}
