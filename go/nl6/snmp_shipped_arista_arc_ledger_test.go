/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// nl6#590, SECOND ARC (PR #599). The Cisco arc went first
// (snmp_shipped_cisco_arc_ledger_test.go, PR #592); this is the Arista one, and
// it is the worst result of the three vendor subtrees audited so far.
//
// SIX ENTERPRISE-ARC FACTS WERE CHECKED AND NONE OF THEM WAS RIGHT. Five OIDs
// under 1.3.6.1.4.1.30065 name objects that do not exist or cannot be read, and
// the sysObjectID value is shaped like an Arista product OID without being one.
// Against nl6#569's 3 of 11 correct on the Palo Alto subtree and nl6#590's 2 of
// 13 on Cisco's, that is 0 of 6.
//
// ── what was read, and how to read the same bytes ───────────────────────────
//
// Five modules, fetched anonymously from https://www.arista.com/assets/data/docs/MIBS/<NAME>.txt
// on 2026-09-01. Each is cited by LAST-UPDATED **and by the SHA-256 of the file
// read**, because a revision string alone does not let a second reader confirm
// they read the same bytes — ARISTA-PRODUCTS-MIB in particular gains products
// continuously and its LAST-UPDATED moves with them. This is the nl6#588 /
// nl6#541 provenance convention (source, fetch date, and the exact artefact)
// applied to a file that cannot be checked in:
//
//	ARISTA-SMI-MIB               201408150000Z  3db704a6a977bbad3f5e54b23b5ab6b1a03ebcc7d5049d66c59648a0d71770c0
//	ARISTA-PRODUCTS-MIB          202603030000Z  f1dff8458987cc9d83327232f850c8e6a77a46c927944dcc06d1f5ce719be409
//	ARISTA-SW-IP-FORWARDING-MIB  201408150000Z  ba196b5d2e424cf030686b8d76529dd258fa9f69e5468571ec64a7aac80da607
//	ARISTA-GENERAL-MIB           201711060000Z  49d1f7803683053d01118d28fc54f59c7b7fa21f66dc45b4da943fb984ba55c3
//	ARISTA-ENTITY-SENSOR-MIB     202302100000Z  c879299d934dea06b4b31f72d815a1b4c2ba5e42fd9c35cabeef1117d0ed1236
//
// Reproduce with: curl -sS https://www.arista.com/assets/data/docs/MIBS/ARISTA-SMI-MIB.txt | shasum -a 256
//
// All five carry a MODULE-IDENTITY, so unlike nl6#591's SMIv1
// OLD-CISCO-SYSTEM-MIB there is a revision string to quote for each.
//
// NO MIB FILE OR EXTRACTED FIXTURE IS CHECKED IN. The reasoning is nl6#590's and
// is not restated: no vendor grants redistribution, Arista's own header asserts
// copyright ("Copyright (c) 2008 Arista Networks, Inc. All rights reserved.")
// and grants nothing, and LibreNMS files its own MIB tree as a GPL-non-compliant
// component rather than claiming the right. Licensing blocks checking in the
// BYTES; it does not block recording their DIGEST, which is why the table above
// exists. So this is a PINNED READING (TestAristaArcMatchesTheMIB below, the
// TestCiscoEnvMonAndMemoryPoolMatchTheMIB shape) and never a live check.
//
// ── the arc, resolved rather than assumed ───────────────────────────────────
//
// From ARISTA-SMI-MIB:
//
//	arista           ::= { enterprises 30065 }   -- assigned by IANA
//	aristaProducts   ::= { arista 1 }            -- "the root object identifier
//	                                                from which sysObjectID values
//	                                                are assigned"
//	aristaModules    ::= { arista 2 }
//	aristaMibs       ::= { arista 3 }
//
// From ARISTA-SW-IP-FORWARDING-MIB, which is the module at { aristaMibs 1 } —
// ARISTA-ENTITY-SENSOR-MIB sits at { aristaMibs 12 } and ARISTA-GENERAL-MIB at
// { aristaMibs 24 }, so nothing else claims 30065.3.1:
//
//	aristaSwIpForwardingMIB ::= { aristaMibs 1 }              -- 30065.3.1
//	aristaSwFwdIp           ::= { aristaSwIpForwardingMIB 1 } -- 30065.3.1.1
//	aristaSwFwdIpStatsTable ::= { aristaSwFwdIp 1 }           -- 30065.3.1.1.1
//
// aristaSwFwdIpStatsTable is aristaSwFwdIp's ONLY child. The module's other
// top-level node is aristaSwIpFwdMIBConformance at { aristaSwIpForwardingMIB 2 },
// which is 30065.3.1.2 and therefore not under 30065.3.1.1 at all.
//
// ── the five deletions ──────────────────────────────────────────────────────
//
// DELETION, NOT CORRECTION, and the reason is nl6#569's: four of the five name
// objects that do not exist, and the fifth names one that cannot be read.
// Inventing a plausible value for an unmodelled object is the defect nl6#569
// exists to stop, and inventing one for an object that is not defined at all
// would be worse.
//
//   - 30065.1.3.1.1.0 sits under aristaProducts, which ARISTA-SMI-MIB says holds
//     sysObjectID values and nothing else. WHAT WAS OBSERVED, stated as observed:
//     every one of ARISTA-PRODUCTS-MIB's 373 assignments names a subtree rooted at
//     aristaProducts whose FIRST sub-identifier is one of sixteen values — 138,
//     447, 1082, 1362, 1470, 1788, 2546, 2682, 2759, 3011, 3413, 3806, 7289, 7358,
//     7368, 7388 — and 3 is not among them. (The assignments themselves run
//     several sub-identifiers deep: the correction below is eight deep. The
//     observation is about the FIRST sub-identifier, which is what settles whether
//     30065.1.3 is a node.) So 30065.1.3.1.1.0 is not an object. It answered
//     "4.29.2F", an EOS version, which sysDescr already carries.
//   - 30065.3.1.1.1.0 is aristaSwFwdIpStatsTable with a scalar `.0` appended.
//     TWO faults at once, and either alone is fatal: a table object is
//     MAX-ACCESS not-accessible, so no GET of it can succeed at any name; and a
//     `.0` on a table is not a legal instance in the first place (the table's
//     rows are indexed by aristaSwFwdIpStatsIPVersion, two levels down). It
//     answered "AR-7280R3-001", a hostname, from an IP-forwarding statistics
//     table.
//   - 30065.3.1.1.2.0, .3.0 and .13.0 are aristaSwFwdIp.2, .3 and .13. Only .1
//     is defined under that node, so none of the three is an object. They
//     answered "31", "48" and "38".
//
// The first is the same shape as the nl6#571 bare-column class (a name that is
// not a legal instance) and the second is the same shape as nl6#591's
// access-mode class (an object that cannot be read). Neither guard sees these,
// because both were written against a specific reading and neither has the
// Arista MIB.
//
// ── the corrections, and the model-identity rule ────────────────────────────
//
// sysObjectID.0 answered 1.3.6.1.4.1.30065.1.3011.7280.3282.32.4. That is a
// well-formed OID under the right PEN, under the right sysObjectID root, and it
// is NOT A PRODUCT. ARISTA-PRODUCTS-MIB mentions "3011 7280" on 109 lines; the
// third sub-identifier observed there is one of 312, 877, 1347, 1359, 1964, 2655,
// 2727, 2899, 2972, 3101, 3232, 3714, 3735 or 3977, and never 3282. (3282 IS a
// real Arista sub-identifier — it appears under 7124, 7148, 7050 and, at a
// different depth, under 7280 2727 3 1810 32 2129 4 — which is exactly why the
// invented OID looks right.) So a collector doing vendor detection on sysObjectID
// got an unresolvable OID, which is the single surface nl6#587/#588/#589 spent
// three changes protecting.
//
// It now answers aristaDCS7280CR332P4M, which ARISTA-PRODUCTS-MIB assigns as
// { aristaProducts 3011 7280 2727 3 32 2129 4 972 }.
//
// THE PRODUCT'S NAME IS "DCS-7280CR3-32P4-M", NOT "DCS-7280CR3-32P4M", AND
// GETTING THAT WRONG WAS THE FIRST CUT OF THIS CHANGE. The ASN.1 IDENTIFIER
// `aristaDCS7280CR332P4M` strips punctuation from every product name in that
// module; the NAME is in the comment immediately above the assignment —
//
//	-- DCS-7280CR3-32P4-M 32x100GbE (QSFP100) & 4x400GbE (OSFP) Ethernet Switch with SSD
//	aristaDCS7280CR332P4M OBJECT IDENTIFIER ::= { aristaProducts 3011 7280 2727 3 32 2129 4 972 }
//
// — and again in the module's own revision note ("Revised to include
// DCS-7280CR3-32P4-M and DCS-7280CR3-32D4-M"). Reading the identifier as the name
// is exactly the wrong-MIB-reading class this whole audit exists to eliminate,
// committed inside the change that exists to eliminate it. Pinned by
// TestAristaArcMatchesTheMIB, which requires the MIB's spelling and REJECTS the
// hyphenless one by name.
//
// THE MODEL-IDENTITY RULE IS PROFILE-WIDE, NOT A sysDescr RULE. The first cut
// applied it at sysDescr.0 alone and left six other responses naming a product
// that does not exist, which made the profile self-contradictory in a way it had
// not been before: `grep -c 7280R3 ARISTA-PRODUCTS-MIB` returns 0, so the profile
// was ALREADY split between two fake models — "DCS-7280R3-32P4-M" in sysDescr and
// SSH, "DCS-7280R3-48C6" in the entity table — and correcting only the first
// created a real-versus-fake contradiction across surfaces. (The real 48C6
// products are DCS-7280SR-48C6, DCS-7280TR-48C6, DCS-7280SRA-48C6 and
// DCS-7280TRA-48C6: SR / TR series, not R3.) Every surface now names the one real
// product the sysObjectID identifies, and TestAristaProfileNamesNoFakeModel scans
// EVERY part of the profile — SNMP entries and SSH responses alike — for the
// string "7280R3".
//
// THE ONE WEAK CALL, recorded rather than smoothed over. entPhysicalModelName.2
// is the model name of "Module 1", a modelled line card, and it was
// "7280R3-48C6". It is corrected to "7280CR3-32P4-M" for consistency, and that is
// the weaker of the two kinds of call this change makes — the sysDescr, entity
// chassis and SSH rows all name the CHASSIS, which the sysObjectID settles, while
// nothing says a module of a fixed-configuration switch has that model name.
// DCS-7280CR3-32P4-M is fixed-configuration and has no pluggable line cards at
// all, so the honest residual is that the profile models a module the product
// does not have. That is a fidelity question about the ENTITY TABLE, not about
// the Arista arc, and it is left open rather than closed by deleting rows this
// audit did not read a MIB about. Same shape as nl6#590's fan-versus-supply
// asymmetry: the stronger call is settled by evidence, the weaker rests on
// consistency, and both are written down.
//
// THE EOS VERSION "4.29.2F" IS DELIBERATELY UNTOUCHED. It is plausible and it is
// not checkable against any MIB — no Arista module publishes a software-version
// registry — so changing it would be an unbacked edit in a change whose whole
// point is that unbacked edits are the defect.
//
// THE PROFILE DIRECTORY IS NOT RENAMED. resources/arista_7280r3/ keeps its name
// and so do its parts: the slug is an nl6 identifier, not a claim about
// hardware, and renaming it would churn every corpus test for no fidelity gain.
// docs/reference/snmp.md records the same decision.
//
// ── fleet-visible surface change ────────────────────────────────────────────
//
// Stated with counts, per the nl6#570 / nl6#574 convention, because this changes
// what a collector sees on every arista_7280r3 device in a running fleet:
//
//   - sysObjectID.0 and sysDescr.0 both change, so VENDOR DETECTION and asset
//     inventory resolve the node differently. sysObjectID was unresolvable and now
//     resolves to a real Arista product; that is the point of the change, not a
//     side effect.
//   - a walk of the profile returns FIVE FEWER OIDs (25152 -> 25147 shipped SNMP
//     entries corpus-wide), and the five that left were the profile's ONLY objects
//     under its own vendor's arc.
//   - four ENTITY-MIB responses and two SSH command outputs change their model
//     string. No OID is added or removed by those, and no tag moves.
//   - no other profile is touched: every edit is in resources/arista_7280r3/.
//
// ── why there is a ledger at all ────────────────────────────────────────────
//
// THREE pinned constants move, and WHICH ones was MEASURED by applying the edits
// and running the suite, not predicted:
//
//   - shippedTagDigest is keyed on (profile, OID, emitted tag). Five triples are
//     removed outright, so it moves. NO CORRECTION MOVES A TAG — sysDescr and the
//     four ENTITY-MIB rows stay OCTET STRINGs and sysObjectID stays an OBJECT
//     IDENTIFIER — which is worth stating because nine of nl6#590's ten Cisco
//     corrections did, and the habit of assuming a correction moves a tag is how a
//     ledger acquires a row it cannot justify.
//   - shippedOIDEncodingDigest hashes each DISTINCT shipped OID NAME against its
//     BER encoding, and collectShippedOIDs gathers OID-typed VALUES as well as
//     names. So this change moves it TWICE OVER: five names leave, and the
//     sysObjectID correction swaps one OID-typed value for another. That second
//     half is why the reversal here is not a pure append the way nl6#590's and
//     nl6#591's are — see nl6590aristaOIDNamesBeforeAudit.
//   - ownVendorArcNamesShipped falls from 333 to 328. ownVendorArcValuesShipped
//     stays 28: arista_7280r3 still answers sysObjectID under its own PEN, and a
//     value count that fell would mean a profile had stopped identifying itself.
//     The correction moves that value WITHIN 30065, so the guard has nothing to
//     say about it — a correct arc is all it checks, and both the old and the
//     new OID are under Arista's.
//
// The SSH rows move NOTHING: shippedSNMPEntries reads doc.SNMP only and
// collectShippedOIDs walks OID positions, so neither digest can see an SSH
// response. They are recorded here anyway, because the audit trail is the point
// and TestAristaProfileNamesNoFakeModel is what actually guards them.
//
// Every recorded oldValue was read OUT OF GIT at 2e16f91 (the revision this
// branch forked from) rather than retyped from the working tree —
// TestAristaArcLedgerValuesMatchTheParentRevision pins that. THE RESIDUAL,
// stated the way the rest of this change states its residuals: that test hashes
// the ledger's own rows against a constant a human derived by reading git, and it
// never reads git itself. So it catches any edit made AFTER the constant was set
// — which is the failure mode that actually happens, a table quietly "fixed" into
// agreeing with itself — and it cannot catch a row that was wrong at the moment
// the constant was computed. Closing that would mean shelling out to git from a
// test, which no ledger in this package does.
//
// This ledger is the NEWEST link in the chain. Every older ledger reverses to its
// own parent starting from today's corpus, so each of them now begins by undoing
// this change: the chain reads
// today -> 2e16f91 -> f47c85d -> 5bded6c -> 87c642d -> 1bca8e8 -> ec4700f -> 3a69927 -> 44ef67f.
//
// DEFERRED, and recorded in deferred-work.md rather than done here: a central
// registry of reversals — one ordered slice every ledger iterates — replacing the
// twelve hand-edited call sites this change had to touch. This is the fourth
// consecutive audit to pay that tax, and it is a refactor across nine files.

// aristaLedgerProfile is the one profile this whole ledger is about. Every row
// must name it; TestAristaArcLedgerIsNotVacuous enforces that, because a row
// naming another profile would assert an absence against the wrong device while
// every digest still reconciled.
const aristaLedgerProfile = "arista_7280r3.json"

// normaliseLedgerOID is the ONE spelling rule for this ledger. shippedSNMPEntries
// hands back OIDs through normaliseResourceOID, which prepends a dot, so the
// tables are written dotted — but the name view (collectShippedOIDs) is undotted,
// and OID-typed VALUES are undotted too. Routing every comparison through one
// helper is what stops a future row written with the other spelling from silently
// matching nothing.
func normaliseLedgerOID(oid string) string { return strings.TrimPrefix(oid, ".") }

// nl6590aristaDeletedEntries are the five shipped entries this change removed.
// Five distinct OIDs, all on one profile, none of them served anywhere else in
// the corpus.
//
// These were the ONLY 30065 OID NAMES arista_7280r3 shipped, so after this change
// the profile serves no object under its own vendor's arc at all — only the
// sysObjectID VALUE. That is correct and intended, exactly as nl6#571 left four
// profiles modelling no storage: a collector that gets nothing has learned that
// nl6 does not model Arista's software-forwarding statistics, while a collector
// that got "AR-7280R3-001" from aristaSwFwdIpStatsTable was told a hostname is an
// IP statistics table. DO NOT restore a row to make the arc non-empty.
var nl6590aristaDeletedEntries = []struct{ profile, oid, oldValue, object, why string }{
	{aristaLedgerProfile, ".1.3.6.1.4.1.30065.1.3.1.1.0", "4.29.2F",
		"undefined, under aristaProducts",
		"aristaProducts holds sysObjectID values only, and no ARISTA-PRODUCTS-MIB assignment has 3 as its first sub-identifier"},
	{aristaLedgerProfile, ".1.3.6.1.4.1.30065.3.1.1.1.0", "AR-7280R3-001",
		"aristaSwFwdIpStatsTable",
		"a table object is MAX-ACCESS not-accessible and .0 is not a legal instance of one"},
	{aristaLedgerProfile, ".1.3.6.1.4.1.30065.3.1.1.2.0", "31",
		"undefined, aristaSwFwdIp.2",
		"aristaSwFwdIpStatsTable at .1 is aristaSwFwdIp's only child"},
	{aristaLedgerProfile, ".1.3.6.1.4.1.30065.3.1.1.3.0", "48",
		"undefined, aristaSwFwdIp.3",
		"aristaSwFwdIpStatsTable at .1 is aristaSwFwdIp's only child"},
	{aristaLedgerProfile, ".1.3.6.1.4.1.30065.3.1.1.13.0", "38",
		"undefined, aristaSwFwdIp.13",
		"aristaSwFwdIpStatsTable at .1 is aristaSwFwdIp's only child"},
}

// nl6590aristaValueCorrections are the six SNMP entries that stayed but changed
// value. NONE moves the emitted tag, which the ledger records explicitly and
// TestAristaArcLedgerIsNotVacuous asserts THROUGH THE ENCODER rather than
// reasoning about from oidTypeTable.
//
// The sysObjectID row is the one that matters to a collector: it is the vendor
// detection surface. Its old value encodes perfectly well — that is the whole
// difficulty, and the reason no load rule could see it. nl6#529's rule 2 asks
// whether an OID-typed value is ENCODABLE, not whether it RESOLVES.
//
// The four ENTITY-MIB rows are the model-identity rule applied profile-wide; see
// the header. entPhysicalModelName.2 is the weak call recorded there.
var nl6590aristaValueCorrections = []struct {
	profile, oid, oldValue, newValue, object string
	oldTag, newTag                           byte
}{
	{aristaLedgerProfile, ".1.3.6.1.2.1.1.1.0",
		"Arista Networks EOS version 4.29.2F running on an Arista Networks DCS-7280R3-32P4-M",
		"Arista Networks EOS version 4.29.2F running on an Arista Networks DCS-7280CR3-32P4-M",
		"sysDescr", ASN1_OCTET_STRING, ASN1_OCTET_STRING},
	{aristaLedgerProfile, ".1.3.6.1.2.1.1.2.0",
		"1.3.6.1.4.1.30065.1.3011.7280.3282.32.4",
		"1.3.6.1.4.1.30065.1.3011.7280.2727.3.32.2129.4.972",
		"sysObjectID", ASN1_OBJECT_ID, ASN1_OBJECT_ID},
	{aristaLedgerProfile, ".1.3.6.1.2.1.47.1.1.1.1.2.1",
		"Arista Networks DCS-7280R3-48C6",
		"Arista Networks DCS-7280CR3-32P4-M",
		"entPhysicalDescr.1", ASN1_OCTET_STRING, ASN1_OCTET_STRING},
	{aristaLedgerProfile, ".1.3.6.1.2.1.47.1.1.1.1.13.1",
		"DCS-7280R3-48C6",
		"DCS-7280CR3-32P4-M",
		"entPhysicalModelName.1", ASN1_OCTET_STRING, ASN1_OCTET_STRING},
	{aristaLedgerProfile, ".1.3.6.1.2.1.47.1.1.1.1.13.2",
		"7280R3-48C6",
		"7280CR3-32P4-M",
		"entPhysicalModelName.2", ASN1_OCTET_STRING, ASN1_OCTET_STRING},
	{aristaLedgerProfile, ".1.3.6.1.2.1.47.1.1.1.1.14.1",
		"ARISTA-7280R3-CHASSIS-01",
		"ARISTA-7280CR3-CHASSIS-01",
		"entPhysicalName.1", ASN1_OCTET_STRING, ASN1_OCTET_STRING},
}

// nl6590aristaSSHCorrections are the three SSH response edits, recorded as the
// SUBSTRING replacements they are rather than as whole command outputs (the two
// responses are several hundred bytes of `show version` / `show running-config`
// text; the parent's full text is recoverable from git at 2e16f91).
//
// They are in their OWN table and NOT in restoreNl6590AristaArc, because neither
// golden digest can see them: shippedSNMPEntries reads doc.SNMP only, and
// collectShippedOIDs walks OID positions. There is nothing to reverse. What
// guards them is TestAristaProfileNamesNoFakeModel, which reads the SSH parts
// directly.
//
// The serial "AR-7280R3-001" is the SAME STRING this change deleted from
// 30065.3.1.1.1.0 as a bogus answer for aristaSwFwdIpStatsTable. Renaming it here
// keeps the profile from carrying, in a second surface, the exact value the audit
// removed from the first.
var nl6590aristaSSHCorrections = []struct{ profile, command, oldText, newText, why string }{
	{aristaLedgerProfile, "show version", "Arista DCS-7280R3-32P4-M", "Arista DCS-7280CR3-32P4-M",
		"names the chassis; 7280R3 is not an Arista product line"},
	{aristaLedgerProfile, "show version", "AR-7280R3-001", "AR-7280CR3-001",
		"the same serial this change deleted from 30065.3.1.1.1.0"},
	{aristaLedgerProfile, "show running-config", "(DCS-7280R3-32P4-M,", "(DCS-7280CR3-32P4-M,",
		"the config banner's device line names the same chassis"},
}

// The two "before" digests live HERE rather than beside the live constants they
// chain onto, matching the nl6#576, nl6#590 and nl6#591 ledgers. The
// cross-reference is written down instead of left for a reader to discover:
//
//	live value                  declared in                       reversed by
//	shippedTagDigest            snmp_hc_counter_table_test.go     TestAristaArcAuditReproducesTheParentCorpus
//	shippedOIDEncodingDigest    snmp_oid_roundtrip_test.go        TestAristaArcRePinIsOnlyTheAudit
//
// Both live constants carry a comment naming this file and these two tests, so
// the chain can be followed from either end. The third moved constant,
// ownVendorArcNamesShipped in snmp_own_vendor_pen_test.go, is a COUNT rather than
// a digest and is re-derived from the corpus by its own test; it carries a
// comment naming this change too.

// shippedTagDigestBeforeAristaArcAudit is the (profile, OID, emitted tag) digest
// of the corpus at 2e16f91 — the value shippedTagDigest held before this change,
// NOT re-derived from the audited tree.
const shippedTagDigestBeforeAristaArcAudit = "bc89ec8bd0e7f12bacf4f9d6653b75159b333146b05a4dfeadc5acce04923b8b"

// shippedOIDEncodingDigestBeforeAristaArcAudit is the OID-name-to-encoding digest
// at the same revision, and the same rule applies to it. It is also the newest
// entry in snmp_oid_roundtrip_test.go's historical run.
const shippedOIDEncodingDigestBeforeAristaArcAudit = "009a63f6ac3597515da42543ca3e61354f408940cb3ef02b79ce635f44b13604"

// nl6590aristaValueDigestAtParent is a SHA-256 over the sorted old-value lines of
// EVERY row this ledger records — the five deletions, the six SNMP corrections
// and the three SSH substring corrections — as they existed at 2e16f91. SNMP rows
// hash as "profile\toid\toldValue"; SSH rows as "profile\tssh:command\toldText",
// so the two kinds cannot collide.
//
// It was computed by reading the four resource parts OUT OF GIT at that revision
// (`git show 2e16f91:go/nl6/resources/arista_7280r3/<part>`), never from the
// tables above, so comparing the tables against it compares them with the tree as
// it actually was. For the five deleted rows nothing else in the package has
// anything left to compare against. See the residual noted in the header: this
// pins edits made after the constant was set, not the constant's own derivation.
const nl6590aristaValueDigestAtParent = "c87040b3448964fea880973bdbe49758ea05176f2120e1fe541ab9b8bfc6c995"

// restoreNl6590AristaArc reverses this change's SNMP edits against a
// (profile, OID) -> value map, so the map afterwards is the corpus as 2e16f91
// shipped it. Shared with every older ledger reversal, whose own starting point
// is the tree this one reconstructs.
//
// EVERY DISAGREEMENT IS FATAL, for the reason restoreNl6576NvidiaArc gives: a
// reversal that carries on past a corpus it does not recognise buries its own
// diagnosis under the caller's opaque digest mismatch.
func restoreNl6590AristaArc(t *testing.T, cur map[[2]string]string) {
	t.Helper()

	for _, d := range nl6590aristaDeletedEntries {
		k := [2]string{d.profile, d.oid}
		if got, ok := cur[k]; ok {
			t.Fatalf("%s %s is in the nl6#590 Arista removal ledger but still ships, valued %q. "+
				"It names %s: %s", d.profile, d.oid, got, d.object, d.why)
		}
		cur[k] = d.oldValue
	}
	for _, c := range nl6590aristaValueCorrections {
		k := [2]string{c.profile, c.oid}
		got, ok := cur[k]
		if !ok {
			t.Fatalf("%s %s (%s) is in the nl6#590 Arista correction ledger but no longer ships",
				c.profile, c.oid, c.object)
		}
		if got != c.newValue {
			t.Fatalf("%s %s (%s) ships %q, but the ledger says this change set it to %q",
				c.profile, c.oid, c.object, got, c.newValue)
		}
		cur[k] = c.oldValue
	}
}

// nl6590aristaVanishedOIDNames are the OID names this change removed from the
// corpus ENTIRELY, in the undotted spelling collectShippedOIDs gathers. Derived
// from the deletion ledger, so the two views cannot drift, and pinned against the
// live corpus by TestAristaArcVanishedNamesAreMeasured.
//
// There is no survivors map here, unlike nl6#590's Cisco one: each deleted name
// was served by exactly this one profile and nothing else, resource part or trap
// catalog. That is a MEASUREMENT, not an assumption — see
// TestAristaArcVanishedNamesAreMeasured.
func nl6590aristaVanishedOIDNames() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, d := range nl6590aristaDeletedEntries {
		o := normaliseLedgerOID(d.oid)
		if _, dup := seen[o]; dup {
			continue
		}
		seen[o] = struct{}{}
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// nl6590aristaOIDTypedCorrections returns the correction rows whose VALUE is an
// OID, i.e. the rows collectShippedOIDs sees in the value position. Exactly one
// row qualifies (sysObjectID), and that is ASSERTED rather than assumed by
// nl6590aristaOIDNamesBeforeAudit: a gate that silently stopped matching would
// turn the name reversal into a no-op, and the only test to fail would be one
// whose documented remedy is to re-pin a golden digest.
func nl6590aristaOIDTypedCorrections() []struct {
	profile, oid, oldValue, newValue, object string
	oldTag, newTag                           byte
} {
	var out []struct {
		profile, oid, oldValue, newValue, object string
		oldTag, newTag                           byte
	}
	for _, c := range nl6590aristaValueCorrections {
		if snmpTypeTag(c.oid) == ASN1_OBJECT_ID {
			out = append(out, c)
		}
	}
	return out
}

// nl6590aristaOIDNamesBeforeAudit maps a list of shipped OID NAMES back to the
// set 2e16f91 shipped. It is the name-view counterpart of restoreNl6590AristaArc,
// and every reversal of shippedOIDEncodingDigest now begins with it — this change
// is the newest link, so it is undone FIRST (innermost in the call chain).
//
// IT IS NOT A PURE APPEND, and that is the one structural difference from
// nl6#590's Cisco version and nl6#591's. collectShippedOIDs gathers OID-typed
// VALUES as well as names, so the sysObjectID correction REPLACED one entry of
// that set with another: reversing it means dropping the corrected value's OID
// and adding the old one back, not just appending. Appending alone would leave
// both OIDs in the reconstructed set and the digest would not come back.
//
// IT TAKES A *testing.T AND IS FATAL ON EVERY DISAGREEMENT, matching
// restoreNl6590AristaArc. It used to be a t-less pure function, which meant a
// gate that stopped matching, or a drop that matched nothing, degraded it to a
// silent no-op — the asymmetry the value view was deliberately written to avoid.
//
// collectShippedOIDs DEDUPLICATES, which is why the drop is a SINGLE-entry drop
// and why the "exactly one owner" question it raises cannot be answered from that
// slice: it reports presence, never a count. TestAristaArcVanishedNamesAreMeasured
// answers it from shippedSNMPEntries instead. This is not a hypothetical
// distinction — a first cut counted with the deduplicated view and a deliberately
// planted second owner did not move it.
func nl6590aristaOIDNamesBeforeAudit(t *testing.T, names []string) []string {
	t.Helper()

	oidTyped := nl6590aristaOIDTypedCorrections()
	if len(oidTyped) != 1 {
		t.Fatalf("%d correction rows have an OID-typed value, want exactly 1 (sysObjectID). "+
			"The name-view reversal drops and re-adds exactly those rows, so a change in this "+
			"count silently changes what the reversal reconstructs", len(oidTyped))
	}

	drop := map[string]struct{}{}
	var add []string
	for _, c := range oidTyped {
		drop[normaliseLedgerOID(c.newValue)] = struct{}{}
		add = append(add, normaliseLedgerOID(c.oldValue))
	}

	out := make([]string, 0, len(names)+len(add))
	dropped := 0
	for _, n := range names {
		if _, skip := drop[normaliseLedgerOID(n)]; skip {
			dropped++
			continue
		}
		out = append(out, n)
	}
	if dropped != len(drop) {
		t.Fatalf("the name-view reversal dropped %d names but expected %d: the corrected "+
			"sysObjectID value is not in the shipped OID set exactly once, so the reconstruction "+
			"is not the parent's set", dropped, len(drop))
	}

	out = append(out, add...)
	return append(out, nl6590aristaVanishedOIDNames()...)
}

// TestAristaArcAuditReproducesTheParentCorpus is the before/after pin for the TAG
// digest: reverse the ledger against today's corpus and 2e16f91's value must come
// back. A missing row, an extra row, or any other edit to shipped data made
// without recording it here all fail.
func TestAristaArcAuditReproducesTheParentCorpus(t *testing.T) {
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
		"triples reconstructed", len(nl6590aristaDeletedEntries), len(nl6590aristaValueCorrections),
		len(lines))

	if got != shippedTagDigestBeforeAristaArcAudit {
		t.Errorf("reconstructed parent digest = %s, want %s.\n"+
			"The ledger no longer accounts for the difference between 2e16f91's shipped data and "+
			"this tree's. Either a row is missing from it, or shipped data changed without being "+
			"recorded.", got, shippedTagDigestBeforeAristaArcAudit)
	}
}

// TestAristaArcRePinIsOnlyTheAudit does the same job for the OID-NAME digest,
// which the tag digest cannot see: it hashes (profile, OID, tag) triples, so it
// says nothing about which distinct NAMES the corpus stopped shipping — nor about
// an OID-typed VALUE changing, which moves no tag at all.
func TestAristaArcRePinIsOnlyTheAudit(t *testing.T) {
	vanished := nl6590aristaVanishedOIDNames()
	if len(vanished) == 0 {
		t.Fatal("the ledger yielded no vanished OID names")
	}

	restored := nl6590aristaOIDNamesBeforeAudit(t, collectShippedOIDs(t))
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

	if got != shippedOIDEncodingDigestBeforeAristaArcAudit {
		t.Errorf("restoring %d deleted OID names and un-correcting the sysObjectID value gives "+
			"digest %s, want the pre-change value %s over %d OIDs.\nSo the re-pin of "+
			"shippedOIDEncodingDigest is NOT explained by this audit alone: something else about "+
			"what a shipped OID puts on the wire has changed.",
			len(vanished), got, shippedOIDEncodingDigestBeforeAristaArcAudit, checked)
	}
	t.Logf("%d shipped OID names with %d deleted names restored reproduce the pre-change digest",
		checked, len(vanished))
}

// TestAristaArcLedgerValuesMatchTheParentRevision pins the ledger's recorded old
// values against the tree at 2e16f91. Without it the five deleted values are
// unfalsifiable: this change removed every one of them from the tree, so nothing
// else in the package has anything left to compare against.
//
// If it fails after an edit to the tables, the tables are wrong — the parent
// revision cannot change. The residual is stated in the header: this test never
// reads git, so it pins edits made AFTER the constant was derived, which is the
// failure mode that actually happens.
func TestAristaArcLedgerValuesMatchTheParentRevision(t *testing.T) {
	var lines []string
	for _, d := range nl6590aristaDeletedEntries {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", d.profile, d.oid, d.oldValue))
	}
	for _, c := range nl6590aristaValueCorrections {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", c.profile, c.oid, c.oldValue))
	}
	for _, s := range nl6590aristaSSHCorrections {
		lines = append(lines, fmt.Sprintf("%s\tssh:%s\t%s", s.profile, s.command, s.oldText))
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	got := hex.EncodeToString(h.Sum(nil))

	if got != nl6590aristaValueDigestAtParent {
		t.Errorf("ledger value digest = %s, want %s (%d rows).\n"+
			"The recorded old values no longer match what 2e16f91 shipped. Re-derive with: "+
			"git show 2e16f91:go/nl6/resources/arista_7280r3/arista_7280r3_snmp_{1,6,11}.json and "+
			"…_ssh_1.json, collect the rows this ledger names, and hash sorted lines "+
			"(\"profile\\tOID\\tvalue\" for SNMP, \"profile\\tssh:command\\ttext\" for SSH). Do not "+
			"re-pin this constant to match an edited table: the parent revision is fixed.",
			got, nl6590aristaValueDigestAtParent, len(lines))
	}
	t.Logf("all %d recorded values match the corpus at 2e16f91", len(lines))
}

// TestAristaArcLedgerIsNotVacuous guards the guard. An emptied ledger would make
// the reversals above pass only if the corpus were untouched, so the census is
// pinned and the SHAPE of every row is checked against the claim made about it.
func TestAristaArcLedgerIsNotVacuous(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"nl6#590 Arista deleted entries", len(nl6590aristaDeletedEntries), 5},
		{"nl6#590 Arista SNMP value corrections", len(nl6590aristaValueCorrections), 6},
		{"nl6#590 Arista SSH value corrections", len(nl6590aristaSSHCorrections), 3},
		{"nl6#590 Arista names that vanished corpus-wide", len(nl6590aristaVanishedOIDNames()), 5},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: ledger has %d rows, want %d — the counts are the census quoted in the "+
				"commit body, the ledger header and docs/reference/snmp.md, so they move together "+
				"or not at all", tc.name, tc.got, tc.want)
		}
	}

	// THE AUDIT'S HEADLINE ARITHMETIC, derived rather than asserted in prose. The
	// docs and the ledger header both quote "0 of 6", and until this row existed
	// neither the numerator nor the denominator appeared in any assertion — only
	// the row counts did, which is a different claim.
	//
	// The DENOMINATOR is the enterprise-arc facts that were checkable: the five
	// OIDs the profile served under 30065 plus the ONE OID-typed value pointing
	// into that arc. The NUMERATOR is how many survived untouched.
	auditedFacts := len(nl6590aristaDeletedEntries) + len(nl6590aristaOIDTypedCorrections())
	correctFacts := 0 // every one was deleted or corrected; none was left as shipped
	if auditedFacts != 6 {
		t.Errorf("the audit's denominator computes to %d enterprise-arc facts, want 6 "+
			"(5 OIDs under 30065 + the sysObjectID value). docs/reference/snmp.md and the "+
			"ledger header both quote 6", auditedFacts)
	}
	if correctFacts != 0 {
		t.Errorf("the audit's numerator is %d, want 0 — every checked fact was wrong, which is "+
			"the finding the docs quote as \"0 of 6\"", correctFacts)
	}

	// Every DELETED row must be under the Arista PEN. A row on another arc would
	// mean this ledger is reversing an edit that belongs to a different audit.
	const aristaPEN = ".1.3.6.1.4.1.30065."
	for _, d := range nl6590aristaDeletedEntries {
		if !strings.HasPrefix(d.oid, aristaPEN) {
			t.Errorf("%s %s is in the nl6#590 Arista ledger but is not under Arista's PEN",
				d.profile, d.oid)
		}
		if strings.TrimSpace(d.object) == "" || strings.TrimSpace(d.why) == "" {
			t.Errorf("%s %s carries no object name or no reason; a deletion ledger row that does "+
				"not say what it deleted and why is not a reading", d.profile, d.oid)
		}
	}

	// Cheap validity guards that cost nothing and catch a phantom row. A deletion
	// row naming an absent profile reverses nothing; a correction row whose old
	// and new values are equal records no change and passes every digest; a row on
	// any other profile asserts an absence against the wrong device.
	shippedProfiles := map[string]struct{}{}
	for _, p := range shippedProfileNames(t) {
		shippedProfiles[p] = struct{}{}
	}
	if _, ok := shippedProfiles[aristaLedgerProfile]; !ok {
		t.Fatalf("%s is not a shipped profile; every row in this ledger is a phantom",
			aristaLedgerProfile)
	}
	for _, d := range nl6590aristaDeletedEntries {
		if d.profile != aristaLedgerProfile {
			t.Errorf("deletion row %s names profile %s, but this ledger is only about %s",
				d.oid, d.profile, aristaLedgerProfile)
		}
	}
	for _, s := range nl6590aristaSSHCorrections {
		if s.profile != aristaLedgerProfile {
			t.Errorf("SSH row %q names profile %s, but this ledger is only about %s",
				s.command, s.profile, aristaLedgerProfile)
		}
		if s.oldText == s.newText {
			t.Errorf("SSH row %q on %s records the same text on both sides, so it documents no "+
				"change and would pass every check", s.command, s.profile)
		}
		if strings.TrimSpace(s.why) == "" {
			t.Errorf("SSH row %q carries no reason", s.command)
		}
	}

	// The CORRECTIONS are the opposite shape and the assertion has to match: all
	// six are standard MIB-II / ENTITY-MIB objects, NOT enterprise OIDs. Requiring
	// the Arista PEN on them would be wrong; what makes sysObjectID part of this
	// audit is that its VALUE is under it.
	for _, c := range nl6590aristaValueCorrections {
		if c.profile != aristaLedgerProfile {
			t.Errorf("correction row %s names profile %s, but this ledger is only about %s",
				c.oid, c.profile, aristaLedgerProfile)
		}
		if strings.HasPrefix(c.oid, ".1.3.6.1.4.1.") {
			t.Errorf("%s %s (%s) is recorded as a correction, but every correction is a MIB-II or "+
				"ENTITY-MIB object; an enterprise OID here means the tables have been mixed up",
				c.profile, c.oid, c.object)
		}
		if c.oldValue == c.newValue {
			t.Errorf("%s %s (%s) records the same value on both sides, so it documents no change "+
				"and would reconcile against every digest", c.profile, c.oid, c.object)
		}

		// Tags asserted through the ENCODER, not reasoned about from oidTypeTable,
		// because the encoder is what decides the wire byte. NO correction moves
		// it, which is the measurement behind the ledger header's claim that
		// shippedTagDigest moves for the deletions ALONE.
		encOld := encodeTypedValue(c.oid, c.oldValue)
		encNew := encodeTypedValue(c.oid, c.newValue)
		if len(encOld) == 0 || encOld[0] != c.oldTag {
			t.Errorf("%s %s (%s): old value %q emits % x, but the ledger records tag 0x%02X",
				c.profile, c.oid, c.object, c.oldValue, encOld, c.oldTag)
		}
		if len(encNew) == 0 || encNew[0] != c.newTag {
			t.Errorf("%s %s (%s): new value %q emits % x, but the ledger records tag 0x%02X",
				c.profile, c.oid, c.object, c.newValue, encNew, c.newTag)
		}
		if c.oldTag != c.newTag {
			t.Errorf("%s %s (%s) records a tag change 0x%02X -> 0x%02X. No Arista correction "+
				"moves a tag; if one now does, the ledger header's account of why "+
				"shippedTagDigest moved is wrong", c.profile, c.oid, c.object, c.oldTag, c.newTag)
		}
	}
}

// TestAristaArcVanishedNamesAreMeasured is what makes "every deleted name left
// the corpus" a measurement rather than a claim. nl6#590's Cisco arc recorded
// seven deleted names of which only five actually left — one still shipped on
// three other profiles, one was still a trap varbind — so the same question has
// to be ASKED here, not inferred from a five-row table on one profile.
//
// collectShippedOIDs walks the trap and syslog catalogs as well as the resource
// parts, so an Arista varbind hiding in a catalog would fail this.
func TestAristaArcVanishedNamesAreMeasured(t *testing.T) {
	// collectShippedOIDs DEDUPLICATES, so this is a presence set and never a
	// census. Its value here is BREADTH: it walks the trap and syslog catalogs as
	// well as the resource parts, so an Arista varbind hiding in a catalog fails
	// the absence check below. Counting is done separately, further down, from a
	// source that does not deduplicate.
	shipped := map[string]struct{}{}
	for _, o := range collectShippedOIDs(t) {
		shipped[normaliseLedgerOID(o)] = struct{}{}
	}

	for _, o := range nl6590aristaVanishedOIDNames() {
		if _, ok := shipped[o]; ok {
			t.Errorf("%s is recorded as having left the corpus but is still named somewhere "+
				"(a resource part or a catalog varbind); the name-digest reversal would "+
				"double-count it", o)
		}
	}

	// The corrected sysObjectID VALUE is the other half of the name-digest
	// reversal and has the mirror-image requirement: the NEW OID must have exactly
	// ONE owner in the corpus and the OLD one must have none.
	//
	// THE "EXACTLY ONE OWNER" IS THE POINT, not decoration.
	// nl6590aristaOIDNamesBeforeAudit removes that OID from the distinct-name set
	// and adds the old one back. If a SECOND profile also served the corrected OID,
	// then the parent revision's distinct-name set CONTAINED it — served by that
	// other profile — and removing it would reconstruct a set the parent never had.
	// nl6#590's Cisco ledger needed a survivors map for exactly this reason, and
	// nothing but this assertion says the Arista case does not.
	//
	// OWNERSHIP IS COUNTED FROM shippedSNMPEntries, NOT FROM collectShippedOIDs,
	// and the distinction is the whole reason this assertion works. The `shipped`
	// map above is built from collectShippedOIDs, which DEDUPLICATES: it answers
	// "is this name in the corpus", never "how many entries carry it", so counting
	// with it reports 1 no matter how many profiles serve an OID. A first cut did
	// exactly that and a planted second owner did not move it.
	owners := map[string]int{}
	for _, e := range shippedSNMPEntries(t) {
		owners[normaliseLedgerOID(e.OID)]++
		// The VALUE position too, decided by the production predicate rather than
		// by string shape — the same gate collectShippedOIDs uses.
		if snmpTypeTag(e.OID) == ASN1_OBJECT_ID {
			owners[normaliseLedgerOID(e.Value)]++
		}
	}

	for _, c := range nl6590aristaOIDTypedCorrections() {
		switch n := owners[normaliseLedgerOID(c.newValue)]; n {
		case 1:
			// as expected
		case 0:
			t.Errorf("%s (%s) is recorded as now answering %s, but no shipped entry names or "+
				"values that OID, so the name-digest reversal drops a name that was never there",
				c.profile, c.object, c.newValue)
		default:
			t.Errorf("%s (%s) now answers %s, and %d shipped entries name or value that OID. The "+
				"name-digest reversal removes it from the distinct-name set, so it would "+
				"reconstruct a parent set that never existed; this ledger needs a survivors map "+
				"the way nl6#590's Cisco one does", c.profile, c.object, c.newValue, n)
		}
		if n := owners[normaliseLedgerOID(c.oldValue)]; n > 0 {
			t.Errorf("%s (%s) still puts %s into the corpus (%d entry/entries); that is the "+
				"invented product OID this change replaced", c.profile, c.object, c.oldValue, n)
		}
		// The dedup view still has to agree that the name is PRESENT — that is what
		// the reversal's drop operates on — so both views are asserted rather than
		// the count view alone.
		if _, ok := shipped[normaliseLedgerOID(c.newValue)]; !ok {
			t.Errorf("%s (%s): %s has an owner but is absent from collectShippedOIDs, so the "+
				"name-digest reversal has nothing to drop", c.profile, c.object, c.newValue)
		}
	}
}

// TestAristaProfileNamesNoFakeModel is the profile-wide half of the
// model-identity rule, and it exists because the first cut of this change applied
// that rule at sysDescr.0 and nowhere else.
//
// `grep -c 7280R3 ARISTA-PRODUCTS-MIB` returns 0 (revision 202603030000Z,
// SHA-256 f1dff845…). The profile was already split between two products that do
// not exist — "DCS-7280R3-32P4-M" in sysDescr and the SSH outputs,
// "DCS-7280R3-48C6" in the entity table — and correcting only sysDescr made the
// profile name a real product on one surface and a fake one on six others.
//
// It scans EVERY part of the profile in BOTH layouts a device type can carry: the
// SNMP entries through shippedSNMPEntries (the shared corpus walker, never a new
// walk) and the SSH parts by reading them directly, because no corpus walker
// gathers SSH responses at all.
func TestAristaProfileNamesNoFakeModel(t *testing.T) {
	const fake = "7280R3"

	// A positive control first, in its own scope: the scan must be able to SEE a
	// planted string, or a test that asserts an absence proves nothing. Both
	// surfaces are controlled, because they are gathered by different code.
	t.Run("positive control", func(t *testing.T) {
		if !strings.Contains("Arista Networks DCS-7280R3-48C6", fake) {
			t.Fatal("the scan's own predicate does not match the string it looks for")
		}
	})

	snmpChecked := 0
	for _, e := range shippedSNMPEntries(t) {
		if e.Profile != aristaLedgerProfile {
			continue
		}
		snmpChecked++
		if strings.Contains(e.Value, fake) {
			t.Errorf("%s %s answers %q, which names %q — a product line that appears NOWHERE in "+
				"ARISTA-PRODUCTS-MIB 202603030000Z. Arista's naming is 7280CR3 / 7280SR3 / "+
				"7280TR3; the profile's one real product is DCS-7280CR3-32P4-M, which "+
				"sysObjectID.0 identifies", e.Part, e.OID, e.Value, fake)
		}
	}
	if snmpChecked == 0 {
		t.Fatalf("no SNMP entries found for %s; the scan is looking at the wrong profile",
			aristaLedgerProfile)
	}

	// ONE pass over the profile's parts, collecting every SSH response, so the
	// absence scan and the positive half below read the same gathered data rather
	// than walking resources/ twice with two chances to diverge.
	type sshResponse struct{ part, command, response string }
	var sshResponses []sshResponse
	for _, part := range shippedResourceParts(t) {
		if shippedProfileOf(part) != aristaLedgerProfile {
			continue
		}
		raw, err := os.ReadFile(part) // #nosec G304 -- test-only, path from a repo walk
		if err != nil {
			t.Fatalf("read %s: %v", part, err)
		}
		var doc DeviceResources
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: does not decode as a resource file: %v", part, err)
		}
		for _, s := range doc.SSH {
			sshResponses = append(sshResponses, sshResponse{part, s.Command, s.Response})
		}
	}
	if len(sshResponses) == 0 {
		t.Fatalf("no SSH responses found for %s; SSH is the surface no corpus digest covers, so "+
			"a scan that reads none of it is vacuous", aristaLedgerProfile)
	}
	for _, s := range sshResponses {
		if strings.Contains(s.response, fake) {
			t.Errorf("%s: the response to %q names %q, a product line that appears nowhere in "+
				"ARISTA-PRODUCTS-MIB. SSH output is not covered by any golden digest, so this "+
				"scan is the only thing that sees it", s.part, s.command, fake)
		}
	}

	t.Logf("%d SNMP entries and %d SSH responses scanned; none names %q",
		snmpChecked, len(sshResponses), fake)

	// The positive half: every recorded SSH correction's NEW text must actually be
	// present, so this is not merely an absence test. An absence is also satisfied
	// by a response that was deleted, which is the failure mode this closes.
	for _, c := range nl6590aristaSSHCorrections {
		found := false
		for _, s := range sshResponses {
			if s.command == c.command && strings.Contains(s.response, c.newText) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the ledger records the response to %q as now containing %q, but no SSH "+
				"response of %s does. The correction was recorded and not applied",
				c.command, c.newText, aristaLedgerProfile)
		}
	}
}

// deviceForProfileWithPlantedOID is deviceForProfile with one extra SNMP row
// spliced in before the lookup indexes are built, so the planted OID is served by
// findResponse AND enumerated into the walk.
//
// It exists for the positive control in TestAristaArcMatchesTheMIB: that test's
// central assertion is an ABSENCE over a walk, and an absence test needs a
// demonstration that the scan can see a presence, or it is satisfied by a scan
// that sees nothing at all.
func deviceForProfileWithPlantedOID(t *testing.T, profile, oid, value string) *SNMPServer {
	t.Helper()

	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources(profile)
	if err != nil {
		t.Fatalf("LoadSpecificResources(%s): %v", profile, err)
	}

	// A COPY, not the cached pointer: LoadSpecificResources publishes into
	// resourcesCache, and mutating what it returned would leak the planted row
	// into any later load in the same process.
	planted := &DeviceResources{
		SNMP:    append(append([]SNMPResource{}, res.SNMP...), SNMPResource{OID: oid, Response: value}),
		SSH:     res.SSH,
		API:     res.API,
		Optical: res.Optical,
	}
	sm.buildResourceIndexes(planted)

	mc := &MetricsCycler{}
	mc.InitIfCounters(planted, 1)
	return &SNMPServer{device: &DeviceSimulator{
		ID:            "arista-arc-control",
		resources:     planted,
		resourceFile:  profile,
		metricsCycler: mc,
	}}
}

// TestAristaArcMatchesTheMIB is the nl6#590 Arista audit, committed as a test
// rather than left in an issue. It is the ONLY form of check available here: no
// load guard can see any of these defects.
//
//   - The five deleted OIDs were well-formed names carrying encodable values, so
//     all three load rules passed them (nl6#523, nl6#529, nl6#541). Being
//     UNDEFINED is not a property of an OID string; it is a property of a MIB.
//   - The nl6#571 bare-column census could not see 30065.3.1.1.1.0 either: its
//     heuristic is "some other shipped OID extends it", and nothing extended it.
//   - nl6#591's access-mode finding is the same class as the not-accessible half
//     of that OID, and nl6#591 says in terms that NO nl6 RULE MODELS MAX-ACCESS.
//   - The sysObjectID value ENCODED FINE — nl6#529's rule 2 asks whether an
//     OID-typed value is encodable, never whether it resolves — and it is under
//     the profile's OWN PEN, so nl6#587/#589's vendor guards had nothing to say.
//
// What it asserts is what a test CAN assert: the exact value served, the tag it
// goes out as, and the absence of the OIDs that were deleted. It does not and
// cannot assert that a value is faithful to the MIB; that came from reading the
// five modules listed at the top of this file, each cited by revision AND by the
// SHA-256 of the file read, and this function is the RECORD OF THAT READING. Read
// it as "this is what the Arista arc audit resolved", never as "CI checks nl6
// against a MIB". NO MIB FILE IS CHECKED IN — see the licence note at the top.
//
// The reading is qualified by REVISION, not stated as correctness: this profile
// matches those revisions of those modules. A device's shipped MIB need not agree
// with them, and Arista's product MIB in particular gains products continuously —
// its own revision list runs to over a hundred entries.
func TestAristaArcMatchesTheMIB(t *testing.T) {
	arista := deviceForProfile(t, aristaLedgerProfile)

	// ── the two identity corrections ──
	//
	// sysObjectID is the vendor-detection surface and is asserted as an exact OID
	// AND as an encodable one: a collector resolves it against ARISTA-PRODUCTS-MIB,
	// so the sub-identifiers are the value, not decoration.
	const sysObjectID = ".1.3.6.1.2.1.1.2.0"
	const dcs7280CR332P4M = "1.3.6.1.4.1.30065.1.3011.7280.2727.3.32.2129.4.972"
	if got := arista.findResponse(sysObjectID); got != dcs7280CR332P4M {
		t.Errorf("sysObjectID.0 answers %q, want %q (aristaDCS7280CR332P4M, which "+
			"ARISTA-PRODUCTS-MIB 202603030000Z assigns as "+
			"{ aristaProducts 3011 7280 2727 3 32 2129 4 972 }). The value this replaced, "+
			"1.3.6.1.4.1.30065.1.3011.7280.3282.32.4, is shaped like a product OID and is not "+
			"one: no assignment in that module uses 3011 7280 3282", got, dcs7280CR332P4M)
	}
	if enc := encodeTypedValue(sysObjectID, arista.findResponse(sysObjectID)); len(enc) == 0 ||
		enc[0] != ASN1_OBJECT_ID {
		t.Errorf("sysObjectID.0 emits % x, want tag 0x%02X", enc, ASN1_OBJECT_ID)
	}

	// sysDescr must name the SAME machine sysObjectID identifies, IN THE MIB'S OWN
	// SPELLING. The model substring is asserted rather than the whole string, so
	// an EOS version bump does not fail this — the version is deliberately
	// unaudited (no Arista module publishes a software-version registry) and only
	// the model is a MIB fact.
	//
	// "DCS-7280CR3-32P4-M" IS THE PRODUCT NAME; "DCS-7280CR3-32P4M" IS THE ASN.1
	// IDENTIFIER WITH ITS PUNCTUATION STRIPPED, and the first cut of this change
	// pinned the identifier. Both spellings are asserted here — the MIB's must be
	// present, the hyphenless one must not — because a test that only requires the
	// right string passes on a value containing both.
	const sysDescrOID = ".1.3.6.1.2.1.1.1.0"
	const productName = "DCS-7280CR3-32P4-M"
	const identifierSpelling = "DCS-7280CR3-32P4M"
	descr := arista.findResponse(sysDescrOID)
	if !strings.Contains(descr, productName) {
		t.Errorf("sysDescr.0 answers %q, which does not name %s — the product whose OID "+
			"sysObjectID.0 now carries. ARISTA-PRODUCTS-MIB gives that name in the comment above "+
			"the assignment (\"-- DCS-7280CR3-32P4-M 32x100GbE (QSFP100) & 4x400GbE (OSFP) "+
			"Ethernet Switch with SSD\") and in its own revision note. sysDescr and sysObjectID "+
			"have to identify the same machine", descr, productName)
	}
	if strings.Contains(descr, identifierSpelling) && !strings.Contains(descr, productName) {
		t.Errorf("sysDescr.0 answers %q, which uses %s — that is the ASN.1 IDENTIFIER "+
			"aristaDCS7280CR332P4M with its punctuation stripped, not the product NAME. Reading "+
			"the identifier as the name is the wrong-MIB-reading class this audit exists to "+
			"eliminate", descr, identifierSpelling)
	}
	if strings.Contains(descr, "7280R3") {
		t.Errorf("sysDescr.0 answers %q. The string \"7280R3\" appears NOWHERE in "+
			"ARISTA-PRODUCTS-MIB 202603030000Z; Arista's naming is 7280CR3 / 7280SR3", descr)
	}
	// The EOS version is UNAUDITED and deliberately preserved. Asserted so that
	// changing it becomes a decision rather than a side effect of editing the
	// model name in the same string.
	if !strings.Contains(descr, "4.29.2F") {
		t.Errorf("sysDescr.0 answers %q; the EOS version 4.29.2F was left alone by this audit "+
			"because it is plausible and not checkable against any Arista MIB. Changing it needs "+
			"its own reason", descr)
	}

	// The four ENTITY-MIB rows the model-identity rule reaches. Asserted exactly,
	// because each is a whole response rather than a substring of one.
	for _, tc := range []struct{ oid, object, want string }{
		{".1.3.6.1.2.1.47.1.1.1.1.2.1", "entPhysicalDescr.1", "Arista Networks DCS-7280CR3-32P4-M"},
		{".1.3.6.1.2.1.47.1.1.1.1.13.1", "entPhysicalModelName.1", "DCS-7280CR3-32P4-M"},
		{".1.3.6.1.2.1.47.1.1.1.1.13.2", "entPhysicalModelName.2", "7280CR3-32P4-M"},
		{".1.3.6.1.2.1.47.1.1.1.1.14.1", "entPhysicalName.1", "ARISTA-7280CR3-CHASSIS-01"},
	} {
		if got := arista.findResponse(tc.oid); got != tc.want {
			t.Errorf("%s %s answers %q, want %q. Every surface of this profile has to name the "+
				"one real product sysObjectID.0 identifies; before this audit the entity table "+
				"named DCS-7280R3-48C6, and the real 48C6 products are SR / TR series, not R3",
				tc.oid, tc.object, got, tc.want)
		}
	}

	// ── the five deletions ──
	//
	// findResponse answers a miss with the valueNoSuchObject sentinel and never
	// with "" (nl6#517), which is the one spelling of absence this asserts.
	for _, tc := range nl6590aristaDeletedEntries {
		if got := arista.findResponse(tc.oid); !isSNMPExceptionValue(got) {
			t.Errorf("%s still answers %s (%s) with %q; it was deleted because %s. "+
				"Do not restore this row with a different value: four of these five OIDs name no "+
				"object at all, and inventing a value for an object that is not defined is the "+
				"nl6#569 defect", aristaLedgerProfile, tc.oid, tc.object, got, tc.why)
		}
	}

	// The arc as a whole. After this change arista_7280r3 serves NO object under
	// 1.3.6.1.4.1.30065 — only the sysObjectID VALUE points there. Asserted over a
	// WALK from the PEN root rather than by re-listing the five OIDs, so a sixth
	// invented Arista object added later fails this instead of arriving unguarded.
	//
	// THE EMPTY-ARC CHECK, AND WHY IT NEEDS A POSITIVE CONTROL RATHER THAN A
	// NON-EMPTY ASSERTION. findNextOIDWithServed returns (nextOID, value) — there
	// is no found bool, and end of MIB is an EMPTY nextOID.
	//
	// The first cut of this test checked only `!strings.HasPrefix(next, root+".")`,
	// which a review flagged as able to pass vacuously. It was RIGHT, and the fix
	// it suggested — require a successor — is wrong here: OIDs sort as strings, so
	// 1.3.6.1.4.1.30065 sorts ABOVE every mib-2 OID this profile serves, and once
	// the five Arista rows are gone the arc root genuinely has NO successor. An
	// empty answer is the CORRECT verdict, not an aborted walk, and asserting a
	// non-empty one fails on a healthy tree (measured: it did).
	//
	// So the vacuity is closed the way this repo closes it everywhere else — with
	// a POSITIVE CONTROL that plants an object and requires the walk to find it.
	// That is what makes the empty answer below mean "the arc is empty" rather
	// than "this assertion cannot see anything".
	const aristaRoot = ".1.3.6.1.4.1.30065"
	t.Run("positive control: the walk can see an object in the arc", func(t *testing.T) {
		planted := deviceForProfileWithPlantedOID(t, aristaLedgerProfile,
			"1.3.6.1.4.1.30065.3.1.1.99.0", "planted")
		next, _ := planted.findNextOIDWithServed(aristaRoot, planted.lldpServedOIDs())
		if !strings.HasPrefix(next, aristaRoot+".") {
			t.Fatalf("with an object planted at 1.3.6.1.4.1.30065.3.1.1.99.0, walking from %s "+
				"reaches %q — the walk cannot see the Arista arc at all, so the emptiness check "+
				"in the parent test proves nothing", aristaRoot, next)
		}
	})

	next, _ := arista.findNextOIDWithServed(aristaRoot, arista.lldpServedOIDs())
	if next != "" {
		t.Errorf("walking from %s reaches %s, so arista_7280r3 serves an object at or above "+
			"Arista's enterprise arc again. Every object nl6 shipped there was undefined or "+
			"unreadable in ARISTA-SMI-MIB 201408150000Z / ARISTA-SW-IP-FORWARDING-MIB "+
			"201408150000Z / ARISTA-PRODUCTS-MIB 202603030000Z; a new one needs a reading, not a "+
			"plausible number", aristaRoot, next)
	}

	// RECORDED, NOT FIXED, and asserted as a PRESENCE so the scope boundary is a
	// decision rather than an oversight.
	//
	// entPhysicalVendorType.1 answers an OID-typed VALUE under aristaProducts 3082.
	// No ARISTA-PRODUCTS-MIB assignment has 3082 as its first sub-identifier — the
	// sixteen observed are 138, 447, 1082, 1362, 1470, 1788, 2546, 2682, 2759,
	// 3011, 3413, 3806, 7289, 7358, 7368 and 7388 — so this is the SAME defect as
	// the sysObjectID one, in the value slot of a different object. It is a
	// SUBCLASS this audit newly surfaced: an OID-typed value under a CORRECT PEN
	// that resolves to no assignment, which nl6#587/#589's guards pass by
	// construction and no load rule can see.
	//
	// It is left alone because entPhysicalVendorType is an ENTITY-MIB question, not
	// an Arista-arc one: 224 shipped values sit in that column across the corpus,
	// 208 of them the reserved-PEN placeholder (see
	// TestEveryProfileServesOnlyItsOwnVendorArc's own census), and correcting one
	// profile's while leaving the class unexamined would be arbitrary. It belongs
	// with an ENTITY-MIB sweep, which no arc audit has done.
	//
	// If a later change corrects it, this assertion has to be edited deliberately
	// rather than a test quietly going green.
	const entPhysicalVendorType1 = ".1.3.6.1.2.1.47.1.1.1.1.3.1"
	const unresolvedVendorType = "1.3.6.1.4.1.30065.1.3082.7280.3714.3"
	if got := arista.findResponse(entPhysicalVendorType1); got != unresolvedVendorType {
		t.Errorf("entPhysicalVendorType.1 answers %q, want %q. This audit deliberately did NOT "+
			"touch it: no ARISTA-PRODUCTS-MIB assignment has 3082 as its first sub-identifier, "+
			"which is the same defect as the sysObjectID one, but it is one of 224 shipped "+
			"entPhysicalVendorType values and belongs with an ENTITY-MIB sweep rather than with a "+
			"vendor-arc audit", got, unresolvedVendorType)
	}
}
