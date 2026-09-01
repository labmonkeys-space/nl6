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
	"strconv"
	"strings"
	"testing"
)

// nl6#602, FOURTH ARC of nl6#590. Cisco went first (nl6#592), Arista second
// (nl6#599), Ciena third (nl6#601), and this is Juniper's, PEN 2636.
//
// ## The result, quoted as a MISS RATE
//
// Two units, because a per-OID rate and a per-entry rate answer different
// questions and the earlier arcs each had to correct one of them. The corpus
// serves 13 distinct OID NAMES under 2636 across two profiles, plus 2 distinct
// OID-TYPED VALUES pointing into it. That is 15 distinct facts. By entry the
// same surface is 20 name-position entries plus 2 value-position ones, so 22.
//
//	Palo Alto (nl6#569)   8 of 11 wrong
//	Cisco     (nl6#592)  11 of 13 wrong
//	Arista    (nl6#599)   6 of  6 wrong
//	Ciena     (nl6#601)   0 of  1 wrong
//	Juniper   (nl6#602)  13 of 15 distinct OIDs wrong, 19 of 22 entries
//
// THE VALUE-POSITION DENOMINATOR IS 2, NOT 3, AND THE MISSING ONE IS A KNOWN
// COVERAGE GAP RATHER THAN AN OVERSIGHT. juniper_mx240 answers
// entPhysicalVendorType.1 with a Juniper product OID too, but the PRODUCTION
// predicate that decides whether a value reaches the wire as an OID is
// snmpTypeTag, and oidTypeTable has exactly one OBJECT IDENTIFIER row
// (sysObjectID). So that value goes out as an OCTET STRING and is outside every
// OID-position measurement in this package. nl6#588 recorded the same gap and
// closed it separately with assertEntPhysicalVendorTypeIsNotCrossVendor.
// Widening the predicate means adding an oidTypeTable row, which is a wire
// change. The value is pinned by TestJuniperArcMatchesTheMIB anyway, because it
// was already right.
//
// The two survivors are jnxBoxSerialNo and juniper_mx240's sysObjectID value.
// One of the 13 misses is a WEAK call and is named as such below: jnxBoxDescr
// carried a legal DisplayString that was an asset tag rather than a product
// description. The strong-call rate is 12 of 15.
//
// ## What was read, and how to read the same bytes
//
// Five modules, fetched anonymously on 2026-09-01, cited by LAST-UPDATED and by
// the SHA-256 of the file read. This is the nl6#599 provenance convention: a
// revision string alone does not let a second reader confirm they read the same
// bytes.
//
//	JUNIPER-SMI                   200910290000Z  67fab3465f8e2bf1148df7d06361e1246591de9ceb8211bd9dce59becc0285ef
//	JUNIPER-MIB                   201010220000Z  d4c4f40c7a881f7e125c49fa706df973030f2687fd041e8d9fc22d7032bb88ad
//	JUNIPER-EX-SMI                (no revision)  f2fb4576bd65f1ced716f7f2b2a35ba04add2025f634a4253946d902309ec006
//	JUNIPER-VIRTUALCHASSIS-MIB    201403180000Z  5214043efe7412493d5b1581a0502b375752747611b743673db895421bae91f2
//	JUNIPER-CHASSIS-DEFINES-MIB   201706230000Z  d503b145ab01665b1ceacb120f2a607a381db32f9044bd07750e1d540e536aab
//
// Reproduce with:
//
//	curl -sS https://raw.githubusercontent.com/librenms/librenms-mibs/master/JUNIPER-SMI | shasum -a 256
//	curl -sS https://raw.githubusercontent.com/librenms/librenms-mibs/master/JUNIPER-MIB | shasum -a 256
//	curl -sS https://raw.githubusercontent.com/librenms/librenms/master/mibs/juniper/junos/JUNIPER-EX-SMI | shasum -a 256
//	curl -sS https://raw.githubusercontent.com/librenms/librenms/master/mibs/juniper/junos/JUNIPER-VIRTUALCHASSIS-MIB | shasum -a 256
//	curl -sS https://raw.githubusercontent.com/netdisco/netdisco-mibs/master/juniper/mib-jnx-chas-defines.txt | shasum -a 256
//
// ALL FIVE COPIES ARE THIRD-PARTY MIRRORS AND THEIR PROVENANCE IS UNESTABLISHED.
// Juniper's own entry point is apps.juniper.net/mib-explorer/, a JavaScript
// shell with no server-rendered content, and nl6#602 recorded two secondary
// sources that contradict each other on whether a login is required. Nothing
// here tested that wall. Three of the five mirrors carry a Juniper copyright
// header ("Copyright (c) 2002-2008", "2002-2009", "1998-2016") and none grants
// redistribution, so the reading is qualified by MIRROR as well as by revision.
//
// That qualification matters more here than it did for Ciena. The Ciena catalog
// had already been transcribed from a reading, and nl6#601's job was to re-check
// somebody else's work. NOBODY HAD READ THESE MODULES BEFORE. The polled data
// carries no provenance claim at all, and the trap catalog's own comment cites
// "oidref.com and Observium's JUNIPER-MIB mirror", which are aggregators rather
// than the module. nl6#601's Ciena comment named the module, its LAST-UPDATED,
// the severity enum and an internal contradiction in the MIB. The gap between
// those two kinds of citation predicted the result almost exactly: the trap
// catalog's seven notification OIDs all resolve, while the polled data missed 13
// of 15.
//
// TWO PROVENANCE ODDITIES ARE RECORDED RATHER THAN SMOOTHED OVER.
// JUNIPER-CHASSIS-DEFINES-MIB declares LAST-UPDATED 201706230000Z while its own
// REVISION list runs on to 201711220000Z, so the module's stated revision is
// five months behind its newest recorded change. JUNIPER-EX-SMI has no
// MODULE-IDENTITY at all, only OBJECT IDENTIFIER assignments and a copyright
// range, so it has no revision string to quote and is cited by digest alone.
// That is the same situation nl6#591 hit with SMIv1 OLD-CISCO-SYSTEM-MIB.
//
// NO MIB FILE OR EXTRACTED FIXTURE IS CHECKED IN, per the licensing finding
// recorded with nl6#592. Licensing blocks the BYTES, not their DIGEST, which is
// what the table above is for. Everything below is a PINNED READING and never a
// live check: nothing in CI compares nl6 against a Juniper MIB.
//
// ## The arc, resolved rather than assumed
//
// From JUNIPER-SMI 200910290000Z:
//
//	juniperMIB   ::= { enterprises 2636 }   -- MODULE-IDENTITY
//	jnxProducts  ::= { juniperMIB 1 }       -- "The root of Juniper's Product OIDs."
//	                                        -- jnxProducts.1 is reserved for Junos-based products
//	jnxServices  ::= { juniperMIB 2 }
//	jnxMibs      ::= { juniperMIB 3 }       -- jnxMibs.1-38 already in use
//	jnxTraps     ::= { juniperMIB 4 }
//	  jnxChassisTraps ::= { jnxTraps 1 }
//	jnxJsMibRoot ::= { jnxMibs 39 }
//	jnxExMibRoot ::= { jnxMibs 40 }         -- the EX-series switch MIB root
//	jnxWxMibRoot ::= { jnxMibs 41 }
//
// From JUNIPER-MIB 201010220000Z, whose MODULE-IDENTITY is jnxBoxAnatomy:
//
//	jnxBoxAnatomy       ::= { jnxMibs 1 }        -- 2636.3.1
//	  jnxBoxClass       ::= { jnxBoxAnatomy 1 }  OBJECT IDENTIFIER, read-only
//	  jnxBoxDescr       ::= { jnxBoxAnatomy 2 }  DisplayString (SIZE (0..255)), read-only
//	  jnxBoxSerialNo    ::= { jnxBoxAnatomy 3 }  DisplayString (SIZE (0..255)), read-only
//	  jnxContentsTable  ::= { jnxBoxAnatomy 8 }  SEQUENCE OF JnxContentsEntry, NOT-ACCESSIBLE
//	  jnxOperatingTable ::= { jnxBoxAnatomy 13 } SEQUENCE OF JnxOperatingEntry, NOT-ACCESSIBLE
//	  jnxFruTable       ::= { jnxBoxAnatomy 15 } SEQUENCE OF JnxFruEntry, NOT-ACCESSIBLE
//
// From JUNIPER-EX-SMI and JUNIPER-VIRTUALCHASSIS-MIB 201403180000Z:
//
//	jnxExSwitching               ::= { jnxExMibRoot 1 }              -- 2636.3.40.1
//	jnxExVirtualChassis          ::= { jnxExSwitching 4 }            -- 2636.3.40.1.4
//	jnxVirtualChassisMemberMIB   ::= { jnxExVirtualChassis 1 }       -- 2636.3.40.1.4.1
//	jnxVirtualChassisMemberTable ::= { jnxVirtualChassisMemberMIB 1 }
//	jnxVirtualChassisMemberEntry ::= { jnxVirtualChassisMemberTable 1 }
//	                                 INDEX { jnxVirtualChassisMemberId }
//
// From JUNIPER-CHASSIS-DEFINES-MIB 201706230000Z:
//
//	jnxClassification ::= { jnxProducts 1 }        -- 2636.1.1
//	jnxClassGeneral   ::= { jnxClassification 1 }  -- 2636.1.1.1
//	jnxProductName    ::= { jnxClassGeneral 2 }    -- 2636.1.1.1.2, the sysObjectID registry
//	  jnxProductNameMX960 ::= { jnxProductName 21 }
//	  jnxProductNameMX480 ::= { jnxProductName 25 }
//	  jnxProductNameMX240 ::= { jnxProductName 29 }
//
// nl6#602 expected that last module to be unobtainable and told the implementer
// to record the two sysObjectID values as UNAUDITED if it was. IT WAS
// OBTAINABLE, from netdisco/netdisco-mibs, and reading it is what found the
// worst defect in this arc. Recording an UNAUDITED verdict without trying the
// second mirror would have shipped it.
//
// ## The finding that matters most to a collector
//
// juniper_mx960 answered sysObjectID.0 with 1.3.6.1.4.1.2636.1.1.1.2.25. That is
// jnxProductNameMX480. The profile is an MX960, its sysDescr says "mx960
// internet router", and its own vendor-detection surface identified it as a
// different chassis in the same family. The correct value is
// 1.3.6.1.4.1.2636.1.1.1.2.21, jnxProductNameMX960.
//
// THIS IS A SUBTLER SHAPE THAN nl6#599's ARISTA sysObjectID AND IT IS WORSE. The
// Arista value was well formed, under the right PEN, under the right registry,
// and RESOLVED TO NOTHING, so a collector's vendor detection failed loudly. This
// one RESOLVES, to a real Juniper product that nl6 does not model, so vendor
// detection succeeds and is wrong. Nothing downstream can tell.
//
// juniper_mx240 answers .29, jnxProductNameMX240, and that is CORRECT. So is the
// entPhysicalVendorType.1 value on the same profile, which carries the same OID.
// Both are pinned below, because a correct fact that no test names is one edit
// away from becoming an incorrect one.
//
// ## The deletions
//
// Twelve entries over eight distinct OIDs. DELETION, NOT CORRECTION, in every
// case, for nl6#569's reason: inventing a value for an object that is not
// defined, or cannot be read, is the defect these audits exist to remove.
//
//   - 2636.3.1.8.0 is jnxContentsTable with a scalar .0 appended, on BOTH
//     profiles. Two independent faults, either one fatal: a table object is
//     MAX-ACCESS not-accessible so no GET of it can succeed at any name, and .0
//     is not a legal instance of a table in the first place. This is the
//     aristaSwFwdIpStatsTable.0 defect of nl6#599 repeated verbatim on another
//     vendor, which is the argument for auditing every arc rather than
//     generalising from one. It answered "38" and "41".
//
//   - 2636.3.40.1.4.1.1.1.{1.0, 2.0, 3.0} and 2636.3.40.1.4.1.1.1.5 are the
//     jnxVirtualChassisMemberTable columns of an EX-SERIES SWITCH, served by two
//     MX-SERIES ROUTERS. jnxExMibRoot is { jnxMibs 40 } and sits between
//     jnxJsMibRoot (39) and jnxWxMibRoot (41), so 2636.3.40 is the EX branch by
//     construction. WRONG PLATFORM WITHIN THE RIGHT VENDOR IS A SUBCLASS NO
//     GUARD SEES: nl6#589's own-vendor PEN rule passes these by construction,
//     because 2636 really is Juniper's. Column by column, the values were not
//     even of the object's kind: .1 is jnxVirtualChassisMemberId, an
//     INTEGER (0..31) that is the table's INDEX and therefore MAX-ACCESS
//     not-accessible, and it answered "AMCC PowerPC 8544E"; .2 is
//     jnxVirtualChassisMemberSerialnumber and answered "6"; .3 is
//     jnxVirtualChassisMemberRole, INTEGER { master(1), backup(2), linecard(3) },
//     and answered "3200". The four read as CPU model, core count, clock MHz and
//     software version, which is what the author meant them to be. No obtainable
//     Juniper module defines a CPU-model object for an MX, so there is nowhere to
//     move them to and deletion is the only honest answer.
//
//   - 2636.3.40.1.4.1.1.1.5 is jnxVirtualChassisMemberSWVersion with NO INSTANCE
//     SUB-IDENTIFIER at all, a BARE COLUMN of the nl6#571 class, on both
//     profiles. Its value "21.4R3-S2.3" / "21.2R3-S4.9" is the only one of the
//     four that suits its column, which is exactly why it survived: it looks
//     right. Note that nl6#571's census could not see it, because its heuristic
//     is "some other shipped OID extends it" and nothing extended this one.
//
//   - 2636.3.1.13.1.8.5.0.0 and 2636.3.1.13.1.11.5.0.0 are jnxOperatingCPU and
//     jnxOperatingBuffer at an ILLEGAL INSTANCE (see the arity section), and they
//     are also the columns nl6 ALREADY SERVES LIVE at a legal instance. See
//     below: correcting them would have created dead data.
//
//   - 2636.3.1.13.1.21.1.1.0 is jnxOperating5MinLoadAvg at an illegal instance,
//     valued "2500". The MIB says of that object "Here it will be shown as
//     percentage value". A five-minute load average of 2500 percent is not a
//     value the object can take, so there is nothing to correct it to.
//
// ## The INDEX arity, resolved
//
// jnxOperatingEntry's INDEX is
//
//	{ jnxOperatingContentsIndex, jnxOperatingL1Index,
//	  jnxOperatingL2Index, jnxOperatingL3Index }
//
// FOUR sub-identifiers. nl6#602's own issue text named the first column
// jnxContainersIndex; it is jnxOperatingContentsIndex, which is defined as "The
// associated jnxContentsContainerIndex in the jnxContentsTable". The arity is
// what matters and it is four either way, but a reading is only worth what its
// accuracy is worth, so the correction is recorded.
//
// BOTH SHIPPED SPELLINGS WERE WRONG, not one of them. The issue observed that
// most rows used .5.0.0 while two used .1.1.0 and .1.2.0 and asked which was
// right. Neither: every one is THREE sub-identifiers where the INDEX clause
// requires four. The differing container index is a second, separate
// disagreement, and it is NOT resolvable from any MIB, because
// jnxOperatingContentsIndex points into jnxContentsTable, whose contents are a
// property of a device rather than of a module. Neither profile ships a single
// jnxContentsTable or jnxContainersTable row to resolve it against.
//
// WHAT SETTLED THE ROW IS nl6's OWN CODE, not a guess. metrics_oids.go serves
// both Juniper profiles jnxOperatingCPU, jnxOperatingBuffer and jnxOperatingTemp
// at instance 9.1.0.0, four sub-identifiers, as LIVE cycling values; the trap
// catalog uses four-sub-identifier instances throughout (9.1.1.0, 4.1.1.0,
// 7.1.1.0, 2.1.1.0). So the corpus already contained the legal spelling in two
// surfaces and the illegal one in a third, and the three columns this change
// renames adopt the row the live values already occupy rather than a new one.
//
// THAT IS ALSO WHY TWO COLUMNS ARE DELETED INSTEAD OF RENAMED. findResponse
// consults the metrics cycler BEFORE the static oidIndex (snmp_handlers.go), so
// a static jnxOperatingCPU row at 9.1.0.0 would never be answered. It would be
// dead data that looks authoritative, which is the nl6#570 defect exactly.
// jnxOperatingDescr, jnxOperating1MinLoadAvg and jnxOperating5MinLoadAvg are not
// cycler-owned, so those three are renamed onto the same row and keep answering.
//
// THE RESIDUAL, stated rather than glossed: contents index 9 is nl6's own
// convention and no obtainable module says a Routing Engine lives there. What
// the MIB settles is the ARITY. The row is inherited from code that already
// shipped, which is the least inventive option available, and it is not a MIB
// fact. The same applies to the new jnxOperatingDescr value "Routing Engine 0":
// the MIB says only "The name or detailed description of this subject", and the
// profile's own trap catalog already calls the 9.x row a Routing Engine.
//
// ## The value that was a number on a DisplayString
//
// 2636.3.1.13.1.5.5.0.0 is jnxOperatingDescr, DisplayString (SIZE (0..255)), and
// it answered "67" on juniper_mx240 and "34" on juniper_mx960. encodeTypedValue
// emits a bare numeric string as tag 0x02 INTEGER, so a collector typing the
// object per the MIB got an INTEGER where a DisplayString belongs. That is the
// nine-row defect nl6#592 corrected on Cisco, and it is also semantically empty:
// a descriptor that says "67" describes nothing. The correction is asserted
// THROUGH THE ENCODER below, because seven of nl6#592's rows survived a first
// cut that asserted the string and not the tag.
//
// ## The weak call
//
// jnxBoxDescr answered "JNP-MX240-002" and "JNP-MX960-001". Both are legal
// DisplayStrings and both encode as OCTET STRINGs, so nothing about them is a
// wire defect. The MIB's DESCRIPTION is "The name, model, or detailed
// description of the box, indicating which product the box is about, for example
// 'M40'", and an asset tag with an instance suffix indicates which UNIT the box
// is, not which PRODUCT. The values now name the product each profile's
// sysObjectID identifies, which is nl6#599's model-identity rule.
//
// THIS IS THE WEAKER OF THE TWO KINDS OF CALL THIS CHANGE MAKES, and it is
// recorded the way nl6#599 recorded its entPhysicalModelName.2 row and nl6#590
// its fan half. A device can be configured to answer anything here. What is not
// arguable is that the previous value did not indicate a product.
//
// ## Fleet-visible surface change
//
// Stated with counts, per the nl6#570 / nl6#574 / nl6#599 convention, because
// this changes what a collector sees on every juniper_mx240 and juniper_mx960
// device in a running fleet:
//
//   - juniper_mx960's sysObjectID.0 changes, so VENDOR DETECTION and asset
//     inventory resolve the node differently. It resolved to an MX480 and now
//     resolves to an MX960. That is the point of the change, not a side effect.
//     juniper_mx240's sysObjectID.0 is UNCHANGED and was already right.
//   - a walk of the two profiles returns TWELVE FEWER OIDs (25152 -> 25140
//     shipped SNMP entries corpus-wide), and THREE OIDs change name (the arity
//     renames), so an mx240 walk loses eight names and renames three while an
//     mx960 walk loses four and renames one.
//   - ownVendorArcNamesShipped falls from 328 to 316. ownVendorArcValuesShipped
//     stays 28: a value count that fell would mean a profile had stopped
//     identifying itself, and the mx960 correction moves its value WITHIN 2636.
//   - four values change without changing a name: two jnxBoxDescr, one
//     jnxOperatingDescr per profile.
//   - no other profile is touched, and no SSH response changes.
//
// ## Why there is a ledger, and which constants move
//
// THREE pinned constants move, and WHICH ones was MEASURED by applying the edits
// and running the suite, not predicted:
//
//   - shippedTagDigest is keyed on (profile, OID, emitted tag). Twelve triples
//     are removed, three are renamed, and ONE CORRECTION MOVES A TAG:
//     jnxOperatingDescr goes 0x02 INTEGER to 0x04 OCTET STRING on both profiles.
//     The other three corrections do not. nl6#599's ledger recorded no tag move
//     at all and said so; recording which corrections move one and which do not
//     is the discipline, not the answer.
//   - shippedOIDEncodingDigest hashes each DISTINCT shipped OID NAME against its
//     BER encoding, and collectShippedOIDs gathers OID-typed VALUES as well as
//     names. This change moves it three ways over: eight names leave, three are
//     renamed, and the sysObjectID correction swaps one OID-typed value for
//     another. So the name-view reversal is neither a pure append nor a pure
//     rewrite. See nl6602juniperOIDNamesBeforeAudit.
//   - ownVendorArcNamesShipped falls 328 -> 316 in snmp_own_vendor_pen_test.go.
//
// ONE PRE-EXISTING TEST HAD TO BE MADE COMPLETE, and it is worth knowing why.
// TestResourceDataDefectLedgerIsNotVacuous checks that each of nl6#571's 14
// deleted bare columns really was an interior node of the corpus at ec4700f, and
// it reconstructed that corpus by hand: today's entries plus nl6#574's own
// removals. That union was incomplete by construction, and this change is what
// made the incompleteness bite. 2636.3.1.13.1.8.5.0.0 was the ONLY OID in the
// whole corpus extending the bare 2636.3.1.13.1.8 column that four CISCO
// profiles shipped, so deleting it from the two Juniper profiles left nl6#571's
// classification of that column unprovable. The reconstruction now walks the
// nl6#600 registry back to ec4700f instead, which is complete by construction.
//
// Every recorded oldValue was read OUT OF GIT at 3830d8f (the revision this
// branch forked from) rather than retyped from the working tree.
// TestJuniperArcLedgerValuesMatchTheParentRevision pins that, with the same
// residual nl6#599 recorded: it hashes the ledger's rows against a constant a
// human derived by reading git, and never reads git itself, so it catches an
// edit made AFTER the constant was set and cannot catch a row that was wrong
// when it was computed.
//
// This ledger is the NEWEST link in the chain, registered as ONE entry in
// newestFirstReversals (nl6#600 replaced the twelve hand-edited call sites the
// Arista ledger had to touch).
//
// ## What this audit did NOT close
//
//   - The trap catalog's OBJECTS-CLAUSE fidelity. The seven notification OIDs
//     all resolve and every varbind uses a legal four-sub-identifier instance,
//     but NOT ONE of the seven emits the varbind list its NOTIFICATION-TYPE's
//     OBJECTS clause names, and one varbind declares a type the MIB contradicts.
//     Both are recorded as measurements by
//     TestJuniperTrapCatalogVarbindsAgainstTheMIB rather than fixed: the catalog
//     is deliberately Class-1-vocabulary only (its own comment says so) and
//     making it follow the clauses is a rewrite of all seven entries.
//   - SEMANTIC faithfulness of the mib-2 rows. juniper_mx960 answers
//     entPhysicalModelName.1 with "MODEL123" and entPhysicalVendorType.1 with
//     "1", neither of which is under the Juniper arc. Those belong with an
//     ENTITY-MIB sweep, which no arc audit has done; nl6#599 left the same class
//     open for the same reason.
//   - WHICH container index a Routing Engine occupies, and therefore whether the
//     renamed rows sit on the right row of a right-shaped table. See the arity
//     section.
//   - Whether the mirrored modules are what Juniper ships. See the provenance
//     note.

// The two profiles this whole ledger is about. Every row must name one of them;
// TestJuniperArcLedgerIsNotVacuous enforces it, because a row naming another
// profile would assert an absence against the wrong device while every digest
// still reconciled.
const (
	juniperMX240Profile = "juniper_mx240.json"
	juniperMX960Profile = "juniper_mx960.json"
)

// juniperArcRoot is the PEN root in the dotted spelling findNextOIDWithServed
// walks. juniperArcBare is the same arc undotted, which is the spelling both the
// VALUE position and collectShippedOIDs use.
const (
	juniperArcRoot = ".1.3.6.1.4.1.2636"
	juniperArcBare = "1.3.6.1.4.1.2636"

	// jnxProductNameMX960OID and jnxProductNameMX240OID are the two correct
	// sysObjectID values, resolved from JUNIPER-CHASSIS-DEFINES-MIB.
	jnxProductNameMX960OID = "1.3.6.1.4.1.2636.1.1.1.2.21"
	jnxProductNameMX240OID = "1.3.6.1.4.1.2636.1.1.1.2.29"

	// jnxProductNameMX480OID is the near miss, named as a constant so the
	// rejection below cannot decay into a bare string a reader mistakes for a
	// right answer. It IS a real Juniper product OID. It is the wrong product.
	jnxProductNameMX480OID = "1.3.6.1.4.1.2636.1.1.1.2.25"

	// jnxOperatingEntryPrefix and jnxFruEntryPrefix are the two chassis tables
	// whose INDEX clause has four columns. Both are used by the arity guard.
	jnxOperatingEntryPrefix = "1.3.6.1.4.1.2636.3.1.13.1"
	jnxFruEntryPrefix       = "1.3.6.1.4.1.2636.3.1.15.1"

	// jnxChassisTrapsRoot is { jnxTraps 1 }, the parent of all seven shipped
	// notification OIDs.
	jnxChassisTrapsRoot = "1.3.6.1.4.1.2636.4.1"
)

// jnxChassisTableIndexArity is the number of sub-identifiers an INSTANCE of
// jnxOperatingTable or jnxFruTable carries. Both entries have a four-column
// INDEX clause in JUNIPER-MIB 201010220000Z:
//
//	jnxOperatingEntry INDEX { jnxOperatingContentsIndex, jnxOperatingL1Index,
//	                          jnxOperatingL2Index,       jnxOperatingL3Index }
//	jnxFruEntry       INDEX { jnxFruContentsIndex,       jnxFruL1Index,
//	                          jnxFruL2Index,             jnxFruL3Index }
const jnxChassisTableIndexArity = 4

// nl6602juniperDeletedEntries are the twelve shipped entries this change
// removed, over eight distinct OIDs and two profiles.
//
// DO NOT RESTORE A ROW TO MAKE THE ARC LOOK FULLER, and do not restore one with
// a different value. Four of the eight OIDs name objects of a switch platform
// these routers are not, two name a table that cannot be read, one is a bare
// column, and the rest are illegal instances whose columns nl6 already serves
// live at a legal one. That is the same instruction nl6#571 left when four
// profiles stopped modelling storage and nl6#599 left when arista_7280r3 stopped
// serving its own vendor's arc.
var nl6602juniperDeletedEntries = []struct{ profile, oid, oldValue, object, why string }{
	{juniperMX240Profile, ".1.3.6.1.4.1.2636.3.1.8.0", "38",
		"jnxContentsTable",
		"a table object is MAX-ACCESS not-accessible and .0 is not a legal instance of one"},
	{juniperMX960Profile, ".1.3.6.1.4.1.2636.3.1.8.0", "41",
		"jnxContentsTable",
		"a table object is MAX-ACCESS not-accessible and .0 is not a legal instance of one"},

	{juniperMX240Profile, ".1.3.6.1.4.1.2636.3.1.13.1.8.5.0.0", "67",
		"jnxOperatingCPU at a three-sub-identifier instance",
		"the INDEX clause wants four, and metrics_oids.go already serves this column live at 9.1.0.0"},
	{juniperMX960Profile, ".1.3.6.1.4.1.2636.3.1.13.1.8.5.0.0", "34",
		"jnxOperatingCPU at a three-sub-identifier instance",
		"the INDEX clause wants four, and metrics_oids.go already serves this column live at 9.1.0.0"},
	{juniperMX240Profile, ".1.3.6.1.4.1.2636.3.1.13.1.11.5.0.0", "78",
		"jnxOperatingBuffer at a three-sub-identifier instance",
		"the INDEX clause wants four, and metrics_oids.go already serves this column live at 9.1.0.0"},
	{juniperMX960Profile, ".1.3.6.1.4.1.2636.3.1.13.1.11.5.0.0", "56",
		"jnxOperatingBuffer at a three-sub-identifier instance",
		"the INDEX clause wants four, and metrics_oids.go already serves this column live at 9.1.0.0"},
	{juniperMX240Profile, ".1.3.6.1.4.1.2636.3.1.13.1.21.1.1.0", "2500",
		"jnxOperating5MinLoadAvg at a three-sub-identifier instance",
		"the INDEX clause wants four, and the MIB says the object is shown as a percentage, which 2500 is not"},

	{juniperMX240Profile, ".1.3.6.1.4.1.2636.3.40.1.4.1.1.1.1.0", "AMCC PowerPC 8544E",
		"jnxVirtualChassisMemberId",
		"an EX-series Virtual Chassis object on an MX router, and the table's INDEX column, so MAX-ACCESS not-accessible"},
	{juniperMX240Profile, ".1.3.6.1.4.1.2636.3.40.1.4.1.1.1.2.0", "6",
		"jnxVirtualChassisMemberSerialnumber",
		"an EX-series Virtual Chassis object on an MX router, answering a core count where a serial number belongs"},
	{juniperMX240Profile, ".1.3.6.1.4.1.2636.3.40.1.4.1.1.1.3.0", "3200",
		"jnxVirtualChassisMemberRole",
		"an EX-series Virtual Chassis object on an MX router, and INTEGER { master(1), backup(2), linecard(3) } cannot take 3200"},
	{juniperMX240Profile, ".1.3.6.1.4.1.2636.3.40.1.4.1.1.1.5", "21.4R3-S2.3",
		"jnxVirtualChassisMemberSWVersion, a BARE COLUMN",
		"an EX-series Virtual Chassis object on an MX router, with no instance sub-identifier at all"},
	{juniperMX960Profile, ".1.3.6.1.4.1.2636.3.40.1.4.1.1.1.5", "21.2R3-S4.9",
		"jnxVirtualChassisMemberSWVersion, a BARE COLUMN",
		"an EX-series Virtual Chassis object on an MX router, with no instance sub-identifier at all"},
}

// nl6602juniperRenamedEntries are the four entries whose OID changed, all of
// them jnxOperatingTable columns moving from a three-sub-identifier instance to
// the four-sub-identifier row nl6's own live values already occupy.
//
// A rename is a DELETE PLUS AN ADD in the (profile, OID) -> value map, which is
// why restoreNl6602JuniperArc handles these separately from the two other
// tables. nl6#576's ledger is the precedent and the reason
// restoreCorpusValuesTo is in-place: merging a rewritten map back over the old
// one leaves BOTH spellings in the reconstruction.
//
// jnxOperatingDescr is the one row that changes value as well as name, and the
// only row in this ledger that moves a TAG.
var nl6602juniperRenamedEntries = []struct {
	profile, oldOID, newOID, oldValue, newValue, object string
	oldTag, newTag                                      byte
}{
	{juniperMX240Profile,
		".1.3.6.1.4.1.2636.3.1.13.1.5.5.0.0", ".1.3.6.1.4.1.2636.3.1.13.1.5.9.1.0.0",
		"67", "Routing Engine 0", "jnxOperatingDescr",
		ASN1_INTEGER, ASN1_OCTET_STRING},
	{juniperMX960Profile,
		".1.3.6.1.4.1.2636.3.1.13.1.5.5.0.0", ".1.3.6.1.4.1.2636.3.1.13.1.5.9.1.0.0",
		"34", "Routing Engine 0", "jnxOperatingDescr",
		ASN1_INTEGER, ASN1_OCTET_STRING},
	{juniperMX240Profile,
		".1.3.6.1.4.1.2636.3.1.13.1.20.5.0.0", ".1.3.6.1.4.1.2636.3.1.13.1.20.9.1.0.0",
		"45", "45", "jnxOperating1MinLoadAvg",
		ASN1_INTEGER, ASN1_INTEGER},
	{juniperMX240Profile,
		".1.3.6.1.4.1.2636.3.1.13.1.21.1.2.0", ".1.3.6.1.4.1.2636.3.1.13.1.21.9.1.0.0",
		"48", "48", "jnxOperating5MinLoadAvg",
		ASN1_INTEGER, ASN1_INTEGER},
}

// nl6602juniperValueCorrections are the three entries that kept their OID and
// changed value. None moves a tag.
//
// Two of them are jnxBoxDescr, the weak call recorded in the header. The third
// is the one that matters to a collector: juniper_mx960's sysObjectID.0 named
// jnxProductNameMX480. Its old value encodes perfectly well, which is the whole
// difficulty and the reason no load rule could see it. nl6#529's rule 2 asks
// whether an OID-typed value is ENCODABLE, never whether it RESOLVES, and
// nl6#589's own-vendor guard passes it because 2636 is genuinely Juniper's.
var nl6602juniperValueCorrections = []struct {
	profile, oid, oldValue, newValue, object string
	oldTag, newTag                           byte
}{
	{juniperMX240Profile, ".1.3.6.1.4.1.2636.3.1.2.0",
		"JNP-MX240-002",
		"Juniper Networks MX240 Universal Edge Router",
		"jnxBoxDescr", ASN1_OCTET_STRING, ASN1_OCTET_STRING},
	{juniperMX960Profile, ".1.3.6.1.4.1.2636.3.1.2.0",
		"JNP-MX960-001",
		"Juniper Networks MX960 Universal Edge Router",
		"jnxBoxDescr", ASN1_OCTET_STRING, ASN1_OCTET_STRING},
	{juniperMX960Profile, ".1.3.6.1.2.1.1.2.0",
		jnxProductNameMX480OID,
		jnxProductNameMX960OID,
		"sysObjectID", ASN1_OBJECT_ID, ASN1_OBJECT_ID},
}

// The two "before" digests live HERE rather than beside the live constants they
// chain onto, matching every ledger since nl6#576. The cross-reference is
// written down instead of left for a reader to discover:
//
//	live value                  declared in                       reversed by
//	shippedTagDigest            snmp_hc_counter_table_test.go     TestJuniperArcAuditReproducesTheParentCorpus
//	shippedOIDEncodingDigest    snmp_oid_roundtrip_test.go        TestJuniperArcRePinIsOnlyTheAudit
//
// The third moved constant, ownVendorArcNamesShipped in
// snmp_own_vendor_pen_test.go, is a COUNT rather than a digest and is re-derived
// from the corpus by its own test.

// juniperArcParentRevision is the revision this change forked from and the one
// its two golden digests below were taken at. Spelled once and read by both the
// tests here and this change's entry in newestFirstReversals, so the chain and
// the digests cannot come to disagree about which corpus is being reconstructed.
const juniperArcParentRevision = "3830d8f"

// shippedTagDigestBeforeJuniperArcAudit is the (profile, OID, emitted tag)
// digest of the corpus at 3830d8f, the value shippedTagDigest held before this
// change, NOT re-derived from the audited tree.
const shippedTagDigestBeforeJuniperArcAudit = "0a75f790fa90a6dd2df2dfe0ee841978ea99de1c873727ba728593015692af70"

// shippedOIDEncodingDigestBeforeJuniperArcAudit is the OID-name-to-encoding
// digest at the same revision, and the same rule applies to it.
const shippedOIDEncodingDigestBeforeJuniperArcAudit = "2c714eef349b5752ad5a3a208c5932b649fc8df6262da1050b0bd239bbbc7c44"

// nl6602juniperValueDigestAtParent is a SHA-256 over the sorted old-value lines
// of every row this ledger records: the twelve deletions, the four renames
// (keyed by their OLD OID) and the three value corrections, nineteen rows in
// all, as they existed at 3830d8f. Lines are "profile\toid\toldValue".
//
// It was computed by reading the six resource parts OUT OF GIT at that revision
// (git show 3830d8f:go/nl6/resources/<part>), never from the tables above, so
// comparing the tables against it compares them with the tree as it actually
// was. For the twelve deleted rows nothing else in the package has anything left
// to compare against.
const nl6602juniperValueDigestAtParent = "b98677ed9314dc81bb4b6ad6b5f1d05d8d4afd2ea8079d61b7867cdd9702b7a0"

// restoreNl6602JuniperArc reverses this change's SNMP edits against a
// (profile, OID) -> value map, so the map afterwards is the corpus as 3830d8f
// shipped it. Shared with every older ledger reversal, whose own starting point
// is the tree this one reconstructs.
//
// EVERY DISAGREEMENT IS FATAL, for the reason restoreNl6576NvidiaArc gives: a
// reversal that carries on past a corpus it does not recognise buries its own
// diagnosis under the caller's opaque digest mismatch.
func restoreNl6602JuniperArc(t *testing.T, cur map[[2]string]string) {
	t.Helper()

	for _, d := range nl6602juniperDeletedEntries {
		k := [2]string{d.profile, d.oid}
		if got, ok := cur[k]; ok {
			t.Fatalf("%s %s is in the nl6#602 Juniper removal ledger but still ships, valued %q. "+
				"It names %s: %s", d.profile, d.oid, got, d.object, d.why)
		}
		cur[k] = d.oldValue
	}
	for _, r := range nl6602juniperRenamedEntries {
		after := [2]string{r.profile, r.newOID}
		before := [2]string{r.profile, r.oldOID}
		got, ok := cur[after]
		if !ok {
			t.Fatalf("%s %s (%s) is in the nl6#602 rename ledger but no longer ships",
				r.profile, r.newOID, r.object)
		}
		if got != r.newValue {
			t.Fatalf("%s %s (%s) ships %q, but the ledger says this change set it to %q",
				r.profile, r.newOID, r.object, got, r.newValue)
		}
		if _, clash := cur[before]; clash {
			t.Fatalf("%s serves %s again, so the illegal three-sub-identifier jnxOperating "+
				"instance is back in the corpus", r.profile, r.oldOID)
		}
		delete(cur, after)
		cur[before] = r.oldValue
	}
	for _, c := range nl6602juniperValueCorrections {
		k := [2]string{c.profile, c.oid}
		got, ok := cur[k]
		if !ok {
			t.Fatalf("%s %s (%s) is in the nl6#602 correction ledger but no longer ships",
				c.profile, c.oid, c.object)
		}
		if got != c.newValue {
			t.Fatalf("%s %s (%s) ships %q, but the ledger says this change set it to %q",
				c.profile, c.oid, c.object, got, c.newValue)
		}
		cur[k] = c.oldValue
	}
}

// nl6602juniperVanishedOIDNames are the OID names this change removed from the
// corpus ENTIRELY, in the undotted spelling collectShippedOIDs gathers. Derived
// from the deletion ledger and deduplicated, because four of the eight are
// served by both profiles and collectShippedOIDs reports presence rather than a
// count. Pinned against the live corpus by TestJuniperArcVanishedNamesAreMeasured.
func nl6602juniperVanishedOIDNames() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, d := range nl6602juniperDeletedEntries {
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

// nl6602juniperOIDTypedCorrections returns the correction rows whose VALUE is an
// OID, which are the rows collectShippedOIDs sees in the value position. Exactly
// one row qualifies (juniper_mx960's sysObjectID), and that is ASSERTED rather
// than assumed by nl6602juniperOIDNamesBeforeAudit: a gate that silently stopped
// matching would turn the value half of the name reversal into a no-op, and the
// only test to fail would be one whose documented remedy is to re-pin a golden
// digest.
func nl6602juniperOIDTypedCorrections() []struct {
	profile, oid, oldValue, newValue, object string
	oldTag, newTag                           byte
} {
	var out []struct {
		profile, oid, oldValue, newValue, object string
		oldTag, newTag                           byte
	}
	for _, c := range nl6602juniperValueCorrections {
		if snmpTypeTag(c.oid) == ASN1_OBJECT_ID {
			out = append(out, c)
		}
	}
	return out
}

// nl6602juniperOIDNamesBeforeAudit maps a list of shipped OID NAMES back to the
// set 3830d8f shipped. It is the name-view counterpart of
// restoreNl6602JuniperArc and is registered as this change's link in
// newestFirstReversals, the newest one, so every name-view walk begins with it.
//
// IT IS THREE OPERATIONS, not one, and that is what makes it worth reading:
//
//  1. eight deleted names are APPENDED;
//  2. three renamed names are DROPPED and their old spellings appended, because
//     collectShippedOIDs deduplicates and the parent's set held the old spelling
//     and not the new one;
//  3. the corrected sysObjectID VALUE is dropped and the old one appended, since
//     collectShippedOIDs gathers OID-typed values as well as names.
//
// Every drop is COUNTED and a count that disagrees is FATAL. A drop that matched
// nothing would silently reconstruct a set the parent never had, and the only
// symptom would be a digest mismatch in an unrelated ledger.
func nl6602juniperOIDNamesBeforeAudit(t *testing.T, names []string) []string {
	t.Helper()

	oidTyped := nl6602juniperOIDTypedCorrections()
	if len(oidTyped) != 1 {
		t.Fatalf("%d correction rows have an OID-typed value, want exactly 1 (juniper_mx960's "+
			"sysObjectID). The name-view reversal drops and re-adds exactly those rows, so a "+
			"change in this count silently changes what the reversal reconstructs", len(oidTyped))
	}

	drop := map[string]struct{}{}
	var add []string
	for _, c := range oidTyped {
		drop[normaliseLedgerOID(c.newValue)] = struct{}{}
		add = append(add, normaliseLedgerOID(c.oldValue))
	}
	for _, r := range nl6602juniperRenamedEntries {
		newName := normaliseLedgerOID(r.newOID)
		oldName := normaliseLedgerOID(r.oldOID)
		if _, dup := drop[newName]; dup {
			continue // both profiles rename jnxOperatingDescr to the same name
		}
		drop[newName] = struct{}{}
		add = append(add, oldName)
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
		t.Fatalf("the name-view reversal dropped %d names but expected %d: the renamed OIDs and "+
			"the corrected sysObjectID value are not each in the shipped OID set exactly once, so "+
			"the reconstruction is not the parent's set", dropped, len(drop))
	}

	out = append(out, add...)
	return append(out, nl6602juniperVanishedOIDNames()...)
}

// TestJuniperArcAuditReproducesTheParentCorpus is the before/after pin for the
// TAG digest: reverse the ledger against today's corpus and 3830d8f's value must
// come back. A missing row, an extra row, or any other edit to shipped data made
// without recording it here all fail.
func TestJuniperArcAuditReproducesTheParentCorpus(t *testing.T) {
	cur := map[[2]string]string{}
	for _, e := range shippedSNMPEntries(t) {
		k := [2]string{e.Profile, e.OID}
		if prev, dup := cur[k]; dup && prev != e.Value {
			t.Fatalf("%s serves %s twice with different values (%q, %q); the reconstruction "+
				"cannot be unambiguous", e.Profile, e.OID, prev, e.Value)
		}
		cur[k] = e.Value
	}

	// This change is the newest link, so the walk applies its reversal and
	// stops. The chain lives in snmp_shipped_corpus_reversals_test.go.
	restoreCorpusValuesTo(t, cur, juniperArcParentRevision)

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

	t.Logf("restored %d deleted entries, un-renamed %d and reverted %d value corrections; "+
		"%d (profile, OID, tag) triples reconstructed", len(nl6602juniperDeletedEntries),
		len(nl6602juniperRenamedEntries), len(nl6602juniperValueCorrections), len(lines))

	if got != shippedTagDigestBeforeJuniperArcAudit {
		t.Errorf("reconstructed parent digest = %s, want %s.\n"+
			"The ledger no longer accounts for the difference between 3830d8f's shipped data and "+
			"this tree's. Either a row is missing from it, or shipped data changed without being "+
			"recorded.", got, shippedTagDigestBeforeJuniperArcAudit)
	}
}

// TestJuniperArcRePinIsOnlyTheAudit does the same job for the OID-NAME digest,
// which the tag digest cannot see: it hashes (profile, OID, tag) triples, so it
// says nothing about which distinct NAMES the corpus stopped shipping, nor about
// an OID-typed VALUE changing, which moves no tag at all.
func TestJuniperArcRePinIsOnlyTheAudit(t *testing.T) {
	vanished := nl6602juniperVanishedOIDNames()
	if len(vanished) == 0 {
		t.Fatal("the ledger yielded no vanished OID names")
	}

	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), juniperArcParentRevision)
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

	if got != shippedOIDEncodingDigestBeforeJuniperArcAudit {
		t.Errorf("restoring %d deleted OID names, un-renaming %d and un-correcting the "+
			"sysObjectID value gives digest %s, want the pre-change value %s over %d OIDs.\n"+
			"So the re-pin of shippedOIDEncodingDigest is NOT explained by this audit alone: "+
			"something else about what a shipped OID puts on the wire has changed.",
			len(vanished), len(nl6602juniperRenamedEntries), got,
			shippedOIDEncodingDigestBeforeJuniperArcAudit, checked)
	}
	t.Logf("%d shipped OID names reconstructed to the pre-change digest", checked)
}

// TestJuniperArcLedgerValuesMatchTheParentRevision pins the ledger's recorded old
// values against the tree at 3830d8f. Without it the twelve deleted values are
// unfalsifiable: this change removed every one of them from the tree, so nothing
// else in the package has anything left to compare against.
//
// If it fails after an edit to the tables, the tables are wrong. The parent
// revision cannot change.
func TestJuniperArcLedgerValuesMatchTheParentRevision(t *testing.T) {
	var lines []string
	for _, d := range nl6602juniperDeletedEntries {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", d.profile, d.oid, d.oldValue))
	}
	for _, r := range nl6602juniperRenamedEntries {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", r.profile, r.oldOID, r.oldValue))
	}
	for _, c := range nl6602juniperValueCorrections {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", c.profile, c.oid, c.oldValue))
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	got := hex.EncodeToString(h.Sum(nil))

	if got != nl6602juniperValueDigestAtParent {
		t.Errorf("ledger value digest = %s, want %s (%d rows).\n"+
			"The recorded old values no longer match what 3830d8f shipped. Re-derive with: "+
			"git show 3830d8f:go/nl6/resources/juniper_mx240/juniper_mx240_snmp_{1,9}.json and "+
			"the juniper_mx960 snmp_{1,17,18} parts, collect the rows this ledger names, and hash "+
			"sorted \"profile\\tOID\\tvalue\" lines. Do not re-pin this constant to match an "+
			"edited table: the parent revision is fixed.",
			got, nl6602juniperValueDigestAtParent, len(lines))
	}
	t.Logf("all %d recorded values match the corpus at 3830d8f", len(lines))
}

// TestJuniperArcLedgerIsNotVacuous guards the guard. An emptied ledger would make
// the reversals above pass only if the corpus were untouched, so the census is
// pinned and the SHAPE of every row is checked against the claim made about it.
func TestJuniperArcLedgerIsNotVacuous(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"nl6#602 Juniper deleted entries", len(nl6602juniperDeletedEntries), 12},
		{"nl6#602 Juniper renamed entries", len(nl6602juniperRenamedEntries), 4},
		{"nl6#602 Juniper value corrections", len(nl6602juniperValueCorrections), 3},
		{"nl6#602 Juniper names that vanished corpus-wide", len(nl6602juniperVanishedOIDNames()), 8},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: ledger has %d rows, want %d. The counts are the census quoted in the "+
				"commit body, the ledger header and docs/reference/snmp.md, so they move together "+
				"or not at all", tc.name, tc.got, tc.want)
		}
	}

	// THE AUDIT'S HEADLINE ARITHMETIC, derived rather than asserted in prose,
	// and derived in BOTH units because the earlier arcs each had to correct
	// one of them. TestJuniperArcIsMeasuredInBothPositions computes the
	// denominators from the corpus; here they are computed from the ledger, and
	// the two have to agree.
	//
	// Distinct OIDs: 13 names under 2636 plus 2 OID-typed values pointing into
	// it. Entries: 20 name-position plus 3 value-position.
	distinctWrong := len(nl6602juniperVanishedOIDNames()) + // 8 deleted names
		3 + // 3 renamed names, counted once each despite four entries
		1 + // jnxBoxDescr, one distinct OID over two profiles
		len(nl6602juniperOIDTypedCorrections()) // the mx960 sysObjectID value
	if distinctWrong != 13 {
		t.Errorf("the ledger accounts for %d wrong distinct facts, want 13. "+
			"docs/reference/snmp.md and the ledger header both quote \"13 of 15\"", distinctWrong)
	}
	entriesWrong := len(nl6602juniperDeletedEntries) +
		len(nl6602juniperRenamedEntries) +
		len(nl6602juniperValueCorrections)
	if entriesWrong != 19 {
		t.Errorf("the ledger accounts for %d wrong entries, want 19; the docs quote "+
			"\"19 of 22 entries\"", entriesWrong)
	}

	// Cheap validity guards that catch a phantom row. A deletion row naming an
	// absent profile reverses nothing; a row whose two sides are equal records
	// no change and passes every digest.
	shippedProfiles := map[string]struct{}{}
	for _, p := range shippedProfileNames(t) {
		shippedProfiles[p] = struct{}{}
	}
	for _, p := range []string{juniperMX240Profile, juniperMX960Profile} {
		if _, ok := shippedProfiles[p]; !ok {
			t.Fatalf("%s is not a shipped profile; every row in this ledger naming it is a "+
				"phantom", p)
		}
	}
	isJuniperProfile := func(p string) bool {
		return p == juniperMX240Profile || p == juniperMX960Profile
	}

	// Every DELETED row must be under the Juniper PEN. A row on another arc
	// would mean this ledger is reversing an edit that belongs elsewhere.
	for _, d := range nl6602juniperDeletedEntries {
		if !isJuniperProfile(d.profile) {
			t.Errorf("deletion row %s names profile %s, but this ledger is only about the two "+
				"Juniper profiles", d.oid, d.profile)
		}
		if !strings.HasPrefix(d.oid, juniperArcRoot+".") {
			t.Errorf("%s %s is in the nl6#602 Juniper ledger but is not under Juniper's PEN",
				d.profile, d.oid)
		}
		if strings.TrimSpace(d.object) == "" || strings.TrimSpace(d.why) == "" {
			t.Errorf("%s %s carries no object name or no reason; a deletion ledger row that does "+
				"not say what it deleted and why is not a reading", d.profile, d.oid)
		}
	}

	// The RENAMES are all jnxOperatingTable columns, and the whole point is the
	// arity, so that is what is asserted: three instance sub-identifiers before,
	// four after. Asserted from the OIDs themselves rather than restated, so a
	// row edited to a different spelling fails here.
	for _, r := range nl6602juniperRenamedEntries {
		if !isJuniperProfile(r.profile) {
			t.Errorf("rename row %s names profile %s", r.oldOID, r.profile)
		}
		if r.oldOID == r.newOID {
			t.Errorf("%s %s (%s) renames to itself, so it documents no change",
				r.profile, r.oldOID, r.object)
		}
		oldArity, ok := jnxInstanceArity(normaliseLedgerOID(r.oldOID), jnxOperatingEntryPrefix)
		if !ok {
			t.Errorf("%s (%s) is not under jnxOperatingEntry, but every rename in this ledger is",
				r.oldOID, r.object)
			continue
		}
		newArity, _ := jnxInstanceArity(normaliseLedgerOID(r.newOID), jnxOperatingEntryPrefix)
		if oldArity != 3 {
			t.Errorf("%s %s (%s) had %d instance sub-identifiers, want 3; the ledger's account of "+
				"why it was renamed is that it was under-specified", r.profile, r.oldOID,
				r.object, oldArity)
		}
		if newArity != jnxChassisTableIndexArity {
			t.Errorf("%s %s (%s) now has %d instance sub-identifiers, want %d. jnxOperatingEntry's "+
				"INDEX clause has four columns in JUNIPER-MIB 201010220000Z", r.profile,
				r.newOID, r.object, newArity, jnxChassisTableIndexArity)
		}

		// Tags through the ENCODER, not reasoned about from oidTypeTable,
		// because the encoder is what decides the wire byte.
		assertLedgerTags(t, r.profile, r.newOID, r.object, r.oldValue, r.newValue,
			r.oldTag, r.newTag)
	}

	for _, c := range nl6602juniperValueCorrections {
		if !isJuniperProfile(c.profile) {
			t.Errorf("correction row %s names profile %s", c.oid, c.profile)
		}
		if c.oldValue == c.newValue {
			t.Errorf("%s %s (%s) records the same value on both sides, so it documents no change "+
				"and would reconcile against every digest", c.profile, c.oid, c.object)
		}
		assertLedgerTags(t, c.profile, c.oid, c.object, c.oldValue, c.newValue, c.oldTag, c.newTag)
	}

	// EXACTLY ONE ROW IN THIS LEDGER MOVES A TAG, and it is asserted as a count
	// rather than left implicit. nl6#599's Arista ledger required that NO
	// correction moved one; requiring the same here would be wrong, and
	// requiring nothing would let the header's account of why shippedTagDigest
	// moved drift away from the data.
	tagMoves := 0
	for _, r := range nl6602juniperRenamedEntries {
		if r.oldTag != r.newTag {
			tagMoves++
		}
	}
	for _, c := range nl6602juniperValueCorrections {
		if c.oldTag != c.newTag {
			tagMoves++
		}
	}
	if tagMoves != 2 {
		t.Errorf("%d ledger rows move a tag, want 2 (jnxOperatingDescr on each profile, "+
			"0x02 INTEGER to 0x04 OCTET STRING). If this changed, the header's account of why "+
			"shippedTagDigest moved is wrong", tagMoves)
	}
}

// assertLedgerTags checks a ledger row's recorded tags THROUGH the production
// encoder, which is what decides the byte that reaches a collector. Shared by
// the rename and correction loops so the two cannot drift.
func assertLedgerTags(t *testing.T, profile, oid, object, oldValue, newValue string,
	oldTag, newTag byte) {
	t.Helper()

	encOld := encodeTypedValue(oid, oldValue)
	encNew := encodeTypedValue(oid, newValue)
	if len(encOld) == 0 || encOld[0] != oldTag {
		t.Errorf("%s %s (%s): old value %q emits % x, but the ledger records tag 0x%02X",
			profile, oid, object, oldValue, encOld, oldTag)
	}
	if len(encNew) == 0 || encNew[0] != newTag {
		t.Errorf("%s %s (%s): new value %q emits % x, but the ledger records tag 0x%02X",
			profile, oid, object, newValue, encNew, newTag)
	}
}

// jnxInstanceArity returns how many trailing sub-identifiers an OID carries
// beyond a table entry's COLUMN, and whether the OID is under that entry at all.
//
// The column is the first sub-identifier after the entry prefix, so an OID of
// the form <entryPrefix>.<column>.<i1>.<i2>... has arity equal to the number of
// sub-identifiers after <column>. A bare column returns 0.
func jnxInstanceArity(oid, entryPrefix string) (int, bool) {
	rest, ok := strings.CutPrefix(oid, entryPrefix+".")
	if !ok {
		return 0, false
	}
	parts := strings.Split(rest, ".")
	return len(parts) - 1, true
}

// TestJuniperArcVanishedNamesAreMeasured is what makes "every deleted name left
// the corpus" a measurement rather than a claim. nl6#592's Cisco arc recorded
// seven deleted names of which only five actually left, one still shipping on
// three other profiles and one still a trap varbind, so the same question has to
// be ASKED here rather than inferred from a table on two profiles.
//
// collectShippedOIDs walks the trap and syslog catalogs as well as the resource
// parts, so a Juniper varbind hiding in a catalog would fail this.
func TestJuniperArcVanishedNamesAreMeasured(t *testing.T) {
	// collectShippedOIDs DEDUPLICATES, so this is a presence set and never a
	// census. Its value here is BREADTH. Counting is done separately below,
	// from a source that does not deduplicate.
	shipped := map[string]struct{}{}
	for _, o := range collectShippedOIDs(t) {
		shipped[normaliseLedgerOID(o)] = struct{}{}
	}

	for _, o := range nl6602juniperVanishedOIDNames() {
		if _, ok := shipped[o]; ok {
			t.Errorf("%s is recorded as having left the corpus but is still named somewhere "+
				"(a resource part or a catalog varbind); the name-digest reversal would "+
				"double-count it", o)
		}
	}

	// OWNERSHIP IS COUNTED FROM shippedSNMPEntries, NOT FROM collectShippedOIDs,
	// and the distinction is the whole reason this assertion works. The set
	// above answers "is this name in the corpus", never "how many entries carry
	// it", so counting with it reports 1 no matter how many profiles serve an
	// OID. nl6#599 recorded a first cut that did exactly that and did not move
	// when a second owner was planted.
	owners := map[string]int{}
	for _, e := range shippedSNMPEntries(t) {
		owners[normaliseLedgerOID(e.OID)]++
		// The VALUE position too, decided by the production predicate rather
		// than by string shape: the same gate collectShippedOIDs uses.
		if snmpTypeTag(e.OID) == ASN1_OBJECT_ID {
			owners[normaliseLedgerOID(e.Value)]++
		}
	}

	// The corrected sysObjectID VALUE has the mirror-image requirement to a
	// deletion: the NEW OID must have exactly ONE owner and the OLD one none.
	// nl6602juniperOIDNamesBeforeAudit removes the new OID from the
	// distinct-name set, so a second owner would mean the parent's set CONTAINED
	// it and the reconstruction would be of a set that never existed.
	for _, c := range nl6602juniperOIDTypedCorrections() {
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
				"the way nl6#592's Cisco one does", c.profile, c.object, c.newValue, n)
		}
		if n := owners[normaliseLedgerOID(c.oldValue)]; n > 0 {
			t.Errorf("%s (%s) still puts %s into the corpus (%d entry/entries); that is "+
				"jnxProductNameMX480, the wrong-product OID this change replaced",
				c.profile, c.object, c.oldValue, n)
		}
	}

	// The RENAMED names must be present and the old spellings gone. Both halves
	// matter: the reversal drops the new name and appends the old one, so an
	// absent new name drops nothing and a surviving old name double-counts.
	for _, r := range nl6602juniperRenamedEntries {
		if _, ok := shipped[normaliseLedgerOID(r.newOID)]; !ok {
			t.Errorf("%s (%s): %s is absent from collectShippedOIDs, so the name-digest reversal "+
				"has nothing to drop", r.profile, r.object, r.newOID)
		}
		if _, ok := shipped[normaliseLedgerOID(r.oldOID)]; ok {
			t.Errorf("%s (%s): %s is shipped again, so the illegal three-sub-identifier instance "+
				"is back and the reversal would append a name the corpus already has",
				r.profile, r.object, r.oldOID)
		}
	}
}

// TestJuniperArcMatchesTheMIB is the nl6#602 audit, committed as a test rather
// than left in an issue. It is the ONLY form of check available here, because no
// load guard can see any of these defects:
//
//   - the deleted OIDs were well-formed names carrying encodable values, so all
//     three load rules passed them (nl6#523, nl6#529, nl6#541). Being UNDEFINED,
//     NOT-ACCESSIBLE or WRONG-PLATFORM is not a property of an OID string; it is
//     a property of a MIB.
//   - the nl6#571 bare-column census could not see the bare
//     jnxVirtualChassisMemberSWVersion column either: its heuristic is "some
//     other shipped OID extends it", and nothing extended it.
//   - the sysObjectID value ENCODED FINE and is under the profile's OWN PEN, so
//     nl6#587 / #588 / #589's vendor guards had nothing to say. It even
//     RESOLVED, to the wrong product.
//
// What it asserts is what a test CAN assert: the exact values served, the tags
// they go out as, and the absence of what was deleted. That the values are
// FAITHFUL comes from reading the five modules listed at the top of this file,
// each cited by revision (where it has one) and by the SHA-256 of the file read,
// and this function is the RECORD OF THAT READING. Read it as "this is what the
// Juniper arc audit resolved", never as "CI checks nl6 against a MIB". NO MIB
// FILE IS CHECKED IN.
//
// The reading is qualified by REVISION, not stated as correctness: these
// profiles match those revisions of those modules, from those mirrors. A
// device's shipped MIB need not agree with them, and JUNIPER-MIB in particular
// is a 2010 revision while the profiles claim Junos 20.4 and 21.4.
func TestJuniperArcMatchesTheMIB(t *testing.T) {
	const sysObjectID = ".1.3.6.1.2.1.1.2.0"

	mx240 := deviceForProfile(t, juniperMX240Profile)
	mx960 := deviceForProfile(t, juniperMX960Profile)

	// ## the identity surface
	//
	// juniper_mx960's sysObjectID is the correction that matters to a collector.
	// The near miss is rejected BY NAME, because a bare "want X, got Y" would
	// not say that Y is a real product.
	if got := mx960.findResponse(sysObjectID); got == jnxProductNameMX480OID {
		t.Fatalf("juniper_mx960 sysObjectID.0 answers %s. THAT IS jnxProductNameMX480, "+
			"{ jnxProductName 25 } in JUNIPER-CHASSIS-DEFINES-MIB 201706230000Z, a REAL Juniper "+
			"product OID for a DIFFERENT chassis. Because it resolves, a collector's vendor "+
			"detection succeeds and is wrong, which is worse than nl6#599's Arista value that "+
			"resolved to nothing. The correct answer is %s, jnxProductNameMX960, "+
			"{ jnxProductName 21 }", got, jnxProductNameMX960OID)
	}
	for _, tc := range []struct {
		dev     *SNMPServer
		profile string
		want    string
		object  string
	}{
		{mx960, juniperMX960Profile, jnxProductNameMX960OID, "jnxProductNameMX960"},
		{mx240, juniperMX240Profile, jnxProductNameMX240OID, "jnxProductNameMX240"},
	} {
		got := tc.dev.findResponse(sysObjectID)
		if got != tc.want {
			t.Errorf("%s sysObjectID.0 answers %q, want %q (%s). jnxProductName is "+
				"{ jnxClassGeneral 2 } under { jnxProducts 1 }, which JUNIPER-SMI 200910290000Z "+
				"reserves for Junos-based products, and JUNIPER-CHASSIS-DEFINES-MIB "+
				"201706230000Z is what assigns the per-product sub-identifier",
				tc.profile, got, tc.want, tc.object)
		}
		if enc := encodeTypedValue(sysObjectID, got); len(enc) == 0 || enc[0] != ASN1_OBJECT_ID {
			t.Errorf("%s sysObjectID.0 emits % x, want tag 0x%02X", tc.profile, enc,
				ASN1_OBJECT_ID)
		}
	}

	// juniper_mx240's entPhysicalVendorType.1 carries the same product OID and
	// was ALSO already correct. Pinned because a correct fact no test names is
	// one edit from becoming an incorrect one, and because nl6#599 found exactly
	// this column carrying an unresolvable value on arista_7280r3.
	const entPhysicalVendorType1 = ".1.3.6.1.2.1.47.1.1.1.1.3.1"
	if got := mx240.findResponse(entPhysicalVendorType1); got != jnxProductNameMX240OID {
		t.Errorf("juniper_mx240 entPhysicalVendorType.1 answers %q, want %q. It carries the same "+
			"jnxProductNameMX240 OID as sysObjectID.0 and was correct before this audit; the two "+
			"have to identify the same machine", got, jnxProductNameMX240OID)
	}

	// ## the values the audit corrected
	for _, tc := range []struct {
		dev             *SNMPServer
		profile, oid    string
		object, want    string
		wantTag         byte
		rejectSubstring string
	}{
		{mx240, juniperMX240Profile, ".1.3.6.1.4.1.2636.3.1.2.0", "jnxBoxDescr",
			"Juniper Networks MX240 Universal Edge Router", ASN1_OCTET_STRING, "JNP-MX240"},
		{mx960, juniperMX960Profile, ".1.3.6.1.4.1.2636.3.1.2.0", "jnxBoxDescr",
			"Juniper Networks MX960 Universal Edge Router", ASN1_OCTET_STRING, "JNP-MX960"},
		{mx240, juniperMX240Profile, ".1.3.6.1.4.1.2636.3.1.13.1.5.9.1.0.0", "jnxOperatingDescr",
			"Routing Engine 0", ASN1_OCTET_STRING, ""},
		{mx960, juniperMX960Profile, ".1.3.6.1.4.1.2636.3.1.13.1.5.9.1.0.0", "jnxOperatingDescr",
			"Routing Engine 0", ASN1_OCTET_STRING, ""},
	} {
		got := tc.dev.findResponse(tc.oid)
		if got != tc.want {
			t.Errorf("%s %s (%s) answers %q, want %q", tc.profile, tc.oid, tc.object, got, tc.want)
		}
		// THE TAG IS THE POINT for jnxOperatingDescr, and asserting the string
		// alone is how seven of nl6#592's nine Cisco rows survived a first cut.
		// Both objects are DisplayString (SIZE (0..255)) in JUNIPER-MIB
		// 201010220000Z, and encodeTypedValue emits a bare numeric string as
		// 0x02 INTEGER.
		if enc := encodeTypedValue(tc.oid, got); len(enc) == 0 || enc[0] != tc.wantTag {
			t.Errorf("%s %s (%s) emits % x, want tag 0x%02X: the object is a DisplayString and a "+
				"numeric value would go out as INTEGER", tc.profile, tc.oid, tc.object, enc,
				tc.wantTag)
		}
		if len(got) > 255 {
			t.Errorf("%s %s (%s) answers %d bytes, over the DisplayString (SIZE (0..255)) bound",
				tc.profile, tc.oid, tc.object, len(got))
		}
		if tc.rejectSubstring != "" && strings.Contains(got, tc.rejectSubstring) {
			t.Errorf("%s %s (%s) answers %q, which still carries the asset tag %q. jnxBoxDescr's "+
				"DESCRIPTION is \"The name, model, or detailed description of the box, indicating "+
				"which product the box is about, for example 'M40'\": an asset tag indicates which "+
				"UNIT, not which PRODUCT. This is the WEAKER of the calls this audit made and it "+
				"is recorded as such", tc.profile, tc.oid, tc.object, got, tc.rejectSubstring)
		}
	}

	// ## what was correct and was left alone
	//
	// jnxBoxSerialNo is one of only two facts this arc got right. Asserted so
	// that changing it becomes a decision rather than a side effect.
	for _, tc := range []struct {
		dev           *SNMPServer
		profile, want string
	}{
		{mx240, juniperMX240Profile, "JN1234MX240"},
		{mx960, juniperMX960Profile, "JN5678MX960"},
	} {
		const jnxBoxSerialNo = ".1.3.6.1.4.1.2636.3.1.3.0"
		got := tc.dev.findResponse(jnxBoxSerialNo)
		if got != tc.want {
			t.Errorf("%s jnxBoxSerialNo answers %q, want %q. It is a DisplayString "+
				"(SIZE (0..255)) at { jnxBoxAnatomy 3 } and it was already right; this audit left "+
				"it alone", tc.profile, got, tc.want)
		}
		if enc := encodeTypedValue(jnxBoxSerialNo, got); len(enc) == 0 ||
			enc[0] != ASN1_OCTET_STRING {
			t.Errorf("%s jnxBoxSerialNo emits % x, want tag 0x%02X", tc.profile, enc,
				ASN1_OCTET_STRING)
		}
	}

	// ## the twelve deletions
	//
	// findResponse answers a miss with the valueNoSuchObject sentinel and never
	// with "" (nl6#517), which is the one spelling of absence this asserts.
	devices := map[string]*SNMPServer{juniperMX240Profile: mx240, juniperMX960Profile: mx960}
	for _, tc := range nl6602juniperDeletedEntries {
		if got := devices[tc.profile].findResponse(tc.oid); !isSNMPExceptionValue(got) {
			t.Errorf("%s still answers %s (%s) with %q; it was deleted because %s. "+
				"Do not restore this row with a different value: inventing a value for an object "+
				"that is not defined, cannot be read, or belongs to another platform is the "+
				"nl6#569 defect", tc.profile, tc.oid, tc.object, got, tc.why)
		}
	}

	// ## the EX-series branch is now empty on both profiles
	//
	// Asserted over a WALK from jnxExMibRoot rather than by re-listing the four
	// OIDs, so a fifth invented EX object added later fails here instead of
	// arriving unguarded. THE POSITIVE CONTROL IS WHAT MAKES THE EMPTINESS MEAN
	// ANYTHING: findNextOIDWithServed answers end of MIB with an EMPTY string,
	// so "the successor is not under the branch" is also satisfied by a walk
	// that sees nothing at all.
	const jnxExMibRoot = ".1.3.6.1.4.1.2636.3.40"
	t.Run("positive control: the walk can see an object under jnxExMibRoot", func(t *testing.T) {
		planted := deviceForProfileWithPlantedOID(t, juniperMX240Profile,
			"1.3.6.1.4.1.2636.3.40.1.4.1.1.1.99.0", "planted")
		next, _ := planted.findNextOIDWithServed(jnxExMibRoot, planted.lldpServedOIDs())
		if !strings.HasPrefix(next, jnxExMibRoot+".") {
			t.Fatalf("with an object planted under jnxExMibRoot, walking from %s reaches %q: the "+
				"walk cannot see that branch at all, so the emptiness check in the parent test "+
				"proves nothing", jnxExMibRoot, next)
		}
	})
	for profile, dev := range devices {
		next, _ := dev.findNextOIDWithServed(jnxExMibRoot, dev.lldpServedOIDs())
		if strings.HasPrefix(next, jnxExMibRoot+".") {
			t.Errorf("%s serves %s, under jnxExMibRoot. That is { jnxMibs 40 } in JUNIPER-SMI "+
				"200910290000Z, the EX-SERIES SWITCH MIB root, sitting between jnxJsMibRoot (39) "+
				"and jnxWxMibRoot (41). These profiles are MX-series ROUTERS. nl6#589's "+
				"own-vendor PEN guard cannot see this, because 2636 really is Juniper's",
				profile, next)
		}
	}
}

// TestJuniperChassisTableInstancesHaveTheIndexArity is the corpus-wide guard the
// arity finding leaves behind, and it is the reason that finding is a rule
// rather than a set of edits.
//
// jnxOperatingEntry and jnxFruEntry each have a FOUR-COLUMN INDEX clause in
// JUNIPER-MIB 201010220000Z, so every varbind name under either is legal only
// with exactly four instance sub-identifiers. Before this audit the corpus held
// THREE different spellings of the same table, in three different surfaces, and
// only the resource files were wrong:
//
//	resource files      5.0.0 / 1.1.0 / 1.2.0   three sub-identifiers, ILLEGAL
//	metrics_oids.go     9.1.0.0                 four, legal, and served LIVE
//	traps.json          9.1.1.0 / 4.1.1.0 ...   four, legal
//
// SCANNING ALL THREE SURFACES IS THE POINT. A scan of resource files alone would
// have reported the defect without the evidence that settled it, and a scan of
// one profile alone would have missed that both spellings shipped. The two
// surfaces that were already right are also the two no golden digest covers:
// shippedSNMPEntries reads doc.SNMP only, and neither digest reads Go source.
func TestJuniperChassisTableInstancesHaveTheIndexArity(t *testing.T) {
	prefixes := []struct{ prefix, table string }{
		{jnxOperatingEntryPrefix, "jnxOperatingEntry"},
		{jnxFruEntryPrefix, "jnxFruEntry"},
	}

	// A positive control first: the arity function must REPORT a wrong arity,
	// or a test that asserts every OID is fine is satisfied by one that classes
	// nothing. Both a short name and a bare column are exercised, because they
	// are different faults that happen to fail the same comparison.
	t.Run("positive control", func(t *testing.T) {
		for _, tc := range []struct {
			oid  string
			want int
		}{
			{jnxOperatingEntryPrefix + ".5.5.0.0", 3},   // the shipped defect
			{jnxOperatingEntryPrefix + ".5", 0},         // a bare column
			{jnxOperatingEntryPrefix + ".5.9.1.0.0", 4}, // the corrected form
			{jnxFruEntryPrefix + ".5.7.1.1.0", 4},       // a shipped trap varbind
		} {
			got, ok := jnxInstanceArity(tc.oid, jnxOperatingEntryPrefix)
			if !ok {
				got, ok = jnxInstanceArity(tc.oid, jnxFruEntryPrefix)
			}
			if !ok || got != tc.want {
				t.Fatalf("jnxInstanceArity(%s) = (%d, %v), want %d; the scan below cannot "+
					"classify anything", tc.oid, got, ok, tc.want)
			}
		}
		if _, ok := jnxInstanceArity("1.3.6.1.2.1.1.1.0", jnxOperatingEntryPrefix); ok {
			t.Fatal("jnxInstanceArity claims sysDescr.0 is under jnxOperatingEntry, so the scan " +
				"below would classify unrelated OIDs")
		}
	})

	checked := 0
	check := func(surface, where, oid string) {
		for _, p := range prefixes {
			arity, under := jnxInstanceArity(oid, p.prefix)
			if !under {
				continue
			}
			checked++
			if arity != jnxChassisTableIndexArity {
				t.Errorf("%s: %s carries %d instance sub-identifier(s) under %s, want %d. "+
					"JUNIPER-MIB 201010220000Z gives that entry a four-column INDEX clause, so a "+
					"name with any other count is not a legal varbind name (nl6#571's class). "+
					"Source: %s", surface, oid, arity, p.table, jnxChassisTableIndexArity, where)
			}
		}
	}

	for _, e := range shippedSNMPEntries(t) {
		check("resource files", e.Part, normaliseLedgerOID(e.OID))
	}
	for profile, oids := range vendorOIDs {
		for oid := range oids {
			check("metrics_oids.go vendorOIDs", profile, normaliseLedgerOID(oid))
		}
	}
	for _, path := range []string{
		"resources/_common/traps.json",
		"resources/juniper_mx240/traps.json",
	} {
		cat, err := LoadCatalogFromFile(path)
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		for _, entry := range cat.Entries {
			for _, vb := range entry.Varbinds {
				if strings.Contains(vb.rawOID, "{{") {
					continue
				}
				check("trap catalog", path+" "+entry.Name, normaliseLedgerOID(vb.rawOID))
			}
		}
	}

	if checked == 0 {
		t.Fatal("no OID under jnxOperatingEntry or jnxFruEntry was seen at all, so this guard " +
			"asserts nothing; the three surfaces it walks have moved")
	}
	t.Logf("%d OIDs under jnxOperatingEntry / jnxFruEntry across three surfaces, all with %d "+
		"instance sub-identifiers", checked, jnxChassisTableIndexArity)
}

// TestJuniperArcIsMeasuredInBothPositions is what makes "13 of 15" and
// "19 of 22" MEASUREMENTS rather than claims about whichever OIDs happened to be
// looked at.
//
// BOTH POSITIONS, because reading names only is the blind spot that hid the AWS
// defect in nl6#588 and the first cut of nl6#587's guard: an enterprise OID can
// be a varbind NAME or an OID-typed VALUE, and sysObjectID, the single most
// consequential one, is always a value. Here the value position is where the
// worst defect of the whole arc lived.
//
// The denominators are the PARENT's counts, so they are computed by reversing
// the ledger rather than read off today's tree. Counting today's corpus would
// give the post-audit shape and quote a rate against the wrong denominator.
func TestJuniperArcIsMeasuredInBothPositions(t *testing.T) {
	nameEntries := map[string]int{}  // distinct OID -> entry count, name position
	valueEntries := map[string]int{} // distinct OID -> entry count, value position

	for _, e := range shippedSNMPEntries(t) {
		if e.Profile != juniperMX240Profile && e.Profile != juniperMX960Profile {
			continue
		}
		if strings.HasPrefix(normaliseLedgerOID(e.OID), juniperArcBare+".") {
			nameEntries[normaliseLedgerOID(e.OID)]++
		}
		// The VALUE position is gated by the PRODUCTION predicate, the same one
		// collectShippedOIDs uses: a value only reaches the wire as an OID if
		// snmpTypeTag says the leaf is one.
		if snmpTypeTag(e.OID) == ASN1_OBJECT_ID &&
			strings.HasPrefix(e.Value, juniperArcBare+".") {
			valueEntries[e.Value]++
		}
	}

	// Reverse the ledger's own edits to recover the parent's shape. Deletions
	// and renames only touch the name position; the one OID-typed correction
	// only touches the value position.
	for _, d := range nl6602juniperDeletedEntries {
		nameEntries[normaliseLedgerOID(d.oid)]++
	}
	for _, r := range nl6602juniperRenamedEntries {
		newName := normaliseLedgerOID(r.newOID)
		nameEntries[newName]--
		if nameEntries[newName] == 0 {
			delete(nameEntries, newName)
		}
		nameEntries[normaliseLedgerOID(r.oldOID)]++
	}
	for _, c := range nl6602juniperOIDTypedCorrections() {
		valueEntries[c.newValue]--
		if valueEntries[c.newValue] == 0 {
			delete(valueEntries, c.newValue)
		}
		valueEntries[c.oldValue]++
	}

	nameEntryCount, valueEntryCount := 0, 0
	for _, n := range nameEntries {
		nameEntryCount += n
	}
	for _, n := range valueEntries {
		valueEntryCount += n
	}

	for _, tc := range []struct {
		what string
		got  int
		want int
	}{
		{"distinct OID names under the arc at 3830d8f", len(nameEntries), 13},
		{"name-position entries at 3830d8f", nameEntryCount, 20},
		{"distinct OID-typed values into the arc at 3830d8f", len(valueEntries), 2},
		{"value-position entries at 3830d8f", valueEntryCount, 2},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %d, want %d. These are the DENOMINATORS this audit's miss rate is "+
				"quoted against in docs/reference/snmp.md and the ledger header: 13 of 15 "+
				"distinct facts, 19 of 22 entries", tc.what, tc.got, tc.want)
		}
	}

	// And the arithmetic the header quotes, spelled out so a reader can check it
	// against the two numbers above rather than trusting prose.
	distinctFacts := len(nameEntries) + len(valueEntries)
	entries := nameEntryCount + valueEntryCount
	if distinctFacts != 15 || entries != 22 {
		t.Errorf("the audit's denominators compute to %d distinct facts and %d entries, want 15 "+
			"and 22", distinctFacts, entries)
	}

	t.Logf("at %s: %d distinct OID names (%d entries) and %d distinct OID-typed values "+
		"(%d entries) under %s", juniperArcParentRevision, len(nameEntries), nameEntryCount,
		len(valueEntries), valueEntryCount, juniperArcBare)
}

// TestJuniperTrapAndPolledDataAgreeOnEveryOID is nl6#593's class, checked
// explicitly here because nl6#602 asked for it: with 30 OID references under
// 2636 in the trap catalog against two profiles' polled data, this arc is where
// a trap declaring a type that disagrees with what a GET answers is most likely.
// cisco_ios demonstrably violated it, declaring ciscoEnvMonSupplyStatusDescr as
// octet-string in a trap while a GET answered INTEGER.
//
// THE RESULT IS TWO SHARED OIDs AND BOTH AGREE, and that is a MEASUREMENT rather
// than an assumption. nl6#601's Ciena version could only assert DISJOINTNESS,
// because that profile shared no OID at all; here there is something to compare,
// so the comparison is made.
func TestJuniperTrapAndPolledDataAgreeOnEveryOID(t *testing.T) {
	polled := map[string]string{} // OID -> value, over both Juniper profiles
	for _, e := range shippedSNMPEntries(t) {
		if e.Profile != juniperMX240Profile && e.Profile != juniperMX960Profile {
			continue
		}
		polled[normaliseLedgerOID(e.OID)] = e.Value
	}
	if len(polled) == 0 {
		t.Fatal("no polled entries for the two Juniper profiles")
	}

	cat, err := LoadCatalogFromFile("resources/juniper_mx240/traps.json")
	if err != nil {
		t.Fatalf("load juniper trap catalog: %v", err)
	}
	trapTypes := map[string]TrapVarbindType{}
	for _, e := range cat.Entries {
		for _, vb := range e.Varbinds {
			// rawOID, not the compiled template: a templated OID has no fixed
			// spelling to compare against a polled one.
			if strings.Contains(vb.rawOID, "{{") {
				continue
			}
			trapTypes[normaliseLedgerOID(vb.rawOID)] = vb.Type
		}
	}
	if len(trapTypes) == 0 {
		t.Fatal("no literal trap varbind OIDs collected; the comparison below would be vacuous")
	}

	// The declared trap type and the tag a GET actually emits have to be the
	// same object's type. The map is deliberately partial: only the types that
	// appear on shared OIDs need an entry, and an unmapped one is a failure
	// rather than a skip.
	wireTagFor := map[TrapVarbindType]byte{
		TrapVTInteger:     ASN1_INTEGER,
		TrapVTOctetString: ASN1_OCTET_STRING,
		TrapVTOID:         ASN1_OBJECT_ID,
	}

	var shared []string
	for oid := range trapTypes {
		if _, ok := polled[oid]; ok {
			shared = append(shared, oid)
		}
	}
	sort.Strings(shared)

	if len(shared) != 2 {
		t.Errorf("the Juniper trap catalog and polled data share %d OID(s), want 2 (jnxBoxDescr "+
			"and jnxBoxSerialNo): %v. That count is what this test's comparison covers, so a new "+
			"shared OID has to be looked at rather than absorbed", len(shared), shared)
	}
	for _, oid := range shared {
		declared := trapTypes[oid]
		wantTag, known := wireTagFor[declared]
		if !known {
			t.Errorf("%s is shared, and the trap declares it %q, which this test has no wire tag "+
				"for. Add it rather than skipping: an unmapped type makes the comparison silently "+
				"cover less than it claims", oid, declared)
			continue
		}
		enc := encodeTypedValue("."+oid, polled[oid])
		if len(enc) == 0 || enc[0] != wantTag {
			t.Errorf("%s: the trap declares %q (tag 0x%02X) but a GET of the same OID answers %q, "+
				"which encodes as % x. That is nl6#593's defect: two surfaces of one simulator "+
				"telling a collector two different types for one object",
				oid, declared, wantTag, polled[oid], enc)
		}
	}

	t.Logf("%d polled OIDs on the two Juniper profiles and %d literal trap varbind OIDs, "+
		"sharing %d: %v", len(polled), len(trapTypes), len(shared), shared)
}

// jnxChassisTrapNotifications is the reading of jnxChassisTraps in JUNIPER-MIB
// 201010220000Z: every notification the shipped catalog uses, with the number of
// objects its OBJECTS clause names.
//
// It is TRANSCRIBED, so it is a record of a reading and not a verification. What
// makes a mutation of a row fail rather than pass quietly is the arithmetic over
// it in TestJuniperTrapCatalogVarbindsAgainstTheMIB.
var jnxChassisTrapNotifications = map[int]struct {
	name        string
	objectCount int
}{
	1: {"jnxPowerSupplyFailure", 5},
	2: {"jnxFanFailure", 5},
	3: {"jnxOverTemperature", 6},
	5: {"jnxFruRemoval", 7},
	6: {"jnxFruInsertion", 7},
	7: {"jnxFruPowerOff", 10},
	9: {"jnxFruFailed", 7},
}

// TestJuniperTrapCatalogVarbindsAgainstTheMIB records the reading of the shipped
// catalog, separately from the polled data, because a claim about the MIB and a
// claim about the JSON must not be conflated.
//
// TWO FINDINGS ARE RECORDED HERE AND NEITHER IS FIXED, which is a decision and
// not an omission:
//
//  1. All seven snmpTrapOIDs resolve to real NOTIFICATION-TYPEs under
//     jnxChassisTraps, and every varbind uses a legal four-sub-identifier
//     instance (pinned by TestJuniperChassisTableInstancesHaveTheIndexArity).
//     But NOT ONE of the seven emits the varbind list its own OBJECTS clause
//     names: the clauses run 5 to 10 objects each and the catalog emits 2 or 3,
//     none of them an index column. The catalog says in its own comment that it
//     is Class-1-vocabulary only, so making it follow the clauses is a rewrite
//     of all seven entries and a Class 2 template epic, not an arc audit.
//  2. ONE VARBIND DECLARES A TYPE THE MIB CONTRADICTS. jnxFruFailed carries
//     2636.3.1.15.1.9.4.1.1.0 as "timeticks" with {{.Uptime}}. { jnxFruEntry 9 }
//     is jnxFruTemp, SYNTAX Gauge32. The author wanted jnxFruLastPowerOff
//     ({ jnxFruEntry 11 }, TimeStamp) or jnxFruLastPowerOn (12), neither of which
//     is in jnxFruFailed's OBJECTS clause either. Retyping it would leave it
//     wrong and deleting it opens finding 1 for all seven entries, so it is
//     recorded as a PRESENCE: a later change that fixes it has to edit this
//     assertion deliberately rather than watch a test go quietly green. This is
//     the same disposition nl6#599 gave arista_7280r3's entPhysicalVendorType.1.
func TestJuniperTrapCatalogVarbindsAgainstTheMIB(t *testing.T) {
	const catalogPath = "resources/juniper_mx240/traps.json"
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
	if len(doc.Traps) != len(jnxChassisTrapNotifications) {
		t.Fatalf("%s has %d entries, and the reading records %d notifications; every assertion "+
			"below pairs them", catalogPath, len(doc.Traps), len(jnxChassisTrapNotifications))
	}

	// THE COMMENT IS PART OF THE DATA, and here it is part of the FINDING. It
	// cites "oidref.com and Observium", which are aggregators rather than the
	// module, where nl6#601's Ciena catalog cited the module and its
	// LAST-UPDATED. That difference is the one this audit asked readers to note,
	// so it is pinned rather than left to be tidied away.
	if !strings.Contains(doc.Comment, "oidref.com and Observium") {
		t.Errorf("%s's comment no longer records that its OIDs were verified against oidref.com "+
			"and Observium. That provenance claim is the finding: an aggregator is not the "+
			"module, and nl6#602 predicted the polled data's miss rate from exactly this "+
			"difference. If the catalog is re-verified against JUNIPER-MIB itself, say so and "+
			"cite the revision, the way resources/ciena_waveserver5/traps.json does", catalogPath)
	}

	varbindsEmitted := 0
	for _, e := range doc.Traps {
		sub, ok := strings.CutPrefix(e.SnmpTrapOID, jnxChassisTrapsRoot+".")
		if !ok {
			t.Errorf("%s: snmpTrapOID %q is not under jnxChassisTraps (%s), which JUNIPER-SMI "+
				"200910290000Z assigns as { jnxTraps 1 }", e.Name, e.SnmpTrapOID,
				jnxChassisTrapsRoot)
			continue
		}
		n, err := strconv.Atoi(sub)
		if err != nil {
			t.Errorf("%s: snmpTrapOID %q has a non-numeric sub-identifier %q",
				e.Name, e.SnmpTrapOID, sub)
			continue
		}
		notif, defined := jnxChassisTrapNotifications[n]
		if !defined {
			t.Errorf("%s: { jnxChassisTraps %d } is not one of the notifications this reading "+
				"records. JUNIPER-MIB 201010220000Z defines .4 jnxRedundancySwitchover, .8 "+
				"jnxFruPowerOn and .10 jnxFruOffline too, but the shipped catalog uses none of "+
				"them, so adding one needs a reading rather than a plausible number", e.Name, n)
			continue
		}
		if !strings.EqualFold(e.Name, notif.name) {
			t.Errorf("%s is registered at { jnxChassisTraps %d }, which JUNIPER-MIB "+
				"201010220000Z defines as %s", e.Name, n, notif.name)
		}
		if e.SnmpTrapEnterprise != juniperArcBare {
			t.Errorf("%s: snmpTrapEnterprise %q, want Juniper's PEN %s",
				e.Name, e.SnmpTrapEnterprise, juniperArcBare)
		}

		// FINDING 1, as an inequality rather than a pass. Every entry emits
		// FEWER varbinds than its OBJECTS clause names, and asserting the
		// shortfall is what keeps it a known gap instead of an unnoticed one.
		if len(e.Varbinds) >= notif.objectCount {
			t.Errorf("%s emits %d varbinds and %s's OBJECTS clause names %d. This audit recorded "+
				"the catalog as emitting FEWER than the clause on every entry; if that is no "+
				"longer true, the finding in this test's doc comment is stale",
				e.Name, len(e.Varbinds), notif.name, notif.objectCount)
		}
		varbindsEmitted += len(e.Varbinds)

		for _, vb := range e.Varbinds {
			if !strings.HasPrefix(vb.OID, juniperArcBare+".") {
				t.Errorf("%s: varbind %s is not under Juniper's PEN", e.Name, vb.OID)
			}
		}
	}

	// FINDING 2, asserted as a PRESENCE.
	const jnxFruTempMisdeclared = "1.3.6.1.4.1.2636.3.1.15.1.9.4.1.1.0"
	found := false
	for _, e := range doc.Traps {
		for _, vb := range e.Varbinds {
			if vb.OID == jnxFruTempMisdeclared && vb.Type == "timeticks" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("%s no longer declares %s as timeticks. That varbind names { jnxFruEntry 9 }, "+
			"jnxFruTemp, SYNTAX Gauge32 in JUNIPER-MIB 201010220000Z, and this audit deliberately "+
			"left it alone: it is not in jnxFruFailed's OBJECTS clause either, so retyping it "+
			"leaves it wrong and deleting it opens the OBJECTS-clause question for all seven "+
			"entries. If a later change fixes it, delete this assertion and say so in "+
			"docs/reference/snmp.md rather than letting the record go quiet", catalogPath,
			jnxFruTempMisdeclared)
	}

	// And it must load through the production loader.
	if _, err := LoadCatalogFromFile(catalogPath); err != nil {
		t.Fatalf("%s does not load: %v", catalogPath, err)
	}
	t.Logf("%d entries, %d varbinds; every snmpTrapOID resolves under jnxChassisTraps and every "+
		"entry emits fewer varbinds than its OBJECTS clause names", len(doc.Traps), varbindsEmitted)
}
