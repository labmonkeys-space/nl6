/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Four Cisco profiles identified as a product other than the one they model,
// or as nothing, on sysObjectID.0 and entPhysicalVendorType.1 (nl6#805). This
// is the defect nl6#801 fixed for asr9k. The chassis each profile models was
// decided on the issue:
//
//	cisco_ios            Catalyst 2960-X, WS-C2960X-24TS-L
//	cisco_crs_x          16-slot CRS-X
//	cisco_nexus_9500     Nexus 9508
//	cisco_catalyst_9500  Catalyst 9500-48Y4C
//
// The old values:
//
//	cisco_ios            sysObjectID.0  9.1.1                ciscoGatewayServer
//	                     vendorType.1   cevChassis 100       cevChassisMC3810
//	cisco_crs_x          sysObjectID.0  9.1.1404             cat3750x24s
//	                     vendorType.1   cevChassis 914       cevChassisN2kC2248TP1GE
//	cisco_nexus_9500     sysObjectID.0  9.12.3.1.3.1437      a cevChassis arc, undefined
//	                     vendorType.1   "1"                  not an OID
//	cisco_catalyst_9500  sysObjectID.0  9.1.1208             cat29xxStack
//	                     vendorType.1   "1"                  not an OID
//
// Other rows of the same identity were fixed with them:
//
//   - cisco_nexus_9500 and cisco_catalyst_9500 had placeholder chassis rows,
//     "Main Chassis" / MODEL123. Their entPhysicalDescr.1 and
//     entPhysicalModelName.1 now name the product, in the words the profile's
//     own CLI output uses.
//   - cisco_crs_x's chassis row read "Cisco CRS-X Carrier Routing System" /
//     CRS-X. It now names the chassis cevChassisCrs16SB describes:
//     "Enhanced CRS 16 slots Line Card Chassis" / CRS-16-LCC-B. The CLI names
//     no chassis PID, so it is unchanged.
//   - cisco_ios answered sysDescr.0 "Cisco IOS Software, Router Version 15.1"
//     and `show version` "Cisco IOS Software, C2900 Software", a 2900 router.
//     Both now read "Cisco IOS Software, C2960X Software
//     (C2960X-UNIVERSALK9-M), Version 15.2(7)E", the 2960-X software line the
//     profile's CDP output already carries. entPhysicalModelName.1 gains the
//     WS- prefix of the real PID.
//
// ## What was read
//
// cisco/cisco-mibs at commit c9ab98c0, read on 2026-10-13, cited by
// LAST-UPDATED and by the SHA-256 of the file read. c9ab98c0 was the head of
// main on that day, so no newer revision exists to pin:
//
//	CISCO-PRODUCTS-MIB               201604290000Z  56b392946c0bae5a192c239656d043e6ead90e1e9d4632dab0541abb559c5255
//	CISCO-ENTITY-VENDORTYPE-OID-MIB  201806050000Z  9bd040a5c660a9043f6560a535d966b057955c9d643c921bf74eafbb00610cec
//
// LAST-UPDATED lags the content: CISCO-PRODUCTS-MIB defines products far newer
// than 2016, the Catalyst 9500 among them.
//
//	catWsC2960x24tsL         ::= { ciscoProducts 1699 }   1.3.6.1.4.1.9.1.1699
//	cevChassisWsC2960x24tsL  ::= { cevChassis 1268 }      1.3.6.1.4.1.9.12.3.1.3.1268
//	ciscoCrs16SB             ::= { ciscoProducts 1331 }   1.3.6.1.4.1.9.1.1331
//	cevChassisCrs16SB        ::= { cevChassis 1012 }      1.3.6.1.4.1.9.12.3.1.3.1012
//	ciscoN9Kc9508            ::= { ciscoProducts 1915 }   1.3.6.1.4.1.9.1.1915
//	cevChassisN9Kc9508       ::= { cevChassis 1467 }      1.3.6.1.4.1.9.12.3.1.3.1467
//	ciscoCat950048Y4C        ::= { ciscoProducts 2568 }   1.3.6.1.4.1.9.1.2568
//	cevChassisC950048Y4C     ::= { cevChassis 1968 }      1.3.6.1.4.1.9.12.3.1.3.1968
//	cevChassis               ::= { cevMIBObjects 3 }
//	cevMIBObjects            ::= { ciscoEntityVendortypeOIDMIB 1 }
//
// Two choices the MIBs leave open:
//
//   - WS-C2960X-24TS-L has two product rows, cat2960xs24tsL (1190) and
//     catWsC2960x24tsL (1699), with the same description. The vendor-type MIB
//     has one chassis row, cevChassisWsC2960x24tsL. 1699 is the product row
//     that pairs with it by name.
//   - No row names CRS-X. A 16-slot CRS-X is the enhanced line card chassis
//     CRS-16-LCC-B with the 400G fabric, which both MIBs call "Enhanced CRS 16
//     slots Line Card Chassis". The 8-slot pair ciscoCRS8SB / cevChassisCrs8SB
//     uses the same SB naming.
//
// Reproduce with:
//
//	curl -sS https://raw.githubusercontent.com/cisco/cisco-mibs/c9ab98c0/v2/CISCO-PRODUCTS-MIB.my | shasum -a 256
//	curl -sS https://raw.githubusercontent.com/cisco/cisco-mibs/c9ab98c0/v2/CISCO-ENTITY-VENDORTYPE-OID-MIB.my | shasum -a 256
//
// No MIB is checked in: Cisco's header grants no redistribution, so this is a
// pinned reading, not a live check.
//
// entPhysicalVendorType.1 goes out as an OCTET STRING, because oidTypeTable
// types only sysObjectID as OBJECT IDENTIFIER. On nexus_9500 and catalyst_9500
// the old "1" went out as an INTEGER, so those two rows changed tag.

const (
	ciscoIdentitySysDescrOID    = ".1.3.6.1.2.1.1.1.0"
	ciscoIdentitySysObjectIDOID = ".1.3.6.1.2.1.1.2.0"
	ciscoIdentityVendorTypeOID  = ".1.3.6.1.2.1.47.1.1.1.1.3.1"
	ciscoIdentityDescrOID       = ".1.3.6.1.2.1.47.1.1.1.1.2.1"
	ciscoIdentityModelNameOID   = ".1.3.6.1.2.1.47.1.1.1.1.13.1"
)

// ciscoIdentityRow is one further OCTET STRING row the fix rewrote.
type ciscoIdentityRow struct {
	name, oid, before, after string
}

// ciscoIdentityFix is one profile's corrected identity.
type ciscoIdentityFix struct {
	profile                    string
	sysObjectID, sysObjectName string
	vendorType, vendorTypeName string
	oldSysObjectID             string
	oldVendorType              string
	rows                       []ciscoIdentityRow
}

func ciscoChassisRows(oldDescr, descr, oldModel, model string) []ciscoIdentityRow {
	return []ciscoIdentityRow{
		{"entPhysicalDescr.1", ciscoIdentityDescrOID, oldDescr, descr},
		{"entPhysicalModelName.1", ciscoIdentityModelNameOID, oldModel, model},
	}
}

var ciscoIdentityFixes = []ciscoIdentityFix{
	{
		profile:     "cisco_ios.json",
		sysObjectID: "1.3.6.1.4.1.9.1.1699", sysObjectName: "catWsC2960x24tsL",
		vendorType: "1.3.6.1.4.1.9.12.3.1.3.1268", vendorTypeName: "cevChassisWsC2960x24tsL",
		oldSysObjectID: "1.3.6.1.4.1.9.1.1",
		oldVendorType:  "1.3.6.1.4.1.9.12.3.1.3.100",
		rows: []ciscoIdentityRow{
			{"sysDescr.0", ciscoIdentitySysDescrOID, "Cisco IOS Software, Router Version 15.1",
				"Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E"},
			{"entPhysicalModelName.1", ciscoIdentityModelNameOID, "C2960X-24TS-L", "WS-C2960X-24TS-L"},
		},
	},
	{
		profile:     "cisco_crs_x.json",
		sysObjectID: "1.3.6.1.4.1.9.1.1331", sysObjectName: "ciscoCrs16SB",
		vendorType: "1.3.6.1.4.1.9.12.3.1.3.1012", vendorTypeName: "cevChassisCrs16SB",
		oldSysObjectID: "1.3.6.1.4.1.9.1.1404",
		oldVendorType:  "1.3.6.1.4.1.9.12.3.1.3.914",
		rows: ciscoChassisRows("Cisco CRS-X Carrier Routing System", "Enhanced CRS 16 slots Line Card Chassis",
			"CRS-X", "CRS-16-LCC-B"),
	},
	{
		profile:     "cisco_nexus_9500.json",
		sysObjectID: "1.3.6.1.4.1.9.1.1915", sysObjectName: "ciscoN9Kc9508",
		vendorType: "1.3.6.1.4.1.9.12.3.1.3.1467", vendorTypeName: "cevChassisN9Kc9508",
		oldSysObjectID: "1.3.6.1.4.1.9.12.3.1.3.1437",
		oldVendorType:  "1",
		rows:           ciscoChassisRows("Main Chassis", "Nexus9000 C9508 (8 Slot) Chassis", "MODEL123", "N9K-C9508"),
	},
	{
		profile:     "cisco_catalyst_9500.json",
		sysObjectID: "1.3.6.1.4.1.9.1.2568", sysObjectName: "ciscoCat950048Y4C",
		vendorType: "1.3.6.1.4.1.9.12.3.1.3.1968", vendorTypeName: "cevChassisC950048Y4C",
		oldSysObjectID: "1.3.6.1.4.1.9.1.1208",
		oldVendorType:  "1",
		rows:           ciscoChassisRows("Main Chassis", "Cisco Catalyst 9500-48Y4C Chassis", "MODEL123", "C9500-48Y4C"),
	},
}

func TestCiscoIdentitiesMatchTheMIB(t *testing.T) {
	for _, f := range ciscoIdentityFixes {
		t.Run(strings.TrimSuffix(f.profile, ".json"), func(t *testing.T) {
			srv := deviceForProfileWithMetrics(t, f.profile)
			type row struct {
				name, oid, want string
				tag             byte
			}
			rows := []row{
				{"sysObjectID.0 (" + f.sysObjectName + ")", ciscoIdentitySysObjectIDOID, f.sysObjectID, ASN1_OBJECT_ID},
				{"entPhysicalVendorType.1 (" + f.vendorTypeName + ")", ciscoIdentityVendorTypeOID, f.vendorType, ASN1_OCTET_STRING},
			}
			for _, r := range f.rows {
				rows = append(rows, row{r.name, r.oid, r.after, ASN1_OCTET_STRING})
			}
			for _, c := range rows {
				got := srv.findResponse(c.oid)
				if got != c.want {
					t.Errorf("%s = %q, want %s", c.name, got, c.want)
				}
				enc := encodeTypedValue(c.oid, got)
				if len(enc) == 0 {
					t.Errorf("%s encodes to nothing, want tag %#02x", c.name, c.tag)
				} else if enc[0] != c.tag {
					t.Errorf("%s encodes with tag %#02x, want %#02x", c.name, enc[0], c.tag)
				}
			}
		})
	}
}

// No old identity value and no placeholder chassis string may come back in any
// part of the four profiles. Values are compared with any leading dot trimmed,
// so ".1.3.6..." cannot slip past as a second spelling of an old OID.
func TestCiscoIdentityProfilesServeNoForeignChassis(t *testing.T) {
	for _, f := range ciscoIdentityFixes {
		dir := strings.TrimSuffix(f.profile, ".json")
		files, err := filepath.Glob(filepath.Join("resources", dir, "*.json"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no %s parts: %v", dir, err)
		}
		bad := []string{f.oldSysObjectID, "Main Chassis", "MODEL123"}
		if f.oldVendorType != "1" { // "1" is a legitimate value of many columns
			bad = append(bad, f.oldVendorType)
		}
		for _, file := range files {
			raw, err := os.ReadFile(file) // #nosec G304 -- test-only, path from a glob
			if err != nil {
				t.Fatal(err)
			}
			var doc DeviceResources
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			for _, r := range doc.SNMP {
				v := strings.TrimPrefix(r.Response, ".")
				for _, s := range bad {
					if v == s {
						t.Errorf("%s still serves %q at %s", file, r.Response, r.OID)
					}
				}
			}
		}
	}
}

// ## The ledger
//
// Both golden digests moved. shippedTagDigest moved because entPhysicalVendorType.1
// of nexus_9500 and catalyst_9500 went from INTEGER 1 to an OCTET STRING.
// shippedOIDEncodingDigest moved because collectShippedOIDs reads sysObjectID
// values as OID names: four left the set and four joined it. No old or new
// value is shared with another profile, so each name enters or leaves the set
// with this change.

// ciscoIdentityParentRevision is the revision the digests below were taken at,
// the merge base of this change.
const ciscoIdentityParentRevision = "2a3f4d57"

// The values shippedTagDigest and shippedOIDEncodingDigest held at the parent,
// NOT re-derived from the new tree.
const (
	shippedTagDigestBeforeCiscoIdentity         = "a24ac010983a7358e3aba2e7e46f17446371ff266d4997f7793c9db31ab21321"
	shippedOIDEncodingDigestBeforeCiscoIdentity = "b573859f7da1f200461ed11ab439213cd43035e645038b981ba745dcd8547e51"
)

// ciscoIdentityEdits is one profile's rows as this change rewrote them.
func ciscoIdentityEdits(f ciscoIdentityFix) []profileRowEdit {
	edits := []profileRowEdit{
		{op: editChg, oid: ciscoIdentitySysObjectIDOID, before: f.oldSysObjectID, after: f.sysObjectID},
		{op: editChg, oid: ciscoIdentityVendorTypeOID, before: f.oldVendorType, after: f.vendorType},
	}
	for _, r := range f.rows {
		edits = append(edits, profileRowEdit{op: editChg, oid: r.oid, before: r.before, after: r.after})
	}
	return edits
}

func restoreCiscoIdentity(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	for _, f := range ciscoIdentityFixes {
		reverseProfileEdits(t, cur, f.profile, f.profile+" identity", ciscoIdentityEdits(f))
	}
}

func ciscoIdentityOIDNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	var added, removed []string
	for _, f := range ciscoIdentityFixes {
		added = append(added, f.sysObjectID)
		removed = append(removed, f.oldSysObjectID)
	}
	return reverseOIDNameEdits(t, names, "Cisco identity", added, removed)
}

func TestCiscoIdentityFixReproducesTheParentCorpus(t *testing.T) {
	if got := corpusTagDigestAt(t, corpusValuesAt(t, ciscoIdentityParentRevision), ciscoIdentityParentRevision); got != shippedTagDigestBeforeCiscoIdentity {
		t.Errorf("reversing the Cisco identity fix gives tag digest %s, want %s: another shipped row changed without being recorded",
			got, shippedTagDigestBeforeCiscoIdentity)
	}
}

func TestCiscoIdentityRePinIsOnlyTheFix(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), ciscoIdentityParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeCiscoIdentity {
		t.Errorf("reversing the Cisco identity fix gives OID-name digest %s, want the pre-change value %s; "+
			"the re-pin of shippedOIDEncodingDigest is not explained by this fix alone",
			got, shippedOIDEncodingDigestBeforeCiscoIdentity)
	}
}
