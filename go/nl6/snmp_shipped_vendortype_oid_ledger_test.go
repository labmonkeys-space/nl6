/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
)

// entPhysicalVendorType is an OBJECT IDENTIFIER (nl6#821). The shipped corpus
// served the bare string "1" for most chassis rows. This change gives two
// profiles real chassis identities and removes a stub row. Typing the column
// is a separate change.
//
// Decisions. The issue is decomposed: line cards keep their synthetic
// vendor type and are deferred to nl6#823. Only the chassis identity and the
// stub are fixed here.
//
// Rows changed, old value to new value:
//
//	juniper_mx960   entPhysicalDescr.1       "Main Chassis" to "Juniper MX960 Chassis"
//	juniper_mx960   entPhysicalModelName.1   "MODEL123" to "MX960"
//	juniper_mx960   entPhysicalVendorType.1  "1" to jnxChassisMX960 1.3.6.1.4.1.2636.1.1.2.1.21
//	palo_alto_pa3220 sysObjectID.0           panPanorama 1.3.6.1.4.1.25461.2.3.7 to panPA-3220 1.3.6.1.4.1.25461.2.3.43
//	palo_alto_pa3220 entPhysicalDescr.1      "Main Chassis" to "PA-3220 Next-Generation Firewall"
//	palo_alto_pa3220 entPhysicalModelName.1  "MODEL123" to "PA-3220"
//	palo_alto_pa3220 entPhysicalVendorType.1 "1" to panPA-3220 1.3.6.1.4.1.25461.2.3.43
//
// Palo Alto defines no chassis vendor type, so panPA-3220 is the only
// PAN-assigned identity for the device and the vendor type uses it. The old
// PA sysObjectID named Panorama, the management appliance, which is a
// different product.
//
// The "Line Card 1" stub was a half-row at index 2 on four profiles
// (cisco_nexus_9500, cisco_catalyst_9500, juniper_mx960, palo_alto_pa3220):
// only entPhysicalDescr.2 and entPhysicalVendorType.2 ("1"), contained in
// nothing. All eight rows are deleted.
//
// MIB citation. LibreNMS librenms/librenms at
// cdc6df4920a660df096806465168171c123fc29a, cited by LAST-UPDATED and by the
// SHA-256 of the file read (the nl6#599 provenance convention). No MIB is
// checked in.
//
//	JUNIPER-CHASSIS-DEFINES-MIB  202306140000Z  5b74009be06cfda45a646487214663c354076047f706cfc78c0b36cdc9cfeea9
//	JUNIPER-SMI                  (jnxProducts)  be8d2a7ff1a022c40de146f0659fa689b17600f5bb16377387bf21a755e7a14e
//	PAN-PRODUCTS-MIB             201304151650Z  04a38ddbf03ea370020ebf681b83c95930e7af3e43083d82bb980be235895d9f
//	PAN-GLOBAL-REG               201106271040Z  524f7088cb3546ba51678dfe75d948e0a0a931cdba3944e71991e3ab607a7517
//
// Reproduce with:
//
//	curl -sS https://raw.githubusercontent.com/librenms/librenms/cdc6df4920a660df096806465168171c123fc29a/mibs/juniper/junos/JUNIPER-CHASSIS-DEFINES-MIB | shasum -a 256
//	curl -sS https://raw.githubusercontent.com/librenms/librenms/cdc6df4920a660df096806465168171c123fc29a/mibs/juniper/JUNIPER-SMI | shasum -a 256
//	curl -sS https://raw.githubusercontent.com/librenms/librenms/cdc6df4920a660df096806465168171c123fc29a/mibs/paloaltonetworks/PAN-PRODUCTS-MIB | shasum -a 256
//	curl -sS https://raw.githubusercontent.com/librenms/librenms/cdc6df4920a660df096806465168171c123fc29a/mibs/paloaltonetworks/PAN-GLOBAL-REG | shasum -a 256

const (
	vendorTypeOIDSysObjectIDOID = ".1.3.6.1.2.1.1.2.0"
	vendorTypeOIDDescr1OID      = ".1.3.6.1.2.1.47.1.1.1.1.2.1"
	vendorTypeOIDDescr2OID      = ".1.3.6.1.2.1.47.1.1.1.1.2.2"
	vendorTypeOIDVendor1OID     = ".1.3.6.1.2.1.47.1.1.1.1.3.1"
	vendorTypeOIDVendor2OID     = ".1.3.6.1.2.1.47.1.1.1.1.3.2"
	vendorTypeOIDModel1OID      = ".1.3.6.1.2.1.47.1.1.1.1.13.1"

	jnxChassisMX960 = "1.3.6.1.4.1.2636.1.1.2.1.21"
	panPA3220       = "1.3.6.1.4.1.25461.2.3.43"
	panPanorama     = "1.3.6.1.4.1.25461.2.3.7"
)

// vendorTypeOIDIdentities are the rows each profile now serves.
var vendorTypeOIDIdentities = []struct {
	profile string
	want    map[string]string // OID -> value
}{
	{"juniper_mx960.json", map[string]string{
		vendorTypeOIDDescr1OID:  "Juniper MX960 Chassis",
		vendorTypeOIDModel1OID:  "MX960",
		vendorTypeOIDVendor1OID: jnxChassisMX960,
	}},
	{"palo_alto_pa3220.json", map[string]string{
		vendorTypeOIDSysObjectIDOID: panPA3220,
		vendorTypeOIDDescr1OID:      "PA-3220 Next-Generation Firewall",
		vendorTypeOIDModel1OID:      "PA-3220",
		vendorTypeOIDVendor1OID:     panPA3220,
	}},
}

func TestVendorTypeOIDIdentitiesMatchTheMIB(t *testing.T) {
	for _, p := range vendorTypeOIDIdentities {
		t.Run(strings.TrimSuffix(p.profile, ".json"), func(t *testing.T) {
			srv := deviceForProfileWithMetrics(t, p.profile)
			for oid, want := range p.want {
				if got := srv.findResponse(oid); got != want {
					t.Errorf("%s = %q, want %q", oid, got, want)
				}
			}
		})
	}
}

// vendorTypeOIDStubProfiles served a half-row "Line Card 1" at index 2: only
// entPhysicalDescr.2 and entPhysicalVendorType.2 ("1"), contained in nothing.
var vendorTypeOIDStubProfiles = []string{
	"cisco_nexus_9500.json", "cisco_catalyst_9500.json", "juniper_mx960.json", "palo_alto_pa3220.json",
}

// No shipped profile serves the stub, and every row of the column is a value
// the OID encoder can represent, decided by encodableAsOID.
func TestNoShippedVendorTypeStubOrNonOID(t *testing.T) {
	for _, e := range shippedSNMPEntries(t) {
		if typeTagIn([]oidTypeEntry{{".1.3.6.1.2.1.47.1.1.1.1.3", ASN1_OBJECT_ID}}, e.OID) == 0 {
			continue
		}
		if !encodableAsOID(e.Value) {
			t.Errorf("%s %s = %q is not an OID", e.Profile, e.OID, e.Value)
		}
	}
	for _, p := range vendorTypeOIDStubProfiles {
		srv := deviceForProfileWithMetrics(t, p)
		for _, oid := range []string{vendorTypeOIDDescr2OID, vendorTypeOIDVendor2OID} {
			if got := srv.findResponse(oid); got != valueNoSuchObject {
				t.Errorf("%s still serves %s = %q", p, oid, got)
			}
		}
	}
}

// vendorTypeOIDParentRevision is main at branch time; the digests below were
// taken there and are NOT re-derived from the new tree.
const vendorTypeOIDParentRevision = "c308f395"

const (
	shippedTagDigestBeforeVendorTypeOID         = "03c3beee1f1b37f43a374de662e6bdbbc7cccf595402c8ce1ffc5bd28bd2de39"
	shippedOIDEncodingDigestBeforeVendorTypeOID = "7852de8aa4ffe09fe6b38766096b68a8b895bbe00d6c4a9936d67f234ab2d222"
)

func vendorTypeOIDEdits() map[string][]profileRowEdit {
	stub := []profileRowEdit{
		{op: editDel, oid: vendorTypeOIDDescr2OID, before: "Line Card 1"},
		{op: editDel, oid: vendorTypeOIDVendor2OID, before: "1"},
	}
	return map[string][]profileRowEdit{
		"cisco_nexus_9500.json":    stub,
		"cisco_catalyst_9500.json": stub,
		"juniper_mx960.json": append([]profileRowEdit{
			{op: editChg, oid: vendorTypeOIDDescr1OID, before: "Main Chassis", after: "Juniper MX960 Chassis"},
			{op: editChg, oid: vendorTypeOIDModel1OID, before: "MODEL123", after: "MX960"},
			{op: editChg, oid: vendorTypeOIDVendor1OID, before: "1", after: jnxChassisMX960},
		}, stub...),
		"palo_alto_pa3220.json": append([]profileRowEdit{
			{op: editChg, oid: vendorTypeOIDSysObjectIDOID, before: panPanorama, after: panPA3220},
			{op: editChg, oid: vendorTypeOIDDescr1OID, before: "Main Chassis", after: "PA-3220 Next-Generation Firewall"},
			{op: editChg, oid: vendorTypeOIDModel1OID, before: "MODEL123", after: "PA-3220"},
			{op: editChg, oid: vendorTypeOIDVendor1OID, before: "1", after: panPA3220},
		}, stub...),
	}
}

func restoreVendorTypeOID(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	for profile, edits := range vendorTypeOIDEdits() {
		reverseProfileEdits(t, cur, profile, profile+" nl6#821", edits)
	}
}

// vendorTypeOIDNamesBefore reverses the OID-name view. panPA-3220 joined the
// names as the new PA-3220 sysObjectID and panPanorama left. The stub removal
// took entPhysicalVendorType.2 out of the whole corpus, so that key left too.
func vendorTypeOIDNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return reverseOIDNameEdits(t, names, "nl6#821", []string{panPA3220}, []string{panPanorama, "1.3.6.1.2.1.47.1.1.1.1.3.2"})
}

func TestVendorTypeOIDFixReproducesTheParentCorpus(t *testing.T) {
	got := corpusTagDigestAt(t, corpusValuesAt(t, vendorTypeOIDParentRevision), vendorTypeOIDParentRevision)
	if got != shippedTagDigestBeforeVendorTypeOID {
		t.Errorf("reversing nl6#821 gives tag digest %s, want %s", got, shippedTagDigestBeforeVendorTypeOID)
	}
}

func TestVendorTypeOIDRePinIsOnlyTheFix(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), vendorTypeOIDParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeVendorTypeOID {
		t.Errorf("reversing nl6#821 gives OID-name digest %s, want %s", got, shippedOIDEncodingDigestBeforeVendorTypeOID)
	}
}
