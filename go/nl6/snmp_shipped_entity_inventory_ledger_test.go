/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"testing"
)

// The ENTITY-MIB chassis rows of 21 profiles served three inventory columns one
// place to the right, and four generated profiles served invented inventory
// values on every port row. This link records the fix.
//
// Chassis rows. RFC 4133 defines entPhysicalMfgDate (.17) as an 8- or 11-octet
// DateAndTime and entPhysicalUris (.18) as space-separated URIs; RFC 6933 adds
// entPhysicalUUID (.19), 16 octets or zero-length. The rows served 14 ASCII hex
// characters at .17, the manufacturer name at .18 and a urn:clei: URI at .19.
// The resource format cannot spell a DateAndTime, whose year octet is above
// 0x7F, and the CLEI codes were invented or read UNASSIGNED, so all three are
// deleted and answer noSuchObject. The IOS-XR capture serves none of them.
// juniper_mx10004's rows come from the junos-chassis generator model.
//
// The four generated profiles served no entPhysicalMfgName.1, so the deleted
// .18.1 value moves there.
//
// Port rows. 208 port rows of the four generated profiles served "1.0" at the
// three revision columns, SN00<index>, "Simulation Vendor", 10GE-PORT or
// 1GE-PORT, and ASSET<index>. RFC 4133 prescribes a zero-length string for an
// unknown or unassigned value, and a port is not a field-replaceable part.
//
// The tag view moves where a deleted or emptied value encoded at a tag other
// than OCTET STRING. The OID-name view moves because no profile serves .17.1,
// .18.1 or .19.1 any more; .12.1 was already a name.

// entityInventoryParentRevision is main at branch time; the digests below were
// taken there and are NOT re-derived from the new tree.
const entityInventoryParentRevision = "e1f256a0"

const (
	shippedTagDigestBeforeEntityInventory         = "1e737c477e1843377b22eea42508d971eeaee390bf77bfbb3bf8add85aae1968"
	shippedOIDEncodingDigestBeforeEntityInventory = "2f958f6a614ae97157f16b8ce973b457bcc1f7a23701af8407032fe7511bede4"
)

const (
	entityInventoryMfgDate1 = "1.3.6.1.2.1.47.1.1.1.1.17.1"
	entityInventoryUris1    = "1.3.6.1.2.1.47.1.1.1.1.18.1"
	entityInventoryUUID1    = "1.3.6.1.2.1.47.1.1.1.1.19.1"
)

// entityInventoryChassis is every chassis row that served the shifted columns,
// with the values it served at .17.1, .18.1 and .19.1.
var entityInventoryChassis = []struct {
	profile             string
	mfgDate, uris, uuid string
}{
	{"arista_7280r3.json", "07E50701000000", "Arista Networks, Inc.", "urn:clei:ARISTAB1AA"},
	{"asr9k.json", "07E30315000000", "Cisco Systems, Inc.", "urn:clei:CNUCAC1BAA"},
	{"check_point_15600.json", "07E50301000000", "Check Point Software Technologies", "urn:clei:UNASSIGNED"},
	{"cisco_catalyst_9500.json", "07E5010F000000", "Cisco Systems, Inc.", "urn:clei:CMICAB4DAA"},
	{"cisco_crs_x.json", "07E20901000000", "Cisco Systems, Inc.", "urn:clei:CNUCAC2BAA"},
	{"cisco_ios.json", "07E40C01000000", "Cisco Systems, Inc.", "urn:clei:CNUCAC3BAA"},
	{"cisco_nexus_9500.json", "07E4060A000000", "Cisco Systems, Inc.", "urn:clei:CMICAB5DAA"},
	{"dell_poweredge_r750.json", "07E50901000000", "Dell Technologies", "urn:clei:UNASSIGNED"},
	{"dlink_dgs3630.json", "07E50101000000", "D-Link Corporation", "urn:clei:UNASSIGNED"},
	{"extreme_vsp4450.json", "07E40301000000", "Extreme Networks, Inc.", "urn:clei:UNASSIGNED"},
	{"fortinet_fortigate_600e.json", "07E40501000000", "Fortinet, Inc.", "urn:clei:FORTAB1DAA"},
	{"hpe_proliant_dl380.json", "07E40A01000000", "Hewlett Packard Enterprise", "urn:clei:UNASSIGNED"},
	{"huawei_ne8000.json", "07E30B01000000", "Huawei Technologies Co., Ltd.", "urn:clei:UNASSIGNED"},
	{"ibm_power_s922.json", "07E50501000000", "IBM Corporation", "urn:clei:UNASSIGNED"},
	{"juniper_mx10004.json", "07E50401000000", "Juniper Networks, Inc.", "urn:clei:JUNIAB1DAA"},
	{"juniper_mx240.json", "07E50401000000", "Juniper Networks, Inc.", "urn:clei:JUNIAB1DAA"},
	{"juniper_mx960.json", "07E40801000000", "Juniper Networks, Inc.", "urn:clei:JUNIAB2DAA"},
	{"nec_ix3315.json", "07E40701000000", "NEC Corporation", "urn:clei:UNASSIGNED"},
	{"nokia_7750_sr12.json", "07E40201000000", "Nokia Corporation", "urn:clei:UNASSIGNED"},
	{"palo_alto_pa3220.json", "07E50201000000", "Palo Alto Networks", "urn:clei:PALOAB1DAA"},
	{"sonicwall_nsa6700.json", "07E50601000000", "SonicWall, Inc.", "urn:clei:UNASSIGNED"},
}

// entityInventoryPorts are the four generated profiles: their port indexes and
// the old entPhysicalModelName of each. tenGigFrom is the first 10GE-PORT index;
// the ports below it were 1GE-PORT.
var entityInventoryPorts = []struct {
	profile                      string
	firstPort, ports, tenGigFrom int
}{
	{"cisco_catalyst_9500.json", 1001, 48, 1049},
	{"cisco_nexus_9500.json", 1001, 64, 1001},
	{"juniper_mx960.json", 1001, 80, 1049},
	{"palo_alto_pa3220.json", 1001, 16, 1017},
}

func entityInventoryEdits() map[string][]profileRowEdit {
	out := map[string][]profileRowEdit{}
	for _, c := range entityInventoryChassis {
		out[c.profile] = []profileRowEdit{
			{op: editDel, oid: "." + entityInventoryMfgDate1, before: c.mfgDate},
			{op: editDel, oid: "." + entityInventoryUris1, before: c.uris},
			{op: editDel, oid: "." + entityInventoryUUID1, before: c.uuid},
		}
	}
	const ent = ".1.3.6.1.2.1.47.1.1.1.1."
	for _, p := range entityInventoryPorts {
		var mfg string
		for _, c := range entityInventoryChassis {
			if c.profile == p.profile {
				mfg = c.uris
			}
		}
		edits := []profileRowEdit{{op: editAdd, oid: ent + "12.1", after: mfg}}
		for i := p.firstPort; i < p.firstPort+p.ports; i++ {
			model := "1GE-PORT"
			if i >= p.tenGigFrom {
				model = "10GE-PORT"
			}
			for _, cell := range [][2]string{
				{"8", "1.0"}, {"9", "1.0"}, {"10", "1.0"},
				{"11", fmt.Sprintf("SN00%d", i)},
				{"12", "Simulation Vendor"},
				{"13", model},
				{"15", fmt.Sprintf("ASSET%d", i)},
			} {
				edits = append(edits, profileRowEdit{
					op: editChg, oid: fmt.Sprintf("%s%s.%d", ent, cell[0], i), before: cell[1], after: "",
				})
			}
		}
		out[p.profile] = append(out[p.profile], edits...)
	}
	return out
}

func restoreEntityInventory(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	for profile, edits := range entityInventoryEdits() {
		reverseProfileEdits(t, cur, profile, profile+" ENTITY-MIB inventory", edits)
	}
}

func entityInventoryNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return reverseOIDNameEdits(t, names, "ENTITY-MIB inventory", nil,
		[]string{entityInventoryMfgDate1, entityInventoryUris1, entityInventoryUUID1})
}

// TestEntityInventoryEditCountIsTheFix pins the size of the edit table, so a
// range that drifts from the data cannot shrink the ledger quietly.
func TestEntityInventoryEditCountIsTheFix(t *testing.T) {
	n := 0
	for _, edits := range entityInventoryEdits() {
		n += len(edits)
	}
	// 21 chassis rows x 3 deleted cells + 4 added manufacturer names + 208 port rows x 7 cells.
	if want := 21*3 + 4 + 208*7; n != want {
		t.Errorf("the ENTITY-MIB inventory ledger records %d edits, want %d", n, want)
	}
}

func TestEntityInventoryFixReproducesTheParentCorpus(t *testing.T) {
	got := corpusTagDigestAt(t, corpusValuesAt(t, entityInventoryParentRevision), entityInventoryParentRevision)
	if got != shippedTagDigestBeforeEntityInventory {
		t.Errorf("reversing the ENTITY-MIB inventory fix gives tag digest %s, want %s: another shipped row "+
			"changed without being recorded", got, shippedTagDigestBeforeEntityInventory)
	}
}

func TestEntityInventoryRePinIsOnlyTheFix(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), entityInventoryParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeEntityInventory {
		t.Errorf("reversing the ENTITY-MIB inventory fix gives OID-name digest %s, want %s",
			got, shippedOIDEncodingDigestBeforeEntityInventory)
	}
}
