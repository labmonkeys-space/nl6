/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

// juniper_mx960's CLI addressed two logical units, ge-0/0/0.0 with
// 192.168.100.1/24 at ifIndex 81 and xe-1/0/1.0 with 10.0.1.1/30 at ifIndex
// 84, but ipAddrTable and ipRouteTable served the second only, because the
// route-table change took each profile's connected subnet from its default
// gateway and the agreement guard required exactly one address row. The
// profile now serves the ipAddrTable row for 192.168.100.1 and the connected
// ipRouteTable row for 192.168.100.0, both on ifIndex 81, shaped like the
// 10.0.1.0 row beside them (direct(3), local(2), the same age). This change
// added those 18 rows and nothing else; no other resource names a
// 192.168.100.x address, so every row is a new OID name for the corpus too.

// mx960UnitAddressParentRevision is main at branch time; the digests below
// were taken there and are NOT re-derived from the new tree.
const mx960UnitAddressParentRevision = "ef12a2d6"

const (
	shippedTagDigestBeforeMx960UnitAddress         = "c9829e4c1982685c491a3a8f097b9dd0c01e089ecfc2ad159da6a31655b88d50"
	shippedOIDEncodingDigestBeforeMx960UnitAddress = "ca4ca2581accdc2cecfd5944d6a7e5d7ad8873eb2b724016578f31c09a84a19d"
)

const juniperMx960Profile = "juniper_mx960.json"

var mx960UnitAddressEdits = []profileRowEdit{
	{op: editAdd, oid: ".1.3.6.1.2.1.4.20.1.1.192.168.100.1", after: "192.168.100.1"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.20.1.2.192.168.100.1", after: "81"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.20.1.3.192.168.100.1", after: "255.255.255.0"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.20.1.4.192.168.100.1", after: "1"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.20.1.5.192.168.100.1", after: "65535"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.1.192.168.100.0", after: "192.168.100.0"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.2.192.168.100.0", after: "81"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.3.192.168.100.0", after: "0"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.4.192.168.100.0", after: "-1"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.5.192.168.100.0", after: "-1"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.6.192.168.100.0", after: "-1"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.7.192.168.100.0", after: "192.168.100.1"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.8.192.168.100.0", after: "3"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.9.192.168.100.0", after: "2"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.10.192.168.100.0", after: "604800"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.11.192.168.100.0", after: "255.255.255.0"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.12.192.168.100.0", after: "-1"},
	{op: editAdd, oid: ".1.3.6.1.2.1.4.21.1.13.192.168.100.0", after: "0.0"},
}

func restoreMx960UnitAddress(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	reverseProfileEdits(t, cur, juniperMx960Profile, "juniper_mx960 unit address", mx960UnitAddressEdits)
}

// mx960UnitAddressNewOIDNames is every edited row: all 18 names are new to
// the corpus.
func mx960UnitAddressNewOIDNames() []string {
	names := make([]string, 0, len(mx960UnitAddressEdits))
	for _, e := range mx960UnitAddressEdits {
		names = append(names, e.oid[1:])
	}
	return names
}

func mx960UnitAddressOIDNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return reverseOIDNameEdits(t, names, "juniper_mx960 unit address", mx960UnitAddressNewOIDNames(), nil)
}

func TestMx960UnitAddressNamesAreNewToTheCorpus(t *testing.T) {
	// The name reversal drops each of the 18 names outright, which is only
	// right while no other profile serves one of them.
	added := map[string]bool{}
	for _, n := range mx960UnitAddressNewOIDNames() {
		added[n] = true
	}
	for _, e := range shippedSNMPEntries(t) {
		if e.Profile != juniperMx960Profile && added[e.OID[1:]] {
			t.Errorf("%s serves %s, so the name is not new to the corpus and the ledger must not drop it", e.Profile, e.OID)
		}
	}
}

func TestMx960UnitAddressReproducesTheParentCorpus(t *testing.T) {
	if got := corpusTagDigestAt(t, corpusValuesAt(t, mx960UnitAddressParentRevision), mx960UnitAddressParentRevision); got != shippedTagDigestBeforeMx960UnitAddress {
		t.Errorf("reversing the juniper_mx960 unit address gives digest %s, want %s: another shipped row changed without being recorded",
			got, shippedTagDigestBeforeMx960UnitAddress)
	}
}

func TestMx960UnitAddressRePinIsOnlyTheEdit(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), mx960UnitAddressParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeMx960UnitAddress {
		t.Errorf("reversing the juniper_mx960 unit address OID names gives digest %s, want %s", got, shippedOIDEncodingDigestBeforeMx960UnitAddress)
	}
}
