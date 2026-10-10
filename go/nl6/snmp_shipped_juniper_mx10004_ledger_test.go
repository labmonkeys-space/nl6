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

// The juniper_mx10004 device type ADDED a profile to the shipped corpus. It was
// generated from juniper_mx240 by a one-off clone script: 48 interface rows
// (xe-0/0/0..xe-0/1/23) instead of 24, sysObjectID.0 and entPhysicalVendorType
// re-pointed at jnxProductNameMX10004, and the MX240 model strings renamed.
//
// An addition edits no existing row, so the ledger is the profile itself:
//
//   - the VALUE view deletes every (juniper_mx10004.json, OID) key, and
//   - the NAME view removes the one distinct OID string no other shipped file
//     carries, the sysObjectID value 1.3.6.1.4.1.2636.1.1.1.2.168. Every OID
//     NAME the profile serves is already served by juniper_mx240 or another
//     profile, so collectShippedOIDs gained only that value. Measured by
//     running collectShippedOIDs with and without the directory.
//
// The parent is 2f06857 (v0.34.2 on main), the merge base of this branch. No
// SNMP resource file moved between it and the commit before this change.

// juniperMx10004ParentRevision is the revision the two golden digests below were
// taken at. Read by this change's entry in newestFirstReversals.
const juniperMx10004ParentRevision = "2f06857"

// juniperMx10004Profile is the profile this change added.
const juniperMx10004Profile = "juniper_mx10004.json"

// juniperMx10004EntriesShipped is the number of distinct (profile, OID) keys the
// profile ships, pinned so the value view cannot delete nothing and pass.
const juniperMx10004EntriesShipped = 1061

// juniperMx10004AddedOIDNames is every distinct OID string the addition put into
// collectShippedOIDs' set. Spelled without a leading dot, as that walk reads
// the raw JSON.
var juniperMx10004AddedOIDNames = []string{"1.3.6.1.4.1.2636.1.1.1.2.168"}

// The values shippedTagDigest and shippedOIDEncodingDigest held before this
// change, NOT re-derived from the new tree.
const (
	shippedTagDigestBeforeJuniperMx10004         = "17e2773527d4329fd50c1fc323488eb809e11e899689a04c0c6cbf752a765da2"
	shippedOIDEncodingDigestBeforeJuniperMx10004 = "be01d6c675b2cf2950bfc00c3e02c37c878467e5c918a9ccb6f1b2c39b4aca56"
)

// restoreJuniperMx10004Addition removes the added profile from a (profile, OID)
// -> value map, in place. Fatal unless exactly juniperMx10004EntriesShipped keys
// go.
func restoreJuniperMx10004Addition(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	removed := 0
	for k := range cur {
		if k[0] == juniperMx10004Profile {
			delete(cur, k)
			removed++
		}
	}
	if removed != juniperMx10004EntriesShipped {
		t.Fatalf("the juniper_mx10004 value-view reversal removed %d keys, want %d. The profile "+
			"changed without this ledger being updated", removed, juniperMx10004EntriesShipped)
	}
}

// juniperMx10004OIDNamesBeforeAddition removes the names the addition introduced.
// Fatal unless each is present exactly once.
func juniperMx10004OIDNamesBeforeAddition(t *testing.T, names []string) []string {
	t.Helper()
	drop := map[string]int{}
	for _, n := range juniperMx10004AddedOIDNames {
		drop[n] = 0
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if _, ok := drop[n]; ok {
			drop[n]++
			continue
		}
		out = append(out, n)
	}
	for n, seen := range drop {
		if seen != 1 {
			t.Fatalf("the juniper_mx10004 name-view reversal found %s %d times, want exactly 1, "+
				"so the reconstruction is not %s's set", n, seen, juniperMx10004ParentRevision)
		}
	}
	return out
}

// TestJuniperMx10004AdditionReproducesTheParentCorpus is the before/after pin for
// the TAG digest: remove the profile from today's corpus and the parent's value
// must come back. Any other edit to shipped data fails it.
func TestJuniperMx10004AdditionReproducesTheParentCorpus(t *testing.T) {
	cur := map[[2]string]string{}
	for _, e := range shippedSNMPEntries(t) {
		k := [2]string{e.Profile, e.OID}
		if prev, dup := cur[k]; dup && prev != e.Value {
			t.Fatalf("%s serves %s twice with different values (%q, %q); the reconstruction "+
				"cannot be unambiguous", e.Profile, e.OID, prev, e.Value)
		}
		cur[k] = e.Value
	}

	restoreCorpusValuesTo(t, cur, juniperMx10004ParentRevision)

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
	if got := hex.EncodeToString(h.Sum(nil)); got != shippedTagDigestBeforeJuniperMx10004 {
		t.Errorf("reconstructed parent digest = %s, want %s.\n"+
			"Removing juniper_mx10004 no longer gives %s's shipped data back: some other shipped "+
			"row changed without being recorded.", got, shippedTagDigestBeforeJuniperMx10004,
			juniperMx10004ParentRevision)
	}
}

// TestJuniperMx10004RePinIsOnlyTheAddition does the same job for the OID-NAME
// digest, which the tag digest cannot see.
func TestJuniperMx10004RePinIsOnlyTheAddition(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), juniperMx10004ParentRevision)
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
	if got := hex.EncodeToString(h.Sum(nil)); got != shippedOIDEncodingDigestBeforeJuniperMx10004 {
		t.Errorf("removing juniper_mx10004's OID names gives digest %s, want the pre-change "+
			"value %s over %d OIDs.\nSo the re-pin of shippedOIDEncodingDigest is NOT explained "+
			"by the addition alone.", got, shippedOIDEncodingDigestBeforeJuniperMx10004, checked)
	}
}
