/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"testing"
)

// The ENTITY-MIB chassis rows of four generated profiles break RFC 4133, and
// their port rows answer entPhysicalVendorType with an OID under the
// IANA-reserved PEN 0. This link records the fix.
//
// Chassis rows. RFC 4133 requires one overall entity. Its entPhysicalContainedIn
// is 0, its class is chassis(3), and its entPhysicalParentRelPos is -1 because it
// is contained in nothing. The four rows were contained in 39, 42, 41 and 55,
// none of which existed, and were of class other(1), so a collector following
// entPhysicalContainedIn found no root. Their entPhysicalFirmwareRev was the
// placeholder "1"; RFC 4133 returns a zero-length string when no firmware is
// associated or it is unknown.
//
//	profile              ContainedIn.1  Class.1  ParentRelPos.1  FirmwareRev.1
//	cisco_nexus_9500     39 to 0        1 to 3   1 to -1         "1" to ""
//	cisco_catalyst_9500  42 to 0        1 to 3   1 to -1         "1" to ""
//	juniper_mx960        41 to 0        1 to 3   1 to -1         "1" to ""
//	palo_alto_pa3220     55 to 0        1 to 3   1 to -1         "1" to ""
//
// Port vendor types. 208 port rows answered 1.3.6.1.4.1.0.0, which resolves to no
// vendor. They now answer zeroDotZero (0.0), the value RFC 4133 prescribes when
// no vendor-specific registration exists or it is unknown. Real per-port vendor
// types would need a reading of each vendor's MIB, and nothing consumes them.
//
// cisco_ios. entPhysicalModelName.2, the switch-module row of a fixed
// WS-C2960X-24TS-L, answered C2960X-24TS-L, which is no part number. A fixed
// 2960-X has no separate module part, so the model name is zero-length, as RFC
// 4133 allows. The row and its containment stay.
//
// The tag view moves at four rows: the firmware revision "1" was encoded as an
// INTEGER and the zero-length string is an OCTET STRING. The OID-name view moves
// because entPhysicalVendorType is OID-typed: 1.3.6.1.4.1.0.0 leaves the set of
// names and 0.0 joins it.

// entityRootParentRevision is main at branch time; the digests below were taken
// there and are NOT re-derived from the new tree.
const entityRootParentRevision = "b7ade03d"

const (
	shippedTagDigestBeforeEntityRoot         = "e99c04bc6034c11caca251d934f710fa14355d36669b4f24b7c22c9ed8838378"
	shippedOIDEncodingDigestBeforeEntityRoot = "62c861f9df6fce48698ba79bc01c8ae15303d72f72b4afc0f2c259380680548b"
)

const (
	entityRootReservedPENVendorType = "1.3.6.1.4.1.0.0"
	entityRootZeroDotZero           = "0.0"
)

// entityRootProfiles are the four profiles with the generated shape: the old
// entPhysicalContainedIn.1 and the port indexes whose vendor type changed.
var entityRootProfiles = []struct {
	profile          string
	oldContainedIn   string
	firstPort, ports int
}{
	{"cisco_catalyst_9500.json", "42", 1001, 48},
	{"cisco_nexus_9500.json", "39", 1001, 64},
	{"juniper_mx960.json", "41", 1001, 80},
	{"palo_alto_pa3220.json", "55", 1001, 16},
}

func entityRootEdits() map[string][]profileRowEdit {
	out := map[string][]profileRowEdit{
		"cisco_ios.json": {
			{op: editChg, oid: ".1.3.6.1.2.1.47.1.1.1.1.13.2", before: "C2960X-24TS-L", after: ""},
		},
	}
	for _, p := range entityRootProfiles {
		edits := []profileRowEdit{
			{op: editChg, oid: ".1.3.6.1.2.1.47.1.1.1.1.4.1", before: p.oldContainedIn, after: "0"},
			{op: editChg, oid: ".1.3.6.1.2.1.47.1.1.1.1.5.1", before: "1", after: "3"},
			{op: editChg, oid: ".1.3.6.1.2.1.47.1.1.1.1.6.1", before: "1", after: "-1"},
			{op: editChg, oid: ".1.3.6.1.2.1.47.1.1.1.1.9.1", before: "1", after: ""},
		}
		for i := p.firstPort; i < p.firstPort+p.ports; i++ {
			edits = append(edits, profileRowEdit{
				op:     editChg,
				oid:    fmt.Sprintf(".1.3.6.1.2.1.47.1.1.1.1.3.%d", i),
				before: entityRootReservedPENVendorType,
				after:  entityRootZeroDotZero,
			})
		}
		out[p.profile] = edits
	}
	return out
}

func restoreEntityRoot(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	for profile, edits := range entityRootEdits() {
		reverseProfileEdits(t, cur, profile, profile+" ENTITY-MIB root", edits)
	}
}

func entityRootNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return reverseOIDNameEdits(t, names, "ENTITY-MIB root",
		[]string{entityRootZeroDotZero}, []string{entityRootReservedPENVendorType})
}

// TestEntityRootEditCountIsTheFix pins the size of the edit table, so a range
// that drifts from the data cannot shrink the ledger quietly.
func TestEntityRootEditCountIsTheFix(t *testing.T) {
	n := 0
	for _, edits := range entityRootEdits() {
		n += len(edits)
	}
	// 4 profiles x 4 chassis cells + 208 vendor types + 1 cisco_ios model name.
	if want := 4*4 + 208 + 1; n != want {
		t.Errorf("the ENTITY-MIB root ledger records %d edits, want %d", n, want)
	}
}

func TestEntityRootFixReproducesTheParentCorpus(t *testing.T) {
	got := corpusTagDigestAt(t, corpusValuesAt(t, entityRootParentRevision), entityRootParentRevision)
	if got != shippedTagDigestBeforeEntityRoot {
		t.Errorf("reversing the ENTITY-MIB root fix gives tag digest %s, want %s: another shipped row "+
			"changed without being recorded", got, shippedTagDigestBeforeEntityRoot)
	}
}

func TestEntityRootRePinIsOnlyTheFix(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), entityRootParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeEntityRoot {
		t.Errorf("reversing the ENTITY-MIB root fix gives OID-name digest %s, want %s",
			got, shippedOIDEncodingDigestBeforeEntityRoot)
	}
}
