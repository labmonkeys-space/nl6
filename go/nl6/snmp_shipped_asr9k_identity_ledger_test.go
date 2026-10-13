/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// asr9k models an ASR 9010: its ENTITY-MIB chassis row reads "ASR 9010
// 20-slot Chassis" / ASR9010-CHASSIS, and its RSPs, line cards, PSUs and fans
// are ASR 9000 parts. It identified as something else on two OID values:
//
//	sysObjectID.0            1.3.6.1.4.1.9.12.3.1.3.1736  cevChassisASR901DC10GSCC,
//	                                                      a vendor-type OID of an
//	                                                      ASR 901, not a product OID
//	entPhysicalVendorType.1  1.3.6.1.4.1.9.12.3.1.3.1186  undefined in the module
//
// A collector doing vendor detection on sysObjectID resolved an ASR 901 or
// nothing. Both objects exist and have a right value for the modelled chassis,
// so they are corrected, not deleted.
//
// ## What was read
//
// cisco/cisco-mibs at commit c9ab98c0, read on 2026-10-12, cited by
// LAST-UPDATED and by the SHA-256 of the file read:
//
//	CISCO-PRODUCTS-MIB               201604290000Z  56b392946c0bae5a192c239656d043e6ead90e1e9d4632dab0541abb559c5255
//	CISCO-ENTITY-VENDORTYPE-OID-MIB  201806050000Z  9bd040a5c660a9043f6560a535d966b057955c9d643c921bf74eafbb00610cec
//
//	ciscoASR9010          ::= { ciscoProducts 1017 }   1.3.6.1.4.1.9.1.1017
//	cevChassisASR9010     ::= { cevChassis 780 }       1.3.6.1.4.1.9.12.3.1.3.780
//	cevChassis            ::= { cevMIBObjects 3 }
//	cevMIBObjects         ::= { ciscoEntityVendortypeOIDMIB 1 }
//
// Reproduce with:
//
//	curl -sS https://raw.githubusercontent.com/cisco/cisco-mibs/c9ab98c0/v2/CISCO-PRODUCTS-MIB.my | shasum -a 256
//	curl -sS https://raw.githubusercontent.com/cisco/cisco-mibs/c9ab98c0/v2/CISCO-ENTITY-VENDORTYPE-OID-MIB.my | shasum -a 256
//
// No MIB is checked in: Cisco's header grants no redistribution, so this is a
// pinned reading, not a live check.
//
// entPhysicalVendorType.1 went out as an OCTET STRING when this ledger was
// written. Since nl6#821 oidTypeTable types the column, so it is an OBJECT
// IDENTIFIER on the wire and an OID name to collectShippedOIDs.

const (
	asr9kProfile           = "asr9k.json"
	asr9kSysObjectIDOID    = ".1.3.6.1.2.1.1.2.0"
	asr9kChassisVendorOID  = ".1.3.6.1.2.1.47.1.1.1.1.3.1"
	asr9kSysObjectIDWant   = "1.3.6.1.4.1.9.1.1017"       // ciscoASR9010
	asr9kChassisVendorWant = "1.3.6.1.4.1.9.12.3.1.3.780" // cevChassisASR9010
	asr9kSysObjectIDOld    = "1.3.6.1.4.1.9.12.3.1.3.1736"
	asr9kChassisVendorOld  = "1.3.6.1.4.1.9.12.3.1.3.1186"
)

func TestASR9kIdentityMatchesTheMIB(t *testing.T) {
	srv := deviceForProfileWithMetrics(t, asr9kProfile)
	for _, c := range []struct {
		name, oid, want string
		tag             byte
	}{
		{"sysObjectID.0 (ciscoASR9010)", asr9kSysObjectIDOID, asr9kSysObjectIDWant, ASN1_OBJECT_ID},
		{"entPhysicalVendorType.1 (cevChassisASR9010)", asr9kChassisVendorOID, asr9kChassisVendorWant, ASN1_OBJECT_ID},
	} {
		got := srv.findResponse(c.oid)
		if got != c.want {
			t.Errorf("%s = %q, want %s", c.name, got, c.want)
		}
		if enc := encodeTypedValue(c.oid, got); len(enc) == 0 || enc[0] != c.tag {
			t.Errorf("%s encodes with tag %#x, want %#x", c.name, enc, c.tag)
		}
	}
}

// Neither shipped value may come back in any asr9k part.
func TestASR9kServesNoForeignChassisOID(t *testing.T) {
	files, err := filepath.Glob("resources/asr9k/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no asr9k parts: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{asr9kSysObjectIDOld, asr9kChassisVendorOld} {
			if strings.Contains(string(b), `"`+bad+`"`) {
				t.Errorf("%s still serves %s", f, bad)
			}
		}
	}
}

// ## The ledger
//
// Two rows changed. Neither changes an emitted tag (sysObjectID stays an
// OBJECT IDENTIFIER, entPhysicalVendorType an OCTET STRING), so
// shippedTagDigest did not move and the ledger has no value view: a view that
// restored both rows was mutated to restore nothing and no test noticed. The
// sysObjectID value is an OID name to collectShippedOIDs, so
// shippedOIDEncodingDigest moved: 1736 left the set and 1.3.6.1.4.1.9.1.1017
// joined it. Measured, not predicted: before the re-pin, only
// TestShippedOIDsUnchangedOnTheWire and the chain tests failed.

// asr9kIdentityParentRevision is the revision the digests below were taken
// at, the merge base of this change.
const asr9kIdentityParentRevision = "68fcd62"

// The values shippedTagDigest and shippedOIDEncodingDigest held at the parent,
// NOT re-derived from the new tree. The tag digest equals today's.
const (
	shippedTagDigestBeforeASR9kIdentity         = "a24ac010983a7358e3aba2e7e46f17446371ff266d4997f7793c9db31ab21321"
	shippedOIDEncodingDigestBeforeASR9kIdentity = "9bf7d2bbd6c8e7aa074ff073d8edcc6f9c181efa5a7571990ccd169808bbb2da"
)

// asr9kOIDNamesBeforeIdentityFix swaps the sysObjectID value back in the
// distinct name list. Fatal unless the new value is present once and the old
// one absent.
func asr9kOIDNamesBeforeIdentityFix(t *testing.T, names []string) []string {
	t.Helper()
	out := make([]string, 0, len(names))
	found := 0
	for _, n := range names {
		switch n {
		case asr9kSysObjectIDWant:
			found++
			continue
		case asr9kSysObjectIDOld:
			t.Fatalf("%s is already in the name set; the reconstruction is not %s's", n, asr9kIdentityParentRevision)
		}
		out = append(out, n)
	}
	if found != 1 {
		t.Fatalf("%s appears %d times in the name set, want exactly 1", asr9kSysObjectIDWant, found)
	}
	return append(out, asr9kSysObjectIDOld)
}

// TestASR9kIdentityFixReproducesTheParentCorpus pins the claim that no tag
// moved: reversing every newer link gives this change's parent tag digest,
// which equals the value shippedTagDigest held before it.
func TestASR9kIdentityFixReproducesTheParentCorpus(t *testing.T) {
	cur := map[[2]string]string{}
	for _, e := range shippedSNMPEntries(t) {
		k := [2]string{e.Profile, e.OID}
		if prev, dup := cur[k]; dup && prev != e.Value {
			t.Fatalf("%s serves %s twice with different values (%q, %q); the reconstruction "+
				"cannot be unambiguous", e.Profile, e.OID, prev, e.Value)
		}
		cur[k] = e.Value
	}
	restoreCorpusValuesTo(t, cur, asr9kIdentityParentRevision)

	// Same line shape and hash as shippedTypedCorpus.
	seen := map[string]struct{}{}
	for k, v := range cur {
		enc := encodeTypedValueAt(t, k[1], v, asr9kIdentityParentRevision)
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
	if got := hex.EncodeToString(h.Sum(nil)); got != shippedTagDigestBeforeASR9kIdentity {
		t.Errorf("reconstructed parent tag digest = %s, want %s: some other shipped row changed without being recorded",
			got, shippedTagDigestBeforeASR9kIdentity)
	}
}

// TestASR9kIdentityRePinIsOnlyTheFix does the same for the OID-name digest,
// the one this change moved.
func TestASR9kIdentityRePinIsOnlyTheFix(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), asr9kIdentityParentRevision)
	sort.Strings(restored)
	h := sha256.New()
	for _, oid := range restored {
		if strings.Contains(oid, "{{") {
			continue
		}
		// hash.Hash.Write never returns an error, but errcheck cannot know that.
		_, _ = fmt.Fprintf(h, "%s=%x\n", oid, encodeOID(oid))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != shippedOIDEncodingDigestBeforeASR9kIdentity {
		t.Errorf("reversing the asr9k identity fix gives digest %s, want the pre-change value %s; "+
			"the re-pin of shippedOIDEncodingDigest is not explained by this fix alone",
			got, shippedOIDEncodingDigestBeforeASR9kIdentity)
	}
}
