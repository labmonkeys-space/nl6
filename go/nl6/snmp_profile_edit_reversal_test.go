/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// Helpers for ledgers that EDIT one profile in place (rows added, deleted or
// rewritten) rather than adding or removing a whole profile. Each such ledger
// commits a machine-generated table of edits and reverses it here.

type profileEditOp int

const (
	editAdd profileEditOp = iota // the change added the row; the reversal deletes it
	editDel                      // the change deleted the row; the reversal restores before
	editChg                      // the change rewrote the value; the reversal restores before
)

type profileRowEdit struct {
	op     profileEditOp
	oid    string // normalised, with a leading dot, as shippedSNMPEntries reports it
	before string
	after  string
}

// reverseProfileEdits undoes edits against a (profile, OID) -> value map in
// place. Fatal on any row that is not in the state the edit left it in.
func reverseProfileEdits(t *testing.T, cur map[[2]string]string, profile, label string, edits []profileRowEdit) {
	t.Helper()
	if len(edits) == 0 {
		t.Fatalf("%s: empty edit table; a ledger that reverses nothing is vacuous", label)
	}
	for _, e := range edits {
		k := [2]string{profile, e.oid}
		got, present := cur[k]
		switch e.op {
		case editAdd, editChg:
			if !present || got != e.after {
				t.Fatalf("%s: %s %s = %q (present %v), want %q", label, profile, e.oid, got, present, e.after)
			}
			if e.op == editAdd {
				delete(cur, k)
			} else {
				cur[k] = e.before
			}
		case editDel:
			if present {
				t.Fatalf("%s: %s %s is still served (%q); the change deleted it", label, profile, e.oid, got)
			}
			cur[k] = e.before
		default:
			t.Fatalf("%s: unknown edit op %d", label, e.op)
		}
	}
}

// reverseOIDNameEdits removes the names a change introduced and restores the
// ones it removed. Fatal unless every added name is present exactly once and
// no removed name is present.
func reverseOIDNameEdits(t *testing.T, names []string, label string, added, removed []string) []string {
	t.Helper()
	drop := map[string]int{}
	for _, n := range added {
		drop[n] = 0
	}
	present := map[string]bool{}
	out := make([]string, 0, len(names)+len(removed))
	for _, n := range names {
		if _, ok := drop[n]; ok {
			drop[n]++
			continue
		}
		present[n] = true
		out = append(out, n)
	}
	for n, seen := range drop {
		if seen != 1 {
			t.Fatalf("%s: added OID name %s found %d times, want exactly 1", label, n, seen)
		}
	}
	for _, n := range removed {
		if present[n] {
			t.Fatalf("%s: removed OID name %s is still shipped", label, n)
		}
		out = append(out, n)
	}
	return out
}

// corpusValuesAt reconstructs the (profile, OID) -> value map at target by
// walking the reversal chain back from today's corpus.
func corpusValuesAt(t *testing.T, target string) map[[2]string]string {
	t.Helper()
	cur := map[[2]string]string{}
	for _, e := range shippedSNMPEntries(t) {
		k := [2]string{e.Profile, e.OID}
		if prev, dup := cur[k]; dup && prev != e.Value {
			t.Fatalf("%s serves %s twice with different values (%q, %q)", e.Profile, e.OID, prev, e.Value)
		}
		cur[k] = e.Value
	}
	restoreCorpusValuesTo(t, cur, target)
	return cur
}

// encodeTypedValueAt encodes value as the wire carried it at revision: a
// column a newer link typed takes the untyped default branch. Membership is
// decided by typeTagIn, the production matcher, over a one-row table.
func encodeTypedValueAt(t *testing.T, oid, value, revision string) []byte {
	t.Helper()
	for _, col := range columnsTypedAfter(t, revision) {
		if typeTagIn([]oidTypeEntry{{col, ASN1_OBJECT_ID}}, oid) != 0 {
			return encodeTypedValueAtTag(oid, value, 0)
		}
	}
	return encodeTypedValue(oid, value)
}

// corpusTagDigestAt hashes a value map the way shippedTagDigest does, as the
// corpus encoded at revision.
func corpusTagDigestAt(t *testing.T, cur map[[2]string]string, revision string) string {
	t.Helper()
	seen := map[string]struct{}{}
	for k, v := range cur {
		enc := encodeTypedValueAt(t, k[1], v, revision)
		if len(enc) == 0 {
			t.Fatalf("%s %s: encodeTypedValueAt(%q) emitted nothing", k[0], k[1], v)
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
	return hex.EncodeToString(h.Sum(nil))
}

// corpusOIDNameDigest hashes a list of OID names the way
// shippedOIDEncodingDigest does.
func corpusOIDNameDigest(names []string) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, oid := range sorted {
		if strings.Contains(oid, "{{") {
			continue
		}
		_, _ = fmt.Fprintf(h, "%s=%x\n", oid, encodeOID(oid))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestReverseProfileEditsRoundTrip(t *testing.T) {
	p := "x.json"
	cur := map[[2]string]string{{p, ".1.1"}: "new", {p, ".1.2"}: "added"}
	reverseProfileEdits(t, cur, p, "test", []profileRowEdit{
		{op: editChg, oid: ".1.1", before: "old", after: "new"},
		{op: editAdd, oid: ".1.2", after: "added"},
		{op: editDel, oid: ".1.3", before: "gone"},
	})
	want := map[[2]string]string{{p, ".1.1"}: "old", {p, ".1.3"}: "gone"}
	if fmt.Sprint(cur) != fmt.Sprint(want) {
		t.Fatalf("reversed to %v, want %v", cur, want)
	}
	got := reverseOIDNameEdits(t, []string{"1.1", "1.2"}, "test", []string{"1.2"}, []string{"1.3"})
	sort.Strings(got)
	if strings.Join(got, ",") != "1.1,1.3" {
		t.Fatalf("names reversed to %v", got)
	}
}

// Before any link types a column, encoding a corpus "as of" any revision is
// exactly today's encoding. This pins the refactor as a no-op.
func TestEncodeTypedValueAtIsTheEncoderWhenNothingWasTyped(t *testing.T) {
	revs := []string{corpusHeadRevision}
	for _, r := range newestFirstReversals {
		revs = append(revs, r.parent)
	}
	for _, rev := range revs {
		if cols := columnsTypedAfter(t, rev); len(cols) != 0 {
			t.Fatalf("columnsTypedAfter(%s) = %v, want none before nl6#821", rev, cols)
		}
	}
	for _, e := range shippedSNMPEntries(t) {
		want := encodeTypedValue(e.OID, e.Value)
		got := encodeTypedValueAt(t, e.OID, e.Value, corpusOldestRevision)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s %s: encodeTypedValueAt = % X, encodeTypedValue = % X", e.Profile, e.OID, got, want)
		}
	}
}

func TestTypeTagInIsSnmpTypeTag(t *testing.T) {
	for _, e := range shippedSNMPEntries(t) {
		if a, b := typeTagIn(oidTypeTable, e.OID), snmpTypeTag(e.OID); a != b {
			t.Fatalf("%s: typeTagIn = %#02x, snmpTypeTag = %#02x", e.OID, a, b)
		}
	}
}
