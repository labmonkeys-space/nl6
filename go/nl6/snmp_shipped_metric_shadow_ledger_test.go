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
	"sync"
	"testing"
)

// nl6#1056 deletes the eleven static rows that sat on an OID the metric engine
// owns. A GET is answered by the engine (findResponseAt asks getMetricValue
// before the static index), while a walk returned the static row, so the two
// paths of one device disagreed and the walked value never moved. Same class
// as the Cisco temperature rows #592 deleted (see
// TestCiscoTemperatureStatusValueIsServedByTheCycler).
//
// DELETED, NOT CORRECTED. The engine is the only source that moves, so a
// static row on an engine-owned OID is dead on GET and wrong on a walk,
// whatever it holds.
//
// Every recorded oldValue was read OUT OF GIT at the parent revision with
// `git show <rev>:go/nl6/resources/<type>/<part>`, never retyped from the
// working tree, and TestMetricShadowLedgerValuesMatchTheParentRevision pins the
// table against a digest of that read (the nl6#573 lesson).
//
// The h100 and h200 hrStorageSize.1 and hrStorageUsed.1 values are the ones
// nl6#541 rescaled them to. This reversal runs BEFORE nl6#541's in the chain,
// so restoring them is what lets that older ledger still find its rows.

// metricShadowParentRevision is the revision this change was taken from, and
// the one its two golden digests below were taken at.
const metricShadowParentRevision = "c7e4cb4"

// The two "before" digests are the values shippedTagDigest and
// shippedOIDEncodingDigest held at the parent, NOT re-derived from the edited
// tree.
const (
	shippedTagDigestBeforeMetricShadow         = "a2de72158ead1fc59200b8cba7edf0f6034d20d91818ff9d61ccb58f8d00cc47"
	shippedOIDEncodingDigestBeforeMetricShadow = "0fb1b930f5744c4c587e9be298d8bac778d180c9c311faa4dc09862231957837"
)

// metricShadowDeletedEntries are the eleven rows this change removed, read out
// of git at the parent.
//
// DO NOT restore any row with a "better" number: the engine serves the OID on
// both paths, and a static row is dead data whatever it holds.
var metricShadowDeletedEntries = []struct{ profile, oid, oldValue string }{
	{"extreme_vsp4450.json", ".1.3.6.1.4.1.1916.1.1.1.8.0", "36"},
	{"huawei_ne8000.json", ".1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11.0", "43"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.2.1.25.2.3.1.5.1", "1073741824"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.2.1.25.2.3.1.6.1", "536870912"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.2.1.25.3.3.1.2.1", "35"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.2.1.25.2.3.1.5.1", "2097152"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.2.1.25.2.3.1.6.1", "1258291"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.2.1.25.3.3.1.2.1", "42"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.2.1.25.2.3.1.5.1", "2097152"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.2.1.25.2.3.1.6.1", "1468006"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.2.1.25.3.3.1.2.1", "38"},
}

// metricShadowValueDigestAtParent is a SHA-256 over the sorted
// "profile\toid\toldValue" lines of the eleven rows as they existed at the
// parent, computed from `git ls-tree` and `git show` at that revision, never
// from the table above.
const metricShadowValueDigestAtParent = "3476e7ffb12e84d14623ce75adfc607ea52918a07097380e552f6c36c9252f0f"

// metricShadowVanishedOIDNames are the OID names this change removed from the
// corpus ENTIRELY. hrStorageSize.1 and hrStorageUsed.1 are not among them:
// hpe_proliant_dl380 still ships both, and nothing maps them to the engine
// there. Measured as the parent's names minus the tree's (6494 against 6491).
var metricShadowVanishedOIDNames = []string{
	"1.3.6.1.2.1.25.3.3.1.2.1",
	"1.3.6.1.4.1.1916.1.1.1.8.0",
	"1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11.0",
}

// restoreMetricShadowRows reverses this change against a (profile, OID) ->
// value map. Fatal on any row that still ships.
func restoreMetricShadowRows(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	for _, d := range metricShadowDeletedEntries {
		reverseProfileEdits(t, cur, d.profile, "nl6#1056 metric shadow rows",
			[]profileRowEdit{{op: editDel, oid: d.oid, before: d.oldValue}})
	}
}

// metricShadowOIDNamesBefore is the name-view counterpart of
// restoreMetricShadowRows.
func metricShadowOIDNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return appendVanishedOIDNames(t, "nl6#1056 metric shadow rows", names, metricShadowVanishedOIDNames)
}

func TestMetricShadowDeletionReproducesTheParentCorpus(t *testing.T) {
	got := corpusTagDigestAt(t, corpusValuesAt(t, metricShadowParentRevision), metricShadowParentRevision)
	if got != shippedTagDigestBeforeMetricShadow {
		t.Errorf("reversing the nl6#1056 deletion gives tag digest %s, want %s: another shipped row "+
			"changed without being recorded", got, shippedTagDigestBeforeMetricShadow)
	}
}

func TestMetricShadowRePinIsOnlyTheDeletion(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), metricShadowParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeMetricShadow {
		t.Errorf("restoring the nl6#1056 names gives digest %s, want %s: the re-pin is NOT the deletion alone",
			got, shippedOIDEncodingDigestBeforeMetricShadow)
	}
}

// TestMetricShadowLedgerValuesMatchTheParentRevision pins the recorded old
// values against the tree at the parent. If it fails after an edit to the
// table, the table is wrong: the parent revision cannot change.
func TestMetricShadowLedgerValuesMatchTheParentRevision(t *testing.T) {
	var lines []string
	for _, d := range metricShadowDeletedEntries {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", d.profile, d.oid, d.oldValue))
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != metricShadowValueDigestAtParent {
		t.Errorf("ledger value digest = %s, want %s (%d rows): the recorded rows no longer match what %s shipped",
			got, metricShadowValueDigestAtParent, len(lines), metricShadowParentRevision)
	}
	if len(metricShadowDeletedEntries) != 11 {
		t.Errorf("nl6#1056 deleted entries: ledger has %d rows, want 11", len(metricShadowDeletedEntries))
	}
}

// TestMetricShadowNamesLeftTheCorpus makes "the name vanished entirely" a
// measurement.
func TestMetricShadowNamesLeftTheCorpus(t *testing.T) {
	shipped := map[string]struct{}{}
	for _, o := range collectShippedOIDs(t) {
		shipped[strings.TrimPrefix(o, ".")] = struct{}{}
	}
	for _, o := range metricShadowVanishedOIDNames {
		if _, ok := shipped[o]; ok {
			t.Errorf("%s is named by a shipped resource or catalog again", o)
		}
	}
}

// staticRowsOnMetricOIDs returns the OIDs of profile that carry a static row
// although the metric engine owns them.
func staticRowsOnMetricOIDs(profile string, res *DeviceResources) []string {
	var out []string
	for oid := range GetMetricOIDs(profile) {
		if _, ok := res.oidIndex.Load(oid); ok {
			out = append(out, oid)
		}
	}
	sort.Strings(out)
	return out
}

// TestNoShippedStaticRowShadowsAMetricOID keeps such rows out of the shipped
// profiles. The walk tie rule also serves the engine value for them, so without
// this test a returning row would be invisible on the wire and only show up as
// dead data. The control plants one row to prove the check can see it.
func TestNoShippedStaticRowShadowsAMetricOID(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	checked := 0
	for _, profile := range shippedProfileNames(t) {
		res, err := sm.LoadSpecificResources(profile)
		if err != nil {
			t.Fatalf("LoadSpecificResources(%s): %v", profile, err)
		}
		if len(GetMetricOIDs(profile)) > 0 {
			checked++
		}
		if rows := staticRowsOnMetricOIDs(profile, res); len(rows) > 0 {
			t.Errorf("%s ships a static row on %d OID(s) the metric engine owns: %v. Delete the rows: "+
				"the engine answers them on GET and on a walk", profile, len(rows), rows)
		}
	}
	if checked < 10 {
		t.Errorf("only %d shipped profiles have a metric map; the check is not looking where it should", checked)
	}

	res, err := sm.LoadSpecificResources("extreme_vsp4450.json")
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	planted := &DeviceResources{oidIndex: &sync.Map{}}
	res.oidIndex.Range(func(k, v any) bool { planted.oidIndex.Store(k, v); return true })
	planted.oidIndex.Store(".1.3.6.1.4.1.1916.1.1.1.8.0", "36")
	if rows := staticRowsOnMetricOIDs("extreme_vsp4450.json", planted); len(rows) != 1 {
		t.Errorf("control: a planted row on extremeCurrentTemperature.0 is reported %d times, want once", len(rows))
	}
}
