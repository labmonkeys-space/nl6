/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The served-counter digest over the shipped corpus.
//
// WHY THIS EXISTS. The counter cycler serves every dial-derived column
// analytically, so no resource-file digest can witness a change to a served
// counter value. The served-state digest covers the three state leaves only.
// Before the counter hold landed, nothing pinned what the dial produced for a
// given interface at a given instant, which is the measurement "always-up
// interfaces are byte-identical" needs.
//
// The digest reads every dial-derived column of every interface of every
// shipped profile through GetDynamicAt at three fixed instants, under the
// default interface-state scenario and a fixed seed. It is taken twice: over
// every interface (shippedServedCounterDigest), and over the interfaces whose
// derived oper-status at seed is up(1) (shippedServedCounterDigestUpOnly).
//
// WHEN THIS FAILS. The failure prints the differing rows. Re-pinning is the
// right move ONLY for an intended wire change. The up-only digest is the one
// with teeth for the counter hold: it was pinned on the parent revision, before
// the hold existed, and the hold must not move it.

// shippedServedCounterDigest is the digest over every interface.
//
// Pinned on the parent revision, before the counter hold:
// see shippedServedCounterDigestBeforeHold.
//
// Re-pinned by the juniper_mx10004 system interfaces (ifIndex 77-80). With
// those rows filtered out every one of the three digests below is exactly
// its previous value: 0652f065470a6aef39c3ef2707f073f3830aea6bca4716bcd61828f86e15aef3,
// 2154bb4d6b037754d728275e889bcc98b318a41b508ab016e3569119142f5c39 and
// a1c6b09ebf850e64f05a02cc020c22a8233dee7ff5b439bae7c58e5c6305841d (measured).
const shippedServedCounterDigest = "7a3838465aaf7f18e7fb3c94155486d31dc10e40a8ac91926f1b1a25734c265f"

// shippedServedCounterDigestBeforeHold is the full digest on the parent
// revision, captured BEFORE the counter hold was written, which is the only
// order in which it has any detection power. The hold moves exactly the rows of
// interfaces that seed in a non-up state; TestServedCounterDigestMovedOnlyAtSeededDownRows
// pins that delta.
const shippedServedCounterDigestBeforeHold = "bdceb57cacc5614833ce3b976837284649337fe96a1a37d017af0d1f006378e1"

// shippedServedCounterDigestUpOnly is the digest over interfaces whose derived
// oper-status at seed is up(1). PINNED ON THE PARENT REVISION, before the
// counter hold existed, in a clean worktree: it is the measurement that the
// hold left every always-up interface byte-identical, and re-pinning it on a
// later revision discards that measurement.
//
// Re-pinned by the counter roll-up: children, aggregates and members moved,
// and the always-up, standalone measurement moved to
// shippedServedCounterDigestStandaloneUp. With the roll-up reverted this
// constant reads c62099ad54d62fdbcfec0c883ede750ec5de4803551f9561b3a42824fde8a204.
const shippedServedCounterDigestUpOnly = "0aa03e2ce2b70fe116319e67f98aeaa67e4142198dfcfdf7eb1e2e641dca45c4"

// shippedServedCounterDigestStandaloneUp is the digest over interfaces that are
// up at seed AND standalone: no parent, not an aggregate, not a member of one.
// PINNED ON THE PARENT REVISION of the counter roll-up, in a clean worktree,
// before any edit: the roll-up moves children, aggregates and members and
// must leave this set byte-identical. Re-pinning it on a later revision
// discards that measurement.
const shippedServedCounterDigestStandaloneUp = "cf0125dff1e55a46bcbe0b4fe5c648e39186f129b3a190e8dbbcaf7b25da06cd"

// normaliseDialsForDigest replaces every per-interface random draw with a
// deterministic function of the slot. InitIfCountersWithScenario draws the
// phases, bases, packet sizes and mix ratios from the seeded RNG while
// iterating a map, so the draw order and therefore every dial differ from
// run to run; a digest over the raw values would never repeat. With the
// dials fixed, the digest pins the serve arithmetic, which is what a change
// to the dispatcher moves, and nothing else.
func normaliseDialsForDigest(ic *IfCounterCycler) {
	for slot := range ic.ifSpeedBps {
		s := float64(slot)
		ic.phaseIn[slot] = 0.9 * float64(slot%7)
		ic.phaseOut[slot] = 1.1 * float64(slot%5)
		ic.baseInOctets[slot] = 1_000_000_000_000 + uint64(slot)*1_000_003
		ic.baseOutOctets[slot] = 900_000_000_000 + uint64(slot)*1_000_033
		ic.pktSizeIn[slot] = 480 + 3*s
		ic.pktSizeOut[slot] = 520 - 2*s
		ic.ucastRatioIn[slot], ic.mcastRatioIn[slot], ic.bcastRatioIn[slot] = 0.85, 0.10, 0.05
		ic.ucastRatioOut[slot], ic.mcastRatioOut[slot], ic.bcastRatioOut[slot] = 0.90, 0.08, 0.02
		for _, b := range [][]uint64{ic.baseInUcast, ic.baseInMcast, ic.baseInBcast, ic.baseOutUcast, ic.baseOutMcast, ic.baseOutBcast} {
			b[slot] = 10_000_000 + uint64(slot)
		}
		ic.errPpmIn[slot], ic.errPpmOut[slot], ic.discPpmIn[slot], ic.discPpmOut[slot] = 120, 80, 40, 20
		for _, b := range [][]uint64{ic.baseInErr, ic.baseOutErr, ic.baseInDisc, ic.baseOutDisc} {
			b[slot] = 1_000 + uint64(slot)
		}
	}
}

// servedCounterExcluded names interfaces that became non-standalone when the
// counter roll-up landed: the cisco_asr9902 bundle and its two members, which
// had no ifStackTable rows before. Excluding them on both sides keeps the
// standalone pin a comparison of one set against itself.
var servedCounterExcluded = map[string]map[int]bool{
	"cisco_asr9902.json": {10: true, 11: true, 51: true},
}

// servedCounterClass classifies one interface from the engine's parent table
// and a direct count of the profile's active ifStackStatus rows.
func servedCounterClass(ic *IfCounterCycler, res *DeviceResources, ifIndex int) string {
	if ic.State().Parent(ifIndex) != 0 {
		return "child"
	}
	known := map[int]bool{}
	for i := range ic.knownIfIndexes {
		known[i] = true
	}
	layers := readStackLayers(res.SNMP, known)
	if layers.members[ifIndex] != nil {
		return "aggregate"
	}
	for _, ls := range layers.members {
		if slices.Contains(ls, ifIndex) {
			return "member"
		}
	}
	return "standalone"
}

// servedCounterInstants are the fixed evaluation instants, in cycler seconds.
// 0 is the pre-seeded base; the others sit inside and past one dial period.
var servedCounterInstants = []float64{0, 600, 3600, 7200}

type servedCounterRow struct {
	Profile string
	IfIndex int
	OID     string
	T       float64
	Value   string
	// Class is standalone, child, aggregate or member, from the engine's parent
	// table and the stack parser (through the parser, not the cycler, so the
	// classification does not depend on what the roll-up did with it). excluded rows are standalone on an older revision and not on
	// this one, so the standalone pin covers one set on both.
	Class string
	// SeedUp records whether the interface's derived oper-status at engine
	// construction is up(1). Read from the engine, not inferred.
	SeedUp bool
}

func (r servedCounterRow) String() string {
	return fmt.Sprintf("%s\t%d\t%s\tt=%g\t%s", r.Profile, r.IfIndex, r.OID, r.T, r.Value)
}

// shippedServedCounterRows builds every shipped device type under the DEFAULT
// interface-state scenario and reads every dial-derived column per ifIndex at
// each instant in servedCounterInstants.
func shippedServedCounterRows(t *testing.T) []servedCounterRow {
	t.Helper()
	withIfScenario(t, IfScenarioAllNormal, 0)

	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	var rows []servedCounterRow
	for _, profile := range shippedProfileNames(t) {
		res, err := sm.LoadSpecificResources(profile)
		if err != nil {
			t.Fatalf("load %s: %v", profile, err)
		}
		mc := NewMetricsCycler(0, GetDeviceProfile(""))
		mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
		ic := mc.ifCounters.Load()
		if ic == nil {
			continue
		}
		normaliseDialsForDigest(ic)
		idx := ic.IfIndices()
		sort.Ints(idx)
		for _, i := range idx {
			seedUp := ic.State().OperStatus(i) == OperUp
			class := servedCounterClass(ic, res, i)
			if servedCounterExcluded[profile][i] {
				class = "excluded"
			}
			for _, c := range ifCyclerColumns {
				if isStateCol(c.col, c.prefix) {
					continue
				}
				oid := c.prefix + strconv.Itoa(c.col) + "." + strconv.Itoa(i)
				for _, at := range servedCounterInstants {
					rows = append(rows, servedCounterRow{
						Profile: profile, IfIndex: i, OID: oid, T: at,
						Value: ic.GetDynamicAt(oid, at), SeedUp: seedUp, Class: class,
					})
				}
			}
		}
	}
	if len(rows) == 0 {
		t.Fatal("no served counter rows collected. Is the test running from go/nl6?")
	}
	return rows
}

func servedCounterDigest(rows []servedCounterRow, keep func(servedCounterRow) bool) (string, []string) {
	lines := make([]string, 0, len(rows))
	for _, r := range rows {
		if keep != nil && !keep(r) {
			continue
		}
		lines = append(lines, r.String())
	}
	sort.Strings(lines)
	sum := sha256.New()
	for _, l := range lines {
		sum.Write([]byte(l))
		sum.Write([]byte{'\n'})
	}
	return hex.EncodeToString(sum.Sum(nil)), lines
}

func reportDigestMismatch(t *testing.T, name, want, got string, lines []string) {
	t.Helper()
	t.Errorf("%s = %s, want %s (%d rows). First rows:\n%s", name, got, want, len(lines),
		strings.Join(lines[:min(len(lines), 12)], "\n"))
}

// TestShippedServedCounterDigest pins what every shipped profile serves for
// every dial-derived counter column at the fixed instants.
func TestShippedServedCounterDigest(t *testing.T) {
	rows := shippedServedCounterRows(t)
	got, lines := servedCounterDigest(rows, nil)
	if got != shippedServedCounterDigest {
		reportDigestMismatch(t, "shippedServedCounterDigest", shippedServedCounterDigest, got, lines)
	}
	gotUp, upLines := servedCounterDigest(rows, func(r servedCounterRow) bool { return r.SeedUp })
	if gotUp != shippedServedCounterDigestUpOnly {
		reportDigestMismatch(t, "shippedServedCounterDigestUpOnly", shippedServedCounterDigestUpOnly, gotUp, upLines)
	}
	gotSA, saLines := servedCounterDigest(rows, func(r servedCounterRow) bool { return r.SeedUp && r.Class == "standalone" })
	if gotSA != shippedServedCounterDigestStandaloneUp {
		reportDigestMismatch(t, "shippedServedCounterDigestStandaloneUp", shippedServedCounterDigestStandaloneUp, gotSA, saLines)
	}
	if len(saLines) == len(upLines) {
		t.Fatalf("every up interface is standalone: the standalone digest then pins nothing about the roll-up")
	}
	if len(upLines) == len(lines) {
		t.Fatalf("every shipped interface seeds up: the up-only digest is then the full digest and pins nothing about the hold")
	}
}

// shippedSeededNotUp is every shipped interface whose derived oper-status at
// engine construction is not up(1) under the default scenario, the exact set
// the counter hold moves in the default fleet: 100 interfaces in 5 profiles.
// The hold's full digest differs from shippedServedCounterDigestBeforeHold at
// these rows and nowhere else, which TestServedCounterDigestMovedOnlyAtSeededDownRows
// checks row by row rather than by count.
var shippedSeededNotUp = map[string][]int{
	"asr9k.json":            {44, 45},
	"cisco_asr9902.json":    {15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 35, 36, 41, 42, 43, 44, 45, 46, 47, 48},
	"cisco_nexus_9500.json": {3, 4, 5, 6, 7, 8, 9, 10, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64},
	"juniper_mx960.json":    {2, 5, 7, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43, 46, 49, 52, 55, 58, 61, 64, 67, 70, 73, 76, 79},
	"palo_alto_pa3220.json": {2},
}

func TestServedCounterDigestMovedOnlyAtSeededDownRows(t *testing.T) {
	if shippedServedCounterDigest == shippedServedCounterDigestBeforeHold {
		t.Fatal("the pinned digest equals the pre-hold one; the hold moves 100 interfaces and a correct pin cannot match")
	}
	rows := shippedServedCounterRows(t)
	got := map[string][]int{}
	seen := map[string]bool{}
	base := map[string]string{}
	for _, r := range rows {
		key := r.Profile + "\t" + strconv.Itoa(r.IfIndex)
		if !r.SeedUp && !seen[key] {
			seen[key] = true
			got[r.Profile] = append(got[r.Profile], r.IfIndex)
		}
		if r.SeedUp {
			continue
		}
		// A seeded-down row holds at its t=0 value at every instant.
		k := key + "\t" + r.OID
		if r.T == 0 {
			base[k] = r.Value
			continue
		}
		if want := base[k]; r.Value != want {
			t.Errorf("%s: held row reads %s at t=%g, want %s", k, r.Value, r.T, want)
		}
	}
	for p := range got {
		sort.Ints(got[p])
	}
	if !reflect.DeepEqual(got, shippedSeededNotUp) {
		t.Errorf("seeded non-up set = %v, want %v", got, shippedSeededNotUp)
	}
}
