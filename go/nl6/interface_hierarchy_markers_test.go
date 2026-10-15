/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"log"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// captureHierarchyLog routes the package logger into a buffer and clears the
// once-per-process dedupe, so a line an earlier test already triggered is
// seen again here. Without the reset a test asserting "no line" passes on
// the dedupe rather than on the rule.
func captureHierarchyLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var sink bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&sink)
	hierarchyLogged = sync.Map{}
	t.Cleanup(func() {
		log.SetOutput(prev)
		hierarchyLogged = sync.Map{}
	})
	return &sink
}

// RFC 2863 keeps at least two ifStackStatus rows per interface: 0.<I> when
// nothing runs over I and <I>.0 when I runs over nothing. Neither is a
// stacking, neither is an unknown ifIndex, and neither is worth a log line.
func TestReadStackLayersMarkerRowsAreSilent(t *testing.T) {
	sink := captureHierarchyLog(t)
	known := map[int]bool{41: true, 42: true, 43: true}
	got := readStackLayers([]SNMPResource{
		{OID: "1.3.6.1.2.1.31.1.2.1.3.41.0", Response: "1"},  // 41 over nothing
		{OID: "1.3.6.1.2.1.31.1.2.1.3.0.42", Response: "1"},  // nothing over 42
		{OID: "1.3.6.1.2.1.31.1.2.1.3.42.41", Response: "1"}, // 42 over 41
		{OID: "1.3.6.1.2.1.31.1.2.1.3.43.0", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.0.43", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.43.77", Response: "1"}, // a real unknown lower layer
	}, known)
	if want := map[int]int{42: 41}; !reflect.DeepEqual(got.parents, want) {
		t.Errorf("parents = %v, want %v", got.parents, want)
	}
	if len(got.members) != 0 {
		t.Errorf("members = %v, want none", got.members)
	}
	lines := strings.Split(strings.TrimSpace(sink.String()), "\n")
	var unknown []string
	for _, l := range lines {
		if strings.Contains(l, "unknown lower layer") {
			unknown = append(unknown, l)
		}
	}
	if len(unknown) != 1 || !strings.Contains(unknown[0], "row 43.77") {
		t.Errorf("unknown-lower-layer lines = %q, want exactly one naming row 43.77", unknown)
	}
}

// A marker row is not counted as a row of its higher layer: a child that
// also carries <I>.0 (a profile defect) stays a child, and an aggregate that
// also carries <A>.0 stays an aggregate. Counting it would demote the child
// to top-level through the "rows of which N resolve" branch.
func TestReadStackLayersMarkerDoesNotDemote(t *testing.T) {
	captureHierarchyLog(t)
	known := map[int]bool{51: true, 52: true, 53: true, 54: true}
	got := readStackLayers([]SNMPResource{
		{OID: "1.3.6.1.2.1.31.1.2.1.3.52.51", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.52.0", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.54.51", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.54.53", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.54.0", Response: "1"},
	}, known)
	if want := map[int]int{52: 51}; !reflect.DeepEqual(got.parents, want) {
		t.Errorf("parents = %v, want %v", got.parents, want)
	}
	if want := map[int][]int{54: {51, 53}}; !reflect.DeepEqual(got.members, want) {
		t.Errorf("members = %v, want %v", got.members, want)
	}
}

// The shipped nokia_7750_sr12 carries the marker rows for all 73 of its
// interfaces; before the rule above each one was reported as an unknown
// lower layer at the first device of the type.
func TestNokiaMarkerRowsLogNothing(t *testing.T) {
	sink := captureHierarchyLog(t)
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("nokia_7750_sr12.json")
	if err != nil {
		t.Fatal(err)
	}
	known := map[int]bool{}
	for _, e := range res.SNMP {
		if rest, ok := strings.CutPrefix(strings.TrimPrefix(e.OID, "."), "1.3.6.1.2.1.31.1.1.1.6."); ok {
			var idx int
			for _, c := range rest {
				idx = idx*10 + int(c-'0')
			}
			known[idx] = true
		}
	}
	if len(known) < 70 {
		t.Fatalf("nokia_7750_sr12 serves %d ifXTable rows, expected its 70+ interfaces", len(known))
	}
	layers := readStackLayers(res.SNMP, known)
	if layers.parents[73] != 1 {
		t.Errorf("toWAN parent = %v, want port 1/1/1 (ifIndex 1)", layers.parents[73])
	}
	if n := strings.Count(sink.String(), "unknown lower layer"); n != 0 {
		t.Errorf("%d unknown-lower-layer lines for marker rows, want 0; first: %s", n, strings.SplitN(sink.String(), "\n", 2)[0])
	}
}
