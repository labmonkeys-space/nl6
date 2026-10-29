/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// TestPathCoversSplitAgreesWithJoined: the split cover answers exactly as
// pathCovers does over the joined path, at every request length around
// the prefix/leaf boundary, with and without wildcard keys.
func TestPathCoversSplitAgreesWithJoined(t *testing.T) {
	prefix := pathFromString(t, "/components/component[name=FPC0]").Elem
	leaf := pathFromString(t, "state/temperature/instant").Elem
	joined := append(append([]*gnmipb.PathElem{}, prefix...), leaf...)
	reqs := []string{
		"/", "/components", "/components/component", "/components/component[name=*]",
		"/components/component[name=FPC0]", "/components/component[name=FPC1]",
		"/components/component[name=FPC0]/state", "/components/component[name=*]/state/temperature",
		"/components/component[name=FPC0]/state/temperature/instant",
		"/components/component[name=FPC0]/state/temperature/instant/extra",
		"/components/component[name=FPC0]/state/nope", "/interfaces",
	}
	// joinedCover is the rule spelled out once more over the joined path,
	// so the test does not pin pathCoversSplit against itself.
	joinedCover := func(q, c []*gnmipb.PathElem) bool {
		if len(q) > len(c) {
			return false
		}
		for i := range q {
			if !elemMatches(q[i], c[i]) {
				return false
			}
		}
		return true
	}
	// Three splits of the same joined path: at the boundary the resolver
	// uses, after one element, and before any element. The keyed element
	// then sits in the prefix, the leaf, or the leaf again.
	splits := []struct {
		name         string
		prefix, leaf []*gnmipb.PathElem
	}{
		{"entry/leaf", prefix, leaf},
		{"one-element prefix", joined[:1], joined[1:]},
		{"empty prefix", nil, joined},
		{"empty leaf", joined, nil},
	}
	for _, r := range reqs {
		q := pathFromString(t, r).Elem
		want := joinedCover(q, joined)
		for _, sp := range splits {
			if got := pathCoversSplit(q, sp.prefix, sp.leaf); got != want {
				t.Errorf("%s, %s: split %v, joined %v", r, sp.name, got, want)
			}
		}
		if got := pathCovers(q, joined); got != want {
			t.Errorf("%s: pathCovers %v, joined %v", r, got, want)
		}
	}
	// A keyed element inside the leaf half: the request must mismatch on
	// that key alone.
	kp := pathFromString(t, "/components/component[name=FPC0]").Elem
	kl := pathFromString(t, "subcomponents/subcomponent[name=X]/state/name").Elem
	if !pathCoversSplit(pathFromString(t, "/components/component[name=FPC0]/subcomponents/subcomponent[name=X]/state").Elem, kp, kl) {
		t.Error("matching key in the leaf half refused")
	}
	if pathCoversSplit(pathFromString(t, "/components/component[name=FPC0]/subcomponents/subcomponent[name=Y]/state").Elem, kp, kl) {
		t.Error("mismatching key in the leaf half accepted")
	}
}

// leafCountCatalog builds a catalogue whose one subtree carries n const
// leaves per component entry, the first of them state/description.
func leafCountCatalog(t *testing.T, n int) *gnmiCatalog {
	t.Helper()
	leaves := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := "state/description"
		if i > 0 {
			name = fmt.Sprintf("state/extra-%d", i)
		}
		leaves = append(leaves, fmt.Sprintf(`{"name": %q, "type": "string", "gen": "const:x"}`, name))
	}
	cat, err := parseGnmiCatalog([]byte(`{
  "comment": "leaf count", "vendor": "testvendor",
  "notification": {"origin": "openconfig", "native_origin": "", "prefix": "list-entry", "encodings": ["PROTO"], "extension": "none"},
  "models": [], "neighbors": [],
  "components": [
    {"name": "Chassis", "type": "CHASSIS", "parent": "", "part_no": "C", "description": "c", "serial_no": "1", "temperature": false},
    {"name": "FPC0", "type": "LINECARD", "parent": "Chassis", "part_no": "L", "description": "l", "serial_no": "2", "temperature": false}
  ],
  "subtrees": [{"path": "/components/component[name=*]", "origin": "openconfig", "keys": [{"source": "components"}],
    "leaves": [`+strings.Join(leaves, ",")+`]}]
}`), "leaves.json")
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// TestCatalogResolver_UncoveredLeavesAllocateNothing: a request that covers
// one leaf of an entry costs the same whatever the number of leaves the
// entry carries, because the cover test no longer joins prefix and leaf
// for every leaf it rejects.
func TestCatalogResolver_UncoveredLeavesAllocateNothing(t *testing.T) {
	dev := newTestGnmiDevice(t, 1)
	req := pathFromString(t, "/components/component[name=*]/state/description")
	allocs := func(n int) float64 {
		r := newCatalogResolver(dev, leafCountCatalog(t, n))
		now := time.Now()
		return testing.AllocsPerRun(200, func() {
			if _, err := r.Resolve(req, now); err != nil {
				t.Fatal(err)
			}
		})
	}
	a4, a16 := allocs(4), allocs(16)
	if a16 != a4 {
		t.Fatalf("allocations per tick grew with the leaf count: %v at 4 leaves, %v at 16", a4, a16)
	}
}
