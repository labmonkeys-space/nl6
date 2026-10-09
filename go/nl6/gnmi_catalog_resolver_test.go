/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sort"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newTestCatalogResolver(t *testing.T) *catalogResolver {
	t.Helper()
	cat, err := parseGnmiCatalog(readTestCatalog(t), "min")
	if err != nil {
		t.Fatal(err)
	}
	return newCatalogResolver(newTestGnmiDevice(t, 2), cat)
}

func pathWithOrigin(t *testing.T, origin, s string) *gnmipb.Path {
	t.Helper()
	p := pathFromString(t, s)
	p.Origin = origin
	return p
}

func TestCatalogResolver_Match(t *testing.T) {
	r := newTestCatalogResolver(t)
	yes := []string{"/interfaces", "/interfaces/interface", "/interfaces/interface[name=*]/state/counters", "/interfaces/interface[name=TestIf1]/state/oper-status", "/components/component[name=FPC0]/state/temperature/instant"}
	no := []string{"/system", "/interfaces/interface[name=TestIf1]/state/counters/out-octets"}
	for _, s := range yes {
		if !r.Match(pathFromString(t, s)) {
			t.Errorf("%s: want match", s)
		}
	}
	for _, s := range no {
		if r.Match(pathFromString(t, s)) {
			t.Errorf("%s: want no match", s)
		}
	}
}

func TestCatalogResolver_ResolveSubtreeGroupsPerEntry(t *testing.T) {
	r := newTestCatalogResolver(t)
	got, err := r.Resolve(pathFromString(t, "/interfaces/interface/state/counters"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("notifications = %d, want 2 (one per interface)", len(got))
	}
	for _, n := range got {
		if ps := pathToString(n.Prefix); !strings.HasPrefix(ps, "/interfaces/interface[name=TestIf") || n.Prefix.Origin != "openconfig" {
			t.Errorf("prefix = %s origin=%q", ps, n.Prefix.Origin)
		}
		if len(n.Updates) != 1 || pathToString(n.Updates[0].Path) != "/state/counters/in-octets" {
			t.Errorf("updates = %v", n.Updates)
		}
		if _, ok := n.Updates[0].Value.(uint64); !ok {
			t.Errorf("in-octets value %T, want uint64", n.Updates[0].Value)
		}
	}
}

func TestCatalogResolver_KeyNarrowing(t *testing.T) {
	r := newTestCatalogResolver(t)
	got, err := r.Resolve(pathFromString(t, "/interfaces/interface[name=TestIf2]"), time.Now())
	if err != nil || len(got) != 1 || len(got[0].Updates) != 2 {
		t.Fatalf("got %v err %v", got, err)
	}
	_, err = r.Resolve(pathFromString(t, "/interfaces/interface[name=Nope]/state"), time.Now())
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown key: %v, want NotFound", err)
	}
	got, err = r.Resolve(pathFromString(t, "/components/component/state/temperature"), time.Now())
	if err != nil || len(got) != 1 || pathToString(got[0].Prefix) != "/components/component[name=FPC0]/state/temperature" {
		t.Fatalf("temperature filter: %v err %v", got, err)
	}
	// Match is shape-only, so Chassis passes it; Resolve applies the
	// temperature filter and finds no entry.
	_, err = r.Resolve(pathFromString(t, "/components/component[name=Chassis]/state/temperature"), time.Now())
	if status.Code(err) != codes.NotFound {
		t.Fatalf("filtered-out component: %v, want NotFound", err)
	}
}

func TestCatalogResolver_Origins(t *testing.T) {
	r := newTestCatalogResolver(t)
	if _, err := r.Resolve(pathWithOrigin(t, "openconfig", "/components"), time.Now()); err != nil {
		t.Fatalf("openconfig origin: %v", err)
	}
	_, err := r.Resolve(pathWithOrigin(t, "cisco", "/components"), time.Now())
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("foreign origin: %v, want InvalidArgument", err)
	}
	if r.Match(pathWithOrigin(t, "testvendor", "/components")) {
		t.Fatal("native origin must not match an openconfig subtree")
	}
}

func TestCatalogResolver_NoCyclerIsUnavailable(t *testing.T) {
	cat, _ := parseGnmiCatalog(readTestCatalog(t), "min")
	r := newCatalogResolver(&DeviceSimulator{ID: "bare"}, cat)
	_, err := r.Resolve(pathFromString(t, "/interfaces"), time.Now())
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("got %v, want Unavailable", err)
	}
}

func TestCatalogResolver_FlatPrefixMode(t *testing.T) {
	src := strings.Replace(string(readTestCatalog(t)), `"prefix": "list-entry"`, `"prefix": "flat"`, 1)
	cat, err := parseGnmiCatalog([]byte(src), "flat")
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 1), cat)
	got, err := r.Resolve(pathFromString(t, "/interfaces/interface/state/counters"), time.Now())
	if err != nil || len(got) != 1 || got[0].Prefix != nil {
		t.Fatalf("flat: %v err %v", got, err)
	}
	if ps := pathToString(got[0].Updates[0].Path); ps != "/interfaces/interface[name=TestIf1]/state/counters/in-octets" {
		t.Fatalf("flat update path = %s", ps)
	}
}

func TestCatalogResolver_AllLeafPathsAndModels(t *testing.T) {
	r := newTestCatalogResolver(t)
	paths := r.AllLeafPaths()
	sort.Strings(paths)
	want := []string{
		"/components/component[name=*]/state/serial-no",
		"/components/component[name=*]/state/temperature/instant",
		"/interfaces/interface[name=*]/state/counters/in-octets",
		"/interfaces/interface[name=*]/state/oper-status",
	}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("leaf paths = %v", paths)
	}
	if m := r.Models(); len(m) != 1 || m[0].Name != "openconfig-interfaces" || m[0].Version != "3.11.1" {
		t.Fatalf("models = %v", m)
	}
}
