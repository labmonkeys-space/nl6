/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sort"
	"strconv"
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
	yes := []string{"/interfaces", "/interfaces/interface", "/interfaces/interface[name=*]", "/interfaces/interface[name=TestIf1]/state/oper-status", "/components/component[name=FPC0]/state/temperature/instant"}
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

func TestCatalogResolver_IfIndexFromCycler(t *testing.T) {
	d := newTestGnmiDevice(t, 2)
	cat, err := parseGnmiCatalog(readTestCatalog(t), "min")
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(d, cat)
	ic := d.metricsCycler.ifCounters.Load()
	now := ic.startTime.Add(5 * time.Second)
	got, err := r.Resolve(pathFromString(t, "/interfaces/interface/state/counters"), now)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v err %v", got, err)
	}
	vals := map[string]uint64{}
	for _, n := range got {
		vals[pathToString(n.Prefix)] = n.Updates[0].Value.(uint64)
	}
	for idx, name := range map[int]string{1: "TestIf1", 2: "TestIf2"} {
		want := ic.GetDynamicAt(ifXTablePrefix+"6."+strconv.Itoa(idx), 5)
		if v := strconv.FormatUint(vals["/interfaces/interface[name="+name+"]"], 10); v != want {
			t.Errorf("%s in-octets = %s, want %s (ifIndex %d)", name, v, want, idx)
		}
	}
	if len(vals) == 2 && vals["/interfaces/interface[name=TestIf1]"] == vals["/interfaces/interface[name=TestIf2]"] {
		t.Error("both interfaces returned the same value")
	}
}

func TestCatalogResolver_IfIndexNotFirstKeySource(t *testing.T) {
	src := string(readTestCatalog(t))
	old := `"path": "/interfaces/interface[name=*]",
      "origin": "openconfig",
      "keys": [{"source": "interfaces"}],`
	if !strings.Contains(src, old) {
		t.Fatal("fixture changed")
	}
	src = strings.Replace(src, old, `"path": "/grp/g[id=*]/interfaces/interface[name=*]",
      "origin": "openconfig",
      "keys": [{"source": "static", "names": ["g1"]}, {"source": "interfaces"}],`, 1)
	cat, err := parseGnmiCatalog([]byte(src), "order")
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 2), cat)
	got, err := r.Resolve(pathFromString(t, "/grp/g/interfaces/interface/state/counters"), time.Now())
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v err %v", got, err)
	}
	for _, n := range got {
		if len(n.Updates) != 1 {
			t.Fatalf("interface leaf missing (ifIndex 0?): %v", n.Updates)
		}
	}
}

func TestParseGnmiCatalog_TwoInterfacesKeySources(t *testing.T) {
	src := string(readTestCatalog(t))
	old := `"path": "/interfaces/interface[name=*]",
      "origin": "openconfig",
      "keys": [{"source": "interfaces"}],`
	src = strings.Replace(src, old, `"path": "/a/x[id=*]/interface[name=*]",
      "origin": "openconfig",
      "keys": [{"source": "interfaces"}, {"source": "interfaces"}],`, 1)
	_, err := parseGnmiCatalog([]byte(src), "dup")
	if err == nil || !strings.Contains(err.Error(), "at most one interfaces key source") {
		t.Fatalf("err = %v", err)
	}
}

// keyPositionCatalog puts the neighbour and component key sources after
// static keys, the way the BGP subtree does.
const keyPositionCatalog = `{
  "vendor": "testvendor",
  "notification": {"origin": "openconfig", "prefix": "list-entry", "encodings": ["PROTO"], "extension": "none"},
  "components": [{"name": "FPC0", "type": "LINECARD", "serial_no": "SN000002"}],
  "neighbors": [{"address": "203.0.113.1", "peer_as": 64496, "local_as": 64500, "state": "ESTABLISHED"}],
  "subtrees": [
    {
      "path": "/network-instances/network-instance[name=*]/protocols/protocol[identifier=*][name=*]/bgp/neighbors/neighbor[neighbor-address=*]",
      "origin": "openconfig",
      "keys": [{"source": "static", "names": ["DEFAULT"]}, {"source": "static", "names": ["BGP"]}, {"source": "static", "names": ["DEFAULT"]}, {"source": "neighbors"}],
      "leaves": [
        {"name": "state/neighbor-address", "type": "union", "gen": "neighbor:address"},
        {"name": "state/peer-as", "type": "uint32", "gen": "neighbor:peer_as"},
        {"name": "state/session-state", "type": "string", "gen": "neighbor:state"}
      ]
    },
    {
      "path": "/slots/slot[id=*]/component[name=*]",
      "origin": "openconfig",
      "keys": [{"source": "static", "names": ["0"]}, {"source": "components"}],
      "leaves": [{"name": "serial-no", "type": "string", "gen": "inventory:serial_no"}]
    }
  ]
}`

func TestCatalogResolver_NeighborAndComponentKeyPosition(t *testing.T) {
	cat, err := parseGnmiCatalog([]byte(keyPositionCatalog), "keypos")
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 1), cat)
	got, err := r.Resolve(pathFromString(t, "/network-instances"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d notifications, want 1", len(got))
	}
	vals := map[string]any{}
	for _, u := range got[0].Updates {
		vals[pathToString(u.Path)] = u.Value
	}
	want := map[string]any{
		"/state/neighbor-address": "203.0.113.1",
		"/state/peer-as":          uint32(64496),
		"/state/session-state":    "ESTABLISHED",
	}
	for p, w := range want {
		if vals[p] != w {
			t.Errorf("%s = %v, want %v", p, vals[p], w)
		}
	}
	got, err = r.Resolve(pathFromString(t, "/slots"), time.Now())
	if err != nil || len(got) != 1 || len(got[0].Updates) != 1 || got[0].Updates[0].Value != "SN000002" {
		t.Fatalf("component behind a static key: %v %v", got, err)
	}
}
