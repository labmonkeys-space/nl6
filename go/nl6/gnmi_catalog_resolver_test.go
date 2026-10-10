/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
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

func TestCatalogResolver_AliasServesWholeSubtree(t *testing.T) {
	data := strings.Replace(string(readTestCatalog(t)), `"keys": [{"source": "components", "filter": "temperature"}]`,
		`"aliases": ["/testvendor/temps/"], "keys": [{"source": "components", "filter": "temperature"}]`, 1)
	data = strings.Replace(data, `"origin": "openconfig",
      "aliases"`, `"origin": "testvendor",
      "aliases"`, 1)
	cat, err := parseGnmiCatalog([]byte(data), "alias")
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 1), cat)
	for _, origin := range []string{"", "testvendor"} {
		p := pathFromString(t, "/testvendor/temps")
		p.Origin = origin
		if !r.Match(p) {
			t.Fatalf("origin %q: alias not matched", origin)
		}
		got, err := r.Resolve(p, time.Now())
		if err != nil {
			t.Fatalf("origin %q: %v", origin, err)
		}
		if len(got) != 1 || pathToString(got[0].Prefix) != "/components/component[name=FPC0]/state/temperature" || got[0].Prefix.GetOrigin() != "testvendor" || len(got[0].Updates) != 1 {
			t.Fatalf("origin %q: got %v", origin, got)
		}
	}
	p := pathFromString(t, "/testvendor/temps")
	p.Origin = "openconfig"
	if r.Match(p) {
		t.Error("alias matched under another origin")
	}
	if r.Match(pathFromString(t, "/testvendor/temps/instant")) {
		t.Error("a path below an alias must not match")
	}
}

// TestCatalogResolver_LeafFilter: a filtered leaf rides inside the
// matching components' notifications and is absent from the rest, so
// one subtree serves every component with one notification each.
func TestCatalogResolver_LeafFilter(t *testing.T) {
	cat, err := parseGnmiCatalog([]byte(`{
  "comment": "leaf filter", "vendor": "testvendor",
  "notification": {"origin": "openconfig", "native_origin": "", "prefix": "list-entry", "encodings": ["PROTO"], "extension": "none"},
  "models": [], "neighbors": [],
  "components": [
    {"name": "Chassis", "type": "CHASSIS", "parent": "", "part_no": "C", "description": "c", "serial_no": "1", "temperature": false},
    {"name": "FPC0", "type": "LINECARD", "parent": "Chassis", "part_no": "L", "description": "l", "serial_no": "2", "temperature": true},
    {"name": "FPC1", "type": "LINECARD", "parent": "Chassis", "part_no": "L", "description": "l", "serial_no": "3", "temperature": false},
    {"name": "RE0", "type": "CONTROLLER_CARD", "parent": "Chassis", "part_no": "R", "description": "r", "serial_no": "4", "temperature": true},
    {"name": "Fan 0", "type": "FAN", "parent": "Chassis", "part_no": "F", "description": "f", "serial_no": "5", "temperature": false}
  ],
  "subtrees": [{"path": "/components/component[name=*]", "origin": "openconfig", "keys": [{"source": "components"}],
    "leaves": [
      {"name": "state/serial-no", "type": "string", "gen": "inventory:serial_no"},
      {"name": "state/temperature/instant", "type": "uint64", "gen": "const:40", "filter": "temperature"},
      {"name": "state/fan-speed", "type": "uint32", "gen": "const:3000", "filter": "FAN"}
    ]}]
}`), "filter.json")
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 1), cat)
	got, err := r.Resolve(pathFromString(t, "/components"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("notifications = %d, want 5 (one per component)", len(got))
	}
	want := map[string]string{"Chassis": "serial-no", "FPC0": "serial-no,temperature", "FPC1": "serial-no", "RE0": "serial-no,temperature", "Fan 0": "serial-no,fan-speed"}
	for _, n := range got {
		name := n.Prefix.Elem[1].Key["name"]
		var leaves []string
		for _, u := range n.Updates {
			el := u.Path.Elem
			leaves = append(leaves, el[len(el)-1].Name)
			if el[len(el)-1].Name == "instant" {
				leaves[len(leaves)-1] = "temperature"
			}
		}
		if got := strings.Join(leaves, ","); got != want[name] {
			t.Errorf("%s: leaves %q, want %q", name, got, want[name])
		}
	}
}

// TestCatalogResolver_SerialPerDevice: two MX10004 devices at different
// addresses report different component serials, and one device's
// components differ among themselves (nl6#769).
func TestCatalogResolver_SerialPerDevice(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	serial := func(ip, component string) string {
		dev := newTestGnmiDevice(t, 1)
		dev.IP = net.ParseIP(ip)
		r := newCatalogResolver(dev, cats["juniper_mx10004"])
		got, err := r.Resolve(pathFromString(t, "/components/component[name="+component+"]/state/serial-no"), time.Now())
		if err != nil || len(got) != 1 || len(got[0].Updates) != 1 {
			t.Fatalf("%s %s: %v %v", ip, component, err, got)
		}
		return got[0].Updates[0].Value.(string)
	}
	a, b := serial("10.42.1.7", "FPC0"), serial("10.42.1.8", "FPC0")
	if a == b || !strings.HasPrefix(a, "NL6FPC") {
		t.Fatalf("two devices: %s vs %s", a, b)
	}
	if m0, m1 := serial("10.42.1.7", "FPC0:MEZZ0"), serial("10.42.1.7", "FPC0:MEZZ1"); m0 == m1 {
		t.Fatalf("two components of one device share %s", m0)
	}
}

// TestCatalogResolver_DecimalWireForm: a catalogue that declares
// decimal_encoding: decimal_val gets gNMI's Decimal64 message at the
// leaf's fraction-digits under PROTO; the default keeps double_val.
func TestCatalogResolver_DecimalWireForm(t *testing.T) {
	mk := func(notif string) *catalogResolver {
		cat, err := parseGnmiCatalog([]byte(`{
  "comment": "decimal", "vendor": "testvendor",
  "notification": {"origin": "openconfig", "native_origin": "", "prefix": "list-entry", "encodings": ["PROTO"], "extension": "none"`+notif+`},
  "models": [], "neighbors": [],
  "components": [{"name": "FPC0", "type": "LINECARD", "parent": "", "part_no": "L", "description": "l", "serial_no": "1", "temperature": true}],
  "subtrees": [{"path": "/components/component[name=*]", "origin": "openconfig", "keys": [{"source": "components"}],
    "leaves": [{"name": "state/temperature/instant", "type": "decimal64", "digits": 1, "gen": "const:38.25"}]}]
}`), "dec.json")
		if err != nil {
			t.Fatal(err)
		}
		return newCatalogResolver(newTestGnmiDevice(t, 1), cat)
	}
	encodeOne := func(r *catalogResolver) *gnmipb.TypedValue {
		got, err := r.Resolve(pathFromString(t, "/components"), time.Now())
		if err != nil || len(got) != 1 {
			t.Fatalf("%v %v", err, got)
		}
		ups, err := encodeUpdates(got[0].Updates, gnmipb.Encoding_PROTO)
		if err != nil || len(ups) != 1 {
			t.Fatalf("%v %v", err, ups)
		}
		return ups[0].GetVal()
	}
	if tv := encodeOne(mk(``)); tv.GetDoubleVal() != 38.25 {
		t.Fatalf("default form: %v", tv)
	}
	tv := encodeOne(mk(`, "decimal_encoding": "decimal_val"`))
	if d := tv.GetDecimalVal(); d == nil || d.GetPrecision() != 1 || d.GetDigits() != 382 { //nolint:staticcheck // gNMI deprecates Decimal64; Junos still sends it (nl6#772) (half-to-even, as the JSON forms round)
		t.Fatalf("decimal_val form: %v", tv)
	}
}

// TestCatalogResolver_AlwaysLeaf: an always-leaf rides along whenever
// another leaf of its entry is covered, and never on its own.
func TestCatalogResolver_AlwaysLeaf(t *testing.T) {
	cat, err := parseGnmiCatalog([]byte(`{
  "comment": "always", "vendor": "testvendor",
  "notification": {"origin": "openconfig", "native_origin": "", "prefix": "list-entry", "encodings": ["PROTO"], "extension": "none"},
  "models": [], "neighbors": [],
  "components": [{"name": "FPC0", "type": "LINECARD", "parent": "", "part_no": "L", "description": "l", "serial_no": "1", "temperature": false}],
  "subtrees": [{"path": "/components/component[name=*]", "origin": "openconfig", "keys": [{"source": "components"}],
    "leaves": [
      {"name": "name", "type": "string", "gen": "key:0", "always": true},
      {"name": "state/serial-no", "type": "string", "gen": "inventory:serial_no"},
      {"name": "state/description", "type": "string", "gen": "inventory:description"}
    ]}]
}`), "always.json")
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 1), cat)
	leaves := func(path string) []string {
		got, err := r.Resolve(pathFromString(t, path), time.Now())
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		var out []string
		for _, u := range got[0].Updates {
			out = append(out, pathToString(u.Path))
		}
		sort.Strings(out)
		return out
	}
	if got := leaves("/components/component/state/serial-no"); strings.Join(got, ",") != "/name,/state/serial-no" {
		t.Fatalf("covered sibling: %v", got)
	}
	if got := leaves("/components/component/name"); strings.Join(got, ",") != "/name" {
		t.Fatalf("always-leaf alone: %v", got)
	}
	if _, err := r.Resolve(pathFromString(t, "/components/component/nothing"), time.Now()); status.Code(err) != codes.NotFound {
		t.Fatalf("uncovered entry must not render the always-leaf: %v", err)
	}
}
