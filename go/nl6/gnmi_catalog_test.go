/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

func readTestCatalog(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/gnmi/catalog_min.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func TestParseGnmiCatalog_Valid(t *testing.T) {
	cat, err := parseGnmiCatalog(readTestCatalog(t), "catalog_min.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cat.Vendor != "testvendor" || len(cat.Subtrees) != 3 {
		t.Fatalf("unexpected catalogue: vendor=%q subtrees=%d", cat.Vendor, len(cat.Subtrees))
	}
	if got := len(cat.Subtrees[0].elems); got != 2 {
		t.Fatalf("subtree 0 compiled elems = %d, want 2", got)
	}
	if cat.Subtrees[0].elems[1].Key["name"] != "*" {
		t.Fatalf("wildcard key not preserved: %v", cat.Subtrees[0].elems[1].Key)
	}
	if !cat.acceptsEncoding(gnmipb.Encoding_PROTO) || !cat.acceptsEncoding(gnmipb.Encoding_JSON) || cat.acceptsEncoding(gnmipb.Encoding_JSON_IETF) {
		t.Fatalf("encoding acceptance wrong")
	}
	if got := cat.components("temperature", ""); len(got) != 1 || got[0].Name != "FPC0" {
		t.Fatalf("temperature filter = %v", got)
	}
}

func TestParseGnmiCatalog_Rejects(t *testing.T) {
	base := string(readTestCatalog(t))
	cases := []struct {
		name, mutate, wantErr string
	}{
		{"unknown field", strings.Replace(base, `"vendor"`, `"vendorr"`, 1), "unknown field"},
		{"duplicate leaf", strings.Replace(base, `{"name": "state/oper-status"`, `{"name": "state/counters/in-octets", "type": "uint64", "gen": "ifcounter:ifHCInOctets"}, {"name": "state/oper-status"`, 1), "duplicate leaf"},
		{"bad key source", strings.Replace(base, `"source": "interfaces"`, `"source": "planets"`, 1), "key source"},
		{"bad prefix mode", strings.Replace(base, `"prefix": "list-entry"`, `"prefix": "sideways"`, 1), "prefix"},
		{"bad encoding", strings.Replace(base, `"PROTO"`, `"XML"`, 1), "encoding"},
		{"empty binding", strings.Replace(base, `"gen": "inventory:serial_no"`, `"gen": ""`, 1), "binding"},
		{"key count mismatch", strings.Replace(base, `"keys": [{"source": "components"}]`, `"keys": []`, 1), "wildcard"},
		{"inventory without components key", strings.Replace(base, `"gen": "ifstate:oper"`, `"gen": "inventory:name"`, 1), "needs a components key source"},
		{"unknown leaf type", strings.Replace(base, `"type": "uint64", "gen": "sine:40,5,600"`, `"type": "float", "gen": "sine:40,5,600"`, 1), "type \"float\""},
		{"empty subtree origin without native origin", strings.Replace(strings.Replace(base, `"native_origin": "testvendor",`, ``, 1), `"origin": "openconfig",
      "keys": [{"source": "components"}]`, `"origin": "",
      "keys": [{"source": "components"}]`, 1), "origin is required"},
		{"alias_leaves without aliases", strings.Replace(base, `"keys": [{"source": "components"}]`, `"alias_leaves": ["state"], "keys": [{"source": "components"}]`, 1), "alias_leaves without aliases scopes nothing"},
		{"alias_leaves covering no leaf", strings.Replace(base, `"keys": [{"source": "components"}]`, `"aliases": ["/testvendor/parts/"], "alias_leaves": ["state/bogus"], "keys": [{"source": "components"}]`, 1), `alias_leaves "state/bogus" covers no leaf`},
		{"alias_leaves root", strings.Replace(base, `"keys": [{"source": "components"}]`, `"aliases": ["/testvendor/parts/"], "alias_leaves": ["/"], "keys": [{"source": "components"}]`, 1), "must be a non-empty leaf path without keys"},
		{"always leaf outside alias_leaves", strings.Replace(strings.Replace(base, `{"name": "state/oper-status", "type": "enumeration"`, `{"name": "state/oper-status", "always": true, "type": "enumeration"`, 1), `"keys": [{"source": "interfaces"}]`, `"aliases": ["/testvendor/ifs/"], "alias_leaves": ["state/counters"], "keys": [{"source": "interfaces"}]`, 1), `always leaf "state/oper-status" is outside alias_leaves`},
		{"alias_only without aliases", strings.Replace(base, `"keys": [{"source": "components"}]`, `"alias_only": true, "keys": [{"source": "components"}]`, 1), "alias_only without aliases is unreachable"},
		{"decimal_encoding on a non-decimal leaf", strings.Replace(base, `"gen": "inventory:serial_no"`, `"gen": "inventory:serial_no", "decimal_encoding": "double"`, 1), "decimal_encoding is for decimal64 leaves, not string"},
		{"unknown leaf decimal_encoding", strings.Replace(base, `"type": "uint64", "gen": "sine:40,5,600"`, `"type": "decimal64", "gen": "sine:40,5,600", "decimal_encoding": "float"`, 1), `decimal_encoding "float"`},
		{"unknown aliased_origin_prefix", strings.Replace(base, `"prefix": "list-entry"`, `"aliased_origin_prefix": "none", "prefix": "list-entry"`, 1), `aliased_origin_prefix "none"`},
		{"aliased_origin_prefix under flat", strings.Replace(base, `"prefix": "list-entry"`, `"aliased_origin_prefix": "empty", "prefix": "flat"`, 1), `aliased_origin_prefix "empty" needs prefix "list-entry"`},
		{"echo_origin with no alias to its origin", strings.Replace(strings.Replace(base, `"prefix": "list-entry"`, `"aliased_origin_prefix": "empty", "prefix": "list-entry"`, 1), `"keys": [{"source": "components"}]`, `"echo_origin": true, "keys": [{"source": "components"}]`, 1), `echo_origin, but no origin_aliases entry maps to "openconfig"`},
		{"echo_origin without an empty aliased prefix", strings.Replace(base, `"keys": [{"source": "components"}]`, `"echo_origin": true, "keys": [{"source": "components"}]`, 1), `echo_origin needs notification.aliased_origin_prefix "empty"`},
		{"wildcard alias", strings.Replace(base, `"keys": [{"source": "components"}]`, `"aliases": ["/testvendor/parts[name=*]/"], "keys": [{"source": "components"}]`, 1), "has a wildcard key"},
		{"malformed alias", strings.Replace(base, `"keys": [{"source": "components"}]`, `"aliases": ["/testvendor/parts[name"], "keys": [{"source": "components"}]`, 1), "unterminated key"},
		{"neighbor without neighbors key", strings.Replace(base, `"gen": "ifstate:oper"`, `"gen": "neighbor:state"`, 1), "needs a neighbors key source"},
		{"leaf filter without components key", strings.Replace(base, `"gen": "ifstate:oper"`, `"gen": "ifstate:oper", "filter": "temperature"`, 1), "filter needs a components key source"},
		{"leaf filter matching nothing", strings.Replace(base, `"gen": "inventory:serial_no"`, `"gen": "inventory:serial_no", "filter": "FAN"`, 1), `filter "FAN" matches no component`},
		{"digits on a non-decimal leaf", strings.Replace(base, `"type": "uint64", "gen": "sine:40,5,600"`, `"type": "uint64", "digits": 1, "gen": "sine:40,5,600"`, 1), "digits is for decimal64 leaves"},
		{"members on a non-union leaf", strings.Replace(base, `"type": "uint64", "gen": "sine:40,5,600"`, `"type": "uint64", "members": ["uint32"], "gen": "sine:40,5,600"`, 1), "members is for union leaves"},
		{"unknown union member", strings.Replace(base, `"type": "uint64", "gen": "sine:40,5,600"`, `"type": "union", "members": ["float"], "gen": "sine:40,5,600"`, 1), `union member "float"`},
		{"digits on a union without a decimal64 member", strings.Replace(base, `"type": "uint64", "gen": "sine:40,5,600"`, `"type": "union", "members": ["uint32", "string"], "digits": 2, "gen": "sine:40,5,600"`, 1), "digits is for decimal64 leaves"},
		{"digits out of range", strings.Replace(base, `"type": "uint64", "gen": "sine:40,5,600"`, `"type": "decimal64", "digits": 19, "gen": "sine:40,5,600"`, 1), "outside YANG's 1..18"},
		{"duplicate component", strings.Replace(base, `{"name": "Chassis"`, `{"name": "FPC0", "type": "CHASSIS", "parent": "", "part_no": "x", "description": "x", "serial_no": "x", "temperature": false}, {"name": "Chassis"`, 1), `"FPC0" listed twice`},
		{"key index past the key sources", strings.Replace(base, `"gen": "inventory:serial_no"`, `"gen": "key:1"`, 1), "key index 1 is outside"},
		{"bad decimal encoding", strings.Replace(base, `"prefix": "list-entry"`, `"decimal_encoding": "float", "prefix": "list-entry"`, 1), `decimal_encoding "float"`},
		{"alias that is a canonical origin", strings.Replace(base, `"prefix": "list-entry"`, `"origin_aliases": {"openconfig": "openconfig"}, "prefix": "list-entry"`, 1), "is a canonical origin, not an alias"},
		{"alias to an unknown origin", strings.Replace(base, `"prefix": "list-entry"`, `"origin_aliases": {"Native": "nokia"}, "prefix": "list-entry"`, 1), `"Native" maps to "nokia", want one of ["openconfig" "testvendor"]`},
		{"parent naming no component", strings.Replace(base, `"keys": [{"source": "components"}]`, `"keys": [{"source": "components", "parent": "FPC9"}]`, 1), `parent "FPC9" names no component`},
		{"parent selecting nothing", strings.Replace(base, `"keys": [{"source": "components"}]`, `"keys": [{"source": "components", "parent": "FPC0"}]`, 1), `parent "FPC0" with filter "" selects no component`},
		{"alias shared across origins", strings.Replace(strings.Replace(base, `"keys": [{"source": "components"}]`, `"aliases": ["/testvendor/shared/"], "keys": [{"source": "components"}]`, 1), `"origin": "openconfig",
      "keys": [{"source": "components", "filter": "temperature"}]`, `"origin": "testvendor", "aliases": ["/testvendor/shared"],
      "keys": [{"source": "components", "filter": "temperature"}]`, 1), `alias "/testvendor/shared" is also listed by a "openconfig" subtree`},
		{"interfaces filter outside the grammar", strings.Replace(base, `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces", "filter": "FAN"}]`, 1), `interfaces filter "FAN": want whitespace-separated terms iftype:<n>[,<n>...], name:<ifDescr>[,...] and !name:<ifDescr>[,...]`},
		{"interfaces filter with a bad iftype", strings.Replace(base, `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces", "filter": "iftype:6,x"}]`, 1), `interfaces filter "iftype:6,x": want`},
		{"interfaces filter with an unknown term", strings.Replace(base, `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces", "filter": "iftype:6 role:mgmt"}]`, 1), `interfaces filter "iftype:6 role:mgmt": want`},
		{"interfaces filter with a repeated term", strings.Replace(base, `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces", "filter": "iftype:6 iftype:24"}]`, 1), `interfaces filter "iftype:6 iftype:24": want`},
		{"interfaces filter with an empty name", strings.Replace(base, `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces", "filter": "name:"}]`, 1), `interfaces filter "name:": want`},
		{"interfaces filter with an empty name in a list", strings.Replace(base, `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces", "filter": "!name:fxp0,"}]`, 1), `interfaces filter "!name:fxp0,": want`},
		{"interfaces filter listing a name twice", strings.Replace(base, `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces", "filter": "!name:fxp0,fxp0"}]`, 1), `interfaces filter "!name:fxp0,fxp0": want`},
		{"interfaces filter listing an iftype twice", strings.Replace(base, `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces", "filter": "iftype:6,6"}]`, 1), `interfaces filter "iftype:6,6": want`},
		{"interfaces filter keeping and dropping one name", strings.Replace(base, `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces", "filter": "name:fxp0,em0 !name:fxp0"}]`, 1), `interfaces filter "name:fxp0,em0 !name:fxp0": "fxp0" is both kept and dropped`},
		{"subinterfaces without an interfaces key before it", strings.Replace(strings.Replace(base, `"path": "/interfaces/interface[name=*]",`, `"path": "/interfaces/interface[name=*]/subinterfaces/subinterface[index=*]",`, 1), `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "static", "names": ["x"]}, {"source": "subinterfaces"}]`, 1), "subinterfaces key source must directly follow an interfaces key source"},
		{"subinterfaces with a filter", strings.Replace(strings.Replace(base, `"path": "/interfaces/interface[name=*]",`, `"path": "/interfaces/interface[name=*]/subinterfaces/subinterface[index=*]",`, 1), `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces"}, {"source": "subinterfaces", "filter": "iftype:6"}]`, 1), "subinterfaces key source takes no filter, names or parent"},
		{"subinterfaces with names", strings.Replace(strings.Replace(base, `"path": "/interfaces/interface[name=*]",`, `"path": "/interfaces/interface[name=*]/subinterfaces/subinterface[index=*]",`, 1), `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces"}, {"source": "subinterfaces", "names": ["100"]}]`, 1), "subinterfaces key source takes no filter, names or parent"},
		{"subinterfaces with a parent", strings.Replace(strings.Replace(base, `"path": "/interfaces/interface[name=*]",`, `"path": "/interfaces/interface[name=*]/subinterfaces/subinterface[index=*]",`, 1), `"keys": [{"source": "interfaces"}]`, `"keys": [{"source": "interfaces"}, {"source": "subinterfaces", "parent": "FPC0"}]`, 1), "subinterfaces key source takes no filter, names or parent"},
		{"leaf filter outside the key filter", strings.Replace(strings.Replace(base, `"keys": [{"source": "components", "filter": "temperature"}]`, `"keys": [{"source": "components", "filter": "CHASSIS"}]`, 1), `"gen": "sine:40,5,600"`, `"gen": "sine:40,5,600", "filter": "temperature"`, 1), `matches no component of this subtree`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseGnmiCatalog([]byte(tc.mutate), "mut.json")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestScanPerTypeGnmiCatalogs_OverridesAndAdds(t *testing.T) {
	dir := t.TempDir()
	for _, slug := range []string{"typea", "typeb"} {
		if err := os.MkdirAll(filepath.Join(dir, slug), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	b := strings.Replace(string(readTestCatalog(t)), `"vendor": "testvendor"`, `"vendor": "fromdir"`, 1)
	if err := os.WriteFile(filepath.Join(dir, "typea", "gnmi.json"), []byte(b), 0o644); err != nil {
		t.Fatal(err)
	}
	embedded, err := parseGnmiCatalog(readTestCatalog(t), "embedded")
	if err != nil {
		t.Fatal(err)
	}
	got, err := scanPerTypeGnmiCatalogs(dir, map[string]*gnmiCatalog{"typea": embedded, "typec": embedded})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got["typea"].Vendor != "fromdir" {
		t.Fatalf("directory file did not override embedded: %q", got["typea"].Vendor)
	}
	if _, ok := got["typec"]; !ok {
		t.Fatalf("embedded-only type lost")
	}
	if _, ok := got["typeb"]; ok {
		t.Fatalf("type without gnmi.json must not appear")
	}
	// A directory with no embedded counterpart still loads.
	if err := os.WriteFile(filepath.Join(dir, "typeb", "gnmi.json"), readTestCatalog(t), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = scanPerTypeGnmiCatalogs(dir, nil)
	if err != nil || got["typeb"] == nil {
		t.Fatalf("new-type catalogue not loaded: %v", err)
	}
}

func TestLoadEmbeddedGnmiCatalogs_ParsesEveryShippedFile(t *testing.T) {
	got, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatalf("embedded catalogues: %v", err)
	}
	for slug, c := range got {
		if strings.HasPrefix(slug, "_") {
			t.Errorf("%s: underscore-prefixed dir must not load", slug)
		}
		if c.Vendor == "" {
			t.Errorf("%s: empty vendor", slug)
		}
	}
}

func TestParseCatalogPath(t *testing.T) {
	elems, err := parseCatalogPath("/components/component[name=*]/properties/property[name=ts-input-packets]/state/value")
	if err != nil {
		t.Fatal(err)
	}
	if len(elems) != 6 || elems[1].Key["name"] != "*" || elems[3].Key["name"] != "ts-input-packets" || elems[5].Name != "value" {
		t.Fatalf("parsed = %v", elems)
	}
	if _, err := parseCatalogPath("components/component[name=*"); err == nil {
		t.Fatal("unterminated key accepted")
	}
	if elems, err := parseCatalogPath("/"); err != nil || len(elems) != 0 {
		t.Fatalf("root path: %v %v", elems, err)
	}
}

// TestLoadGnmiCatalogs_OverrideWinsWhereACatalogueExists: -gnmi-catalog
// replaces the catalogue of every type that has one, a directory file or
// an embedded one, and reaches no other type; without it, directory files
// and embedded catalogues apply per type and other types get none.
func TestLoadGnmiCatalogs_OverrideWinsWhereACatalogueExists(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "typea"), 0o755); err != nil {
		t.Fatal(err)
	}
	fromDir := strings.Replace(string(readTestCatalog(t)), `"vendor": "testvendor"`, `"vendor": "fromdir"`, 1)
	if err := os.WriteFile(filepath.Join(dir, "typea", "gnmi.json"), []byte(fromDir), 0o644); err != nil {
		t.Fatal(err)
	}
	override := filepath.Join(t.TempDir(), "override.json")
	if err := os.WriteFile(override, []byte(strings.Replace(string(readTestCatalog(t)), `"vendor": "testvendor"`, `"vendor": "override"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	devs := map[string]*DeviceSimulator{
		"typea":           {resourceFile: "typea.json"},
		"juniper_mx10004": {resourceFile: "juniper_mx10004.json"},
		"cisco_ios":       {resourceFile: "cisco_ios.json"},
	}

	sm := &SimulatorManager{}
	if err := sm.LoadGnmiCatalogs(override, dir); err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{"typea", "juniper_mx10004"} {
		if c := sm.gnmiCatalogFor(devs[slug]); c == nil || c.Vendor != "override" {
			t.Errorf("override: %s got %v", slug, c)
		}
	}
	// A type with no catalogue of its own gets none from the override: on
	// ciena_waveserver5 a catalogue would shadow the optical resolver.
	if c := sm.gnmiCatalogFor(devs["cisco_ios"]); c != nil {
		t.Errorf("override reached a type without a catalogue: %s", c.Vendor)
	}

	sm = &SimulatorManager{}
	if err := sm.LoadGnmiCatalogs("", dir); err != nil {
		t.Fatal(err)
	}
	if c := sm.gnmiCatalogFor(devs["typea"]); c == nil || c.Vendor != "fromdir" {
		t.Errorf("directory file: got %v", c)
	}
	if c := sm.gnmiCatalogFor(devs["juniper_mx10004"]); c == nil || c.Vendor != "juniper" {
		t.Errorf("embedded: got %v", c)
	}
	if c := sm.gnmiCatalogFor(devs["cisco_ios"]); c != nil {
		t.Errorf("type without a catalogue got %s", c.Vendor)
	}
	if err := sm.LoadGnmiCatalogs(filepath.Join(dir, "missing.json"), dir); err == nil {
		t.Error("missing override file accepted")
	}
}

// twoSubtreeCatalog builds a catalogue with two subtrees at one entry
// path, for the same-path guard. Each subtree is spelled as raw JSON
// fragments for its origin and keys.
func twoSubtreeCatalog(origin1, keys1, origin2, keys2 string) []byte {
	return []byte(`{
  "comment": "same-path guard",
  "vendor": "testvendor",
  "notification": {"origin": "openconfig", "native_origin": "testvendor", "prefix": "list-entry", "encodings": ["PROTO"], "extension": "none"},
  "models": [],
  "components": [
    {"name": "Chassis", "type": "CHASSIS", "parent": "", "part_no": "C", "description": "c", "serial_no": "1", "temperature": false},
    {"name": "FPC0", "type": "LINECARD", "parent": "Chassis", "part_no": "L", "description": "l", "serial_no": "2", "temperature": true}
  ],
  "neighbors": [],
  "subtrees": [
    {"path": "/components/component[name=*]", "origin": "` + origin1 + `", "keys": ` + keys1 + `,
     "leaves": [{"name": "state/description", "type": "string", "gen": "const:a"}]},
    {"path": "/components/component[name=*]", "origin": "` + origin2 + `", "keys": ` + keys2 + `,
     "leaves": [{"name": "state/temperature/instant", "type": "uint64", "gen": "const:40"}]}
  ]
}`)
}

// TestParseGnmiCatalog_SamePathOverlappingKeysRefused is the guard
// for nl6#765: two subtrees of one origin on one entry path whose
// load-resolvable keys intersect render one prefix twice. The first
// two rows are the positive controls that must still load.
func TestParseGnmiCatalog_SamePathOverlappingKeysRefused(t *testing.T) {
	static := func(names string) string { return `[{"source": "static", "names": [` + names + `]}]` }
	cases := []struct {
		name    string
		cat     []byte
		wantErr string // empty = must load
	}{
		{"disjoint static keys load", twoSubtreeCatalog("openconfig", static(`"A", "B"`), "openconfig", static(`"C"`)), ""},
		{"different origin loads", twoSubtreeCatalog("openconfig", static(`"A", "B"`), "testvendor", static(`"B"`)), ""},
		{"overlapping static keys", twoSubtreeCatalog("openconfig", static(`"A", "B"`), "openconfig", static(`"B", "C"`)), `entry "B"`},
		{"components against filtered components", twoSubtreeCatalog("openconfig", `[{"source": "components"}]`, "openconfig", `[{"source": "components", "filter": "temperature"}]`), `entry "FPC0"`},
		{"trailing-slash spelling of one path", []byte(strings.Replace(string(twoSubtreeCatalog("openconfig", static(`"A"`), "openconfig", static(`"A"`))), `"path": "/components/component[name=*]", "origin": "openconfig", "keys": [{"source": "static", "names": ["A"]}],
     "leaves": [{"name": "state/temperature/instant"`, `"path": "/components/component[name=*]/", "origin": "openconfig", "keys": [{"source": "static", "names": ["A"]}],
     "leaves": [{"name": "state/temperature/instant"`, 1)), `entry "A"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseGnmiCatalog(tc.cat, "two.json")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("must load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "subtree 0") || !strings.Contains(err.Error(), "subtree 1") || !strings.Contains(err.Error(), "fold the leaves") {
				t.Fatalf("err = %v, want naming both subtrees, %q and the fold remedy", err, tc.wantErr)
			}
			if strings.Contains(tc.name, "components") != strings.Contains(err.Error(), "leaf filter") {
				t.Fatalf("err = %v: the leaf-filter remedy belongs only to a subtree with a components key", err)
			}
		})
	}
}

// twoInterfaceSubtreeCatalog is a catalogue with two openconfig subtrees
// on one interface entry path, each keyed by the given key list.
func twoInterfaceSubtreeCatalog(path, keys1, keys2 string) []byte {
	return []byte(`{
  "vendor": "testvendor",
  "notification": {"origin": "openconfig", "native_origin": "testvendor", "prefix": "list-entry", "encodings": ["PROTO"], "extension": "none"},
  "subtrees": [
    {"path": "` + path + `", "origin": "openconfig", "keys": ` + keys1 + `,
     "leaves": [{"name": "state/counters/in-octets", "type": "uint64", "gen": "ifcounter:ifHCInOctets"}]},
    {"path": "` + path + `", "origin": "openconfig", "keys": ` + keys2 + `,
     "leaves": [{"name": "state/counters/out-octets", "type": "uint64", "gen": "ifcounter:ifHCOutOctets"}]}
  ]
}`)
}

// TestParseGnmiCatalog_SamePathInterfacePairs: a same-path pair keyed
// on interfaces exists only per device, so load decides it from the
// filters alone. It loads when the filters cannot share an interface
// (disjoint ifType sets, disjoint name lists, a name list inside the
// other's exclusions) or another key position is disjoint, and is
// refused otherwise naming both filters. Before this, such a pair was
// not checked at all and rendered one prefix twice.
func TestParseGnmiCatalog_SamePathInterfacePairs(t *testing.T) {
	ifs := func(filter string) string {
		if filter == "" {
			return `{"source": "interfaces"}`
		}
		return `{"source": "interfaces", "filter": "` + filter + `"}`
	}
	const entry = "/interfaces/interface[name=*]"
	const subif = "/interfaces/interface[name=*]/subinterfaces/subinterface[index=*]/state/counters"
	const queue = "/interfaces/interface[name=*]/state/counters/out-queue[queue-number=*]"
	cases := []struct {
		name    string
		cat     []byte
		wantErr string // empty = must load
	}{
		{"split by name loads", twoInterfaceSubtreeCatalog(entry, "["+ifs("iftype:6 !name:fxp0")+"]", "["+ifs("name:fxp0")+"]"), ""},
		{"split by name in either order loads", twoInterfaceSubtreeCatalog(entry, "["+ifs("name:fxp0,em0")+"]", "["+ifs("!name:em0,fxp0,lo0")+"]"), ""},
		{"split by ifType loads", twoInterfaceSubtreeCatalog(subif, "["+ifs("iftype:6")+`, {"source": "subinterfaces"}]`, "["+ifs("iftype:161")+`, {"source": "subinterfaces"}]`), ""},
		{"disjoint name lists load", twoInterfaceSubtreeCatalog(entry, "["+ifs("name:fxp0")+"]", "["+ifs("name:em0")+"]"), ""},
		{"disjoint static key beside one interface filter loads", twoInterfaceSubtreeCatalog(queue, "["+ifs("iftype:6")+`, {"source": "static", "names": ["0", "1"]}]`, "["+ifs("iftype:6")+`, {"source": "static", "names": ["2"]}]`), ""},
		{"ifType against a name", twoInterfaceSubtreeCatalog(entry, "["+ifs("iftype:6")+"]", "["+ifs("name:fxp0")+"]"), `interfaces filters "iftype:6" and "name:fxp0"`},
		{"unfiltered against a filter", twoInterfaceSubtreeCatalog(entry, "["+ifs("")+"]", "["+ifs("iftype:6")+"]"), `interfaces filters "" and "iftype:6"`},
		{"overlapping ifType sets", twoInterfaceSubtreeCatalog(subif, "["+ifs("iftype:6,161")+`, {"source": "subinterfaces"}]`, "["+ifs("iftype:161")+`, {"source": "subinterfaces"}]`), `interfaces filters "iftype:6,161" and "iftype:161"`},
		{"exclusion short of the name list", twoInterfaceSubtreeCatalog(entry, "["+ifs("name:fxp0,em0")+"]", "["+ifs("iftype:6 !name:fxp0")+"]"), `interfaces filters "name:fxp0,em0" and "iftype:6 !name:fxp0"`},
		{"interfaces keys at different positions", twoInterfaceSubtreeCatalog(queue, "["+ifs("iftype:6")+`, {"source": "static", "names": ["0"]}]`, `[{"source": "static", "names": ["0"]}, `+ifs("iftype:24")+"]"), `interfaces keys at positions 0 and 1`},
		{"overlapping static key beside one interface filter", twoInterfaceSubtreeCatalog(queue, "["+ifs("iftype:6")+`, {"source": "static", "names": ["0", "1"]}]`, "["+ifs("iftype:6")+`, {"source": "static", "names": ["1"]}]`), `interfaces filters "iftype:6" and "iftype:6"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseGnmiCatalog(tc.cat, "two.json")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("must load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "subtree 0 and subtree 1") || !strings.Contains(err.Error(), "disjoint") {
				t.Fatalf("err = %v, want naming both subtrees, %s and disjointness as the remedy", err, tc.wantErr)
			}
		})
	}
}

// TestParseGnmiCatalog_ParentScopesComponentsKey: a `parent` on a
// components key source keys the subtree on one component's children
// (nl6#767), narrowed further by the filter, and the same-path guard
// sees the scoped set.
func TestParseGnmiCatalog_ParentScopesComponentsKey(t *testing.T) {
	data := strings.Replace(string(readTestCatalog(t)), `"keys": [{"source": "components"}]`, `"keys": [{"source": "components", "parent": "Chassis", "filter": "temperature"}]`, 1)
	cat, err := parseGnmiCatalog([]byte(data), "parent")
	if err != nil {
		t.Fatal(err)
	}
	vals, ok := cat.keyValues(cat.Subtrees[1].Keys[0])
	if !ok || len(vals) != 1 || vals[0] != "FPC0" {
		t.Fatalf("parent-scoped key values = %v, want [FPC0]", vals)
	}
	chassisOnly := cat.components("", "")
	if len(chassisOnly) != 2 {
		t.Fatalf("unscoped components = %d, want 2", len(chassisOnly))
	}
	// Scoped against a same-path subtree keyed by the same child: the
	// guard must see the overlap through the parent scope.
	_, err = parseGnmiCatalog(twoSubtreeCatalog("openconfig", `[{"source": "components", "parent": "Chassis"}]`, "openconfig", `[{"source": "static", "names": ["FPC0"]}]`), "guard")
	if err == nil || !strings.Contains(err.Error(), `entry "FPC0"`) {
		t.Fatalf("overlap through a parent scope not refused: %v", err)
	}
}

// digits is allowed on a union whose members include decimal64: the
// cast hands them to that member (nl6#807).
func TestParseGnmiCatalog_UnionDigits(t *testing.T) {
	base := string(readTestCatalog(t))
	ok := strings.Replace(base, `"type": "uint64", "gen": "sine:40,5,600"`, `"type": "union", "members": ["uint32", "decimal64"], "digits": 3, "gen": "sine:40,5,600"`, 1)
	if _, err := parseGnmiCatalog([]byte(ok), "union.json"); err != nil {
		t.Fatal(err)
	}
}
