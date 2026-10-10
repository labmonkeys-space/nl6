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
	if got := cat.components("temperature"); len(got) != 1 || got[0].Name != "FPC0" {
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
		{"wildcard alias", strings.Replace(base, `"keys": [{"source": "components"}]`, `"aliases": ["/testvendor/parts[name=*]/"], "keys": [{"source": "components"}]`, 1), "has a wildcard key"},
		{"malformed alias", strings.Replace(base, `"keys": [{"source": "components"}]`, `"aliases": ["/testvendor/parts[name"], "keys": [{"source": "components"}]`, 1), "unterminated key"},
		{"neighbor without neighbors key", strings.Replace(base, `"gen": "ifstate:oper"`, `"gen": "neighbor:state"`, 1), "needs a neighbors key source"},
		{"leaf filter without components key", strings.Replace(base, `"gen": "ifstate:oper"`, `"gen": "ifstate:oper", "filter": "temperature"`, 1), "filter needs a components key source"},
		{"leaf filter matching nothing", strings.Replace(base, `"gen": "inventory:serial_no"`, `"gen": "inventory:serial_no", "filter": "FAN"`, 1), `filter "FAN" matches no component`},
		{"bad decimal encoding", strings.Replace(base, `"prefix": "list-entry"`, `"decimal_encoding": "float", "prefix": "list-entry"`, 1), `decimal_encoding "float"`},
		{"alias that is a canonical origin", strings.Replace(base, `"prefix": "list-entry"`, `"origin_aliases": {"openconfig": "openconfig"}, "prefix": "list-entry"`, 1), "is a canonical origin, not an alias"},
		{"alias to an unknown origin", strings.Replace(base, `"prefix": "list-entry"`, `"origin_aliases": {"Native": "nokia"}, "prefix": "list-entry"`, 1), `"Native" maps to "nokia", want one of ["openconfig" "testvendor"]`},
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

// TestLoadGnmiCatalogs_OverrideWinsEverywhere: -gnmi-catalog replaces
// every type's catalogue, including a directory file and the embedded
// set; without it, directory files and embedded catalogues apply per
// type and other types get none.
func TestLoadGnmiCatalogs_OverrideWinsEverywhere(t *testing.T) {
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
	for slug, d := range devs {
		if c := sm.gnmiCatalogFor(d); c == nil || c.Vendor != "override" {
			t.Errorf("override: %s got %v", slug, c)
		}
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
