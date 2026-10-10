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
		{"neighbor without neighbors key", strings.Replace(base, `"gen": "ifstate:oper"`, `"gen": "neighbor:state"`, 1), "needs a neighbors key source"},
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
	// A directory with no embedded counterpart still loads (Review Focus 2).
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
	// Until Task 8 ships juniper_mx10004 this may be empty; the loader
	// must still succeed.
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
