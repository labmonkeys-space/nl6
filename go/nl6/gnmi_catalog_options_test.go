/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// minCatalogWith loads testdata/gnmi/catalog_min.json, applies edit to its
// decoded form and parses the result.
func minCatalogWith(t *testing.T, edit func(m map[string]any)) (*gnmiCatalog, error) {
	t.Helper()
	b, err := os.ReadFile("testdata/gnmi/catalog_min.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return parseGnmiCatalog(out, "test")
}

func setModuleOrigin(m map[string]any, module string) {
	m["notification"].(map[string]any)["response_origin"] = "module"
	for _, st := range m["subtrees"].([]any) {
		st.(map[string]any)["module"] = module
	}
}

// IOS-XR answers with the subtree's YANG module as the prefix origin,
// whatever origin the request carried.
func TestResponseOriginModule(t *testing.T) {
	cat, err := minCatalogWith(t, func(m map[string]any) { setModuleOrigin(m, "openconfig-interfaces") })
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(nil, cat)
	st := cat.Subtrees[0]
	for _, req := range []string{"", "openconfig", "openconfig-interfaces"} {
		if got := r.prefixOrigin(req, "openconfig", st); got != "openconfig-interfaces" {
			t.Errorf("request origin %q: prefix origin %q, want openconfig-interfaces", req, got)
		}
	}
}

func TestResponseOriginModuleRefusals(t *testing.T) {
	for _, c := range []struct {
		name, want string
		edit       func(m map[string]any)
	}{
		{"subtree without module", "module", func(m map[string]any) {
			setModuleOrigin(m, "openconfig-interfaces")
			delete(m["subtrees"].([]any)[0].(map[string]any), "module")
		}},
		{"with aliased_origin_prefix empty", "aliased_origin_prefix", func(m map[string]any) {
			setModuleOrigin(m, "openconfig-interfaces")
			m["notification"].(map[string]any)["aliased_origin_prefix"] = "empty"
		}},
		{"unknown value", "response_origin", func(m map[string]any) {
			m["notification"].(map[string]any)["response_origin"] = "subtree"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := minCatalogWith(t, c.edit); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error naming %q", err, c.want)
			}
		})
	}
}

// Without the option nothing changes: the canonical origin answers.
func TestResponseOriginDefaultIsCanonical(t *testing.T) {
	cat, err := minCatalogWith(t, func(map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	if got := newCatalogResolver(nil, cat).prefixOrigin("", "openconfig", cat.Subtrees[0]); got != "openconfig" {
		t.Fatalf("prefix origin %q, want openconfig", got)
	}
}

// A tag:<name> filter selects the components carrying that tag, so a leaf
// group present on some components of a type is served on exactly those.
func TestTagFilterSelectsTaggedComponents(t *testing.T) {
	cat, err := minCatalogWith(t, func(m map[string]any) {
		cs := m["components"].([]any)
		cs[0].(map[string]any)["tags"] = []any{"firmware-version"}
	})
	if err != nil {
		t.Fatal(err)
	}
	got := cat.components("tag:firmware-version", "")
	if len(got) != 1 || got[0].Name != cat.Components[0].Name {
		t.Fatalf("tag filter selected %v, want only %s", got, cat.Components[0].Name)
	}
	if len(cat.components("tag:absent", "")) != 0 {
		t.Fatal("a tag no component carries selected something")
	}
}

func setJSONIETFLayout(m map[string]any, layout string) {
	n := m["notification"].(map[string]any)
	n["json_ietf_layout"] = layout
	n["encodings"] = []any{"PROTO", "JSON_IETF"}
}

func TestJSONIETFLayoutAccepted(t *testing.T) {
	for _, layout := range []string{"", "leaf", "container"} {
		cat, err := minCatalogWith(t, func(m map[string]any) { setJSONIETFLayout(m, layout) })
		if err != nil {
			t.Fatalf("layout %q: %v", layout, err)
		}
		if got := cat.jsonIETFContainer(); got != (layout == "container") {
			t.Errorf("layout %q: jsonIETFContainer() = %v", layout, got)
		}
	}
}

// container would load and do nothing without a list-entry prefix or
// without JSON_IETF in encodings, so both are refused.
func TestJSONIETFLayoutRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(m map[string]any)
	}{
		{"unknown value", func(m map[string]any) { setJSONIETFLayout(m, "nested") }},
		{"container without list-entry", func(m map[string]any) {
			setJSONIETFLayout(m, "container")
			m["notification"].(map[string]any)["prefix"] = "flat"
		}},
		{"container without JSON_IETF", func(m map[string]any) {
			setJSONIETFLayout(m, "container")
			m["notification"].(map[string]any)["encodings"] = []any{"PROTO", "JSON"}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := minCatalogWith(t, c.edit); err == nil || !strings.Contains(err.Error(), "json_ietf_layout") {
				t.Fatalf("got %v, want an error naming json_ietf_layout", err)
			}
		})
	}
}
