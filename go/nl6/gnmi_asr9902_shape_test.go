/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// xrFixture is a reduced hardware fixture: wildcarded prefixes and the
// JSON class each leaf showed.
type xrFixture struct {
	Prefixes []string `json:"prefixes"`
	Leaves   []struct {
		Path  string `json:"path"`
		Class string `json:"class"`
	} `json:"leaves"`
}

// xrSubscriptions is the origin and path gnmic subscribed to per fixture.
var xrSubscriptions = map[string][2]string{
	"if-counters": {"openconfig-interfaces", "/interfaces/interface/state/counters"},
	"subif":       {"openconfig-interfaces", "/interfaces/interface/subinterfaces/subinterface/state/counters"},
	"components":  {"openconfig-platform", "/components/component/state"},
	"sys-cpu":     {"openconfig-system", "/system/cpus/cpu/state"},
	"sys-mem":     {"openconfig-system", "/system/memory/state"},
}

// kindsForClass are the PROTO TypedValue kinds a JSON class admits.
var kindsForClass = map[string][]string{
	"integer": {"uint", "int", "decimal", "double"}, "fraction": {"decimal", "double"},
	"string": {"string"}, "bool": {"bool"},
}

func classAdmits(class, kind string) bool {
	for _, c := range strings.Split(class, "|") {
		if slices.Contains(kindsForClass[c], kind) {
			return true
		}
	}
	return false
}

// TestASR9902ShapeMatchesCapture subscribes ONCE in PROTO to each fixture's
// path with the module origin gnmic used and requires the served leaf set,
// prefix forms and value classes to equal the fixture's.
func TestASR9902ShapeMatchesCapture(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	cat := cats["cisco_asr9902"]
	if cat == nil {
		t.Fatal("embedded cisco_asr9902 catalogue missing")
	}
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, cat, 4)
	defer cleanup()
	files, _ := filepath.Glob("testdata/gnmi/cisco_asr9902/*-hardware.json")
	if len(files) != len(xrSubscriptions) {
		t.Fatalf("%d fixtures, want %d", len(files), len(xrSubscriptions))
	}
	for _, f := range files {
		stem := strings.TrimSuffix(filepath.Base(f), "-hardware.json")
		t.Run(stem, func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var fx xrFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				t.Fatal(err)
			}
			sub := xrSubscriptions[stem]
			resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, sub[0], sub[1])
			if err != nil {
				t.Fatal(err)
			}
			gotLeaves, gotPrefixes := map[string]string{}, map[string]bool{}
			for _, r := range resps {
				n := r.GetUpdate()
				if n == nil {
					continue
				}
				pfx := wildcardKeys(pathToString(n.GetPrefix()))
				gotPrefixes[n.GetPrefix().GetOrigin()+":"+pfx] = true
				for _, u := range n.GetUpdate() {
					full := strings.TrimSuffix(pfx, "/") + "/" + strings.TrimPrefix(wildcardKeys(pathToString(u.GetPath())), "/")
					gotLeaves[full] = typedValueKind(u.GetVal(), gnmipb.Encoding_PROTO)
				}
			}
			var problems []string
			want := map[string]bool{}
			for _, l := range fx.Leaves {
				want[l.Path] = true
				switch k, ok := gotLeaves[l.Path]; {
				case !ok:
					problems = append(problems, "missing "+l.Path)
				case !classAdmits(l.Class, k):
					problems = append(problems, "kind "+k+" outside class "+l.Class+": "+l.Path)
				}
			}
			for l := range gotLeaves {
				if !want[l] {
					problems = append(problems, "extra "+l)
				}
			}
			for p := range gotPrefixes {
				if !slices.Contains(fx.Prefixes, p) {
					problems = append(problems, "prefix "+p+" not in the fixture")
				}
			}
			for _, p := range fx.Prefixes {
				if !gotPrefixes[p] {
					problems = append(problems, "fixture prefix "+p+" never served")
				}
			}
			sort.Strings(problems)
			if len(problems) > 0 {
				t.Fatalf("%d shape differences:\n  %s", len(problems), strings.Join(problems, "\n  "))
			}
		})
	}
}

// A request with no origin, or with the canonical one, reaches the same
// subtrees and is also answered with the module origin.
func TestASR9902OriginlessRequestsGetModuleOrigin(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, cats["cisco_asr9902"], 2)
	defer cleanup()
	for _, origin := range []string{"", "openconfig"} {
		resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, origin, "/system/memory/state")
		if err != nil {
			t.Fatalf("origin %q: %v", origin, err)
		}
		seen := 0
		for _, r := range resps {
			if n := r.GetUpdate(); n != nil {
				seen++
				if got := n.GetPrefix().GetOrigin(); got != "openconfig-system" {
					t.Errorf("origin %q: prefix origin %q, want openconfig-system", origin, got)
				}
			}
		}
		if seen == 0 {
			t.Errorf("origin %q: no notification", origin)
		}
	}
}
