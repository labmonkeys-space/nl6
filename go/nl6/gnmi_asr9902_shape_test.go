/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// xrFixture is a reduced hardware fixture: wildcarded prefixes, the JSON
// class each leaf showed and whether every notification of its prefixes
// carried it.
type xrFixture struct {
	Prefixes []string `json:"prefixes"`
	Leaves   []struct {
		Path   string `json:"path"`
		Class  string `json:"class"`
		Always bool   `json:"always"`
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

// classProblems compares the kinds a leaf was served with against its
// fixture class. Every served kind must be admitted. A union class
// (`integer|string`) must also have each of its classes observed at
// least once, or a leaf that only ever sends one member passes (nl6#807).
func classProblems(class string, kinds map[string]bool) []string {
	var problems []string
	for k := range kinds {
		if !classAdmits(class, k) {
			problems = append(problems, "kind "+k+" outside class "+class)
		}
	}
	if strings.Contains(class, "|") {
		for _, c := range strings.Split(class, "|") {
			seen := false
			for k := range kinds {
				seen = seen || classAdmits(c, k)
			}
			if !seen {
				problems = append(problems, "class "+c+" of "+class+" never served")
			}
		}
	}
	return problems
}

// TestASR9902ShapeMatchesCapture subscribes ONCE in PROTO to each fixture's
// path with the module origin gnmic used, on a device with the shipped
// cisco_asr9902 interfaces, and requires the served leaf set, prefix forms,
// value classes and always flags to equal the fixture's. A leaf is always
// when every notification of the prefixes it appears under carries it, as
// go/cmd/gnmi-shape reduces it.
func TestASR9902ShapeMatchesCapture(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	cat := cats["cisco_asr9902"]
	if cat == nil {
		t.Fatal("embedded cisco_asr9902 catalogue missing")
	}
	_, _, addr, cleanup := startTestGnmiServerWithDevice(t, cat, newASR9902Device(t))
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
			gotLeaves, gotPrefixes := map[string]map[string]bool{}, map[string]int{}
			leafSeen, leafPrefixes := map[string]int{}, map[string]map[string]bool{}
			for _, r := range resps {
				n := r.GetUpdate()
				if n == nil {
					continue
				}
				pfx := wildcardKeys(pathToString(n.GetPrefix()))
				pkey := n.GetPrefix().GetOrigin() + ":" + pfx
				gotPrefixes[pkey]++
				seen := map[string]bool{}
				for _, u := range n.GetUpdate() {
					full := strings.TrimSuffix(pfx, "/") + "/" + strings.TrimPrefix(wildcardKeys(pathToString(u.GetPath())), "/")
					if gotLeaves[full] == nil {
						gotLeaves[full] = map[string]bool{}
					}
					gotLeaves[full][typedValueKind(u.GetVal(), gnmipb.Encoding_PROTO)] = true
					if !seen[full] {
						seen[full] = true
						leafSeen[full]++
						if leafPrefixes[full] == nil {
							leafPrefixes[full] = map[string]bool{}
						}
						leafPrefixes[full][pkey] = true
					}
				}
			}
			var problems []string
			want := map[string]bool{}
			for _, l := range fx.Leaves {
				want[l.Path] = true
				kinds, ok := gotLeaves[l.Path]
				if !ok {
					problems = append(problems, "missing "+l.Path)
					continue
				}
				for _, p := range classProblems(l.Class, kinds) {
					problems = append(problems, p+": "+l.Path)
				}
				total := 0
				for p := range leafPrefixes[l.Path] {
					total += gotPrefixes[p]
				}
				if (leafSeen[l.Path] == total) != l.Always {
					problems = append(problems, fmt.Sprintf("always %v, fixture %v: %s", leafSeen[l.Path] == total, l.Always, l.Path))
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
				if gotPrefixes[p] == 0 {
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

// The catalogue owns only the interface subscriptions the reference
// capture verified. A broader interface request is answered by the
// resolver every device type has, so it keeps the state leaves and
// ON_CHANGE it served before the catalogue existed.
func TestASR9902BroaderInterfaceRequestsKeepState(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, cats["cisco_asr9902"], 2)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "openconfig-interfaces", "/interfaces/interface/state")
	if err != nil {
		t.Fatal(err)
	}
	oper := false
	for _, r := range resps {
		n := r.GetUpdate()
		for _, u := range n.GetUpdate() {
			full := pathToString(n.GetPrefix()) + "/" + pathToString(u.GetPath())
			if strings.HasSuffix(full, "/oper-status") {
				oper = true
			}
		}
	}
	if !oper {
		t.Error("ONCE /interfaces/interface/state served no oper-status")
	}

	// ON_CHANGE gets the shared resolver's answers, not the catalogue's
	// refusal: a state leaf streams, and the whole state container is
	// refused because it holds counters, as on every type.
	for _, c := range []struct {
		path string
		want codes.Code
	}{
		{"/interfaces/interface/state/oper-status", codes.OK},
		{"/interfaces/interface/state", codes.InvalidArgument},
	} {
		conn := dialTestGnmi(t, addr)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err := gnmipb.NewGNMIClient(conn).Subscribe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = stream.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
			Mode: gnmipb.SubscriptionList_STREAM, Encoding: gnmipb.Encoding_PROTO,
			Subscription: []*gnmipb.Subscription{{Path: pathFromString(t, c.path), Mode: gnmipb.SubscriptionMode_ON_CHANGE}},
		}}})
		_, err = stream.Recv()
		if got := status.Code(err); got != c.want {
			t.Errorf("ON_CHANGE %s: %v, want %v", c.path, err, c.want)
		}
		cancel()
		conn.Close()
	}
}
