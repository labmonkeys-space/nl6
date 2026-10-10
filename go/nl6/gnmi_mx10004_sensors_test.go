/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// TestMX10004FabricSensor covers nl6#767: the fabric sensor alias
// resolves to both direction subtrees and renders under the prefix
// hardware shows, with one notification per edge and class.
func TestMX10004FabricSensor(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	for _, origin := range []string{"Native", "juniper", "junos-fabric", ""} {
		resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, origin, "/junos/system/linecard/fabric/")
		if err != nil {
			t.Fatalf("origin %q: %v", origin, err)
		}
		edges := map[string]bool{}
		n := 0
		for _, r := range resps {
			u := r.GetUpdate()
			if u == nil {
				continue
			}
			n++
			if u.GetPrefix().GetOrigin() != "juniper" {
				t.Fatalf("origin %q: prefix origin %q", origin, u.GetPrefix().GetOrigin())
			}
			elems := u.GetPrefix().GetElem()
			if len(elems) != 6 || elems[0].Name != "junos" || elems[1].Name != "fabric-statistics" || elems[3].Name != "edges" || elems[4].Name != "class-stats" || elems[5].Name != "transmit-counts" {
				t.Fatalf("origin %q: prefix %s", origin, pathToString(u.GetPrefix()))
			}
			k := elems[3].Key
			if len(k) != 6 {
				t.Fatalf("edges carries %d keys, want 6: %v", len(k), k)
			}
			st, dt := k["src-type"], k["dst-type"]
			if !(st == "LINECARD" && dt == "SWITCH-FABRIC") && !(st == "SWITCH-FABRIC" && dt == "LINECARD") {
				t.Fatalf("edge types %q -> %q", st, dt)
			}
			if pr := elems[4].Key["priority"]; pr != "high" && pr != "low" {
				t.Fatalf("priority %q", pr)
			}
			edges[pathToString(u.GetPrefix())] = true
			if len(u.GetUpdate()) != 14 {
				t.Fatalf("%s: %d updates, want 14", pathToString(u.GetPrefix()), len(u.GetUpdate()))
			}
			for _, up := range u.GetUpdate() {
				if _, ok := up.GetVal().GetValue().(*gnmipb.TypedValue_UintVal); !ok {
					t.Fatalf("%s/%s is not uint64: %v", pathToString(u.GetPrefix()), pathToString(up.GetPath()), up.GetVal())
				}
			}
		}
		if n != 96 || len(edges) != 96 {
			t.Fatalf("origin %q: %d notifications over %d distinct prefixes, want 96 (48 edges x 2 classes)", origin, n, len(edges))
		}
	}
}

// TestMX10004FabricCountersMonotonic resolves one edge an hour apart.
func TestMX10004FabricCountersMonotonic(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 1), cats["juniper_mx10004"])
	p := pathFromString(t, "/junos/fabric-statistics/fabric-message/edges[dst-pfe=0][dst-slot=3][dst-type=SWITCH-FABRIC][src-pfe=2][src-slot=0][src-type=LINECARD]/class-stats[priority=low]/transmit-counts")
	p.Origin = "juniper"
	read := func(at time.Time) map[string]uint64 {
		got, err := r.Resolve(p, at)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("%d notifications for one edge", len(got))
		}
		out := map[string]uint64{}
		for _, u := range got[0].Updates {
			v, ok := u.Value.(uint64)
			if !ok {
				t.Fatalf("%s is %T, want uint64", pathToString(u.Path), u.Value)
			}
			out[pathToString(u.Path)] = v
		}
		return out
	}
	now := time.Now()
	a, b := read(now), read(now.Add(time.Hour))
	for _, leaf := range []string{"/packets", "/bytes"} {
		if b[leaf] <= a[leaf] {
			t.Fatalf("%s did not advance: %d then %d", leaf, a[leaf], b[leaf])
		}
	}
	for _, leaf := range []string{"/drop-packets", "/drop-bytes", "/drop-packets-per-second", "/drop-bytes-per-second", "/error-packets", "/error-packets-per-second"} {
		if a[leaf] != 0 || b[leaf] != 0 {
			t.Fatalf("%s is %d/%d, want 0", leaf, a[leaf], b[leaf])
		}
	}
}

// TestMX10004FpcEnvironment covers the YANG-derived environment
// sensor: one power record, one temperature record per FPC0 sensor in
// the inventory and the voltage rails, each record naming itself.
func TestMX10004FpcEnvironment(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "juniper", "/junos/system/linecard/environment/")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, r := range resps {
		u := r.GetUpdate()
		if u == nil {
			continue
		}
		elems := u.GetPrefix().GetElem()
		if len(elems) != 5 || elems[2].Key["name"] != "FPC0" || elems[3].Name != "environment" {
			t.Fatalf("prefix %s", pathToString(u.GetPrefix()))
		}
		rec := elems[4]
		counts[rec.Name]++
		vals := map[string]*gnmipb.TypedValue{}
		for _, up := range u.GetUpdate() {
			vals[pathToString(up.GetPath())] = up.GetVal()
		}
		switch rec.Name {
		case "power-record":
			if vals["/fpc-power"].GetUintVal() > vals["/max-fpc-power"].GetUintVal() {
				t.Fatalf("fpc-power %d above max-fpc-power %d", vals["/fpc-power"].GetUintVal(), vals["/max-fpc-power"].GetUintVal())
			}
		case "temp-record":
			if got := vals["/temp-sensor-name"].GetStringVal(); got != rec.Key["temp-sensor-name"] {
				t.Fatalf("temp-sensor-name %q under key %q", got, rec.Key["temp-sensor-name"])
			}
			if vals["/temp-value"].GetUintVal() == 0 {
				t.Fatalf("temp-value missing on %s", pathToString(u.GetPrefix()))
			}
		case "voltage-record":
			if got := vals["/voltage-sensor-name"].GetStringVal(); got != rec.Key["voltage-sensor-name"] {
				t.Fatalf("voltage-sensor-name %q under key %q", got, rec.Key["voltage-sensor-name"])
			}
		default:
			t.Fatalf("unexpected record %s", rec.Name)
		}
	}
	if counts["power-record"] != 1 || counts["temp-record"] != 36 || counts["voltage-record"] != 5 {
		t.Fatalf("records = %v, want 1 power, 36 temperature, 5 voltage", counts)
	}
}
