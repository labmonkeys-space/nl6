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

// TestMX10004FabricSensor covers nl6#767 and nl6#785: the fabric sensor
// alias resolves to all three edge subtrees and follows the hardware
// edge rule. Line-card-to-line-card edges carry class-stats[priority];
// switch fabric edges use a keyless class-stats and name only slot 0,
// PFE 0.
func TestMX10004FabricSensor(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	for _, origin := range []string{"Native", "juniper", "junos-fabric", ""} {
		resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, origin, "/junos/system/linecard/fabric/")
		if err != nil {
			t.Fatalf("origin %q: %v", origin, err)
		}
		edges := map[string]bool{}
		linecard, toFabric, fromFabric := 0, 0, 0
		for _, r := range resps {
			u := r.GetUpdate()
			if u == nil {
				continue
			}
			if u.GetPrefix().GetOrigin() != "juniper" {
				t.Fatalf("origin %q: prefix origin %q", origin, u.GetPrefix().GetOrigin())
			}
			elems := u.GetPrefix().GetElem()
			if len(elems) != 6 || elems[0].Name != "junos" || elems[1].Name != "fabric-statistics" || elems[3].Name != "edges" || elems[4].Name != "class-stats" || elems[5].Name != "transmit-counts" {
				t.Fatalf("origin %q: prefix %s", origin, pathToString(u.GetPrefix()))
			}
			name := pathToString(u.GetPrefix())
			k := elems[3].Key
			if len(k) != 6 {
				t.Fatalf("%s: edges carries %d keys, want 6", name, len(k))
			}
			st, dt := k["src-type"], k["dst-type"]
			pr, keyed := elems[4].Key["priority"]
			switch {
			case st == "LINECARD" && dt == "LINECARD":
				if !keyed || len(elems[4].Key) != 1 || (pr != "high" && pr != "low") {
					t.Fatalf("%s: line-card edge needs priority high or low", name)
				}
				linecard++
			case st == "LINECARD" && dt == "SWITCH-FABRIC", st == "SWITCH-FABRIC" && dt == "LINECARD":
				if len(elems[4].Key) != 0 {
					t.Fatalf("%s: switch fabric edge carries class-stats keys", name)
				}
				side := "dst"
				if st == "SWITCH-FABRIC" {
					side = "src"
				}
				if k[side+"-slot"] != "0" || k[side+"-pfe"] != "0" {
					t.Fatalf("%s: switch fabric side is not slot 0, PFE 0", name)
				}
				if side == "src" {
					fromFabric++
				} else {
					toFabric++
				}
			default:
				t.Fatalf("%s: edge types %q -> %q", name, st, dt)
			}
			edges[name] = true
			if len(u.GetUpdate()) != 14 {
				t.Fatalf("%s: %d updates, want 14", name, len(u.GetUpdate()))
			}
			for _, up := range u.GetUpdate() {
				if _, ok := up.GetVal().GetValue().(*gnmipb.TypedValue_UintVal); !ok {
					t.Fatalf("%s/%s is not uint64: %v", name, pathToString(up.GetPath()), up.GetVal())
				}
			}
		}
		if linecard != 32 || toFabric != 4 || fromFabric != 4 || len(edges) != 40 {
			t.Fatalf("origin %q: %d line-card, %d to and %d from switch fabric notifications over %d distinct prefixes, want 32 + 4 + 4 = 40", origin, linecard, toFabric, fromFabric, len(edges))
		}
	}
}

// TestMX10004FabricCountersMonotonic resolves one edge of each fabric
// subtree an hour apart: keyed line card, keyless to and from the
// switch fabric.
func TestMX10004FabricCountersMonotonic(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 1), cats["juniper_mx10004"])
	for _, edge := range []string{
		"/junos/fabric-statistics/fabric-message/edges[dst-pfe=3][dst-slot=0][dst-type=LINECARD][src-pfe=2][src-slot=0][src-type=LINECARD]/class-stats[priority=low]/transmit-counts",
		"/junos/fabric-statistics/fabric-message/edges[dst-pfe=0][dst-slot=0][dst-type=SWITCH-FABRIC][src-pfe=2][src-slot=0][src-type=LINECARD]/class-stats/transmit-counts",
		"/junos/fabric-statistics/fabric-message/edges[dst-pfe=1][dst-slot=0][dst-type=LINECARD][src-pfe=0][src-slot=0][src-type=SWITCH-FABRIC]/class-stats/transmit-counts",
	} {
		p := pathFromString(t, edge)
		p.Origin = "juniper"
		read := func(at time.Time) map[string]uint64 {
			got, err := r.Resolve(p, at)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("%s: %d notifications for one edge", edge, len(got))
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
				t.Fatalf("%s %s did not advance: %d then %d", edge, leaf, a[leaf], b[leaf])
			}
		}
		for _, leaf := range []string{"/drop-packets", "/drop-bytes", "/drop-packets-per-second", "/drop-bytes-per-second", "/error-packets", "/error-packets-per-second"} {
			if a[leaf] != 0 || b[leaf] != 0 {
				t.Fatalf("%s %s is %d/%d, want 0", edge, leaf, a[leaf], b[leaf])
			}
		}
	}
}

// TestMX10004FpcEnvironment covers the YANG-derived environment
// sensor: one power record, one temperature record per FPC0 sensor in
// the inventory and the voltage rails, each record naming itself.
func TestMX10004FpcEnvironment(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	for _, origin := range []string{"juniper", "Native", "junos-fpc-env", ""} {
		checkFpcEnvironment(t, addr, origin)
	}
}

func checkFpcEnvironment(t *testing.T, addr, origin string) {
	t.Helper()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, origin, "/junos/system/linecard/environment/")
	if err != nil {
		t.Fatalf("origin %q: %v", origin, err)
	}
	counts := map[string]int{}
	railValues := map[uint64]bool{}
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
			railValues[vals["/voltage-value"].GetUintVal()/100] = true
		default:
			t.Fatalf("unexpected record %s", rec.Name)
		}
	}
	if counts["power-record"] != 1 || counts["temp-record"] != 36 || counts["voltage-record"] != 5 {
		t.Fatalf("origin %q: records = %v, want 1 power, 36 temperature, 5 voltage", origin, counts)
	}
	// Each rail sits near its nominal voltage, so no two share a value.
	if len(railValues) != 5 {
		t.Fatalf("origin %q: the five rails serve %d distinct voltages (in units of 100 mV)", origin, len(railValues))
	}
}
