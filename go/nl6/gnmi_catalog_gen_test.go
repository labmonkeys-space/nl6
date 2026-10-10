/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math"
	"net"
	"strings"
	"testing"
	"time"
)

func genCtxForTest(t *testing.T) *gnmiGenCtx {
	t.Helper()
	dev := newTestGnmiDevice(t, 2)
	cat, err := parseGnmiCatalog(readTestCatalog(t), "min")
	if err != nil {
		t.Fatal(err)
	}
	return &gnmiGenCtx{dev: dev, cat: cat, keys: []string{"TestIf1"}, ifIndex: 1, t: 10, now: time.Unix(1_700_000_000, 0)}
}

func TestCompileGnmiBinding_Rejects(t *testing.T) {
	for _, spec := range []string{"", "nosuch:1", "sine:1,2", "sine:1,2,0", "sine:a,b,c", "counter:x", "ifcounter:ifNoSuchColumn", "ifstate:colour", "key:x", "timestamp:yesterday"} {
		if _, err := compileGnmiBinding(spec); err == nil {
			t.Errorf("%q accepted", spec)
		}
	}
}

func TestGnmiBindings(t *testing.T) {
	ctx := genCtxForTest(t)
	get := func(spec string) any {
		t.Helper()
		g, err := compileGnmiBinding(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		v, ok := g(ctx)
		if !ok {
			t.Fatalf("%s: not ok", spec)
		}
		return v
	}
	if v := get("const:UP"); v != "UP" {
		t.Errorf("const = %v", v)
	}
	if v := get("key:0"); v != "TestIf1" {
		t.Errorf("key:0 = %v", v)
	}
	if v := get("ifstate:name"); v != "TestIf1" {
		t.Errorf("ifstate:name = %v", v)
	}
	if v := get("ifstate:ifindex"); v != uint64(1) {
		t.Errorf("ifstate:ifindex = %v (%T)", v, v)
	}
	if v := get("ifstate:oper"); v != "UP" && v != "DOWN" {
		t.Errorf("ifstate:oper = %v", v)
	}
	ic := ctx.dev.metricsCycler.ifCounters.Load()
	want := ic.GetDynamicAt(ifXTablePrefix+"6.1", 10)
	if v := get("ifcounter:ifHCInOctets"); v.(string) != want {
		t.Errorf("ifcounter = %v, want %v", v, want)
	}
	// sine is deterministic in (ip, key, t) and stays within base±amp.
	a := get("sine:40,5,600").(float64)
	b := get("sine:40,5,600").(float64)
	if a != b || a < 35 || a > 45 {
		t.Errorf("sine = %v / %v", a, b)
	}
	ctx2 := *ctx
	ctx2.dev = &DeviceSimulator{IP: net.IPv4(10, 42, 0, 2), metricsCycler: ctx.dev.metricsCycler}
	g, _ := compileGnmiBinding("sine:40,5,600")
	c, _ := g(&ctx2)
	if c == a {
		t.Errorf("sine ignores device seed")
	}
	// counter is monotonic in t.
	g, _ = compileGnmiBinding("counter:100")
	c1, _ := g(ctx)
	ctx.t = 20
	c2, _ := g(ctx)
	if c2.(uint64) <= c1.(uint64) {
		t.Errorf("counter not monotonic: %v then %v", c1, c2)
	}
	ctx.keys = []string{"FPC0"}
	if v := get("inventory:serial_no"); v != "SN000002" {
		t.Errorf("inventory = %v", v)
	}
	ctx.keys = []string{"203.0.113.1"}
	if v := get("neighbor:peer_as"); v != uint64(64496) {
		t.Errorf("neighbor = %v", v)
	}
	if v := get("timestamp:now"); v != uint64(ctx.now.UnixNano()) {
		t.Errorf("timestamp:now = %v", v)
	}
	if v := get("timestamp:boot"); v != uint64(ctx.now.Add(-time.Duration(ctx.t)*time.Second).UnixNano()) {
		t.Errorf("timestamp:boot = %v", v)
	}
}

func TestGnmiBindings_MissingLookupsAreNotOk(t *testing.T) {
	ctx := genCtxForTest(t)
	ctx.keys = []string{"NoSuchComponent"}
	g, _ := compileGnmiBinding("inventory:serial_no")
	if _, ok := g(ctx); ok {
		t.Error("unknown component reported ok")
	}
	g, _ = compileGnmiBinding("neighbor:state")
	if _, ok := g(ctx); ok {
		t.Error("unknown neighbor reported ok")
	}
	ctx.dev = &DeviceSimulator{IP: net.IPv4(10, 42, 0, 3)} // no cycler (Review Focus 3)
	g, _ = compileGnmiBinding("ifcounter:ifHCInOctets")
	if _, ok := g(ctx); ok {
		t.Error("ifcounter without cycler reported ok")
	}
}

func TestCastGnmiLeaf(t *testing.T) {
	cases := []struct {
		in   any
		typ  string
		want any
	}{
		{"123456", "uint64", uint64(123456)},
		{float64(41.7), "uint64", uint64(41)},
		{float64(41.7), "uint32", uint32(41)},
		{float64(-3), "int64", int64(-3)},
		{"UP", "enumeration", "UP"},
		{"x", "string", "x"},
		{true, "boolean", true},
		{"true", "boolean", true},
		{float64(41.7), "decimal64", gnmiDecimal{val: 41.7, digits: 2}},
		{uint64(7), "string", "7"},
	}
	for _, c := range cases {
		got, err := castGnmiLeaf(c.in, c.typ)
		if err != nil || got != c.want {
			t.Errorf("cast(%v,%s) = %v,%v want %v", c.in, c.typ, got, err, c.want)
		}
	}
	if _, err := castGnmiLeaf("abc", "uint64"); err == nil || !strings.Contains(err.Error(), "uint64") {
		t.Errorf("bad uint accepted: %v", err)
	}
	if _, err := castGnmiLeaf(1, "quaternion"); err == nil {
		t.Error("unknown type accepted")
	}
	// Every type catalogue load accepts must be one castGnmiLeaf handles.
	for typ := range gnmiLeafTypes {
		if _, err := castGnmiLeaf("1", typ); err != nil {
			t.Errorf("load accepts %s but cast fails: %v", typ, err)
		}
	}
	if math.IsNaN(0) {
		t.Fatal("unreachable")
	}
}
