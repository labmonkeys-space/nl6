/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math"
	"net"
	"strings"
	"sync"
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
	ctx.dev = &DeviceSimulator{IP: net.IPv4(10, 42, 0, 3)} // no cycler
	g, _ = compileGnmiBinding("ifcounter:ifHCInOctets")
	if _, ok := g(ctx); ok {
		t.Error("ifcounter without cycler reported ok")
	}
}

// A union leaf with members takes the first member that accepts the
// value, in YANG declaration order. openconfig-system's CPU index is
// union { enumeration { enum ALL; } uint32; }: ALL stays a string and a
// numbered CPU becomes a uint32 (nl6#807).
func TestCastGnmiUnionLeaf(t *testing.T) {
	cpu := &gnmiCatalogLeaf{Type: "union", Members: []string{"enumeration", "uint32"}, Enum: []string{"ALL"}}
	for _, c := range []struct {
		in, want any
	}{{"ALL", "ALL"}, {"0", uint32(0)}, {"5", uint32(5)}, {uint64(3), uint32(3)}} {
		if got, err := cpu.cast(c.in); err != nil || got != c.want {
			t.Errorf("cast(%v) = %v (%T), %v; want %v (%T)", c.in, got, got, err, c.want, c.want)
		}
	}
	if got, err := cpu.cast("any"); err == nil {
		t.Errorf("cast(any) = %v, want an error: no member accepts it", got)
	}
	// A string-like member accepts anything, so it wins when first.
	if got, err := (&gnmiCatalogLeaf{Type: "union", Members: []string{"string", "uint32"}}).cast("7"); err != nil || got != "7" {
		t.Errorf("string-first union cast(7) = %v, %v; want \"7\"", got, err)
	}
	// An integer member takes a float only when it is integral, so 3.7
	// falls through to the next member instead of truncating to 3. A
	// decimal64 member keeps the leaf's fraction digits.
	dec := &gnmiCatalogLeaf{Type: "union", Members: []string{"uint32", "decimal64"}, Digits: 3}
	for _, c := range []struct {
		leaf     *gnmiCatalogLeaf
		in, want any
	}{
		{dec, float64(3.7), newGnmiDecimal(3.7, 3)},
		{dec, float64(3), uint32(3)},
		{&gnmiCatalogLeaf{Type: "union", Members: []string{"uint32", "string"}}, float64(3.7), "3.7"},
		{&gnmiCatalogLeaf{Type: "union", Members: []string{"int32", "string"}}, float64(-2.5), "-2.5"},
	} {
		if got, err := c.leaf.cast(c.in); err != nil || got != c.want {
			t.Errorf("%v cast(%v) = %v (%T), %v; want %v (%T)", c.leaf.Members, c.in, got, got, err, c.want, c.want)
		}
	}
	// Without members a union keeps the historical string form.
	if got, err := (&gnmiCatalogLeaf{Type: "union"}).cast("7"); err != nil || got != "7" {
		t.Errorf("member-less union cast(7) = %v, %v; want \"7\"", got, err)
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
		{float64(41.7), "decimal64", newGnmiDecimal(41.7, 2)},
		{uint64(7), "string", "7"},
	}
	for _, c := range cases {
		got, err := castGnmiLeaf(c.in, c.typ)
		if err != nil || got != c.want {
			t.Errorf("cast(%v,%s) = %v,%v want %v", c.in, c.typ, got, err, c.want)
		}
	}
	for _, c := range []struct {
		in  any
		typ string
	}{
		{"4294967296", "uint32"}, {float64(4294967296), "uint32"}, {"65536", "uint16"}, {"256", "uint8"},
		{float64(2147483648), "int32"}, {float64(-32769), "int16"}, {float64(128), "int8"},
	} {
		if _, err := castGnmiLeaf(c.in, c.typ); err == nil {
			t.Errorf("cast(%v,%s) accepted an out-of-range value", c.in, c.typ)
		}
	}
	if got, err := castGnmiLeaf("4294967295", "uint32"); err != nil || got != uint32(4294967295) {
		t.Errorf("cast(max,uint32) = %v,%v", got, err)
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

func TestGnmiBindings_Device(t *testing.T) {
	ctx := genCtxForTest(t)
	if _, err := compileGnmiBinding("device:serial"); err == nil {
		t.Fatal("unknown device field accepted")
	}
	sysname, _ := compileGnmiBinding("device:sysname")
	id, _ := compileGnmiBinding("device:id")
	if v, ok := sysname(ctx); !ok || v != ctx.dev.ID {
		t.Errorf("sysname without a cached sysName = %v, want the device ID %q", v, ctx.dev.ID)
	}
	ctx.dev.cachedSysName.Store("edge-r1")
	if v, _ := sysname(ctx); v != "edge-r1" {
		t.Errorf("sysname = %v, want edge-r1", v)
	}
	if v, _ := id(ctx); v != ctx.dev.ID {
		t.Errorf("id = %v, want %q", v, ctx.dev.ID)
	}
	ctx.dev = nil
	if _, ok := sysname(ctx); ok {
		t.Error("sysname without a device reported ok")
	}
}

// TestPerDeviceSerial: the suffix carries the whole IPv4 and keeps the
// full component ordinal, so devices in different /16s and components
// whose ordinals differ above the tens never collide.
func TestPerDeviceSerial(t *testing.T) {
	a := perDeviceSerial("NL6FPC000001", net.ParseIP("10.42.1.7"))
	b := perDeviceSerial("NL6FPC000001", net.ParseIP("10.43.1.7"))
	if a != "NL6FPC0A2A0107000001" || b != "NL6FPC0A2B0107000001" {
		t.Fatalf("got %s and %s", a, b)
	}
	if x0, x1 := perDeviceSerial("NL6XCV000000", net.ParseIP("10.42.1.7")), perDeviceSerial("NL6XCV000100", net.ParseIP("10.42.1.7")); x0 == x1 {
		t.Fatalf("ordinals 000000 and 000100 collide: %s", x0)
	}
	if got := perDeviceSerial("NL6MX10004001", net.ParseIP("10.42.1.7")); got != "NL6MX0A2A010710004001" {
		t.Fatalf("model digits must survive, got %s", got)
	}
	if got := perDeviceSerial("NL6FPC000001", nil); got != "NL6FPC000001" {
		t.Fatalf("no IPv4 must serve the constant, got %s", got)
	}
	if got := perDeviceSerial("ABCDEF", net.ParseIP("10.42.1.7")); got != "ABCDEF" {
		t.Fatalf("no trailing digits must serve the constant, got %s", got)
	}
}

func TestIfMIBBinding(t *testing.T) {
	ctx := genCtxForTest(t)
	idx := &sync.Map{}
	idx.Store(ifTablePrefix+"4.3", "9216")
	idx.Store(ifXTablePrefix+"15.3", "400000")
	ctx.dev.resources = &DeviceResources{oidIndex: idx}
	ctx.ifIndex = 3
	for spec, want := range map[string]string{"ifmib:ifMtu": "9216", "ifmib:ifHighSpeed": "400000"} {
		g, err := compileGnmiBinding(spec)
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := g(ctx); !ok || v != want {
			t.Errorf("%s = %v, %v; want %s", spec, v, ok, want)
		}
	}
	if _, err := compileGnmiBinding("ifmib:ifInOctets"); err == nil {
		t.Error("ifmib accepted a column it does not serve")
	}
}

func TestIfMIBBindingMissingRowIsNotOk(t *testing.T) {
	ctx := genCtxForTest(t)
	ctx.dev.resources = &DeviceResources{oidIndex: &sync.Map{}}
	ctx.ifIndex = 3
	g, _ := compileGnmiBinding("ifmib:ifHighSpeed")
	if v, ok := g(ctx); ok {
		t.Errorf("missing ifHighSpeed row served %v", v)
	}
	ctx.ifIndex = 0
	if _, ok := g(ctx); ok {
		t.Error("ifmib served without an interface")
	}
}

func TestInventoryOpticFields(t *testing.T) {
	ctx := genCtxForTest(t)
	x := gnmiCatalogComponent{Name: "FPC1:PIC0:PORT0:Xcvr0", Type: "TRANSCEIVER", FormFactor: "QSFP56_DD_TYPE1", EthernetPMD: "ETH_400GBASE_DR4"}
	p := gnmiCatalogComponent{Name: "FPC1:PIC0:PORT0", Type: "PORT", Wavelength: "1310"}
	ctx.cat = &gnmiCatalog{componentByName: map[string]*gnmiCatalogComponent{x.Name: &x, p.Name: &p}}
	ctx.componentKey = 0
	for _, c := range []struct{ key, spec, want string }{
		{x.Name, "inventory:form_factor", "QSFP56_DD_TYPE1"},
		{x.Name, "inventory:ethernet_pmd", "ETH_400GBASE_DR4"},
		{p.Name, "inventory:wavelength", "1310"},
	} {
		ctx.keys = []string{c.key}
		g, err := compileGnmiBinding(c.spec)
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := g(ctx); !ok || v != c.want {
			t.Errorf("%s on %s = %v, %v; want %s", c.spec, c.key, v, ok, c.want)
		}
	}
}
