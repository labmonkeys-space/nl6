/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func rowMap(t *testing.T, c *Chassis) map[string]string {
	t.Helper()
	rows, err := RenderSNMPRows(c)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for i, r := range rows {
		if _, dup := m[r.OID]; dup {
			t.Fatalf("OID %s rendered twice", r.OID)
		}
		if i > 0 && !oidLess(rows[i-1].OID, r.OID) {
			t.Fatalf("rows not in OID order at %s", r.OID)
		}
		m[r.OID] = r.Response
	}
	return m
}

// Entity 1 is the chassis; every other entity is contained in its nearest
// ancestor that is an entity; every port maps to its ifIndex.
func TestEntityRowsMini(t *testing.T) {
	c, err := Expand(miniModel(t))
	if err != nil {
		t.Fatal(err)
	}
	m := rowMap(t, c)
	const ent = "1.3.6.1.2.1.47.1.1.1.1."
	idx := map[string]string{}
	for oid, v := range m {
		if strings.HasPrefix(oid, ent+"7.") {
			idx[v] = strings.TrimPrefix(oid, ent+"7.")
		}
	}
	if idx["Rack 0"] != "1" || m[ent+"4.1"] != "0" || m[ent+"5.1"] != "3" || m[ent+"3.1"] != "1.3.6.1.4.1.9.12.3.1.3.1" {
		t.Fatalf("entity 1 is not the chassis: %v", idx)
	}
	if m[ent+"4."+idx["0/0"]] != idx["Rack 0-Card Slot 0"] {
		t.Error("the card is not contained in its slot")
	}
	// The bay's parent (the port module) is not an entity: containment skips to the slice's card.
	if m[ent+"4."+idx["0/0-SFP+ bay 0"]] != idx["0/0"] {
		t.Error("the bay is not contained in its nearest entity ancestor")
	}
	if _, ok := m[ent+"3."+idx["TenGigE0/0/0/0"]]; ok {
		t.Error("a PID without vendor_types got an entPhysicalVendorType row")
	}
	for _, p := range c.Ports {
		if m["1.3.6.1.2.1.47.1.3.2.1.2."+idx[p.Component]+".0"] != "1.3.6.1.2.1.2.2.1.1."+strconv.Itoa(p.IfIndex) {
			t.Errorf("port %s has no entAliasMapping row", p.IfName)
		}
	}
}

func TestIfTableMini(t *testing.T) {
	c, err := Expand(miniModel(t))
	if err != nil {
		t.Fatal(err)
	}
	m := rowMap(t, c)
	if m["1.3.6.1.2.1.2.1.0"] != "3" || m["1.3.6.1.2.1.2.2.1.2.2"] != "HundredGigE0/0/0/1" || m["1.3.6.1.2.1.31.1.1.1.15.2"] != "100000" {
		t.Fatal("ifNumber, ifDescr or ifHighSpeed wrong")
	}
	if m["1.3.6.1.2.1.2.2.1.5.2"] != "4294967295" || m["1.3.6.1.2.1.2.2.1.5.3"] != "1000000000" {
		t.Error("ifSpeed must saturate at 4294967295 and be exact below it")
	}
	for _, col := range []string{"7", "8"} {
		if m["1.3.6.1.2.1.2.2.1."+col+".1"] != "1" {
			t.Errorf("ifTable .%s is the state engine's seed and must be shipped", col)
		}
	}
	if m["1.3.6.1.2.1.31.1.1.1.6.1"] == "" || m["1.3.6.1.2.1.31.1.1.1.10.1"] == "" {
		t.Error("the HC registration rows .6 and .10 are missing")
	}
}

// Every component with a serial is in show inventory, once; every port is in
// show interfaces brief; every platform node is in show platform.
func TestSSHTextsShipped(t *testing.T) {
	c := shipped(t)
	ssh := map[string]string{}
	for _, e := range RenderSSHEntries(c) {
		ssh[e.Command] = e.Response
	}
	inv := ssh["show inventory"]
	for _, comp := range c.Components {
		// Serials are fixed-width (NL6 plus 8 digits), so one cannot be a prefix of another.
		if comp.SerialNo != "" && !strings.Contains(inv, "SN: "+comp.SerialNo) {
			t.Errorf("%s (%s) missing from show inventory", comp.Name, comp.SerialNo)
		}
	}
	for _, p := range c.Ports {
		if !strings.Contains(ssh["show interfaces brief"], p.IfName+" ") {
			t.Errorf("%s missing from show interfaces brief", p.IfName)
		}
	}
	for _, p := range c.Model.Platform {
		if !strings.Contains(ssh["show platform"], p.Node) {
			t.Errorf("%s missing from show platform", p.Node)
		}
	}
}

// The layouts follow the ASR 9000 System Management command reference
// samples: show platform columns at 0, 16, 42 and 59, and show inventory's
// PID padded to 18 characters before ", VID:".
func TestSSHLayoutsMini(t *testing.T) {
	c, err := Expand(miniModel(t))
	if err != nil {
		t.Fatal(err)
	}
	ssh := map[string]string{}
	for _, e := range RenderSSHEntries(c) {
		ssh[e.Command] = e.Response
	}
	plat := strings.Split(ssh["show platform"], "\n")
	if plat[0] != "Node            Type                      State            Config State" || plat[1] != strings.Repeat("-", 77) {
		t.Errorf("show platform header %q / %q", plat[0], plat[1])
	}
	if plat[2] != "0/0/CPU0        T-CARD                    IOS XR RUN       PWR,NSHUT,MON" {
		t.Errorf("show platform row %q", plat[2])
	}
	if !strings.Contains(ssh["show inventory"], "NAME: \"Rack 0\", DESCR: \"Test Chassis\"\nPID: T-CHASSIS         , VID: V01, SN: NL600000001") {
		t.Errorf("show inventory entry:\n%s", ssh["show inventory"])
	}
}

// Logical ports and subinterfaces follow the physical ports in ifTable and
// show interfaces brief, with their own ifType, and have no entity.
func TestLogicalPortsMini(t *testing.T) {
	m := miniModel(t)
	m.LogicalPorts = []LogicalPort{{IfName: "Bundle-Ether1", Short: "BE1", IfType: 161, SpeedMbps: 200000}, {IfName: "Loopback0", Short: "Lo0", IfType: 24, MTU: "1500", NoPhysAddress: true}}
	m.Subinterfaces = []Subinterface{{Parent: "HundredGigE0/0/0/1", Index: 100}, {Parent: "Bundle-Ether1", Index: 300}}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	r := rowMap(t, c)
	if r["1.3.6.1.2.1.2.1.0"] != "7" {
		t.Fatalf("ifNumber %s, want 7", r["1.3.6.1.2.1.2.1.0"])
	}
	for ix, want := range map[string][4]string{
		"2": {"HundredGigE0/0/0/1", "Hu0/0/0/1", "6", "100000"},
		"4": {"Bundle-Ether1", "BE1", "161", "200000"},
		"5": {"Loopback0", "Lo0", "24", "0"},
		"6": {"HundredGigE0/0/0/1.100", "Hu0/0/0/1.100", "135", "100000"},
		"7": {"Bundle-Ether1.300", "BE1.300", "135", "200000"},
	} {
		got := [4]string{r["1.3.6.1.2.1.2.2.1.2."+ix], r["1.3.6.1.2.1.31.1.1.1.1."+ix], r["1.3.6.1.2.1.2.2.1.3."+ix], r["1.3.6.1.2.1.31.1.1.1.15."+ix]}
		if got != want {
			t.Errorf("ifIndex %s: descr, name, type, high speed %v, want %v", ix, got, want)
		}
		if r["1.3.6.1.2.1.31.1.1.1.6."+ix] == "" {
			t.Errorf("ifIndex %s: no HC registration row", ix)
		}
	}
	if v, ok := r["1.3.6.1.2.1.2.2.1.6.5"]; !ok || v != "" || r["1.3.6.1.2.1.2.2.1.4.5"] != "1500" {
		t.Errorf("Loopback0 ifPhysAddress %q (present %v), ifMtu %q; want empty and 1500", v, ok, r["1.3.6.1.2.1.2.2.1.4.5"])
	}
	if r["1.3.6.1.2.1.2.2.1.6.4"] == "" || r["1.3.6.1.2.1.2.2.1.4.4"] != "1514" {
		t.Error("Bundle-Ether1 lost its ifPhysAddress or the default ifMtu")
	}
	for oid, v := range r {
		if strings.HasPrefix(oid, "1.3.6.1.2.1.47.1.3.2.1.2.") && slices.Contains([]string{"4", "5", "6", "7"}, strings.TrimPrefix(v, "1.3.6.1.2.1.2.2.1.1.")) {
			t.Errorf("logical ifIndex %s has an entAliasMapping row", v)
		}
	}
	brief := ""
	for _, e := range RenderSSHEntries(c) {
		if e.Command == "show interfaces brief" {
			brief = e.Response
		}
	}
	for _, n := range []string{"Bundle-Ether1 ", "Loopback0 ", "HundredGigE0/0/0/1.100 ", "Bundle-Ether1.300 "} {
		if !strings.Contains(brief, n) {
			t.Errorf("%q missing from show interfaces brief", n)
		}
	}
}

// An empty bay has no transceiver entity and no show inventory line, and its
// PORT entity still maps its ifIndex (nl6#811).
func TestEmptyBayRendersNoTransceiver(t *testing.T) {
	m := miniModel(t)
	m.FrontPorts.EmptyBays = []int{0}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	rows := rowMap(t, c)
	const ent = "1.3.6.1.2.1.47.1.1.1.1."
	var names []string
	for oid, v := range rows {
		if strings.HasPrefix(oid, ent+"7.") {
			names = append(names, v)
		}
	}
	if slices.Contains(names, "TenGigE0/0/0/0") || !slices.Contains(names, "HundredGigE0/0/0/1") {
		t.Errorf("entPhysicalName %v: want the populated transceiver only", names)
	}
	if !slices.Contains(names, "0/0-TenGigE0/0/0/0") || rows["1.3.6.1.2.1.2.2.1.2.1"] != "TenGigE0/0/0/0" {
		t.Error("the empty bay's PORT entity or interface is gone")
	}
	inv := RenderSSHEntries(c)[0].Response
	if strings.Contains(inv, `"TenGigE0/0/0/0"`) || !strings.Contains(inv, `"HundredGigE0/0/0/1"`) {
		t.Errorf("show inventory lists the empty bay's optic or drops the populated one:\n%s", inv)
	}
	// A port with no optic is admin up, oper down, in SNMP and the CLI.
	if rows["1.3.6.1.2.1.2.2.1.7.1"] != "1" || rows["1.3.6.1.2.1.2.2.1.8.1"] != "2" || rows["1.3.6.1.2.1.2.2.1.8.2"] != "1" {
		t.Errorf("admin/oper of the empty port %s/%s and oper of the populated one %s, want 1/2 and 1",
			rows["1.3.6.1.2.1.2.2.1.7.1"], rows["1.3.6.1.2.1.2.2.1.8.1"], rows["1.3.6.1.2.1.2.2.1.8.2"])
	}
	brief := strings.Split(RenderSSHEntries(c)[2].Response, "\n")
	if brief[1] != "TenGigE0/0/0/0     unassigned  down    down" || brief[2] != "HundredGigE0/0/0/1 unassigned  up      up" {
		t.Errorf("show interfaces brief rows %q / %q", brief[1], brief[2])
	}
}

// Entity indices and serials are reserved per bay, so emptying a bay
// removes its optic's rows and renumbers nothing else (nl6#811).
func TestEmptyBayKeepsEntityIndicesAndSerials(t *testing.T) {
	full, err := Expand(miniModel(t))
	if err != nil {
		t.Fatal(err)
	}
	m := miniModel(t)
	m.FrontPorts.EmptyBays = []int{0}
	empty, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	before, after := rowMap(t, full), rowMap(t, empty)
	removed := 0
	for oid, v := range before {
		if strings.HasPrefix(oid, "1.3.6.1.2.1.2.2.1.8.") {
			continue // oper status is the intended change
		}
		got, ok := after[oid]
		switch {
		case !ok:
			removed++
		case got != v:
			t.Errorf("%s: %q became %q", oid, v, got)
		}
	}
	if len(after) != len(before)-removed || removed == 0 {
		t.Errorf("%d rows removed and %d rows added; want only the empty bay's optic removed", removed, len(after)-len(before)+removed)
	}
	for _, comp := range empty.Components {
		if full.Component(comp.Name).SerialNo != comp.SerialNo {
			t.Errorf("%s: serial %s, was %s", comp.Name, comp.SerialNo, full.Component(comp.Name).SerialNo)
		}
	}
}

// An aggregate renders one active ifStackStatus row per member and nothing
// else names it as a higher layer.
func TestRenderSNMPRowsStackRowsForBundleMembers(t *testing.T) {
	c := shipped(t)
	rows, err := RenderSNMPRows(c)
	if err != nil {
		t.Fatal(err)
	}
	// Only the rows with the bundle as higher layer: the rest of the table
	// is pinned by TestRenderSNMPRowsStackTableIsComplete.
	var got []string
	for _, r := range rows {
		if strings.HasPrefix(r.OID, "1.3.6.1.2.1.31.1.2.1.3.51.") {
			got = append(got, r.OID+"="+r.Response)
		}
	}
	want := []string{"1.3.6.1.2.1.31.1.2.1.3.51.10=1", "1.3.6.1.2.1.31.1.2.1.3.51.11=1"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("ifStackStatus rows = %v, want %v", got, want)
	}
}

// stackRows returns the ifStackStatus rows of a render as "<higher>.<lower>=<value>".
func stackRows(t *testing.T, rows []SNMPRow) []string {
	t.Helper()
	var got []string
	for _, r := range rows {
		if rest, ok := strings.CutPrefix(r.OID, "1.3.6.1.2.1.31.1.2.1.3."); ok {
			got = append(got, rest+"="+r.Response)
		}
	}
	return got
}

// The shipped table is RFC 2863 complete: every interface appears as a higher
// and as a lower layer at least once, with 0 where nothing is above or below.
// The expected set is written out from the model's relations, not derived
// from the renderer's own loops.
func TestRenderSNMPRowsStackTableIsComplete(t *testing.T) {
	c := shipped(t)
	rows, err := RenderSNMPRows(c)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]int{}
	for _, p := range c.Ports {
		byName[p.IfName] = p.IfIndex
	}
	hu8, be1 := byName["HundredGigE0/0/0/8"], byName["Bundle-Ether1"]
	if hu8 == 0 || be1 == 0 {
		t.Fatalf("shipped model lacks HundredGigE0/0/0/8 (%d) or Bundle-Ether1 (%d)", hu8, be1)
	}
	// The relations the model states: bundle over members, subinterface over parent.
	relations := [][2]int{
		{be1, byName["HundredGigE0/0/0/9"]},
		{be1, byName["HundredGigE0/0/0/10"]},
		{byName["HundredGigE0/0/0/8.100"], hu8},
		{byName["HundredGigE0/0/0/8.200"], hu8},
		{byName["Bundle-Ether1.300"], be1},
	}
	want := map[string]bool{}
	hasAbove, hasBelow := map[int]bool{}, map[int]bool{}
	for _, r := range relations {
		if r[0] == 0 || r[1] == 0 {
			t.Fatalf("relation %v names an interface the model lacks", r)
		}
		want[strconv.Itoa(r[0])+"."+strconv.Itoa(r[1])+"=1"] = true
		hasAbove[r[1]], hasBelow[r[0]] = true, true
	}
	for _, p := range c.Ports {
		if !hasAbove[p.IfIndex] {
			want["0."+strconv.Itoa(p.IfIndex)+"=1"] = true
		}
		if !hasBelow[p.IfIndex] {
			want[strconv.Itoa(p.IfIndex)+".0=1"] = true
		}
	}
	got := stackRows(t, rows)
	gotSet := map[string]bool{}
	for _, g := range got {
		if gotSet[g] {
			t.Errorf("row %s emitted twice", g)
		}
		gotSet[g] = true
		if !want[g] {
			t.Errorf("unexpected row %s", g)
		}
	}
	for w := range want {
		if !gotSet[w] {
			t.Errorf("missing row %s", w)
		}
	}
	// Spot checks a reader can verify against the model without the loops above.
	for _, w := range []string{
		strconv.Itoa(be1) + ".0", "0." + strconv.Itoa(be1), // the bundle has members below and a subinterface above
		"0." + strconv.Itoa(hu8), // the port carries two subinterfaces
	} {
		if gotSet[w+"=1"] {
			t.Errorf("row %s must not exist", w)
		}
	}
	for _, w := range []string{strconv.Itoa(hu8) + ".0", "0." + strconv.Itoa(byName["Bundle-Ether1.300"]), "1.0", "0.1"} {
		if !gotSet[w+"=1"] {
			t.Errorf("row %s must exist", w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d ifStackStatus rows, want %d", len(got), len(want))
	}
}

func TestSubinterfacesCarryTheirParentIfIndex(t *testing.T) {
	c := shipped(t)
	byName := map[string]Port{}
	for _, p := range c.Ports {
		byName[p.IfName] = p
	}
	for child, parent := range map[string]string{
		"HundredGigE0/0/0/8.100": "HundredGigE0/0/0/8",
		"HundredGigE0/0/0/8.200": "HundredGigE0/0/0/8",
		"Bundle-Ether1.300":      "Bundle-Ether1",
	} {
		if got, want := byName[child].Parent, byName[parent].IfIndex; got != want || want == 0 {
			t.Errorf("%s.Parent = %d, want %d (%s)", child, got, want, parent)
		}
	}
	for _, p := range c.Ports {
		if _, _, isSub := strings.Cut(p.IfName, "."); !isSub && p.Parent != 0 {
			t.Errorf("%s is not a subinterface but has Parent %d", p.IfName, p.Parent)
		}
	}
}
