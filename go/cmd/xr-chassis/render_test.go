/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
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
