/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
)

const resourceDir = "../../nl6/resources/juniper_mx10004"

func TestExpandPortsAreInIfIndexOrder(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range c.Ports {
		if p.IfIndex != i+1 {
			t.Fatalf("port %d has ifIndex %d", i, p.IfIndex)
		}
	}
	if first, last := c.Ports[0].IfName, c.Ports[len(c.Ports)-1].IfName; first != "xe-0/0/0" || last != "et-1/5/3" {
		t.Fatalf("ports run %s..%s", first, last)
	}
}

func TestExpandRejectsDuplicateNamesAndSerials(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	m.FPCs = append(m.FPCs, FPCSlot{Slot: 0, Card: "LC480"})
	if _, err := Expand(m); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("a second FPC0 expanded without error: %v", err)
	}
	m, _ = loadModel()
	m.Tail = append(m.Tail, Component{Name: "Extra", Type: "FAN", Parent: "Chassis", SerialNo: "NL6FPC000001"})
	if _, err := Expand(m); err == nil || !strings.Contains(err.Error(), "duplicate serial") {
		t.Fatalf("a reused serial expanded without error: %v", err)
	}
}

func TestExpandRejectsMoreThan255Ports(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	card := m.CardTypes["LC480"]
	card.PortsPerPIC = 128
	m.CardTypes["LC480"] = card
	if _, err := Expand(m); err == nil || !strings.Contains(err.Error(), "255") {
		t.Fatalf("256 ports expanded without error: %v", err)
	}
}

func TestExpandRejectsUnknownCardAndSlot(t *testing.T) {
	m, _ := loadModel()
	m.FPCs = []FPCSlot{{Slot: 0, Card: "LC9999"}}
	if _, err := Expand(m); err == nil {
		t.Fatal("unknown card type expanded")
	}
	m, _ = loadModel()
	m.FPCs = []FPCSlot{{Slot: 4, Card: "LC480"}}
	if _, err := Expand(m); err == nil {
		t.Fatal("FPC slot 4 expanded on a 4-slot chassis")
	}
	// An optic missing a field the catalogue reads would silently drop
	// that leaf for every port of the card.
	m, _ = loadModel()
	card := m.CardTypes["LC480"]
	card.Optic.ConnectorType = ""
	m.CardTypes["LC480"] = card
	if _, err := Expand(m); err == nil || !strings.Contains(err.Error(), "connector_type") {
		t.Fatalf("optic without connector_type: err = %v", err)
	}
}

func TestExpandUnitsFollowThePorts(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Units) != 4 {
		t.Fatalf("%d units, want 4", len(c.Units))
	}
	u := c.Units[0]
	if u.IfIndex != len(c.Ports)+1 || u.IfName != "xe-0/0/0.0" || u.Parent.IfName != "xe-0/0/0" || u.Inet != "192.168.1.1/24" {
		t.Fatalf("unit = %+v", u)
	}
	// The VRF units carry no address and number on in model order.
	for i, name := range []string{"xe-0/0/0.100", "xe-0/0/0.200", "xe-0/0/0.999"} {
		if u := c.Units[i+1]; u.IfIndex != len(c.Ports)+i+2 || u.IfName != name || u.Inet != "" {
			t.Fatalf("unit %d = %+v, want %s at ifIndex %d with no address", i+1, u, name, len(c.Ports)+i+2)
		}
	}
	if got := c.UnitsOf("xe-0/0/0"); len(got) != 4 || got[0].IfName != "xe-0/0/0.0" {
		t.Fatalf("UnitsOf(xe-0/0/0) = %+v", got)
	}
	if got := c.UnitsOf("xe-0/0/1"); len(got) != 0 {
		t.Fatalf("UnitsOf(xe-0/0/1) = %+v", got)
	}
}

func TestExpandRejectsBadUnits(t *testing.T) {
	for name, tc := range map[string]struct {
		units []Unit
		want  string
	}{
		"unknown parent": {[]Unit{{Parent: "xe-9/0/0"}}, "not a port"},
		"negative":       {[]Unit{{Parent: "xe-0/0/0", Unit: -1}}, "outside"},
		"above range":    {[]Unit{{Parent: "xe-0/0/0", Unit: maxJunosUnit + 1}}, "outside"},
		"duplicate":      {[]Unit{{Parent: "xe-0/0/0"}, {Parent: "xe-0/0/0"}}, "twice"},
		"no prefix len":  {[]Unit{{Parent: "xe-0/0/0", Inet: "192.168.1.1"}}, "inet"},
		"bad address":    {[]Unit{{Parent: "xe-0/0/0", Inet: "192.168.1.300/24"}}, "inet"},
	} {
		m, err := loadModel()
		if err != nil {
			t.Fatal(err)
		}
		m.Units = tc.units
		if _, err := Expand(m); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// A VRF unit is configured `family inet;` with no address: the model says so
// with family, an address implies the family, and any other family is refused.
func TestExpandUnitsCarryTheFamily(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range c.UnitsOf("xe-0/0/0") {
		if u.Family != "inet" {
			t.Errorf("%s: family %q, want inet (unit 0 by its address, the VRF units by the model)", u.IfName, u.Family)
		}
	}
	for _, bad := range []Unit{
		{Parent: "xe-0/0/0", Unit: 7, Family: "inet6"},
		{Parent: "xe-0/0/0", Unit: 8, Inet: "192.0.2.1/24", Family: "iso"},
	} {
		m2 := *m
		m2.Units = append(append([]Unit(nil), m.Units...), bad)
		if _, err := Expand(&m2); err == nil || !strings.Contains(err.Error(), "family") {
			t.Errorf("unit %d with family %q: err = %v, want a family error", bad.Unit, bad.Family, err)
		}
	}
}
