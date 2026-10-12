/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func miniModel(t *testing.T) *Model {
	t.Helper()
	b, err := os.ReadFile("testdata/mini.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseModel(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestExpandMini(t *testing.T) {
	c, err := Expand(miniModel(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Rack 0", "Rack 0-Card Slot 0", "0/0", "0/0-Slice 0 SFP Port Module #0", "0/0-SFP+ bay 0",
		"0/0-TenGigE0/0/0/0", "TenGigE0/0/0/0", "TenGigE0/0/0/0-Tx Lane 0 Current", "TenGigE0/0/0/0-Module Temp", "TenGigE0/0/0/0-3.3 V",
		"TenGigE0/0/0/0-IDPROM", "0/0-QSFP bay 1", "0/0-HundredGigE0/0/0/1", "HundredGigE0/0/0/1-Rx Lane 3 Power"} {
		if c.Component(name) == nil {
			t.Errorf("component %q missing", name)
		}
	}
	if got := c.Component("0/0-HundredGigE0/0/0/1").Parent; got != "0/0-Slice 0 QSFP Port Module #1" {
		t.Errorf("QSFP port parent %q, want its own port module", got)
	}
	if len(c.Ports) != 3 || c.Ports[0].IfName != "TenGigE0/0/0/0" || c.Ports[1].Short != "Hu0/0/0/1" || c.Ports[2].IfIndex != 3 {
		t.Fatalf("ports %+v", c.Ports)
	}
	if c.Component("Rack 0").SerialNo == "" || c.Component("0/0-Slice 0 Lightspeed").SerialNo != "" {
		t.Error("a serial goes to every component with a part number and to no other")
	}
	if !c.Component("TenGigE0/0/0/0-Module Temp").Temperature || c.Component("TenGigE0/0/0/0-3.3 V").Temperature {
		t.Error("only the module temperature sensor carries temperature")
	}
}

// Each broken model must be refused with an error naming the defect.
func TestExpandRefuses(t *testing.T) {
	for _, c := range []struct {
		name, want string
		edit       func(m *Model)
	}{
		{"unknown kind", "unknown kind", func(m *Model) { m.Boards[1].Kind = "nope" }},
		{"unresolved placeholder", "placeholder {slott}", func(m *Model) { m.Kinds["card"][1].Description = "PSE {slott}" }},
		{"parent not earlier", "is not an earlier component", func(m *Model) { m.Kinds["card"][1].Parent = "0/9" }},
		{"duplicate name", "duplicate component", func(m *Model) { m.Kinds["card"][1].Name = "{loc}" }},
		{"stale vendor type", "vendor_types", func(m *Model) { m.VendorTypes["T-UNUSED"] = "1.3.6.1.4.1.9.12.3.1.3.9" }},
		{"vendor type outside the MIB", "CISCO-ENTITY-VENDORTYPE-OID-MIB", func(m *Model) { m.VendorTypes["T-CARD"] = "1.3.6.1.4.1.9.1.1" }},
		{"platform PID unknown", "platform", func(m *Model) { m.Platform[0].Type = "T-NONE" }},
		{"missing sensor description", "sensor_descriptions", func(m *Model) { delete(m.FrontPorts.QSFP.SensorDescr, "voltage") }},
		{"management port without component", "mgmt", func(m *Model) { m.MgmtPorts[0].IfName = "MgmtEth9/9/CPU0/0" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := miniModel(t)
			c.edit(m)
			if _, err := Expand(m); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestParseModelRejectsUnknownFields(t *testing.T) {
	if _, err := parseModel([]byte(`{"comment":"x","bogus":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}
func shipped(t *testing.T) *Chassis {
	t.Helper()
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The hardware guide's chassis: two A99-RP-F, one ASR-9902-LC, three fan
// trays, two PWR-1.6KW-AC in one power tray, 48 front ports.
func TestShippedModelMatchesTheHardwareGuide(t *testing.T) {
	c := shipped(t)
	count := map[[2]string]int{}
	for _, comp := range c.Components {
		count[[2]string{comp.Type, comp.PartNo}]++
	}
	for k, want := range map[[2]string]int{
		{"CHASSIS", "ASR-9902"}: 1, {"CONTROLLER_CARD", "A99-RP-F"}: 2, {"LINECARD", "ASR-9902-LC"}: 1,
		{"FRU", "ASR-9902-FAN"}: 3, {"POWER_SUPPLY", "PWR-1.6KW-AC"}: 2, {"FRU", "ASR-9900-AC-PEM"}: 1,
	} {
		if count[k] != want {
			t.Errorf("%s %s: %d, want %d", k[0], k[1], count[k], want)
		}
	}
	xcvr := 0
	for _, comp := range c.Components {
		if comp.Type == "TRANSCEIVER" {
			xcvr++
		}
	}
	if xcvr != 48 || len(c.Ports) != 50 {
		t.Errorf("%d transceivers and %d ports, want 48 and 50 (48 front, 2 management)", xcvr, len(c.Ports))
	}
}

// Positions 8-11 and 36-39 are QSFP bays named HundredGigE; the other 40
// are SFP bays named TenGigE, slice 0 holding 0-23 and slice 1 24-47.
func TestShippedPortLayout(t *testing.T) {
	c := shipped(t)
	for _, p := range c.Ports[:48] {
		n := p.IfIndex - 1
		want := "TenGigE"
		if (n >= 8 && n <= 11) || (n >= 36 && n <= 39) {
			want = "HundredGigE"
		}
		if p.IfName != want+"0/0/0/"+strconv.Itoa(n) {
			t.Errorf("position %d is %s, want %s0/0/0/%d", n, p.IfName, want, n)
		}
		if !strings.HasPrefix(c.Component(p.Component).Parent, "0/0-Slice "+strconv.Itoa(n/24)+" ") {
			t.Errorf("%s is not under slice %d", p.Component, n/24)
		}
	}
}

// XR serves slot containers, motherboards and FPD modules with no type leaf.
func TestShippedModelKeepsUntypedComponents(t *testing.T) {
	c := shipped(t)
	for _, name := range []string{"Rack 0-RouteProcessor Slot 0", "0/RP0-Motherboard", "0/0-Motherboard", "0/RP0-CPU Module"} {
		comp := c.Component(name)
		if comp == nil || comp.Type != "" {
			t.Errorf("%s: want an untyped component, got %+v", name, comp)
		}
	}
}

// The vendor types are read from CISCO-ENTITY-VENDORTYPE-OID-MIB at
// cisco/cisco-mibs c9ab98c0; the two power PIDs have no entry and no row.
func TestShippedVendorTypesFromTheMIB(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"ASR-9902":     "1.3.6.1.4.1.9.12.3.1.3.2432",
		"A99-RP-F":     "1.3.6.1.4.1.9.12.3.1.9.74.147",
		"ASR-9902-LC":  "1.3.6.1.4.1.9.12.3.1.9.74.157",
		"ASR-9902-FAN": "1.3.6.1.4.1.9.12.3.1.9.74.158",
	}
	if len(m.VendorTypes) != len(want) {
		t.Fatalf("vendor_types %v, want exactly %v", m.VendorTypes, want)
	}
	for pid, oid := range want {
		if m.VendorTypes[pid] != oid {
			t.Errorf("%s: %s, want %s", pid, m.VendorTypes[pid], oid)
		}
	}
}

// The model publishes product-invariant names only. The SSD vendor varies
// per unit, and a per-bay FPD row set narrower than the QSFP bays could
// encode which bays a captured unit had populated.
func TestShippedModelCarriesNoPerUnitData(t *testing.T) {
	c := shipped(t)
	for _, comp := range c.Components {
		// An SSD FPD is named by its slot letter only; anything after it
		// would be the per-unit vendor.
		if i := strings.Index(comp.Name, "-SSD"); i >= 0 && !strings.HasSuffix(comp.Name, "-SSDa") && !strings.HasSuffix(comp.Name, "-SSDb") {
			t.Errorf("%s: an SSD FPD must be named <location>-SSDa or -SSDb", comp.Name)
		}
		if strings.Contains(comp.Name, "-QDD_") && !strings.Contains(comp.Name, "-QDD_BRT_") {
			t.Errorf("%s is a per-bay FPD row outside the QDD_BRT set that covers every QSFP bay", comp.Name)
		}
	}
}
