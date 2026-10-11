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
