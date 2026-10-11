/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const resourceDir = "../../nl6/resources/juniper_mx10004"

// TestExpandReproducesCommittedComponents: the model expands to exactly the
// component list gnmi-bindings.json carries, in the same order.
func TestExpandReproducesCommittedComponents(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(resourceDir, "gnmi-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Components []Component `json:"components"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if len(c.Components) != len(b.Components) {
		t.Fatalf("expanded %d components, bindings carry %d", len(c.Components), len(b.Components))
	}
	for i := range b.Components {
		if !reflect.DeepEqual(c.Components[i], b.Components[i]) {
			t.Fatalf("component %d: expanded %+v, bindings %+v", i, c.Components[i], b.Components[i])
		}
	}
}

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
	if first, last := c.Ports[0].IfName, c.Ports[len(c.Ports)-1].IfName; first != "xe-0/0/0" || last != "xe-0/1/23" {
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
}
