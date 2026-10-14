/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"os"
	"slices"
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
		{"logical port without ifType", "logical_ports: Loopback0 needs a positive if_type", func(m *Model) {
			m.LogicalPorts = []LogicalPort{{IfName: "Loopback0", Short: "Lo0"}}
		}},
		{"duplicate interface name", "interface TenGigE0/0/0/0 defined twice", func(m *Model) {
			m.LogicalPorts = []LogicalPort{{IfName: "TenGigE0/0/0/0", Short: "Te0/0/0/0", IfType: 24}}
		}},
		{"subinterface of an unknown parent", "subinterfaces: parent Bundle-Ether9 is not an earlier interface", func(m *Model) {
			m.Subinterfaces = []Subinterface{{Parent: "Bundle-Ether9", Index: 100}}
		}},
		{"empty bay out of range", "front_ports: empty bay 2 is not a front port", func(m *Model) { m.FrontPorts.EmptyBays = []int{2} }},
		{"subinterface index 0", "subinterfaces: TenGigE0/0/0/0 index 0 must be positive", func(m *Model) {
			m.Subinterfaces = []Subinterface{{Parent: "TenGigE0/0/0/0", Index: 0}}
		}},
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

// An empty bay keeps its module, bay and PORT; its transceiver and sensors go.
func TestExpandEmptyBayMini(t *testing.T) {
	m := miniModel(t)
	m.FrontPorts.EmptyBays = []int{0}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"0/0-Slice 0 SFP Port Module #0", "0/0-SFP+ bay 0", "0/0-TenGigE0/0/0/0"} {
		if c.Component(name) == nil {
			t.Errorf("component %q missing", name)
		}
	}
	for _, comp := range c.Components {
		if strings.HasPrefix(comp.Name, "TenGigE0/0/0/0") {
			t.Errorf("empty bay serves %s", comp.Name)
		}
	}
	if c.Component("HundredGigE0/0/0/1") == nil || c.Ports[0].IfName != "TenGigE0/0/0/0" {
		t.Error("the populated bay or the empty bay's interface is gone")
	}
	if c.Component("0/0-QDD_0_1") == nil {
		t.Error("a populated QSFP bay has no QDD FPD row")
	}
	m.FrontPorts.EmptyBays = []int{1}
	if c, err = Expand(m); err != nil {
		t.Fatal(err)
	}
	if c.Component("0/0-QDD_0_1") != nil {
		t.Error("an empty QSFP bay has a QDD FPD row")
	}
}

// A template naming {package} in any field is instantiated once per
// package, and {n} is the board's ordinal among the boards of its kind.
func TestExpandPackagesMini(t *testing.T) {
	m := miniModel(t)
	m.Packages = []string{"p-a", "p-b"}
	m.Kinds["sw"] = []Component{
		{Name: "IOSXR-NODE {node}", Type: "OPERATING_SYSTEM"},
		{Name: "IOSXR-PKG/{n} {node}", Type: "SOFTWARE_MODULE", Description: "{package}"},
	}
	m.Boards = append(m.Boards, Board{Kind: "sw", Vars: map[string]string{"node": "A"}}, Board{Kind: "sw", Vars: map[string]string{"node": "B"}})
	_, err := Expand(m)
	if err == nil || !strings.Contains(err.Error(), "duplicate component") {
		t.Fatalf("a {package} in the description fans the row out, so its name repeats: got %v", err)
	}
	m.Kinds["sw"][1] = Component{Name: "IOSXR-PKG/{n} {package}", Type: "SOFTWARE_MODULE", Description: "Package"}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"IOSXR-NODE A", "IOSXR-NODE B", "IOSXR-PKG/1 p-a", "IOSXR-PKG/1 p-b", "IOSXR-PKG/2 p-a", "IOSXR-PKG/2 p-b"} {
		if c.Component(name) == nil {
			t.Errorf("component %q missing", name)
		}
	}
	m.Packages = nil
	if _, err := Expand(m); err == nil || !strings.Contains(err.Error(), "placeholder {package}") {
		t.Errorf("a {package} template with no packages: got %v", err)
	}
	m.Packages = []string{"p-a"}
	delete(m.Kinds, "sw")
	m.Boards = m.Boards[:len(m.Boards)-2]
	if _, err := Expand(m); err == nil || !strings.Contains(err.Error(), "packages: no template names {package}") {
		t.Errorf("packages with no {package} template: got %v", err)
	}
	m = miniModel(t)
	m.Boards[1].Vars["n"] = "7"
	if _, err := Expand(m); err == nil || !strings.Contains(err.Error(), "{n} is the board's ordinal") {
		t.Errorf("a board setting n: got %v", err)
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
	physical := 0
	for _, p := range c.Ports {
		if p.Component != "" {
			physical++
		}
	}
	if xcvr != 28 || physical != 50 {
		t.Errorf("%d transceivers and %d physical ports, want 28 and 50 (48 front of which 28 populated, 2 management)", xcvr, physical)
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

// The SSD vendor is a chosen value (nl6#811): one vendor for every slot.
// QDD_BRT_0_<port> covers every QSFP bay; QDD_0_<port>, the plugged
// module's FPD, exists only where the bay holds an optic.
func TestShippedSSDAndQDDRows(t *testing.T) {
	c := shipped(t)
	ssd := 0
	for _, comp := range c.Components {
		if strings.Contains(comp.Name, "-SSD") {
			ssd++
			if !strings.HasSuffix(comp.Name, "-SSDa-INNODISK") && !strings.HasSuffix(comp.Name, "-SSDb-INNODISK") {
				t.Errorf("%s: an SSD FPD must be named <location>-SSDa-INNODISK or -SSDb-INNODISK", comp.Name)
			}
		}
	}
	if ssd != 5 {
		t.Errorf("%d SSD components, want 5 (SSDa and SSDb on each RP, SSDa on the LC)", ssd)
	}
	want := map[string]bool{}
	for _, n := range c.Model.FrontPorts.QSFPBays {
		want[fmt.Sprintf("0/0-QDD_BRT_0_%d", n)] = true
		if c.Component(fmt.Sprintf("HundredGigE0/0/0/%d", n)) != nil {
			want[fmt.Sprintf("0/0-QDD_0_%d", n)] = true
		}
	}
	for _, comp := range c.Components {
		if !strings.Contains(comp.Name, "-QDD_") {
			continue
		}
		if !want[comp.Name] {
			t.Errorf("%s: no QSFP bay, or no optic in it, accounts for this QDD row", comp.Name)
		}
		if comp.Type != "" || comp.Parent != "0/0-Motherboard" || !slices.Contains(comp.Tags, "firmware-version") {
			t.Errorf("%s: want an untyped FPD module under 0/0-Motherboard, got %+v", comp.Name, comp)
		}
		delete(want, comp.Name)
	}
	for name := range want {
		t.Errorf("%s missing", name)
	}
}

// IOS-XR names a node's OS component IOSXR-NODE <node> and reports each
// active package once per node as IOSXR-PKG/<n> <package>, n counting the
// nodes from 1 (nl6#811).
func TestShippedNodeAndPackageNames(t *testing.T) {
	c := shipped(t)
	nodes := []string{"0/RP0/CPU0", "0/RP1/CPU0", "0/0/CPU0"}
	pkgs := []string{"asr9k-xr-24.2.2", "asr9k-isis-x64-1.0.0.0-r2422", "asr9k-k9sec-x64-1.0.0.0-r2422",
		"asr9k-mgbl-x64-1.0.0.0-r2422", "asr9k-mpls-x64-1.0.0.0-r2422", "asr9k-ospf-x64-1.0.0.0-r2422"}
	for i, node := range nodes {
		if c.Component(node) != nil {
			t.Errorf("component %q: IOS-XR names it IOSXR-NODE %s", node, node)
		}
		if comp := c.Component("IOSXR-NODE " + node); comp == nil || comp.Type != "OPERATING_SYSTEM" || comp.Parent != "" {
			t.Errorf("IOSXR-NODE %s: want a parentless OPERATING_SYSTEM component, got %+v", node, comp)
		}
		for _, p := range pkgs {
			name := fmt.Sprintf("IOSXR-PKG/%d %s", i+1, p)
			if comp := c.Component(name); comp == nil || comp.Type != "SOFTWARE_MODULE" || comp.Parent != "" {
				t.Errorf("%s: want a parentless SOFTWARE_MODULE component, got %+v", name, comp)
			}
		}
	}
	sw := 0
	for _, comp := range c.Components {
		if comp.Type == "SOFTWARE_MODULE" {
			sw++
		}
	}
	if sw != len(nodes)*len(pkgs) {
		t.Errorf("%d SOFTWARE_MODULE components, want %d", sw, len(nodes)*len(pkgs))
	}
}

// Every QSFP bay and the lowest ten SFP bays of each slice hold an optic;
// the other twenty SFP bays are empty (nl6#811). An empty bay keeps its
// port module, bay and PORT, has no transceiver or sensor, and its port is
// oper-down.
func TestShippedOpticPopulation(t *testing.T) {
	c := shipped(t)
	fp := c.Model.FrontPorts
	byPort := map[string][]string{} // interface name -> its transceiver and sensor rows
	for _, comp := range c.Components {
		if name, _, _ := strings.Cut(comp.Name, "-"); strings.HasPrefix(name, "TenGigE") || strings.HasPrefix(name, "HundredGigE") {
			byPort[name] = append(byPort[name], comp.Name)
		}
	}
	sfpSeen := map[int]int{}
	for n := 0; n < fp.Count; n++ {
		want := true
		if !slices.Contains(fp.QSFPBays, n) {
			s := n / fp.PerSlice
			sfpSeen[s]++
			want = sfpSeen[s] <= 10
		}
		p := c.Ports[n]
		if c.Component(p.Component) == nil {
			t.Errorf("%s: PORT component %s missing", p.IfName, p.Component)
		}
		if got := c.Component(p.IfName) != nil; got != want {
			t.Errorf("%s: transceiver present %v, want %v", p.IfName, got, want)
		}
		if !want && len(byPort[p.IfName]) > 0 {
			t.Errorf("%s: empty bay serves %v", p.IfName, byPort[p.IfName])
		}
		if p.OperDown == want {
			t.Errorf("%s: oper-down %v, want %v", p.IfName, p.OperDown, !want)
		}
	}
}

// leafTags is every tag a component may carry: the leaf groups an ASR 9902
// reports on some components of a type but not all. A tag outside it, or
// one no component carries, fails.
var leafTags = []string{"allocated-power", "empty", "firmware-version", "hardware-version", "id", "location", "memory", "mfg-name",
	"openconfig-platform-ext:entity-id", "oper-status", "parent", "part-no", "pcie", "serial-no", "software-version", "type", "used-power"}

func TestShippedTagsAreKnownAndUsed(t *testing.T) {
	c := shipped(t)
	used := map[string]int{}
	for _, comp := range c.Components {
		for _, tag := range comp.Tags {
			if !slices.Contains(leafTags, tag) {
				t.Errorf("%s carries unknown tag %q", comp.Name, tag)
			}
			used[tag]++
		}
	}
	for _, tag := range leafTags {
		if used[tag] == 0 {
			t.Errorf("tag %q is carried by no component", tag)
		}
	}
	// Spot checks from the hardware's leaf profile.
	if comp := c.Component("0/RP0-Lionheart-FPGA"); comp == nil || !slices.Contains(comp.Tags, "firmware-version") {
		t.Error("an FPD module must report firmware-version")
	}
	if comp := c.Component("Rack 0-RouteProcessor Slot 0"); comp == nil || slices.Contains(comp.Tags, "type") {
		t.Error("an untyped slot container reports no type leaf")
	}
}

// The shipped logical interfaces and VLAN subinterfaces an IOS-XR 24.2.2
// ASR 9902 reports (nl6#810, nl6#808), after the 50 physical ports.
func TestShippedLogicalInterfaces(t *testing.T) {
	c := shipped(t)
	var got []string
	for _, p := range c.Ports[50:] {
		got = append(got, p.IfName+"="+strconv.Itoa(p.IfType))
		if p.Component != "" {
			t.Errorf("%s has component %s; a logical interface has none", p.IfName, p.Component)
		}
	}
	want := "Bundle-Ether1=161 BVI1=53 Loopback0=24 Null0=1 HundredGigE0/0/0/8.100=135 HundredGigE0/0/0/8.200=135 Bundle-Ether1.300=135"
	if strings.Join(got, " ") != want {
		t.Fatalf("logical interfaces\n got %s\nwant %s", strings.Join(got, " "), want)
	}
	for _, p := range c.Ports[:50] {
		if p.IfType != 6 {
			t.Errorf("%s ifType %d, want 6 (ethernetCsmacd)", p.IfName, p.IfType)
		}
	}
}

// Bundle-Ether1 is made of two populated 100G bays that carry no
// subinterface, and its speed is their sum.
func TestShippedBundleMembers(t *testing.T) {
	c := shipped(t)
	var bundle Port
	for _, p := range c.Ports {
		if p.IfName == "Bundle-Ether1" {
			bundle = p
		}
	}
	var names []string
	speed := 0
	for _, m := range bundle.Members {
		names = append(names, c.Ports[m-1].IfName)
		speed += c.Ports[m-1].SpeedMbps
	}
	if got := strings.Join(names, " "); got != "HundredGigE0/0/0/9 HundredGigE0/0/0/10" {
		t.Fatalf("members = %q", got)
	}
	if speed != bundle.SpeedMbps {
		t.Errorf("bundle speed %d, members sum %d", bundle.SpeedMbps, speed)
	}
}

func TestBundleMembersAreValidated(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		members    []string
		speed      int
	}{
		{"unknown port", "member HundredGigE0/0/0/99 is not an earlier physical port", []string{"HundredGigE0/0/0/9", "HundredGigE0/0/0/99"}, 200000},
		{"twice", "member HundredGigE0/0/0/9 listed twice", []string{"HundredGigE0/0/0/9", "HundredGigE0/0/0/9"}, 200000},
		{"speed", "speed_mbps 300000 is not the sum of its members, 200000", []string{"HundredGigE0/0/0/9", "HundredGigE0/0/0/10"}, 300000},
		{"not a lag", "BVI1 has bundle_members but if_type 53 is not ieee8023adLag(161)", nil, 0},
	} {
		m, err := loadModel()
		if err != nil {
			t.Fatal(err)
		}
		if tc.members == nil {
			m.LogicalPorts[1].BundleMembers = []string{"HundredGigE0/0/0/9"}
		} else {
			m.LogicalPorts[0].BundleMembers = tc.members
			m.LogicalPorts[0].SpeedMbps = tc.speed
		}
		_, err = Expand(m)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}
