/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func firstDiff(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		if len(a) < len(b) {
			return len(a)
		}
		return len(b)
	}
	return -1
}

func TestJSONStringKeepsHTMLCharacters(t *testing.T) {
	if got := jsonString(`a<b>&"c"`); got != `"a<b>&\"c\""` {
		t.Fatalf("jsonString = %s", got)
	}
	if got := jsonList([]string{"0", "1"}); got != `["0", "1"]` {
		t.Fatalf("jsonList = %s", got)
	}
	if got := jsonList(nil); got != `[]` {
		t.Fatalf("empty jsonList = %s", got)
	}
}

func TestComponentJSONMatchesBindingsLayout(t *testing.T) {
	c := Component{Name: "FPC0", Type: "LINECARD", Parent: "Chassis", PartNo: "JNP10K-LC480", Description: "JNP10K-LC480", SerialNo: "NL6FPC000001", Temperature: true}
	want := `{"name": "FPC0", "type": "LINECARD", "parent": "Chassis", "part_no": "JNP10K-LC480", "description": "JNP10K-LC480", "serial_no": "NL6FPC000001", "temperature": true}`
	if got := componentJSON(c); got != want {
		t.Fatalf("componentJSON =\n%s\nwant\n%s", got, want)
	}
	c.FormFactor, c.EthernetPMD = "SFP_PLUS", "ETH_10GBASE_SR"
	want = want[:len(want)-1] + `, "form_factor": "SFP_PLUS", "ethernet_pmd": "ETH_10GBASE_SR"}`
	if got := componentJSON(c); got != want {
		t.Fatalf("componentJSON with optic =\n%s\nwant\n%s", got, want)
	}
}

func TestHwrowFollowsJunosColumns(t *testing.T) {
	cases := map[string][5]string{
		"FPC 0            REV 06   JNP10K-LC480 NL6FPC000001      JNP10K-LC480": {"FPC 0", "REV 06", "JNP10K-LC480", "NL6FPC000001", "JNP10K-LC480"},
		"  CPU            REV 06   JNP10K-LC480-CPU NL6CPU000001  LC480 PMB":    {"  CPU", "REV 06", "JNP10K-LC480-CPU", "NL6CPU000001", "LC480 PMB"},
		"  MEZZ 0         REV 06   JNP10K-LC480-MEZZ NL6MEZ000001 LC480 Mezz":   {"  MEZZ 0", "REV 06", "JNP10K-LC480-MEZZ", "NL6MEZ000001", "LC480 Mezz"},
		"    Xcvr 10      REV 01   740-021308   NL6XCV000010      SFP+-10G-SR":  {"    Xcvr 10", "REV 01", "740-021308", "NL6XCV000010", "SFP+-10G-SR"},
		"Routing Engine 0 REV 06   JNP10K-RE1   NL6RE0000001      RE-S-X6-64G":  {"Routing Engine 0", "REV 06", "JNP10K-RE1", "NL6RE0000001", "RE-S-X6-64G"},
	}
	for want, f := range cases {
		if got := hwrow(f[0], f[1], f[2], f[3], f[4]); got != want {
			t.Errorf("hwrow =\n%q\nwant\n%q", got, want)
		}
	}
}

func TestEnvrowFollowsJunosColumns(t *testing.T) {
	want := "Temp  CB 0 Intake-A                   OK         31 degrees C / 87 degrees F"
	if got := envrow("Temp", "CB 0 Intake-A", 31); got != want {
		t.Fatalf("envrow =\n%q\nwant\n%q", got, want)
	}
}

func TestRenderSNMPRows(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	var order []string
	rows, err := RenderSNMPRows(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if _, dup := got[r.OID]; dup {
			t.Fatalf("duplicate OID %s", r.OID)
		}
		got[r.OID] = r.Response
		order = append(order, r.OID)
	}
	want := map[string]string{
		"1.3.6.1.2.1.2.1.0":      "80",
		"1.3.6.1.2.1.2.2.1.2.76": "xe-0/0/0.999",
		"1.3.6.1.2.1.2.2.1.3.76": "53",
		"1.3.6.1.2.1.2.2.1.5.76": "4294967295",
		// The system interfaces and their units follow the port units:
		// the management port with a MAC and a 1 Gbit/s ifSpeed, the
		// loopback with no MAC and speed 0, the units propVirtual on the
		// parent's MAC.
		"1.3.6.1.2.1.2.2.1.2.77":               "fxp0",
		"1.3.6.1.2.1.2.2.1.3.77":               "6",
		"1.3.6.1.2.1.2.2.1.4.77":               "1514",
		"1.3.6.1.2.1.2.2.1.5.77":               "1000000000",
		"1.3.6.1.2.1.2.2.1.6.77":               "00:1A:2B:3C:00:4d",
		"1.3.6.1.2.1.31.1.1.1.15.77":           "1000",
		"1.3.6.1.2.1.31.1.1.1.18.77":           "",
		"1.3.6.1.2.1.2.2.1.2.78":               "fxp0.0",
		"1.3.6.1.2.1.2.2.1.3.78":               "53",
		"1.3.6.1.2.1.2.2.1.6.78":               "00:1A:2B:3C:00:4d",
		"1.3.6.1.2.1.2.2.1.2.79":               "lo0",
		"1.3.6.1.2.1.2.2.1.3.79":               "24",
		"1.3.6.1.2.1.2.2.1.4.79":               "65536",
		"1.3.6.1.2.1.2.2.1.5.79":               "0",
		"1.3.6.1.2.1.2.2.1.6.79":               "",
		"1.3.6.1.2.1.31.1.1.1.15.79":           "0",
		"1.3.6.1.2.1.2.2.1.2.80":               "lo0.0",
		"1.3.6.1.2.1.2.2.1.3.80":               "53",
		"1.3.6.1.2.1.2.2.1.6.80":               "",
		"1.3.6.1.2.1.31.1.1.1.1.80":            "lo0.0",
		"1.3.6.1.2.1.2.2.1.2.73":               "xe-0/0/0.0",
		"1.3.6.1.2.1.2.2.1.3.73":               "53",
		"1.3.6.1.2.1.2.2.1.4.73":               "1500",
		"1.3.6.1.2.1.2.2.1.6.73":               "00:1A:2B:3C:00:01",
		"1.3.6.1.2.1.31.1.1.1.1.73":            "xe-0/0/0.0",
		"1.3.6.1.2.1.31.1.1.1.15.73":           "10000",
		"1.3.6.1.2.1.31.1.1.1.18.73":           "",
		"1.3.6.1.2.1.2.2.1.2.1":                "xe-0/0/0",
		"1.3.6.1.2.1.2.2.1.4.1":                "9216",
		"1.3.6.1.2.1.2.2.1.6.26":               "00:1A:2B:3C:00:1a",
		"1.3.6.1.2.1.31.1.1.1.6.24":            "14181198160",
		"1.3.6.1.2.1.31.1.1.1.6.25":            "13897247566",
		"1.3.6.1.2.1.31.1.1.1.10.48":           "14051568552",
		"1.3.6.1.2.1.31.1.1.1.15.48":           "10000",
		"1.3.6.1.2.1.2.2.1.2.49":               "et-1/0/0",
		"1.3.6.1.2.1.31.1.1.1.15.49":           "400000",
		"1.3.6.1.2.1.31.1.1.1.18.7":            "to-core-07",
		"1.3.6.1.4.1.2636.3.1.13.1.5.9.1.0.0":  "Routing Engine 0",
		"1.3.6.1.4.1.2636.3.1.13.1.20.9.1.0.0": "5",
		"1.3.6.1.4.1.2636.3.1.13.1.8.9.2.0.0":  "1",
		"1.3.6.1.4.1.2636.3.1.13.1.11.9.2.0.0": "12",
		"1.3.6.1.4.1.2636.3.1.13.1.7.9.2.0.0":  "36",
		"1.3.6.1.2.1.47.1.1.1.1.11.1":          "NL6MX10004001",
		"1.3.6.1.2.1.47.1.1.1.1.13.1":          "JNP10004",
		"1.3.6.1.2.1.47.1.1.1.1.8.1":           "REV 06",
		"1.3.6.1.2.1.47.1.1.1.1.10.8":          "24.2R1.17",
		"1.3.6.1.2.1.47.1.1.1.1.3.1":           "1.3.6.1.4.1.2636.1.1.1.2.168",
	}
	for oid, v := range want {
		if got[oid] != v {
			t.Errorf("%s = %q, want %q", oid, got[oid], v)
		}
	}
	if got["1.3.6.1.2.1.47.1.3.2.1.2.1001.0"] != "1.3.6.1.2.1.2.2.1.1.1" {
		t.Error("port entity 1001 does not alias ifIndex 1")
	}
	// The system interfaces are not line-card ports, so no port entity.
	for _, ix := range []string{"1077", "1079"} {
		if _, ok := got["1.3.6.1.2.1.47.1.1.1.1.2."+ix]; ok {
			t.Errorf("entity %s exists; fxp0 and lo0 are not PIC ports", ix)
		}
	}
	for i := 1; i < len(order); i++ {
		if !oidLess(order[i-1], order[i]) {
			t.Fatalf("rows not in OID order at %s, %s", order[i-1], order[i])
		}
	}
}

// TestEntityRowsRejectsUnindexedParent: a board whose parent is not an
// earlier entity (here a sensor) fails instead of rendering contained-in 0.
func TestEntityRowsRejectsUnindexedParent(t *testing.T) {
	c := &Chassis{Model: &Model{}, Components: []Component{
		{Name: "Chassis", Type: "CHASSIS"},
		{Name: "CB0:MIDDLE_TEMP_SENSOR", Type: "SENSOR", Parent: "Chassis"},
		{Name: "Orphan", Type: "LINECARD", Parent: "CB0:MIDDLE_TEMP_SENSOR"},
	}}
	if _, err := entityRows(c); err == nil || !strings.Contains(err.Error(), "Orphan") {
		t.Errorf("err = %v, want an error naming Orphan", err)
	}
}

// TestRenderSSHMatchesCommittedResponses compares every rendered command
// with the response the committed SSH parts hold for it, wherever it lives.
// Before Task 5 that is juniper_mx10004_ssh_1.json; after it, the
// generated chassis part.
func TestRenderSSHMatchesCommittedResponses(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := RenderSSHEntries(c)
	if err != nil {
		t.Fatal(err)
	}
	committed := map[string]string{}
	for _, f := range []string{"juniper_mx10004_ssh_1.json", "juniper_mx10004_ssh_chassis.json"} {
		raw, err := os.ReadFile(filepath.Join(resourceDir, f))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			SSH []sshEntry `json:"ssh"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, e := range doc.SSH {
			committed[e.Command] = e.Response
		}
	}
	for _, e := range entries {
		want, ok := committed[e.Command]
		if !ok {
			t.Errorf("%s: no committed response", e.Command)
			continue
		}
		if e.Response != want {
			i := firstDiff([]byte(e.Response), []byte(want))
			t.Errorf("%s differs at byte %d:\nrendered:  %q\ncommitted: %q", e.Command, i,
				e.Response[max(0, i-60):min(len(e.Response), i+60)], want[max(0, i-60):min(len(want), i+60)])
		}
	}
}

// The shipped table is RFC 2863 complete: each unit over its port, 0.<unit>
// because nothing runs over a unit, <port>.0 because a port runs over
// nothing, and 0.<port> only for a port with no unit.
func TestRenderSNMPRowsStackTable(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := RenderSNMPRows(c)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	n := 0
	for _, r := range rows {
		if rest, ok := strings.CutPrefix(r.OID, "1.3.6.1.2.1.31.1.2.1.3."); ok {
			if r.Response != "1" {
				t.Errorf("row %s = %s, want active(1)", rest, r.Response)
			}
			got[rest] = true
			n++
		}
	}
	want := map[string]bool{}
	withUnit := map[int]bool{}
	for _, u := range c.Units {
		want[fmt.Sprintf("%d.%d", u.IfIndex, u.Parent.IfIndex)] = true
		want[fmt.Sprintf("0.%d", u.IfIndex)] = true
		withUnit[u.Parent.IfIndex] = true
	}
	for _, p := range c.Interfaces() {
		want[fmt.Sprintf("%d.0", p.IfIndex)] = true
		if !withUnit[p.IfIndex] {
			want[fmt.Sprintf("0.%d", p.IfIndex)] = true
		}
	}
	// The system interfaces stack their unit over themselves.
	for _, w := range []string{"78.77", "0.78", "77.0", "80.79", "0.80", "79.0"} {
		want[w] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("missing row %s", w)
		}
	}
	for g := range got {
		if !want[g] {
			t.Errorf("unexpected row %s", g)
		}
	}
	if n != len(want) {
		t.Errorf("%d rows, want %d", n, len(want))
	}
	// The issue's acceptance row, and that xe-0/0/0 is no longer top-most.
	if len(c.Units) == 0 || c.Units[0].IfName != "xe-0/0/0.0" {
		t.Fatalf("first unit = %+v, want xe-0/0/0.0", c.Units)
	}
	u := c.Units[0]
	if u.IfIndex != 73 || !got["73."+strconv.Itoa(u.Parent.IfIndex)] {
		t.Errorf("xe-0/0/0.0 is ifIndex %d on port %d; row 73.<port> present: %v", u.IfIndex, u.Parent.IfIndex, got["73."+strconv.Itoa(u.Parent.IfIndex)])
	}
	if got["0."+strconv.Itoa(u.Parent.IfIndex)] {
		t.Errorf("xe-0/0/0 (ifIndex %d) carries units but has a 0.<port> row", u.Parent.IfIndex)
	}
}

// show interfaces terse prints the family column for a unit configured
// `family inet;` with no address, the address after it when there is one, and
// nothing after the link state for a unit with neither.
func TestRenderTerseUnitFamilies(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	m.Units = []Unit{
		{Parent: "xe-0/0/0", Unit: 0, Inet: "192.0.2.1/24"},
		{Parent: "xe-0/0/0", Unit: 100, Family: "inet"},
		{Parent: "xe-0/0/0", Unit: 200},
	}
	m.SystemInterfaces = []SystemInterface{
		{Name: "em0", IfType: 6, MTU: "1514", SpeedMbps: 1000, Inet: "198.51.100.1/24"},
		{Name: "lo9", IfType: 24, MTU: "65536", Inet: "198.51.100.9/32"},
	}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := RenderSSHEntries(c)
	if err != nil {
		t.Fatal(err)
	}
	var terse string
	for _, e := range entries {
		if e.Command == "show interfaces terse" {
			terse = e.Response
		}
	}
	for _, want := range []string{
		"xe-0/0/0.0              up    up   inet     192.0.2.1/24\n",
		"xe-0/0/0.100            up    up   inet\n",
		"xe-0/0/0.200            up    up\n",
		"em0                     up    up\nem0.0                   up    up   inet     198.51.100.1/24\n",
		"lo9                     up    up\nlo9.0                   up    up   inet     198.51.100.9        --> 0/0",
	} {
		if !strings.Contains(terse, want) {
			t.Errorf("terse output lacks %q:\n%s", want, terse)
		}
	}
}

// The management port is ethernetCsmacd like a line-card port, so the
// bindings exclude it from the line-card and out-queue subtrees by name
// and serve it from a subtree of its own keyed by name. A model with no
// Ethernet system interface renders neither, so its interface subtrees
// are keyed as they were before system interfaces existed.
func TestRenderBindingsManagementPort(t *testing.T) {
	render := func(system []SystemInterface) string {
		t.Helper()
		m, err := loadModel()
		if err != nil {
			t.Fatal(err)
		}
		m.SystemInterfaces = system
		c, err := Expand(m)
		if err != nil {
			t.Fatal(err)
		}
		b, err := RenderBindings(c)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	shipped := render([]SystemInterface{
		{Name: "fxp0", IfType: 6, MTU: "1514", SpeedMbps: 1000, Inet: "10.0.0.1/24"},
		{Name: "lo0", IfType: 24, MTU: "65536", Inet: "10.255.0.1/32"},
	})
	if n := strings.Count(shipped, `"filter": "iftype:6 !name:fxp0"`); n != 2 {
		t.Errorf("shipped bindings exclude fxp0 from %d subtrees, want the line-card and out-queue subtrees", n)
	}
	if n := strings.Count(shipped, `"filter": "name:fxp0"`); n != 1 {
		t.Errorf("shipped bindings carry %d management subtrees, want 1", n)
	}
	if n := strings.Count(shipped, `"filter": "iftype:6"`); n != 1 {
		t.Errorf("shipped bindings keep %d subtrees on the bare iftype:6, want the subinterface subtree only", n)
	}
	two := render([]SystemInterface{
		{Name: "fxp0", IfType: 6, MTU: "1514", SpeedMbps: 1000, Inet: "10.0.0.1/24"},
		{Name: "em0", IfType: 6, MTU: "1514", SpeedMbps: 1000, Inet: "10.0.1.1/24"},
	})
	if !strings.Contains(two, `"filter": "iftype:6 !name:fxp0,em0"`) || !strings.Contains(two, `"filter": "name:fxp0,em0"`) {
		t.Errorf("two management ports are not listed together in the filters")
	}
	none := render([]SystemInterface{{Name: "lo0", IfType: 24, MTU: "65536", Inet: "10.255.0.1/32"}})
	if strings.Contains(none, "name:") {
		t.Errorf("a model without an Ethernet system interface renders a name term")
	}
	if n := strings.Count(none, `"filter": "iftype:6"`); n != 3 {
		t.Errorf("a model without an Ethernet system interface keys %d subtrees on iftype:6, want 3", n)
	}
	if n := strings.Count(none, `"path": "/interfaces/interface[name=*]",`); n != 1 {
		t.Errorf("a model without an Ethernet system interface renders %d interface entry subtrees, want 1", n)
	}
}
