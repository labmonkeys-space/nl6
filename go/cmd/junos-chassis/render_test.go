/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

// TestRenderBindingsMatchesCommitted: the template reproduces the committed
// gnmi-bindings.json byte for byte.
func TestRenderBindingsMatchesCommitted(t *testing.T) {
	m, err := loadModel()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Expand(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RenderBindings(c)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(resourceDir, "gnmi-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		i := firstDiff(got, want)
		lo := max(0, i-80)
		t.Fatalf("rendered bindings differ at byte %d:\nrendered: %q\ncommitted: %q", i, got[lo:min(len(got), i+80)], want[lo:min(len(want), i+80)])
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
	for _, r := range RenderSNMPRows(c) {
		if _, dup := got[r.OID]; dup {
			t.Fatalf("duplicate OID %s", r.OID)
		}
		got[r.OID] = r.Response
		order = append(order, r.OID)
	}
	want := map[string]string{
		"1.3.6.1.2.1.2.1.0":                    "48",
		"1.3.6.1.2.1.2.2.1.2.1":                "xe-0/0/0",
		"1.3.6.1.2.1.2.2.1.4.1":                "9216",
		"1.3.6.1.2.1.2.2.1.6.26":               "00:1A:2B:3C:00:1a",
		"1.3.6.1.2.1.31.1.1.1.6.24":            "14181198160",
		"1.3.6.1.2.1.31.1.1.1.6.25":            "13897247566",
		"1.3.6.1.2.1.31.1.1.1.10.48":           "14051568552",
		"1.3.6.1.2.1.31.1.1.1.15.48":           "10000",
		"1.3.6.1.2.1.31.1.1.1.18.7":            "to-core-07",
		"1.3.6.1.4.1.2636.3.1.13.1.5.9.1.0.0":  "Routing Engine 0",
		"1.3.6.1.4.1.2636.3.1.13.1.20.9.1.0.0": "45",
		"1.3.6.1.2.1.47.1.1.1.1.3.1":           "1.3.6.1.4.1.2636.1.1.1.2.168",
	}
	for oid, v := range want {
		if got[oid] != v {
			t.Errorf("%s = %q, want %q", oid, got[oid], v)
		}
	}
	if len(got) != 1+48*13+3+len(m.LegacySNMP) {
		t.Errorf("%d rows, want ifNumber + 48x13 interface rows + 3 jnxOperating + %d legacy", len(got), len(m.LegacySNMP))
	}
	for i := 1; i < len(order); i++ {
		if !oidLess(order[i-1], order[i]) {
			t.Fatalf("rows not in OID order at %s, %s", order[i-1], order[i])
		}
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
