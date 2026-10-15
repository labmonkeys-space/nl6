/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// A Junos profile answers three commands that describe the same device:
// show configuration, show interfaces terse and show route instance detail.
// They drifted apart once: the detail output reported three VRFs on units
// 100, 200 and 999 while the configuration had one untagged unit 0, which
// Junos would not commit. This guard parses the three and requires them to
// agree on units, VLAN tagging, VRF membership and router IDs.

// junosNode is one block of a Junos configuration: "name {" ... "}".
type junosNode struct {
	name     string
	stmts    []string
	children []*junosNode
}

func (n *junosNode) child(name string) *junosNode {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

func (n *junosNode) has(stmt string) bool {
	for _, s := range n.stmts {
		if s == stmt {
			return true
		}
	}
	return false
}

// stmtArg returns the rest of the first statement starting with prefix.
func (n *junosNode) stmtArg(prefix string) (string, bool) {
	for _, s := range n.stmts {
		if rest, ok := strings.CutPrefix(s, prefix+" "); ok {
			return rest, true
		}
	}
	return "", false
}

// parseJunosConfig builds the block tree. Comments (## ...) and the
// "version" line are statements like any other; a "## SECRET-DATA" trailer
// is dropped from its statement.
func parseJunosConfig(text string) (*junosNode, error) {
	root := &junosNode{name: ""}
	stack := []*junosNode{root}
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "##") || (strings.HasPrefix(line, "/*") && strings.HasSuffix(line, "*/")) {
			continue
		}
		// A "; ## SECRET-DATA" trailer follows the statement; " ## " inside a
		// quoted value is part of the value.
		if j := strings.Index(line, "; ##"); j >= 0 {
			line = line[:j+1]
		}
		top := stack[len(stack)-1]
		switch {
		case line == "}":
			if len(stack) == 1 {
				return nil, fmt.Errorf("line %d: unbalanced }", i+1)
			}
			stack = stack[:len(stack)-1]
		case strings.HasSuffix(line, " {"):
			n := &junosNode{name: strings.TrimSuffix(line, " {")}
			top.children = append(top.children, n)
			stack = append(stack, n)
		case strings.HasSuffix(line, ";"):
			top.stmts = append(top.stmts, strings.TrimSuffix(line, ";"))
		default:
			return nil, fmt.Errorf("line %d: %q is neither a block, a statement nor a close", i+1, raw)
		}
	}
	if len(stack) != 1 {
		return nil, fmt.Errorf("unclosed block %q", stack[len(stack)-1].name)
	}
	return root, nil
}

// junosUnit is one logical unit as a surface describes it.
type junosUnit struct {
	family  string // "inet" or ""
	address string // without prefix length, "" when none
	vlanID  int    // -1 when absent (config only)
}

func stripPrefixLen(a string) string {
	if i := strings.IndexByte(a, '/'); i >= 0 {
		return a[:i]
	}
	return a
}

// configUnits returns port -> unit number -> unit, and the ports with
// vlan-tagging.
// tagged maps a port to the tagging statement it carries ("vlan-tagging" or
// "flexible-vlan-tagging"); a port with neither is absent.
func configUnits(root *junosNode) (map[string]map[int]junosUnit, map[string]string, error) {
	units := map[string]map[int]junosUnit{}
	tagged := map[string]string{}
	ifs := root.child("interfaces")
	if ifs == nil {
		return nil, nil, fmt.Errorf("no interfaces block")
	}
	for _, port := range ifs.children {
		for _, t := range []string{"vlan-tagging", "flexible-vlan-tagging"} {
			if port.has(t) {
				tagged[port.name] = t
			}
		}
		for _, c := range port.children {
			numStr, ok := strings.CutPrefix(c.name, "unit ")
			if !ok {
				continue
			}
			num, err := strconv.Atoi(numStr)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %q is not a unit number", port.name, c.name)
			}
			u := junosUnit{vlanID: -1}
			if v, ok := c.stmtArg("vlan-id"); ok {
				if u.vlanID, err = strconv.Atoi(v); err != nil {
					return nil, nil, fmt.Errorf("%s unit %d: vlan-id %q", port.name, num, v)
				}
			}
			if fam, ok := c.stmtArg("family"); ok {
				u.family = fam
			}
			for _, fam := range c.children {
				if name, ok := strings.CutPrefix(fam.name, "family "); ok {
					u.family = name
					if a, ok := fam.stmtArg("address"); ok {
						u.address = stripPrefixLen(a)
					}
				}
			}
			if units[port.name] == nil {
				units[port.name] = map[int]junosUnit{}
			}
			units[port.name][num] = u
		}
	}
	return units, tagged, nil
}

// terseUnits reads show interfaces terse: port -> unit number -> unit.
func terseUnits(text string) (map[string]map[int]junosUnit, error) {
	units := map[string]map[int]junosUnit{}
	for _, line := range strings.Split(text, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		port, unit, ok := splitSubinterfaceName(f[0])
		if !ok {
			continue
		}
		num, _ := strconv.Atoi(unit)
		u := junosUnit{vlanID: -1}
		if len(f) >= 4 {
			u.family = f[3]
		}
		if len(f) >= 5 {
			u.address = stripPrefixLen(f[4])
		}
		if units[port] == nil {
			units[port] = map[int]junosUnit{}
		}
		units[port][num] = u
	}
	if len(units) == 0 {
		return nil, fmt.Errorf("show interfaces terse lists no unit")
	}
	return units, nil
}

// junosVRF is one instance as show route instance detail prints it.
type junosVRF struct {
	name, routerID, rd, typ    string
	interfaces                 []string
	vrfImport, vrfExport       string
	importTarget, exportTarget string
}

func parseInstanceDetail(text string) ([]junosVRF, error) {
	var out []junosVRF
	var cur *junosVRF
	inIfs := false
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
			flush()
		case !strings.HasPrefix(raw, " ") && strings.HasSuffix(line, ":"):
			flush()
			cur = &junosVRF{name: strings.TrimSuffix(line, ":")}
			inIfs = false
		case cur == nil:
			continue
		case line == "Interfaces:":
			inIfs = true
		case inIfs && strings.HasPrefix(raw, "    "):
			cur.interfaces = append(cur.interfaces, line)
		default:
			inIfs = false
			k, v, ok := strings.Cut(line, ": ")
			if !ok {
				continue
			}
			v = strings.TrimSpace(strings.Trim(strings.TrimSpace(v), "[]"))
			switch k {
			case "Type":
				cur.typ = strings.Fields(v)[0]
			case "Router ID":
				cur.routerID = v
			case "Route-distinguisher":
				cur.rd = v
			case "Vrf-import":
				cur.vrfImport = v
			case "Vrf-export":
				cur.vrfExport = v
			case "Vrf-import-target":
				cur.importTarget = v
			case "Vrf-export-target":
				cur.exportTarget = v
			}
		}
	}
	flush()
	// Only VRFs are routing-instances stanzas; the master instance (Type:
	// forwarding) a real capture leads with is the default routing table.
	vrfs := out[:0]
	for _, v := range out {
		if v.typ == "vrf" {
			vrfs = append(vrfs, v)
		}
	}
	if len(vrfs) == 0 {
		return nil, fmt.Errorf("show route instance detail lists no vrf instance")
	}
	return vrfs, nil
}

// junosCLIFindings applies the rules to one profile's three responses and
// returns every disagreement, each naming what disagrees.
func junosCLIFindings(ssh map[string]string) []string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	root, err := parseJunosConfig(ssh["show configuration"])
	if err != nil {
		return []string{"show configuration: " + err.Error()}
	}
	cfg, tagged, err := configUnits(root)
	if err != nil {
		return []string{"show configuration: " + err.Error()}
	}
	terse, err := terseUnits(ssh["show interfaces terse"])
	if err != nil {
		return []string{err.Error()}
	}
	vrfs, err := parseInstanceDetail(ssh["show route instance detail"])
	if err != nil {
		return []string{err.Error()}
	}

	// Rule 1: the same units per port, same family and address.
	ports := map[string]bool{}
	for p := range cfg {
		ports[p] = true
	}
	for p := range terse {
		ports[p] = true
	}
	for _, p := range junosSortedPorts(ports) {
		for _, n := range sortedUnitNumbers(cfg[p]) {
			if _, ok := terse[p][n]; !ok {
				add("%s unit %d is configured but show interfaces terse does not list it", p, n)
			}
		}
		for _, n := range sortedUnitNumbers(terse[p]) {
			cu, ok := cfg[p][n]
			if !ok {
				add("show interfaces terse lists %s.%d but show configuration does not configure it", p, n)
				continue
			}
			tu := terse[p][n]
			if cu.family != tu.family || cu.address != tu.address {
				add("%s.%d: show configuration has family %q address %q, show interfaces terse %q %q", p, n, cu.family, cu.address, tu.family, tu.address)
			}
		}
		// Rule 2: tagging.
		hasHigher := false
		for n := range cfg[p] {
			if n > 0 {
				hasHigher = true
			}
		}
		if !hasHigher {
			continue
		}
		if tagged[p] == "" {
			add("%s carries a unit above 0 but has no vlan-tagging", p)
		}
		for _, n := range sortedUnitNumbers(cfg[p]) {
			switch {
			case n == 0 && tagged[p] == "vlan-tagging" && cfg[p][n].vlanID < 0:
				add("%s unit 0 has no vlan-id on a vlan-tagging port", p)
			case n > 0 && cfg[p][n].vlanID != n:
				add("%s unit %d: vlan-id is %d, want %d", p, n, cfg[p][n].vlanID, n)
			}
		}
	}

	// Rule 3: every VRF is an instance that says the same.
	ri := root.child("routing-instances")
	po := root.child("policy-options")
	communities := map[string]string{}
	if po != nil {
		for _, s := range po.stmts {
			if rest, ok := strings.CutPrefix(s, "community "); ok {
				name, members, _ := strings.Cut(rest, " members ")
				communities[name] = strings.TrimSpace(strings.Trim(strings.TrimSpace(members), "[]"))
			}
		}
	}
	policyCommunity := func(policy, verb string) (string, bool) {
		if po == nil {
			return "", false
		}
		ps := po.child("policy-statement " + policy)
		if ps == nil {
			return "", false
		}
		var walk func(n *junosNode) (string, bool)
		walk = func(n *junosNode) (string, bool) {
			for _, s := range n.stmts {
				if rest, ok := strings.CutPrefix(s, verb+" "); ok {
					return rest, true
				}
			}
			for _, c := range n.children {
				if v, ok := walk(c); ok {
					return v, true
				}
			}
			return "", false
		}
		return walk(ps)
	}
	for _, v := range vrfs {
		var inst *junosNode
		if ri != nil {
			inst = ri.child(v.name)
		}
		if inst == nil {
			add("VRF %s (router ID %s) has no routing-instances stanza", v.name, v.routerID)
			continue
		}
		if !inst.has("instance-type vrf") {
			add("routing-instance %s is not instance-type vrf", v.name)
		}
		var cfgIfs []string
		for _, s := range inst.stmts {
			if rest, ok := strings.CutPrefix(s, "interface "); ok {
				cfgIfs = append(cfgIfs, rest)
			}
		}
		sort.Strings(cfgIfs)
		want := append([]string(nil), v.interfaces...)
		sort.Strings(want)
		if strings.Join(cfgIfs, ",") != strings.Join(want, ",") {
			add("routing-instance %s configures interfaces %v, show route instance detail lists %v", v.name, cfgIfs, want)
		}
		for _, name := range v.interfaces {
			p, unit, ok := splitSubinterfaceName(name)
			n, _ := strconv.Atoi(unit)
			u, configured := cfg[p][n]
			switch {
			case !ok || !configured:
				add("VRF %s uses %s, which show configuration does not configure as a unit", v.name, name)
			case u.family != "inet":
				add("VRF %s uses %s, which has no family inet", v.name, name)
			case u.address != "":
				add("VRF %s uses %s, which carries address %s; VRF units carry none", v.name, name, u.address)
			}
		}
		if rd, _ := inst.stmtArg("route-distinguisher"); rd != v.rd {
			add("routing-instance %s: route-distinguisher %q, show route instance detail says %q", v.name, rd, v.rd)
		}
		rid := ""
		if ro := inst.child("routing-options"); ro != nil {
			rid, _ = ro.stmtArg("router-id")
		}
		if rid != v.routerID {
			add("routing-instance %s: router-id %q, show route instance detail says Router ID %s", v.name, rid, v.routerID)
		}
		for _, pol := range []struct{ stmt, want, verb, target string }{
			{"vrf-import", v.vrfImport, "from community", v.importTarget},
			{"vrf-export", v.vrfExport, "community add", v.exportTarget},
		} {
			got, _ := inst.stmtArg(pol.stmt)
			if got != pol.want {
				add("routing-instance %s: %s %q, show route instance detail says %q", v.name, pol.stmt, got, pol.want)
				continue
			}
			comm, ok := policyCommunity(got, pol.verb)
			if !ok {
				add("policy-statement %s (%s of %s) is missing or names no community via %q", got, pol.stmt, v.name, pol.verb)
				continue
			}
			if members, ok := communities[comm]; !ok || members != pol.target {
				add("community %s (via %s) has members %q, show route instance detail says %s %s", comm, got, members, pol.stmt+"-target", pol.target)
			}
		}
	}
	return out
}

func junosSortedPorts(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedUnitNumbers(m map[int]junosUnit) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// isJunosProfile: the detail output is Junos's, and the other two exist.
func isJunosProfile(ssh map[string]string) bool {
	return strings.Contains(ssh["show route instance detail"], "Route-distinguisher:") &&
		ssh["show configuration"] != "" && ssh["show interfaces terse"] != ""
}

const junosControlConfig = `interfaces {
    xe-1/0/0 {
        vlan-tagging;
        unit 0 {
            vlan-id 1;
            family inet {
                address 192.0.2.1/24;
            }
        }
        unit 100 {
            vlan-id 100;
            family inet;
        }
    }
}
policy-options {
    policy-statement A-export {
        term 1 {
            then {
                community add A;
                accept;
            }
        }
    }
    policy-statement A-import {
        term 1 {
            from community A;
            then accept;
        }
        term 2 {
            then reject;
        }
    }
    community A members target:65001:100;
}
routing-instances {
    A {
        instance-type vrf;
        interface xe-1/0/0.100;
        route-distinguisher 65001:100;
        vrf-import A-import;
        vrf-export A-export;
        routing-options {
            router-id 10.100.0.9;
        }
    }
}
`

const junosControlTerse = `Interface               Admin Link Proto    Local                 Remote
xe-1/0/0                up    up
xe-1/0/0.0              up    up   inet     192.0.2.1/24
xe-1/0/0.100            up    up   inet
`

const junosControlDetail = `A:
  Router ID: 10.100.0.9
  Type: vrf    State: Active
  Interfaces:
    xe-1/0/0.100
  Route-distinguisher: 65001:100
  Vrf-import: [ A-import ]
  Vrf-export: [ A-export ]
  Vrf-import-target: [ target:65001:100 ]
  Vrf-export-target: [ target:65001:100 ]
  Fast-external-fallover enabled
  Tables:
    A.inet.0                 : 1 routes (1 active, 0 holddown, 0 hidden)
`

func junosControl() map[string]string {
	return map[string]string{
		"show configuration":         junosControlConfig,
		"show interfaces terse":      junosControlTerse,
		"show route instance detail": junosControlDetail,
	}
}

// The positive control: a consistent trio passes, and each planted defect
// is reported by name. A guard that read zero Junos profiles would pass on
// nothing, so this is what gives the corpus test below its meaning.
func TestJunosCLIGuardControl(t *testing.T) {
	if got := junosCLIFindings(junosControl()); len(got) != 0 {
		t.Fatalf("the consistent control has findings: %v", got)
	}
	cases := []struct {
		name, cmd, from, to, want string
	}{
		{"unit missing from config", "show configuration", "        unit 100 {\n            vlan-id 100;\n            family inet;\n        }\n", "", "xe-1/0/0.100 but show configuration does not configure it"},
		{"unit missing from terse", "show interfaces terse", "xe-1/0/0.100            up    up   inet\n", "", "unit 100 is configured but show interfaces terse does not list it"},
		{"router ID disagrees", "show configuration", "router-id 10.100.0.9", "router-id 10.100.0.8", "routing-instance A: router-id \"10.100.0.8\", show route instance detail says Router ID 10.100.0.9"},
		{"no vlan-tagging", "show configuration", "        vlan-tagging;\n", "", "xe-1/0/0 carries a unit above 0 but has no vlan-tagging"},
		{"VRF unit with an address", "show configuration", "            family inet;\n", "            family inet {\n                address 10.100.0.9/24;\n            }\n", "carries address 10.100.0.9; VRF units carry none"},
		{"instance missing", "show configuration", "    A {\n        instance-type vrf;", "    B {\n        instance-type vrf;", "VRF A (router ID 10.100.0.9) has no routing-instances stanza"},
		{"community members disagree", "show configuration", "members target:65001:100", "members target:65001:101", "community A (via A-import) has members \"target:65001:101\""},
	}
	// Legal variants that must stay quiet: a master instance in the detail
	// output, a bracketed community, an inet6 unit, an annotated stanza, a
	// flexible-vlan-tagging port whose unit 0 is native.
	for _, c := range []struct{ name, cmd, from, to string }{
		{"master instance", "show route instance detail", "A:\n", "master:\n  Router ID: 192.0.2.1\n  Type: forwarding    State: Active\n  Tables:\n    inet.0                   : 2 routes (2 active, 0 holddown, 0 hidden)\n\nA:\n"},
		{"bracketed community", "show configuration", "members target:65001:100", "members [ target:65001:100 ]"},
		{"annotation", "show configuration", "    A {\n", "    /* customer A */\n    A {\n"},
		{"native unit 0", "show configuration", "        vlan-tagging;\n        unit 0 {\n            vlan-id 1;\n", "        flexible-vlan-tagging;\n        native-vlan-id 1;\n        unit 0 {\n"},
	} {
		ssh := junosControl()
		if !strings.Contains(ssh[c.cmd], c.from) {
			t.Fatalf("%s: control lacks %q", c.name, c.from)
		}
		ssh[c.cmd] = strings.Replace(ssh[c.cmd], c.from, c.to, 1)
		if got := junosCLIFindings(ssh); len(got) != 0 {
			t.Errorf("%s: legal variant has findings %v", c.name, got)
		}
	}
	ssh := junosControl()
	ssh["show configuration"] = strings.Replace(ssh["show configuration"], "        unit 100 {\n            vlan-id 100;\n            family inet;\n", "        unit 100 {\n            vlan-id 100;\n            family inet6 {\n                address 2001:db8::1/64;\n            }\n", 1)
	ssh["show interfaces terse"] = strings.Replace(ssh["show interfaces terse"], "xe-1/0/0.100            up    up   inet\n", "xe-1/0/0.100            up    up   inet6    2001:db8::1/64\n", 1)
	ssh["show route instance detail"] = strings.Replace(ssh["show route instance detail"], "    xe-1/0/0.100\n", "", 1)
	ssh["show configuration"] = strings.Replace(ssh["show configuration"], "        interface xe-1/0/0.100;\n", "", 1)
	for _, g := range junosCLIFindings(ssh) {
		if strings.Contains(g, "xe-1/0/0.100") {
			t.Errorf("an inet6 unit that both surfaces agree on is reported: %s", g)
		}
	}
	for _, c := range cases {
		ssh := junosControl()
		if !strings.Contains(ssh[c.cmd], c.from) {
			t.Fatalf("%s: control lacks %q", c.name, c.from)
		}
		ssh[c.cmd] = strings.Replace(ssh[c.cmd], c.from, c.to, 1)
		got := junosCLIFindings(ssh)
		found := false
		for _, g := range got {
			if strings.Contains(g, c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: findings %v do not contain %q", c.name, got, c.want)
		}
	}
}

func TestShippedJunosCLIOutputsAgree(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	checked := 0
	for _, profile := range shippedProfileNames(t) {
		res, err := sm.LoadSpecificResources(profile)
		if err != nil {
			t.Fatal(err)
		}
		ssh := map[string]string{}
		for _, e := range res.SSH {
			ssh[e.Command] = e.Response
		}
		if !isJunosProfile(ssh) {
			continue
		}
		checked++
		for _, f := range junosCLIFindings(ssh) {
			t.Errorf("%s: %s", profile, f)
		}
	}
	if checked < 3 {
		t.Errorf("%d Junos profiles checked, want the three shipped ones at least", checked)
	}
}
