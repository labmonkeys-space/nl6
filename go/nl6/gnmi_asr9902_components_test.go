/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

var (
	qddRowRe     = regexp.MustCompile(`-QDD_\d+_\d+$`)
	ssdRowRe     = regexp.MustCompile(`-SSD[ab]-[A-Z]+$`)
	bareNodeRe   = regexp.MustCompile(`^0/(RP[01]|0)/CPU0$`)
	pkgNodeRe    = regexp.MustCompile(`^IOSXR-PKG/(\d+) `)
	frontPortRe  = regexp.MustCompile(`^(TenGigE|HundredGigE)0/0/0/\d+$`)
	invNameRe    = regexp.MustCompile(`NAME: "([^"]+)"`)
	briefStateRe = regexp.MustCompile(`^(\S+)\s+unassigned\s+(\S+)\s+(\S+)$`)
)

// servedASR9902Components subscribes ONCE to the component state and
// returns, per component name, its served leaves and its type.
func servedASR9902Components(t *testing.T) (leaves map[string]map[string]bool, types map[string]string) {
	t.Helper()
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, cats["cisco_asr9902"], 2)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "openconfig-platform", "/components/component/state")
	if err != nil {
		t.Fatal(err)
	}
	leaves, types = map[string]map[string]bool{}, map[string]string{}
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		var name string
		for _, e := range n.GetPrefix().GetElem() {
			if e.GetName() == "component" {
				name = e.GetKey()["name"]
			}
		}
		if leaves[name] == nil {
			leaves[name] = map[string]bool{}
		}
		for _, u := range n.GetUpdate() {
			p := strings.TrimPrefix(pathToString(u.GetPath()), "/")
			leaves[name][p] = true
			if p == "type" {
				types[name] = u.GetVal().GetStringVal()
			}
		}
	}
	if len(leaves) == 0 {
		t.Fatal("no component served")
	}
	return leaves, types
}

// IOS-XR 24.2.2 names node OS components IOSXR-NODE <node>, reports each
// active package per node as IOSXR-PKG/<n> <package>, suffixes SSD FPDs
// with the vendor and has a QDD_<n>_<n> FPD beside each QDD_BRT one
// (nl6#811). Leaf counts are the reference's.
func TestASR9902ComponentNamesFollowIOSXR(t *testing.T) {
	leaves, types := servedASR9902Components(t)
	count := map[string]int{}
	for name, l := range leaves {
		var kind string
		switch {
		case strings.HasPrefix(name, "IOSXR-NODE "):
			kind = "node"
			if types[name] != "OPERATING_SYSTEM" || len(l) != 7 || l["parent"] {
				t.Errorf("%s: type %q, %d leaves, parent %v; want OPERATING_SYSTEM, 7, none", name, types[name], len(l), l["parent"])
			}
		case strings.HasPrefix(name, "IOSXR-PKG/"):
			kind = "pkg"
			if types[name] != "SOFTWARE_MODULE" || len(l) != 6 || l["parent"] {
				t.Errorf("%s: type %q, %d leaves, parent %v; want SOFTWARE_MODULE, 6, none", name, types[name], len(l), l["parent"])
			}
		case qddRowRe.MatchString(name):
			kind = "qdd"
			if port := name[strings.LastIndexByte(name, '_')+1:]; types["HundredGigE0/0/0/"+port] != "TRANSCEIVER" {
				t.Errorf("%s: QSFP bay %s holds no optic", name, port)
			}
			if l["type"] || len(l) != 11 {
				t.Errorf("%s: type leaf %v, %d leaves; want no type and 11 leaves", name, l["type"], len(l))
			}
		case strings.Contains(name, "-SSD"):
			kind = "ssd"
			if !ssdRowRe.MatchString(name) {
				t.Errorf("%s: want <loc>-SSDa-<VENDOR> or -SSDb-<VENDOR>", name)
			}
		case bareNodeRe.MatchString(name) || strings.HasPrefix(name, "asr9k-"):
			t.Errorf("%s: IOS-XR does not name a component this way", name)
		}
		count[kind]++
	}
	for name := range leaves {
		if m := pkgNodeRe.FindStringSubmatch(name); m != nil && m[1] != "1" && m[1] != "2" && m[1] != "3" {
			t.Errorf("%s: package node number outside 1..3", name)
		}
	}
	// QDD_0_<port> (QDD_BRT does not match) on the eight populated QSFP bays.
	for kind, want := range map[string]int{"node": 3, "pkg": 18, "qdd": 8, "ssd": 5} {
		if count[kind] != want {
			t.Errorf("%d %s components, want %d", count[kind], kind, want)
		}
	}
	for n := 1; n <= 3; n++ {
		if !leaves[fmt.Sprintf("IOSXR-PKG/%d asr9k-xr-24.2.2", n)]["name"] {
			t.Errorf("node %d does not report the base package", n)
		}
	}
}

// Only a front port with an optic has transceiver components, and gNMI,
// ENTITY-MIB and show inventory agree on which ports those are. Every
// port's interface stays; an empty one is admin up and oper down in the
// state engine SNMP reads and in show interfaces brief (nl6#811).
// cisco_asr9902 serves no gNMI interface oper-status leaf.
func TestASR9902EmptyPortsAgreeAcrossSurfaces(t *testing.T) {
	leaves, types := servedASR9902Components(t)
	res := loadCiscoAsr9902(t)
	var gnmiOptics, entOptics, cliOptics, ports []string
	for name := range leaves {
		if types[name] == "TRANSCEIVER" && frontPortRe.MatchString(name) {
			gnmiOptics = append(gnmiOptics, name)
		}
	}
	entName, entClass := map[string]string{}, map[string]string{}
	for _, e := range res.SNMP {
		switch {
		case strings.HasPrefix(e.OID, "1.3.6.1.2.1.47.1.1.1.1.7."):
			entName[strings.TrimPrefix(e.OID, "1.3.6.1.2.1.47.1.1.1.1.7.")] = e.Response
		case strings.HasPrefix(e.OID, "1.3.6.1.2.1.47.1.1.1.1.5."):
			entClass[strings.TrimPrefix(e.OID, "1.3.6.1.2.1.47.1.1.1.1.5.")] = e.Response
		case strings.HasPrefix(e.OID, "1.3.6.1.2.1.2.2.1.2.") && frontPortRe.MatchString(e.Response):
			ports = append(ports, e.Response)
		}
	}
	for ix, name := range entName {
		if entClass[ix] == "9" && frontPortRe.MatchString(name) {
			entOptics = append(entOptics, name)
		}
	}
	brief := map[string]string{} // interface -> "status/protocol"
	for _, e := range res.SSH {
		switch e.Command {
		case "show inventory":
			for _, m := range invNameRe.FindAllStringSubmatch(e.Response, -1) {
				if frontPortRe.MatchString(m[1]) {
					cliOptics = append(cliOptics, m[1])
				}
			}
		case "show interfaces brief":
			for _, line := range strings.Split(e.Response, "\n") {
				if m := briefStateRe.FindStringSubmatch(line); m != nil {
					brief[m[1]] = m[2] + "/" + m[3]
				}
			}
		}
	}
	sort.Strings(gnmiOptics)
	sort.Strings(entOptics)
	sort.Strings(cliOptics)
	if len(ports) != 48 {
		t.Errorf("%d front-port interfaces in ifTable, want 48", len(ports))
	}
	if len(gnmiOptics) != 28 {
		t.Errorf("%d optics in gNMI, want 28 (8 HundredGigE, 20 of 40 TenGigE)", len(gnmiOptics))
	}
	if strings.Join(gnmiOptics, " ") != strings.Join(entOptics, " ") || strings.Join(gnmiOptics, " ") != strings.Join(cliOptics, " ") {
		t.Errorf("optics disagree\n gNMI %v\n  ENT %v\n  CLI %v", gnmiOptics, entOptics, cliOptics)
	}
	populated := map[string]bool{}
	for _, o := range gnmiOptics {
		populated[o] = true
	}
	ic := newASR9902Device(t).metricsCycler.ifCounters.Load()
	ifIndex := map[string]string{}
	for _, e := range res.SNMP {
		if strings.HasPrefix(e.OID, "1.3.6.1.2.1.2.2.1.2.") {
			ifIndex[e.Response] = strings.TrimPrefix(e.OID, "1.3.6.1.2.1.2.2.1.2.")
		}
	}
	for _, p := range ports {
		wantOper, wantBrief := "1", "up/up"
		if !populated[p] {
			wantOper, wantBrief = "2", "down/down"
		}
		if got := ic.GetDynamic(ifTablePrefix + "8." + ifIndex[p]); got != wantOper {
			t.Errorf("%s ifOperStatus %s, want %s", p, got, wantOper)
		}
		if got := ic.GetDynamic(ifTablePrefix + "7." + ifIndex[p]); got != "1" {
			t.Errorf("%s ifAdminStatus %s, want 1", p, got)
		}
		if brief[p] != wantBrief {
			t.Errorf("%s show interfaces brief %q, want %q", p, brief[p], wantBrief)
		}
		if populated[p] {
			continue
		}
		if leaves["0/0-"+p] == nil {
			t.Errorf("empty port %s lost its PORT component", p)
		}
		for name := range leaves {
			if strings.HasPrefix(name, p+"-") {
				t.Errorf("empty port %s serves %s", p, name)
			}
		}
	}
}
