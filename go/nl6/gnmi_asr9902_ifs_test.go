/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"slices"
	"sort"
	"strings"
	"testing"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// newASR9902Device is a device on the shipped cisco_asr9902 resources, so
// its interface set is the generated IF-MIB rows.
func newASR9902Device(t *testing.T) *DeviceSimulator {
	t.Helper()
	res := loadCiscoAsr9902(t)
	mc := &MetricsCycler{}
	mc.InitIfCounters(res, 1)
	return &DeviceSimulator{ID: "asr9902", IP: net.IPv4(10, 42, 0, 9), resourceFile: "cisco_asr9902.json", resources: res, metricsCycler: mc}
}

// asr9902Entries subscribes ONCE in PROTO with gnmic's origin and returns,
// per list entry (the prefix with its keys), the notification count and
// the sorted leaf paths relative to the entry.
func asr9902Entries(t *testing.T, path string, entry func(*gnmipb.Path) string) (count map[string]int, leaves map[string][]string) {
	t.Helper()
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	_, _, addr, cleanup := startTestGnmiServerWithDevice(t, cats["cisco_asr9902"], newASR9902Device(t))
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "openconfig-interfaces", path)
	if err != nil {
		t.Fatal(err)
	}
	count, leaves = map[string]int{}, map[string][]string{}
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		e := entry(n.GetPrefix())
		count[e]++
		for _, u := range n.GetUpdate() {
			_, leaf, _ := strings.Cut(pathToString(n.GetPrefix())+pathToString(u.GetPath()), "/state/counters/")
			leaves[e] = append(leaves[e], leaf)
		}
	}
	for e := range leaves {
		sort.Strings(leaves[e])
	}
	return count, leaves
}

// counterLeaves are the 19 interface counter leaves an IOS-XR 24.2.2 ASR
// 9902 sends per physical port, relative to state/counters.
var counterLeaves = []string{
	"carrier-transitions", "in-broadcast-pkts", "in-discards", "in-errors", "in-fcs-errors", "in-multicast-pkts",
	"in-octets", "in-pkts", "in-unicast-pkts", "in-unknown-protos", "last-clear", "last-read-time",
	"out-broadcast-pkts", "out-discards", "out-errors", "out-multicast-pkts", "out-octets", "out-pkts", "out-unicast-pkts",
}

// nl6#810: Bundle-Ether, BVI and Null0 answer like a physical port, a
// Loopback sends one notification with carrier-transitions only, and no
// subinterface row is listed as an interface.
func TestASR9902InterfaceCountersServeLogicalInterfaces(t *testing.T) {
	count, leaves := asr9902Entries(t, "/interfaces/interface/state/counters", func(p *gnmipb.Path) string {
		return p.GetElem()[1].GetKey()["name"]
	})
	for _, name := range []string{"HundredGigE0/0/0/8", "TenGigE0/0/0/0", "MgmtEth0/RP0/CPU0/0", "Bundle-Ether1", "BVI1", "Null0"} {
		if count[name] != 2 || !slices.Equal(leaves[name], counterLeaves) {
			t.Errorf("%s: %d notifications, leaves %v; want 2 and the 19 counter leaves", name, count[name], leaves[name])
		}
	}
	if count["Loopback0"] != 1 || !slices.Equal(leaves["Loopback0"], []string{"carrier-transitions"}) {
		t.Errorf("Loopback0: %d notifications, leaves %v; want 1 with carrier-transitions only", count["Loopback0"], leaves["Loopback0"])
	}
	for name := range count {
		if strings.Contains(name, ".") {
			t.Errorf("subinterface %s is listed as an interface", name)
		}
	}
	if len(count) != 54 {
		t.Errorf("%d interfaces, want 54 (50 physical, 4 logical)", len(count))
	}
}

// nl6#808: only the configured VLAN subinterfaces answer, never index 0. A
// Bundle-Ether subinterface omits the six unicast, multicast and broadcast
// counters and last-clear; a HundredGigE subinterface carries all 19.
func TestASR9902SubinterfaceCountersServeVLANSubinterfaces(t *testing.T) {
	count, leaves := asr9902Entries(t, "/interfaces/interface/subinterfaces/subinterface/state/counters", func(p *gnmipb.Path) string {
		e := p.GetElem()
		return e[1].GetKey()["name"] + "." + e[3].GetKey()["index"]
	})
	var got []string
	for e := range count {
		got = append(got, e)
	}
	sort.Strings(got)
	if strings.Join(got, " ") != "Bundle-Ether1.300 HundredGigE0/0/0/8.100 HundredGigE0/0/0/8.200" {
		t.Fatalf("subinterfaces %v, want Bundle-Ether1.300 and HundredGigE0/0/0/8.100, .200", got)
	}
	for _, e := range []string{"HundredGigE0/0/0/8.100", "HundredGigE0/0/0/8.200"} {
		if count[e] != 2 || !slices.Equal(leaves[e], counterLeaves) {
			t.Errorf("%s: %d notifications, leaves %v; want 2 and the 19 counter leaves", e, count[e], leaves[e])
		}
	}
	var bundle []string
	for _, l := range counterLeaves {
		if l != "last-clear" && !strings.HasSuffix(l, "cast-pkts") {
			bundle = append(bundle, l)
		}
	}
	if count["Bundle-Ether1.300"] != 2 || !slices.Equal(leaves["Bundle-Ether1.300"], bundle) {
		t.Errorf("Bundle-Ether1.300: %d notifications, leaves %v; want 2 and %v", count["Bundle-Ether1.300"], leaves["Bundle-Ether1.300"], bundle)
	}
}

// The gNMI interface and subinterface names are the IF-MIB rows: every
// ifDescr is an interface or a <parent>.<index> subinterface, and back.
func TestASR9902GnmiInterfacesAreTheIfTable(t *testing.T) {
	res := loadCiscoAsr9902(t)
	var ifDescr []string
	for _, e := range res.SNMP {
		if strings.HasPrefix(e.OID, "1.3.6.1.2.1.2.2.1.2.") {
			ifDescr = append(ifDescr, e.Response)
		}
	}
	ifs, _ := asr9902Entries(t, "/interfaces/interface/state/counters", func(p *gnmipb.Path) string {
		return p.GetElem()[1].GetKey()["name"]
	})
	subs, _ := asr9902Entries(t, "/interfaces/interface/subinterfaces/subinterface/state/counters", func(p *gnmipb.Path) string {
		e := p.GetElem()
		return e[1].GetKey()["name"] + "." + e[3].GetKey()["index"]
	})
	var served []string
	for n := range ifs {
		served = append(served, n)
	}
	for n := range subs {
		served = append(served, n)
	}
	sort.Strings(served)
	sort.Strings(ifDescr)
	if !slices.Equal(served, ifDescr) {
		t.Errorf("gNMI serves %d names, ifTable lists %d:\n gNMI %v\n ifTable %v", len(served), len(ifDescr), served, ifDescr)
	}
}

// Loopback0 and Null0 carry no traffic (IOS-XR reports bandwidth 0), on
// SNMP and gNMI alike, and have no ifPhysAddress.
func TestASR9902LoopbackAndNull0CarryNoTraffic(t *testing.T) {
	d := newASR9902Device(t)
	ic := d.metricsCycler.ifCounters.Load()
	idx := map[string]string{}
	for _, e := range loadCiscoAsr9902(t).SNMP {
		if strings.HasPrefix(e.OID, "1.3.6.1.2.1.2.2.1.2.") {
			idx[e.Response] = strings.TrimPrefix(e.OID, "1.3.6.1.2.1.2.2.1.2.")
		}
	}
	for _, name := range []string{"Loopback0", "Null0"} {
		if v := ic.GetDynamicAt(ifXTablePrefix+"6."+idx[name], 3600); v != "0" {
			t.Errorf("%s ifHCInOctets = %s, want 0", name, v)
		}
		if v, ok := d.resources.oidIndex.Load(ifTablePrefix + "6." + idx[name]); !ok || v != "" {
			t.Errorf("%s ifPhysAddress = %v (present %v), want an empty row", name, v, ok)
		}
	}
	if v, _ := d.resources.oidIndex.Load(ifTablePrefix + "6." + idx["Bundle-Ether1"]); v == "" {
		t.Error("Bundle-Ether1 has no ifPhysAddress")
	}
	leaves := asr9902Values(t, "/interfaces/interface/state/counters")["Null0"]
	if leaves["in-octets"] != 0 || leaves["out-pkts"] != 0 {
		t.Errorf("Null0 gNMI counters %v, want in-octets and out-pkts 0", leaves)
	}
}

// OpenConfig in-pkts and out-pkts are totals: unicast plus multicast plus
// broadcast, on interfaces and subinterfaces.
func TestASR9902PktsAreTheSumOfTheCastCounters(t *testing.T) {
	ifs := asr9902Values(t, "/interfaces/interface/state/counters")
	subs := asr9902Values(t, "/interfaces/interface/subinterfaces/subinterface/state/counters")
	for path, v := range map[string]map[string]uint64{"HundredGigE0/0/0/8": ifs["HundredGigE0/0/0/8"], "HundredGigE0/0/0/8.100": subs["HundredGigE0/0/0/8.100"]} {
		for _, dir := range []string{"in", "out"} {
			sum := v[dir+"-unicast-pkts"] + v[dir+"-multicast-pkts"] + v[dir+"-broadcast-pkts"]
			if v[dir+"-pkts"] < sum || v[dir+"-pkts"] <= v[dir+"-unicast-pkts"] {
				t.Errorf("%s: %s-pkts %d, want at least unicast+multicast+broadcast %d", path, dir, v[dir+"-pkts"], sum)
			}
		}
	}
}

// asr9902Values subscribes ONCE in PROTO to the counters alias path on
// the shipped device and returns the unsigned leaves per entry, keyed by
// interface name, with ".<index>" appended for a subinterface.
func asr9902Values(t *testing.T, path string) map[string]map[string]uint64 {
	t.Helper()
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	_, _, addr, cleanup := startTestGnmiServerWithDevice(t, cats["cisco_asr9902"], newASR9902Device(t))
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "openconfig-interfaces", path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]uint64{}
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		e := n.GetPrefix().GetElem()
		key := e[1].GetKey()["name"]
		if len(e) > 3 && e[3].GetName() == "subinterface" {
			key += "." + e[3].GetKey()["index"]
		}
		if out[key] == nil {
			out[key] = map[string]uint64{}
		}
		for _, u := range n.GetUpdate() {
			ue := u.GetPath().GetElem()
			out[key][ue[len(ue)-1].GetName()] = u.GetVal().GetUintVal()
		}
	}
	return out
}
