/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// defaultRouteRow names the SSH command that prints a profile's default route
// and a regexp whose first group captures its next hop. A zero row marks a
// profile where only ONE surface has a default route: its CLI prints one while
// SNMP serves no ipRouteNextHop.0.0.0.0, or the reverse. The test then requires
// that it stays one-sided, so a profile that gains the other side must get a
// real row and agree.
type defaultRouteRow struct {
	command string
	nextHop *regexp.Regexp
	// The connected route and its interface, checked when port is set:
	// port is the IF-MIB ifDescr both ipRouteTable rows and the ipAddrTable
	// row name; cliPort is how the CLI's route table spells it, which is the
	// same name on every shipped profile; prefix and
	// addr are the connected subnet and the device's own address on it;
	// proto is the default route's ipRouteProto, netmgmt(3) for static and
	// bgp(14) for BGP.
	port, cliPort, prefix, addr string
	proto                       int
	// more lists the other interfaces the CLI addresses, each with its
	// own connected route and ipAddrTable row.
	more []connectedNet
}

// connectedNet is one subnet the CLI addresses an interface on: port is the
// IF-MIB ifDescr the ipRouteTable and ipAddrTable rows name, cliPort how the
// CLI's route table spells it, prefix the subnet and addr the device's own
// address on it.
type connectedNet struct {
	port, cliPort, prefix, addr string
}

func routeRow(command, nextHop string) defaultRouteRow {
	return defaultRouteRow{command: command, nextHop: regexp.MustCompile(nextHop)}
}

// connected adds the connected-route plan to a row.
func (r defaultRouteRow) connected(port, cliPort, prefix, addr string, proto int) defaultRouteRow {
	r.port, r.cliPort, r.prefix, r.addr, r.proto = port, cliPort, prefix, addr, proto
	return r
}

// also adds a further addressed interface to a row. juniper_mx960 addresses
// ge-0/0/0.0 as well as the unit its default route leaves on, and SNMP served
// the rows for the second only.
func (r defaultRouteRow) also(port, cliPort, prefix, addr string) defaultRouteRow {
	r.more = append(r.more, connectedNet{port, cliPort, prefix, addr})
	return r
}

var defaultRouteCLI = map[string]defaultRouteRow{
	"arista_7280r3.json": routeRow("show ip route", `0\.0\.0\.0/0 \S+ via (\S+),`).
		connected("Ethernet1/1", "Ethernet1/1", "192.168.201.0/24", "192.168.201.1", 3),
	"cisco_catalyst_9500.json": routeRow("show ip route", `0\.0\.0\.0/0 \S+ via (\S+)`).
		connected("GigabitEthernet1/0/47", "GigabitEthernet1/0/47", "192.168.1.0/24", "192.168.1.10", 3),
	"cisco_crs_x.json": routeRow("show route ipv4", `0\.0\.0\.0/0 \S+ via (\S+),`).
		connected("HundredGigE0/1/0/0", "HundredGigE0/1/0/0", "192.168.30.0/24", "192.168.30.1", 3),
	"cisco_ios.json": routeRow("show ip route", `Gateway of last resort is (\S+)`).
		connected("GigabitEthernet0/0", "GigabitEthernet0/0", "192.168.1.0/24", "192.168.1.10", 3),
	"cisco_nexus_9500.json": routeRow("show ip route", `0\.0\.0\.0/0,[^\n]*\n\s*\*via (\S+),`).
		connected("Ethernet1/11", "Ethernet1/11", "192.168.101.0/24", "192.168.101.1", 3),
	"fortinet_fortigate_600e.json": routeRow("get router info routing-table all", `0\.0\.0\.0/0 \S+ via (\S+),`).
		connected("port1", "port1", "192.168.2.0/24", "192.168.2.1", 3),
	"huawei_ne8000.json": routeRow("display ip routing-table", `0\.0\.0\.0/0\s+Static\s+\d+\s+\d+\s+\S+\s+(\S+)`).
		connected("100GE1/0/0", "100GE1/0/0", "192.168.102.0/24", "192.168.102.1", 3),
	"juniper_mx10004.json": routeRow("show route", `0\.0\.0\.0/0[^\n]*\n\s*> to (\S+) via`).
		connected("xe-0/0/0.0", "xe-0/0/0.0", "192.168.1.0/24", "192.168.1.1", 3),
	"juniper_mx240.json": routeRow("show route", `0\.0\.0\.0/0[^\n]*\n\s*> to (\S+) via`).
		connected("xe-1/0/0.0", "xe-1/0/0.0", "192.168.1.0/24", "192.168.1.1", 3),
	"juniper_mx960.json": routeRow("show route", `0\.0\.0\.0/0[^\n]*\n\s*> to (\S+) via`).
		connected("xe-1/0/1.0", "xe-1/0/1.0", "10.0.1.0/30", "10.0.1.1", 14).
		also("ge-0/0/0.0", "ge-0/0/0.0", "192.168.100.0/24", "192.168.100.1"),
	"nokia_7750_sr12.json": routeRow("show router route-table", `0\.0\.0\.0/0[^\n]*\n\s*(\S+)`).
		connected("toWAN", "toWAN", "192.168.40.0/24", "192.168.40.1", 3),
	"palo_alto_pa3220.json": routeRow("show routing route", `0\.0\.0\.0/0\s+(\S+)`).
		connected("ethernet1/1", "ethernet1/1", "10.0.0.0/24", "10.0.0.1", 3),

	// The CLI prints a default route; SNMP serves none.
	"check_point_15600.json": {},
	"dlink_dgs3630.json":     {},
	"extreme_vsp4450.json":   {},
	"linux_server.json":      {},
	"nec_ix3315.json":        {},
	// SNMP serves a default route; the CLI prints none.
	"asr9k.json":               {},
	"cisco_asr9902.json":       {},
	"dell_poweredge_r750.json": {},
	"hpe_proliant_dl380.json":  {},
}

// printsDefaultRoute recognises the default-route line of every CLI shape the
// corpus ships: a /0 prefix, an IOS-style "route ... 0.0.0.0 0.0.0.0" (anchored
// on "route" so an unaddressed interface's "ip: 0.0.0.0 0.0.0.0" is not one),
// IOS's gateway of last resort, Linux's "default via", and the netstat/route -n
// table row.
var printsDefaultRoute = regexp.MustCompile(`(?m)0\.0\.0\.0/0|route[^\n]*0\.0\.0\.0 0\.0\.0\.0|Gateway of last resort is \d|^default\s+via|^0\.0\.0\.0\s+\d`)

const ipRouteNextHopDefault = "1.3.6.1.2.1.4.21.1.7.0.0.0.0"

// TestShippedDefaultRouteAgreesWithCLI: profiles answered ipRouteNextHop.0.0.0.0
// with a template address while their CLI named another gateway, and two CLIs
// named addresses that are not IPv4.
func TestShippedDefaultRouteAgreesWithCLI(t *testing.T) {
	for _, c := range []struct {
		line string
		want bool
	}{
		{"S*   0.0.0.0/0 [1/0] via 192.0.2.1", true},
		{"0.0.0.0         192.0.2.254 0.0.0.0         UG    0      0        0 eth0", true},
		{"ip route 0.0.0.0 0.0.0.0 192.0.2.254", true},
		{"default via 192.0.2.1 dev eth0", true},
		{"C 192.0.2.0/24 is directly connected", false},
		{"name: port2   mode: interface   ip: 0.0.0.0 0.0.0.0   status: down", false},
	} {
		if printsDefaultRoute.MatchString(c.line) != c.want {
			t.Fatalf("control: detector on %q = %v, want %v", c.line, !c.want, c.want)
		}
	}
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	shipped := map[string]bool{}
	for _, profile := range shippedProfileNames(t) {
		shipped[profile] = true
		res, err := sm.LoadSpecificResources(profile)
		if err != nil {
			t.Fatalf("%s: %v", profile, err)
		}
		ssh := map[string]string{}
		printed := false
		for _, e := range res.SSH {
			ssh[e.Command] = e.Response
			printed = printed || printsDefaultRoute.MatchString(e.Response)
		}
		snmp, served := "", false
		for _, e := range res.SNMP {
			if strings.TrimPrefix(e.OID, ".") == ipRouteNextHopDefault {
				snmp, served = e.Response, true
			}
		}
		row, listed := defaultRouteCLI[profile]
		switch {
		case !listed && (printed || served):
			t.Errorf("%s has a default route on SSH (%v) or SNMP (%v) but no defaultRouteCLI row, so nothing checks the two agree", profile, printed, served)
			continue
		case !listed:
			continue
		case row.nextHop == nil:
			if printed == served {
				t.Errorf("%s is listed as having a default route on one surface only, but SSH prints one: %v, SNMP serves one: %v", profile, printed, served)
			}
			continue
		}
		m := row.nextHop.FindStringSubmatch(ssh[row.command])
		if m == nil {
			t.Errorf("%s: no default-route next hop found in %q", profile, row.command)
			continue
		}
		if ip := net.ParseIP(m[1]); ip == nil || ip.To4() == nil {
			t.Errorf("%s: CLI next hop %q is not an IPv4 address", profile, m[1])
		}
		if snmp != m[1] {
			t.Errorf("%s: ipRouteNextHop.0.0.0.0 = %q, %s says %q", profile, snmp, row.command, m[1])
		}
		if row.port == "" {
			t.Errorf("%s: its defaultRouteCLI row has no connected route plan", profile)
			continue
		}
		checkConnectedRoute(t, profile, row, res, ssh)
	}
	for profile := range defaultRouteCLI {
		if !shipped[profile] {
			t.Errorf("defaultRouteCLI lists %s, which is not a shipped profile", profile)
		}
	}
}

// shippedTextResponses yields every string response of every non-SNMP array
// (ssh, api, ...) in every shipped part, with a label naming where it lives.
func shippedTextResponses(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, part := range shippedResourceParts(t) {
		raw, err := os.ReadFile(part)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]json.RawMessage
		if json.Unmarshal(raw, &doc) != nil {
			continue // not an object part; other tests own its shape
		}
		for key, arr := range doc {
			if key == "snmp" {
				continue
			}
			var entries []map[string]any
			if json.Unmarshal(arr, &entries) != nil {
				continue
			}
			for i, e := range entries {
				if r, ok := e["response"].(string); ok {
					out[part+" "+key+"["+strconv.Itoa(i)+"]"] = r
				}
			}
		}
	}
	return out
}

// literalEscape matches the two-character sequences a double-escaped JSON
// string leaves behind. Other backslashes are content (DOMAIN\user1). A real
// response that needs one of these, such as a Windows path starting \n, must
// be written another way: the cost of that is small next to unreadable output.
var literalEscape = regexp.MustCompile(`\\[nrt"]`)

// TestShippedResponsesHaveRealLineBreaks: thirty SSH commands on five profiles
// printed the characters \n instead of line breaks, because their JSON escaped
// them twice and the servers send a response as stored.
func TestShippedResponsesHaveRealLineBreaks(t *testing.T) {
	if !literalEscape.MatchString(`a\nb`) || !literalEscape.MatchString(`say \"x\"`) || literalEscape.MatchString("DOMAIN\\user1\nnext") {
		t.Fatal("control: the escape detector does not tell a literal escape from content")
	}
	for where, r := range shippedTextResponses(t) {
		if loc := literalEscape.FindStringIndex(r); loc != nil {
			t.Errorf("%s carries a literal %s at byte %d; write a real newline, tab or quote", where, r[loc[0]:loc[1]], loc[0])
		}
	}
}

var dottedQuad = regexp.MustCompile(`(^|[^\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})($|[^\d.])`)

// invalidQuad returns the first dotted quad in s with an octet above 255.
func invalidQuad(s string) string {
	for _, m := range dottedQuad.FindAllStringSubmatch(s, -1) {
		for _, o := range m[2:6] {
			if n, _ := strconv.Atoi(o); n > 255 {
				return strings.Join(m[2:6], ".")
			}
		}
	}
	return ""
}

// TestShippedResponsesNameValidIPv4: six profiles printed addresses such as
// 192.168.300.254, which a collector parsing the CLI cannot read as IPv4.
func TestShippedResponsesNameValidIPv4(t *testing.T) {
	if invalidQuad("via 192.168.300.254,") != "192.168.300.254" || invalidQuad("via 192.168.30.254, IOS 15.255.0.1 v1.2.3.4.5") != "" {
		t.Fatal("control: the address check does not tell an invalid quad from a valid one")
	}
	for where, r := range shippedTextResponses(t) {
		if q := invalidQuad(r); q != "" {
			t.Errorf("%s names %s, which is not an IPv4 address", where, q)
		}
	}
}

// checkConnectedRoute holds a profile's ipRouteTable and ipAddrTable to its
// CLI. The template served a connected 192.168.1.0/24 via ifIndex 2 and no
// ipAddrTable on every profile, so the default route's next hop lay in no
// subnet SNMP served and its egress interface was not the one the CLI named.
// Every interface the CLI addresses gets a connected route and an address
// row; the first one listed is the one the default route leaves on.
func checkConnectedRoute(t *testing.T, profile string, row defaultRouteRow, res *DeviceResources, ssh map[string]string) {
	t.Helper()
	const route, addrTab, ifDescr = "1.3.6.1.2.1.4.21.1.", "1.3.6.1.2.1.4.20.1.", "1.3.6.1.2.1.2.2.1.2."
	nets := append([]connectedNet{{row.port, row.cliPort, row.prefix, row.addr}}, row.more...)
	snmp := map[string]string{}
	ifIndexOf := map[string]string{}
	var dests, addrs []string
	for _, e := range res.SNMP {
		oid := strings.TrimPrefix(e.OID, ".")
		snmp[oid] = e.Response
		switch {
		case strings.HasPrefix(oid, route+"1."):
			dests = append(dests, e.Response)
		case strings.HasPrefix(oid, addrTab+"1."):
			addrs = append(addrs, e.Response)
		case strings.HasPrefix(oid, ifDescr):
			if prev, dup := ifIndexOf[e.Response]; dup {
				t.Errorf("%s: ifDescr %q is served at ifIndex %s and %s, so no address row can name it", profile, e.Response, prev, strings.TrimPrefix(oid, ifDescr))
			}
			ifIndexOf[e.Response] = strings.TrimPrefix(oid, ifDescr)
		}
	}
	lines := strings.Split(ssh[row.command], "\n")
	wantDests, wantAddrs := []string{"0.0.0.0"}, []string{}
	for i, n := range nets {
		_, subnet, err := net.ParseCIDR(n.prefix)
		if err != nil {
			t.Fatalf("%s: bad prefix %q", profile, n.prefix)
		}
		net0, mask := subnet.IP.String(), net.IP(subnet.Mask).String()
		wantDests, wantAddrs = append(wantDests, net0), append(wantAddrs, n.addr)
		ifIndex := ifIndexOf[n.port]
		if ifIndex == "" {
			t.Errorf("%s: IF-MIB serves no %q", profile, n.port)
			continue
		}
		checks := []struct{ oid, want string }{
			{route + "2." + net0, ifIndex},
			{route + "7." + net0, n.addr},
			{route + "8." + net0, "3"},
			{route + "11." + net0, mask},
			{addrTab + "2." + n.addr, ifIndex},
			{addrTab + "3." + n.addr, mask},
		}
		if i == 0 {
			if nh := net.ParseIP(snmp[route+"7.0.0.0.0"]); nh == nil || !subnet.Contains(nh) {
				t.Errorf("%s: default next hop %s is not in the connected subnet %s", profile, snmp[route+"7.0.0.0.0"], n.prefix)
			}
			checks = append(checks, []struct{ oid, want string }{
				{route + "2.0.0.0.0", ifIndex},
				{route + "8.0.0.0.0", "4"},
				{route + "11.0.0.0.0", "0.0.0.0"},
				{route + "9.0.0.0.0", strconv.Itoa(row.proto)},
			}...)
		}
		for _, c := range checks {
			if got := snmp[c.oid]; got != c.want {
				t.Errorf("%s: %s = %q, want %q", profile, c.oid, got, c.want)
			}
		}
		// The route table must print the connected prefix with its egress
		// port on the same line, or on the next one where the vendor puts
		// the next hop there (Junos, NX-OS, SR OS). Both are matched as
		// whole tokens, so Ethernet1/1 is not found inside Ethernet1/11.
		prefixTok, portTok := cliToken(n.prefix), cliToken(n.cliPort)
		onPort := false
		for i, l := range lines {
			if !prefixTok.MatchString(l) {
				continue
			}
			if portTok.MatchString(l) || (i+1 < len(lines) && portTok.MatchString(lines[i+1])) {
				onPort = true
			}
		}
		if !onPort {
			t.Errorf("%s: %s does not route %s via %s", profile, row.command, n.prefix, n.cliPort)
		}
		addrTok := regexp.MustCompile(`(^|[^\d.])` + regexp.QuoteMeta(n.addr) + `($|[^\d])`)
		shown := false
		for _, r := range ssh {
			shown = shown || addrTok.MatchString(r)
		}
		if !shown {
			t.Errorf("%s: no SSH output shows the device address %s", profile, n.addr)
		}
	}
	sort.Strings(dests)
	sort.Strings(wantDests)
	if !slices.Equal(dests, wantDests) {
		t.Errorf("%s: ipRouteTable destinations = %v, want %v", profile, dests, wantDests)
	}
	sort.Strings(addrs)
	sort.Strings(wantAddrs)
	if !slices.Equal(addrs, wantAddrs) {
		t.Errorf("%s: ipAddrTable addresses = %v, want %v", profile, addrs, wantAddrs)
	}
}

// cliToken matches s as a whole CLI token: not preceded or followed by a
// character that would extend an interface name or an address.
func cliToken(s string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^\w./-])` + regexp.QuoteMeta(s) + `($|[^\w/-])`)
}

// cliInterfaceNames are, per profile, the interface names its CLI configures
// that IF-MIB must serve as rows of their own. The Junos and SR OS profiles
// routed through logical interfaces IF-MIB did not serve, and huawei_ne8000
// spelled its ports HundredGigE while VRP prints 100GE. juniper_mx10004's VRF
// view named units on a ge-0/0/0 port that profile does not have.
//
// A Huawei name with a .N suffix is a VRP subinterface, which IF-MIB serves
// through its port; the test then requires the port.
var cliInterfaceNames = map[string]*regexp.Regexp{
	"juniper_mx240.json":   regexp.MustCompile(`\b(?:xe|ge|et)-\d+/\d+/\d+\.\d+\b`),
	"juniper_mx960.json":   regexp.MustCompile(`\b(?:xe|ge|et)-\d+/\d+/\d+\.\d+\b`),
	"juniper_mx10004.json": regexp.MustCompile(`\b(?:xe|ge|et)-\d+/\d+/\d+\.\d+\b`),
	"nokia_7750_sr12.json": regexp.MustCompile(`interface "([^"]+)"`),
	"huawei_ne8000.json":   regexp.MustCompile(`(?:^|[^\w/-])((?:\d*X?GE|HundredGigE|GigabitEthernet|Eth-Trunk)\d+(?:/\d+)*)(?:\.\d+)?\b`),
}

func TestCLIInterfacesAreIFMIBRows(t *testing.T) {
	if !cliInterfaceNames["juniper_mx240.json"].MatchString("> via xe-1/0/0.0") || cliInterfaceNames["juniper_mx240.json"].MatchString("xe-1/0/0 up") {
		t.Fatal("control: the Junos unit pattern does not tell a unit from its port")
	}
	for _, name := range []string{"XGE1/1/0", "10GE1/0/1", "100GE1/0/0", "GE0/0/1", "Interfaces : XGE1/1/0.200"} {
		if !cliInterfaceNames["huawei_ne8000.json"].MatchString(name) {
			t.Fatalf("control: the VRP pattern misses %q", name)
		}
	}
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	for profile, pat := range cliInterfaceNames {
		res, err := sm.LoadSpecificResources(profile)
		if err != nil {
			t.Fatalf("%s: %v", profile, err)
		}
		served := map[string]bool{}
		for _, e := range res.SNMP {
			if strings.HasPrefix(strings.TrimPrefix(e.OID, "."), "1.3.6.1.2.1.2.2.1.2.") {
				served[e.Response] = true
			}
		}
		seen := 0
		for _, e := range res.SSH {
			for _, m := range pat.FindAllStringSubmatch(e.Response, -1) {
				name := m[len(m)-1]
				seen++
				if !served[name] {
					t.Errorf("%s: %q names %s, which IF-MIB does not serve", profile, e.Command, name)
				}
			}
		}
		if seen == 0 {
			t.Errorf("%s: no CLI interface matched; the pattern no longer fits the profile", profile)
		}
	}
}

// junosTerseAddress matches a unit line of show interfaces terse that carries
// an inet address: any <name>.<unit>, admin and link state, inet, then
// a.b.c.d with /n on a subnet address and none on a loopback, which Junos
// prints as "a.b.c.d --> 0/0".
var junosTerseAddress = regexp.MustCompile(`(?m)^(\S+\.\d+)\s+\S+\s+\S+\s+inet\s+(\d+\.\d+\.\d+\.\d+)(?:/(\d+))?`)

// junosDirectRoute matches a Direct/0 route of show route: the prefix and
// its length, with the unit on the next line.
var junosDirectRoute = regexp.MustCompile(`(?m)^(\d+\.\d+\.\d+\.\d+)/(\d+)\s+\*\[Direct/0\][^\n]*\n\s*> via (\S+)`)

// junosUnitsOutsideIFMIB lists, per profile, the addressed units the terse
// output shows that IF-MIB does not serve, so no ipAddrTable row can name
// their ifIndex, each with the reason. The guard requires an excluded unit
// to still be absent from IF-MIB, so the exclusion cannot outlive the gap.
var junosUnitsOutsideIFMIB = map[string]map[string]string{
	"juniper_mx10004.json": {
		"fxp0.0": "the chassis model has no management port, so IF-MIB serves no fxp0",
		"lo0.0":  "the chassis model has no loopback, so IF-MIB serves no lo0; its /32 is a host route, which no profile mirrors",
	},
}

// junosAddressGaps returns, for every unit show interfaces terse addresses and
// every Direct/0 route show route prints, what ipAddrTable and ipRouteTable
// fail to serve for it, and how many addressed units it saw. Host routes
// (/32) are not mirrored on any profile, so a Direct/0 host route is not
// checked; excluded names the units IF-MIB does not serve.
func junosAddressGaps(res *DeviceResources, excluded map[string]string) (gaps []string, seen int) {
	const route, addrTab, ifDescr = "1.3.6.1.2.1.4.21.1.", "1.3.6.1.2.1.4.20.1.", "1.3.6.1.2.1.2.2.1.2."
	snmp := map[string]string{}
	ifIndexOf := map[string]string{}
	for _, e := range res.SNMP {
		oid := strings.TrimPrefix(e.OID, ".")
		snmp[oid] = e.Response
		if strings.HasPrefix(oid, ifDescr) {
			if prev, dup := ifIndexOf[e.Response]; dup {
				gaps = append(gaps, "ifDescr "+strconv.Quote(e.Response)+" is served at ifIndex "+prev+" and "+strings.TrimPrefix(oid, ifDescr)+", so no address row can name it")
			}
			ifIndexOf[e.Response] = strings.TrimPrefix(oid, ifDescr)
		}
	}
	for _, e := range res.SSH {
		switch e.Command {
		case "show interfaces terse":
			for _, m := range junosTerseAddress.FindAllStringSubmatch(e.Response, -1) {
				unit, addr, bits := m[1], m[2], m[3]
				seen++
				if _, ok := excluded[unit]; ok {
					if ifIndex := ifIndexOf[unit]; ifIndex != "" {
						gaps = append(gaps, unit+" is excluded as not served by IF-MIB, but ifDescr."+ifIndex+" serves it; drop the exclusion and add its rows")
					}
					continue
				}
				if bits == "" {
					bits = "32"
				}
				_, subnet, err := net.ParseCIDR(addr + "/" + bits)
				if err != nil {
					gaps = append(gaps, unit+": terse prints "+addr+"/"+bits+", which is not a prefix")
					continue
				}
				net0, mask := subnet.IP.String(), net.IP(subnet.Mask).String()
				ifIndex := ifIndexOf[unit]
				if ifIndex == "" {
					gaps = append(gaps, unit+": IF-MIB serves no such ifDescr")
					continue
				}
				for _, c := range []struct{ oid, want, what string }{
					{addrTab + "2." + addr, ifIndex, "ipAdEntIfIndex." + addr},
					{addrTab + "3." + addr, mask, "ipAdEntNetMask." + addr},
					{route + "2." + net0, ifIndex, "ipRouteIfIndex." + net0},
					{route + "7." + net0, addr, "ipRouteNextHop." + net0},
					{route + "11." + net0, mask, "ipRouteMask." + net0},
				} {
					if got := snmp[c.oid]; got != c.want {
						gaps = append(gaps, unit+" ("+addr+"/"+bits+", ifIndex "+ifIndex+"): "+c.what+" = "+strconv.Quote(got)+", want "+strconv.Quote(c.want))
					}
				}
			}
		case "show route":
			for _, m := range junosDirectRoute.FindAllStringSubmatch(e.Response, -1) {
				net0, bits, unit := m[1], m[2], m[3]
				if bits == "32" {
					continue
				}
				if got := snmp[route+"1."+net0]; got != net0 {
					gaps = append(gaps, "show route prints "+net0+"/"+bits+" as Direct/0 via "+unit+", but ipRouteDest."+net0+" = "+strconv.Quote(got))
				}
			}
		}
	}
	return gaps, seen
}

// TestJunosTerseAddressesAreIPAddrTableRows: juniper_mx960 addressed
// ge-0/0/0.0 on the CLI and served ipAddrTable and ipRouteTable rows for
// xe-1/0/1.0 only. The agreement test's plan lists what it checks, so an
// address it did not list was invisible to it; this derives the rows every
// addressed unit and every connected route must have from the CLI itself.
func TestJunosTerseAddressesAreIPAddrTableRows(t *testing.T) {
	control := &DeviceResources{
		SNMP: []SNMPResource{{OID: "1.3.6.1.2.1.2.2.1.2.9", Response: "ge-0/0/9.0"}},
		SSH: []SSHResource{
			{Command: "show interfaces terse", Response: "Interface Admin Link Proto Local Remote\nge-0/0/9 up up\nge-0/0/9.0 up up inet 10.9.9.1/24\nge-0/0/9.100 up up inet\nlo0.0 up up inet 10.255.9.9 --> 0/0\n"},
			{Command: "show route", Response: "10.9.9.0/24 *[Direct/0] 1d 00:00:00\n > via ge-0/0/9.0\n10.255.9.9/32 *[Direct/0] 1d 00:00:00\n > via lo0.0\n"},
		},
	}
	gaps, seen := junosAddressGaps(control, nil)
	if seen != 2 || len(gaps) != 7 ||
		!strings.HasPrefix(gaps[0], "ge-0/0/9.0 (10.9.9.1/24, ifIndex 9): ipAdEntIfIndex.10.9.9.1") ||
		gaps[5] != "lo0.0: IF-MIB serves no such ifDescr" ||
		!strings.HasPrefix(gaps[6], "show route prints 10.9.9.0/24 as Direct/0 via ge-0/0/9.0, but ipRouteDest.10.9.9.0") {
		t.Fatalf("control: an addressed unit with no rows gives seen=%d gaps=%q, want 2 and 7 naming the units and the route", seen, gaps)
	}
	if gaps, _ := junosAddressGaps(control, map[string]string{"ge-0/0/9.0": "planted", "lo0.0": "planted"}); len(gaps) != 2 || !strings.HasPrefix(gaps[0], "ge-0/0/9.0 is excluded as not served by IF-MIB, but ifDescr.9 serves it") {
		t.Fatalf("control: an exclusion on a served unit gives gaps=%q, want one naming the stale exclusion and the unserved route", gaps)
	}
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	for profile := range cliInterfaceNames {
		if !strings.HasPrefix(profile, "juniper_") {
			continue
		}
		res, err := sm.LoadSpecificResources(profile)
		if err != nil {
			t.Fatalf("%s: %v", profile, err)
		}
		gaps, seen := junosAddressGaps(res, junosUnitsOutsideIFMIB[profile])
		if seen == 0 {
			t.Errorf("%s: show interfaces terse addresses no unit; the pattern no longer fits the profile", profile)
		}
		for _, g := range gaps {
			t.Errorf("%s: %s", profile, g)
		}
	}
	for profile := range junosUnitsOutsideIFMIB {
		if _, ok := cliInterfaceNames[profile]; !ok {
			t.Errorf("junosUnitsOutsideIFMIB lists %s, which the guard does not visit", profile)
		}
	}
}
