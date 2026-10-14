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
}

func routeRow(command, nextHop string) defaultRouteRow {
	return defaultRouteRow{command, regexp.MustCompile(nextHop)}
}

var defaultRouteCLI = map[string]defaultRouteRow{
	"arista_7280r3.json":           routeRow("show ip route", `0\.0\.0\.0/0 \S+ via (\S+),`),
	"cisco_catalyst_9500.json":     routeRow("show ip route", `0\.0\.0\.0/0 \S+ via (\S+)`),
	"cisco_crs_x.json":             routeRow("show route ipv4", `0\.0\.0\.0/0 \S+ via (\S+),`),
	"cisco_ios.json":               routeRow("show ip route", `Gateway of last resort is (\S+)`),
	"cisco_nexus_9500.json":        routeRow("show ip route", `0\.0\.0\.0/0,[^\n]*\n\s*\*via (\S+),`),
	"fortinet_fortigate_600e.json": routeRow("get router info routing-table all", `0\.0\.0\.0/0 \S+ via (\S+),`),
	"huawei_ne8000.json":           routeRow("display ip routing-table", `0\.0\.0\.0/0\s+Static\s+\d+\s+\d+\s+\S+\s+(\S+)`),
	"juniper_mx10004.json":         routeRow("show route", `0\.0\.0\.0/0[^\n]*\n\s*> to (\S+) via`),
	"juniper_mx240.json":           routeRow("show route", `0\.0\.0\.0/0[^\n]*\n\s*> to (\S+) via`),
	"juniper_mx960.json":           routeRow("show route", `0\.0\.0\.0/0[^\n]*\n\s*> to (\S+) via`),
	"nokia_7750_sr12.json":         routeRow("show router route-table", `0\.0\.0\.0/0[^\n]*\n\s*(\S+)`),
	"palo_alto_pa3220.json":        routeRow("show routing route", `0\.0\.0\.0/0\s+(\S+)`),

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
