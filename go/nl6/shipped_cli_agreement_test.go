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
	"strings"
	"testing"
)

// defaultRouteCLI names, per shipped profile, the SSH command that prints the
// default route and a regexp whose first group captures its next hop. An empty
// command marks a profile whose CLI prints a default route while its SNMP serves
// no ipRouteTable row for it; the test then requires that SNMP still serves
// none, so adding one forces agreement.
var defaultRouteCLI = map[string]struct{ command, nextHop string }{
	"arista_7280r3.json":           {"show ip route", `0\.0\.0\.0/0 \S+ via (\S+),`},
	"cisco_catalyst_9500.json":     {"show ip route", `0\.0\.0\.0/0 \S+ via (\S+)`},
	"cisco_crs_x.json":             {"show route ipv4", `0\.0\.0\.0/0 \S+ via (\S+),`},
	"cisco_ios.json":               {"show ip route", `Gateway of last resort is (\S+)`},
	"cisco_nexus_9500.json":        {"show ip route", `0\.0\.0\.0/0,[^\n]*\n\s*\*via (\S+),`},
	"fortinet_fortigate_600e.json": {"get router info routing-table all", `0\.0\.0\.0/0 \S+ via (\S+),`},
	"huawei_ne8000.json":           {"display ip routing-table", `0\.0\.0\.0/0\s+Static\s+\d+\s+\d+\s+\S+\s+(\S+)`},
	"juniper_mx10004.json":         {"show route", `0\.0\.0\.0/0[^\n]*\n\s*> to (\S+) via`},
	"juniper_mx240.json":           {"show route", `0\.0\.0\.0/0[^\n]*\n\s*> to (\S+) via`},
	"juniper_mx960.json":           {"show route", `0\.0\.0\.0/0[^\n]*\n\s*> to (\S+) via`},
	"nokia_7750_sr12.json":         {"show router route-table", `0\.0\.0\.0/0[^\n]*\n\s*(\S+)`},
	"palo_alto_pa3220.json":        {"show routing route", `0\.0\.0\.0/0\s+(\S+)`},
	"dlink_dgs3630.json":           {},
	"extreme_vsp4450.json":         {},
	"linux_server.json":            {},
	"nec_ix3315.json":              {},
}

var printsDefaultRoute = regexp.MustCompile(`(?m)0\.0\.0\.0/0|0\.0\.0\.0 0\.0\.0\.0|Gateway of last resort is \d|^default via`)

const ipRouteNextHopDefault = "1.3.6.1.2.1.4.21.1.7.0.0.0.0"

// TestShippedDefaultRouteAgreesWithCLI: profiles answered ipRouteNextHop.0.0.0.0
// with a template address while their CLI named another gateway, and two CLIs
// named addresses that are not IPv4.
func TestShippedDefaultRouteAgreesWithCLI(t *testing.T) {
	if !printsDefaultRoute.MatchString("S*   0.0.0.0/0 [1/0] via 192.0.2.1") || printsDefaultRoute.MatchString("C 192.0.2.0/24 is directly connected") {
		t.Fatal("control: the default-route detector does not tell a default route from a connected one")
	}
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	for _, profile := range shippedProfileNames(t) {
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
		case !listed && printed:
			t.Errorf("%s prints a default route over SSH but has no defaultRouteCLI row, so nothing checks SNMP agrees", profile)
			continue
		case !listed:
			continue
		}
		if row.command == "" {
			if served {
				t.Errorf("%s now serves ipRouteNextHop.0.0.0.0 = %s; give it a defaultRouteCLI row so the CLI must agree", profile, snmp)
			}
			continue
		}
		m := regexp.MustCompile(row.nextHop).FindStringSubmatch(ssh[row.command])
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
}

// literalEscape matches the two-character sequences a double-escaped JSON
// string leaves behind. Other backslashes are content (DOMAIN\user1).
var literalEscape = regexp.MustCompile(`\\[n"]`)

// TestShippedSSHResponsesHaveRealLineBreaks: thirty commands on five profiles
// printed the characters \n instead of line breaks, because their JSON escaped
// them twice and the SSH server sends a response as stored.
func TestShippedSSHResponsesHaveRealLineBreaks(t *testing.T) {
	if !literalEscape.MatchString(`a\nb`) || !literalEscape.MatchString(`say \"x\"`) || literalEscape.MatchString("DOMAIN\\user1\nnext") {
		t.Fatal("control: the escape detector does not tell a literal escape from content")
	}
	for _, part := range shippedResourceParts(t) {
		raw, err := os.ReadFile(part)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			SSH []struct{ Command, Response string } `json:"ssh"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			continue // not an object part; other tests own its shape
		}
		for _, e := range doc.SSH {
			if loc := literalEscape.FindStringIndex(e.Response); loc != nil {
				t.Errorf("%s %q carries a literal %s at byte %d; write a real newline or quote", part, e.Command, e.Response[loc[0]:loc[1]], loc[0])
			}
		}
	}
}
