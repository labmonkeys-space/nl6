/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

// Eleven profiles answered ipRouteNextHop.0.0.0.0 with a template address,
// 10.0.0.1 or 10.1.0.1, while their CLI route table named another gateway.
// Each now serves the gateway its CLI names. Two CLIs named addresses that are
// not IPv4 (192.168.300.254, 192.168.400.254); those subnets were renumbered
// in the SSH resource to 192.168.30.0/24 and 192.168.40.0/24 first. Every value
// is IpAddress before and after, so no tag moved and neither digest below
// differs from the current pin; the link exists so the chain restores the
// parent corpus's VALUES.

// defaultRouteParentRevision is main at branch time; the digests below were
// taken there and are NOT re-derived from the new tree.
const defaultRouteParentRevision = "2da94270"

const (
	shippedTagDigestBeforeDefaultRoute         = "8c46e960fac968c5527f4391a71fa80f56371cc1879bf95a78bfcf017a1499e0"
	shippedOIDEncodingDigestBeforeDefaultRoute = "1e16764e84ee6f73e8ec78f03683bc6c1121bbedd4732f7a2166b75cce09c248"
)

const defaultRouteNextHopOID = ".1.3.6.1.2.1.4.21.1.7.0.0.0.0"

// defaultRouteEdits is profile -> (before, after) for ipRouteNextHop.0.0.0.0.
var defaultRouteEdits = map[string][2]string{
	"arista_7280r3.json":           {"10.1.0.1", "192.168.201.254"},
	"cisco_catalyst_9500.json":     {"10.1.0.1", "192.168.1.1"},
	"cisco_crs_x.json":             {"10.0.0.1", "192.168.30.254"},
	"cisco_ios.json":               {"10.0.0.1", "192.168.1.1"},
	"cisco_nexus_9500.json":        {"10.1.0.1", "192.168.101.254"},
	"fortinet_fortigate_600e.json": {"10.1.0.1", "192.168.2.254"},
	"huawei_ne8000.json":           {"10.0.0.1", "192.168.102.254"},
	"juniper_mx240.json":           {"10.0.0.1", "192.168.1.254"},
	"juniper_mx960.json":           {"10.0.0.1", "10.0.1.2"},
	"nokia_7750_sr12.json":         {"10.0.0.1", "192.168.40.254"},
	"palo_alto_pa3220.json":        {"10.1.0.1", "10.0.0.254"},
}

var defaultRouteAddedOIDNames = []string{}

var defaultRouteRemovedOIDNames = []string{}

func restoreDefaultRoute(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	for profile, v := range defaultRouteEdits {
		reverseProfileEdits(t, cur, profile, "default route next hop", []profileRowEdit{
			{op: editChg, oid: defaultRouteNextHopOID, before: v[0], after: v[1]},
		})
	}
}

func defaultRouteOIDNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return reverseOIDNameEdits(t, names, "default route next hop", defaultRouteAddedOIDNames, defaultRouteRemovedOIDNames)
}

func TestDefaultRouteReproducesTheParentCorpus(t *testing.T) {
	if got := corpusTagDigestAt(t, corpusValuesAt(t, defaultRouteParentRevision), defaultRouteParentRevision); got != shippedTagDigestBeforeDefaultRoute {
		t.Errorf("reversing the default route change gives digest %s, want %s: another shipped row changed without being recorded",
			got, shippedTagDigestBeforeDefaultRoute)
	}
}

func TestDefaultRouteRePinIsOnlyTheEdit(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), defaultRouteParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeDefaultRoute {
		t.Errorf("reversing the default route OID names gives digest %s, want %s", got, shippedOIDEncodingDigestBeforeDefaultRoute)
	}
}
