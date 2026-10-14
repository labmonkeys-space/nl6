/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

// juniper_mx10004 answered ipRouteNextHop.0.0.0.0 with 10.0.0.1, an address no
// interface of the device reaches, while show route and show configuration send
// the default route to 192.168.1.254 via xe-0/0/0.0 (192.168.1.1/24). The value
// now matches the CLI. Both values are IpAddress, so no tag moved and neither
// digest below differs from the current pin; the link exists so the chain
// restores the parent corpus's VALUES, which the tag digest cannot see.

// mx10004RouteParentRevision is main at branch time; the digests below were
// taken there and are NOT re-derived from the new tree.
const mx10004RouteParentRevision = "ec33f509"

const (
	shippedTagDigestBeforeMx10004Route         = "8c46e960fac968c5527f4391a71fa80f56371cc1879bf95a78bfcf017a1499e0"
	shippedOIDEncodingDigestBeforeMx10004Route = "1e16764e84ee6f73e8ec78f03683bc6c1121bbedd4732f7a2166b75cce09c248"
)

var mx10004RouteEdits = []profileRowEdit{
	{op: editChg, oid: ".1.3.6.1.2.1.4.21.1.7.0.0.0.0", before: "10.0.0.1", after: "192.168.1.254"},
}

var mx10004RouteAddedOIDNames = []string{}

var mx10004RouteRemovedOIDNames = []string{}

func restoreMx10004Route(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	reverseProfileEdits(t, cur, juniperMx10004Profile, "juniper_mx10004 default route", mx10004RouteEdits)
}

func mx10004RouteOIDNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return reverseOIDNameEdits(t, names, "juniper_mx10004 default route", mx10004RouteAddedOIDNames, mx10004RouteRemovedOIDNames)
}

func TestMx10004RouteReproducesTheParentCorpus(t *testing.T) {
	if got := corpusTagDigestAt(t, corpusValuesAt(t, mx10004RouteParentRevision), mx10004RouteParentRevision); got != shippedTagDigestBeforeMx10004Route {
		t.Errorf("reversing the default route change gives digest %s, want %s: another shipped row changed without being recorded",
			got, shippedTagDigestBeforeMx10004Route)
	}
}

func TestMx10004RouteRePinIsOnlyTheEdit(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), mx10004RouteParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeMx10004Route {
		t.Errorf("reversing the default route OID names gives digest %s, want %s", got, shippedOIDEncodingDigestBeforeMx10004Route)
	}
}
