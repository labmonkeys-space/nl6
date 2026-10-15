/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

// cisco_asr9902's Bundle-Ether1 reported 200 Gbit/s of traffic that no member
// port carried, because the profile modelled no membership. The xr-chassis
// model names HundredGigE0/0/0/9 and HundredGigE0/0/0/10 (ifIndex 10 and 11)
// as its members and the generator now renders the two active ifStackStatus
// rows, which the counter cycler reads to make the bundle the sum of its
// members. This change added those two rows and nothing else; both OID names
// are new to the corpus, so the name view gains exactly them.

// ciscoAsr9902BundleMembersParentRevision is main at branch time; the digests
// below were taken there and are NOT re-derived from the new tree.
const ciscoAsr9902BundleMembersParentRevision = "e925613f"

const (
	shippedTagDigestBeforeCiscoAsr9902BundleMembers         = "3d6b23bf8a3dab9be83e0141745cd841f7e104d4618d729aa3fc78b57ad3f6a7"
	shippedOIDEncodingDigestBeforeCiscoAsr9902BundleMembers = "f6a56b7156551f632c58735bcfefdf99b9bf523b4ecb5f85eebf0d53d068489c"
)

var ciscoAsr9902BundleMembersEdits = []profileRowEdit{
	{op: editAdd, oid: ".1.3.6.1.2.1.31.1.2.1.3.51.10", after: "1"},
	{op: editAdd, oid: ".1.3.6.1.2.1.31.1.2.1.3.51.11", after: "1"},
}

var ciscoAsr9902BundleMembersAddedOIDNames = []string{
	"1.3.6.1.2.1.31.1.2.1.3.51.10",
	"1.3.6.1.2.1.31.1.2.1.3.51.11",
}

func restoreCiscoAsr9902BundleMembers(t *testing.T, cur map[[2]string]string) {
	t.Helper()
	reverseProfileEdits(t, cur, ciscoAsr9902Profile, "cisco_asr9902 bundle members", ciscoAsr9902BundleMembersEdits)
}

func ciscoAsr9902BundleMembersOIDNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return reverseOIDNameEdits(t, names, "cisco_asr9902 bundle members", ciscoAsr9902BundleMembersAddedOIDNames, nil)
}

func TestCiscoAsr9902BundleMembersReproduceTheParentCorpus(t *testing.T) {
	if got := corpusTagDigestAt(t, corpusValuesAt(t, ciscoAsr9902BundleMembersParentRevision), ciscoAsr9902BundleMembersParentRevision); got != shippedTagDigestBeforeCiscoAsr9902BundleMembers {
		t.Errorf("reversing the bundle members change gives digest %s, want %s: another shipped row changed without being recorded",
			got, shippedTagDigestBeforeCiscoAsr9902BundleMembers)
	}
}

func TestCiscoAsr9902BundleMembersRePinIsOnlyTheEdit(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), ciscoAsr9902BundleMembersParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeCiscoAsr9902BundleMembers {
		t.Errorf("reversing the bundle members OID names gives digest %s, want %s", got, shippedOIDEncodingDigestBeforeCiscoAsr9902BundleMembers)
	}
}
