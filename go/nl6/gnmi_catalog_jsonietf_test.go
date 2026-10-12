/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"testing"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// jp builds a path from "/a/b[k=v]/c" with origin o.
func jp(t *testing.T, o, s string) *gnmipb.Path {
	t.Helper()
	p, err := parseGnmiPath(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	p.Origin = o
	return p
}

func ru(t *testing.T, rel string, v any) resolvedUpdate {
	t.Helper()
	return resolvedUpdate{Path: jp(t, "", rel), Value: v}
}

// foldedGet folds notifs for request and returns each update as
// "origin:path => json".
func foldedGet(t *testing.T, request *gnmipb.Path, notifs []catalogNotification) []string {
	t.Helper()
	ups, err := foldJSONIETFGet(request, notifs)
	if err != nil {
		t.Fatal(err)
	}
	return renderFolded(ups)
}

func renderFolded(ups []*gnmipb.Update) []string {
	out := make([]string, 0, len(ups))
	for _, u := range ups {
		out = append(out, u.GetPath().GetOrigin()+":"+pathToString(u.GetPath())+" => "+string(u.GetVal().GetJsonIetfVal()))
	}
	return out
}

func wantFolded(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d updates %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("update %d:\n got  %s\n want %s", i, got[i], want[i])
		}
	}
}

const oci = "openconfig-interfaces"

func TestFoldGetListEntryContainer(t *testing.T) {
	notifs := []catalogNotification{{
		Prefix: jp(t, oci, "/interfaces/interface[name=eth0]/state/counters"),
		Updates: []resolvedUpdate{
			ru(t, "/in-octets", uint64(5)),
			ru(t, "/in-errors", uint32(3)),
		},
	}}
	got := foldedGet(t, jp(t, "", "/interfaces/interface[name=eth0]/state"), notifs)
	wantFolded(t, got, oci+`:/interfaces/interface[name=eth0]/state => {"counters":{"in-errors":3,"in-octets":"5"}}`)
}

// A list the request ends above becomes an array whose entries repeat
// their keys, in resolver order rather than key order.
func TestFoldGetWholeList(t *testing.T) {
	var notifs []catalogNotification
	for _, name := range []string{"eth1", "eth0"} {
		notifs = append(notifs, catalogNotification{
			Prefix:  jp(t, oci, "/interfaces/interface[name="+name+"]/state"),
			Updates: []resolvedUpdate{ru(t, "/oper-status", "UP")},
		})
	}
	got := foldedGet(t, jp(t, oci, "/interfaces"), notifs)
	wantFolded(t, got, oci+`:/interfaces => {"interface":[{"name":"eth1","state":{"oper-status":"UP"}},{"name":"eth0","state":{"oper-status":"UP"}}]}`)
}

// The IOS-XR carrier-transitions split: two subtrees with different
// prefix depths merge into one state object.
func TestFoldGetMergesSubtrees(t *testing.T) {
	notifs := []catalogNotification{
		{Prefix: jp(t, oci, "/interfaces/interface[name=eth0]/state"),
			Updates: []resolvedUpdate{ru(t, "/counters/carrier-transitions", uint64(1))}},
		{Prefix: jp(t, oci, "/interfaces/interface[name=eth0]/state/counters"),
			Updates: []resolvedUpdate{ru(t, "/in-octets", uint64(5))}},
	}
	got := foldedGet(t, jp(t, "", "/interfaces/interface[name=eth0]/state"), notifs)
	wantFolded(t, got, oci+`:/interfaces/interface[name=eth0]/state => {"counters":{"carrier-transitions":"1","in-octets":"5"}}`)
}

func TestFoldGetSingleLeafIsScalar(t *testing.T) {
	notifs := []catalogNotification{{
		Prefix:  jp(t, oci, "/interfaces/interface[name=eth0]/state/counters"),
		Updates: []resolvedUpdate{ru(t, "/in-octets", uint64(5))},
	}}
	got := foldedGet(t, jp(t, "", "/interfaces/interface[name=eth0]/state/counters/in-octets"), notifs)
	wantFolded(t, got, oci+`:/interfaces/interface[name=eth0]/state/counters/in-octets => "5"`)
}

// A request crossing a list without a key has one instance per entry,
// as gNMI wildcard expansion gives; each gets its own update.
func TestFoldGetAcrossListWithoutKey(t *testing.T) {
	var notifs []catalogNotification
	for _, name := range []string{"eth0", "eth1"} {
		notifs = append(notifs, catalogNotification{
			Prefix:  jp(t, oci, "/interfaces/interface[name="+name+"]/state/counters"),
			Updates: []resolvedUpdate{ru(t, "/in-octets", uint64(5))},
		})
	}
	got := foldedGet(t, jp(t, oci, "/interfaces/interface/state/counters"), notifs)
	wantFolded(t, got,
		oci+`:/interfaces/interface[name=eth0]/state/counters => {"in-octets":"5"}`,
		oci+`:/interfaces/interface[name=eth1]/state/counters => {"in-octets":"5"}`)
}

// An `always` leaf rides along on a deeper request but sits outside the
// requested node, so a nested value cannot hold it.
func TestFoldGetDropsLeavesOutsideTheRequest(t *testing.T) {
	notifs := []catalogNotification{{
		Prefix: jp(t, "openconfig-platform", "/components/component[name=C]/state"),
		Updates: []resolvedUpdate{
			ru(t, "/temperature/instant", uint64(40)),
			ru(t, "/name", "C"),
		},
	}}
	got := foldedGet(t, jp(t, "", "/components/component[name=C]/state/temperature"), notifs)
	wantFolded(t, got, `openconfig-platform:/components/component[name=C]/state/temperature => {"instant":"40"}`)
}

// Members are sorted, so one request always folds to the same bytes.
func TestFoldGetMemberOrderIsDeterministic(t *testing.T) {
	leaves := []string{"/z", "/a", "/m/y", "/m/b"}
	notif := func(order []int) []catalogNotification {
		n := catalogNotification{Prefix: jp(t, oci, "/interfaces/interface[name=eth0]/state")}
		for _, i := range order {
			n.Updates = append(n.Updates, ru(t, leaves[i], "v"))
		}
		return []catalogNotification{n}
	}
	req := jp(t, "", "/interfaces/interface[name=eth0]/state")
	a := foldedGet(t, req, notif([]int{0, 1, 2, 3}))
	b := foldedGet(t, req, notif([]int{3, 2, 1, 0}))
	wantFolded(t, a, oci+`:/interfaces/interface[name=eth0]/state => {"a":"v","m":{"b":"v","y":"v"},"z":"v"}`)
	wantFolded(t, b, a...)
}

// Each folded scalar is byte-for-byte the per-leaf JSON_IETF value.
func TestFoldScalarsMatchPerLeafEncoding(t *testing.T) {
	values := map[string]any{
		"/u64": uint64(18446744073709551615),
		"/u32": uint32(7),
		"/i64": int64(-3),
		"/b":   true,
		"/s":   `quote " and \ slash`,
		"/d":   gnmiDecimal{val: 1.25e-5, digits: 18},
	}
	for rel, v := range values {
		n := catalogNotification{Prefix: jp(t, oci, "/x"), Updates: []resolvedUpdate{ru(t, rel, v)}}
		ups, err := foldJSONIETFGet(jp(t, "", "/x"+rel), []catalogNotification{n})
		if err != nil {
			t.Fatal(err)
		}
		tv, err := gnmiEncodeTypedValue(v, gnmipb.Encoding_JSON_IETF)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(ups[0].GetVal().GetJsonIetfVal()), string(tv.GetJsonIetfVal()); got != want {
			t.Errorf("%s: folded %s, per-leaf %s", rel, got, want)
		}
	}
}

// Subscribe folds per entry: the update path is the entry prefix with
// its keys and origin, the value the entry's leaves, always leaves
// included since they sit under the entry.
func TestFoldEntry(t *testing.T) {
	n := catalogNotification{
		Prefix: jp(t, "openconfig-platform", "/components/component[name=C]/state"),
		Updates: []resolvedUpdate{
			ru(t, "/temperature/instant", uint64(40)),
			ru(t, "/name", "C"),
		},
	}
	up, err := foldJSONIETFEntry(n)
	if err != nil {
		t.Fatal(err)
	}
	wantFolded(t, renderFolded([]*gnmipb.Update{up}),
		`openconfig-platform:/components/component[name=C]/state => {"name":"C","temperature":{"instant":"40"}}`)
}

// An entry the type filter emptied contributes no keys-only skeleton.
func TestFoldGetSkipsEmptiedEntries(t *testing.T) {
	notifs := []catalogNotification{{Prefix: jp(t, oci, "/interfaces/interface[name=eth0]/state")}}
	got := foldedGet(t, jp(t, oci, "/interfaces"), notifs)
	wantFolded(t, got)
}

// Two leaves on one node are a defect, not last-writer-wins; a leaf
// restating its entry's key replaces the key member.
func TestFoldGetLeafCollisions(t *testing.T) {
	dup := []catalogNotification{
		{Prefix: jp(t, oci, "/interfaces/interface[name=eth0]/state"),
			Updates: []resolvedUpdate{ru(t, "/counters/in-octets", uint64(1))}},
		{Prefix: jp(t, oci, "/interfaces/interface[name=eth0]/state/counters"),
			Updates: []resolvedUpdate{ru(t, "/in-octets", uint64(2))}},
	}
	if _, err := foldJSONIETFGet(jp(t, "", "/interfaces/interface[name=eth0]/state"), dup); err == nil {
		t.Fatal("two leaves on one path folded without an error")
	}
	key := []catalogNotification{{Prefix: jp(t, oci, "/interfaces/interface[name=eth0]"),
		Updates: []resolvedUpdate{ru(t, "/name", "eth0")}}}
	wantFolded(t, foldedGet(t, jp(t, oci, "/interfaces"), key), oci+`:/interfaces => {"interface":[{"name":"eth0"}]}`)
}

// x[a="1][b=2"] and x[a=1][b=2] print alike under pathToString; they
// are distinct entries and stay distinct updates.
func TestFoldGetInstanceIDsDoNotCollide(t *testing.T) {
	entry := func(keys map[string]string) catalogNotification {
		return catalogNotification{
			Prefix:  &gnmipb.Path{Origin: oci, Elem: []*gnmipb.PathElem{{Name: "c"}, {Name: "x", Key: keys}}},
			Updates: []resolvedUpdate{ru(t, "/v", "v")},
		}
	}
	notifs := []catalogNotification{entry(map[string]string{"a": "1][b=2"}), entry(map[string]string{"a": "1", "b": "2"})}
	if a, b := pathToString(notifs[0].Prefix), pathToString(notifs[1].Prefix); a != b {
		t.Fatalf("control: %s and %s no longer print alike", a, b)
	}
	ups, err := foldJSONIETFGet(jp(t, "", "/c/x"), notifs)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 2 {
		t.Fatalf("%d updates, want 2 distinct instances: %q", len(ups), renderFolded(ups))
	}
}
