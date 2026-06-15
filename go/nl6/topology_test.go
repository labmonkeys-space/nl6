/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func ep(ip string, ifx int) LinkEndpointJSON { return LinkEndpointJSON{IP: ip, IfIndex: ifx} }

func TestTopology_AddAndLinksForBothEndpoints(t *testing.T) {
	tp := NewTopology()
	if err := tp.AddLink(ep("10.0.0.1", 5), ep("10.0.0.2", 12)); err != nil {
		t.Fatalf("AddLink: %v", err)
	}
	a := tp.LinksFor("10.0.0.1")
	if len(a) != 1 || a[0].LocalIfIndex != 5 || a[0].PeerIP != "10.0.0.2" || a[0].PeerIfIndex != 12 {
		t.Fatalf("LinksFor(.1) = %+v", a)
	}
	b := tp.LinksFor("10.0.0.2")
	if len(b) != 1 || b[0].LocalIfIndex != 12 || b[0].PeerIP != "10.0.0.1" || b[0].PeerIfIndex != 5 {
		t.Fatalf("LinksFor(.2) = %+v", b)
	}
}

func TestTopology_RejectSelfLoop(t *testing.T) {
	tp := NewTopology()
	if err := tp.AddLink(ep("10.0.0.1", 5), ep("10.0.0.1", 5)); err == nil {
		t.Fatal("expected self-loop rejection")
	}
	if tp.Count() != 0 {
		t.Fatalf("graph should be empty, got %d", tp.Count())
	}
}

func TestTopology_RejectDuplicate(t *testing.T) {
	tp := NewTopology()
	must(t, tp.AddLink(ep("10.0.0.1", 5), ep("10.0.0.2", 12)))
	// Reversed endpoints = same undirected link.
	if err := tp.AddLink(ep("10.0.0.2", 12), ep("10.0.0.1", 5)); err == nil {
		t.Fatal("expected duplicate rejection")
	}
}

func TestTopology_RejectReusedPort(t *testing.T) {
	tp := NewTopology()
	must(t, tp.AddLink(ep("10.0.0.1", 5), ep("10.0.0.2", 12)))
	// Different peer, but reuses local port (10.0.0.1, 5).
	if err := tp.AddLink(ep("10.0.0.1", 5), ep("10.0.0.3", 7)); err == nil {
		t.Fatal("expected reused-port rejection")
	}
}

func TestTopology_AcceptNonexistentDeviceLazily(t *testing.T) {
	tp := NewTopology()
	// No device existence check at add time — lazy resolution.
	if err := tp.AddLink(ep("10.9.9.9", 1), ep("10.9.9.10", 2)); err != nil {
		t.Fatalf("link to non-existent devices must be accepted: %v", err)
	}
}

func TestTopology_RejectBadIP(t *testing.T) {
	tp := NewTopology()
	if err := tp.AddLink(ep("not-an-ip", 1), ep("10.0.0.2", 2)); err == nil {
		t.Fatal("expected bad-IP rejection")
	}
	if err := tp.AddLink(ep("10.0.0.1", 0), ep("10.0.0.2", 2)); err == nil {
		t.Fatal("expected ifindex<1 rejection")
	}
}

func TestTopology_PruneDevice(t *testing.T) {
	tp := NewTopology()
	must(t, tp.AddLink(ep("10.0.0.1", 1), ep("10.0.0.2", 1)))
	must(t, tp.AddLink(ep("10.0.0.2", 2), ep("10.0.0.3", 1)))
	tp.PruneDevice("10.0.0.2")
	if tp.Count() != 0 {
		t.Fatalf("both links touched .2, expected 0 remaining, got %d", tp.Count())
	}
}

func TestTopology_RemoveLink(t *testing.T) {
	tp := NewTopology()
	must(t, tp.AddLink(ep("10.0.0.1", 5), ep("10.0.0.2", 12)))
	if !tp.RemoveLink(ep("10.0.0.2", 12), ep("10.0.0.1", 5)) {
		t.Fatal("RemoveLink (reversed) should find the link")
	}
	if tp.Count() != 0 {
		t.Fatalf("expected empty after remove, got %d", tp.Count())
	}
	if tp.RemoveLink(ep("10.0.0.1", 5), ep("10.0.0.2", 12)) {
		t.Fatal("RemoveLink of absent link should return false")
	}
}

func TestTopology_LoadFromFile(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(valid, []byte(`{"links":[{"a":{"ip":"10.0.0.1","ifindex":5},"b":{"ip":"10.0.0.2","ifindex":12}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	tp := NewTopology()
	if err := tp.LoadFromFile(valid); err != nil {
		t.Fatalf("valid load: %v", err)
	}
	if tp.Count() != 1 {
		t.Fatalf("expected 1 link, got %d", tp.Count())
	}

	// Self-loop → fatal-worthy error.
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"links":[{"a":{"ip":"10.0.0.1","ifindex":5},"b":{"ip":"10.0.0.1","ifindex":5}}]}`), 0o644)
	if err := NewTopology().LoadFromFile(bad); err == nil {
		t.Fatal("expected self-loop load error")
	}

	// Unknown field → rejected.
	unk := filepath.Join(dir, "unk.json")
	os.WriteFile(unk, []byte(`{"links":[{"a":{"ip":"10.0.0.1","ifindex":5},"b":{"ip":"10.0.0.2","ifindex":12}}],"bogus":1}`), 0o644)
	if err := NewTopology().LoadFromFile(unk); err == nil {
		t.Fatal("expected unknown-field load error")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
