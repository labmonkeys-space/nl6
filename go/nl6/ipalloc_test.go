/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	cases := map[string]int{"8": 8, "16": 16, "24": 24, "": 16, "garbage": 16, "0": 16}
	for in, want := range cases {
		if got := parsePrefix(in); got != want {
			t.Errorf("parsePrefix(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestAssignableHost(t *testing.T) {
	const m24, m16 = uint32(0x000000FF), uint32(0x0000FFFF)
	// /24: only .0 and .255 are reserved.
	if assignableHost(0x0A000000, m24) { // 10.0.0.0 network
		t.Error("/24 network 10.0.0.0 wrongly assignable")
	}
	if assignableHost(0x0A0000FF, m24) { // 10.0.0.255 broadcast
		t.Error("/24 broadcast 10.0.0.255 wrongly assignable")
	}
	if !assignableHost(0x0A000001, m24) { // 10.0.0.1
		t.Error("/24 host 10.0.0.1 wrongly reserved")
	}
	// /16: .x.0 and .x.255 ARE hosts; only A.B.0.0 / A.B.255.255 reserved.
	if !assignableHost(0x0A2A0500, m16) { // 10.42.5.0
		t.Error("/16 host 10.42.5.0 wrongly reserved")
	}
	if !assignableHost(0x0A2A05FF, m16) { // 10.42.5.255
		t.Error("/16 host 10.42.5.255 wrongly reserved")
	}
	if assignableHost(0x0A2A0000, m16) { // 10.42.0.0 network
		t.Error("/16 network 10.42.0.0 wrongly assignable")
	}
	if assignableHost(0x0A2AFFFF, m16) { // 10.42.255.255 broadcast
		t.Error("/16 broadcast 10.42.255.255 wrongly assignable")
	}
}

func ip4(s string) net.IP { return net.ParseIP(s).To4() }

func TestNextHostStep(t *testing.T) {
	cases := []struct {
		from   string
		prefix int
		want   string
	}{
		// /24 — skips .0 and .255 (parity with historical incrementIP).
		{"10.0.0.1", 24, "10.0.0.2"},
		{"10.0.0.254", 24, "10.0.1.1"}, // .255 + next .0 skipped
		// /16 — .x.0 and .x.255 are valid hosts.
		{"10.42.0.254", 16, "10.42.0.255"},
		{"10.42.0.255", 16, "10.42.1.0"},
		{"10.42.1.0", 16, "10.42.1.1"},
		{"10.42.255.254", 16, "10.43.0.1"}, // /16 broadcast + next /16 network skipped
		// /8 — only A.0.0.0 / A.255.255.255 reserved.
		{"10.0.0.255", 8, "10.0.1.0"},
		{"10.255.255.254", 8, "11.0.0.1"},
	}
	for _, c := range cases {
		if got := nextHost(ip4(c.from), c.prefix).String(); got != c.want {
			t.Errorf("nextHost(%s, /%d) = %s, want %s", c.from, c.prefix, got, c.want)
		}
	}
}

// TestNextHostNeverReserved walks the /16 plane across several /24 boundaries and
// asserts the walk is strictly increasing and never lands on the /16 network or
// broadcast — while it DOES produce .x.0 / .x.255 hosts.
func TestNextHostNeverReserved(t *testing.T) {
	cur := ip4("10.42.0.1")
	prev := uint32(0x0A2A0001)
	sawDotZero, sawDot255 := false, false
	for i := 0; i < 3000; i++ {
		cur = nextHost(cur, 16)
		n := uint32(cur[0])<<24 | uint32(cur[1])<<16 | uint32(cur[2])<<8 | uint32(cur[3])
		if n <= prev {
			t.Fatalf("walk not increasing at step %d: %s", i, cur)
		}
		if n == 0x0A2A0000 || n == 0x0A2AFFFF {
			t.Fatalf("walk hit reserved /16 address %s at step %d", cur, i)
		}
		if cur[3] == 0 {
			sawDotZero = true
		}
		if cur[3] == 255 {
			sawDot255 = true
		}
		prev = n
	}
	if !sawDotZero || !sawDot255 {
		t.Errorf("flat /16 walk should produce .x.0 (%v) and .x.255 (%v) hosts", sawDotZero, sawDot255)
	}
}

// TestNextHost24Parity pins the /24 walk to the historical skip-.0/.255 behaviour
// so the common (explicit-/24) path is provably unchanged.
func TestNextHost24Parity(t *testing.T) {
	cur := ip4("10.0.0.1")
	for i := 0; i < 1000; i++ {
		cur = nextHost(cur, 24)
		if cur[3] == 0 || cur[3] == 255 {
			t.Fatalf("/24 walk produced reserved last octet %s at step %d", cur, i)
		}
	}
}

func TestNetworkCIDR(t *testing.T) {
	cases := []struct {
		ip     string
		prefix int
		want   string
	}{
		{"10.42.5.7", 16, "10.42.0.0/16"},
		{"10.0.0.5", 24, "10.0.0.0/24"},
		{"10.5.6.7", 8, "10.0.0.0/8"},
	}
	for _, c := range cases {
		if got := networkCIDR(ip4(c.ip), c.prefix); got != c.want {
			t.Errorf("networkCIDR(%s, /%d) = %s, want %s", c.ip, c.prefix, got, c.want)
		}
	}
}

func TestNetworkRoutesBetween(t *testing.T) {
	// Flat /16 batch in one /16 → a single covering route.
	got := networkRoutesBetween(ip4("10.42.0.1"), ip4("10.42.48.64"), 16)
	if len(got) != 1 || got[0] != "10.42.0.0/16" {
		t.Errorf("/16 single-plane routes = %v, want [10.42.0.0/16]", got)
	}
	// Explicit /24 batch spanning three /24s → per-/24 routes.
	got = networkRoutesBetween(ip4("10.0.0.1"), ip4("10.0.2.5"), 24)
	want := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}
	if len(got) != len(want) {
		t.Fatalf("/24 routes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("/24 routes = %v, want %v", got, want)
		}
	}
	// /16 batch spanning two /16s → two routes.
	got = networkRoutesBetween(ip4("10.42.0.1"), ip4("10.43.0.1"), 16)
	if len(got) != 2 || got[0] != "10.42.0.0/16" || got[1] != "10.43.0.0/16" {
		t.Errorf("two-/16 routes = %v, want [10.42.0.0/16 10.43.0.0/16]", got)
	}
	// Every emitted CIDR must be canonical (no host bits set) or `ip route`
	// rejects it with "Invalid prefix for given prefix length". Preserves the
	// guard from the deleted route_cidr_test.go across all supported prefixes.
	for _, prefix := range []int{8, 16, 24} {
		for _, cidr := range networkRoutesBetween(ip4("10.42.5.7"), ip4("10.45.9.3"), prefix) {
			parsed, network, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Errorf("networkRoutesBetween emitted unparseable CIDR %q: %v", cidr, err)
			} else if !parsed.Equal(network.IP) {
				t.Errorf("networkRoutesBetween emitted non-canonical CIDR %q (host bits set)", cidr)
			}
		}
	}
}
