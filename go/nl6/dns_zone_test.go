/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"strings"
	"testing"
)

func TestSanitiseDNSLabel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"core-rtr-01", "core-rtr-01"},
		{"CORE-RTR-01", "core-rtr-01"},
		{"core_rtr_01", "core-rtr-01"},
		{"ATLAS NYC", "atlas-nyc"},
		{"a..b//c", "a-b-c"},
		{"--edge--", "edge"},
		{"", ""},
		{"!!!", ""},
		// 70 chars -> truncated to 63, no trailing dash
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for _, c := range cases {
		if got := sanitiseDNSLabel(c.in); got != c.want {
			t.Errorf("sanitiseDNSLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Truncation must land on a valid (<=63) label and never end with '-'.
	got := sanitiseDNSLabel("edge-" + strings.Repeat("a", 60) + "----")
	if len(got) > 63 {
		t.Errorf("sanitiseDNSLabel over-length: %d", len(got))
	}
	if got[len(got)-1] == '-' {
		t.Errorf("sanitiseDNSLabel ends with '-': %q", got)
	}
}

func TestIPv4Label(t *testing.T) {
	if got := ipv4Label(net.ParseIP("10.42.0.5")); got != "dev-10-42-0-5" {
		t.Errorf("ipv4Label = %q, want dev-10-42-0-5", got)
	}
	if got := ipv4Label(net.ParseIP("::1")); got != "" {
		t.Errorf("ipv4Label(v6) = %q, want empty", got)
	}
}

func TestReversePTRName(t *testing.T) {
	if got := reversePTRName(net.ParseIP("10.42.0.5")); got != "5.0.42.10.in-addr.arpa." {
		t.Errorf("reversePTRName = %q", got)
	}
}

func TestParseReverseZone(t *testing.T) {
	cases := []struct {
		in       string
		ok       bool
		contains string // an IP that must be inside
		outside  string // an IP that must be outside
		labels   int
	}{
		{"42.10.in-addr.arpa", true, "10.42.0.5", "10.43.0.5", 2},
		{"0.42.10.in-addr.arpa", true, "10.42.0.200", "10.42.1.0", 3},
		{"10.in-addr.arpa", true, "10.99.99.99", "11.0.0.0", 1},
		{"42.10.in-addr.arpa.", true, "10.42.255.255", "9.0.0.0", 2},
		{"nl6.local", false, "", "", 0},
		{"256.10.in-addr.arpa", false, "", "", 0},
		{"1.2.3.4.5.in-addr.arpa", false, "", "", 0},
		// Non-canonical numeric labels must be rejected, not silently coerced.
		{"010.10.in-addr.arpa", false, "", "", 0},
		{"+5.10.in-addr.arpa", false, "", "", 0},
		{"10..in-addr.arpa", false, "", "", 0},
		{"in-addr.arpa", false, "", "", 0},
	}
	for _, c := range cases {
		z, ok := parseReverseZone(c.in)
		if ok != c.ok {
			t.Errorf("parseReverseZone(%q) ok=%v want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if z.labelCount != c.labels {
			t.Errorf("parseReverseZone(%q) labels=%d want %d", c.in, z.labelCount, c.labels)
		}
		if !z.Net.Contains(net.ParseIP(c.contains)) {
			t.Errorf("parseReverseZone(%q) should contain %s", c.in, c.contains)
		}
		if z.Net.Contains(net.ParseIP(c.outside)) {
			t.Errorf("parseReverseZone(%q) should NOT contain %s", c.in, c.outside)
		}
	}
}

func TestReverseZoneForMostSpecific(t *testing.T) {
	zones := []revZone{}
	for _, n := range []string{"10.in-addr.arpa", "42.10.in-addr.arpa", "0.42.10.in-addr.arpa"} {
		z, _ := parseReverseZone(n)
		zones = append(zones, z)
	}
	// 10.42.0.5 is in all three -> most specific is the /24.
	z, ok := reverseZoneFor(net.ParseIP("10.42.0.5"), zones)
	if !ok || z.Origin != "0.42.10.in-addr.arpa." {
		t.Fatalf("most-specific = %q ok=%v, want 0.42.10.in-addr.arpa.", z.Origin, ok)
	}
	// 10.42.1.5 misses the /24 -> falls back to the /16.
	z, ok = reverseZoneFor(net.ParseIP("10.42.1.5"), zones)
	if !ok || z.Origin != "42.10.in-addr.arpa." {
		t.Fatalf("fallback = %q, want 42.10.in-addr.arpa.", z.Origin)
	}
	// 11.0.0.1 matches nothing.
	if _, ok := reverseZoneFor(net.ParseIP("11.0.0.1"), zones); ok {
		t.Fatalf("11.0.0.1 should match no zone")
	}
}

func TestNextSerial(t *testing.T) {
	if got := nextSerial(0, 1000); got != 1000 {
		t.Errorf("nextSerial(0,1000)=%d want 1000", got)
	}
	if got := nextSerial(1000, 1000); got != 1001 {
		t.Errorf("nextSerial(1000,1000)=%d want 1001 (same-second bump)", got)
	}
	if got := nextSerial(5000, 1000); got != 5001 {
		t.Errorf("nextSerial(5000,1000)=%d want 5001 (no regress)", got)
	}
}

func dev(ip, name string) deviceDNS { return deviceDNS{IP: net.ParseIP(ip), SysName: name} }

func findA(recs []dnsRecord, name string) (string, bool) {
	for _, r := range recs {
		if r.Name == name && r.Kind == recA {
			return r.Value, true
		}
	}
	return "", false
}

func TestBuildZoneView_ForwardAndRoundTrip(t *testing.T) {
	v := buildZoneView([]deviceDNS{dev("10.42.0.5", "core-rtr-01")}, "nl6.local", []string{"42.10.in-addr.arpa"})

	if v.DevicesPublished != 1 || v.PTRsEmitted != 1 || v.PTRsOmitted != 0 {
		t.Fatalf("counters: pub=%d ptr=%d omit=%d", v.DevicesPublished, v.PTRsEmitted, v.PTRsOmitted)
	}
	if got, ok := findA(v.Forward, "core-rtr-01.nl6.local."); !ok || got != "10.42.0.5" {
		t.Errorf("forward A core-rtr-01 = %q ok=%v", got, ok)
	}
	if got, ok := findA(v.Forward, "ip4.mgmt.core-rtr-01.nl6.local."); !ok || got != "10.42.0.5" {
		t.Errorf("forward A ip4.mgmt = %q ok=%v (round-trip target must resolve)", got, ok)
	}
	ptrs := v.Reverse["42.10.in-addr.arpa."]
	if len(ptrs) != 1 || ptrs[0].Name != "5.0.42.10.in-addr.arpa." || ptrs[0].Value != "ip4.mgmt.core-rtr-01.nl6.local." {
		t.Fatalf("PTR = %+v", ptrs)
	}
}

func TestBuildZoneView_CollisionDisambiguation(t *testing.T) {
	// Two devices with the same sysName; lowest IP keeps the bare label.
	devices := []deviceDNS{
		dev("10.42.0.9", "edge-swh-01"),
		dev("10.42.0.5", "edge-swh-01"),
	}
	v := buildZoneView(devices, "nl6.local", []string{"42.10.in-addr.arpa"})
	if v.NamesDisambiguated != 1 {
		t.Fatalf("disambiguated=%d want 1", v.NamesDisambiguated)
	}
	if _, ok := findA(v.Forward, "edge-swh-01.nl6.local."); !ok {
		t.Errorf("lowest IP (10.42.0.5) should keep bare label")
	}
	bareVal, _ := findA(v.Forward, "edge-swh-01.nl6.local.")
	if bareVal != "10.42.0.5" {
		t.Errorf("bare label maps to %q, want 10.42.0.5", bareVal)
	}
	if _, ok := findA(v.Forward, "edge-swh-01-0-9.nl6.local."); !ok {
		t.Errorf("collider should get IP-suffixed label edge-swh-01-0-9")
	}
	// PTR targets must be distinct (no two PTRs share a forward name).
	ptrs := v.Reverse["42.10.in-addr.arpa."]
	if len(ptrs) != 2 || ptrs[0].Value == ptrs[1].Value {
		t.Fatalf("PTR targets must be unique: %+v", ptrs)
	}
}

func TestBuildZoneView_Deterministic(t *testing.T) {
	a := []deviceDNS{dev("10.42.0.9", "dup"), dev("10.42.0.5", "dup")}
	b := []deviceDNS{dev("10.42.0.5", "dup"), dev("10.42.0.9", "dup")}
	va := buildZoneView(a, "nl6.local", nil)
	vb := buildZoneView(b, "nl6.local", nil)
	// Regardless of input order, 10.42.0.5 keeps the bare label.
	if v1, _ := findA(va.Forward, "dup.nl6.local."); v1 != "10.42.0.5" {
		t.Errorf("va bare -> %q", v1)
	}
	if v2, _ := findA(vb.Forward, "dup.nl6.local."); v2 != "10.42.0.5" {
		t.Errorf("vb bare -> %q", v2)
	}
}

func TestBuildZoneView_PTROmittedOutsideZone(t *testing.T) {
	// Device IP outside the only configured reverse zone -> forward A but no PTR.
	v := buildZoneView([]deviceDNS{dev("192.168.1.7", "srv-01")}, "nl6.local", []string{"42.10.in-addr.arpa"})
	if v.PTRsEmitted != 0 || v.PTRsOmitted != 1 {
		t.Fatalf("emit=%d omit=%d, want 0/1", v.PTRsEmitted, v.PTRsOmitted)
	}
	if _, ok := findA(v.Forward, "srv-01.nl6.local."); !ok {
		t.Errorf("device must still resolve forward")
	}
	if len(v.Reverse) != 0 {
		t.Errorf("no reverse records expected, got %v", v.Reverse)
	}
}

func TestBuildZoneView_ThreeWayCollisionAllUnique(t *testing.T) {
	// Three devices share a base label; every published name must be unique
	// and a valid (<=63 octet, no trailing '-') DNS label.
	devices := []deviceDNS{
		dev("10.42.0.5", "dup"), dev("10.42.0.9", "dup"), dev("10.42.0.13", "dup"),
	}
	v := buildZoneView(devices, "nl6.local", nil)
	if v.NamesDisambiguated != 2 {
		t.Fatalf("disambiguated=%d want 2", v.NamesDisambiguated)
	}
	seen := map[string]bool{}
	for _, r := range v.Forward {
		label, _, _ := strings.Cut(r.Name, ".")
		if seen[r.Name] {
			t.Errorf("duplicate forward name %q", r.Name)
		}
		seen[r.Name] = true
		if len(label) > 63 {
			t.Errorf("label over 63 octets: %q (%d)", label, len(label))
		}
		if strings.HasSuffix(label, "-") {
			t.Errorf("label ends with '-': %q", label)
		}
	}
}

func TestBuildZoneView_CollisionStaysWithin63(t *testing.T) {
	// A 70-char sysName sanitises to 63 octets; a colliding second device must
	// still yield a <=63-octet label (base is trimmed to fit the suffix).
	long := strings.Repeat("a", 70)
	devices := []deviceDNS{dev("10.42.0.5", long), dev("10.42.0.9", long)}
	v := buildZoneView(devices, "nl6.local", nil)
	for _, r := range v.Forward {
		// ip4.mgmt.* records carry the "ip4" / "mgmt" labels; the device label
		// is the last label before the domain.
		parts := strings.Split(strings.TrimSuffix(r.Name, ".nl6.local."), ".")
		label := parts[len(parts)-1]
		if len(label) > 63 {
			t.Errorf("collision label over 63 octets: %q (%d)", label, len(label))
		}
	}
}

func TestBuildZoneView_MultipleCollisionGroups(t *testing.T) {
	devices := []deviceDNS{
		dev("10.42.0.5", "aaa"), dev("10.42.0.6", "aaa"),
		dev("10.42.0.7", "bbb"), dev("10.42.0.8", "bbb"), dev("10.42.0.9", "bbb"),
	}
	v := buildZoneView(devices, "nl6.local", nil)
	// 1 collider in group aaa + 2 colliders in group bbb = 3.
	if v.NamesDisambiguated != 3 {
		t.Fatalf("disambiguated=%d want 3", v.NamesDisambiguated)
	}
	if _, ok := findA(v.Forward, "aaa.nl6.local."); !ok {
		t.Errorf("aaa bare label missing")
	}
	if _, ok := findA(v.Forward, "bbb.nl6.local."); !ok {
		t.Errorf("bbb bare label missing")
	}
}

func TestBuildZoneView_EmptySysNameFallback(t *testing.T) {
	v := buildZoneView([]deviceDNS{dev("10.42.0.5", "")}, "nl6.local", nil)
	if _, ok := findA(v.Forward, "dev-10-42-0-5.nl6.local."); !ok {
		t.Errorf("empty sysName should fall back to ipv4 label")
	}
}
