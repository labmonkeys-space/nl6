/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// dns_zone.go holds the pure, dependency-free DNS zone model: it turns the
// live device set (IP + sysName) into the forward A records and reverse PTR
// records that the hidden-primary DNS server (dns_server.go) serves and the
// status endpoint reports. Everything here is stdlib-only and deterministic so
// it can be exercised without a DNS library or a running simulator.
//
// Naming scheme (see openspec/changes/add-coredns-service-discovery):
//   forward  <device>.nl6.local            A   <ip>
//   forward  ip4.mgmt.<device>.nl6.local   A   <ip>   (PTR target round-trips)
//   reverse  <rev-nibbles>.in-addr.arpa    PTR ip4.mgmt.<device>.nl6.local.
//
// The device label and the ip4.mgmt target are computed once per device so the
// forward A and the reverse PTR target are always consistent.

// dnsRecordKind enumerates the device-derived record kinds the zone model
// produces. SOA / NS records are synthesised by the server layer (they need
// the serial and SOA tunables), so they are intentionally absent here.
type dnsRecordKind uint8

const (
	recA   dnsRecordKind = iota // Value is a dotted IPv4 address
	recPTR                      // Value is a target FQDN (trailing dot)
)

// dnsRecord is one owner-name → value mapping in a zone. Name and (for PTR)
// Value are fully-qualified with a trailing dot.
type dnsRecord struct {
	Name  string
	Kind  dnsRecordKind
	Value string
}

// deviceDNS is the zone builder's input view of a device. The manager adapts
// ListDevices() into this so the builder stays free of DeviceSimulator.
type deviceDNS struct {
	IP      net.IP
	SysName string
}

// zoneView is the full derived DNS view over a device set: the forward records,
// the reverse records grouped by reverse-zone origin, and the counters the
// status endpoint reports. It is recomputed from scratch on demand (no stored
// per-device DNS state).
type zoneView struct {
	Domain  string                 // forward apex, FQDN (e.g. "nl6.local.")
	Forward []dnsRecord            // A records (device + ip4.mgmt)
	Reverse map[string][]dnsRecord // reverse-zone origin (FQDN) -> PTR records

	DevicesPublished   int
	PTRsEmitted        int
	PTRsOmitted        int // device IPs with no matching configured reverse zone
	NamesDisambiguated int
}

// sanitiseDNSLabel turns an arbitrary sysName into a single valid DNS label:
// lowercased, every character outside [a-z0-9-] replaced with '-', runs of '-'
// collapsed, leading/trailing '-' trimmed, truncated to 63 octets (and
// re-trimmed so it never ends on '-'). Returns "" when nothing survives.
func sanitiseDNSLabel(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	out = strings.Trim(out, "-")
	if len(out) > 63 {
		out = strings.TrimRight(out[:63], "-")
	}
	return out
}

// ipv4Label renders an IPv4 as a DNS-safe label (e.g. "dev-10-42-0-5"). Used as
// the fallback forward name when a sysName sanitises to empty. Returns "" for
// non-IPv4 input.
func ipv4Label(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("dev-%d-%d-%d-%d", ip4[0], ip4[1], ip4[2], ip4[3])
}

// dnsLabelMax is the RFC 1035 maximum length (octets) of a single DNS label.
const dnsLabelMax = 63

// ipSuffixShort is the two-low-octet disambiguation suffix (e.g. "0-5"); within
// the default flat /16 plane this is unique. ipSuffixFull is the all-four-octet
// suffix, unique across any IPv4 space and the terminating fallback.
func ipSuffixShort(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d-%d", ip4[2], ip4[3])
}

func ipSuffixFull(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d-%d-%d-%d", ip4[0], ip4[1], ip4[2], ip4[3])
}

// joinLabel returns "<base>-<suffix>" trimmed so the result is a valid DNS
// label: never longer than dnsLabelMax octets and never ending on '-'. The base
// is shortened (not the suffix) so the disambiguating suffix is preserved
// intact — the suffix is what guarantees uniqueness.
func joinLabel(base, suffix string) string {
	room := dnsLabelMax - len(suffix) - 1
	if room < 1 {
		// Pathological: the suffix alone fills the label. Use it, capped.
		return strings.TrimRight(suffix[:min(len(suffix), dnsLabelMax)], "-")
	}
	if len(base) > room {
		base = strings.TrimRight(base[:room], "-")
	}
	return base + "-" + suffix
}

// disambiguate returns a unique, valid label for a device whose base label is
// already taken. It prefers a stable IP-derived suffix (two low octets, then the
// full address) and falls back to an incrementing counter, so the result is
// always unique within taken, valid (<=63 octets, no trailing '-'), and works
// even for a non-IPv4 IP (where the IP-derived suffixes are empty).
func disambiguate(base string, ip net.IP, taken map[string]bool) string {
	for _, suf := range []string{ipSuffixShort(ip), ipSuffixFull(ip)} {
		if suf == "" {
			continue
		}
		if cand := joinLabel(base, suf); !taken[cand] {
			return cand
		}
	}
	for i := 2; ; i++ {
		if cand := joinLabel(base, strconv.Itoa(i)); !taken[cand] {
			return cand
		}
	}
}

// fqdn returns name with exactly one trailing dot (and lowercased).
func fqdn(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return name + "."
}

// reversePTRName returns the in-addr.arpa owner name for an IPv4, e.g.
// 10.42.0.5 -> "5.0.42.10.in-addr.arpa.". Returns "" for non-IPv4 input.
func reversePTRName(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip4[3], ip4[2], ip4[1], ip4[0])
}

// revZone is a parsed -dns-reverse-zone entry: its FQDN origin plus the IPv4
// network it covers. labelCount drives most-specific selection.
type revZone struct {
	Origin     string // FQDN, e.g. "42.10.in-addr.arpa."
	Net        *net.IPNet
	labelCount int
}

// parseReverseZone parses an in-addr.arpa zone name into the IPv4 network it
// represents. "42.10.in-addr.arpa" -> 10.42.0.0/16; "0.42.10.in-addr.arpa" ->
// 10.42.0.0/24; "10.in-addr.arpa" -> 10.0.0.0/8. Returns ok=false for anything
// that is not a 1–4 label in-addr.arpa name with octets in range.
func parseReverseZone(name string) (revZone, bool) {
	low := strings.TrimSuffix(strings.ToLower(name), ".")
	if !strings.HasSuffix(low, ".in-addr.arpa") {
		return revZone{}, false
	}
	prefix := strings.TrimSuffix(low, ".in-addr.arpa")
	if prefix == "" {
		return revZone{}, false
	}
	parts := strings.Split(prefix, ".")
	if len(parts) > 4 {
		return revZone{}, false
	}
	var octets [4]byte
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		// Reject non-canonical labels ("+5", "010", " 5") that Atoi tolerates
		// but are not valid in-addr.arpa octet labels.
		if err != nil || v < 0 || v > 255 || strconv.Itoa(v) != p {
			return revZone{}, false
		}
		// in-addr.arpa labels are least-significant first, so the first
		// label is the highest-index network octet.
		octets[len(parts)-1-i] = byte(v)
	}
	maskLen := len(parts) * 8
	ipnet := &net.IPNet{
		IP:   net.IPv4(octets[0], octets[1], octets[2], octets[3]).Mask(net.CIDRMask(maskLen, 32)),
		Mask: net.CIDRMask(maskLen, 32),
	}
	return revZone{Origin: fqdn(low), Net: ipnet, labelCount: len(parts)}, true
}

// reverseZoneFor returns the most-specific (longest-prefix) parsed reverse zone
// that contains ip, or ok=false when none do.
func reverseZoneFor(ip net.IP, zones []revZone) (revZone, bool) {
	best := revZone{}
	found := false
	for _, z := range zones {
		if z.Net != nil && z.Net.Contains(ip) {
			if !found || z.labelCount > best.labelCount {
				best, found = z, true
			}
		}
	}
	return best, found
}

// nextSerial returns the next SOA serial: the current Unix time in seconds, but
// never less than prev+1 so rapid changes within one second still advance. The
// result is monotonically increasing for any non-decreasing nowUnix.
//
// SOA serials are 32-bit by RFC 1035; the uint32 truncation of epoch seconds is
// the standard epoch-serial construction (resolvers compare with RFC 1982
// wrap-aware arithmetic). The max(prev+1, …) keeps it strictly advancing.
func nextSerial(prev uint32, nowUnix int64) uint32 {
	cand := uint32(nowUnix)
	if cand <= prev {
		cand = prev + 1
	}
	return cand
}

// buildZoneView computes the full forward+reverse DNS view for a device set.
// Devices are processed in ascending-IP order so the bare-label assignment is
// deterministic (lowest IP keeps the bare label; colliders get an IP-derived
// suffix). reverseZoneNames that fail to parse are skipped.
func buildZoneView(devices []deviceDNS, domain string, reverseZoneNames []string) zoneView {
	domainFQDN := fqdn(domain)

	zones := make([]revZone, 0, len(reverseZoneNames))
	for _, n := range reverseZoneNames {
		if z, ok := parseReverseZone(n); ok {
			zones = append(zones, z)
		}
	}

	sorted := make([]deviceDNS, len(devices))
	copy(sorted, devices)
	sort.Slice(sorted, func(i, j int) bool {
		return bytesCompareIP(sorted[i].IP, sorted[j].IP) < 0
	})

	view := zoneView{
		Domain:  domainFQDN,
		Reverse: make(map[string][]dnsRecord),
	}

	// Pass 1 — assign a unique forward label per device.
	taken := make(map[string]bool, len(sorted))
	labelByIP := make(map[string]string, len(sorted))
	for _, d := range sorted {
		base := sanitiseDNSLabel(d.SysName)
		if base == "" {
			base = ipv4Label(d.IP)
		}
		if base == "" {
			continue // non-IPv4 with empty sysName: unaddressable, skip
		}
		name := base
		if taken[name] {
			name = disambiguate(base, d.IP, taken)
			view.NamesDisambiguated++
		}
		taken[name] = true
		// IP is the DNS identity key; the create path guarantees unique device
		// IPs, so this never clobbers a distinct device.
		labelByIP[d.IP.String()] = name
	}

	// Pass 2 — emit forward A and reverse PTR from the assigned labels.
	for _, d := range sorted {
		label, ok := labelByIP[d.IP.String()]
		if !ok {
			continue
		}
		view.DevicesPublished++

		devName := label + "." + domainFQDN
		mgmtName := "ip4.mgmt." + label + "." + domainFQDN
		ipStr := d.IP.String()
		view.Forward = append(view.Forward,
			dnsRecord{Name: devName, Kind: recA, Value: ipStr},
			dnsRecord{Name: mgmtName, Kind: recA, Value: ipStr},
		)

		z, ok := reverseZoneFor(d.IP, zones)
		if !ok {
			view.PTRsOmitted++
			continue
		}
		view.Reverse[z.Origin] = append(view.Reverse[z.Origin], dnsRecord{
			Name:  reversePTRName(d.IP),
			Kind:  recPTR,
			Value: mgmtName,
		})
		view.PTRsEmitted++
	}

	return view
}

// bytesCompareIP compares two IPs by their 4-byte (or 16-byte) form so the
// device ordering is a stable numeric ascending sort.
func bytesCompareIP(a, b net.IP) int {
	a4, b4 := a.To4(), b.To4()
	if a4 != nil && b4 != nil {
		return bytes.Compare(a4, b4)
	}
	return bytes.Compare(a.To16(), b.To16())
}
