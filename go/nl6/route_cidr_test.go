/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"testing"
)

// TestSubnet24CIDR pins the host-route CIDR format. The regression it guards:
// emitting a device's netmask verbatim (e.g. /16) onto a /24-aligned ".0"
// network address produced non-canonical prefixes like "10.42.4.0/16" that the
// kernel rejects ("Invalid prefix for given prefix length") — surfaced by Clos
// fabrics, which spread devices across many /24s inside one /16.
func TestSubnet24CIDR(t *testing.T) {
	cases := []struct {
		o0, o1, o2 byte
		want       string
	}{
		{10, 42, 0, "10.42.0.0/24"},   // core tier
		{10, 42, 4, "10.42.4.0/24"},   // agg tier — was "10.42.4.0/16" (invalid)
		{10, 42, 8, "10.42.8.0/24"},   // edge tier
		{10, 42, 16, "10.42.16.0/24"}, // host tier
		{192, 168, 100, "192.168.100.0/24"},
	}
	for _, c := range cases {
		got := subnet24CIDR(c.o0, c.o1, c.o2)
		if got != c.want {
			t.Errorf("subnet24CIDR(%d,%d,%d) = %q, want %q", c.o0, c.o1, c.o2, got, c.want)
		}
		// Encode the invariant `ip route` enforces: the address must equal the
		// network address for the prefix (no host bits set). The old "/16" form
		// failed this — net.ParseCIDR silently masks, so compare the parsed IP
		// to the network it belongs to rather than relying on a parse error.
		ip, network, err := net.ParseCIDR(got)
		if err != nil {
			t.Errorf("subnet24CIDR(%d,%d,%d) = %q is not a valid CIDR: %v", c.o0, c.o1, c.o2, got, err)
			continue
		}
		if !ip.Equal(network.IP) {
			t.Errorf("subnet24CIDR(%d,%d,%d) = %q is not a canonical network CIDR (host bits set; ip route would reject it)", c.o0, c.o1, c.o2, got)
		}
	}
}
