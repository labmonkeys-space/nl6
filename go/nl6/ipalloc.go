/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

// defaultPrefixLen is the management-plane default: the simulated fleet is
// addressed as a single flat /16 management network. A device IP is a
// management address (how the device is polled), not a production data-plane
// address, so the only reserved addresses are the /16 network and broadcast.
const defaultPrefixLen = 16

// parsePrefix converts a netmask string ("8" / "16" / "24") to a prefix
// length, defaulting to the flat-/16 management plane when empty or
// unrecognised. Out-of-range values fall back to the default so nextHost can
// never spin on a degenerate subnet.
func parsePrefix(netmask string) int {
	switch netmask {
	case "8":
		return 8
	case "16":
		return 16
	case "24":
		return 24
	default:
		return defaultPrefixLen
	}
}

// assignableHost reports whether n is a usable unicast host of a subnet whose
// host portion is hostMask — i.e. neither the network address (host bits all
// zero) nor the broadcast address (host bits all one).
func assignableHost(n, hostMask uint32) bool {
	h := n & hostMask
	return h != 0 && h != hostMask
}

// nextHost returns the next assignable IPv4 host after ip within ip's own
// /prefix subnet, skipping that subnet's network and broadcast addresses and
// carrying into the next subnet at the boundary. It is the single allocation
// rule shared by every device-creation path (sequential, parallel, prealloc)
// and the route-range calculation, so the IP set the creator produces and the
// IP range the routing layer covers can never diverge.
//
// For /24 it skips .0/.255 (bit-identical to the historical behaviour); for the
// default /16 it skips only A.B.0.0 / A.B.255.255, so A.B.x.0 and A.B.x.255 are
// ordinary management hosts. Returns a fresh net.IP (does not mutate ip).
func nextHost(ip net.IP, prefix int) net.IP {
	v4 := ip.To4()
	if v4 == nil {
		return ip // only IPv4 is supported
	}
	n := binary.BigEndian.Uint32(v4)
	if prefix < 0 || prefix >= 31 {
		// /31 and /32 have no reserved host addresses (RFC 3021); guard against
		// a spin and just advance. Not used by the simulator, but defensive.
		n++
	} else {
		hostMask := ^uint32(0) >> uint(prefix)
		// At most two iterations for /8../24: the only consecutive skip is a
		// subnet broadcast immediately followed by the next subnet's network.
		for n++; !assignableHost(n, hostMask); n++ {
		}
	}
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, n)
	return out
}

// networkCIDR returns the CIDR of the /prefix subnet that contains ip, e.g.
// networkCIDR(10.42.5.7, 16) == "10.42.0.0/16". Empty for non-IPv4 input.
func networkCIDR(ip net.IP, prefix int) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	netIP := v4.Mask(net.CIDRMask(prefix, 32))
	return fmt.Sprintf("%s/%d", netIP.String(), prefix)
}

// networkRoutesBetween returns the distinct /prefix network CIDRs spanning the
// inclusive range [start, end], so the route layer can cover a batch with one
// route per subnet — a single /16 for the flat management plane, or per-/24 for
// an explicit /24 batch. Empty for non-IPv4 input.
func networkRoutesBetween(start, end net.IP, prefix int) []string {
	s, e := start.To4(), end.To4()
	if s == nil || e == nil || prefix < 0 || prefix > 32 {
		return nil
	}
	block := uint32(1) << uint(32-prefix)
	mask := ^(block - 1)
	cur := binary.BigEndian.Uint32(s) & mask
	last := binary.BigEndian.Uint32(e) & mask
	var out []string
	for {
		ipb := make(net.IP, 4)
		binary.BigEndian.PutUint32(ipb, cur)
		out = append(out, fmt.Sprintf("%s/%d", ipb.String(), prefix))
		if cur >= last || cur+block < cur { // reached end or uint32 overflow guard
			break
		}
		cur += block
	}
	return out
}
