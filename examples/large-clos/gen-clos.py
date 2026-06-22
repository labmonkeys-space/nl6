#!/usr/bin/env python3
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# gen-clos.py — generate a k-ary fat-tree (folded 3-tier Clos) for nl6.
#
# The classic Al-Fares fat-tree: k pods, each with k/2 edge + k/2 aggregation
# switches; (k/2)^2 core switches; every switch has exactly k ports. Sizes:
#
#   core  = (k/2)^2          aggregation = k * (k/2)
#   edge  = k * (k/2)        hosts       = k^3 / 4
#   total devices = 5k^2/4 + k^3/4
#
# k=20 (the default) yields 100 core + 200 agg + 200 edge + 2000 hosts = 2500
# devices and 6000 inter-device LLDP links. Override with CLOS_K=<even int>.
#
# Subcommands:
#   topology   print the {"links":[...]} graph as JSON (POST to /api/v1/topology)
#   tiers      print one TAB-separated `start_ip count resource label` per tier
#   summary    print a one-line device/link count (default)
#
# Every switch uses ports 1..k, so k must not exceed the smallest interface
# table among the switch resources — the Arista 7280R3 (agg tier) with 32 ports
# (crs_x has 144, catalyst 48). k <= 32 keeps every link resolvable to a real
# ifDescr; a larger k would reference non-existent ports on the agg switches.

import ipaddress
import json
import os
import sys

MAX_K = 32  # Arista 7280R3 port count — the tightest switch interface table.

_raw_k = os.environ.get("CLOS_K", "20")
try:
    K = int(_raw_k)
except ValueError:
    sys.exit("CLOS_K must be a positive even integer (got %r)" % _raw_k)
if K < 2 or K % 2 != 0:
    sys.exit("CLOS_K must be a positive even integer (got %d)" % K)
if K > MAX_K:
    sys.exit("CLOS_K must be <= %d (Arista 7280R3 has %d ports; got %d)"
             % (MAX_K, MAX_K, K))
HALF = K // 2

N_CORE = HALF * HALF       # (k/2)^2
N_AGG = K * HALF           # k pods * k/2 aggregation
N_EDGE = K * HALF          # k pods * k/2 edge
N_HOST = K * HALF * HALF   # k^3 / 4

# Per-tier base IP (within 10.42.0.0/16) and resource type. Bases are spaced so
# the switch tiers never collide; hosts start at .16 and grow upward.
BASE = {"core": "10.42.0.1", "agg": "10.42.4.1", "edge": "10.42.8.1", "host": "10.42.16.1"}
RES = {
    "core": "cisco_crs_x.json",
    "agg": "arista_7280r3.json",
    "edge": "cisco_catalyst_9500.json",
    "host": "linux_server.json",
}


def ip(tier, idx):
    # Resolve the idx-th host of a tier the same way nl6's device creator
    # (SimulatorManager.incrementIP) does: octet-4 runs 1..254 within each /24,
    # skipping .0 (network) and .255 (broadcast) and carrying into octet-3 on
    # each boundary. A naive base+idx would name the .0/.255 addresses the
    # creator never assigns, leaving the topology graph with dangling endpoints
    # at every /24 boundary. Every tier BASE ends in .1, so octet-4 is a valid
    # host here. O(1).
    base = int(ipaddress.IPv4Address(BASE[tier]))
    b4 = base & 255
    prefix = base - b4
    first_run = 255 - b4
    if idx < first_run:
        return str(ipaddress.IPv4Address(prefix + b4 + idx))
    rest = idx - first_run
    subnets = 1 + rest // 254
    o4 = 1 + rest % 254
    return str(ipaddress.IPv4Address(prefix + subnets * 256 + o4))


def core_id(j, i):    # core group j (0..HALF-1), member i (0..HALF-1)
    return j * HALF + i


def agg_id(p, a):     # pod p, aggregation switch a
    return p * HALF + a


def edge_id(p, e):    # pod p, edge switch e
    return p * HALF + e


def host_id(p, e, h):  # pod p, edge e, host h
    return (p * HALF + e) * HALF + h


def links():
    out = []
    # Edge <-> aggregation: full mesh inside each pod. Edge uplink ports 1..k/2,
    # aggregation downlink ports 1..k/2.
    for p in range(K):
        for e in range(HALF):
            for a in range(HALF):
                out.append({
                    "a": {"ip": ip("edge", edge_id(p, e)), "ifindex": 1 + a},
                    "b": {"ip": ip("agg", agg_id(p, a)), "ifindex": 1 + e},
                })
    # Aggregation <-> core: aggregation switch a connects to core group a
    # (cores a*k/2 .. a*k/2+k/2-1). Aggregation uplink ports k/2+1..k; each core
    # uses port (pod+1), one per pod.
    for p in range(K):
        for a in range(HALF):
            for i in range(HALF):
                out.append({
                    "a": {"ip": ip("agg", agg_id(p, a)), "ifindex": HALF + 1 + i},
                    "b": {"ip": ip("core", core_id(a, i)), "ifindex": 1 + p},
                })
    # Edge <-> host: each edge switch fans out to k/2 hosts on downlink ports
    # k/2+1..k; the host uses eth0 (ifIndex 2).
    for p in range(K):
        for e in range(HALF):
            for h in range(HALF):
                out.append({
                    "a": {"ip": ip("edge", edge_id(p, e)), "ifindex": HALF + 1 + h},
                    "b": {"ip": ip("host", host_id(p, e, h)), "ifindex": 2},
                })
    return out


def tiers():
    return [
        (BASE["core"], N_CORE, RES["core"], "core (Tier 1)"),
        (BASE["agg"], N_AGG, RES["agg"], "aggregation (Tier 2)"),
        (BASE["edge"], N_EDGE, RES["edge"], "edge (Tier 3)"),
        (BASE["host"], N_HOST, RES["host"], "hosts"),
    ]


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "summary"
    if cmd == "topology":
        json.dump({"links": links()}, sys.stdout)
        sys.stdout.write("\n")
    elif cmd == "tiers":
        for base, count, res, label in tiers():
            print("%s\t%d\t%s\t%s" % (base, count, res, label))
    elif cmd == "summary":
        total = N_CORE + N_AGG + N_EDGE + N_HOST
        print("k=%d fat-tree: %d core + %d agg + %d edge + %d hosts = %d devices, %d links"
              % (K, N_CORE, N_AGG, N_EDGE, N_HOST, total, len(links())))
    else:
        sys.exit("usage: gen-clos.py [topology|tiers|summary]")


if __name__ == "__main__":
    main()
