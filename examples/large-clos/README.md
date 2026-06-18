# Large Clos Fabric (k-ary fat-tree, 2500 devices)

A scale example that stands up a **20-ary fat-tree** — a folded 3-tier Clos with
**2500 devices** and **6000 inter-device LLDP links** — in [nl6](../../README.md).
Where [`5-stage-clos`](../5-stage-clos/) is a hand-authored 14-device fabric you
can eyeball, this one is generator-driven and meant for SNMP/scale testing.

It's the classic Al-Fares k-ary fat-tree: `k` pods, each with `k/2` edge and
`k/2` aggregation switches, plus `(k/2)²` core switches. Every switch has exactly
`k` ports, so port counts stay bounded as the fabric grows.

```
              core  (k/2)² = 100        cisco_crs_x          ── 20 ports each
                 ╲   ╱   (each core → one port per pod)
  ┌─────────── pod 0 ───────────┐        ┌──── pod 19 ────┐
  agg   k/2 = 10  arista_7280r3   …        agg  …            k pods
  edge  k/2 = 10  cisco_catalyst_9500     edge …            (full mesh edge↔agg)
   │ (each edge → k/2 = 10 hosts)
  hosts  k³/4 = 2000  linux_server
```

| Tier         | Count | Type                  | Ports used (ifIndex)                |
|--------------|-------|-----------------------|-------------------------------------|
| Core         | 100   | `cisco_crs_x`         | 1..20 (one per pod)                 |
| Aggregation  | 200   | `arista_7280r3`       | 1..10 down (edge), 11..20 up (core) |
| Edge         | 200   | `cisco_catalyst_9500` | 1..10 up (agg), 11..20 down (host)  |
| Hosts        | 2000  | `linux_server`        | `eth0` (ifIndex 2)                  |

**Total: 2500 devices, 6000 links.** Counts: `core=(k/2)²`, `agg=edge=k·k/2`,
`hosts=k³/4`.

## Files

| File | Purpose |
|------|---------|
| `gen-clos.py` | Generates the device tiers and the LLDP link graph (source of truth) |
| `nl6-provision.sh` | Creates the tiers + loads the topology in a running nl6 |
| [`../onms-provision.sh`](../onms-provision.sh) | Generate + import the nl6 devices into OpenNMS as a requisition (shared by all examples) |

There is no static `clos.json` — at 6000 links it's generated on demand:
`python3 gen-clos.py topology` emits the `{"links":[…]}` body, and
`python3 gen-clos.py tiers` emits the per-tier create commands.

## Prerequisites

- A running nl6 reachable at `NL6_URL` (default `http://localhost:8080`), started
  with root (TUN/network-namespace) and enough capacity for 2500 devices.
- The four resource types ship with nl6: `cisco_crs_x`, `arista_7280r3`,
  `cisco_catalyst_9500`, `linux_server`.
- `python3` and `curl` on the machine running the script.

## Usage

```bash
# Provision the full 2500-device fabric
NL6_URL=http://my-nl6:8080 ./nl6-provision.sh

# Smaller fabric for a quick try (k=8 → 208 devices, 384 links)
CLOS_K=8 ./nl6-provision.sh

# Inspect without provisioning
python3 gen-clos.py summary     # device/link counts
python3 gen-clos.py topology    # the link graph JSON
```

Verify after provisioning:

```bash
curl -s "$NL6_URL/api/v1/topology/status"   # {subsystem_active, configured_links, active_links}
```

Import the devices into OpenNMS with the shared script (point `OPENNMS_BASE_URL`
at your instance — one knob for scheme + host + port + context path):

```bash
OPENNMS_BASE_URL=https://onms:443/opennms ../onms-provision.sh --import
```

## Notes

- **IP layout** (`10.42.0.0/16`, `/16` netmask): core `10.42.0.1+`, aggregation
  `10.42.4.1+`, edge `10.42.8.1+`, hosts `10.42.16.1+` (2000 hosts span several
  /24s). Bases are sized for the default `k=20`; a much larger `k` may need them
  rebased.
- **Topology visualization:** 2500 nodes / 6000 links is far above the web
  console's render cap (500 / 2000), so the topology panel shows the summary, not
  the graph. This example targets SNMP/scale and LLDP, not the visual canvas —
  use `5-stage-clos` for the interactive view.
- Provisioning 2500 devices in one batch can take a little time; the script
  creates each tier with a single batch `POST /api/v1/devices`.
