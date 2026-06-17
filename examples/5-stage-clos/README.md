# 5-Stage Clos Fabric

A worked example that stands up a **5-stage folded Clos** (3-tier fat-tree)
in [nl6](../../README.md) and imports the resulting nodes into OpenNMS.

The "5 stages" are the switch hops a packet crosses end-to-end:
**leaf → spine → superspine → spine → leaf**. The two Linux hosts are
endpoints, not stages.

```
  TIER 1        ┌──────────────┐        ┌──────────────┐
  superspine    │ .100 crs_x   │        │ .101 crs_x   │       cisco_crs_x ×2
                └──┬──┬──┬──┬──┘        └──┬──┬──┬──┬──┘
                   └──┴──┴──┴───full mesh───┴──┴──┴──┘
  TIER 2   ┌────────┐ ┌────────┐      ┌────────┐ ┌────────┐
  spine    │.120 7280│ │.121 7280│     │.122 7280│ │.123 7280│  arista_7280r3 ×4
           └──┬───┬─┘ └─┬────┬─┘      └──┬───┬─┘ └─┬────┬─┘
  TIER 3   ┌────────┐ ┌────────┐      ┌────────┐ ┌────────┐
  leaf     │.130 9500│ │.131 9500│     │.132 9500│ │.133 9500│  catalyst_9500 ×4
           └────┬────┘ └────────┘      └────┬────┘ └────────┘
                │                           │
           ┌─────────┐                 ┌─────────┐
  hosts    │.140 srv │                 │.141 srv │            linux_server ×2
           └─────────┘                 └─────────┘

  POD A: spines .120/.121 ↔ leaves .130/.131
  POD B: spines .122/.123 ↔ leaves .132/.133
  Each spine: port1 → superspine .100, port2 → superspine .101
```

12 fabric devices + 2 hosts, 18 inter-device LLDP links (`clos.json`).

## Files

| File | Purpose |
|------|---------|
| `provision.sh` | Create the devices + load the topology in nl6 |
| `clos.json` | The 18-link inter-device LLDP graph |
| `import.sh` | Import the nl6 devices into OpenNMS as a requisition |
| `nl6-requisition.sh` | Vendored requisition generator (see caveat below) |

## Prerequisites

- A running nl6 instance reachable at `NL6_URL` (default `http://localhost:8080`).
  The four resource types must be present: `cisco_crs_x`, `arista_7280r3`,
  `cisco_catalyst_9500`, `linux_server` (all ship with nl6).
- For the import step: an OpenNMS instance and `python3` on the machine running
  the script.

## Usage

```bash
# 1. Provision the fabric in nl6
NL6_URL=http://my-nl6:8080 ./provision.sh

# 2. Import the nodes into OpenNMS
NL6_URL=http://my-nl6:8080 \
OPENNMS_HOST=onms OPENNMS_PORT=8980 OPENNMS_USER=admin OPENNMS_PASS=admin \
  ./import.sh --import

# Preview the requisition XML without uploading:
./import.sh --import --dry-run
```

Run `./import.sh --help` for the full list of OpenNMS / gNMI environment knobs.

## Caveats

- **`import.sh` imports the *whole* nl6 instance**, not just this fabric — the
  requisition is built from `GET /api/v1/devices`. Point `NL6_URL` at an nl6
  dedicated to the Clos example, or expect extra nodes in the requisition.
- **`nl6-requisition.sh` is a vendored copy** of the script in the
  `opennms-benchmark` repo, captured so this example is self-contained. It can
  drift from the upstream original.
- **Node geolocation:** the requisition emits `latitude` / `longitude` / `city`
  asset fields from each device's nl6-assigned location, so nodes appear on the
  OpenNMS geomap. Locations are assigned **randomly per device**, so the fabric
  is geographically scattered rather than sitting at one site — pinning a fabric
  to a location needs a per-device location override on `POST /api/v1/devices`,
  which is a separate change.
