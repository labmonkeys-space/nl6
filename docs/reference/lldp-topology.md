# LLDP topology

nl6 can model **inter-device links** and expose them as a standards-compliant
LLDP-MIB (IEEE 802.1AB, OID root `1.0.8802.1.1.2`) neighbor table on every
participating device, plus a transparent `ifAlias` link label. The intended
consumer is OpenNMS Enlinkd LLDP discovery: point it at the simulator and it
builds a topology map of the fleet.

This is the capability reference. For the design rationale see
[`openspec/specs/lldp-topology/spec.md`](https://github.com/labmonkeys-space/nl6/blob/main/openspec/specs/lldp-topology/spec.md).

## Quick example — a fleet with a topology

### One command: 4 devices, 2 point-to-point links

The default auto-start device type has a single interface (`ifIndex 1`), so it
can form point-to-point **pairs**. Create `pairs.json`:

```json
{
  "links": [
    { "a": {"ip": "10.0.0.1", "ifindex": 1}, "b": {"ip": "10.0.0.2", "ifindex": 1} },
    { "a": {"ip": "10.0.0.3", "ifindex": 1}, "b": {"ip": "10.0.0.4", "ifindex": 1} }
  ]
}
```

```bash
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 4 -topology-config pairs.json
```

The graph loads at startup; the four devices come up in the background and the
links resolve lazily. Verify:

```bash
snmpwalk -v2c -c public 10.0.0.1 1.0.8802.1.1.2          # local + neighbor (10.0.0.2)
snmpget  -v2c -c public 10.0.0.1 1.3.6.1.2.1.1.5.0       # this device's (random) sysName
snmpget  -v2c -c public 10.0.0.1 1.3.6.1.2.1.31.1.1.1.18.1  # ifAlias = to_<peer-sysName>_<peer-port>
curl -s http://localhost:8080/api/v1/topology/status | jq # {subsystem_active:true, configured_links:2, active_links:2}
```

### A 5-stage Clos fabric over REST

A realistic example: the minimal 5-stage Clos from
[containerlab's `min-5clos`](https://containerlab.dev/lab-examples/min-5clos/)
— two superspines, two pods of two spines + two leaves each, and a client on a
leaf in each pod. Twelve devices, eighteen links, with a sensible device type
per tier:

| Tier | Device type | Nodes | IPs | Ports used |
|------|-------------|-------|-----|------------|
| Superspine | `cisco_crs_x` (144-port core) | 2 | `10.0.0.1–2` | 1–4 (to the 4 spines) |
| Spine | `arista_7280r3` | 4 | `10.0.1.1–4` | 1–2 up (superspines), 3–4 down (leaves) |
| Leaf | `cisco_catalyst_9500` | 4 | `10.0.2.1–4` | 1–2 up (spines), 3 down (client) |
| Client | `linux_server` | 2 | `10.0.3.1–2` | 1 (to its leaf) |

```
          superspine1 (10.0.0.1)        superspine2 (10.0.0.2)
            /     |       |    \           /    |      |     \
       spine1  spine2  spine3  spine4  ...full mesh superspine↔spine...
        (10.0.1.1) (.2)   (.3)   (.4)
        /  \      /  \     |  \     |  \
     leaf1 leaf2 ...      leaf3 leaf4
    (10.0.2.1)(.2)      (10.0.2.3)(.4)
       |                    |
     client1 (10.0.3.1)   client2 (10.0.3.2)
```

Boot the server and create the four tiers:

```bash
sudo ./nl6        # subsystems are always-on; no topology flag needed

curl -X POST http://localhost:8080/api/v1/devices -H 'Content-Type: application/json' \
  -d '{"start_ip":"10.0.0.1","device_count":2,"netmask":"24","resource_file":"cisco_crs_x.json"}'        # superspines
curl -X POST http://localhost:8080/api/v1/devices -H 'Content-Type: application/json' \
  -d '{"start_ip":"10.0.1.1","device_count":4,"netmask":"24","resource_file":"arista_7280r3.json"}'      # spines
curl -X POST http://localhost:8080/api/v1/devices -H 'Content-Type: application/json' \
  -d '{"start_ip":"10.0.2.1","device_count":4,"netmask":"24","resource_file":"cisco_catalyst_9500.json"}' # leaves
curl -X POST http://localhost:8080/api/v1/devices -H 'Content-Type: application/json' \
  -d '{"start_ip":"10.0.3.1","device_count":2,"netmask":"24","resource_file":"linux_server.json"}'        # clients
```

Wire the fabric — save as `clos.json` and POST it:

```json
{ "links": [
  { "a": {"ip":"10.0.0.1","ifindex":1}, "b": {"ip":"10.0.1.1","ifindex":1} },
  { "a": {"ip":"10.0.0.1","ifindex":2}, "b": {"ip":"10.0.1.2","ifindex":1} },
  { "a": {"ip":"10.0.0.1","ifindex":3}, "b": {"ip":"10.0.1.3","ifindex":1} },
  { "a": {"ip":"10.0.0.1","ifindex":4}, "b": {"ip":"10.0.1.4","ifindex":1} },
  { "a": {"ip":"10.0.0.2","ifindex":1}, "b": {"ip":"10.0.1.1","ifindex":2} },
  { "a": {"ip":"10.0.0.2","ifindex":2}, "b": {"ip":"10.0.1.2","ifindex":2} },
  { "a": {"ip":"10.0.0.2","ifindex":3}, "b": {"ip":"10.0.1.3","ifindex":2} },
  { "a": {"ip":"10.0.0.2","ifindex":4}, "b": {"ip":"10.0.1.4","ifindex":2} },
  { "a": {"ip":"10.0.1.1","ifindex":3}, "b": {"ip":"10.0.2.1","ifindex":1} },
  { "a": {"ip":"10.0.1.1","ifindex":4}, "b": {"ip":"10.0.2.2","ifindex":1} },
  { "a": {"ip":"10.0.1.2","ifindex":3}, "b": {"ip":"10.0.2.1","ifindex":2} },
  { "a": {"ip":"10.0.1.2","ifindex":4}, "b": {"ip":"10.0.2.2","ifindex":2} },
  { "a": {"ip":"10.0.1.3","ifindex":3}, "b": {"ip":"10.0.2.3","ifindex":1} },
  { "a": {"ip":"10.0.1.3","ifindex":4}, "b": {"ip":"10.0.2.4","ifindex":1} },
  { "a": {"ip":"10.0.1.4","ifindex":3}, "b": {"ip":"10.0.2.3","ifindex":2} },
  { "a": {"ip":"10.0.1.4","ifindex":4}, "b": {"ip":"10.0.2.4","ifindex":2} },
  { "a": {"ip":"10.0.2.1","ifindex":3}, "b": {"ip":"10.0.3.1","ifindex":1} },
  { "a": {"ip":"10.0.2.3","ifindex":3}, "b": {"ip":"10.0.3.2","ifindex":1} }
] }
```

```bash
curl -X POST http://localhost:8080/api/v1/topology \
  -H 'Content-Type: application/json' --data @clos.json
```

Now each tier shows its fabric neighbors. A spine (`10.0.1.1`) has **4**
neighbors — two superspines (ports 1–2) and two leaves (ports 3–4); a leaf
(`10.0.2.1`) has **3** — two spines and its client:

```bash
snmpwalk -v2c -c public 10.0.1.1 1.0.8802.1.1.2.1.4      # spine: 4 lldpRem rows
snmpwalk -v2c -c public 10.0.2.1 1.0.8802.1.1.2.1.4      # leaf:  3 lldpRem rows
curl -s http://localhost:8080/api/v1/topology/status | jq # configured_links:18, active_links:18
```

Each device's `sysName` is randomly generated at creation (e.g. `SPINE-AB12`),
so the `ifAlias` labels (`to_<peer-sysName>_<peer-port>`) and `lldpRemSysName`
values uniquely identify the far end of every fabric link. Read a device's own
name with `snmpget … 1.3.6.1.2.1.1.5.0`.

### Watch a link go down

Take one end of the spine1↔leaf1 link down and its neighbor rows disappear on
**both** sides, while the `ifAlias` (configured intent) stays:

```bash
# leaf1 (10.0.2.1) port 1 faces spine1 (10.0.1.1) port 3
curl -X POST http://localhost:8080/api/v1/devices/10.0.2.1/interfaces/1/oper-status \
  -H 'Content-Type: application/json' -d '{"status":"DOWN"}'

curl -s http://localhost:8080/api/v1/topology/status | jq '.active_links'   # now 17
snmpwalk -v2c -c public 10.0.1.1 1.0.8802.1.1.2.1.4 | wc -l                  # spine1: one fewer neighbor
snmpget  -v2c -c public 10.0.2.1 1.3.6.1.2.1.31.1.1.1.18.1                   # leaf1 ifAlias unchanged
```

> **Walk anchor.** LLDP lives at `1.0.8802.*`, which sorts *before* the mib-2
> tree — a walk rooted at `1.3.6.1` never reaches it. Anchor at `1.0.8802`
> (and point OpenNMS Enlinkd at the LLDP root).

## Model

A link is a single **undirected** edge between two endpoints, each an
`(deviceIP, ifIndex)` pair. The graph is simulator-wide and owned by the
manager — it is the single source of truth, and each device derives its own
LLDP local-system data, local-port table, and remote (neighbor) table from
the edges touching it.

- **One link per local port** (point-to-point). A second link on a port that
  is already used is rejected.
- **Lazy resolution.** A link is validated *syntactically* at add time
  (no self-loop, no duplicate, one link per port). Device existence and
  ifIndex ownership are resolved later, when SNMP is served — so a link may
  reference a device that hasn't been created yet (e.g. an auto-start batch
  still spinning up). The edge stays inert until both ends resolve.
- **Edges are pruned** automatically when a referenced device is deleted.

## Configuration

### Startup file

```bash
sudo ./nl6 -topology-config links.json
```

```json
{
  "links": [
    { "a": {"ip": "10.0.0.1", "ifindex": 1}, "b": {"ip": "10.0.0.2", "ifindex": 2} },
    { "a": {"ip": "10.0.0.2", "ifindex": 3}, "b": {"ip": "10.0.0.3", "ifindex": 1} }
  ]
}
```

Syntactic validation failures are fatal at startup. Unknown JSON fields are
rejected.

### Runtime REST

| Method & path | Body | Result |
|---|---|---|
| `POST /api/v1/topology` | `{"links":[{"a":{...},"b":{...}}]}` | `201`; all-or-nothing (a rejected link rolls back the batch) |
| `GET /api/v1/topology` | — | `200` `{"links":[…]}` |
| `DELETE /api/v1/topology` | `{"a":{...},"b":{...}}` | `204`, or `404` if the link is absent |
| `GET /api/v1/topology/status` | — | `200` `{"subsystem_active", "configured_links", "active_links"}` |

`active_links` counts links whose both endpoints are resolvable and
operationally up — i.e. those currently producing a neighbor row. The
difference between `configured_links` and `active_links` is your down-link
count.

## What is served

Per device with at least one configured link:

| OID | Value |
|---|---|
| `lldpLocChassisIdSubtype.0` (`…1.3.1.0`) | `4` (macAddress) |
| `lldpLocChassisId.0` (`…1.3.2.0`) | 6-byte MAC `02:42:<ipv4>` |
| `lldpLocSysName.0` (`…1.3.3.0`) | device `sysName` |
| `lldpLocSysDesc.0` (`…1.3.4.0`) | device `sysDescr` |
| `lldpLocPortTable` (`…1.3.7.1.{2,3,4}.<ifIndex>`) | port id subtype `5`, `lldpLocPortId`/`Desc` = `ifDescr` |
| `lldpRemTable` (`…1.4.1.1.{4..10}.0.<localPort>.1`) | the peer's chassis id, port id, sysName, sysDesc |
| `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18.<ifIndex>`) | `to_<peerSysName>_<peerIfDescr>` |

The neighbor row index is `{lldpRemTimeMark=0, lldpRemLocalPortNum=ifIndex,
lldpRemIndex=1}`.

**Stitching.** `lldpRemChassisId`/`lldpRemPortId` on one device are derived
from the peer's own canonical sources (the `02:42:<ipv4>` chassis MAC and the
peer's `ifDescr`) — identical to what the peer advertises in its local data —
so Enlinkd matches the two half-links.

## Liveness vs. intent

- **`lldpRemTable` rows are oper-status-aware.** A neighbor row is served only
  while both endpoints are operationally up. Take either port down (flap
  scenario, or `POST .../oper-status DOWN`) and the row disappears on both
  sides; bring it back up and the row returns. A device type with no
  interface-state engine is treated as up. Because the two ends live on
  different devices, the both-sides property is eventually-consistent.
- **`ifAlias` reflects configured intent** and is present regardless of
  oper-status. So `ifXTable` shows what *should* be connected and the LLDP
  table shows what is *actually up* — diff the two to find down links.

An `ifAlias` is emitted only for a link whose peer is resolvable; an
unresolvable peer yields no label (never a malformed `to__`), leaving any
static `ifAlias` in place.

## Walking it

LLDP lives at `1.0.8802.1.1.2`, which sorts **before** the standard mib-2
tree — a walk anchored at `1.3.6.1` will never reach it. Anchor at the LLDP
root:

```bash
snmpwalk -v2c -c public 10.0.0.1 1.0.8802.1.1.2
snmpget  -v2c -c public 10.0.0.1 1.3.6.1.2.1.31.1.1.1.18.1   # ifAlias link label
```

## Out of scope

Capability bitmaps (`lldpRemSysCapSupported`/`Enabled`),
`lldpStatistics` / `lldpConfiguration`, gNMI/openconfig-lldp, multi-neighbor
(shared-segment) ports, and operator-supplied custom alias text.
