# Fleet inventory

A *fleet* is the set of devices a running nl6 simulator hosts. The
[`scripts/fleet.sh`](https://github.com/labmonkeys-space/nl6/blob/main/scripts/fleet.sh)
helper captures a fleet to a JSON file (`export`) and replays it
into another simulator (`import`) — useful for moving an interesting
test topology between hosts, snapshotting a long-running scale lab
before a redeploy, or shipping a reproducible inventory alongside a
bug report.

For the underlying REST surface see [Web API](../reference/web-api.md).

## Prerequisites

- A running nl6 simulator with its REST API reachable
  (default `:8080`).
- `curl` and `jq` on the host running `fleet.sh`.

## Export

Capture the current device inventory from a running simulator:

```bash
scripts/fleet.sh export http://sim-a:8080 nl6-inventory.json
```

The output is the raw `GET /api/v1/devices` response — one entry per
device with its `ip`, `resource_file`, `snmp_port`, and any
configured `flow`, `traps`, and `syslog` blocks. Server-assigned
fields (`id`, `interface`, `running`) are kept in the file for
reference but are dropped on import.

If the file argument is omitted, `nl6-inventory.json` in the current
directory is used.

## Import

Replay an inventory file against another simulator:

```bash
scripts/fleet.sh import http://sim-b:8080 nl6-inventory.json --netmask 16
```

`--netmask` is a **prefix length** and defaults to `16` — the flat
`10.42.0.0/16` management plane the fleet now uses. `POST /api/v1/devices`
accepts only `8`, `16`, or `24` (a dotted mask like `255.255.0.0` is
rejected with `400`), and the `GET` response does not echo a netmask, so
import supplies one.

:::warning[Dotted netmask in an inventory file]
A batch-manifest file (`[{start_ip,...}]`) is posted verbatim, so `--netmask`
does **not** apply to it — an entry carrying its own dotted `netmask` field
(e.g. from an older export) is rejected with `400`. Regenerate the export, or
rewrite the field to a prefix length (`16`).
:::

Import auto-detects the file shape:

| File shape                              | Behavior                                                                 |
|-----------------------------------------|--------------------------------------------------------------------------|
| `{data:[{ip,...},...]}` (export output) | One POST per device — preserves per-device `flow` / `traps` / `syslog`   |
| `[{start_ip, device_count,...},...]`    | One POST per batch — compact range manifests like `inventory/devices.example.json` |

## Round-trip example

```bash
# Snapshot the source
scripts/fleet.sh export http://sim-a:8080 my-fleet.json

# Replay against a fresh target
scripts/fleet.sh import http://sim-b:8080 my-fleet.json
```

A 56-device sample lives at
[`inventory/nl6-inventory.json`](https://github.com/labmonkeys-space/nl6/blob/main/inventory/nl6-inventory.json)
— drop it into any empty simulator to populate a heterogeneous fleet
spanning many of the 29 device types nl6 ships with.

## Behavior and limits

- **Fail-fast, except on 409.** The first failed POST aborts the run, so
  a partial import is obvious. The one exception is `409 Conflict`, which
  means another creation batch holds the simulator's one-batch-at-a-time
  gate, not that anything is wrong with the request: `import` waits and
  retries that entry (`RETRY_409_LIMIT`, default 60 attempts;
  `RETRY_409_DELAY`, default 5s — 5 minutes in total). Aborting there
  would be worse than waiting, because it is reachable on a normal boot:
  with `-auto-start-ip` the startup batch holds the gate while the
  container is already healthy, which is exactly when `compose up` runs
  this import. Raise `RETRY_409_LIMIT` if your startup batch takes longer
  than five minutes. A duplicate IP is **not** a 409 — the simulator
  absorbs an already-present address as a success.
- **Sequential POSTs.** Each device or batch is POSTed in series,
  no parallelism. For very large fleets prefer the batch-manifest
  shape — one POST can create many devices via `device_count`.
- **Server-assigned fields dropped.** `id`, `interface`, and
  `running` are produced by the simulator at device-attach time and
  are not part of the POST surface.
