# Web API

The simulator exposes a REST control-plane on port 8080 (override with
[`-port`](cli-flags.md#core-flags)) for device CRUD, CSV / route-script
export, system stats, and flow-export status. The same port also serves the
management web UI at `/`.

## Endpoint catalog

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/devices` | POST | Create devices (bulk, round-robin, category-based). |
| `/api/v1/devices` | GET | List all devices. |
| `/api/v1/devices/{id}` | DELETE | Delete a specific device. |
| `/api/v1/devices` | DELETE | Delete all devices. |
| `/api/v1/devices/export` | GET | Export device list to CSV. |
| `/api/v1/devices/routes` | GET | Generate a routing script (Debian/Ubuntu). |
| `/api/v1/resources` | GET | List available device resource types. |
| `/api/v1/status` | GET | Manager status. |
| `/api/v1/system-stats` | GET | System stats (file descriptors, memory). |
| `/api/v1/version` | GET | Running simulator version string. Immutable per process; response carries `Cache-Control: max-age=3600`. |
| `/api/v1/flows/status` | GET | Flow export status and cumulative counters. |
| `/api/v1/traps/status` | GET | SNMP trap export status, INFORM counters, and per-type catalog map. |
| `/api/v1/devices/{ip}/trap` | POST | Fire a named catalog trap on a specific device. |
| `/api/v1/syslog/status` | GET | UDP syslog export status, counters, and per-type catalog map. |
| `/api/v1/devices/{ip}/syslog` | POST | Fire a named catalog syslog message on a specific device. |
| `/api/v1/gnmi/status` | GET | gNMI (dial-in) subsystem status: listeners, subscriptions, update/state-event counters. |
| `/api/v1/gnmi/dialout/status` | GET | gNMI dial-out status: per-(collector, flavor) streams, updates sent/dropped, reconnects, send failures. |
| `/api/v1/dns/status` | GET | DNS service-discovery status: zones + serials, publish counters, NOTIFY tallies. |
| `/health` | GET | Health check endpoint. |

## Create devices

Bulk creation supports round-robin across all device types, category-based
filtering, per-request SNMP port selection, and an optional SNMPv3 block.

> **Addressing.** Device IPs are *management* addresses on a flat `/16` plane.
> `netmask` is optional and **defaults to `/16`** — only the `/16` network and
> broadcast are reserved, so `.x.0` and `.x.255` are assigned as ordinary hosts.
> An explicit `"netmask": "24"` (or `"8"`) is still honored if you want classic
> per-`/24` semantics (which skip `.0`/`.255`).

```bash
# Round-robin across all device types
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 10,
    "netmask": "16",
    "round_robin": true
  }'

# Non-privileged SNMP port (avoids CAP_NET_BIND_SERVICE)
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 5,
    "netmask": "16",
    "snmp_port": 1161
  }'

# Filter by category
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 3,
    "netmask": "16",
    "round_robin": true,
    "category": "GPU Servers"
  }'

# SNMPv3
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 5,
    "netmask": "16",
    "snmpv3": {
      "enabled": true,
      "engine_id": "0x80001234",
      "username": "admin",
      "password": "authpass123",
      "auth_protocol": "md5",
      "priv_protocol": "aes128"
    }
  }'

# Per-device error-counter scenario
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 3,
    "netmask": "16",
    "if_error_scenario": "degraded"
  }'
```

The `if_error_scenario` field controls the per-device ppm bands used to
derive `ifInErrors`, `ifOutErrors`, `ifInDiscards`, and `ifOutDiscards`
from live packet counters. Accepted values: `clean` (default, no error
growth), `typical`, `degraded`, `failing`. Unknown values reject the
batch atomically with 400. REST-created devices default to `clean`
independently of the `-if-error-scenario` CLI flag — you must opt in
explicitly. See [SNMP reference](snmp.md#per-device-error-scenario) for
the full scenario bands and counter model.

A specific resource file can be requested directly (useful for storage
devices):

```bash
# Create a Pure Storage FlashArray device
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 1,
    "netmask": "16",
    "resource_file": "pure_storage_flasharray.json"
  }'
```

### Per-device export blocks

`POST /api/v1/devices` accepts four optional top-level blocks —
`flow`, `traps`, `syslog`, `gnmi_dialout` — that attach export
configuration to every device created by the request. Any block can be
omitted; omitted blocks mean "this batch does not participate in that
export subsystem."

The subsystems are always-on after `main()` — flow / trap / syslog /
gNMI dial-out scheduler goroutines and catalog loaders run regardless
of whether any CLI seed was supplied, so REST-created devices can opt
in to any combination.

**`flow` block:**

```json
"flow": {
  "collector":        "192.168.1.10:2055",      // required; host:port
  "protocol":         "netflow9",               // optional; "netflow9" | "ipfix" | "netflow5" | "sflow" (alias: "sflow5"); default "netflow9"
  "tick_interval":    "5s",                      // optional; global ticker used, per-device value validated and logged if divergent
  "active_timeout":   "30s",                     // optional; default 30s
  "inactive_timeout": "15s",                     // optional; default 15s
  "sub_agent_id":     0,                         // optional; sFlow datagram sub_agent_id, default 0; ignored by non-sFlow protocols
  "options_interface_table": ""                  // optional; "" (off, default) | "if-scoped" | "system-scoped"; netflow9/ipfix only — other protocols rejected with 400
}
```

No per-device override exists for `source_per_device` — the
`-flow-source-per-device` CLI flag is simulator-wide (see
[CLI flags → Flow export](cli-flags.md#flow-export-flags)). Setting
`"source_per_device"` in the REST body is rejected by
`DisallowUnknownFields`.

**`traps` block:**

```json
"traps": {
  "collector":       "192.168.1.10:162",        // required; host:port
  "mode":            "trap",                     // optional; "trap" | "inform"; default "trap"
  "community":       "public",                   // optional; SNMPv2c community; default "public"
  "interval":        "30s",                      // optional; per-device mean Poisson firing interval; default 30s
  "inform_timeout":  "5s",                       // optional; INFORM retry timeout; default 5s
  "inform_retries":  2                           // optional; max retransmissions per INFORM; default 2
}
```

INFORM mode requires the simulator-wide `-trap-source-per-device=true`
(the default). The check is **enforced at device-attach time**: if a
request sets `mode: "inform"` while the flag is false, the attach
fails per-device and the device's `trapConfig` is cleared so
`ListDevices` doesn't show a ghost entry. This is distinct from
request-level validation (which would fail the whole batch) — INFORM
without per-device binding is a runtime attach failure, not a 400.

**`syslog` block:**

```json
"syslog": {
  "collector": "192.168.1.10:514",              // required; host:port
  "format":    "5424",                           // optional; "5424" | "3164"; default "5424"
  "interval":  "10s"                             // optional; per-device mean Poisson firing interval; default 10s
}
```

**`gnmi_dialout` block** (see the
[gNMI dial-out reference](gnmi-dial-out.md) for full semantics):

```json
"gnmi_dialout": {
  "collector":       "10.0.0.5:6030",                              // required; host:port
  "flavor":          "gnmireverse",                                 // optional; only shipped flavor; default "gnmireverse"
  "encoding":        "json_ietf",                                   // optional; "json_ietf" | "proto"; default "json_ietf"
  "mode":            "sample",                                      // optional; "sample" | "on-change"; default "sample"
  "paths":           ["/interfaces/interface[name=*]/state"],       // optional; default: full state subtree
  "sample_interval": "10s",                                         // optional; SAMPLE cadence, 1s floor; default 10s
  "tls": {                                                          // optional; default {"enabled": true}
    "enabled": true,
    "insecure_skip_verify": false,                                  // dev only
    "ca_file": "",                                                  // PEM CA bundle; empty = system roots
    "mtls": false                                                   // present the shared cert as a client cert
  }
}
```

Durations accept Go duration strings (`"10s"`, `"5m"`, `"1m30s"`);
integer seconds are rejected.

**Combined example — flow + traps + syslog on the same batch:**

```bash
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "10.0.0.1",
    "device_count": 100,
    "netmask": "16",
    "flow": {
      "collector": "192.168.1.10:4739",
      "protocol":  "ipfix"
    },
    "traps": {
      "collector": "192.168.1.10:162",
      "mode":      "trap",
      "community": "public"
    },
    "syslog": {
      "collector": "192.168.1.10:514",
      "format":    "5424"
    }
  }'
```

**Heterogeneous fleet — two batches pointing at different collectors:**

```bash
# Batch A: 50 devices → collector A, 5424
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "10.0.0.1",
    "device_count": 50,
    "syslog": {"collector": "192.168.1.10:514", "format": "5424"}
  }'

# Batch B: 20 devices → collector A, 3164 (same host, different format)
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "10.0.1.1",
    "device_count": 20,
    "syslog": {"collector": "192.168.1.10:514", "format": "3164"}
  }'

# Batch C: 30 devices → collector B, 5424
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "10.0.2.1",
    "device_count": 30,
    "syslog": {"collector": "192.168.1.20:514", "format": "5424"}
  }'
```

`GET /api/v1/syslog/status` then reports three collector records keyed
by `(collector, format)`. See
[Syslog export status](#syslog-export-status).

**Validation failures return `400` with the underlying error** (e.g.
`unknown protocol`, `invalid collector address`, unresolvable host,
explicitly invalid syslog format — non-`5424` / non-`3164`); no device
from the batch is created (atomic batch failure). Unknown / typo'd JSON
fields at any level are also rejected via `DisallowUnknownFields` —
e.g. `"interval_ms": 10000` lands as a 400, not a silent drop.

## List devices

```bash
curl http://localhost:8080/api/v1/devices
```

Each device record includes a `resource_file` field (e.g. `"asr9k.json"`)
— the canonical identifier accepted by `POST /api/v1/devices`. The
sibling `device_type` field is a human-readable display label and is
many-to-one (e.g. `cisco_catalyst_9500`, `cisco_crs_x`, and
`cisco_nexus_9500` all surface as `"Cisco Router/Switch"`), so use
`resource_file` for any replay or programmatic recreation use case.

The field is omitted (JSON `omitempty`) for devices whose underlying
`device.resourceFile` is empty. Two paths produce that:

- Devices created via the `-auto-start-ip` CLI flag (no CLI equivalent of
  `resource_file`).
- POST requests that omit **both** `resource_file` and `round_robin: true`,
  falling back to the simulator's default resource set.

POSTs that name a `resource_file` or use `round_robin: true` always carry it.

Each record also echoes the per-device export blocks that were configured at
creation — `flow`, `traps`, `syslog`, `gnmi_dialout` — so a GET response can
be replayed against `POST /api/v1/devices` without reconstructing the export
config. Blocks are omitted (`omitempty`) for devices that don't participate
in that subsystem.

Each record also carries the device's geolocation: `location` (the world-city
string also served as SNMP `sysLocation.0`), and `latitude` / `longitude`
(decimal degrees, drawn from the same world-cities dataset). The coordinates
are emitted as a **pair** — both present or both omitted. They are `omitempty`
on a nullable type so that an *unresolved* location omits them entirely rather
than reporting a misleading `0`; a device whose true coordinates are `0.0,0.0`
still reports them as present. `location` is omitted when empty.

```json
{ "id": "...", "ip": "10.42.0.100", "resource_file": "cisco_crs_x.json",
  "location": "Amsterdam, Netherlands", "latitude": 52.3676, "longitude": 4.9041 }
```

Note: locations are assigned **randomly per device**, so a deployed fabric is
geographically scattered rather than clustered by site.

## Export to CSV

```bash
curl http://localhost:8080/api/v1/devices/export -o devices.csv
```

The CSV columns are, in order: `Device ID`, `IP Address`, `Interface`,
`SNMP Port`, `SSH Port`, `Status`, `Resource File`. `Resource File` is
appended at the end so any downstream consumer that indexes columns
positionally (`awk -F, '{print $2}'`, spreadsheet macros) is unaffected
by the new column. Devices without a known resource file emit `N/A` in
that column, matching the `Interface` convention.

Note: `N/A` is a display sentinel, not a valid resource filename. A
re-import tool that POSTs each row back must translate `N/A` to an
omitted `resource_file` field, not pass it through as a literal value
(POST would reject `"N/A"` as a non-existent file).

## Generate a route script

```bash
curl http://localhost:8080/api/v1/devices/routes -o add_routes.sh
```

The generated script adds Linux kernel routes for every device IP — handy
when running the simulator inside a VM and testing from the host.

## Delete devices

```bash
# Single device
curl -X DELETE http://localhost:8080/api/v1/devices/{device-id}

# All devices
curl -X DELETE http://localhost:8080/api/v1/devices
```

## Version

Report the running simulator's version. The value is baked into the binary
at build time via the Makefile's `APP_VERSION` variable (resolution order:
`APP_VERSION` env > `git describe --tags` > `dev`) and passed to `go build`
as `-ldflags "-X main.Version=…"`. It never changes for the lifetime of the
process, so the endpoint sets `Cache-Control: max-age=3600` — reloads of
the web UI within a browser session will reuse the cached value.

Release binaries report the clean tag (e.g., `v0.5.0`). A `make build`
from a HEAD that is ahead of the last tag reports the commit-distance
form (e.g., `v0.4.1-11-g0356c42`), so a post-release dev binary never
masquerades as the tagged release.

```bash
curl http://localhost:8080/api/v1/version
```

```json
{"version": "v0.5.0"}
```

For an untagged development build (or any build produced by `go build`
directly, bypassing the Makefile), the reported version is the literal
string `dev`. Operators troubleshooting a version mismatch can call the
same string from the CLI without starting the server:

```bash
./nl6 -version
# → v0.5.0
```

## Flow export status

```bash
curl http://localhost:8080/api/v1/flows/status
```

When flow export is enabled:

```json
{
  "success": true,
  "message": "Success",
  "data": {
    "subsystem_active": true,
    "collectors": [
      {"collector": "192.168.1.10:4739", "protocol": "ipfix",    "devices": 50, "sent_packets": 8123, "sent_bytes": 12123456, "sent_records": 243690},
      {"collector": "192.168.1.20:6343", "protocol": "sflow",    "devices": 20, "sent_packets": 3100, "sent_bytes":  5560000, "sent_records":  62000}
    ],
    "devices_exporting": 70,
    "last_template_send": "2026-04-23T10:35:00Z"
  }
}
```

Response fields:

| Field | Meaning |
|-------|---------|
| `subsystem_active` | `true` after `main()` boots the flow ticker goroutine — always-on. Not reachable as `false` via the HTTP endpoint during normal operation: the subsystem initialises with the rest of the process and only stops at process exit, alongside the HTTP server itself. |
| `collectors[]` | One record per `(collector, protocol)` tuple that ever had a device. Deleted-device counters persist in the aggregate until process exit. |
| `collectors[].devices` | Count of LIVE exporters for this tuple. `0` means no live device but the aggregate remembers prior fires. |
| `collectors[].sent_packets` / `sent_bytes` / `sent_records` | Cumulative across live + historical exporters for this tuple (monotonic within subsystem lifecycle). |
| `devices_exporting` | Total LIVE exporters across all tuples. |
| `last_template_send` | ISO-8601 timestamp of the most recent template emission (NetFlow v9 / IPFIX only). |

Clients detect "no flow export configured" via `len(collectors) == 0`.
The retired scalar fields (`enabled`, `protocol`, `collector`,
`total_flows_exported`, `total_packets_sent`, `total_bytes_sent`) were
removed in phase 3; callers that depended on them must migrate to the
array-of-collectors shape.

See [Flow export (operator guide)](../ops/flow-export.md) and
[Flow export reference](flow-export.md) for protocol-specific details.

## Trap export status

```bash
curl http://localhost:8080/api/v1/traps/status
```

Unlike the flow-status endpoint, this response is **not** wrapped in the
`{success, message, data}` envelope — the handler serialises `TrapStatus`
directly.

```json
{
  "subsystem_active": true,
  "collectors": [
    {
      "collector": "192.168.1.10:162",
      "mode":      "inform",
      "devices":   80,
      "sent":      182430,
      "informs_pending": 17,
      "informs_acked":   182380,
      "informs_failed":  33,
      "informs_dropped": 0
    },
    {
      "collector": "192.168.1.20:162",
      "mode":      "trap",
      "devices":   20,
      "sent":      6000
    }
  ],
  "devices_exporting": 100,
  "rate_limiter_tokens_available": 94,
  "catalogs_by_type": {
    "_universal":    {"entries": 5,  "source": "embedded"},
    "cisco_ios":     {"entries": 12, "source": "file:resources/cisco_ios/traps.json"},
    "juniper_mx240": {"entries": 12, "source": "file:resources/juniper_mx240/traps.json"}
  }
}
```

The four `informs_*` fields **only appear on records whose `mode == inform`**.
TRAP-mode records omit them.

`subsystem_active` is the authoritative feature-on signal — `true`
after `StartTrapSubsystem` runs. In normal operation, the HTTP
endpoint always returns `true`: the subsystem initialises from `main()`
and the only path that sets `subsystem_active=false` is `StopTrapExport`,
which is invoked at process shutdown alongside the HTTP server. A
`false` value is therefore only observable programmatically (e.g.
from a test harness calling `GetTrapStatus` without starting the
subsystem). Clients that previously branched on the retired `enabled`
scalar should use `subsystem_active`. `len(collectors) == 0` with
`subsystem_active=true` means the subsystem is running but no device
has opted in.

`catalogs_by_type` keys are device-type slugs (plus the reserved
`_universal` entry for the fallback catalog). `source` is
`"embedded"`, `"file:<path>"`, or `"override:<path>"` when
`-trap-catalog` was supplied. When disabled:

```json
{"subsystem_active": false, "collectors": [], "devices_exporting": 0}
```

`rate_limiter_tokens_available` is only present when `-trap-global-cap` is
set. The `sent` counter increments on **every wire emission including
INFORM retransmissions**, so it can exceed `informs_acked + informs_failed
+ informs_dropped + informs_pending` under retry churn.

Counters are **monotonic within a subsystem lifecycle**: deleting a
device does not zero its collector's `sent`; the aggregate survives.

See [SNMP trap / INFORM export (operator guide)](../ops/snmp-traps.md) and
[SNMP trap reference](snmp-traps.md) for the full feature details.

## Fire a trap on demand

```bash
curl -X POST http://localhost:8080/api/v1/devices/192.168.100.1/trap \
  -H "Content-Type: application/json" \
  -d '{"name":"linkDown","varbindOverrides":{"IfIndex":"3"}}'
```

Request body:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `name` | string | yes | Catalog entry name (e.g. `linkDown`, `ciscoConfigManEvent`). Must match an entry in the **device's resolved catalog** (per-type overlay if present, universal otherwise) — not the universal catalog globally. |
| `varbindOverrides` | object | no | Map of template-field → string-value overrides. Only fields from the nine-field unified vocabulary are accepted (`IfIndex`, `IfName`, `Uptime`, `Now`, `DeviceIP`, `SysName`, `Model`, `Serial`, `ChassisID`). |

Response:

| Status | Body | When |
|--------|------|------|
| `202 Accepted` | `{"requestId": <uint32>}` | Trap has been enqueued. In INFORM mode the `requestId` is the INFORM PDU's `request-id`. |
| `400 Bad Request` | `{"error": "...", "catalog": "<slug>", "availableEntries": [...]}` | Unknown catalog entry for this device. The enriched body reports which catalog the device resolved to (`cisco_ios`, `_universal`, etc.) and lists its entries alphabetically so a scripted caller can fix its call without a separate discovery endpoint. For malformed JSON or missing `name`, the legacy envelope form `{"success": false, "message": "..."}` applies. |
| `404 Not Found` | error JSON | Unknown device IP. |
| `500 Internal Server Error` | error JSON | Template resolve error, catalog resolution returned nil despite feature active (pathological manager state), or write failure. |
| `503 Service Unavailable` | error JSON | The trap subsystem has not started **or** the target device has no trap config. |

The endpoint does not block waiting for an INFORM ack — use
`/api/v1/traps/status` to observe INFORM lifecycle counters.

## Syslog export status

```bash
curl http://localhost:8080/api/v1/syslog/status
```

When syslog export is enabled:

```json
{
  "subsystem_active": true,
  "collectors": [
    {"collector": "192.168.1.10:514", "format": "5424", "devices": 50, "sent": 18240, "send_failures": 3},
    {"collector": "192.168.1.10:514", "format": "3164", "devices": 20, "sent":  6130, "send_failures": 0}
  ],
  "devices_exporting": 70,
  "rate_limiter_tokens_available": 380,
  "catalogs_by_type": {
    "_universal":    {"entries": 6,  "source": "embedded"},
    "cisco_ios":     {"entries": 14, "source": "file:resources/cisco_ios/syslog.json"},
    "juniper_mx240": {"entries": 13, "source": "file:resources/juniper_mx240/syslog.json"}
  }
}
```

Tuples are keyed by `(collector, format)`: a single collector receiving
5424 from some devices and 3164 from others surfaces as two separate
records. Per-device bind failures are non-fatal — the exporter falls
back to the shared-pool socket with a warning and the `sent` counter
still increments.

`subsystem_active` has the same semantics as on the trap status
endpoint; `len(collectors) == 0` is **not** sufficient on its own to
imply "feature off." When disabled:

```json
{"subsystem_active": false, "collectors": [], "devices_exporting": 0}
```

`format` is `"5424"` or `"3164"`. `catalogs_by_type` follows the same
shape as the trap endpoint. `rate_limiter_tokens_available` is present
only when `-syslog-global-cap` is set. When disabled the response is
`{"enabled": false}`.

See [UDP syslog export (operator guide)](../ops/syslog-export.md) and
[UDP syslog reference](syslog-export.md) for the full feature details.

## Fire a syslog message on demand

```bash
curl -X POST http://localhost:8080/api/v1/devices/192.168.100.1/syslog \
  -H "Content-Type: application/json" \
  -d '{"name":"interface-down","templateOverrides":{"IfIndex":"3"}}'
```

Request body:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `name` | string | yes | Catalog entry name. Same device's-catalog resolution rule as the trap endpoint. |
| `templateOverrides` | object | no | Nine-field unified vocabulary (same set as `varbindOverrides` on the trap side). |

Response:

| Status | Body | When |
|--------|------|------|
| `202 Accepted` | `{}` | Message emitted. On-demand fires **do not** consume global rate-cap tokens. |
| `400 Bad Request` | `{"error": "...", "catalog": "<slug>", "availableEntries": [...]}` | Unknown catalog entry for this device. Same enriched-error shape as the trap endpoint. |
| `404 Not Found` | error JSON | Unknown device IP. |
| `500 Internal Server Error` | error JSON | Pathological catalog-resolution-nil state. |
| `503 Service Unavailable` | error JSON | The syslog subsystem has not started **or** the target device has no syslog config. |

## Device interaction

The control-plane only manages devices — once a device is up, you interact
with it via its own IP on port 22 (SSH), 161 (SNMP), and, for storage
devices, 8443 (HTTPS).

```bash
# SSH (VT100 terminal emulation)
ssh simadmin@192.168.100.1     # password: simadmin

# SNMP v2c
snmpget  -v2c -c public 192.168.100.1 1.3.6.1.2.1.1.1.0
snmpwalk -v2c -c public 192.168.100.1 1.3.6.1.2.1.2.2.1

# SNMP v3 (when enabled)
snmpget -v3 -l authPriv -u admin -a MD5 -A authpass123 -x AES -X privpass123 \
  -e 0x80001234 192.168.100.1 1.3.6.1.2.1.1.1.0
```

See [SNMP reference](snmp.md) for the OID coverage, including the dynamic HC
interface counters on `ifXTable`.

### Storage HTTPS endpoints

Storage devices expose vendor-shaped REST APIs on port 8443 with shared TLS
certificates generated at simulator startup.

```bash
# Pure Storage FlashArray
curl -k https://192.168.100.1:8443/api/2.14/volumes
curl -k https://192.168.100.1:8443/api/2.14/arrays
curl -k https://192.168.100.1:8443/api/2.14/arrays/space

# NetApp ONTAP
curl -k https://192.168.100.1:8443/api/cluster
curl -k https://192.168.100.1:8443/api/storage/volumes
curl -k https://192.168.100.1:8443/api/storage/aggregates

# AWS S3
curl http://192.168.100.1:8443/            # list buckets
curl http://192.168.100.1:8443/my-bucket   # bucket contents
```
