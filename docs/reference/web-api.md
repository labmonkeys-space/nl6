---
sidebar_label: "Web API"
description: "The REST control plane on port 8080, with device CRUD, CSV and route-script export, subsystem status endpoints and runtime switches."
---

# Web API

The simulator exposes a REST control-plane on port 8080 (override with [`-port`](cli-flags.md#core-flags)) for device CRUD, CSV / route-script export, system stats, and flow-export status.
The same port also serves the management web UI at `/`.

## Endpoint catalog

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/devices` | POST | Create devices (bulk, round-robin, category-based). One batch at a time: a concurrent create is refused `409`. |
| `/api/v1/devices` | GET | List all devices. |
| `/api/v1/devices/{id}` | DELETE | Delete a specific device. |
| `/api/v1/devices` | DELETE | Delete all devices. |
| `/api/v1/devices/export` | GET | Export device list to CSV. |
| `/api/v1/devices/routes` | GET | Generate a routing script (Debian/Ubuntu). |
| `/api/v1/resources` | GET | List available device resource types. |
| `/api/v1/resources/reload` | POST | Evict cached device profiles so the next creation re-reads them from disk. Existing devices keep their snapshot. `409` during a creation batch. |
| `/api/v1/status` | GET | Manager status. |
| `/api/v1/system-stats` | GET | System stats (file descriptors, memory). |
| `/api/v1/version` | GET | Running simulator version string. Immutable per process; response carries `Cache-Control: private, max-age=3600`. |
| `/api/v1/flows/status` | GET | Flow export status and cumulative counters. See [Flow export → Status API](flow-export.md#status-api). |
| `/api/v1/traps/status` | GET | SNMP trap export status, INFORM counters, and per-type catalog map. See [SNMP traps → Trap export status](snmp-traps.md#trap-export-status). |
| `/api/v1/devices/{ip}/trap` | POST | Fire a named catalog trap on a specific device. See [SNMP traps → Fire a trap on demand](snmp-traps.md#fire-a-trap-on-demand). |
| `/api/v1/syslog/status` | GET | Syslog export status, counters, and per-type catalog map. See [Syslog → Syslog export status](syslog-export.md#syslog-export-status). |
| `/api/v1/devices/{ip}/syslog` | POST | Fire a named catalog syslog message on a specific device. See [Syslog → Fire a syslog message on demand](syslog-export.md#fire-a-syslog-message-on-demand). |
| `/api/v1/devices/{ip}/optical/{component}/degrade` | POST | Degrade one optical channel on demand (optional auto-expiring window). |
| `/api/v1/devices/{ip}/optical` | GET | Current degradation state of every optical channel on a device. |
| `/api/v1/devices/{ip}/interfaces/{ifIndex}/oper-status` | POST | Move one interface's link state, with optional `duration` auto-revert. See [Interface state](./interface-state.md). |
| `/api/v1/devices/{ip}/interfaces/{ifIndex}/admin-status` | POST | Set one interface's admin status, with optional `duration` auto-revert. See [Interface state](./interface-state.md). |
| `/api/v1/topology` | POST | Add inter-device LLDP links. See [LLDP topology](./lldp-topology.md). |
| `/api/v1/topology` | GET | List configured links. |
| `/api/v1/topology` | DELETE | Remove links. |
| `/api/v1/topology/status` | GET | `{subsystem_active, configured_links, active_links}`. |
| `/api/v1/topology/graph` | GET | Node and edge graph for the web console's topology view. |
| `/api/v1/scenarios` | POST | Create a load-test scenario. See [Load-test scenario REST API](./loadtest-api.md). |
| `/api/v1/scenarios` | GET | List scenarios. |
| `/api/v1/scenarios/{id}` | GET | Scenario status. |
| `/api/v1/scenarios/{id}` | DELETE | Delete a scenario. |
| `/api/v1/scenarios/{id}/arm` | POST | Arm a scenario. |
| `/api/v1/scenarios/{id}/start` | POST | Start an armed scenario. |
| `/api/v1/scenarios/{id}/stop` | POST | Stop a running scenario. |
| `/api/v1/scenarios/{id}/report` | GET | Scenario report. |
| `/api/v1/scenarios/{id}/metrics` | GET | Scenario metrics. |
| `/api/v1/gnmi/status` | GET | gNMI (dial-in) subsystem status: listeners, subscriptions, update/state-event counters. |
| `/api/v1/netconf/status` | GET | NETCONF subsystem status: listeners, sessions, subscriptions, notification counters. See [NETCONF reference](netconf.md#status-endpoint). |
| `/api/v1/netconf/callhome/status` | GET | NETCONF call-home counters per client: devices, sessions up, connect attempts and failures, handshake failures, sessions ended, unsupported devices. See [NETCONF reference](netconf.md#call-home-status). |
| `/api/v1/netconf/tls` | GET | NETCONF over TLS client trust: the client CA PEM, the identity table and the default username. `404` when the NETCONF subsystem is off. See [NETCONF reference](netconf.md#rest). |
| `/api/v1/netconf/tls` | PUT | Replace the whole NETCONF over TLS client trust. An omitted field clears it. `404` when the subsystem is off, `400` for a bad body. |
| `/api/v1/tls/ca` | GET | PEM of the CA that signed the shared server certificate, as `application/x-pem-file`. `404` when no shared TLS certificate exists. |
| `/api/v1/gnmi/dialout/status` | GET | gNMI dial-out status: per-(collector, flavor) streams, updates sent/dropped, reconnects, send failures. |
| `/api/v1/dns/status` | GET | DNS service-discovery status: zones + serials, publish counters, NOTIFY tallies. |
| `/api/v1/prometheus/sd` | GET | Prometheus HTTP service discovery: one target group per running device, for snmp_exporter. See [Prometheus service discovery](prometheus-sd.md). |
| `/api/v1/fidelity` | GET | Fidelity mode: the value **in force**, the startup flag it began from, and any pending auto-revert. |
| `/api/v1/fidelity` | POST | Toggle fleet silence at runtime, with optional `duration` auto-revert (24h cap). |
| `/api/v1/profiling` | GET | Continuous-profiling gate: the value **in force**, the startup flag, whether the SDK is pushing, and any pending auto-revert. |
| `/api/v1/profiling` | POST | Open or close the gate at runtime, optionally with a push `server_address` and a `duration` auto-revert (24h cap). |
| `/debug/pprof/` | GET | The Go `net/http/pprof` surface plus `godeltaprof`'s `delta_heap` / `delta_block` / `delta_mutex`, for a Grafana Alloy scrape. `503` while the gate is closed. |
| `/health` | GET | Health check endpoint. |
| `/` and `/ui` | GET | The management web console. |
| `/web/*` | GET | Static assets (CSS, JS) for the console. |

## Fidelity mode

`GET /api/v1/fidelity` reports fleet silence; `POST` changes it without a restart.
What a silent fleet still does is in [Fidelity mode](../ops/loadtest-scenarios.md#fidelity-mode).

```json
// GET response .data
{
  "silent": true,           // the value IN FORCE
  "startup_flag": false,    // what -fidelity was set to at launch
  "revert_pending": true,
  "revert_at": "2026-08-24T14:32:10Z",
  "revert_to": false        // what the pending revert restores
}
```

```bash
curl -X POST .../api/v1/fidelity -H 'Content-Type: application/json' \
  -d '{"silent": true}'                        # standing change

curl -X POST .../api/v1/fidelity -H 'Content-Type: application/json' \
  -d '{"silent": true, "duration": "20m"}'     # auto-reverts, 24h cap
```

`silent` is **required**: omitting it would read as `false` and un-mute the fleet, so a body without it is rejected with `400`.

**Auto-revert restores the value from before the current chain of timed toggles**, not simply the previous value.
Shortening or extending a window keeps the same destination; a toggle in the *opposite* direction starts a new chain and reverts to whatever was in force when it was issued.
`revert_to` reports the target, because it is not inferable from `silent`.

## Continuous profiling

`GET /api/v1/profiling` reports the profiling gate; `POST` changes it without a restart.
The gate's behaviour, the `server_address` shapes, credentials and the pprof surface are in [Profile the simulator](../ops/profiling.md).

```json
// GET response .data
{
  "enabled": true,                              // the gate IN FORCE
  "startup_flag": "http://pyroscope:4040",      // what -profiling-pyroscope was at launch ("" when unset)
  "server_address": "http://pyroscope:4040",    // push destination in force; "" = pull-only or off
  "pushing": true,                              // the SDK is RUNNING (false with enabled:true = pull-only, or a failed start); says nothing about upload success
  "sdk_errors": 3,                              // every error the SDK reported for the CURRENT push (failed upload, refused CPU collector, full queue); omitted while zero
  "last_error": "...",                          // the Start failure, or the latest SDK error of the current push
  "pprof_path": "/debug/pprof/",
  "revert_pending": true,
  "revert_at": "2026-09-04T12:00:00Z",
  "revert_to": false,                           // the gate value the pending revert restores
  "revert_to_address": "http://pyroscope:4040"  // the push address it restores with it; omitted when that is pull-only or off
}
```

```bash
curl -X POST .../api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled": true, "server_address": "http://pyroscope:4040"}'   # push
curl -X POST .../api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled": true, "server_address": ""}'                        # pull-only (Alloy scrape); an OMITTED server_address keeps a running push, else uses the flag's address
curl -X POST .../api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled": true, "server_address": "http://pyroscope:4040", "duration": "30m"}'   # auto-off after 30m, 24h cap
curl -X POST .../api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled": false}'                                             # off; the last profiles are flushed (bounded, 20 s) before 200
```

`enabled` is **required**.

| Status | When |
|--------|------|
| `200` | The gate is in the requested state. `{"enabled":false}` answers after the SDK flush, bounded at 20 s. |
| `400` | `enabled` missing, an unknown field, a non-positive or over-cap `duration`, a `server_address` that is not an `http://` or `https://` URL or embeds credentials, a query or a fragment, or a `server_address` on an `enabled:false` request. |
| `500` | The SDK refused to start the push. The body carries the state (`enabled:true`, `pushing:false`, `last_error`); the pull surface still serves. |

Auto-revert restores the whole (gate, address) pair; `revert_to_address` reports the address.

## Create devices

Bulk creation supports round-robin across all device types, category-based filtering, per-request SNMP port selection, and an optional SNMPv3 block.

`category` filters a `round_robin` batch.
It accepts exactly five strings: `Network Devices`, `GPU Servers`, `Storage`, `Servers`, `Optical Transport`.
Any other value matches no device type and is rejected with 400.

**Addressing.** Device IPs are *management* addresses on a flat `/16` plane.
`netmask` is optional and **defaults to `/16`**.
Only the `/16` network and broadcast are reserved, so `.x.0` and `.x.255` are assigned as ordinary hosts.
An explicit `"netmask": "24"` (or `"8"`) is still honored if you want classic per-`/24` semantics (which skip `.0`/`.255`).
`start_ip` must be an IPv4 address.
It is refused with 400 and one of three messages: `start_ip is required` (missing or empty), `invalid start IP address: "<value>"` (does not parse) or `start IP address must be IPv4: "<value>"` (any IPv6 literal, the IPv4-mapped `::ffff:10.42.0.3` included).
The value is echoed quoted, so a trailing space or tab that caused the refusal is visible.
The same check runs on `-auto-start-ip` at startup, where a refusal is fatal.

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
      "auth_protocol": 1,
      "priv_protocol": 2
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

# Devices that accept a SetRequest
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 3,
    "netmask": "16",
    "write_community": "writeme",
    "snmpv3": {
      "enabled": true,
      "engine_id": "0x80001234",
      "username": "admin",
      "password": "authpass123",
      "auth_protocol": 1,
      "set_min_security_level": "auth"
    }
  }'
```

### Request fields

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `start_ip` | string | required | First IPv4 address of the batch. See **Addressing** above. |
| `device_count` | int | required | Number of devices to create, `1` to `100000`. A value outside that range is rejected with 400. |
| `netmask` | string | `16` | Prefix length: `8`, `16` or `24`. Any other value is rejected with 400. |
| `resource_file` | string | empty (`asr9k.json`) | Device type to create, as a resource file name. See [`resource_file` failures](#resource_file-failures). |
| `round_robin` | bool | `false` | Cycle through every device type. |
| `category` | string | empty | Filter a `round_robin` batch to one category. |
| `snmp_port` | int | `161` | UDP port of each device's SNMP listener, `1` to `65535`. |
| `snmpv3` | object | absent | SNMPv3 settings for the batch. |
| `pre_allocate` | bool | `false` | Accepted and ignored. A batch of 10 or more devices always pre-allocates its TUN interfaces. |
| `max_workers` | int | `0` (adaptive) | Worker count for TUN pre-allocation, `0` to `1000`. A value outside that range is rejected with 400. |
| `if_error_scenario` | string | `clean` | Per-device error and discard scenario. See below. |
| `if_flap_scenario` | string | `clean` | Per-device link-flap scenario: `clean`, `rare`, `typical` or `aggressive`. Not inherited from `-if-flap-scenario`. An unknown value is rejected with 400. |
| `optical_scenario` | string | `clean` | Optical health band. See [Optical health band](#optical-health-band). |
| `write_community` | string | empty | SNMPv1/v2c write community. See [Write admission](#write-admission). |
| `flow`, `traps`, `syslog`, `gnmi_dialout` | object | absent | Per-device export blocks. See [Per-device export blocks](#per-device-export-blocks). |
| `netconf_callhome` | object | absent | NETCONF call home for the created `juniper_mx10004` devices: `client` (`host:port`, required) and `device_id` (optional, default sysName). `400` when `-netconf-enable` is off, when `client` is IPv6, or when no requested profile has call home. See [NETCONF reference](netconf.md#call-home). |

An unknown field anywhere in the body is rejected with 400.

### Response

A successful batch answers `200` with the counts in `data`:

```json
{
  "success": true,
  "message": "Created 10 devices starting from 192.168.100.1",
  "data": {"created": 10, "requested": 10, "failed": 0}
}
```

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `created` | int | n/a | Devices that started. |
| `requested` | int | n/a | `device_count` from the request. |
| `failed` | int | n/a | `requested - created`. Devices can fail to start under resource pressure at scale. Reconcile against `requested`. |
| `warnings` | array | omitted | Reserved for settings that were accepted but are not honoured. Currently always omitted. |

When `failed` is not zero, `message` reads `Created 8 of 10 devices (2 failed to start) starting from 192.168.100.1`.

### Write admission

Writes are **opt-in**.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `write_community` | string (top level) | empty | SNMPv1/v2c community required to write. A mismatch is discarded with no response, which `snmpset` reports as a timeout. Empty admits no v1/v2c `SET`. |
| `snmpv3.set_min_security_level` | `none` \| `auth` \| `priv` | `auth` | Lowest security level a v3 `SetRequest` may carry. Below it, the device answers a `usmStatsUnsupportedSecLevels` Report. An unrecognised value is rejected **400**. |

Neither field is inherited from the CLI seed, and `write_community` is never echoed by any response.
The admission rules are in [SNMP → Write admission for a `SET`](snmp.md#write-admission-for-a-set).

A `snmpv3` block that enables a privacy protocol (`des` / `aes128`) without a password is rejected with **400**.
Either `password` or `priv_password` satisfies it; `priv_password` wins when both are set **on the DES path only**.
The AES128 path ignores `priv_password` and always derives from `password`, so a device configured with two distinct passwords and `"priv_protocol": 2` encrypts under a key no RFC 3414 manager derives.
That configuration is accepted without a warning.

The `if_error_scenario` field controls the per-device ppm bands used to derive `ifInErrors`, `ifOutErrors`, `ifInDiscards`, and `ifOutDiscards` from live packet counters.
Accepted values: `clean` (default, no error growth), `typical`, `degraded`, `failing`.
Unknown values reject the batch atomically with 400.
REST-created devices default to `clean` independently of the `-if-error-scenario` CLI flag.
You must opt in explicitly.
See [SNMP reference](snmp.md#per-device-error-scenario) for the full scenario bands and counter model.

A specific resource file can be requested directly (useful for storage devices):

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

### On-demand optical degradation

`POST /api/v1/devices/{ip}/optical/{component}/degrade` drives one named optical channel across the SD-FEC threshold on demand.
What each knob moves, and the four diagnostic quadrants, are in [Optical telemetry → On-demand degradation](optical-telemetry.md#on-demand-degradation).

```bash
# Drive OCH-1-1 past the FEC threshold for 30 seconds, then back automatically.
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade \
  -H "Content-Type: application/json" \
  -d '{"noise_rise_db": 8, "duration": "30s"}'
```

| Field | Type | Meaning |
|---|---|---|
| `input_power_drop_db` | number | Attenuates received power. Signal and accumulated ASE fall together, so power drops while **OSNR is unchanged** and no FEC errors accrue. This models a fibre or connector fault. |
| `noise_rise_db` | number | Raises accumulated ASE only. Power holds while OSNR falls. This models a sick amplifier. |
| `duration` | Go duration string | Optional. Omitted means open-ended; capped at 24 h. |

Both are optional; **a request with neither (or an empty body) clears** active degradation on that channel.
A second POST on the same channel supersedes the first.
**Crossing the FEC threshold takes `noise_rise_db`**, because attenuation alone leaves OSNR unchanged.
`input_power_drop_db` models loss downstream of the amplifier chain; for loss upstream of an amplifier, set both knobs.
The channel returns to its band when the window ends, and `fec-uncorrectable-blocks` never decreases across a degrade and revert cycle.

Query what is in force with `GET /api/v1/devices/{ip}/optical`:

```json
{"device":"10.42.0.1","channels":[
  {"component":"OCH-1-1","input_power_drop_db":0,"noise_rise_db":0,"degraded":false},
  {"component":"OCH-1-2","input_power_drop_db":4,"noise_rise_db":1,"degraded":true}
]}
```

Responses: `200` with the episode echoed back; `404` for an unknown device, an unknown component (the body lists `availableComponents`), or a device type with no optical channels; `503` for an optical device still initialising its engine (transient, so retry); `400` for a malformed body, an unknown field, a non-positive or over-cap `duration`, or an out-of-range offset.

### Optical health band

`optical_scenario` sets the steady-state health of every coherent optical channel on an optical transport device:

```bash
# Two Waveserver 5 devices with a service-affecting optical span
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 2,
    "netmask": "16",
    "resource_file": "ciena_waveserver5.json",
    "optical_scenario": "failing"
  }'
```

Accepted values: `clean` (default), `typical`, `degraded`, `failing`.
Unknown values reject the batch atomically with 400.
As with `if_error_scenario`, REST-created devices default to `clean` independently of the `-optical-scenario` CLI flag.
You must opt in explicitly.

The field applies **only to device types that have optical channels** (today `ciena_waveserver5`).
Two consequences:

- A non-`clean` band on any other type is rejected with **400**, rather than accepted and silently ignored. A mixed `round_robin` batch is still accepted. The optical devices take the band and the rest ignore it.
- `GET /api/v1/devices` omits `optical_scenario` entirely for non-optical types, so the API never advertises a knob that does nothing there.

Only `failing` crosses the SD-FEC threshold, so `fec-uncorrectable-blocks > 0` is a reliable service-affecting signal; `degraded` shows an elevated `pre-fec-ber` that FEC still corrects.
See [CLI flags](cli-flags.md#optical-health-band) for the per-tier OSNR / Q / BER table.

### A create call blocks until the batch ends

`POST /api/v1/devices` answers when the whole batch has been created, not when it has been accepted.
At fleet scale that takes minutes: thousands of devices can run well past 30 seconds.
The server-wide 30-second write timeout does not apply to this response, so a client that waits gets its `200` (or its error) however long the batch runs.
Set a long or no read timeout on the client.
Once the batch ends, the response must be read within 10 seconds.

If the connection drops anyway, for example because a proxy or the client gave up, the batch still runs to completion.
Treat the request as submitted: poll `GET /api/v1/status` until `create_batch_in_progress` is `false`, then compare `total_devices` with the count you expected.
Do not re-send the request while the batch runs; it is refused with `409` (next section).

### One creation batch at a time (`409`)

**Only one device-creation batch runs at a time.** A `POST /api/v1/devices` that arrives while another batch is in flight is answered **`409 Conflict`** and creates nothing.
The refusal is fail-fast, not a queue.

The response carries `Retry-After: 5`, and a body naming the batch in the way:

```json
{
  "success": false,
  "message": "device creation already in progress: batch #7 (2000 devices, started 1.482s ago) is running; retry once it finishes. Device IP allocation is a shared cursor, so a second concurrent batch would hand out overlapping addresses and silently create fewer devices than requested"
}
```

**How to wait.** Poll `GET /api/v1/status` until both `create_batch_in_progress` and `resource_reload_in_progress` are `false`, then retry.
`create_batch_requested` reports the running batch's requested device count.
A [profile reload](#reload-device-profiles) holds the same gate briefly; a create refused during one is told so in its `409` body.
Do not poll `is_creating_devices`: it can read `false` while a create would still be refused.
`Retry-After` is always 5 seconds.

**The auto-start batch counts as a batch.** A REST create issued while the `-auto-start-ip` batch runs gets the `409` until that batch completes, even though `GET /api/v1/status` already answers `200`.

- `scripts/fleet.sh import` treats a `409` as a wait: it retries the entry (`RETRY_409_LIMIT` attempts, default 60, `RETRY_409_DELAY` seconds apart, default 5). A client of your own should do the same.
- The web console's Clos-fabric wizard does **not** retry. A `409` from another batch aborts it and leaves a **half-built fabric**: the devices created so far stay, and the topology links are not loaded. Re-running the wizard on the same subnet is safe, because existing addresses are absorbed as successes.

**What the gate does not cover.** `DELETE /api/v1/devices`, shutdown, and the detached pre-allocation workers of a batch that timed out in pre-allocation (5-minute timeout) do not take the gate.
A create that overlaps a delete-all, or follows such a timed-out batch, is not protected.

**Check order.** Malformed request *shape* is refused with 400 before the gate, with no server log line: `device_count`, `max_workers`, `netmask`, `snmp_port`, the SNMPv3 block and the export blocks.
Everything else runs inside the gate, in this order: `start_ip`, then the batch publishes its progress state (`is_creating_devices`, `create_batch_in_progress`), then the fleet freeze check, `resource_file` and the privilege check.
Those are logged as `create devices: rejected with <status>: ...`.
So with a batch in flight, a request with a bad `start_ip` or `resource_file` gets 409, not 400.

A create against a fleet frozen by a running load-test scenario is answered `500` with the freeze message.
On a frozen fleet, `DELETE /api/v1/devices/{id}` answers `404` and `DELETE /api/v1/devices` answers `500`, both with the freeze message.
On this endpoint `409` means a concurrent creation batch or a concurrent profile reload, and nothing else; the body says which.

### `resource_file` failures

`resource_file` names the device type to load, and a request naming one the simulator cannot use is answered **`400`**, not `500`.

Response:

| Status | Body | When |
|--------|------|------|
| `400 Bad Request` | `{"success": false, "message": "resource <base-name>: <what is wrong>"}` | The file name is not a device-type slug; no such device type is shipped (including a `round_robin` batch in which none of the requested types is, or a `category` matching none); or the file's content is invalid: JSON that does not parse, a document that is literally `null`, anything trailing the document, no entries at all, a device-type directory with no JSON part or whose parts hold no entries between them, an SNMP value the load-time guard rejects, or an optical inventory disagreeing with the type's channel count. |
| `500 Internal Server Error` | `{"success": false, "message": "<raw error>"}` | The loader could not classify the failure: a file it cannot open, a directory it cannot list. The raw message may contain a full path. |

The `message` field carries the diagnosis.
It names the file's **base name**, and for a fault attributable to one entry the OID and the value as well:

```json
{
  "success": false,
  "message": "resource restbad_snmp.json: OID 1.3.6.1.2.1.1.1.0 has value \"noSuchObject\", which collides with an SNMP exception sentinel and would be encoded as an RFC 3416 exception instead of a string. There is no escaping form: change the value. To make the OID answer noSuchObject on purpose, omit the entry entirely, since an absent OID already answers with the exception"
}
```

A parse failure, a `null` document, an empty file or directory, an optical mismatch and a rejected file name have no single entry to name, so they carry neither OID nor value.

The `400` body never contains a directory path, neither in the file name nor inside an interpolated cause such as a failed read.
Control characters and bidi formatting runes are stripped from it, and it is length-capped.
The full path goes to the **server log** instead.
That guarantee covers the `400` class only; the `500` class returns the raw error.

`resource_file` is validated **before** TUN pre-allocation and before the privilege check, so a request naming a bad device type gets this `400` without allocating anything, whether or not the simulator runs as root.
A request naming a good one proceeds, and without root gets `500` `root privileges required to create TUN interfaces`.

### Per-device export blocks

`POST /api/v1/devices` accepts four optional top-level blocks (`flow`, `traps`, `syslog`, `gnmi_dialout`) that attach export configuration to every device created by the request.
Any block can be omitted; omitted blocks mean "this batch does not participate in that export subsystem."

The export subsystems run whether or not any CLI seed was supplied, so REST-created devices can opt in to any combination.

**`flow` block:**

```json
"flow": {
  "collector":        "192.168.1.10:2055",      // required; host:port
  "protocol":         "netflow9",               // optional; "netflow9" | "ipfix" | "netflow5" | "sflow"; aliases "nf9", "ipfix10", "nf5", "sflow5"; default "netflow9"
  "active_timeout":   "30s",                     // optional; default 30s
  "inactive_timeout": "15s",                     // optional; default 15s
  "sub_agent_id":     0,                         // optional; sFlow datagram sub_agent_id, default 0; ignored by non-sFlow protocols
  "options_interface_table": "",                 // optional; "" (off, default) | "if-scoped" | "system-scoped"; netflow9/ipfix only, other protocols rejected with 400
  "nbar2":            false                      // optional; Cisco AVC (NBAR2) records, ipfix only (other protocols 400); cisco_ios / cisco_catalyst_9500 only (an entirely incapable type set is 400; in a mixed batch incapable devices emit plain IPFIX with nbar2 cleared). Echoed only on devices that emit AVC. See flow-export.md
}
```

No per-device override exists for `source_per_device`.
The `-flow-source-per-device` CLI flag is simulator-wide (see [CLI flags → Flow export](cli-flags.md#flow-export-flags)).
Setting `"source_per_device"` in the REST body is rejected with 400 as an unknown field.

**`traps` block:**

```json
"traps": {
  "collector":       "192.168.1.10:162",        // required; host:port
  "mode":            "trap",                     // optional; "trap" | "inform"; default "trap"
  "community":       "public",                   // optional; SNMPv2c community; default "public"
  "inform_timeout":  "5s",                       // optional; INFORM retry timeout; default 5s
  "inform_retries":  2                           // optional; max retransmissions per INFORM; 0 or omitted = default 2; negative is 400
}
```

A `traps` block with `mode: "inform"` is rejected with 400 when `-trap-source-per-device` is `false`; see [TRAP vs INFORM](../ops/snmp-traps.md#trap-vs-inform).
The wire version and the SNMPv3 settings are fleet-wide (`-trap-snmp-version`, `-trap-snmpv3-*`), with no per-device field.

**`syslog` block:**

```json
"syslog": {
  "collector": "192.168.1.10:514",              // required; host:port (default port 514, 6514 under tls)
  "format":    "5424",                           // optional; "5424" | "3164"; default "5424"
  "transport": "udp",                            // optional; "udp" | "tcp" | "tls"; default "udp"
  "framing":   "octet-counting",                 // optional; "octet-counting" | "non-transparent"; default "octet-counting" under tcp and tls; tls accepts only "octet-counting" (400 otherwise); rejected under udp
  "tls": {                                       // optional; read under transport tls
    "ca_pem": "",                                // PEM CA bundle INLINE verifying the collector; empty = system roots
    "insecure_skip_verify": false                // dev only
  }
}
```

`tls.mtls` is rejected with 400 under `tls`: client-certificate authentication is not implemented.

### No per-device cadence

The REST blocks carry no cadence field.
`syslog.interval`, `traps.interval` and `flow.tick_interval` are rejected with 400, and the error names the flag that sets the fleet-wide value:

```
syslog: interval is not supported per device — one central scheduler fires every device at the simulator-wide mean; use -syslog-interval
traps: interval is not supported per device — one central scheduler fires every device at the simulator-wide mean; use -trap-interval
flow: tick_interval is not supported per device — one simulator-wide ticker drives every device; use -flow-tick-interval
```

The syslog and trap schedulers fire every device at their simulator-wide mean (`-syslog-interval`, `-trap-interval`).
Flow drives every device from one simulator-wide ticker (`-flow-tick-interval`).

`GET /api/v1/devices` still reports the cadence in force in a sibling object, `effective_intervals`, present only on devices that export something.
It carries one key per block the device has: `syslog_interval`, `traps_interval` and `flow_tick_interval`.

```json
"syslog": {
  "collector": "192.0.2.144:1514",
  "format":    "5424"
},
"effective_intervals": {
  "syslog_interval": "10s"          // what the scheduler is configured with
}
```

`effective_intervals.*` is a configured mean, not an observed emission rate.
`-syslog-global-cap` / `-trap-global-cap` throttle by blocking, `-fidelity` suppresses background emission entirely, and a running scenario drives its participants at its own rate.
None of those change the reported value.

### A GET block is a valid POST block

Config blocks round-trip: take a `flow` / `traps` / `syslog` object from `GET /api/v1/devices`, change what you like, and POST it back.
Nothing needs stripping.
Strict decoding still catches a typo:

```console
# 400 Invalid JSON: unknown field "intervl"
POST /api/v1/devices  {"syslog": {"collector": "x:514", "intervl": "24h"}}
```

`scripts/fleet.sh export | fleet.sh import` relies on this round trip.

**`gnmi_dialout` block** (see the [gNMI dial-out reference](gnmi-dial-out.md) for full semantics):

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
    "ca_pem": "",                                                   // PEM CA bundle INLINE; empty = system roots.
                                                                    // Not a path; use -gnmi-dialout-tls-ca for a file.
                                                                    // "ca_file" is rejected.
    "mtls": false                                                   // present the shared cert as a client cert
  }
}
```

Durations accept Go duration strings (`"10s"`, `"5m"`, `"1m30s"`); integer seconds are rejected.

**Combined example with flow + traps + syslog on the same batch:**

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

To point batches at different collectors or protocols, send one request per batch, as in [Run a heterogeneous fleet](../ops/flow-export.md#run-a-heterogeneous-fleet-multiple-collectors--protocols).

**Validation failures return `400` with the underlying error** (e.g. `unknown protocol`, `invalid collector address`, unresolvable host, explicitly invalid syslog format, i.e. non-`5424` / non-`3164`); no device from the batch is created (atomic batch failure).
Unknown JSON fields at any level are also rejected with 400.
For example, `"interval_ms": 10000` lands as a 400, not a silent drop.

## List devices

```bash
curl http://localhost:8080/api/v1/devices
```

Each device record includes a `resource_file` field (e.g. `"asr9k.json"`), the canonical identifier accepted by `POST /api/v1/devices`.
The sibling `device_type` field is a human-readable display label and is many-to-one (e.g. `cisco_catalyst_9500`, `cisco_crs_x`, and `cisco_nexus_9500` all surface as `"Cisco Router/Switch"`), so use `resource_file` for any replay or programmatic recreation use case.

The field is omitted (JSON `omitempty`) for devices whose underlying `device.resourceFile` is empty.
Two paths produce that:

- Devices created via the `-auto-start-ip` CLI flag (no CLI equivalent of `resource_file`).
- POST requests that omit **both** `resource_file` and `round_robin: true`, falling back to the simulator's default resource set.

POSTs that name a `resource_file` or use `round_robin: true` always carry it.

Each record also echoes the per-device export blocks that were configured at creation (`flow`, `traps`, `syslog`, `gnmi_dialout`), so a GET response can be replayed against `POST /api/v1/devices` without reconstructing the export config.
Blocks are omitted (`omitempty`) for devices that don't participate in that subsystem.

Each record also carries the device's geolocation: `location` (the world-city string also served as SNMP `sysLocation.0`), and `latitude` / `longitude` (decimal degrees, drawn from the same world-cities dataset).
The coordinates are emitted as a **pair**: both present or both omitted.
An *unresolved* location omits them; a device whose true coordinates are `0.0,0.0` still reports them.
`location` is omitted when empty.

```json
{ "id": "...", "ip": "10.42.0.100", "resource_file": "cisco_crs_x.json",
  "location": "Amsterdam, Netherlands", "latitude": 52.3676, "longitude": 4.9041 }
```

Note: locations are assigned **randomly per device**, so a deployed fabric is geographically scattered rather than clustered by site.

## Reload device profiles

`POST /api/v1/resources/reload` makes an edited profile under `resources/` take effect without a restart.
It **evicts** cached profiles; it never rewrites one.

```bash
curl -X POST http://localhost:8080/api/v1/resources/reload                # every cached profile
curl -X POST http://localhost:8080/api/v1/resources/reload \
  -H 'Content-Type: application/json' -d '{"resource_file":"cisco_ios.json"}'   # one profile
```

```json
// 200 response .data
{
  "evicted": ["cisco_ios.json"],
  "devices_on_old_snapshot": {"cisco_ios.json": 40},
  "present_on_disk": {"cisco_ios.json": true},
  "note": "existing devices keep the snapshot they were built from until they are recreated; the next device creation of an evicted type reads the profile from disk. Trap and syslog catalogs (traps.json, syslog.json) are NOT reloaded by this endpoint and still need a restart"
}
```

**What a reload does and does not change.** A profile is read from disk the first time a device of that type is created and cached.
A reload drops the cache entry and nothing else: a device created **before** the reload serves exactly what it served before, and a device created **after** it serves the file as it is now.
`devices_on_old_snapshot` counts, per evicted key, how many running devices still serve a pre-reload set (any earlier generation, not only the one evicted now).
A concurrent delete can make it lower by the time the response is read.
To move devices onto the edited profile, delete and recreate them.
`present_on_disk` says whether the profile still exists on disk at the time of the reload, so a renamed or removed directory is reported now rather than at the next create.

**The default profile is covered.** The profile a device gets with no `resource_file` (`asr9k`, the one the `-auto-start-ip` fleet serves) is cached under the key `asr9k.json`.
Reloading `asr9k.json` covers devices created with and without a `resource_file`, and both are counted under that key.
The exception is the compiled-in default used when no `asr9k` directory or file exists at all; it is never reloaded.

**Not reloaded: trap and syslog catalogs.** `resources/<type>/traps.json` and `syslog.json` are loaded when the trap and syslog subsystems start and are never re-read.
Editing one and calling this endpoint gets a `200` that evicts the profile and leaves the catalog as it was; the `note` says so.
A catalog edit still needs a restart.

The workflow for verifying a profile fix is: edit the file, `POST /resources/reload`, then `POST /devices` for the type.
A profile that fails to load after the edit is answered by that create with the usual `400` (see [`resource_file` failures](#resource_file-failures)); a rejection is never cached, so fixing the file and creating again needs no second reload.

| Status | When |
|--------|------|
| `200` | Evicted. `evicted` lists the keys as `<slug>.json`, sorted; with nothing cached it is `[]`. |
| `400` | Malformed JSON, an unknown field, an explicitly empty `resource_file` (omit the field to mean "all"), a `resource_file` that is not a device-type slug, or one naming a type that is **not shipped** (no directory or file under `resources/`). |
| `404` | `resource_file` names a type that is shipped but not cached, because no device of it has been created since startup or since the last reload. Not a silent no-op: the body names the key and says the next creation reads from disk regardless. |
| `409` | A device-creation batch, or another reload, holds the gate. Same `Retry-After: 5` and body as the [create endpoint's `409`](#one-creation-batch-at-a-time-409). |
| `413` | The body exceeds 4 KiB. |

**A reload is refused during a batch**, because evicting while a load is in flight could republish the old file.
While a reload holds the gate, `GET /api/v1/status` reports `resource_reload_in_progress: true`; poll it as for the [create endpoint's `409`](#one-creation-batch-at-a-time-409).

There is no file watcher.
Reload is explicit.

## Export to CSV

```bash
curl http://localhost:8080/api/v1/devices/export -o devices.csv
```

The CSV columns are, in order: `Device ID`, `IP Address`, `Interface`, `SNMP Port`, `SSH Port`, `Status`, `Resource File`.
Devices without a known resource file emit `N/A` in that column, matching the `Interface` convention.

A re-import tool must translate `N/A` to an omitted `resource_file` field; POST rejects `"N/A"`.

## Generate a route script

```bash
curl http://localhost:8080/api/v1/devices/routes -o add_routes.sh
```

The generated script adds Linux kernel routes for every device IP.
Use it when running the simulator inside a VM and testing from the host.

## Delete devices

```bash
# Single device
curl -X DELETE http://localhost:8080/api/v1/devices/{device-id}

# All devices
curl -X DELETE http://localhost:8080/api/v1/devices
```

## Version

Report the running simulator's version.
The value is set at build time from the Makefile's `APP_VERSION` (resolution order: `APP_VERSION` env > `git describe --tags` > `dev`).
It never changes for the lifetime of the process, so the endpoint sets `Cache-Control: private, max-age=3600`.

Release binaries report the clean tag (e.g., `vX.Y.Z`).
A `make build` from a HEAD ahead of the last tag reports the commit-distance form (e.g., `vX.Y.Z-11-g0356c42`).

```bash
curl http://localhost:8080/api/v1/version
```

```json
{"version": "vX.Y.Z"}
```

A build without tags, or one made by `go build` directly, reports `dev`.
`-version` prints the same string without starting the server:

```bash
./nl6 -version
# → vX.Y.Z
```

## Export status and on-demand fires

The flow, trap and syslog status and fire endpoints are documented on each protocol's reference page, linked from the [endpoint catalog](#endpoint-catalog).

## Device interaction

The control-plane only manages devices.
Once a device is up, you interact with it via its own IP on port 22 (SSH), 161 (SNMP), and, for storage devices, 8443 (HTTPS).

```bash
# SSH (VT100 terminal emulation)
ssh simadmin@192.168.100.1     # password: simadmin

# SNMP v2c
snmpget  -v2c -c public 192.168.100.1 1.3.6.1.2.1.1.1.0
snmpwalk -v2c -c public 192.168.100.1 1.3.6.1.2.1.2.2.1

# SNMP v3 (when enabled). RFC 3414 USM, verified against net-snmp.
# A CLI-started fleet uses simadmin for the user and for both passwords, and
# defaults to -snmpv3-auth md5 with privacy off, so the level you can poll
# follows the flags the simulator was started with.
snmpget -v3 -l noAuthNoPriv -u simadmin 192.168.100.1 1.3.6.1.2.1.1.1.0

# started with -snmpv3-auth md5 (the default)
snmpget -v3 -l authNoPriv -u simadmin -a MD5 -A simadmin \
  192.168.100.1 1.3.6.1.2.1.1.1.0

# started with -snmpv3-auth sha1 -snmpv3-priv aes128
snmpget -v3 -l authPriv -u simadmin -a SHA -A simadmin -x AES -X simadmin \
  192.168.100.1 1.3.6.1.2.1.1.1.0
```

See [SNMP reference](snmp.md) for the OID coverage, including the dynamic HC interface counters on `ifXTable`.

### Storage HTTPS endpoints

Storage devices expose vendor-shaped REST APIs on port 8443 with shared TLS certificates generated at simulator startup.

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
curl -k https://192.168.100.1:8443/            # list buckets
curl -k https://192.168.100.1:8443/my-bucket   # bucket contents
```
