# CLI flags

The `simulator` binary is driven entirely by command-line flags. This page is
the authoritative catalog — new flags land here first.

Run the simulator with:

```bash
sudo ./nl6 [options]
```

Root is required because the simulator creates TUN interfaces and manages the
`opensim` network namespace. See [Network namespace](../ops/network-namespace.md)
for the namespace details and [Quick start](../getting-started/quick-start.md)
for a minimal invocation.

## Core flags

| Flag | Type | Default | Purpose |
|------|------|---------|---------|
| `-auto-start-ip` | string | — | Auto-create devices starting from this IP (e.g. `192.168.100.1`). |
| `-auto-count` | int | 0 | Number of devices to auto-create. Requires `-auto-start-ip`. |
| `-auto-netmask` | string | `24` | Netmask for auto-created devices. |
| `-port` | string | `8080` | HTTP API server port. |
| `-snmp-port` | int | `161` | UDP port for the SNMP listener on each device. Use `1161` to avoid requiring `CAP_NET_BIND_SERVICE`. |
| `-no-namespace` | bool | `false` | Disable network namespace isolation (run in the root namespace). |
| `-help` | — | — | Show the help message and exit. |
| `-version` | — | — | Print the simulator version string to stdout and exit 0. Runs before any startup side effects (no TUN, no netns, no port binds) so it works from unprivileged shells and inside minimal containers. |

## SNMPv3 flags

Omit the engine-id flag to run in v2c-only mode.

| Flag | Values | Default | Purpose |
|------|--------|---------|---------|
| `-snmpv3-engine-id` | string | — | Enable SNMPv3 with the specified engine ID (e.g. `0x80001234`). |
| `-snmpv3-auth` | `none` \| `md5` \| `sha1` | `md5` | SNMPv3 auth protocol. |
| `-snmpv3-priv` | `none` \| `des` \| `aes128` | `none` | SNMPv3 privacy protocol. |

See [SNMP reference](snmp.md) for the auth/priv compatibility matrix.

## Interface-state scenarios

The `-if-scenario` flag controls the SNMP admin/oper status reported for all
simulated interfaces, so you can reproduce common network conditions without
editing resource files.

| Flag | Type | Default | Purpose |
|------|------|---------|---------|
| `-if-scenario` | int | `2` | Interface state scenario: 1=all-shutdown, 2=all-normal, 3=all-failure, 4=pct-failure. |
| `-if-failure-pct` | int | `10` | Percentage of interfaces with oper-down (used with `-if-scenario 4`, 0–100). |

| Scenario | Name | `ifAdminStatus` | `ifOperStatus` | Use case |
|----------|------|-----------------|----------------|----------|
| 1 | all-shutdown | down (2) | down (2) | Planned maintenance, device decommission |
| 2 | all-normal *(default)* | up (1) | up (1) | Normal steady-state operations |
| 3 | all-failure | up (1) | down (2) | Link failures, SFP issues, cable pull |
| 4 | pct-failure | up (1) | down for n% | Partial outage, staged rollout testing |

Scenario 4 uses a deterministic rule (`ifIndex % 100 < n`) so test runs are
reproducible across restarts.

### Error / discard scenario

`-if-scenario` governs **which interfaces are up**. A companion flag,
`-if-error-scenario`, governs **how clean the interfaces that are up
behave** — the ppm ranges used to derive `ifInErrors`, `ifOutErrors`,
`ifInDiscards`, and `ifOutDiscards` from the live packet counters.

| Flag | Values | Default | Purpose |
|------|--------|---------|---------|
| `-if-error-scenario` | `clean` \| `typical` \| `degraded` \| `failing` | `clean` | Auto-start-batch default for per-device error / discard counter cycling. REST-created devices default to `clean` independently (they opt in via `if_error_scenario` in the POST body). |

| Scenario | `errPpm` range | `discPpm` range | Use case |
|----------|----------------|-----------------|----------|
| `clean` *(default)* | 0 | 0 | Pristine lab gear — counters stay at the pre-seeded baseline |
| `typical` | 10 – 100 | 20 – 200 | Good production gear; faint error/discard growth visible in long-period polls |
| `degraded` | 1 000 – 10 000 | 2 000 – 20 000 | Congested / faulty optics; 0.1 – 1 % error rate |
| `failing` | 10 000 – 100 000 | 20 000 – 200 000 | Link-flap / bad cable; 1 – 10 % error rate |

Each interface within a device draws its per-direction ppm deterministically
from the scenario's band at device creation — so repeated runs with the
same auto-start layout produce the same per-interface values. `clean`
(`0/0`) is the backwards-compatible default and leaves all error/discard
counters at their pre-seeded zero.

Unlike `-if-scenario`, this setting is **per-device**: every device carries
its own scenario, so one simulator can host 100 `clean` lab devices
alongside 5 `degraded` ones for alert-threshold testing. See
[`if-counters` reference](snmp.md#dynamic-if-mib-counters).

## Export flag scope

Export flags (flow / trap / syslog) fall into two categories:

- **seed** — applies only to devices created by the `-auto-start-ip` batch at
  startup. Devices subsequently created via `POST /api/v1/devices` do NOT
  inherit these values; they must opt in by including a `flow` / `traps` /
  `syslog` block in the request body.
- **global** — applies simulator-wide regardless of how the device was
  created. Shared sockets, catalogs, rate-limiter, and network-namespace
  bind policy sit here.

**Duration units differ between CLI and REST:** CLI flags that express a
duration take **integer seconds** (e.g. `-flow-tick-interval 5`,
`-trap-interval 30`), while the REST per-device blocks require **Go
duration strings** (`"tick_interval": "5s"`, `"interval": "30s"`).
Passing an integer in the REST body (`"interval": 30`) is rejected with
400 by design — the two forms are not interchangeable.

See [Web API](web-api.md) for the per-device block schema and
[Migration](../ops/migration-per-device-exports.md) for converting
pre-per-device-config invocations.

## Flow export flags

See [Flow export (operator guide)](../ops/flow-export.md) for prerequisites and
collector setup, and [Flow export reference](flow-export.md) for protocol
details.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-flow-collector` | string | — | **seed** | Enable flow export to this UDP collector (e.g. `192.168.1.10:2055`) for the auto-start batch. |
| `-flow-protocol` | `netflow9` \| `ipfix` \| `netflow5` \| `sflow` | `netflow9` | **seed** | Flow export protocol (alias: `sflow5`). |
| `-flow-tick-interval` | int (seconds) | `5` | **seed** | Flow ticker interval. |
| `-flow-active-timeout` | int (seconds) | `30` | **seed** | Active flow timeout. |
| `-flow-inactive-timeout` | int (seconds) | `15` | **seed** | Inactive flow timeout. |
| `-flow-template-interval` | int (seconds) | `60` | **global** | Template retransmission interval (NetFlow v9 / IPFIX only). |
| `-flow-source-per-device` | bool | `true` | **global** | Use each device's IP as the UDP source address. |

## SNMP trap / INFORM export flags

See [SNMP trap / INFORM export (operator guide)](../ops/snmp-traps.md) for
prerequisites and `snmptrapd` smoke-test, and
[SNMP trap reference](snmp-traps.md) for wire format and catalog JSON.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-trap-collector` | string | — | **seed** | Enable trap export to this UDP collector (e.g. `192.168.1.10:162`) for the auto-start batch. Empty disables seeding; REST-created devices can still opt in via the `traps` block. |
| `-trap-mode` | `trap` \| `inform` | `trap` | **seed** | Notification mode. TRAP is fire-and-forget; INFORM is acknowledged and retried. |
| `-trap-interval` | duration | `30s` | **seed** | Per-device mean firing interval (Poisson-distributed, not periodic). |
| `-trap-global-cap` | int (tps) | `0` | **global** | Simulator-wide rate ceiling across fires + INFORM retries. `0` is unlimited. |
| `-trap-catalog` | string | — | **global** | Path to a JSON catalog; empty uses the embedded universal 5-trap catalog + per-type overlays from `resources/<slug>/traps.json`. Setting this flag **disables per-type overlays** — the file becomes the sole catalog for every device. |
| `-trap-community` | string | `public` | **seed** | SNMPv2c community string. |
| `-trap-source-per-device` | bool | `true` | **global** | Use each device's IP as the UDP source address. **Required** when a device is configured `mode=inform` — enforced at device-attach time: the attach fails per-device and the device's `trapConfig` is cleared. |
| `-trap-inform-timeout` | duration | `5s` | **seed** | Per-retry timeout in INFORM mode. |
| `-trap-inform-retries` | int | `2` | **seed** | Maximum retransmissions per INFORM before it's declared failed. |

## UDP syslog export flags

See [UDP syslog export (operator guide)](../ops/syslog-export.md) for
prerequisites and `netcat` smoke-test, and
[UDP syslog reference](syslog-export.md) for wire format and catalog JSON.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-syslog-collector` | string | — | **seed** | Enable syslog export to this UDP collector (e.g. `192.168.1.10:514`) for the auto-start batch. Empty disables seeding; REST-created devices can still opt in via the `syslog` block. |
| `-syslog-format` | `5424` \| `3164` | `5424` | **seed** | Wire format. RFC 5424 is structured (recommended); RFC 3164 is legacy BSD. Per-device as of phase 5 — different devices can emit different formats to the same collector; the shared-socket pool is keyed by `(collector, format)` so streams never interleave. |
| `-syslog-interval` | duration | `10s` | **seed** | Per-device mean firing interval (Poisson-distributed, not periodic). |
| `-syslog-global-cap` | int (rate) | `0` | **global** | Simulator-wide rate ceiling across scheduled fires. On-demand HTTP fires bypass the cap. `0` is unlimited. |
| `-syslog-catalog` | string | — | **global** | Path to a JSON catalog; empty uses the embedded universal 6-entry catalog + per-type overlays from `resources/<slug>/syslog.json`. Setting this flag **disables per-type overlays** — the file becomes the sole catalog for every device. |
| `-syslog-source-per-device` | bool | `true` | **global** | Use each device's IP as the UDP source address. Per-device bind failures are non-fatal (unlike INFORM mode on the trap side) — the exporter falls back to the shared socket with a warning. |

## Examples

```bash
# Start server only (all interfaces up/up by default)
sudo ./nl6

# Auto-create 5 devices starting from 192.168.100.1
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 5

# Custom API port and subnet
sudo ./nl6 -auto-start-ip 10.10.10.1 -auto-count 100 -port 9090

# Non-privileged SNMP port (no CAP_NET_BIND_SERVICE needed)
sudo ./nl6 -auto-start-ip 10.10.10.1 -auto-count 10 -snmp-port 1161

# SNMPv3 with MD5 auth and AES128 privacy
sudo ./nl6 -snmpv3-engine-id 0x80001234 -snmpv3-auth md5 -snmpv3-priv aes128

# Disable network namespace isolation
sudo ./nl6 -no-namespace -auto-start-ip 192.168.100.1 -auto-count 10

# Maintenance window — all interfaces admin-shutdown
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 10 -if-scenario 1

# Link failure — all interfaces admin-up but oper-down
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 10 -if-scenario 3

# Partial outage — 30% of interfaces oper-down
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 10 \
    -if-scenario 4 -if-failure-pct 30
```
