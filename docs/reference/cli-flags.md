# CLI flags

The `simulator` binary is driven entirely by command-line flags. This page is
the authoritative catalog — new flags land here first.

Run the simulator with:

```bash
sudo ./nl6 [options]
```

Root is required because the simulator creates TUN interfaces and manages the
`nl6sim` network namespace. See [Network namespace](../ops/network-namespace.md)
for the namespace details and [Quick start](../getting-started/quick-start.md)
for a minimal invocation.

## Core flags

| Flag | Type | Default | Purpose |
|------|------|---------|---------|
| `-auto-start-ip` | string | — | Auto-create devices starting from this IP (e.g. `192.168.100.1`). |
| `-auto-count` | int | 0 | Number of devices to auto-create. Requires `-auto-start-ip`. |
| `-auto-netmask` | string | `16` | Netmask (prefix length) for auto-created devices. The fleet is a flat `/16` management plane — only the `/16` network and broadcast are reserved, so `.x.0`/`.x.255` are ordinary device hosts. Accepts `8` / `16` / `24`; an explicit `24` keeps classic per-`/24` semantics (skips `.0`/`.255`). |
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

### Link-flap scenario

`-if-flap-scenario` drives Poisson-distributed link flaps per
`(device, ifIndex)`. Mutations go through the interface state engine
that powers SNMP `ifOperStatus` / `ifAdminStatus` / `ifLastChange` and
gNMI ON_CHANGE subscribers, so all three surfaces see the same value at
the same instant.

| Flag | Values | Default | Scope | Purpose |
|------|--------|---------|-------|---------|
| `-if-flap-scenario` | `clean` \| `rare` \| `typical` \| `aggressive` | `clean` | **seed** | Auto-start-batch per-device link-flap scenario. REST devices default to `clean`; opt in via `if_flap_scenario` POST body. |
| `-if-flap-global-cap` | int (events/sec) | `0` | **global** | Simulator-wide rate ceiling on flap events. `0` is unlimited. |

| Scenario | Mean inter-flap | Down duration | Use case |
|----------|-----------------|---------------|----------|
| `clean` *(default)* | ∞ (no flaps) | n/a | Steady-state regression testing |
| `rare` | ~6 hours / interface | uniform 1–10 s | Long-running fleets, background variance |
| `typical` | ~15 minutes / interface | uniform 1–30 s | Collector alarm-pipeline stress |
| `aggressive` | ~1 minute / interface | uniform 1–5 s | Chaos / churn measurement |

See [interface state engine reference](interface-state.md) for the REST
control plane (`POST /api/v1/devices/{ip}/interfaces/{ifIndex}/{oper,admin}-status`),
auto-revert semantics, and the cross-protocol consistency contract.

### Optical health band

`-optical-scenario` sets the steady-state health of each coherent optical
channel on **optical transport device types only** (today
`ciena_waveserver5`). It is keyed by OCH component name, never by
`ifIndex`, and it drives the whole receive-side cascade: received power
and accumulated noise are two independent dials, `osnr = pIn - nAse`, and
`osnr` feeds `q-value` → `pre-fec-ber` →
`fec-uncorrectable-blocks`.

| Flag | Values | Default | Scope | Purpose |
|------|--------|---------|-------|---------|
| `-optical-scenario` | `clean` \| `typical` \| `degraded` \| `failing` | `clean` | **seed** | Auto-start-batch per-device optical health band. REST devices default to `clean`; opt in via `optical_scenario` in the POST body. |

| Scenario | OSNR (dB) | Q (dB) | pre-FEC BER | Uncorrectable blocks | Use case |
|----------|-----------|--------|-------------|----------------------|----------|
| `clean` *(default)* | 18.30 | 11.42 | 9.8e-05 | never | Healthy 400G line; baseline regression testing |
| `typical` | 16.68 | 9.80 | 1.0e-03 | never | Good production span with normal margin |
| `degraded` | 15.60 | 8.72 | 3.2e-03 | never | Visibly elevated BER that FEC still corrects — the window where a proactive alarm has value |
| `failing` | 10.10 | 3.22 | 7.4e-02 | always | Past the 2e-2 SD-FEC threshold; genuinely service-affecting |

Only `failing` crosses the FEC threshold, and it does so for every channel
across the entire dial period — so `fec-uncorrectable-blocks > 0` is a
reliable "service-affecting" signal for a collector rule. `degraded` stays
clear of the threshold for every channel, which is what makes the
distinction useful.

Setting a non-`clean` band on a device type that has no optical channels
is rejected with **400**: the value would silently do nothing, so the
contradiction is surfaced rather than accepted. For the same reason
`optical_scenario` is absent from `GET /api/v1/devices` for
non-optical types. A mixed `round_robin` batch is still accepted — the
optical devices take the band and the rest ignore it.

Values are deterministic per `(device, channel)` and analytic — no
per-channel goroutine — so SNMP and gNMI agree byte-for-byte at the same
instant. See [gNMI reference](gnmi.md) for the served leaf set.

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
| `-flow-tick-interval` | int (seconds) | `5` | **seed** | Flow ticker cadence. Sets **batching, not volume** — see the note below. Applied at construction and not runtime-mutable. The per-device `tick_interval` is still accepted and not honored ([nl6#445](https://github.com/labmonkeys-space/nl6/issues/445)). |
| `-flow-active-timeout` | int (seconds) | `30` | **seed** | Cap on how long a still-running flow stays cached before it is exported. |
| `-flow-inactive-timeout` | int (seconds) | `15` | **seed** | Idle time after a flow's last packet before it is exported. |

| `-flow-template-interval` | int (seconds) | `60` | **global** | Template retransmission interval (NetFlow v9 / IPFIX only). |
| `-flow-sub-agent-id` | uint | `0` | **seed** | sFlow `sub_agent_id` emitted in every datagram header by the auto-start batch (one value for the whole batch; per-group values via the REST `flow.sub_agent_id` field). Ignored by non-sFlow protocols. See [Flow export reference → sFlow sub-agent id](flow-export.md#sflow-sub-agent-id). |
| `-flow-option-interface-table` | `if-scoped` \| `system-scoped` | — (off) | **seed** | Emit v9/IPFIX interface option records ("option interface-table") for the auto-start batch: `if-scoped` carries the ifIndex in the scope with fields 82+83; `system-scoped` carries it as option field `INPUT_SNMP(10)` with field 83 only (the IOS-XR shape). Requires `-flow-protocol netflow9` or `ipfix` — other protocols fail startup validation. Per-group shapes via the REST `flow.options_interface_table` field. See [Flow export reference → Interface option records](flow-export.md#interface-option-records-netflow-v9--ipfix). |
| `-flow-source-per-device` | bool | `true` | **global** | Use each device's IP as the UDP source address. |

:::note Tick interval sets batching, not volume

It is natural to reach for `-flow-tick-interval` to turn flow volume up or down. It is not that knob.

Export volume is set by how many flows exist and how long they live:

```
records/s  ≈  ConcurrentFlows / mean-flow-lifetime
mean-flow-lifetime = mean of  min(active-timeout, flow-duration + inactive-timeout)
```

The tick interval decides how finely that stream is cut into datagrams. A slower tick sends **bigger datagrams**, not proportionally fewer records. A residual dependence remains — export polls, so a flow sits cached up to one interval past its deadline, worth roughly `T/2` on average — but it is bounded by the interval and is not a proportional control.

To change volume, change the device profile's concurrent-flow count or the timeouts.

**Before [nl6#446](https://github.com/labmonkeys-space/nl6/issues/446) was fixed**, this flag was inert (every deployment ticked at 5s) and volume *did* step with cadence, because the whole cache expired on one tick and then sat empty. Both are fixed; a deployment that set this flag will see a different cadence and every flow deployment will see a different record rate. See [Flow export](./flow-export.md).

:::

## SNMP trap / INFORM export flags

See [SNMP trap / INFORM export (operator guide)](../ops/snmp-traps.md) for
prerequisites and `snmptrapd` smoke-test, and
[SNMP trap reference](snmp-traps.md) for wire format and catalog JSON.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-trap-collector` | string | — | **seed** | Enable trap export to this UDP collector (e.g. `192.168.1.10:162`) for the auto-start batch. Empty disables seeding; REST-created devices can still opt in via the `traps` block. |
| `-trap-mode` | `trap` \| `inform` | `trap` | **seed** | Notification mode. TRAP is fire-and-forget; INFORM is acknowledged and retried. |
| `-trap-interval` | duration | `30s` | **seed** | **Simulator-wide** mean firing interval (Poisson-distributed, not periodic). Every trap-enabled device fires at this cadence; the per-device `interval` in a REST `traps` block is accepted, echoed by `GET /api/v1/devices`, and **not honored** ([nl6#445](https://github.com/labmonkeys-space/nl6/issues/445)). To silence a fleet use `-fidelity` (or `POST /api/v1/fidelity` at runtime), not a long interval. |
| `-trap-global-cap` | int (tps) | `0` | **global** | Simulator-wide rate ceiling across fires + INFORM retries. `0` is unlimited. |
| `-trap-catalog` | string | — | **global** | Path to a JSON catalog; empty uses the embedded universal 5-trap catalog + per-type overlays from `resources/<slug>/traps.json`. Setting this flag **disables per-type overlays** — the file becomes the sole catalog for every device. |
| `-trap-community` | string | `public` | **seed** | SNMPv2c community string. |
| `-trap-source-per-device` | bool | `true` | **global** | Use each device's IP as the UDP source address. **Required** when a device is configured `mode=inform` — enforced at device-attach time: the attach fails per-device and the device's `trapConfig` is cleared. |
| `-trap-inform-timeout` | duration | `5s` | **seed** | Per-retry timeout in INFORM mode. |
| `-trap-inform-retries` | int | `2` | **seed** | Maximum retransmissions per INFORM before it's declared failed. |

## gNMI target flags

The gNMI subsystem is always-on by default and serves a read-only OpenConfig
interfaces subset over gRPC + TLS on every device. See
[gNMI target reference](gnmi.md) for path coverage, subscribe semantics, and
`gnmic` invocation examples.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-gnmi-port` | int | `9339` | **global** | TCP port for the gNMI listener on each device. |
| `-gnmi-disable` | bool | `false` | **global** | Disable the subsystem; no device listens on the gNMI port. |

## gNMI dial-out flags

Dial-out reverses the connection direction: the device dials a collector
and pushes telemetry over a `gNMIReverse.Publish` stream. Per-device and
opt-in — the fleet can mix dial-in and dial-out devices. See
[gNMI dial-out reference](gnmi-dial-out.md) for wire protocol, modes,
TLS, and the per-device `gnmi_dialout` REST block.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-gnmi-mode` | `dial-in` \| `dial-out` | `dial-in` | **seed** | gNMI mode for the auto-start batch. `dial-out` additionally pushes telemetry to `-gnmi-dialout-collector`; the dial-in listener keeps serving either way. |
| `-gnmi-dialout-collector` | string | — | **seed** | Dial-out collector address (`host:port`). Required when `-gnmi-mode=dial-out`. |
| `-gnmi-dialout-flavor` | string | `gnmireverse` | **seed** | Dial-out wire flavor (Arista `gNMIReverse` is the only shipped flavor). |
| `-gnmi-dialout-encoding` | `json_ietf` \| `proto` | `json_ietf` | **seed** | Value encoding for pushed updates. |
| `-gnmi-dialout-sub-mode` | `sample` \| `on-change` | `sample` | **seed** | Subscription mode: fixed-interval snapshots or interface-state transitions. |
| `-gnmi-dialout-interval` | duration | `10s` | **seed** | SAMPLE cadence (clamped to a 1s floor). |
| `-gnmi-dialout-tls` | bool | `true` | **seed** | Use TLS to the collector (`false` = plaintext, Arista `-collector_tls=false` parity). |
| `-gnmi-dialout-tls-insecure` | bool | `false` | **seed** | Skip collector certificate verification (dev only). |
| `-gnmi-dialout-tls-ca` | string | — | **seed** | PEM CA bundle to verify the collector against (empty = system roots). |
| `-gnmi-dialout-mtls` | bool | `false` | **seed** | Present the shared TLS certificate as a client cert (mutual TLS). |

## UDP syslog export flags

See [UDP syslog export (operator guide)](../ops/syslog-export.md) for
prerequisites and `netcat` smoke-test, and
[UDP syslog reference](syslog-export.md) for wire format and catalog JSON.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-syslog-collector` | string | — | **seed** | Enable syslog export to this UDP collector (e.g. `192.168.1.10:514`) for the auto-start batch. Empty disables seeding; REST-created devices can still opt in via the `syslog` block. |
| `-syslog-format` | `5424` \| `3164` | `5424` | **seed** | Wire format. RFC 5424 is structured (recommended); RFC 3164 is legacy BSD. Per-device as of phase 5 — different devices can emit different formats to the same collector; the shared-socket pool is keyed by `(collector, format)` so streams never interleave. |
| `-syslog-interval` | duration | `10s` | **seed** | **Simulator-wide** mean firing interval (Poisson-distributed, not periodic). Every syslog-enabled device fires at this cadence; the per-device `interval` in a REST `syslog` block is accepted, echoed by `GET /api/v1/devices`, and **not honored** ([nl6#445](https://github.com/labmonkeys-space/nl6/issues/445)). To silence a fleet use `-fidelity` (or `POST /api/v1/fidelity` at runtime), not a long interval. |
| `-syslog-global-cap` | int (rate) | `0` | **global** | Simulator-wide rate ceiling across scheduled fires. On-demand HTTP fires bypass the cap. `0` is unlimited. |
| `-syslog-catalog` | string | — | **global** | Path to a JSON catalog; empty uses the embedded universal 6-entry catalog + per-type overlays from `resources/<slug>/syslog.json`. Setting this flag **disables per-type overlays** — the file becomes the sole catalog for every device. |
| `-syslog-source-per-device` | bool | `true` | **global** | Use each device's IP as the UDP source address. Per-device bind failures are non-fatal (unlike INFORM mode on the trap side) — the exporter falls back to the shared socket with a warning. |

## Load-test scenario flags

Global switches for the [load-test scenario subsystem](loadtest-overview.md).
The scenarios themselves are driven over REST (`/api/v1/scenarios`); these
flags shape the whole fleet at startup.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-fidelity` | bool | `false` | **global** | Keep the fleet **silent** — no autonomous flow / SNMP-trap / syslog / gNMI-dial-out push — except during a running scenario's `[T0,T1)` window, for a clean measurement window. Devices still answer polls; explicit on-demand fires still go through. Also togglable at runtime via `POST /api/v1/fidelity`, so bracketing a measurement does not require a restart; this flag is then the startup **default** rather than the value in force. See [Fidelity mode](loadtest-scenarios.md#fidelity-mode). |
| `-scenario-pen` | uint | `0` | **global** | IANA Private Enterprise Number for PEN-dependent scenario [run tags](loadtest-scenarios.md#run-tagging--isolating-experiment-traffic) (syslog SD-PARAM, SNMP enterprise varbind). `0` = unset → those levers degrade to window + source-IP isolation. |

## LLDP topology flag

Pre-load an inter-device LLDP link graph at startup. The graph is also mutable
at runtime via `POST` / `DELETE /api/v1/topology`. See
[LLDP topology reference](lldp-topology.md).

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-topology-config` | string | — | **global** | Path to a JSON inter-device LLDP link graph (`{"links":[{"a":{"ip","ifindex"},"b":{"ip","ifindex"}}]}`). Loaded at startup; validation is syntactic only (device / ifIndex are resolved lazily at serve time). |

## DNS service-discovery flags

nl6 acts as a hidden DNS primary; a CoreDNS secondary transfers the zones. Off
by default. See [DNS service-discovery reference](dns-service-discovery.md).

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-dns-enable` | bool | `false` | **global** | Enable the DNS service-discovery server. |
| `-dns-domain` | string | `nl6.local` | **global** | Forward zone apex (`<device-name>.<domain>`). |
| `-dns-listen` | string | `:5353` | **global** | Bind address (host:port) in the container's default netns. |
| `-dns-reverse-zone` | string | `42.10.in-addr.arpa` | **global** | Comma-separated `in-addr.arpa` reverse zone(s). IPs outside get an `A` but no `PTR`. |
| `-dns-notify` | string | — | **global** | Comma-separated secondary NOTIFY targets (`host:port`); empty disables NOTIFY. |
| `-dns-debounce` | duration | `1s` | **global** | Quiescence window coalescing a burst of device changes into one serial bump + NOTIFY. |

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
