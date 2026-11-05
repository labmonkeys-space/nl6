---
sidebar_label: "CLI flags"
description: "Every command-line flag the simulator accepts, grouped by subsystem, with defaults and which flags apply to the auto-start batch only."
---

# CLI flags

The `simulator` binary is driven entirely by command-line flags.
This page is the authoritative catalog.

Run the simulator with:

```bash
sudo ./nl6 [options]
```

Root is required because the simulator creates TUN interfaces and manages the `nl6sim` network namespace.
See [Network namespace](../ops/network-namespace.md) for the namespace details and [Quick start](../getting-started/quick-start.md) for a minimal invocation.

## Core flags

| Flag | Type | Default | Purpose |
|------|------|---------|---------|
| `-auto-start-ip` | string | empty | Auto-create devices starting from this IP (e.g. `192.168.100.1`). |
| `-auto-count` | int | 0 | Number of devices to auto-create. Requires `-auto-start-ip`. |
| `-auto-netmask` | string | `16` | Netmask (prefix length) for auto-created devices. The fleet is a flat `/16` management plane. Only the `/16` network and broadcast are reserved, so `.x.0`/`.x.255` are ordinary device hosts. Accepts `8` / `16` / `24`; an explicit `24` keeps classic per-`/24` semantics (skips `.0`/`.255`). |
| `-port` | string | `8080` | HTTP API server port. |
| `-snmp-port` | int | `161` | UDP port for the SNMP listener on each device. Use `1161` to avoid requiring `CAP_NET_BIND_SERVICE`. |
| `-no-namespace` | bool | `false` | Disable network namespace isolation (run in the root namespace). |
| `-help` | n/a | n/a | Show the help message and exit. |
| `-version` | n/a | n/a | Print the simulator version string to stdout and exit 0. Runs before any startup side effects (no TUN, no netns, no port binds) so it works from unprivileged shells and inside minimal containers. |

## SNMPv3 flags

Omit the engine-id flag to run in v2c-only mode.

| Flag | Values | Default | Purpose |
|------|--------|---------|---------|
| `-snmpv3-engine-id` | string | empty | Enable SNMPv3 with the specified engine ID (e.g. `800000090300AABBCCDD`). |
| `-snmpv3-auth` | `none` \| `md5` \| `sha1` | `md5` | SNMPv3 authentication protocol (RFC 3414 USM), verified against net-snmp. It also selects the hash used to localize the **privacy** key (§2.6). Inbound messages are verified, so a wrong password is answered with a `usmStatsWrongDigests` Report. |
| `-snmpv3-priv` | `none` \| `des` \| `aes128` | `none` | SNMPv3 privacy protocol. Requires `-snmpv3-auth`, since USM defines no privacy-without-authentication level. The key comes from the per-device `snmpv3.priv_password` REST field, falling back to the auth password. A CLI-started fleet has no separate privacy-password flag and reuses the shared password. |

See [SNMP reference](snmp.md) for the auth/priv compatibility matrix.

### Write admission (`SetRequest`)

Writes are **opt-in**.
A fleet booted with neither flag below answers no `SET` at any version.

| Flag | Values | Default | Scope | Description |
|------|--------|---------|-------|-------------|
| `-snmp-write-community` | string | empty | **seed** | SNMPv1/v2c community required to **write**. Empty admits no v1/v2c `SET`. A mismatch is **discarded**. No datagram comes back, which `snmpset` reports as a timeout, and the cause is logged once per device. Reads are unaffected: nl6 checks no community on a poll, at any version. REST-created devices set `write_community` on the create body. |
| `-snmp-set-min-security-level` | `none` \| `auth` \| `priv` | `auth` | **seed** | Lowest SNMPv3 security level a `SetRequest` may carry (`noAuthNoPriv` / `authNoPriv` / `authPriv`). Below it, the request is answered with a `usmStatsUnsupportedSecLevels` Report (RFC 3414 §3.2 step 5). On a fleet run with `-snmpv3-auth none` nothing can reach the default, so no v3 `SET` is admitted. The startup log says so. REST-created devices set `snmpv3.set_min_security_level`. |

An unrecognised `-snmp-set-min-security-level` is fatal at startup.
The admission rules, the refusal shapes and the startup policy line are in [SNMP → Write admission for a `SET`](snmp.md#write-admission-for-a-set).

## Interface-state scenarios

`-if-scenario` sets the **initial** admin and link state of every simulated interface.
What each scenario seeds, and how it interacts with flaps and SETs, is in [Interface state → Interface-state scenarios](interface-state.md#interface-state-scenarios).

| Flag | Type | Default | Purpose |
|------|------|---------|---------|
| `-if-scenario` | int | `2` | Interface state scenario: 1=all-shutdown, 2=all-normal, 3=all-failure, 4=pct-failure. A value outside 1..4 is refused at startup. |
| `-if-failure-pct` | int | `10` | Percentage of interfaces with oper-down (used with `-if-scenario 4`, 0 to 100). A value outside 0..100 is refused at startup. |

### Error / discard scenario

`-if-scenario` governs **which interfaces are up**.
A companion flag, `-if-error-scenario`, governs **how clean the interfaces that are up behave**: the ppm ranges used to derive `ifInErrors`, `ifOutErrors`, `ifInDiscards`, and `ifOutDiscards` from the live packet counters.

| Flag | Values | Default | Purpose |
|------|--------|---------|---------|
| `-if-error-scenario` | `clean` \| `typical` \| `degraded` \| `failing` | `clean` | Auto-start-batch default for per-device error / discard counter cycling. REST-created devices default to `clean` independently (they opt in via `if_error_scenario` in the POST body). |

| Scenario | `errPpm` range | `discPpm` range | Use case |
|----------|----------------|-----------------|----------|
| `clean` *(default)* | 0 | 0 | Pristine lab gear. Counters stay at the pre-seeded baseline |
| `typical` | 10 to 100 | 20 to 200 | Good production gear; faint error/discard growth visible in long-period polls |
| `degraded` | 1 000 to 10 000 | 2 000 to 20 000 | Congested / faulty optics; 0.1 to 1 % error rate |
| `failing` | 10 000 to 100 000 | 20 000 to 200 000 | Link-flap / bad cable; 1 to 10 % error rate |

Each interface within a device draws its per-direction ppm deterministically from the scenario's band at device creation, so repeated runs with the same auto-start layout produce the same per-interface values.
`clean` (`0/0`) leaves all error/discard counters at their pre-seeded zero.

Unlike `-if-scenario`, this setting is **per-device**: every device carries its own scenario, so one simulator can host 100 `clean` lab devices alongside 5 `degraded` ones for alert-threshold testing.
See [`if-counters` reference](snmp.md#dynamic-if-mib-counters).

### Link-flap scenario

`-if-flap-scenario` drives Poisson-distributed link flaps per `(device, ifIndex)`.

| Flag | Values | Default | Scope | Purpose |
|------|--------|---------|-------|---------|
| `-if-flap-scenario` | `clean` \| `rare` \| `typical` \| `aggressive` | `clean` | **seed** | Auto-start-batch per-device link-flap scenario. REST devices default to `clean`; opt in via `if_flap_scenario` POST body. |
| `-if-flap-global-cap` | int (events/sec) | `0` | **global** | Simulator-wide rate ceiling on flap events. `0` is unlimited. |

The scenario rates, the masking rule and the REST control plane are in [Interface state → Link-flap scenarios](interface-state.md#link-flap-scenarios).

### Optical health band

`-optical-scenario` sets the steady-state health of each coherent optical channel on **optical transport device types only** (today `ciena_waveserver5`).
It is keyed by OCH component name, never by `ifIndex`, and drives the receive-side cascade described in [Optical telemetry](optical-telemetry.md).

| Flag | Values | Default | Scope | Purpose |
|------|--------|---------|-------|---------|
| `-optical-scenario` | `clean` \| `typical` \| `degraded` \| `failing` | `clean` | **seed** | Auto-start-batch per-device optical health band. REST devices default to `clean`; opt in via `optical_scenario` in the POST body. |

| Scenario | OSNR (dB) | Q (dB) | pre-FEC BER | Uncorrectable blocks | Use case |
|----------|-----------|--------|-------------|----------------------|----------|
| `clean` *(default)* | 18.30 | 11.42 | 9.8e-05 | never | Healthy 400G line; baseline regression testing |
| `typical` | 16.68 | 9.80 | 1.0e-03 | never | Good production span with normal margin |
| `degraded` | 15.60 | 8.72 | 3.2e-03 | never | Visibly elevated BER that FEC still corrects. This is the window where a proactive alarm has value |
| `failing` | 10.10 | 3.22 | 7.4e-02 | always | Past the 2e-2 SD-FEC threshold; genuinely service-affecting |

Only `failing` crosses the FEC threshold, and it does so for every channel across the entire dial period.
So `fec-uncorrectable-blocks > 0` is a reliable "service-affecting" signal for a collector rule.
`degraded` stays clear of the threshold for every channel.

Setting a non-`clean` band on a device type that has no optical channels is rejected with **400**.
`optical_scenario` is absent from `GET /api/v1/devices` for non-optical types.
A mixed `round_robin` batch is still accepted.
The optical devices take the band and the rest ignore it.

Values are deterministic per `(device, channel)`, so SNMP and gNMI agree byte-for-byte at the same instant.
See [gNMI reference](gnmi.md) for the served leaf set.

## Export flag scope

Export flags (flow / trap / syslog) fall into two categories:

- **seed**: applies only to devices created by the `-auto-start-ip` batch at startup. Devices subsequently created via `POST /api/v1/devices` do NOT inherit these values; they must opt in by including a `flow` / `traps` / `syslog` block in the request body.
- **global**: applies simulator-wide regardless of how the device was created. Shared sockets, catalogs, rate-limiter, and network-namespace bind policy sit here.
  So do the three cadence flags `-flow-tick-interval`, `-trap-interval` and `-syslog-interval`.
  Each drives one simulator-wide scheduler, so it applies to REST-created devices too.

**Duration flags.** Every time-valued CLI flag accepts a Go duration string: `-trap-interval 30s`, `-trap-inform-timeout 5s`, `-syslog-interval 10s`, `-gnmi-dialout-interval 10s`, `-dns-debounce 1s`, `-flow-tick-interval 5s`.
The four flow flags `-flow-tick-interval`, `-flow-active-timeout`, `-flow-inactive-timeout` and `-flow-template-interval` also accept a bare integer, read as seconds (`-flow-tick-interval 5`).
Every other duration flag **requires a unit**: a bare `-trap-interval 30` does not parse.
On the four flow flags a value of zero or less, or a bare number with a fraction (`1.5`), is refused at startup.
Sub-second values are accepted and have no floor, so `-flow-tick-interval 500ms` drives every device's export tick at that cadence.
The tick interval's upper bound stays a logged fallback: a value above 1h is replaced by the 5s default at manager construction.
The REST per-device blocks carry **no cadence field at all**: `flow.tick_interval`, `traps.interval` and `syslog.interval` are rejected with 400, and the error names the flag to use instead.
The other REST durations (`active_timeout`, `inactive_timeout`, `inform_timeout`, `sample_interval`) are Go duration strings (`"30s"`); a bare integer is rejected with 400.

See [Web API](web-api.md) for the per-device block schema.

## Flow export flags

See [Flow export how-to](../ops/flow-export.md) for prerequisites and collector setup, and [Flow export reference](flow-export.md) for protocol details.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-flow-collector` | string | empty | **seed** | Enable flow export to this UDP collector (e.g. `192.168.1.10:2055`) for the auto-start batch. |
| `-flow-protocol` | `netflow9` \| `ipfix` \| `netflow5` \| `sflow` | `netflow9` | **seed** | Flow export protocol (alias: `sflow5`). |
| `-flow-tick-interval` | seconds or duration | `5s` | **global** | Flow ticker cadence. Sets **batching, not volume**: a slower tick sends bigger datagrams, not proportionally fewer records. To change volume, change the device profile's concurrent-flow count or the timeouts. See [Flow export → Tick interval and datagrams](flow-export.md#tick-interval-and-datagrams). Applied at construction and not runtime-mutable. This flag is the only cadence: a per-device `tick_interval` in a REST `flow` block is rejected with 400. |
| `-flow-active-timeout` | seconds or duration | `30s` | **seed** | Cap on how long a still-running flow stays cached before it is exported. Sets a **mean, not an exact deadline**: each flow's deadline is jittered by ±25 %, so `30s` spreads expiry over 22.5s to 37.5s. See [Flow export → emission shape](flow-export.md#emission-shape). |
| `-flow-inactive-timeout` | seconds or duration | `15s` | **seed** | Idle time after a flow's last packet before it is exported. |
| `-flow-template-interval` | seconds or duration | `1m0s` | **global** | Template retransmission interval (NetFlow v9 / IPFIX only). |
| `-flow-sub-agent-id` | uint | `0` | **seed** | sFlow `sub_agent_id` emitted in every datagram header by the auto-start batch (one value for the whole batch; per-group values via the REST `flow.sub_agent_id` field). Ignored by non-sFlow protocols. See [Flow export reference → sFlow sub-agent id](flow-export.md#sflow-sub-agent-id). |
| `-flow-option-interface-table` | `if-scoped` \| `system-scoped` | empty (off) | **seed** | Emit v9/IPFIX interface option records ("option interface-table") for the auto-start batch: `if-scoped` carries the ifIndex in the scope with fields 82+83; `system-scoped` carries it as option field `INPUT_SNMP(10)` with field 83 only (the IOS-XR shape). Requires `-flow-protocol netflow9` or `ipfix`. Other protocols fail startup validation. Per-group shapes via the REST `flow.options_interface_table` field. See [Flow export reference → Interface option records](flow-export.md#interface-option-records-netflow-v9--ipfix). |
| `-flow-nbar2` | bool | `false` | **seed** | Emit Cisco AVC (NBAR2) IPFIX records (template 258) and the RFC 6759 application table (259) from NBAR2-capable auto-start devices (`cisco_ios`, `cisco_catalyst_9500`). Requires `-flow-protocol ipfix`, `-flow-collector` and an NBAR2-capable auto-start type; fatal at startup otherwise. **The auto-start batch is built as `asr9k` and no flag selects another type, so the flag is refused on every boot today**; create NBAR2 devices over REST with `resource_file: "cisco_ios.json"` and `flow.nbar2` instead. Incapable devices in a mixed batch keep their flow block and emit plain IPFIX. Per-device via the REST `flow.nbar2` field. See [Flow export reference → NBAR2](flow-export.md#nbar2-application-records-ipfix-only). |
| `-nbar2-catalog` | path | empty (embedded) | global | Replace the embedded universal NBAR2 application catalog (`resources/_common/nbar2.json`) and suppress every per-type overlay (`resources/<type>/nbar2.json`). Read once at startup; not reloaded by `POST /api/v1/resources/reload`. Entries too large for the `-datagram-mtu` budget are disabled and named at startup, never a boot failure. |
| `-flow-tick-sync` | bool | `false` | **global** | Sweep every device on the same ticker firing, so the fleet exports in one burst per tick interval (the restart-storm pattern). Off by default: each device keeps the tick cadence but is swept at its own phase within the period, so the collector sees a near-flat arrival rate. Applied at construction and not runtime-mutable. Reported as `tick_synchronized` on `GET /api/v1/flows/status`. See [Flow export → fleet arrival shape](flow-export.md#fleet-arrival-shape). |
| `-flow-source-per-device` | bool | `true` | **global** | Use each device's IP as the UDP source address. |
| `-datagram-mtu` | int (bytes) | `1500` | **global** | Assumed MTU of the egress path to collectors. Every UDP-emitting subsystem derives its budget from it: flow datagrams, trap PDUs and the SNMP response bound, GETBULK included. Validated at startup (`576..65535`); an out-of-range value is fatal, after `-help` / `-version`. Lower it when the collector path is not standard Ethernet (a Docker overlay is typically `1450`). Lowering it far enough disables shipped optical trap entries, which are named in the startup log. See [Datagram MTU](#datagram-mtu). |

### Datagram MTU

`-datagram-mtu` is the one MTU every UDP-emitting subsystem sizes its datagrams to.
It governs flow export, SNMP trap notifications and SNMP responses.
Syslog is excluded and keeps its own 1400-byte ceiling.

The 1500 default holds for nl6's own TUN and veth interfaces, which take the kernel default.
It is an assumption about the **egress** path to the collector, which nl6 does not control.

**Lower it when the collector path is not standard Ethernet.**
A Docker overlay or VXLAN network is typically 1450, and a tunnelled path lower still.
At 1450, a default-sized NetFlow v9 (1480-byte frame), IPFIX (1484) or NetFlow v5 (1492) datagram fragments, as does an SNMP GETBULK at OpenNMS's default collector settings (1464).
Only sFlow and SNMP traps fit.

What each subsystem does with the value:

- **Flow.** The payload budget is the MTU minus the IP and UDP headers. The per-protocol effect, including the NetFlow v5 30-record cap, is in [Flow export → How much flow a device emits](flow-export.md#how-much-flow-a-device-emits).
- **SNMP responses.** A GETBULK truncates to the frame, and a GET or GETNEXT that cannot fit answers `tooBig`. See [SNMP → Response size](snmp.md#response-size-max-repetitions-and-truncation).
- **SNMP traps.** Lowering the MTU far enough stops shipped optical alarm entries from firing rather than shrinking them. They are disabled at catalog load and named in the startup log with the MTU that would admit them.

The value is validated at startup, and an out-of-range one is fatal.

nl6 does not discover the MTU, and does no path-MTU discovery.
If you see fragments, check the egress interface MTU and set the flag to match.

## SNMP trap / INFORM export flags

See [SNMP trap export how-to](../ops/snmp-traps.md) for prerequisites and `snmptrapd` smoke-test, and [SNMP trap reference](snmp-traps.md) for wire format and catalog JSON.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-trap-collector` | string | empty | **seed** | Enable trap export to this UDP collector (e.g. `192.168.1.10:162`) for the auto-start batch. Empty disables seeding; REST-created devices can still opt in via the `traps` block. |
| `-trap-mode` | `trap` \| `inform` | `trap` | **seed** | Notification mode. TRAP is fire-and-forget; INFORM is acknowledged and retried. |
| `-trap-interval` | duration | `30s` | **global** | **Simulator-wide** mean firing interval (Poisson-distributed, not periodic). Every trap-enabled device fires at this cadence. This flag is the only cadence: a per-device `interval` in a REST `traps` block is rejected with 400. To silence a fleet use `-fidelity` (or `POST /api/v1/fidelity` at runtime), not a long interval. |
| `-trap-global-cap` | int (tps) | `0` | **global** | Simulator-wide rate ceiling across fires + INFORM retries. `0` is unlimited. |
| `-trap-catalog` | string | empty | **global** | Path to a JSON catalog; empty uses the embedded universal 5-trap catalog + per-type overlays from `resources/<slug>/traps.json`. Setting this flag **disables per-type overlays**. The file becomes the sole catalog for every device. |
| `-trap-community` | string | `public` | **seed** | SNMPv2c community string. **Ignored under `-trap-snmp-version=v3`**. An SNMPv3 message carries no community string anywhere; nl6 warns at startup if you set it explicitly. |
| `-trap-snmp-version` | `v2c` \| `v1` \| `v3` | `v2c` | **seed** | Notification wire format. `v1` emits RFC 1157 Trap-PDUs (tag `0xA4`) with the identity derived per RFC 3584 §3.2. `v3` emits the same SNMPv2-Trap-PDU as `v2c` inside an RFC 3414 USM envelope. One per fleet; neither `v1` nor `v3` can be combined with `-trap-mode inform`. |
| `-trap-snmpv3-user` | string | empty | **seed** | USM user name carried in `msgUserName`. Required when `-trap-snmp-version=v3`; USM has no anonymous identity. |
| `-trap-snmpv3-auth` | `none` \| `md5` \| `sha1` | `none` | **seed** | USM authentication protocol for notifications. Also selects the hash that localizes the privacy key (RFC 3414 §2.6). **Strict**: an unrecognised value is fatal at startup, unlike `-snmpv3-auth`, which logs and falls back to MD5. |
| `-trap-snmpv3-priv` | `none` \| `des` \| `aes128` | `none` | **seed** | USM privacy protocol for notifications. Requires an authentication protocol. USM defines no privacy-without-authentication security level. |
| `-trap-snmpv3-password` | string | empty | **seed** | USM authentication password. Required when `-trap-snmpv3-auth` is not `none`. **Visible in `ps`.** |
| `-trap-snmpv3-priv-password` | string | empty | **seed** | USM privacy password. Empty reuses `-trap-snmpv3-password`, matching the poll path's own fallback. **Visible in `ps`.** |
| `-trap-source-per-device` | bool | `true` | **global** | Use each device's IP as the UDP source address. **Required** in INFORM mode. An auto-start device fails its trap attach and its `traps` block is cleared; a REST `traps` block with `mode: inform` is rejected with 400. |
| `-trap-inform-timeout` | duration | `5s` | **seed** | Per-retry timeout in INFORM mode. |
| `-trap-inform-retries` | int | `2` | **seed** | Maximum retransmissions per INFORM before it's declared failed. |

The two password flags are the only secrets nl6 takes on the command line, and every local user can read them.
See the warning in [Receive SNMPv3 notifications](../ops/snmp-traps.md#receive-snmpv3-notifications).

**There is no `-trap-snmpv3-engine-id`.** Each device derives its own engine ID from its IPv4 address.
The `-trap-snmpv3-*` flags are separate from the `-snmpv3-*` poll flags, so a polled device and a trap from it report **different `snmpEngineID` values**.
See [SNMP trap reference → SNMPv3 notifications](snmp-traps.md#snmpv3-notifications).
`GET /api/v1/traps/status` reports each exporting device's derived engine ID under `snmpv3.engine_ids_by_device`, which is what a receiver's `createUser -e` line needs.

## gNMI dial-in flags

The gNMI subsystem is always-on by default and serves a read-only OpenConfig interfaces subset over gRPC + TLS on every device.
See [gNMI dial-in reference](gnmi.md) for path coverage, subscribe semantics, and `gnmic` invocation examples.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-gnmi-port` | int | `9339` | **global** | TCP port for the gNMI dial-in listener on each device. The listener serves **TLS** unless `-gnmi-tls=false`. |
| `-gnmi-disable` | bool | `false` | **global** | Disable the subsystem; no device listens on the gNMI port. |
| `-gnmi-tls` | bool | `true` | **global** | Serve dial-in over TLS with the simulator's shared self-signed certificate; clients need `--skip-verify` or `--tls-ca`. `false` serves plaintext gRPC instead. A client whose transport does not match the listener gets a completed TCP connection and no bytes. See [gNMI troubleshooting](../ops/validate-gnmi-collector.md#troubleshooting). |
| `-gnmi-catalog` | path | empty (shipped catalogues) | **global** | JSON gNMI path catalogue that replaces the catalogue of every device type that carries one (`resources/<type>/gnmi.json`). Types without a catalogue keep none. Read once at startup; a file that fails to load is fatal. See [gNMI catalogue files → Overrides](gnmi-catalogue.md#overrides). |

## NETCONF flags

NETCONF is off by default.
When enabled, two device types serve it.
`cisco_catalyst_9500` serves it over SSH.
`juniper_mx10004` serves it over SSH and over TLS (TLS 1.2, mutual authentication).
See [NETCONF reference](netconf.md).

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-netconf-enable` | bool | `false` | **global** | Enable the NETCONF subsystem: `cisco_catalyst_9500` over SSH on `-netconf-port`, `juniper_mx10004` over SSH on `-netconf-port` and over TLS on `-netconf-tls-port`. |
| `-netconf-port` | int | `830` | **global** | TCP port of the per-device NETCONF over SSH listener. |
| `-netconf-authorized-keys` | path | empty | **global** | OpenSSH `authorized_keys` file. Its keys log in as `simadmin` on every NETCONF SSH listener, next to the password. Read once at startup; an unreadable file or a line that is not a key stops the simulator. Port 22 keeps password login only. |
| `-netconf-tls-port` | int | `6513` | **global** | TCP port of the per-device NETCONF over TLS listener. |
| `-netconf-tls-client-ca` | path | empty | **global** | PEM file with the CA that must have signed NETCONF TLS client certificates. Requires `-netconf-enable`. With no CA the TLS listeners still bind, but every handshake is refused. Also settable at runtime with `PUT /api/v1/netconf/tls`. |
| `-netconf-tls-client-identity` | `fingerprint=username` | empty | **global** | One entry of the client identity table: the SHA-256 fingerprint of a client certificate, with or without the `04:` prefix, mapped to a NETCONF user. Repeat the flag for more entries. Requires `-netconf-enable`. |
| `-netconf-tls-default-username` | string | empty | **global** | NETCONF user for a client certificate missing from the identity table. Empty refuses such a certificate. Requires `-netconf-enable`. |
| `-netconf-callhome-client` | `host:port` | empty | **seed** | NETCONF client that auto-started `juniper_mx10004` devices dial with call home over SSH. Empty means no call home. Requires `-netconf-enable`. Applies only with `-auto-start-ip`. See [NETCONF reference](netconf.md#call-home). |
| `-netconf-callhome-device-id` | string | empty | **seed** | `DEVICE-ID` the call-home preamble carries. Empty means each device's sysName. Requires `-netconf-callhome-client`. |

## gNMI dial-out flags

Dial-out reverses the connection direction: the device dials a collector and pushes telemetry over a `gNMIReverse.Publish` stream.
Dial-out is per-device and opt-in, so the fleet can mix dial-in and dial-out devices.
See [gNMI dial-out reference](gnmi-dial-out.md) for wire protocol, modes, TLS, and the per-device `gnmi_dialout` REST block.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-gnmi-mode` | `dial-in` \| `dial-out` | `dial-in` | **seed** | gNMI mode for the auto-start batch. `dial-out` additionally pushes telemetry to `-gnmi-dialout-collector`; the dial-in listener keeps serving either way. |
| `-gnmi-dialout-collector` | string | empty | **seed** | Dial-out collector address (`host:port`). Required when `-gnmi-mode=dial-out`. |
| `-gnmi-dialout-flavor` | string | `gnmireverse` | **seed** | Dial-out wire flavor (Arista `gNMIReverse` is the only shipped flavor). |
| `-gnmi-dialout-encoding` | `json_ietf` \| `proto` | `json_ietf` | **seed** | Value encoding for pushed updates. |
| `-gnmi-dialout-sub-mode` | `sample` \| `on-change` | `sample` | **seed** | Subscription mode: fixed-interval snapshots or interface-state transitions. |
| `-gnmi-dialout-interval` | duration | `10s` | **seed** | SAMPLE cadence (clamped to a 1s floor). |
| `-gnmi-dialout-tls` | bool | `true` | **seed** | Use TLS to the collector (`false` = plaintext, Arista `-collector_tls=false` parity). |
| `-gnmi-dialout-tls-insecure` | bool | `false` | **seed** | Skip collector certificate verification (dev only). |
| `-gnmi-dialout-tls-ca` | string | empty | **seed** | PEM CA bundle to verify the collector against (empty = system roots). |
| `-gnmi-dialout-mtls` | bool | `false` | **seed** | Present the shared TLS certificate as a client cert (mutual TLS). |
| `-yang-push-collector` | `host:port` | empty | **seed** | YANG-Push over UDP-notif collector that auto-started `huawei_ne8000` devices stream to. Empty means off. Applies only with `-auto-start-ip`. |

## UDP syslog export flags

See [Syslog export how-to](../ops/syslog-export.md) for prerequisites and `netcat` smoke-test, and [Syslog export reference](syslog-export.md) for wire format and catalog JSON.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-syslog-collector` | string | empty | **seed** | Enable syslog export to this UDP collector (e.g. `192.168.1.10:514`) for the auto-start batch. Empty disables seeding; REST-created devices can still opt in via the `syslog` block. |
| `-syslog-format` | `5424` \| `3164` | `5424` | **seed** | Wire format. RFC 5424 is structured (recommended); RFC 3164 is legacy BSD. Per-device, so different devices can emit different formats to the same collector. |
| `-syslog-interval` | duration | `10s` | **global** | **Simulator-wide** mean firing interval (Poisson-distributed, not periodic). Every syslog-enabled device fires at this cadence. This flag is the only cadence: a per-device `interval` in a REST `syslog` block is rejected with 400. To silence a fleet use `-fidelity` (or `POST /api/v1/fidelity` at runtime), not a long interval. |
| `-syslog-global-cap` | int (rate) | `0` | **global** | Simulator-wide rate ceiling across scheduled fires. On-demand HTTP fires bypass the cap. `0` is unlimited. |
| `-syslog-catalog` | string | empty | **global** | Path to a JSON catalog; empty uses the embedded universal 6-entry catalog + per-type overlays from `resources/<slug>/syslog.json`. Setting this flag **disables per-type overlays**. The file becomes the sole catalog for every device. |
| `-syslog-transport` | `udp` \| `tcp` \| `tls` | `udp` | **seed** | Transport for the auto-start batch. `tls` is RFC 5425 (TCP inside TLS, port **6514** by default, octet-counting only); it verifies the collector and presents no certificate of its own. `tcp` is RFC 6587 syslog-over-TCP: one connection per device, reconnecting with capped backoff. Per-device via the REST `syslog.transport` field. See [Syslog export → TCP transport](syslog-export.md#tcp-transport-rfc-6587). |
| `-syslog-framing` | `octet-counting` \| `non-transparent` | empty (`octet-counting` under `tcp` and `tls`) | **seed** | RFC 6587 framing, used only when the transport is `tcp` or `tls`. Under `tls` an empty value defaults to `octet-counting` and any other value is rejected (RFC 5425 §4.3.1). Setting it while the transport is `udp` is **rejected at startup** rather than ignored. |
| `-syslog-tls-ca` | path | empty | **seed** | PEM CA bundle verifying the syslog collector under `-syslog-transport tls`. Empty uses the host's root store. Read **once at startup**; the per-device REST config carries the PEM inline (`tls.ca_pem`) rather than a path. |
| `-syslog-tls-insecure` | bool | `false` | **seed** | Skip verification of the collector's certificate. Development only. Requires `-syslog-transport tls`. |
| `-syslog-source-per-device` | bool | `true` | **global** | Use each device's IP as the source address. Per-device bind failures are non-fatal under **udp**: the exporter falls back to the shared socket with a warning. Under **tcp** and **tls** there is no shared-socket fallback, so setting this to `false` makes the attach **fail**; see [Syslog export → TCP transport](syslog-export.md#tcp-transport-rfc-6587). |

## Load-test scenario flags

Global switches for the [load-test scenario subsystem](loadtest-overview.md).
The scenarios themselves are driven over REST (`/api/v1/scenarios`); these flags shape the whole fleet at startup.

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-fidelity` | bool | `false` | **global** | Keep the fleet **silent**, with no autonomous flow / SNMP-trap / syslog / gNMI-dial-out push, except during a running scenario's `[T0,T1)` window, for a clean measurement window. Devices still answer polls; explicit on-demand fires still go through. Also togglable at runtime via `POST /api/v1/fidelity`, so bracketing a measurement does not require a restart; this flag is then the startup **default** rather than the value in force. See [Fidelity mode](../ops/loadtest-scenarios.md#fidelity-mode). |
| `-scenario-pen` | uint | `0` | **global** | IANA Private Enterprise Number for PEN-dependent scenario [run tags](loadtest-report-schema.md#run-tag-levers) (syslog SD-PARAM, SNMP enterprise varbind). `0` = unset → those levers degrade to window + source-IP isolation. |

## LLDP topology flag

Pre-load an inter-device LLDP link graph at startup.
The graph is also mutable at runtime via `POST` / `DELETE /api/v1/topology`.
See [LLDP topology reference](lldp-topology.md).

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-topology-config` | string | empty | **global** | Path to a JSON inter-device LLDP link graph (`{"links":[{"a":{"ip","ifindex"},"b":{"ip","ifindex"}}]}`). Loaded at startup; validation is syntactic only (device / ifIndex are resolved lazily at serve time). |

## DNS service-discovery flags

nl6 acts as a hidden DNS primary; a CoreDNS secondary transfers the zones.
Off by default.
See [DNS service-discovery reference](dns-service-discovery.md).

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-dns-enable` | bool | `false` | **global** | Enable the DNS service-discovery server. |
| `-dns-domain` | string | `nl6.local` | **global** | Forward zone apex (`<device-name>.<domain>`). |
| `-dns-listen` | string | `:5353` | **global** | Bind address (host:port) in the container's default netns. |
| `-dns-reverse-zone` | string | `42.10.in-addr.arpa` | **global** | Comma-separated `in-addr.arpa` reverse zone(s). IPs outside get an `A` but no `PTR`. |
| `-dns-notify` | string | empty | **global** | Comma-separated secondary NOTIFY targets (`host:port`); empty disables NOTIFY. |
| `-dns-debounce` | duration | `1s` | **global** | Quiescence window coalescing a burst of device changes into one serial bump + NOTIFY. |

## Continuous profiling flags

Off by default: with none of these set and no `POST /api/v1/profiling`, no profiler runs and `/debug/pprof/` answers `503`.
The gate is also switchable at runtime (`POST /api/v1/profiling`), so `-profiling-pyroscope` is the startup **default** rather than the value in force.
See [Continuous profiling](../ops/profiling.md).

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-profiling-pyroscope` | string | empty | **global** | Pyroscope push URL (`http://host:4040` or `https://`). Starts the `pyroscope-go` SDK at boot (CPU, goroutines, four heap views, tagged `service_name=nl6`, `version`, `hostname`) and opens the gated `/debug/pprof/` surface. An unparseable URL, a scheme other than `http`/`https`, or embedded credentials are fatal at startup, after `-help` and `-version` and before any subsystem starts. A Pyroscope that is down at boot is not a start failure (the SDK never touches the network at start); it shows as `sdk_errors` and `last_error` on `GET /api/v1/profiling` and as one log line per push. With this flag set, startup also refuses to run while `PYROSCOPE_ADHOC_SERVER_ADDRESS` is set, which the SDK would silently honour over the flag (without the flag, a runtime push refuses it instead). |
| `-profiling-force-gc` | bool | `true` | **global** | Let the SDK force a `runtime.GC()` before a heap snapshot when no collection ran during the upload interval. A forced GC costs about 29 ms at 30,000 devices. `false` sets the SDK's `DisableGCRuns`. |
| `-profiling-pyroscope-basic-auth` | string | empty | **global** | HTTP basic auth for the push as `user:pass`, both parts non-empty (the SDK sends no `Authorization` header when either is empty, so `user:` is refused rather than pushing unauthenticated). Requires `-profiling-pyroscope` and is sent only to that address (compared normalised): a REST-supplied `server_address` that differs is pushed to without it. Flag-only, never settable or echoed over REST. The value is visible to every local user through the process arguments (`/proc/<pid>/cmdline`, `docker inspect`, shell history). There is no file or environment form. |
| `-profiling-pyroscope-tenant` | string | empty | **global** | Pyroscope tenant ID (`X-Scope-OrgID`) for the push. Requires `-profiling-pyroscope`; flag-only, bound to the flag's address like the basic auth. |

## Examples

```bash
# Start the API server only, with no devices
sudo ./nl6

# Auto-create 5 devices starting from 192.168.100.1
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 5

# Custom API port and start IP
sudo ./nl6 -auto-start-ip 10.10.10.1 -auto-count 100 -port 9090

# Non-privileged SNMP port (no CAP_NET_BIND_SERVICE needed)
sudo ./nl6 -auto-start-ip 10.10.10.1 -auto-count 10 -snmp-port 1161

# SNMPv3. USM is implemented and verified against net-snmp, so all three
# security levels are reachable. The user and password both default to
# "simadmin"; -snmpv3-auth defaults to md5 and -snmpv3-priv to none.
sudo ./nl6 -snmpv3-engine-id 800000090300AABBCCDD
snmpget -v3 -l authNoPriv -u simadmin -a MD5 -A simadmin \
  10.42.0.1 1.3.6.1.2.1.1.1.0

# authPriv needs a privacy protocol on the fleet as well.
sudo ./nl6 -snmpv3-engine-id 800000090300AABBCCDD -snmpv3-auth sha1 -snmpv3-priv aes128
snmpget -v3 -l authPriv -u simadmin -a SHA -A simadmin -x AES -X simadmin \
  10.42.0.1 1.3.6.1.2.1.1.1.0

# Disable network namespace isolation
sudo ./nl6 -no-namespace -auto-start-ip 192.168.100.1 -auto-count 10

# Maintenance window: all interfaces admin-shutdown
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 10 -if-scenario 1

# Link failure: all interfaces admin-up but oper-down
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 10 -if-scenario 3

# Partial outage: 30% of interfaces oper-down
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 10 \
    -if-scenario 4 -if-failure-pct 30
```

