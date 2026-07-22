# Flow export reference

nl6 emits synthetic flow telemetry in four protocols: **NetFlow v5**
(Cisco), **NetFlow v9** (RFC 3954), **IPFIX** (RFC 7011), and **sFlow v5**
(`sflow_version_5.txt`). This page covers the protocol-level details. For
deployment, collector setup, and `rp_filter` tuning see
[Flow export (operator guide)](../ops/flow-export.md); for the CLI flags see
[CLI flags → Flow export](cli-flags.md#flow-export-flags).

## Architecture

- One **shared UDP socket** per host (or per-device sockets when
  `-flow-source-per-device=true`, the default), driven by a single ticker
  goroutine in `flow_exporter.go`.
- Each simulated device owns a `FlowCache` populated with
  role-appropriate synthetic flows (edge router, DC switch, firewall, …).
- `FlowEncoder` is a protocol-agnostic interface; `netflow5.go`,
  `netflow9.go`, `ipfix.go`, and `sflow.go` implement it.
- Batch pagination is protocol-aware (different header sizes, different
  record limits per UDP datagram).
- Template refresh is handled in v9 / IPFIX via the
  [`-flow-template-interval`](cli-flags.md#flow-export-flags) flag.

## Protocol details

| Protocol    | Version field | Template ID              | Record size                      | Timestamps                                    |
|-------------|---------------|--------------------------|----------------------------------|-----------------------------------------------|
| NetFlow v5  | `5`           | n/a (no template)        | 48 B / record (30 max per PDU)   | `SysUptime`-relative ms (First / Last)        |
| NetFlow v9  | `9`           | FlowSet ID 0             | 46 B / record                    | `SysUptime`-relative ms (FIRST / LAST_SWITCHED) |
| IPFIX       | `10`          | Set ID 2                 | 54 B / record                    | Absolute epoch ms (IE 152 / 153)              |
| sFlow v5    | `5` (XDR)     | n/a (self-describing)    | ~100 B / record typical (variable) | uptime (ms) + `sampling_rate` per sample    |

NetFlow v5, v9, and IPFIX all use the same core field set (bytes, packets,
protocol, ToS, TCP flags, src/dst ports, src/dst IPv4, src/dst mask,
ingress/egress interface, next-hop, src/dst AS, timestamps). The v9 / IPFIX
template carries a 19th field, `DIRECTION` / `flowDirection` (field type /
IE 61), emitted as a constant `0x00` (**ingress**) on every record — the
shape of a real exporter running `ip flow ingress` on all interfaces.
Collectors that classify flows by direction (some drop direction-less
flows from every flow query) ingest nl6 flows as
`direction: ingress`. NetFlow v5 bakes the core fields into a fixed 48-byte
on-wire record (no direction field exists in v5) and has no template
mechanism at all, so `-flow-template-interval` is a silent no-op under both
v5 and sFlow.

## sFlow caveat

sFlow is a packet-sampling protocol built for real devices that observe real
traffic. nl6 has no packet stream to sample — sFlow output is
synthesised from the same `FlowCache` records the other protocols consume,
re-wrapped as `FLOW_SAMPLE` records with a fixed, synthetic `sampling_rate`
of `10 × FlowProfile.ConcurrentFlows`. Collectors that multiply sample rate
by captured packet count to estimate link utilisation will produce
plausibly-shaped numbers that do not reflect any real traffic. Use sFlow
mode for collector-plumbing validation, not for link-volume benchmarks.

sFlow v5 emits one `FLOW_SAMPLE` per `FlowRecord` with a `sampled_header`
flow-record carrying a synthesised IPv4 + UDP/TCP header derived from the
5-tuple. On every tick it also emits `COUNTERS_SAMPLE` records (Phase 2)
for each interface's `if_counters`, a processor sample, and a memory sample.

### sFlow sub-agent id

Every sFlow datagram header carries a `sub_agent_id` (default `0`,
single-agent). Set it per device via the REST `flow.sub_agent_id` field —
or `-flow-sub-agent-id` for the whole auto-start batch — so collectors
that attribute flows by `(agent_address, sub_agent_id)` can be exercised
with distinct sub-agent values. Both datagram types a device emits
(`FLOW_SAMPLE` and `COUNTERS_SAMPLE`) always carry the same value, and
sequence numbers are already per-(agent, sub-agent) — each nl6 device is
its own agent, so per-group values (`POST` one batch per group) yield
distinct `(agent_address, sub_agent_id)` tuples. Ignored by the NetFlow /
IPFIX encoders.

## Interface option records (NetFlow v9 / IPFIX)

With `options_interface_table` set on a device (or
`-flow-option-interface-table` for the auto-start batch), the exporter
additionally emits a Cisco-style **option interface-table**: on every
template-refresh tick, one self-contained datagram carrying an options
template (template ID 257; NF9 Options Template FlowSet ID 1 / IPFIX
Options Template Set ID 3) plus one option data record per interface —
`interfaceName(82)` / `interfaceDescription(83)` resolved from the same
`ifDescr` values the SNMP agent serves. Collectors use these records to
enrich flows with interface names **without polling SNMP**.

Two wire shapes are available; the names describe where the ifIndex lives:

| | `if-scoped` | `system-scoped` |
|---|---|---|
| ifIndex carrier | the scope (NF9 scope type Interface(2) / IPFIX `ingressInterface(10)` scope IE) | option field `INPUT_SNMP(10)`, system scope |
| String fields | `interfaceName(82)` + `interfaceDescription(83)` | `interfaceDescription(83)` only (matches real IOS-XR exporters) |
| Record size | 68 B | 40 B |
| Collector path exercised | scope resolution | field fallback |

Each device emits **one** shape; run two device groups with different
shapes to cover both collector resolution paths. String fields are fixed
32-byte NUL-padded values. The options datagram advances the sequence
counter by 1 (both protocols) and counts toward `sent_packets` /
`sent_bytes` but not `sent_records` (option records are metadata, not
flows). Valid only under `netflow9` / `ipfix` — combining it with
`netflow5` / `sflow` is rejected at validation. Default off; devices
without the field emit byte-identical output to previous releases.

```bash
# 20 devices emitting NetFlow v9 + an if-scoped option interface-table
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.2.1",
    "device_count": 20,
    "flow": {
      "collector": "192.168.1.10:2055",
      "protocol": "netflow9",
      "options_interface_table": "if-scoped"
    }
  }'
```

## Per-device source IP

By default (`-flow-source-per-device=true`), each device binds its own UDP
socket inside the `nl6sim` namespace so the collector observes flow packets
with the **device's IP as the source address**, not the simulator host's.
This makes per-device attribution work out of the box on collectors that key
on the exporter source IP (OpenNMS, Elastiflow, nfcapd, …).

Set the flag to `false` to fall back to a single shared socket bound in the
host namespace.

See [Flow export (operator guide)](../ops/flow-export.md#prerequisites-for-per-device-source-ip)
for the prerequisites (iptables `FORWARD` rule, route to the collector from
the namespace, collector-side `rp_filter` tuning).

## Starting flow export

Flow export is opt-in per device. There are two ways to configure it:

### 1. CLI seed (auto-start batch)

The `-flow-*` flags seed auto-created devices. Each device in the batch
gets the same collector, protocol, and timeouts.

```bash
# NetFlow v9 → 192.168.1.10:2055, 100 auto-created devices
sudo ./nl6 \
  -auto-start-ip 10.0.0.1 -auto-count 100 \
  -flow-collector 192.168.1.10:2055 \
  -flow-protocol netflow9

# Mixed fleet isn't achievable via CLI — use the REST body.
```

### 2. REST body (per-device)

`POST /api/v1/devices` accepts an optional `flow` block on each request.
Devices in different requests can point at different collectors or emit
different protocols.

```bash
# One batch of 50 emitting IPFIX to collector A
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.0.1",
    "device_count": 50,
    "flow": {
      "collector": "192.168.1.10:4739",
      "protocol": "ipfix",
      "active_timeout": "30s"
    }
  }'

# Second batch of 20 emitting sFlow to collector B — same process,
# /api/v1/flows/status reports both as separate collector records.
# sub_agent_id tags this group's datagram headers (default 0).
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.1.1",
    "device_count": 20,
    "flow": {
      "collector": "192.168.1.20:6343",
      "protocol": "sflow",
      "sub_agent_id": 2
    }
  }'
```

The `flow` block is **optional** on every request — omit it and the
device doesn't export.

**Duration fields** (`tick_interval`, `active_timeout`,
`inactive_timeout`) require **Go duration strings** (`"5s"`, `"30s"`,
`"1m30s"`). Integer seconds (`"tick_interval": 5`) are rejected with
400 — a deliberate mismatch with the `-flow-tick-interval` / `-flow-*-timeout`
CLI flags, which take integer seconds.

See [Web API → POST /api/v1/devices](web-api.md#create-devices) for the
full per-device schema.

## Status API

```bash
curl http://localhost:8080/api/v1/flows/status
```

Returns an array-of-collectors aggregated by `(collector, protocol)`:

```json
{
  "subsystem_active": true,
  "collectors": [
    {"collector": "192.168.1.10:4739", "protocol": "ipfix",    "devices": 50, "sent_packets": 8123, "sent_bytes": 12123456, "sent_records": 243690},
    {"collector": "192.168.1.20:6343", "protocol": "sflow",    "devices": 20, "sent_packets": 3100, "sent_bytes":  5560000, "sent_records":  62000}
  ],
  "devices_exporting": 70,
  "last_template_send": "2026-04-23T10:35:00Z"
}
```

`subsystem_active=false` with `collectors: []` means flow export never
ran (the subsystem starts on-demand when the first device with a `flow`
block attaches). See [Web API → Flow export status](web-api.md#flow-export-status)
for the full field reference.
