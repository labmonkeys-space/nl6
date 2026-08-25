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

## How much flow a device emits

Export volume is a property of the flow cache, not of the export cadence:

```
records/s  ≈  ConcurrentFlows / mean-flow-lifetime

mean-flow-lifetime = mean of  min(active-timeout, flow-duration + inactive-timeout)
```

Each synthetic flow is given a duration sampled from the device profile. A flow still running when it reaches the **active timeout** is exported and restarted; a flow that has ended and then sat idle for the **inactive timeout** is exported then. Under the shipped edge-router profile (durations U(0.2s, 120s), 30s active, 15s inactive) about 92 % leave by the active timeout and 8 % by the inactive one, giving a mean cached lifetime near 29s.

The **active timeout is jittered per flow**, by ±25 % of its configured value. A 30s active timeout therefore produces deadlines spread over 22.5s to 37.5s rather than landing on exactly 30s. The jitter is symmetric. It does not move the mean lifetime, so it changes when records leave, not how many. See [Changed in nl6#462: emission shape](#changed-in-nl6462-emission-shape) for why.

Expiry is noticed by a periodic sweep. A flow's real residency is therefore the mean lifetime **plus about half a tick interval**, because it waits for the sweep that notices its deadline. That term matters for pacing. A scenario sizing a cache to hit a requested rate divides by the residency, not the lifetime.

`-flow-tick-interval` sets how finely that stream is cut into datagrams, not how much of it there is. Because export polls, a flow can sit cached up to one interval past its deadline, so a slower tick reduces the rate somewhat — bounded by the interval rather than proportional to it. Measured across a 30x cadence range:

| tick | records/s | mean records per tick |
|---|---|---|
| 1s | 4.37 | 4 |
| 5s | 4.24 | 21 |
| 15s | 3.94 | 59 |
| 30s | 3.63 | 109 |

Note "more records per datagram" holds only up to the MTU: NetFlow v9 fits about 31 records per datagram, so a 128-record tick is emitted as roughly five back-to-back datagrams rather than one large one. Cadence therefore controls burst *size* at the collector, which is the quantity a collector's capacity actually responds to.

Setting the tick close to or above the mean flow lifetime is not useful — every flow then lives about one tick and the cache turns over wholesale. Values above 1h are rejected.

To raise or lower volume, change the concurrent-flow count or the timeouts.

### Changed in nl6#446: cadence and volume both moved

> **Measured on the wire.** The emission model here was derived by reading the code and simulating the loop. Two of its predictions were then checked against a packet capture, and the rest were not — the distinction matters, so it is drawn explicitly below.
>
> The capture ran on a **simulated** fleet: one nl6 device of type `cisco_ios` (a simulated device type, not a physical router) on a KVM virtual machine, 300s per cell, netflow9, comparing binaries built from the two commits either side of this change.
>
> | cell | measured | model | delta |
> |---|---|---|---|
> | pre-change, 5s cadence | 6.07 rec/s, **40 of 54 ticks silent** | 6.40 | −5.2 % |
> | post-change, 5s cadence | 4.12 rec/s, **0 of 58 silent** | 4.24 | −2.8 % |
> | pre-change, 30s cadence | 6.09 rec/s | — | flag inert, confirmed |
> | post-change, 30s cadence | 3.03 rec/s | 3.63 | **−16.5 %** |
>
> The rows of the cadence table above at 1s and 15s were **not** captured; they are model output.
>
> What the capture establishes: the flag really was inert (5s and 30s gave the same rate before the change), the cohort sawtooth really existed (roughly 3 of every 4 ticks emitted nothing, the emitting ones carrying the whole cache), and the volume ratio is 0.679 against the 0.66 stated here.
>
> The model runs about 5 % hot in every cell, which is expected — it advances time in exact tick increments with no scheduling jitter or warm-up truncation, so it counts expiries the wire narrowly misses.
>
> **The 30s cell is the exception and is not explained by that.** A 16.5 % shortfall is larger than jitter accounts for. Capture-side packet loss was the leading alternative and is **excluded**: NetFlow v9 carries a per-exporter datagram sequence number, and all four captures are sequence-continuous with zero gaps, so nothing was dropped between the exporter and the measurement. The remaining candidate is the model's own quantisation — at a 30s cadence against a ~29s mean lifetime the cache turns over wholesale each tick, so a flow whose lifetime lands just past a boundary slips a whole period, which the model resolves identically every time and real timing does not. That is a hypothesis, not a finding. Treat coarse-cadence rate predictions as approximate, which is a further reason to keep the tick well below the mean flow lifetime.

Two independent corrections landed together. **Both change the load a given configuration offers**, so measurements taken across this boundary are not comparable on the flow axis. Reports carry `nl6_version`, so the boundary stays identifiable.

| | before | after |
|---|---|---|
| **cadence** — deployments setting `-flow-tick-interval` | flag inert; every deployment ticked at 5s | the configured cadence applies |
| **volume** — **every** flow deployment, flag or not | ~6.4 records/s per device | **~4.2 records/s** (about 0.66x) |
| **shape** | whole cache exported on one tick, then several silent ticks | records on every tick, at every cadence |

The volume change reaches deployments that set no flag at all, which makes it the wider-reaching of the two.

It happened because a flow's "last seen" time was pinned to its creation instant, so every flow looked idle from birth. Expiry collapsed to whichever timeout was smaller, `-flow-active-timeout` could not bind above `-flow-inactive-timeout`, and because a cache refill created every flow at one instant, the whole cache expired together — a burst followed by silence that no real exporter produces. Flow lifetimes now derive from the duration the profile already sampled.

### Changed in nl6#462: emission shape

Volume is unchanged. **Timing is not**, and it moves for every flow deployment whether or not a scenario runs.

| | before | after |
|---|---|---|
| **volume** | ~4.2 records/s per device | unchanged |
| **active-timeout deadline** | exactly the configured value | uniform over ±25 % of it |
| **shape** | a disturbance repeats every flow lifetime, indefinitely | it fades within about four lifetimes |
| **per-device scenario ceiling** | ~8.5–9.7 records/s | ~8.1–9.2 records/s |

**Why the deadline was a problem.** Flow creation is driven by expiry. The cache refills exactly what it lost. When the expiry offset is also deterministic, the creation profile becomes a pure delay of itself:

```
expiries at t  →  refills at t  →  expiries at t+30s  →  refills at t+30s  →  …
```

There is no mixing term, so nothing damps. Any irregularity is re-emitted every lifetime forever. A scenario arming, a re-pacing, a scheduling hiccup: all of them persist. Real exporters do not behave this way, and the reason is exactly the coupling. Their flows are created by arriving traffic, a process independent of what the cache happens to be releasing.

Measured as autocorrelation of per-tick record counts across multiples of the flow lifetime, after re-pacing a device:

| | 1 lifetime | 2 | 3 | 4 |
|---|---|---|---|---|
| before, GPU-server profile | +0.96 | +0.94 | +0.91 | **+0.89** |
| before, edge-router profile | +0.87 | +0.77 | +0.68 | **+0.59** |
| after, edge-router profile | +0.23 | +0.18 | +0.08 | **+0.01** |

**What this means for a collector.** A rule keyed on flows arriving at exactly the configured active timeout will now see a spread instead of a spike. `-flow-active-timeout` sets a mean, not an exact deadline.

**Why the ceiling moved.** The stated per-device scenario ceiling was `MaxFlows / mean-flow-lifetime`, which omitted the sweep delay described above. Pacing now divides by the real residency. The ceiling is about 5 % lower, and a paced rate is actually achieved. Before this, pacing ran a few percent low at every rate, which is what [nl6#462](https://github.com/labmonkeys-space/nl6/issues/462) was reporting.

The old figure was not wrong by accident. With a deterministic deadline, flows created on a tick boundary expired on a tick boundary, so the sweep genuinely cost nothing. That alignment was an artifact of synthetic timing, and the jitter removed it.

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
