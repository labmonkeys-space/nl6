---
sidebar_label: "Flow export"
description: "The NetFlow v5, NetFlow v9, IPFIX and sFlow formats nl6 emits, with templates, field layouts, datagram sizing and the sFlow caveat."
---

# Flow export

nl6 emits synthetic flow telemetry in four protocols: **NetFlow v5** (Cisco), **NetFlow v9** (RFC 3954), **IPFIX** (RFC 7011), and **sFlow v5** (`sflow_version_5.txt`).
For deployment, collector setup, and `rp_filter` tuning see [Flow export how-to](../ops/flow-export.md); for the CLI flags see [CLI flags → Flow export](cli-flags.md#flow-export-flags).

## Architecture

- Per-device UDP sockets when `-flow-source-per-device=true` (the default).
  Otherwise a pool of **shared UDP sockets** keyed by `(collector, protocol)`.
  One ticker drives both.
- Each simulated device owns a flow cache populated with role-appropriate synthetic flows (edge router, DC switch, firewall, …).
- Batch pagination is protocol-aware (different header sizes, different record limits per UDP datagram).
- Template refresh is handled in v9 / IPFIX via the [`-flow-template-interval`](cli-flags.md#flow-export-flags) flag.

## Protocol details

| Protocol    | Version field | Template ID              | Record size                      | Timestamps                                    |
|-------------|---------------|--------------------------|----------------------------------|-----------------------------------------------|
| NetFlow v5  | `5`           | n/a (no template)        | 48 B / record (30 max per PDU)   | `SysUptime`-relative ms (First / Last)        |
| NetFlow v9  | `9`           | FlowSet ID 0             | 46 B / record                    | `SysUptime`-relative ms (FIRST / LAST_SWITCHED) |
| IPFIX       | `10`          | Set ID 2                 | 54 B / record                    | Absolute epoch ms (IE 152 / 153)              |
| sFlow v5    | `5` (XDR)     | n/a (self-describing)    | ~100 B / record typical (variable) | uptime (ms) + `sampling_rate` per sample    |

NetFlow v5, v9, and IPFIX all use the same core field set (bytes, packets, protocol, ToS, TCP flags, src/dst ports, src/dst IPv4, src/dst mask, ingress/egress interface, next-hop, src/dst AS, timestamps).
The v9 / IPFIX template carries a 19th field, `DIRECTION` / `flowDirection` (field type / IE 61), emitted as a constant `0x00` (**ingress**) on every record.
That is the shape of a real exporter running `ip flow ingress` on all interfaces.
Collectors that classify flows by direction (some drop direction-less flows from every flow query) ingest nl6 flows as `direction: ingress`.
NetFlow v5 bakes the core fields into a fixed 48-byte on-wire record (no direction field exists in v5) and has no template mechanism at all, so `-flow-template-interval` is a silent no-op under both v5 and sFlow.

## sFlow caveat

sFlow is a packet-sampling protocol built for real devices that observe real traffic.
nl6 has no packet stream to sample.
sFlow output is synthesised from the same `FlowCache` records the other protocols consume, re-wrapped as `FLOW_SAMPLE` records with a fixed, synthetic `sampling_rate` of `10 × FlowProfile.ConcurrentFlows`.
Collectors that multiply sample rate by captured packet count to estimate link utilisation will produce plausibly-shaped numbers that do not reflect any real traffic.
Use sFlow mode for collector-plumbing validation, not for link-volume benchmarks.

sFlow v5 emits one `FLOW_SAMPLE` per `FlowRecord` with a `sampled_header` flow-record carrying a synthesised IPv4 + UDP/TCP header derived from the 5-tuple.
On every tick it also emits `COUNTERS_SAMPLE` records for each interface's `if_counters`, a processor sample, and a memory sample.

### sFlow sub-agent id

Every sFlow datagram header carries a `sub_agent_id` (default `0`, single-agent).
Set it per device via the REST `flow.sub_agent_id` field, or `-flow-sub-agent-id` for the whole auto-start batch, so collectors that attribute flows by `(agent_address, sub_agent_id)` can be exercised with distinct sub-agent values.
Both datagram types a device emits (`FLOW_SAMPLE` and `COUNTERS_SAMPLE`) always carry the same value, and sequence numbers are already per-(agent, sub-agent).
Each nl6 device is its own agent, so per-group values (`POST` one batch per group) yield distinct `(agent_address, sub_agent_id)` tuples.
Ignored by the NetFlow / IPFIX encoders.

## Interface option records (NetFlow v9 / IPFIX)

With `options_interface_table` set on a device (or `-flow-option-interface-table` for the auto-start batch), the exporter additionally emits a Cisco-style **option interface-table**: on every template-refresh tick, one self-contained datagram carrying an options template (template ID 257; NF9 Options Template FlowSet ID 1 / IPFIX Options Template Set ID 3) plus one option data record per interface, with `interfaceName(82)` / `interfaceDescription(83)` resolved from the same `ifDescr` values the SNMP agent serves.
Collectors use these records to enrich flows with interface names **without polling SNMP**.

Two wire shapes are available; the names describe where the ifIndex lives:

| | `if-scoped` | `system-scoped` |
|---|---|---|
| ifIndex carrier | the scope (NF9 scope type Interface(2) / IPFIX `ingressInterface(10)` scope IE) | option field `INPUT_SNMP(10)`, system scope |
| String fields | `interfaceName(82)` + `interfaceDescription(83)` | `interfaceDescription(83)` only (matches real IOS-XR exporters) |
| Record size | 68 B | 40 B |
| Collector path exercised | scope resolution | field fallback |

Each device emits **one** shape; run two device groups with different shapes to cover both collector resolution paths.
String fields are fixed 32-byte NUL-padded values.
The options datagram advances the sequence counter per its protocol's rule: NetFlow v9 by 1 (RFC 3954 counts export packets), IPFIX by the number of Options Data Records it carries (RFC 7011 §3.1 counts Data Records, and an Options Data Record is one).
It counts toward `sent_packets` / `sent_bytes` but not `sent_records` (option records are metadata, not flows).
`send_failures` counts refused datagrams and, for an AVC device, records dropped because they fit no datagram; the drop is logged once per exporter.
Valid only under `netflow9` / `ipfix`; combining it with `netflow5` / `sflow` is rejected at validation.
Default off.

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

## NBAR2 application records (IPFIX only)

NBAR2 export adds Cisco layer-7 application fields to a device's IPFIX records.
Cisco calls the classifier NBAR2 and the export format AVC.
NBAR2 is a record format inside IPFIX, not a separate `protocol` value.
The status API and the socket pool report an NBAR2 device as `ipfix`.

Only two device types have NBAR2.
The export is conformant to RFC 7011 and RFC 6759 and is interop-tested against open decoders.
It is not Cisco-faithful.
A real IOS-XE router differs from nl6 in five recorded ways, listed under [Differences from IOS-XE](#differences-from-ios-xe-260102).

### Enabling NBAR2

Set `"nbar2": true` in a device's `flow` block.
The block must also set `protocol: "ipfix"`.
Any other protocol, including the `netflow9` default, is rejected with a 400.

| Type | OS | NBAR2 |
|---|---|---|
| `cisco_ios` | IOS | yes |
| `cisco_catalyst_9500` | IOS-XE | yes |
| `cisco_nexus_9500` | NX-OS | no |
| `cisco_crs_x` | IOS-XR | no |
| `asr9k` | IOS-XR | no |
| `cisco_asr9902` | IOS-XR | no |

The set is curated by type name, not derived from a slug prefix.
A request whose whole resolved type set lacks NBAR2 is rejected with a 400 naming the type and its OS.

A mixed round-robin batch is accepted.
Two rules apply to devices that cannot do what the request asks, and they differ:

| Device | Outcome |
|---|---|
| Cannot export flow at all | No flow block is attached. The device is skipped with a log line. |
| Exports flow but lacks NBAR2 | Keeps its flow block. Emits the plain IPFIX record, template 256, with `nbar2` cleared. Logged once per type. |

`GET /api/v1/devices` echoes `nbar2` only on devices that emit AVC records.
A device that degraded to plain IPFIX shows no `nbar2` field.
`GET /api/v1/flows/status` lists an NBAR2 device under its collector with `protocol: "ipfix"`.
The same response reports the resolved catalogs under `nbar2_catalogs_by_type`.
Each row carries `entries`, `oversized` when non-zero, and `source`.
`source` is `embedded`, `file:resources/<type>/nbar2.json` or `override:<path>`.

```bash
# 20 cisco_ios devices emitting Cisco AVC records to an IPFIX collector
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.3.1",
    "device_count": 20,
    "resource_file": "cisco_ios.json",
    "flow": {
      "collector": "192.168.1.10:4739",
      "protocol": "ipfix",
      "nbar2": true
    }
  }'
```

`resource_file` must carry the `.json` suffix.

The seed flag `-flow-nbar2` exists for the auto-start batch but is refused at startup on every boot today.
The auto-start batch is always built as `asr9k`, which has no NBAR2, and no flag selects another type.
The error names the REST remedy.

There is no per-device catalog path on the REST surface.
The catalog is chosen per device type, see [The catalog](#the-catalog).

### What a collector sees

An NBAR2 device sends data records under template 258. The first 54 bytes are byte-identical to the plain IPFIX record, template 256.

| Field | PEN | Length |
|---|---|---|
| the plain IPFIX record, template 256 | IANA | 54 bytes fixed |
| `applicationId` (IE 95) | IANA | 4 |
| `ciscoHTTPHost` (IE 12235) | 9 | variable, RFC 7011 §7 |
| `ciscoHTTPURIStatistics` (IE 9357) | 9 | variable, RFC 7011 §7 |

Cisco's 2015 AVC guide quotes the two PEN 9 fields as wire specifiers 45003 and 42125. Those are the IE ids with bit 15 set: 12235 + 32768 = 45003 and 9357 + 32768 = 42125.

**`applicationId`** is `engine << 24 | selector`, per RFC 6759. The shipped `http` entry has engine 3 and selector 80, so its id is `0x03000050`.
A collector shows that as 50331728 or as `3:80`.
Join on this id, not on the name.
A collector's own classification may disagree with `applicationName`.

**`ciscoHTTPHost`** always starts with the constant six bytes `03 00 00 50 34 02`.
The first four bytes are the `applicationId` of `http`.
The last two are Cisco's sub-application id 0x3402.
The hostname follows.
A record with no host carries exactly the six bytes.
The field is never empty.
The prefix is the same on every record, whatever the record's own `applicationId` says.
This is the layout the IOS-XE 26.01.02 reference capture shows on every record.

**`ciscoHTTPURIStatistics`** is the URI, a NUL byte, then a 2-byte big-endian hit count.
There is no trailing delimiter.
Cisco's guide leaves both the byte order and the delimiter open.
The reference capture confirms both.

Both PEN 9 fields carry binary bytes.
A collector that renders them as strings must keep non-printable characters.
In CESNET IPFIXcol2 that is the `nonPrintableChar` option.
The shipped `examples/ipfixcol2/ipfixcol2.xml` has it on.
With it off, IPFIXcol2 drops the non-printable bytes silently and shows the host as `P4www.example.com`.

**Template 259** is an options table describing every application the device can emit.

| Field | Length |
|---|---|
| `applicationId` (IE 95, scope) | 4 |
| `applicationName` (IE 96) | 24 |
| `applicationDescription` (IE 94) | 55 |

It is sent on the template refresh cadence, `-flow-template-interval`.
When the device also has an interface option table configured, template 257 is sent on the same cadence.
Without one, only 259 is sent.

The IPFIX Sequence Number counts Data Records, options records included, per RFC 7011 §3.1. That is the same rule the plain IPFIX encoder follows.

### Application-first generation

For an NBAR2 device the catalog decides protocol and destination port, not the `FlowProfile`.
Each flow draws an application by weight.
The application fixes the protocol and port.
The flow then draws a host and a URI by weight from that application's lists.
The exporter therefore never emits a record on port 443 tagged as an application that runs elsewhere.

The profile's volume knobs still apply.
Concurrent flows, lifetimes and per-device record ceilings come from the `FlowProfile`.
Only the port and protocol distribution comes from the catalog.

The host and URI draws happen on every flow, even for an entry with no host or URI list.
A seeded device therefore reproduces its stream exactly.
Adding a host list to one entry does not shift any other entry's stream.

Enabling NBAR2 on one device does not change what any other device emits.

### The catalog

`resources/_common/nbar2.json` is compiled into the binary.
`resources/<type>/nbar2.json` overlays it for that type.
The overlay follows the `extends` rule the trap and syslog catalogs use.
With `extends: true`, the default, a same-name entry replaces the universal one and new names are appended.
With `extends: false` the per-type file is the whole catalog for that type.

`-nbar2-catalog <path>` replaces the universal catalog and suppresses every overlay.
It is read once at startup.
`POST /api/v1/resources/reload` does not reload it.
A catalog edit needs a restart.

```json
{
  "comment": "optional",
  "extends": true,
  "entries": [
    {
      "name": "http",
      "description": "Hypertext Transfer Protocol",
      "engine": 3,
      "selector": 80,
      "proto": "tcp",
      "dst_port": 80,
      "weight": 30,
      "hosts": [ {"value": "www.example.com", "weight": 6} ],
      "uris":  [ {"value": "/index.html", "weight": 4} ]
    }
  ]
}
```

| Field | Required | Value |
|---|---|---|
| `comment` | no | Free text. |
| `extends` | no | Per-type files only. Default `true`. |
| `name` | yes | Unique in the merged catalog. At most 24 bytes. Becomes `applicationName`. |
| `description` | yes | At most 55 bytes. Becomes `applicationDescription`. |
| `engine` | yes | `3` IANA-L4, `6` user-defined or `13` PANA-L7, per RFC 6759 §4.1. Any other value fails the load. |
| `selector` | yes | `0` to `16777215`. `engine << 24 \| selector` must be unique in the merged catalog. |
| `proto` | yes | `tcp`, `udp`, `icmp` or an integer `0` to `255`. |
| `dst_port` | tcp, udp | `0` to `65535`. Under `icmp` omit it or set `0`. |
| `weight` | no | Draw weight. `0` or omitted draws as `1`. Negative fails the load. |
| `hosts` | no | Weighted values for `ciscoHTTPHost`. |
| `uris` | no | Weighted values for `ciscoHTTPURIStatistics`. |

A refused load names the file, the entry and the rule that failed.

The shipped entries all use engine 3 with the IANA port as selector.
RFC 6759 defines that mapping, so no Cisco protocol-pack number is needed to verify it.
Cisco's PANA-L7 selectors are protocol-pack data.
The reference capture sourced three of them: `unknown` `0x0d000001`, `binary-over-http` `0x0d0001af` and `ping` `0x0d0001df`.
None is shipped.
An operator catalog is where they go.

#### Size budget

At load, each entry's worst-case record is encoded through the production encoder.
The worst case is the entry's longest host and longest URI.
It must fit an empty datagram at the `-datagram-mtu` payload budget.
The budget used is the IPv6 one, the smaller of the two address families.
An entry that passes therefore fits a datagram to any collector.

An entry that cannot fit is disabled, not rejected.
It stays out of generation and out of the application table.
The startup log names it with its size, the gap and the MTU that would admit it.
Loading does not fail on size, because the budget follows an operator-settable MTU.
A device whose resolved catalog has no usable entry is refused at attach with that reason.
The remedy is a larger `-datagram-mtu` or shorter hosts and URIs, followed by a restart.

No shipped entry is disabled at any legal MTU.
At the 576-byte floor the IPv6 budget is 528 bytes, and every shipped entry fits it.

### Interoperability

`make test-interop-ipfix` decodes nl6's AVC records with CESNET IPFIXcol2 using libfds's own Cisco element definitions.
The two PEN 9 fields resolve by name, as `cisco:appHTTPHost` and `cisco:appHTTPUriStatistics`.
An `en9:idNNNN` field name in a collector's output means its element definitions lack them.
The gate reconciles a scenario report against the collector's records with no tolerance.

### Differences from IOS-XE 26.01.02

The reference is a Cisco Catalyst 8000V running IOS-XE 26.01.02.
nl6 matches its IE 9357 layout, application table string lengths, `http` id, sequence arithmetic and HTTP host prefix.
Five differences remain.
Every open decoder tried reads nl6's records correctly.

| | IOS-XE 26.01.02 | nl6 | What a collector sees |
|---|---|---|---|
| Record model | A connection record. Template 258 has 17 fields including `connectionId` (PEN 9 IE 12242, 4 bytes, zero on ICMP). Match fields first, then the two variable-length fields, then counters. URI statistics before host. | The 54-byte unidirectional record, then `applicationId`, host, URI statistics. No connection id. | Different field order and no connection id to join on. This is the one difference that changes what a collector computes. |
| Where host and URI appear | On the ingress-direction record of an HTTP request only. The reverse record carries the six-byte host prefix and an empty URI. | On every AVC record. | Layer-7 values on both directions. |
| URI depth | First path segment only. `/api/v1` arrives as `/api`. | Full catalog value, such as `/api/v1/items`. | Longer URIs than a router produces. |
| Application table | 1560 rows, two-thirds engine 13. Reclassifies HTTP mid-connection to `binary-over-http` and emits a second record. | Every entry is engine 3. One record per flow with a stable id. | Fewer applications and no mid-flow reclassification. |
| Template ids and option widths | Interface table under 256 with 33-byte name, 65-byte description and egressInterface. Application table under 257. Data under 258. | Interface table under 257 with 32 and 32 and no egressInterface. Application table under 259. Data under 258. | The option-table ids collide with Cisco's numbering. Decode by template content, not by id. |

## Starting flow export

Starting export, per-device source IPs and their prerequisites are covered in the [flow export how-to](../ops/flow-export.md#start-flow-export).
The per-device `flow` block of `POST /api/v1/devices` is in [Web API → Per-device export blocks](web-api.md#per-device-export-blocks).

## How much flow a device emits

Export volume is a property of the flow cache, not of the export cadence:

```
records/s  ≈  ConcurrentFlows / mean-flow-lifetime

mean-flow-lifetime = mean of  min(active-timeout, flow-duration + inactive-timeout)
```

Each flow gets a duration sampled from the device profile.
A flow still running when it reaches the **active timeout** is exported and restarted.
A flow that has ended and then sat idle for the **inactive timeout** is exported then.
Under the shipped edge-router profile (durations U(0.2s, 120s), 30s active, 15s inactive) about 92 % leave by the active timeout and 8 % by the inactive one.
The mean cached lifetime is near 29s.
The periodic sweep adds about half a tick of residency, so at the 5s default tick the edge-router profile (128 concurrent flows) exports about 4.1 records/s per device.

To raise or lower volume, change the concurrent-flow count or the timeouts.

### Emission shape

The **active timeout is jittered per flow**, by ±25 % of its configured value.
A 30s active timeout therefore produces deadlines spread over 22.5s to 37.5s.
`-flow-active-timeout` sets a mean, not an exact deadline.
A collector rule keyed on flows arriving at exactly the configured active timeout sees a spread instead of a spike.
The jitter lowers the mean lifetime by 0.05 % to 1.18 % across the shipped profiles, most on the campus-switch profile.

A scenario sizing a cache to hit a requested rate divides by the residency (lifetime plus half a tick), not the lifetime.
The per-device scenario ceiling is about 8.1 to 9.2 records/s at the 5s default tick.

### Tick interval and datagrams

`-flow-tick-interval` sets how finely the stream is cut into datagrams, not how much of it there is.
A flow can sit cached up to one interval past its deadline, so a slower tick reduces the rate somewhat.
The reduction is bounded by the interval rather than proportional to it.
Treat rate predictions at a coarse cadence as approximate.
Setting the tick close to or above the mean flow lifetime is not useful: every flow then lives about one tick and the cache turns over wholesale.
A value of zero or less is refused at startup.
A value above 1h is not rejected: nl6 logs `flow export: ignoring out-of-range tick interval` at startup and runs at the 5s default.

A slower tick puts more records in each tick, up to the MTU.
NetFlow v9 fits 31 records per datagram, so a 128-record tick is emitted as roughly five back-to-back datagrams.
Cadence therefore controls burst *size* at the collector.

The per-datagram record count follows from the payload budget, which is the MTU minus the IP and UDP headers.
At the default 1500 MTU that is 1472 bytes for an IPv4 collector and 1452 for IPv6; both move with `-datagram-mtu`.
nl6 paginates so the whole frame fits the MTU and no export datagram is IP-fragmented.
A single lost fragment discards the entire datagram, and some collectors and middleboxes drop fragments outright.

**NetFlow v5 does not scale with the MTU.** Cisco v5 caps a datagram at 30 records regardless of how much space is available, so a v5 exporter stays at 30 records and roughly 1464 bytes whatever `-datagram-mtu` is set to.
Raising the MTU for a jumbo path increases v9 and IPFIX datagram size but leaves v5 emitting the same number of the same-sized datagrams.

The MTU defaults to 1500.
What it governs beyond flow and when to lower it are in [CLI flags → Datagram MTU](cli-flags.md#datagram-mtu).

### Fleet arrival shape

Each device is swept once per tick interval, at its own phase within the period, so a collector sees a near-flat stream of small bursts.

| Rule | Value |
|---|---|
| Phase slots per tick interval | 50 (100ms each at the 5s default) |
| Sub-period floor | 50ms. A sub-second `-flow-tick-interval` gets fewer slots; a period at or under 50ms is a single slot. |
| Phase source | Derived from the device IP, so consecutive IPs spread across the slots and a seeded device reproduces its stream. |
| Scenario-owned ticker | Follows the same rule. |
| `-flow-tick-sync` | Sweeps every device on one firing, so the fleet exports in one burst per interval. |

Use `-flow-tick-sync` only to model a restart storm or a traffic event, where many routers flush their caches together.
Under it a capacity test measures burst absorption, not sustained throughput, so label such a run as that scenario.

## Status API

```bash
curl http://localhost:8080/api/v1/flows/status
```

Returns an array-of-collectors aggregated by `(collector, protocol)`:

```json
{
  "success": true,
  "message": "Success",
  "data": {
    "collectors": [
      {"collector": "192.168.1.10:4739", "protocol": "ipfix",    "devices": 50, "sent_packets": 8123, "sent_bytes": 12123456, "sent_records": 243690, "send_failures": 0},
      {"collector": "192.168.1.20:6343", "protocol": "sflow",    "devices": 20, "sent_packets": 3100, "sent_bytes":  5560000, "sent_records":  62000, "send_failures": 2}
    ],
    "devices_exporting": 70,
    "last_template_send": "2026-04-23T10:35:00Z",
    "tick_synchronized": false,
    "tick_phase_slots": 50,
    "nbar2_catalogs_by_type": {
      "_universal": {"entries": 7, "source": "embedded"},
      "cisco_ios":  {"entries": 8, "source": "file:resources/cisco_ios/nbar2.json"}
    }
  }
}
```

The body is the standard `{success, message, data}` envelope.

| Field | Meaning |
|-------|---------|
| `collectors[]` | One record per `(collector, protocol)` tuple that ever had a device. Deleted-device counters persist in the aggregate until process exit. |
| `collectors[].devices` | Count of live exporters for this tuple. `0` means no live device but the aggregate remembers prior fires. |
| `collectors[].sent_packets` / `sent_bytes` / `sent_records` | Cumulative across live and deleted exporters for this tuple, monotonic within the subsystem lifecycle. `sent_*` means the datagram **reached the kernel**. |
| `collectors[].send_failures` | Datagrams the kernel refused. A refused datagram is counted here once and in none of the `sent_*` fields, so a down collector shows up here. |
| `devices_exporting` | Total live exporters across all tuples. |
| `last_template_send` | ISO-8601 timestamp of the most recent template emission (NetFlow v9 and IPFIX only). |
| `tick_synchronized` | `true` when the running ticker sweeps every device on one firing (`-flow-tick-sync`, or a tick interval at or under the 50ms sub-period floor), so the fleet exports in one burst per interval. `false` when devices are spread over `tick_phase_slots` phase slots within the interval. Reports the running ticker, not the flag. See [Fleet arrival shape](#fleet-arrival-shape). |
| `tick_phase_slots` | Number of phase slots the tick interval is divided into (`50` at the 5s default; `1` when synchronized). |
| `nbar2_catalogs_by_type` | Resolved NBAR2 application catalogs, keyed by `_universal` and per-type slug. Each value carries `entries`, `oversized` (entries the load-time dry render disabled, omitted when zero) and `source`. Absent when no NBAR2 catalog loaded. |

An NBAR2 device and a plain IPFIX device to the same collector share one `ipfix` row; the collector tells them apart by template id.

Flow status has no `subsystem_active` field.
`collectors: []` means no device with a `flow` block has attached yet.
