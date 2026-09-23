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

Each device emits **one** shape; run two device groups with different shapes to cover both collector resolution paths.
String fields are fixed 32-byte NUL-padded values.
The options datagram advances the sequence counter per its protocol's rule: NetFlow v9 by 1 (RFC 3954 counts export packets), IPFIX by the number of Options Data Records it carries (RFC 7011 §3.1 counts Data Records, and an Options Data Record is one).
It counts toward `sent_packets` / `sent_bytes` but not `sent_records` (option records are metadata, not flows).
`send_failures` counts refused datagrams and, for an AVC device, records dropped because they fit no datagram; the drop is logged once per exporter through its own gate, separate from encoder errors.
Valid only under `netflow9` / `ipfix`; combining it with `netflow5` / `sflow` is rejected at validation.
Default off; devices without the field emit byte-identical output to previous releases.

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
This section uses NBAR2 for the feature and AVC for the record layout.
NBAR2 is a record format carried inside the IPFIX protocol.
It is not a separate `protocol` value.
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

The set is curated by name in `nbar2_capability.go`, with a reason per row.
It is never derived from a slug prefix.
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
Refusing is deliberate.
A batch that booted and silently emitted plain IPFIX under an NBAR2 flag would look configured while doing nothing.

There is no per-device catalog path on the REST surface.
The catalog is chosen per device type, see [The catalog](#the-catalog).

### What a collector sees

An NBAR2 device sends data records under template 258.
The first 54 bytes are byte-identical to the plain IPFIX record, template 256.

| Field | PEN | Length |
|---|---|---|
| the plain IPFIX record, template 256 | IANA | 54 bytes fixed |
| `applicationId` (IE 95) | IANA | 4 |
| `ciscoHTTPHost` (IE 12235) | 9 | variable, RFC 7011 §7 |
| `ciscoHTTPURIStatistics` (IE 9357) | 9 | variable, RFC 7011 §7 |

Cisco's 2015 AVC guide quotes the two PEN 9 fields as wire specifiers 45003 and 42125.
Those are the IE ids with bit 15 set: 12235 + 32768 = 45003 and 9357 + 32768 = 42125.

**`applicationId`** is `engine << 24 | selector`, per RFC 6759.
The shipped `http` entry has engine 3 and selector 80, so its id is `0x03000050`.
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

The IPFIX Sequence Number counts Data Records, options records included, per RFC 7011 §3.1.
That is the same rule the plain IPFIX encoder follows.

All AVC constants and field lengths derive from `testdata/cisco-avc/elements.tsv`.

### Application-first generation

For an NBAR2 device the catalog decides protocol and destination port, not the `FlowProfile`.
Each flow draws an application by weight.
The application fixes the protocol and port.
The flow then draws a host and a URI by weight from that application's lists.
The exporter therefore never emits a record on port 443 tagged as an application that runs elsewhere.

The profile's volume knobs still apply.
Concurrent flows, lifetimes and per-device record ceilings come from the `FlowProfile` as before.
Only the port and protocol distribution comes from the catalog.

The host and URI draws happen on every flow, even for an entry with no host or URI list.
A seeded device therefore reproduces its stream exactly.
Adding a host list to one entry does not shift any other entry's stream.

Enabling NBAR2 on one device does not change what any other device emits.
A digest over every shipped type and protocol pins that.

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
The disable path is exercised only by a load-time test with a planted 1400-byte URI.

### Interoperability

`make test-interop-ipfix` decodes nl6's AVC records with CESNET IPFIXcol2 using libfds's own Cisco element definitions.
It requires the two PEN 9 fields to resolve by name, as `cisco:appHTTPHost` and `cisco:appHTTPUriStatistics`.
It decodes `applicationId` to a catalog entry, receives the application table, and reconciles a scenario report against the collector's records with no tolerance.
The gate runs in CI and fails rather than skips when docker is missing.
An `en9:idNNNN` field name in the collector's output is the failure signal.

### Differences from IOS-XE 26.01.02

A Cisco Catalyst 8000V running IOS-XE 26.01.02 exported AVC records through containerlab on 2026-09-21.
The capture is checked in and each row below is pinned by a test that decodes it.
The capture confirmed the IE 9357 layout, the application table string lengths, the `http` id and the sequence arithmetic.
It also showed that the HTTP host carries a constant prefix.
nl6 emits that prefix.

Five differences remain and are recorded rather than fixed.
nl6 exists so collectors can be tested against layer-7 records at scale, and every open decoder tried reads its records correctly.
An item is fixed when a consumer needs it.

| | IOS-XE 26.01.02 | nl6 | What a collector sees |
|---|---|---|---|
| Record model | A connection record. Template 258 has 17 fields including `connectionId` (PEN 9 IE 12242, 4 bytes, zero on ICMP). Match fields first, then the two variable-length fields, then counters. URI statistics before host. | The 54-byte unidirectional record, then `applicationId`, host, URI statistics. No connection id. | Different field order and no connection id to join on. This is the one difference that changes what a collector computes. |
| Where host and URI appear | On the ingress-direction record of an HTTP request only. The reverse record carries the six-byte host prefix and an empty URI. | On every AVC record. | Layer-7 values on both directions. |
| URI depth | First path segment only. `/api/v1` arrives as `/api`. | Full catalog value, such as `/api/v1/items`. | Longer URIs than a router produces. |
| Application table | 1560 rows, two-thirds engine 13. Reclassifies HTTP mid-connection to `binary-over-http` and emits a second record. | Every entry is engine 3. One record per flow with a stable id. | Fewer applications and no mid-flow reclassification. |
| Template ids and option widths | Interface table under 256 with 33-byte name, 65-byte description and egressInterface. Application table under 257. Data under 258. | Interface table under 257 with 32 and 32 and no egressInterface. Application table under 259. Data under 258. | The option-table ids collide with Cisco's numbering. Decode by template content, not by id. |


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

**Duration fields** (`active_timeout`, `inactive_timeout`) require
**Go duration strings** (`"30s"`, `"1m30s"`). Integer seconds
(`"active_timeout": 30`) are rejected with 400 — a deliberate mismatch
with the `-flow-*-timeout` CLI flags, which take integer seconds.
A per-device `tick_interval` is rejected with 400 (nl6#445); the fleet-wide cadence is `-flow-tick-interval`.

See [Web API → POST /api/v1/devices](web-api.md#create-devices) for the
full per-device schema.

## How much flow a device emits

Export volume is a property of the flow cache, not of the export cadence:

```
records/s  ≈  ConcurrentFlows / mean-flow-lifetime

mean-flow-lifetime = mean of  min(active-timeout, flow-duration + inactive-timeout)
```

Each synthetic flow is given a duration sampled from the device profile. A flow still running when it reaches the **active timeout** is exported and restarted; a flow that has ended and then sat idle for the **inactive timeout** is exported then. Under the shipped edge-router profile (durations U(0.2s, 120s), 30s active, 15s inactive) about 92 % leave by the active timeout and 8 % by the inactive one, giving a mean cached lifetime near 29s.

The **active timeout is jittered per flow**, by ±25 % of its configured value. A 30s active timeout therefore produces deadlines spread over 22.5s to 37.5s rather than landing on exactly 30s. The jitter is symmetric, but symmetric in the deadline is not symmetric in the lifetime: the lifetime is a **minimum** of that deadline and another, and a minimum is concave, so a spread lowers it slightly. Measured across the shipped profiles the mean lifetime falls by 0.05 % to **1.18 %**, largest on the campus-switch profile whose sampled durations cluster near the timeout. So the jitter changes when records leave, and how many by about a percent. See [Emission shape](#emission-shape) for why.

Expiry is noticed by a periodic sweep. A flow's real residency is therefore the mean lifetime **plus about half a tick interval**, because it waits for the sweep that notices its deadline. That term matters for pacing. A scenario sizing a cache to hit a requested rate divides by the residency, not the lifetime.

`-flow-tick-interval` sets how finely that stream is cut into datagrams, not how much of it there is. Because export polls, a flow can sit cached up to one interval past its deadline, so a slower tick reduces the rate somewhat — bounded by the interval rather than proportional to it. Measured across a 30x cadence range:

| tick | records/s | mean records per tick |
|---|---|---|
| 1s | 4.37 | 4 |
| 5s | 4.24 | 21 |
| 15s | 3.94 | 59 |
| 30s | 3.63 | 109 |

Note "more records per datagram" holds only up to the MTU: NetFlow v9 fits 31 records per datagram, so a 128-record tick is emitted as roughly five back-to-back datagrams rather than one large one. Cadence therefore controls burst *size* at the collector, which is the quantity a collector's capacity actually responds to.

The per-datagram record count follows from the payload budget, which is the MTU minus the IP and UDP headers. At the default 1500 MTU that is 1472 bytes for an IPv4 collector and 1452 for IPv6; both move with `-datagram-mtu` (below). nl6 paginates so the whole frame fits the MTU and no export datagram is IP-fragmented. That matters on a real path because a single lost fragment discards the entire datagram, taking all 31 records with it, and some collectors and middleboxes drop fragments outright.

**NetFlow v5 does not scale with the MTU.** Cisco v5 caps a datagram at 30 records regardless of how much space is available, so a v5 exporter stays at 30 records and roughly 1464 bytes whatever `-datagram-mtu` is set to. Raising the MTU for a jumbo path increases v9 and IPFIX datagram size but leaves v5 emitting the same number of the same-sized datagrams. That cap is also why v5 fit inside the old, incorrect budget by accident rather than by design.

The MTU defaults to 1500 and is set with `-datagram-mtu`. That default holds for nl6's own TUN and veth interfaces, which take the kernel default, but it is an assumption about the **egress** path to the collector rather than a fact nl6 controls.

**Lower it when the collector path is not standard Ethernet.** A Docker overlay or VXLAN network is typically 1450 and a tunnelled path lower still. Measured at 1450 against a 1500-derived build, NetFlow v9 (1480 B frame), IPFIX (1484) and NetFlow v5 (1492) all fragment, as does an SNMP GETBULK at OpenNMS's default collector settings (1464). Only sFlow and SNMP traps fit.

**The flag governs flow export, SNMP trap notifications and SNMP responses.** The SNMP response bound is recomputed from the same value, so a GETBULK truncates to the frame and a GET or GETNEXT that cannot fit answers `tooBig`; see [SNMP → Response size](snmp.md#response-size-max-repetitions-and-truncation). Syslog is deliberately excluded and keeps its own 1400-byte ceiling.

On the trap side, lowering the MTU far enough stops shipped optical alarm entries from firing rather than shrinking them — they are disabled at catalog load and named in the startup log with the MTU that would admit them.

The value is validated at startup and an out-of-range one is fatal, so a misconfiguration surfaces immediately rather than as per-datagram encode failures across the fleet.

nl6 does not discover the MTU, deliberately. Reading the route's interface MTU would work for flow, traps and syslog, which each have a configured collector known when the exporter attaches — but not for SNMP, which answers whoever polls it and knows the destination only per request. Since one value has to cover every subsystem, discovery cannot be the mechanism. There is no path-MTU discovery either: a route lookup sees only the first hop, so a tunnel further along the path is invisible either way. If you see fragments, check the egress interface MTU and set the flag to match.

Setting the tick close to or above the mean flow lifetime is not useful. Every flow then lives about one tick and the cache turns over wholesale. A value of zero or above 1h is not rejected: nl6 logs `flow export: ignoring out-of-range tick interval` at startup and runs at the 5s default.

To raise or lower volume, change the concurrent-flow count or the timeouts.

### Cadence and volume

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

### Emission shape

Volume is unchanged. **Timing is not**, and it moves for every flow deployment whether or not a scenario runs.

| | before | after |
|---|---|---|
| **volume** | ~4.2 records/s per device | unchanged |
| **active-timeout deadline** | exactly the configured value | uniform over ±25 % of it |
| **shape** | a disturbance repeats every flow lifetime, indefinitely | it fades within about four lifetimes |
| **per-device scenario ceiling** | ~8.5–9.7 records/s | ~8.1–9.2 records/s at the 5s default tick |

**Why the deadline was a problem.** Flow creation is driven by expiry. The cache refills exactly what it lost. When the expiry offset is also deterministic, the creation profile becomes a pure delay of itself:

```
expiries at t  →  refills at t  →  expiries at t+30s  →  refills at t+30s  →  …
```

There is no mixing term, so nothing damps. Any irregularity is re-emitted every lifetime forever. A scenario arming, a re-pacing, a scheduling hiccup: all of them persist. Real exporters do not behave this way, and the reason is exactly the coupling. Their flows are created by arriving traffic, a process independent of what the cache happens to be releasing.

Measured in-process as autocorrelation of per-tick record counts across multiples of the flow lifetime, after re-pacing a device:

| | 1 lifetime | 2 | 3 | 4 |
|---|---|---|---|---|
| before, GPU-server profile | +0.96 | +0.94 | +0.91 | **+0.89** |
| before, edge-router profile | +0.87 | +0.77 | +0.68 | **+0.59** |
| after, edge-router profile | +0.23 | +0.18 | +0.08 | **+0.01** |

**On the wire the same defect shows up as dispersion rather than periodicity**, and the distinction is worth stating because the table above overstates what a capture sees. Five devices, 20-minute windows, three paced rates:

| requested | before: CV / r(1 lifetime) | after: CV / r(1 lifetime) |
|---|---|---|
| 2 rec/s | 0.98 / +0.22 | **0.57** / +0.08 |
| 4 rec/s | 0.78 / +0.29 | **0.49** / −0.00 |
| 8 rec/s | 0.99 / +0.15 | **0.20** / +0.18 |

Autocorrelation at one lifetime never exceeded +0.29 on the wire, so the repetition an in-process probe sees at +0.96 is not what a collector was receiving. What a collector was receiving is over-dispersion: before the change, per-tick counts scattered three to six times wider than Poisson counting noise allows; after it, the 8 rec/s case sits essentially at the Poisson floor.

Both symptoms come from the same deterministic deadline. Flows created in one tick expire in one tick, which lumps each tick's output immediately (variance) and repeats the lump a lifetime later (periodicity). The warm first fill already staggered creation ages enough to blunt the repetition on real timing, leaving the variance as the dominant wire symptom.

**What this means for a collector.** A rule keyed on flows arriving at exactly the configured active timeout will now see a spread instead of a spike. `-flow-active-timeout` sets a mean, not an exact deadline.

**Why the ceiling moved.** The stated per-device scenario ceiling was `MaxFlows / mean-flow-lifetime`, which omitted the sweep delay described above. Pacing now divides by the real residency. The ceiling is about 5 % lower, and a paced rate is actually achieved. Before this, pacing ran a few percent low at every rate, which is what the sweep-residency correction was reporting.

The old figure was not wrong by accident. With a deterministic deadline, flows created on a tick boundary expired on a tick boundary, so the sweep genuinely cost nothing. That alignment was an artifact of synthetic timing, and the jitter removed it.

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
    "nbar2_catalogs_by_type": {
      "_universal": {"entries": 7, "source": "embedded"},
      "cisco_ios":  {"entries": 8, "source": "file:resources/cisco_ios/nbar2.json"}
    }
  }
}
```

The body is the standard `{success, message, data}` envelope.
`sent_packets`, `sent_bytes` and `sent_records` count datagrams that reached the kernel.
A datagram the kernel refused is counted once in `send_failures` and in none of the `sent_*` fields.

An NBAR2 device and a plain IPFIX device to the same collector share one `ipfix` row; the collector tells them apart by template id.
`nbar2_catalogs_by_type` is absent when no catalog loaded, and each row carries `oversized` when the load-time dry render disabled any entry.

Flow status has no `subsystem_active` field.
`collectors: []` means no device with a `flow` block has attached yet.
See [Web API → Flow export status](web-api.md#flow-export-status)
for the full field reference.
