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

`IPFIXAVCEncoder` emits Cisco AVC (NBAR2) layer-7 flow records: template ID 258 for the data records, plus template ID 259 for an application table carried on the refresh cadence beside the interface option table.
An AVC record is the plain 54-byte prefix (byte-identical to template 256) followed by a 4-byte `applicationId` and two RFC 7011 §7 variable-length PEN 9 fields: `ciscoHTTPHost` (IE 12235) and `ciscoHTTPURIStatistics` (IE 9357).
Cisco's 2015 AVC guide quotes these as wire specifiers 45003 and 42125, the same IE ids with the enterprise bit set, not separate identifiers.
The IE 12235 value is Cisco's constant six-byte prefix `03 00 00 50 34 02` (applicationId `http`, then sub-application id 0x3402) followed by the hostname, and exactly the six bytes when the record carries no host; the field is never empty and the prefix does not follow the record's own `applicationId`.
That is the layout the IOS-XE 26.01.02 reference capture shows on every record, pinned against the production constant `avcHostPrefix` by `TestCiscoAVCCapture_HTTPHostCarriesConstantPrefix` (nl6#679).
The IE 9357 hit count is encoded big-endian with no trailing delimiter after the URI; Cisco's guide leaves both decisions open, and both are confirmed by the IOS-XE 26.01.02 reference capture, pinned by `TestCiscoAVCCapture_URIStatisticsLayout`.

The export is **conformant and interop-tested against open decoders**.
It is not Cisco-faithful: the design spec's evidence rule made that claim conditional on a Cisco document or a capture, and the IOS-XE 26.01.02 reference capture of 2026-09-21 contradicts the encoder on six points, so the claim was withdrawn (nl6#680) and the differences are listed under [Known differences from IOS-XE 26.01.02](#known-differences-from-ios-xe-260102).
All AVC constants and field lengths derive from `testdata/cisco-avc/elements.tsv`, pinned by `TestIPFIXAVCConstantsMatchEvidence`.
An AVC device carries both options tables, 257 (interfaces) and 259 (applications), on the same refresh cadence.
The IPFIX Sequence Number counts Data Records including options records, per RFC 7011 §3.1, the same rule the plain IPFIX encoder follows.

### Enabling NBAR2

Set `"nbar2": true` in a device's `flow` block.
It requires `protocol: "ipfix"`; any other protocol is rejected with a 400.
The seed flag `-flow-nbar2` exists for the auto-start batch, but that batch is built as `asr9k` (IOS-XR, no NBAR2) and no flag selects another type, so the flag is refused at startup on every boot today with the REST remedy named; it is fatal rather than ignored because a batch that booted and emitted plain IPFIX under an NBAR2 flag is the accepted-and-ignored failure (nl6#445).
Only `cisco_ios` and `cisco_catalyst_9500` have NBAR2; the set is curated by name with a reason per row in `nbar2_capability.go`, never by slug prefix, because `cisco_nexus_9500` (NX-OS), `cisco_crs_x` and `asr9k` (IOS-XR) do not.
A request whose whole resolved type set is incapable is rejected with a 400 naming the type and its OS.
A mixed round-robin batch is accepted, and here the rule differs from flow's own skip: an NBAR2-incapable but flow-capable device **keeps its flow block and emits the plain IPFIX record** (template 256) with `nbar2` cleared, logged once per type.
Flow's incapable skip attaches no flow block at all.
The two outcomes differ in byte identity and in what a collector sees, so `GET /api/v1/devices` echoes `nbar2` only on devices that emit AVC.

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

### Application-first generation

For an NBAR2 device the catalog, not the `FlowProfile`, decides protocol and destination port: each flow draws an application by weight, takes the application's protocol and port, then draws a host and a URI by weight.
The exporter therefore never emits a record on port 443 tagged as an application that runs elsewhere.
The profile's port mix and per-device record ceilings still describe the non-NBAR2 fleet; an NBAR2 device's port and protocol distribution is its catalog's.
The host and URI draws are unconditional, so a seeded device reproduces its stream exactly.
Every device not using NBAR2 emits byte-identical output to the previous release, pinned by a digest over every shipped type and protocol (`testdata/flow-digests/pre-nbar2.tsv`).
The NBAR2 stream itself is pinned the same way (`testdata/flow-digests/plan-b-nbar2.tsv`, taken at the Plan B merge), so later work on the ledger or the report cannot move an AVC byte unnoticed.

### Verified against an independent collector

`make test-interop-ipfix` is the check with detection power for this feature, in the sense `make test-interop` is for SNMPv3: every other IPFIX and AVC test decodes nl6's bytes with nl6's own decoder, so a shared misreading of RFC 7011 section 7 or of Cisco's PEN 9 numbers would pass all of them.
The target builds `examples/ipfixcol2/` (Debian forky's `ipfixcol2` 2.8.0 package with libfds's own `cisco.xml`; Ubuntu 24.04 does not package it), starts CESNET IPFIXcol2 on the host network, and runs two tests that read the collector's own NDJSON output.
The first drives a real exporter through `Tick` and requires that the collector resolves IEs 12235 and 9357 under PEN 9 **by name** (`cisco:appHTTPHost`, `cisco:appHTTPUriStatistics`; the `en9:idNNNN` form is the failure signal and the test names both causes), decodes `applicationId` to an id in the device's catalog with the record's protocol and port matching it, carries the host and URI as catalog values, receives the application table (template 259) with name and description for every id seen in a data record, keeps the RFC 7011 section 3.1 sequence arithmetic per observation domain, and shows none of that on a plain IPFIX control.
The second runs a real scenario over three NBAR2 participants and one plain one and reconciles the report's `applications[]` and `l7_values[]` against sums over the collector's decoded records per key, with no tolerance band.
Both were verified by mutation: disabling the host fold or never resolving the id fails them by name.
libfds types IEs 12235 and 9357 as strings, and IPFIXcol2's JSON output DROPS non-printable bytes from a string unless `nonPrintableChar` is on: off, the collector showed the URI statistics as the URI alone and would show a Cisco-layout host as `P4www.example.com` (the two printable bytes of the prefix, then the name).
The gate's config has the flag on, so every byte arrives as a `\u00XX` escape and the test asserts the six-byte host prefix and the URI's NUL and big-endian hit count byte for byte, against the collector's own element definitions.
An earlier version of this paragraph said the collector "cuts the value at its NUL"; it discards non-printables, which looks the same on a URI and hides four of the six prefix bytes on a host.
The gate runs in CI beside the SNMPv3 and Pyroscope interop steps and fails rather than skips when docker is missing.

### Verified on the wire over veth

Loopback has an MTU of 65536, so no Go test can see fragmentation; the check that can is a capture on the simulator's own veth, the nl6#488 method.
Taken 2026-09-20 in an Ubuntu 24.04 arm64 VM, kernel default MTU 1500 on the veth, from the commit that added this section: ten `cisco_ios` devices created over REST with `flow: {protocol: "ipfix", nbar2: true}`, a 1-second tick, 3-second active and 2-second inactive timeouts, captured for 45 seconds on `veth-sim-host` with the filter `udp port 4739 or (ip[6:2] & 0x3fff != 0)`.

| `-datagram-mtu` | datagrams captured | fragmented | largest IP length | entries disabled at startup |
|---|---|---|---|---|
| 1500 (default) | 963 | 0 | 1500 | none |
| 1000 | 1415 | 0 | 1000 | none |
| 576 (floor) | 2451 | 0 | 576 | none |

The largest datagram sits exactly at the configured MTU in every run and nothing fragments, which is the frame budget doing its job.
No shipped catalog entry goes oversized at any legal MTU: the worst case of the longest shipped entry fits the 548-byte payload a 576-byte frame leaves, so the dry render's disable-and-name path is exercised only by the load-time test with a planted 1400-byte URI, not by the shipped data.
The first capture attempt found a real defect rather than a fragment: a create request naming the type as `cisco_ios` without the `.json` suffix was refused as NBAR2-incapable, because the capability gates run before the name validator and indexed their maps with the raw string; `resourceFileKey` now normalises the lookup for the NBAR2, flow and optical gates, and the example above carries the suffix the API requires.

### Known differences from IOS-XE 26.01.02

A real Cisco Catalyst 8000V running IOS-XE 26.01.02 exported AVC records through containerlab on 2026-09-21; the capture, the router's configuration and the files that regenerate it are in `go/nl6/testdata/cisco-avc/capture/`, and `cisco_avc_capture_test.go` decodes the pcap with its own template parser and pins each fact below.
The design spec's evidence rule (`docs/superpowers/specs/2026-09-18-nbar2-ipfix-l7-export-design.md`, section 1) said a contradicting capture would make the encoder follow or the claim downgrade.
The claim downgraded (nl6#680): the feature exists so collectors can be tested against layer-7 records at scale, every open decoder tried reads nl6's records correctly, and following would be seven wire changes plus a generation change to transaction-end aging for a fidelity no consumer has asked for.
The differences are recorded here rather than filed; an item is filed individually when a consumer needs it.

1. **HTTP host (IE 12235) carries a constant prefix. Resolved.** Every router record starts the field with `03 00 00 50 34 02` (applicationId `http` then sub-application id 0x3402) and then the hostname; a record with no host carries exactly the six bytes. nl6 emitted the bare hostname until nl6#679, the one correctness item in this list, since a decoder written to Cisco's layout misread the value; since nl6#679 (the release after v0.29.2) nl6 emits the prefix from the single constant `avcHostPrefix`, the wire change moved `plan-b-nbar2.tsv`, and the interop gate asserts the prefix on every record the collector decodes. Pinned by `TestCiscoAVCCapture_HTTPHostCarriesConstantPrefix`, which compares the capture against the production constant.
2. **The record is a connection record with a different field order.** IOS-XE refuses to bind a monitor that collects URI statistics without `match connection id` (PEN 9 IE 12242, 4 bytes, zero on ICMP) and refuses that without `cache timeout event transaction-end`. The router's template 258 has 17 fields with match fields first, the two variable-length fields before the counters and URI statistics before host; nl6's is the 54-byte unidirectional prefix followed by applicationId, host, URI statistics, with no connection id. This is the one item that would change what a collector computes, since it is a generation model, not an encoding. Pinned by `TestCiscoAVCCapture_DataTemplateFieldOrder`.
3. **Host and URI appear on ingress records only.** The router puts them on the ingress-direction record of an HTTP request; the reverse-direction record carries the six-byte host prefix and an empty URI field. nl6 puts host and URI on every AVC record. Pinned by `TestCiscoAVCCapture_LayerSevenValuesAreIngressHTTPOnly`.
4. **URI statistics record the first path segment only.** `/api/v1` arrives as `/api`, `/static/app.js` as `/static`. nl6's shipped catalogs carry multi-segment URIs such as `/api/v1/items`. Pinned by `TestCiscoAVCCapture_URIStatisticsLayout`.
5. **A real application table is two-thirds engine 13.** The router's table has 1560 rows across engines 1 (127), 3 (748) and 13 (685), and NBAR2 reclassified half the plain HTTP transactions mid-connection to `binary-over-http` (`0x0d0001af`), emitting a second record per request. Every nl6 catalog entry is engine 3 and no engine-13 application exists. Ids the capture sourced: `unknown` `0x0d000001`, `binary-over-http` `0x0d0001af`, `ping` `0x0d0001df`. Pinned by `TestCiscoAVCCapture_OptionsTemplates`.
6. **The interface option table differs in width, fields and template ids.** The router sends scope ingressInterface, then interfaceName at 33 bytes, interfaceDescription at 65 bytes and egressInterface, under template 256; Cisco numbers the tables 256 interface, 257 application, 258 data. nl6's `if-scoped` shape is 32 and 32 with no egressInterface under 257, and its application table is 259. Pinned by `TestCiscoAVCCapture_OptionsTemplates`.

What the capture confirmed: the IE 9357 layout (URI, NUL, big-endian 2-byte hit count, no trailing delimiter, so `uriStatsValue` reproduces the router's bytes exactly), the application table string lengths of 24 and 55, the engine-3 `http` id `0x03000050`, sequence numbers that count option data records, and a maximum datagram of 1420 bytes with no fragmentation (`TestCiscoAVCCapture_URIStatisticsLayout`, `TestCiscoAVCCapture_OptionsTemplates`, `TestCiscoAVCCapture_MessageShape`).
The evidence base (`go/nl6/testdata/cisco-avc/NOTES.md`) says which of the remaining facts are Cisco-sourced and which are nl6 decisions; `capture/README.md` says how to regenerate the capture in about five minutes against a vrnetlab-built `cisco_c8000v` image.

### The catalog

`resources/_common/nbar2.json` is compiled into the binary.
`resources/<type>/nbar2.json` overlays it for that type with the trap and syslog catalogs' `extends` semantic: `true` (the default) replaces same-name entries and appends new ones, `false` makes the per-type file the whole catalog for that type.
`-nbar2-catalog <path>` replaces the universal **and** suppresses every overlay; it is read once at startup, and there is no per-device catalog path on the REST surface.
`POST /api/v1/resources/reload` does not reload it.

```json
{
  "comment":  "optional",
  "extends":  true,                       // per-type files only; default true
  "entries": [
    {
      "name":        "http",              // unique; at most 24 bytes (applicationName)
      "description": "Hypertext Transfer Protocol",   // at most 55 bytes (applicationDescription)
      "engine":      3,                   // RFC 6759 section 4.1: 3 IANA-L4, 6 USER-Defined, 13 PANA-L7
      "selector":    80,                  // 0..16777215; applicationId = engine<<24 | selector, unique in the merged catalog
      "proto":       "tcp",               // tcp | udp | icmp | 0..255
      "dst_port":    80,                  // 0..65535; must be 0 under icmp
      "weight":      30,                  // draw weight; default 1
      "hosts": [ {"value": "www.example.com", "weight": 6} ],   // optional; ciscoHTTPHost
      "uris":  [ {"value": "/index.html",     "weight": 4} ]    // optional; ciscoHTTPURIStatistics
    }
  ]
}
```

Every rule names the file, the entry and the rule when it refuses a load.
The shipped entries all use engine 3 with the IANA port as selector, which RFC 6759 defines and which needs no Cisco protocol-pack number to verify; Cisco's PANA-L7 selectors are protocol-pack data; the reference capture sourced three (listed under known differences) and none is shipped, so an operator catalog is where they go.
A collector's own classification may disagree with `applicationName`; join on the id.

At load, each entry's worst-case record (its longest host and URI) is encoded through the production encoder against an empty datagram at the `-datagram-mtu` payload budget.
An entry that cannot fit is **disabled, not rejected**: it stays out of generation and out of the application table, and the startup log names it with its size, the gap and the MTU that would admit it.
Loading does not fail on size because the budget follows an operator-settable MTU.
A device whose resolved catalog has no usable entry is refused at attach with that reason.
The budget used is the IPv6 one, the smaller of the two address families, so an entry that passes load fits a datagram to any collector.
`GET /api/v1/flows/status` reports the resolved catalogs under `nbar2_catalogs_by_type` with entry counts, the number disabled, and the source (`embedded`, `file:resources/<type>/nbar2.json`, `override:<path>`).

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

The **active timeout is jittered per flow**, by ±25 % of its configured value. A 30s active timeout therefore produces deadlines spread over 22.5s to 37.5s rather than landing on exactly 30s. The jitter is symmetric, but symmetric in the deadline is not symmetric in the lifetime: the lifetime is a **minimum** of that deadline and another, and a minimum is concave, so a spread lowers it slightly. Measured across the shipped profiles the mean lifetime falls by 0.05 % to **1.18 %**, largest on the campus-switch profile whose sampled durations cluster near the timeout. So the jitter changes when records leave, and how many by about a percent. See [Changed in nl6#462: emission shape](#changed-in-nl6462-emission-shape) for why.

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

**The flag governs flow export and SNMP trap notifications.** SNMP GETBULK responses still carry their own fixed bound and are not yet derived from it, so on a 1450 path a default-settings GETBULK keeps fragmenting even with `-datagram-mtu 1450` set; that subsystem joins the shared value when nl6#489 lands. Syslog is deliberately excluded and keeps its own 1400-byte ceiling.

On the trap side, lowering the MTU far enough stops shipped optical alarm entries from firing rather than shrinking them — they are disabled at catalog load and named in the startup log with the MTU that would admit them.

The value is validated at startup and an out-of-range one is fatal, so a misconfiguration surfaces immediately rather than as per-datagram encode failures across the fleet.

nl6 does not discover the MTU, deliberately. Reading the route's interface MTU would work for flow, traps and syslog, which each have a configured collector known when the exporter attaches — but not for SNMP, which answers whoever polls it and knows the destination only per request. Since one value has to cover every subsystem, discovery cannot be the mechanism. There is no path-MTU discovery either: a route lookup sees only the first hop, so a tunnel further along the path is invisible either way. If you see fragments, check the egress interface MTU and set the flag to match.

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

Both symptoms come from the same deterministic deadline. Flows created in one tick expire in one tick, which lumps each tick's output immediately (variance) and repeats the lump a lifetime later (periodicity). The warm first fill added by [nl6#446](https://github.com/labmonkeys-space/nl6/issues/446) already staggered creation ages enough to blunt the repetition on real timing, leaving the variance as the dominant wire symptom.

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
  "last_template_send": "2026-04-23T10:35:00Z",
  "nbar2_catalogs_by_type": {
    "_universal": {"entries": 7, "source": "embedded"},
    "cisco_ios":  {"entries": 8, "source": "file:resources/cisco_ios/nbar2.json"}
  }
}
```

An NBAR2 device and a plain IPFIX device to the same collector share one `ipfix` row; the collector tells them apart by template id.
`nbar2_catalogs_by_type` is absent when no catalog loaded, and each row carries `oversized` when the load-time dry render disabled any entry.

`subsystem_active=false` with `collectors: []` means flow export never
ran (the subsystem starts on-demand when the first device with a `flow`
block attaches). See [Web API → Flow export status](web-api.md#flow-export-status)
for the full field reference.
