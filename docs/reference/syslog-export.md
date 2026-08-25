# UDP syslog reference

nl6 emits UDP syslog messages in either **RFC 5424** (modern,
structured) or **RFC 3164** (legacy BSD) format. Only one format is
active per simulator process. The two encoders sit behind a shared
`SyslogEncoder` interface in `go/nl6/syslog_wire.go`; the per-
device `SyslogExporter` holds a UDP socket (per-device or shared) and
fires messages at times drawn by a central Poisson scheduler. This
page covers the wire format, the catalog JSON schema, the HTTP
endpoints, and the status JSON shape. For enabling the feature, CLI
flags, and troubleshooting see
[UDP syslog export (operator guide)](../ops/syslog-export.md) and
[CLI flags → UDP syslog export](cli-flags.md#udp-syslog-export-flags).

## Architecture

- **Central scheduler goroutine** (`syslog_scheduler.go`) owns a
  min-heap of `(nextFire, deviceIP)` entries. Single goroutine
  regardless of device count — identical design to
  [trap export](snmp-traps.md#architecture).
- **Per-device `SyslogExporter`** (`syslog_exporter.go`) owns the
  device's UDP socket and stats. Class 1 device-context fields
  (`SysName`, `Model`, `Serial`, `ChassisID`) are captured at
  exporter construction — stable for the device's lifetime.
- **Shared `SyslogEncoder` interface** (`syslog_wire.go`) with two
  implementations: `RFC5424Encoder` and `RFC3164Encoder`. Both
  produce a single UDP datagram per message.
- **Embedded catalog** loaded via `go:embed` from
  `resources/_common/syslog.json` at startup. `-syslog-catalog <path>`
  replaces the entire catalog surface (universal + per-type overlays)
  with a single user-supplied JSON file.
- **Per-device-type catalog overlays** loaded from
  `resources/<slug>/syslog.json` when present. Each device of type
  `<slug>` fires from the merged catalog (universal + per-type) —
  see [Per-type catalog overlays](#per-type-catalog-overlays).
- **Global rate limiter** (`golang.org/x/time/rate`) gates scheduled
  fires. On-demand fires via the HTTP endpoint **bypass** the cap —
  they're for fault injection, not load shaping.

## Scope

The simulator emits syslog over **UDP only** — TCP (RFC 6587) and TLS
(RFC 5425) transports are follow-up work
([#92](https://github.com/labmonkeys-space/nl6/issues/92),
[#93](https://github.com/labmonkeys-space/nl6/issues/93)).
UDP is the form most network-device simulation scenarios test against;
adding TCP/TLS requires connection management that doesn't fit the
fire-and-forget single-socket design.

## RFC 5424 wire format

```
<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-PARAM]* MSG
```

| Field | Source | Example |
|-------|--------|---------|
| `<PRI>` | `facility * 8 + severity` | `<187>` (local7.debug) |
| Version | Always `1` | `1` |
| `TIMESTAMP` | ISO 8601 UTC with fractional seconds | `2026-04-21T13:30:45.123Z` |
| `HOSTNAME` | Catalog `hostname` template → `sysName.0` → `DeviceIP` | `rtr-dc-01` |
| `APP-NAME` | Catalog entry's `appName` (required) | `IFMGR` |
| `PROCID` | Always `NILVALUE` (`-`) | `-` |
| `MSGID` | Catalog entry's `msgId` (optional; NILVALUE if omitted) | `LINKDOWN` |
| `[SD-PARAM]` | Zero or more structured-data blocks from the catalog's `structuredData` map | `[ifIndex="3" ifName="ge-0/0/3"]` |
| `MSG` | Catalog entry's `template` rendered | `Interface ge-0/0/3 changed state to down` |

All header tokens pass through sanitisation per RFC 5424 §6: spaces
become hyphens, non-ASCII bytes become `_`, lengths are capped. The
dry-render check at catalog load rejects any entry whose worst-case
expansion exceeds 1400 bytes.

### Structured-data grammar

Each key in the catalog's `structuredData` map becomes one SD-PARAM
inside a single `[<SD-ID>=...]` block whose SD-ID is the catalog entry
`appName`. Keys must match the RFC 5424 §6.3.3 SD-NAME grammar
(PRINTUSASCII, no space / `=` / `]` / `"`, 1..32 chars). Values are
rendered through the standard template vocabulary. SD-PARAM value
escapes (`"` → `\"`, `\` → `\\`, `]` → `\]`) are applied automatically.

## RFC 3164 wire format

```
<PRI>TIMESTAMP HOSTNAME TAG[pid]: MSG
```

| Field | Source | Example |
|-------|--------|---------|
| `<PRI>` | Same computation as 5424 | `<187>` |
| `TIMESTAMP` | BSD-style, no year | `Apr 21 13:30:45` |
| `HOSTNAME` | Same derivation chain as 5424 | `rtr-dc-01` |
| `TAG` | Catalog entry's `appName` | `IFMGR` |
| Pid | Always `[-]` (placeholder; simulator doesn't track per-device pids) | `[-]` |
| `MSG` | Catalog entry's `template` rendered | `Interface ge-0/0/3 changed state to down` |

RFC 3164 has **no structured-data support**; the catalog's
`structuredData` and `msgId` fields are silently dropped for this
format. If a catalog entry depends on structured data for
correlation, stay on 5424.

## PRI calculation

Per RFC 5424 §6.2.1 (shared by both formats):

```
PRI = facility * 8 + severity
```

Range 0..191. No leading zeros on the wire.

| Facility name | Value |
|---------------|-------|
| `kern` | 0 |
| `user` | 1 |
| `mail` | 2 |
| `daemon` | 3 |
| `auth` | 4 |
| `syslog` | 5 |
| `lpr` | 6 |
| `news` | 7 |
| `uucp` | 8 |
| `cron` | 9 |
| `authpriv` | 10 |
| `ftp` | 11 |
| `local0`..`local7` | 16..23 |

| Severity name | Value | Aliases |
|---------------|-------|---------|
| `emerg` | 0 | |
| `alert` | 1 | |
| `crit` | 2 | |
| `err` | 3 | `error` |
| `warning` | 4 | `warn` |
| `notice` | 5 | |
| `info` | 6 | |
| `debug` | 7 | |

The catalog loader accepts either the canonical name or the integer
value; out-of-range integers or unknown names are rejected.

## HOSTNAME derivation

Resolved at fire time, in priority order:

1. **Catalog `hostname` template** — if the entry defines a non-empty
   `hostname` field, render it through the template vocabulary and
   use the result.
2. **Device's `sysName.0`** — captured at device construction from
   the SNMP OID table. Used when the catalog entry has no `hostname`
   template and the device's sysName is non-empty.
3. **Device's IPv4** — dotted-quad fallback when sysName is also
   empty.

Whatever branch fires, the result is passed through hostname
sanitisation: spaces → hyphens (mandated by both RFCs), non-ASCII
and control chars → `_`.

## Catalog JSON schema

The embedded universal catalog at
`go/nl6/resources/_common/syslog.json` is the authoritative
example:

```json
{
  "entries": [
    {
      "name": "interface-down",
      "weight": 40,
      "facility": "local7",
      "severity": "error",
      "appName": "IFMGR",
      "msgId": "LINKDOWN",
      "structuredData": {
        "ifIndex": "{{.IfIndex}}",
        "ifName": "{{.IfName}}"
      },
      "template": "Interface {{.IfName}} (ifIndex={{.IfIndex}}) changed state to down"
    }
  ]
}
```

Top-level:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `entries` | array | yes | List of catalog entries. Must contain at least one. |
| `extends` | bool | no (default `true`) | **Per-type overlays only.** Controls whether the per-type catalog merges on top of the universal (`true`) or fully replaces it for devices of that type (`false`). Ignored on the universal catalog itself. |

Per-entry:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `name` | string | yes | Unique within the catalog. Used by the HTTP fire-on-demand endpoint and for log attribution. |
| `weight` | integer | no (default `1`) | Relative weight for weighted-random selection. Zero means omit from scheduled firing (still reachable via HTTP). |
| `facility` | string or integer | yes | Canonical name (`kern`..`local7`) or integer 0..23. |
| `severity` | string or integer | yes | Canonical name (`emerg`..`debug`) or integer 0..7. |
| `appName` | string | yes | RFC 5424 APP-NAME / RFC 3164 TAG. 1..48 ASCII chars; sanitised at render time. |
| `msgId` | string | no | RFC 5424 MSGID. Dropped in 3164. |
| `hostname` | string | no | HOSTNAME override template. Empty means use the default derivation (sysName → DeviceIP). |
| `structuredData` | object | no | Map of SD-NAME → value-template. Keys must be RFC 5424 §6.3.3 SD-NAME compliant. Dropped entirely in 3164. |
| `template` | string | yes | MSG body template. |

### Universal catalog (embedded default)

Ships six generic entries matching common network-device semantics:

| Name | Facility.Severity | APP-NAME | MSGID | Weight |
|------|-------------------|----------|-------|--------|
| `interface-up` | `local7.notice` | `IFMGR` | `LINKUP` | 40 |
| `interface-down` | `local7.error` | `IFMGR` | `LINKDOWN` | 40 |
| `auth-success` | `authpriv.info` | `sshd` | `LOGIN` | 20 |
| `auth-failure` | `authpriv.warning` | `sshd` | `FAIL` | 20 |
| `config-change` | `local7.notice` | `SYSMGR` | `CONFIG` | 10 |
| `system-restart` | `local7.warning` | `SYSMGR` | `RESTART` | 5 |

Weights sum to 135. Interface state dominates; authentication and
system events round out the tail.

### Template vocabulary

Both the `template` body, `hostname` override, and every value in
`structuredData` are evaluated as Go `text/template` strings per fire.
The vocabulary is **unified with the trap subsystem** — the same
nine fields work on both sides:

| Field | Evaluation |
|-------|-----------|
| `{{.IfIndex}}` | Random ifIndex drawn from the device's simulated interface set at fire time |
| `{{.IfName}}` | `ifDescr.<IfIndex>` live lookup from the device's SNMP OID table; falls back to synthesised `GigabitEthernet0/<N>` on miss |
| `{{.Uptime}}` | Device uptime in 1/100-second ticks |
| `{{.Now}}` | Unix epoch seconds |
| `{{.DeviceIP}}` | Dotted-quad IPv4 of the device |
| `{{.SysName}}` | Device's `sysName.0` value (captured at construction) |
| `{{.Model}}` | Human-readable model string derived from device-type slug (e.g., `cisco_ios` → `Cisco IOS`) |
| `{{.Serial}}` | Deterministic `SN` + 8-hex-digit serial synthesised from the device's IPv4 |
| `{{.ChassisID}}` | Deterministic locally-administered MAC-style chassis ID synthesised from the device's IPv4 (`02:42:xx:xx:xx:xx`) |

References to any other field are rejected at catalog load.
Class 2 random-per-fire fields (`PeerIP`, `User`, `SourceIP`,
`RuleName`, `NeighborRouterID`) are explicitly unsupported — they're
tracked as follow-up work so syslog entries that semantically
require them (sshd auth, BGP/OSPF events, firewall rules) are either
shipped bland or deferred.

## Per-type catalog overlays

Devices can ship vendor-flavoured syslog content via per-type JSON
files at `resources/<slug>/syslog.json`. When a per-type file exists,
the simulator merges it with the universal catalog using **name-based
overlay semantics**:

1. Entries whose names are unique to the per-type file are **added**.
2. Entries whose names match a universal entry **override** the
   universal entry for devices of that type.
3. Universal entries with no matching per-type name **carry through**.

Set `"extends": false` at the top of the per-type file for a pure
replacement (no universal entries carry through for that type). The
default is `"extends": true`.

### Shipped vendor catalogs

| Slug | Count | Notable entries |
|------|-------|-----------------|
| `cisco_ios` | 8 Cisco-format entries (merged total 14) | `cisco-link-updown-up/down` (`%LINK-3-UPDOWN:`), `cisco-lineproto-updown-up/down` (`%LINEPROTO-5-UPDOWN:`), `cisco-sys-config` (`%SYS-5-CONFIG_I:`), `cisco-snmp-coldstart`, `cisco-sys-restart` (uses `{{.Model}}` / `{{.Serial}}` / `{{.ChassisID}}`), `cisco-envmon-temp-ok` |
| `juniper_mx240` | 7 Junos-format entries (merged total 13) | `juniper-snmp-link-up/down` (`SNMP_TRAP_LINK_*`), `juniper-mib2d-encaps-mismatch` (`MIB2D_IFD_IFL_ENCAPS_MISMATCH`), `juniper-chassisd-temp-critical` (`CHASSISD_FRU_TEMP_CRITICAL`), `juniper-chassisd-eeprom-fail` (uses `{{.ChassisID}}` / `{{.Serial}}`), `juniper-license-expired`, `juniper-ui-commit-complete` |

Message bodies match the vendor's canonical shape verbatim so
collector-side pattern matchers tuned for Cisco / Juniper strings
fire correctly. Other cisco_* slugs (`cisco_catalyst_9500`,
`cisco_crs_x`, etc.), `juniper_mx960`, Arista, Linux, and Palo Alto
fall back to the universal catalog in this epic — their realistic
content depends on Class 2 random fields deferred to a follow-up.

Family-catalog concept (one catalog shared by all `cisco_*` slugs,
one by all `juniper_*`) is also a follow-up refactor.

## Starting syslog export

Syslog export is opt-in per device. There are two ways to configure it:

### 1. CLI seed (auto-start batch)

The `-syslog-*` flags seed auto-created devices. Every device in the
auto-start batch gets the same collector, format, and interval.

```bash
# RFC 5424 → 192.168.1.10:514, 100 auto-created devices
sudo ./nl6 \
  -auto-start-ip 10.0.0.1 -auto-count 100 \
  -syslog-collector 192.168.1.10:514

# RFC 3164 legacy BSD format for downstream parsers that don't groket 5424
sudo ./nl6 \
  -auto-start-ip 10.0.0.1 -auto-count 50 \
  -syslog-collector 192.168.1.10:514 \
  -syslog-format 3164
```

### 2. REST body (per-device)

`POST /api/v1/devices` accepts an optional `syslog` block per request.
Different batches can target different collectors or mix formats
(5424 and 3164 streams never interleave on the same socket — the
shared-socket pool is keyed by `(collector, format)`).

```bash
# A: 50 devices emitting 5424 to collector A
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.0.1",
    "device_count": 50,
    "syslog": {
      "collector": "192.168.1.10:514",
      "format": "5424",
      "interval": "15s"
    }
  }'

# B: 20 devices emitting 3164 to the SAME collector (different socket,
# separate status record)
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.1.1",
    "device_count": 20,
    "syslog": {
      "collector": "192.168.1.10:514",
      "format": "3164"
    }
  }'
```

> **Note:** the `interval` field above is accepted and stored but **not honored** — every device fires at the simulator-wide `-syslog-interval` cadence ([nl6#445](https://github.com/labmonkeys-space/nl6/issues/445)). The create response returns a `warnings` entry saying so. To silence a fleet use `-fidelity`, or `POST /api/v1/fidelity` to toggle it at runtime, not a long interval.

`/api/v1/syslog/status` reports both batches as separate records keyed
by `(collector, format)`.

The `syslog` block is **optional** on every request — omit it and the
device doesn't emit syslog. See
[Web API → POST /api/v1/devices](web-api.md#create-devices) for the full
per-device schema.

**Duration fields** (`interval`) require **Go duration strings**
(`"10s"`, `"5m"`, `"1m30s"`). Integer seconds (`"interval": 10`) are
rejected with 400 — a deliberate mismatch with the `-syslog-interval`
CLI flag, which takes integer seconds.

## TCP transport (RFC 6587)

Syslog is UDP by default. Setting `-syslog-transport tcp`, or a per-device
`"transport": "tcp"`, carries the same messages over a per-device TCP
connection instead.

The message does not change. Catalog, template vocabulary, wire format and the
resolved bytes are properties of the message; the transport only decides how
those bytes reach the collector. Moving a deployment between transports gives
you the same bytes, framed differently.

### Framing

| framing | shape | when |
|---|---|---|
| `octet-counting` (default) | `<byteCount> SP <msg>` | RFC 6587 §3.4.1. What rsyslog emits, and unambiguous for any payload. |
| `non-transparent` | `<msg> LF` | RFC 6587 §3.4.2. Some Cisco platforms speak only this. |

Octet-counting is the default because it is safe by construction. LF framing is
only unambiguous because the message body cannot contain a bare line feed, and
that guarantee comes from a control-byte replacement added to prevent injection
of a forged `<PRI>` line. It holds today, but it is a precondition, and the
default should not depend on one.

Setting `framing` while the transport is `udp` is **rejected**, not ignored.

### TCP refuses where UDP degrades

Under UDP a device that cannot bind its own socket falls back to a shared one,
losing source-address attribution and nothing else. A datagram socket is
stateless, so one socket can serve any number of devices.

There is no equivalent for TCP. A shared connection would multiplex several
devices into **one framed byte stream carrying no field to demultiplex on**, so
the collector would see a single client and per-device identity would be
destroyed rather than degraded.

Two consequences:

- A device whose connection cannot be established does not attach.
- `-syslog-source-per-device=false` makes a TCP attach **fail**, because the
  fallback it selects does not exist for a stream transport.

The dial itself is asynchronous: attach succeeds once the reconnect loop is
running. Requiring the collector to be up at attach time would make fleet
startup depend on collector availability, which is the condition the reconnect
loop exists to ride out.

### Connection handling

One connection per device, dialled from inside the device's network namespace
so the source address is the device's own. Reconnect uses capped backoff, and
the backoff only resets once a connection has survived long enough to count as
working — a collector that accepts and immediately closes (an ACL reject) backs
off instead of being re-dialled every second by every device.

TCP keepalives are on. Without them a collector that dies **without closing**
(host crash, network partition) is undetectable on an idle connection: the read
that would notice never returns, and the device is silently gone.

### What `sent` means under TCP

`GET /api/v1/syslog/status` rows carry a `transport` field, so TCP and UDP
devices sending the same format to the same collector do not merge into one row.

On the datagram path `sent` approximates "on the wire". **On TCP it means
"handed to the kernel"**, and under load those differ by however deep the send
buffer is.

The per-connection send buffer is capped deliberately rather than inherited.
Linux auto-tunes it to roughly 4 MiB against a collector that has stopped
reading; at 30,000 devices that would be ~117 GiB of kernel buffer, so the
default is the difference between the feature existing at fleet scale and not.
The cap also means a stalled collector is noticed in seconds rather than
minutes.

A write that cannot complete within a short bound is dropped and the connection
replaced. Blocking is not an option: the syslog scheduler fires inline for the
whole fleet, so one stalled collector would stop every device.

### Collector-side caveats

- `rp_filter` may need relaxing (`net.ipv4.conf.*.rp_filter=0` or `2`) to accept
  connections whose source addresses are in the simulated range — the same
  caveat already documented for flow, trap and UDP syslog.
- A fleet means **one connection per device**. A collector accepting 30,000
  concurrent connections from 30,000 distinct source addresses is a different
  proposition from receiving datagrams, and file-descriptor and accept-backlog
  limits are usually what bites first.
- **OpenNMS's classic Syslogd is UDP-only** — `syslogd-configuration.xml` has no
  transport attribute. The documented pattern is to terminate TCP in rsyslog or
  syslog-ng and relay onward. Measured, rsyslog's `imtcp` absorbs roughly
  262,000 frames/s, comfortably above what a simulated fleet produces, so a
  realistic deployment does not approach backpressure.

## HTTP endpoints

### Fire a syslog message on demand

`POST /api/v1/devices/{ip}/syslog` — fires one message for the
named device immediately, bypassing the Poisson scheduler and the
global rate cap. Body:

```json
{
  "name": "interface-down",
  "templateOverrides": {
    "IfIndex": "7",
    "IfName": "GigabitEthernet0/7"
  }
}
```

`name` is required and must match an entry in the **device's
resolved catalog** (per-type overlay if present, universal otherwise).
`templateOverrides` is optional — supplied keys pin the corresponding
template field for this fire only.

Responses:

| Status | Body | When |
|--------|------|------|
| `202 Accepted` | `{}` | Success; the message was emitted. |
| `400 Bad Request` | `{"error": "...", "catalog": "<slug>", "availableEntries": [...]}` | Unknown catalog entry for the device. The enriched body tells the caller which catalog the device resolved to and lists its entries so a scripted caller can self-service. |
| `404 Not Found` | error JSON | Unknown device IP. |
| `503 Service Unavailable` | error JSON | The syslog subsystem has not started **or** the target device has no syslog config (i.e. it was created without a `syslog` block and didn't inherit the CLI seed). |
| `500 Internal Server Error` | error JSON | Pathological: catalog resolution returned nil while the feature reports active. Indicates a broken manager invariant, not a transient issue. |

On-demand fires **do not** consume global rate-cap tokens.

### Syslog export status

`GET /api/v1/syslog/status` — current snapshot of the syslog subsystem.

**Response shape** (array-of-collectors aggregated by `(collector, format)`):

```json
{
  "subsystem_active": true,
  "collectors": [
    {
      "collector":     "192.168.1.10:514",
      "format":        "5424",
      "devices":       50,
      "sent":          18240,
      "send_failures": 3
    },
    {
      "collector":     "192.168.1.10:514",
      "format":        "3164",
      "devices":       20,
      "sent":          6130,
      "send_failures": 0
    }
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

Fields:

| Field | Meaning |
|-------|---------|
| `subsystem_active` | `true` after `StartSyslogSubsystem` runs. During normal operation of the HTTP server this value is always `true`: the subsystem initialises in `main()` and the only path that flips it to `false` is `StopSyslogExport`, which runs at process exit alongside the HTTP server. A `false` value is therefore only observable programmatically (e.g. a test harness calling `GetSyslogStatus` without starting the subsystem). |
| `collectors[]` | One record per `(collector, format)` tuple that ever had a device. |
| `collectors[].collector` | Target `host:port` (canonicalised). |
| `collectors[].format` | `"5424"` or `"3164"`. |
| `collectors[].devices` | Count of LIVE devices emitting to this tuple. `0` means no live device but the aggregate remembers prior fires (monotonic within subsystem lifecycle). |
| `collectors[].sent` | Cumulative wire emissions across all devices (live + deleted) for this tuple. |
| `collectors[].send_failures` | UDP write errors (collector unreachable, socket-level failure). |
| `devices_exporting` | Total count of LIVE devices with a `SyslogExporter` across all tuples. |
| `rate_limiter_tokens_available` | Present only when `-syslog-global-cap` is set; instantaneous snapshot, not synchronised with concurrent waits. |
| `catalogs_by_type` | Map of `<slug>` → `{entries, source}` showing the merged-catalog state. `_universal` key is always present when the subsystem is running. `source` is `"embedded"`, `"file:<path>"`, or `"override:<path>"` when `-syslog-catalog` was supplied. |

When the subsystem is stopped (or never started):

```json
{"subsystem_active": false, "collectors": [], "devices_exporting": 0}
```

Clients that previously branched on the retired `enabled` scalar
should branch on `subsystem_active` (primary) or `len(collectors) > 0`
(secondary — true only when at least one device has opted in).

## CLI flags

Documented with types, defaults, and purposes at
[CLI flags → UDP syslog export](cli-flags.md#udp-syslog-export-flags).

## Related

- [UDP syslog export (operator guide)](../ops/syslog-export.md) — enabling, per-device source binding, smoke test
- [SNMP trap reference](snmp-traps.md) — sibling feature; unified template vocabulary and catalog overlay semantics
- [Web API](web-api.md) — control-plane REST surface
- Epic [#76](https://github.com/labmonkeys-space/nl6/issues/76) for original design and implementation context; epic [#103](https://github.com/labmonkeys-space/nl6/issues/103) for per-type catalogs + unified vocabulary
