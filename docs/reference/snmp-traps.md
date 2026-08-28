# SNMP trap / INFORM reference

nl6 emits **SNMPv2c** notifications only. The PDU encoder in
`go/nl6/trap_v2c.go` handles TRAPs and INFORMs; SNMPv1 traps and SNMPv3
notifications are deferred and tracked as follow-up work. This page covers
the wire format, the JSON catalog schema, the HTTP endpoints, and the status
JSON shape. For enabling the feature, CLI flags, and troubleshooting see
[SNMP trap / INFORM export (operator guide)](../ops/snmp-traps.md) and
[CLI flags → SNMP trap / INFORM export](cli-flags.md#snmp-trap--inform-export-flags).

## Scope and security posture

Traps are always emitted as **SNMPv2c** regardless of whether the
simulator's polling side is configured with `-snmpv3-engine-id` — the
two paths are independent. An operator running v3-authenticated polls
against the simulator still sees v2c community-authenticated traps on
port 162.

The SNMPv2c community string (`-trap-community`, default `public`) rides
in the clear on every trap and inform. This is a property of SNMPv2c
itself, not a simulator choice, and matches how the simulator's polling
side treats v2c. Do not select a production-like community secret — the
simulator is for testing collector plumbing, not for ingesting
confidential data.

## Architecture

- **Central scheduler goroutine** (`trap_scheduler.go`) owns a min-heap of
  `(nextFire, deviceIP)` entries. Single goroutine regardless of device
  count — no 30k `time.Ticker`s.
- **Per-device `TrapExporter`** (`trap_exporter.go`) owns the device's UDP
  socket, request-id counter, pending-inform map, and stats.
- **Shared `TrapEncoder` interface** (`trap_v2c.go`) — narrow surface
  (`EncodeTrap`, `EncodeInform`, `ParseAck`) so SNMPv1 and SNMPv3 encoders
  can layer in later without changing the scheduler or exporter.
- **Embedded catalog** loaded via `go:embed` from
  `resources/_common/traps.json` at startup — no filesystem dependency
  for the out-of-box experience. `-trap-catalog <path>` replaces the
  entire catalog surface (universal + per-type overlays) with a single
  user-supplied JSON file.
- **Per-device-type catalog overlays** loaded from
  `resources/<slug>/traps.json` when present. Each device of type
  `<slug>` fires from the merged catalog (universal + per-type).
  See [Per-type catalog overlays](#per-type-catalog-overlays).
- **Global rate limiter** (`golang.org/x/time/rate`) gates both fresh
  fires and INFORM retransmissions so a collector outage cannot amplify
  wire traffic past the operator-configured ceiling.

## Wire format

Every SNMPv2c notification is a BER-encoded SEQUENCE containing three
top-level fields:

| Field | Type | Value |
|-------|------|-------|
| `version` | INTEGER | `1` (SNMPv2c) |
| `community` | OCTET STRING | From `-trap-community` (default `public`) |
| `data` | PDU | TRAP or InformRequest |

The PDU envelope is one of three ASN.1 tags:

| Tag | Name | Direction | Used for |
|-----|------|-----------|----------|
| `0xA7` | SNMPv2-Trap-PDU | simulator → collector | `-trap-mode trap` |
| `0xA6` | InformRequest-PDU | simulator → collector | `-trap-mode inform` |
| `0xA2` | GetResponse-PDU | collector → simulator | INFORM acknowledgement |

Inside each PDU: `request-id` (INTEGER), `error-status` (INTEGER, always 0
on emission), `error-index` (INTEGER, always 0), and a variable-bindings
SEQUENCE.

### Auto-prepended varbinds

RFC 3416 §4.2.6 mandates the first two varbinds of every SNMPv2
notification. The encoder always prepends them automatically — catalog
authors supply only body varbinds, and the catalog loader rejects entries
that list either reserved OID:

| Position | OID | Type | Source |
|----------|-----|------|--------|
| 1 | `1.3.6.1.2.1.1.3.0` (`sysUpTime.0`) | TimeTicks (`0x43`) | Device uptime in 1/100-second ticks |
| 2 | `1.3.6.1.6.3.1.1.4.1.0` (`snmpTrapOID.0`) | OID (`0x06`) | Catalog entry's `snmpTrapOID` |
| 3 (optional) | `1.3.6.1.6.3.1.1.4.3.0` (`snmpTrapEnterprise.0`) | OID (`0x06`) | Catalog entry's `snmpTrapEnterprise` field, when set |

Positions 1 and 2 are unconditional per RFC 3416 §4.2.6. Position 3 is
emitted only when the catalog entry declares a non-empty
`snmpTrapEnterprise` field — per SNMPv2-MIB §10 this additional-info
varbind aids v1↔v2c cross-compatibility on collectors that expect the
enterprise OID, and RFC 3584 §4.1 pins the positional ordering. All
three reserved OIDs (`sysUpTime.0`, `snmpTrapOID.0`,
`snmpTrapEnterprise.0`) are rejected when they appear as body varbind
OIDs — the encoder emits them automatically.

Everything after the auto-prepended varbinds is the catalog entry's
body varbinds with templates resolved to concrete values.

### INFORM acknowledgement

The collector replies to an INFORM with a GetResponse-PDU (`0xA2`) whose
`request-id` matches the INFORM's. The simulator demultiplexes acks via
each device's per-device UDP socket — no global request-id table. Acks
without a matching pending entry (duplicates, stale responses) are
silently ignored.

## Catalog JSON schema

The embedded universal catalog at
`go/nl6/resources/_common/traps.json` is the authoritative example
of the schema:

```json
{
  "traps": [
    {
      "name": "linkDown",
      "snmpTrapOID": "1.3.6.1.6.3.1.1.5.3",
      "weight": 40,
      "varbinds": [
        { "oid": "1.3.6.1.2.1.2.2.1.1.{{.IfIndex}}", "type": "integer", "value": "{{.IfIndex}}" },
        { "oid": "1.3.6.1.2.1.2.2.1.7.{{.IfIndex}}", "type": "integer", "value": "2" },
        { "oid": "1.3.6.1.2.1.2.2.1.8.{{.IfIndex}}", "type": "integer", "value": "2" }
      ]
    }
  ]
}
```

Top-level object:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `traps` | array | yes | List of catalog entries. Must contain at least one. |
| `extends` | bool | no (default `true`) | **Per-type overlays only.** Controls whether the per-type catalog merges on top of the universal (`true`) or fully replaces it for devices of that type (`false`). Ignored on the universal catalog itself. |

Per-entry object:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `name` | string | yes | Unique within the catalog. Used by the HTTP fire-on-demand endpoint and for log attribution. |
| `snmpTrapOID` | string | yes | Dotted-decimal OID. Becomes the value of the auto-prepended `snmpTrapOID.0` varbind. |
| `snmpTrapEnterprise` | string | no | Dotted-decimal OID for the optional `snmpTrapEnterprise.0` varbind. When set, the encoder emits a third prepended varbind after `snmpTrapOID.0` and before body varbinds. Useful for v1↔v2c proxy compatibility (RFC 3584 §4.1); conventionally the MIB module root. |
| `weight` | integer | no (default `1`) | Relative weight for weighted-random selection by the scheduler. Zero means omit the entry from scheduled firing (still reachable via the HTTP endpoint). |
| `varbinds` | array | yes (may be empty) | Body varbinds following the auto-prepended ones. |

Per-varbind object:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `oid` | string | yes | Dotted-decimal OID. Templates allowed. Must not be `1.3.6.1.2.1.1.3.0` (`sysUpTime.0`) or `1.3.6.1.6.3.1.1.4.1.0` (`snmpTrapOID.0`). |
| `type` | string | yes | One of `integer`, `octet-string`, `oid`, `counter32`, `gauge32`, `timeticks`, `counter64`, `ipaddress`. |
| `value` | string | yes | Literal value, type-parsed against the `type` field. Templates allowed. |

### What counts as a well-formed OID

Every dotted OID in this file, whether a varbind name, `snmpTrapOID` or `snmpTrapEnterprise`, must satisfy the rules the encoder can actually represent (X.690 §8.19):

- The first arc is `0`, `1` or `2`.
- When the first arc is `0` or `1`, the second arc is at most `39`. A wider one would be indistinguishable on the wire from a higher first arc, since `1.40` and `2.0` both encode to the same value. Only a first arc of `2` may carry a large second arc, which is how OIDs such as the ITU test arc `2.999` exist.
- Every arc, and the combined value of the first two, is at most `4294967295`.
- Every component is a number. A non-numeric component is not treated as zero.

Literal `snmpTrapEnterprise` values are checked for digits-and-dots at load and rejected otherwise; the arc bounds above are not checked at load for any field. Only templated varbind names can carry a non-numeric component to the encoder.

An OID that breaks any of these is emitted as a degenerate `06 00` rather than as a different, valid-looking OID. That is deliberate, and it is visible: a collector will reject the message rather than record an OID nobody wrote. Before nl6#529 such an OID was silently fabricated instead, so `3.40.1` went on the wire as `.4.0.1`.

A templated OID such as `1.3.6.1.2.1.2.2.1.7.{{.IfIndex}}` is checked after rendering, so an override supplying a non-numeric or out-of-range `IfIndex` produces the degenerate encoding at fire time.
That fire is not observable from nl6: the encoder has no error return, so no log line is written and no status counter moves. The collector's rejection is the only signal.

### Universal catalog (embedded default)

Ships five entries, all from `SNMPv2-MIB`:

| Name | `snmpTrapOID` | Weight | Body varbinds |
|------|---------------|--------|---------------|
| `linkDown` | `1.3.6.1.6.3.1.1.5.3` | 40 | `ifIndex`, `ifAdminStatus` = 2, `ifOperStatus` = 2 |
| `linkUp` | `1.3.6.1.6.3.1.1.5.4` | 40 | `ifIndex`, `ifAdminStatus` = 1, `ifOperStatus` = 1 |
| `authenticationFailure` | `1.3.6.1.6.3.1.1.5.5` | 10 | _(none)_ |
| `coldStart` | `1.3.6.1.6.3.1.1.5.1` | 5 | _(none)_ |
| `warmStart` | `1.3.6.1.6.3.1.1.5.2` | 5 | _(none)_ |

Weights bias scheduled firing toward link-state notifications (the most
common interesting traps for monitoring-pipeline validation) while still
exercising the other three types.

### Template vocabulary

Both `oid` and `value` fields are evaluated as Go `text/template`
strings per fire. The vocabulary is **unified with the syslog
subsystem** — the same nine fields work on both sides:

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

References to any other field are rejected at catalog load — the
simulator refuses to start rather than silently emitting a trap with
an empty OID component. Class 2 random-per-fire fields (`PeerIP`,
`User`, `SourceIP`, `RuleName`, `NeighborRouterID`, `PeerAS`) are
explicitly unsupported and tracked as follow-up work.

## Per-type catalog overlays

Devices can ship vendor-flavoured trap content via per-type JSON files
at `resources/<slug>/traps.json`. When a per-type file exists, the
simulator merges it with the universal catalog using **name-based
overlay semantics**:

1. Entries whose names are unique to the per-type file are **added**.
2. Entries whose names match a universal entry **override** the
   universal entry for devices of that type.
3. Universal entries with no matching per-type name **carry through**.

Set `"extends": false` at the top of the per-type file for a pure
replacement. Weights are recomputed over the merged entry set after
overlay — operators tuning the distribution should check
`GET /api/v1/traps/status` → `catalogs_by_type` for the resulting
entry counts.

### Shipped vendor catalogs

| Slug | Count | Notable entries |
|------|-------|-----------------|
| `cisco_ios` | 7 Cisco-MIB entries (merged total 12) | `ciscoConfigManEvent`, `ciscoEnvMonSupplyStatusChangeNotif`, `ciscoEnvMonTemperatureNotification`, `cefcModuleStatusChange`, `cefcFanTrayStatusChangeNotif`, `ciscoEntSensorThresholdNotification`, `ciscoFlashDeviceChangeTrap`. All with `snmpTrapEnterprise` set to `1.3.6.1.4.1.9.9.<mib-root>`. |
| `juniper_mx240` | 7 JUNIPER-MIB entries (merged total 12) | `jnxPowerSupplyFailure`, `jnxFanFailure`, `jnxOverTemperature`, `jnxFruRemoval`, `jnxFruInsertion`, `jnxFruPowerOff`, `jnxFruFailed` (all `jnxChassisTraps` family). `snmpTrapEnterprise` = `1.3.6.1.4.1.2636` on all entries. |

Other cisco_* slugs (`cisco_catalyst_9500`, `cisco_crs_x`,
`cisco_nexus_9500`, `asr9k`), `juniper_mx960`, Arista, Linux, and
Palo Alto fall back to the universal catalog — their realistic
content depends on Class 2 random fields deferred to a follow-up.
Family-catalog concept (one catalog shared by all `cisco_*` slugs) is
also a follow-up refactor.

## Starting trap export

Trap export is opt-in per device. There are two ways to configure it:

### 1. CLI seed (auto-start batch)

The `-trap-*` flags seed auto-created devices. Every device in the
auto-start batch gets the same collector, mode, community, and interval.

```bash
# SNMPv2c TRAP → 192.168.1.10:162, 100 auto-created devices, default
# interval=30s / community=public
sudo ./nl6 \
  -auto-start-ip 10.0.0.1 -auto-count 100 \
  -trap-collector 192.168.1.10:162

# INFORM mode (acknowledged) — requires -trap-source-per-device=true
# (the default). The check is enforced at device-attach time: if it's
# disabled, attach fails per-device and trapConfig is cleared.
sudo ./nl6 \
  -auto-start-ip 10.0.0.1 -auto-count 50 \
  -trap-collector 192.168.1.10:162 \
  -trap-mode inform \
  -trap-inform-timeout 3s -trap-inform-retries 5
```

### 2. REST body (per-device)

`POST /api/v1/devices` accepts an optional `traps` block per request.
Different batches can target different collectors or mix TRAP and INFORM.

```bash
# A: 50 TRAP-mode devices → collector A, community public
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.0.1",
    "device_count": 50,
    "traps": {
      "collector": "192.168.1.10:162",
      "mode": "trap",
      "community": "public",
      "interval": "30s"
    }
  }'

# B: 20 INFORM-mode devices → collector B, tight retry budget
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.1.1",
    "device_count": 20,
    "traps": {
      "collector": "192.168.1.20:162",
      "mode": "inform",
      "community": "private",
      "interval": "60s",
      "inform_timeout": "2s",
      "inform_retries": 3
    }
  }'
```

> **Note:** the `interval` field above is accepted and stored but **not honored** — every device fires at the simulator-wide `-trap-interval` cadence ([nl6#445](https://github.com/labmonkeys-space/nl6/issues/445)). The create response returns a `warnings` entry saying so. To silence a fleet use `-fidelity`, or `POST /api/v1/fidelity` to toggle it at runtime, not a long interval.

`/api/v1/traps/status` reports both batches as separate records keyed by
`(collector, mode)`.

The `traps` block is **optional** on every request — omit it and the
device doesn't fire traps. See
[Web API → POST /api/v1/devices](web-api.md#create-devices) for the full
per-device schema.

**Duration fields** (`interval`, `inform_timeout`) require **Go duration
strings** (`"30s"`, `"5m"`, `"1m30s"`). Integer seconds (`"interval": 30`)
are rejected with 400 — a deliberate mismatch with the `-trap-interval`
CLI flag, which takes integer seconds.

## HTTP endpoints

### Fire a trap on demand

`POST /api/v1/devices/{ip}/trap` — schedules one trap for the named
device immediately, bypassing the Poisson scheduler. Body:

```json
{
  "name": "linkDown",
  "varbindOverrides": {
    "IfIndex": "3"
  }
}
```

`name` is required and must match a catalog entry. `varbindOverrides` is
optional — supplied keys pin the corresponding template field for this
fire only.

Responses:

| Status | Body | When |
|--------|------|------|
| `202 Accepted` | `{"requestId": <uint32>}` | Success; the trap has been enqueued. For INFORM mode the `requestId` is the INFORM PDU's `request-id` — correlate with `/api/v1/traps/status` to watch its lifecycle. |
| `400 Bad Request` | `{"error": "...", "catalog": "<slug>", "availableEntries": [...]}` | Unknown catalog entry for the device. The enriched body tells the caller which catalog the device resolved to (`cisco_ios`, `_universal`, etc.) and lists its entries alphabetically so a scripted caller can self-service when it targeted the wrong vendor. For malformed JSON or missing `name`, the legacy envelope form `{"success": false, "message": "..."}` applies. |
| `404 Not Found` | `{"success": false, "message": "..."}` | Unknown device IP. |
| `500 Internal Server Error` | `{"success": false, "message": "..."}` | `Fire` failed for a non-lookup reason — template resolve error, catalog resolution returned nil despite feature active (pathological manager state), or write failure. Logs on the simulator side carry the detail. |
| `503 Service Unavailable` | `{"success": false, "message": "..."}` | The trap subsystem has not started **or** the target device has no trap config (i.e. it was created without a `traps` block and didn't inherit the CLI seed). |

The endpoint is fire-and-forget — it does **not** block waiting for an
INFORM ack.

### Trap export status

`GET /api/v1/traps/status` — current snapshot of the trap subsystem.

Unlike `/api/v1/flows/status`, this endpoint does **not** wrap its body
in the `{success, message, data}` envelope — `TrapStatus` is serialised
directly at the top level.

**Response shape** (array-of-collectors aggregated by `(collector, mode)`):

```json
{
  "subsystem_active": true,
  "collectors": [
    {
      "collector": "192.168.1.10:162",
      "mode":      "inform",
      "devices":   80,
      "sent":      182430,
      "informs_pending": 17,
      "informs_acked":   182380,
      "informs_failed":  33,
      "informs_dropped": 0
    },
    {
      "collector": "192.168.1.20:162",
      "mode":      "trap",
      "devices":   20,
      "sent":      6000
    }
  ],
  "devices_exporting": 100,
  "rate_limiter_tokens_available": 94,
  "catalogs_by_type": {
    "_universal":    {"entries": 5,  "source": "embedded"},
    "cisco_ios":     {"entries": 12, "source": "file:resources/cisco_ios/traps.json"},
    "juniper_mx240": {"entries": 12, "source": "file:resources/juniper_mx240/traps.json"}
  }
}
```

The **four `informs_*` fields appear only on records whose `mode == inform`**.
TRAP-mode records omit them.

`subsystem_active` is the authoritative "is the feature live?" signal —
`true` after `StartTrapSubsystem` runs. During normal operation of the
HTTP server this value is always `true`: the subsystem initialises in
`main()` and the only path that flips it to `false` is `StopTrapExport`,
which runs at process exit alongside the HTTP server. A `false` value
is therefore only observable programmatically (test harness, embedded
use). Clients should still branch on `subsystem_active` rather than
length-checking `collectors`. `subsystem_active=true` with
`collectors=[]` means the subsystem is running but no device has opted
in.

Counters are **monotonic within a subsystem lifecycle**: deleting a
device does not zero its collector's `sent` counter; the aggregate
persists via `sm.trapAggregates` until `StopTrapExport` (which is
today's process-exit path). A `devices=0` record therefore means "no
live devices for this tuple, but historical fires still counted."

`catalogs_by_type` is present whenever `subsystem_active=true`. Keys
are device-type slugs with the reserved `_universal` entry for the
fallback catalog. Values include the merged entry count and the
catalog's provenance: `"embedded"` (compiled-in universal),
`"file:<path>"` (per-type overlay on disk), or
`"override:<path>"` when `-trap-catalog` was supplied (in which case
`catalogs_by_type` contains a single `_universal` entry).

`rate_limiter_tokens_available` is present only when `-trap-global-cap`
is set; it's a best-effort instantaneous snapshot, not synchronised with
concurrent rate-limiter waits.

The `sent` counter increments on **every wire emission including INFORM
retransmissions**, so `sent` can exceed the sum of the four INFORM state
counters under retry churn. The counter invariant below applies to
*originated* informs, not to the `sent` tally.

### Counter invariant

For INFORM mode, the four disjoint terminal states of every originated
INFORM satisfy:

```
informs_pending + informs_acked + informs_failed + informs_dropped == informs_originated
```

`informs_originated` isn't exposed in the status JSON — it's an internal
counter verified by `TestInformInvariant_AtExporterLevel` in
`trap_api_test.go`. If the four exposed counters don't add up across two
successive polls (after allowing for newly-originated informs between
reads), something is miscounted or a retransmit path is skipping a
state transition.

## CLI flags

The nine `-trap-*` flags are documented with their types, defaults, and
purposes at
[CLI flags → SNMP trap / INFORM export](cli-flags.md#snmp-trap--inform-export-flags).

## Related

- [SNMP trap / INFORM export (operator guide)](../ops/snmp-traps.md) — how to enable, INFORM constraints, `snmptrapd` smoke test
- [SNMP reference](snmp.md) — polling-side SNMP (v2c/v3 GETs, GETNEXTs, OID lookup, HC counters)
- [Web API](web-api.md) — control-plane REST surface
- Epic [#52](https://github.com/labmonkeys-space/nl6/issues/52) and PR [#65](https://github.com/labmonkeys-space/nl6/pull/65) for the original design and implementation context
