---
sidebar_label: "SNMP traps"
description: "The trap and INFORM wire format for SNMP v1, v2c and v3, the catalog JSON schema, the HTTP endpoints and the status JSON shape."
---

# SNMP traps and INFORMs

nl6 emits notifications in **all three SNMP versions**, one per fleet, selected with `-trap-snmp-version`: SNMPv2c (default), SNMPv1 Trap-PDUs, and SNMPv3 with RFC 3414 USM authentication and privacy.
INFORM is SNMPv2c only.
For enabling the feature, CLI flags, and troubleshooting see [SNMP trap export how-to](../ops/snmp-traps.md) and [CLI flags → SNMP trap / INFORM export](cli-flags.md#snmp-trap--inform-export-flags).

## Scope and security posture

**The notification path and the polling path are configured independently.** `-snmpv3-engine-id` and the `-snmpv3-*` flags configure the device's *polling* engine; `-trap-snmp-version` and the `-trap-snmpv3-*` flags configure what it *sends*.
A fleet can poll over SNMPv3 and emit v2c traps, or the reverse.

Polls over SNMPv3 are authenticated: nl6's USM implementation is RFC 3414 conformant and verified against net-snmp.

Under `-trap-snmp-version v2c` (the default) or `v1`, notifications carry no authentication at all.
The SNMPv2c community string (`-trap-community`, default `public`) rides in the clear on every trap and inform.
Do not select a production-like community secret.
The simulator is for testing collector plumbing, not for ingesting confidential data.

## Architecture

- **One central scheduler** fires every device, whatever the device count.
- **Each device** owns its UDP socket, request-id counter, pending-inform map and stats.
- **The universal catalog** is compiled in from `resources/_common/traps.json`. `-trap-catalog <path>` replaces the entire catalog surface (universal + per-type overlays) with a single JSON file.
- **Per-type catalog overlays** load from `resources/<slug>/traps.json` when present. Each device of type `<slug>` fires from the merged catalog (universal + per-type). See [Per-type catalog overlays](#per-type-catalog-overlays).
- **The global rate limiter** (`-trap-global-cap`) gates both fresh fires and INFORM retransmissions, so a collector outage cannot push wire traffic past the ceiling.

## Wire format

Every SNMPv2c notification is a BER-encoded SEQUENCE containing three top-level fields:

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
| `0xA4` | Trap-PDU (SNMPv1) | simulator → collector | `-trap-snmp-version v1` |

Inside each PDU: `request-id` (INTEGER), `error-status` (INTEGER, always 0 on emission), `error-index` (INTEGER, always 0), and a variable-bindings SEQUENCE.

Under `-trap-snmp-version v3` the `data` field is the **same `0xA7` SNMPv2-Trap-PDU**, and it is the top-level shape that changes: `community` is gone and the PDU travels inside a ScopedPDU and a USM envelope.
See [SNMPv3 notifications](#snmpv3-notifications).

## SNMPv1 traps

`-trap-snmp-version v1` switches the whole fleet to the RFC 1157 Trap-PDU, for exercising a collector's v1 path (OpenNMS `trapd` handles both).

The v1 message carries `version` `0` and a differently shaped PDU: `enterprise` (OBJECT IDENTIFIER), `agent-addr` (IpAddress, the device's own IPv4), `generic-trap` and `specific-trap` (INTEGER), `time-stamp` (TimeTicks), then the variable-bindings.

**The v1 identity is derived, not configured.** nl6 maps each existing catalog entry per [RFC 3584] §3.2, so no `traps.json` needs new fields:

| `snmpTrapOID` | `generic-trap` | `specific-trap` | `enterprise` |
|---|---|---|---|
| one of the six standard traps | `0` to `5` to match | `0` | the entry's `snmpTrapEnterprise` if it declares one, else `snmpTraps` (`1.3.6.1.6.3.1.1.5`) |
| anything else | `6` (enterpriseSpecific) | the OID's last sub-identifier | the OID with its last **two** sub-identifiers removed when the next-to-last is `0`, else its last **one** |

**A declared `snmpTrapEnterprise` is not an override.** RFC 3584 honours it only for a standard trap.
Across the shipped catalogs that means it is used by the v1 path in *zero* cases: the five standard entries declare none, and every vendor entry is enterprise-specific and therefore derives.
It is still emitted as a varbind under v2c.

**A v1 trap carries none of the three varbinds v2c prepends.** `sysUpTime.0` becomes `time-stamp`, `snmpTrapOID.0` becomes the identity above, and `snmpTrapEnterprise.0` becomes `enterprise`.
Only the entry's body varbinds appear in the variable-bindings list.

**There is no v1 INFORM.** RFC 1157 defines no acknowledged notification, so `-trap-snmp-version v1` with `-trap-mode inform` is refused at startup rather than silently downgraded.
A device that requests `inform` over REST while the fleet runs v1 is refused at attach for the same reason.

Several catalog entries can collapse to one v1 identity.
`ciena_waveserver5`'s four optical alarm entries share a trap OID, so under v1 they differ only in their varbinds, as on the real device.

[RFC 3584]: https://www.rfc-editor.org/rfc/rfc3584.txt

## SNMPv3 notifications

`-trap-snmp-version v3` switches the whole fleet to RFC 3414 USM-secured notifications, for exercising a collector's SNMPv3 trap path.

**The PDU is identical to v2c**, `0xA7` and all three auto-prepended varbinds included.
Only what wraps it changes:

| Layer | v2c | v3 |
|-------|-----|-----|
| outer | `version` + `community` + PDU | `version` + `msgGlobalData` + `msgSecurityParameters` + ScopedPDU |
| authentication | community string, in the clear | HMAC-MD5-96 or HMAC-SHA-96 over the whole message |
| confidentiality | none | CBC-DES or CFB-AES128 over the ScopedPDU |
| context | none | `contextEngineID` = the device's own engine ID, default (empty) context name |

`-trap-community` is ignored under v3: there is no community string anywhere in an SNMPv3 message.
nl6 says so at startup if you set it explicitly.

The USM passwords are command-line flags that every local user can read; see the warning in [Receive SNMPv3 notifications](../ops/snmp-traps.md#receive-snmpv3-notifications).

### Every device is its own SNMP engine

**The engine ID is derived from the device's IPv4 address and is not configurable.** It is an RFC 3411 §5 format-3 (MAC address) identity, 11 octets:

```
80 00 7E D9 | 03 | 02 42 aa bb cc dd
 PEN 32473  |fmt |  the device's own MAC
```

PEN 32473 is [RFC 5612]'s documentation number, held by IANA.
The MAC is the device's synthesized chassis ID, the same value `{{.ChassisID}}` renders and the LLDP provider advertises.
Two devices sharing a user and password therefore localize different keys.
A device whose address is not IPv4 is **refused at attach**.

**A polled device and a trap from it report different engine IDs.**
The polling engine's ID is fleet-wide (`-snmpv3-engine-id`).
A notification originator is authoritative for its own engine (RFC 3414 §2.1) and supplies its own `msgAuthoritativeEngineID`, `msgAuthoritativeEngineBoots` and `msgAuthoritativeEngineTime`.
There is no discovery on the trap path.

`msgAuthoritativeEngineTime` is seconds since **that device's engine** booted, not a Unix epoch, so a collector applying RFC 3414 §3.2's 150-second window accepts it.

### Configuring a receiver

Receiver setup, with the `snmptrapd` configuration and the `createUser` pitfall, is in [Receive SNMPv3 notifications](../ops/snmp-traps.md#receive-snmpv3-notifications).
`GET /api/v1/traps/status` reports each device's engine ID under `snmpv3.engine_ids_by_device`.

### Restart resets every engine, and traps have no discovery

`msgAuthoritativeEngineBoots` is **always 1** and is not persisted across a restart, while `msgAuthoritativeEngineTime` restarts from 0.

On the **poll** path a manager recovers by re-running discovery.
On the **trap** path there is no discovery: the receiver keeps whatever `(boots, time)` it last saw and applies RFC 3414 §3.2's 150-second window to it.
So after nl6 restarts, a collector that cached `(boots=1, time=T)` sees notifications claiming `(boots=1, time≈0)` and **rejects them as outside the time window** until its own estimate ages past T.

Restarting nl6 mid-run can therefore silently stop notification delivery to a long-lived collector.
`snmpEngineBoots` never increments, so a collector cannot distinguish a restart from a clock anomaly.
Clear the receiver's persistent USM state (see [Receive SNMPv3 notifications](../ops/snmp-traps.md#receive-snmpv3-notifications)) after restarting nl6, or wait the window out.

### No SNMPv3 INFORM

An SNMPv3 InformRequest is authoritative at the **receiver** (RFC 3414 §3.1), and nl6 does not discover the collector's engine.
`-trap-snmp-version v3` with `-trap-mode inform` is refused at startup, at per-device attach, and at fire.
It is never silently downgraded.

### Envelope size and the datagram budget

The USM envelope adds **91 bytes** to each shipped notification at `authPriv`/SHA1+AES (88 to 91 across the whole shipped corpus).
That matters only near the datagram budget: `ciena_waveserver5`'s 39-varbind optical alarms encode to 989 to 1000 bytes under v2c and 1080 to 1091 under v3, so **a low `-datagram-mtu` disables them sooner under v3 than under v2c**.
Between roughly MTU 1028 and 1119 they fire on a v2c fleet and are disabled on a v3 one.
The load-time budget check measures the fleet's own wire format, so the startup log names those entries with their v3 size and the MTU that would admit them.

v3 is the most expensive format per fire: about 6 to 7 times the allocations of the v2c path.
Benchmark on your own hardware if fire rate matters.

[RFC 5612]: https://www.rfc-editor.org/rfc/rfc5612.txt

### Auto-prepended varbinds

RFC 3416 §4.2.6 mandates the first two varbinds of every SNMPv2 notification.
The encoder always prepends them automatically.
Catalog authors supply only body varbinds; an entry listing any of the three reserved OIDs below as a body varbind fails catalog load:

| Position | OID | Type | Source |
|----------|-----|------|--------|
| 1 | `1.3.6.1.2.1.1.3.0` (`sysUpTime.0`) | TimeTicks (`0x43`) | Device uptime in 1/100-second ticks |
| 2 | `1.3.6.1.6.3.1.1.4.1.0` (`snmpTrapOID.0`) | OID (`0x06`) | Catalog entry's `snmpTrapOID` |
| 3 (optional) | `1.3.6.1.6.3.1.1.4.3.0` (`snmpTrapEnterprise.0`) | OID (`0x06`) | Catalog entry's `snmpTrapEnterprise` field, when set |

Positions 1 and 2 are unconditional per RFC 3416 §4.2.6.
Position 3 is emitted only when the catalog entry declares a non-empty `snmpTrapEnterprise` field.
RFC 3584 §4.1 pins the positional ordering.

Everything after the auto-prepended varbinds is the catalog entry's body varbinds with templates resolved to concrete values.

### INFORM acknowledgement

The collector replies to an INFORM with a GetResponse-PDU (`0xA2`) whose `request-id` matches the INFORM's.
The simulator demultiplexes acks via each device's per-device UDP socket, so there is no global request-id table.
Acks without a matching pending entry (duplicates, stale responses) are silently ignored.

## Catalog JSON schema

The embedded universal catalog at `resources/_common/traps.json` is the authoritative example of the schema:

```json
{
  "traps": [
    {
      "name": "linkDown",
      "snmpTrapOID": "1.3.6.1.6.3.1.1.5.3",
      "weight": 40,
      "role": "link-down",
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
| `comment` | string | no | Free text for the catalog author. Ignored by the loader. Any other unknown top-level key fails catalog load. |

Per-entry object:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `name` | string | yes | Unique within the catalog. Used by the HTTP fire-on-demand endpoint and for log attribution. |
| `snmpTrapOID` | string | yes | Dotted-decimal OID. Becomes the value of the auto-prepended `snmpTrapOID.0` varbind. |
| `snmpTrapEnterprise` | string | no | Dotted-decimal OID for the optional `snmpTrapEnterprise.0` varbind. When set, the encoder emits a third prepended varbind after `snmpTrapOID.0` and before body varbinds. Useful for v1↔v2c proxy compatibility (RFC 3584 §4.1); conventionally the MIB module root. |
| `weight` | integer | no (default `1`) | Relative weight for weighted-random selection by the scheduler. `0` or omitted is coerced to `1`; a negative value fails catalog load. To keep an entry out of scheduled firing, give it a `role`. |
| `role` | string | no | Tags the entry as state-driven. Allowed: `link-down`, `link-up`, `optical-sd-raise`, `optical-sd-clear`, `optical-sf-raise`, `optical-sf-clear`. Unknown values fail catalog load. A role-tagged entry is excluded from the scheduler's weighted pick and fires only through `EntriesByRole` on the matching transition (link roles on an interface oper-status change, optical roles on a pre-FEC threshold crossing). Empty means untagged, scheduler-driven. |
| `varbinds` | array | yes (may be empty) | Body varbinds following the auto-prepended ones. |

Per-varbind object:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `oid` | string | yes | Dotted-decimal OID. Templates allowed. Must not be `1.3.6.1.2.1.1.3.0` (`sysUpTime.0`), `1.3.6.1.6.3.1.1.4.1.0` (`snmpTrapOID.0`) or `1.3.6.1.6.3.1.1.4.3.0` (`snmpTrapEnterprise.0`; use the entry's `snmpTrapEnterprise` field). |
| `type` | string | yes | One of `integer`, `octet-string`, `oid`, `counter32`, `gauge32`, `timeticks`, `counter64`, `ipaddress`. |
| `value` | string | yes | Literal value, type-parsed against the `type` field. Templates allowed. |

### What counts as a well-formed OID

Every dotted OID in this file, whether a varbind name, `snmpTrapOID` or `snmpTrapEnterprise`, must satisfy the rules the encoder can actually represent (X.690 §8.19):

- The first arc is `0`, `1` or `2`.
- When the first arc is `0` or `1`, the second arc is at most `39`. Only a first arc of `2` may carry a large second arc, such as the ITU test arc `2.999`.
- Every arc, and the combined value of the first two, is at most `4294967295`.
- Every component is a number. A non-numeric component is not treated as zero.

An OID that breaks any of these is **rejected when the catalog loads**, naming the entry and the field.
That covers `snmpTrapOID`, `snmpTrapEnterprise` and literal body-varbind OIDs.
The load check is slightly stricter than the encoder on spelling and length: a signed component such as `+1.3` and an OID over 256 characters are refused at load even though the encoder could carry them.
A rejected entry fails its catalog file at load, like every other catalog validation error.

A **templated** varbind OID such as `1.3.6.1.2.1.2.2.1.7.{{.IfIndex}}` is checked only after it renders, since a `varbindOverrides` value supplied over REST can make it unencodable at fire time whatever the catalog says.
An override supplying a non-numeric or out-of-range component therefore makes the trap fail to encode at fire time.
The same refusal covers the value of an `oid`-typed varbind, which can go bad by the identical rendered-template route.
The failure is logged once per device and counted in `send_failures` on `GET /api/v1/traps/status`, so a template that renders badly is visible without a packet capture.

### Universal catalog (embedded default)

Ships five entries, all from `SNMPv2-MIB`:

| Name | `snmpTrapOID` | Weight | Role | Body varbinds |
|------|---------------|--------|------|---------------|
| `linkDown` | `1.3.6.1.6.3.1.1.5.3` | 40 | `link-down` | `ifIndex`, `ifAdminStatus` = 2, `ifOperStatus` = 2 |
| `linkUp` | `1.3.6.1.6.3.1.1.5.4` | 40 | `link-up` | `ifIndex`, `ifAdminStatus` = 1, `ifOperStatus` = 1 |
| `authenticationFailure` | `1.3.6.1.6.3.1.1.5.5` | 10 | _(none)_ | _(none)_ |
| `coldStart` | `1.3.6.1.6.3.1.1.5.1` | 5 | _(none)_ | _(none)_ |
| `warmStart` | `1.3.6.1.6.3.1.1.5.2` | 5 | _(none)_ | _(none)_ |

`linkDown` and `linkUp` are role-tagged and never fire from the scheduler.
They fire on an interface oper-status transition: a flap scenario (`-if-flap-scenario`), a REST `oper-status` or `admin-status` POST, or an SNMP SET of `ifAdminStatus`.
The scheduler draws from the three untagged entries only, so the scheduled weight is 20.

### Template vocabulary

Both `oid` and `value` fields are evaluated as Go `text/template` strings per fire.
The vocabulary is **unified with the syslog subsystem**.
The same twelve fields work on both sides:

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
| `{{.NowLocal}}` | Fire time as local `2006-01-02 15:04:05`, for DisplayString date varbinds such as CIENA-WS `DateAndTime` |
| `{{.Detail}}` | Per-fire free-form measurement suffix. Empty unless the firing site supplies it (the optical alarms carry the triggering OSNR this way) |
| `{{.IfAdminStatus}}` | Admin status of `IfIndex` read from the interface state engine at fire time. Syslog spells it `up(1)` or `down(2)` as an SNMP display renders `ifAdminStatus`; a trap renders the IF-MIB integer `1` or `2` so it can fill a typed `ifAdminStatus` varbind. A state-driven link fire carries the admin value of its event. Up on a device without an engine |

References to any other field fail catalog load, and the simulator refuses to start.
Class 2 random-per-fire fields (`PeerIP`, `User`, `SourceIP`, `RuleName`, `NeighborRouterID`, `PeerAS`) are not supported.

## Per-type catalog overlays

Devices can ship vendor-flavoured trap content via per-type JSON files at `resources/<slug>/traps.json`.
When a per-type file exists, the simulator merges it with the universal catalog using **name-based overlay semantics**:

1. Entries whose names are unique to the per-type file are **added**.
2. Entries whose names match a universal entry **override** the universal entry for devices of that type.
3. Universal entries with no matching per-type name **carry through**.

Set `"extends": false` at the top of the per-type file for a pure replacement.
Weights are recomputed over the merged entry set after overlay.
Operators tuning the distribution should check `GET /api/v1/traps/status` → `catalogs_by_type` for the resulting entry counts.

### Shipped vendor catalogs

| Slug | Count | Notable entries |
|------|-------|-----------------|
| `cisco_ios` | 7 Cisco-MIB entries (merged total 12) | `ciscoConfigManEvent`, `ciscoEnvMonSupplyStatusChangeNotif`, `ciscoEnvMonTemperatureNotification`, `cefcModuleStatusChange`, `cefcFanTrayStatusChangeNotif`, `ciscoEntSensorThresholdNotification`, `ciscoFlashDeviceChangeTrap`. All with `snmpTrapEnterprise` set to `1.3.6.1.4.1.9.9.<mib-root>`. |
| `juniper_mx240` | 7 JUNIPER-MIB entries (merged total 12) | `jnxPowerSupplyFailure`, `jnxFanFailure`, `jnxOverTemperature`, `jnxFruRemoval`, `jnxFruInsertion`, `jnxFruPowerOff`, `jnxFruFailed` (all `jnxChassisTraps` family). `snmpTrapEnterprise` = `1.3.6.1.4.1.2636` on all entries. |
| `juniper_mx10004` | 7 JUNIPER-MIB entries (merged total 12) | The same seven `jnxChassisTraps` entries as `juniper_mx240`. `snmpTrapEnterprise` = `1.3.6.1.4.1.2636` on all entries. |
| `ciena_waveserver5` | 4 CIENA-WS entries (merged total 9) | `opticalPreFecSdRaise`, `opticalPreFecSdClear`, `opticalPreFecSfRaise`, `opticalPreFecSfClear`. All role-tagged (`optical-sd-*`, `optical-sf-*`), so they fire on a pre-FEC threshold crossing and never from the scheduler. |

Other cisco_* slugs (`cisco_catalyst_9500`, `cisco_crs_x`, `cisco_nexus_9500`, `asr9k`, `cisco_asr9902`), `juniper_mx960`, Arista, Linux, and Palo Alto fall back to the universal catalog.
Their realistic content depends on Class 2 random fields, which are not supported.

## Starting trap export

Starting export, INFORM mode and per-device source IPs are covered in the [trap export how-to](../ops/snmp-traps.md#enable-trap-export).
The per-device `traps` block of `POST /api/v1/devices` is in [Web API → Per-device export blocks](web-api.md#per-device-export-blocks).

## HTTP endpoints

### Fire a trap on demand

`POST /api/v1/devices/{ip}/trap` schedules one trap for the named device immediately, bypassing the Poisson scheduler.
Body:

```json
{
  "name": "linkDown",
  "varbindOverrides": {
    "IfIndex": "3"
  }
}
```

`name` is required and must match an entry in the **device's resolved catalog** (the per-type overlay if present, the universal catalog otherwise).
`varbindOverrides` is optional.
Supplied keys pin the corresponding template field for this fire only.
Only the twelve fields of the [template vocabulary](#template-vocabulary) are accepted.

Responses:

| Status | Body | When |
|--------|------|------|
| `202 Accepted` | `{"requestId": <uint32>}` | Success; the trap has been enqueued. For INFORM mode the `requestId` is the INFORM PDU's `request-id`. Correlate with `/api/v1/traps/status` to watch its lifecycle. |
| `400 Bad Request` | `{"error": "...", "catalog": "<slug>", "availableEntries": [...]}` | Unknown catalog entry for the device. The body names the catalog the device resolved to (`cisco_ios`, `_universal`, etc.) and lists its entries alphabetically. For malformed JSON or missing `name`, the legacy envelope form `{"success": false, "message": "..."}` applies. |
| `404 Not Found` | `{"success": false, "message": "..."}` | Unknown device IP. |
| `500 Internal Server Error` | `{"success": false, "message": "..."}` | The fire failed for a non-lookup reason, such as a template resolve error or a write failure. The simulator log carries the detail. |
| `503 Service Unavailable` | `{"success": false, "message": "..."}` | The trap subsystem has not started **or** the target device has no trap config (i.e. it was created without a `traps` block and didn't inherit the CLI seed). |

The endpoint is fire-and-forget.
It does **not** block waiting for an INFORM ack.

### Trap export status

`GET /api/v1/traps/status` returns a current snapshot of the trap subsystem.

Unlike `/api/v1/flows/status`, this endpoint does **not** wrap its body in the `{success, message, data}` envelope.
`TrapStatus` is serialised directly at the top level.

**Response shape** (array-of-collectors aggregated by `(collector, mode)`):

```json
{
  "subsystem_active": true,
  "snmp_version": "v3",
  "snmpv3": {
    "user": "nl6trap",
    "security_level": "authPriv",
    "auth_protocol": "sha1",
    "priv_protocol": "aes128",
    "engine_id_format": "RFC 3411 section 5 format 3: 80007ed9 (PEN 32473) || 03 || 0242 || the device's IPv4 in hex",
    "engine_ids_by_device": {"10.0.0.1": "80007ed90302420a000001"}
  },
  "collectors": [
    {
      "collector": "192.168.1.10:162",
      "mode":      "inform",
      "devices":   80,
      "sent":      182430,
      "send_failures": 2,
      "informs_pending": 17,
      "informs_acked":   182380,
      "informs_failed":  33,
      "informs_dropped": 0
    },
    {
      "collector": "192.168.1.20:162",
      "mode":      "trap",
      "devices":   20,
      "sent":      6000,
      "send_failures": 0
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
`sent` means the datagram reached the kernel.
`send_failures` counts fires that did not: a template that resolves or renders to something unencodable, a refused write, or a failed INFORM retransmission.
It moves on every occurrence, though the matching log line is emitted once per exporter.
`snmp_version` (`v2c`, `v1` or `v3`) is present once the subsystem is active.
`snmpv3` is present only under `-trap-snmp-version v3` and reports what a receiver needs: `user`, `security_level`, `auth_protocol`, `priv_protocol`, `engine_id_format` and `engine_ids_by_device` (device IP to lowercase hex engine ID, the string `createUser -e 0x...` wants).
No password or localized key is reported.

`subsystem_active` is `true` whenever the HTTP server is answering.
Branch on it rather than length-checking `collectors`.
`subsystem_active=true` with `collectors=[]` means no device has opted in.

Counters are **monotonic until process exit**: deleting a device does not zero its collector's `sent` counter.
A `devices=0` record therefore means "no live devices for this tuple, but historical fires still counted."

`catalogs_by_type` is present whenever `subsystem_active=true`.
Keys are device-type slugs with the reserved `_universal` entry for the fallback catalog.
Values include the merged entry count and the catalog's provenance: `"embedded"` (compiled-in universal), `"file:<path>"` (per-type overlay on disk), or `"override:<path>"` when `-trap-catalog` was supplied (in which case `catalogs_by_type` contains a single `_universal` entry).

`rate_limiter_tokens_available` is present only when `-trap-global-cap` is set; it's a best-effort instantaneous snapshot, not synchronised with concurrent rate-limiter waits.

The `sent` counter increments on **every wire emission including INFORM retransmissions**, so `sent` can exceed the sum of the four INFORM state counters under retry churn.
The counter invariant below applies to *originated* informs, not to the `sent` tally.

### Counter invariant

For INFORM mode, the four disjoint terminal states of every originated INFORM satisfy:

```
informs_pending + informs_acked + informs_failed + informs_dropped == informs_originated
```

`informs_originated` is not exposed in the status JSON.
If the four exposed counters do not add up across two successive polls, after allowing for informs originated between reads, report it as a bug.

## CLI flags

The `-trap-*` flags, including the five `-trap-snmpv3-*` USM settings, are documented with their types, defaults, and purposes at [CLI flags → SNMP trap / INFORM export](cli-flags.md#snmp-trap--inform-export-flags).

## Related

- [SNMP trap export how-to](../ops/snmp-traps.md) for how to enable it, INFORM constraints, and the `snmptrapd` smoke test
- [SNMP reference](snmp.md) for polling-side SNMP (v2c/v3 GETs, GETNEXTs, OID lookup, HC counters)
- [Web API](web-api.md) for the control-plane REST surface
