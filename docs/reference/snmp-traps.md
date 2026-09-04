# SNMP trap / INFORM reference

nl6 emits notifications in **all three SNMP versions**, one per fleet, selected
with `-trap-snmp-version`: SNMPv2c (default, `go/nl6/trap_v2c.go`), SNMPv1
Trap-PDUs (`go/nl6/trap_v1.go`), and SNMPv3 with RFC 3414 USM authentication and
privacy (`go/nl6/trap_v3.go`). INFORM is SNMPv2c only. This page covers
the wire format, the JSON catalog schema, the HTTP endpoints, and the status
JSON shape. For enabling the feature, CLI flags, and troubleshooting see
[SNMP trap / INFORM export (operator guide)](../ops/snmp-traps.md) and
[CLI flags → SNMP trap / INFORM export](cli-flags.md#snmp-trap--inform-export-flags).

## Scope and security posture

**The notification path and the polling path are configured independently.**
`-snmpv3-engine-id` and the `-snmpv3-*` flags configure the device's *polling*
engine; `-trap-snmp-version` and the `-trap-snmpv3-*` flags configure what it
*sends*. A fleet can poll over SNMPv3 and emit v2c traps, or the reverse.

Polls over SNMPv3 are authenticated: nl6's USM implementation is RFC 3414
conformant and verified against net-snmp
([nl6#624](https://github.com/labmonkeys-space/nl6/issues/624)).

Under `-trap-snmp-version v2c` (the default) or `v1`, notifications carry no
authentication at all. The SNMPv2c community string (`-trap-community`, default
`public`) rides
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
  (`EncodeTrap`, `EncodeInform`, `ParseAck`). The SNMPv1 and SNMPv3 encoders
  implement it without changing the scheduler or exporter; each ignores the
  argument its wire format has no field for (v1 the request-id, v3 the
  community).
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
| `0xA4` | Trap-PDU (SNMPv1) | simulator → collector | `-trap-snmp-version v1` |

Inside each PDU: `request-id` (INTEGER), `error-status` (INTEGER, always 0
on emission), `error-index` (INTEGER, always 0), and a variable-bindings
SEQUENCE.

Under `-trap-snmp-version v3` the `data` field is the **same `0xA7`
SNMPv2-Trap-PDU**, and it is the top-level shape that changes: `community` is
gone and the PDU travels inside a ScopedPDU and a USM envelope. See
[SNMPv3 notifications](#snmpv3-notifications).

## SNMPv1 traps

`-trap-snmp-version v1` switches the whole fleet to the RFC 1157 Trap-PDU, for
exercising a collector's v1 path (OpenNMS `trapd` handles both).
The default is `v2c` and is unchanged.

The v1 message carries `version` `0` and a differently shaped PDU: `enterprise`
(OBJECT IDENTIFIER), `agent-addr` (IpAddress, the device's own IPv4),
`generic-trap` and `specific-trap` (INTEGER), `time-stamp` (TimeTicks), then the
variable-bindings.

**The v1 identity is derived, not configured.** nl6 maps each existing catalog
entry per [RFC 3584] §3.2, so no `traps.json` needs new fields:

| `snmpTrapOID` | `generic-trap` | `specific-trap` | `enterprise` |
|---|---|---|---|
| one of the six standard traps | `0`–`5` to match | `0` | the entry's `snmpTrapEnterprise` if it declares one, else `snmpTraps` (`1.3.6.1.6.3.1.1.5`) |
| anything else | `6` (enterpriseSpecific) | the OID's last sub-identifier | the OID with its last **two** sub-identifiers removed when the next-to-last is `0`, else its last **one** |

**A declared `snmpTrapEnterprise` is not an override.** RFC 3584 honours it only
for a standard trap. Across the shipped catalogs that means it is used by the v1
path in *zero* cases: the five standard entries declare none, and every vendor
entry is enterprise-specific and therefore derives. It is still emitted as a
varbind under v2c, which is unchanged.

**A v1 trap carries none of the three varbinds v2c prepends.** `sysUpTime.0`
becomes `time-stamp`, `snmpTrapOID.0` becomes the identity above, and
`snmpTrapEnterprise.0` becomes `enterprise`. Only the entry's body varbinds
appear in the variable-bindings list.

**There is no v1 INFORM.** RFC 1157 defines no acknowledged notification, so
`-trap-snmp-version v1` with `-trap-mode inform` is refused at startup rather
than silently downgraded. A device that requests `inform` over REST while the
fleet runs v1 is refused at attach for the same reason.

One consequence worth expecting: several catalog entries can collapse to one v1
identity. `ciena_waveserver5`'s four optical alarm entries share a trap OID, so
under v1 they differ only in their varbinds. That is how v1 works and what the
real device does; it is not a mapping defect.

[RFC 3584]: https://www.rfc-editor.org/rfc/rfc3584.txt

## SNMPv3 notifications

`-trap-snmp-version v3` switches the whole fleet to RFC 3414 USM-secured
notifications, for exercising a collector's SNMPv3 trap path. The default is
`v2c` and is unchanged.

**The PDU is identical to v2c**, `0xA7` and all three auto-prepended varbinds
included. Only what wraps it changes:

| Layer | v2c | v3 |
|-------|-----|-----|
| outer | `version` + `community` + PDU | `version` + `msgGlobalData` + `msgSecurityParameters` + ScopedPDU |
| authentication | community string, in the clear | HMAC-MD5-96 or HMAC-SHA-96 over the whole message |
| confidentiality | none | CBC-DES or CFB-AES128 over the ScopedPDU |
| context | none | `contextEngineID` = the device's own engine ID, default (empty) context name |

`-trap-community` is ignored under v3: there is no community string anywhere in
an SNMPv3 message. nl6 says so at startup if you set it explicitly.

:::danger The USM passwords are on the command line

`-trap-snmpv3-password` and `-trap-snmpv3-priv-password` are the **first
secrets nl6 accepts as CLI flags** — the polling side deliberately has none. A
command line is not private: it is visible to every user on the host through
`ps`, readable at `/proc/<pid>/cmdline`, recorded in your shell history, and
echoed verbatim by `docker inspect` and `kubectl describe pod`.

Treat these as test credentials for a lab collector. Do not reuse a password
that protects anything else. An environment-variable or file form is recorded as
follow-up work; until it exists there is no way to pass these privately.
:::

### Every device is its own SNMP engine

**The engine ID is derived from the device's IPv4 address and is not
configurable.** It is an RFC 3411 §5 format-3 (MAC address) identity, 11 octets:

```
80 00 7E D9 | 03 | 02 42 aa bb cc dd
 PEN 32473  |fmt |  the device's own MAC
```

PEN 32473 is [RFC 5612]'s documentation number, held by IANA — nl6 has no PEN of
its own and claims nobody else's, the same call
[nl6#588](https://github.com/labmonkeys-space/nl6/issues/588) made for
`sysObjectID`. The MAC is the device's synthesized chassis ID, the same value
`{{.ChassisID}}` renders and the LLDP provider advertises, so the engine
identity is the identity the device already asserts elsewhere.

Deriving it is what makes **two devices sharing a user and password localize
different keys** — RFC 3414 localization is `H(Ku || engineID || Ku)`. A
configured, fleet-wide engine ID would give every simulated device the same
notification identity and the same key.

A device whose address is not IPv4 is **refused at attach** rather than falling
back to a default engine ID, for the same reason.

:::warning A polled device and a trap from it report different engine IDs

This looks like a bug and is not. The polling engine's ID is fleet-wide
(`-snmpv3-engine-id`), while a notification originator is authoritative for its
own engine (RFC 3414 §2.1) and supplies its own `msgAuthoritativeEngineID`,
`msgAuthoritativeEngineBoots` and `msgAuthoritativeEngineTime`. There is no
discovery on the trap path and nothing to echo.

:::

`msgAuthoritativeEngineTime` is seconds since **that device's engine** booted,
not a Unix epoch, so a collector applying RFC 3414 §3.2's 150-second window
accepts it.

### Configuring a receiver

`snmptrapd` needs the engine ID up front, because a trap carries no discovery
exchange for it to learn one from:

```
disableAuthorization yes
createUser -e 0x80007ed90302420a2a0009 trapuser SHA "authpass" AES "privpass"
authUser log trapuser priv
```

`0x80007ed9 03 0242<ip-in-hex>` is the device's derived engine ID: for
`10.42.0.9` that is `0a2a0009`. You do not have to compute it —
`GET /api/v1/traps/status` reports `snmpv3.engine_ids_by_device` for every
exporting device, along with the user name, security level and protocols.

:::warning `createUser` is consumed on first read

net-snmp **rewrites its own config**: on startup `snmptrapd` moves each
`createUser` line into its persistent store (`/var/lib/snmp/snmptrapd.conf` by
default) and deletes it from yours. A second run with a corrected password
therefore keeps the **stale** user and silently drops every trap.

Point the daemon at a scratch directory while you are iterating, and clear it
between attempts:

```bash
export SNMP_PERSISTENT_DIR=/tmp/nl6-trapd
rm -rf "$SNMP_PERSISTENT_DIR" && mkdir -p "$SNMP_PERSISTENT_DIR"
snmptrapd -f -Lo -On -C -c ./snmptrapd.conf udp:127.0.0.1:1162
```

`-C -c` makes it read only your file, so a host `/etc/snmp/snmptrapd.conf`
cannot change the result, and `-On` prints numeric OIDs so no MIBs are needed.
nl6's own interop test does exactly this.
:::

### Restart resets every engine, and traps have no discovery

`msgAuthoritativeEngineBoots` is **always 1** and is not persisted across a
restart, while `msgAuthoritativeEngineTime` restarts from 0.

On the **poll** path a manager recovers by re-running discovery. On the **trap**
path there is no discovery: the receiver keeps whatever `(boots, time)` it last
saw and applies RFC 3414 §3.2's 150-second window to it. So after nl6 restarts,
a collector that cached `(boots=1, time=T)` sees notifications claiming
`(boots=1, time≈0)` and **rejects them as outside the time window** until its own
estimate ages past T. The trap path is worse than the poll path here precisely
because it cannot re-synchronise itself.

Two consequences worth planning around: restarting nl6 mid-run can silently
stop notification delivery to a long-lived collector, and `snmpEngineBoots`
never increments, so a collector cannot distinguish a restart from a clock
anomaly. Clear the receiver's persistent USM state (see the warning above) after
restarting nl6, or wait the window out.

### No SNMPv3 INFORM

An SNMPv3 InformRequest is authoritative at the **receiver** (RFC 3414 §3.1):
the originator must first discover the *collector's* engine ID, boots and time,
localize a second key against that engine, and track its time window per
collector. nl6 has none of that state, so `-trap-snmp-version v3` with
`-trap-mode inform` is refused at startup, at per-device attach, and at fire —
never silently downgraded.

### Throughput cost

v3 is the most expensive format per fire, and unavoidably so: it skips the
allocation-free fast encoder (a v2c-only path by decision, exactly as SNMPv1
does), adds an HMAC over the whole message, and at `authPriv` adds a cipher pass
plus 8 bytes of `crypto/rand` salt. Measured on an Apple M1 Max with
`go test ./nl6/ -bench BenchmarkTrapEncode -benchmem`, four body varbinds:

| Format | allocations / fire | bytes / fire |
|--------|-------------------:|-------------:|
| v2c, fast encoder (what a v2c fleet runs) | 33 | 1,232 |
| v1 | 102 | 3,448 |
| v2c, reference encoder | 144 | 4,715 |
| v3 `noAuthNoPriv` | 207 | 6,002 |
| v3 `authNoPriv` | 215 | 6,754 |
| v3 `authPriv` (AES128) | 227 | 7,994 |
| v3 `authPriv` (DES) | 231 | 7,898 |

Roughly **6–7× the allocations of the shipped v2c fast path**, and about 1.5×
the reference encoder's. Allocation counts are stable across runs and machines,
which is why the table quotes those and not nanoseconds: on the M1 Max above a
v3 `authPriv` fire measured 9–12 µs against 2.6–4.6 µs for the v2c fast path,
but the spread within a single run was wide enough that the ratio is not worth
quoting as a number. Run the benchmark on the hardware you care about.

Per-device *setup* is cheap and deliberately so: about 0.7 µs and 15
allocations to build one device's encoder, because RFC 3414 §A.2's
password-to-key step — a megabyte of hashing — is cached fleet-wide on the
password, and only the short localization hash is per device. A 30,000-device v3
fleet therefore pays that megabyte once.

The USM envelope adds **91 bytes** to each shipped notification at
`authPriv`/SHA1+AES (88–91 across the whole shipped corpus). That matters only
near the datagram budget: `ciena_waveserver5`'s 39-varbind optical alarms encode
to 989–1000 bytes under v2c and 1080–1091 under v3, so **a low `-datagram-mtu`
disables them sooner under v3 than under v2c** — between roughly MTU 1028 and
1119 they fire on a v2c fleet and are disabled on a v3 one.

The load-time budget check is measured at the fleet's **own** wire format, so
those entries are named in the startup log with their v3 size and the MTU that
would admit them, exactly as they are under v2c. (Before nl6#98 that check
always measured v2c, so a v3 fleet in that band disabled nothing and failed at
every fire instead.)

[RFC 5612]: https://www.rfc-editor.org/rfc/rfc5612.txt

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

An OID that breaks any of these is **rejected when the catalog loads**, naming the entry and the field (nl6#539).
That covers `snmpTrapOID`, `snmpTrapEnterprise` and literal body-varbind OIDs.
Whether a value qualifies is decided by asking the encoder itself, so the catalog can never load an OID the encoder then refuses.
The load check is slightly stricter than the encoder on spelling and length: a signed component such as `+1.3` and an OID over 256 characters are refused at load even though the encoder could carry them.
A rejected entry fails its catalog file at load, like every other catalog validation error.

A **templated** varbind OID such as `1.3.6.1.2.1.2.2.1.7.{{.IfIndex}}` is checked only after it renders, since a `varbindOverrides` value supplied over REST can make it unencodable at fire time whatever the catalog says.
An override supplying a non-numeric or out-of-range component therefore makes the trap fail to encode at fire time (nl6#540).
The same refusal covers the value of an `oid`-typed varbind, which can go bad by the identical rendered-template route.
The failure is logged once per device and counted in `send_failures` on `GET /api/v1/traps/status`, so a template that renders badly is visible without a packet capture.
The history of this spot: before nl6#529 such an OID was silently fabricated, so `3.40.1` went on the wire as `.4.0.1`; nl6#529 replaced the fabrication with a degenerate `06 00`, a binding no manager can match, still with no log line and no counter; nl6#540 replaced that emission with the refusal.

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

# SNMPv3 authPriv notifications. The engine ID is derived per device and is
# not configurable; -trap-community is ignored. INFORM is not available here.
sudo ./nl6 \
  -auto-start-ip 10.0.0.1 -auto-count 100 \
  -trap-collector 192.168.1.10:162 \
  -trap-snmp-version v3 \
  -trap-snmpv3-user trapuser \
  -trap-snmpv3-auth sha1 -trap-snmpv3-password authpass \
  -trap-snmpv3-priv aes128 -trap-snmpv3-priv-password privpass
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

`sent` means the datagram reached the kernel; a fire that did not lands in `send_failures` instead — a template that resolves or renders to something unencodable (nl6#540), a refused write, or a failed INFORM retransmission.
The counter moves on every occurrence even though the matching log line is emitted only once per exporter.
This is the same split flow and syslog status use (nl6#491).

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

The `-trap-*` flags — including the five `-trap-snmpv3-*` USM settings — are
documented with their types, defaults, and purposes at
[CLI flags → SNMP trap / INFORM export](cli-flags.md#snmp-trap--inform-export-flags).

## Related

- [SNMP trap / INFORM export (operator guide)](../ops/snmp-traps.md) — how to enable, INFORM constraints, `snmptrapd` smoke test
- [SNMP reference](snmp.md) — polling-side SNMP (v2c/v3 GETs, GETNEXTs, OID lookup, HC counters)
- [Web API](web-api.md) — control-plane REST surface
- Epic [#52](https://github.com/labmonkeys-space/nl6/issues/52) and PR [#65](https://github.com/labmonkeys-space/nl6/pull/65) for the original design and implementation context
