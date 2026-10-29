# Trap and syslog export: catalogs, operational notes, syslog transports

Moved from CLAUDE.md so the auto-loaded file stays under its size limit. Read this before changing the area it covers.
The v1 Trap-PDU and v3 USM notification paths are in `context/snmpv3-usm-and-notifications.md`; the entry schemas and PRI vocabulary are in `docs/reference/snmp-traps.md` and `docs/reference/syslog-export.md`.

## Trap catalog

**Trap catalog:**
- Default catalog is compiled into the binary from `resources/_common/traps.json` via `embed.FS`, so the out-of-box experience has no filesystem dependency.
- Override with `-trap-catalog <path>` (complete replacement, not merge). When set, per-type overlays are NOT loaded. The single file becomes the catalog for every device.
- Universal catalog ships 5 entries: `coldStart`, `warmStart`, `linkDown`, `linkUp`, `authenticationFailure` (RFC 3418). Weights: linkDown=40, linkUp=40, authenticationFailure=10, coldStart=5, warmStart=5.
- **Catalog `role` field (Tier C, `correlate-state-notifications`):** an optional per-entry `"role"` (`link-down` | `link-up`; unknown rejected, empty = untagged) tags an entry as **state-driven**. Role-tagged entries are excluded from the scheduler's weighted-random `Pick` (a separate schedulable-weight tally that may be zero, so an all-role-tagged catalog still loads) and are instead fired by an oper-status transition via `EntriesByRole` (vendor-wins-per-role: overlay entries suppress the universal one). `linkDown`/`linkUp` are role-tagged in the shipped universal catalog, so the scheduler's effective universal weight drops to 20 (coldStart 5 + warmStart 5 + auth 10); link traps now come from real state changes. The loader warns (non-fatal) on a linkDown/linkUp-OID entry that lacks a role.
- **Per-type overlays:** `resources/<type>/traps.json` overlays the universal for devices of that type (e.g., `resources/cisco_ios/traps.json` affects all cisco_ios devices). Resolved lazily per fire via `SimulatorManager.CatalogFor(ip)` → `trapCatalogsByType[slug]` → `_universal`. Devices whose type has no per-type file fall through to the universal. `GET /api/v1/traps/status` exposes a `catalogs_by_type` object showing per-type entry counts and sources (embedded / file / override).
- **Shipped vendor catalogs** (PRs 4 & 5 of epic #103):
  - `cisco_ios/traps.json` carries 7 Cisco-MIB notifications: `ciscoConfigManEvent`, `ciscoEnvMonSupplyStatusChangeNotif`, `ciscoEnvMonTemperatureNotification`, `cefcModuleStatusChange`, `cefcFanTrayStatusChangeNotif`, `ciscoEntSensorThresholdNotification`, `ciscoFlashDeviceChangeTrap`. Merged with universal 5 → cisco_ios devices fire from 12 entries. All use `snmpTrapEnterprise` for v1↔v2c proxy compatibility.
  - `juniper_mx240/traps.json` carries 7 JUNIPER-MIB jnxChassisTraps-family notifications, all verified against the canonical MIB registration: `jnxPowerSupplyFailure` (.4.1.1), `jnxFanFailure` (.4.1.2), `jnxOverTemperature` (.4.1.3), `jnxFruRemoval` (.4.1.5), `jnxFruInsertion` (.4.1.6), `jnxFruPowerOff` (.4.1.7), `jnxFruFailed` (.4.1.9). Merged with universal 5 → juniper_mx240 devices fire from 12 entries. `snmpTrapEnterprise` = `1.3.6.1.4.1.2636` (Juniper Networks) on all entries. `jnxFruEntry` varbind OIDs use the correct 4-index INDEX suffix (container, L1, L2, L3).
  - Other cisco_* slugs (`cisco_catalyst_9500`, `cisco_crs_x`, `cisco_nexus_9500`, `asr9k`) and `juniper_mx960` fall back to universal in this epic. Family-catalog concept is a follow-up refactor.
- **Overlay semantic:** per-type files default to `"extends": true`. Entries unique to the per-type file are added, same-name entries override the universal, unused universal entries carry through. Set `"extends": false` at the top of the per-type JSON for a pure replacement (no universal content for that type). Weights are recomputed post-merge.
- **Unified template vocabulary (11 fields, trap + syslog share the same surface):** `{{.IfIndex}}`, `{{.IfName}}` (synthesised `GigabitEthernet0/<N>` in PR2; live `ifDescr.<N>` lookup in PR3), `{{.Uptime}}`, `{{.Now}}`, `{{.DeviceIP}}`, `{{.SysName}}`, `{{.Model}}` (human-readable label from slug → `deviceTypeLabels`), `{{.Serial}}` (`SN<hex>` synthesised from device IP, deterministic), `{{.ChassisID}}` (`02:42:xx:xx:xx:xx` MAC-style synthesised from device IP), `{{.NowLocal}}` (fire time as local `2006-01-02 15:04:05`, for DisplayString date varbinds like CIENA-WS DateAndTime), `{{.Detail}}` (per-fire free-form measurement, empty unless the firing site overrides it. Optical SD/SF alarms carry the triggering OSNR this way). Unknown fields are rejected at catalog load. Class 2 random-per-fire fields (`PeerIP`, `User`, `SourceIP`, `RuleName`, …) are explicitly deferred and rejected.
- Class 1 fields (SysName, Model, Serial, ChassisID) are resolved at exporter construction and captured on the exporter; IfName is resolved per fire via a callback. `FieldResolver` interface in `field_resolver.go` is the seam for testability and for the PR3 swap to live `ifDescr` lookup.
- The two mandatory SNMPv2-Trap varbinds (`sysUpTime.0`, `snmpTrapOID.0`) are prepended automatically by the encoder. Catalog authors supply only body varbinds; entries that list either reserved OID (or `snmpTrapEnterprise.0`) as a body varbind are rejected.
- Optional top-level `snmpTrapEnterprise` field (string, dotted OID) per entry. When set, the encoder emits an additional `snmpTrapEnterprise.0` varbind (OID `1.3.6.1.6.3.1.1.4.3.0`) after the two mandatory ones. It is useful for v1↔v2c cross-compatibility on collectors that expect the enterprise OID per SNMPv2-MIB §10. Catalog-loader rejects reserved OIDs (`sysUpTime.0`, `snmpTrapOID.0`, `snmpTrapEnterprise.0`) as enterprise values. Omit the field to keep the backward-compatible 2-varbind prefix.

## Trap operational notes

**Trap operational notes:**
- **`maxTrapPDU` is a FRAME bound, derived, not a literal (nl6#487).** It is `linkMTU - ipv4HeaderBytes - udpHeaderBytes` (1472 at the default MTU), registered in `recomputeDatagramBudgets()` so it tracks `-datagram-mtu`. It was previously a literal 1500 justified as "matches the buffer the legacy path allocated". That was the same payload-versus-frame conflation as nl6#485, which put a full-size trap at 1528 B on the wire. **Wire-verified:** an entry sized between the two bounds fragments 40/40 datagrams under the old bound and is refused under the new one. No address-family branch (unlike flow), because trap collectors resolve `udp4` only. Three sites read it and must stay in agreement: the `trapBufPool` allocation, the reference-encoder scratch clamp (both `trap_exporter.go`), and the encode guard (`trap_encode_fast.go`).
- **Two size enforcement points; the load-time one DISABLES rather than rejects.** Catalog load dry-renders each entry (worst-case context INCLUDING a worst-case `{{.Detail}}` and a max request ID. Rendering `Detail` empty let a Raise entry pass load and fail at every fire while its Clear was disabled, which can strand an alarm) and marks anything over budget `oversized`: it stays in the catalog but is excluded from BOTH `Pick` and `EntriesByRole`, and is named once at startup. Filtering only `Pick` would leave an oversized `linkDown` firing on every oper-status transition. Loading does NOT fail, because the budget follows an operator-settable MTU. Rejecting would make any `-datagram-mtu` below ~1004 refuse to boot on nl6's own shipped optical catalogs, which the operator can fix from neither side. The fire-time encode guard remains the backstop for runtime `{{.Detail}}` and REST `varbindOverrides`, which a load-time render cannot bound.
- **Lowering `-datagram-mtu` disables shipped optical trap entries.** The Ciena `opticalPreFecS[DF]{Raise,Clear}` alarms carry 39 varbinds and encode to 989-1000 B once `{{.Detail}}` and a worst-case request ID are accounted for, so below roughly MTU 1028 they stop firing and are named in the startup log with the size, the gap, and the MTU that would admit them. If optical alarms go quiet after an MTU change, that log line is the answer.
- `TrapSubsystemConfig.PDUBudget` is **required** and passed explicitly by the caller after `SetLinkMTU` has run; a non-positive value is rejected rather than defaulted. The loader does not read the global, so a size check cannot silently run against the default MTU if startup order changes.
- The fire-path resolve/encode error log is `sync.Once`-gated per exporter (`logFirstEncodeErr`), matching `firstWriteErr`. Ungated it was ~1,000 lines/second at 30k devices for a defect present since startup. `sendFailures` still counts every occurrence. Only the log line is suppressed.
- INFORM mode (`-trap-mode inform`) requires `-trap-source-per-device=true` (the default) so the per-device UDP socket can demux acks without a global request-id table. Enforced at device-attach time (phase 4 moved it out of startup).
- Pending-inform map is bounded at 100 per device with oldest-drop overflow policy (exposed as `informsDropped` in `GET /api/v1/traps/status`).
- Retransmissions consume global-cap tokens (design decision to prevent retry-storm amplification when the collector is unreachable).
- Collector-side `rp_filter` may need relaxing (`net.ipv4.conf.*.rp_filter=0` or `2`) to accept UDP/162 with 10.42.0.0/16 source IPs. Flow export documents the same caveat.
- Per-device UDP source binding reuses the same `setupVethPair` + `FORWARD -i veth-sim-host -j ACCEPT` iptables rule that flow export already relies on. No new netns / iptables surface.
- **`StopTrapExport` is shutdown-only** (phase-5 review D1). It is not safe to race concurrent device creation: `startDeviceTrapExporter` captures scheduler / pool / encoder pointers under a short RLock and uses them outside that lock, so a concurrent Stop can leave orphan exporters or closed sockets. Today it is only called from the process-exit signal handler. Do not introduce a runtime "restart trap subsystem" control path without first tightening the attach-path lock discipline.

**Trap HTTP endpoints:**
- `GET /api/v1/traps/status` returns a JSON array-of-collectors: `{subsystem_active, collectors: [{collector, mode, devices, sent, send_failures, informs_pending?, informs_acked?, informs_failed?, informs_dropped?}], devices_exporting, rate_limiter_tokens_available?, catalogs_by_type?}`. `subsystem_active=false` means `StartTrapSubsystem` has not run; `subsystem_active=true` with `collectors=[]` means running but no device has opted in. INFORM counters are only present on records with `mode=inform`. `sent` means reached the kernel; a fire that did not (resolve/encode failure incl. an unencodable rendered OID per nl6#540, refused write, failed INFORM retransmission) lands in `send_failures`, which moves on every occurrence while the log line stays `sync.Once`-gated. `catalogs_by_type` reports per-type overlay counts and source (`embedded` / `file:resources/<slug>/traps.json` / `override:<path>`).
- `POST /api/v1/devices/{ip}/trap` takes the body `{"name":"linkDown","varbindOverrides":{"IfIndex":"3"}}` → `202 Accepted` + `{"requestId": N}`. `400` for unknown catalog entry (response body includes `catalog` (the device's resolved catalog label) and `availableEntries` list so operators can self-service), `404` for unknown device, `503` when the subsystem is not running or the device has no trap config. Fire-and-forget: returns without waiting on INFORM ack.

## Syslog catalog

**Syslog catalog:**
- Default catalog is compiled into the binary from `resources/_common/syslog.json` via `embed.FS`, so the feature works out of the box.
- Override with `-syslog-catalog <path>` (complete replacement, not merge). When set, per-type overlays are NOT loaded.
- Universal catalog ships 6 entries: `interface-up` / `interface-down` (local7.notice/error, IFMGR), `auth-success` / `auth-failure` (authpriv.info/warning, sshd), `config-change` / `system-restart` (local7.notice/warning, SYSMGR). Weights sum to 135.
- **Catalog `role` field (Tier C):** same semantics as the trap side. `interface-down`/`interface-up` are role-tagged (excluded from `Pick`, fired by oper transitions). With vendor-wins-per-role, a `cisco_ios` port-down fires both `%LINK-3-UPDOWN` and `%LINEPROTO-5-UPDOWN` (and NOT the generic `interface-down`); `juniper_mx240` fires `SNMP_TRAP_LINK_DOWN`/`_UP`.
- **Per-type overlays:** mirror trap-side behaviour. `resources/<type>/syslog.json` overlays the universal for devices of that type. Resolved via `SimulatorManager.SyslogCatalogFor(ip)`. Defaults to `"extends": true` (merge, same-name override); set `"extends": false` for pure replacement. `GET /api/v1/syslog/status` reports `catalogs_by_type` for observability. `POST /api/v1/devices/{ip}/syslog` resolves entry names against the device's catalog; a 400 response includes `catalog` and `availableEntries` for self-service.
- **Shipped vendor catalogs** (PRs 4 & 5 of epic #103):
  - `cisco_ios/syslog.json` carries 8 Cisco-format messages: `%LINK-3-UPDOWN` (up/down pair), `%LINEPROTO-5-UPDOWN` (up/down pair), `%SYS-5-CONFIG_I`, `%SNMP-5-COLDSTART`, `%SYS-5-RESTART`, `%ENVMON-5-TEMP_OK`. Merged with universal 6 → cisco_ios devices fire from 14 entries. Message bodies match IOS's `%FACILITY-SEVERITY-MNEMONIC:` form verbatim so OpenNMS UEI matchers tuned for Cisco strings fire correctly.
  - `juniper_mx240/syslog.json` carries 7 Junos-format messages using daemon tags (`snmpd`, `mib2d`, `chassisd`, `mgd`, `license-check`) and Junos MSGID structure: `SNMP_TRAP_LINK_UP` / `SNMP_TRAP_LINK_DOWN`, `MIB2D_IFD_IFL_ENCAPS_MISMATCH`, `CHASSISD_FRU_TEMP_CRITICAL`, `CHASSISD_EEPROM_READ_FAIL`, `LICENSE_EXPIRED_KEY_DELETED`, `UI_COMMIT_COMPLETED`. Merged with universal 6 → juniper_mx240 devices fire from 13 entries. Message bodies match Junos's canonical `MSGID: body` form verbatim.
  - Linux / Palo Alto / Arista are deferred, because their realistic content requires Class 2 random-per-fire fields.
- **Unified template vocabulary (11 fields, same set as trap):** `{{.DeviceIP}}`, `{{.SysName}}`, `{{.IfIndex}}`, `{{.IfName}}`, `{{.Now}}`, `{{.Uptime}}`, `{{.Model}}`, `{{.Serial}}`, `{{.ChassisID}}`. Unknown fields are rejected at catalog load. Class 2 random fields (`PeerIP`, `User`, `SourceIP`, `RuleName`, …) remain deferred. See trap section above for resolution semantics. Trap and syslog share the same `FieldResolver` seam and Class 1 values are captured at exporter construction.
- SD-NAME keys are validated against RFC 5424 §6.3.3 at load; each templated value is pre-compiled to a `*template.Template` so the fire hot path is allocation-light (measured 894 ns/op).
- Entry `appName` is required (RFC 3164 TAG has no NILVALUE). Facility and severity accept canonical names (`local7`, `error`) or integers in range (`0..23` / `0..7`). MTU-safety dry-render rejects entries whose worst-case rendered output exceeds 1400 bytes.

## Syslog HOSTNAME derivation priority

**HOSTNAME derivation priority** (resolved at fire time, per design §D5):
1. If the catalog entry defines a non-empty `hostname` template, render it (with the six-field vocabulary) and use the result.
2. Otherwise, use the device's stored `sysName.0` value (captured at device construction).
3. Otherwise, use the device's IPv4 as dotted-quad.

In every branch the result is run through `sanitiseHostname`: spaces become hyphens (spec mandate), other framing / control chars become `_`.

## Syslog transport seam: TCP (nl6#92)

**Syslog transport seam (`add-syslog-tcp`, nl6#92):** `SyslogTransport` (`syslog_transport.go`) sits UNDER the write; catalog resolution, template vocabulary, the scenario gate and ledger accounting stay above it and are transport-independent. `udpTransport` is the datagram path byte-for-byte (including the per-device-bind → shared-pool ladder); `tcpTransport` (`syslog_transport_tcp.go`) is RFC 6587. Same shape as `DialoutTransport`. **TCP is deliberately NOT symmetric with UDP:** it has no shared-socket rung, because one connection carrying several devices multiplexes them into a framed stream with no field to demultiplex on. So a failed connection refuses the attach, and `-syslog-source-per-device=false` makes a TCP attach FAIL rather than degrade. Three things are load-bearing and non-obvious: (1) `SO_SNDBUF` is capped at 16 KiB because Linux auto-tunes to ~4 MiB per connection and this opens one per device (~117 GiB at 30k devices); (2) every write carries a deadline, because the syslog scheduler fires INLINE for the whole fleet so one stalled collector would stop every device; (3) only a read ERROR counts as connection loss, because a collector banner would otherwise cause a permanent connect/drop loop. `sent` means "handed to the kernel" on TCP, not "on the wire"; status rows carry `transport` so TCP and UDP devices do not merge. **`maxSyslogMessageBytes = 1400` is a DATAGRAM bound that applies to every catalog regardless of transport**. That is deliberate, since the check is a once-per-entry dry render at load and making it transport-aware would defer it to a per-device runtime failure.

## Syslog TLS (nl6#93)

**Syslog TLS (`add-syslog-tls`, nl6#93):** there is NO `tlsTransport` type. RFC 5425 IS RFC 6587 inside a TLS session, so TLS decorates the DIALER (`syslog_transport_tls.go`) and `tcpTransport` is reused whole. **nl6 is the CLIENT: it verifies the COLLECTOR (`tls.ca_pem` INLINE / system roots / explicit `insecure_skip_verify`) and presents no cert.** The CA is inline PEM, not a path, because the per-device config is REST-settable and a path there is an arbitrary-file-read primitive (CodeQL `go/path-injection`); a path survives only as `-syslog-tls-ca`, read once at startup by `loadSyslogTLSCAFile`. The issue asked which cert to present. That misreads the direction; `sharedTLSCert` is a SERVER identity and is relevant only under mTLS, which is rejected until implemented. **The trap to know:** `dialOnce` caps `SO_SNDBUF` and sets keepalives via `c.(*net.TCPConn)`, which a `*tls.Conn` does not satisfy. So the TLS dialer calls `applySyslogTCPSocketOptions` on the raw socket BEFORE wrapping. Skip that and every TLS device silently inherits Linux's ~4 MiB auto-tuned buffer (~117 GiB at 30k devices). Port defaults to 6514 vs 514, so a bare hostname changes port when the transport changes. TLS record buffers are per connection and ADDITIONAL to the socket buffer, so the plaintext fleet-memory figure does not carry over.

## Syslog operational notes and endpoints

**Syslog operational notes:**
- The format is per-device post-phase-5. Each device's `syslogConfig.Format` sets its own wire format. The shared-socket pool is keyed by `(collector, format)` so 5424 and 3164 streams never interleave on the same socket.
- Per-device UDP source binding reuses the same `setupVethPair` + `FORWARD -i veth-sim-host -j ACCEPT` rule shared by flow / trap. No new netns / iptables surface.
- Per-device bind failure is **non-fatal** for syslog (unlike INFORM): exporter logs a warning and falls back to the shared socket. When the primary per-device write fails but the shared fallback succeeds, the primary failure is logged and stats count the send as successful. If **both** per-device bind and shared-pool open fail, the attach is rejected so `ListDevices` doesn't show a ghost entry.
- The collector-side `rp_filter` caveat is the same as flow / trap. Accept UDP from device IPs with `net.ipv4.conf.*.rp_filter=0` or `2`.
- On-demand HTTP fires **bypass the global rate limiter** (test-harness use case; scheduler-driven traffic still honours `-syslog-global-cap`).
- **`StopSyslogExport` is shutdown-only** (phase-5 review D1). Same constraint as trap: `startDeviceSyslogExporter` uses captured pointers outside the short RLock. Only called from the process-exit path today. Tightening is a pre-requisite for any runtime "restart" control plane.

**Syslog HTTP endpoints:**
- `GET /api/v1/syslog/status` returns a JSON array-of-collectors: `{subsystem_active, collectors: [{collector, format, devices, sent, send_failures}], devices_exporting, rate_limiter_tokens_available?, catalogs_by_type?}`. Same `subsystem_active` semantics as trap. The `(collector, format)` tuple lets devices emit different wire formats to the same collector without interleaving on one socket.
- `POST /api/v1/devices/{ip}/syslog` takes the body `{"name":"interface-down","templateOverrides":{"IfIndex":"3","IfName":"Gi0/3"}}` → `202 Accepted` + `{}`. `400` for unknown catalog entry or malformed JSON, `404` for unknown device, `503` when the subsystem is not running or the device has no syslog config. Typo'd fields rejected via `DisallowUnknownFields`.

## PRI calculation and vocabulary

- `PRI = facility * 8 + severity`, emitted as `<N>` with no leading zeros (range 0..191).
- Catalog entries accept either the canonical name or the integer:

  | Facility   | Int | Facility   | Int | Facility   | Int |
  |------------|-----|------------|-----|------------|-----|
  | `kern`     | 0   | `cron`     | 9   | `local0`   | 16  |
  | `user`     | 1   | `authpriv` | 10  | `local1`   | 17  |
  | `mail`     | 2   | `ftp`      | 11  | `local2`   | 18  |
  | `daemon`   | 3   | `ntp`      | 12  | `local3`   | 19  |
  | `auth`     | 4   | `audit`    | 13  | `local4`   | 20  |
  | `syslog`   | 5   | `alert`    | 14  | `local5`   | 21  |
  | `lpr`      | 6   | `clock`    | 15  | `local6`   | 22  |
  | `news`     | 7   |            |     | `local7`   | 23  |
  | `uucp`     | 8   |            |     |            |     |

  | Severity  | Int | Aliases       |
  |-----------|-----|---------------|
  | `emerg`   | 0   |               |
  | `alert`   | 1   |               |
  | `crit`    | 2   |               |
  | `err`     | 3   | `error`       |
  | `warning` | 4   | `warn`        |
  | `notice`  | 5   |               |
  | `info`    | 6   |               |
  | `debug`   | 7   |               |

  Out-of-range integers or unknown names are rejected at catalog load.
