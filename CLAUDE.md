# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Build
cd go/nl6
go mod tidy
go build -o nl6 .

# Run (requires root for TUN/network namespace)
sudo ./nl6 [flags]

# Key flags
-auto-start-ip <IP>     # Auto-create devices starting at this IP
-auto-count <N>         # Number of devices to auto-create
-port <port>            # HTTP API port (default: 8080)
-snmp-port <port>       # UDP port for SNMP listener on each device (default: 161)
-snmpv3-engine-id <id>  # Enable SNMPv3 (omit for v2c only)
-snmpv3-auth <proto>    # none | md5 | sha1
-snmpv3-priv <proto>    # none | des | aes128
-no-namespace           # Disable network namespace isolation
-version                # Print version string and exit (no startup side effects)
-fidelity               # [global] Fidelity mode: keep the fleet silent (no autonomous flow/trap/syslog/gNMI-dial-out push) except during a running load-test scenario window. Devices still answer polls; on-demand fires still go through. Default: false.
-scenario-pen <uint>    # [global] IANA PEN for PEN-dependent scenario run tags (syslog SD-PARAM, SNMP enterprise varbind); 0 = unset → those levers degrade to window+source-IP.
-optical-scenario <s>   # [seed]   Auto-start-batch per-device optical health band (optical transport types only): clean (default) | typical | degraded | failing. REST-created devices default to clean; opt in via optical_scenario.
-if-error-scenario <s>  # Auto-start-batch per-device error/discard scenario: clean (default) | typical | degraded | failing. REST-created devices default to clean; opt in via if_error_scenario.
-if-flap-scenario <s>   # [seed]   Auto-start-batch per-device link-flap scenario: clean (default; no flaps) | rare (~6h mean) | typical (~15min) | aggressive (~1min). REST-created devices default to clean; opt in via if_flap_scenario.
-if-flap-global-cap <r> # [global] Simulator-wide tps ceiling on flap events (0 = unlimited)
-gnmi-port <port>       # TCP port for gNMI listener on each device (default: 9339)
-gnmi-disable           # Disable the gNMI subsystem; no device listens on the gNMI port (default: false, subsystem on)

# gNMI dial-out (telemetry push) flags. [seed] flags apply ONLY to the auto-start batch;
# REST-created devices opt in via a per-device `gnmi_dialout` block. Dial-out is per-device
# and independent of dial-in, so the fleet can run mixed.
-gnmi-mode <mode>              # [seed] dial-in (default; serve gNMI) | dial-out (also push to collector)
-gnmi-dialout-collector <h:p>  # [seed] dial-out collector host:port (required when -gnmi-mode=dial-out)
-gnmi-dialout-flavor <f>       # [seed] gnmireverse (Arista; only shipped flavor)
-gnmi-dialout-encoding <e>     # [seed] json_ietf (default) | proto
-gnmi-dialout-sub-mode <m>     # [seed] sample (default) | on-change
-gnmi-dialout-interval <dur>   # [seed] SAMPLE cadence (default 10s; 1s floor)
-gnmi-dialout-tls              # [seed] TLS to collector (default true; false = plaintext)
-gnmi-dialout-tls-insecure     # [seed] skip collector cert verification (dev only)
-gnmi-dialout-tls-ca <path>    # [seed] PEM CA bundle to verify collector (empty = system roots)
-gnmi-dialout-mtls             # [seed] present shared cert as client cert (mutual TLS)
-topology-config <path> # [global] JSON inter-device LLDP link graph ({"links":[{"a":{"ip","ifindex"},"b":{"ip","ifindex"}}]}). Loaded at startup; syntactic validation only (device/ifIndex resolved lazily at serve time). Also mutable at runtime via POST/DELETE /api/v1/topology.

# DNS service-discovery flags (hidden DNS primary for a CoreDNS secondary; off by default)
-dns-enable             # Enable the DNS service-discovery server (default: false)
-dns-domain <domain>    # Forward zone apex; <device-name>.<domain> (default: nl6.local)
-dns-listen <host:port> # Bind address in the container's default netns (default: :5353; avoids privileged :53)
-dns-reverse-zone <z>   # Comma-separated in-addr.arpa reverse zone(s) (default: 42.10.in-addr.arpa = flat 10.42.0.0/16). IPs outside get an A but no PTR (counted).
-dns-notify <h:p,...>   # Comma-separated secondary NOTIFY targets (host:port); empty disables NOTIFY
-dns-debounce <dur>     # Quiescence window coalescing a burst of device changes into one serial bump + NOTIFY (default: 1s)

# Flow export flags (NetFlow v5 / v9 / IPFIX / sFlow v5)
# Flags marked [seed] apply ONLY to auto-start devices (-auto-start-ip batch).
# REST-created devices (POST /api/v1/devices) opt in via a per-device `flow` block.
# Flags marked [global] retain simulator-wide effect.
-flow-collector <host:port>       # [seed]   Seed collector for auto-start batch
-flow-protocol <proto>            # [seed]   netflow9 (default) | ipfix | netflow5 | sflow (alias: sflow5)
-flow-tick-interval <duration>    # [seed]   How often to emit flows (default: 5s)
-flow-active-timeout <duration>   # [seed]   Active flow expiry timeout (default: 30s)
-flow-inactive-timeout <duration> # [seed]   Inactive flow expiry timeout (default: 15s)
-flow-template-interval <dur>     # [global] Re-send template every N seconds (default: 60s; ignored under netflow5/sflow)
-flow-sub-agent-id <uint>         # [seed]   sFlow sub_agent_id for the auto-start batch (default: 0; one value for the whole batch — use per-device REST flow.sub_agent_id for per-group values; ignored by non-sflow protocols)
-flow-option-interface-table <s>  # [seed]   v9/IPFIX interface option records: if-scoped (ifIndex in scope, fields 82+83) | system-scoped (ifIndex as option field, field 83 only; IOS-XR shape). Empty = off (default). Requires netflow9/ipfix; per-group shapes via REST flow.options_interface_table
-flow-source-per-device           # [global] Bind per-device UDP socket so src IP = device IP (default: true)

# SNMP trap / INFORM export flags (SNMPv2c only)
-trap-collector <host:port>       # [seed]   Seed trap collector for auto-start batch (default port 162)
-trap-mode <proto>                # [seed]   trap (default, fire-and-forget) | inform (acknowledged)
-trap-interval <duration>         # [seed]   Per-device mean firing interval, Poisson-distributed (default: 30s)
-trap-global-cap <tps>            # [global] Simulator-wide tps ceiling (0 = unlimited)
-trap-catalog <path>              # [global] Override embedded universal catalog (5 entries) + per-type overlays — when set, the single file becomes the catalog for every device
-trap-community <string>          # [seed]   SNMPv2c community (default: public)
-trap-source-per-device           # [global] Source IP = device IP (default: true; REQUIRED in inform mode)
-trap-inform-timeout <duration>   # [seed]   Per-retry timeout in inform mode (default: 5s)
-trap-inform-retries <int>        # [seed]   Max retransmissions per inform (default: 2)

# UDP syslog export flags (RFC 5424 / RFC 3164)
-syslog-collector <host:port>     # [seed]   Seed collector for auto-start batch (default port 514)
-syslog-format <fmt>              # [seed]   5424 (default, structured) | 3164 (legacy BSD)
-syslog-interval <duration>       # [seed]   Per-device mean firing interval, Poisson-distributed (default: 10s)
-syslog-global-cap <rate>         # [global] Simulator-wide rate ceiling (0 = unlimited)
-syslog-catalog <path>            # [global] Override embedded universal 6-entry catalog
-syslog-source-per-device         # [global] Source IP = device IP (default: true; bind failure is non-fatal, falls back to shared socket)

# Tests
cd go
go test ./...

# Run a single test
go test ./nl6/ -run TestSomething
```

## Architecture

**nl6** is a Go-based network device simulator capable of running 30,000+ concurrent simulated devices, each responding to SNMP (v2c/v3), SSH, and HTTPS REST protocols. It uses Linux TUN interfaces and network namespaces to give each device its own IP address.

### Package layout

| Path | Purpose |
|------|---------|
| `go/nl6/` | Core simulator — all device simulation logic and tests |
| `go/nl6/resources/` | 389 JSON files (29 device types) with SNMP/SSH/REST response data |

### Core simulator components (`go/nl6/`)

**Device lifecycle:** `simulator.go` (CLI/entry) → `manager.go` (SimulatorManager, shared keys/certs) → `device.go` (per-device startup, protocol server lifecycle)

**SNMP stack:** `snmp_server.go` → `snmp.go` (request handling) → `snmp_handlers.go` (OID lookup via sync.Map) → `snmp_response.go` (response building) → `snmp_encoding.go` (ASN.1 BER/DER). SNMPv3 is handled separately in `snmpv3.go` + `snmpv3_crypto.go` (MD5/SHA1 auth, DES/AES128 privacy).

**Dynamic IF-MIB counters (`if_counters.go`):** `IfCounterCycler.GetDynamic` serves every per-interface counter under `ifTable` (`.1.3.6.1.2.1.2.2.1`) and `ifXTable` (`.1.3.6.1.2.1.31.1.1.1`) analytically — no per-interface goroutine. `ifHCInOctets` / `ifHCOutOctets` are the master dial (sine wave, 60–100 % of `ifSpeed`, 1 h period); HC packet counters (ucast / mcast / bcast) derive from octets ÷ jittered packet size × jittered ratios; Counter32 shadow columns (`ifInUcastPkts`, `ifInMulticastPkts`, etc.) return the low 32 bits of the matching Counter64 HC column; error / discard counters derive from per-device ppm bands set by the `IfErrorScenario` field (`clean` | `typical` | `degraded` | `failing`). The same dispatcher powers the sFlow `counter_sample` body path in `counter_source.go`, so SNMP and sFlow values agree byte-for-byte at the same instant.

**Interface state engine (`interface_state.go`, added by add-interface-state):** `IfCounterCycler` owns an `InterfaceState` per device that stores `oper-status` / `admin-status` / `last-change` per ifIndex in a packed `atomic.Uint64` slot (3 bits + 3 bits + 58 bits wall-relative ns). `ifAdminStatus.<N>` (`.7`), `ifOperStatus.<N>` (`.8`), `ifLastChange.<N>` (`.9`) are now claimed by the cycler — `GetDynamicAt` reads them from the state engine, so SNMP and gNMI agree byte-for-byte at the same instant. Mutators are `SetOperStatus` / `SetAdminStatus` (CAS-loop, idempotent on no-op), fed by two sources: the flap scheduler (`flap_scheduler.go`, single shared min-heap goroutine driving Poisson-distributed flaps per (device, ifIndex) — same shape as `trap_scheduler.go`) and the REST control plane (`POST /api/v1/devices/{ip}/interfaces/{ifIndex}/{oper,admin}-status`). State transitions broadcast a `StateChange` event to every registered ON_CHANGE Subscribe listener via a per-stream depth-16 channel with drop-oldest on overflow. Cross-protocol consistency in Tier B: SNMP, gNMI Get, and gNMI Subscribe ON_CHANGE all see the same value at the same instant. **Tier C (`correlate-state-notifications`):** an oper-status transition now also fires correlated link traps + syslog for that ifIndex — `InterfaceState.SetNotify` installs an `atomic.Pointer[func(StateChange)]` hook invoked (oper-only, gated on `LeafOperStatus`) at the end of `Broadcast`, after the slot store commits. The manager wires it at trap/syslog attach time (`wireStateNotify`) to call `FireForInterface(entry, ifIndex)` on the role-matched catalog entries (`EntriesByRole`, vendor-wins-per-role); the closure snapshots the exporters under `device.mu.RLock` and fires outside the lock (closing-guard handles teardown). Covers all three mutation sources (REST, flap scheduler, REST auto-revert) via the single `Broadcast` funnel. Link telemetry volume now rides real state changes (`-if-flap-scenario` / REST), and state-driven fires bypass the Poisson global cap on initial transmit.

**REST auto-revert convention.** `POST .../oper-status` and `POST .../admin-status` accept an optional `duration` field (`{"status":"DOWN","duration":"30s"}`). When set: (1) the handler snapshots the pre-mutation slot value at POST time; (2) `SimulatorManager.revertTimers` registers the timer keyed by `(ip, ifIndex, isOper)` so a subsequent duration POST on the same leaf cancels the first; (3) `device.Stop()` cancels per-device timers, `manager.Shutdown()` cancels all; (4) `duration` is capped at 24h (`maxRevertAfter`) — over-cap returns 400; (5) on-demand HTTP fires bypass the flap scheduler's `-if-flap-global-cap` rate limiter, matching the trap/syslog convention for test-harness use.

**Metrics engine:** `metrics_cycler.go` drives 100-point pre-generated sine-wave patterns per device. `gpu_metrics.go` handles per-GPU metrics (utilization, VRAM, temperature, power, clocks). `device_profiles.go` defines per-category baselines.

**Network infrastructure:** `tun.go` creates TUN interfaces, `netns.go` manages the `nl6sim` network namespace, `prealloc.go` does parallel pre-allocation of TUN interfaces (configurable worker count 100–200) for fast scaling.

**Web API:** `web.go` (route setup) + `api.go` (handlers) + `web_routes*.go` (Linux route script generation). Serves device CRUD, CSV export, system stats, simulator version (`GET /api/v1/version` → `{"version":"vX.Y.Z"}`, immutable per process, `Cache-Control: max-age=3600`), flow export status (`GET /api/v1/flows/status`), trap export status (`GET /api/v1/traps/status`), syslog export status (`GET /api/v1/syslog/status`), gNMI subsystem status (`GET /api/v1/gnmi/status`, also reports `state_events_emitted` / `state_events_dropped` for ON_CHANGE fan-out), on-demand trap firing (`POST /api/v1/devices/{ip}/trap`), on-demand syslog firing (`POST /api/v1/devices/{ip}/syslog`), interface state control (`POST /api/v1/devices/{ip}/interfaces/{ifIndex}/{oper,admin}-status`), and inter-device topology (`POST` / `GET` / `DELETE /api/v1/topology`, `GET /api/v1/topology/status` → `{subsystem_active, configured_links, active_links}`).

**Flow export (per-device config, phase 3):** `flow_exporter.go` (FlowExporter, FlowEncoder interface, SimulatorManager integration) + `netflow9.go` (NetFlow9Encoder, RFC 3954) + `ipfix.go` (IPFIXEncoder, RFC 7011) + `netflow5.go` (NetFlow5Encoder, Cisco v5: 24B header, 48B/record, IPv4-only, 30-record datagram cap, no templates) + `sflow.go` (SFlowEncoder, sFlow v5 per sflow_version_5.txt: 28B XDR datagram header, variable-length flow_sample records carrying sampled_header=IPv4+UDP/TCP synthesized from the FlowRecord 5-tuple, no template mechanism). Each device owns its collector/protocol/timeouts on `DeviceFlowConfig`; the manager owns a shared-socket pool keyed by `(collector, protocol)` and one ticker goroutine. `FlowStatus` is an array-of-collectors aggregated by `(collector, protocol)`. Protocols:

| Protocol   | Header | Record size    | Template? | Timestamps         | IPv6 records | Notes |
|------------|--------|----------------|-----------|--------------------|--------------|-------|
| `netflow5` | 24B    | 48B fixed      | none      | SysUptime-relative | filtered     | 30-record datagram cap; 32-bit ASNs clamp to `23456` (AS_TRANS, RFC 6793 §2); `-flow-template-interval` is a silent no-op |
| `netflow9` | 20B    | 46B fixed      | yes       | SysUptime-relative | filtered     | Single 19-field template, ID 256; last field DIRECTION(61) = constant ingress (0x00) |
| `ipfix`    | 16B    | 54B fixed      | yes       | absolute epoch ms  | filtered     | Template Set ID 2, IE-based fields; last IE flowDirection(61) = constant ingress (0x00) |
| `sflow`    | 28B    | variable (~100B typical) | none (self-describing) | uptime + flow_sample sampling_rate | filtered (IPv4 agent only) | Synthetic sampling_rate = `10 × FlowProfile.ConcurrentFlows` (see `SyntheticSamplingRateMultiplier`); emits flow_sample (type 1) + Phase-2 counters_sample (type 2) per tick. **sFlow output is synthetic — the simulator does not observe real packet streams.** Agent identity = device IPv4; `-flow-source-per-device` makes the UDP source IP match `agent_address`. |

The `FlowEncoder` interface has a `MaxRecordSize() int` extension point: fixed-size encoders return 0 (NetFlow5/9, IPFIX), variable-length encoders (sFlow) return a worst-case per-record byte bound that `FlowExporter.Tick` uses for MTU-safe pagination.

**Flow application ground truth (`scenario-app-traffic`):** flow-protocol scenario reports carry a fleet-wide `applications[]` block — sent-basis `bytes`/`packets`/`records` per `(l4_proto, dst_port)` plus `avg_bytes_per_second` (in-window bytes ÷ window; drain bytes count in totals but never inflate the rate), aggregated at the Tick write-return ledger hook via `scenarioPart.countApps` (set at `installScenPart`; sflow excluded — collector byte math is sampling extrapolation). Shipped `FlowProfile`s floor `SrcPortMin` at 49152 (IANA dynamic range) so random source ports can't collide with collector-side registered-port classification rules, and ICMP records carry zero ports (aggregating under `(icmp, 0)`) — both wire-visible on all flow protocols. See `docs/reference/loadtest-report-schema.md`.

**SNMP trap export (per-device config, phase 4):** `trap_manager.go` (SimulatorManager integration, `TrapSubsystemConfig`, `StartTrapSubsystem` / `StopTrapExport`, HTTP handlers' helpers, `TrapStatus`) + `trap_catalog.go` (JSON catalog loader with embedded universal set + weighted-random pick + `text/template`-based varbind resolution) + `trap_v2c.go` (SNMPv2c TRAP [0xA7] and InformRequest [0xA6] PDU encoder, GetResponse [0xA2] ack parser — reuses `snmp_encoding.go` ASN.1 primitives) + `trap_scheduler.go` (single central min-heap scheduler goroutine with Poisson inter-arrival + `golang.org/x/time/rate` global cap) + `trap_exporter.go` (per-device `TrapExporter` with atomic per-device UDP socket, bounded pending-inform map with oldest-drop, reader/retry goroutines in INFORM mode). Each device owns its collector/mode/community/interval/inform-* settings on `DeviceTrapConfig`; the manager owns a shared-socket pool keyed by collector and a per-(collector, mode) monotonic counter aggregate that survives device deletion. `TrapStatus` is an array-of-collectors aggregated by `(collector, mode)`, with a top-level `subsystem_active` bool for observability.

**Trap catalog:**
- Default catalog is compiled into the binary from `resources/_common/traps.json` via `embed.FS` — no filesystem dependency for the out-of-box experience.
- Override with `-trap-catalog <path>` (complete replacement, not merge). When set, per-type overlays are NOT loaded — the single file becomes the catalog for every device.
- Universal catalog ships 5 entries: `coldStart`, `warmStart`, `linkDown`, `linkUp`, `authenticationFailure` (RFC 3418). Weights: linkDown=40, linkUp=40, authenticationFailure=10, coldStart=5, warmStart=5.
- **Catalog `role` field (Tier C, `correlate-state-notifications`):** an optional per-entry `"role"` (`link-down` | `link-up`; unknown rejected, empty = untagged) tags an entry as **state-driven**. Role-tagged entries are excluded from the scheduler's weighted-random `Pick` (a separate schedulable-weight tally that may be zero — an all-role-tagged catalog still loads) and are instead fired by an oper-status transition via `EntriesByRole` (vendor-wins-per-role: overlay entries suppress the universal one). `linkDown`/`linkUp` are role-tagged in the shipped universal catalog, so the scheduler's effective universal weight drops to 20 (coldStart 5 + warmStart 5 + auth 10); link traps now come from real state changes. The loader warns (non-fatal) on a linkDown/linkUp-OID entry that lacks a role.
- **Per-type overlays:** `resources/<type>/traps.json` overlays the universal for devices of that type (e.g., `resources/cisco_ios/traps.json` affects all cisco_ios devices). Resolved lazily per fire via `SimulatorManager.CatalogFor(ip)` → `trapCatalogsByType[slug]` → `_universal`. Devices whose type has no per-type file fall through to the universal. `GET /api/v1/traps/status` exposes a `catalogs_by_type` object showing per-type entry counts and sources (embedded / file / override).
- **Shipped vendor catalogs** (PRs 4 & 5 of epic #103):
  - `cisco_ios/traps.json` — 7 Cisco-MIB notifications: `ciscoConfigManEvent`, `ciscoEnvMonSupplyStatusChangeNotif`, `ciscoEnvMonTemperatureNotification`, `cefcModuleStatusChange`, `cefcFanTrayStatusChangeNotif`, `ciscoEntSensorThresholdNotification`, `ciscoFlashDeviceChangeTrap`. Merged with universal 5 → cisco_ios devices fire from 12 entries. All use `snmpTrapEnterprise` for v1↔v2c proxy compatibility.
  - `juniper_mx240/traps.json` — 7 JUNIPER-MIB jnxChassisTraps-family notifications, all verified against the canonical MIB registration: `jnxPowerSupplyFailure` (.4.1.1), `jnxFanFailure` (.4.1.2), `jnxOverTemperature` (.4.1.3), `jnxFruRemoval` (.4.1.5), `jnxFruInsertion` (.4.1.6), `jnxFruPowerOff` (.4.1.7), `jnxFruFailed` (.4.1.9). Merged with universal 5 → juniper_mx240 devices fire from 12 entries. `snmpTrapEnterprise` = `1.3.6.1.4.1.2636` (Juniper Networks) on all entries. `jnxFruEntry` varbind OIDs use the correct 4-index INDEX suffix (container, L1, L2, L3).
  - Other cisco_* slugs (`cisco_catalyst_9500`, `cisco_crs_x`, `cisco_nexus_9500`, `asr9k`) and `juniper_mx960` fall back to universal in this epic. Family-catalog concept is a follow-up refactor.
- **Overlay semantic:** per-type files default to `"extends": true` — entries unique to the per-type file are added, same-name entries override the universal, unused universal entries carry through. Set `"extends": false` at the top of the per-type JSON for a pure replacement (no universal content for that type). Weights are recomputed post-merge.
- **Unified template vocabulary (9 fields, trap + syslog share the same surface):** `{{.IfIndex}}`, `{{.IfName}}` (synthesised `GigabitEthernet0/<N>` in PR2; live `ifDescr.<N>` lookup in PR3), `{{.Uptime}}`, `{{.Now}}`, `{{.DeviceIP}}`, `{{.SysName}}`, `{{.Model}}` (human-readable label from slug → `deviceTypeLabels`), `{{.Serial}}` (`SN<hex>` synthesised from device IP, deterministic), `{{.ChassisID}}` (`02:42:xx:xx:xx:xx` MAC-style synthesised from device IP). Unknown fields are rejected at catalog load — Class 2 random-per-fire fields (`PeerIP`, `User`, `SourceIP`, `RuleName`, …) are explicitly deferred and rejected.
- Class 1 fields (SysName, Model, Serial, ChassisID) are resolved at exporter construction and captured on the exporter; IfName is resolved per fire via a callback. `FieldResolver` interface in `field_resolver.go` is the seam for testability and for the PR3 swap to live `ifDescr` lookup.
- The two mandatory SNMPv2-Trap varbinds (`sysUpTime.0`, `snmpTrapOID.0`) are prepended automatically by the encoder — catalog authors supply only body varbinds; entries that list either reserved OID (or `snmpTrapEnterprise.0`) as a body varbind are rejected.
- Optional top-level `snmpTrapEnterprise` field (string, dotted OID) per entry. When set, the encoder emits an additional `snmpTrapEnterprise.0` varbind (OID `1.3.6.1.6.3.1.1.4.3.0`) after the two mandatory ones — useful for v1↔v2c cross-compatibility on collectors that expect the enterprise OID per SNMPv2-MIB §10. Catalog-loader rejects reserved OIDs (`sysUpTime.0`, `snmpTrapOID.0`, `snmpTrapEnterprise.0`) as enterprise values. Omit the field to keep the backward-compatible 2-varbind prefix.

**Trap operational notes:**
- INFORM mode (`-trap-mode inform`) requires `-trap-source-per-device=true` (the default) so the per-device UDP socket can demux acks without a global request-id table. Enforced at device-attach time (phase 4 moved it out of startup).
- Pending-inform map is bounded at 100 per device with oldest-drop overflow policy (exposed as `informsDropped` in `GET /api/v1/traps/status`).
- Retransmissions consume global-cap tokens (design decision to prevent retry-storm amplification when the collector is unreachable).
- Collector-side `rp_filter` may need relaxing (`net.ipv4.conf.*.rp_filter=0` or `2`) to accept UDP/162 with 10.42.0.0/16 source IPs — same caveat already documented for flow export.
- Per-device UDP source binding reuses the same `setupVethPair` + `FORWARD -i veth-sim-host -j ACCEPT` iptables rule that flow export already relies on. No new netns / iptables surface.
- **`StopTrapExport` is shutdown-only** (phase-5 review D1). It is not safe to race concurrent device creation: `startDeviceTrapExporter` captures scheduler / pool / encoder pointers under a short RLock and uses them outside that lock, so a concurrent Stop can leave orphan exporters or closed sockets. Today it is only called from the process-exit signal handler. Do not introduce a runtime "restart trap subsystem" control path without first tightening the attach-path lock discipline.

**Trap HTTP endpoints:**
- `GET /api/v1/traps/status` — JSON array-of-collectors: `{subsystem_active, collectors: [{collector, mode, devices, sent, informs_pending?, informs_acked?, informs_failed?, informs_dropped?}], devices_exporting, rate_limiter_tokens_available?, catalogs_by_type?}`. `subsystem_active=false` means `StartTrapSubsystem` has not run; `subsystem_active=true` with `collectors=[]` means running but no device has opted in. INFORM counters are only present on records with `mode=inform`. `catalogs_by_type` reports per-type overlay counts and source (`embedded` / `file:resources/<slug>/traps.json` / `override:<path>`).
- `POST /api/v1/devices/{ip}/trap` — body `{"name":"linkDown","varbindOverrides":{"IfIndex":"3"}}` → `202 Accepted` + `{"requestId": N}`. `400` for unknown catalog entry (response body includes `catalog` — the device's resolved catalog label — and `availableEntries` list so operators can self-service), `404` for unknown device, `503` when the subsystem is not running or the device has no trap config. Fire-and-forget: returns without waiting on INFORM ack.

**UDP syslog export (per-device config, phase 5):** `syslog_manager.go` (SimulatorManager integration, `SyslogSubsystemConfig`, `StartSyslogSubsystem` / `StopSyslogExport`, `SyslogStatus`) + `syslog_catalog.go` (JSON catalog with embedded universal 6-entry set; weighted-random pick; `text/template`-based body / structured-data resolution with all templates pre-compiled at load) + `syslog_wire.go` (`SyslogEncoder` interface with `RFC5424Encoder` and `RFC3164Encoder` — PRI calc, ISO 8601 / `Mmm DD HH:MM:SS` timestamps, SD-PARAM escape per §6.3.3, HOSTNAME / APP-NAME / MSGID / TAG sanitisation, MaxMessageSize enforcement) + `syslog_scheduler.go` (single central min-heap scheduler with Poisson inter-arrival + `golang.org/x/time/rate` global cap; derived context so `Stop()` is bounded-time under cap) + `syslog_exporter.go` (per-device `SyslogExporter` with atomic per-device UDP socket and shared-socket fallback). Each device owns its collector/format/interval on `DeviceSyslogConfig`; the manager owns a shared-socket pool keyed by `(collector, format)`, a per-format encoder cache, and a per-(collector, format) monotonic counter aggregate. `SyslogStatus` is an array-of-collectors aggregated by `(collector, format)`, with a top-level `subsystem_active` bool.

**Syslog catalog:**
- Default catalog is compiled into the binary from `resources/_common/syslog.json` via `embed.FS` — feature works out of the box.
- Override with `-syslog-catalog <path>` (complete replacement, not merge). When set, per-type overlays are NOT loaded.
- Universal catalog ships 6 entries: `interface-up` / `interface-down` (local7.notice/error, IFMGR), `auth-success` / `auth-failure` (authpriv.info/warning, sshd), `config-change` / `system-restart` (local7.notice/warning, SYSMGR). Weights sum to 135.
- **Catalog `role` field (Tier C):** same semantics as the trap side — `interface-down`/`interface-up` are role-tagged (excluded from `Pick`, fired by oper transitions). With vendor-wins-per-role, a `cisco_ios` port-down fires both `%LINK-3-UPDOWN` and `%LINEPROTO-5-UPDOWN` (and NOT the generic `interface-down`); `juniper_mx240` fires `SNMP_TRAP_LINK_DOWN`/`_UP`.
- **Per-type overlays:** mirror trap-side behaviour. `resources/<type>/syslog.json` overlays the universal for devices of that type. Resolved via `SimulatorManager.SyslogCatalogFor(ip)`. Defaults to `"extends": true` (merge, same-name override); set `"extends": false` for pure replacement. `GET /api/v1/syslog/status` reports `catalogs_by_type` for observability. `POST /api/v1/devices/{ip}/syslog` resolves entry names against the device's catalog; a 400 response includes `catalog` and `availableEntries` for self-service.
- **Shipped vendor catalogs** (PRs 4 & 5 of epic #103):
  - `cisco_ios/syslog.json` — 8 Cisco-format messages: `%LINK-3-UPDOWN` (up/down pair), `%LINEPROTO-5-UPDOWN` (up/down pair), `%SYS-5-CONFIG_I`, `%SNMP-5-COLDSTART`, `%SYS-5-RESTART`, `%ENVMON-5-TEMP_OK`. Merged with universal 6 → cisco_ios devices fire from 14 entries. Message bodies match IOS's `%FACILITY-SEVERITY-MNEMONIC:` form verbatim so OpenNMS UEI matchers tuned for Cisco strings fire correctly.
  - `juniper_mx240/syslog.json` — 7 Junos-format messages using daemon tags (`snmpd`, `mib2d`, `chassisd`, `mgd`, `license-check`) and Junos MSGID structure: `SNMP_TRAP_LINK_UP` / `SNMP_TRAP_LINK_DOWN`, `MIB2D_IFD_IFL_ENCAPS_MISMATCH`, `CHASSISD_FRU_TEMP_CRITICAL`, `CHASSISD_EEPROM_READ_FAIL`, `LICENSE_EXPIRED_KEY_DELETED`, `UI_COMMIT_COMPLETED`. Merged with universal 6 → juniper_mx240 devices fire from 13 entries. Message bodies match Junos's canonical `MSGID: body` form verbatim.
  - Linux / Palo Alto / Arista deferred — their realistic content requires Class 2 random-per-fire fields.
- **Unified template vocabulary (9 fields, same set as trap):** `{{.DeviceIP}}`, `{{.SysName}}`, `{{.IfIndex}}`, `{{.IfName}}`, `{{.Now}}`, `{{.Uptime}}`, `{{.Model}}`, `{{.Serial}}`, `{{.ChassisID}}`. Unknown fields are rejected at catalog load — Class 2 random fields (`PeerIP`, `User`, `SourceIP`, `RuleName`, …) remain deferred. See trap section above for resolution semantics — trap and syslog share the same `FieldResolver` seam and Class 1 values are captured at exporter construction.
- SD-NAME keys are validated against RFC 5424 §6.3.3 at load; each templated value is pre-compiled to a `*template.Template` so the fire hot path is allocation-light (measured 894 ns/op).
- Entry `appName` is required (RFC 3164 TAG has no NILVALUE). Facility and severity accept canonical names (`local7`, `error`) or integers in range (`0..23` / `0..7`). MTU-safety dry-render rejects entries whose worst-case rendered output exceeds 1400 bytes.

**Syslog catalog JSON schema** (one entry; the file is `{"entries":[…]}`):

```json
{
  "name":     "interface-down",       // required; unique within catalog
  "weight":   40,                     // weighted-random Pick; 0/omitted → 1
  "facility": "local7",               // name (kern/user/.../local0..local7) or integer 0..23
  "severity": "error",                // name (emerg/alert/crit/err|error/warning|warn/notice/info/debug) or integer 0..7
  "appName":  "IFMGR",                // required (3164 TAG has no NILVALUE); sanitised to ASCII token
  "msgId":    "LINKDOWN",             // 5424 MSGID; empty → NILVALUE; dropped in 3164
  "hostname": "{{.SysName}}",         // optional override; empty → sysName→DeviceIP fallback
  "structuredData": {                 // 5424 STRUCTURED-DATA; empty map → NILVALUE; dropped in 3164
    "ifIndex": "{{.IfIndex}}",        // keys must match RFC 5424 §6.3.3 SD-NAME grammar
    "ifName":  "{{.IfName}}"
  },
  "template": "Interface {{.IfName}} (ifIndex={{.IfIndex}}) changed state to down"
}
```

**HOSTNAME derivation priority** (resolved at fire time, per design §D5):
1. If the catalog entry defines a non-empty `hostname` template, render it (with the six-field vocabulary) and use the result.
2. Otherwise, use the device's stored `sysName.0` value (captured at device construction).
3. Otherwise, use the device's IPv4 as dotted-quad.

In every branch the result is run through `sanitiseHostname`: spaces become hyphens (spec mandate), other framing / control chars become `_`.

**PRI calculation and vocabulary** (per RFC 5424 §6.2.1, shared by 5424 and 3164):

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

**Syslog operational notes:**
- The format is per-device post-phase-5 — each device's `syslogConfig.Format` sets its own wire format. The shared-socket pool is keyed by `(collector, format)` so 5424 and 3164 streams never interleave on the same socket.
- Per-device UDP source binding reuses the same `setupVethPair` + `FORWARD -i veth-sim-host -j ACCEPT` rule shared by flow / trap. No new netns / iptables surface.
- Per-device bind failure is **non-fatal** for syslog (unlike INFORM): exporter logs a warning and falls back to the shared socket. When the primary per-device write fails but the shared fallback succeeds, the primary failure is logged and stats count the send as successful. If **both** per-device bind and shared-pool open fail, the attach is rejected so `ListDevices` doesn't show a ghost entry.
- The collector-side `rp_filter` caveat is the same as flow / trap — accept UDP from device IPs with `net.ipv4.conf.*.rp_filter=0` or `2`.
- On-demand HTTP fires **bypass the global rate limiter** (test-harness use case; scheduler-driven traffic still honours `-syslog-global-cap`).
- **`StopSyslogExport` is shutdown-only** (phase-5 review D1). Same constraint as trap: `startDeviceSyslogExporter` uses captured pointers outside the short RLock. Only called from the process-exit path today. Tightening is a pre-requisite for any runtime "restart" control plane.

**Syslog HTTP endpoints:**
- `GET /api/v1/syslog/status` — JSON array-of-collectors: `{subsystem_active, collectors: [{collector, format, devices, sent, send_failures}], devices_exporting, rate_limiter_tokens_available?, catalogs_by_type?}`. Same `subsystem_active` semantics as trap. The `(collector, format)` tuple lets devices emit different wire formats to the same collector without interleaving on one socket.
- `POST /api/v1/devices/{ip}/syslog` — body `{"name":"interface-down","templateOverrides":{"IfIndex":"3","IfName":"Gi0/3"}}` → `202 Accepted` + `{}`. `400` for unknown catalog entry or malformed JSON, `404` for unknown device, `503` when the subsystem is not running or the device has no syslog config. Typo'd fields rejected via `DisallowUnknownFields`.

**gNMI target:** `gnmi_paths.go` (path resolver — wildcard expansion, single-name reverse-ifDescr lookup, subtree flattening, scoped to `/interfaces/interface[name=*]/state/{name,ifindex,oper-status,admin-status,last-change,counters/*}`) + `gnmi_handlers.go` (`gnmi.GNMIServer`: `Capabilities`, `Get`, `Subscribe`, `Set` returning `Unimplemented`) + `gnmi_subscribe.go` (per-stream ticker + send goroutine with 100-deep oldest-drop send buffer; ONCE handled synchronously) + `gnmi_subscribe_onchange.go` (ON_CHANGE handler with listener-channel fan-out from `InterfaceState`, per-sub heartbeat tickers, (ifIndex, leaf) filtering) + `gnmi_server.go` (per-device gRPC + TLS listener bound inside the `nl6sim` netns; reuses `SimulatorManager.sharedTLSCert` — same cert as the HTTPS REST surface; `MaxConcurrentStreams=16` per-connection) + `gnmi_manager.go` (`GnmiSubsystemConfig`, `StartGnmiSubsystem` / shutdown-only `StopGnmiSubsystem`, atomic counters for `active_subscriptions`, `updates_sent`, `updates_dropped`, `state_events_emitted`, `state_events_dropped`). Read-only by design — `Set` returns `Unimplemented`. Subscribe modes: STREAM/SAMPLE + STREAM/ON_CHANGE (state-leaf paths only) + ONCE; mixed ON_CHANGE+SAMPLE in one request rejected with `InvalidArgument`; POLL rejected with `Unimplemented`; TARGET_DEFINED treated as SAMPLE; sub-second `sample_interval` and `heartbeat_interval` clamped to 1s silently. Encoding: `JSON_IETF` default + `PROTO` advertised. State and counter values reuse `IfCounterCycler.GetDynamicAt`, so gNMI / SNMP / sFlow agree byte-for-byte at the same instant. `subsystem_active=false` when `-gnmi-disable` is set.

**gNMI optical serving (`/components` branch):** `Resolve` and `ClassifyLeaves` dispatch on `elems[0]` — `interfaces` for the packet surface, `components` for the optical one, everything under the single prefix `/components/component[name=$och]/optical-channel/` (`optical-channel` augments `/components/component`, so one branch suffices). `gnmiOpticalLeaves` is the served contract, classified by container shape: `opticalLeafScalar` (in **both** `config/` and `state/`), `opticalLeafStats` (`state/<leaf>/{instant,avg,min,max}`), `opticalLeafCounter` (`fec-uncorrectable-blocks` — a **bare** leaf; asking for `/instant` on it returns a `NotFound` that says why, because that is the mistake a collector author makes by analogy). Values come from `OpticalCycler.GetDynamicAt`, keyed by **component name**, with one elapsed offset per response taken from the optical engine's own `StartTime()`. `config/` and `state/` return the same value for the four scalars — a simulator's configured intent cannot diverge from its operational state. **Three invariants worth not breaking:** (1) the `ifCounters`/`Unavailable` guard lives INSIDE the interfaces branch — hoisted, it asserted the *interface* engine for optical paths, so an optical Get on a device with no HC counters failed with a misleading "interface counters not initialized"; (2) optical absence is `NotFound` on a packet device (permanent) but `Unavailable` on an optical type mid-initialisation (retryable) — `IsOpticalDeviceType` decides, and conflating them tells a client to poll forever for a surface the device cannot have; (3) `ClassifyLeaves` reads no value engine at all, which is what keeps ON_CHANGE rejection cheap and unable to return `Unavailable`. ON_CHANGE on an optical path is rejected `InvalidArgument` with a **leaf-class-branched** message (`isOpticalLeafSelector`) — the counter wording would tell an operator that `osnr` is a counter. `Capabilities` advertises `openconfig-terminal-device` 2026-01-14, `openconfig-platform` 2025-07-15 and `openconfig-platform-transceiver` 2026-03-25 (the last is **not** decoration: `optical-channel/state` reuses its `optical-power-state` grouping for input/output power and laser bias). `post-fec-ber` is **not** served though OpenConfig defines it — Ciena removed it, so a rule keyed on it would never fire against real hardware; `TestOpticalPathManifest` asserts its absence so "completing the model" requires editing a test that explains why. That test also pins served == manifest in both directions, catching an invented or dropped path in CI; it does **not** prove manifest == YANG (the table was traced by hand against the pinned revisions — a ygot check would need them vendored).

**gNMI dial-out (telemetry push, `add-gnmi-dialout`):** `gnmi_dialout_transport.go` (`DialoutTransport` seam + `gnmiReverseTransport` over `github.com/aristanetworks/goarista/gnmireverse`, the Arista `gNMIReverse.Publish(stream SubscribeResponse) → Empty` fire-and-forget flavor; also the shared `parseGnmiPath` / `parseDialoutEncoding` helpers) + `gnmi_dialout_exporter.go` (`GnmiDialoutExporter`: per-device `grpc.ClientConn`+`Publish` stream held in `atomic.Pointer`, own dial→publish reconnect loop with 1s→30s capped backoff, SAMPLE ticker + ON_CHANGE `InterfaceState.AddListener` fan-out, bounded send channel with drop-oldest via `pushOrDrop`) + `gnmi_dialout_manager.go` (`StartGnmiDialoutSubsystem` / shutdown-only `StopGnmiDialout`, `startDeviceGnmiDialoutExporter` captured-pointer-under-RLock attach, `buildDialoutCreds`, `gnmiDialoutAggregates` monotonic per-(collector,flavor) counters, `GET /api/v1/gnmi/dialout/status`). **Dial-out reverses the gRPC role, not the data direction** — the device is the client. Payload generation (`pathResolver`→`encodeUpdates`) and state fan-out are reused verbatim from dial-in, so dial-out/dial-in/SNMP/sFlow agree byte-for-byte at the same instant; only transport + pacing are new. Every dial-out notification carries `Notification.Prefix.Target` = device IP (in-band identity, à la Arista `-target_value`; dial-in responses stay prefix-less). **One ClientConn + one stream per device** (NOT a shared pool — a single Go ClientConn caps at ~100 concurrent HTTP/2 streams); the client dials from inside the device netns with source IP = device IP (reuses the existing veth + FORWARD egress rule). Two-level config: `[seed]` flags (`-gnmi-mode dial-out`, `-gnmi-dialout-*`) for the auto-start batch + a per-device `gnmi_dialout` REST block (`DeviceGnmiDialoutConfig`), enabling a **mixed dial-in/dial-out fleet**. TLS: `tls.enabled=false` → plaintext; else verify against `ca_file`/system roots (or `insecure_skip_verify` dev toggle), optional `mtls` reuses `sharedTLSCert` as a **client** cert (it cannot verify the collector — hence `ca_file`). Drop-on-outage, no buffering; `StopGnmiDialout` is shutdown-only. See `docs/reference/gnmi-dial-out.md`.

**LLDP topology:** `topology.go` (`Topology` — a `SimulatorManager`-owned, mutex-guarded graph of undirected `(deviceIP, ifIndex)` links; the single source of truth for inter-device connectivity) + `lldp_table.go` (the dynamic SNMP provider). Configured via `-topology-config` at startup and `POST` / `GET` / `DELETE /api/v1/topology` at runtime (`topology_api.go`); pruned on `DeleteDevice`. Validation at add time is **syntactic only** (no self-loop, no duplicate, one link per local port — point-to-point); device existence and ifIndex ownership resolve **lazily at SNMP-serve time**, so a link may reference an auto-start device the background goroutine hasn't created yet. The provider serves the Enlinkd-minimal LLDP-MIB subset (`1.0.8802.1.1.2`): `lldpLocalSystemData` + `lldpLocPortTable` + `lldpRemTable`, plus an `ifAlias` (ifXTable .18) link label `to_<peerSysName>_<peerIfDescr>`. It hooks `snmp_handlers.go` `findResponse` (GET) and `findNextOID` (WALK) — the latter adds an `lldpClear` fast-path term (LLDP sorts *before* all static OIDs) and an `overrideLLDP` walk-value rewrite (so the dynamic ifAlias wins over a statically-shipped `.18.N` on GETNEXT/GETBULK). Stitching invariant: `lldpRemChassisId`/`lldpRemPortId` are derived from the *peer's* canonical sources (the `02:42:<ipv4>` chassis MAC and the peer's `ifDescr`), identical to what the peer advertises locally, so Enlinkd matches the two half-links. `lldpRemTable` rows are oper-status-aware (emitted only when both ends are UP; a peer with no state engine is treated as UP; nil-guarded); `ifAlias` reflects configured intent and persists when the port is DOWN. Reads the global `manager` (like gNMI), so no per-device field or device-creation-path change. Walk anchor: a mib-2-rooted walk never reaches `1.0.8802` — point Enlinkd at the LLDP root. Out of scope: capability bitmaps, `lldpStatistics`/`lldpConfiguration`, gNMI/openconfig-lldp.

**DNS service discovery:** `dns_zone.go` (pure, dependency-free zone model — `sanitiseDNSLabel`, deterministic collision disambiguation, `in-addr.arpa` reverse-zone parse/membership, `buildZoneView` producing forward `A` (`<device>` + `ip4.mgmt.<device>`) + reverse `PTR` records + status counters, monotonic `nextSerial`) + `dns_server.go` (`miekg/dns` hidden-primary authoritative server bound in the **default** netns on `-dns-listen` (`:5353`): SOA/NS/A/PTR direct answers, AXFR streaming in 256-record envelopes, IXFR→AXFR fallback, concurrent context-cancellable NOTIFY sender, apex SOA/NS fast path that skips the full rebuild) + `dns_manager.go` (`SimulatorManager` implements the server's `zoneDataProvider` — `DNSDevices`/`ZoneSerial` over the live device map, no per-device DNS state; `StartDnsSubsystem` / shutdown-only `StopDnsSubsystem`; `markDNSDirty` funnelled from every device create/delete; debounce worker coalesces a burst into one serial bump + one NOTIFY round) + `dns_api.go` (`GET /api/v1/dns/status`, `-dns-domain` validation, comma-list flag split). Off by default (`-dns-enable`); the zone content is a derived view over `ListDevices()` (like the LLDP/topology providers). nl6 is the hidden primary; a CoreDNS secondary transfers the zones (`examples/coredns-sidecar/`). Forward `<device-name>.nl6.local` → mgmt IP; reverse PTR → `ip4.mgmt.<device-name>.nl6.local` (round-trips). Names are sanitised `sysName`; duplicates disambiguated by ascending-IP order. SOA serial is epoch-seeded and not persisted (restart-with-clock-rollback caveat, documented). Out of scope: `ip6.*` records, per-interface IPs, IXFR, DNSSEC/TSIG. See `docs/reference/dns-service-discovery.md`.

**Topology visualization (web console):** `web/topology_logic.js` (pure, DOM-free, node-tested in `topology_logic.test.js`: model building, layouts, structure/state diffing, click-to-flap target resolution, scale guard) + `web/app_topology.js` (sigma.js/graphology glue, poll loop, interaction). Polls `GET /api/v1/topology/graph`, relayouts only on structure change (recolors on state-only). Two layouts: `tieredLayout` (**default** — horizontal fabric bands; tier rank from the device model label via the `TIER_RANK` table mirroring `deviceProfileMap` categories, compacted to dense bands, untyped/missing nodes fall one band below their highest typed neighbour, within-band barycenter sweeps cut crossings) and `forceLayout` (organic Fruchterman-Reingold). A Force/Tiered toggle in the topology panel switches layouts (a structural-render trigger). Device labels render over a theme-coloured background box (custom `defaultDrawNodeLabel`/`defaultDrawNodeHover`, bg from `--surface`/`--bg` at 0.88 alpha) so text stays legible over edges/nodes.

**Resource loading:** `resources.go` loads and caches the 389 JSON files at startup. Each device type directory has split JSON files for SNMP, SSH, and REST responses that are merged at load time.

### Key design decisions

- **sync.Map for OID lookups** — lock-free O(1) access during concurrent SNMP queries
- **Pre-computed next-OID mappings** — efficient SNMP GETNEXT/WALK without scanning
- **Buffer pool** — reduces GC pressure on SNMP request handling
- **Shared SSH/TLS keys** across all devices — avoids per-device key generation overhead
- **Network namespace isolation** (`nl6sim` namespace) — prevents systemd-networkd interference
- **Per-device flow egress** — `setupVethPair` installs a `FORWARD -i veth-sim-host -j ACCEPT` iptables rule so that per-device flow exporters can send UDP out of the ns through the host's routing table (Docker-present hosts default FORWARD to drop). Rule is removed in `NetNamespace.Close`. The simulator image includes `iptables` for this reason. On the downstream flow collector, `rp_filter` may need to be relaxed (`net.ipv4.conf.*.rp_filter=0` or `2`) to accept packets with 10.42.0.0/16 source IPs.

### Device types

29 device types across 9 categories: Core Routers, Edge Routers, Data Center Switches, Campus Switches, Firewalls, Servers, GPU Servers (NVIDIA DGX-A100/H100/HGX-H200), Storage Systems (AWS S3, Pure Storage, NetApp ONTAP, Dell EMC Unity), Optical Transport (Ciena Waveserver 5).

**Optical value engine (`optical_cycler.go`):** `OpticalCycler.GetDynamicAt(component, leaf, t)` is the single dispatcher for every coherent-optical leaf, keyed by **OCH component name** (never `ifIndex`). Same contract as `IfCounterCycler`: pure function of elapsed time, no per-channel goroutine, immutable after publish, single-init panic guard, per-channel jitter over a **sorted** channel slice (seed salt `^0x4F43_0000`). **Two independent dials** — received power `pIn` and accumulated noise `nAse`, with `osnr = pIn − nAse` in dB — because a single power dial makes OSNR perfectly correlated with power and leaves the *attenuation* (low power / normal OSNR) and *ASE* (normal power / low OSNR) quadrants unreachable. Cascade: `osnr → q-value → pre-fec-ber` (`½·erfc`, monotonic — the erfc tail is **shallow** at the 2e-2 SD-FEC threshold, ~3× per 2 dB, so decade-scale assertions there are wrong physics) `→ fec-uncorrectable-blocks`. Off-spine leaves (`output-power`, `target-output-power`, `laser-bias-current`, `chromatic-dispersion`, `polarization-mode-dispersion`, `polarization-dependent-loss`, `frequency`, `operational-mode`, `line-port`) read none of the receive dials — that flatness *is* the fibre-vs-transponder diagnostic. Both dials share a period so their difference collapses exactly to one sinusoid, making the above-threshold integral behind the block counter closed-form, O(1) and monotonic by construction. Types come from the **pinned OpenConfig revision** (terminal-device 2026-01-14 + platform-transceiver 2026-03-25), which governs over Ciena's native model: statistics leaves at `fraction-digits 2`, `pre-fec-ber` at `fraction-digits 18`, `fec-uncorrectable-blocks` a bare `uint64` counter with **no** stats container. **`post-fec-ber` is not served** — OpenConfig defines it but Ciena removed it, so a collector rule keyed on it would never fire against real hardware. `-optical-scenario` / per-device `optical_scenario` selects the health band via `opticalBandFor`; only `failing` crosses the FEC threshold. **Band boundaries are sized against the jitter envelope, not the nominal point:** each dial mean is jittered ±`opticalMeanJitterDB`, so the OSNR mean — their *difference* — spreads over ±2× that, stacked on top of the OSNR sine amplitude (≤ `1.1×(pInAmp+nAseAmp)` in antiphase). The tier contracts (`degraded` never accrues uncorrectable blocks, `failing` always does) must hold for every channel of every seed, so changing any mean, amplitude, or the jitter constant invalidates the arithmetic documented at `opticalBandFor` — `TestOpticalBandContractsHoldAcrossSeeds` sweeps seeds because a single-seed test passes while a fleet-sized share of channels violates the contract. **Capability symmetry with flow:** a non-clean `optical_scenario` on a type with no OCH inventory is rejected **400** (`opticalIncapableRequest`, the inverse mirror of `flowIncapableRequest`), and `opticalScenarioFieldFor` omits the field from `GET /api/v1/devices` for non-optical types rather than reporting a knob that does nothing.

**On-demand optical degradation (`optical_degrade.go`, `optical_api.go`):** `POST /api/v1/devices/{ip}/optical/{component}/degrade` with `input_power_drop_db` / `noise_rise_db` / optional `duration` (24h cap; neither offset = clear). Two knobs, not one severity dial — they select the diagnostic quadrant (attenuation: power down, OSNR roughly held; ASE: power held, OSNR down), which is the discrimination collector rules key on and the reason the engine has two dials. **Degradation is an append-only list of immutable `opticalEpisode`s** (`atomic.Pointer[[]opticalEpisode]` per channel, copy-on-append), NOT an install-and-clear pointer: `fec-uncorrectable-blocks` is the time integral of an above-threshold indicator over `[0,t]`, so clearing a "current sag" would remove already-elapsed degradation from the integral and make the counter **decrease** — a collector reads that as a device reboot. Two load-bearing invariants: a published episode's window is frozen (past segments can never change → monotonic by construction), and `t0` is never in the past (no already-observable value is rewritten; a backdated request clamps forward). The one permitted mutation is truncating an *open* episode's end forward to `now` when a later POST supersedes it. `aboveThresholdSeconds` is therefore **piecewise**: the OSNR mean steps at episode boundaries, so the interval splits there and the same closed-form arcsine applies per segment (cost O(boundaries), not O(t); an undegraded channel takes the original single-segment path). The sag is applied in `pInAt`, `nAseAt` **and `osnrAt`** — `osnrAt` reads the precomputed phasor, so sagging `pInAt` alone would move the input-power leaf while leaving the whole cascade untouched. **No revert timer** (deviation from the story's letter, contract preserved): an episode carries its own end and the engine is a pure function of `t`, so the revert is arithmetic — nothing to schedule, cancel, or leak, unlike the interface-state convention which must put mutated state back.

**gNMI decimal values:** `resolvedUpdate.Value` gained `gnmiDecimal{val, digits}` — a distinct type, not a pre-formatted string, because JSON_IETF needs an RFC 7951 quoted decimal while PROTO needs `double_val`; a Go `string` would silently take the `string_val` branch and corrupt an advertised encoding. At 18 fraction digits `double_val` is lossy (inherent to decimal64 in gNMI's PROTO scalar set); JSON_IETF preserves the digits.

**Per-device-type protocol capability.** Device types are not uniformly capable. `ciena_waveserver5` is a layer-1 coherent optical transport platform: it performs no L3/L4 inspection and therefore **exports no flow records**. Absence has to be *implemented*, not omitted — `GetFlowProfile` (`flow_profiles.go`) falls back to `flowProfileEdgeRouter` for any type absent from `flowProfileMap`, so leaving a type out would silently give it edge-router flow ground truth. The explicit marker is `flowIncapableTypes` + `SupportsFlowExport`, consulted at both device-creation paths; a batch-wide flow seed **skips** incapable devices with a log line (so `-flow-collector` stays usable with `-round-robin`), while a request whose entire resolved type set is incapable is rejected with **400** (`flowIncapableRequest`). Its optical inventory is keyed by OCH **component name** (`OCH-1-1`) in an `optical` resource part, never by `ifIndex`; `validateOpticalInventory` fails the load loudly if that part is missing, malformed, or disagrees with `OpticalProfile.ChannelCount`, because the resource decoder is not strict and would otherwise discard it silently.

Each device type has resource files under `resources/<device-type>/` containing JSON for SNMP OID responses, SSH command responses, and REST API responses.

## Source file headers

This repo is a fork of `saichler/l8opensim`. Header policy depends on whether a source file is **forked** (basename exists in `go/simulator/*.go` upstream) or **new** (created in this fork):

- **Forked files** keep upstream's full Apache 2.0 boilerplate header verbatim. Do not replace, trim, or modify it — Apache 2.0 §4(c) requires the original copyright notice be preserved when redistributing.
- **New files** (every file in `go/nl6/` whose basename has no upstream counterpart) get the canonical SPDX-short header, no exceptions:

  ```go
  /*
   * Copyright <YEAR> Ronny Trommer <ronny@no42.org>
   * SPDX-License-Identifier: Apache-2.0
   */
  ```

  - `<YEAR>` = file's creation year. Do not bump it on every edit.
  - Email in angle brackets (`<…>`), not parens — REUSE/SPDX scanner convention.
  - **No `Created by` line.** Authorship lives in `git log`, not in headers — it goes stale and conflates authorship (factual) with copyright (legal).
  - Header sits at the very top of the file, with one blank line between the closing `*/` and the next non-blank line (`//go:build` directive, `package` clause, or a leading comment block).

This overrides the OpenNMS Group form in the global `CLAUDE.md` for this repo only — the override is intentional because this fork is a personal project under no42.org, not OpenNMS Group work.

## Commit convention

Follow Conventional Commits: `<type>[scope]: <description>`
Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`

