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
-snmpv3-auth <proto>    # none | md5 | sha1. RFC 3414 USM, net-snmp-verified (nl6#624). Also selects the privacy key's hash
-snmpv3-priv <proto>    # none | des | aes128
-no-namespace           # Disable network namespace isolation
-version                # Print version string and exit (no startup side effects)
-fidelity               # [global] Keep the fleet silent (no autonomous flow/trap/syslog/gNMI dial-out push) outside a running load-test scenario window; polls and on-demand fires still work. This is THE way to silence a fleet: a long per-device interval is REJECTED with 400. Runtime-togglable via POST /api/v1/fidelity (optional duration, 24h cap); GET reports the value in force and the startup default
-scenario-pen <uint>    # [global] IANA PEN for PEN-dependent scenario run tags (syslog SD-PARAM, SNMP enterprise varbind); 0 = unset → those levers degrade to window+source-IP.

# Continuous profiling flags. OFF BY DEFAULT (no profiler goroutine, /debug/pprof/* answers 503); runtime-togglable via POST /api/v1/profiling, so the flags are defaults. See context/profiling.md
-profiling-pyroscope <url>            # [global] Pyroscope push URL; a bad URL or scheme is fatal at startup
-profiling-force-gc                   # [global] Let the SDK force a GC before a heap snapshot (default true, sized from BenchmarkForcedGCOnFleetHeap)
-profiling-pyroscope-basic-auth u:p   # [global] Basic auth for the push. FLAG-ONLY, never echoed by REST
-profiling-pyroscope-tenant <id>      # [global] Pyroscope tenant (X-Scope-OrgID). Flag-only
-optical-scenario <s>   # [seed]   Auto-start-batch per-device optical health band (optical transport types only): clean (default) | typical | degraded | failing. REST-created devices default to clean; opt in via optical_scenario.
-if-error-scenario <s>  # Auto-start-batch per-device error/discard scenario: clean (default) | typical | degraded | failing. REST-created devices default to clean; opt in via if_error_scenario.
-if-flap-scenario <s>   # [seed]   Auto-start-batch per-device link-flap scenario: clean (default; no flaps) | rare (~6h mean) | typical (~15min) | aggressive (~1min). REST-created devices default to clean; opt in via if_flap_scenario.
-if-flap-global-cap <r> # [global] Simulator-wide tps ceiling on flap events (0 = unlimited)
-gnmi-port <port>       # TCP port for gNMI listener on each device (default: 9339)
-gnmi-disable           # Disable the gNMI subsystem; no device listens on the gNMI port (default: false, subsystem on)
-gnmi-catalog <path>    # [global] JSON gNMI path catalogue replacing the catalogue of every type that CARRIES one (resources/<type>/gnmi.json). Catalogues are GENERATED (make gen-gnmi-catalog, gen-junos-chassis, gen-xr-chassis); drift tests fail on hand edits. Load rules (one entry = one notification, same-path overlap refusal, interfaces filters, origin aliases): context/gnmi-serving.md

# NETCONF over SSH flags (off by default)
-netconf-enable         # [global] Serve NETCONF over SSH (IOS XE draft dialect) on cisco_catalyst_9500 devices only. Off by default. Record: context/netconf.md
-netconf-port <port>    # [global] TCP port of the per-device NETCONF listener (default: 830)

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
-flow-tick-interval <secs|dur>    # [seed]   ONE simulator-wide ticker cadence (default 5s). A BATCHING knob, not a volume knob. Per-device tick_interval is REJECTED with 400
-flow-active-timeout <secs|dur>   # [seed]   Mean cap on a still-running flow's cache residency (default 30s; each flow's deadline carries ±25% jitter)
-flow-inactive-timeout <secs|dur> # [seed]   Idle time after a flow's last packet before export (default 15s). These three take an integer (seconds) or a duration; zero or less is refused. Details: context/flow-export.md
-flow-template-interval <secs|dur> # [global] Re-send template every N seconds (default: 60s; ignored under netflow5/sflow)
-flow-sub-agent-id <uint>         # [seed]   sFlow sub_agent_id for the auto-start batch (default: 0; one value for the whole batch — use per-device REST flow.sub_agent_id for per-group values; ignored by non-sflow protocols)
-flow-option-interface-table <s>  # [seed]   v9/IPFIX interface option records: if-scoped (ifIndex in scope, fields 82+83) | system-scoped (ifIndex as option field, field 83 only; IOS-XR shape). Empty = off (default). Requires netflow9/ipfix; per-group shapes via REST flow.options_interface_table
-flow-tick-sync                   # [global] Sweep the whole fleet on ONE ticker firing (restart-storm pattern). Default false: each device is swept at its own IP-hashed phase slot so a collector sees a near-flat arrival rate
-flow-source-per-device           # [global] Bind per-device UDP socket so src IP = device IP (default: true)
-flow-nbar2                       # [seed]   Cisco AVC (NBAR2) IPFIX records from NBAR2-capable auto-start devices (curated in nbar2_capability.go). Requires ipfix, a collector AND a capable auto-start type, else FATAL at startup; the auto-start batch is asr9k, so today this is refused on every boot and NBAR2 devices come from REST flow.nbar2
-nbar2-catalog <path>             # [global] Replace the embedded NBAR2 catalog and every per-type overlay; read once at startup; oversized entries are DISABLED and named, never a boot failure
-datagram-mtu <bytes>             # [global] Assumed MTU of the EGRESS path to collectors (default 1500; 576..65535, out of range is fatal). EVERY UDP-emitting subsystem (flow, trap, SNMP GETBULK) sizes datagrams to this frame. Lower it on overlays and tunnels (Docker overlay is typically 1450; at 1450 every default-sized datagram fragments, measured). Deliberately NOT auto-discovered: SNMP learns the destination only per request. See context/flow-export.md

# SNMP trap / INFORM export flags (SNMPv2c only)
-trap-collector <host:port>       # [seed]   Seed trap collector for auto-start batch (default port 162)
-trap-mode <proto>                # [seed]   trap (default, fire-and-forget) | inform (acknowledged)
-trap-interval <duration>         # [seed]   SIMULATOR-WIDE mean firing interval, Poisson-distributed (default: 30s). Per-device `interval` is REJECTED with a 400, same as syslog (nl6#445).
-trap-global-cap <tps>            # [global] Simulator-wide tps ceiling (0 = unlimited)
-trap-catalog <path>              # [global] Override embedded universal catalog (5 entries) + per-type overlays — when set, the single file becomes the catalog for every device
-trap-community <string>          # [seed]   SNMPv2c community (default: public)
-trap-source-per-device           # [global] Source IP = device IP (default: true; REQUIRED in inform mode)
-trap-inform-timeout <duration>   # [seed]   Per-retry timeout in inform mode (default: 5s)
-trap-inform-retries <int>        # [seed]   Max retransmissions per inform (default: 2)
-trap-snmp-version <v>            # [seed]   v2c (default) | v1 (RFC 1157 Trap-PDU) | v3 (RFC 3414 USM). One per fleet; neither v1 nor v3 can serve -trap-mode inform
-trap-snmpv3-user <name>          # [seed]   USM user name for v3 notifications (REQUIRED when -trap-snmp-version=v3)
-trap-snmpv3-auth <proto>         # [seed]   none (default) | md5 | sha1. STRICT: an unknown value is fatal, unlike -snmpv3-auth
-trap-snmpv3-priv <proto>         # [seed]   none (default) | des | aes128. Requires an auth protocol
-trap-snmpv3-password <pw>        # [seed]   USM auth password for v3 notifications
-trap-snmpv3-priv-password <pw>   # [seed]   USM privacy password (empty = reuse -trap-snmpv3-password)
                                  #          No -trap-snmpv3-engine-id: each device derives its own from its IPv4 (RFC 3411 §5 format 3), so a polled device and a trap from it report DIFFERENT snmpEngineIDs. Correct per RFC 3414 §2.1; context/snmpv3-usm-and-notifications.md

# UDP syslog export flags (RFC 5424 / RFC 3164)
-syslog-collector <host:port>     # [seed]   Seed collector for auto-start batch (default port 514)
-syslog-transport <t>             # [seed]   udp (default) | tcp (RFC 6587) | tls (RFC 5425: tcp inside TLS, port 6514 default, octet-counting FORCED). TCP is one connection PER DEVICE with capped-backoff reconnect and keepalives; per-device via REST `syslog.transport`.
-syslog-framing <f>               # [seed]   octet-counting (default) | non-transparent. TCP only — setting it under udp is REJECTED at startup, not ignored (nl6#445 failure mode).
-syslog-format <fmt>              # [seed]   5424 (default, structured) | 3164 (legacy BSD)
-syslog-interval <duration>       # [seed]   SIMULATOR-WIDE mean firing interval, Poisson-distributed (default: 10s). Per-device interval is REJECTED with 400; silence a fleet with -fidelity
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
| `go/nl6/resources/` | 412 JSON files (31 device types) with SNMP/SSH/REST response data |

### Core simulator components (`go/nl6/`)

**Device lifecycle:** `simulator.go` (CLI/entry) → `manager.go` (SimulatorManager, shared keys/certs) → `device.go` (per-device startup, protocol server lifecycle)

**SNMP stack:** `snmp_server.go` → `snmp.go` (request handling) → `snmp_handlers.go` (OID lookup via sync.Map) → `snmp_response.go` (response building) → `snmp_encoding.go` (ASN.1 BER/DER).

**SNMP SET (`snmp_set.go`).** SetRequest is served at v1/v2c/v3 on ONE curated writable column (`ifAdminStatus.<N>`), through the RFC 3416 §4.2.5 ladder, validate-all-then-apply, and the `ApplyAdminStatus` funnel every admin mutation takes (it does NOT cascade: oper is derived). **Write admission is OPT-IN and a default fleet answers NO SET at any version**: `-snmp-write-community` / REST `write_community` gates v1/v2c (a mismatch is silently DISCARDED, as hardware does), `-snmp-set-min-security-level` (default `auth`) / `snmpv3.set_min_security_level` gates v3 (a `usmStatsUnsupportedSecLevels` Report). Reads are untouched at every version. The write community is write-only and never echoed. Record: `context/snmp-set.md`.

**Long-form engineering record.** The per-issue narrative for the areas below lives in `context/`, not here, because this file is auto-loaded into every session. Read the matching file BEFORE changing any of these areas. Each records what the defect was, how it was found, and the mistake that is easy to reintroduce.

| Area | File |
|------|------|
| SNMP response sizing, exceptions, v1 divergence, GETBULK bounds | `context/snmp-wire-encoding.md` |
| SNMP SET ladder and write admission | `context/snmp-set.md` |
| Resource-file load rules, corpus guards, shipped-data ledgers | `context/snmp-resource-data-quality.md` |
| Vendor enterprise arcs, PEN ownership, audit miss rates | `context/snmp-vendor-arcs.md` |
| SNMPv3 USM conformance, v1/v3 notifications | `context/snmpv3-usm-and-notifications.md` |
| Dynamic IF-MIB counters, counter hold and roll-up, interface-state clock | `context/if-counters.md` |
| Interface state engine, subinterfaces, scenario seed, REST auto-revert | `context/interface-state.md` |
| Device-creation locking, batch gate, test seams, write deadline, sysName uniqueness | `context/device-creation-batching.md` |
| Flow export: datagram budget, status counters, jitter and pacing, NBAR2 | `context/flow-export.md` |
| NBAR2 evidence and the IOS-XE reference capture | `context/nbar2-evidence.md` |
| Trap and syslog catalogs, operational notes, syslog TCP/TLS transports | `context/trap-syslog-export.md` |
| gNMI catalogue load rules, handshake counting, dial-out, decimals, unions | `context/gnmi-serving.md` |
| gNMI vendor profiles, public sources, vJunos capture record | `context/gnmi-vendor-sources.md` |
| Optical value engine, degradation, gNMI optical paths | `context/optical-engine.md` |
| Continuous profiling | `context/profiling.md` |
| Scenario drain barrier | `context/scenario-drain-barrier.md` |
| Profile reload | `context/resource-reload.md` |

**SNMP rules in one paragraph (the files above hold the reasoning).** Response size is a FRAME bound that tracks `-datagram-mtu`; GETBULK truncates, GET and GETNEXT answer `tooBig` with an empty binding list, and sizing is exact via `snmpMessageSizeFor`, never estimated. An absent OID is `noSuchObject`; exceptions travel as sentinel strings, which is why the load guard refuses a resource value spelled like one; SNMPv1 diverts a sentinel to `noSuchName`, and Counter64 under v1 is a GET error but a GETNEXT SKIP (RFC 3584 §4.2.2.1). SNMPv3 USM is RFC 3414 conformant and net-snmp verified (`make test-interop`); the engine ID is fleet-wide and `engineBoots` is always 1. The load guards (`validateSNMPResourceValues`, the typed-class rule, the bare-column and trap-versus-poll checks) prove ENCODABILITY, not SEMANTICS. Vendor-arc audits are quoted as MISS RATES; every vendor arc is audited, labelled `UNAUDITED-ARC(<pen>)` or excluded by name, and every profile serves its own PEN and no other. A data edit adds exactly ONE entry to `newestFirstReversals`. Deleting rows may legitimately empty a table: never restore a row to make a table non-empty.

**Dynamic IF-MIB counters and interface state (`if_counters.go`, `interface_state.go`).** `IfCounterCycler.GetDynamic` serves `ifTable`/`ifXTable` counters analytically; Counter32 columns are the low 32 bits of the HC column read at the SAME `t`; `ifCyclerColumns` is in MIB lex order and doubles as the walk enumeration. A static row on a cycler-owned column is dead data, EXCEPT `.7` `ifAdminStatus` and `.8` `ifOperStatus`, which seed the engine and must never be deleted. `InterfaceState` stores link, admin and last-change per ifIndex in one packed atomic slot; **oper is DERIVED by `deriveOper(admin, link)`, never stored**. `SetLinkState` moves the link (flap scheduler, REST oper-status POST) and the `ApplyAdminStatus` funnel moves admin (REST admin-status POST, its auto-revert, SNMP SET) without cascading; `Broadcast` keys on the derived transition and fires the Tier C link traps and syslog. Subinterfaces follow their parent (`lowerLayerDown(7)`, `familyMu`), `-if-scenario` is a SEED applied once at init with no read-time override, counters hold while oper is not up and roll up through `ifStackTable`, auto-revert POSTs snapshot the LINK, and the engine's clock is injectable with three reads that move together. Records: `context/if-counters.md` and `context/interface-state.md`.

**Metrics engine:** `metrics_cycler.go` drives 100-point pre-generated sine-wave patterns per device. `gpu_metrics.go` handles per-GPU metrics (utilization, VRAM, temperature, power, clocks). `device_profiles.go` defines per-category baselines.

**Network infrastructure:** `tun.go` creates TUN interfaces, `netns.go` manages the `nl6sim` network namespace, `prealloc.go` does parallel pre-allocation of TUN interfaces (configurable worker count 100–200) for fast scaling.

**Device creation is one batch at a time (`createBatchGate`; a concurrent batch gets 409).** `sm.mu` governs `nextTunIndex`, `currentIP`, `tunPoolSize` and `maxWorkers`; `tunPoolMutex` governs `tunInterfacePool`; lock order is `sm.mu` then `tunPoolMutex`; no lock is held across interface creation. `reservePreAllocBatch` commits the TUN base, pool size and end IP in ONE critical section before any worker starts, and a worker never reads `sm.nextTunIndex`. The gate spans reservation AND the IP walk, sits above the freeze check and resource resolution, and reports the running batch from the `createBatch` token (`create_batch_in_progress` on `GET /api/v1/status`); `scripts/fleet.sh import` retries on 409. The create handler re-arms its write deadline after the batch returns. `reserveSysName` keeps `sysName` unique among live devices and `DeleteAllDevices` must never reset the map. Record, including what the gate does NOT close and the two test seams: `context/device-creation-batching.md`.

**Continuous profiling** (`profiling.go`, `profiling_api.go`) is one gate, off by default, with the `/debug/pprof/` surface on the ROOT router; credentials are flag-only and bound to the flag's address; lock order is `profilingLifecycle` then `profiling.mu`; `make test-interop-pyroscope` is the check with detection power. Record: `context/profiling.md`.

**Web API:** `web.go` (route setup) + `api.go` (handlers) + `web_routes*.go` (Linux route script generation). Serves device CRUD, CSV export, system stats, simulator version (`GET /api/v1/version` → `{"version":"vX.Y.Z"}`, immutable per process, `Cache-Control: max-age=3600`), flow export status (`GET /api/v1/flows/status`), trap export status (`GET /api/v1/traps/status`), syslog export status (`GET /api/v1/syslog/status`), gNMI subsystem status (`GET /api/v1/gnmi/status`, also reports `state_events_emitted` / `state_events_dropped` for ON_CHANGE fan-out), on-demand trap firing (`POST /api/v1/devices/{ip}/trap`), on-demand syslog firing (`POST /api/v1/devices/{ip}/syslog`), interface state control (`POST /api/v1/devices/{ip}/interfaces/{ifIndex}/{oper,admin}-status`), device-profile reload by eviction (`POST /api/v1/resources/reload`, nl6#519; see the resources paragraph), the continuous-profiling gate (`GET`/`POST /api/v1/profiling` plus the gated root-router `/debug/pprof/`, nl6#635; see the profiling paragraph), and inter-device topology (`POST` / `GET` / `DELETE /api/v1/topology`, `GET /api/v1/topology/status` → `{subsystem_active, configured_links, active_links}`), and Prometheus HTTP service discovery (`GET /api/v1/prometheus/sd`, `prometheus_sd.go`: one target group per RUNNING device for snmp_exporter, `__meta_nl6_*` labels, never `null`; the `promSDDevice` field set is the credential boundary and is pinned exact).

**Flow export (per-device config, phase 3):** `flow_exporter.go` (FlowExporter, FlowEncoder interface, SimulatorManager integration) + `netflow9.go` (NetFlow9Encoder, RFC 3954) + `ipfix.go` (IPFIXEncoder, RFC 7011) + `netflow5.go` (NetFlow5Encoder, Cisco v5: 24B header, 48B/record, IPv4-only, 30-record datagram cap, no templates) + `sflow.go` (SFlowEncoder, sFlow v5 per sflow_version_5.txt: 28B XDR datagram header, variable-length flow_sample records carrying sampled_header=IPv4+UDP/TCP synthesized from the FlowRecord 5-tuple, no template mechanism). Each device owns its collector/protocol/timeouts on `DeviceFlowConfig`; the manager owns a shared-socket pool keyed by `(collector, protocol)` and one ticker goroutine. `FlowStatus` is an array-of-collectors aggregated by `(collector, protocol)`. Protocols:

| Protocol   | Header | Record size    | Template? | Timestamps         | IPv6 records | Notes |
|------------|--------|----------------|-----------|--------------------|--------------|-------|
| `netflow5` | 24B    | 48B fixed      | none      | SysUptime-relative | filtered     | 30-record datagram cap; 32-bit ASNs clamp to `23456` (AS_TRANS, RFC 6793 §2); `-flow-template-interval` is a silent no-op |
| `netflow9` | 20B    | 46B fixed      | yes       | SysUptime-relative | filtered     | Single 19-field template, ID 256; last field DIRECTION(61) = constant ingress (0x00) |
| `ipfix`    | 16B    | 54B fixed      | yes       | absolute epoch ms  | filtered     | Template Set ID 2, IE-based fields; last IE flowDirection(61) = constant ingress (0x00). Sequence Number counts **Data Records** (RFC 7011 §3.1; options data records included, template records excluded), so a template-only message advances it by 0. v9 counts export packets; the two differ and `SeqIncrement` is the seam. |
| `sflow`    | 28B    | variable (~100B typical) | none (self-describing) | uptime + flow_sample sampling_rate | filtered (IPv4 agent only) | Synthetic sampling_rate = `10 × FlowProfile.ConcurrentFlows` (see `SyntheticSamplingRateMultiplier`); emits flow_sample (type 1) + Phase-2 counters_sample (type 2) per tick. **sFlow output is synthetic — the simulator does not observe real packet streams.** Agent identity = device IPv4; `-flow-source-per-device` makes the UDP source IP match `agent_address`. |
| `ipfix` (AVC template 258) | 16B | 54B fixed prefix + applicationId 4B + two variable-length PEN 9 fields | yes (258, plus application table 259 on the refresh cadence) | absolute epoch ms | filtered | NBAR2 layer-7 export; constants derive from `testdata/cisco-avc/elements.tsv`; IE 9357 hit count (wire specifier 42125) is big-endian with no trailing delimiter (capture-confirmed, nl6#681; documented at `uriStatsValue`); enabled per device by `flow.nbar2` / `-flow-nbar2` (Plan B, below). **The claim is "conformant and interop-tested against open decoders", NOT Cisco-faithful** (nl6#680, decided against the IOS-XE 26.01.02 capture); the six capture-shown differences are listed in `docs/reference/flow-export.md`, the first of them (the IE 12235 host prefix, nl6#679) resolved. |

**Flow export rules (record: `context/flow-export.md`).** `Tick` sizes every datagram against the frame budget (`flowPayloadBudget`: 1472 for an IPv4 collector, 1452 for IPv6) derived from `-datagram-mtu`; fragmentation is invisible on loopback and visible on veth. `FlowEncoder.MaxRecordSize()` is the per-record worst-case bound `Tick` paginates variable-length encoders (sFlow) with; fixed-size encoders return 0. Status counters mean REACHED THE KERNEL; a refused write lands in `send_failures` while `flow_sequence` still advances. Each flow's active-timeout deadline carries ±25% jitter drawn UNCONDITIONALLY from the device RNG, and pacing divides by `effectiveFlowLifetime` (mean lifetime plus half a sweep, at the SCENARIO's cadence). NBAR2 (`nbar2_catalog.go`) is the third catalog of the trap/syslog shape, one encoder per resolved catalog; capability is curated per type and an incapable device in a mixed batch keeps plain IPFIX. Non-NBAR2 output is pinned byte-identical by `flow_digest_test.go`; regenerate the digest ONLY for an intended wire change and say so. Flow scenario reports carry sent-basis `applications[]` and `l7_values[]` ground truth, and `make test-interop-ipfix` reconciles them against a real IPFIXcol2. The scenario post-window phase is a BARRIER with one shared budget, not a duration (`context/scenario-drain-barrier.md`).

**SNMP trap export (per-device config, phase 4):** `trap_manager.go` (SimulatorManager integration, `TrapSubsystemConfig`, `StartTrapSubsystem` / `StopTrapExport`, HTTP handlers' helpers, `TrapStatus`) + `trap_catalog.go` (JSON catalog loader with embedded universal set + weighted-random pick + `text/template`-based varbind resolution) + `trap_v2c.go` (SNMPv2c TRAP [0xA7] and InformRequest [0xA6] PDU encoder, GetResponse [0xA2] ack parser — reuses `snmp_encoding.go` ASN.1 primitives) + `trap_scheduler.go` (single central min-heap scheduler goroutine with Poisson inter-arrival + `golang.org/x/time/rate` global cap) + `trap_exporter.go` (per-device `TrapExporter` with atomic per-device UDP socket, bounded pending-inform map with oldest-drop, reader/retry goroutines in INFORM mode). Each device owns its collector/mode/community/interval/inform-* settings on `DeviceTrapConfig`; the manager owns a shared-socket pool keyed by collector and a per-(collector, mode) monotonic counter aggregate that survives device deletion. `TrapStatus` is an array-of-collectors aggregated by `(collector, mode)`, with a top-level `subsystem_active` bool for observability.

**Trap catalog.** The universal catalog is embedded from `resources/_common/traps.json` (5 RFC 3418 entries); `-trap-catalog` is a complete replacement; `resources/<type>/traps.json` overlays per type (`extends` defaults to true, weights recomputed post-merge). Role-tagged entries (`link-down` / `link-up`) are excluded from the scheduler's `Pick` and fired by oper-status transitions via `EntriesByRole` (vendor wins per role). Trap and syslog share one 11-field template vocabulary (`IfIndex`, `IfName`, `Uptime`, `Now`, `DeviceIP`, `SysName`, `Model`, `Serial`, `ChassisID`, `NowLocal`, `Detail`); unknown fields are rejected at load. The encoder prepends `sysUpTime.0` and `snmpTrapOID.0` (plus `snmpTrapEnterprise.0` when the entry sets it); listing those as body varbinds is rejected. `-trap-snmp-version v1` emits the RFC 1157 Trap-PDU derived from `snmpTrapOID` per RFC 3584 §3.2 (no catalog change; a declared enterprise is NOT an override); `v3` wraps the same PDU in a USM envelope from an encoder-private `SNMPServer`, with a per-device engine ID derived from the IP. Neither serves INFORM. Record: `context/trap-syslog-export.md`, `context/snmpv3-usm-and-notifications.md`.

**Trap operational rules.** `maxTrapPDU` is a FRAME bound derived from `-datagram-mtu`, read at three sites that must agree. Catalog load dry-renders every entry at worst case (including `{{.Detail}}`) and marks over-budget entries `oversized`: excluded from `Pick` AND `EntriesByRole`, named at startup, never a load failure. Lowering the MTU below roughly 1028 silences the shipped Ciena optical alarms, and the startup log says so. INFORM mode requires per-device source binding; the pending-inform map is bounded at 100 with oldest-drop; retransmissions consume global-cap tokens. `StopTrapExport` is shutdown-only. Endpoints (`GET /api/v1/traps/status`, `POST /api/v1/devices/{ip}/trap`): `docs/reference/snmp-traps.md`.

**UDP syslog export (per-device config, phase 5):** `syslog_manager.go` (SimulatorManager integration, `SyslogSubsystemConfig`, `StartSyslogSubsystem` / `StopSyslogExport`, `SyslogStatus`) + `syslog_catalog.go` (JSON catalog with embedded universal 6-entry set; weighted-random pick; `text/template`-based body / structured-data resolution with all templates pre-compiled at load) + `syslog_wire.go` (`SyslogEncoder` interface with `RFC5424Encoder` and `RFC3164Encoder` — PRI calc, ISO 8601 / `Mmm DD HH:MM:SS` timestamps, SD-PARAM escape per §6.3.3, HOSTNAME / APP-NAME / MSGID / TAG sanitisation, MaxMessageSize enforcement) + `syslog_scheduler.go` (single central min-heap scheduler with Poisson inter-arrival + `golang.org/x/time/rate` global cap; derived context so `Stop()` is bounded-time under cap) + `syslog_exporter.go` (per-device `SyslogExporter` with atomic per-device UDP socket and shared-socket fallback). Each device owns its collector/format/interval on `DeviceSyslogConfig`; the manager owns a shared-socket pool keyed by `(collector, format)`, a per-format encoder cache, and a per-(collector, format) monotonic counter aggregate. `SyslogStatus` is an array-of-collectors aggregated by `(collector, format)`, with a top-level `subsystem_active` bool.

**Syslog catalog.** Same shape as trap: an embedded universal 6-entry catalog, `-syslog-catalog` as a replacement, per-type overlays, role-tagged `interface-up` / `interface-down` fired by oper transitions, the same 11-field vocabulary, every template pre-compiled at load. `appName` is required (RFC 3164 TAG has no NILVALUE); facility and severity accept names or integers; SD-NAME keys follow RFC 5424 §6.3.3; HOSTNAME is the entry's `hostname` template, else `sysName`, else the IP, always through `sanitiseHostname`. `maxSyslogMessageBytes = 1400` is a DATAGRAM bound applied to every catalog regardless of transport. Entry schema, PRI vocabulary and endpoints: `docs/reference/syslog-export.md`.

**Syslog transports.** `SyslogTransport` sits UNDER the write, so catalog resolution, the scenario gate and ledger accounting are transport-independent. UDP is the datagram path byte-for-byte; TCP (RFC 6587) is one connection PER DEVICE with no shared-socket rung (a failed connect refuses the attach, and `-syslog-source-per-device=false` fails a TCP attach); TLS (RFC 5425) decorates the DIALER and reuses `tcpTransport` whole, verifying the COLLECTOR with inline `tls.ca_pem` (never a path: the block is REST-settable). Three load-bearing details: `SO_SNDBUF` is capped at 16 KiB per connection and the TLS dialer must apply it on the raw socket BEFORE wrapping, every write carries a deadline, and only a read ERROR counts as connection loss. Per-device UDP bind failure falls back to the shared socket; `StopSyslogExport` is shutdown-only. Record: `context/trap-syslog-export.md`.

**gNMI target:** `gnmi_paths.go` (path resolver — wildcard expansion, single-name reverse-ifDescr lookup, subtree flattening, scoped to `/interfaces/interface[name=*]/state/{name,ifindex,oper-status,admin-status,last-change,counters/*}`) + `gnmi_handlers.go` (`gnmi.GNMIServer`: `Capabilities`, `Get`, `Subscribe`, `Set` returning `Unimplemented`) + `gnmi_subscribe.go` (per-stream ticker + send goroutine with 100-deep oldest-drop send buffer; ONCE handled synchronously) + `gnmi_subscribe_onchange.go` (ON_CHANGE handler with listener-channel fan-out from `InterfaceState`, per-sub heartbeat tickers, (ifIndex, leaf) filtering) + `gnmi_server.go` (per-device gRPC listener bound inside the `nl6sim` netns, **TLS by default and plaintext under `-gnmi-tls=false`**; the TLS path reuses `SimulatorManager.sharedTLSCert` — same cert as the HTTPS REST surface; `MaxConcurrentStreams=16` per-connection) + `gnmi_manager.go` (`GnmiSubsystemConfig`, `StartGnmiSubsystem` / shutdown-only `StopGnmiSubsystem`, atomic counters for `active_subscriptions`, `updates_sent`, `updates_dropped`, `state_events_emitted`, `state_events_dropped`). Read-only by design — `Set` returns `Unimplemented`. Subscribe modes: STREAM/SAMPLE + STREAM/ON_CHANGE (state-leaf paths only) + ONCE; mixed ON_CHANGE+SAMPLE in one request rejected with `InvalidArgument`; POLL rejected with `Unimplemented`; TARGET_DEFINED treated as SAMPLE; sub-second `sample_interval` and `heartbeat_interval` clamped to 1s silently. Encoding: `JSON_IETF` default + `PROTO` advertised. State and counter values reuse `IfCounterCycler.GetDynamicAt`, so gNMI / SNMP / sFlow agree byte-for-byte at the same instant. `subsystem_active=false` when `-gnmi-disable` is set.

**gNMI dial-out** (`gnmi_dialout_*.go`) reverses the gRPC role, not the data direction: one `ClientConn` and one `Publish` stream per device over Arista `gnmireverse`, dialled from inside the device netns, payload and state fan-out reused verbatim from dial-in, `Prefix.Target` = device IP. `ca_pem` is INLINE and `certificateBlocksOnly` strips non-certificate blocks at both entry points, because `GET /api/v1/devices` echoes the block. Drop-on-outage; shutdown-only stop. On dial-in, `tls_handshake_failures` is counted from a `TransportCredentials` wrapper, because gRPC handshakes AFTER `Accept` returns. Record: `context/gnmi-serving.md`, `docs/reference/gnmi-dial-out.md`.

**NETCONF over SSH (opt-in, `netconf_*.go`):** one listener per `cisco_catalyst_9500` device on `-netconf-port`, SSH `netconf` subsystem only, the device SSH login and shared host key. It serves the IOS XE draft `establish-subscription` on `Cisco-IOS-XE-interfaces-oper` and pushes `push-update` / `push-change-update` from an `InterfaceState` listener (never `SetNotify`). It emulates one real Cat9300 and serves less where uncaptured: no `ietf-interfaces` on-change, no RFC 8639, no `get`, no TLS, and no notification for an admin change on a link-down interface. Read `context/netconf.md` before changing it; status at `GET /api/v1/netconf/status`.

**LLDP topology:** `topology.go` (`Topology` — a `SimulatorManager`-owned, mutex-guarded graph of undirected `(deviceIP, ifIndex)` links; the single source of truth for inter-device connectivity) + `lldp_table.go` (the dynamic SNMP provider). Configured via `-topology-config` at startup and `POST` / `GET` / `DELETE /api/v1/topology` at runtime (`topology_api.go`); pruned on `DeleteDevice`. Validation at add time is **syntactic only** (no self-loop, no duplicate, one link per local port — point-to-point); device existence and ifIndex ownership resolve **lazily at SNMP-serve time**, so a link may reference an auto-start device the background goroutine hasn't created yet. The provider serves the Enlinkd-minimal LLDP-MIB subset (`1.0.8802.1.1.2`): `lldpLocalSystemData` + `lldpLocPortTable` + `lldpRemTable`, plus an `ifAlias` (ifXTable .18) link label `to_<peerSysName>_<peerIfDescr>`. It hooks `snmp_handlers.go` `findResponse` (GET) and `findNextOID` (WALK) — the latter adds an `lldpClear` fast-path term (LLDP sorts *before* all static OIDs) and an `overrideLLDP` walk-value rewrite (so the dynamic ifAlias wins over a statically-shipped `.18.N` on GETNEXT/GETBULK). Stitching invariant: `lldpRemChassisId`/`lldpRemPortId` are derived from the *peer's* canonical sources (the `02:42:<ipv4>` chassis MAC and the peer's `ifDescr`), identical to what the peer advertises locally, so Enlinkd matches the two half-links. `lldpRemTable` rows are oper-status-aware (emitted only when both ends are UP; a peer with no state engine is treated as UP; nil-guarded); `ifAlias` reflects configured intent and persists when the port is DOWN. Reads the global `manager` (like gNMI), so no per-device field or device-creation-path change. Walk anchor: a mib-2-rooted walk never reaches `1.0.8802` — point Enlinkd at the LLDP root. Out of scope: capability bitmaps, `lldpStatistics`/`lldpConfiguration`, gNMI/openconfig-lldp.

**DNS service discovery:** `dns_zone.go` (pure, dependency-free zone model — `sanitiseDNSLabel`, deterministic collision disambiguation, `in-addr.arpa` reverse-zone parse/membership, `buildZoneView` producing forward `A` (`<device>` + `ip4.mgmt.<device>`) + reverse `PTR` records + status counters, monotonic `nextSerial`) + `dns_server.go` (`miekg/dns` hidden-primary authoritative server bound in the **default** netns on `-dns-listen` (`:5353`): SOA/NS/A/PTR direct answers, AXFR streaming in 256-record envelopes, IXFR→AXFR fallback, concurrent context-cancellable NOTIFY sender, apex SOA/NS fast path that skips the full rebuild) + `dns_manager.go` (`SimulatorManager` implements the server's `zoneDataProvider` — `DNSDevices`/`ZoneSerial` over the live device map, no per-device DNS state; `StartDnsSubsystem` / shutdown-only `StopDnsSubsystem`; `markDNSDirty` funnelled from every device create/delete; debounce worker coalesces a burst into one serial bump + one NOTIFY round) + `dns_api.go` (`GET /api/v1/dns/status`, `-dns-domain` validation, comma-list flag split). Off by default (`-dns-enable`); the zone content is a derived view over `ListDevices()` (like the LLDP/topology providers). nl6 is the hidden primary; a CoreDNS secondary transfers the zones (`examples/coredns-sidecar/`). Forward `<device-name>.nl6.local` → mgmt IP; reverse PTR → `ip4.mgmt.<device-name>.nl6.local` (round-trips). Names are sanitised `sysName`; duplicates disambiguated by ascending-IP order. SOA serial is epoch-seeded and not persisted (restart-with-clock-rollback caveat, documented). Out of scope: `ip6.*` records, per-interface IPs, IXFR, DNSSEC/TSIG. See `docs/reference/dns-service-discovery.md`.

**Topology visualization (web console):** `web/topology_logic.js` (pure, DOM-free, node-tested in `topology_logic.test.js`: model building, layouts, structure/state diffing, click-to-flap target resolution, scale guard) + `web/app_topology.js` (sigma.js/graphology glue, poll loop, interaction). Polls `GET /api/v1/topology/graph`, relayouts only on structure change (recolors on state-only). Two layouts: `tieredLayout` (**default** — horizontal fabric bands; tier rank from the device model label via the `TIER_RANK` table mirroring `deviceProfileMap` categories, compacted to dense bands, untyped/missing nodes fall one band below their highest typed neighbour, within-band barycenter sweeps cut crossings) and `forceLayout` (organic Fruchterman-Reingold). A Force/Tiered toggle in the topology panel switches layouts (a structural-render trigger). Device labels render over a theme-coloured background box (custom `defaultDrawNodeLabel`/`defaultDrawNodeHover`, bg from `--surface`/`--bg` at 0.88 alpha) so text stays legible over edges/nodes.

**Resource loading:** `resources.go` loads and caches the 412 JSON files at startup. Each device type directory has split JSON files for SNMP, SSH, and REST responses that are merged at load time.

**Resource loading** (`resources.go`) caches the JSON profiles behind `resourcesCacheMu`; the canonical locking rule is the `resourcesCache` comment in `types.go` (two write sites, one per layout; a rejection is not cached). `POST /api/v1/resources/reload` is EVICTION, never mutation: a device holds its snapshot and serves exactly what it served before. `sm.deviceResources` is read from `resources/asr9k/` through the cache, and the reload holds `createBatchGate`. Record: `context/resource-reload.md`.

### Key design decisions

- **sync.Map for OID lookups** — lock-free O(1) access during concurrent SNMP queries
- **Pre-computed next-OID mappings** — efficient SNMP GETNEXT/WALK without scanning
- **Buffer pool** — reduces GC pressure on SNMP request handling
- **Shared SSH/TLS keys** across all devices — avoids per-device key generation overhead
- **Network namespace isolation** (`nl6sim` namespace) — prevents systemd-networkd interference
- **Per-device flow egress** — `setupVethPair` installs a `FORWARD -i veth-sim-host -j ACCEPT` iptables rule so that per-device flow exporters can send UDP out of the ns through the host's routing table (Docker-present hosts default FORWARD to drop). Rule is removed in `NetNamespace.Close`. The simulator image includes `iptables` for this reason. On the downstream flow collector, `rp_filter` may need to be relaxed (`net.ipv4.conf.*.rp_filter=0` or `2`) to accept packets with 10.42.0.0/16 source IPs.

### Device types

31 device types across 9 categories: Core Routers, Edge Routers, Data Center Switches, Campus Switches, Firewalls, Servers, GPU Servers (NVIDIA DGX-A100/H100/HGX-H200), Storage Systems (AWS S3, Pure Storage, NetApp ONTAP, Dell EMC Unity), Optical Transport (Ciena Waveserver 5).

**Optical value engine (`optical_cycler.go`, `optical_degrade.go`).** `OpticalCycler.GetDynamicAt(component, leaf, t)` is keyed by OCH component name, a pure function of elapsed time with two independent dials (received power and ASE noise, `osnr = pIn − nAse`) cascading through q-value and `pre-fec-ber` (½·erfc, shallow at the SD-FEC threshold) to `fec-uncorrectable-blocks`. The health band comes from `-optical-scenario` / `optical_scenario` via `opticalBandFor`, and the band contracts must hold for every seed. Degradation is an append-only list of immutable episodes, so the block counter is monotonic by construction and there is no revert timer. `post-fec-ber` is deliberately not served. A non-clean scenario on a non-optical type is a 400. gNMI serves it under `/components/component[name=$och]/optical-channel/`. Record: `context/optical-engine.md`.

**gNMI decimals and unions.** A decimal leaf is a `gnmiDecimal` built ONLY by `newGnmiDecimal(v, digits)`, rounded once, so JSON_IETF, `double_val` and `decimal_val` serve one reading. A union leaf's `members` are generated in declaration order and the cast takes the first member that accepts the value; never paper over a union with a `string` override. Record: `context/gnmi-serving.md`.

**Per-device-type protocol capability.** Device types are not uniformly capable. `ciena_waveserver5` is a layer-1 coherent optical transport platform: it performs no L3/L4 inspection and therefore **exports no flow records**. Absence has to be *implemented*, not omitted — `GetFlowProfile` (`flow_profiles.go`) falls back to `flowProfileEdgeRouter` for any type absent from `flowProfileMap`, so leaving a type out would silently give it edge-router flow ground truth. The explicit marker is `flowIncapableTypes` + `SupportsFlowExport`, consulted at both device-creation paths; a batch-wide flow seed **skips** incapable devices with a log line (so `-flow-collector` stays usable with `-round-robin`), while a request whose entire resolved type set is incapable is rejected with **400** (`flowIncapableRequest`). Its optical inventory is keyed by OCH **component name** (`OCH-1-1`) in an `optical` resource part, never by `ifIndex`; `validateOpticalInventory` fails the load loudly if that part is missing, malformed, or disagrees with `OpticalProfile.ChannelCount`, because the resource decoder is not strict and would otherwise discard it silently.

**Capability-gating boundary (#364):** GROUND-TRUTH-BEARING surfaces — things a collector validates against (flow byte math, optical values) — get per-type fidelity gating (`flowIncapableTypes`, `opticalIncapableRequest`). TRANSPORT PLUMBING deliberately does not: gNMI dial-out is Arista-flavored `gnmireverse` on a fleet with zero Arista types, because its purpose is letting teams test a dial-out collector at scale against a heterogeneous fleet — gating it by fidelity would gate it to the empty set. The absence of dial-out gating is a decision, not an omission. Completeness of the flow maps is enforced in CI (`TestFlowCapabilityCompleteness`: every repo type in `flowProfileMap` XOR `flowIncapableTypes`); operator-supplied custom resource files fall back to the edge-router flow profile with a once-per-type log line, since the compiled-in maps are unreachable to them.

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

