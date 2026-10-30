# Architecture

nl6 is a single Go program that stands up thousands of simulated devices inside a dedicated Linux network namespace.
Each simulated device has its own IP address on a TUN interface, its own SNMP listener, its own SSH server, a gNMI server, and, for storage devices, its own HTTPS REST endpoint.

## System overview

The diagram is a [C4 container](https://c4model.com/#ContainerDiagram) view rendered as a Mermaid flowchart.
It shows what lives inside the nl6 process, the host-side Linux infrastructure it depends on, and how operators and monitoring systems reach it.

```mermaid
%%{init: {'themeVariables': {'fontSize': '18px'}}}%%
flowchart LR
    operator(["Operator<br/><small>human</small>"]):::person
    nms(["NMS / Monitoring<br/><small>Prometheus, flow / trap /<br/>syslog / gNMI collectors</small>"]):::ext

    subgraph nl6 ["nl6 (Go process)"]
        simulator["<b>Simulator</b><br/><small>Go binary</small><br/>Device lifecycle,<br/>SNMP v1/v2c/v3, SSH, gNMI,<br/>NETCONF, HTTPS REST,<br/>metrics engine, exporters"]
        resources[("<b>Resources</b><br/><small>412 JSON files</small><br/>31 device-type directories + _common<br/>SNMP / SSH / REST fixtures")]
    end

    subgraph kernel ["Linux kernel (host)"]
        netns["<b>nl6sim netns</b><br/><small>network namespace</small><br/>Isolated routing,<br/>iptables FORWARD rule"]
        tun["<b>TUN interfaces</b><br/><small>Linux TUN</small><br/>Per-device IP,<br/>pre-allocated in parallel"]
    end

    operator -->|"CLI flags, REST API<br/><small>HTTP :8080</small>"| simulator
    simulator -->|loads on first use| resources
    simulator -->|creates, writes<br/><small>ioctl</small>| tun
    simulator -->|runs inside| netns
    nms -->|"polls devices<br/><small>SNMP / SSH / gNMI /<br/>NETCONF / HTTPS</small>"| tun
    simulator -->|"exports<br/><small>NetFlow, IPFIX, sFlow,<br/>traps, syslog, gNMI dial-out</small>"| nms

    classDef person fill:#08427b,stroke:#052e56,color:#fff
    classDef ext fill:#999,stroke:#666,color:#fff
    classDef default fill:#438dd5,stroke:#2e6da4,color:#fff
    class simulator,resources,netns,tun default
```

The namespace was `opensim` before the fork was renamed; see [Network namespace](../ops/network-namespace.md) for the one-time cleanup.

## Management surfaces

| | gNMI dial-in | gNMI dial-out | NETCONF | SSH CLI |
|---|---|---|---|---|
| **Model** | OpenConfig, plus native origins from a per-type catalogue | Same as dial-in | Cisco native `Cisco-IOS-XE-interfaces-oper` | None, CLI text |
| **Encoding** | `JSON_IETF`, `PROTO` | Same as dial-in | XML | Plain text |
| **Transport** | gRPC over TLS | gRPC over TLS | SSH `netconf` subsystem | SSH shell |
| **Port (default)** | `9339` | Collector's port | `830` | `22` |
| **Who connects** | Collector dials the device | Device dials the collector | Client dials the device | Client dials the device |
| **Auth** | Shared self-signed server cert, no client auth | Collector verified by `ca_pem`, optional mTLS | Device SSH login | Device SSH login |
| **Plaintext option** | `-gnmi-tls=false` | `tls.enabled=false` | Not available | Not available |
| **Devices** | All | Opt-in per device | `cisco_catalyst_9500` only | All |
| **Default** | On | Off | Off | On |
| **Writes** | No, `Set` is `Unimplemented` | No | No | No |

gNMI and NETCONF both carry YANG-modelled data, OpenConfig or a vendor's native model.
SSH appears twice because NETCONF reuses it as a transport: the same login and host key, a different subsystem, a different port.

### Scope

- **gNMI dial-in**: `Capabilities`, `Get` and `Subscribe` in SAMPLE, ON_CHANGE and ONCE mode over `/interfaces` and `/components`. `cisco_asr9902` and `juniper_mx10004` add a per-type catalogue with native origins. See [gNMI dial-in](../reference/gnmi.md).
- **gNMI dial-out**: the dial-in payload pushed to a collector over Arista `gnmireverse`, dropped on outage. See [gNMI dial-out](../reference/gnmi-dial-out.md).
- **NETCONF**: the IOS XE draft `establish-subscription` with `push-update` and `push-change-update` on interface state. No `get`, no `edit-config`, no RFC 8639. See [NETCONF](../reference/netconf.md).

## Package layout

| Path | Purpose |
|------|---------|
| `go/nl6/` | Core simulator, with all device simulation logic and tests. |
| `go/nl6/resources/` | Per-device-type JSON resource files (SNMP / SSH / REST) across 31 device-type directories, plus the shared trap, syslog and NBAR2 catalogs under `_common/`. |
| `go/nl6/worldcities/` | The `sysLocation` city dataset: 97 CSV shards plus `header.csv`, about 47,000 rows. |

The [`Makefile`](https://github.com/labmonkeys-space/nl6/blob/main/Makefile) is the canonical build entry point.

## Core simulator components

| Component | Responsibility | Files | Reference |
|-----------|----------------|-------|-----------|
| Device lifecycle | CLI entry, `SimulatorManager` with shared keys and certs, per-device startup and protocol server lifecycle | `simulator.go`, `manager.go`, `device.go` | |
| SNMP stack | Request handling, OID lookup via `sync.Map`, response building, ASN.1 BER/DER | `snmp_server.go`, `snmp.go`, `snmp_handlers.go`, `snmp_response.go`, `snmp_encoding.go` | [SNMP](../reference/snmp.md) |
| SNMPv3 | Message framing, DES / AES128 privacy, RFC 3414 USM key derivation, HMAC-MD5-96 / HMAC-SHA-96 and inbound verification, verified against net-snmp | `snmpv3.go`, `snmpv3_crypto.go`, `snmpv3_usm.go` | [SNMP](../reference/snmp.md) |
| Interface state | Link and admin state per ifIndex, flap scheduler, REST control, link traps and syslog | `interface_state.go`, `if_counters.go` | [Interface state](../reference/interface-state.md) |
| Metrics engine | 100-point pre-generated sine-wave patterns per device, per-GPU metrics, per-category baselines | `metrics_cycler.go`, `gpu_metrics.go`, `device_profiles.go` | [GPU simulation](../reference/gpu/index.md) |
| Network infrastructure | TUN interfaces, the `nl6sim` namespace, parallel pre-allocation (100 to 200 workers by default, sized by batch; `max_workers` overrides it, clamped to 500) | `tun.go`, `netns.go`, `prealloc.go` | [Network namespace](../ops/network-namespace.md) |
| Web API | The control plane: routes, handlers, Linux route script generation | `web.go`, `api.go`, `web_routes*.go` | [Web API](../reference/web-api.md) |
| Flow export | NetFlow v5 / v9, IPFIX, sFlow v5 encoders behind one `FlowEncoder` interface; a socket per collector and protocol, or per device under `-flow-source-per-device` (the default); one ticker goroutine | `flow_exporter.go`, `netflow5.go`, `netflow9.go`, `ipfix.go`, `sflow.go` | [Flow export](../reference/flow-export.md) |
| Trap export | Catalog-driven SNMP traps and informs, central Poisson scheduler with a global rate cap | `trap_*.go` | [SNMP traps](../reference/snmp-traps.md) |
| Syslog export | Catalog-driven RFC 5424 / 3164 messages over UDP, TCP or TLS, same scheduler shape as traps | `syslog_*.go` | [Syslog export](../reference/syslog-export.md) |
| gNMI dial-in | Path resolver, `Capabilities` / `Get` / `Subscribe` handlers, per-stream ticker with a bounded send buffer, per-device gRPC listener | `gnmi_paths.go`, `gnmi_handlers.go`, `gnmi_subscribe.go`, `gnmi_server.go`, `gnmi_manager.go` | [gNMI dial-in](../reference/gnmi.md) |
| gNMI dial-out | Per-device gRPC client: one `ClientConn` and one `Publish` stream, reconnect with backoff, the same payload as dial-in with `Prefix.Target` set to the device IP | `gnmi_dialout_*.go` | [gNMI dial-out](../reference/gnmi-dial-out.md) |
| NETCONF | Per-device SSH `netconf` subsystem on `cisco_catalyst_9500`, IOS XE draft subscriptions pushed from the interface state engine | `netconf_*.go` | [NETCONF](../reference/netconf.md) |
| LLDP topology | Inter-device link graph and the dynamic LLDP-MIB provider | `topology.go`, `lldp_table.go` | [LLDP topology](../reference/lldp-topology.md) |
| DNS service discovery | Hidden-primary zone over the live device map for a CoreDNS secondary | `dns_*.go` | [DNS service discovery](../reference/dns-service-discovery.md) |
| Resource loading | Loads and caches a device type the first time a device of that type is created; only the auto-start default, `asr9k`, loads at startup | `resources.go` | [Resource files](../reference/resource-files.md) |

Counter values for SNMP, gNMI and sFlow come from one dispatcher, `IfCounterCycler.GetDynamicAt`, so every protocol reports the same number at the same instant.

## Key design decisions

| Choice | Gained | Given up |
|--------|--------|----------|
| `sync.Map` for OID lookups | Lock-free O(1) reads under concurrent SNMP load | Simple iteration; walks need the pre-computed next-OID map |
| Pre-computed next-OID mappings | `GETNEXT` and `WALK` without scanning the table | Memory per loaded device type |
| Buffer pool on the SNMP path | Less GC pressure at high request rates | Every handler path must return its buffer to the pool |
| Shared SSH and TLS keys across all devices | No per-device key generation, so 30,000 devices start in minutes | Every device presents the same host key and certificate; nl6 does not model PKI |
| Analytic IF-MIB counters | Every `ifTable` and `ifXTable` counter is computed on demand from a per-direction sine wave, with no polling loop | Traffic shapes other than the sine wave. See [SNMP](../reference/snmp.md#dynamic-if-mib-counters) |
| Network namespace isolation | The `nl6sim` namespace keeps systemd-networkd off the TUN interfaces | Linux only, and root is required |
| Per-device flow egress | A `FORWARD -i veth-sim-host -j ACCEPT` rule lets per-device exporters send out of the namespace on Docker hosts that default `FORWARD` to `DROP` | An iptables dependency in the image; the rule is removed in `NetNamespace.Close` |

## Container image

The simulator is published as `ghcr.io/labmonkeys-space/nl6`.
[`ci.yml`](https://github.com/labmonkeys-space/nl6/blob/main/.github/workflows/ci.yml) publishes on push to `main`; [`release.yml`](https://github.com/labmonkeys-space/nl6/blob/main/.github/workflows/release.yml) publishes on a release tag.
See [Docker](../getting-started/docker.md) to run it.
