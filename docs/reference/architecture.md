# Architecture

nl6 is a single Go program that stands up thousands of simulated
devices inside a dedicated Linux network namespace. Each simulated device has
its own IP address on a TUN interface, its own SNMP listener, its own SSH
server, and — for storage devices — its own HTTPS REST endpoint.

This page covers the package layout, core components, and the key design
decisions that make the 30,000-device target tractable.

## System overview

The diagram below is laid out as a [C4 container](https://c4model.com/#ContainerDiagram)
view (rendered as a Mermaid flowchart): it shows what lives inside the
nl6 process boundary, the host-side Linux infrastructure it depends on,
and how operators and monitoring systems interact with it.

```mermaid
%%{init: {'themeVariables': {'fontSize': '18px'}}}%%
flowchart LR
    operator(["Operator<br/><small>human</small>"]):::person
    nms(["NMS / Monitoring<br/><small>OpenNMS, Prometheus,<br/>flow collectors</small>"]):::ext

    subgraph nl6 ["nl6 (Go process)"]
        simulator["<b>Simulator</b><br/><small>Go binary</small><br/>Device lifecycle,<br/>SNMP v2c/v3 + SSH + HTTPS REST,<br/>metrics engine, flow exporter"]
        resources[("<b>Resources</b><br/><small>379 JSON files</small><br/>28 device-type directories<br/>SNMP / SSH / REST fixtures")]
    end

    subgraph kernel ["Linux kernel (host)"]
        netns["<b>opensim netns</b><br/><small>network namespace</small><br/>Isolated routing,<br/>iptables FORWARD rule"]
        tun["<b>TUN interfaces</b><br/><small>Linux TUN</small><br/>Per-device IP,<br/>pre-allocated in parallel"]
    end

    operator -->|"CLI flags, REST API<br/><small>HTTP :8080</small>"| simulator
    simulator -->|loads on startup| resources
    simulator -->|creates, writes<br/><small>ioctl</small>| tun
    simulator -->|runs inside| netns
    nms -->|"polls devices<br/><small>SNMP / SSH / HTTPS</small>"| tun
    simulator -->|"exports flows<br/><small>NetFlow v5/v9,<br/>IPFIX, sFlow v5</small>"| nms

    classDef person fill:#08427b,stroke:#052e56,color:#fff
    classDef ext fill:#999,stroke:#666,color:#fff
    classDef default fill:#438dd5,stroke:#2e6da4,color:#fff
    class simulator,resources,netns,tun default
```

The `opensim` namespace name is an operational identifier kept stable across
the project rename so existing rescue tooling (e.g., scripts that grep
`ip netns list` for `opensim`) continues to work — see
[Network namespace](../ops/network-namespace.md).

## Package layout

| Path | Purpose |
|------|---------|
| `go/nl6/` | Core simulator — all device simulation logic and tests. |
| `go/nl6/resources/` | Per-device-type JSON resource files (SNMP / SSH / REST) across 28 device-type directories, plus the `worldcities/` datasets used for `sysLocation`. |

Top-level helper scripts: `diagnose_system.sh`, `ubuntu_setup.sh`,
`increase_file_limits.sh`. The [`Makefile`](https://github.com/labmonkeys-space/nl6/blob/main/Makefile)
is the canonical build entry point.

## Core simulator components (`go/nl6/`)

### Device lifecycle

`simulator.go` (CLI entry) → `manager.go` (`SimulatorManager`, shared keys /
certs) → `device.go` (per-device startup, protocol server lifecycle).

### SNMP stack

`snmp_server.go` → `snmp.go` (request handling) → `snmp_handlers.go` (OID
lookup via `sync.Map`) → `snmp_response.go` (response building) →
`snmp_encoding.go` (ASN.1 BER/DER). SNMPv3 is handled separately in
`snmpv3.go` + `snmpv3_crypto.go` (MD5 / SHA1 auth, DES / AES128 privacy).

### Metrics engine

`metrics_cycler.go` drives 100-point pre-generated sine-wave patterns per
device. `gpu_metrics.go` handles per-GPU metrics (utilization, VRAM,
temperature, power, clocks). `device_profiles.go` defines per-category
baselines.

### Network infrastructure

`tun.go` creates TUN interfaces, `netns.go` manages the `opensim` network
namespace, `prealloc.go` does parallel pre-allocation of TUN interfaces
(configurable worker count 100–200) for fast scaling. See
[Network namespace](../ops/network-namespace.md) for the namespace operator
guide.

### Web API

`web.go` (route setup) + `api.go` (handlers) + `web_routes*.go` (Linux route
script generation). Serves device CRUD, CSV export, system stats, and flow
export status (`GET /api/v1/flows/status`). See [Web API](web-api.md) for
the endpoint catalog.

### Flow export

`flow_exporter.go` (`FlowExporter`, `FlowEncoder` interface, `SimulatorManager`
integration) + `netflow5.go` / `netflow9.go` / `ipfix.go` / `sflow.go`.
One shared UDP socket and ticker goroutine; per-device `FlowExporter` owns
a `FlowCache`. See [Flow export reference](flow-export.md).

### gNMI target

`gnmi_paths.go` (path resolver), `gnmi_handlers.go` (Capabilities / Get /
Subscribe / Set), `gnmi_subscribe.go` (per-stream ticker + bounded send
buffer), `gnmi_server.go` (per-device gRPC + TLS listener lifecycle),
`gnmi_manager.go` (subsystem config + status). Counter values come from the
same `IfCounterCycler.GetDynamicAt` dispatcher that drives SNMP and sFlow,
so all three protocols agree byte-for-byte at the same instant. Read-only;
`Set` returns `Unimplemented`. See [gNMI target reference](gnmi.md).

### Resource loading

`resources.go` loads and caches the 379 JSON files at startup. Each device
type directory has split JSON files for SNMP, SSH, and REST responses that
are merged at load time. See [Resource files](resource-files.md).

## Key design decisions

- **`sync.Map` for OID lookups** — lock-free O(1) access during concurrent
  SNMP queries.
- **Pre-computed next-OID mappings** — efficient SNMP `GETNEXT` / `WALK`
  without scanning the table.
- **Buffer pool** — reduces GC pressure on SNMP request handling.
- **Shared SSH / TLS keys** across all devices — avoids per-device key
  generation overhead.
- **Analytic IF-MIB counters** — every per-interface counter in `ifTable`
  and `ifXTable` computed on demand from a single per-direction octet
  sine wave, instead of maintained by a polling loop; see
  [SNMP reference](snmp.md#dynamic-if-mib-counters).
- **Network namespace isolation** — the `opensim` namespace prevents
  systemd-networkd interference on many Linux distros.
- **Per-device flow egress** — a `FORWARD -i veth-sim-host -j ACCEPT`
  iptables rule lets per-device flow exporters send UDP out of the
  namespace through the host's routing table (Docker-present hosts default
  `FORWARD` to `DROP`). The rule is removed in `NetNamespace.Close`.

## Container image

The simulator is published as `ghcr.io/labmonkeys-space/nl6` on
push to `main` and on release tags — see the project's CI workflow
files.
