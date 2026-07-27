# Device types

nl6 ships resource files for **29 device types across 9 categories**.
Each device type has its own directory under `go/nl6/resources/`
containing JSON responses for SNMP OIDs, SSH commands, and (for storage
devices) REST API endpoints. See [Resource files](resource-files.md) for the
JSON format.

## Core routers

| Device | Ports | Description |
|--------|-------|-------------|
| Cisco ASR9K | 48 | High-end service provider router |
| Cisco CRS-X | 144 | Carrier-class router |
| Huawei NE8000 | 96 | Carrier-class router |
| Nokia 7750 SR-12 | 72 | IP/MPLS service router |
| Juniper MX960 | 96 | Service provider edge router |

## Edge routers

| Device | Ports | Description |
|--------|-------|-------------|
| Juniper MX240 | 24 | Compact modular router |
| NEC IX3315 | 48 | Enterprise router |
| Cisco IOS | 4 | Standard IOS router |

## Data center switches

| Device | Ports | Description |
|--------|-------|-------------|
| Cisco Nexus 9500 | 48 | Data center spine switch |
| Arista 7280R3 | 32 | High-performance switch |

## Campus switches

| Device | Ports | Description |
|--------|-------|-------------|
| Cisco Catalyst 9500 | 48 | Enterprise core switch |
| Extreme VSP4450 | 48 | Campus switch |
| D-Link DGS-3630 | 52 | L3 managed switch |

## Firewalls

| Device | Ports | Description |
|--------|-------|-------------|
| Palo Alto PA-3220 | 12 | Next-gen firewall |
| Fortinet FortiGate-600E | 20 | Enterprise firewall |
| SonicWall NSa 6700 | 16 | Next-gen firewall |
| Check Point 15600 | 24 | Security gateway |

## Servers

| Device | Ports | Description |
|--------|-------|-------------|
| Dell PowerEdge R750 | 4 | Server BMC/iDRAC |
| HPE ProLiant DL380 | 4 | Server iLO interface |
| IBM Power S922 | 4 | Power Systems server |
| Linux Server | — | Ubuntu 24.04 LTS (SNMP, SSH) |

## GPU servers

| Device | GPUs | VRAM/GPU | Description |
|--------|------|----------|-------------|
| NVIDIA DGX-A100 | 8 | 80 GB | A100 GPU training system |
| NVIDIA DGX-H100 | 8 | 80 GB | H100 GPU training system |
| NVIDIA HGX-H200 | 8 | 141 GB | H200 GPU inference system |

See [GPU simulation](gpu/index.md) for the DCGM OID layout, per-GPU metric
cycling, and the pollaris / parser integration.

## Storage systems

| Device | Type | Protocols |
|--------|------|-----------|
| AWS S3 Storage | Object storage | SNMP, SSH, HTTPS REST |
| Pure Storage FlashArray | All-flash array | SNMP, SSH, HTTPS REST |
| NetApp ONTAP | Unified storage | SNMP, SSH, HTTPS REST |
| Dell EMC Unity | Unified storage | SNMP, SSH, HTTPS REST |

Storage devices expose their management API over HTTPS on port 8443 using a
set of shared TLS certificates generated at startup. See [Web API](web-api.md)
for the simulator's own control-plane endpoints; the storage APIs themselves
are defined entirely by the JSON resource files in each storage device's
directory.

## Optical transport

| Device | Channels | Protocols |
|--------|----------|-----------|
| Ciena Waveserver 5 | 2 × WaveLogic 5 Extreme | SNMP, SSH |

A coherent DWDM transport platform rather than a packet device. Its
per-channel discovery key is the optical-channel (OCH) **component name**
(`OCH-1-1`), carried in an `optical` resource part — not an `ifIndex`, since
an optical channel is not an interface.

Being a layer-1 transport platform it performs no layer-3/4 inspection, so it
**exports no flow records** (NetFlow / IPFIX / sFlow). A batch-level flow seed
skips it with a log line; an explicit per-device `flow` block naming this type
is rejected with HTTP 400.

Optical state is served over gNMI under
`/components/component[name=$och]/optical-channel/`. See
[Optical telemetry](optical-telemetry.md) for the served paths, the health
bands, the on-demand degradation endpoint and a per-use-case validation
walkthrough, and the
[limitations doc](https://github.com/labmonkeys-space/nl6/blob/main/go/nl6/resources/ciena_waveserver5_limitations.md)
for where the simulation stops.

## Enhanced features (all network devices)

- **Entity MIB alignment** — ifTable and Entity MIB rows are consistent across
  chassis, line cards, power supplies, fans, and temperature sensors.
- **`entAliasMappingTable`** — physical-to-logical port mappings.
- **Dynamic metrics** — CPU, memory, and temperature cycle through a 100-point
  sine-wave pattern per device. See [Architecture](architecture.md).
- **Dynamic HC interface counters** — `ifHCInOctets` / `ifHCOutOctets` are
  computed on-demand as monotonically increasing Counter64 values, with
  per-interface phase offsets. See [SNMP reference](snmp.md).
- **GPU metrics via NVIDIA DCGM OIDs** — per-GPU utilization, VRAM,
  temperature, power, fan, and clocks. See [GPU simulation](gpu/index.md).
- **SNMPv3 support** — engine ID, MD5/SHA1 auth, DES/AES128 privacy. See
  [SNMP reference](snmp.md).
- **Per-category baselines** — CPU / memory / temperature ranges and spike
  amplitudes are driven by per-category device profiles.
- **Interface stats and operational status**, **system information**,
  **vendor-specific OIDs**, **CDP & LLDP**, and **OSPF / BGP / VRF** via SSH.

## World cities for `sysLocation`

Device `sysLocation` values are drawn from a bundled 98-city dataset so large
fleets have plausible geographic spread. The dataset ships under
`go/nl6/resources/worldcities/`.

Each entry's **latitude/longitude** are retained from the dataset and exposed
per device via `GET /api/v1/devices` (`location` / `latitude` / `longitude`) —
see the [web API reference](web-api.md). The `sysLocation` string itself is
unchanged; coordinates are an additive surface on the control-plane API.
