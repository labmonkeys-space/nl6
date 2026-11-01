---
sidebar_label: "DCGM simulation"
description: "The SNMP OIDs, metric value behaviour, SSH commands and REST paths that the three simulated NVIDIA GPU server profiles serve."
---

# NVIDIA DCGM simulation

nl6 simulates three NVIDIA GPU servers with eight GPUs each: `nvidia_dgx_a100`, `nvidia_dgx_h100` and `nvidia_hgx_h200`.
The metric vocabulary and the `nvidia-smi` and `dcgmi` output are modelled on NVIDIA Data Center GPU Manager (DCGM).
The server models, `sysObjectID` values and the collector OID contract are in [GPU simulation](index.md).

## SNMP

### The OID layout is nl6's own

`1.3.6.1.4.1.5703` is NVIDIA's IANA-registered PEN, so `sysObjectID` identifies a simulated DGX as an NVIDIA system.
Nothing below the PEN is published by NVIDIA.
NVIDIA ships no SNMP GPU MIB, and real DCGM exposes a Prometheus `/metrics` endpoint, not SNMP.
Treat the layout below as nl6's contract with its collectors, never as a vendor specification.
The arc used to sit under `1.3.6.1.4.1.53246`, which is no longer served; see [GPU simulation](index.md#collector-oid-contract).

No OID below `5703` has an explicit SNMP type.
A numeric value is encoded as INTEGER and any other value as OCTET STRING.

### Module objects

| OID | Name | Type | Value |
|-----|------|------|-------|
| `1.3.6.1.4.1.5703.1.1.1.0.1.0` | GPU count | INTEGER | `8` |
| `1.3.6.1.4.1.5703.1.1.1.0.2.0` | DCGM version | OCTET STRING | `3.1.8` (A100), `3.3.0` (H100), `3.4.1` (H200) |

### Per-GPU objects

Every per-GPU OID is `1.3.6.1.4.1.5703.1.1.1.1.<column>.<gpu>`, with `<gpu>` from `0` to `7`.

Static columns come from the `*_snmp_gpu.json` resource file and never change.

| Column | Name | Type | H100 example |
|--------|------|------|--------------|
| 1 | GPU name | OCTET STRING | `NVIDIA H100 80GB HBM3` |
| 2 | GPU UUID | OCTET STRING | `GPU-d4e8f2a1-7b3c-4d9e-a1f0-8c2d3e4f5a6b` |
| 3 | GPU serial | OCTET STRING | `1560833002DEF` |
| 4 | PCI bus ID | OCTET STRING | `00000000:07:00.0` |
| 13 | Driver version | OCTET STRING | `535.129.03` |
| 14 | CUDA version | OCTET STRING | `12.2` |
| 15 | ECC errors, corrected | INTEGER | `0` |
| 16 | ECC errors, uncorrected | INTEGER | `0` |
| 17 | NVLink active links | INTEGER | `18` (A100: `6`) |

Dynamic columns come from the metrics cycler.
Eight columns times eight GPUs gives 64 dynamic GPU OIDs per device.
With the three Host Resources OIDs under [Standard MIBs](#standard-mibs), each device serves 67 dynamic OIDs.

| Column | Name | Type and unit | Behaviour |
|--------|------|---------------|-----------|
| 5 | GPU utilization | INTEGER, percent | 0 to 100 |
| 6 | VRAM used | INTEGER, MiB | Follows utilization, 5 to 98 percent of VRAM total |
| 7 | VRAM total | INTEGER, MiB | Constant: `81920` (A100, H100), `144384` (H200) |
| 8 | Temperature | INTEGER, degrees Celsius | Rises with utilization, clamped to 25 to 95 |
| 9 | Power draw | INTEGER, watts | Follows utilization, clamped to the profile's power range |
| 10 | Fan speed | INTEGER, percent | `0` (liquid cooled) unless the GPU is above 70 °C, then 5 to 19 |
| 11 | SM clock | INTEGER, MHz | 60 to 100 percent of the base clock, higher under load |
| 12 | Memory clock | INTEGER, MHz | 70 to 100 percent of the base clock, higher under load |

### Value behaviour

Each GPU holds a pre-generated cycle of 100 points per metric, seeded per device and per GPU.
Every read of a dynamic column returns the next point, so the value moves per read, not per unit of time.
Two collectors polling the same OID share one cursor.
SM clock and memory clock share a cursor too, so a read of either advances both.
VRAM total is constant and never advances.

A GETNEXT can advance a cursor without returning its OID.
GETNEXT reads the first dynamic OID after the requested OID as a candidate, even when a static OID sorts first and is returned.
This happens on every GETNEXT and GETBULK step whose next static OID sorts after `hrStorageSize.1` and whose requested OID sorts before the last GPU metric OID.
A walk of the static GPU columns 1 to 4 is 32 GETNEXT steps, and each one reads GPU 0 utilization.
That column has moved 32 points by the time the walk returns it.
Do not expect a dynamic OID to move one step per poll when the collector also walks neighbouring columns.

The per-profile ranges the cycles are drawn from:

| Parameter | A100 | H100 | H200 |
|-----------|------|------|------|
| Utilization base, percent | 15 to 85 | 20 to 90 | 20 to 90 |
| Temperature base, °C | 35 to 75 | 35 to 80 | 35 to 78 |
| Power draw, W | 100 to 400 | 150 to 700 | 150 to 700 |
| SM base clock, MHz | 1410 | 1980 | 1980 |
| Memory base clock, MHz | 1512 | 2619 | 2619 |

### Standard MIBs

The profiles also serve `system`, the IF-MIB interface tables and Host Resources (`1.3.6.1.2.1.25`).
Interface counters come from the same engine as every other device type; see [SNMP](../snmp.md).

Three Host Resources OIDs are dynamic and come from the device's metrics cycler, not the static resource file.

| OID | Name | Behaviour |
|-----|------|-----------|
| `1.3.6.1.2.1.25.3.3.1.2.1` | `hrProcessorLoad.1` | Cycling CPU percent, advances on every read |
| `1.3.6.1.2.1.25.2.3.1.5.1` | `hrStorageSize.1` | Constant physical memory total from the device profile, never advances |
| `1.3.6.1.2.1.25.2.3.1.6.1` | `hrStorageUsed.1` | Cycling physical memory used, advances on every read |

The other Host Resources OIDs, including storage row 2, are static.

## SSH

Each profile answers exactly these fourteen commands, and nothing else.
The output is static text from the `*_ssh.json` resource file.
It does not track the SNMP metric values.

| Command | Output |
|---------|--------|
| `nvidia-smi` | GPU summary table for all eight GPUs, with processes |
| `nvidia-smi -q -d MEMORY` | Per-GPU memory detail |
| `nvidia-smi -q -d UTILIZATION` | Per-GPU utilization detail |
| `nvidia-smi -q -d TEMPERATURE` | Per-GPU temperature and thresholds |
| `nvidia-smi -q -d POWER` | Per-GPU power draw and limits |
| `nvidia-smi topo -m` | GPU topology matrix |
| `dcgmi discovery -l` | GPUs discovered by DCGM |
| `dcgmi health -c` | DCGM health check |
| `show version` | OS version with NVIDIA driver details |
| `uname -a` | Kernel details |
| `hostname` | Host name |
| `free -h` | System memory summary |
| `lscpu` | CPU details |
| `lspci \| grep -i nvidia` | NVIDIA PCI devices |

## REST

Each profile serves seven `GET` paths on the device's HTTPS API port (`8443` by default).
The bodies are static JSON from the `*_api.json` resource file and do not track the SNMP metric values.
There is no per-GPU path such as `/api/v1/gpu/devices/{id}`.
The top-level fields differ between profiles on every path except `/api/v1/gpu/devices`.

| Path | Profile | Top-level fields |
|------|---------|------------------|
| `/api/v1/gpu/status` | A100 | `gpu_count`, `driver_version`, `cuda_version`, `dcgm_version`, `overall_health`, `gpus` |
| `/api/v1/gpu/status` | H100, H200 | `gpu_count`, `driver_version`, `cuda_version`, `dcgm_version`, `gpus` |
| `/api/v1/gpu/devices` | All | `count`, `devices` |
| `/api/v1/gpu/topology` | A100 | `nvlink_version`, `nvswitch_count`, `gpu_count`, `connectivity`, `numa_affinity` |
| `/api/v1/gpu/topology` | H100, H200 | `gpu_count`, `nvlink_version`, `nvswitch_count`, `topology`, `links_per_gpu`, `bandwidth_per_link_gbps`, `total_bandwidth_per_gpu_gbps`, `connections` |
| `/api/v1/dcgm/health` | A100 | `overall_health`, `checks`, `last_check` |
| `/api/v1/dcgm/health` | H100, H200 | `overall_health`, `checks`, `gpu_health` |
| `/api/v1/dcgm/config` | A100 | `dcgm_version`, `monitoring_interval_ms`, `features`, `watched_fields` |
| `/api/v1/dcgm/config` | H100, H200 | `dcgm_version`, `monitoring_enabled`, `collection_interval_ms`, `health_check_interval_s`, `profiling_enabled`, `watched_fields` |
| `/api/v1/system/info` | A100 | `hostname`, `os`, `kernel`, `architecture`, `nvidia_driver`, `cuda_version`, `dcgm_version`, `dgx_software_version`, `cpu_model`, `cpu_sockets`, `cpu_cores_total`, `gpu_count`, `gpu_model`, `infiniband_ports`, `infiniband_speed_gbps` |
| `/api/v1/system/info` | H100 | `hostname`, `os`, `kernel`, `architecture`, `driver_version`, `cuda_version`, `dcgm_version`, `dgx_software_version`, `cpu`, `gpu`, `network` |
| `/api/v1/system/info` | H200 | `hostname`, `os`, `kernel`, `architecture`, `driver_version`, `cuda_version`, `dcgm_version`, `hgx_software_version`, `cpu`, `gpu`, `network` |
| `/api/v1/system/memory` | A100 | `system_memory`, `gpu_memory`, `swap` |
| `/api/v1/system/memory` | H100, H200 | `total_gb`, `used_gb`, `free_gb`, `shared_gb`, `buff_cache_gb`, `available_gb`, `swap_total_gb`, `swap_used_gb`, `swap_free_gb` |
