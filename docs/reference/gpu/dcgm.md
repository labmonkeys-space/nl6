# NVIDIA DCGM simulation

:::note[Simulator side of the GPU story]
This page covers the **simulator** — the metric OID types, the GPU
cycler extension, device profiles, resource file layout, and
integration points. Pair it with [Protobuf model](proto-model.md) (the
shape of the output data) and [Pollaris and parsing rules](pollaris.mdx)
(the collector side).
:::

## Overview

nl6 simulates NVIDIA Data Center GPU Manager (DCGM) servers. Each
simulated device represents a GPU server (e.g. DGX A100, DGX H100, HGX
H200) with multiple GPUs. The simulation exposes GPU metrics via all three
existing protocols: SNMP (enterprise MIB OIDs), SSH (`nvidia-smi` CLI), and
REST API (DCGM HTTP endpoints).

## What DCGM Exposes in the Real World

NVIDIA DCGM provides:
- **GPU utilization** (compute and memory controller %)
- **GPU memory** (used/total VRAM per GPU)
- **GPU temperature** (current, shutdown threshold, slowdown threshold)
- **Power draw** (current watts, power limit)
- **Fan speed** (% of max)
- **GPU clock speeds** (SM clock, memory clock in MHz)
- **PCIe throughput** (TX/RX MB/s)
- **ECC error counts** (single-bit corrected, double-bit uncorrected)
- **NVLink bandwidth** (active links, throughput)
- **GPU health status** (healthy, warning, critical)
- **Process/job info** (running PIDs, memory per process)

These are accessible via:
1. **SNMP**: OIDs under `1.3.6.1.4.1.5703`, NVIDIA Corporation's IANA-registered Private Enterprise Number
2. **SSH**: `nvidia-smi` command variants (e.g., `nvidia-smi`, `nvidia-smi -q`, `nvidia-smi dmon`, `dcgmi diag`, `dcgmi health`)
3. **REST API**: DCGM exporter HTTP endpoints (`/api/v1/gpu/status`, `/api/v1/gpu/{id}/metrics`, etc.)

:::warning[The objects below the PEN are nl6's own invention]

`1.3.6.1.4.1.5703` is NVIDIA Corporation's real PEN, so `sysObjectID` correctly identifies a simulated DGX as an NVIDIA system.
Nothing *below* the PEN is published by NVIDIA.
**NVIDIA ships no SNMP GPU MIB at all.**
Its own GPU telemetry story is DCGM and Prometheus, not SNMP.
So `1.3.6.1.4.1.5703.1.1.1.*` names no registered object and cannot be resolved against a real MIB.
Treat the layout as nl6's own contract with its collectors, never as a vendor specification.

**Migration (nl6#576).** This arc used to be `1.3.6.1.4.1.53246`, which the IANA enterprise-numbers registry allocates to Mailteck, S.A., a company unrelated to NVIDIA.
A collector doing vendor detection resolved a simulated DGX as Mailteck.
Every sub-identifier below the PEN was preserved exactly, so a downstream pollaris rule, `oid_base`, or vendor-detection prefix needs only `53246` replaced with `5703`.
No object was added, removed, or renumbered, and no OID's value or type changed.

Two things did change, and both are the point of the exercise rather than side effects.
Every OID **name** under the arc moved.
So did the three per-model `sysObjectID` **values**, from `…53246.1.2.{1,2,3}` to `…5703.1.2.{1,2,3}`, which is the string a collector reads to identify the vendor.
The suffixes stayed distinct and in the same order, so the three models are still told apart.

The old arc is no longer served at all.
An SNMPv2c or v3 GET under `1.3.6.1.4.1.53246` answers the RFC 3416 `noSuchObject` exception.
An SNMPv1 manager gets `error-status = noSuchName` with the requested names echoed instead, since v1 has no exceptions (RFC 3584 §4.2.2.2.1).
Either way the response carries no value, so an unmigrated rule collects nothing rather than collecting stale data.

:::

## Scope

### Device Flavors (3 resource profiles)

| Resource File | GPU Model | GPUs | VRAM/GPU | Total VRAM | System RAM |
|---|---|---|---|---|---|
| `nvidia_dgx_a100.json` | A100 80GB SXM | 8 | 80 GB | 640 GB | 1 TB |
| `nvidia_dgx_h100.json` | H100 80GB SXM | 8 | 80 GB | 640 GB | 2 TB |
| `nvidia_hgx_h200.json` | H200 141GB SXM | 8 | 141 GB | 1128 GB | 2 TB |

Each flavor gets its own resource directory under `resources/` with SNMP, SSH, and API JSON data.

### GPU-Specific Metric Types (new)

Extend `MetricsCycler` to generate cycling values for GPU metrics alongside existing CPU/memory/temperature metrics.

---

## Phase 1: GPU Metric Types and Cycler Extension

### 1.1 New Metric OID Types (`metrics_oids.go`)

Add new `MetricOIDType` constants:

```go
MetricGPUUtil       MetricOIDType = iota + 10  // GPU compute utilization %
MetricGPUMemUsed                                // GPU memory used (MB)
MetricGPUMemTotal                               // GPU memory total (MB, constant)
MetricGPUMemUtil                                // GPU memory utilization %
MetricGPUTemp                                   // GPU temperature (Celsius)
MetricGPUPower                                  // GPU power draw (Watts)
MetricGPUFanSpeed                               // GPU fan speed %
MetricGPUClockSM                                // GPU SM clock (MHz)
MetricGPUClockMem                               // GPU memory clock (MHz)
```

Add `vendorOIDs` entries for each NVIDIA resource file, using NVIDIA's enterprise OID prefix `1.3.6.1.4.1.5703`. Each GPU (0-7) gets its own OID suffix. Example for GPU 0:

```
1.3.6.1.4.1.5703.1.1.1.1.5.0  → MetricGPUUtil       (GPU 0 utilization)
1.3.6.1.4.1.5703.1.1.1.1.6.0  → MetricGPUMemUsed    (GPU 0 memory used)
1.3.6.1.4.1.5703.1.1.1.1.7.0  → MetricGPUMemTotal   (GPU 0 memory total)
1.3.6.1.4.1.5703.1.1.1.1.8.0  → MetricGPUTemp       (GPU 0 temperature)
1.3.6.1.4.1.5703.1.1.1.1.9.0  → MetricGPUPower      (GPU 0 power draw)
1.3.6.1.4.1.5703.1.1.1.1.10.0 → MetricGPUFanSpeed   (GPU 0 fan speed)
...
1.3.6.1.4.1.5703.1.1.1.1.5.7  → MetricGPUUtil       (GPU 7 utilization)
```

That's 6 metric OIDs × 8 GPUs = 48 dynamic metric OIDs per device, plus the existing CPU/memory/temperature host metrics.

### 1.2 GPU Device Profile (`device_profiles.go`)

Add three new profiles:

```go
var profileGPUServerA100 = DeviceProfile{
    CPUBaseMin: 20, CPUBaseMax: 55, CPUSpike: 25,
    MemTotalKB: 1024 * 1024 * 1024,  // 1 TB system RAM
    MemBaseMin: 40, MemBaseMax: 75, MemVariance: 12,
    TempBaseMin: 32, TempBaseMax: 48, TempSpike: 6,
}

var profileGPUServerH100 = DeviceProfile{
    CPUBaseMin: 25, CPUBaseMax: 60, CPUSpike: 28,
    MemTotalKB: 2 * 1024 * 1024 * 1024,  // 2 TB system RAM
    MemBaseMin: 45, MemBaseMax: 80, MemVariance: 12,
    TempBaseMin: 34, TempBaseMax: 50, TempSpike: 7,
}

var profileGPUServerH200 = DeviceProfile{
    CPUBaseMin: 25, CPUBaseMax: 60, CPUSpike: 28,
    MemTotalKB: 2 * 1024 * 1024 * 1024,  // 2 TB system RAM
    MemBaseMin: 45, MemBaseMax: 80, MemVariance: 12,
    TempBaseMin: 34, TempBaseMax: 50, TempSpike: 7,
}
```

Add to `deviceProfileMap`:
```go
"nvidia_dgx_a100.json": profileGPUServerA100,
"nvidia_dgx_h100.json": profileGPUServerH100,
"nvidia_hgx_h200.json": profileGPUServerH200,
```

### 1.3 GPU Metrics in MetricsCycler (`metrics_cycler.go`)

Add a new `GPUMetrics` struct with per-GPU cycling arrays:

```go
type GPUMetrics struct {
    gpuUtil     [numDataPoints]int    // GPU utilization % (0-100)
    gpuMemUsed  [numDataPoints]int64  // GPU memory used (MB)
    gpuMemTotal int64                 // GPU VRAM total (MB, constant)
    gpuTemp     [numDataPoints]int    // GPU temperature (Celsius)
    gpuPower    [numDataPoints]int    // GPU power draw (Watts)
    gpuFanSpeed [numDataPoints]int    // GPU fan speed % (0-100)
    gpuClockSM  [numDataPoints]int    // SM clock MHz
    gpuClockMem [numDataPoints]int    // Memory clock MHz
    utilIndex   uint32
    memIndex    uint32
    tempIndex   uint32
    powerIndex  uint32
    fanIndex    uint32
    clockIndex  uint32
}
```

Add `gpuMetrics [8]*GPUMetrics` field to `MetricsCycler`. These are only allocated when the device profile is a GPU server (checked by resource file name).

Each GPU gets its own seed (`baseSeed + gpuIndex`) so GPUs within the same server have different but correlated curves (e.g., GPU 0 might run hotter when GPU 1 is under heavy compute load).

**GPU-specific profile parameters** (new struct):

```go
type GPUProfile struct {
    GPUCount       int   // Number of GPUs (8 for DGX/HGX)
    VRAMPerGPUMB   int64 // VRAM per GPU in MB
    GPUUtilMin     int   // Min GPU utilization %
    GPUUtilMax     int   // Max GPU utilization %
    GPUUtilSpike   int   // Utilization spike amplitude
    GPUTempMin     int   // Min GPU temp (Celsius)
    GPUTempMax     int   // Max GPU temp (Celsius)
    GPUTempSpike   int   // Temp spike amplitude
    GPUPowerMin    int   // Min power draw (Watts)
    GPUPowerMax    int   // Max power draw (Watts)
    GPUPowerSpike  int   // Power spike amplitude
    GPUClockSMBase int   // Base SM clock (MHz)
    GPUClockMemBase int  // Base memory clock (MHz)
}
```

| Parameter | A100 | H100 | H200 |
|---|---|---|---|
| VRAMPerGPUMB | 81920 | 81920 | 144384 |
| GPUUtilMin/Max | 15-85 | 20-90 | 20-90 |
| GPUTempMin/Max | 35-75 | 35-80 | 35-78 |
| GPUPowerMin/Max | 100-400 | 150-700 | 150-700 |
| GPUClockSMBase | 1410 | 1980 | 1980 |
| GPUClockMemBase | 1512 | 2619 | 2619 |

### 1.4 Getter Methods for GPU Metrics

Add methods to `MetricsCycler`:

```go
func (c *MetricsCycler) GetGPUUtil(gpuIndex int) string
func (c *MetricsCycler) GetGPUMemUsed(gpuIndex int) string
func (c *MetricsCycler) GetGPUMemTotal(gpuIndex int) string
func (c *MetricsCycler) GetGPUMemUtil(gpuIndex int) string
func (c *MetricsCycler) GetGPUTemp(gpuIndex int) string
func (c *MetricsCycler) GetGPUPower(gpuIndex int) string
func (c *MetricsCycler) GetGPUFanSpeed(gpuIndex int) string
func (c *MetricsCycler) GetGPUClockSM(gpuIndex int) string
func (c *MetricsCycler) GetGPUClockMem(gpuIndex int) string
```

### 1.5 SNMP Handler Extension (`snmp_handlers.go`)

Update `getMetricValue()` to handle the new GPU metric types. The OID encodes the GPU index in the last component (e.g., `.0` for GPU 0, `.7` for GPU 7), so the handler must extract the GPU index from the OID suffix and call the appropriate getter.

Add a helper to parse GPU index from OID:
```go
func parseGPUIndexFromOID(oid string) int {
    // Last component of OID is the GPU index
    parts := strings.Split(oid, ".")
    idx, _ := strconv.Atoi(parts[len(parts)-1])
    return idx
}
```

### Files Modified
- `metrics_oids.go` — new metric types + NVIDIA vendor OID mappings
- `device_profiles.go` — 3 new profiles + GPUProfile struct + profile map entries
- `metrics_cycler.go` — GPUMetrics struct, GPU data point generation, getter methods
- `snmp_handlers.go` — GPU metric cases in `getMetricValue()`

---

## Phase 2: SNMP Resource Files

### 2.1 Directory Structure

```
resources/
├── nvidia_dgx_a100/
│   ├── nvidia_dgx_a100_snmp_system.json    # sysDescr, sysObjectID, sysUpTime, sysContact, interfaces
│   ├── nvidia_dgx_a100_snmp_host.json      # Host Resources MIB (hrStorage, hrProcessor, hrDevice)
│   ├── nvidia_dgx_a100_snmp_gpu.json       # NVIDIA enterprise GPU MIB OIDs (static baselines)
│   ├── nvidia_dgx_a100_ssh.json            # SSH command/response pairs
│   └── nvidia_dgx_a100_api.json            # REST API endpoint responses
├── nvidia_dgx_h100/
│   ├── nvidia_dgx_h100_snmp_system.json
│   ├── nvidia_dgx_h100_snmp_host.json
│   ├── nvidia_dgx_h100_snmp_gpu.json
│   ├── nvidia_dgx_h100_ssh.json
│   └── nvidia_dgx_h100_api.json
└── nvidia_hgx_h200/
    ├── nvidia_hgx_h200_snmp_system.json
    ├── nvidia_hgx_h200_snmp_host.json
    ├── nvidia_hgx_h200_snmp_gpu.json
    ├── nvidia_hgx_h200_ssh.json
    └── nvidia_hgx_h200_api.json
```

### 2.2 SNMP System MIB (per flavor)

Standard MIB-II system group OIDs with GPU-server-appropriate values:

| OID | Description | Example (DGX H100) |
|---|---|---|
| `1.3.6.1.2.1.1.1.0` | sysDescr | `NVIDIA DGX H100 - DCGM 3.3.0, Driver 535.129.03, CUDA 12.2` |
| `1.3.6.1.2.1.1.2.0` | sysObjectID | `1.3.6.1.4.1.5703.1.2.2` |
| `1.3.6.1.2.1.1.3.0` | sysUpTime | `234567800` |
| `1.3.6.1.2.1.1.4.0` | sysContact | `GPU Infrastructure Team` |
| `1.3.6.1.2.1.1.7.0` | sysServices | `72` |

Plus IF-MIB interfaces (management NIC, InfiniBand/RoCE ports), Host Resources MIB entries (CPU, memory, storage).

### 2.3 SNMP GPU objects (nl6's own layout under NVIDIA's PEN)

Static OIDs under `1.3.6.1.4.1.5703` for per-GPU identity info.
These object definitions are nl6's, not NVIDIA's: see the note at the top of this page.

| OID Pattern | Description | Example |
|---|---|---|
| `.1.1.1.1.1.{gpu}` | GPU name | `NVIDIA H100 80GB HBM3` |
| `.1.1.1.1.2.{gpu}` | GPU UUID | `GPU-a1b2c3d4-...` |
| `.1.1.1.1.3.{gpu}` | GPU serial | `1234567890ABC` |
| `.1.1.1.1.4.{gpu}` | GPU PCI bus ID | `0000:07:00.0` |
| `.1.1.1.1.13.{gpu}` | Driver version | `535.129.03` |
| `.1.1.1.1.14.{gpu}` | CUDA version | `12.2` |
| `.1.1.1.1.15.{gpu}` | ECC errors (corrected) | `0` |
| `.1.1.1.1.16.{gpu}` | ECC errors (uncorrected) | `0` |
| `.1.1.1.1.17.{gpu}` | NVLink active links | `12` |

Dynamic OIDs (cycling via MetricsCycler) are listed in Phase 1.1 above.

### Files Created
- `resources/nvidia_dgx_a100/nvidia_dgx_a100_snmp_system.json`
- `resources/nvidia_dgx_a100/nvidia_dgx_a100_snmp_host.json`
- `resources/nvidia_dgx_a100/nvidia_dgx_a100_snmp_gpu.json`
- `resources/nvidia_dgx_h100/nvidia_dgx_h100_snmp_system.json`
- `resources/nvidia_dgx_h100/nvidia_dgx_h100_snmp_host.json`
- `resources/nvidia_dgx_h100/nvidia_dgx_h100_snmp_gpu.json`
- `resources/nvidia_hgx_h200/nvidia_hgx_h200_snmp_system.json`
- `resources/nvidia_hgx_h200/nvidia_hgx_h200_snmp_host.json`
- `resources/nvidia_hgx_h200/nvidia_hgx_h200_snmp_gpu.json`

---

## Phase 3: SSH Resources (`nvidia-smi` and `dcgmi` CLI)

### 3.1 Supported Commands

Each flavor's SSH resource file provides responses for these commands:

| Command | Description |
|---|---|
| `nvidia-smi` | Default GPU summary table (all 8 GPUs, utilization, memory, temp, power) |
| `nvidia-smi -q` | Detailed query (full GPU specs, clocks, ECC, power, thermals per GPU) |
| `nvidia-smi -q -d MEMORY` | Memory details (used/free/total per GPU) |
| `nvidia-smi -q -d UTILIZATION` | Utilization details (GPU%, memory controller%, encoder%, decoder%) |
| `nvidia-smi -q -d TEMPERATURE` | Temperature details (current, shutdown, slowdown thresholds) |
| `nvidia-smi -q -d POWER` | Power details (draw, limit, default limit, min/max limits) |
| `nvidia-smi -q -d CLOCK` | Clock details (current, max, SM, memory, video clocks) |
| `nvidia-smi -q -d ECC` | ECC error counts |
| `nvidia-smi topo -m` | GPU topology matrix (NVLink connections) |
| `nvidia-smi nvlink -s` | NVLink status |
| `dcgmi discovery -l` | DCGM discovered GPUs |
| `dcgmi diag -r 1` | DCGM quick diagnostic (level 1) |
| `dcgmi health -c` | DCGM health check |
| `dcgmi stats -e` | DCGM stats enable |
| `show version` | Linux OS version with NVIDIA driver info |
| `uname -a` | Linux kernel info |
| `lspci \| grep -i nvidia` | PCI device listing for GPUs |
| `cat /proc/driver/nvidia/version` | NVIDIA kernel module version |
| `free -h` | System memory summary |
| `lscpu` | CPU info (AMD EPYC / Intel Xeon for DGX) |
| `ip addr` | Network interfaces (management, InfiniBand) |
| `ibstat` | InfiniBand HCA status |
| `hostname` | Hostname |

### 3.2 Example `nvidia-smi` Output (H100)

```
Fri Mar 14 12:00:00 2026
+-----------------------------------------------------------------------------------------+
| NVIDIA-SMI 535.129.03   Driver Version: 535.129.03   CUDA Version: 12.2                 |
|-----------------------------------------+------------------------+----------------------+
| GPU  Name                  Persistence-M | Bus-Id          Disp.A | Volatile Uncorr. ECC |
| Fan  Temp   Perf          Pwr:Usage/Cap  |           Memory-Usage | GPU-Util  Compute M. |
|=========================================+========================+======================|
|   0  NVIDIA H100 80GB HBM3          On  | 00000000:07:00.0   Off |                    0 |
| N/A   42C    P0             320W / 700W  |   45312MiB / 81920MiB  |     67%      Default |
|-----------------------------------------+------------------------+----------------------|
|   1  NVIDIA H100 80GB HBM3          On  | 00000000:0B:00.0   Off |                    0 |
| N/A   39C    P0             285W / 700W  |   38400MiB / 81920MiB  |     54%      Default |
...  (GPUs 2-7)
+-----------------------------------------------------------------------------------------+
| Processes:                                                                              |
|  GPU   GI   CI        PID   Type   Process name                              GPU Memory |
|        ID   ID                                                               Usage       |
|=========================================================================================|
|    0   N/A  N/A     12345      C   python3                                     44800MiB |
|    1   N/A  N/A     12346      C   python3                                     37888MiB |
...
+-----------------------------------------------------------------------------------------+
```

### Files Created
- `resources/nvidia_dgx_a100/nvidia_dgx_a100_ssh.json`
- `resources/nvidia_dgx_h100/nvidia_dgx_h100_ssh.json`
- `resources/nvidia_hgx_h200/nvidia_hgx_h200_ssh.json`

---

## Phase 4: REST API Resources (DCGM HTTP Endpoints)

### 4.1 API Endpoints

Each device exposes a REST API on its `APIPort` with these endpoints:

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/gpu/status` | Overall GPU cluster health and summary |
| `GET` | `/api/v1/gpu/devices` | List of all GPUs with IDs, names, UUIDs |
| `GET` | `/api/v1/gpu/devices/{id}` | Single GPU detailed info |
| `GET` | `/api/v1/gpu/devices/{id}/metrics` | GPU metrics (util, memory, temp, power, clocks) |
| `GET` | `/api/v1/gpu/topology` | NVLink/NVSwitch topology |
| `GET` | `/api/v1/gpu/processes` | Running GPU processes |
| `GET` | `/api/v1/dcgm/health` | DCGM health check results |
| `GET` | `/api/v1/dcgm/diag` | DCGM diagnostic results |
| `GET` | `/api/v1/dcgm/config` | DCGM configuration |
| `GET` | `/api/v1/system/info` | System info (OS, driver, CUDA, hostname) |
| `GET` | `/api/v1/system/memory` | System memory stats |
| `GET` | `/api/v1/system/network` | Network interface info |

### 4.2 Example Response: `/api/v1/gpu/status`

```json
{
  "status": "healthy",
  "gpu_count": 8,
  "driver_version": "535.129.03",
  "cuda_version": "12.2",
  "dcgm_version": "3.3.0",
  "gpus": [
    {
      "index": 0,
      "name": "NVIDIA H100 80GB HBM3",
      "uuid": "GPU-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "pci_bus_id": "00000000:07:00.0",
      "temperature_gpu": 42,
      "utilization_gpu": 67,
      "utilization_memory": 55,
      "memory_used_mib": 45312,
      "memory_total_mib": 81920,
      "power_draw_w": 320,
      "power_limit_w": 700,
      "fan_speed_pct": 0,
      "sm_clock_mhz": 1980,
      "mem_clock_mhz": 2619,
      "ecc_errors_corrected": 0,
      "ecc_errors_uncorrected": 0,
      "health": "healthy"
    }
  ]
}
```

### 4.3 Example Response: `/api/v1/gpu/topology`

```json
{
  "gpu_count": 8,
  "nvlink_version": 4,
  "nvswitch_count": 4,
  "topology_matrix": [
    { "gpu": 0, "connections": [
      { "peer_gpu": 1, "type": "NVLink", "bandwidth_gbps": 900 },
      { "peer_gpu": 2, "type": "NVLink", "bandwidth_gbps": 900 },
      ...
    ]},
    ...
  ]
}
```

### Files Created
- `resources/nvidia_dgx_a100/nvidia_dgx_a100_api.json`
- `resources/nvidia_dgx_h100/nvidia_dgx_h100_api.json`
- `resources/nvidia_hgx_h200/nvidia_hgx_h200_api.json`

---

## Phase 5: Integration with Simulator Framework

### 5.1 Resource Loading (`resources.go`)

**No changes needed** — the existing directory-based loading and merging already handles new resource directories automatically. The `loadSpecificResourcesFromDir()` function will pick up all JSON files in each NVIDIA directory and merge SNMP + SSH + API resources.

### 5.2 Device Type Detection (`resources.go`)

Add NVIDIA detection to `getDeviceTypeFromName()`:

```go
} else if strings.Contains(nameLower, "nvidia") || strings.Contains(nameLower, "dgx") || strings.Contains(nameLower, "hgx") {
    return "NVIDIA GPU Server"
}
```

### 5.3 Round-Robin Registration (`types.go`)

Add the 3 NVIDIA resource files to `RoundRobinDeviceTypes`:

```go
var RoundRobinDeviceTypes = []string{
    // ... existing 19 types ...
    "nvidia_dgx_a100.json",
    "nvidia_dgx_h100.json",
    "nvidia_hgx_h200.json",
}
```

This brings the total to 22 device types in round-robin mode.

### 5.4 API Resource Merging (`resources.go`)

Update `loadResourcesFromDir()` and `loadSpecificResourcesFromDir()` to also merge API resources (currently only merges SNMP and SSH):

```go
resources.API = append(resources.API, partResources.API...)
```

Initialize the API slice:
```go
resources := &DeviceResources{
    SNMP: make([]SNMPResource, 0),
    SSH:  make([]SSHResource, 0),
    API:  make([]APIResource, 0),  // Add this
}
```

### Files Modified
- `resources.go` — NVIDIA device type detection + API merging in directory loader
- `types.go` — 3 new entries in `RoundRobinDeviceTypes`

---

## Phase 6: Build and Verify

1. `cd go && go build ./nl6/` — verify compilation
2. `cd go && go vet ./nl6/` — verify no issues
3. Start the simulator and create a single NVIDIA DGX H100 device
4. Verify SNMP walk returns GPU OIDs with cycling values
5. Verify SSH `nvidia-smi` returns formatted output
6. Verify REST API `/api/v1/gpu/status` returns GPU data
7. Create devices in round-robin mode — verify NVIDIA types appear among the 22 types
8. Verify web UI shows "NVIDIA GPU Server" as device type

---

## File Change Summary

### New Files (15 resource JSON files)

```
resources/nvidia_dgx_a100/
    nvidia_dgx_a100_snmp_system.json
    nvidia_dgx_a100_snmp_host.json
    nvidia_dgx_a100_snmp_gpu.json
    nvidia_dgx_a100_ssh.json
    nvidia_dgx_a100_api.json

resources/nvidia_dgx_h100/
    nvidia_dgx_h100_snmp_system.json
    nvidia_dgx_h100_snmp_host.json
    nvidia_dgx_h100_snmp_gpu.json
    nvidia_dgx_h100_ssh.json
    nvidia_dgx_h100_api.json

resources/nvidia_hgx_h200/
    nvidia_hgx_h200_snmp_system.json
    nvidia_hgx_h200_snmp_host.json
    nvidia_hgx_h200_snmp_gpu.json
    nvidia_hgx_h200_ssh.json
    nvidia_hgx_h200_api.json
```

### Modified Files (6 Go files)

| File | Changes |
|---|---|
| `metrics_oids.go` | 9 new MetricOIDType constants + 3 NVIDIA vendor OID map entries (48 OIDs each) |
| `device_profiles.go` | GPUProfile struct + 3 GPU device profiles + profile map entries |
| `metrics_cycler.go` | GPUMetrics struct + GPU data generation in NewMetricsCycler + 9 GPU getter methods |
| `snmp_handlers.go` | GPU metric cases in getMetricValue() + parseGPUIndexFromOID helper |
| `resources.go` | NVIDIA device type detection + API merging in directory loaders |
| `types.go` | 3 new entries in RoundRobinDeviceTypes |

### No Changes Required

| File | Why |
|---|---|
| `device.go` | MetricsCycler already initialized per device; GPU init keyed on resource file |
| `manager.go` | Resource caching and device lifecycle unchanged |
| `snmp_server.go` | Protocol handling unchanged |
| `snmp_encoding.go` | Encoding unchanged |
| `ssh.go` | Command matching unchanged |
| `api.go` | API server already handles arbitrary endpoints from resource files |
| `web.go` | Web UI device listing works with new device types automatically |
| `web_routes.go` | Routes unchanged |
| `web/index.html` | Device type dropdown auto-populated from resources |
| `web/app_ui.js` | Renders device_type from API response automatically |
| `web/app_api.js` | API client unchanged |
