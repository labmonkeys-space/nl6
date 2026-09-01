# GPU protobuf model

:::note[Source of truth]
The authoritative definition lives in
`probler/proto/inventory.proto`. This page is the reference write-up
originally authored as a design plan and kept here so the navigation
flow (simulator → pollaris → model) is complete.
:::

## Overview

A `GpuDevice` protobuf model in `probler/proto/inventory.proto` represents
GPU server devices (NVIDIA DGX / HGX) at the same level as `NetworkDevice`.
The model captures the GPU-specific hierarchy: a host system containing
multiple GPUs, each with their own utilization, memory, thermal, power, and
clock metrics — plus host-level CPU, memory, storage, and network
interfaces.

## Design Principles

- Follow the same structural patterns as `NetworkDevice` (top-level entity with `id`, nested physical/logical containers, time-series metrics via `l8api.L8TimeSeriesPoint`)
- GPU-specific components (individual GPUs, NVLinks, NVSwitches) are embedded child types — not separate services
- Host-level components (CPU, memory, storage, NICs) reuse existing messages where possible (`Cpu`, `Memory`, `Fan`, `PowerSupply`, `PerformanceMetrics`)
- Dynamic metrics use `repeated l8api.L8TimeSeriesPoint` for time-series data, matching the existing pattern

## Data Source Mapping

The opensim GPU simulator exposes data via three protocols. This model must represent all of it:

| Source | Data | Model Location |
|--------|------|----------------|
| SNMP OID `5703.1.1.1.1.5-12.{gpu}` | Per-GPU utilization, memory, temp, power, fan, clocks | `Gpu` message fields |
| SNMP Host Resources MIB | Host CPU, system memory, storage | `GpuDeviceSystem` fields |
| SSH commands (`nvidia-smi`, `dcgm-diag`) | GPU details, topology, health | `Gpu`, `GpuTopology`, `GpuHealthCheck` |
| REST API (`/api/v1/gpu/*`) | GPU inventory, metrics, health | All fields |

`5703` is NVIDIA Corporation's IANA-registered Private Enterprise Number.
It used to be `53246`, which IANA allocates to an unrelated company.
nl6#576 re-homed the arc and preserved every sub-identifier below the PEN.
See [GPU pollaris and parsing rules](./pollaris.mdx) for the migration note.

## Protobuf Messages

### Top-Level Entity

```protobuf
message GpuDeviceList {
  repeated GpuDevice list = 1;
  l8api.L8MetaData metadata = 2;
}

message GpuDevice {
  string id = 1;
  GpuDeviceInfo device_info = 2;
  GpuDeviceSystem system = 3;
  repeated Gpu gpus = 4;
  GpuTopology topology = 5;
  GpuDeviceHealth health = 6;
}
```

### Device Info (static identification — analogous to `EquipmentInfo`)

```protobuf
message GpuDeviceInfo {
  string hostname = 1;
  string vendor = 2;             // "NVIDIA"
  string model = 3;              // "DGX A100", "DGX H100", "HGX H200"
  string serial_number = 4;
  string ip_address = 5;
  string location = 6;
  double latitude = 7;
  double longitude = 8;
  string os_version = 9;         // "Ubuntu 22.04.3 LTS"
  string kernel_version = 10;    // "5.15.0-91-generic"
  string driver_version = 11;    // "525.105.17"
  string cuda_version = 12;      // "12.0"
  string dcgm_version = 13;      // "3.1.8"
  DeviceStatus device_status = 14;
  string last_seen = 15;
  string uptime = 16;
  uint32 gpu_count = 17;
}
```

### Host System Resources

```protobuf
message GpuDeviceSystem {
  // Host CPU
  string cpu_model = 1;                // "AMD EPYC 7742 64-Core Processor"
  uint32 cpu_sockets = 2;
  uint32 cpu_cores_total = 3;
  repeated l8api.L8TimeSeriesPoint cpu_utilization_percent = 4;

  // Host Memory
  uint64 memory_total_bytes = 5;       // e.g. 1 TB
  repeated l8api.L8TimeSeriesPoint memory_used_bytes = 6;
  repeated l8api.L8TimeSeriesPoint memory_free_bytes = 7;

  // Storage
  string storage_description = 8;      // "NVMe SSD 15.36 TB"
  uint64 storage_total_bytes = 9;
  repeated l8api.L8TimeSeriesPoint storage_used_bytes = 10;

  // Network Interfaces
  repeated GpuNetworkInterface network_interfaces = 11;

  // Power Supplies & Fans (reuse existing messages)
  repeated PowerSupply power_supplies = 12;
  repeated Fan fans = 13;
}

message GpuNetworkInterface {
  string name = 1;               // "mgmt0", "ib0"
  string interface_type = 2;     // "Ethernet", "InfiniBand"
  uint64 speed_bps = 3;          // 10Gbps, 200Gbps
  string status = 4;             // "up", "down"
  string mac_address = 5;
  string ip_address = 6;
  repeated l8api.L8TimeSeriesPoint bytes_in = 7;
  repeated l8api.L8TimeSeriesPoint bytes_out = 8;
}
```

### Individual GPU

```protobuf
message Gpu {
  uint32 gpu_index = 1;                // 0-7
  string device_uuid = 2;              // "GPU-a1b2c3d4-..."
  string device_name = 3;              // "NVIDIA A100-SXM4-80GB"
  string pci_bus_id = 4;               // "00000000:07:00.0"
  string serial_number = 5;
  string compute_capability = 6;       // "8.0"
  bool persistence_mode = 7;
  uint32 numa_node = 8;

  // VRAM
  uint64 vram_total_mib = 9;           // 81920 for A100
  repeated l8api.L8TimeSeriesPoint vram_used_mib = 10;

  // Utilization
  repeated l8api.L8TimeSeriesPoint gpu_utilization_percent = 11;
  repeated l8api.L8TimeSeriesPoint memory_utilization_percent = 12;
  repeated l8api.L8TimeSeriesPoint encoder_utilization_percent = 13;
  repeated l8api.L8TimeSeriesPoint decoder_utilization_percent = 14;

  // Thermal
  repeated l8api.L8TimeSeriesPoint temperature_celsius = 15;
  repeated l8api.L8TimeSeriesPoint memory_temperature_celsius = 16;
  uint32 shutdown_temperature = 17;     // Max temp before shutdown
  uint32 slowdown_temperature = 18;     // Max temp before throttling

  // Power
  uint32 power_limit_watts = 19;
  repeated l8api.L8TimeSeriesPoint power_draw_watts = 20;

  // Fan
  repeated l8api.L8TimeSeriesPoint fan_speed_percent = 21;

  // Clocks
  uint32 sm_clock_base_mhz = 22;
  uint32 mem_clock_base_mhz = 23;
  repeated l8api.L8TimeSeriesPoint sm_clock_mhz = 24;
  repeated l8api.L8TimeSeriesPoint mem_clock_mhz = 25;

  // ECC Errors
  uint64 ecc_corrected_count = 26;
  uint64 ecc_uncorrected_count = 27;

  // Health
  GpuComponentHealth health = 28;

  // Running Processes
  repeated GpuProcess processes = 29;
}

message GpuProcess {
  uint32 pid = 1;
  string name = 2;
  uint64 used_memory_mib = 3;
  string type = 4;               // "C" (compute), "G" (graphics)
}
```

### Topology (NVLink/NVSwitch interconnects)

```protobuf
message GpuTopology {
  uint32 nvlink_version = 1;            // 3 for A100, 4 for H100/H200
  uint32 nvswitch_count = 2;            // 6 for DGX A100
  repeated GpuLink gpu_links = 3;
}

message GpuLink {
  uint32 gpu_src = 1;
  uint32 gpu_dst = 2;
  string link_type = 3;                 // "NV12", "NV18"
  uint32 nvlink_count = 4;              // 12 for A100, 18 for H100
  string status = 5;                    // "healthy", "degraded"
}
```

### Health

```protobuf
message GpuDeviceHealth {
  GpuHealthStatus overall_status = 1;
  repeated GpuHealthCheck checks = 2;
}

message GpuHealthCheck {
  string check_name = 1;               // "pcie", "memory", "thermal", "power", "nvlink", "inforom"
  GpuHealthStatus status = 2;
  string detail = 3;
}

message GpuComponentHealth {
  GpuHealthStatus pcie_status = 1;
  GpuHealthStatus memory_status = 2;
  GpuHealthStatus thermal_status = 3;
  GpuHealthStatus power_status = 4;
  GpuHealthStatus nvlink_status = 5;
  GpuHealthStatus inforom_status = 6;
}
```

### New Enums

```protobuf
enum GpuHealthStatus {
  GPU_HEALTH_UNKNOWN = 0;
  GPU_HEALTH_HEALTHY = 1;
  GPU_HEALTH_WARNING = 2;
  GPU_HEALTH_CRITICAL = 3;
}
```

### Existing Enums to Extend

Add `DEVICE_TYPE_GPU_SERVER = 9;` to the existing `DeviceType` enum.

## Implementation Phases

### Phase 1: Add proto messages and enum
- Add all messages listed above to `probler/proto/inventory.proto`
- Add `DEVICE_TYPE_GPU_SERVER = 9` to `DeviceType` enum
- Run `make-bindings.sh` to regenerate Go types
- Verify build: `go build ./...`

### Phase 2: Verify generated types
- Confirm `.pb.go` files contain all new types with correct JSON field names
- Verify no naming conflicts with existing messages

## Notes

- `PowerSupply`, `Fan`, `DeviceStatus` are reused from the existing inventory.proto — no duplication
- `l8api.L8TimeSeriesPoint` is already imported — all dynamic metrics use time-series arrays matching the `NetworkDevice` pattern
- `GpuNetworkInterface` is a separate message (not reusing `Interface`) because GPU server NICs are simpler and don't need BGP/OSPF/MPLS/QoS/TE fields
- The `Gpu` message with its `processes` field is an embedded child type (not a prime object) — GPUs don't have independent lifecycles outside their host device
