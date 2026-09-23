# GPU simulation

nl6 simulates NVIDIA DGX and HGX GPU servers with per-GPU SNMP metrics, `nvidia-smi` and `dcgmi` SSH output, and DCGM-shaped REST endpoints.
The SNMP OID layout under NVIDIA's PEN (`1.3.6.1.4.1.5703`) is defined by nl6.
NVIDIA publishes no SNMP GPU MIB; real DCGM exposes a Prometheus `/metrics` endpoint, not SNMP.
The metric vocabulary and the command output are modelled on DCGM.

## Pages

- **[DCGM simulation](dcgm.md)**: how the simulator produces the data: metric OID types, the GPU cycler extension, device profiles, resource file layout, SSH commands and REST paths.

## Supported GPU servers

| Device | Profile | GPUs | VRAM/GPU | System RAM | `sysObjectID` |
|--------|---------|------|----------|------------|---------------|
| NVIDIA DGX-A100 | `nvidia_dgx_a100` | 8 | 80 GB | 1 TB | `1.3.6.1.4.1.5703.1.2.1` |
| NVIDIA DGX-H100 | `nvidia_dgx_h100` | 8 | 80 GB | 2 TB | `1.3.6.1.4.1.5703.1.2.2` |
| NVIDIA HGX-H200 | `nvidia_hgx_h200` | 8 | 141 GB | 2 TB | `1.3.6.1.4.1.5703.1.2.3` |

See [Device types → GPU servers](../device-types.md#gpu-servers) for where these sit in the broader device catalogue.

## Collector OID contract

The OIDs a collector polls from a simulated GPU server.
Every object below the PEN is nl6's own definition and resolves against no vendor MIB.

Anchor vendor detection on the full dotted prefix `.1.3.6.1.4.1.5703.`, never on the bare digits: `5703` occurs inside `15703`, `45703` and inside instance identifiers, so a substring rule claims unrelated devices as NVIDIA GPU servers.

The arc used to sit under `1.3.6.1.4.1.53246`, a PEN IANA allocates to an unrelated company.
Every sub-identifier below the PEN is unchanged, so a rule written for the old arc needs only its prefix replaced.
A GET under the old arc answers `noSuchObject` (SNMPv2c/v3) or `error-status = noSuchName` (SNMPv1); nothing under it carries a value.

### Module-level

| OID | Object | Example |
|-----|--------|---------|
| `1.3.6.1.4.1.5703.1.1.1.0.1.0` | GPU count | `8` |
| `1.3.6.1.4.1.5703.1.1.1.0.2.0` | DCGM version | `3.3.0` |

### Per-GPU static objects

Pattern `1.3.6.1.4.1.5703.1.1.1.1.<X>.<gpu>`, with `<gpu>` from `0` to `7`. Values come from the resource file and do not change.

| X | Object | Example |
|---|--------|---------|
| 1 | GPU name | `NVIDIA H100 80GB HBM3` |
| 2 | GPU UUID | `GPU-a1b2c3d4-...` |
| 3 | GPU serial | `1234567890ABC` |
| 4 | PCI bus ID | `0000:07:00.0` |
| 13 | Driver version | `535.129.03` |
| 14 | CUDA version | `12.2` |
| 15 | ECC errors, corrected | `0` |
| 16 | ECC errors, uncorrected | `0` |
| 17 | NVLink active links | `18` |

### Per-GPU dynamic metrics

Same pattern, `<X>` from `5` to `12`. Values come from the metrics cycler and change every poll.
Eight metrics times eight GPUs is 64 dynamic OIDs per device.

| X | Metric | Unit |
|---|--------|------|
| 5 | GPU utilization | percent |
| 6 | VRAM used | MiB |
| 7 | VRAM total | MiB, constant |
| 8 | Temperature | degrees Celsius |
| 9 | Power draw | watts |
| 10 | Fan speed | percent |
| 11 | SM clock | MHz |
| 12 | Memory clock | MHz |

### Standard MIBs

The profiles also serve `system` (`1.3.6.1.2.1.1`), the IF-MIB interface tables (`1.3.6.1.2.1.2.2.1`, `1.3.6.1.2.1.31.1.1.1`) and Host Resources (`1.3.6.1.2.1.25`).
The interface counters are served by the same cycler as every other device type; see [SNMP → Dynamic IF-MIB counters](../snmp.md).

## Design-note provenance

Every page in this section was originally authored as a design plan under the repository's `plans/` directory.
Run `git log --follow docs/reference/gpu/dcgm.md` to see the full history including the original `plans/` entries.
The two plans for external repositories, the `probler` protobuf model and the `l8parser` polling rules, are retired; their nl6-facing content is the collector OID contract above.
