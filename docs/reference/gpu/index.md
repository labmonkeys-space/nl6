# GPU simulation

nl6 simulates NVIDIA DGX and HGX GPU servers — complete with NVIDIA
DCGM OIDs, `nvidia-smi` SSH output, and DCGM-shaped REST endpoints. This
section consolidates the GPU-specific design notes originally kept under
`plans/`.

## Pages

- **[DCGM simulation](dcgm.md)** — the simulator-side plan: new metric OID
  types, the GPU cycler extension, device profiles, resource file layout,
  and integration points. This describes how the simulator produces the
  data the other two pages consume.
- **[Protobuf model](proto-model.md)** — the `GpuDevice` protobuf schema
  in `probler/proto/inventory.proto`: top-level entity, host system
  resources, individual GPUs, NVLink / NVSwitch topology, and health.
- **[Pollaris and parsing rules](pollaris.mdx)** — the l8parser pollaris
  definitions and parsing rules that collect SNMP, SSH, and REST data from
  the simulator and populate the `GpuDevice` model. Part 1 covers the
  foundational SNMP polls; Part 2 covers SSH / REST and the gap closure to
  full coverage.

## Supported GPU servers

| Device | GPUs | VRAM/GPU | System RAM |
|--------|------|----------|------------|
| NVIDIA DGX-A100 | 8 | 80 GB | 1 TB |
| NVIDIA DGX-H100 | 8 | 80 GB | 2 TB |
| NVIDIA HGX-H200 | 8 | 141 GB | 2 TB |

See [Device types → GPU servers](../device-types.md#gpu-servers) for where
these sit in the broader device catalogue.

## Design-note provenance

Every page in this section was originally authored as a design plan under
the repository's `plans/` directory. The `plans/` directory has been
retired — the pages here are the current reference. History is preserved
via `git mv`; run `git log --follow docs/reference/gpu/<page>.md` to see
the full history including the original `plans/` entries.
