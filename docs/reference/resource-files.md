# Resource files

Every device type has a directory under `go/nl6/resources/` containing
one or more JSON files. At startup, `resources.go` loads and caches every
`*.json` file in each directory, merging the `snmp`, `ssh`, and (optionally)
`api` sections. There are currently 379 JSON files across 28 device-type
directories.

OIDs in the `snmp` section may be written with or without a leading dot —
the loader normalises them to the net-snmp convention (`.1.3.6.1…`) at
startup.

## JSON schema

Each file is a JSON object with up to three top-level keys:

```json
{
  "snmp": [
    {
      "oid": ".1.3.6.1.2.1.1.1.0",
      "response": "Cisco IOS Software, Router Version 15.1"
    }
  ],
  "ssh": [
    {
      "command": "show version",
      "response": "Cisco IOS Software, Router Version 15.1\nDevice Simulator v1.0"
    }
  ],
  "api": [
    {
      "method": "GET",
      "path": "/api/v1/system",
      "status": 200,
      "response": "{\"name\": \"device-01\", \"status\": \"healthy\"}"
    }
  ]
}
```

The `api` section is optional and used primarily for storage device
simulation — see [Device types → Storage systems](device-types.md#storage-systems).

## Directory layout

Each device type directory is split by concern so the files stay small and
reviewable. The loader is directory-based: any `*.json` file inside is
merged, so split files however you like.

A typical naming convention:

```
go/nl6/resources/asr9k/
├── asr9k_snmp_system.json         # MIB-II system group
├── asr9k_snmp_interfaces.json     # IF-MIB / IF-MIB-HC
├── asr9k_snmp_entity.json         # Entity MIB
├── asr9k_snmp_vendor.json         # vendor-specific OIDs
├── asr9k_ssh.json                 # SSH command/response
└── asr9k_api.json                 # (storage devices only)
```

Browse [`go/nl6/resources/asr9k/`](https://github.com/labmonkeys-space/nl6/tree/main/go/nl6/resources/asr9k)
for a representative example.

## Round-robin and category selection

The REST API's [`/api/v1/devices`](web-api.md#create-devices) endpoint
supports `round_robin: true` (spread device creation across every
registered resource file) and `category: "<name>"` (restrict to a single
category — e.g. `"GPU Servers"`). The catalog of categories and per-category
device lists lives in [Device types](device-types.md).

## Dynamic values

Not every OID is static. The following are computed at query time regardless
of what the resource files contain:

- **CPU, memory, temperature** — cycle through a 100-point sine-wave pattern
  per device. See [SNMP reference → Dynamic metrics](snmp.md#dynamic-cpu--memory--temperature-metrics).
- **Dynamic IF-MIB counters** — every per-interface counter in `ifTable`
  and `ifXTable` (octets, HC packets, Counter32 shadows, errors, discards)
  is computed analytically from the octet sine wave, phase-offset per
  interface. See [SNMP reference → Dynamic IF-MIB counters](snmp.md#dynamic-if-mib-counters).
- **Interface state** — `ifAdminStatus` / `ifOperStatus` depend on
  [`-if-scenario`](cli-flags.md#interface-state-scenarios).
- **GPU metrics** — per-GPU utilization, VRAM, temp, power, fan, clocks.
  See [GPU simulation](gpu/index.md).
