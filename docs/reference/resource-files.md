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

## Load-time validation

The `response` of an entry in the `snmp` array must not be exactly `noSuchObject` or `endOfMibView`.
Those two strings are the internal sentinels for the RFC 3416 exceptions, so a value equal to one of them would go on the wire as an exception rather than as a string.
A file containing one is rejected when it is loaded, with the file, the OID and the value named in the error.

The match is exact, so `noSuchObject seen` and `NoSuchObject` are ordinary data.
There is no escaping form.
If you actually want an OID to answer `noSuchObject`, omit the entry: an absent OID already answers with that exception.

The rule covers the `snmp` array only.
`ssh`, `api` and `optical` entries are not checked, because they never reach the SNMP encoder.

Where the rejection surfaces matters:

- Resource files are also loaded on REST device creation, so a bad file is a failed API call (HTTP 500, carrying the same error text) in the middle of a run, not only a refusal at startup.
- In a device-type directory each JSON part is validated separately, so the error names the part that is wrong rather than the directory.
- Two call sites downgrade the rejection to a log line instead of failing: the startup load falls back to the `cisco_ios` profile, and round-robin device creation skips the offending device type.

This is the only rule on `snmp` values enforced at load, and it covers resource files only.
The `optical` part of an optical transport type has its own load-time check, which fails the load when the OCH inventory is missing, malformed, or disagrees with the type's channel count.
`sysName` and `sysLocation` are served from elsewhere (`sysLocation` from the worldcities CSV) and are not checked.
A malformed OID, a non-OID value on `sysObjectID` (tracked as nl6#529), and a non-numeric `Counter32`/`Gauge32`/`TimeTicks` or unparseable `ipAdEntAddr` value are all still accepted, and degrade silently when served.
See [SNMP reference → A resource value that collides with a sentinel is rejected at load](snmp.md#a-resource-value-that-collides-with-a-sentinel-is-rejected-at-load).

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
