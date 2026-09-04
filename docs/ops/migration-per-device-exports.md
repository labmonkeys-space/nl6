# Migration: per-device export config

The per-device-export-config change (phases 3 + 4 + 5) rewrote how
flow, trap, and syslog export are configured and how their status
endpoints respond. This page covers the operator-facing migration.

## What changed

Before the change, each subsystem had a **single simulator-wide**
collector / protocol / mode / format. The `-X-collector` CLI flag was
both the "enable" switch and the sole target. `GET /api/v1/X/status`
returned scalar fields describing that one collector.

After the change:

- **Each device owns its own export configuration.** The
  `DeviceFlowConfig` / `DeviceTrapConfig` / `DeviceSyslogConfig` block
  is attached to the device at creation time — either seeded from the
  CLI flags (for `-auto-start-ip` devices) or explicitly in the
  `POST /api/v1/devices` request body.
- **The CLI flags are now seeds for the auto-start batch only.**
  REST-created devices do not inherit them; they opt in via the
  request body.
- **The subsystems are always-on.** `StartTrapSubsystem` /
  `StartSyslogSubsystem` / the flow ticker run from `main()` regardless
  of whether any device has configured export. Enabling export is now
  a per-device decision.
- **`GET /api/v1/{flows,traps,syslog}/status` is an array-of-collectors.**
  One record per `(collector, protocol)` / `(collector, mode)` /
  `(collector, format)` tuple, aggregated across devices. Counters are
  monotonic within a subsystem lifecycle.

See the [CLI flags reference](../reference/cli-flags.md) for the full
per-flag Scope taxonomy and the [Web API reference](../reference/web-api.md)
for the request/response schemas.

## Migrating your invocations

### Case 1: auto-start batch with a single export target

**Before — and after.** The CLI-seed form is unchanged for operators
who only used `-auto-start-ip` + one collector:

```bash
# Still works, still produces the same wire behaviour
sudo ./nl6 \
  -auto-start-ip 10.0.0.1 -auto-count 100 \
  -flow-collector 192.168.1.10:2055 \
  -trap-collector 192.168.1.10:162 \
  -syslog-collector 192.168.1.10:514
```

The only change visible here is the **status-endpoint response
shape** — see Case 4 below.

### Case 2: REST-created devices that previously inherited the CLI seed

**Before:** the simulator was started with a CLI flag, and
`POST /api/v1/devices` created devices that silently inherited the
CLI-wide collector.

```bash
# Before: CLI seed implicitly applied to REST-created devices
sudo ./nl6 -syslog-collector 192.168.1.10:514

curl -X POST http://localhost:8080/api/v1/devices \
  -d '{"start_ip":"10.0.0.50", "device_count":1}'
# ← this device used to inherit -syslog-collector. It no longer does.
```

**After:** REST-created devices must opt in via the request body.

```bash
sudo ./nl6   # no CLI export flags

curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.0.50",
    "device_count": 1,
    "syslog": {"collector": "192.168.1.10:514", "format": "5424"}
  }'
```

This is a **breaking change** for any deployment that relied on the
implicit inheritance. If your orchestration creates devices via REST
after booting with export CLI flags, you need to add the corresponding
`flow` / `traps` / `syslog` blocks to the request body.

### Case 3: heterogeneous fleet (multiple collectors or protocols)

**Before:** impossible — the simulator supported only one collector
per subsystem per process.

**After:** natural. Issue one `POST /api/v1/devices` per collector /
protocol / mode / format combination. `/api/v1/X/status` reports each
tuple as its own record.

See [Web API → Heterogeneous fleet](../reference/web-api.md#create-devices)
for a worked example.

### Case 4: status-endpoint consumers

**Before — flow status:**

```json
{
  "success": true,
  "data": {
    "enabled": true,
    "protocol": "ipfix",
    "collector": "192.168.1.10:4739",
    "total_packets_sent": 91215,
    "total_bytes_sent":  136823040,
    "devices_exporting": 100
  }
}
```

**After — flow status:**

```json
{
  "success": true,
  "data": {
    "subsystem_active": true,
    "collectors": [
      {"collector": "192.168.1.10:4739", "protocol": "ipfix", "devices": 100, "sent_packets": 91215, "sent_bytes": 136823040, "sent_records": 2436900}
    ],
    "devices_exporting": 100,
    "last_template_send": "2026-04-23T10:35:00Z"
  }
}
```

**Trap / syslog status** are symmetric — both retired their scalar
fields (`enabled`, `mode`, `collector`, `community`, `sent`,
`informs_*`, `format`, `send_failures`) in favour of the
array-of-collectors form with a top-level `subsystem_active` bool.

**Dashboard / CI / probe migration:**

- Replace `enabled == true` with `subsystem_active == true`.
- Replace scalar `collector` / `protocol` / `mode` / `format` with
  `collectors[i].collector` + its protocol/mode/format companion.
- Replace scalar counters (`sent`, `total_*`, `send_failures`,
  `informs_*`) with their per-record counterparts under
  `collectors[i]`. If you want a simulator-wide total, sum across
  `collectors[]`.
- `informs_pending` / `informs_acked` / `informs_failed` /
  `informs_dropped` now appear **only on records whose `mode == inform`**.
  TRAP-mode records omit them.

## Go API migration

Programmatic callers of the manager (tests, embedded-use cases):

- `StartTrapExport(TrapConfig)` → `StartTrapSubsystem(TrapSubsystemConfig)` +
  per-device `DeviceTrapConfig`.
- `StartSyslogExport(SyslogConfig)` → `StartSyslogSubsystem(SyslogSubsystemConfig)` +
  per-device `DeviceSyslogConfig`.
- **Stop-side naming is asymmetric**: `StopTrapExport` / `StopSyslogExport`
  kept their names. There is NO `StopTrapSubsystem` / `StopSyslogSubsystem`
  symbol — a grep for that won't find anything. The asymmetry is
  intentional (Stop retains its pre-phase-4 scope: tear down the scheduler
  and close every exporter).
- The retired `TrapConfig` / `SyslogConfig` types bundled subsystem +
  per-device settings. The new `*SubsystemConfig` types hold only
  catalog path, global cap, per-device-source flag, and the
  scheduler's mean interval. Everything else moves to the per-device
  config attached via `ExportSeed` (auto-start path) or
  `POST /api/v1/devices` (REST path).
- `sm.trapActive` / `sm.syslogActive` atomic bools are retired — a
  device participates if its own `trapConfig` / `syslogConfig` is
  non-nil. Check the subsystem itself via
  `sm.GetTrapStatus().SubsystemActive` /
  `sm.GetSyslogStatus().SubsystemActive`.

## Known constraints carried into this change

- **`Stop*Export` is process-shutdown-only.** The subsystems are not
  safe to restart at runtime — attach paths capture scheduler pointers
  outside the main lock, so a concurrent Stop can orphan exporters.
  Phase-5 review D1 deferred the lock-discipline tightening; don't
  introduce a REST "restart subsystem" endpoint without addressing it
  first.
- **Per-device `tick_interval` / `interval` are validated but not
  honored by the scheduler today.** A single warning is logged per
  subsystem lifecycle if any attached device's value differs from the
  simulator-wide mean. Design debt tracked against phases 3-5.

## References

- [CLI flags reference](../reference/cli-flags.md) — per-flag scope taxonomy.
- [Web API reference](../reference/web-api.md) — per-device block schemas and status shapes.
- [Flow export reference](../reference/flow-export.md) — protocol-level details.
- [SNMP trap reference](../reference/snmp-traps.md) — TRAP / INFORM wire format and catalog.
- [Syslog export reference](../reference/syslog-export.md) — RFC 5424 / 3164 wire format and catalog.
