<!--
Copyright 2026 Ronny Trommer <ronny@no42.org>
SPDX-License-Identifier: Apache-2.0
-->

# Load-test scenario report schema

The report is the machine-readable output of a finalized scenario — the
authoritative record of what nl6 **sent**, which an operator diffs against a
monitor's **received** counts to localize missed or duplicated telemetry. It
is built once at stop/abort, immutable thereafter, and served by
`GET /api/v1/scenarios/{id}/report` (also returned by `stop`). See the
[API reference](./loadtest-api.md) and the [runbook](./loadtest-runbook.md).

## Shape

```json
{
  "summary": {
    "id": "s-000001",
    "phase": "stopped",
    "protocol": "syslog",
    "config_sha256": "9b8d8c9c…969314",
    "seed": 42,
    "nl6_version": "v0.16.0",
    "t0": "2026-07-18T09:00:05.000Z",
    "t1": "2026-07-18T09:00:07.000Z",
    "duration": "2s",
    "participants_armed": 2,
    "participants_excluded": 1,
    "emitted": 40, "in_window": 40, "drain": 0,
    "suppressed_pre_window": 0, "send_failures": 0, "dropped": 0,
    "informational": {"background_suppressed": 0},
    "excluded": [
      {"device": "10.42.0.9", "reason": "device not found",
       "remediation_hint": "create the device before arming, or remove it from the scenario"}
    ]
  },
  "counters": [
    {"protocol": "syslog", "source_ip": "10.42.0.1", "collector": "10.0.0.9:514",
     "emitted": 20, "in_window": 20, "drain": 0,
     "suppressed_pre_window": 0, "send_failures": 0, "dropped": 0,
     "informational": {"background_suppressed": 0}}
  ]
}
```

The top-level `summary` block always serializes **before** `counters` so a
streaming consumer sees the aggregate first.

## `summary`

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | Scenario ID (`s-000001`). |
| `phase` | string | Terminal phase: `stopped` (window elapsed / explicit stop) or `aborted` (graceful shutdown). |
| `protocol` | string | Participating protocol (MVP `syslog`). |
| `config_sha256` | string | SHA-256 over the canonicalized submit config. With `seed` + `nl6_version`, the reproducibility fingerprint. |
| `seed` | number | The seed that pinned every random draw. |
| `nl6_version` | string | Simulator version that produced the report. |
| `t0` | RFC3339-ms | Actual window open (emission start). |
| `t1` | RFC3339-ms | Actual window close — the planned `T1` for a full run, or the abort instant for an early abort (never later than the planned `T1`). |
| `duration` | string | `t1 − t0` as a Go duration, from the monotonic clock — the window that actually ran. |
| `participants_armed` | number | Devices that armed and ran. |
| `participants_excluded` | number | Declared participants that did not arm (see `excluded`). |
| `emitted` … `dropped` | number | Fleet-wide sums of the per-device **identity** buckets below. |
| `informational` | object | Fleet-wide sum of the disclosure counters (see `counters[].informational`). Outside the identity. |
| `excluded` | array | Arm-time exclusions, each `{device, reason, remediation_hint}`. |

## `counters[]` — per participant

One row per participant, keyed by the **join tuple** `(protocol, source_ip,
collector)` — the same tuple a collector groups its received counts by, so the
two sides line up row-for-row. Every ledger field is always present (explicit
zeros, never omitted), so a zero-valued row still diffs cleanly.

| Field | Meaning |
|-------|---------|
| `protocol` | Participating protocol. |
| `source_ip` | Device management IP (the emitter). |
| `collector` | Configured collector `host:port` for this device (empty if the device was deleted post-window). |
| `emitted` | Records **generated**: gate-passed fires + emission-suppressed pre-window fires. |
| `in_window` | Records sent (write returned success) with the write-return timestamp in `[T0, T1)`. |
| `drain` | Records sent during the post-`T1` drain grace. |
| `suppressed_pre_window` | State-driven / on-demand fires that occurred before `T0` — counted but not emitted on the wire. |
| `send_failures` | Resolve / encode / write errors (nl6 could not send). |
| `dropped` | Records generated but never confirmed on the wire (straggler past the drain barrier, or a shutdown-race socket drop). |
| `informational.background_suppressed` | **Informational, quarantined in its own sub-object** — background-cadence fires the gate suppressed for this participant during the scenario. Deliberately **not** a flat sibling of the identity buckets and **not** part of the ledger identity. |

The six identity fields (`emitted` + the five loss buckets) are flat siblings;
the disclosure counter is the sole member of the nested `informational` object.
A consumer computing the identity iterates the flat fields and never has to
know which keys to exclude.

## The ledger identity

Every counter row (and the summary) satisfies, exactly:

```
emitted = in_window + drain + send_failures + dropped + suppressed_pre_window
sent    = in_window + drain
```

`informational.background_suppressed` sits **outside** this identity by design
— it counts generation-suppressed background fires that were never generated as
scenario records, which is exactly why it lives in its own sub-object rather
than as a flat sibling. Use `sent` (`in_window + drain`) as the number to
reconcile against a collector's received count.

## Field / semver evolution policy

The report is a versioned contract. Consumers should tolerate unknown fields.

- **Patch / minor (backward-compatible):** new fields may be **added** to
  `summary` or `counters`; a new top-level block may be added **after**
  `counters`. Existing field names, types, units, and the `summary`-before-
  `counters` order never change within a major.
- **Major (breaking):** renaming/removing a field, changing a type or unit, or
  reordering the top-level blocks. Breaking changes are gated on a major
  `nl6_version` bump and called out in the changelog.
- The **ledger identity** above is a stability guarantee — it holds in every
  version that ships these fields.
- `config_sha256` covers only the **submit config**, not the report shape; the
  report contract is tracked by `nl6_version`.

Future projections (CSV, additional protocols in `counters`, richer
loss-localization blocks) are **additive** under this policy.
