<!--
Copyright 2026 Ronny Trommer <ronny@no42.org>
SPDX-License-Identifier: Apache-2.0
-->

# Load-test scenario REST API

The load-test scenario subsystem is driven entirely over REST under
`/api/v1/scenarios`. A scenario moves through a fixed lifecycle —
`submitted → armed → running → stopped` (with `armed → canceled` and
`running → aborted` branches) — and finalizes an immutable
[report](./loadtest-report-schema.md) an operator diffs against a monitor's
received counts.

MVP scope: **one active scenario at a time**, **syslog** protocol only. See
the [runbook](./loadtest-runbook.md) for how to use these endpoints to run a
fidelity check and troubleshoot failures.

## Conventions

- **JSON everywhere**, `snake_case` field names, direct objects (no envelope).
- **Success** returns the resource directly. **Errors** return
  `{"error": "<message>"}`, plus `"field": "<json.key>"` for `400` validation
  failures (fail-fast — the first offending field only). `409` bodies name the
  current phase, the scenario ID, and the verb that could not resolve.
- Timestamps are **RFC 3339 with millisecond precision**
  (`2006-01-02T15:04:05.000Z07:00`).
- Request bodies are decoded with `DisallowUnknownFields` (a typo'd or unknown
  key is a `400`) and capped at 64 KiB.

## Endpoints

| Verb | Path | Success | Errors |
|------|------|---------|--------|
| `POST` | `/api/v1/scenarios` | `202` `{id, config_sha256}` | `400`, `409` |
| `POST` | `/api/v1/scenarios/{id}/arm` | `200` readiness | `404`, `409` |
| `POST` | `/api/v1/scenarios/{id}/start` | `200` status | `404`, `409` |
| `POST` | `/api/v1/scenarios/{id}/stop` | `200` [report](./loadtest-report-schema.md) | `404`, `409` |
| `GET` | `/api/v1/scenarios/{id}/report` | `200` [report](./loadtest-report-schema.md) | `404`, `409` |
| `GET` | `/api/v1/scenarios/{id}` | `200` status | `404` |
| `DELETE` | `/api/v1/scenarios/{id}` | `200` `{}` | `404`, `409` |

`{id}` is the zero-padded monotonic scenario ID (`s-000001`).

### `POST /api/v1/scenarios` — submit

Registers a scenario and validates it structurally. Returns the allocated ID
and the config fingerprint. Refused (`409`) while another scenario is
non-terminal (MVP allows one active scenario; a terminal scenario is
transparently replaced).

Request body:

```json
{
  "participants": ["10.42.0.1", "10.42.0.2"],
  "protocol": "syslog",
  "rate": 10,
  "window": "2s",
  "drain": "500ms",
  "seed": 42
}
```

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `participants` | `[]string` | yes | Device management IPs (dotted quad). Non-empty; each must parse as an IP. Existence is **not** checked here — that is an arm-time concern (see readiness `excluded`). |
| `protocol` | `string` | yes | Participating push protocol. MVP: `"syslog"` only. |
| `rate` | `number` | yes | Per-device events/second. Finite, `> 0`, `≤ 1000` (the scheduler's 1 ms floor). The MVP scheduler emits at exactly this constant rate. |
| `window` | `string` | yes | Measurement window length as a Go duration (`"2s"`, `"5m"`). `> 0`, `≤ 24h`. `T1 = T0 + window`; the window is half-open `[T0, T1)`. |
| `drain` | `string` | no | Grace period after `T1` for in-flight sends to complete (bucketed `drain`). `≥ 0`; omitted/`0` selects the 2 s default. |
| `seed` | `number` | no | Pins every random draw the scenario makes (determinism / reproducibility). |

Response `202`:

```json
{"id": "s-000001", "config_sha256": "9b8d8c9c…969314"}
```

`config_sha256` is the SHA-256 over the canonicalized (key-sorted) request
JSON, so two byte-different-but-equal submissions fingerprint identically.

`400` examples:

```json
{"error": "scenario: unknown protocol \"snmp\" (supported: syslog)"}
{"error": "invalid window \"nope\": …", "field": "window"}
{"error": "json: unknown field \"bogus\""}
```

### `POST /api/v1/scenarios/{id}/arm` — arm

Resolves participants against the live fleet, installs the per-device
participation handles, and publishes the armed gate (which suppresses the
fleet's ordinary background cadence for participants). Unknown or ineligible
devices are reported in `excluded` rather than failing the arm.

Response `200` (readiness):

```json
{
  "id": "s-000001",
  "phase": "armed",
  "participants_armed": 1,
  "excluded": [
    {"device": "10.42.0.9", "reason": "device not found",
     "remediation_hint": "create the device before arming, or remove it from the scenario"}
  ]
}
```

### `POST /api/v1/scenarios/{id}/start` — start

Freezes fleet membership (device create/delete is rejected while running —
so counter deltas cannot be corrupted mid-window), publishes the running gate
at `T0`, and starts the scenario-owned scheduler. **Refused (`409`) when 0/N
participants armed.** The window self-closes at `T1` (auto-stop). Returns the
status object.

### `POST /api/v1/scenarios/{id}/stop` — stop

Ends emission, drains in-flight fires, finalizes the immutable report, and
unfreezes the fleet. **Idempotent**: a scenario that already auto-closed at
`T1` returns `200` with the same report (only a stop with no finalized result
— e.g. before start — is a `409`). Returns the
[report](./loadtest-report-schema.md).

### `GET /api/v1/scenarios/{id}/report` — report

Returns the finalized [report](./loadtest-report-schema.md). `409` while the
scenario has not reached a terminal phase (`submitted` / `armed` / `running`).

Add **`?format=csv`** to get a flat `text/csv` projection of `counters[]`
(header row + one row per participant, join-ready on
`(protocol, source_ip, collector)`) instead of JSON — see the
[CSV projection](./loadtest-report-schema.md#csv-projection).

### `GET /api/v1/scenarios/{id}` — status

```json
{
  "id": "s-000001",
  "phase": "running",
  "config_sha256": "9b8d8c9c…969314",
  "seed": 42,
  "transitions": [
    {"phase": "submitted", "at": "2026-07-18T09:00:00.000Z"},
    {"phase": "armed",     "at": "2026-07-18T09:00:03.000Z"},
    {"phase": "running",   "at": "2026-07-18T09:00:05.000Z"}
  ]
}
```

`transitions` is the ordered lifecycle log; it is how a SIGTERM-driven
`aborted` is observable after the fact.

### `DELETE /api/v1/scenarios/{id}` — cancel / release

Releases the scenario. An `armed` scenario is canceled — transports release
and **no report is produced**. A `submitted` or terminal scenario is simply
dropped, freeing the single-active slot. A `running` scenario is refused
(`409`) — stop or abort it first. After a successful `DELETE`, the ID returns
`404`.

## Phase / verb matrix

| Phase | `arm` | `start` | `stop` | `report` | `DELETE` |
|-------|-------|---------|--------|----------|----------|
| `submitted` | → armed | 409 | 409 | 409 | drop |
| `armed` | idempotent | → running (409 if 0/N) | 409 | 409 | cancel |
| `running` | 409 | 409 | → stopped (report) | 409 | 409 |
| `stopped` / `aborted` | 409 | 409 | 200 (idempotent) | 200 | drop |
| `canceled` | 409 | 409 | 409 | 409 | drop |

This matrix is enforced by the table-driven contract test
(`scenario_api_test.go`).
