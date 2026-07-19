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
| `GET` | `/api/v1/scenarios/{id}/metrics` | `200` Prometheus text | `404` |
| `GET` | `/api/v1/scenarios` | `200` `{scenarios:[{id,phase}]}` | — |
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
| `protocol` | `string` | yes | Participating push protocol: `"syslog"`, `"netflow9"`, `"ipfix"`, `"gnmi-dialout"`, `"snmp-trap"`, `"sflow"`, or `"netflow5"`. |
| `rate` | `number` | yes | Per-device events/second. Finite, `> 0`, `≤ 1000` (the scheduler's 1 ms floor). Drives the emission cadence for `syslog` and the **flow-tick cadence** for flow protocols (`ipfix`/`netflow9`): during `[T0,T1)` the scenario ticks each participant's flow exporter every `1/rate` s, and the fleet's own flow ticker yields to it (D1 flow-cadence adaptation). Always required and fingerprinted. |
| `window` | `string` | yes | Measurement window length as a Go duration (`"2s"`, `"5m"`). `> 0`, `≤ 24h`. `T1 = T0 + window`; the window is half-open `[T0, T1)`. |
| `drain` | `string` | no | Grace period after `T1` for in-flight sends to complete (bucketed `drain`). `≥ 0`; omitted/`0` selects the 2 s default. |
| `seed` | `number` | no | Pins every random draw the scenario makes (determinism / reproducibility). |
| `rate_profile` | `object` | no | Time-varying intensity λ(t) (see below). Omitted or `{"kind":"constant"}` keeps the flat `rate`. |
| `abort_predicate` | `object` | no | Self-abort a runaway run when a mid-run ledger metric crosses a threshold (see below). |

#### Abort predicate — `abort_predicate`

An optional guard that aborts the scenario through the standard
`running → aborted` pipeline when a fleet-wide ledger metric stays over a
threshold for a grace period — so a bad experiment stops itself before
drowning the collector (FR7).

```json
{"metric": "send_failures", "threshold": 100, "grace": "5s"}
```

| Field | Meaning |
|-------|---------|
| `metric` | Ledger counter to watch: `send_failures` \| `dropped` \| `deferred` \| `sent` (= in_window + drain). |
| `threshold` | Abort when the fleet-wide sum of `metric` exceeds this. `> 0`. |
| `grace` | The threshold must hold this long before aborting (Go duration; omitted = 0). |

The predicate is evaluated on a 1 s cadence using **approximate mid-run
reads** of the live atomics (no drain barrier). The resulting report is a
normal `aborted` artifact (see the [runbook](./loadtest-runbook.md)).

#### Rate profiles — `rate_profile`

By default a scenario emits at the flat `rate` with an exact fixed-interval
cadence. A `rate_profile` instead shapes emission over the window as a
**non-homogeneous Poisson process** drawn by inversion of the integrated
intensity Λ(t) — production-shaped load, not a flat trickle. Every profile's
peak rate is capped at 1000 events/s and must stay strictly positive.

| `kind` | Fields | λ(t) |
|--------|--------|------|
| `constant` (default) | — | flat `rate`, exact cadence (deterministic count) |
| `linear` | `start_rate`, `end_rate` | ramps linearly from `start_rate` at T0 to `end_rate` at T1 |
| `sine` | `mean_rate` (default `rate`), `amplitude` (`< mean_rate`), `period` (duration) | `mean_rate + amplitude·sin(2π·t/period)` |
| `staged` | `stages: [{duration, rate}, …]` | piecewise-constant; the last stage extends to T1 |

```json
{ "participants": ["10.42.0.1"], "protocol": "syslog", "rate": 10, "window": "5m", "seed": 42,
  "rate_profile": { "kind": "linear", "start_rate": 5, "end_rate": 200 } }
```

`rate` is still required (it is the fixed-cadence rate and the `sine` mean
default). A given `(seed, profile)` is fully reproducible: the per-device
arrival stream is seeded from `(seed, device IP)`, so the fleet is
deterministic yet devices are not phase-locked. An over-cap profile is still
governed by the shared global rate limiter.

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

An optional body schedules the start at an **absolute T0** (FR11) so a run
aligns to a wall-clock schedule without a warm operator:

```json
{"at": "2026-07-18T22:00:00Z"}
```

The scenario stays `armed` and a controller timer fires the start at `at`
(surfaced as `scheduled_start` in the status). A **past** `at` (or an
unparseable one) is a `400 {"error","field":"at"}`. A `DELETE` before `T0`
cancels cleanly — the timer is stopped, transports released, and no report is
produced. Omit the body to start immediately.

### `POST /api/v1/scenarios/{id}/stop` — stop

Ends emission, drains in-flight fires, finalizes the immutable report, and
unfreezes the fleet. **Idempotent**: a scenario that already auto-closed at
`T1` returns `200` with the same report (only a stop with no finalized result
— e.g. before start — is a `409`). Returns the
[report](./loadtest-report-schema.md).

### `GET /api/v1/scenarios/{id}/report` — report

Returns the finalized [report](./loadtest-report-schema.md). `409` while the
scenario has not reached a terminal phase (`submitted` / `armed` / `running`).

**sFlow** (`sflow`) counts **raw samples** — `flow_sample` flow-records, **never**
`samples × sampling_rate` — so the synthetic sampling-rate extrapolation can't
manufacture phantom loss. The `flow_sample` data path is gated (suppressed
pre-T0/post-window, counted in-window); the periodic **`counters_sample` is a
keepalive** — it flows continuously (including before T0) to signal agent
liveness and is **never counted** as scenario `sent`. Consequence: because
counters_sample keeps advancing the agent's datagram sequence number
pre-T0, the sequence is **not 0 at T0** (expected; the collector should key on
sample sequence, not datagram sequence, for the measured window).

**gNMI dial-out** (`gnmi-dialout`) is gated at both producers (SAMPLE +
ON_CHANGE): arming requires a **live Publish stream** (a device whose stream is
not established is `excluded` — the collector is unreachable); no updates flow
before T0 (silent arming); in-window a notification counts `sent` when written
to a live stream, or `send_failures` when the stream is down (a collector blip
is visible, never masked). `rate` is not used for dial-out (its SAMPLE cadence
comes from the device's dial-out config), but is still required + fingerprinted.

Add **`?format=csv`** to get a flat `text/csv` projection of `counters[]`
(header row + one row per participant, join-ready on
`(protocol, source_ip, collector)`) instead of JSON — see the
[CSV projection](./loadtest-report-schema.md#csv-projection).

### `GET /api/v1/scenarios/{id}/metrics` — live gauges (Prometheus)

Returns the scenario's live state in **Prometheus text-exposition format**
(`text/plain; version=0.0.4`) — no third-party client dependency, scrape it
directly. Deterministic ordering (participants sorted by source IP). `404` for
an unknown id; valid in every phase (a `submitted` scenario has no participant
rows yet, only the two gauges).

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `nl6_scenario_phase` | gauge | `id`, `phase` | `1` on the active phase label (info-style) |
| `nl6_scenario_target_rate` | gauge | `id` | configured base rate (events/s); for a `rate_profile` scenario this is the constant base rate, **not** the instantaneous λ(t) |
| `nl6_scenario_sent_total` | counter | `id`, `protocol`, `source_ip`, `collector` | records sent (`in_window + drain`) per participant |
| `nl6_scenario_emitted_total` … `nl6_scenario_dropped_total` | counter | (same tuple) | the remaining ledger-identity buckets, per participant |

Every counter is labeled on the report join tuple `(protocol, source_ip,
collector)`, so **summing a family reproduces the matching report summary
total** — e.g. `sum(nl6_scenario_sent_total)` equals `summary.sent`. Because
each counter only advances in-window, a Prometheus range query
(`increase(nl6_scenario_sent_total[…])` over `[T0,T1]`) reproduces the report
totals (NFR-O2). Every lifecycle transition is also written to the process log
as a structured `scenario=<id> phase=<phase>` line for correlation.

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

While a scenario is running (or after it finalizes), status also carries the
live **window** and a **counts** block for unattended observability (FR30):

```json
{
  "id": "s-000001", "phase": "running", "protocol": "syslog", "window": "30s",
  "t0": "2026-07-18T09:00:05.000Z", "t1": "2026-07-18T09:00:35.000Z",
  "elapsed": "12.3s", "remaining": "17.7s",
  "counts": {"participants_armed": 2, "emitted": 1220, "sent": 1220,
             "in_window": 1220, "drain": 0, "suppressed_pre_window": 0,
             "send_failures": 0, "dropped": 0}
}
```

`counts` uses **approximate mid-run atomic reads** (no drain barrier) — a live
progress snapshot that may lag an in-flight fire; the finalized
[report](./loadtest-report-schema.md) is the exact record. `t0`/`t1` are the
actual window bounds (the running gate's, or the finalized result's).

### `GET /api/v1/scenarios` — list

```json
{"scenarios": [{"id": "s-000001", "phase": "running"}]}
```

Lists the active scenarios with their phases (MVP: 0 or 1 — one active at a
time). Empty `scenarios: []` when none.

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
