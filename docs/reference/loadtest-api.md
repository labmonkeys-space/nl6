---
sidebar_label: "Scenario API"
description: "The /api/v1/scenarios endpoints that submit, arm, start, stop and report a load-test scenario, with their request and response shapes."
---

# Load-test scenario API

The load-test scenario subsystem is driven entirely over REST under `/api/v1/scenarios`.
A scenario moves through the fixed lifecycle `submitted → armed → running → stopped`, with `armed → canceled` and `running → aborted` branches.
It finalizes an immutable [report](./loadtest-report-schema.md) that an operator diffs against a monitor's received counts.

See the [scenarios guide](../ops/loadtest-scenarios.md) for how to use these endpoints to run a fidelity check and troubleshoot failures.

## Conventions

- **JSON everywhere**, `snake_case` field names, direct objects (no envelope).
- **Success** returns the resource directly. **Errors** return `{"error": "<message>"}`, plus `"field": "<json.key>"` for `400` validation failures (fail-fast, so only the first offending field). `409` bodies name the current phase, the scenario ID, and the verb that could not resolve.
- Timestamps are **RFC 3339 with millisecond precision** (`2006-01-02T15:04:05.000Z07:00`).
- Request bodies are decoded with `DisallowUnknownFields` (a typo'd or unknown key is a `400`). `POST /api/v1/scenarios` caps its body at **1,865,536 bytes** (≈1.78 MiB); `POST /api/v1/scenarios/{id}/start` reads at most 1 KiB.
- The submit cap holds a ceiling-sized participant list (100,000 entries × 18 bytes for `"255.255.255.255",`) plus a **shared** 64 KiB allowance for all other fields.
  Send participant lists as compact JSON, because pretty-printing adds bytes per entry and can exceed the cap on its own.
  A large `rate_profile` or `abort_predicate` on a ceiling-sized list can exceed it too.
  An over-cap body returns a `400` naming the cap, with no `"field"` key, because the limit trips during transport decoding.

## Endpoints

| Verb | Path | Success | Errors |
|------|------|---------|--------|
| `POST` | `/api/v1/scenarios` | `202` `{id, config_sha256}` | `400`, `409` |
| `POST` | `/api/v1/scenarios/{id}/arm` | `200` readiness | `404`, `409` |
| `POST` | `/api/v1/scenarios/{id}/start` | `200` status | `404`, `409` |
| `POST` | `/api/v1/scenarios/{id}/stop` | `200` [report](./loadtest-report-schema.md) | `404`, `409` |
| `GET` | `/api/v1/scenarios/{id}/report` | `200` [report](./loadtest-report-schema.md) | `404`, `409` |
| `GET` | `/api/v1/scenarios/{id}/metrics` | `200` Prometheus text | `404` |
| `GET` | `/api/v1/scenarios` | `200` `{scenarios:[{id,phase}]}` | none |
| `GET` | `/api/v1/scenarios/{id}` | `200` status | `404` |
| `DELETE` | `/api/v1/scenarios/{id}` | `200` `{}` | `404`, `409` |

`{id}` is the zero-padded monotonic scenario ID (`s-000001`).

### `POST /api/v1/scenarios` (submit)

Registers a scenario and validates it structurally.
Returns the allocated ID and the config fingerprint.
Refused (`409`) only when **8 scenarios are already non-terminal**.
Exclusivity is per *device*, not per submit, so scenarios with disjoint participants run concurrently and overlapping ones are refused at `arm`, where membership is finally known.
Submit cannot make that call: `participants_cidr` resolves against the live fleet, so at submit the participant set is not merely unknown but unknowable.

Request body:

```json
{
  "participants": ["10.42.0.1", "10.42.0.2"],
  "protocol": "syslog",
  "rate": 10,
  "window": "2s",
  "seed": 42
}
```

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `participants` | `[]string` | yes¹ | Device management IPs, as a **set**. At most **100,000** entries, **no repeats** (a duplicate is a `400`). Each must be an **IPv4 dotted quad**; IPv6 and IPv4-mapped IPv6 (`::ffff:10.42.0.1`) are a `400`. Existence is checked at arm, not here. |
| `participants_cidr` | `[]string` | yes¹ | Compact prefix selector: IPv4 CIDR prefixes in **canonical (masked) form**, at most **1,024** entries. The participant set is the **union** of `participants` and every live device whose IP falls inside any prefix, resolved at arm time. `400` at submit for: a non-canonical prefix (`10.42.1.5/16`, and the error names the canonical form), an IPv6 or IPv4-mapped prefix, a duplicate prefix, or a prefix nested inside another (it adds nothing to the union). An explicit `participants` entry covered by a prefix is allowed and makes that address's absence loud. `["0.0.0.0/0"]` spells whole-fleet. |
| `protocol` | `string` | yes | Participating push protocol: `"syslog"`, `"netflow9"`, `"ipfix"`, `"gnmi-dialout"`, `"snmp-trap"`, `"sflow"`, or `"netflow5"`. |
| `rate` | `number` | yes | Per-device events/second. Finite, `> 0`, `≤ 1000` (the scheduler's 1 ms floor). Drives the emission cadence for `syslog` and `snmp-trap` (one event per scheduler pop).<br/><br/>For **flow protocols** it sets the record rate by sizing each participant's flow cache, and it has a per-device ceiling; see [Choose participant cardinality and rate](../ops/loadtest-scenarios.md#choose-participant-cardinality-and-rate).<br/><br/>For `gnmi-dialout`, `rate` does **not** control emission, because the stream runs at its dial-out SAMPLE interval. No `nl6_scenario_target_rate` gauge is published for such a run.<br/><br/>Always required and fingerprinted. |
| `window` | `string` | yes | Measurement window length as a Go duration (`"2s"`, `"5m"`). `> 0`, `≤ 24h`. `T1 = T0 + window`; the window is half-open `[T0, T1)`. |
| `seed` | `number` | no | Pins every random draw the scenario makes (determinism / reproducibility). |
| `rate_profile` | `object` | no | Time-varying intensity λ(t) (see below). Omitted or `{"kind":"constant"}` keeps the flat `rate`. |
| `expect_participants` | `number` | no | Declared participant cardinality: how many devices you expect the selectors to resolve to. **Exact.** Start is refused when the participating count differs in *either* direction, because a silently different denominator is what makes a run incomparable to its baseline. Must be between `1` and **100,000**; an explicit `0` is a `400` (use omission to mean "no expectation", so a caller that computes this number and hits a zero-length bug cannot silently lose the guard). Without `participants_cidr` it must also be `<=` the number of declared `participants`, since the armed set cannot exceed the list. A larger value is unsatisfiable by construction and is refused at submit rather than deferred to a `409` at start. Also checked when scheduling an absolute `T0`, so a doomed schedule is refused immediately instead of at fire time. Fingerprinted in `config_sha256`, because it is declared intent. Don't know the number yet? Submit without it, arm, read `participants_armed`, then re-submit with it. |
| `abort_predicate` | `object` | no | Self-abort a runaway run when a mid-run ledger metric crosses a threshold (see below). |

¹ At least one of `participants` / `participants_cidr` must be non-empty; both empty is a `400`.

##### Removed request fields

A removed request field is a **breaking change for a harness**: a submit carrying it returns a `400`.
The submit config carries no version of its own, so it moves with `nl6_version` and removals are listed here.

| Field | Why |
|-------|-----|
| `drain` | It configured nothing: the post-window phase is a [barrier, not a duration](./loadtest-report-schema.md#the-drain-barrier-is-bounded). The refusal keys on the key's *presence*, so `""`, `null`, `0s` and a non-string value are all `400`; delete the key. A body that never carried it keeps its `config_sha256`, so baselines stay comparable. The `drain` ledger bucket and the `drain_end` timestamp are unaffected. |


#### Abort predicate (`abort_predicate`)

An optional guard that aborts the scenario through the standard `running → aborted` pipeline when a fleet-wide ledger metric stays over a threshold for a grace period, so a bad experiment stops itself before drowning the collector.

```json
{"metric": "send_failures", "threshold": 100, "grace": "5s"}
```

| Field | Meaning |
|-------|---------|
| `metric` | Ledger counter to watch: `send_failures` \| `dropped` \| `deferred` \| `sent` (= in_window + drain). |
| `threshold` | Abort when the fleet-wide sum of `metric` exceeds this. `> 0`. |
| `grace` | The threshold must hold this long before aborting (Go duration; omitted = 0). |

The predicate is evaluated on a 1 s cadence using **approximate mid-run reads** of the live atomics (no drain barrier).
The resulting report is a normal `aborted` artifact (see the [scenarios guide](../ops/loadtest-scenarios.md)).

#### Rate profiles (`rate_profile`)

By default a scenario emits at the flat `rate` with an exact fixed-interval cadence.
A `rate_profile` instead shapes emission over the window as a **non-homogeneous Poisson process** drawn by inversion of the integrated intensity Λ(t).
This gives production-shaped load, not a flat trickle.
Every profile's peak rate is capped at 1000 events/s and must stay strictly positive.

| `kind` | Fields | λ(t) |
|--------|--------|------|
| `constant` (default) | none | flat `rate`, exact cadence (deterministic count) |
| `linear` | `start_rate`, `end_rate` | ramps linearly from `start_rate` at T0 to `end_rate` at T1 |
| `sine` | `mean_rate` (default `rate`), `amplitude` (`< mean_rate`), `period` (duration) | `mean_rate + amplitude·sin(2π·t/period)` |
| `staged` | `stages: [{duration, rate}, …]` | piecewise-constant; the last stage extends to T1 |

```json
{ "participants": ["10.42.0.1"], "protocol": "syslog", "rate": 10, "window": "5m", "seed": 42,
  "rate_profile": { "kind": "linear", "start_rate": 5, "end_rate": 200 } }
```

`rate` is still required (it is the fixed-cadence rate and the `sine` mean default).
A given `(seed, profile)` is fully reproducible: the per-device arrival stream is seeded from `(seed, device IP)`, so the fleet is deterministic yet devices are not phase-locked.
An over-cap profile is still governed by the shared global rate limiter.

Response `202`:

```json
{"id": "s-000001", "config_sha256": "9b8d8c9c…969314"}
```

`config_sha256` is the SHA-256 over the canonicalized (key-sorted) request JSON, so two byte-different-but-equal submissions fingerprint identically.

`400` examples:

```json
{"error": "scenario: unknown protocol \"snmp\" (supported: syslog, netflow9, ipfix, gnmi-dialout, snmp-trap, sflow, netflow5)"}
{"error": "invalid window \"nope\": …", "field": "window"}
{"error": "json: unknown field \"bogus\""}
```

### `POST /api/v1/scenarios/{id}/arm` (arm)

Resolves participants against the live fleet, installs the per-device participation handles, and publishes the armed gate, which suppresses background telemetry for participants.
Unknown or ineligible devices are reported in `excluded` rather than failing the arm.

**Re-arming re-resolves membership from scratch.**
The `excluded` set is rebuilt and the armed count can go down.
Counters already accrued for a participant that stays armed carry forward.
Re-arming also cancels a pending absolute-`T0` start, reported as `"scheduled_start_cancelled": true`.
A scheduled start that fails on its own (every participant deleted, or a device-creation batch in progress at `T0`) leaves the scenario `armed`, logs the failure and releases the schedule without retrying.

Response `200` (readiness):

```json
{
  "id": "s-000001",
  "phase": "armed",
  "participants_armed": 1,
  "excluded": [
    {"device": "10.42.0.9", "reason": "device not found",
     "remediation_hint": "create the device before arming, or remove it from the scenario"}
  ],
  "excluded_total": 1
}
```

**The `excluded` rows are capped at 1,000; the counts are not.**
Arm-time exclusions get 900 rows and 100 are reserved for devices deleted between arm and start, whose identity you cannot recover otherwise.
So readiness carries at most 900 rows and the report up to 1,000.
`excluded_total` is always present (including `0`) and is the authoritative count; the report's `participants_excluded` derives from it.
`excluded_by_reason` gives `reason → count` over every exclusion whenever there is one.
`excluded_truncated: true` appears only when rows were dropped.
Fix what the rows show, re-arm, and the next batch surfaces.

**Prefix selectors silence only "not found".**
An address inside a `participants_cidr` prefix that matches no device produces no `excluded` row, while a matched device that cannot participate still gets one.
List an address in `participants` as well to make its absence loud.
Prefix matches resolve in address order, so re-arming an unchanged fleet returns a byte-identical response.

**Declared expectation.** With `expect_participants` set, readiness echoes it as `participants_expected` and adds an `expectation_mismatch` diagnosis when the counts disagree.
Arm discloses the mismatch; `start` enforces it.

| Situation | What it means |
|---|---|
| short, and exclusions account for it | Devices were found and rejected; see `excluded_by_reason`. |
| short, with **no** exclusions | The selectors matched fewer live devices than expected, typically a prefix one bit too narrow. |
| more than declared | The fleet holds matching devices your expectation omits. |

**Resolved-set ceiling (`409`).** The resolved union is bounded by the same 100,000 cap, checked before any state changes.
A refused re-arm leaves the previous arm intact, and a refused first arm leaves the scenario `submitted`.

### `POST /api/v1/scenarios/{id}/start` (start)

Freezes fleet membership (device create/delete is rejected while running, so counter deltas cannot be corrupted mid-window), publishes the running gate at `T0`, and starts the scenario-owned scheduler.
**Refused (`409`) when 0/N participants armed.** The window self-closes at `T1` (auto-stop).
Returns the status object.

An optional body schedules the start at an **absolute T0** so a run aligns to a wall-clock schedule without a warm operator:

```json
{"at": "2026-07-18T22:00:00Z"}
```

The scenario stays `armed` and a controller timer fires the start at `at` (surfaced as `scheduled_start` in the status).
A **past** `at` (or an unparseable one) is a `400 {"error","field":"at"}`.
A `DELETE` before `T0` cancels cleanly.
The timer is stopped, transports are released, and no report is produced.
Omit the body to start immediately.

### `POST /api/v1/scenarios/{id}/stop` (stop)

Ends emission, drains in-flight fires, finalizes the immutable report, and unfreezes the fleet.
**Idempotent**: a scenario that already auto-closed at `T1` returns `200` with the same report (only a stop with no finalized result, such as one before start, is a `409`).
Returns the [report](./loadtest-report-schema.md).

### `GET /api/v1/scenarios/{id}/report` (report)

Returns the finalized [report](./loadtest-report-schema.md).
`409` while the scenario has not reached a terminal phase (`submitted` / `armed` / `running`).

What each protocol counts as one record, including sFlow and gNMI dial-out, is in the [report schema](./loadtest-report-schema.md#counters-per-participant).

The `format` query parameter selects the representation (default JSON):

- **`?format=csv`** returns a flat `text/csv` projection of `counters[]` (header row + one row per participant, join-ready on `(protocol, source_ip, collector)`); see the [CSV projection](./loadtest-report-schema.md#csv-projection).
- **`?format=html`** returns a **self-contained** `text/html` page (embedded CSS, no external fonts / JS / frameworks): stat cards, the per-time-bucket loss-localization bar chart, run-tag panel, identity totals, and the participant table with per-row status. It is the human-readable view of the same data. Open it in a browser or attach it to a run. JSON stays the machine source of truth.

### `GET /api/v1/scenarios/{id}/metrics` (live Prometheus gauges)

Returns the scenario's live state in **Prometheus text-exposition format** (`text/plain; version=0.0.4`).
It needs no third-party client dependency. Scrape it directly.
Deterministic ordering (participants sorted by source IP).
`404` for an unknown id.
It is valid in every phase.
A `submitted` scenario has no participant rows yet.
It shows only `nl6_scenario_phase` and `nl6_scenario_target_rate`, or only `nl6_scenario_phase` for `gnmi-dialout`.

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `nl6_scenario_phase` | gauge | `id`, `phase` | `1` on the active phase label (info-style) |
| `nl6_scenario_target_rate` | gauge | `id` | configured base rate (events/s); for a `rate_profile` scenario this is the constant base rate, **not** the instantaneous λ(t); absent for `gnmi-dialout`, which paces to its SAMPLE interval, not to a rate |
| `nl6_scenario_sent_total` | counter | `id`, `protocol`, `source_ip`, `collector` | records sent (`in_window + drain`) per participant |
| `nl6_scenario_emitted_total` | counter | (same tuple) | records emitted (identity total) per participant |
| `nl6_scenario_in_window_total` | counter | (same tuple) | records sent inside the measurement window per participant |
| `nl6_scenario_drain_total` | counter | (same tuple) | records sent during the drain tail per participant |
| `nl6_scenario_suppressed_pre_window_total` | counter | (same tuple) | fires suppressed before `T0` per participant |
| `nl6_scenario_send_failures_total` | counter | (same tuple) | transport send failures per participant |
| `nl6_scenario_dropped_total` | counter | (same tuple) | records dropped after the drain end per participant |

Every counter is labeled on the report join tuple `(protocol, source_ip, collector)`, so **summing a family reproduces the matching report summary total**.
For example, `sum(nl6_scenario_sent_total)` equals `summary.sent`.
Because each counter only advances in-window, a Prometheus range query (`increase(nl6_scenario_sent_total[…])` over `[T0,T1]`) reproduces the report totals.
Every lifecycle transition is also written to the process log as a structured `scenario=<id> phase=<phase>` line for correlation.

### `GET /api/v1/scenarios/{id}` (status)

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

`transitions` is the ordered lifecycle log; it is how a SIGTERM-driven `aborted` is observable after the fact.

While a scenario is running (or after it finalizes), status also carries the live **window** and a **counts** block for unattended observability:

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

`counts` uses **approximate mid-run atomic reads** (no drain barrier).
It is a live progress snapshot that may lag an in-flight fire.
The finalized [report](./loadtest-report-schema.md) is the exact record.
`t0`/`t1` are the actual window bounds (the running gate's, or the finalized result's).

### `GET /api/v1/scenarios` (list)

```json
{"scenarios": [{"id": "s-000001", "phase": "running"}]}
```

Lists every registered scenario with its phase, in ID order.
That is up to 8 non-terminal scenarios plus the 8 most recent terminal ones; older terminal scenarios are reaped.
Empty `scenarios: []` when none.

### `DELETE /api/v1/scenarios/{id}` (cancel / release)

Releases the scenario.
An `armed` scenario is canceled.
Transports release and **no report is produced**.
A `submitted` or terminal scenario is dropped, releasing any devices it held.
A `running` scenario is refused (`409`).
Stop or abort it first.
After a successful `DELETE`, the ID returns `404`.

## Phase / verb matrix

| Phase | `arm` | `start` | `stop` | `report` | `DELETE` |
|-------|-------|---------|--------|----------|----------|
| `submitted` | → armed | 409 | 409 | 409 | drop |
| `armed` | → armed (re-resolves membership) | → running (409 if 0/N) | 409 | 409 | cancel |
| `running` | 409 | 409 | → stopped (report) | 409 | 409 |
| `stopped` / `aborted` | 409 | 409 | 200 (idempotent) | 200 | drop |
| `canceled` | 409 | 409 | 409 | 409 | drop |

