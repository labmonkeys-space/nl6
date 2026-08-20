# Load-test scenario report schema

The report is the machine-readable output of a finalized scenario — the
authoritative record of what nl6 **sent**, which an operator diffs against a
monitor's **received** counts to localize missed or duplicated telemetry. It
is built once at stop/abort, immutable thereafter, and served by
`GET /api/v1/scenarios/{id}/report` (also returned by `stop`). See the
[API reference](./loadtest-api.md) and the [scenarios guide](./loadtest-scenarios.md).

## Shape

```json
{
  "summary": {
    "id": "s-000001",
    "phase": "stopped",
    "protocol": "syslog",
    "metadata": {
      "config_sha256": "9b8d8c9c…969314",
      "resolved_participants_sha256": "3f1c…a204",
      "seed": 42,
      "nl6_version": "v0.16.0",
      "t0": "2026-07-18T09:00:05.000Z",
      "t1": "2026-07-18T09:00:07.000Z",
      "drain_end": "2026-07-18T09:00:07.500Z",
      "sub_window_count": 10,
      "sub_window_duration": "200ms",
      "run_tags": {
        "protocol": "syslog", "mechanism": "window_source_ip", "value": "",
        "pen": 0, "pen_required": true, "degraded": true,
        "note": "no PEN configured (-scenario-pen); SD-PARAM lever unavailable, isolate by source IP + [t0,t1)"
      }
    },
    "duration": "2s",
    "participants_armed": 2,
    "participants_excluded": 1,
    "emitted": 40, "in_window": 40, "drain": 0,
    "suppressed_pre_window": 0, "send_failures": 0, "dropped": 0,
    "informational": {"background_suppressed": 0},
    "sub_windows": [4, 4, 4, 4, 4, 4, 4, 4, 4, 4],
    "excluded": [
      {"device": "10.42.0.9", "reason": "device not found",
       "remediation_hint": "create the device before arming, or remove it from the scenario"}
    ]
  },
  "counters": [
    {"protocol": "syslog", "source_ip": "10.42.0.1", "collector": "10.0.0.9:514",
     "emitted": 20, "sent": 20, "in_window": 20, "drain": 0,
     "suppressed_pre_window": 0, "send_failures": 0, "dropped": 0,
     "informational": {"background_suppressed": 0, "requested": 20, "deferred": 0},
     "sub_windows": [2, 2, 2, 2, 2, 2, 2, 2, 2, 2]}
  ],
  "applications": []
}
```

(The example is a **syslog** run, so `applications` is empty — see
[`applications[]`](#applications--fleet-wide-flow-traffic-ground-truth) for a
populated flow-scenario example.)

The top-level blocks always serialize in the order `summary`, `counters`,
`applications`, so a streaming consumer sees the aggregate first and can rely
on the trailer position of the applications block.

## `summary`

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | Scenario ID (`s-000001`). |
| `phase` | string | Terminal phase: `stopped` (window elapsed / explicit stop) or `aborted` (graceful shutdown). |
| `protocol` | string | Participating protocol. |
| `metadata` | object | The reproducibility fingerprint + actual window timestamps (see below). |
| `duration` | string | `t1 − t0` as a Go duration, from the monotonic clock — the window that actually ran. |
| `participants_armed` | number | Devices that armed and ran. |
| `participants_excluded` | number | Declared participants that did not arm — the **true total**, derived from the exclusion counter rather than from `len(excluded)`, which is capped (see `excluded_truncated`). |
| `emitted` … `dropped` | number | Fleet-wide sums of the per-device **identity** buckets below. |
| `informational` | object | Fleet-wide sum of the disclosure counters (see `counters[].informational`). Outside the identity. |
| `sub_windows` | array | Fleet-wide **loss localization**: in-window sends per time bucket — element-wise sum of the `counters[].sub_windows` rows. Length `metadata.sub_window_count`; sums to `in_window`. See [Loss localization](#loss-localization). |
| `excluded` | array | Arm-time exclusions, each `{device, reason, remediation_hint}`. **Capped at 1,000 rows** (900 for arm-time exclusions + 100 reserved for start-time ones) — one row per unresolved participant would be ~14 MB at the participant ceiling. |
| `excluded_truncated` | bool | Present (`true`) only when the row cap dropped rows, i.e. `participants_excluded > len(excluded)`. Absent otherwise, so the common case is unchanged. |
| `excluded_by_reason` | object | `reason → count` over **every** exclusion, capped or not. This is where the complete disclosure lives when `excluded` is a sample. Absent when there are no exclusions. |

### `summary.metadata`

The reproducibility fingerprint plus the timestamps the run actually observed.
Copy the `(config_sha256, seed)` back into a resubmit on the same
`nl6_version` to re-run a scenario exactly.

Two fingerprints appear here and they answer **different questions**.
`config_sha256` pins what you *declared* — it is the submit-time idempotency key.
`resolved_participants_sha256` pins what actually *ran*.
They diverge as soon as membership is derived rather than enumerated: a
`participants_cidr` scenario resolves against the live fleet, so one
`config_sha256` legitimately produces different participant sets on different
days, or against a half-built fleet. When two runs share a config fingerprint
but disagree on counts, comparing the resolved digest tells you in one step
whether you are looking at a pipeline change or simply a different fleet.

| Field | Type | Meaning |
|-------|------|---------|
| `config_sha256` | string | SHA-256 over the canonicalized submit config — **declared intent**. |
| `resolved_participants_sha256` | string | SHA-256 identifying the devices that **actually participated**. Computed over post-prune membership (the same set `counters[]` serializes and `participants_armed` counts), so a run that lost devices between arm and start cannot digest identically to a whole one. Independent of *how* membership was declared: an explicit list and a prefix selector resolving to the same live devices agree, which is what keeps a baseline comparable to a re-declared repeat. |
| `seed` | number | The seed that pinned every random draw. |
| `nl6_version` | string | Simulator version that produced the report — reproduction is guaranteed only on the same version. |
| `t0` | RFC3339-ms | Actual window open (emission start). |
| `t1` | RFC3339-ms | Actual window close — the planned `T1`, or the abort instant for an early abort (never later than planned `T1`). |
| `drain_end` | RFC3339-ms | When the drain barrier finished and the report was finalized. |
| `sub_window_count` | number | Loss-localization granularity: the number of equal time buckets `[T0,T1)` is sliced into (currently `10`). |
| `sub_window_duration` | string | Width of one bucket as a Go duration — the **planned** window `/ sub_window_count` (the basis fires were bucketed against). Bucket `i` covers `[T0 + i·d, T0 + (i+1)·d)`. For an **aborted** run the buckets after the abort instant are simply empty (bucketing uses the planned t1, not the shortened actual one). |
| `run_tags` | object | **Run tagging**: how this run's traffic is isolated from background noise per its protocol's lever — `{protocol, mechanism, value, pen, pen_required, degraded, note}`. See [Run tagging](./loadtest-scenarios.md#run-tagging--isolating-experiment-traffic). `mechanism` is one of `syslog_sd_param`, `snmp_enterprise_varbind`, `netflow9_source_id`, `ipfix_odid`, `sflow_sub_agent_id`, `gnmi_synthetic_path`, `window_source_ip`. `degraded=true` means a PEN-dependent lever fell back to `window_source_ip` because no `-scenario-pen` was set. |

#### Reproducing `resolved_participants_sha256`

The encoding is deliberately the dumbest one that a checker can reproduce
without a parser: each participating address followed by `\n`, in **byte order**,
SHA-256, hex. So a collector that recorded which sources it received from can
answer "did I receive from the same fleet nl6 sent from?" with one string
comparison:

```sh
# "$IPS" = the source addresses your collector saw during [t0,t1)
printf '%s\n' "$IPS" | LC_ALL=C sort | sha256sum
```

`LC_ALL=C` is **required, not decoration**. Under a UTF-8 locale, glibc's
collation ignores punctuation at the primary level, so `sort` orders
`10.42.10.1` *before* `10.42.1.2` while byte order puts `10.42.1.2` first. That
yields a different digest and an operator reads a false "different fleet" from
the very comparison this section exists to enable. macOS/BSD `sort` happens to
agree with byte order, so the mistake reproduces only on the Linux collector
hosts that are the actual audience.

Byte order is a deliberate departure from the **address** order used for the
`excluded[]` rows. Those rows are read by humans, where `10.42.0.10` sorting
before `10.42.0.2` looks broken; this is input to a hash function, where any
total order does, and byte order is the one every language sorts strings in by
default. The trailing newline after the final address is part of the encoding.

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
| `sent` | `in_window + drain` — the **loss denominator** for reconciliation (convenience; derived). |
| `in_window` | Records sent (write returned success) with the write-return timestamp in `[T0, T1)`. |
| `drain` | Records sent during the post-`T1` drain grace. |
| `suppressed_pre_window` | State-driven / on-demand fires that occurred before `T0` — counted but not emitted on the wire. |
| `send_failures` | Resolve / encode / write errors (nl6 could not send). |
| `dropped` | Records generated but never confirmed on the wire (straggler past the drain barrier, or a shutdown-race socket drop). |
| `informational.background_suppressed` | **Informational, quarantined in its own sub-object** — background-cadence fires the gate suppressed for this participant during the scenario. Deliberately **not** a flat sibling of the identity buckets and **not** part of the ledger identity. |
| `informational.informs_acked` / `informs_pending` | SNMP **INFORM** ack settlement (best-effort, collector-side). An origination counts `sent` at first-transmit; `informs_pending = originations − acked` at report time (still-awaiting-ack). Zero for fire-and-forget traps and non-trap protocols. Outside the identity. |
| `informational.requested` | Scheduler **demand** — every fire the scenario scheduler popped (pre-limiter). `requested = sent + deferred + send_failures + dropped`. |
| `informational.deferred` | Fires the **shared global cap** had no token for — throttled, **not fired, NOT lost**. Outside the identity and the loss denominator, so a cap throttle never masquerades as pipeline loss. |
| `sub_windows` | **Loss localization**: this participant's in-window sends per time bucket. Length `metadata.sub_window_count`; sums to `in_window`. See [Loss localization](#loss-localization). |

The six identity fields (`emitted` + the five loss buckets) are flat siblings;
the disclosure counter is the sole member of the nested `informational` object.
A consumer computing the identity iterates the flat fields and never has to
know which keys to exclude.

## `applications[]` — fleet-wide flow traffic ground truth

For scenarios on a flow protocol (`netflow5` / `netflow9` / `ipfix`), one row
per distinct `(l4_proto, dst_port)` across all **sent** flow records — the
trusted-sender reference for validating a collector's per-application
aggregation. Rows are sorted ascending by the numeric `(protocol, dst_port)`
key; the block is always present (`[]` for non-flow and `sflow` scenarios).
Additive block per the evolution policy below.

```json
"applications": [
  {"l4_proto": "tcp", "dst_port": 443, "app_hint": "https",
   "records": 3, "bytes": 3000, "packets": 30,
   "avg_bytes_per_second": 500.0,
   "sub_window_bytes": [300, 300, 300, 300, 300, 300, 300, 300, 300, 300]}
]
```

(A 6-second window carrying 3000 in-window bytes → `3000 / 6 = 500.0` B/s.)

| Field | Type | Meaning |
|-------|------|---------|
| `l4_proto` | string | Transport protocol name (`tcp` / `udp` / `icmp`; numeric fallback). Join key, part 1. |
| `dst_port` | number | Flow destination port. Join key, part 2. ICMP records carry zero source and destination ports (ICMP has no transport ports), so ICMP traffic aggregates under a single `(icmp, 0)` row. |
| `app_hint` | string | Convenience label from a built-in well-known-port map (`443` → `https`, `53` → `domain`, …); `""` for unmapped ports. **Informational** — collector classification is user-configurable, so join on `(l4_proto, dst_port)`, never on the hint. |
| `records` | number | Sent flow records for this application (`sent` basis: in-window + drain). For a pure flow scenario, `Σ applications[].records == summary.sent`. |
| `bytes` | number | Sum of the records' flow byte counters — exactly what a conforming collector sums for the same window. |
| `packets` | number | Sum of the records' flow packet counters. |
| `avg_bytes_per_second` | number | **In-window** bytes ÷ `(t1 − t0)` (actual window). The headline rate reference. Drain bytes stay in `bytes` (the reconciliation total) but are excluded here — the denominator excludes drain time, so including them would inflate the rate. In-window bytes = `Σ sub_window_bytes`. |
| `sub_window_bytes` | array | In-window bytes per localization bucket (drain bytes excluded — same convention as `sub_windows` vs `sent`). **Informational**: collectors interpolate a flow's bytes across its `[start, end]` interval, so per-bucket comparison is approximate; reconcile on totals (see [validation methodology](./loadtest-scenarios.md#validating-a-collector-against-the-report)). |

`sflow` scenarios are excluded by design: an sFlow collector derives byte
volumes by sampling extrapolation (`frame_length × sampling_rate`), not by
summing record byte counters, so these totals are not the numbers a correct
sFlow collector would report.

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

Future projections (additional protocols in `counters`, richer
loss-localization blocks) are **additive** under this policy.

One assumption a consumer may have held is now false, and is called out rather
than left to be discovered: **`participants_excluded == len(excluded)` no longer
holds** once the 1,000-row exclusion cap bites. `excluded_truncated` marks
exactly that case and `excluded_by_reason` carries the complete breakdown. The
field names, types and order are unchanged, so this is minor under the policy
above — but read the count from `participants_excluded`, never from the array
length.

## Loss localization

A fleet total answers *how much* was lost; `sub_windows` answers *where* — by
**device-set** (the per-participant `counters[]` rows, keyed on the join tuple)
and by **time** (the array within each row). The **planned** window `[T0,T1)`
is sliced into `metadata.sub_window_count` equal buckets, each
`metadata.sub_window_duration` wide; `sub_windows[i]` counts the in-window sends
whose write-return time fell in bucket `i` (`[T0 + i·d, T0 + (i+1)·d)`). An early
**abort** shortens the run but not the bucket basis — buckets past the abort
instant are simply empty.

- **Bucketing choice.** A fixed *count* (10), not a fixed duration — the report
  stays bounded and window-length-independent (a 10 s window → 1 s buckets; a
  10 min window → 60 s buckets).
- **Scope.** Localizes **in-window** sends only: `sum(sub_windows) == in_window`
  for every row and the summary. Drain-tail sends are post-`T1` by definition
  and carry no sub-window (reconcile them via the `drain` total).
- **How to use it.** Bucket your collector's *received* records the same way
  (receive-time relative to `T0`, same bucket width) and diff per bucket:
  *"1,204 records lost, all from `[T0+30s, T0+45s]`"* points at a time window,
  not just a fleet total. Combined with the per-row `source_ip`, loss narrows to
  a device-set **and** a time span.
- **JSON only.** The flat [CSV projection](#csv-projection) is unchanged, so
  index-keyed CSV parsers keep working; localization lives in the JSON report.

Additive under the [semver policy](#field--semver-evolution-policy) — the
policy explicitly anticipates "richer loss-localization blocks."

## CSV projection

`GET /api/v1/scenarios/{id}/report?format=csv` serves a flat `text/csv`
projection of `counters[]` — one header row plus one row per participant,
join-ready on the first three columns:

```csv
protocol,source_ip,collector,emitted,in_window,drain,suppressed_pre_window,send_failures,dropped,background_suppressed
syslog,10.42.0.1,10.0.0.9:514,20,20,0,0,0,0,0
syslog,10.42.0.2,10.0.0.9:514,20,20,0,0,0,0,0
```

The `informational.background_suppressed` counter flattens to a trailing
`background_suppressed` column. `summary`-level fields are not in the CSV — it
is purely the per-device counter projection, so it joins directly against a
collector's received-counts export on `(protocol, source_ip, collector)`.
