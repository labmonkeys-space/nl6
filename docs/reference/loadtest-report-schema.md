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

**Resubmitting a body archived before v0.28.0:** if it carries a `drain` key,
strip it. That field is refused with a `400` since v0.28.0 ([nl6#500]) — it
configured nothing. A body that never carried one hashes to the same
`config_sha256` as it always did, so baselines stay comparable.

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
| `drain_end` | RFC3339-ms | When the drain barrier finished and the report was finalized. **Observed, not configured**: the barrier returns as soon as the writes admitted before `T1` return, typically single-digit milliseconds after `t1`. It is also **bounded**: if those writes have not returned within the ceiling, the barrier gives up and `drain_end` is the give-up instant. See `drain_stragglers`. |
| `drain_stragglers` | number | **Absent on a healthy run.** Present only when the drain barrier hit its ceiling and gave up, and then it counts the sends that were still in flight at that moment. A run that reports it was **finalized while its counters were still moving**, so the affected participants may not satisfy the ledger identity and the totals are a lower bound rather than a settled figure. Deliberately its own field and never folded into `dropped`: a straggler was admitted and may still have reached the collector, so calling it dropped would assert an outcome nothing observed. See [The drain barrier is bounded](#the-drain-barrier-is-bounded). |
| `sub_window_count` | number | Loss-localization granularity: the number of equal time buckets `[T0,T1)` is sliced into (currently `10`). |
| `sub_window_duration` | string | Width of one bucket as a Go duration — the **planned** window `/ sub_window_count` (the basis fires were bucketed against). Bucket `i` covers `[T0 + i·d, T0 + (i+1)·d)`. For an **aborted** run the buckets after the abort instant are simply empty (bucketing uses the planned t1, not the shortened actual one). |
| `rate` | object | **Rate disclosure**: `{requested_per_device, paced, achieved_per_device}`. `paced=false` means this protocol's emission cadence is not driven by the scenario rate at all (gnmi-dial-out streams at its own SAMPLE interval), so `achieved_per_device` still reports what happened but the request explains none of it. `achieved_per_device` counts **in-window records only**, so a capture it is compared against must be bounded to `[t0, t1)`. See [`achieved_per_device` is an in-window rate](#achieved_per_device-is-an-in-window-rate). |
| `rate_cap` | object | **Shared-cap disclosure**, present only when this run's protocol has a fleet-wide ceiling in force (`{per_second, shared_with}`). Rate limiters are **per protocol** — syslog and SNMP trap each own one, flow protocols and gNMI dial-out have none — so only *same-protocol* runs contend. `shared_with` names the same-protocol *scenarios* whose windows overlapped this one, sequence-ordered. An empty list means no peer scenario overlapped — **not** that the bucket was uncontended: the scenario scheduler shares the fleet limiter, and background firing spends a token per pop even for fires the scenario gate suppresses, so on a busy non-`-fidelity` fleet a solo run is still throttled by background traffic. The cap is the one in force when the run **began**, not when the report was fetched. Currently emitted for `syslog` only — it is the one protocol whose scenario emission provably passes through the fleet limiter; `-trap-global-cap` governs background trap firing, which the scenario trap path does not go through. A run that shared its bucket did not measure what it would have measured alone, and this is what makes that visible in the artifact instead of silently changing the numbers. Overlaps are recorded as they begin, not reconstructed at finalize, so a peer stopped and deleted before this run finishes is still named. |
| `run_tags` | object | **Run tagging**: how this run's traffic is isolated from background noise per its protocol's lever — `{protocol, mechanism, value, pen, pen_required, degraded, note}`. See [Run tagging](./loadtest-scenarios.md#run-tagging--isolating-experiment-traffic). `mechanism` is one of `syslog_sd_param`, `snmp_enterprise_varbind`, `netflow9_source_id`, `ipfix_odid`, `sflow_sub_agent_id`, `gnmi_synthetic_path`, `window_source_ip`. `degraded=true` means a PEN-dependent lever fell back to `window_source_ip` because no `-scenario-pen` was set. |

#### `achieved_per_device` is an in-window rate

```
achieved_per_device = sum(counters[].in_window) / (t1 - t0) / len(counters)
```

Both halves of that are deliberate. `in_window` counts the records whose socket write returned inside `[t0, t1)`, and the denominator is that same window. Nothing else belongs in either half.

`in_window` excludes records that were produced during the window but written after it. Those are counted under `drain` instead. Attributing them to the window would divide them by the window's own duration, which inflates the rate by exactly the records the window did not have time to emit. So the exclusion is correct, and it is also tiny: post-`T1` fires are suppressed at *generation*, so the `drain` bucket can only catch work already admitted at the `T1` instant — one write on the syslog and trap paths, one paginated batch on the flow paths (the flow exporter admits around a whole `Tick`). On syslog, with a 30 s drain configured on the then-existing knob, `drain_end` landed 9 ms after `t1` and `drain` was 0 ([nl6#500]).

**To compare against a capture, bound the capture to `[t0, t1)`.** That is the whole correction. Do not adjust the figure by a drain: the tail is bounded by that admitted work rather than by any duration, so it cannot move a 120 s window by percent, and the `drain` duration is no longer a configurable field at all ([nl6#500] — submitting one is now a 400).

### The drain barrier is bounded

The barrier that produces `drain_end` waits for every send admitted before `T1` to return.
Until [nl6#567] nothing capped that wait, and the shutdown path runs it: one admitted send that never returned held shutdown open indefinitely.
Two cases reach that state.
A stream transport whose write sets no deadline blocks for as long as it blocks.
And an admitted send that never completes at all, because its write path panicked or a callback was dropped, would never return no matter what deadline the transport carried.

That second case is why the **barrier** is bounded rather than the transports.
A per-transport write deadline cannot see it, and it could not bound the total anyway: syslog TCP serialises behind a per-connection mutex, so a device's worst case is its own 2 s write timeout times the sends queued behind it.

**The ceiling bounds the barrier, not finalize as a whole.**
Finalize joins the scenario's scheduler and its trap and flow tickers before it reaches the barrier, and none of those joins is bounded.
The syslog and trap schedulers fire inline, so a stalled *scheduler-driven* write parks finalize ahead of the barrier and the ceiling is never armed.
What the ceiling reaches is a send admitted outside the scheduler, such as a REST on-demand fire or a state-driven link notification.
So `drain_stragglers` appearing tells you a run was truncated; its absence does not by itself prove finalize was never blocked.

The barrier now gives up after a fixed ceiling of **60 s** and records how many sends were still outstanding in `drain_stragglers`.
A `drain_end` exactly 60 s past `t1` is the signature of a give-up rather than a slow drain.
**The stragglers are not cancelled**, because nothing can interrupt a write parked in the kernel.
They keep running and keep moving ledger counters after the report was snapshotted.

So a report carrying `drain_stragglers` should be read as a **lower bound taken over a set that was still moving**, not as a settled measurement.
The counters are atomics, so nothing is corrupted and no participant's row is invalid on its own; what is lost is the guarantee that a participant's buckets add up, because `emitted` is incremented when a record is generated and `sent` only when its write returns.
A straggler sits between those two increments at the instant of the snapshot.
On a healthy run the field is absent and none of this applies.

An earlier version of this section claimed the figure carried a bias proportional to the drain's share of the window, and advised dividing `sent` by the window plus the drain instead. Both were wrong, and the advice made measurements worse rather than better: `sent` already includes the drain bucket, and that bucket is ~0, so lengthening the denominator by a drain that nothing emitted into deflates the result by `drain ÷ (window + drain)`. On a 120 s window with a 5 s drain that is 5/125 = **4.0 %** of pure, self-inflicted error. (The superseded sentence quoted 4.2 %, which is 5/120 — the drain's share of the *window*, the quantity its own wrong model was about, not the error its own remedy introduced.)

[nl6#463] resolved what the gap actually was. Setup for both parts: netflow9, five participants, 120 s window, capture taken on the emitting node over a **veth** (loopback would not fragment, which is why an earlier capture misled). Template FlowSets subtracted, non-first fragments skipped.

Part one, at rate 4/device, seed 42, with capture and report taken on the same clock — **2349 wire data records against 2349 ledger records in `[t0, t1)`, zero ledger error**, with 0 records in `[t1, drain_end)` and 0 after it.

Part two re-analysed the four original cells that had produced the −3 % to −8 % figures. Every one of them lands on its published `achieved_per_device` at published precision once three measurement-side terms are removed. Taking the rate-8 cell, whose capture holds **4327 data records** — the denominator for both percentages below:

| term | records | share of the 4327 captured |
|---|---|---|
| template FlowSets counted as data records ("phantoms") | 10 | 0.23 % |
| emission after the window, counted as wire¹ | 320 | 7.4 % |
| **ledger error** | **0** | **0 %** |

¹ Those 320 were separated by a rule fixed before the comparison — records after the largest inter-datagram gap past 80 % of the window — because these older captures have no report JSON alongside them, so `t1` is inferred rather than read. Four independent cells landing on four different published values is what carries the conclusion, not the rule.

The third term is not a record count and so is not a row above: the capture *span* was used as the denominator instead of the window — 121.2 s against 120 s, a further 1 % deflation.

The post-window burst is not drain. It is traffic emitted after the scenario stopped and the gate came off, which the ledger never counts and should not: it belongs to no window.

**What this means in practice.** `achieved_per_device` answers "did pacing hit its target" directly, and it is comparable across runs of *different* window lengths: it is an in-window count over its own window, and with the drain model gone no term in it scales with window length. What a short window still costs is precision, not bias — fewer records, so first-fire alignment and scheduler jitter are a larger share of the total. For an absolute rate, measure on the wire with the capture bounded to `[t0, t1)` and template records excluded.

[nl6#500]: https://github.com/labmonkeys-space/nl6/issues/500
[nl6#567]: https://github.com/labmonkeys-space/nl6/issues/567
[nl6#463]: https://github.com/labmonkeys-space/nl6/issues/463

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
| `drain` | Records whose write returned at or after `T1` — the drain barrier's tail. Bounded by the writes already in flight at `T1`, so on a healthy run it is 0; it is not a configurable grace period ([nl6#500]). |
| `suppressed_pre_window` | State-driven / on-demand fires that occurred before `T0` — counted but not emitted on the wire. |
| `send_failures` | Resolve / encode / write errors (nl6 could not send). |
| `dropped` | Records generated but never confirmed on the wire. The barrier waits for every fire it admitted, so this is not a "slow write" bucket: the real causes are a fire that reached the barrier *after* it closed (the detach/teardown race) and a shutdown-race socket drop. |
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
| `avg_bytes_per_second` | number | **In-window** bytes ÷ `(t1 − t0)` (actual window). The headline rate reference. Drain bytes stay in `bytes` (the reconciliation total) but are excluded here — the denominator is the window, and a drain byte was written outside it, so counting it would credit the window with bytes it did not carry. (There is no "drain time" to add to the denominator; the tail is a barrier, not a span — [nl6#500].) In-window bytes = `Σ sub_window_bytes`. |
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
- The **submit config** has no separate version of its own; it moves with
  `nl6_version` too, and a removed request field is a breaking change for
  harnesses. Removals are listed in the API reference's [Removed request
  fields](./loadtest-api.md#removed-request-fields) with the release that
  removed them, so a reader on an older binary can tell which one changed.
  So far: `drain`, refused with a `400` since v0.28.0 ([nl6#500]).

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
