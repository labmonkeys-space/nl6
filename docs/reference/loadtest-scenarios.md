# Running a load-test scenario

The operating guide for the nl6 load-test scenario subsystem — the lifecycle,
fidelity mode, run isolation, reconciliation, and troubleshooting. New to the
feature? Start with the [overview](./loadtest-overview.md). For copy-pasteable
recipes by use case, see the [runbooks](./loadtest-runbooks.md); for endpoints
and shapes, the [REST API](./loadtest-api.md) and [report schema](./loadtest-report-schema.md).

Scope: **up to 8 concurrent scenarios**, each over any one of the seven shipped
push protocols — **syslog**, **SNMP trap/inform**, **NetFlow v5/v9**, **IPFIX**,
**sFlow**, and **gNMI dial-out**. Each protocol opts a device in via its own
export config; the scenario gates whichever protocol it targets.

## Run a fidelity check

The lifecycle is `submit → arm → start → (window elapses) → stop → report`.

```bash
NL6=http://localhost:8080

# 1. Submit — validate + fingerprint. Returns the scenario id.
ID=$(curl -sf -X POST $NL6/api/v1/scenarios -H 'Content-Type: application/json' -d '{
  "participants": ["10.42.0.1","10.42.0.2","10.42.0.3"],
  "protocol": "syslog", "rate": 10, "window": "30s", "drain": "2s", "seed": 42
}' | jq -r .id)

# 2. Arm — resolve participants; check the excluded list before starting.
curl -sf -X POST $NL6/api/v1/scenarios/$ID/arm | jq

# 3. Start — freezes the fleet, opens the window at T0. Refused at 0/N armed.
curl -sf -X POST $NL6/api/v1/scenarios/$ID/start | jq

# 4. Wait for the window (it self-closes at T1), then finalize + fetch report.
sleep 33
curl -sf -X POST $NL6/api/v1/scenarios/$ID/stop | jq

# 5. Reconcile: report `sent` (in_window + drain) vs your collector's received.
```

`stop` is idempotent, so it is safe to call after the window has already
auto-closed — you get the same report back.

To **reconcile**, sum `in_window + drain` per `counters[]` row and compare to
your monitor's received count for the same `(protocol, source_ip, collector)`
tuple. `send_failures` vs `dropped` separates "nl6 could not send" from "nl6
sent but the wire lost it". See the
[report schema](./loadtest-report-schema.md#the-ledger-identity).

**Prefer a browser?** Add `?format=html` for a self-contained page (stat cards,
a loss-localization bar chart, and the participant table) you can eyeball or
attach to a run report; `?format=csv` gives the flat join-ready projection. JSON
(no `format`) stays the machine source of truth.

## Fidelity mode

**`-fidelity` — a silent fleet.** By default every device starts pushing its
background telemetry — flow, SNMP
traps, syslog, gNMI dial-out — on its own cadence the moment it comes up. So a
scenario's window is mixed in with steady background noise, and the fleet keeps
emitting after the run ends. Start nl6 with **`-fidelity`** to invert that: the
fleet is **silent** — no autonomous push leaves any device — **except** during a
running scenario's `[T0,T1)` window, where only that scenario's gated traffic
flows. Silence before the run, only the scenario during it, silence again after.

Fidelity is also togglable **at runtime**, which is what you want when
bracketing a measurement on a fleet you would rather not rebuild — a restart
destroys every REST-created device:

```console
curl -sX POST $NL6/api/v1/fidelity -H 'Content-Type: application/json' \
  -d '{"silent": true}'

# or bound it, so it restores itself even if you forget
curl -sX POST $NL6/api/v1/fidelity -H 'Content-Type: application/json' \
  -d '{"silent": true, "duration": "20m"}'

curl -s $NL6/api/v1/fidelity   # value in force, startup flag, pending revert
```

`GET` reports the value in force **and** the startup flag separately: once the
value is mutable, `-fidelity` is only a default, and a surface reporting the
flag alone would assert something the engine may have stopped honouring.

- Devices still answer **polls** (SNMP / SSH / HTTPS) normally — fidelity mutes
  only autonomous *push* telemetry.
- Explicit **on-demand** fires (`POST /devices/{ip}/{trap,syslog}`) still go
  through — a deliberate action, not background chatter.
- Fleet-wide and static: set once at startup, **off by default**.
- It mutes **autonomous** push. A gNMI **dial-in** subscription is
  client-initiated (the collector `Subscribe`d), so it keeps streaming — cancel
  the subscription if you need the gNMI path quiet too.

The payoff is the cleanest possible measurement environment — a report you can
diff against a collector with zero background contamination on either side. Add
`-fidelity` to any launch command in the [runbooks](./loadtest-runbooks.md).

## NetFlow v5 run isolation (time-window + source-IP only)

NetFlow v5 is a fixed-format protocol — no templates, no option records, no
in-band field a scenario could tag. So a v5 fidelity run is isolated purely by
**the measurement window `[T0,T1)` and the participant source IPs**: the
collector attributes scenario traffic by `(source_ip, arrival time)`, not by any
per-flow marker. Keep this in mind when reconciling — filter the collector's v5
records to the participant IPs **and** the window before diffing against the
report's `sent`. (The other protocols carry richer identity — v9/IPFIX
templates, sFlow agent/sub-agent, trap varbinds — but the report's join tuple
`(protocol, source_ip, collector)` is the same across all of them.)

## Run tagging — isolating experiment traffic

On a **shared collector** — one that also receives background/production
telemetry — you must separate this run's traffic from the noise before
reconciling. Each protocol is isolated by its **native lever**; the report's
`metadata.run_tags` records the mechanism + value so you know how to filter.
This is *tag-what-exists*: the levers below are already carried by the wire
encoders (or, for PEN-dependent ones, degrade cleanly).

| Protocol | `mechanism` | Lever | PEN? |
|----------|-------------|-------|------|
| NetFlow v9 | `netflow9_source_id` | filter received flows by the device's **Source ID** | no |
| IPFIX | `ipfix_odid` | filter by the **Observation Domain ID** (enterprise IE is a secondary, PEN-only lever) | no |
| sFlow v5 | `sflow_sub_agent_id` | filter by **`sub_agent_id`** | no |
| gNMI dial-out | `gnmi_synthetic_path` | dial-out stamps the device IP in `Notification.Prefix.Target`; filter by target | no |
| Syslog 5424 | `syslog_sd_param` | RFC 5424 SD-PARAM `[nl6@<PEN> runId="<id>"]` | **yes** |
| SNMP trap/inform | `snmp_enterprise_varbind` | enterprise varbind under the nl6 PEN | **yes** |
| NetFlow v5 | `window_source_ip` | no taggable field — isolate by participant source IPs + `[T0,T1)` | n/a |

- **In every case** the measurement window `[T0,T1)` plus the participant source
  IPs already narrow the traffic; the per-protocol lever adds a second, in-band
  discriminator where one exists.
- **PEN-dependent levers degrade gracefully.** Syslog SD-PARAM and the SNMP
  enterprise varbind need an IANA **Private Enterprise Number**. Without one
  (`-scenario-pen` unset, the default), `run_tags.mechanism` is
  `window_source_ip` and `run_tags.degraded` is `true` — you fall back to window
  + source-IP isolation, which is always available. Set `-scenario-pen <n>` once
  your PEN is registered to activate the clean levers; `run_tags.value` then
  carries the `runId` a receiver keys on.
- `nl6-reconcile`'s `PHANTOM` status flags received traffic that is **not** in
  the report — usually background noise that leaked past your filter. Tighten
  the filter using the `run_tags` mechanism above.

## Reconciliation walkthrough

The instrument's one job is to make loss **measurable**. The arithmetic:

```
sent       = in_window + drain          (per counters[] row, or summed)
received   = your monitor's count for the same (protocol, source_ip, collector)
loss_ratio = (sent − received) / sent
```

### `nl6-reconcile` — one command, not a spreadsheet

`nl6-reconcile` does the join for you. It is **read-only**: give it a saved
report and your collector's received-counts export, and it outer-joins on
`(protocol, source_ip, collector)` and prints `loss_ratio` per key with an
in-flight tolerance band. See [Getting nl6-reconcile](#getting-nl6-reconcile).

```bash
# Report as JSON (or CSV via ?format=csv); received as a collector CSV export.
curl -sf $NL6/api/v1/scenarios/$ID/report > report.json

nl6-reconcile -report report.json -received collector.csv
# PROTOCOL  SOURCE_IP   COLLECTOR     SENT  RECEIVED  DELTA  LOSS%   STATUS
# syslog    10.42.0.1   10.0.0.9:514  1000  1000      0      0.00%   OK
# syslog    10.42.0.2   10.0.0.9:514  1000  950       50     5.00%   RESIDUAL
#
# Summary: 2 keys | 1 OK | 1 flagged | tolerance 0.50% | sent=2000 received=1950 fleet_residual=2.50%
#
# NOTE: shortfalls above are UNCLASSIFIED (RESIDUAL, or MISSING with no received row).
# Still-queued messages are backlog and resolve themselves; drained-and-missing
# messages are loss and do not. Re-run with -drained once the collector's input
# queue has emptied to classify them.
```

- **Inputs.** `-report` takes the report **JSON** or the flat **CSV** projection
  (auto-detected). `-received` takes a **CSV** (`protocol,source_ip,collector,received`
  columns) or a **Prometheus range-query result** (`/api/v1/query_range` JSON —
  the last sample of each series is the received count, keyed by its
  `protocol`/`source_ip`/`collector` labels). Either input may be `-` for stdin.
- **Tolerance.** `-tolerance 0.005` (default 0.5 %) is the in-flight band:
  `|loss_ratio|` within it is `OK` — records still on the wire at `T1` cause a
  tiny delta that is not real loss. Widen it for lossy paths, tighten to `0` for
  an exact check.
- **Statuses.** `OK` · `RESIDUAL` (received < sent, queue state unknown) ·
  `LOSS` (received < sent **and** you passed `-drained`) · `DUP` (received > sent —
  duplication) · `MISSING` (in the report, no received row — a join gap, or the
  100 % case of the same shortfall ambiguity, so it is unclassified without
  `-drained` too) · `PHANTOM` (received but not in the report — background noise leaked
  into your export; see the run-tagging notes to isolate it).
- **`-drained`: classify the shortfall.** A shortfall measured while the
  collector's input queue is still draining is **backlog**, and backlog resolves
  itself. The same shortfall measured after the queue has emptied is **loss**,
  and loss does not. They have opposite remedies, so `nl6-reconcile` will not
  guess: it cannot see your collector's queue, and by default reports a
  shortfall as `RESIDUAL`. Pass `-drained` once the queue has emptied to assert
  the run is over and get `LOSS`. Reporting a single unclassified residual as
  loss is the defect this flag exists to prevent — see
  [Collector ceiling](./loadtest-collector-ceiling.md).
- **Compatibility note.** `-drained` changed the DEFAULT output: a shortfall that
  previously printed `LOSS` now prints `RESIDUAL`, in text, CSV and JSON alike,
  and the summary reads `fleet_residual` (or `fleet_delta` when the figure is
  zero or negative). Exit codes are unchanged, so CI gates still fire as before,
  but a pipeline grepping for the literal `LOSS` or `fleet_loss=` needs either
  `-drained` or an updated pattern.
- **Exit code.** `0` when every key is `OK`, `1` when any key is flagged — so
  `nl6-reconcile` drops straight into a CI gate. Use `-format csv|json` for a
  machine-readable diff.

#### Getting nl6-reconcile

`nl6-reconcile` is a small, stateless, **cross-platform** Go CLI — it runs
wherever you diff (your laptop, a CI runner, the monitoring host), not on the
Linux-only simulator host. Three ways to get it:

- **Download a release binary** (recommended). Grab `nl6-reconcile-<os>-<arch>`
  from the [releases](https://github.com/labmonkeys-space/nl6/releases) —
  `linux` / `darwin` / `windows` × `amd64` / `arm64` — then `chmod +x` and put it
  on your `PATH`.
- **`go install`** (any platform with a Go toolchain):

  ```bash
  go install github.com/labmonkeys-space/nl6/go/cmd/nl6-reconcile@latest
  ```

- **From source**: `make reconcile` builds `go/nl6-reconcile`; run it as
  `./go/nl6-reconcile` or copy it onto your `PATH`.

`nl6-reconcile -version` prints the build version (stamped from the same release
tag as the simulator, so a report's `metadata.nl6_version` and the diff tool's
version together pin a reconciliation).

To reconcile **by hand** instead:

1. **Join** the report's `counters[]` (or the [CSV
   projection](./loadtest-report-schema.md#csv-projection)) against your
   monitor's received-counts export **on `(protocol, source_ip, collector)`** —
   the report is keyed by exactly that tuple so the join is 1:1.
2. **Per row**, compute `loss_ratio`. `0` = perfect fidelity. A positive ratio
   localizes to that `source_ip`; a *negative* ratio (received > sent) means
   **duplication** in the path (retransmits, a misconfigured fan-out).
3. **Loss model.** `sent` is the authoritative denominator — it is exact and,
   with a fixed `seed`, reproducible. Any shortfall is real wire/collector
   loss, **not** measurement noise. The simulator proves this: an injected X%
   drop is recovered by this arithmetic within ±1 pp (0 % exactly) — see the
   `examples/scenario-syslog-fidelity` "injecting known loss" section.

### When the numbers don't add up

- **`received` < `sent` but the network is fine** → the collector host is
  dropping datagrams before your monitor counts them. Check the kernel UDP
  drop counters: `nstat -az | grep -i Udp` or
  `cat /proc/net/snmp | grep Udp:` — a rising **`UdpRcvbufErrors`** /
  **`InErrors`** means the receive buffer overflowed under burst. Raise the
  collector's `SO_RCVBUF` (or `net.core.rmem_max`) and re-run; that loss is on
  the collector, not the wire.
- **`received` == 0 despite `sent` > 0** → almost always the collector host's
  **`rp_filter`** dropping `10.42.0.0/16` source IPs (see *Collector
  unreachable* below), not real loss.
- Always confirm the join tuple matches: a mismatched `collector` column means
  you are diffing against the wrong receiver.
- **`sent` far below `informational.requested`** → the shared global cap
  throttled the run: the shortfall is in `informational.deferred` (fires the
  cap had no token for — **not fired, not lost**). Deferral is *not* loss and
  is excluded from `sent` (the loss denominator), so `loss_ratio` stays honest.
  Raise the cap, lower the profile rate, or accept the throttle — but don't
  read it as pipeline loss.

## Validating a collector against the report

For flow scenarios (`netflow5` / `netflow9` / `ipfix`) the report's
[`applications[]`](./loadtest-report-schema.md#applications--fleet-wide-flow-traffic-ground-truth)
block is the trusted-sender ground truth for per-application traffic: total
`bytes` / `packets` / `records` and `avg_bytes_per_second` per
`(l4_proto, dst_port)`. To validate a collector's per-application view
(a "Top Applications" dashboard or equivalent) against it:

1. **Reconcile on totals, not time buckets.** nl6 attributes a flow's bytes
   at the moment its record hits the wire; collectors **interpolate** each
   flow's bytes across its `[flowStart, flowEnd]` interval (shipped-profile
   flow durations run up to 300 s). Per-bucket series will never line up —
   `sub_window_bytes` is a sanity curve, not a reconciliation target.
2. **Pad the collector-side query window** to
   `[t0 − max profile flow duration, t1 + drain]` so interpolated bytes that
   the collector attributes before `t0` are captured. Filter by the
   scenario's exporter IPs (the `counters[].source_ip` set).
3. **Join on `(l4_proto, dst_port)`, not on names.** Collector classification
   is user-configurable; `app_hint` is a convenience label only. Generated
   source ports sit in the IANA dynamic range (≥ 49152), so a collector rule
   matching registered ports on either side of the flow cannot reclassify
   nl6 traffic away from its destination-port application.
4. In **fidelity mode** the fleet is silent outside the window, so the block
   is the *complete* record of what the trusted sender emitted — any
   collector-side surplus is foreign traffic, any deficit is loss or
   misclassification.

`sflow` scenarios have no `applications` rows: sFlow byte volumes are derived
by sampling extrapolation at the collector, which is not comparable to
record-byte totals.

## Clock sync (chrony/NTP) — required for time localization

Reconciliation totals (`sent` vs `received`) need **no** clock agreement — a
counter is a counter. But **time localization** ([`sub_windows`](./loadtest-report-schema.md#loss-localization))
does: nl6 buckets each send by its write-return time relative to `T0`, and to
line your received data up against those buckets you must bucket **your**
records by receive-time relative to the **same** `T0`. If nl6's host and the
collector's host disagree on the wall clock, the two bucketings shear and a
loss that is really in `[T0+30s, T0+45s]` appears smeared across neighbours.

- Run **chrony** (or ntpd) on both the simulator host and every collector host,
  disciplined to the **same** upstream sources. Confirm with `chronyc tracking`
  — keep the estimated offset well under one `sub_window_duration` (a 30 s
  window → 3 s buckets → sub-second sync is ample; tighten for shorter windows).
- The report's `metadata.t0`/`t1` are the simulator's clock. Bucket your
  received records against **that** `t0`, not your own start time.
- Fleet totals and `loss_ratio` are unaffected by skew — only the per-bucket
  `sub_windows` attribution is. If localization looks smeared but totals
  reconcile, suspect clock skew before suspecting the pipeline.

## Troubleshooting arm failures

`arm` never fails wholesale for a bad participant — it accounts for every one of
them in the readiness response and reports up to 900 individually in the
`excluded[]` list as `{device, reason, remediation_hint}` (100 of the 1,000-row
budget is reserved for exclusions found at `start`). Check that list before
`start`.

Above 900 arm-time exclusions the list is a **sample**: `excluded_truncated` is set,
`excluded_total` holds the true count, and `excluded_by_reason` gives the full
`reason → count` breakdown. Read the counts from those, never from
`len(excluded)`. Fix what the sample shows, re-arm, and the next batch surfaces.

| Symptom | Cause | Fix |
|---------|-------|-----|
| `excluded[].reason = "device not found"` | The participant IP is not in the live fleet. | Create the device (`POST /api/v1/devices`) before arming, or remove it from `participants`. |
| `excluded[].reason = "device has no syslog exporter"` | The device exists but syslog export is not enabled on it. | Enable syslog export on the device — the `-syslog-collector` seed flag (auto-start batch) or a per-device `syslog` block in `POST /api/v1/devices`. |
| `excluded[].reason = "device deleted between arm and start"` | The device was deleted in the arm→start gap (before the freeze). | Re-arm after the fleet is stable. |
| `start` → `409 … 0/N participants armed` | Every declared participant was excluded (or, with `participants_cidr` only, no live device matched any prefix — prefix non-matches are silent, so `excluded[]` can be empty). | Fix the exclusions above, or check the prefixes against the fleet's addressing; you cannot start a scenario with no armed devices. |
| `POST /scenarios` → `400 … has host bits set; the canonical form is …` | A `participants_cidr` entry like `10.42.1.5/16` — a host address where a network was meant. | Use the canonical (masked) prefix from the error message, or a `/32` if one address was intended. |
| `POST /scenarios` → `400 … is covered by …; a nested prefix adds nothing` | One prefix contains another (or repeats it). | Remove the narrower prefix — the wider one already selects every address in it. (An explicit `participants` entry inside a prefix is fine: that is the loud-miss assertion form.) |
| `arm` → `409 selectors resolve to N live devices, exceeding the 100000 participant cap` | The prefix selector matched more of the fleet than a scenario may hold. | Narrow the selector or shrink the fleet, then re-arm; a refused re-arm leaves the previous arm intact. |
| Armed count is lower than the prefix "should" match | Addresses inside a prefix with no live device are silently skipped — a typo'd prefix can half-match without any error. | Declare `expect_participants` so the shortfall is refused instead of measured. Without it, compare `participants_armed` against your expected fleet size by hand. |
| `start` → `409 expected N participants, M armed: … nothing was excluded` | The selectors matched fewer live devices than declared, and nothing was rejected — so the shortfall is entirely silent. | Almost always a prefix one bit too narrow (`/19` for `/18`), or a fleet smaller than you think. Check the prefix, then `GET /api/v1/devices` for the real count. |
| `start` → `409 expected N participants, M armed: … see excluded_by_reason` | Devices were found but rejected, so the shortfall has enumerable causes. | Fix what `excluded_by_reason` reports (usually a missing exporter), re-arm, and the count recovers. |
| `start` → `409 expected N participants, M armed: M−N more than declared` | The fleet holds devices your selectors match but your expectation omits. | Either the fleet grew or the expectation is stale. Update `expect_participants` — an over-sized run is refused because it is no longer comparable to the baseline it would be measured against. |
| `POST /scenarios` → `409 too many active scenarios` | 8 scenarios are already non-terminal. | Stop / abort / `DELETE` one first (`GET /api/v1/scenarios` lists them with their phases). |
| `arm` → `409 … participant(s) are claimed by scenario …` | Those devices belong to another non-terminal scenario. A device participates in at most one scenario at a time (FR38). | Stop or delete the named scenario, or narrow this one's participants. Note an **armed** scenario already holds its fleet — it does not have to be running — so cancelling it releases the devices. |
| `start` / `stop` → `409 cannot … in phase …` | Illegal lifecycle transition. | The `409` body names the current phase and the resolving verb; follow the [phase/verb matrix](./loadtest-api.md#phase--verb-matrix). |
| `report` → `409 … available only after stop or abort` | The scenario has not finalized yet. | Stop it (or wait for the window to auto-close at `T1`), then re-request the report. |
| Device create/delete → `409 fleet … frozen by running scenario` | Membership is frozen while a scenario runs, so counter deltas can't be corrupted mid-window. | Wait for the scenario to finish, or stop it. |

### Collector unreachable

If the scenario runs but your monitor receives nothing:

- **`report.send_failures` is high** → nl6 itself could not send (socket bind
  failure, no route). Check the device's configured collector `host:port` and
  that the simulator container can reach it.
- **`report.sent` is high but the collector received 0** → the datagrams left
  nl6 but were dropped en route. The usual culprit is the collector host's
  **reverse-path filter** rejecting UDP with `10.42.0.0/16` source IPs when
  `-syslog-source-per-device=true` (the default). Relax it
  (`net.ipv4.conf.*.rp_filter=0` or `2`) or run with
  `-syslog-source-per-device=false` so datagrams carry the simulator's own
  source IP.
- Confirm the device's collector matches where your monitor listens
  (`counters[].collector` in the report).

## Heartbeat / silence-alert warning

⚠️ **A scenario suppresses the fleet's ordinary background telemetry cadence for
its participants for the entire time it is armed and running.** Before `T0`,
background fires from armed participants are *generation-suppressed*
(`informational.background_suppressed` in the report counts them). This is intentional — it
keeps the measurement window clean — but it means:

- **Silence-based alerts** (heartbeat monitors, "no syslog in N minutes"
  detectors) watching a participant **may fire during a scenario** because the
  device's normal chatter is paused. Schedule fidelity checks in a maintenance
  window, suppress those alerts for the participants, or keep windows short.
- Non-participant devices are unaffected — their background cadence continues.

## Participant cardinality vs. rate

A scenario may name up to **100,000 participants**, which is a *bounds* limit,
not a throughput promise. The two dimensions have separate ceilings and the
interesting one is usually cardinality:

- **Cardinality is what the instrument measures.** The ledger reconciles on
  `(protocol, source_ip, collector)`, and the failure modes a fidelity check
  exists to expose are all per-source: `rp_filter` drops, neighbour-table
  pressure, collector per-agent state, and node cardinality in the monitoring
  system. **Rate cannot substitute for distinct source IPs** — 4,300 devices at
  7/s loads a collector's throughput about like 30,000 at 1/s, but tells you
  nothing about whether the pipeline survives 30,000 agents. (Participants are a
  **set**: a repeated IP is rejected at submit, so cardinality is always the
  number of entries you sent.)
- **Aggregate rate has its own, lower ceiling.** `syslog` and `snmp-trap` fire
  inline on a single scheduler goroutine (one datagram per event), so their
  aggregate throughput is bounded by one core's per-event cost regardless of how
  the per-device rate and participant count are divided. Flow protocols are far
  cheaper per record because v9/IPFIX pack many records per datagram.

  ⚠️ **That ceiling has not been measured.** A per-event cost estimate of
  ~3–5 µs puts it somewhere around 200–350k events/s per subsystem, but this is
  an *estimate from code inspection*, not a benchmark. Treat it as an order of
  magnitude, and measure on your own hardware before designing a run that
  depends on the exact number.

So high-cardinality runs are best driven at **low per-device rates**: 30,000
participants at `rate: 0.5` is a comfortable 15k events/s, while the same fleet
at `rate: 10` asks for 300k/s and will likely be scheduler-bound rather than
collector-bound — measuring nl6 instead of the system under test.

If a `syslog` or `snmp-trap` run's `sent` total comes in low, check these in
order before suspecting the collector:

1. **The arm-time exclusions.** Participants are not existence-checked at submit,
   so the expected total is `participants_armed × rate × window`, not
   `participants × rate × window`. Use `participants_armed` (or
   `excluded_total`) — **not** `len(excluded)`, which is capped (900 arm-time
   rows, 1,000 in the report) and understates the exclusions on a large run. Long participant lists make this
   the most common cause by far.
2. **The scheduler ceiling above**, if the remaining participants × rate is in
   the hundreds of thousands per second.

This arithmetic applies to **`syslog` and `snmp-trap` only** — protocols where
one scheduled fire is one event. Do not apply it to flow protocols: there `rate`
is the flow-*tick* cadence, not an event rate, and the ledger counts flow
**records**. A tick emits however many records expired under the active/inactive
timeouts, which is frequently **zero** at a fast tick cadence, so `sent` bears no
fixed relationship to `participants × rate × window` in either direction. For a
flow run, reconcile the report's `sent` against the collector directly rather
than against a predicted total.

## Graceful abort produces a finalized report

A SIGTERM/SIGINT during a *running* scenario does **not** silently discard the
run. The shutdown path aborts the scenario through the same drain-and-finalize
pipeline a normal stop uses (bounded by the drain grace), so:

- The report is **finalized and marked `phase: "aborted"`**, with `metadata.t0`
  and a `metadata.t1` equal to the **abort instant** (the window that actually
  ran, always earlier than the planned `T1`). `duration` reflects the truncated
  window.
- It is **immutable** and served by `GET /api/v1/scenarios/{id}/report`
  **exactly like a `stopped` report** — same schema, same ledger identity, same
  `counters[]`. Only the `phase` differs.
- The fleet freeze is released as part of the abort, so device CRUD works again.

The catch is timing: the report lives in memory (see the non-goal below), so a
graceful abort finalizes it but the process still exits. **If you need the
abort report, fetch it before the process is fully gone** — or drive the abort
by other means and read the report while nl6 is still up.

**SIGKILL** (or a crash / OOM) makes **no promise** beyond the in-memory-loss
non-goal below: there is no abort pipeline, so no report is produced.

## Non-goal: scenarios are in-memory

**Scenarios do not persist.** The active scenario, its ledger, and its
finalized report live entirely in the simulator process's memory. They do
**not** survive a restart:

- Restarting nl6 (or the container) **discards** any active scenario and any
  finalized-but-not-yet-fetched report. **Fetch the report before restarting.**
- There is no scenario history or store — `GET /api/v1/scenarios/{id}` returns
  `404` for any ID the current process did not allocate, and IDs
  (`s-000001`, …) reset on restart.
- On a graceful shutdown (SIGTERM/SIGINT) a *running* scenario is **aborted**
  first — it finalizes its report (still in-memory) and releases the fleet
  freeze — so the shutdown is clean, but the report is still lost once the
  process exits.

Persistence is a deliberate non-goal for this subsystem: a fidelity check is a
short, operator-driven experiment whose result is consumed immediately (diffed
against a monitor), not an audit log. Capture the report JSON yourself if you
need to keep it.
