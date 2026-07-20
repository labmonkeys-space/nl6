# Load-test scenario runbook

This is **the** runbook for the nl6 load-test scenario subsystem — a
telemetry-fidelity instrument. You arm a bounded experiment over a set of
simulated devices, run it for a fixed window, and get back an exact
machine-readable [report](./loadtest-report-schema.md) of what nl6 **sent**.
Diff that against what your monitor **received** and any delta localizes
missed or duplicated telemetry.

Later epics extend this runbook in place (more protocols, richer reports); it
stays the single operator entry point.

- **API reference:** [loadtest-api.md](./loadtest-api.md) — every endpoint,
  request/response shape, and error code.
- **Report schema:** [loadtest-report-schema.md](./loadtest-report-schema.md) —
  every field, the ledger identity, and the semver policy.
- **Runnable example:** `examples/scenario-syslog-fidelity/` — a compose stack
  (nl6 + a counting collector) and a `run.sh` that reproduces a documented
  known result.

Scope: **one active scenario at a time**, over any one of the seven shipped
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
`-fidelity` to any launch command below.

## Worked examples

Each recipe below is complete: how to start nl6 so the target protocol is
exporting, the scenario to submit, and what to read back. They all assume
`NL6=http://localhost:8080`, the [lifecycle](#run-a-fidelity-check) above
(`submit → arm → start → stop → report`), and that every `POST` sends
`Content-Type: application/json`. nl6 runs as root (TUN / network namespace).
For a clean window with no background noise, add [`-fidelity`](#fidelity-mode)
to the launch line.

The scenario **gates an export that already exists** — it never configures the
wire. So each device must have the target protocol's exporter enabled first,
via the seed flags shown (auto-start batch) or a per-device block in
`POST /api/v1/devices`. A device without that exporter lands in the arm
`excluded[]` list, never in the run.

### 1. Fixed-rate syslog fidelity (the baseline)

Prove a syslog pipeline loses nothing at a steady 10 msg/s per device.

```bash
# 3 auto-start devices (10.42.0.1–3), each exporting syslog to your collector.
sudo ./nl6 -auto-start-ip 10.42.0.1 -auto-count 3 -syslog-collector 10.0.0.9:514

ID=$(curl -sf -X POST $NL6/api/v1/scenarios -H 'Content-Type: application/json' -d '{
  "participants": ["10.42.0.1","10.42.0.2","10.42.0.3"],
  "protocol": "syslog", "rate": 10, "window": "30s", "drain": "2s", "seed": 42
}' | jq -r .id)
curl -sf -X POST $NL6/api/v1/scenarios/$ID/arm | jq   # check excluded[] is empty
curl -sf -X POST $NL6/api/v1/scenarios/$ID/start
sleep 33
curl -sf -X POST $NL6/api/v1/scenarios/$ID/stop | jq .summary
```

A `constant` profile is deterministic: `summary.sent` is exactly
`rate × window × devices = 10 × 30 × 3 = 900`. Reconcile that against your
collector; `loss_ratio` should be `0`.

### 2. NetFlow v9 flow-export fidelity

A different protocol — the device needs **flow** export, not syslog.

```bash
sudo ./nl6 -auto-start-ip 10.42.0.1 -auto-count 5 \
  -flow-collector 10.0.0.9:2055 -flow-protocol netflow9

curl -sf -X POST $NL6/api/v1/scenarios -H 'Content-Type: application/json' -d '{
  "participants": ["10.42.0.1","10.42.0.2","10.42.0.3","10.42.0.4","10.42.0.5"],
  "protocol": "netflow9", "rate": 20, "window": "1m", "drain": "5s", "seed": 7
}'
```

Swap `-flow-protocol` (and the scenario `protocol`) for `ipfix`, `sflow`, or
`netflow5` to exercise the others. On a shared collector, isolate the run by
its lever (v9 Source ID, IPFIX ODID, sFlow `sub_agent_id`) — see
[Run tagging](#run-tagging--isolating-experiment-traffic); the report's
`metadata.run_tags` records which one and how.

### 3. Production-shaped ramp + loss localization

Ramp 5 → 200 msg/s over 5 minutes and see **where** loss lands, not just how
much.

```bash
curl -sf -X POST $NL6/api/v1/scenarios -H 'Content-Type: application/json' -d '{
  "participants": ["10.42.0.1"], "protocol": "syslog", "rate": 100, "window": "5m", "seed": 42,
  "rate_profile": { "kind": "linear", "start_rate": 5, "end_rate": 200 }
}'
```

After stop, read `summary.sub_windows` — 10 equal time buckets over the window
(see [Loss localization](./loadtest-report-schema.md#loss-localization)). Loss
concentrated in the **late, high-rate** buckets points at collector overload
under burst rather than steady-state loss. Bucket your collector's received
data the same way (receive-time relative to `metadata.t0`) and diff per bucket.
Try `"kind": "sine"` (`mean_rate`, `amplitude`, `period`) for a cyclic load or
`"kind": "staged"` (`stages: [{duration, rate}, …]`) for step changes.

### 4. Self-aborting experiment (abort predicate)

Stop the run automatically before it floods an unhealthy collector.

```bash
sudo ./nl6 -auto-start-ip 10.42.0.1 -auto-count 2 -trap-collector 10.0.0.9:162

curl -sf -X POST $NL6/api/v1/scenarios -H 'Content-Type: application/json' -d '{
  "participants": ["10.42.0.1","10.42.0.2"], "protocol": "snmp-trap", "rate": 50, "window": "10m", "seed": 1,
  "abort_predicate": { "metric": "send_failures", "threshold": 100, "grace": "5s" }
}'
```

If the fleet-wide `send_failures` stays over `100` for `5s`, the scenario
aborts through the normal drain-and-finalize pipeline and produces an
`aborted` report (`phase: "aborted"`) — same schema, still reconcilable. Watch
`metric` be any of `send_failures` / `dropped` / `deferred` / `sent`.

### 5. Coordinated start across systems (scheduled T0)

Line nl6's window up with a load generator or a monitoring capture window: arm
now, but open the window at a precise absolute `T0`.

```bash
# … submit + arm as usual, then:
curl -sf -X POST $NL6/api/v1/scenarios/$ID/start \
  -H 'Content-Type: application/json' -d '{"at":"2026-07-20T09:00:00Z"}'
```

The scenario stays `armed` (transports connected, **no data on the wire**)
until the RFC3339 `at` instant, then runs its window. A past timestamp is
rejected `400`.

### 6. Diff the report in one command

Skip the manual join — feed the report and your collector's counts to
[`nl6-reconcile`](#nl6-reconcile--one-command-not-a-spreadsheet):

```bash
curl -sf $NL6/api/v1/scenarios/$ID/report > report.json
nl6-reconcile -report report.json -received collector.csv
# exit 1 (and a LOSS / PHANTOM row) if anything is off — drop it into CI.
```

### 7. IPFIX-only fidelity

IPFIX carries the cleanest run-isolation lever — the Observation Domain ID —
and, unlike NetFlow v9, its **data-record sequence legitimately starts at 0 at
T0** (templates are counted separately), so a collector sees no pre-window
sequence advance.

```bash
# -fidelity keeps the 5 devices silent until the scenario window opens, so the
# collector sees IPFIX only for [T0,T1) — no startup or post-run background.
sudo ./nl6 -fidelity -auto-start-ip 10.42.0.1 -auto-count 5 \
  -flow-collector 10.0.0.9:4739 -flow-protocol ipfix

curl -sf -X POST $NL6/api/v1/scenarios -H 'Content-Type: application/json' -d '{
  "participants": ["10.42.0.1","10.42.0.2","10.42.0.3","10.42.0.4","10.42.0.5"],
  "protocol": "ipfix", "rate": 20, "window": "1m", "drain": "5s", "seed": 7
}'
```

Reconcile per `metadata.run_tags` (mechanism `ipfix_odid`): filter the
collector's records by each device's Observation Domain ID within `[T0,T1)`.

### 8. Mixed flow-protocol fleet (20% v5 / 20% v9 / 60% IPFIX)

A scenario targets **one protocol** (MVP: one active scenario at a time), so a
mixed fleet is measured with **one scenario per protocol** over that protocol's
device subset, run **back-to-back**. The 20 / 20 / 60 split is just how many
devices you configure for each protocol. Seed flags apply a single protocol to
the whole auto-start batch, so build the mix with per-device `flow` blocks
instead.

With nl6 running (no flow seed flags needed), create the three groups — here a
10-device fleet split 2 / 2 / 6:

```bash
# start_ip  count  protocol  collector
for grp in \
  '10.0.2.1 2 netflow5 10.0.0.9:2055' \
  '10.0.3.1 2 netflow9 10.0.0.9:2055' \
  '10.0.4.1 6 ipfix    10.0.0.9:4739'; do
  set -- $grp
  curl -sf -X POST $NL6/api/v1/devices -H 'Content-Type: application/json' -d "{
    \"start_ip\": \"$1\", \"device_count\": $2,
    \"flow\": { \"collector\": \"$4\", \"protocol\": \"$3\" }
  }"
done
```

Then run one scenario per protocol, in sequence — each finalizes before the
next submits (a terminal scenario is transparently replaced, so the single
active slot is free):

```bash
run() { # $1=protocol  $2=participants-csv
  ID=$(curl -sf -X POST $NL6/api/v1/scenarios -H 'Content-Type: application/json' -d "{
    \"participants\": [$2], \"protocol\": \"$1\", \"rate\": 20, \"window\": \"1m\", \"drain\": \"5s\", \"seed\": 7
  }" | jq -r .id)
  curl -sf -X POST $NL6/api/v1/scenarios/$ID/arm   >/dev/null
  curl -sf -X POST $NL6/api/v1/scenarios/$ID/start >/dev/null
  sleep 66   # window + drain
  curl -sf -X POST $NL6/api/v1/scenarios/$ID/stop > "report-$1.json"
}
run netflow5 '"10.0.2.1","10.0.2.2"'
run netflow9 '"10.0.3.1","10.0.3.2"'
run ipfix    '"10.0.4.1","10.0.4.2","10.0.4.3","10.0.4.4","10.0.4.5","10.0.4.6"'
```

Each run produces its own report keyed by `(protocol, source_ip, collector)`;
reconcile the three independently (`nl6-reconcile -report report-ipfix.json …`
per protocol). The fleet exports all three protocols the whole time — a
scenario just measures one subset's window at a time. To weight the mix by
**traffic** rather than device count, keep the device split and give each
protocol's scenario a proportional `rate`.

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
in-flight tolerance band. Build it with `make reconcile` (→ `go/nl6-reconcile`).

```bash
# Report as JSON (or CSV via ?format=csv); received as a collector CSV export.
curl -sf $NL6/api/v1/scenarios/$ID/report > report.json

nl6-reconcile -report report.json -received collector.csv
# PROTOCOL  SOURCE_IP   COLLECTOR     SENT  RECEIVED  DELTA  LOSS%   STATUS
# syslog    10.42.0.1   10.0.0.9:514  1000  1000      0      0.00%   OK
# syslog    10.42.0.2   10.0.0.9:514  1000  950       50     5.00%   LOSS
#
# Summary: 2 keys | 1 OK | 1 flagged | tolerance 0.50% | sent=2000 received=1950 fleet_loss=2.50%
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
- **Statuses.** `OK` · `LOSS` (received < sent) · `DUP` (received > sent —
  duplication) · `MISSING` (in the report, no received row — total loss or a
  join gap) · `PHANTOM` (received but not in the report — background noise leaked
  into your export; see the run-tagging notes to isolate it).
- **Exit code.** `0` when every key is `OK`, `1` when any key is flagged — so
  `nl6-reconcile` drops straight into a CI gate. Use `-format csv|json` for a
  machine-readable diff.

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

`arm` never fails wholesale for a bad participant — it reports each one in the
readiness `excluded[]` list as `{device, reason, remediation_hint}`. Check that
list before `start`.

| Symptom | Cause | Fix |
|---------|-------|-----|
| `excluded[].reason = "device not found"` | The participant IP is not in the live fleet. | Create the device (`POST /api/v1/devices`) before arming, or remove it from `participants`. |
| `excluded[].reason = "device has no syslog exporter"` | The device exists but syslog export is not enabled on it. | Enable syslog export on the device — the `-syslog-collector` seed flag (auto-start batch) or a per-device `syslog` block in `POST /api/v1/devices`. |
| `excluded[].reason = "device deleted between arm and start"` | The device was deleted in the arm→start gap (before the freeze). | Re-arm after the fleet is stable. |
| `start` → `409 … 0/N participants armed` | Every declared participant was excluded. | Fix the exclusions above; you cannot start a scenario with no armed devices. |
| `POST /scenarios` → `409 a scenario is already active` | Another scenario is still non-terminal (MVP allows one). | Stop / abort / `DELETE` the active scenario first (`GET /api/v1/scenarios/{id}` to see its phase). |
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

## Graceful abort produces a finalized report (FR14)

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

## Non-goal: scenarios are in-memory (FR42)

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
