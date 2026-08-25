# Runbooks

Worked, copy-pasteable recipes — one per use case. Each is complete: how to
start nl6 so the target protocol is exporting, the scenario to submit, and what
to read back. They build on the operating guide: the
[lifecycle](./loadtest-scenarios.md#run-a-fidelity-check) and
[fidelity mode](./loadtest-scenarios.md#fidelity-mode). All assume
`NL6=http://localhost:8080`, that every `POST` sends
`Content-Type: application/json`, and that nl6 runs as root (TUN / network
namespace). For a clean window with no background noise, add
[`-fidelity`](./loadtest-scenarios.md#fidelity-mode) to the launch line.

> **A long per-device `interval` will not silence a fleet.** The per-device
> `interval` / `tick_interval` fields are accepted, echoed back by
> `GET /api/v1/devices`, and **not honored**
> ([nl6#445](https://github.com/labmonkeys-space/nl6/issues/445)): every device
> fires at the simulator-wide `-syslog-interval` / `-trap-interval` cadence
> regardless. Setting `"interval": "24h"` on 500 devices leaves ~50 events/s of
> background running, which is enough to contaminate an accept-rate measurement
> while every surface reports success. `-fidelity` is the supported way. Set it
> at launch, or toggle it at runtime with `POST /api/v1/fidelity` (optional
> `duration` auto-reverts, capped at 24h), which is what you want when
> bracketing a measurement on a fleet you do not wish to rebuild.
> `GET /api/v1/fidelity` reports the value in force alongside the startup flag,
> because once the value is mutable the flag is only a default.

A scenario **gates an export that already exists** — it never configures the
wire. So each device must have the target protocol's exporter enabled first, via
the seed flags shown (auto-start batch) or a per-device block in
`POST /api/v1/devices`. A device without that exporter lands in the arm
`excluded[]` list, never in the run.

| # | Use this when you want to… | Protocol |
|---|-----------------------------|----------|
| [1](#1-fixed-rate-syslog-fidelity-the-baseline) | prove a pipeline loses nothing at a steady rate | syslog |
| [2](#2-netflow-v9-flow-export-fidelity) | check a flow-export pipeline | NetFlow v9 |
| [3](#3-production-shaped-ramp--loss-localization) | see *where* loss lands under ramping load | syslog + rate profile |
| [4](#4-self-aborting-experiment-abort-predicate) | stop a bad run before it floods a collector | SNMP trap |
| [5](#5-coordinated-start-across-systems-scheduled-t0) | line the window up with an external capture | any |
| [6](#6-diff-the-report-in-one-command) | diff the report against received counts in CI | any |
| [7](#7-ipfix-only-fidelity) | a clean IPFIX-only run | IPFIX |
| [8](#8-mixed-flow-protocol-fleet-20-v5--20-v9--60-ipfix) | measure a mixed-protocol fleet | NetFlow v5/v9 + IPFIX |

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
  "protocol": "netflow9", "rate": 4, "window": "1m", "drain": "5s", "seed": 7
}'
```

Swap `-flow-protocol` (and the scenario `protocol`) for `ipfix`, `sflow`, or
`netflow5` to exercise the others. On a shared collector, isolate the run by
its lever (v9 Source ID, IPFIX ODID, sFlow `sub_agent_id`) — see
[Run tagging](./loadtest-scenarios.md#run-tagging--isolating-experiment-traffic);
the report's `metadata.run_tags` records which one and how.

### 3. Production-shaped ramp + loss localization

Ramp 5 → 200 msg/s over 5 minutes and see **where** loss lands, not just how
much.

> **Flow rate is per device and capped.** Flow protocols are paced by sizing each
> device's flow cache, which bounds the per-device rate at roughly 8.1–9.2 records/s
> at the default 5s tick (lower on a longer one).
> A rate above a participant's ceiling excludes it at arm. Earlier revisions of this
> runbook used `"rate": 20`, which every shipped profile now refuses. Scale a run
> with participants rather than per-device rate.

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
[`nl6-reconcile`](./loadtest-scenarios.md#nl6-reconcile--one-command-not-a-spreadsheet):

```bash
curl -sf $NL6/api/v1/scenarios/$ID/report > report.json
nl6-reconcile -report report.json -received collector.csv
# exit 1 (and a RESIDUAL / PHANTOM row) if anything is off — drop it into CI.

# A shortfall is RESIDUAL until you assert the collector's queue has drained.
# Backlog resolves itself; loss does not. Re-run once the queue is empty:
nl6-reconcile -report report.json -received collector.csv -drained
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
  "protocol": "ipfix", "rate": 4, "window": "1m", "drain": "5s", "seed": 7
}'
```

Reconcile per `metadata.run_tags` (mechanism `ipfix_odid`): filter the
collector's records by each device's Observation Domain ID within `[T0,T1)`.

### 8. Mixed flow-protocol fleet (20% v5 / 20% v9 / 60% IPFIX)

A scenario targets **one protocol** (one active scenario at a time), so a
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
