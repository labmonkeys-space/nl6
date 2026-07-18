<!--
Copyright 2026 Ronny Trommer <ronny@no42.org>
SPDX-License-Identifier: Apache-2.0
-->

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

MVP scope: **one active scenario at a time**, **syslog** only.

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

## Reconciliation walkthrough

The instrument's one job is to make loss **measurable**. The arithmetic:

```
sent       = in_window + drain          (per counters[] row, or summed)
received   = your monitor's count for the same (protocol, source_ip, collector)
loss_ratio = (sent − received) / sent
```

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
