<!--
Copyright 2026 Ronny Trommer <ronny@no42.org>
SPDX-License-Identifier: Apache-2.0
-->

# scenario-syslog-fidelity

A self-contained **telemetry-fidelity check**: run a bounded syslog load-test
scenario against a simulated fleet, then diff nl6's exact `sent` count against
what a collector actually received. A zero delta proves the path under test
neither dropped nor duplicated a single event; a non-zero delta localizes the
loss.

This is the reproducible example for the nl6 load-test scenario subsystem — a
third party running it should reproduce the documented known result below.

## What's in the box

| File | Role |
|------|------|
| `compose.yml` | `nl6` (5-device syslog fleet) + `collector` (UDP sink that counts datagrams) |
| `collector.py` | stdlib-only UDP:514 counter with `GET /count` and `POST /reset` |
| `run.sh` | drives one scenario over REST: submit → arm → reset → start → stop → report → **reconcile** |

## Run it

```bash
docker compose up -d --build
./run.sh            # requires curl + jq on the host
```

## The scenario

`run.sh` submits:

```json
{
  "participants": ["10.42.0.1","10.42.0.2","10.42.0.3","10.42.0.4","10.42.0.5"],
  "protocol": "syslog", "rate": 10, "window": "2s", "drain": "500ms", "seed": 42
}
```

5 devices × 10 events/s × a 2 s half-open window ⇒ **100 in-window events**
(20 per device, the fire at exactly T1 excluded). The scenario self-closes at
T1; `run.sh` fetches the report and sums `in_window + drain` per counter row.

## Documented known result

```
==> submit
    scenario s-000001
==> arm
    {"phase":"armed","participants_armed":5,"excluded":[]}
==> reset collector (clears any pre-window background traffic)
==> start
    {"phase":"running"}
==> running the 2 s window ...
==> stop / fetch report
    nl6 report sent = 100
    collector received = 100
==> reconciliation
    PASS: sent == received (100) — zero missed, zero duplicated
```

**The leading indicator is the reconciliation, not the absolute count.** On a
loaded host the scheduler may fire a hair fewer than 100 (real wall-clock
jitter), but `sent == received` holds regardless: both sides count the same
actual fires. The invariant under test is **`sent == received ± 0`**.

### Reading a failure

If `run.sh` reports a delta, the report's per-`(protocol, source_ip, collector)`
counter rows localize it — the `source_ip` whose `sent` exceeds the collector's
share of `received` is the lossy path. `send_failures` and `dropped` in the
report separate "nl6 could not send" from "nl6 sent but the wire lost it".

## How suppression keeps the count clean

Before `start`, the fleet's ordinary background syslog cadence is
**generation-suppressed** for armed participants, so the collector sees no
pre-window traffic from them. `run.sh` still calls `POST /reset` right after
arm as a belt-and-suspenders zero, so the count reflects only `[T0, T1)`
scenario traffic.

## Notes

- `-syslog-source-per-device=false` is set so every datagram shares nl6's
  container source IP — this avoids the `rp_filter` friction that per-device
  10.42.0.0/16 source IPs can cause on the collector host. Flip it to `true`
  (the default) to exercise per-device source binding; you may then need
  `net.ipv4.conf.*.rp_filter=0` or `2` on the collector side.
- `NL6_IMAGE` / `PYTHON_IMAGE` env vars override the images.
