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

## Injecting a known loss (accuracy proof)

The whole point of the instrument is that a **known** loss is recovered by the
reconciliation arithmetic. You can demonstrate this on the collector by
dropping a deterministic fraction of inbound UDP and confirming the report
recovers it within ±1 pp.

Drop 5 % of inbound syslog on the collector container:

```bash
# 1-in-20 probabilistic drop on UDP/514 into the collector
docker compose exec collector sh -c \
  "apk add --no-cache iptables >/dev/null 2>&1; \
   iptables -A INPUT -p udp --dport 514 -m statistic --mode nth --every 20 --packet 0 -j DROP"

./run.sh    # now reports a delta

# Reconcile: loss_ratio = (sent − received) / sent  ≈ 0.05  (±1 pp)
# Remove the rule to return to the 0 % control:
docker compose exec collector iptables -D INPUT -p udp --dport 514 \
  -m statistic --mode nth --every 20 --packet 0 -j DROP
```

`--mode nth --every 20` drops exactly every 20th matching packet — a
deterministic 5 %, so the recovered ratio is stable, not noisy. (`iptables
-m statistic` needs `NET_ADMIN`, which the nl6 service already has; add it to
the `collector` service if you run the rule there instead.)

### Rule out collector-side loss first

A shortfall must be **real** loss, not the collector host silently dropping
datagrams under burst. Before trusting a non-zero delta:

- **UDP receive-buffer overflow** — check the kernel drop counters on the
  collector host: `nstat -az | grep -i Udp` or `cat /proc/net/snmp | grep Udp:`.
  A rising **`UdpRcvbufErrors`** means the socket buffer overflowed; raise
  `net.core.rmem_max` / the collector's `SO_RCVBUF` (this example already sets a
  4 MiB buffer in `collector.py`) and re-run.
- **`rp_filter`** — with `-syslog-source-per-device=true` the collector may
  reject `10.42.0.0/16` source IPs; relax `net.ipv4.conf.*.rp_filter` to `0`/`2`
  (this example sidesteps it with `-syslog-source-per-device=false`).

The control (`X = 0`, no rule) must reconcile **exactly** (`sent == received`);
if it doesn't, fix the collector-side loss above before measuring an injected X.

## Notes

- `-syslog-source-per-device=false` is set so every datagram shares nl6's
  container source IP — this avoids the `rp_filter` friction that per-device
  10.42.0.0/16 source IPs can cause on the collector host. Flip it to `true`
  (the default) to exercise per-device source binding; you may then need
  `net.ipv4.conf.*.rp_filter=0` or `2` on the collector side.
- `NL6_IMAGE` / `PYTHON_IMAGE` env vars override the images.
