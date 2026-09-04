<!--
Copyright 2026 Ronny Trommer <ronny@no42.org>
SPDX-License-Identifier: Apache-2.0
-->

# pyroscope

Continuous profiling of a live nl6 fleet with [Grafana Pyroscope](https://grafana.com/oss/pyroscope/).
nl6 pushes CPU, goroutine and heap profiles through the `pyroscope-go` SDK, and every profile carries a `subsystem` label (`snmp`, `trap`, `syslog`, `flow`, `gnmi`, `gnmi-dialout`, `scenario`) so cost can be attributed to a subsystem.

Profiling is **off by default** in nl6.
This directory is the only place in the repository that sets `-profiling-pyroscope`; the shipped `compose.yml`, the Helm chart and the systemd unit do not.
See [docs/ops/profiling.md](../../docs/ops/profiling.md) for the full reference.

## What's in the box

| File | Role |
|------|------|
| `compose.yml` | `nl6` (50-device fleet, pushing) + `pyroscope` + optional `alloy` scraper (`--profile alloy`) |
| `alloy-scrape.alloy` | Alloy's default `pyroscope.scrape` block plus the three `godeltaprof` endpoints; also what `make test-interop-pyroscope` runs |
| `run.sh` | waits for profiles to arrive and checks the `subsystem` label is filterable |

## Run it

```bash
docker compose up -d
./run.sh            # requires curl + jq on the host
```

Open `http://localhost:4040`, pick the `nl6` service, and filter by `subsystem`.

## The scrape variant

```bash
docker compose --profile alloy up -d
./run.sh
```

`run.sh` switches nl6 to pull-only (`POST /api/v1/profiling {"enabled":true}` with no `server_address`) before waiting, because the Go runtime allows one CPU profile at a time: while the SDK's CPU collector runs, Alloy's `/debug/pprof/profile` scrape is answered `500`.
The scraped profiles land under `service_name=nl6-interop-scrape`, the name pinned in `alloy-scrape.alloy`.

## Runtime toggle

```bash
curl -s localhost:8080/api/v1/profiling | jq .data                                  # state
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":false}'                                                            # off
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":true,"server_address":"http://pyroscope:4040","duration":"30m"}'  # on, auto-off after 30m
```
