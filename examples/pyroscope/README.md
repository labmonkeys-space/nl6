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

`run.sh` is what verifies the stack.
The `grafana/pyroscope` image ships no shell, `wget` or `curl`, so it cannot carry a compose healthcheck; nl6 starts as soon as the Pyroscope container does, and `run.sh` polls Pyroscope's `/ready` from the host (Pyroscope 2 answers `503` for about a minute after start) and then waits for the profiles.
Uploads that fail while Pyroscope is still booting are counted in `sdk_errors` on `GET /api/v1/profiling` and recover on the next interval.
The subsystem check needs the SNMP read loops to have burned CPU, so poll the fleet if `run.sh` reports no `subsystem=snmp` samples: from a host with a route to `10.42.0.0/16`, `snmpwalk -v2c -c public 10.42.0.1 1.3.6.1.2.1.2`; or, without one, from a sidecar sharing the nl6 container's network namespace:

```bash
docker run -d --rm --name nl6-poller --network container:nl6-pyroscope-nl6-1 alpine:3.20 sh -c \
  'apk add -q net-snmp-tools; while true; do for i in 1 2 3 4 5; do snmpwalk -v2c -c public -t 1 10.42.0.$i 1.3.6.1.2.1.2 >/dev/null 2>&1; done; done'
```

Open `http://localhost:4040`, pick the `nl6` service, and filter by `subsystem`.

## The scrape variant

```bash
docker compose --profile alloy up -d
./run.sh
```

`run.sh` switches nl6 to pull-only (`POST /api/v1/profiling {"enabled":true,"server_address":""}`; an omitted `server_address` would keep the push) before waiting, because the Go runtime allows one CPU profile at a time: while the SDK's CPU collector runs, Alloy's `/debug/pprof/profile` scrape is answered `500`.
The scraped profiles land under `service_name=nl6-interop-scrape`, the name pinned in `alloy-scrape.alloy`.

## Runtime toggle

```bash
curl -s localhost:8080/api/v1/profiling | jq .data                                  # state
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":false}'                                                            # off
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":true,"server_address":"http://pyroscope:4040","duration":"30m"}'  # on, auto-off after 30m
```
