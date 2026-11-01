---
sidebar_label: "Profiling"
description: "Switch on continuous profiling with a Grafana Pyroscope push or an Alloy pprof scrape, at startup or at runtime, and switch it off again."
---

# Profile the simulator

nl6 can profile itself continuously with [Grafana Pyroscope](https://grafana.com/oss/pyroscope/), and it can serve the standard Go `net/http/pprof` surface for a [Grafana Alloy](https://grafana.com/docs/alloy/latest/) scrape.
Both sit behind one gate that is **off by default**.
With no flag and no `POST /api/v1/profiling`, no profiler goroutine exists, no outbound connection is made, and every path under `/debug/pprof/` answers `503` with the remedy in the body.

The gate is runtime-switchable in the same shape as [fidelity mode](../reference/web-api.md#fidelity-mode): a `POST` changes it without a restart, an optional `duration` reverts it, and `GET` reports the value in force beside the startup flag.

## What is served

| Surface | When | What |
|---------|------|------|
| Push (SDK) | gate open **and** a `server_address` | CPU, goroutines, `alloc_objects`, `alloc_space`, `inuse_objects`, `inuse_space`, uploaded every 15 s under `service_name=nl6` with tags `version=<nl6 version>` and `hostname=<os.Hostname>` |
| Pull (`/debug/pprof/`) | gate open | `net/http/pprof`'s index, `profile`, `symbol`, `trace`, the named runtime profiles (`heap`, `allocs`, `goroutine`, `threadcreate`, `block`, `mutex`), and `godeltaprof`'s `delta_heap`, `delta_block`, `delta_mutex` |

Mutex and block profiles are served but **empty**: nl6 does not set `runtime.SetMutexProfileFraction` or `runtime.SetBlockProfileRate`, because their cost has not been measured.

The pull surface is mounted on the root router, not under `/api/v1`, so Alloy's default `pyroscope.scrape` paths resolve without configuration.
`/debug/pprof/cmdline` is deliberately not served: it prints the process arguments, which carry `-profiling-pyroscope-basic-auth`, and Alloy never scrapes it.
`/debug/pprof` without the trailing slash redirects onto the gated prefix.
`profile?seconds=N` and `trace?seconds=N` are refused by `net/http/pprof` when `N` reaches the HTTP server's 30 s `WriteTimeout`, so Alloy's `delta_profiling_duration` (14 s by default) must stay under it.
A `trace` records every scheduling event and costs far more than the sampled profiles, so keep its `seconds` short.

## The gate

```bash
# boot with the push on
nl6 -profiling-pyroscope http://pyroscope:4040

# state: the value in force AND the startup flag
curl -s localhost:8080/api/v1/profiling | jq .data
```

```json
{
  "enabled": true,
  "startup_flag": "http://pyroscope:4040",
  "server_address": "http://pyroscope:4040",
  "pushing": true,
  "pprof_path": "/debug/pprof/",
  "revert_pending": false
}
```

```bash
# runtime on, pushing to an address learned at runtime
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":true,"server_address":"http://pyroscope:4040"}'

# runtime on, PULL-ONLY: /debug/pprof/ served, nothing pushed (the explicit
# empty server_address; omitted, it would keep a running push or use the flag)
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":true,"server_address":""}'

# on for 30 minutes, then back to whatever it was
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":true,"server_address":"http://pyroscope:4040","duration":"30m"}'

# off: the SDK flushes its last profiles (bounded, 20 s) before the response is written
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":false}'
```

### The request

The request fields and status codes are in [Web API → Continuous profiling](../reference/web-api.md#continuous-profiling).
A `server_address` on an `enabled:false` request is refused rather than ignored, because validated-then-ignored is worse than refused.

`server_address` has three shapes:

| Shape | Effect |
|---|---|
| omitted | Keeps the address in force if a push is running, else uses the startup flag's, else pull-only. A bare `{"enabled":true,"duration":"30m"}` on a pushing process therefore keeps pushing. |
| `""` | Pull-only, even when the flag is set. This is the only way to reach pull-only on a process booted with `-profiling-pyroscope`. |
| a value | Re-targets. The same address twice is a no-op; a different one stops the old push and starts a new one. |

A push the SDK refuses to start answers `500` with the state attached; the pull surface still serves.

`duration` is a Go duration such as `30m`.
It must be positive and at most `24h`; a longer one is refused with `400`.
A `duration` revert restores the gate and the push address together, following the same chain rule as [fidelity mode](../reference/web-api.md#fidelity-mode).
While a revert is pending, `GET` reports it in four fields:

| Field | Meaning |
|---|---|
| `revert_pending` | `true` while a `duration` revert is scheduled. Always present. |
| `revert_at` | When the revert fires, RFC 3339 in UTC. Omitted when nothing is pending. |
| `revert_to` | The gate value the revert restores. This is the value before the first timed request of a chain, so it cannot be inferred from `enabled`. Omitted when nothing is pending. |
| `revert_to_address` | The push address the revert restores with it. Empty when the restored state is pull-only or off. |

### What the status means

`pushing:true` means the SDK is running, not that uploads succeed.
`pyroscope.Start` never touches the network, so a collector that is down, answers `401` or rejects the tenant is invisible to it.
Every error the SDK reports (a failed upload, a refused CPU collector, a full upload queue) shows on `GET` as `sdk_errors`, a count for the current push, and `last_error`.
It is logged once per push, on the first occurrence: `[profiling] push to ... failing`.

### Switch profiling off

Off first asks the SDK to flush (a final CPU and heap snapshot, then the queued uploads) and then stops it; `Profiler.Stop` alone uploads nothing.
The flush is bounded by two upload timeouts (20 s).
Past that it is abandoned with a log line and the last profiles may not have reached the collector.
`GET` never waits behind it.

### Credentials

Basic auth (`-profiling-pyroscope-basic-auth user:pass`, both parts required) and the tenant (`-profiling-pyroscope-tenant`) are flag-only, because `GET` echoes everything REST can set.
Both require `-profiling-pyroscope` and are refused at startup without it.

They are bound to the flag's address, compared normalised (scheme and host case-insensitive, trailing slash ignored).
A `server_address` supplied over REST that differs from the flag is pushed to without them, and the transition log says `credentials withheld: address differs from -profiling-pyroscope`.
Otherwise an unauthenticated `POST` could redirect the operator's credentials, and the profiles, to any host.
A Go heap profile carries allocation sites and sizes, not object contents; a CPU profile carries stack traces.

### Refused inputs

- An address that embeds credentials (`http://user:pass@host`): it would be echoed by `GET` and the logs.
- An address with a query or a fragment: the SDK appends `/ingest` and mangles it.
- `PYROSCOPE_ADHOC_SERVER_ADDRESS` in the environment: the SDK would silently push there instead of to the address nl6 was told. Refused at startup when `-profiling-pyroscope` is set, otherwise at the start of a runtime push (`500`, `last_error`, one log line), so a process that never profiles is not stopped by an unrelated tool's environment.

### Threat statement

`POST /api/v1/profiling` and `/debug/pprof/` are exactly as unauthenticated as the rest of the REST API.
Anyone who can reach `-port` can start CPU sampling and a forced GC every 15 s, or a 30 s execution trace, and can read every profile.
nl6 is a lab tool; the scope is stated in [`SECURITY.md`](https://github.com/labmonkeys-space/nl6/blob/main/SECURITY.md), and the gate is off by default for that reason.
The basic-auth flag value is visible to every local user through the process arguments (`/proc/<pid>/cmdline`, `docker inspect`, shell history).
There is no file or environment form.

## The CPU-contention rule

The Go runtime allows **one CPU profile at a time**.
While the SDK's CPU collector runs, a scrape of `/debug/pprof/profile` is answered `500` by `net/http/pprof` ("cpu profiling already in use").
That is deliberate: masking it would hand Alloy an empty profile that looks like an idle process.
To scrape CPU with Alloy, open the gate **pull-only** (`"server_address":""`); the heap, goroutine and delta paths are unaffected either way.

## Subsystem labels

Every profile carries a `subsystem` pprof label with one of `snmp`, `trap`, `syslog`, `flow`, `gnmi`, `gnmi-dialout`, `scenario`.
In Pyroscope, filter with `{service_name="nl6",subsystem="trap"}`.
A long-lived goroutine (the SNMP read loop, the trap INFORM loops, the syslog TCP reconnect loop, the gNMI dial-out loop and the two flow tickers) is labelled once at birth.
A trap or syslog fire, a flow tick, a gNMI `Get` or `Subscribe`, and a scenario start or finish are labelled for the call's duration.
A trap or syslog fire is always labelled `trap` or `syslog`, even when a scenario started it.

**What "off by default pays nothing" means.** The labels are set whether or not profiling is on.
They cost about 3 allocations and 104 bytes per trap or syslog fire.
Everything else, the SDK, its goroutines, the forced GC, the upload connection, and the pull handlers, exists only while the gate is open.
The feature opens no listener of its own.

## Scrape with Alloy

[`examples/pyroscope/alloy-scrape.alloy`](https://github.com/labmonkeys-space/nl6/tree/main/examples/pyroscope) is Alloy's unmodified default `pyroscope.scrape` profiling block plus the three `godeltaprof` endpoints.
Simplified here (the file reads its target and the Pyroscope URL from `NL6_SCRAPE_TARGET` and `PYROSCOPE_URL`, defaulting to `127.0.0.1:18080` and `http://127.0.0.1:4040`, and labels the scraped profiles `service_name=nl6-interop-scrape`):

```alloy
pyroscope.scrape "nl6" {
  targets    = [{ "__address__" = "127.0.0.1:18080", "service_name" = "nl6-interop-scrape" }]
  forward_to = [pyroscope.write.local.receiver]

  profiling_config {
    profile.godeltaprof_memory { enabled = true }
    profile.godeltaprof_mutex  { enabled = true }
    profile.godeltaprof_block  { enabled = true }
  }
}
```

The shipped file keeps the cumulative `memory`, `mutex` and `block` scrapes **on**, deliberately: the interop test's claim is that Grafana's unmodified default block works against nl6, and disabling them would test a modified one.
In production, disable them when the delta variants are on, so each profile is stored once:

```alloy
  profiling_config {
    profile.memory             { enabled = false }
    profile.mutex              { enabled = false }
    profile.block              { enabled = false }
    profile.godeltaprof_memory { enabled = true }
    profile.godeltaprof_mutex  { enabled = true }
    profile.godeltaprof_block  { enabled = true }
  }
```

`make test-interop-pyroscope` runs this exact file against real `grafana/pyroscope` and `grafana/alloy` containers in CI.

**Do pprof labels survive an Alloy scrape?** Yes.
A pprof label is a sample label inside the pprof body, so a scrape carries it exactly as a push does.

## The forced-GC default, measured

Before each heap snapshot the SDK forces a `runtime.GC()` if no collection ran during the upload interval, so the heap profile is fresh.
`-profiling-force-gc` controls it (`false` sets the SDK's `DisableGCRuns`).
The default is `true` because one forced GC, extrapolated to 30,000 devices, stays under 150 ms (1% of one core per 15 s upload window).

| N devices | live heap | ms per `runtime.GC()` (3 runs of `-benchtime=5x`) |
|-----------|-----------|----------------------------------------------------|
| 1000 | 16.7 MiB | 1.0, 1.0, 1.5 |
| 5000 | 78.5 MiB | 4.3, 4.8, 5.8 |

Linear from the N=5000 median (4.8 ms): **~29 ms at 30,000 devices**.
The devices in this measurement have no sockets, TUN interfaces or namespace, so a real fleet's heap is larger and its GC slower.
If a forced GC on your fleet approaches 150 ms, run with `-profiling-force-gc=false`.

## Web console

The console's "heap profile" and "CPU profile" buttons fetch `/debug/pprof/heap` and `/debug/pprof/profile?seconds=5`.
With the gate closed they show the server's `503` message instead of a silent empty download.
