# Continuous profiling

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
A test pins both at 0 across an on/off/on cycle, so a change that sets them has to restore them on stop.

The pull surface is mounted on the root router, not under `/api/v1`, so Alloy's default `pyroscope.scrape` paths resolve without configuration.
`/debug/pprof/cmdline` is deliberately not served: it prints the process arguments, which carry `-profiling-pyroscope-basic-auth`, and Alloy never scrapes it.
`/debug/pprof` without the trailing slash redirects onto the gated prefix.

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

# runtime on, PULL-ONLY: /debug/pprof/ served, nothing pushed
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":true}'

# on for 30 minutes, then back to whatever it was
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":true,"server_address":"http://pyroscope:4040","duration":"30m"}'

# off: the SDK flushes its last upload before the response is written
curl -s -X POST localhost:8080/api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled":false}'
```

`enabled` is required; a body without it is a `400`, and so is a `server_address` on an `enabled:false` request (validated-then-ignored is the nl6#445 family).
A bare `{"enabled":true}` pushes to the startup flag's address when there is one and is pull-only otherwise.
The same address twice is a no-op; a different address stops the old push and starts a new one.
A push that cannot start (the SDK refuses the address) answers `500` with the state attached: `enabled:true`, `pushing:false`, and `last_error`, and the pull surface still serves.
`pushing:true` means the SDK is **running**, not that uploads succeed: `pyroscope.Start` never touches the network, so a collector that is down, answers `401`, or rejects the tenant is invisible to it.
Those failures show as `upload_failures` (a count for the current push) and `last_error` on `GET`, and as **one** log line per push (`[profiling] push to ... failing`), the first occurrence only.
Switching off flushes the last upload before the response is written, bounded by the 10 s upload timeout; `GET` never waits behind that flush.
Basic auth (`-profiling-pyroscope-basic-auth user:pass`, both parts required) and the tenant (`-profiling-pyroscope-tenant`) are flag-only, because `GET` echoes everything REST can set.
They are also **bound to the flag's address**: a `server_address` supplied over REST that differs from `-profiling-pyroscope` is pushed to without them, and the transition log says `credentials withheld: address differs from -profiling-pyroscope`.
Otherwise an unauthenticated `POST` could redirect heap profiles plus the operator's credentials to any host.
An address that embeds credentials (`http://user:pass@host`) is refused everywhere, because it would be echoed by `GET` and the logs.
nl6 refuses to start while `PYROSCOPE_ADHOC_SERVER_ADDRESS` is set, because the SDK would silently push there instead of to the flag.

## The CPU-contention rule

The Go runtime allows **one CPU profile at a time**.
While the SDK's CPU collector runs, a scrape of `/debug/pprof/profile` is answered `500` by `net/http/pprof` ("cpu profiling already in use").
That is deliberate: masking it would hand Alloy an empty profile that looks like an idle process.
To scrape CPU with Alloy, open the gate **pull-only** (no `server_address`); the heap, goroutine and delta paths are unaffected either way.

## Subsystem labels

Every profile carries a `subsystem` pprof label with one of `snmp`, `trap`, `syslog`, `flow`, `gnmi`, `gnmi-dialout`, `scenario`, set at each subsystem's funnel: once at goroutine birth for the per-device SNMP read loop and gNMI dial-out loop and the scenario flow ticker, and through `pprof.Do` per fire on the shared trap and syslog schedulers, per tick on the flow ticker, per RPC on gNMI `Get` and `Subscribe`, and around a scenario start and finish.
In Pyroscope, filter with `{service_name="nl6",subsystem="trap"}`.
Labels nest by the runtime's rule: `pprof.Do` restores the labels of the context it was given, so a goroutine labelled at birth keeps its label across a funnel because it hands the funnel its birth context (the scenario ticker carries `scenario` between ticks and `flow` inside one).
A label merely **inherited** by a goroutine, such as the scenario scheduler spawned under a scenario start, does not survive a trap or syslog funnel, by design: those fires are trap and syslog work.
The interop test proves that a label set through the funnel helper reaches Pyroscope and is filterable, over both the push and the Alloy scrape; the seven shipped funnels are each pinned in-process by a `TestProfilingLabel_*` test.

**What "off by default pays nothing" means.**
The labels are set whether or not profiling is on.
A goroutine label is a pointer swap set once per long-lived goroutine; `pprof.Do` on a shared scheduler goroutine allocates one small map per fire: measured on `BenchmarkSyslogExporterFire` (Apple M1 Max, 3 runs) as 22 to 25 allocs, 2661 to 2765 B and about 4% wall time per fire.
Re-labelling live goroutines on toggle would need every long-lived loop to poll the gate, which costs more than the label, so that cost is paid unconditionally and this sentence is the disclosure.
Everything else, the SDK, its goroutines, the forced GC, the upload connection, and the pull handlers, exists only while the gate is open.
The feature opens no listener of its own by construction: the two files that implement it never call anything that opens a socket, and a test scans them for that.

## Alloy scrape

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

The default block also scrapes the cumulative `memory`, `mutex` and `block` paths; Grafana's docs suggest disabling those when the delta variants are on, to avoid storing both.
`make test-interop-pyroscope` runs this exact file against real `grafana/pyroscope` and `grafana/alloy` containers and asserts, through Pyroscope's query API, that the pushed CPU and `alloc_space` profiles and the scraped `process_cpu` and `goroutine` series arrive, that the `subsystem` label filters on both the pushed and the scraped service, and that a `service_name` nothing pushed under returns nothing (the control without which the other rows prove reachability, not ingestion).
It is a CI gate.

**Do pprof labels survive an Alloy scrape?**
Yes.
A pprof label is a sample label inside the pprof body, so a scrape carries it exactly as a push does; the interop test's second row runs a labelled CPU burn while Alloy scrapes and requires `{service_name="nl6-interop-scrape",subsystem="interop-probe"}` to return ticks and a bogus label to return none.

## The forced-GC default, measured

Before each heap snapshot the SDK forces a `runtime.GC()` if no collection ran during the upload interval, so the heap profile is fresh.
`-profiling-force-gc` controls it (`false` sets the SDK's `DisableGCRuns`).
Its default was **set from a measurement, not chosen**, by a rule registered before the number was known: run `BenchmarkForcedGCOnFleetHeap`; if one `runtime.GC()` on a heap built from N=5000 TUN-less devices, extrapolated linearly to 30,000, exceeds 150 ms (1% of one core per 15 s upload window), default `false`; otherwise default `true`.

| N devices | live heap | ms per `runtime.GC()` (3 runs of `-benchtime=5x`) |
|-----------|-----------|----------------------------------------------------|
| 1000 | 16.7 MiB | 1.0, 1.0, 1.5 |
| 5000 | 78.5 MiB | 4.3, 4.8, 5.8 |

Linear from the N=5000 median (4.8 ms): **~29 ms at 30,000 devices**, ~35 ms from the worst run.
Machine: Apple M1 Max, darwin/arm64, Go 1.27.0, `asr9k` profile, `cd go && go test ./nl6/ -run '^$' -bench BenchmarkForcedGCOnFleetHeap -benchtime=5x -count=3`.
Under the 150 ms line by a factor of five, so **the default is `true`** (the SDK default), and `simulator.go`'s flag default reads from the same constant.

This is an **in-process proxy**.
The benchmark's devices carry their value engines and resource pointers but no sockets, TUN interfaces or namespace, so a real 30,000-device fleet's heap is larger and its GC slower than the extrapolation.
The fleet-scale measurement on the Ubuntu VM is listed under [Follow-ups](#follow-ups); if it crosses the line, flip the constant and this table.

## Go version coupling

`godeltaprof` forks `runtime/pprof` internals and reaches into the runtime with `go:linkname`.
It has broken on Go major releases before (pyroscope-go issues #38 and #103).
`github.com/grafana/pyroscope-go/godeltaprof` is pinned to the newest tag that declares support for the Go version in `go.mod` (`v0.1.12` carries a `go1.27` build file).
**When bumping Go**: check that a `godeltaprof` tag declares the new major before bumping `go.mod`, then rebuild with `CGO_ENABLED=0 GOOS=linux` (the Dockerfile's shape).
If no tag does, the Go bump waits; do not pin an older Go and do not vendor a fork.

## Web console

The console's "heap profile" and "CPU profile" buttons fetch `/debug/pprof/heap` and `/debug/pprof/profile?seconds=5`.
With the gate closed they show the server's `503` message instead of a silent empty download.

## Not built, by decision

- No eBPF profiling (`pyroscope.ebpf`, a privileged Alloy sidecar). It is the only way to get kernel frames and off-CPU time, it is CPU-only and blind to goroutines, and Grafana's own pages disagree on its kernel floor (4.9 versus 5.10). See [Follow-ups](#follow-ups).
- No span profiles or OpenTelemetry bridge.
- No mTLS or CA pinning for the push; the address is a plain `http://` or `https://` URL.

## Follow-ups

- **Fleet-scale forced-GC measurement.** The `-profiling-force-gc` default rests on an in-process proxy (N=5000 TUN-free devices, ~29 ms extrapolated to 30,000). A real fleet's heap also holds sockets, buffers, TUN and namespace state. Time one forced `runtime.GC()` on the Ubuntu VM with 30,000 real devices against the 150 ms rule, and watch the SDK's 15 s cadence under load. If it crosses the line, flip `profilingForceGCDefault` and the table above.
- **Mutex and block profile rates.** Served but empty until `runtime.SetMutexProfileFraction` / `SetBlockProfileRate` have a measured cost. `TestProfilingRuntimeGlobalsStayZero` pins them at 0, so setting them is a decision with a test to change.
- **eBPF for kernel frames and off-CPU time.** The only thing `pyroscope.ebpf` offers that the SDK cannot. Revisit only if a question needs kernel frames; it is CPU-only, blind to goroutines and to the `subsystem` labels, and its kernel floor is contradicted between Grafana's own pages.
