# Scaling

nl6 is tested up to **30,000 concurrent simulated devices on a single host**.
Each device has its own IP, SNMP listener, SSH server, and flow exporter, so the working set is dominated by file descriptors and the Go runtime's goroutine / heap footprint rather than raw CPU.

## Resource envelope

| Dimension | Footprint |
|-----------|-----------|
| **Memory** | About 16 KiB of live heap per device: 78.5 MiB measured at 5,000 devices, see [Profiling](profiling.md#the-forced-gc-default-measured). |
| **CPU** | Minimal during steady state; bursts during device bring-up. |
| **File descriptors** | Dominated by per-device sockets. nl6 raises its soft limit to the hard limit at startup and the packaged systemd unit sets `LimitNOFILE=1048576`; intervene only when the hard limit is capped (see below). |
| **Network** | `nl6sim` namespace isolation prevents systemd-networkd overhead. |

## Optimisations already in place

The simulator ships the following out of the box, with no tuning required:

- **Pre-generated 100-point metric arrays.** CPU / memory / temperature / GPU metrics are computed once at startup and indexed on poll.
- **Lock-free `sync.Map`** for O(1) OID lookups under concurrent SNMP load.
- **Pre-computed next-OID mappings** for `GETNEXT` / `WALK` without table scans.
- **Buffer pool** for SNMP reads, which reduces GC pressure on sustained traffic.
- **Shared SSH / TLS keys** across all devices, which avoids per-device key generation.
- **Parallel TUN pre-allocation.** `prealloc.go` spins up 100 to 200 workers by default (sized by batch; `max_workers` in the create request overrides it, clamped to 500) to bring a large fleet online in seconds.

See [Architecture](../explanation/architecture.md) for the component map.

## Prepare the host

Run these before a large deployment:

- **File-descriptor limits.** Each device opens several sockets, so a large fleet needs a high `nofile`. The Go runtime nl6 is built on raises the process's soft limit to the **hard** limit at startup, so on a typical host no action is needed. You only have to intervene when the *hard* limit is capped low, for example in a restrictive container or a systemd unit with `LimitNOFILE=…:1024`. The packaged unit under `deploy/packages/systemd/` sets `LimitNOFILE=1048576`, so a `.deb` / `.rpm` install is covered. Otherwise raise the hard ceiling:
  ```bash
  ulimit -Hn 1048576         # current shell (then nl6 lifts the soft limit to it)
  ```
  For a persistent limit, raise `LimitNOFILE` on the systemd unit or `nofile` in `/etc/security/limits.conf`, preserving any existing PAM limits.
- **Keep network namespaces enabled** (default). Only pass [`-no-namespace`](../reference/cli-flags.md#core-flags) for debugging. Running in the root namespace pulls systemd-networkd into every interface change and kills throughput.
- **Prefer the container path** for repeatable setup. The [Docker](../getting-started/docker.md) image bundles the dependencies and the tuning above.

## Monitor a running fleet

- **`ulimit -Hn` / `ulimit -Sn`** must exceed the device count by a comfortable margin (each device opens several sockets).
- **`htop`** during bring-up shows a short CPU spike, which is normal as TUN interfaces come up in parallel. Steady-state load should be near-idle.
- **`ip netns exec nl6sim ip addr`** confirms TUN interfaces exist inside the namespace. Unexpected entries in the host namespace usually mean `-no-namespace` was used.
- **`/api/v1/system-stats`** returns the current file-descriptor count, memory, and load average. See [Web API](../reference/web-api.md#endpoint-catalog).

## Scale in a container

When running under Docker, pair the host tuning above with:

- `--cap-add=NET_ADMIN` + `--device=/dev/net/tun` so the container can manage TUN / netns.
- `--network=host` so per-device TUN IPs are reachable from outside the container.
- A memory budget of about `16 KiB * device_count` of live heap plus a comfortable buffer for the Go runtime.

See [Docker](../getting-started/docker.md) for the full bring-up recipe and [Troubleshooting](troubleshooting.md) for bring-up failures.

Kubernetes is not a supported deployment target.
`deploy/helm/nl6-minion/` is a single-node lab chart, not a supported path.
[Why Kubernetes is out of scope](../explanation/kubernetes.md) lists the constraints.
