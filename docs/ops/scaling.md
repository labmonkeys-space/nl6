# Scaling

nl6 is tested up to **30,000 concurrent simulated devices on a single
host**. Each device has its own IP, SNMP listener, SSH server, and flow
exporter, so the working set is dominated by file descriptors and the Go
runtime's goroutine / heap footprint rather than raw CPU.

## Resource envelope

| Dimension | Footprint |
|-----------|-----------|
| **Memory** | ~50 MB base + ~1 KB per device. |
| **CPU** | Minimal during steady state; bursts during device bring-up. |
| **File descriptors** | Dominated by per-device sockets — raise `ulimit -n` well above the device count. |
| **Network** | `opensim` namespace isolation prevents systemd-networkd overhead. |

## Optimisations already in place

The simulator ships the following out of the box — no tuning required:

- **Pre-generated 100-point metric arrays** — CPU / memory / temperature /
  GPU metrics are computed once at startup and indexed on poll.
- **Lock-free `sync.Map`** for O(1) OID lookups under concurrent SNMP load.
- **Pre-computed next-OID mappings** — `GETNEXT` / `WALK` without table
  scans.
- **Buffer pool** for SNMP reads — reduces GC pressure on sustained traffic.
- **Shared SSH / TLS keys** across all devices — avoids per-device key
  generation.
- **Parallel TUN pre-allocation** — `prealloc.go` spins up 100–200 workers
  to bring a large fleet online in seconds.

See [Architecture](../reference/architecture.md) for the component map.

## Host preparation

Run these before a large deployment:

- **Raise file-descriptor limits:**
  ```bash
  sudo ./increase_file_limits.sh
  ```
  Sets `nofile` to a level that comfortably handles 30k devices — review the
  script before running it if you have existing PAM limits to preserve.
- **Keep network namespaces enabled** (default). Only pass
  [`-no-namespace`](../reference/cli-flags.md#core-flags) for debugging —
  running in the root namespace pulls systemd-networkd into every interface
  change and kills throughput.
- **Verify system readiness:**
  ```bash
  sudo ./diagnose_system.sh
  ```
- **Ubuntu one-shot** for fresh hosts:
  ```bash
  sudo ./ubuntu_setup.sh
  ```

## What to watch

- **`ulimit -Hn` / `ulimit -Sn`** — must exceed the device count by a
  comfortable margin (each device opens several sockets).
- **`htop`** during bring-up — a short CPU spike is normal as TUN interfaces
  come up in parallel. Steady-state load should be near-idle.
- **`ip netns exec opensim ip addr`** — confirm TUN interfaces exist inside
  the namespace. Unexpected entries in the host namespace usually mean
  `-no-namespace` was used.
- **`/api/v1/system-stats`** — returns the current file-descriptor count,
  memory, and load average. See
  [Web API](../reference/web-api.md#endpoint-catalog).

## Container scaling

When running under Docker, pair the host tuning above with:

- `--cap-add=NET_ADMIN` + `--device=/dev/net/tun` so the container can
  manage TUN / netns.
- `--network=host` so per-device TUN IPs are reachable from outside the
  container.
- A memory budget of `~50 MB base + ~1 KiB * device_count` plus a
  comfortable buffer.

See [Docker](../getting-started/docker.md) for the full bring-up recipe and
[Troubleshooting](troubleshooting.md) for bring-up failures.

Kubernetes is not currently supported as a deployment target — see
[Kubernetes (not supported)](kubernetes.md) for the constraints that put it
out of scope.
