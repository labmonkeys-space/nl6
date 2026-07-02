# gNMI dial-out

By default every nl6 device is a gNMI **dial-in** target: a collector opens the
connection and calls `Subscribe`. With **dial-out** the roles reverse — the
device opens a gRPC connection *to a collector* and streams telemetry to it.
Dial-out is firewall/NAT-friendly (outbound only, no inbound service) and is the
mechanism behind [Arista EOS gNMIReverse](https://aristanetworks.github.io/openmgmt/telemetry/adapters/gnmi-dial-out/).

Dial-out is **opt-in and per-device**, so the fleet can run mixed: some devices
serve dial-in on `:9339` while others push dial-out to a collector.

```
   dial-in  (default)                 dial-out (opt-in)
   collector ── Subscribe ─▶ device   device ── Publish(stream) ─▶ collector
                                       (source IP = device IP; one
                                        ClientConn + stream per device)
```

## Wire protocol

nl6 ships the **Arista `gNMIReverse`** flavor:
`Publish(stream gnmi.SubscribeResponse) → google.protobuf.Empty` — fire-and-forget
(no per-message ack). The payload is the standard `gnmi.SubscribeResponse`, the
exact message nl6's dial-in `Subscribe` produces, so **dial-out and dial-in
values agree byte-for-byte at the same instant**. The `DialoutTransport` seam
leaves room to add the SONiC `gNMIDialOut` flavor later; only `gnmireverse` is
implemented today.

Every pushed notification carries the device identity **in-band**:
`Notification.Prefix.Target` is set to the device's management IP (the same
job the Arista client's `-target_value` flag does). Collectors can attribute
messages by target instead of source IP — useful behind NAT/proxies and a
prerequisite for any future shared-transport mode. Dial-in responses are
unaffected (servers echo a client-set target; they don't invent one).

## Subscription modes

| Mode | Behaviour |
|------|-----------|
| `sample` (default) | Re-resolve every configured path on a fixed interval (`sample_interval`, clamped to a 1s floor) and push a `SubscribeResponse`. |
| `on-change` | Push on interface-state transitions via the same `InterfaceState` fan-out dial-in ON_CHANGE uses. Only `oper-status`, `admin-status`, and `last-change` fire on a change; `name` and `ifindex` are static and appear in the initial snapshot only. Any counter leaves a path covers are ignored, so a subtree path like the default `/interfaces/interface[name=*]/state` works (counters are filtered at emit). A path that covers *only* counters (e.g. `.../state/counters/in-octets`) is rejected at attach, since it could never fire on-change. |

Paths are gNMI paths under `/interfaces/interface[name=*]/state/...`. The default
path is the full state subtree (`/interfaces/interface[name=*]/state`).

## Connection model

Each dial-out device owns **one `grpc.ClientConn` and one `Publish` stream** —
never a shared pool. A single Go `ClientConn` caps at ~100 concurrent HTTP/2
streams with no automatic multi-connection, so a shared pool would silently
bottleneck at fleet scale; per-device is also the faithful simulation (each real
device is its own dial-out client). When network namespaces are enabled the
client dials from inside the device's netns with the source IP pinned to the
device IP, reusing the existing veth + `FORWARD` egress rule (no new netns /
iptables surface).

Hostname collectors are resolved **per-dial in the host namespace** (the sim
netns has no resolver), so DNS failover is picked up on every reconnect and
the gRPC authority stays the hostname — TLS `ServerName` verification works
against the collector's certificate. Only **IPv4** records are used (the sim
netns is IPv4-only); a hostname resolving exclusively to AAAA records fails
the dial with a clear error. In-namespace dial concurrency is bounded
(64 concurrent dials, 10s per-dial timeout) so an unreachable collector
cannot exhaust OS threads at fleet scale.

## Resilience

- **Own reconnect loop.** A broken `Publish` stream ends the RPC, so the exporter
  wraps dial→publish in a capped exponential backoff loop (1s → 30s), resetting
  after a stream stays up.
- **Drop-on-outage, no buffering.** During a collector outage telemetry is
  dropped, matching vendor behaviour. A slow collector cannot stall the device —
  sends go through a bounded channel with drop-oldest (counted as
  `updates_dropped`).
- **Shutdown-only stop.** `StopGnmiDialout` runs only at process exit (same
  constraint as trap/syslog/gNMI Stop); there is no runtime restart path.

## Configuration

Two levels, mirroring flow / trap / syslog:

### Global seed flags (`[seed]` — auto-start batch only)

| Flag | Default | Meaning |
|------|---------|---------|
| `-gnmi-mode` | `dial-in` | `dial-in` (serve gNMI) or `dial-out` (also push) for the auto-start batch |
| `-gnmi-dialout-collector` | — | Collector `host:port` (required when `-gnmi-mode=dial-out`) |
| `-gnmi-dialout-flavor` | `gnmireverse` | Dial-out wire flavor |
| `-gnmi-dialout-encoding` | `json_ietf` | `json_ietf` or `proto` |
| `-gnmi-dialout-sub-mode` | `sample` | `sample` or `on-change` |
| `-gnmi-dialout-interval` | `10s` | SAMPLE cadence (1s floor) |
| `-gnmi-dialout-tls` | `true` | Use TLS (false = plaintext, Arista `-collector_tls=false` parity) |
| `-gnmi-dialout-tls-insecure` | `false` | Skip collector cert verification (dev only) |
| `-gnmi-dialout-tls-ca` | — | PEM CA bundle to verify the collector (empty = system roots) |
| `-gnmi-dialout-mtls` | `false` | Present the shared cert as a client cert (mutual TLS) |

REST-created devices do **not** inherit these — they opt in per device.

### Per-device REST block (`POST /api/v1/devices`)

```json
{
  "start_ip": "10.42.0.1",
  "device_count": 1,
  "gnmi_dialout": {
    "collector": "10.0.0.5:6030",
    "flavor": "gnmireverse",
    "encoding": "json_ietf",
    "mode": "on-change",
    "paths": ["/interfaces/interface[name=*]/state/oper-status"],
    "sample_interval": "10s",
    "tls": { "enabled": true, "insecure_skip_verify": false, "ca_file": "", "mtls": false }
  }
}
```

Omitting `gnmi_dialout` leaves the device dial-in only. Unknown fields are
rejected (`400`).

### TLS note

`tls.enabled=false` selects a plaintext gRPC connection. When enabled, the
collector is verified against `ca_file` (or the system roots), or verification is
skipped with `insecure_skip_verify` (dev only). The simulator's shared TLS
certificate is a **server leaf** cert — it can be presented as a client cert
(`mtls: true`) but cannot verify the collector, which is why `ca_file` exists.

## Status

`GET /api/v1/gnmi/dialout/status`:

```json
{
  "subsystem_active": true,
  "collectors": [
    {
      "collector": "10.0.0.5:6030",
      "flavor": "gnmireverse",
      "devices": 100,
      "streams_active": 100,
      "updates_sent": 1234567,
      "updates_dropped": 0,
      "reconnects": 2,
      "send_failures": 0
    }
  ],
  "devices_exporting": 100
}
```

Counters are monotonic across device deletion (a deleted device's totals persist
in the per-(collector, flavor) aggregate).

## Operational notes

- The collector-side `rp_filter` caveat is the same as flow / trap / syslog:
  relax `net.ipv4.conf.*.rp_filter` to `0` or `2` to accept connections whose
  source IP is a `10.42.0.0/16` device address.
- No data is buffered during a collector outage.
- Test collectors: `goarista/gnmireverse/server` (reference), or Nokia
  [gNMIc](https://gnmic.openconfig.net/cmd/listen/) `listen`.
