# gNMI target

Every simulated device exposes a read-only [gNMI](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md) gRPC server on TCP port 9339. The target serves OpenConfig interface state and counter telemetry, scoped to `/interfaces/interface[name=*]/state/*`. Counter values come from the same `IfCounterCycler.GetDynamicAt` dispatcher that drives SNMP and sFlow, so gNMI / SNMP / sFlow agree byte-for-byte at the same instant.

## Enablement

The gNMI subsystem is **always-on by default**. Every device gets a listener; no per-device opt-in. To turn the subsystem off simulator-wide, pass `-gnmi-disable`.

| Flag | Default | Purpose |
|------|---------|---------|
| `-gnmi-port` | `9339` | TCP port for the gNMI listener on each device. |
| `-gnmi-disable` | `false` | Disable the subsystem; no device listens on the gNMI port. |

## TLS

The server presents the simulator's shared self-signed certificate (the same cert used by the HTTPS REST surface). Client-certificate authentication is **not required**. Connect with `gnmic --skip-verify` for the easy path, or `gnmic --tls-ca <path>` if you want the cert chain validated.

> The shared-cert model is a simulator convention — every simulated device presents the same certificate. The simulator does not pretend to model PKI.

## Supported paths

Path coverage is scoped to the OpenConfig `interfaces` model, read-only:

| Path leaf | Type | Source |
|---|---|---|
| `/interfaces/interface[name=*]/state/name` | string | `ifDescr.<N>` |
| `/interfaces/interface[name=*]/state/ifindex` | uint32 | `<N>` (the ifIndex) |
| `/interfaces/interface[name=*]/state/oper-status` | enum | static `UP` |
| `/interfaces/interface[name=*]/state/admin-status` | enum | static `UP` |
| `/interfaces/interface[name=*]/state/counters/in-octets` | uint64 | `ifHCInOctets.<N>` |
| `/interfaces/interface[name=*]/state/counters/out-octets` | uint64 | `ifHCOutOctets.<N>` |
| `/interfaces/interface[name=*]/state/counters/in-unicast-pkts` | uint64 | `ifHCInUcastPkts.<N>` |
| `/interfaces/interface[name=*]/state/counters/in-multicast-pkts` | uint64 | `ifHCInMulticastPkts.<N>` |
| `/interfaces/interface[name=*]/state/counters/in-broadcast-pkts` | uint64 | `ifHCInBroadcastPkts.<N>` |
| `/interfaces/interface[name=*]/state/counters/out-unicast-pkts` | uint64 | `ifHCOutUcastPkts.<N>` |
| `/interfaces/interface[name=*]/state/counters/out-multicast-pkts` | uint64 | `ifHCOutMulticastPkts.<N>` |
| `/interfaces/interface[name=*]/state/counters/out-broadcast-pkts` | uint64 | `ifHCOutBroadcastPkts.<N>` |
| `/interfaces/interface[name=*]/state/counters/in-discards` | uint64 | `ifInDiscards.<N>` |
| `/interfaces/interface[name=*]/state/counters/in-errors` | uint64 | `ifInErrors.<N>` |
| `/interfaces/interface[name=*]/state/counters/out-discards` | uint64 | `ifOutDiscards.<N>` |
| `/interfaces/interface[name=*]/state/counters/out-errors` | uint64 | `ifOutErrors.<N>` |

Wildcards (`name=*`) enumerate every ifIndex known to the device. Subtree subscribes (e.g. `/state/counters` with no leaf) flatten to all 12 counter leaves in one tick. Specific names (`name=GigabitEthernet0/0`) reverse-resolve via the `ifDescr` table; unknown names return `codes.NotFound`.

Paths outside the table above — including `/interfaces/interface/config/*`, `/interfaces/interface/subinterfaces`, and anything outside `/interfaces/` — return `codes.NotFound`.

## Subscribe semantics

| RPC | Status |
|---|---|
| `Capabilities` | implemented; advertises `JSON_IETF`, `PROTO`, gNMI 0.10.0, `openconfig-interfaces` |
| `Get` | implemented for any supported path |
| `Subscribe` (STREAM/SAMPLE) | implemented |
| `Subscribe` (ONCE) | implemented; one batch + `sync_response` then close |
| `Subscribe` (TARGET_DEFINED) | treated as SAMPLE |
| `Subscribe` (ON_CHANGE) | rejected with `InvalidArgument` |
| `Subscribe` (POLL) | rejected with `Unimplemented` |
| `Set` | rejected with `Unimplemented` (read-only simulator) |

**Sample-interval clamp:** any `sample_interval` below 1 second is silently clamped to 1 second.

**Backpressure:** each subscribe stream owns a 100-deep send buffer with oldest-drop on overflow. Drops are counted simulator-wide and exposed via `GET /api/v1/gnmi/status`.

**Why ON_CHANGE is rejected:** counter values change continuously under the analytical engine (degenerate trigger every sample), and `oper-status` / `admin-status` are static `UP` (would never trigger). Accepting ON_CHANGE would silently produce useless streams. Reject loudly.

## gnmic invocation examples

Boot the simulator with one device for these examples:

```bash
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 1
```

Then from the host:

```bash
# Capabilities — sanity check the target is reachable
gnmic -a 192.168.100.1:9339 --skip-verify capabilities

# Get all counters for one interface
gnmic -a 192.168.100.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=GigabitEthernet0/0]/state/counters'

# Get in-octets across every interface (wildcard)
gnmic -a 192.168.100.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=*]/state/counters/in-octets'

# Subscribe — stream every counter, every 5 seconds
gnmic -a 192.168.100.1:9339 --skip-verify subscribe \
    --path '/interfaces/interface[name=*]/state/counters' \
    --sample-interval 5s

# Subscribe ONCE — one snapshot, then exit
gnmic -a 192.168.100.1:9339 --skip-verify subscribe \
    --path '/interfaces/interface[name=*]/state/counters/in-octets' \
    --mode once
```

## Quick validation with gnmic

A typical "is the gNMI surface working?" check takes about a minute. The
sequence below walks capability discovery, one-shot `Get`, streaming
`Subscribe`, and a counter cross-check against SNMP — useful as both a
smoke test after a deployment and a regression check after touching the
gNMI code path.

### Install gnmic

`gnmic` ships from the OpenConfig project. The Go toolchain install is
the most portable form:

```bash
go install github.com/openconfig/gnmic/cmd/gnmic@latest
```

Pre-built binaries are also published on the
[`openconfig/gnmic` GitHub releases page](https://github.com/openconfig/gnmic/releases).

### 1. Boot the simulator with a small fleet

```bash
sudo ./nl6 -auto-start-ip 10.42.0.1 -auto-count 5
```

Five devices come up at `10.42.0.1` through `10.42.0.5`, each listening
on port 9339.

### 2. Capabilities — sanity-check the target is reachable

```bash
gnmic -a 10.42.0.1:9339 --skip-verify capabilities
```

Expected output:

```
gNMI version: 0.10.0
supported models:
  - openconfig-interfaces, OpenConfig working group, 4.0.0
supported encodings:
  - JSON_IETF
  - PROTO
```

`--skip-verify` is required because every device presents the simulator's
shared self-signed cert (see [TLS](#tls) above).

### 3. Get — confirm path resolution and counter shape

Single leaf:

```bash
gnmic -a 10.42.0.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=GigabitEthernet0/0]/state/counters/in-octets'
```

Expected output (timestamp + value will differ each call — the counter
is a sine-wave function of time):

```json
[
  {
    "source": "10.42.0.1:9339",
    "time": "2026-05-09T10:00:30Z",
    "updates": [
      {
        "Path": "interfaces/interface[name=GigabitEthernet0/0]/state/counters/in-octets",
        "values": {
          "interfaces/interface/state/counters/in-octets": "12345678"
        }
      }
    ]
  }
]
```

Wildcard against every interface, full counter subtree:

```bash
gnmic -a 10.42.0.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=*]/state/counters'
```

Returns one notification per interface, each carrying all 12 counter
leaves.

### 4. Subscribe — streaming telemetry

The high-value test: confirm SAMPLE-mode streaming works at the configured
cadence.

```bash
gnmic -a 10.42.0.1:9339 --skip-verify subscribe \
    --path '/interfaces/interface[name=*]/state/counters/in-octets' \
    --sample-interval 5s
```

A line per interface streams every 5 seconds. Stop with `Ctrl-C`.

Multi-target subscribe across the whole fleet:

```bash
gnmic --skip-verify subscribe \
    -a 10.42.0.1:9339,10.42.0.2:9339,10.42.0.3:9339,10.42.0.4:9339,10.42.0.5:9339 \
    --path '/interfaces/interface[name=*]/state/counters/in-octets' \
    --sample-interval 5s
```

`gnmic` opens parallel streams to each target; the `source:` field in
each output line identifies the originating device.

Mixed-cadence streams in one Subscribe (post-D1 per-sub tickers):

```bash
gnmic -a 10.42.0.1:9339 --skip-verify subscribe \
    --path '/interfaces/interface[name=*]/state/counters/in-octets' --sample-interval 1s \
    --path '/interfaces/interface[name=*]/state/ifindex'              --sample-interval 30s
```

The `in-octets` path streams every second, the `ifindex` path every
30 seconds — each subscription has its own ticker.

ONCE mode (snapshot, no streaming):

```bash
gnmic -a 10.42.0.1:9339 --skip-verify subscribe \
    --path '/interfaces/interface[name=*]/state/counters' \
    --mode once
```

### 5. Cross-check counter values against SNMP

The gNMI / SNMP / sFlow surfaces all read from the same
`IfCounterCycler.GetDynamicAt` dispatcher, so values agree byte-for-byte
at the same instant:

```bash
# Read ifHCInOctets.1 via SNMP
snmpget -v2c -c public 10.42.0.1 1.3.6.1.2.1.31.1.1.1.6.1

# Read /interfaces/interface[name=Gi0/0]/state/counters/in-octets via gNMI
gnmic -a 10.42.0.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=GigabitEthernet0/0]/state/counters/in-octets'
```

The two values should agree within the sub-second elapsed between the
two commands. If they differ by more than the natural ramp rate of the
sine wave at that instant, the resolver and the SNMP path have drifted
— investigate `gnmi_paths.go:resolveLeaf` and `snmp_handlers.go`.

### 6. Confirm subsystem-level metrics

After running a Subscribe for ~30 seconds, check the simulator's
accounting:

```bash
curl -s http://localhost:8080/api/v1/gnmi/status | jq
```

```json
{
  "subsystem_active": true,
  "listeners": 5,
  "active_subscriptions": 0,
  "updates_sent": 30,
  "updates_dropped": 0,
  "tls_handshake_failures": 0
}
```

`active_subscriptions` is non-zero only while a Subscribe is live;
`updates_sent` is monotonic across the simulator's lifetime. The exact
`updates_sent` count depends on how many interfaces each device has and
how long the stream ran.

`updates_dropped > 0` means the send buffer overflowed — typically
indicates a slow consumer or a sample interval too aggressive for the
path coverage. `tls_handshake_failures > 0` usually means clients
connecting without `--skip-verify` (or with a wrong `--tls-ca`).

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| `tls: failed to verify certificate` | Add `--skip-verify`, or pass the simulator's cert via `--tls-ca` |
| `connection refused` | Device IP not reachable from your shell — check routing into the `opensim` netns; the host route script is at `GET /api/v1/devices/routes` |
| `code = InvalidArgument desc = unsupported encoding ASCII` | Only `JSON_IETF` and `PROTO` are advertised; `gnmic` defaults to `JSON_IETF` so this only triggers if you passed `-e ASCII` / `-e BYTES` |
| Subscribe drops after ~5 min idle | Hit the keepalive limit — server closes idle connections after 5 m by default (see [Operational notes](#operational-notes)) |
| `code = DeadlineExceeded desc = no SubscribeRequest received within 30s` | The slowloris guard fired — your client opened a stream and didn't send the SubscribeRequest within 30 s |
| `Get` with `--type config` returns empty | Expected — the simulator exposes only the state subtree; no config tree exists |
| `code = NotFound desc = origin "junos" not supported` | The simulator only serves OpenConfig; drop the `origin` field or set it to `openconfig` (or empty) |
| `code = Unimplemented desc = POLL ...` / `Set ...` | Expected — see [Subscribe semantics](#subscribe-semantics) for the supported RPC surface |

## Status endpoint

```bash
curl -s http://localhost:8080/api/v1/gnmi/status | jq
```

```json
{
  "subsystem_active": true,
  "listeners": 1,
  "active_subscriptions": 0,
  "updates_sent": 0,
  "updates_dropped": 0
}
```

`subsystem_active` is `false` when `-gnmi-disable` is set. `listeners` equals the device count when active. The three counters are aggregates across the simulator's lifetime; `updates_dropped` increments per backpressure-discard event.

## Known limitations

- **Read-only.** `Set` returns `Unimplemented`. The simulator's deterministic-state guarantee is incompatible with mutation.
- **No ON_CHANGE.** All counter values are continuously changing; `oper-status` is static. ON_CHANGE has no useful semantic in v1.
- **No POLL.** Returns `Unimplemented`. STREAM/SAMPLE and ONCE cover the common cases.
- **Static `oper-status` and `admin-status`.** Always `UP`. Will become dynamic when link-state simulation is added.
- **Single shared certificate.** All devices present the same self-signed cert. Real fleets have per-device PKI; the simulator does not.
- **No client-cert auth.** The simulator runs in lab contexts; mutual-TLS is out of scope.
- **No subinterfaces, no config tree, no `/system`, no LLDP, no platform/components.** Only the interfaces leaves listed above.

## Operational notes

- **Port surface.** Each device adds one TCP listener on port 9339 (or whatever `-gnmi-port` says). Per-listener cost is ~10 KiB RSS + 1 fd + 1 goroutine. At 30,000 devices the total is ~320 MiB RSS.
- **Per-device source IP.** Listeners bind inside the `opensim` netns so the source IP for accepted connections matches the device IP. Same model as SNMP / SSH / HTTPS REST.
- **Collector-side `rp_filter`.** If your collector rejects packets from the `10.42.0.0/16` (or whatever device subnet) range, set `net.ipv4.conf.*.rp_filter=0` or `2`. Same caveat already documented for flow / trap / syslog.
- **Slowloris hardening.** Per-device gRPC servers cap concurrent streams at 64, reap idle connections after 5 minutes, and ping clients every 30s with a 10s ack timeout. The `Subscribe` handler enforces a 30-second deadline on the initial `SubscribeRequest` — clients that open a stream and never send the `subscription_list` are rejected with `DeadlineExceeded`.

## See also

- [SNMP reference](snmp.md) — the IF-MIB counter source, including the analytical sine-wave model.
- [Architecture](architecture.md) — where the gNMI target sits in the simulator's component map.
- [CLI flags](cli-flags.md) — the canonical flag catalog.
