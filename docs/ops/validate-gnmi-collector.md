---
sidebar_label: "Validate a gNMI collector"
description: "Check a gNMI collector against nl6 with gnmic: capabilities, Get, Subscribe, an SNMP cross-check, subsystem counters and common errors."
---

# Validate a gNMI collector

A typical "is the gNMI surface working?" check takes about a minute.
The sequence below walks capability discovery, one-shot `Get`, streaming `Subscribe`, and a counter cross-check against SNMP.
Use it as a smoke test after a deployment and as a regression check after touching the gNMI code path.

## Install gnmic

`gnmic` ships from the OpenConfig project.
The Go toolchain install is the most portable form:

```bash
go install github.com/openconfig/gnmic/cmd/gnmic@latest
```

Pre-built binaries are also published on the [`openconfig/gnmic` GitHub releases page](https://github.com/openconfig/gnmic/releases).

## 1. Boot the simulator with a small fleet

```bash
sudo ./nl6 -auto-start-ip 10.42.0.1 -auto-count 5
```

Five devices come up at `10.42.0.1` through `10.42.0.5`, each listening on port 9339.

## 2. Capabilities (sanity-check the target is reachable)

```bash
gnmic -a 10.42.0.1:9339 --skip-verify capabilities
```

Expected output:

```
gNMI version: 0.10.0
supported models:
  - openconfig-interfaces, OpenConfig working group, 3.0.0
supported encodings:
  - JSON_IETF
  - PROTO
```

On an optical transport device the model list carries three more entries: `openconfig-terminal-device` (2026-01-14), `openconfig-platform` (2025-07-15) and `openconfig-platform-transceiver` (2026-03-25).
Packet device types advertise only `openconfig-interfaces`, so a collector that generates subscriptions from `Capabilities` never subscribes optical paths against a device that cannot serve them.

`--skip-verify` is required because no device certificate carries the device IP as a SAN (see [TLS](../reference/gnmi.md#tls)).

## 3. Get (confirm path resolution and counter shape)

Single leaf:

```bash
gnmic -a 10.42.0.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=MgmtEth0/RP0/CPU0/0]/state/counters/in-octets'
```

Expected output (timestamp and value differ on each call, because the counter is a sine-wave function of time):

```json
[
  {
    "source": "10.42.0.1:9339",
    "time": "2026-05-09T10:00:30Z",
    "updates": [
      {
        "Path": "interfaces/interface[name=MgmtEth0/RP0/CPU0/0]/state/counters/in-octets",
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

Returns one notification per interface, each carrying all 12 counter leaves.

## 4. Subscribe (streaming telemetry)

The high-value test: confirm SAMPLE-mode streaming works at the configured cadence.

```bash
gnmic -a 10.42.0.1:9339 --skip-verify subscribe \
    --path '/interfaces/interface[name=*]/state/counters/in-octets' \
    --sample-interval 5s
```

A line per interface streams every 5 seconds.
Stop with `Ctrl-C`.

Multi-target subscribe across the whole fleet:

```bash
gnmic --skip-verify subscribe \
    -a 10.42.0.1:9339,10.42.0.2:9339,10.42.0.3:9339,10.42.0.4:9339,10.42.0.5:9339 \
    --path '/interfaces/interface[name=*]/state/counters/in-octets' \
    --sample-interval 5s
```

`gnmic` opens parallel streams to each target; the `source:` field in each output line identifies the originating device.

Mixed-cadence streams in one Subscribe:

```bash
gnmic -a 10.42.0.1:9339 --skip-verify subscribe \
    --path '/interfaces/interface[name=*]/state/counters/in-octets' --sample-interval 1s \
    --path '/interfaces/interface[name=*]/state/ifindex'              --sample-interval 30s
```

The `in-octets` path streams every second, the `ifindex` path every 30 seconds.
Each subscription has its own ticker.

ONCE mode (snapshot, no streaming):

```bash
gnmic -a 10.42.0.1:9339 --skip-verify subscribe \
    --path '/interfaces/interface[name=*]/state/counters' \
    --mode once
```

## 5. Cross-check counter values against SNMP

The gNMI / SNMP / sFlow surfaces all read from the same `IfCounterCycler.GetDynamicAt` dispatcher, so values agree byte-for-byte at the same instant:

```bash
# Read ifHCInOctets.1 via SNMP
snmpget -v2c -c public 10.42.0.1 1.3.6.1.2.1.31.1.1.1.6.1

# Read /interfaces/interface[name=MgmtEth0/RP0/CPU0/0]/state/counters/in-octets via gNMI
gnmic -a 10.42.0.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=MgmtEth0/RP0/CPU0/0]/state/counters/in-octets'
```

The two values should agree within the sub-second elapsed between the two commands.
If they differ by more than the natural ramp rate of the sine wave at that instant, the resolver and the SNMP path have drifted.
Investigate `gnmi_paths.go:resolveLeaf` and `snmp_handlers.go`.

## 6. Confirm subsystem-level metrics

After running a Subscribe for ~30 seconds, check the simulator's accounting:

```bash
curl -s http://localhost:8080/api/v1/gnmi/status | jq
```

```json
{
  "subsystem_active": true,
  "tls_enabled": true,
  "listeners": 5,
  "active_subscriptions": 0,
  "updates_sent": 30,
  "updates_dropped": 0,
  "tls_handshake_failures": 0,
  "listener_accept_failures": 0,
  "state_events_emitted": 0,
  "state_events_dropped": 0
}
```

`active_subscriptions` is non-zero only while a Subscribe is live; `updates_sent` is monotonic across the simulator's lifetime.
The exact `updates_sent` count depends on how many interfaces each device has and how long the stream ran.

`updates_dropped > 0` means the send buffer overflowed.
The usual cause is a slow consumer or a sample interval too aggressive for the path coverage.

Every field is described under [Status endpoint](../reference/gnmi.md#status-endpoint).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| TCP connects but the server sends **zero bytes** and closes; the collector never leaves `TRANSIENT_FAILURE` | Transport mismatch. A plaintext client against the TLS listener sends the HTTP/2 preface, which is a malformed ClientHello, so the server closes without replying. Add `--skip-verify` to the client, or start nl6 with `-gnmi-tls=false`. Check `tls_enabled` and `tls_handshake_failures` on `/api/v1/gnmi/status` to confirm |
| `tls: failed to verify certificate` | Add `--skip-verify`, or pass the simulator's cert via `--tls-ca` |
| `connection refused` | Device IP not reachable from your shell. Check routing into the `nl6sim` netns. The host route script is at `GET /api/v1/devices/routes` |
| `code = InvalidArgument desc = unsupported encoding ASCII` | Only `JSON_IETF` and `PROTO` are advertised; `gnmic` defaults to `JSON_IETF` so this only triggers if you passed `-e ASCII` / `-e BYTES` |
| Subscribe drops after ~5 min idle | Hit the keepalive limit. The server closes idle connections after 5 m by default (see [Operational notes](../reference/gnmi.md#operational-notes)) |
| `code = DeadlineExceeded desc = no SubscribeRequest received within 30s` | The slowloris guard fired. Your client opened a stream and didn't send the SubscribeRequest within 30 s |
| `Get` with `--type config` returns empty | Expected on packet device types, whose interface surface is state-only. On optical transport types `CONFIG` returns the four optical config scalars (see [Optical channel paths](../reference/optical-telemetry.md#served-paths)) |
| `code = NotFound desc = origin "junos" not supported` | A device type without a catalogue serves OpenConfig only; drop the `origin` field or set it to `openconfig` (or empty). A catalogue type accepts its `origin_aliases` as well (the MX10004 takes module names and `Native`) |
| `code = Unimplemented desc = POLL ...` / `Set ...` | Expected. See [Subscribe semantics](../reference/gnmi.md#subscribe-semantics) for the supported RPC surface |
