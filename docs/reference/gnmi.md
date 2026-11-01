---
sidebar_label: "gNMI dial-in"
description: "The read-only gNMI server each device runs on port 9339, with its served paths, catalogue subtrees, TLS, subscribe modes and encodings."
---

# gNMI dial-in

Every simulated device exposes a read-only [gNMI](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md) gRPC server on TCP port 9339.
Every device serves OpenConfig interface state and counter telemetry under `/interfaces/interface[name=*]/state/*`.
Optical transport types add optical-channel paths under `/components`.
The types that ship a gNMI catalogue serve further subtrees, such as `/system`, `/components`, subinterfaces and BGP neighbours (see [Catalogue-driven paths](#catalogue-driven-paths)).
Counter values come from the same `IfCounterCycler.GetDynamicAt` dispatcher that drives SNMP and sFlow, so gNMI / SNMP / sFlow agree byte-for-byte at the same instant.

This page covers **dial-in**, the default, where the collector connects to the device.
Devices can additionally **push** telemetry to a collector over an outbound gRPC stream; see [gNMI dial-out](gnmi-dial-out.md).

## Enablement

The gNMI subsystem is **always-on by default**.
Every device gets a listener; no per-device opt-in.
To turn the subsystem off simulator-wide, pass `-gnmi-disable`.

| Flag | Default | Purpose |
|------|---------|---------|
| `-gnmi-port` | `9339` | TCP port for the gNMI dial-in listener on each device. |
| `-gnmi-disable` | `false` | Disable the subsystem; no device listens on the gNMI port. |
| `-gnmi-tls` | `true` | Serve dial-in over TLS. `false` serves plaintext gRPC. |

## TLS

**Dial-in is TLS by default.**
The server presents the simulator's shared certificate (the same cert used by the HTTPS REST surface).
A CA generated at startup signs it, and `GET /api/v1/tls/ca` serves that CA certificate.
Client-certificate authentication is **not required**.
Connect with `gnmic --skip-verify`.
`gnmic --tls-ca <path>` with that CA does not pass host verification.
The certificate carries only the IP SANs `0.0.0.0` and `::`, never a device IP.

> The shared-cert model is a simulator convention. Every simulated device presents the same certificate. The simulator does not pretend to model PKI.

### Plaintext dial-in

`-gnmi-tls=false` binds the per-device listener without transport credentials, for collectors that dial plaintext gRPC.
This mirrors the dial-out side's `-gnmi-dialout-tls=false`.
The mode is simulator-wide: every device serves the same transport, and there is no per-device override.

The two modes do not coexist on one port, by design.
A client that dialed the wrong one could not tell from the port which it got.
A transport mismatch in either direction looks the same from the client: TCP connects, the server sends nothing, and the connection closes.
See [Validate a gNMI collector](../ops/validate-gnmi-collector.md#troubleshooting).

## Supported paths

Every device serves these OpenConfig `interfaces` paths, read-only:

| Path leaf | Type | Source |
|---|---|---|
| `/interfaces/interface[name=*]/state/name` | string | `ifDescr.<N>` |
| `/interfaces/interface[name=*]/state/ifindex` | uint32 | `<N>` (the ifIndex) |
| `/interfaces/interface[name=*]/state/oper-status` | enum | interface state engine (UP / DOWN / TESTING / DORMANT / NOT_PRESENT / LOWER_LAYER_DOWN) |
| `/interfaces/interface[name=*]/state/admin-status` | enum | interface state engine (UP / DOWN / TESTING) |
| `/interfaces/interface[name=*]/state/last-change` | uint64 | absolute Unix nanoseconds of the most recent state transition |
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

Wildcards (`name=*`) enumerate every ifIndex known to the device except subinterfaces whose names are `<interface>.<unit>` (see [interface state](interface-state.md#subinterfaces)); an interface stacked by `ifStackTable`, such as Nokia's `toWAN`, is still listed.
A subinterface name returns `codes.NotFound`, and its state changes produce no ON_CHANGE update on these paths.
Subtree subscribes (e.g. `/state/counters` with no leaf) flatten to all 12 counter leaves in one tick.
Specific names (`name=MgmtEth0/RP0/CPU0/0`) reverse-resolve via the `ifDescr` table; unknown names return `codes.NotFound`.

Paths outside the tables on this page return `codes.NotFound`.
On a type without a catalogue, this includes `/interfaces/interface/config/*`, `/interfaces/interface/subinterfaces`, and anything outside `/interfaces/` and `/components/`.

## Optical channel paths \{#optical-channel-paths-optical-transport-types}

Optical transport types (today `ciena_waveserver5`) also serve the OpenConfig optical-channel surface under `/components`; see [Optical telemetry](optical-telemetry.md#served-paths) for the paths, types and error codes.

## Decimal values

Every `decimal64` value is rounded once, half-to-even, to its declared fraction digits.
`JSON_IETF`, `double_val` and `decimal_val` all derive from that one rounded decimal, so they serve the same reading.
`double_val` is the float64 nearest that decimal, so it never carries more digits than the YANG type declares.
A value that rounds to zero is served as `0`, never as negative zero.

## Catalogue-driven paths

Device types that ship `resources/<type>/gnmi.json` serve the subtrees that file lists, in addition to the interface and optical paths above.
The types with a catalogue are `juniper_mx10004` and `cisco_asr9902`; see [Device types](device-types.md).
A catalogue is parsed once per type and shared by every device of that type.
Each device adds a 48-byte resolver.
`BenchmarkCatalogResolverMemory` measures about 460 bytes per device for the resolver plus a minimal device struct.

The file format, generator bindings, overrides and the Junos and IOS-XR shapes are described in [gNMI catalogue files](gnmi-catalogue.md).

## Subscribe semantics

| RPC | Status |
|---|---|
| `Capabilities` | implemented; advertises `JSON_IETF`, `PROTO`, gNMI 0.10.0, `openconfig-interfaces`, plus `openconfig-terminal-device`, `openconfig-platform` and `openconfig-platform-transceiver` on optical transport types; catalogue types add their own models and encodings |
| `Get` | implemented for any supported path |
| `Subscribe` (STREAM/SAMPLE) | implemented |
| `Subscribe` (STREAM/ON_CHANGE) | implemented for state-leaf paths, on legacy and catalogue devices; rejected for counter and sensor paths |
| `Subscribe` (ONCE) | implemented; one batch + `sync_response` then close |
| `Subscribe` (TARGET_DEFINED) | treated as SAMPLE |
| `Subscribe` (mixed ON_CHANGE + SAMPLE) | rejected with `InvalidArgument`. Split into two SubscribeRequests |
| `Subscribe` (POLL) | rejected with `Unimplemented` |
| `Set` | rejected with `Unimplemented` (read-only simulator) |

**Sample-interval clamp:** any `sample_interval` below 1 second is silently clamped to 1 second.
The same clamp applies to `heartbeat_interval` on ON_CHANGE subscriptions.

**Backpressure:** each STREAM/SAMPLE stream owns a 100-deep send buffer with oldest-drop on overflow.
One buffer element is one tick, so a catalogue tick with one notification per list entry is dropped or delivered whole.
ON_CHANGE streams own a 16-deep listener channel (state events are rare; depth 16 absorbs multi-second collector stalls).
Both drop counters are simulator-wide and exposed via `GET /api/v1/gnmi/status` as `updates_dropped` and `state_events_dropped` respectively.

**Per-leaf ON_CHANGE acceptance.** ON_CHANGE is accepted only when every subscription's resolved path touches the state-engine-backed leaves; counter leaves are rejected because counters change continuously under the analytical engine (every observation produces a different value, which would degenerate to unbounded fan-out).
The rejection error names the offending leaf and recommends SAMPLE.

| Leaf | ON_CHANGE | SAMPLE |
|---|---|---|
| `state/name` | ✓ | ✓ |
| `state/ifindex` | ✓ | ✓ |
| `state/oper-status` | ✓ | ✓ |
| `state/admin-status` | ✓ | ✓ |
| `state/last-change` | ✓ | ✓ |
| `state/counters/*` (12 leaves) | ✗ (rejected with InvalidArgument) | ✓ |

**ON_CHANGE event sources.** Mutations come from the per-device flap scheduler (`-if-flap-scenario`), the REST control plane (`POST /api/v1/devices/{ip}/interfaces/{ifIndex}/{oper,admin}-status`) and its auto-revert, and an SNMP `SET` of `ifAdminStatus.<N>`.
Every transition fans out as a `SubscribeResponse{update}` to every matching subscriber within ~milliseconds.
See [interface state engine](interface-state.md) for the full picture.

**Heartbeat.** Per gNMI §3.5.1.5.2, `heartbeat_interval` lets a client request periodic re-emission of the current value even when nothing has changed.
Set the field on an ON_CHANGE subscription to enable; sub-second values are clamped to 1 second.
`heartbeat_interval=0` (unset) means no heartbeat.
The target emits only on actual state transitions.

**Mixed-mode rejection.** A single `SubscribeRequest` that mixes ON_CHANGE and SAMPLE subscriptions is rejected with `InvalidArgument`.
The two paths have different emission models (event-driven vs ticker-driven); weaving them in one stream would inflate complexity for negligible value.
Standard collectors (e.g. `gnmic`) naturally issue two separate requests.

## gnmic invocation examples

Boot the simulator with one device for these examples:

```bash
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 1
```

Then from the host:

```bash
# Capabilities: sanity check the target is reachable
gnmic -a 192.168.100.1:9339 --skip-verify capabilities

# Get all counters for one interface
gnmic -a 192.168.100.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=MgmtEth0/RP0/CPU0/0]/state/counters'

# Get in-octets across every interface (wildcard)
gnmic -a 192.168.100.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=*]/state/counters/in-octets'

# Subscribe: stream every counter, every 5 seconds
gnmic -a 192.168.100.1:9339 --skip-verify subscribe \
    --path '/interfaces/interface[name=*]/state/counters' \
    --sample-interval 5s

# Subscribe ONCE: one snapshot, then exit
gnmic -a 192.168.100.1:9339 --skip-verify subscribe \
    --path '/interfaces/interface[name=*]/state/counters/in-octets' \
    --mode once
```

For a step-by-step check of a collector against a small fleet, see [Validate a gNMI collector](../ops/validate-gnmi-collector.md).

## Status endpoint

```bash
curl -s http://localhost:8080/api/v1/gnmi/status | jq
```

```json
{
  "subsystem_active": true,
  "tls_enabled": true,
  "listeners": 1,
  "active_subscriptions": 0,
  "updates_sent": 0,
  "updates_dropped": 0,
  "tls_handshake_failures": 0,
  "listener_accept_failures": 0,
  "state_events_emitted": 0,
  "state_events_dropped": 0
}
```

`subsystem_active` is `false` when `-gnmi-disable` is set.
`listeners` equals the device count when active.
Every counter is cumulative since process start; `updates_dropped` increments per backpressure-discard event.
`updates_sent` counts gNMI Updates, not leaves: under the [IOS-XR JSON_IETF layout](gnmi-catalogue.md#ios-xr-json_ietf-layout) one Update carries a whole list entry, so the same traffic counts fewer Updates than in PROTO.
The state-engine counters are explained in the [interface state engine reference](interface-state.md#status-endpoint).

`tls_enabled` reports the dial-in transport the subsystem is configured for, so you can tell a TLS fleet from a plaintext one without reading the simulator's flags.
It describes the configuration rather than any live listener, so read it alongside `subsystem_active`: when that is `false` there are no listeners for it to apply to.

`tls_handshake_failures` counts connections that were accepted and whose TLS handshake then failed.
The usual causes are a client connecting without `--skip-verify` (or with a wrong `--tls-ca`), and a client dialing **plaintext** against the TLS listener.
It stays 0 under `-gnmi-tls=false`, where no handshake happens.
The first failure is logged once per process; the counter keeps moving after that.

`listener_accept_failures` counts `Accept` errors on the per-device listener.
These are faults on the simulator's side, not client misconfigurations.
At fleet scale the realistic one is file-descriptor exhaustion.

**What `tls_handshake_failures` counts.** In older releases the field carried `Accept` errors.
gRPC runs the TLS handshake *after* `Accept` returns, so the field could never report a handshake failure and read 0 in every situation the `tls_handshake_failures` paragraph above describes.
If you are comparing against an older deployment, a value going from 0 to non-zero is the corrected counter working, not a new fault.
The `Accept` signal now lives in `listener_accept_failures`.

## Known limitations

- **Read-only.** `Set` returns `Unimplemented`. The simulator's deterministic-state guarantee is incompatible with mutation.
- **No POLL.** Returns `Unimplemented`. STREAM/SAMPLE and ONCE cover the common cases.
- **No `suppress_redundant`.** A SAMPLE stream sends every interval, including the held value of an interface whose `oper-status` is not `up(1)` (see [Interface state](./interface-state.md)).
- **Single shared certificate.**
  All devices present the same CA-signed cert.
  Real fleets have per-device PKI; the simulator does not.
- **No client-cert auth.** The simulator runs in lab contexts; mutual-TLS is out of scope.
- **No subinterfaces, no `/system`, no LLDP without a catalogue.**
  A type without a catalogue serves only the interface state leaves listed above, plus `optical-channel` under `/components` on optical transport types.
  `juniper_mx10004` and `cisco_asr9902` also serve the subtrees their [catalogues](#catalogue-driven-paths) list, including subinterfaces and `/system`.
  No type serves LLDP.

## Operational notes

- **Port surface.** Each device adds one TCP listener on port 9339 (or whatever `-gnmi-port` says). Per-listener cost is ~10 KiB RSS + 1 fd + 1 goroutine. At 30,000 devices the total is ~320 MiB RSS.
- **Per-device source IP.** Listeners bind inside the `nl6sim` netns so the source IP for accepted connections matches the device IP. Same model as SNMP / SSH / HTTPS REST.
- **Collector-side `rp_filter`.** If your collector rejects packets from the `10.42.0.0/16` (or whatever device subnet) range, set `net.ipv4.conf.*.rp_filter=0` or `2`. Same caveat already documented for flow / trap / syslog.
- **Slowloris hardening.** Per-device gRPC servers cap concurrent streams at 16, reap idle connections after 5 minutes, and ping clients every 30s with a 10s ack timeout. The `Subscribe` handler enforces a 30-second deadline on the initial `SubscribeRequest`. Clients that open a stream and never send the `subscription_list` are rejected with `DeadlineExceeded`. The 17th concurrent stream on a single TCP connection is queued at the HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS layer until a slot frees. gRPC does not surface a status code in this case, and the client's `Subscribe.Recv` blocks until a slot frees. A collector holding more than 16 streams on one connection will see the 17th hang silently. To service >16 parallel streams, open a second `grpc.ClientConn` (multiple TCP connections each get their own quota).
- **Observable to clients:** the 16-stream cap per connection is observable to clients that previously opened more than 16 parallel streams per device-connection. The realistic ceiling is 2 to 3 (one primary collector and maybe a debug session); 16 is conservative.
- **ON_CHANGE on subtree paths is rejected.** The `/interfaces/interface[name=*]/state` subtree includes 12 counter leaves; ON_CHANGE on a subtree that touches a counter leaf is rejected with `InvalidArgument` (the error names the offending leaf and recommends SAMPLE). Subscribers wanting ON_CHANGE coverage of the state leaves should enumerate them explicitly: e.g., one sub per `state/oper-status`, `state/admin-status`, `state/last-change`. The whole-`/state` subtree is incompatible with ON_CHANGE under the analytical counter engine because counter values change continuously.

## See also

- [SNMP reference](snmp.md) covers the IF-MIB counter source, including the analytical sine-wave model.
- [Architecture](../explanation/architecture.md) shows where the gNMI dial-in server sits in the simulator's component map.
- [CLI flags](cli-flags.md) is the canonical flag catalog.
