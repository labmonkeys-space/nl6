# gNMI dial-in

Every simulated device exposes a read-only [gNMI](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md) gRPC server on TCP port 9339. The target serves OpenConfig interface state and counter telemetry, scoped to `/interfaces/interface[name=*]/state/*`.
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

**Dial-in is TLS by default.** The server presents the simulator's shared self-signed certificate (the same cert used by the HTTPS REST surface).
Client-certificate authentication is **not required**.
Connect with `gnmic --skip-verify` for the easy path, or `gnmic --tls-ca <path>` if you want the cert chain validated.

> The shared-cert model is a simulator convention. Every simulated device presents the same certificate. The simulator does not pretend to model PKI.

### Plaintext dial-in

`-gnmi-tls=false` binds the per-device listener without transport credentials, for collectors that dial plaintext gRPC.
This mirrors the dial-out side's `-gnmi-dialout-tls=false`.
The mode is simulator-wide: every device serves the same transport, and there is no per-device override.

The two modes do not coexist on one port, by design.
A client that dialed the wrong one could not tell from the port which it got.
A transport mismatch in either direction looks the same from the client: TCP connects, the server sends nothing, and the connection closes.
See [Troubleshooting](#troubleshooting).

## Supported paths

Path coverage is scoped to the OpenConfig `interfaces` model, read-only:

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

Wildcards (`name=*`) enumerate every ifIndex known to the device.
Subtree subscribes (e.g. `/state/counters` with no leaf) flatten to all 12 counter leaves in one tick.
Specific names (`name=GigabitEthernet0/0`) reverse-resolve via the `ifDescr` table; unknown names return `codes.NotFound`.

Paths outside the tables on this page return `codes.NotFound`.
This includes `/interfaces/interface/config/*`, `/interfaces/interface/subinterfaces`, and anything outside `/interfaces/` and `/components/`.

## Optical channel paths (optical transport types)

Devices whose type carries coherent optical channels (today `ciena_waveserver5`) additionally serve the OpenConfig optical surface, keyed by **OCH component name**, never by `ifIndex`:

```
/components/component[name=OCH-1-1]/optical-channel/{config,state}/…
```

| Path | Type | Notes |
|---|---|---|
| `…/optical-channel/{config,state}/frequency` | uint64 | MHz |
| `…/optical-channel/{config,state}/target-output-power` | decimal64 (2 fd) | dBm |
| `…/optical-channel/{config,state}/operational-mode` | uint16 | |
| `…/optical-channel/{config,state}/line-port` | string | leafref |
| `…/optical-channel/state/input-power/{instant,avg,min,max}` | decimal64 (2 fd) | dBm |
| `…/optical-channel/state/output-power/{instant,avg,min,max}` | decimal64 (2 fd) | dBm |
| `…/optical-channel/state/laser-bias-current/{instant,avg,min,max}` | decimal64 (2 fd) | mA |
| `…/optical-channel/state/osnr/{instant,avg,min,max}` | decimal64 (2 fd) | dB |
| `…/optical-channel/state/esnr/{instant,avg,min,max}` | decimal64 (2 fd) | dB |
| `…/optical-channel/state/q-value/{instant,avg,min,max}` | decimal64 (2 fd) | dB |
| `…/optical-channel/state/pre-fec-ber/{instant,avg,min,max}` | decimal64 (**18** fd) | |
| `…/optical-channel/state/chromatic-dispersion/{instant,avg,min,max}` | decimal64 (2 fd) | ps-nm |
| `…/optical-channel/state/polarization-mode-dispersion/{instant,avg,min,max}` | decimal64 (2 fd) | ps |
| `…/optical-channel/state/polarization-dependent-loss/{instant,avg,min,max}` | decimal64 (2 fd) | dB |
| `…/optical-channel/state/fec-uncorrectable-blocks` | uint64 | **bare counter, no statistics container** |

See [Optical telemetry](optical-telemetry.md) for the value model, health bands, the degradation endpoint and a validation walkthrough.

Wildcards (`name=*`) enumerate every channel in sorted order; subtree subscribes flatten as on the interface side.
Asking for a statistic on `fec-uncorrectable-blocks` (e.g. `/instant`) returns `codes.NotFound`.
The pinned model defines it as a bare leaf.

**`post-fec-ber` is deliberately not served.** OpenConfig defines it, but Ciena removed it from their model, so a collector rule keyed on it would never fire against real hardware.
Serving it would produce exactly the false pass this device type exists to prevent.

**Not an optical device?** Optical paths return `codes.NotFound` on device types with no channels.
The error is permanent, not retryable, and those devices do not advertise the optical models in `Capabilities`.
`codes.Unavailable` is reserved for an optical device still initialising.

**ON_CHANGE is rejected for optical paths** (`InvalidArgument`): these are analog measurements that change continuously, so use SAMPLE with `sample_interval`.

**Precision caveat:** `pre-fec-ber` carries 18 fraction digits, which exceeds a float64 significand.
`PROTO`'s `double_val` is lossy for it.
Prefer `JSON_IETF`, which preserves the digits (RFC 7951 renders decimal64 as a string).

**`GetRequest.type`:** because the optical surface has a real `config/` subtree, `CONFIG` returns only the four config scalars, `STATE`/`OPERATIONAL` only state leaves, and `ALL` (the default) everything.
The interface surface is state-only, so it is unaffected.

## Catalogue-driven paths

Device types that ship `resources/<type>/gnmi.json` serve the subtrees that file lists, in addition to the interface and optical paths above.
The first such type is `juniper_mx10004`; see [Device types](device-types.md).
A catalogue is parsed once per type and shared by every device of that type.
Each device adds a 48-byte resolver.
`BenchmarkCatalogResolverMemory` measures about 460 bytes per device for the resolver plus a minimal device struct.

### File format

| Key | Meaning |
|---|---|
| `notification.origin` / `native_origin` | the origins served; a request with an empty origin maps to `origin` |
| `notification.origin_aliases` | request origins accepted as another spelling of `origin` or `native_origin`, such as a YANG module name (`openconfig-interfaces`) or Junos's `Native`; responses carry the canonical origin. The generator adds every subtree's `module` as an alias of `origin`, so the bindings list only spellings no module names, such as `Native` |
| `notification.prefix` | `list-entry` emits one Notification per list entry with the entry path as prefix and leaf-relative updates (Junos); `flat` emits absolute paths |
| `notification.encodings` | the encodings Capabilities advertises; others are refused with `Unimplemented` |
| `notification.extension` | `juniper-header` attaches Juniper's telemetry header extension (registered id 1) to every response |
| `models` | `ModelData` entries Capabilities advertises |
| `components`, `neighbors` | chassis inventory and BGP peers, the key sources for component and neighbour subtrees |
| `subtrees[].path` | the list-entry path with `*` keys; `/` is a root entry with no keys |
| `subtrees[].aliases` | optional subscription paths without wildcards that request the whole subtree, with an empty origin or the subtree's origin |
| `subtrees[].keys` | one key source per wildcard: `interfaces` (the ifDescr table), `components` (optional `filter`), `neighbors`, or `static` with `names` |
| `subtrees[].leaves` | relative path, YANG type, optional enum, a generator binding, and an optional `filter` |
| `notification.decimal_encoding` | PROTO wire form of `decimal64` leaves: `double` (default, `double_val`) or `decimal_val` (gNMI `Decimal64` with the leaf's fraction digits as precision, what Junos sends); JSON forms are the RFC 7951 string either way |
| `subtrees[].leaves[].digits` | `decimal64` fraction-digits (1..18), written by the generator from the YANG model, or declared on an `extra` binding leaf; absent means two; refused on a non-decimal leaf |
| `subtrees[].leaves[].filter` | narrows the leaf to the components matching the value (`temperature` or a component type, the `components` key-source vocabulary); the leaf is omitted from every other entry of the subtree |

Under `prefix: list-entry` one entry renders as exactly one Notification, so every leaf an entry serves belongs in one subtree.
A per-component leaf such as `state/temperature/instant` is therefore a filtered leaf of the inventory subtree, not a second subtree serving the same entries.
Two subtrees of one origin on one path are legal when their entry sets are disjoint; the shipped MX10004 keeps the static `CPU0:CORE0` subtree beside the inventory subtree that way.
Loading refuses the pair when their entries overlap, by subtree index, path and the first colliding entry, and names the leaf filter as the remedy where the subtree has a components key.
The check enumerates the key sources it can resolve without a device (`components`, `neighbors`, `static`); a pair with an `interfaces` key on either side is not checked, because the interface name set exists only per device.

### Generator bindings

| Binding | Value |
|---|---|
| `ifcounter:<IF-MIB column>` | the same counter SNMP serves, e.g. `ifHCInOctets` |
| `ifstate:name\|ifindex\|oper\|admin\|last-change` | interface state engine |
| `sine:base,amplitude,period_s` | deterministic wave seeded by device IP and entry key |
| `counter:rate_per_s` | monotonic counter with seeded jitter |
| `inventory:<field>` / `neighbor:<field>` | from `components` / `neighbors` |
| `const:<literal>` / `key:<n>` / `timestamp:now\|boot` | literal, the n-th key value, nanosecond timestamps |
| `device:sysname\|id` | the device sysName (falling back to the device ID), or the device ID |
| `inventory:serial_no_per_device` | the component's `serial_no` with its trailing digits replaced by a per-device suffix from the IPv4 (four hex digits of the low 16 bits plus the ordinal's last two digits), so devices and components never share a serial; a device without an IPv4 serves the constant. SSH output is static text, so `show chassis hardware`, `show chassis routing-engine` and `show chassis power` print the catalogue constants |

Time-based bindings share the interface counter cycler's start as their epoch, so a catalogue counter equals the SNMP counter read at the same instant.

### Overrides

`-gnmi-catalog <file>` replaces every type's catalogue with one file.
A `gnmi.json` in a resource directory replaces that type's embedded catalogue, including for types that ship none.
Catalogues are generated, not hand-edited: `make gen-gnmi-catalog` runs `go/cmd/gnmi-catalog` over a pinned Juniper/yang checkout and `gnmi-bindings.json`.
The generator's `-path` flag adds directories that are searched only to resolve imports, and the Makefile passes `native/jti/models` because Juniper's augments and deviations import `junos-*` modules.
A drift test regenerates the file and fails when the committed copy differs.
It runs only where the YANG cache exists, which `make gen-gnmi-catalog` populates, and skips elsewhere.

### Junos shape

The MX10004 reproduces what vJunos-router 25.4R1.12 sends.
It serves PROTO and JSON only, and JSON_IETF is refused with the Junos message.
It sends one notification per list entry, with prefixes such as `openconfig:/interfaces/interface[name=xe-0/0/0]`.
Native sensors sit under the `juniper` origin.
The component tree carries the MX10004 hardware's cardinality: 256 components across the chassis, control board and routing engine with their sensors, the LC480 with two 24-port PICs, every port and transceiver, the FPC sensors, two PEMs with sensors, two fan tray controllers, 24 fans and six switch fabric boards with eleven sensors each; sensor-bearing components serve the full temperature record with `instant`, `avg`, `min` and `max` as `Decimal64` precision 1.
Every port carries a transceiver component serving the static transceiver state (`transceiver/state/{connector-type, date-code, ethernet-pmd, form-factor, present, serial-no, vendor, vendor-part, ...}`) in the component's notification and the analog leaves (`state/enabled`, `state/input-power/instant`, `state/output-power/instant`, `state/laser-bias-current/instant`, decimals) under the `component[name=*]/transceiver` prefix, plus `properties/property[name=wavelength]/state/{configurable,value}` on the port component.
Hardware also emits `oper-status` alone under a `component[name=*]/state` prefix from the same sensor; nl6 serves `oper-status` in the component's notification and does not emit a leaf the request path does not cover.
A `/components/component/transceiver` path on a device type without a catalogue is refused with `NotFound` naming the path.
Every subinterface carries the eight `state/counters` leaves, `ipv4/state/counters` and `ipv6/state/counters` with octets, packets and multicast octets and packets each, and `init-time`; the IPv4 family rides the interface's HC counters so it agrees with SNMP, IPv6 moves at its own rates, and the families do not sum exactly to the subinterface totals.
BGP serves the two neighbours' state (with `state/peer-group`), their `afi-safis/afi-safi` entries for `IPV4_UNICAST` (28 leaves, with the `ipv4-unicast` containers) and `IPV6_UNICAST` (27 leaves, with the `ipv6-unicast` containers), and two peer-groups, `EBGP-TRANSIT` (external, both neighbours) and `IBGP-CORE` (internal, no members), each with afi-safi entries (21 and 20 leaves, including `total-paths` and `total-prefixes`); the transit group's totals stay above its members' received counts, and the peer-group prefix counters are outside the pinned model and declared as extra leaves because hardware sends them.
The module names `openconfig-interfaces`, `openconfig-platform`, `openconfig-system` and `openconfig-network-instance` are accepted as the `openconfig` origin and `Native` as `juniper`, which is what an operator types against a real MX; the notifications are the same as for the canonical origin.
A subscription to `/junos/system/linecard/packet/usage/`, with origin `juniper` or none, returns the packet-usage counters under the component paths Junos renders them at.
The header extension carries the hostname and sensor name.
ON_CHANGE is not available on catalogue paths in this release, and Subscribe returns `Unimplemented`.

## Subscribe semantics

| RPC | Status |
|---|---|
| `Capabilities` | implemented; advertises `JSON_IETF`, `PROTO`, gNMI 0.10.0, `openconfig-interfaces`, plus `openconfig-terminal-device`, `openconfig-platform` and `openconfig-platform-transceiver` on optical transport types; catalogue types add their own models and encodings |
| `Get` | implemented for any supported path |
| `Subscribe` (STREAM/SAMPLE) | implemented |
| `Subscribe` (STREAM/ON_CHANGE) | implemented for state-leaf paths; rejected for counter paths |
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
    --path '/interfaces/interface[name=GigabitEthernet0/0]/state/counters'

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

## Quick validation with gnmic

A typical "is the gNMI surface working?" check takes about a minute.
The sequence below walks capability discovery, one-shot `Get`, streaming `Subscribe`, and a counter cross-check against SNMP.
Use it as a smoke test after a deployment and as a regression check after touching the gNMI code path.

### Install gnmic

`gnmic` ships from the OpenConfig project.
The Go toolchain install is the most portable form:

```bash
go install github.com/openconfig/gnmic/cmd/gnmic@latest
```

Pre-built binaries are also published on the [`openconfig/gnmic` GitHub releases page](https://github.com/openconfig/gnmic/releases).

### 1. Boot the simulator with a small fleet

```bash
sudo ./nl6 -auto-start-ip 10.42.0.1 -auto-count 5
```

Five devices come up at `10.42.0.1` through `10.42.0.5`, each listening on port 9339.

### 2. Capabilities (sanity-check the target is reachable)

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

`--skip-verify` is required because every device presents the simulator's shared self-signed cert (see [TLS](#tls) above).

### 3. Get (confirm path resolution and counter shape)

Single leaf:

```bash
gnmic -a 10.42.0.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=GigabitEthernet0/0]/state/counters/in-octets'
```

Expected output (timestamp and value differ on each call, because the counter is a sine-wave function of time):

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

Returns one notification per interface, each carrying all 12 counter leaves.

### 4. Subscribe (streaming telemetry)

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

### 5. Cross-check counter values against SNMP

The gNMI / SNMP / sFlow surfaces all read from the same `IfCounterCycler.GetDynamicAt` dispatcher, so values agree byte-for-byte at the same instant:

```bash
# Read ifHCInOctets.1 via SNMP
snmpget -v2c -c public 10.42.0.1 1.3.6.1.2.1.31.1.1.1.6.1

# Read /interfaces/interface[name=Gi0/0]/state/counters/in-octets via gNMI
gnmic -a 10.42.0.1:9339 --skip-verify get \
    --path '/interfaces/interface[name=GigabitEthernet0/0]/state/counters/in-octets'
```

The two values should agree within the sub-second elapsed between the two commands.
If they differ by more than the natural ramp rate of the sine wave at that instant, the resolver and the SNMP path have drifted.
Investigate `gnmi_paths.go:resolveLeaf` and `snmp_handlers.go`.

### 6. Confirm subsystem-level metrics

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

`tls_enabled` reports the dial-in transport the subsystem is configured for, so you can tell a TLS fleet from a plaintext one without reading the simulator's flags.
It describes the configuration rather than any live listener, so read it alongside `subsystem_active`: when that is `false` there are no listeners for it to apply to.

`updates_dropped > 0` means the send buffer overflowed.
The usual cause is a slow consumer or a sample interval too aggressive for the path coverage.

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

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| TCP connects but the server sends **zero bytes** and closes; the collector never leaves `TRANSIENT_FAILURE` | Transport mismatch. A plaintext client against the TLS listener sends the HTTP/2 preface, which is a malformed ClientHello, so the server closes without replying. Add `--skip-verify` to the client, or start nl6 with `-gnmi-tls=false`. Check `tls_enabled` and `tls_handshake_failures` on `/api/v1/gnmi/status` to confirm |
| `tls: failed to verify certificate` | Add `--skip-verify`, or pass the simulator's cert via `--tls-ca` |
| `connection refused` | Device IP not reachable from your shell. Check routing into the `nl6sim` netns. The host route script is at `GET /api/v1/devices/routes` |
| `code = InvalidArgument desc = unsupported encoding ASCII` | Only `JSON_IETF` and `PROTO` are advertised; `gnmic` defaults to `JSON_IETF` so this only triggers if you passed `-e ASCII` / `-e BYTES` |
| Subscribe drops after ~5 min idle | Hit the keepalive limit. The server closes idle connections after 5 m by default (see [Operational notes](#operational-notes)) |
| `code = DeadlineExceeded desc = no SubscribeRequest received within 30s` | The slowloris guard fired. Your client opened a stream and didn't send the SubscribeRequest within 30 s |
| `Get` with `--type config` returns empty | Expected on packet device types, whose interface surface is state-only. On optical transport types `CONFIG` returns the four optical config scalars (see [Optical channel paths](#optical-channel-paths-optical-transport-types)) |
| `code = NotFound desc = origin "junos" not supported` | A device type without a catalogue serves OpenConfig only; drop the `origin` field or set it to `openconfig` (or empty). A catalogue type accepts its `origin_aliases` as well (the MX10004 takes module names and `Native`) |
| `code = Unimplemented desc = POLL ...` / `Set ...` | Expected. See [Subscribe semantics](#subscribe-semantics) for the supported RPC surface |

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
The TLS counters are explained under [Troubleshooting](#troubleshooting), the state-engine counters in the [interface state engine reference](interface-state.md#status-endpoint).

## Known limitations

- **Read-only.** `Set` returns `Unimplemented`. The simulator's deterministic-state guarantee is incompatible with mutation.
- **No POLL.** Returns `Unimplemented`. STREAM/SAMPLE and ONCE cover the common cases.
- **Single shared certificate.** All devices present the same self-signed cert. Real fleets have per-device PKI; the simulator does not.
- **No client-cert auth.** The simulator runs in lab contexts; mutual-TLS is out of scope.
- **No subinterfaces, no `/system`, no LLDP.** The interface surface serves only the state leaves listed above. `/components` is served only for `optical-channel` on optical transport types.

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
