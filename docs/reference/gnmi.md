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
The types with a catalogue are `juniper_mx10004` and `cisco_asr9902`; see [Device types](device-types.md).
A catalogue is parsed once per type and shared by every device of that type.
Each device adds a 48-byte resolver.
`BenchmarkCatalogResolverMemory` measures about 460 bytes per device for the resolver plus a minimal device struct.

### File format

| Key | Meaning |
|---|---|
| `notification.origin` / `native_origin` | the origins served; a request with an empty origin maps to `origin` |
| `notification.origin_aliases` | request origins accepted as another spelling of `origin` or `native_origin`, such as a YANG module name (`openconfig-interfaces`) or Junos's `Native`; the prefix origin of the response follows `aliased_origin_prefix`. The generator adds every subtree's `module` as an alias of `origin`, mapped to the origin of the subtrees naming it (`native_origin` for a native sensor model such as `junos-fabric`, `origin` when both use it), so the bindings list only spellings no module names, such as `Native` |
| `notification.aliased_origin_prefix` | prefix origin of a response to a request whose origin is an `origin_aliases` key: `canonical` (default) or `empty`; a request with no origin or a canonical one always gets the canonical origin. The MX10004 uses `empty`: a module-name or `Native:` request is answered with no prefix origin, as hardware does, while an origin-less request gets `openconfig` or `juniper`, as vJunos 25.4 does |
| `notification.response_origin` | `module` answers every request with the rendering subtree's YANG module as the prefix origin (`openconfig-interfaces:interfaces/...`), as IOS-XR does; every subtree then carries its `module`, and it cannot be combined with `aliased_origin_prefix: empty` |
| `notification.json_ietf_layout` | `leaf` (default) answers JSON_IETF with one update per leaf; `container` answers with one update per requested node, its value the node's leaves nested as RFC 7951 JSON, as IOS-XR does. `container` needs `prefix: list-entry` and `JSON_IETF` in `encodings` |
| `notification.prefix` | `list-entry` emits one Notification per list entry with the entry path as prefix and leaf-relative updates (Junos); `flat` emits absolute paths |
| `notification.encodings` | the encodings Capabilities advertises; others are refused with `Unimplemented` |
| `notification.extension` | `juniper-header` attaches Juniper's telemetry header extension (registered id 1) to every response |
| `models` | `ModelData` entries Capabilities advertises |
| `components`, `neighbors` | chassis inventory and BGP peers, the key sources for component and neighbour subtrees |
| `components[].tags` | leaf groups a component reports beyond its type's, selected by a `tag:<name>` leaf filter; an IOS-XR FPD module carries `firmware-version`, a slot container no `type` |
| `subtrees[].path` | the list-entry path with `*` keys; `/` is a root entry with no keys |
| `subtrees[].aliases` | optional subscription paths without wildcards that request the whole subtree, with an empty origin or the subtree's origin; several subtrees of one origin may carry the same alias and all of them answer it |
| `subtrees[].alias_leaves` | optional leaf paths relative to the entry; a request through an alias then renders only the leaves at or below one of them instead of the whole subtree; load refuses it on a subtree without aliases, an entry with keys or covering no leaf, and an `always` leaf outside it |
| `subtrees[].keys` | one key source per wildcard, listed in the order the wildcards are filled (an element with several keys fills them in sorted key-name order): `interfaces` (the ifDescr table), `components` (optional `filter`, optional `parent` naming the component whose children are the keys), `neighbors`, or `static` with `names` |
| `subtrees[].leaves` | relative path, YANG type, optional enum, a generator binding, and an optional `filter` |
| `subtrees[].echo_origin` | under `aliased_origin_prefix: empty`, the prefix carries the request's own origin spelling; the MX10004 property subtrees use it, so `openconfig-platform:/components/component/properties/...` is answered with origin `openconfig-platform` |
| `notification.decimal_encoding` | PROTO wire form of `decimal64` leaves: `double` (default, `double_val`) or `decimal_val` (gNMI `Decimal64` with the leaf's fraction digits as precision, what Junos sends); JSON forms are the RFC 7951 string either way |
| `subtrees[].leaves[].digits` | `decimal64` fraction-digits (1..18), written by the generator from the YANG model, or declared on an `extra` binding leaf; absent means two; refused on a non-decimal leaf |
| `subtrees[].alias_only` | the subtree answers only a request equal to one of its aliases, never path coverage; load refuses it without aliases. How a sensor sends a shape the YANG path does not cover without the shape leaking into other subscriptions |
| `subtrees[].leaves[].decimal_encoding` | per-leaf override of `notification.decimal_encoding` on a `decimal64` leaf (bindings `decimal_encodings` map); the MX10004 sends temperature as `Decimal64` and the transceiver optic readings as doubles |
| `subtrees[].leaves[].always` | rendered whenever its entry renders at all, even when the request path does not cover it (bindings `always` list); how a Junos sensor sends identity leaves such as `name` and `init-time` with every counters notification |
| `subtrees[].leaves[].members` | a `union` leaf's member types in YANG declaration order, written by the generator with nested unions flattened and leafref members resolved to their targets; `enum` then names the enumeration members' values, and `digits` the first `decimal64` member's fraction digits. A union with a member the runtime cannot serve (`binary`, `bits`, `empty`, ...) gets no `members`. A value takes the first member that accepts it: an enumeration only its names, a string-like member anything, an integer member an integral value in range (`3.7` falls through rather than truncating), a `decimal64` member any number. The ASR 9902 CPU `state/index` (`ALL` or `uint32`) sends `ALL` as a string and a numbered CPU as `uint_val`, a JSON number in JSON_IETF. A `union` without `members` is served as a string; load refuses `members` on another type |
| `subtrees[].leaves[].filter` | narrows the leaf to the components matching the value (`temperature`, `tag:<name>` or a component type, the `components` key-source vocabulary); the leaf is omitted from every other entry of the subtree |

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
Catalogues are generated, not hand-edited: `make gen-gnmi-catalog` runs `go/cmd/gnmi-catalog` over a pinned Juniper/yang checkout for `juniper_mx10004` and a pinned YangModels/yang `vendor/cisco/xr/2422` checkout for `cisco_asr9902`, each with its `gnmi-bindings.json`.
For `cisco_asr9902`, `-modules` reads only the modules in `go/cmd/xr-chassis/yang-modules.txt`, which `capabilities-asr9k-x64.xml` advertises.
The generator's `-path` flag adds directories that are searched only to resolve imports, and the Makefile passes `native/jti/models` because Juniper's augments and deviations import `junos-*` modules.
A module under `-path` is also loaded when a binding subtree names it in `module`, which is how the Junos native sensor models (`junos-fabric`, `junos-fpc-env`) are read without walking every JTI model.
A binding subtree may set `yang_path` when Junos renders a sensor under a prefix that differs from its YANG tree: the leaves are looked up at `yang_path` and the catalogue keeps `path` as the rendered prefix.
A drift test regenerates the file and fails when the committed copy differs.
It runs only where the YANG cache exists, which `make gen-gnmi-catalog` populates, and skips elsewhere.

### Junos shape

The MX10004 reproduces what vJunos-router 25.4R1.12 sends.
It serves PROTO and JSON only, and JSON_IETF is refused with the Junos message.
It sends one notification per list entry, with prefixes such as `openconfig:/interfaces/interface[name=xe-0/0/0]`.
Native sensors sit under the `juniper` origin.
The component tree carries the MX10004 hardware's cardinality: 393 components across the chassis, both control boards and both routing engines with their sensors, the LC480 in FPC0 with two 24-port PICs and the LC9600 in FPC1 with six 4-port QSFP-DD PICs, every port and transceiver, the FPC sensors, two PEMs with sensors, two fan tray controllers, 24 fans and six switch fabric boards with seventeen sensors each; sensor-bearing components serve the full temperature record with `instant`, `avg`, `min` and `max` as `Decimal64` precision 1.
FPC1's sensor set is modelled on the LC480's, because no public source names the LC9600's.
The Routing Engine serves eight CPUs under /system/cpus/cpu, the count MX10004 hardware reports, although Juniper documents the RE X10 as a 10-core CPU.
Every port carries a transceiver component serving the static transceiver state (`transceiver/state/{connector-type, date-code, ethernet-pmd, form-factor, present, serial-no, vendor, vendor-part, ...}`) in the component's notification and the analog leaves (`state/enabled`, `state/input-power/instant`, `state/output-power/instant`, `state/laser-bias-current/instant`, doubles) under the `component[name=*]/transceiver` prefix, plus `properties/property[name=wavelength]/state/{configurable,value}` on the port component.
A subscription to `/components/component/transceiver/state/` also carries `oper-status` alone under a `component[name=*]/state` prefix for every port and every transceiver, as hardware does.
That path is an alias carried by four subtrees; the two `oper-status` subtrees are `alias_only`, so `/components/component/state` does not repeat them.
A `/components/component/transceiver` path on a device type without a catalogue is refused with `NotFound` naming the path.
Each interface's out-queues carry exactly `queue-number`, `queued-bytes`, `queued-pkts`, `hp-red-drop-pkts` and `lp-red-drop-pkts`.
That set comes from the MX10004 hardware reference set behind nl6#775, which is not public; the vJunos capture sent eleven buffer and drop leaves more.
A counters subscription also carries `name`, `init-time`, `state/high-speed` and `state/parent-ae-name`, because those leaves are marked `always`, and nothing else from the interface entry.
The router's ONCE chunking of one interface into several notifications is not modelled.
Every subinterface carries the eight `state/counters` leaves, `ipv4/state/counters` and `ipv6/state/counters` with octets, packets and multicast octets and packets each, and `init-time`.
A subscription to `/interfaces/interface/subinterfaces/subinterface/state/counters` is a subtree alias scoped by `alias_leaves`.
It renders the 8 `state/counters/*` leaves, the 16 `ipv4/state/counters/*` and `ipv6/state/counters/*` leaves and `init-time`, as the Junos sensor does.
The subinterface `state/*` leaves come only from a subscription to `.../subinterface/state`.
The subinterface totals ride the interface's HC counters and agree with SNMP.
The family counters are independent synthetic counters at their own rates; nothing ties them to the totals, so do not derive a remainder from them.
BGP serves the two neighbours' state (with `state/peer-group`), their `afi-safis/afi-safi` entries for `IPV4_UNICAST` (28 leaves, with the `ipv4-unicast` containers) and `IPV6_UNICAST` (27 leaves, with the `ipv6-unicast` containers), and two peer-groups, `EBGP-TRANSIT` (external, both neighbours) and `IBGP-CORE` (internal, no members), each with afi-safi entries (21 and 20 leaves, including `total-paths` and `total-prefixes`); the transit group's totals stay above its members' received counts, and the peer-group prefix counters are outside the pinned model and declared as extra leaves because hardware sends them.
The module names `openconfig-interfaces`, `openconfig-platform`, `openconfig-system` and `openconfig-network-instance` are accepted as the `openconfig` origin and `Native` as `juniper`, which is what an operator types against a real MX.
The notifications are the same as for the canonical origin except the prefix origin: a module-name or `Native` request gets none, and a property subscription gets the module name, as the router sends.
A subscription to `/junos/system/linecard/packet/usage/`, with origin `juniper` or none, returns the packet-usage counters under the component paths Junos renders them at.
A subscription to `/junos/system/linecard/fabric/`, with origin `juniper`, `Native`, `junos-fabric` or none, returns the fabric sensor under the prefixes hardware renders it at, one notification per edge with the 14 `uint64` leaves of `junos-fabric.yang`.
Edges between line card PFEs render under `junos/fabric-statistics/fabric-message/edges[...]/class-stats[priority=*]/transmit-counts`, once per class `high` and `low`.
Edges to and from the switch fabric render under the keyless `junos/fabric-statistics/fabric-message/edges[...]/class-stats/transmit-counts` and name only `SWITCH-FABRIC` slot 0, PFE 0.
The prefixes, keys, leaf names and this edge rule come from an MX10004 hardware capture.
The edge count follows nl6's two line cards with 4 + 12 PFEs: every PFE to every other, themselves included, in both classes, plus one edge each way between every PFE and the switch fabric, 544 notifications.
The partial notifications with fewer leaves that the router also sends are not modelled.
A subscription to `/junos/system/linecard/environment/`, with origin `juniper`, `Native`, `junos-fpc-env` or none, returns, per FPC, one power record, one temperature record per sensor and five voltage rails near their nominal voltage, with the leaves of `junos-fpc-env.yang`.
That subtree is YANG-derived: no capture exists, so the prefix depth, the sensor names and the values are nl6's reading of the model, not what an MX sends.
The header extension carries the hostname and sensor name.
ON_CHANGE is not available on catalogue paths in this release, and Subscribe returns `Unimplemented`.

### IOS-XR JSON_IETF layout

`cisco_asr9902` sets `json_ietf_layout: container`.
A JSON_IETF Get then returns one Notification with no prefix per requested path.
It holds one update per concrete instance of the path, with the response origin, and the value nests every leaf below that node.
A request that names every list key it crosses has one instance.
The counters alias `/interfaces/interface/state/counters` crosses the interface list without a key, so it gets one update per interface.
Lists become arrays, and each entry repeats its keys as members, so `/components` answers `{"component": [{"name": "...", "state": {...}}, ...]}`.
Scalars keep the per-leaf JSON_IETF form: 64-bit integers and decimals are quoted strings, 32-bit integers and booleans are bare.
A leaf marked `always` that sits outside the requested node is left out, because the nested value cannot hold it.
A list key repeated inside a value is the path key cast through the subtree's `state/<key>` leaf when the catalogue has one, whichever leaves the request covered, because an OpenConfig list key is a leafref to that leaf.
So a numbered CPU entry under `/system/cpus` is `{"index": 0, "state": {"index": 0, ...}}` and the aggregate is `{"index": "ALL", ...}`.
A key with no such leaf in the catalogue stays a JSON string.
The path key is a string in every encoding, as gNMI requires.
A JSON_IETF Subscribe in ONCE or SAMPLE mode sends one update per list entry, at the entry path with its keys, with no prefix.
PROTO, ON_CHANGE and the paths the shared resolver answers keep one update per leaf, so `/interfaces/interface/state` stays per-leaf on an ASR 9902.
The layout follows Cisco's xrdocs article [Getting started with gNMI](https://xrdocs.io/programmability/blogs/OpenConfig-gNMI), which shows it for IOS-XR 7.
It is not verified on IOS-XR 24.2.2, because the reference capture is PROTO only.

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
`updates_sent` counts gNMI Updates, not leaves: under the [IOS-XR JSON_IETF layout](#ios-xr-json_ietf-layout) one Update carries a whole list entry, so the same traffic counts fewer Updates than in PROTO.
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
