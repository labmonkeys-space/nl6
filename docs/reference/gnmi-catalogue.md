---
sidebar_label: "gNMI catalogue files"
description: "The gnmi.json catalogue format a device type uses to serve extra gNMI subtrees: keys, leaves, bindings, overrides and vendor shapes."
---

# gNMI catalogue files

A gNMI catalogue, `resources/<type>/gnmi.json`, lists the subtrees a device type serves beyond the interface and optical paths every device shares.
This page describes the file for profile authors.
For what a running device serves and how to subscribe, see [gNMI dial-in](gnmi.md).

## File format

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
| `subtrees[].keys` | one key source per wildcard, listed in the order the wildcards are filled (an element with several keys fills them in sorted key-name order): `interfaces` (the ifDescr table; optional `filter` of whitespace-separated terms, each at most once: `iftype:<n>[,<n>...]` keeps the interfaces whose IF-MIB ifType is listed, `name:<ifDescr>[,...]` keeps only the named interfaces, `!name:<ifDescr>[,...]` drops them; an interface is listed when every term admits it), `subinterfaces` (directly after an `interfaces` key: per interface, the index of every ifDescr row named `<interface>.<index>` whose index is a `uint32`, unit 0 included; the entry reads that row's counters, and an interface without such rows has no entry), `components` (optional `filter`, optional `parent` naming the component whose children are the keys), `neighbors`, or `static` with `names` |
| `subtrees[].leaves` | relative path, YANG type, optional enum, a generator binding, and an optional `filter` |
| `subtrees[].echo_origin` | under `aliased_origin_prefix: empty`, the prefix carries the request's own origin spelling; the MX10004 property subtrees use it, so `openconfig-platform:/components/component/properties/...` is answered with origin `openconfig-platform` |
| `notification.decimal_encoding` | PROTO wire form of `decimal64` leaves: `double` (default, `double_val`) or `decimal_val` (gNMI `Decimal64` with the leaf's fraction digits as precision, what Junos sends); JSON forms are the RFC 7951 string either way; every form is rounded to the leaf's `digits` |
| `subtrees[].leaves[].digits` | `decimal64` fraction-digits (1..18), written by the generator from the YANG model, or declared on an `extra` binding leaf; absent means two; refused on a non-decimal leaf |
| `subtrees[].alias_only` | the subtree answers only a request equal to one of its aliases, never path coverage; load refuses it without aliases. How a sensor sends a shape the YANG path does not cover without the shape leaking into other subscriptions |
| `subtrees[].leaves[].decimal_encoding` | per-leaf override of `notification.decimal_encoding` on a `decimal64` leaf (bindings `decimal_encodings` map); the MX10004 sends temperature as `Decimal64` and the transceiver optic readings as doubles |
| `subtrees[].leaves[].always` | rendered whenever its entry renders at all, even when the request path does not cover it (bindings `always` list); how a Junos sensor sends identity leaves such as `name` and `init-time` with every counters notification |
| `subtrees[].leaves[].members` | a `union` leaf's member types in YANG declaration order, written by the generator with nested unions flattened and leafref members resolved to their targets; `enum` then names the enumeration members' values, and `digits` the first `decimal64` member's fraction digits. A union with a member the runtime cannot serve (`binary`, `bits`, `empty`, ...) gets no `members`. A value takes the first member that accepts it: an enumeration only its names, a string-like member anything, an integer member an integral value in range (`3.7`, as a number or a string, falls through rather than truncating; a plain integer leaf refuses the string `3.7` and the resolver skips it), a `decimal64` member any number. The ASR 9902 CPU `state/index` (`ALL` or `uint32`) sends `ALL` as a string and a numbered CPU as `uint_val`, a JSON number in JSON_IETF. A `union` without `members` is served as a string; load refuses `members` on another type |
| `subtrees[].leaves[].filter` | narrows the leaf to the components matching the value (`temperature`, `tag:<name>` or a component type, the `components` key-source vocabulary); the leaf is omitted from every other entry of the subtree |

An `interfaces` key with a `filter` outside that grammar fails to load, as does one with a repeated term, an empty name, or a name both kept and dropped.
Names match `ifDescr` exactly, no globs: nothing on a device beyond `ifDescr` and `ifType` tells a Routing Engine port from a line-card port of the same `ifType`, so a generated profile names the ports it treats differently.
An interface whose profile ships no `ifDescr` row is listed under the synthesised name the catalogue serves as its key, and a name term matches that name.
A `subinterfaces` key with a `filter`, `names` or `parent` fails to load too.

Under `prefix: list-entry` one entry renders as exactly one Notification, so every leaf an entry serves belongs in one subtree.
A per-component leaf such as `state/temperature/instant` is therefore a filtered leaf of the inventory subtree, not a second subtree serving the same entries.
Two subtrees of one origin on one path are legal when their entry sets are disjoint; the shipped MX10004 keeps the static `CPU0:CORE0` subtree beside the inventory subtree that way.
Loading refuses the pair when their entries overlap, by subtree index, path and the first colliding entry, and names the leaf filter as the remedy where the subtree has a components key.
The check enumerates the key sources it can resolve without a device (`components`, `neighbors`, `static`).
A pair with an `interfaces` key on both sides at the same position is decided from the two filters alone, because the interface name set exists only per device: it loads when the filters are disjoint by construction (both carry `iftype` sets with no common value, both carry `name` lists with no common name, or one carries a `name` list wholly inside the other's `!name` list) or when another key position is disjoint, and is refused otherwise, naming both subtrees and both filters.
The shipped `cisco_asr9902` splits its subinterface counters by `iftype:6` and `iftype:161`, and the shipped `juniper_mx10004` splits its interface entry by `iftype:6 !name:fxp0` and `name:fxp0`.
A pair with `interfaces` keys at different positions is refused, since filters on different path keys prove nothing; a pair with an `interfaces` key on one side only is not checked.

## Generator bindings

| Binding | Value |
|---|---|
| `ifcounter:<IF-MIB column>` | the same counter SNMP serves, e.g. `ifHCInOctets`; columns joined by `+` serve their sum, e.g. `ifHCInUcastPkts+ifHCInMulticastPkts+ifHCInBroadcastPkts` |
| `ifstate:name\|ifindex\|oper\|admin\|last-change` | interface state engine |
| `sine:base,amplitude,period_s` | deterministic wave seeded by device IP and entry key |
| `counter:rate_per_s` | monotonic counter with seeded jitter |
| `inventory:<field>` / `neighbor:<field>` | from `components` / `neighbors` |
| `const:<literal>` / `key:<n>` / `timestamp:now\|boot` | literal, the n-th key value, nanosecond timestamps |
| `device:sysname\|id` | the device sysName (falling back to the device ID), or the device ID |
| `inventory:serial_no_per_device` | the component's `serial_no` with its trailing digits replaced by a per-device suffix from the IPv4 (four hex digits of the low 16 bits plus the ordinal's last two digits), so devices and components never share a serial; a device without an IPv4 serves the constant. SSH output is static text, so `show chassis hardware`, `show chassis routing-engine` and `show chassis power` print the catalogue constants |

Time-based bindings share the interface counter cycler's start as their epoch, so a catalogue counter equals the SNMP counter read at the same instant.

## Overrides

`-gnmi-catalog <file>` replaces the catalogue of every type that carries one with that file.
A type without a catalogue keeps none, so `ciena_waveserver5` keeps its optical resolver and a legacy type keeps its encodings.
A `gnmi.json` in a resource directory replaces that type's embedded catalogue, including for types that ship none.
Catalogues are generated, not hand-edited: `make gen-gnmi-catalog` runs `go/cmd/gnmi-catalog` over a pinned Juniper/yang checkout for `juniper_mx10004` and a pinned YangModels/yang `vendor/cisco/xr/2422` checkout for `cisco_asr9902`, each with its `gnmi-bindings.json`.
For `cisco_asr9902`, `-modules` reads only the modules in `go/cmd/xr-chassis/yang-modules.txt`, which `capabilities-asr9k-x64.xml` advertises.
The generator's `-path` flag adds directories that are searched only to resolve imports, and the Makefile passes `native/jti/models` because Juniper's augments and deviations import `junos-*` modules.
A module under `-path` is also loaded when a binding subtree names it in `module`, which is how the Junos native sensor models (`junos-fabric`, `junos-fpc-env`) are read without walking every JTI model.
A binding subtree may set `yang_path` when Junos renders a sensor under a prefix that differs from its YANG tree: the leaves are looked up at `yang_path` and the catalogue keeps `path` as the rendered prefix.
A drift test regenerates the file and fails when the committed copy differs.
CI runs it through `make test-gnmi-drift`, which clones the pinned checkouts and fails if they are missing.
A plain `go test` run skips it when the YANG cache is absent; `make yang-cache` populates the cache.

## Junos shape

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
A counters subscription also carries `name`, `init-time`, `state/high-speed` and `state/parent-ae-name`, because those leaves are marked `always`, and nothing else from the interface entry.
The router's ONCE chunking of one interface into several notifications is not modelled.
The subinterfaces are the device's five logical units: unit 0 (`xe-0/0/0.0`) and the VRF units `xe-0/0/0.100`, `xe-0/0/0.200` and `xe-0/0/0.999` on `xe-0/0/0`, which `show route instance detail` names, and `fxp0.0` on the management port `fxp0`.
Each is also an `ifTable` row of its own, at ifIndex 73 to 76 and 78, and a line of `show interfaces terse`, and its `state/name` and `state/ifindex` read that row.
`fxp0` is the 73rd interface of the list, beside the 72 ports, because it is an Ethernet port (`ifType` 6), but it is a Routing Engine port, not a line-card one, so a subtree of its own keyed `name:fxp0` serves it: the OpenConfig interface state, `state/high-speed` and the IF-MIB counters, and no out-queue, `hardware-port`, `init-time`, `parent-ae-name` or FCS and pause statistics.
The line-card and out-queue subtrees exclude it with `!name:fxp0`, so the 576 out-queues belong to the 72 ports.
No line-card sensor stands behind `fxp0`, so its subtree marks no leaf `always`: a counters subscription renders its counters and nothing else, while a line-card port's notification also carries the sensor's identity leaves.
The loopback `lo0` and its unit `lo0.0` are IF-MIB rows (ifIndex 79 and 80) and terse lines but not gNMI interfaces: the catalogue's interface leaves describe an Ethernet port, so a loopback is filtered out by `ifType`.
No other port has a subinterface, and no unit is listed as an interface on dial-in or dial-out.
Every subinterface carries the eight `state/counters` leaves, `ipv4/state/counters` and `ipv6/state/counters` with octets, packets and multicast octets and packets each, and `init-time`.
A subscription to `/interfaces/interface/subinterfaces/subinterface/state/counters` is a subtree alias scoped by `alias_leaves`.
It renders the 8 `state/counters/*` leaves, the 16 `ipv4/state/counters/*` and `ipv6/state/counters/*` leaves and `init-time`, as the Junos sensor does.
The subinterface `state/*` leaves come only from a subscription to `.../subinterface/state`.
The subinterface totals ride the unit's own `ifTable` row's HC counters and agree with SNMP.
The family counters are independent synthetic counters at their own rates; nothing ties them to the totals, so do not derive a remainder from them.
BGP serves the two neighbours' state (with `state/peer-group`), their `afi-safis/afi-safi` entries for `IPV4_UNICAST` (28 leaves, with the `ipv4-unicast` containers) and `IPV6_UNICAST` (27 leaves, with the `ipv6-unicast` containers), and two peer-groups, `EBGP-TRANSIT` (external, both neighbours) and `IBGP-CORE` (internal, no members), each with afi-safi entries (21 and 20 leaves, including `total-paths` and `total-prefixes`); the transit group's totals stay above its members' received counts, and the peer-group prefix counters are outside the pinned model and declared as extra leaves because hardware sends them.
The module names `openconfig-interfaces`, `openconfig-platform`, `openconfig-system` and `openconfig-network-instance` are accepted as the `openconfig` origin and `Native` as `juniper`, which is what an operator types against a real MX.
The notifications are the same as for the canonical origin except the prefix origin: a module-name or `Native` request gets none, and a property subscription gets the module name, as the router sends.
A subscription to `/junos/system/linecard/packet/usage/`, with origin `juniper` or none, returns the packet-usage counters under the component paths Junos renders them at.
A subscription to `/junos/system/linecard/fabric/`, with origin `juniper`, `Native`, `junos-fabric` or none, returns the fabric sensor under the prefixes hardware renders it at, one notification per edge with the 14 `uint64` leaves of `junos-fabric.yang`.
Edges between line card PFEs render under `junos/fabric-statistics/fabric-message/edges[...]/class-stats[priority=*]/transmit-counts`, once per class `high` and `low`.
Edges to and from the switch fabric render under the keyless `junos/fabric-statistics/fabric-message/edges[...]/class-stats/transmit-counts` and name only `SWITCH-FABRIC` slot 0, PFE 0.
The edge count follows nl6's two line cards with 4 + 12 PFEs: every PFE to every other, themselves included, in both classes, plus one edge each way between every PFE and the switch fabric, 544 notifications.
The partial notifications with fewer leaves that the router also sends are not modelled.
A subscription to `/junos/system/linecard/environment/`, with origin `juniper`, `Native`, `junos-fpc-env` or none, returns, per FPC, one power record, one temperature record per sensor and five voltage rails near their nominal voltage, with the leaves of `junos-fpc-env.yang`.
That subtree is YANG-derived: no capture exists, so the prefix depth, the sensor names and the values are nl6's reading of the model, not what an MX sends.
The header extension carries the hostname and sensor name.
ON_CHANGE is served on catalogue paths.
The stream starts with the snapshot of every covered leaf in the catalogue shape, then `sync_response`.
On an interface state change it sends one notification for the entry whose interface moved, carrying the `ifstate` leaves whose field changed (`oper-status` on an oper change, `admin-status` on an admin change, `last-change` on any change) and the entry's `always` leaves.
Every other leaf, whatever its binding (inventory, constants, keys, neighbours, IF-MIB columns, timestamps, device fields, `ifstate` name and ifindex), is sent in the snapshot and on heartbeat only.
A subscription covering a counter leaf (`ifcounter` or `counter`) is refused with `InvalidArgument` and the counter message described under [Subscribe semantics](gnmi.md#subscribe-semantics); one covering a sensor leaf (a `sine` binding such as a temperature) is refused the same way, because a sensor reading changes continuously.

## IOS-XR interfaces

The ASR 9902 interface set comes from its chassis model: 48 front ports and two management ports, Bundle-Ether1, BVI1, Loopback0, Null0, and the VLAN subinterfaces HundredGigE0/0/0/8.100, HundredGigE0/0/0/8.200 and Bundle-Ether1.300.
SNMP `ifTable`, `show interfaces brief` and gNMI agree on this set.
`ifTable` and `show interfaces brief` list the VLAN subinterfaces as interfaces of their own.
gNMI serves them only in their parent's `subinterfaces/subinterface` list, as IOS-XR does.
A subscription to `/interfaces/interface/state/counters` sends two notifications per physical port, Bundle-Ether, BVI and Null0, with the 19 counter leaves.
A Loopback sends one notification with `counters/carrier-transitions` only.
A subscription to `/interfaces/interface/subinterfaces/subinterface/state/counters` sends only the VLAN subinterfaces the profile ships (`.100`, `.200` and `.300`), so there is no index 0.
A HundredGigE subinterface carries the 19 leaves.
A Bundle-Ether subinterface omits `in-`/`out-` `unicast-pkts`, `multicast-pkts`, `broadcast-pkts` and `last-clear`.
The router shows `last-clear` on some subinterfaces only; nl6 ties it to the parent kind, which the reference does not confirm.
Interface and subinterface counters read the IF-MIB row's HC counters, so they agree with SNMP.
`in-pkts` and `out-pkts` are the sum of the unicast, multicast and broadcast counters.
Loopback0 and Null0 declare speed 0 and carry no traffic.
Their `ifPhysAddress` is empty and their `ifMtu` is 1500.
The interface kinds and leaf sets follow an ASR 9902 on IOS-XR 24.2.2; which interfaces exist, their ifTypes and speeds are chosen.

## IOS-XR JSON_IETF layout

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
