---
sidebar_label: "Interface state"
description: "How nl6 tracks oper, admin and last-change per interface, the ways to change them, and the link traps and syslog a change fires."
---

# Interface state engine

nl6 maintains a per-device, in-memory **interface state engine** that owns `oper-status`, `admin-status`, and `last-change` for every known ifIndex.
SNMP, gNMI `Get`, and gNMI `Subscribe ON_CHANGE` all read from the same slot table.
Values agree byte-for-byte at every instant.
State can be mutated by a scheduled link-flap scenario, by a REST control plane or by an SNMP `SET` of `ifAdminStatus.<N>`.
A derived `ifOperStatus` transition also fires the device's role-tagged link trap and syslog entries for that interface.
Every counter the cycler derives from the octet dial holds while the derived `ifOperStatus` is not `up(1)`, and resumes from the held value when it returns.

This is the capability reference.
For the gNMI subscribe semantics see [gNMI reference](gnmi.md#subscribe-semantics).

## Model

- The engine is the **single source of truth** for `ifOperStatus.<N>`, `ifAdminStatus.<N>` and `ifLastChange.<N>`. SNMP and gNMI reads go through it, and an ON_CHANGE subscription receives an event on every mutation.
- The engine stores the **link state** and `ifAdminStatus`. `ifOperStatus` is **derived** from the pair per RFC 2863 and is never stored.
- Three mutation sources: the **flap scheduler**, the **REST control plane** and an **SNMP `SET`** of `ifAdminStatus.<N>`. The flap scheduler and the REST `oper-status` POST move the link. The REST `admin-status` POST and the `SET` move admin.
- **No gNMI `Set`.**
- Every derived `ifOperStatus` transition fires the role-tagged `linkDown` / `linkUp` trap and `interface-down` / `interface-up` syslog entries of the device's catalog for that ifIndex.
- Per-interface bandwidth does not scale with admin-status changes, and gNMI SAMPLE subscriptions do not support `suppress_redundant`.
- For an ifIndex the device does not own, the engine reports `ifAdminStatus` up(1) but `ifOperStatus` unknown(4). IF-MIB has no unknown admin value. SNMP does not serve such an ifIndex from the engine, but a template that reads it does: `{{.IfAdminStatus}}` on an on-demand fire with a pinned `IfIndex` reads up(1). Check the device's interface list before trusting the admin value.

## Counter hold

Every octet, packet, error and discard column the counter engine derives holds while the derived `ifOperStatus` is not `up(1)`.
That covers admin-down, a subinterface reading `lowerLayerDown(7)` because its parent is down, and an interface seeded down at boot (an empty optic bay).
An interface that boots in a non-up state reads its pre-seeded base from the first poll.

When the interface returns to `up(1)` the columns resume from the held value with no jump.
The traffic the dial would have produced during the hold is dropped, never replayed.
Counters never decrease, even under tight flapping.

SNMP, both gNMI resolvers, gNMI dial-out and the sFlow `counter_sample` read the same held value at the same instant.
A gNMI SAMPLE stream keeps sending the held value every interval.
The sFlow `counter_sample` status word reads admin and oper from the same engine.
`ifLastChange`, `ifSpeed` and `ifHighSpeed` do not hold: a down port keeps its line rate, as IOS-XR and Junos do.

Two surfaces do not follow the hold.
The SSH CLI counter text is static profile JSON.
Flow records (NetFlow, IPFIX, sFlow flow samples) name a fixed ingress ifIndex and keep flowing regardless of interface state.

**Roll-up.** An interface with one lower layer (a `<port>.<unit>` subinterface, or an interface stacked on one port in `ifStackTable`) serves a fixed share of its parent's served octet delta instead of its own dial.
The shares of one parent's children sum below 1, so on every Counter64 column and on the error and discard columns a parent is at least the sum of its children at every instant, held or not.
An interface stacked on two or more lower layers is an aggregate (a bundle) and serves the sum of its members' served deltas.
Its octet columns equal the member sum exactly, and its packet columns read within one packet per member of it.
The composition is applied after each parent's or member's own hold, so a member cable pull lowers the bundle and a held parent holds its children.
A bundle's own `oper-status` does not follow its members, so a bundle whose members are all down stays up.

## CLI flags

The flag tables for `-if-scenario`, `-if-failure-pct`, `-if-flap-scenario` and `-if-flap-global-cap` are in [CLI flags → Interface-state scenarios](cli-flags.md#interface-state-scenarios).
The flap scheduler is **always started**, so REST-created devices with a non-`clean` `if_flap_scenario` register and flap regardless of the CLI default.

## Interface-state scenarios

`-if-scenario` seeds the **initial** `ifAdminStatus` and link state of every simulated interface, so you can reproduce common network conditions without editing resource files.
`ifOperStatus` is never seeded; it is derived from admin and link.
The seed is applied once per device, when the engine is built, to every device the process creates: the auto-start batch and REST-created devices alike.
There is no read-time override, so a `SET`, a REST POST or a flap is read back by the next `GET`, walk, gNMI read or REST view under every scenario.

| Scenario | Name | `ifAdminStatus` | Link | `ifOperStatus` | Use case |
|----------|------|-----------------|------|----------------|----------|
| 1 | all-shutdown | down (2) | as shipped | down (2), derived | Planned maintenance, device decommission |
| 2 | all-normal *(default)* | as shipped | shipped `ifOperStatus` | derived; down (2) where shipped admin is down | Normal steady-state operations |
| 3 | all-failure | up (1) | down | down (2) | Link failures, SFP issues, cable pull |
| 4 | pct-failure | up (1) | down where `ifIndex % 100 < n`, else up | down for n% | Partial outage, staged rollout testing |

`n` is `-if-failure-pct`, default `10`.
Scenario 4's rule is deterministic, so results are reproducible across restarts.

Scenario 2 does not force anything up.
It seeds admin from the shipped `ifAdminStatus` and the link from the shipped `ifOperStatus`, and most shipped profiles declare both up.
`ifOperStatus` is still derived, so a row shipped admin-down with `ifOperStatus` 1 reads down (2).
Five profiles ship interfaces down:

| Profile | `ifAdminStatus` down (2) | `ifOperStatus` down (2) |
|---------|--------------------------|-------------------------|
| `asr9k` | none | ifIndex 44 and 45 |
| `cisco_asr9902` | none | ifIndex 15 to 24, 35 and 36, 41 to 48 |
| `cisco_nexus_9500` | ifIndex 33 to 64 | ifIndex 3 to 10, 21 to 30, 41 to 50, 61 to 64 |
| `juniper_mx960` | none | 27 interfaces, ifIndex 2, 5, 7 and every third ifIndex from 10 to 79 |
| `palo_alto_pa3220` | none | ifIndex 2 |

Those interfaces boot down under the default scenario.
Use scenario 3 if you want every interface down regardless of profile.

The seed is initial state, not a transition.
It fires no link trap, no syslog and no gNMI `ON_CHANGE` update, and `ifLastChange` reads `0` until something changes.

`lldpRemTable` only emits a row when both ends of a link are oper-up.
Scenarios 1 and 3 therefore empty every device's neighbour table, and scenario 4 drops the rows whose local or remote port it put down.
`ifAlias` reflects configured intent and stays.

Scenario 1 shuts the port and **preserves the link underneath it**.
Admin-down forces `ifOperStatus` to `down(2)` while the link keeps whatever the profile declared.
A `SET` of `ifAdminStatus` to `up(1)` or a REST `admin-status` POST brings an interface back to the value its link had reached, which for most profiles is up.

Scenario 3 seeds the **link** down, so it survives an admin bounce.
Shutting and unshutting a port under scenario 3 leaves `ifOperStatus = 2`: the scenario models a cable pull, and an administrative bounce does not repair a cable.
RFC 2863 describes this: admin-up releases `ifOperStatus` to the physical layer rather than forcing it up.

Paired with a link-flap scenario:

- Under scenario 1 every flap is masked (see [Link-flap scenarios](#link-flap-scenarios)). Unshutting a port shows whatever its link had reached.
- Under scenarios 3 and 4 the first up-flap brings a failed interface back, because the port is administratively up and a flap is a real link event. For a fleet that stays down, leave `-if-flap-scenario` at `clean` or use scenario 1.

The scenario reaches the interfaces the counter engine knows: those with an `ifXTable` `.6` (`ifHCInOctets`) row in the device's resource files.
An `ifAdminStatus` or `ifOperStatus` row for any other ifIndex is served from the resource file unchanged.

To spot-check a scenario, walk the two columns:

```bash
snmpwalk -v2c -c public 10.42.0.1 1.3.6.1.2.1.2.2.1.7   # ifAdminStatus
snmpwalk -v2c -c public 10.42.0.1 1.3.6.1.2.1.2.2.1.8   # ifOperStatus
```

## Link-flap scenarios

| Scenario | Mean inter-flap (per interface) | Down duration | Use case |
|----------|---------------------------------|---------------|----------|
| `clean` (default) | ∞ (no flaps) | n/a | Steady-state regression testing |
| `rare` | ~6 hours | uniform 1 to 10 s | Background variance for long-running fleets |
| `typical` | ~15 minutes | uniform 1 to 30 s | Stress-testing collector alarm pipelines |
| `aggressive` | ~1 minute | uniform 1 to 5 s | Chaos / churn measurement |

Inter-arrival times are exponentially distributed (Poisson process).
A flap sets the link down, and the matching up-event follows after the down duration.
`ifLastChange` moves, and an ON_CHANGE update fires, only when the derived `ifOperStatus` moves.

A flap on an interface whose `ifAdminStatus` is `DOWN` or `TESTING` is **masked**: the link moves, nothing observable changes, `ifLastChange` does not advance, and no trap, syslog or ON_CHANGE update fires.
The link is still there when the port is unshut.
This is what the hardware does, so `-if-scenario 1 -if-flap-scenario aggressive` never reports `ifAdminStatus = down(2)` with `ifOperStatus = up(1)`.
The REST `oper-status` endpoint sets the link too, so the same masking applies and its `202` body reports `"masked": true`.

The down-up pair is atomic per `(device, ifIndex)`.
A new flap is not scheduled while the interface is already down.

`-if-flap-global-cap 10` caps simulator-wide event rate at 10/s, backpressuring the scheduler when needed.
Default `0` is unlimited.
At 30k devices × `typical`, the expected steady-state rate is ~30k / 900s ≈ 33 events/s.
A cap below that floor systematically delays the scheduler, and a cap of 50 leaves 50% headroom for bursts.

## Subinterfaces

A subinterface is an interface whose `ifDescr` is another interface's `ifDescr` followed by `.` and an unsigned integer, such as `xe-0/0/0.0` under `xe-0/0/0`.
The gNMI catalogue uses the same rule for its `subinterfaces` key source.
An interface whose name does not say which port it rides on gets a parent from the profile's `ifStackTable`: an `ifStackStatus.<higher>.<lower>` row of `active(1)`.
The name rule decides first.
Shipped profiles with subinterfaces:

- `juniper_mx10004`, `juniper_mx240` and `juniper_mx960`: the logical units their CLI shows, by name. The MX10004 also states each unit's port in `ifStackTable`.
- `cisco_asr9902`: three VLAN subinterfaces, by name, each also stated over its port or bundle in `ifStackTable`.
- `nokia_7750_sr12`: router interface `toWAN`, stacked on `port 1/1/1`.

Where a profile states a parent both ways the rows agree, so the hierarchy is the same with or without the table.
The RFC 2863 marker rows (`ifStackStatus.0.<I>`, `ifStackStatus.<I>.0`) give no interface a parent and are not logged.

A stacked interface follows its parent the same way, but gNMI still lists it under `/interfaces/interface`, because it is not a `<port>.<unit>` subinterface.

A subinterface goes down with its parent.
Its `ifOperStatus` reads `lowerLayerDown(7)` while its parent is not up, unless its own state already forces a value.
Its own `ifAdminStatus = down(2)` still reads `down(2)`.
The subinterface's stored link and admin values are not written, so it comes back with its parent.

A parent transition is also a transition of each subinterface it moves.
`ifLastChange` is stamped with the parent's time, and the subinterface gets its own ON_CHANGE update.
This holds for every mutation source: the flap scheduler, the REST endpoints, auto-revert and SNMP SET.
No link trap or syslog message fires for that move.
RFC 2863 sends `linkDown` on entering `down(2)` and `linkUp` on leaving it, and a move between `up(1)` and `lowerLayerDown(7)` does neither.
A subinterface's own move to or from `down(2)` still fires them.

The flap scheduler does not schedule an interface without a physical link of its own: a subinterface, or a `softwareLoopback(24)` such as `lo` on `linux_server`, `Loopback0` on `cisco_asr9902` and `system` on `nokia_7750_sr12`.

## REST control plane

### `POST /api/v1/devices/{ip}/interfaces/{ifIndex}/oper-status`

Sets the interface's **link state**, the physical-layer reading.
`ifOperStatus` is derived from `(ifAdminStatus, link)`, so this endpoint moves what a collector observes only when the interface is administratively up.

The path is named for the leaf a caller is trying to move, not the leaf it writes.

Body:

```json
{
  "status": "UP" | "DOWN" | "TESTING",
  "duration": "<go-duration>"   // optional
}
```

Returns:

- `202 Accepted` with the outcome on success:

  ```json
  { "link": "UP", "oper_status": "DOWN", "admin_status": "DOWN", "masked": true, "peer_down": false }
  ```

  `masked` is `true` whenever `ifAdminStatus` is `DOWN` or `TESTING`.
  It is also `true` on a subinterface whose link is `UP` while its parent is not up, because it reads `LOWER_LAYER_DOWN` whatever the link does.
  And it is `true` on a port whose link is `UP` while its topology partner does not transmit, which `peer_down: true` reports (only with `-topology-link-propagation`; see [Link propagation](lldp-topology.md#link-propagation)).
  In that state the link state you now hold is not what collectors see.
  While it is set, no link trap, syslog message or gNMI `ON_CHANGE` update will fire from this interface and `ifLastChange` will not move, whatever the link does.
  It is a property of the interface, not of the request, so a POST that changes nothing still reports it.
- `400 Bad Request` for malformed body, unknown `status`, or unknown `ifIndex` (400 body includes `validIfIndexes` array)
- `404 Not Found` for unknown device IP
- `503 Service Unavailable` when the device has no metrics cycler / state engine

Examples:

```bash
# Force ifIndex 3 down indefinitely
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/interfaces/3/oper-status \
  -H 'Content-Type: application/json' \
  -d '{"status":"DOWN"}'

# Flap ifIndex 3 down for 30 seconds; auto-revert to the prior value
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/interfaces/3/oper-status \
  -H 'Content-Type: application/json' \
  -d '{"status":"DOWN","duration":"30s"}'

# Stage a fault on a shut port: accepted, link moves, reads stay down
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/interfaces/3/oper-status \
  -H 'Content-Type: application/json' \
  -d '{"status":"UP"}'
# {"link":"UP","oper_status":"DOWN","admin_status":"DOWN","masked":true,"peer_down":false}
# Raising admin-status afterwards surfaces the link with no further request.

# Bad ifIndex: 400 with valid list
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/interfaces/999/oper-status \
  -H 'Content-Type: application/json' \
  -d '{"status":"DOWN"}'
# {"error":"ifIndex 999 not present on device","validIfIndexes":[1,2,3,...]}
```

### `POST /api/v1/devices/{ip}/interfaces/{ifIndex}/admin-status`

Same shape and semantics, mutates `ifAdminStatus.<ifIndex>`.
Accepted statuses are `UP` / `DOWN` / `TESTING` (per IF-MIB ifAdminStatus enum).

**`oper-status` follows `admin-status`, asymmetrically**, per RFC 2863:

- `DOWN` and `TESTING` **force** `ifOperStatus` to `down(2)` / `testing(3)`.
- `UP` **forces nothing**. It releases `ifOperStatus` to the link state, so an interface whose link is down stays `down(2)`.

An admin bounce therefore does not repair a simulated link fault.
Under `-if-scenario 3` ("link failures, SFP issues, cable pull"), shutting and unshutting a port leaves `ifOperStatus = 2`, because the cable is still out.

The link trap, the syslog message and the ON_CHANGE update fire exactly when the derived `ifOperStatus` moves, and `ifLastChange` is stamped exactly then.
An admin change that does not move it, such as `UP` → `DOWN` over an already-down link, reports the admin leaf alone and leaves `ifLastChange` where the link-down transition put it, which is what RFC 2863 defines that object to mean.

An SNMP `SET` of `ifAdminStatus.<N>` is a third source through the same funnel (see the SNMP reference), so a SET and this POST are indistinguishable to every reader.

There is no way to hold an interface operationally up while it is administratively down.
RFC 2863 forbids that state, and no mutation source can produce it.

### Auto-revert semantics

When `duration` is set, the handler:

1. **Snapshots** the pre-mutation value at POST time. For `oper-status` that is the **link**, not the derived `ifOperStatus`, so a masked POST's revert restores the link it found instead of writing the mask into it
2. Performs the requested mutation immediately
3. Registers a timer keyed by `(ip, ifIndex, leaf)`
4. After `duration` elapses, reverts the slot back to the snapshotted value

An `admin-status` revert goes through the same admin funnel as the POST.
Oper therefore follows the restored admin value.
It is released to whatever the link has reached, not forced up, and fires the matching link trap only if that moves it.

Properties:

- A subsequent `duration` POST on the same leaf **cancels** the prior timer (the new timer's snapshot wins)
- Deleting the device or shutting the simulator down cancels all pending timers
- `duration` is capped at **24 hours**; values above this are rejected with 400
- Auto-revert **bypasses** `-if-flap-global-cap`, which limits only scheduler-driven flaps

If the slot was already at the requested status when the POST arrived (idempotent no-op), the auto-revert still fires but returns the slot to that same snapshotted value.
The auto-revert is therefore harmless on already-target slots.

## Cross-protocol consistency

A REST POST that flips a state field is observable simultaneously via:

| Surface | Read path | Value |
|---------|-----------|-------|
| SNMP `GET ifOperStatus.3` | `.1.3.6.1.2.1.2.2.1.8.3` | `INTEGER: 2` |
| gNMI `Get /interfaces/interface[name=Gi0/3]/state/oper-status` | state engine | `openconfig-interfaces:DOWN` |
| gNMI `Subscribe ON_CHANGE` on same path | state-change event | `update {oper-status: openconfig-interfaces:DOWN}` |

All three read the same engine slot, so the values match byte-for-byte at every instant.

**Trap and syslog firings follow state transitions.** Every derived `ifOperStatus` transition also fires the device's role-tagged link trap and syslog entries for that ifIndex, so a `POST DOWN` puts a `linkDown` trap and an `interface-down` syslog message on the wire.
A vendor overlay may fire more than one entry per role; `cisco_ios` fires both `%LINK-3-UPDOWN` and `%LINEPROTO-5-UPDOWN`.
Role-tagged entries are excluded from the random Poisson pick, so a link trap on the wire always corresponds to a state transition.
The on-demand endpoints (`POST .../trap`, `POST .../syslog`) still fire an entry without moving state.

## Status endpoint

`GET /api/v1/gnmi/status` reports two counters for the state engine:

```json
{
  "subsystem_active": true,
  "tls_enabled": true,
  "listeners": 30000,
  "active_subscriptions": 12,
  "updates_sent": 567,
  "updates_dropped": 0,
  "tls_handshake_failures": 0,
  "listener_accept_failures": 0,
  "state_events_emitted": 42,
  "state_events_dropped": 0
}
```

- `state_events_emitted`: cumulative count of state-change events successfully fanned out to ON_CHANGE listeners. Counts per-listener, not per-event: a flap on a device with 3 listeners increments by 3.
- `state_events_dropped`: per-listener drop count when a depth-16 channel overflows. Drop policy is oldest-drop.

## Operational notes

- **Per-device cost.** The state engine adds ~24 bytes per ifIndex. At 30k devices × ~10 interfaces that is ≈ 7 MiB total. Each ON_CHANGE subscriber adds one depth-16 listener channel and one goroutine, ≈ 4 KiB.
