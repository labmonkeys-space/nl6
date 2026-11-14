# Interface state engine

Engineering record for `interface_state.go`, `link_propagation.go`, `interface_hierarchy.go`, `if_state.go` and `interface_state_api.go`.
Moved from CLAUDE.md so the auto-loaded file stays under its size limit.
Read this before changing any of these areas.
Each section states the rule first, then the defect that produced it, then the mistake that is easy to reintroduce.

The counter side (dials, hold, roll-up, clock) is in `context/if-counters.md`.
The user-facing reference is `docs/reference/interface-state.md`.

## Contents

| Section | Issue | One-line rule |
| --- | --- | --- |
| [Oper status is derived](#oper-status-is-derived-never-stored) | nl6#694 | `deriveOper(admin, link, peerDown)` is the only place RFC 2863's rule is written |
| [Mutators and events](#mutators-and-events) | nl6#694 | Events, `lastChange` and Tier C fire on the derived transition only |
| [Link propagation](#link-propagation-across-the-topology-graph) | nl6#1023, nl6#1029 | The far end holds a `peerDown` cause bit; what propagates is `Transmits`, never the bit |
| [Subinterfaces](#subinterfaces-follow-their-parent) | nl6#842, nl6#843 | A child reads `lowerLayerDown(7)` while its parent is not up |
| [Scenario seed](#-if-scenario-is-a-seed) | nl6#692 | The scenario seeds once at init; there is no read-time override |
| [REST auto-revert](#rest-auto-revert) | | `duration` reverts the slot, keyed per leaf, capped at 24h |

## Oper status is derived, never stored

**Rule:** `oper-status` is a pure function of the slot.
`deriveOper(admin, link, peerDown)` is the single place RFC 2863's rule is written, and the rule is asymmetric.

| Admin | Effect on oper |
| --- | --- |
| `down(2)`, `testing(3)` | Forces oper to the admin value |
| `up(1)` | Releases oper to the link, held `down(2)` while `peerDown` is set |

**Storage:** `IfCounterCycler` owns one `InterfaceState` per device.
Each ifIndex has a packed `atomic.Uint64` slot.

| Bits | Field | Note |
| --- | --- | --- |
| 3 | link | The bits that held oper before nl6#694 |
| 2 | admin | IF-MIB uses values 1..3, so 2 bits suffice |
| 1 | `peerDown` | Split off the admin field by nl6#1023 |
| 58 | `lastChange` | Wall-relative ns, untouched by both splits |

**Served columns:** `ifAdminStatus.<N>` (`.7`), `ifOperStatus.<N>` (`.8`) and `ifLastChange.<N>` (`.9`) are claimed by the cycler.
`GetDynamicAt` reads them from the engine, so SNMP and gNMI agree byte for byte at the same instant.
Cross-protocol consistency in Tier B: SNMP, gNMI Get and gNMI Subscribe ON_CHANGE all see the same value at the same instant.

**Why no fourth field for oper:** it would cost about 8 years of `lastChange` range and create a second source of truth for a pure function of the other two.
nl6#1023 split the admin field for `peerDown` for the same reason.

## Mutators and events

**Rule:** every event, `lastChange` stamp and Tier C notification keys on the derived transition.
A masked link move stamps nothing and fires nothing.

| Mutator | Moves | Returns | Callers |
| --- | --- | --- | --- |
| **`SetLinkState`** | link | `(LinkMutation, []StateChange)` | Flap scheduler, REST `oper-status` POST and its auto-revert |
| **`ApplyAdminStatus`** | admin, one CAS, no cascade | `[]StateChange` | REST `admin-status` POST and its auto-revert, SNMP SET of `ifAdminStatus.<N>` (`snmp_set.go`) |
| **`SetPeerDown`** | `peerDown` | `[]StateChange` | `resyncLinks` without `seed` |
| **`SeedPeerDown`** | `peerDown`, silently | `[]int` | `resyncLinks` with `seed` |

`SetAdminStatus` is unexported as `setAdminLeaf`, so `ApplyAdminStatus` is the only admin door.
Admin-up over a down link returns one event and does not raise oper.

**`LinkMutation` is three-way** (`LinkUnchanged`, `LinkMovedMasked`, `LinkMovedVisible`).
The `bool` it replaced conflated "already at target" with "suppressed".
That is why the flap scheduler's no-op log once named two causes, one of which described a guard that did not exist.

**Broadcast path:**

1. The slot store commits.
2. `Broadcast` sends a `StateChange` to every registered ON_CHANGE Subscribe listener through a per-stream depth-16 channel, drop-oldest on overflow.
   It drops a zero-`Changed` event rather than fanning out an update for ifIndex 0.
3. The counter-hold hook (`if_counter_hold.go`) reconciles every dial-derived column against the derived oper.
   Columns hold while oper is not `up(1)`, through a per-slot immutable ledger applied at the one `heldDeltasAt` read in `GetDynamicAt`, with a seqlock and two instant clamps that keep polls monotonic. Details in `context/if-counters.md`.
4. The Tier C hook fires, oper-only, gated on `LeafOperStatus`.

**Tier C (`correlate-state-notifications`):** an oper transition fires correlated link traps and syslog for that ifIndex.
`InterfaceState.SetNotify` installs an `atomic.Pointer[func(StateChange)]` hook.
The manager wires it at trap and syslog attach time (`wireStateNotify`) to call `FireForInterface(entry, ifIndex)` on the role-matched catalog entries (`EntriesByRole`, vendor wins per role).
The closure snapshots the exporters under `device.mu.RLock` and fires outside the lock; a closing guard handles teardown.
All mutation sources are covered because they share the single `Broadcast` funnel.
Link telemetry volume rides real state changes (`-if-flap-scenario` or REST), and state-driven fires bypass the Poisson global cap on initial transmit.

**Flap scheduler (`flap_scheduler.go`):** one shared min-heap goroutine drives Poisson-distributed flaps per (device, ifIndex), the same shape as `trap_scheduler.go`.
It needs no admin guard.
An admin-down interface is protected by the derivation, so a masked flap moves real state that surfaces when the port is unshut.
Masked flaps are deliberately not logged: at `aggressive` on a shut fleet that is about 30k lines per minute describing the feature working.

**`POST .../oper-status` is breaking:** it sets the link and answers 202 with `{link, oper_status, admin_status, masked, masked_by, peer_down}`.
Under admin-down its effect is masked, not refused, because a 409 would make the contract depend on another leaf.
`masked_by` (nl6#1025) names the cause, present only while `masked` is true: `admin`, `peer` or `parent`, the first clause of `deriveChildOper` that fired, in that function's order. The REST layer adds no rule of its own; a consumer reads the field instead of re-deriving the cause from `peer_down` and `admin_status`.

**Counter roll-up (`if_counter_rollup.go`):** a child with one lower layer serves a hashed share of its parent's served delta.
An aggregate with two or more `ifStackTable` lower layers (from `readStackLayers`) serves the sum of its members', composed inside the same bracket.
The child's packet profile and bases are inherited so the bound is exact per column.
xr-chassis `bundle_members` renders the stack rows.

**Do not reintroduce:**

- A cascade in `ApplyAdminStatus`. Oper is derived; the single CAS is the contract.
- An auto-revert that snapshots the derived oper. It must snapshot `Snapshot().Link`, or a masked POST's revert writes the mask into the link.
- A log line for masked flaps.

## Link propagation across the topology graph

**Rule:** with **`-topology-link-propagation`** (off by default), the far end of a topology link goes down while the near end does not transmit.
The far end's fault is a cause, not a copy.
Its slot carries the `peerDown` bit and `deriveOper` holds an up link `down(2)` under admin up.
The far end's own link is never written.

**What propagates is `StateSnapshot.Transmits`:** admin up and own link up.
Never `peerDown`.
Counting the bit latched a link down: A shut, B held, B's echo stored beneath A's shutdown as `LinkMovedMasked`, both down after `no shutdown`.
Reproduced on 4d873b6.

**Why a cause bit and not a link copy:** a fault on each end composes, and each end's flap schedule, REST POST and auto-revert keep owning their own link.
Copying the near end's link let one end's up fire cut the other's outage short.

**`SetPeerDown` has `SetLinkState`'s contract:** events only on a derived transition (stamping `lastChange`, cascading to subinterfaces), masked beneath admin down or an own fault, a no-op on the same value.

**`publishStateChanges` (`link_propagation.go`) is the one post-mutation helper at every broadcast site.**
Sites: the flap scheduler through `FlapSchedulerOptions.Publish`, REST `oper-status` and `admin-status` and their auto-reverts, SNMP SET.
It runs after a masked link move too, because a masked move fires nothing but changes what the port transmits.

**Every call is a resync**, in this order:

1. Resolve both ends to their engines. Resolution reads `sm.mu`, which `DeleteDevice` holds across a teardown.
2. Under `linkPropMu`: re-check the link, read the near end, write the far end. The last resync sees the newest state, and a link removal's release cannot be overtaken.
3. Broadcast after the lock, because the Tier C hook takes the far device's `mu`.

**Lifecycle:**

| Event | Action | Visible? |
| --- | --- | --- |
| `AddTopologyLinks` | `resyncLinks(links, false)` | Yes |
| Device publication, both creation paths, beside `invalidateLLDPServedCache` | `resyncDeviceLinks`, which calls `resyncLinks(links, true)` | No, see below |
| Any mutation through `publishStateChanges` | Resync of the moved port's links | Yes |
| `RemoveTopologyLink`, `Clear` | Release | Yes |
| `PruneDevice`, deferred after `sm.mu` in `DeleteDevice` | Release | Yes |

**Silent seed at publication (nl6#1029):** with **`-topology-config`**, a port seeded down holds its partner from the moment the later of the two devices is published.
`SeedPeerDown` sets the bit and the counter hold with no event and no `lastChange` stamp, on both ends.
That includes the existing partner's port, which was up only because its neighbour did not exist yet.
Every other path stays visible.

**Edge cases:**

- A missing device, or an `ifIndex` its device does not have, holds nothing and takes nothing.
- A seed never clears a bit in practice. A port carries one link (`AddLinks` rejects a second), a fresh engine holds no bit, and a pruned partner was released visibly by `PruneDevice` first. The symmetric write stays because the same-value no-op is what makes a resync idempotent.
- A device type with no engine transmits.
- `Transmits` reads the port's own admin and link only, so a subinterface end does not propagate its parent's outage. Documented: configure links on physical ports.
- `StateChange.PeerDown` lets the IOS XE NETCONF dialect treat a held port as carrier-less (`iosxeSuppress`).
- The REST body reports `peer_down`. On an `oper-status` POST, `masked` is true while the bit holds an up link down, and `masked_by` is `peer` unless admin is also down (then `admin`: the engine returns on admin first).
- `downEnd` in the graph names only ends down by their own admin or link.

**Do not reintroduce:**

- Propagating `peerDown` instead of `Transmits`.
- Writing the far end's link.
- Broadcasting under `linkPropMu`.

## Subinterfaces follow their parent

**Rule:** `deriveChildOper` wraps `deriveOper`.
A child that would be up reads `lowerLayerDown(7)` while its parent is not up.
Its own forced state wins.
The child's stored link and admin are never written.

**Parent sources**, in order:

| Source | Rule | Where |
| --- | --- | --- |
| Name | `<parent>.<canonical uint32>` via `splitSubinterfaceName` (`interface_hierarchy.go`) | Catalogue `subinterfaces` key, engine parent table, legacy resolver |
| `ifStackTable` | `stackedParents`, `ifStackStatus.<higher>.<lower>` = `active(1)` | Only where the name rule gives none; how Nokia's `toWAN` follows `port 1/1/1` |

The engine's parent table (`setParents`) is built in `InitIfCountersWithScenario` before publish, immutable, one level.
The stack is cached per `*DeviceResources`.
Hierarchy warnings log once per process, since the hierarchy is rebuilt per device.

**Cascade:** a parent's visible transition CAS-stamps each moved child's `lastChange` and returns the child's event after the parent's.
That is why `SetLinkState` returns `(LinkMutation, []StateChange)` and every caller broadcasts all of them.
It is what gives the unit its ON_CHANGE update from every mutation source.

**Traps:** `linkRoleFor` fires no trap for `up(1)` to `lowerLayerDown(7)` in either direction.
RFC 2863 keys both traps on `down(2)`, so a port bounce sends its unit no unpaired `linkUp`.
Events carry `PrevOper` for consumers that need the pair.

**Locking:** mutations inside a family hold `familyMu`.
A child's oper reads its parent's slot.
Per-slot CAS alone let a stale cascade stamp a child with an older parent transition (`ifLastChange` went backwards), and let a child move derive from a parent that changed before its CAS.
Interfaces outside a family never take the lock.

**Who sees a child:**

| Consumer | Behaviour |
| --- | --- |
| gNMI | Hides only `NamedSubinterface`s, served under their port's `subinterfaces`; a stacked child stays an interface |
| `FlapScheduler.Register` | Skips `Linkless` interfaces: children and `softwareLoopback(24)` |
| Legacy `pathResolver` | Skips children on `*`, answers `NotFound` for a child name, drops child events in `changedUpdatesForPath`; this is why dial-out lists what dial-in lists |

## `-if-scenario` is a seed

**Rule:** **`-if-scenario`** is applied once per device at init.
There is no read-time override (nl6#692).

`scenarioSeed` (`if_state.go`) overlays the scenario on the JSON `.7`/`.8` rows inside `InitIfCountersWithScenario`'s seed loop, through `Seed`.
Not through the mutators: they stamp `lastChange` and broadcast, so a fleet would report a transition per interface at boot and fire Tier C link telemetry for state that never changed.
The flag is validated at startup (`IfStateConfig.validate`), fatal after `-help` and `-version`.

**Scenario 1 seeds admin only and preserves the link (nl6#694).**
Writing the link down too would model 30,000 severed cables rather than 30,000 shut ports, so unshutting a port would leave it dead.
It had to write oper as well while a cascade existed.

**Scenario 2 is the identity.**
The default fleet's wire output is unchanged except at the 18 `cisco_nexus_9500` interfaces (ifIndex 33-40, 51-60) whose JSON ships `ifAdminStatus = 2` with `ifOperStatus = 1`.
The derivation serves those `2`.
The rows are not edited: read as a link seed, `ifOperStatus = 1` on a shut port means the cable is good.

**The defect (nl6#692):** `findResponse` asked the cycler before `getIfStateOverride`.
The cycler has served `.7`/`.8`/`.9` from the engine since v0.8.0, so the override was dead on every engine-backed device and was never wired into GETNEXT or GETBULK.
The flag had done nothing for 22 releases while `cli-flags.md` documented four working scenarios.
The issue reported the inverse of the defect; the probe is what caught it.

**Measurement:** `TestShippedServedStateDigest` and `TestServedStateDigestMovedOnlyAtTheNexusRows` (`if_served_state_digest_test.go`).
nl6#694 had to build them because `shippedTagDigest` and `shippedOIDEncodingDigest` read resource files, not served values.
Neither could witness a change to `.7`/`.8`/`.9`, so nl6#693's "byte-identical" acceptance line named a measurement nothing implemented.

**Do not reintroduce:** a read-time override.
It shadows a SET and a REST POST, which is what nl6#692 was filed for, and re-splits GET from the walk.

## REST auto-revert

**Rule:** `POST .../oper-status` and `POST .../admin-status` accept an optional `duration` field.

```json
{"status":"DOWN","duration":"30s"}
```

| Behaviour | Detail |
| --- | --- |
| Snapshot | The handler snapshots the pre-mutation slot value at POST time; for `oper-status` that is `Snapshot().Link`, never the derived oper |
| Timer key | `SimulatorManager.revertTimers`, keyed by `(ip, ifIndex, isOper)`; a later duration POST on the same leaf cancels the first |
| Cancellation | `device.Stop()` cancels per-device timers, `manager.Shutdown()` cancels all |
| Cap | 24h (`maxRevertAfter`); over cap returns 400 |
| Rate limit | On-demand HTTP fires bypass the flap scheduler's `-if-flap-global-cap`, matching the trap and syslog convention for test-harness use |
