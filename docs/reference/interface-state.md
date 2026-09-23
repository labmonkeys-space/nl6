# Interface state engine

nl6 maintains a per-device, in-memory **interface state engine** that owns `oper-status`, `admin-status`, and `last-change` for every known ifIndex.
SNMP, gNMI `Get`, and gNMI `Subscribe ON_CHANGE` all read from the same slot table — values agree byte-for-byte at every instant.
State can be mutated by a scheduled link-flap scenario, by a REST control plane or by an SNMP `SET` of `ifAdminStatus.<N>`.
A derived `ifOperStatus` transition also fires the device's role-tagged link trap and syslog entries for that interface.
Counter cycling is unaffected by state changes.

This is the capability reference.
For the gNMI subscribe semantics see [gNMI reference](gnmi.md#subscribe-semantics).

## Scope

Current behaviour:

- The state engine is the **single source of truth** for `ifOperStatus.<N>`, `ifAdminStatus.<N>`, and `ifLastChange.<N>`. SNMP reads pass through the engine; gNMI reads pass through it; ON_CHANGE Subscribe receives fan-out events on every mutation.
- The engine stores the **link state** and `ifAdminStatus`; `ifOperStatus` is **derived** from the pair per RFC 2863 and is never stored.
- Three mutation sources: the **flap scheduler** (Poisson-distributed link flaps per configured scenario), the **REST control plane** (`POST .../oper-status`, `POST .../admin-status`) and an **SNMP `SET`** of `ifAdminStatus.<N>`. The first two move the link; the last two move admin.
- **No gNMI `Set`.**

State-driven telemetry: every derived `ifOperStatus` transition fires the role-tagged `linkDown` / `linkUp` trap and `interface-down` / `interface-up` syslog entries of the device's catalog for that ifIndex (`InterfaceState.SetNotify`, wired at trap and syslog attach time).

Out of scope:

- Pausing the counter cycler when `oper-status` is `DOWN`
- Per-interface bandwidth scaling on admin-status changes

## Architecture

- **`InterfaceState` (`interface_state.go`)** — per-device state engine. Slot table: one `atomic.Uint64` per ifIndex, packed as `[lastChangeNs:58, admin:3, link:3]`. `ifOperStatus` is derived from `(admin, link)` on read, not stored, so the word is unchanged in width. A single atomic word guarantees a reader never sees a torn `(link, admin, lastChange)` tuple, and the derived `oper-status` comes from the same load. Reads are lock-free; writes are CAS-loop. `lastChangeNs` is wall-relative to the engine's construction time; mid-stream clock rewinds surface as a `LastChangeRewindSentinel` value in the public API and log a warning.
- **IF-MIB integration (`if_counters.go`)** — the `IfCounterCycler` owns the `InterfaceState` and dispatches the three state OIDs through it. `GetDynamicAt` for `.7` (admin) / `.8` (oper) / `.9` (last-change) reads atomically from the slot table; the SNMP wire encoding (decimal enum for `.7`/`.8`, TimeTicks for `.9`) is computed without locking.
- **Initial state (`if_counters.go`, `if_state.go`)** — each slot is seeded once at engine construction from the device's `ifAdminStatus.<N>` / `ifOperStatus.<N>` resource rows — the latter seeding the **link** — overlaid by the process-wide [`-if-scenario`](cli-flags.md#interface-state-scenarios). The seed stores `lastChangeNs = 0` and broadcasts nothing, so a scenario costs no link trap, no syslog and no ON_CHANGE update at fleet start. The scenario is applied here and nowhere else: there is no read-time override on the SNMP path, so every later mutation is what readers see.
- **Flap scheduler (`flap_scheduler.go`)** — single shared min-heap goroutine driving Poisson-distributed flaps per `(device, ifIndex)`. Mirrors `trap_scheduler.go` exactly. Mutates the **link state** directly; each `SetLinkState` call broadcasts a `StateChange` event only when the derived `ifOperStatus` moves.
- **REST control plane (`interface_state_api.go`)** — `setOperStatusHandler` / `setAdminStatusHandler` for explicit test-harness transitions. Supports optional `duration` for time-bounded transitions with snapshot-based auto-revert.
- **ON_CHANGE fan-out** — each Subscribe stream registers a depth-16 listener channel on `InterfaceState`; mutators call `Broadcast` after every state transition. See [gNMI reference](gnmi.md#subscribe-semantics) for the subscribe path.

## CLI flags

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-if-flap-scenario` | `clean` \| `rare` \| `typical` \| `aggressive` | `clean` | **seed** | Per-device flap scenario for the auto-start batch. REST-created devices default to `clean`; opt in via `if_flap_scenario` POST body. |
| `-if-flap-global-cap` | int (events/sec) | `0` | **global** | Simulator-wide rate ceiling on flap events. `0` is unlimited. |

The scheduler is **always started** so REST-created devices with a non-`clean` scenario will register and flap regardless of the CLI default.

## Scenarios

| Scenario | Mean inter-flap (per interface) | Down duration | Use case |
|----------|---------------------------------|---------------|----------|
| `clean` (default) | ∞ — no flaps | n/a | Steady-state regression testing |
| `rare` | ~6 hours | uniform 1–10 s | Background variance for long-running fleets |
| `typical` | ~15 minutes | uniform 1–30 s | Stress-testing collector alarm pipelines |
| `aggressive` | ~1 minute | uniform 1–5 s | Chaos / churn measurement |

Inter-arrival times are exponentially distributed (Poisson process); the scheduler runs a single shared min-heap goroutine across all devices.
When a flap fires:

1. Atomic-update the slot: `link = DOWN`, and `lastChangeNs = elapsed` if the derived `ifOperStatus` moved
2. Broadcast `StateChange{IfIndex, Oper=DOWN, ...}` to ON_CHANGE listeners — **only if it moved**
3. Schedule the matching up-event at `now + uniform(downLow, downHigh)`
4. When the up-event fires, repeat with `link = UP`

A flap on an interface whose `ifAdminStatus` is `DOWN` or `TESTING` is **masked**: the link moves, nothing observable changes, `ifLastChange` does not advance, and no trap, syslog or ON_CHANGE update fires.
The link is still there when the port is unshut.
This is what the hardware does, and it is why `-if-scenario 1 -if-flap-scenario aggressive` no longer produces a fleet reporting `ifAdminStatus = down(2)` with `ifOperStatus = up(1)`.

The down-up pair is atomic per `(device, ifIndex)` — a new flap is not scheduled while the interface is already down.

`-if-flap-global-cap 10` caps simulator-wide event rate at 10/s, backpressuring the scheduler when needed.
Default `0` is unlimited.
**Operational note:** at 30k devices × `typical` scenario, expected steady-state rate is ~30k / 900s ≈ 33 events/s.
Setting a cap below that floor will systematically delay the scheduler.

## REST control plane

### `POST /api/v1/devices/{ip}/interfaces/{ifIndex}/oper-status`

Sets the interface's **link state** — the physical-layer reading.
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
  { "link": "UP", "oper_status": "DOWN", "admin_status": "DOWN", "masked": true }
  ```

  `masked` is `true` whenever `ifAdminStatus` is `DOWN` or `TESTING` — that is, whenever the link state you now hold is not what collectors see.
  While it is set, no link trap, syslog message or gNMI `ON_CHANGE` update will fire from this interface and `ifLastChange` will not move, whatever the link does.
  It is deliberately a property of the interface rather than of the individual request: a POST that finds the link already at the requested value changes nothing and still needs to report masking, and a POST whose link value happens to equal the masked `ifOperStatus` is masked too.
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
# {"link":"UP","oper_status":"DOWN","admin_status":"DOWN","masked":true}
# Raising admin-status afterwards surfaces the link with no further request.

# Bad ifIndex — 400 with valid list
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/interfaces/999/oper-status \
  -H 'Content-Type: application/json' \
  -d '{"status":"DOWN"}'
# {"error":"ifIndex 999 not present on device","validIfIndexes":[1,2,3,...]}
```

### `POST /api/v1/devices/{ip}/interfaces/{ifIndex}/admin-status`

Same shape and semantics, mutates `ifAdminStatus.<ifIndex>`.
Accepted statuses are `UP` / `DOWN` / `TESTING` (per IF-MIB ifAdminStatus enum).

**`oper-status` follows `admin-status`, asymmetrically.** The POST goes through the engine's admin funnel (`InterfaceState.ApplyAdminStatus`).
RFC 2863's rule is not symmetric, and the asymmetry is the model:

- `DOWN` and `TESTING` **force** `ifOperStatus` to `down(2)` / `testing(3)`.
- `UP` **forces nothing**. It releases `ifOperStatus` to the link state, so an interface whose link is down stays `down(2)`.

An admin bounce therefore does not repair a simulated link fault.
Under `-if-scenario 3` — "link failures, SFP issues, cable pull" — shutting and unshutting a port leaves `ifOperStatus = 2`, because the cable is still out.

The link trap, the syslog message and the ON_CHANGE update fire exactly when the derived `ifOperStatus` moves, and `ifLastChange` is stamped exactly then.
An admin change that does not move it — `UP` → `DOWN` over an already-down link — reports the admin leaf alone and leaves `ifLastChange` where the link-down transition put it, which is what RFC 2863 defines that object to mean.

An SNMP `SET` of `ifAdminStatus.<N>` is a third source through the same funnel (see the SNMP reference), so a SET and this POST are indistinguishable to every reader.

There is no way to hold an interface operationally up while it is administratively down.
That state is what RFC 2863 forbids, and it is now unrepresentable rather than merely discouraged: the engine stores the link and derives `ifOperStatus`, so no mutation source can write the two into disagreement.

### Auto-revert semantics

When `duration` is set, the handler:

1. **Snapshots** the pre-mutation value at POST time — for `oper-status` that is the **link**, not the derived `ifOperStatus`, so a masked POST's revert restores the link it found instead of writing the mask into it
2. Performs the requested mutation immediately
3. Registers a timer in `SimulatorManager.revertTimers`, keyed by `(ip, ifIndex, leaf)`
4. After `duration` elapses, reverts the slot back to the snapshotted value

An `admin-status` revert goes through the same admin funnel as the POST.
Oper therefore follows the restored admin value — released to whatever the link has reached, not forced up — and fires the matching link trap only if that moves it.

Properties:

- A subsequent `duration` POST on the same leaf **cancels** the prior timer (the new timer's snapshot wins)
- `device.Stop()` and `manager.Shutdown()` cancel **all** pending timers for the device / process — no orphan goroutines after deletion
- `duration` is capped at **24 hours** (`maxRevertAfter`); values above this are rejected with 400
- Auto-revert **bypasses** `-if-flap-global-cap` — on-demand HTTP fires match the trap/syslog convention; the rate-limiter is for the scheduler-driven flap traffic, not for test-harness operator actions

If the slot was already at the requested status when the POST arrived (idempotent no-op), the auto-revert still fires but returns the slot to that same snapshotted value — i.e., the auto-revert is harmless on already-target slots.
This is the snapshot semantic (vs an earlier flip-to-opposite design that surprised on already-DOWN slots).

## Cross-protocol consistency

A REST POST that flips a state field is observable simultaneously via:

| Surface | Read path | Value |
|---------|-----------|-------|
| SNMP `GET ifOperStatus.3` | `.1.3.6.1.2.1.2.2.1.8.3` | `INTEGER: 2` |
| gNMI `Get /interfaces/interface[name=Gi0/3]/state/oper-status` | `state.OperStatus(3)` | `openconfig-interfaces:DOWN` |
| gNMI `Subscribe ON_CHANGE` on same path | listener channel event | `update {oper-status: openconfig-interfaces:DOWN}` |

All three read from the same `atomic.Uint64` slot, so the values match byte-for-byte at every instant.
The smoke test on the Linux deploy host verified this end-to-end (`smoke-results-linux.md`).

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

- `state_events_emitted` — cumulative count of state-change events successfully fanned out to ON_CHANGE listeners. Counts per-listener, not per-event: a flap on a device with 3 listeners increments by 3.
- `state_events_dropped` — per-listener drop count when a depth-16 channel overflows. Drop policy is oldest-drop.

## Operational notes

- **Per-device cost.** The state engine adds ~24 bytes per ifIndex (one `atomic.Uint64` slot) — at 30k devices × ~10 ifs ≈ 7 MiB total. Per ON_CHANGE subscriber: one depth-16 listener channel + one goroutine ≈ ~4 KiB. The §0.4 / §9.5 Linux scale spikes measured the full envelope.
- **Cap sizing.** `-if-flap-global-cap` should leave headroom for expected steady-state. At 30k devices × `typical` (~15 min mean) = ~33 events/s; a cap of 50 leaves 50% headroom for burst.
- **No `Reset()`.** `Snapshot(ifIndex)` exists and the REST auto-revert reads it; there is no `Reset()`. A "reload scenario" feature would need one. Today the only transition paths are the one-time seed at construction and the mutator API.
- **`InitIfCountersWithScenario` panics on re-init.** The engine enforces single-init per device to prevent silently orphaning gNMI ON_CHANGE listeners. Any future code path that needs to re-init must first migrate listeners explicitly.
- **`ifAdminStatus` collapses three cases to `up(1)`** — out-of-range ifIndex, in-range-but-unseeded slot, and explicit AdminUp all return the same value. IF-MIB does not define an "unknown" enum for `ifAdminStatus` (only `up(1) | down(2) | testing(3)`), so the engine cannot surface a sentinel without violating the on-wire contract. Consumers that need to distinguish "ghost interface" from "real interface up" MUST consult `IfIndices()` upstream rather than inferring from `AdminStatus(ifIndex)`. `ifOperStatus` is asymmetric here — IF-MIB defines `unknown(4)`, so `OperStatus` returns `OperUnknown` for the same ghost cases.
- **Wall-relative timestamps cap at ~9.13 years.** `last-change` is packed into a 58-bit relative-nanoseconds field; the all-ones value (`0x03FF…FF`, ~9.13y from engine boot) is reserved as the in-band clock-rewind sentinel. A simulator running past this uptime would see legitimate timestamps collide with the sentinel and surface as `LastChangeRewindSentinel` on the gNMI wire / `"0"` on SNMP. This is well outside realistic test-harness operational scope — the simulator does not target multi-year continuous-uptime workloads. If you need longer ranges, the slot layout (3+3+58) can be widened by re-packing.
