# Interface state engine

nl6 maintains a per-device, in-memory **interface state engine** that owns
`oper-status`, `admin-status`, and `last-change` for every known ifIndex.
SNMP, gNMI `Get`, and gNMI `Subscribe ON_CHANGE` all read from the same
slot table — values agree byte-for-byte at every instant. State can be
mutated by a scheduled link-flap scenario or by a REST control plane;
counter cycling and other protocols are unaffected by state changes in
Tier B.

This is the capability reference. For the design rationale see
[`openspec/specs/interface-state/spec.md`](https://github.com/labmonkeys-space/nl6/blob/main/openspec/specs/interface-state/spec.md);
for the gNMI subscribe semantics see [gNMI reference](gnmi.md#subscribe-semantics).

## Scope

In Tier B (the current shipping version):

- The state engine is the **single source of truth** for `ifOperStatus.<N>`,
  `ifAdminStatus.<N>`, and `ifLastChange.<N>`. SNMP reads pass through
  the engine; gNMI reads pass through it; ON_CHANGE Subscribe receives
  fan-out events on every mutation.
- Two mutation sources: the **flap scheduler** (Poisson-distributed link
  flaps per configured scenario) and the **REST control plane**
  (`POST .../oper-status`, `POST .../admin-status`).
- **No gNMI `Set`, no SNMP `Set`.** The simulator is read-only against
  external collectors; state mutation is REST-only.

Out of scope for Tier B (deferred to Tier C):

- Tying link-state transitions to `linkDown` / `linkUp` SNMP traps
- Tying transitions to `interface-up` / `interface-down` syslog messages
- Pausing the counter cycler when `oper-status` is `DOWN`
- Per-interface bandwidth scaling on admin-status changes

In Tier B SNMP and gNMI agree on state; trap / syslog firings remain on
their independent random schedule (decoupled). The Tier C follow-up
wires them together.

## Architecture

- **`InterfaceState` (`interface_state.go`)** — per-device state engine.
  Slot table: one `atomic.Uint64` per ifIndex, packed as
  `[lastChangeNs:58, admin:3, oper:3]`. Single atomic word guarantees a
  reader never sees a torn `(oper, admin, lastChange)` tuple. Reads are
  lock-free; writes are CAS-loop. `lastChangeNs` is wall-relative to the
  engine's construction time; mid-stream clock rewinds surface as a
  `LastChangeRewindSentinel` value in the public API and log a warning.
- **IF-MIB integration (`if_counters.go`)** — the `IfCounterCycler`
  owns the `InterfaceState` and dispatches the three state OIDs through
  it. `GetDynamicAt` for `.7` (admin) / `.8` (oper) / `.9` (last-change)
  reads atomically from the slot table; the SNMP wire encoding (decimal
  enum for `.7`/`.8`, TimeTicks for `.9`) is computed without locking.
- **Flap scheduler (`flap_scheduler.go`)** — single shared min-heap
  goroutine driving Poisson-distributed flaps per `(device, ifIndex)`.
  Mirrors `trap_scheduler.go` exactly. Mutates `InterfaceState` directly;
  each `SetOperStatus` call broadcasts a `StateChange` event.
- **REST control plane (`interface_state_api.go`)** — `setOperStatusHandler`
  / `setAdminStatusHandler` for explicit test-harness transitions.
  Supports optional `duration` for time-bounded transitions with
  snapshot-based auto-revert.
- **ON_CHANGE fan-out** — each Subscribe stream registers a depth-16
  listener channel on `InterfaceState`; mutators call `Broadcast` after
  every state transition. See [gNMI reference](gnmi.md#subscribe-semantics)
  for the subscribe path.

## CLI flags

| Flag | Type | Default | Scope | Purpose |
|------|------|---------|-------|---------|
| `-if-flap-scenario` | `clean` \| `rare` \| `typical` \| `aggressive` | `clean` | **seed** | Per-device flap scenario for the auto-start batch. REST-created devices default to `clean`; opt in via `if_flap_scenario` POST body. |
| `-if-flap-global-cap` | int (events/sec) | `0` | **global** | Simulator-wide rate ceiling on flap events. `0` is unlimited. |

The scheduler is **always started** so REST-created devices with a
non-`clean` scenario will register and flap regardless of the CLI
default.

## Scenarios

| Scenario | Mean inter-flap (per interface) | Down duration | Use case |
|----------|---------------------------------|---------------|----------|
| `clean` (default) | ∞ — no flaps | n/a | Steady-state regression testing |
| `rare` | ~6 hours | uniform 1–10 s | Background variance for long-running fleets |
| `typical` | ~15 minutes | uniform 1–30 s | Stress-testing collector alarm pipelines |
| `aggressive` | ~1 minute | uniform 1–5 s | Chaos / churn measurement |

Inter-arrival times are exponentially distributed (Poisson process); the
scheduler runs a single shared min-heap goroutine across all devices.
When a flap fires:

1. Atomic-update the slot: `oper-status = DOWN`, `lastChangeNs = elapsed`
2. Broadcast `StateChange{IfIndex, Oper=DOWN, ...}` to ON_CHANGE listeners
3. Schedule the matching up-event at `now + uniform(downLow, downHigh)`
4. When the up-event fires, repeat with `oper-status = UP`

The down-up pair is atomic per `(device, ifIndex)` — a new flap is not
scheduled while the interface is already down.

`-if-flap-global-cap 10` caps simulator-wide event rate at 10/s,
backpressuring the scheduler when needed. Default `0` is unlimited.
**Operational note:** at 30k devices × `typical` scenario, expected
steady-state rate is ~30k / 900s ≈ 33 events/s. Setting a cap below
that floor will systematically delay the scheduler.

## REST control plane

### `POST /api/v1/devices/{ip}/interfaces/{ifIndex}/oper-status`

Mutates `ifOperStatus.<ifIndex>` on the device.

Body:

```json
{
  "status": "UP" | "DOWN" | "TESTING",
  "duration": "<go-duration>"   // optional
}
```

Returns:

- `202 Accepted` with empty `{}` body on success
- `400 Bad Request` for malformed body, unknown `status`, or unknown `ifIndex`
  (400 body includes `validIfIndexes` array)
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

# Bad ifIndex — 400 with valid list
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/interfaces/999/oper-status \
  -H 'Content-Type: application/json' \
  -d '{"status":"DOWN"}'
# {"error":"ifIndex 999 not present on device","validIfIndexes":[1,2,3,...]}
```

### `POST /api/v1/devices/{ip}/interfaces/{ifIndex}/admin-status`

Same shape and semantics, mutates `ifAdminStatus.<ifIndex>`. Accepted
statuses are `UP` / `DOWN` / `TESTING` (per IF-MIB ifAdminStatus enum).

### Auto-revert semantics

When `duration` is set, the handler:

1. **Snapshots** the pre-mutation slot value at POST time
2. Performs the requested mutation immediately
3. Registers a timer in `SimulatorManager.revertTimers`, keyed by
   `(ip, ifIndex, leaf)`
4. After `duration` elapses, reverts the slot back to the snapshotted value

Properties:

- A subsequent `duration` POST on the same leaf **cancels** the prior
  timer (the new timer's snapshot wins)
- `device.Stop()` and `manager.Shutdown()` cancel **all** pending timers
  for the device / process — no orphan goroutines after deletion
- `duration` is capped at **24 hours** (`maxRevertAfter`); values above
  this are rejected with 400
- Auto-revert **bypasses** `-if-flap-global-cap` — on-demand HTTP fires
  match the trap/syslog convention; the rate-limiter is for the
  scheduler-driven flap traffic, not for test-harness operator actions

If the slot was already at the requested status when the POST arrived
(idempotent no-op), the auto-revert still fires but returns the slot to
that same snapshotted value — i.e., the auto-revert is harmless on
already-target slots. This is the snapshot semantic (vs an earlier
flip-to-opposite design that surprised on already-DOWN slots).

## Cross-protocol consistency

A REST POST that flips a state field is observable simultaneously via:

| Surface | Read path | Value |
|---------|-----------|-------|
| SNMP `GET ifOperStatus.3` | `.1.3.6.1.2.1.2.2.1.8.3` | `INTEGER: 2` |
| gNMI `Get /interfaces/interface[name=Gi0/3]/state/oper-status` | `state.OperStatus(3)` | `openconfig-interfaces:DOWN` |
| gNMI `Subscribe ON_CHANGE` on same path | listener channel event | `update {oper-status: openconfig-interfaces:DOWN}` |

All three read from the same `atomic.Uint64` slot, so the values match
byte-for-byte at every instant. The smoke test on the Linux deploy host
verified this end-to-end (`smoke-results-linux.md`).

In Tier B, **trap and syslog firings do NOT automatically follow state
transitions** — `linkDown` traps and `interface-down` syslog messages
still fire on their independent random Poisson schedule, decoupled from
the actual `InterfaceState`. Tier C will wire them together. Until then,
operators expecting one-to-one correlation between a `POST DOWN` and a
`linkDown` trap on the wire should drive both via the existing
on-demand endpoints (`POST .../trap`, `POST .../syslog`).

## Status endpoint

`GET /api/v1/gnmi/status` reports two counters for the state engine:

```json
{
  "subsystem_active": true,
  "listeners": 30000,
  "active_subscriptions": 12,
  "updates_sent": 567,
  "updates_dropped": 0,
  "tls_handshake_failures": 0,
  "state_events_emitted": 42,
  "state_events_dropped": 0
}
```

- `state_events_emitted` — cumulative count of state-change events
  successfully fanned out to ON_CHANGE listeners. Counts per-listener,
  not per-event: a flap on a device with 3 listeners increments by 3.
- `state_events_dropped` — per-listener drop count when a depth-16
  channel overflows. Drop policy is oldest-drop.

## Operational notes

- **Per-device cost.** The state engine adds ~24 bytes per ifIndex
  (one `atomic.Uint64` slot) — at 30k devices × ~10 ifs ≈ 7 MiB total.
  Per ON_CHANGE subscriber: one depth-16 listener channel + one
  goroutine ≈ ~4 KiB. The §0.4 / §9.5 Linux scale spikes measured the
  full envelope.
- **Cap sizing.** `-if-flap-global-cap` should leave headroom for
  expected steady-state. At 30k devices × `typical` (~15 min mean) =
  ~33 events/s; a cap of 50 leaves 50% headroom for burst.
- **Snapshot is internal-only.** The state engine's `Snapshot()` /
  `Reset()` are intentionally absent in Tier B. A future "reload
  scenario" feature would require both; today the only state-engine
  transition path is the mutator API.
- **`InitIfCountersWithScenario` panics on re-init.** The engine
  enforces single-init per device to prevent silently orphaning gNMI
  ON_CHANGE listeners. Any future code path that needs to re-init must
  first migrate listeners explicitly.
