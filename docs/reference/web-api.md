# Web API

The simulator exposes a REST control-plane on port 8080 (override with
[`-port`](cli-flags.md#core-flags)) for device CRUD, CSV / route-script
export, system stats, and flow-export status. The same port also serves the
management web UI at `/`.

## Endpoint catalog

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/devices` | POST | Create devices (bulk, round-robin, category-based). One batch at a time: a concurrent create is refused `409`. |
| `/api/v1/devices` | GET | List all devices. |
| `/api/v1/devices/{id}` | DELETE | Delete a specific device. |
| `/api/v1/devices` | DELETE | Delete all devices. |
| `/api/v1/devices/export` | GET | Export device list to CSV. |
| `/api/v1/devices/routes` | GET | Generate a routing script (Debian/Ubuntu). |
| `/api/v1/resources` | GET | List available device resource types. |
| `/api/v1/resources/reload` | POST | Evict cached device profiles so the next creation re-reads them from disk. Existing devices keep their snapshot. `409` during a creation batch. |
| `/api/v1/status` | GET | Manager status. |
| `/api/v1/system-stats` | GET | System stats (file descriptors, memory). |
| `/api/v1/version` | GET | Running simulator version string. Immutable per process; response carries `Cache-Control: max-age=3600`. |
| `/api/v1/flows/status` | GET | Flow export status and cumulative counters. |
| `/api/v1/traps/status` | GET | SNMP trap export status, INFORM counters, and per-type catalog map. |
| `/api/v1/devices/{ip}/trap` | POST | Fire a named catalog trap on a specific device. |
| `/api/v1/syslog/status` | GET | UDP syslog export status, counters, and per-type catalog map. |
| `/api/v1/devices/{ip}/syslog` | POST | Fire a named catalog syslog message on a specific device. |
| `/api/v1/devices/{ip}/optical/{component}/degrade` | POST | Degrade one optical channel on demand (optional auto-expiring window). |
| `/api/v1/devices/{ip}/optical` | GET | Current degradation state of every optical channel on a device. |
| `/api/v1/gnmi/status` | GET | gNMI (dial-in) subsystem status: listeners, subscriptions, update/state-event counters. |
| `/api/v1/gnmi/dialout/status` | GET | gNMI dial-out status: per-(collector, flavor) streams, updates sent/dropped, reconnects, send failures. |
| `/api/v1/dns/status` | GET | DNS service-discovery status: zones + serials, publish counters, NOTIFY tallies. |
| `/api/v1/fidelity` | GET | Fidelity mode: the value **in force**, the startup flag it began from, and any pending auto-revert. |
| `/api/v1/fidelity` | POST | Toggle fleet silence at runtime, with optional `duration` auto-revert (24h cap). |
| `/api/v1/profiling` | GET | Continuous-profiling gate: the value **in force**, the startup flag, whether the SDK is pushing, and any pending auto-revert. |
| `/api/v1/profiling` | POST | Open or close the gate at runtime, optionally with a push `server_address` and a `duration` auto-revert (24h cap). |
| `/debug/pprof/` | GET | The Go `net/http/pprof` surface plus `godeltaprof`'s `delta_heap` / `delta_block` / `delta_mutex`, for a Grafana Alloy scrape. `503` while the gate is closed. |
| `/health` | GET | Health check endpoint. |

## Fidelity mode

`GET /api/v1/fidelity` reports fleet silence; `POST` changes it without a restart.

```json
// GET response .data
{
  "silent": true,           // the value IN FORCE
  "startup_flag": false,    // what -fidelity was set to at launch
  "revert_pending": true,
  "revert_at": "2026-08-24T14:32:10Z",
  "revert_to": false        // what the pending revert restores
}
```

`silent` and `startup_flag` are reported separately because once the value is mutable the flag is only a default; a surface reporting the flag alone would assert something the engine may have stopped honouring.

```bash
curl -X POST .../api/v1/fidelity -H 'Content-Type: application/json' \
  -d '{"silent": true}'                        # standing change

curl -X POST .../api/v1/fidelity -H 'Content-Type: application/json' \
  -d '{"silent": true, "duration": "20m"}'     # auto-reverts, 24h cap
```

`silent` is **required**: omitting it would read as `false` and un-mute the fleet, so a body without it is rejected with `400`.

**Auto-revert restores the value from before the current chain of timed toggles**, not simply the previous value. Shortening or extending a window keeps the same destination; a toggle in the *opposite* direction starts a new chain and reverts to whatever was in force when it was issued. `revert_to` reports the target, because it is not inferable from `silent`.

A scenario report records `fidelity.silent_at_start` and `fidelity.changed_during_window`, so an archived measurement can say whether the rest of the fleet was quiet for its window.

## Continuous profiling

`GET /api/v1/profiling` reports the profiling gate; `POST` changes it without a restart.
Off by default: booted without `-profiling-pyroscope` and never POSTed, no profiler goroutine exists and `/debug/pprof/*` answers `503` naming this endpoint.
The full reference, including the one-CPU-profile-at-a-time rule and the subsystem labels, is [Continuous profiling](../ops/profiling.md).

```json
// GET response .data
{
  "enabled": true,                              // the gate IN FORCE
  "startup_flag": "http://pyroscope:4040",      // what -profiling-pyroscope was at launch ("" when unset)
  "server_address": "http://pyroscope:4040",    // push destination in force; "" = pull-only or off
  "pushing": true,                              // the SDK is RUNNING (false with enabled:true = pull-only, or a failed start); says nothing about upload success
  "sdk_errors": 3,                              // every error the SDK reported for the CURRENT push (failed upload, refused CPU collector, full queue); omitted while zero
  "last_error": "...",                          // the Start failure, or the latest SDK error of the current push
  "pprof_path": "/debug/pprof/",
  "revert_pending": true,
  "revert_at": "2026-09-04T12:00:00Z",
  "revert_to": false,                           // the gate value the pending revert restores
  "revert_to_address": "http://pyroscope:4040"  // the push address it restores with it; omitted when that is pull-only or off
}
```

```bash
curl -X POST .../api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled": true, "server_address": "http://pyroscope:4040"}'   # push
curl -X POST .../api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled": true, "server_address": ""}'                        # pull-only (Alloy scrape); an OMITTED server_address keeps a running push, else uses the flag's address
curl -X POST .../api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled": true, "server_address": "http://pyroscope:4040", "duration": "30m"}'   # auto-off after 30m, 24h cap
curl -X POST .../api/v1/profiling -H 'Content-Type: application/json' \
  -d '{"enabled": false}'                                             # off; the last profiles are flushed (bounded, 20 s) before 200
```

`enabled` is **required**; a body without it is rejected with `400`, as is an unknown field, a non-positive or over-cap `duration`, a `server_address` that is not an `http://` or `https://` URL or embeds credentials or a query or fragment, or a `server_address` on an `enabled:false` request.
`server_address` has three shapes: omitted keeps the address in force if a push is running, else uses the startup flag's, else is pull-only; an explicit `""` is pull-only even when the flag is set; a value re-targets.
The same address twice is a no-op; a different address re-targets the push in one transition.
A push the SDK refuses to start answers `500` with the state attached (`enabled:true`, `pushing:false`, `last_error`); the pull surface serves regardless.
`pushing` means the SDK is running; a collector that is down or rejecting shows in `sdk_errors` and `last_error`, since `pyroscope.Start` never touches the network.
`{"enabled":false}` asks the SDK to flush (a final snapshot plus the queued uploads) and then stops it, bounded by two upload timeouts (20 s) after which the flush is abandoned and logged; `GET` does not wait behind that flush.
`/debug/pprof/profile?seconds=N` and `trace?seconds=N` are refused by `net/http/pprof` once `N` reaches the server's 30 s write timeout.
Auto-revert follows the fidelity chain rule above and restores the whole (gate, address) pair; `revert_to_address` reports the address.
Basic auth and the tenant ID are flag-only (`-profiling-pyroscope-basic-auth`, `-profiling-pyroscope-tenant`), because this endpoint echoes everything REST can set, and they are sent only to the flag's own address: a differing `server_address` is pushed to without them.

**Removed.** The two hand-rolled `GET /api/v1/debug/...` handlers (a heap download and a fixed 5 s CPU download) are gone; a request to either is a `404`.
Their replacements are `GET /debug/pprof/heap` and `GET /debug/pprof/profile?seconds=N`, which require the gate to be open (`503` otherwise).

## Create devices

Bulk creation supports round-robin across all device types, category-based
filtering, per-request SNMP port selection, and an optional SNMPv3 block.

> **Addressing.** Device IPs are *management* addresses on a flat `/16` plane.
> `netmask` is optional and **defaults to `/16`** — only the `/16` network and
> broadcast are reserved, so `.x.0` and `.x.255` are assigned as ordinary hosts.
> An explicit `"netmask": "24"` (or `"8"`) is still honored if you want classic
> per-`/24` semantics (which skip `.0`/`.255`).

```bash
# Round-robin across all device types
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 10,
    "netmask": "16",
    "round_robin": true
  }'

# Non-privileged SNMP port (avoids CAP_NET_BIND_SERVICE)
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 5,
    "netmask": "16",
    "snmp_port": 1161
  }'

# Filter by category
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 3,
    "netmask": "16",
    "round_robin": true,
    "category": "GPU Servers"
  }'

# SNMPv3
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 5,
    "netmask": "16",
    "snmpv3": {
      "enabled": true,
      "engine_id": "0x80001234",
      "username": "admin",
      "password": "authpass123",
      "auth_protocol": 1,
      "priv_protocol": 2
    }
  }'

# Per-device error-counter scenario
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 3,
    "netmask": "16",
    "if_error_scenario": "degraded"
  }'
```

A `snmpv3` block that enables a privacy protocol (`des` / `aes128`) without a
password is rejected with **400**.
Key localisation repeats the password to fill a buffer (RFC 3414 §A.2), which
has no defined result for an empty one, so the block is checked at creation
rather than at the first encrypted request — a 201 followed by every encrypted
poll to that device failing gives the operator nothing to act on.
Either `password` or `priv_password` satisfies it; `priv_password` wins when
both are set **on the DES path only**. The AES128 path ignores `priv_password`
and always derives from `password`
([nl6#624](https://github.com/labmonkeys-space/nl6/issues/624)), so a device
configured with two distinct passwords and `"priv_protocol": 2` encrypts under
a key no RFC 3414 manager derives. `Validate` accepts the configuration
regardless.

The `if_error_scenario` field controls the per-device ppm bands used to
derive `ifInErrors`, `ifOutErrors`, `ifInDiscards`, and `ifOutDiscards`
from live packet counters. Accepted values: `clean` (default, no error
growth), `typical`, `degraded`, `failing`. Unknown values reject the
batch atomically with 400. REST-created devices default to `clean`
independently of the `-if-error-scenario` CLI flag — you must opt in
explicitly. See [SNMP reference](snmp.md#per-device-error-scenario) for
the full scenario bands and counter model.

A specific resource file can be requested directly (useful for storage
devices):

```bash
# Create a Pure Storage FlashArray device
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 1,
    "netmask": "16",
    "resource_file": "pure_storage_flasharray.json"
  }'
```

### On-demand optical degradation

`POST /api/v1/devices/{ip}/optical/{component}/degrade` drives one named
optical channel across the SD-FEC threshold on demand — the tool for
validating threshold and alarm logic without waiting for a health band to
wander there.

```bash
# Drive OCH-1-1 past the FEC threshold for 30 seconds, then back automatically.
# Crossing the threshold is an OSNR phenomenon, so it takes a noise rise:
# attenuation alone drops power without moving OSNR (see the quadrant table).
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade \
  -H "Content-Type: application/json" \
  -d '{"noise_rise_db": 8, "duration": "30s"}'
```

| Field | Type | Meaning |
|---|---|---|
| `input_power_drop_db` | number | Attenuates received power. Signal and accumulated ASE fall together, so power drops while **OSNR is unchanged** and no FEC errors accrue — a fibre or connector fault. |
| `noise_rise_db` | number | Raises accumulated ASE only. Power holds while OSNR falls — a sick amplifier. |
| `duration` | Go duration string | Optional. Omitted means open-ended; capped at 24 h. |

Two knobs rather than one severity dial because they select which diagnostic
quadrant the fault lands in, and collector correlation rules key on exactly
that difference. Both are optional; **a request with neither (or an empty
body) clears** active degradation on that channel.

The whole receive cascade follows — `input-power`, `osnr`, `esnr`, `q-value`,
`pre-fec-ber` and `fec-uncorrectable-blocks` — while the off-spine leaves
(`output-power`, `laser-bias-current`, `chromatic-dispersion`,
`polarization-mode-dispersion`, `polarization-dependent-loss`) stay flat.
That asymmetry *is* the fibre-vs-transponder diagnostic; a simulator that
moved every needle together would teach a collector nothing.

**Revert needs no timer.** A degradation window is frozen at publish, and the
value engine is a pure function of elapsed time, so the channel returns to
its band by arithmetic when the window ends — there is no scheduled mutation
to cancel. A second POST on the same channel supersedes the first.

**`fec-uncorrectable-blocks` never decreases** across a degrade → revert
cycle. The counter is the time integral of an above-threshold indicator, and
degradation is stored as append-only immutable episodes precisely so that
reverting cannot remove already-elapsed degradation from that integral. A
counter that walked backwards would be read as a device reboot.

Because attenuation leaves OSNR untouched, **crossing the FEC threshold takes
`noise_rise_db`** — a pure power sag models a lossy span, not a failing one.
Use both together for the fourth quadrant (power down *and* OSNR down).

Scope of the attenuation model: `input_power_drop_db` holds OSNR *exactly*
constant, which is loss **downstream of the amplifier chain** (a dirty
receive connector, a patch-panel fault). Loss *upstream* of an amplifier is
different in reality — the amplifier then adds ASE against a weaker signal,
so OSNR degrades too. Model that case with both knobs rather than expecting
`input_power_drop_db` alone to produce it.

Query what is in force with `GET /api/v1/devices/{ip}/optical`:

```json
{"device":"10.42.0.1","channels":[
  {"component":"OCH-1-1","input_power_drop_db":0,"noise_rise_db":0,"degraded":false},
  {"component":"OCH-1-2","input_power_drop_db":4,"noise_rise_db":1,"degraded":true}
]}
```

Responses: `200` with the episode echoed back; `404` for an unknown device,
an unknown component (the body lists `availableComponents`), or a device type
with no optical channels; `503` for an optical device still initialising its
engine (transient — retry); `400` for a malformed body, an unknown field, a
non-positive or over-cap `duration`, or an out-of-range offset.

### Optical health band

`optical_scenario` sets the steady-state health of every coherent optical
channel on an optical transport device:

```bash
# Two Waveserver 5 devices with a service-affecting optical span
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.100.1",
    "device_count": 2,
    "netmask": "16",
    "resource_file": "ciena_waveserver5.json",
    "optical_scenario": "failing"
  }'
```

Accepted values: `clean` (default), `typical`, `degraded`, `failing`.
Unknown values reject the batch atomically with 400. As with
`if_error_scenario`, REST-created devices default to `clean` independently
of the `-optical-scenario` CLI flag — you must opt in explicitly.

The field applies **only to device types that have optical channels**
(today `ciena_waveserver5`). Two consequences:

- A non-`clean` band on any other type is rejected with **400**, rather
  than accepted and silently ignored. A mixed `round_robin` batch is still
  accepted — the optical devices take the band and the rest ignore it.
- `GET /api/v1/devices` omits `optical_scenario` entirely for non-optical
  types, so the API never advertises a knob that does nothing there.

Only `failing` crosses the SD-FEC threshold, so
`fec-uncorrectable-blocks > 0` is a reliable service-affecting signal;
`degraded` shows an elevated `pre-fec-ber` that FEC still corrects. See
[CLI flags](cli-flags.md#optical-health-band) for the per-tier OSNR / Q /
BER table.

### One creation batch at a time (`409`)

**Behaviour change in nl6#565.** Only one device-creation batch runs at a time.
A `POST /api/v1/devices` that arrives while another batch is in flight is answered **`409 Conflict`** and creates nothing.
Two such requests used to interleave.

The response carries `Retry-After: 5`, and a body naming the batch in the way:

```json
{
  "success": false,
  "message": "device creation already in progress: batch #7 (2000 devices, started 1.482s ago) is running; retry once it finishes. Device IP allocation is a shared cursor, so a second concurrent batch would hand out overlapping addresses and silently create fewer devices than requested (nl6#565)"
}
```

The refusal is fail-fast, not a queue.
A large batch would otherwise make a small one wait minutes with no feedback, and an HTTP client that times out mid-wait cannot tell whether its batch ran.

**How to wait properly.** `GET /api/v1/status` reports `create_batch_in_progress` (and `create_batch_requested`, the running batch's requested device count) and `resource_reload_in_progress`.
The gate is held exactly when either is true: poll both until both are false, then retry.
The second holder is a [profile reload](#reload-device-profiles), which borrows the same gate for microseconds; a create refused during one is told so in its `409` body rather than told a batch is running.
`is_creating_devices` is a proxy, not the gate — it is published just after the gate is taken and cleared just before it is released, so it can read `false` while a create would still be refused.
`Retry-After` is a fixed, deliberately short 5 seconds; the handler has no way to estimate the remaining work of a batch whose rate it does not know.

Why the refusal is needed: device IPs come from a shared cursor, not a reservation.
A batch rewinds that cursor to its own start address after pre-allocating TUN interfaces, because the devices have to land on the addresses the pool carries.
Two overlapping batches therefore walked overlapping address ranges, the duplicate IPs were absorbed as "already exists", and the second batch silently created fewer devices than requested while reporting success.

**The auto-start batch counts as a batch.** `-auto-start-ip` runs on the same code path alongside the HTTP server, so a REST create issued during fleet startup gets the `409` until the startup batch completes.
That is intended (the fleet is mid-construction), and it is reachable on a normal boot: the container is healthy and `GET /api/v1/status` answers `200` while the startup batch still holds the gate.
The shipped clients behave as follows, and a client of your own should do the first:

- `scripts/fleet.sh import` treats a `409` as a wait: it retries the entry (`RETRY_409_LIMIT` attempts, default 60, `RETRY_409_DELAY` seconds apart, default 5). This is what keeps `compose up`'s bootstrapper working with `-auto-start-ip` set.
- The web console's Clos-fabric wizard does **not** retry. Its per-tier POSTs are sequential, so it never conflicts with itself, but a `409` from another batch (an auto-start batch, another operator, a script) aborts it and leaves a **half-built fabric** — the devices created so far stay, and the topology links are not loaded. Re-running the wizard on the same subnet is safe: existing addresses are absorbed as successes.

**What "one batch at a time" does and does not cover.** It excludes one creation batch from another creation batch, and from a profile reload, and nothing more.
Three paths still mutate creation state without holding the gate, all pre-existing: a previous batch's **detached pre-allocation workers** (the pre-allocator's 5-minute timeout returns while its workers keep writing the interface pool), `DELETE /api/v1/devices` (which clears the device and interface maps), and shutdown.
So a create that overlaps a delete-all, or that follows a batch which timed out in pre-allocation, is not protected by this gate.

The gate sits above every other check in the batch, the `resource_file` validation below and the privilege check included: a concurrency verdict must not depend on caller data.
When no batch is in flight, nothing about a single batch changes, the `400` and `500` answers documented next included.

**One neighbouring status is inconsistent, and this change did not fix it.** A create against a fleet frozen by a running load-test scenario is answered `500` with the freeze message, while [`loadtest-scenarios.md`](loadtest-scenarios.md) documents it as a `409`.
That divergence predates this change and was left alone deliberately: the freeze check is shared with the delete endpoints, so aligning it is a change to those too.
Today `409` on this endpoint means a concurrent creation batch or a concurrent profile reload, and nothing else; the body says which.

### `resource_file` failures

`resource_file` names the device type to load, and a request naming one the
simulator cannot use is answered **`400`** (nl6#538), not `500`.

Response:

| Status | Body | When |
|--------|------|------|
| `400 Bad Request` | `{"success": false, "message": "resource <base-name>: <what is wrong>"}` | The file name is not a device-type slug; no such device type is shipped (including a `round_robin` batch in which none of the requested types is, or a `category` matching none); or the file's content is invalid — JSON that does not parse, a document that is literally `null`, anything trailing the document, no entries at all, a device-type directory with no JSON part or whose parts hold no entries between them, an SNMP value the load-time guard rejects, or an optical inventory disagreeing with the type's channel count. |
| `500 Internal Server Error` | `{"success": false, "message": "<raw error>"}` | The loader could not classify the failure: a file it cannot open, a directory it cannot list. The raw message may contain a full path. |

The `message` field carries the diagnosis. It names the file's **base name**,
and for a fault attributable to one entry the OID and the value as well:

```json
{
  "success": false,
  "message": "resource restbad_snmp.json: OID 1.3.6.1.2.1.1.1.0 has value \"noSuchObject\", which collides with an SNMP exception sentinel and would be encoded as an RFC 3416 exception instead of a string. There is no escaping form: change the value. To make the OID answer noSuchObject on purpose, omit the entry entirely, since an absent OID already answers with the exception"
}
```

A parse failure, a `null` document, an empty file or directory, an optical
mismatch and a rejected file name have no single entry to name, so they carry
neither OID nor value.

The `400` body never contains a directory path — not in the file name, and not
inside an interpolated cause such as a failed read — control characters and
bidi formatting runes are stripped from it, and it is length-capped. The full
path goes to the **server log** instead. That guarantee covers the `400` class
only; the `500` class returns the raw error.

`resource_file` is validated **before** TUN pre-allocation and before the
privilege check, so a request naming a bad device type gets this `400` without
allocating anything, whether or not the simulator runs as root. A request
naming a good one proceeds, and without root gets the pre-existing `500`
`root privileges required to create TUN interfaces`.

### Per-device export blocks

`POST /api/v1/devices` accepts four optional top-level blocks —
`flow`, `traps`, `syslog`, `gnmi_dialout` — that attach export
configuration to every device created by the request. Any block can be
omitted; omitted blocks mean "this batch does not participate in that
export subsystem."

The subsystems are always-on after `main()` — flow / trap / syslog /
gNMI dial-out scheduler goroutines and catalog loaders run regardless
of whether any CLI seed was supplied, so REST-created devices can opt
in to any combination.

**`flow` block:**

```json
"flow": {
  "collector":        "192.168.1.10:2055",      // required; host:port
  "protocol":         "netflow9",               // optional; "netflow9" | "ipfix" | "netflow5" | "sflow" (alias: "sflow5"); default "netflow9"
  "tick_interval":    "5s",                      // optional; global ticker used, per-device value validated and logged if divergent
  "active_timeout":   "30s",                     // optional; default 30s
  "inactive_timeout": "15s",                     // optional; default 15s
  "sub_agent_id":     0,                         // optional; sFlow datagram sub_agent_id, default 0; ignored by non-sFlow protocols
  "options_interface_table": ""                  // optional; "" (off, default) | "if-scoped" | "system-scoped"; netflow9/ipfix only — other protocols rejected with 400
}
```

No per-device override exists for `source_per_device` — the
`-flow-source-per-device` CLI flag is simulator-wide (see
[CLI flags → Flow export](cli-flags.md#flow-export-flags)). Setting
`"source_per_device"` in the REST body is rejected by
`DisallowUnknownFields`.

**`traps` block:**

```json
"traps": {
  "collector":       "192.168.1.10:162",        // required; host:port
  "mode":            "trap",                     // optional; "trap" | "inform"; default "trap"
  "community":       "public",                   // optional; SNMPv2c community; default "public"
  "interval":        "30s",                      // optional; ACCEPTED AND STORED BUT NOT HONORED (see below); default 30s
  "inform_timeout":  "5s",                       // optional; INFORM retry timeout; default 5s
  "inform_retries":  2                           // optional; max retransmissions per INFORM; default 2
}
```

INFORM mode requires the simulator-wide `-trap-source-per-device=true`
(the default). The check is **enforced at device-attach time**: if a
request sets `mode: "inform"` while the flag is false, the attach
fails per-device and the device's `trapConfig` is cleared so
`ListDevices` doesn't show a ghost entry. This is distinct from
request-level validation (which would fail the whole batch) — INFORM
without per-device binding is a runtime attach failure, not a 400.

**`syslog` block:**

```json
"syslog": {
  "collector": "192.168.1.10:514",              // required; host:port
  "format":    "5424",                           // optional; "5424" | "3164"; default "5424"
  "interval":  "10s"                             // optional; ACCEPTED AND STORED BUT NOT HONORED (see below); default 10s
}
```

### Interval fields are not honored

Three per-device cadence settings are accepted, stored, and echoed back, but the engine ignores them: `syslog.interval`, `traps.interval`, and `flow.tick_interval`.

The syslog and trap schedulers fire every device at their simulator-wide mean (`-syslog-interval`, `-trap-interval`). Flow drives every device from one simulator-wide ticker. Setting a per-device value changes nothing. The simulator-wide `-flow-tick-interval` **is** honored ([nl6#446](https://github.com/labmonkeys-space/nl6/issues/446) is fixed); it is the per-device override that is not.

So that the API does not confirm a wrong belief, both values are reported:

| field | means |
|---|---|
| `interval` / `tick_interval` | what you **asked for** (inert) |
| `effective_intervals.*` (sibling object) | the cadence the scheduler is **configured** with |

Omitted for subsystems a device does not use. Present only when the device exports something.

**`*_effective` is not an observed emission rate.** It is strictly more truthful than the inert `interval`, but three things modulate real output without changing it:

- **`-syslog-global-cap` / `-trap-global-cap`** throttle by *blocking*, so a cap of 5/s across 30,000 devices gives a real cadence near 100 minutes while the field still reports `10s`.
- **`-fidelity`** (and `POST /api/v1/fidelity` at runtime) suppresses background emission entirely — the device emits nothing while the field still reports the mean.
- **A running scenario** drives its participants from a scenario-owned scheduler at the scenario's own rate, which this field never sees.

Use it to answer "is my per-device setting doing anything?" (it is not), not to compute expected event volume.

For flow specifically, `effective_intervals.flow_tick_interval` reports the period the ticker actually latched — the simulator-wide cadence in force, which is `-flow-tick-interval` when set and `5s` otherwise.

```json
"syslog": {
  "collector": "192.0.2.144:1514",
  "format":    "5424",
  "interval":  "24h0m0s"            // what was requested (inert)
},
"effective_intervals": {
  "syslog_interval": "10s"          // what the scheduler is configured with
}
```

An interval you did **not** set is omitted from the echo entirely: the stored value would just be the package default, and reporting it would attribute a choice to you that you never made (and make a re-POST of the body warn about it). `effective_intervals` tells you the cadence in force either way.

The effective values sit in a **sibling object**, deliberately not inside the config blocks. A block that carried a read-only field would stop being a valid `POST` body — `POST /api/v1/devices` rejects unknown fields and that strictness reaches into nested objects — which would break every read-modify-write client, `scripts/fleet.sh import` included.

A create request that SETS any of these fields gets a `warnings` entry in the response — including when the value happens to match the simulator-wide cadence, because the field is inert either way. Note it sits under `data`, inside the standard response envelope, so a scripted client reads `.data.warnings` and not `.warnings`:

A **rejected** request carries the same disclosure. If a body is both invalid and sets an inert interval, the `400` reports the validation error in `message` and the disclosure in `data.warnings`, so both facts arrive in one round trip:

```json
{
  "success": false,
  "message": "syslog: invalid collector \"not-a-host-port\"",
  "data": {
    "requested": 1,
    "warnings": [{ "field": "syslog.interval", "message": "syslog.interval is not honored: ..." }]
  }
}
```

The warning text describes the **field**, never the request's outcome, which is what lets the identical message ride a success, a partial batch, and a rejection alike.

```json
{
  "success": true,
  "message": "Created 500 devices starting from 10.42.0.1",
  "data": {
    "created": 500, "requested": 500, "failed": 0,
    "warnings": [{
      "field": "syslog.interval", "requested": "24h0m0s", "effective": "10s",
      "message": "syslog.interval is not honored: every device is scheduled at the simulator-wide 10s, not the 24h0m0s given. ..."
    }]
  }
}
```

### A GET block is a valid POST block

Config blocks round-trip: take a `flow` / `traps` / `syslog` object from `GET /api/v1/devices`, change what you like, and POST it back. Nothing needs stripping.

That is why the effective cadences live in a sibling object rather than inside the blocks. Strict decoding is retained, so a genuine typo is still caught:

```console
# 400 Invalid JSON: unknown field "intervl"
POST /api/v1/devices  {"syslog": {"collector": "x:514", "intervl": "24h"}}
```

`scripts/fleet.sh export | fleet.sh import` relies on this round trip.

**`gnmi_dialout` block** (see the
[gNMI dial-out reference](gnmi-dial-out.md) for full semantics):

```json
"gnmi_dialout": {
  "collector":       "10.0.0.5:6030",                              // required; host:port
  "flavor":          "gnmireverse",                                 // optional; only shipped flavor; default "gnmireverse"
  "encoding":        "json_ietf",                                   // optional; "json_ietf" | "proto"; default "json_ietf"
  "mode":            "sample",                                      // optional; "sample" | "on-change"; default "sample"
  "paths":           ["/interfaces/interface[name=*]/state"],       // optional; default: full state subtree
  "sample_interval": "10s",                                         // optional; SAMPLE cadence, 1s floor; default 10s
  "tls": {                                                          // optional; default {"enabled": true}
    "enabled": true,
    "insecure_skip_verify": false,                                  // dev only
    "ca_pem": "",                                                   // PEM CA bundle INLINE; empty = system roots.
                                                                    // Not a path: this block is REST-settable, and a path
                                                                    // would let a caller name any file to open. Use
                                                                    // -gnmi-dialout-tls-ca for a file. "ca_file" is rejected.
    "mtls": false                                                   // present the shared cert as a client cert
  }
}
```

Durations accept Go duration strings (`"10s"`, `"5m"`, `"1m30s"`);
integer seconds are rejected.

**Combined example — flow + traps + syslog on the same batch:**

```bash
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "10.0.0.1",
    "device_count": 100,
    "netmask": "16",
    "flow": {
      "collector": "192.168.1.10:4739",
      "protocol":  "ipfix"
    },
    "traps": {
      "collector": "192.168.1.10:162",
      "mode":      "trap",
      "community": "public"
    },
    "syslog": {
      "collector": "192.168.1.10:514",
      "format":    "5424"
    }
  }'
```

**Heterogeneous fleet — two batches pointing at different collectors:**

```bash
# Batch A: 50 devices → collector A, 5424
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "10.0.0.1",
    "device_count": 50,
    "syslog": {"collector": "192.168.1.10:514", "format": "5424"}
  }'

# Batch B: 20 devices → collector A, 3164 (same host, different format)
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "10.0.1.1",
    "device_count": 20,
    "syslog": {"collector": "192.168.1.10:514", "format": "3164"}
  }'

# Batch C: 30 devices → collector B, 5424
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "10.0.2.1",
    "device_count": 30,
    "syslog": {"collector": "192.168.1.20:514", "format": "5424"}
  }'
```

`GET /api/v1/syslog/status` then reports three collector records keyed
by `(collector, format)`. See
[Syslog export status](#syslog-export-status).

**Validation failures return `400` with the underlying error** (e.g.
`unknown protocol`, `invalid collector address`, unresolvable host,
explicitly invalid syslog format — non-`5424` / non-`3164`); no device
from the batch is created (atomic batch failure). Unknown / typo'd JSON
fields at any level are also rejected via `DisallowUnknownFields` —
e.g. `"interval_ms": 10000` lands as a 400, not a silent drop.

## List devices

```bash
curl http://localhost:8080/api/v1/devices
```

Each device record includes a `resource_file` field (e.g. `"asr9k.json"`)
— the canonical identifier accepted by `POST /api/v1/devices`. The
sibling `device_type` field is a human-readable display label and is
many-to-one (e.g. `cisco_catalyst_9500`, `cisco_crs_x`, and
`cisco_nexus_9500` all surface as `"Cisco Router/Switch"`), so use
`resource_file` for any replay or programmatic recreation use case.

The field is omitted (JSON `omitempty`) for devices whose underlying
`device.resourceFile` is empty. Two paths produce that:

- Devices created via the `-auto-start-ip` CLI flag (no CLI equivalent of
  `resource_file`).
- POST requests that omit **both** `resource_file` and `round_robin: true`,
  falling back to the simulator's default resource set.

POSTs that name a `resource_file` or use `round_robin: true` always carry it.

Each record also echoes the per-device export blocks that were configured at
creation — `flow`, `traps`, `syslog`, `gnmi_dialout` — so a GET response can
be replayed against `POST /api/v1/devices` without reconstructing the export
config. Blocks are omitted (`omitempty`) for devices that don't participate
in that subsystem.

Each record also carries the device's geolocation: `location` (the world-city
string also served as SNMP `sysLocation.0`), and `latitude` / `longitude`
(decimal degrees, drawn from the same world-cities dataset). The coordinates
are emitted as a **pair** — both present or both omitted. They are `omitempty`
on a nullable type so that an *unresolved* location omits them entirely rather
than reporting a misleading `0`; a device whose true coordinates are `0.0,0.0`
still reports them as present. `location` is omitted when empty.

```json
{ "id": "...", "ip": "10.42.0.100", "resource_file": "cisco_crs_x.json",
  "location": "Amsterdam, Netherlands", "latitude": 52.3676, "longitude": 4.9041 }
```

Note: locations are assigned **randomly per device**, so a deployed fabric is
geographically scattered rather than clustered by site.

## Reload device profiles

`POST /api/v1/resources/reload` makes an edited profile under `resources/` take effect without a restart (nl6#519).
It **evicts** cached profiles; it never rewrites one.

```bash
curl -X POST http://localhost:8080/api/v1/resources/reload                # every cached profile
curl -X POST http://localhost:8080/api/v1/resources/reload \
  -H 'Content-Type: application/json' -d '{"resource_file":"cisco_ios.json"}'   # one profile
```

```json
// 200 response .data
{
  "evicted": ["cisco_ios.json"],
  "devices_on_old_snapshot": {"cisco_ios.json": 40},
  "present_on_disk": {"cisco_ios.json": true},
  "note": "existing devices keep the snapshot they were built from until they are recreated; the next device creation of an evicted type reads the profile from disk. Trap and syslog catalogs (traps.json, syslog.json) are NOT reloaded by this endpoint and still need a restart"
}
```

**What a reload does and does not change.** A profile is read from disk the first time a device of that type is created and cached.
Every device built from it holds a pointer to that cached set and serves from indexes built on it, so rewriting the set in place would change what 30,000 devices answer mid-walk.
A reload therefore drops the cache entry and nothing else: a device created **before** the reload serves exactly what it served before, and a device created **after** it serves the file as it is now.
`devices_on_old_snapshot` counts, per evicted key, how many running devices still serve a pre-reload set (any earlier generation, not only the one evicted now).
It is a snapshot taken under the gate: `DELETE /api/v1/devices/{id}` is not gated, so the number can already be lower by the time the response is read.
To move devices onto the edited profile, delete and recreate them.
`present_on_disk` says whether the profile still exists on disk at the time of the reload, so a renamed or removed directory is reported now rather than at the next create.

**The default profile is covered.** The profile a device gets with no `resource_file` (`asr9k`, the same one the whole `-auto-start-ip` fleet serves) is read from `resources/asr9k/` at startup through the same cache under the key `asr9k.json`, so a device created with `"resource_file":"asr9k.json"` and one created without it share one object, and reloading `asr9k.json` covers both.
Devices created without a `resource_file` are counted under that key.
The only default that stays outside the cache is the compiled-in one the simulator synthesises when no `asr9k` directory or file exists at all.

**Not reloaded: trap and syslog catalogs.** `resources/<type>/traps.json` and `syslog.json` are loaded when the trap and syslog subsystems start and are never re-read.
Editing one and calling this endpoint gets a `200` that evicts the profile and leaves the catalog as it was; the `note` says so.
A catalog edit still needs a restart.

The workflow for verifying a profile fix is: edit the file, `POST /resources/reload`, then `POST /devices` for the type.
A profile that fails to load after the edit is answered by that create with the usual `400` (see [`resource_file` failures](#resource_file-failures)); a rejection is never cached, so fixing the file and creating again needs no second reload.

| Status | When |
|--------|------|
| `200` | Evicted. `evicted` lists the keys as `<slug>.json`, sorted; with nothing cached it is `[]`. |
| `400` | Malformed JSON, an unknown field, an explicitly empty `resource_file` (omit the field to mean "all"), a `resource_file` that is not a device-type slug, or one naming a type that is **not shipped** (no directory or file under `resources/`). |
| `404` | `resource_file` names a type that is shipped but not cached, because no device of it has been created since startup or since the last reload. Not a silent no-op: the body names the key and says the next creation reads from disk regardless. |
| `409` | A device-creation batch, or another reload, holds the gate. Same `Retry-After: 5` and body as the [create endpoint's `409`](#one-creation-batch-at-a-time-409). |
| `413` | The body exceeds 4 KiB. |

**Why a reload is refused during a batch.** Every profile load runs inside a creation batch, and the cache keeps the **first** entry published for a key (two goroutines may both miss and both load; only one set is retained).
An evict that raced a load already in flight would clear the slot and then watch that load publish the *old* file's contents into it.
The reload takes the same one-batch-at-a-time gate as creation, so that ordering cannot happen.
It is fail-fast, never queued, for the reasons given for the create endpoint; poll `create_batch_in_progress` and `resource_reload_in_progress` on `GET /api/v1/status` and retry.
While a reload holds the gate, `GET /api/v1/status` reports `resource_reload_in_progress: true` and `create_batch_in_progress: false`, and a create refused in that window is told a reload holds the gate, not that a batch is running.

There is no file watcher. Reload is explicit.

## Export to CSV

```bash
curl http://localhost:8080/api/v1/devices/export -o devices.csv
```

The CSV columns are, in order: `Device ID`, `IP Address`, `Interface`,
`SNMP Port`, `SSH Port`, `Status`, `Resource File`. `Resource File` is
appended at the end so any downstream consumer that indexes columns
positionally (`awk -F, '{print $2}'`, spreadsheet macros) is unaffected
by the new column. Devices without a known resource file emit `N/A` in
that column, matching the `Interface` convention.

Note: `N/A` is a display sentinel, not a valid resource filename. A
re-import tool that POSTs each row back must translate `N/A` to an
omitted `resource_file` field, not pass it through as a literal value
(POST would reject `"N/A"` as a non-existent file).

## Generate a route script

```bash
curl http://localhost:8080/api/v1/devices/routes -o add_routes.sh
```

The generated script adds Linux kernel routes for every device IP — handy
when running the simulator inside a VM and testing from the host.

## Delete devices

```bash
# Single device
curl -X DELETE http://localhost:8080/api/v1/devices/{device-id}

# All devices
curl -X DELETE http://localhost:8080/api/v1/devices
```

## Version

Report the running simulator's version. The value is baked into the binary
at build time via the Makefile's `APP_VERSION` variable (resolution order:
`APP_VERSION` env > `git describe --tags` > `dev`) and passed to `go build`
as `-ldflags "-X main.Version=…"`. It never changes for the lifetime of the
process, so the endpoint sets `Cache-Control: max-age=3600` — reloads of
the web UI within a browser session will reuse the cached value.

Release binaries report the clean tag (e.g., `v0.5.0`). A `make build`
from a HEAD that is ahead of the last tag reports the commit-distance
form (e.g., `v0.4.1-11-g0356c42`), so a post-release dev binary never
masquerades as the tagged release.

```bash
curl http://localhost:8080/api/v1/version
```

```json
{"version": "v0.5.0"}
```

For an untagged development build (or any build produced by `go build`
directly, bypassing the Makefile), the reported version is the literal
string `dev`. Operators troubleshooting a version mismatch can call the
same string from the CLI without starting the server:

```bash
./nl6 -version
# → v0.5.0
```

## Flow export status

```bash
curl http://localhost:8080/api/v1/flows/status
```

When flow export is enabled:

```json
{
  "success": true,
  "message": "Success",
  "data": {
    "subsystem_active": true,
    "collectors": [
      {"collector": "192.168.1.10:4739", "protocol": "ipfix",    "devices": 50, "sent_packets": 8123, "sent_bytes": 12123456, "sent_records": 243690},
      {"collector": "192.168.1.20:6343", "protocol": "sflow",    "devices": 20, "sent_packets": 3100, "sent_bytes":  5560000, "sent_records":  62000}
    ],
    "devices_exporting": 70,
    "last_template_send": "2026-04-23T10:35:00Z"
  }
}
```

Response fields:

| Field | Meaning |
|-------|---------|
| `subsystem_active` | `true` after `main()` boots the flow ticker goroutine — always-on. Not reachable as `false` via the HTTP endpoint during normal operation: the subsystem initialises with the rest of the process and only stops at process exit, alongside the HTTP server itself. |
| `collectors[]` | One record per `(collector, protocol)` tuple that ever had a device. Deleted-device counters persist in the aggregate until process exit. |
| `collectors[].devices` | Count of LIVE exporters for this tuple. `0` means no live device but the aggregate remembers prior fires. |
| `collectors[].sent_packets` / `sent_bytes` / `sent_records` | Cumulative across live + historical exporters for this tuple (monotonic within subsystem lifecycle). |
| `devices_exporting` | Total LIVE exporters across all tuples. |
| `last_template_send` | ISO-8601 timestamp of the most recent template emission (NetFlow v9 / IPFIX only). |

Clients detect "no flow export configured" via `len(collectors) == 0`.
The retired scalar fields (`enabled`, `protocol`, `collector`,
`total_flows_exported`, `total_packets_sent`, `total_bytes_sent`) were
removed in phase 3; callers that depended on them must migrate to the
array-of-collectors shape.

See [Flow export (operator guide)](../ops/flow-export.md) and
[Flow export reference](flow-export.md) for protocol-specific details.

## Trap export status

```bash
curl http://localhost:8080/api/v1/traps/status
```

Unlike the flow-status endpoint, this response is **not** wrapped in the
`{success, message, data}` envelope — the handler serialises `TrapStatus`
directly.

```json
{
  "subsystem_active": true,
  "collectors": [
    {
      "collector": "192.168.1.10:162",
      "mode":      "inform",
      "devices":   80,
      "sent":      182430,
      "informs_pending": 17,
      "informs_acked":   182380,
      "informs_failed":  33,
      "informs_dropped": 0
    },
    {
      "collector": "192.168.1.20:162",
      "mode":      "trap",
      "devices":   20,
      "sent":      6000
    }
  ],
  "devices_exporting": 100,
  "rate_limiter_tokens_available": 94,
  "catalogs_by_type": {
    "_universal":    {"entries": 5,  "source": "embedded"},
    "cisco_ios":     {"entries": 12, "source": "file:resources/cisco_ios/traps.json"},
    "juniper_mx240": {"entries": 12, "source": "file:resources/juniper_mx240/traps.json"}
  }
}
```

The four `informs_*` fields **only appear on records whose `mode == inform`**.
TRAP-mode records omit them.

`subsystem_active` is the authoritative feature-on signal — `true`
after `StartTrapSubsystem` runs. In normal operation, the HTTP
endpoint always returns `true`: the subsystem initialises from `main()`
and the only path that sets `subsystem_active=false` is `StopTrapExport`,
which is invoked at process shutdown alongside the HTTP server. A
`false` value is therefore only observable programmatically (e.g.
from a test harness calling `GetTrapStatus` without starting the
subsystem). Clients that previously branched on the retired `enabled`
scalar should use `subsystem_active`. `len(collectors) == 0` with
`subsystem_active=true` means the subsystem is running but no device
has opted in.

`catalogs_by_type` keys are device-type slugs (plus the reserved
`_universal` entry for the fallback catalog). `source` is
`"embedded"`, `"file:<path>"`, or `"override:<path>"` when
`-trap-catalog` was supplied. When disabled:

```json
{"subsystem_active": false, "collectors": [], "devices_exporting": 0}
```

`rate_limiter_tokens_available` is only present when `-trap-global-cap` is
set. The `sent` counter increments on **every wire emission including
INFORM retransmissions**, so it can exceed `informs_acked + informs_failed
+ informs_dropped + informs_pending` under retry churn.

Counters are **monotonic within a subsystem lifecycle**: deleting a
device does not zero its collector's `sent`; the aggregate survives.

See [SNMP trap / INFORM export (operator guide)](../ops/snmp-traps.md) and
[SNMP trap reference](snmp-traps.md) for the full feature details.

## Fire a trap on demand

```bash
curl -X POST http://localhost:8080/api/v1/devices/192.168.100.1/trap \
  -H "Content-Type: application/json" \
  -d '{"name":"linkDown","varbindOverrides":{"IfIndex":"3"}}'
```

Request body:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `name` | string | yes | Catalog entry name (e.g. `linkDown`, `ciscoConfigManEvent`). Must match an entry in the **device's resolved catalog** (per-type overlay if present, universal otherwise) — not the universal catalog globally. |
| `varbindOverrides` | object | no | Map of template-field → string-value overrides. Only fields from the nine-field unified vocabulary are accepted (`IfIndex`, `IfName`, `Uptime`, `Now`, `DeviceIP`, `SysName`, `Model`, `Serial`, `ChassisID`). |

Response:

| Status | Body | When |
|--------|------|------|
| `202 Accepted` | `{"requestId": <uint32>}` | Trap has been enqueued. In INFORM mode the `requestId` is the INFORM PDU's `request-id`. |
| `400 Bad Request` | `{"error": "...", "catalog": "<slug>", "availableEntries": [...]}` | Unknown catalog entry for this device. The enriched body reports which catalog the device resolved to (`cisco_ios`, `_universal`, etc.) and lists its entries alphabetically so a scripted caller can fix its call without a separate discovery endpoint. For malformed JSON or missing `name`, the legacy envelope form `{"success": false, "message": "..."}` applies. |
| `404 Not Found` | error JSON | Unknown device IP. |
| `500 Internal Server Error` | error JSON | Template resolve error, catalog resolution returned nil despite feature active (pathological manager state), or write failure. |
| `503 Service Unavailable` | error JSON | The trap subsystem has not started **or** the target device has no trap config. |

The endpoint does not block waiting for an INFORM ack — use
`/api/v1/traps/status` to observe INFORM lifecycle counters.

## Syslog export status

```bash
curl http://localhost:8080/api/v1/syslog/status
```

When syslog export is enabled:

```json
{
  "subsystem_active": true,
  "collectors": [
    {"collector": "192.168.1.10:514", "format": "5424", "devices": 50, "sent": 18240, "send_failures": 3},
    {"collector": "192.168.1.10:514", "format": "3164", "devices": 20, "sent":  6130, "send_failures": 0}
  ],
  "devices_exporting": 70,
  "rate_limiter_tokens_available": 380,
  "catalogs_by_type": {
    "_universal":    {"entries": 6,  "source": "embedded"},
    "cisco_ios":     {"entries": 14, "source": "file:resources/cisco_ios/syslog.json"},
    "juniper_mx240": {"entries": 13, "source": "file:resources/juniper_mx240/syslog.json"}
  }
}
```

Tuples are keyed by `(collector, format)`: a single collector receiving
5424 from some devices and 3164 from others surfaces as two separate
records. Per-device bind failures are non-fatal — the exporter falls
back to the shared-pool socket with a warning and the `sent` counter
still increments.

`subsystem_active` has the same semantics as on the trap status
endpoint; `len(collectors) == 0` is **not** sufficient on its own to
imply "feature off." When disabled:

```json
{"subsystem_active": false, "collectors": [], "devices_exporting": 0}
```

`format` is `"5424"` or `"3164"`. `catalogs_by_type` follows the same
shape as the trap endpoint. `rate_limiter_tokens_available` is present
only when `-syslog-global-cap` is set. When disabled the response is
`{"enabled": false}`.

See [UDP syslog export (operator guide)](../ops/syslog-export.md) and
[UDP syslog reference](syslog-export.md) for the full feature details.

## Fire a syslog message on demand

```bash
curl -X POST http://localhost:8080/api/v1/devices/192.168.100.1/syslog \
  -H "Content-Type: application/json" \
  -d '{"name":"interface-down","templateOverrides":{"IfIndex":"3"}}'
```

Request body:

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `name` | string | yes | Catalog entry name. Same device's-catalog resolution rule as the trap endpoint. |
| `templateOverrides` | object | no | Nine-field unified vocabulary (same set as `varbindOverrides` on the trap side). |

Response:

| Status | Body | When |
|--------|------|------|
| `202 Accepted` | `{}` | Message emitted. On-demand fires **do not** consume global rate-cap tokens. |
| `400 Bad Request` | `{"error": "...", "catalog": "<slug>", "availableEntries": [...]}` | Unknown catalog entry for this device. Same enriched-error shape as the trap endpoint. |
| `404 Not Found` | error JSON | Unknown device IP. |
| `500 Internal Server Error` | error JSON | Pathological catalog-resolution-nil state. |
| `503 Service Unavailable` | error JSON | The syslog subsystem has not started **or** the target device has no syslog config. |

## Device interaction

The control-plane only manages devices — once a device is up, you interact
with it via its own IP on port 22 (SSH), 161 (SNMP), and, for storage
devices, 8443 (HTTPS).

```bash
# SSH (VT100 terminal emulation)
ssh simadmin@192.168.100.1     # password: simadmin

# SNMP v2c
snmpget  -v2c -c public 192.168.100.1 1.3.6.1.2.1.1.1.0
snmpwalk -v2c -c public 192.168.100.1 1.3.6.1.2.1.2.2.1

# SNMP v3 (when enabled). RFC 3414 USM, verified against net-snmp (nl6#624).
# A CLI-started fleet uses simadmin for the user and for both passwords, and
# defaults to -snmpv3-auth md5 with privacy off, so the level you can poll
# follows the flags the simulator was started with.
snmpget -v3 -l noAuthNoPriv -u simadmin 192.168.100.1 1.3.6.1.2.1.1.1.0

# started with -snmpv3-auth md5 (the default)
snmpget -v3 -l authNoPriv -u simadmin -a MD5 -A simadmin \
  192.168.100.1 1.3.6.1.2.1.1.1.0

# started with -snmpv3-auth sha1 -snmpv3-priv aes128
snmpget -v3 -l authPriv -u simadmin -a SHA -A simadmin -x AES -X simadmin \
  192.168.100.1 1.3.6.1.2.1.1.1.0
```

See [SNMP reference](snmp.md) for the OID coverage, including the dynamic HC
interface counters on `ifXTable`.

### Storage HTTPS endpoints

Storage devices expose vendor-shaped REST APIs on port 8443 with shared TLS
certificates generated at simulator startup.

```bash
# Pure Storage FlashArray
curl -k https://192.168.100.1:8443/api/2.14/volumes
curl -k https://192.168.100.1:8443/api/2.14/arrays
curl -k https://192.168.100.1:8443/api/2.14/arrays/space

# NetApp ONTAP
curl -k https://192.168.100.1:8443/api/cluster
curl -k https://192.168.100.1:8443/api/storage/volumes
curl -k https://192.168.100.1:8443/api/storage/aggregates

# AWS S3
curl http://192.168.100.1:8443/            # list buckets
curl http://192.168.100.1:8443/my-bucket   # bucket contents
```
