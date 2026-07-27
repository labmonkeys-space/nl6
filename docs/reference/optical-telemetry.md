# Optical telemetry

nl6 simulates a **Ciena Waveserver 5** (WaveLogic 5 Extreme) coherent DWDM
transport platform and serves its optical state over **gNMI**, using the
pinned OpenConfig model. This page is the working reference: what is served,
what the values mean, how to drive a channel across the FEC threshold, and how
to validate a monitoring use case end to end.

Two companion documents matter as much as this one:

- [Waveserver 5 limitations](https://github.com/labmonkeys-space/nl6/blob/main/go/nl6/resources/ciena_waveserver5_limitations.md)
  states where the simulation stops. Read it before building anything you
  intend to deploy against real hardware.
- [gNMI reference](gnmi.md) covers the transport, TLS, subscribe modes and
  encodings shared with the packet surface.

## The failure mode this device type is designed against

Not "synthetic-looking values". The **false pass**: you build a rule against
nl6, it works, you deploy against a real Waveserver, and it does not. Every
design decision below is ordered by that risk, which is why exact paths,
types and negative states are treated as more important than exact values.

Concretely, that is why `post-fec-ber` is **not served** even though
OpenConfig defines it. Ciena removed it from their model, so a collector rule
keyed on it could never fire against real hardware. A test asserts its
absence.

## Keying: component name, never ifIndex

An optical channel is not an interface. Every path is keyed by the
optical-channel (OCH) **component name**:

```
/components/component[name=OCH-1-1]/optical-channel/...
```

A stock `ciena_waveserver5` device has two channels, `OCH-1-1` and `OCH-1-2`,
one per WaveLogic 5 Extreme modem. Enumerate them with a wildcard
(`name=*`), which expands in sorted order.

## Served paths

All under `/components/component[name=$och]/optical-channel/`. Statistics
containers expose `{instant, avg, min, max}`.

| Path | Type | Unit |
|---|---|---|
| `{config,state}/frequency` | uint64 | MHz |
| `{config,state}/target-output-power` | decimal64, 2 fd | dBm |
| `{config,state}/operational-mode` | uint16 | |
| `{config,state}/line-port` | string (leafref) | |
| `state/input-power/{instant,avg,min,max}` | decimal64, 2 fd | dBm |
| `state/output-power/{instant,avg,min,max}` | decimal64, 2 fd | dBm |
| `state/laser-bias-current/{instant,avg,min,max}` | decimal64, 2 fd | mA |
| `state/osnr/{instant,avg,min,max}` | decimal64, 2 fd | dB |
| `state/esnr/{instant,avg,min,max}` | decimal64, 2 fd | dB |
| `state/q-value/{instant,avg,min,max}` | decimal64, 2 fd | dB |
| `state/pre-fec-ber/{instant,avg,min,max}` | decimal64, **18 fd** | ratio |
| `state/chromatic-dispersion/{instant,avg,min,max}` | decimal64, 2 fd | ps-nm |
| `state/polarization-mode-dispersion/{instant,avg,min,max}` | decimal64, 2 fd | ps |
| `state/polarization-dependent-loss/{instant,avg,min,max}` | decimal64, 2 fd | dB |
| `state/fec-uncorrectable-blocks` | uint64 | blocks |

Pinned model revisions, advertised in `Capabilities` by optical devices only:
`openconfig-terminal-device` 2026-01-14, `openconfig-platform` 2025-07-15,
`openconfig-platform-transceiver` 2026-03-25. The transceiver model is
required rather than decorative: `optical-channel/state` reuses its
`optical-power-state` grouping for input power, output power and laser bias.

Three shapes worth knowing before you write a subscription:

- **`fec-uncorrectable-blocks` is a bare counter.** It has no statistics
  container in the pinned model, so `.../fec-uncorrectable-blocks/instant`
  returns `NotFound`. That is the mistake most collector authors make here, by
  analogy with the leaves around it.
- **The measured leaves are state-only.** Only the four scalars have a
  `config/` twin.
- **Precision is model-mandated.** Statistics leaves carry 2 fraction digits;
  `pre-fec-ber` carries 18. Ciena's native model uses 3-digit decimals and a
  scientific-notation string, but nl6 serves OpenConfig, whose types govern.

## Value model: two dials, one cascade

Received power `pIn` and accumulated noise `nAse` are **two independent
dials**, with `osnr = pIn - nAse` in dB. A single power dial would make OSNR
perfectly correlated with power and leave two of the four diagnostic quadrants
unreachable, which is exactly what collector correlation rules key on.

The receive-side spine cascades:

```
osnr -> q-value -> pre-fec-ber -> fec-uncorrectable-blocks
```

`pre-fec-ber` comes from the Gaussian tail (`0.5 * erfc(q/sqrt(2))`). Note the
tail is **shallow** at the 2e-2 SD-FEC threshold, roughly 3x per 2 dB, not a
decade. Assert monotonicity there and reserve step-change assertions for the
block counter.

**Off-spine leaves stay flat** under a receive-side fault: output power,
target output power, laser bias current, chromatic dispersion, PMD, PDL,
frequency, operational mode, line port. That flatness *is* the
fibre-versus-transponder diagnostic. A simulator that moved every needle
together would teach a collector nothing.

Values are analytic and deterministic: a pure function of
`(component, leaf, elapsed time)`, with no per-channel goroutine. Every
protocol surface reads one dispatcher, so gNMI and any other surface agree at
the same instant.

## Health bands

`-optical-scenario` (seed batch) or `optical_scenario` (REST) sets the
steady-state band per device.

| Tier | OSNR | Q | pre-FEC BER | Uncorrectable blocks |
|---|---|---|---|---|
| `clean` (default) | 18.30 | 11.42 | 9.8e-05 | never |
| `typical` | 16.68 | 9.80 | 1.0e-03 | never |
| `degraded` | 15.60 | 8.72 | 3.2e-03 | never |
| `failing` | 10.10 | 3.22 | 7.4e-02 | always |

Only `failing` crosses the FEC threshold, and it does so for **every** channel
across the whole dial period, so `fec-uncorrectable-blocks > 0` is a reliable
service-affecting signal. `degraded` deliberately stays clear of the
threshold: a visibly elevated BER that FEC still corrects is the window in
which a proactive alarm has any value.

These boundaries hold for every channel of every seed, not merely at the
nominal point. Per-channel jitter is sized against the tier gaps, and a test
sweeps seeds to keep it that way.

Setting a non-`clean` band on a device type with no optical channels is
rejected with 400, and `optical_scenario` is omitted from
`GET /api/v1/devices` for those types.

## On-demand degradation

The health band is steady state. To drive a specific channel across the
threshold when you want it, use the degrade endpoint (full schema in
[Web API](web-api.md#on-demand-optical-degradation)):

```bash
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade \
  -H "Content-Type: application/json" \
  -d '{"noise_rise_db": 8, "duration": "30s"}'
```

Two knobs, because they select the diagnostic quadrant:

| Request | Power | OSNR | FEC errors | Models |
|---|---|---|---|---|
| `input_power_drop_db` | falls | **unchanged** | none | dirty connector, lossy span |
| `noise_rise_db` | unchanged | falls | yes, if past threshold | sick amplifier, ASE accumulation |
| both | falls | falls | yes, if past threshold | loss upstream of an amplifier |

Attenuation leaves OSNR untouched because signal and accumulated ASE traverse
the same fibre and attenuate together, so the loss cancels out of their
difference. **Crossing the FEC threshold therefore requires `noise_rise_db`.**

Two properties a collector can rely on:

- **The revert needs no timer.** A degradation window is frozen at publish and
  the value engine is a pure function of time, so the channel returns to band
  by arithmetic when the window ends.
- **`fec-uncorrectable-blocks` never decreases** across a degrade and revert
  cycle. Degradation is stored as append-only immutable episodes precisely so
  that reverting cannot remove already-elapsed degradation from the integral.
  A counter that walked backwards would be read as a device reboot.

Query what is in force with `GET /api/v1/devices/{ip}/optical`.

## SAMPLE, not ON_CHANGE

Optical paths are rejected for `STREAM/ON_CHANGE` with `InvalidArgument`.
These are analog measurements that change continuously, so ON_CHANGE would
degenerate into an unbounded update storm. Use SAMPLE with a
`sample_interval`; sub-second intervals are clamped to 1s.

The rejection message names the leaf class, so a rejected `osnr` subscription
does not get told it is a counter.

## Encoding caveat for BER

`pre-fec-ber` carries 18 fraction digits, which exceeds a float64 significand.
Under `PROTO` the value goes out as `double_val` and is **lossy**. This is
inherent to representing decimal64 in gNMI's PROTO scalar set, not an nl6
shortcut. Prefer `JSON_IETF`, where RFC 7951 renders decimal64 as a string and
the digits survive.

## Validating a use case

The device exists to let a monitoring team validate optical use cases without
hardware. Each of the following is a concrete exercise. Assume one optical
device at `10.42.0.1`, gNMI on 9339, REST on 8080.

Create one:

```bash
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{"start_ip":"10.42.0.1","device_count":1,"netmask":"16",
       "resource_file":"ciena_waveserver5.json"}'
```

### 1. Discovery and inventory

Enumerate channels and read identity, frequency, mode and target power.

```bash
gnmic -a 10.42.0.1:9339 --skip-verify capabilities | grep terminal-device
gnmic -a 10.42.0.1:9339 --skip-verify get \
  --path '/components/component[name=*]/optical-channel/config'
```

Expect two channels, each with `frequency`, `target-output-power`,
`operational-mode` and `line-port`. Capabilities must advertise the three
optical models; a packet device advertises none of them.

### 2. Metric collection into a timeseries

```bash
gnmic -a 10.42.0.1:9339 --skip-verify subscribe \
  --path '/components/component[name=*]/optical-channel/state/osnr/instant' \
  --path '/components/component[name=*]/optical-channel/state/input-power/instant' \
  --sample-interval 10s
```

Check units and precision on the wire, not just presence: dBm and dB at two
fraction digits, and negative power values rendered correctly.

### 3. Threshold and alarm rules

Drive the crossing on demand rather than waiting:

```bash
# Watch the counter
gnmic -a 10.42.0.1:9339 --skip-verify subscribe \
  --path '/components/component[name=OCH-1-1]/optical-channel/state/fec-uncorrectable-blocks' \
  --sample-interval 5s &

# Push it past the SD-FEC threshold for a minute
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade \
  -H "Content-Type: application/json" \
  -d '{"noise_rise_db": 9, "duration": "60s"}'
```

`pre-fec-ber` climbs past 2e-2 and the block counter starts advancing, then
stops when the window closes.

The crossing also raises a **real Ciena notification**: a trap
(`wsLinkStateAlarmNotification`, `1.3.6.1.4.1.1271.3.2.12`, with
`OtuPreFecSd`/`OtuPreFecSf` condition flags and the MIB's non-contiguous
severity enum) and a matching syslog line, with a distinct clear on recovery.
Detection runs in a shared evaluator with 0.5 dB hysteresis and a 30 s soak,
so a channel resting near a threshold does not flap. SD is predictive (below
~14.3 dB OSNR, below every healthy tier's excursion envelope); SF is
service-affecting and is by construction the same threshold that starts the
`fec-uncorrectable-blocks` counter. Note the clear-correlation caveat in the
[limitations doc](https://github.com/labmonkeys-space/nl6/blob/main/go/nl6/resources/ciena_waveserver5_limitations.md):
a clear names its condition only in the Description text — that is Ciena's
model, reproduced faithfully.

### 4. Correlation and root cause

The two quadrants, run against the same channel and compared:

```bash
# Attenuation: power drops, OSNR holds, no FEC errors
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade \
  -H "Content-Type: application/json" -d '{"input_power_drop_db": 8, "duration": "60s"}'

# ASE: power holds, OSNR drops, FEC errors accrue
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade \
  -H "Content-Type: application/json" -d '{"noise_rise_db": 8, "duration": "60s"}'
```

A correlation rule that cannot tell these apart is the bug this exercise
exists to catch. Confirm at the same time that the off-spine leaves
(`output-power`, `laser-bias-current`, `chromatic-dispersion`) do not move in
either case.

### 5. Service-affecting detection

`fec-uncorrectable-blocks` going 0 to nonzero is the service-affecting
transition, and it is monotonic. Run a degrade and revert cycle while
sampling, and assert the counter never decreases. A rule keyed on
"counter increased in the last N minutes" is the shape that works; one keyed
on an absolute value is not portable across restarts.

### 6. Graphing, units and precision

Compare the same leaf under both encodings:

```bash
gnmic -a 10.42.0.1:9339 --skip-verify get -e json_ietf \
  --path '/components/component[name=OCH-1-1]/optical-channel/state/pre-fec-ber/instant'
gnmic -a 10.42.0.1:9339 --skip-verify get -e proto \
  --path '/components/component[name=OCH-1-1]/optical-channel/state/pre-fec-ber/instant'
```

JSON_IETF preserves all 18 digits as a string; PROTO loses precision. If your
pipeline parses BER as a float, this is where you find out.

### 7. Negative and edge handling

```bash
# Unknown component -> NotFound
gnmic -a 10.42.0.1:9339 --skip-verify get \
  --path '/components/component[name=OCH-9-9]/optical-channel/state/osnr/avg'

# Statistic on the bare counter -> NotFound, with a message saying why
gnmic -a 10.42.0.1:9339 --skip-verify get \
  --path '/components/component[name=OCH-1-1]/optical-channel/state/fec-uncorrectable-blocks/instant'

# Optical path on a packet device -> NotFound, not Unavailable
gnmic -a 10.42.0.2:9339 --skip-verify get \
  --path '/components/component[name=*]/optical-channel/state/osnr/avg'
```

`NotFound` means permanently absent; `Unavailable` is reserved for an optical
device still initialising, and is retryable. A client that conflates the two
will either retry forever or give up too early.

Per-counter `supported` and `invalid-data-flag` have no leaves here, by
decision ([#334](https://github.com/labmonkeys-space/nl6/issues/334)): on the
OpenConfig surface the `supported` equivalent **is leaf absence** — exactly
what the three checks above exercise — and `invalid-data-flag` is
inexpressible without inventing behaviour, so it is deliberately not
simulated. See the limitations doc for the full rationale.

## Example configuration

A ready-to-run `gnmic` config lives in
[`examples/gnmic-optical/`](https://github.com/labmonkeys-space/nl6/tree/main/examples/gnmic-optical),
including the correct shape for an OTLP bridge:
`nl6 -> gNMI -> gnmic -> OTLP -> collector`. The device does **not** speak
OTLP; no Ciena source claims it does, and pretending otherwise would be a
false pass in the other direction.
