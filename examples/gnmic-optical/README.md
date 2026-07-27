# gnmic + nl6 optical telemetry

A ready-to-run [`gnmic`](https://gnmic.openconfig.net/) configuration that
consumes the optical surface of a simulated Ciena Waveserver 5, plus the
two-command loop for exercising a threshold crossing on demand.

Full reference: [`docs/reference/optical-telemetry.md`](../../docs/reference/optical-telemetry.md).
Where the simulation stops: [`ciena_waveserver5_limitations.md`](../../go/nl6/resources/ciena_waveserver5_limitations.md).

## 1. Create an optical device

```bash
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{"start_ip":"10.42.0.1","device_count":1,"netmask":"16",
       "resource_file":"ciena_waveserver5.json"}'
```

Two channels come up, `OCH-1-1` and `OCH-1-2`, one per WaveLogic 5 Extreme
modem. Channels are keyed by **component name**, never by ifIndex.

## 2. Subscribe

```bash
gnmic --config gnmic.yaml subscribe
```

`gnmic.yaml` defines three subscriptions:

| Subscription | Cadence | Why separate |
|---|---|---|
| `optical-spine` | 10s | The receive-side cascade. Their ratio is the diagnostic. |
| `optical-fec` | 30s | The service-affecting counter, so it can carry its own alerting policy. |
| `optical-offspine` | 60s | Subscribe to prove these stay flat during a fault. |

Only the first two are attached to the target by default; add
`optical-offspine` when running the correlation exercise below.

**SAMPLE only.** Optical paths are rejected for ON_CHANGE: these are analog
measurements that change continuously, so ON_CHANGE would be an unbounded
update storm.

## 3. Drive a threshold crossing

The health band is steady state. To make something happen when you want it:

```bash
# Past the SD-FEC threshold for 60s, then automatically back to band
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade \
  -H "Content-Type: application/json" \
  -d '{"noise_rise_db": 9, "duration": "60s"}'
```

`pre-fec-ber` climbs past 2e-2 and `fec-uncorrectable-blocks` starts
advancing, then stops when the window closes. The counter never decreases.

## 4. Tell a fibre fault from an amplifier fault

The reason there are two knobs rather than one severity dial:

```bash
# Attenuation: power falls, OSNR UNCHANGED, no FEC errors
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade \
  -H "Content-Type: application/json" -d '{"input_power_drop_db": 8, "duration": "60s"}'

# ASE: power unchanged, OSNR falls, FEC errors accrue
curl -X POST http://localhost:8080/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade \
  -H "Content-Type: application/json" -d '{"noise_rise_db": 8, "duration": "60s"}'
```

Signal and accumulated ASE traverse the same fibre and attenuate together, so
a span loss cancels out of their difference and leaves OSNR untouched. A
correlation rule that cannot separate these two is the bug this exercise
exists to find.

Clear early with an empty body, and check current state with
`GET /api/v1/devices/10.42.0.1/optical`.

## 5. If you want this in an OTel pipeline

Bridge it, in this order:

```
nl6  ->  gNMI  ->  gnmic  ->  OTLP  ->  collector
```

The device does **not** speak OTLP, and no Ciena source claims a Waveserver
does. Emitting OTLP device-side would be exactly the false pass this device
type is built to avoid. See the commented `outputs` block in `gnmic.yaml`.

## Precision warning for BER

`pre-fec-ber` carries 18 fraction digits, more than a float64 significand
holds. The config uses `json_ietf`, where RFC 7951 renders decimal64 as a
string and the digits survive. Under `proto` the value goes out as
`double_val` and is lossy. If your pipeline parses BER as a float, decide
that deliberately rather than discovering it in production.
