# Ciena Waveserver 5 — simulation limitations

**Read this before building anything against `ciena_waveserver5` that you
intend to run against real hardware.**

This device type exists so a monitoring team can implement and validate
optical use cases without a lab. The failure mode that matters is not
synthetic-looking values, it is the **false pass**: you build against nl6, it
works, you deploy against a real Waveserver, and it breaks. A team that cannot
see where the simulation ends will trust it past its edges. This file is where
it ends.

## Loud ones first

### sysObjectID is a placeholder, and device detection will mis-identify

The shipped value is:

```
1.3.6.1.4.1.1271.3
```

That is the **`waveserver` subtree node**, confirmed from the public MIB
mirror. It is *not* the per-model product OID a real Waveserver 5 returns,
because `CIENA-PRODUCTS-MIB` is not in the public mirror and the real value is
behind the Ciena support portal.

Consequence: **sysObjectID-based device detection will not match** what your
system learns from real hardware. If your provisioning keys on sysObjectID,
treat this value as unknown rather than as ground truth. Replace it here if
you can confirm the product OID.

### Statistics are instantaneous, not 15-minute PM bins

nl6 computes `{instant, avg, min, max}` over a trailing window and answers
every request live. A real Waveserver accumulates **15-minute PM bins with 96
bins of history**, plus 24-hour bins, and exposes bin boundaries, bin state
and suspect-interval flags.

Consequence: anything that consumes bin semantics does not exist here. There
is no bin rollover to observe, no historical bin retrieval, and no
suspect-interval marking. A rule that waits for a bin to close will never
fire.

### Values are analytic, not captured from hardware

Every value is a deterministic function of elapsed time: sinusoidal dials, a
closed-form cascade, per-channel jitter from a fixed seed. They are shaped to
be *physically coherent* (OSNR drives Q drives BER drives uncorrectable
blocks; attenuation moves power but not OSNR), not to reproduce any measured
trace. Real coherent optics exhibit noise, transients and correlations this
model does not attempt.

Use nl6 to validate that your logic reacts correctly to a given shape. Do not
use it to characterise what shapes real hardware produces.

## Not served, and why

| Absent | Why |
|---|---|
| `post-fec-ber` | Defined by OpenConfig, but **Ciena removed it** from their model. Serving it would let a rule pass here that could never fire against real hardware. Deliberate; a test asserts its absence. |
| Per-counter `supported` / `invalid-data-flag` | Present on every counter in `ciena-waveserver-pm`, but OpenConfig defines no equivalent leaf. Expressing them would mean inventing a path. Tracked in [#334](https://github.com/labmonkeys-space/nl6/issues/334). |
| SD/SF alarm notifications | The FEC threshold crossing is observable through values and the block counter, but no trap or syslog fires on it yet. Tracked in [#347](https://github.com/labmonkeys-space/nl6/issues/347). |
| NETCONF, and the native `ciena-waveserver-*` models | nl6 serves the OpenConfig surface over gNMI only. A team that talks to real Waveservers over NETCONF with Ciena's own models is exercising a different interface entirely. |
| Flow export (NetFlow / IPFIX / sFlow) | Correct, not missing. A layer-1 transport platform performs no layer-3/4 inspection and exports no flow records, so nl6 must not either. A batch flow seed skips this type; an explicit `flow` block naming it is rejected with 400. |
| gNMI dial-out | The shipped dial-out flavor is `gnmireverse`, which is Arista-specific. This device serves dial-in only. |
| OTLP | **No Ciena source claims OTLP support.** If you want optical telemetry in an OTel pipeline, bridge it: `nl6 -> gNMI -> gnmic -> OTLP -> collector`. Emitting OTLP device-side would be a false pass. |
| `cwsAlarmActiveTable` / `cwsAlarmHistoryTable` | A real Waveserver exposes active alarms as SNMP tables for polling. Not simulated. |

## Divergences you can observe on the wire

| Aspect | Real Waveserver | nl6 | Why |
|---|---|---|---|
| Statistics precision | `decimal-3-dig` (3 dp) | 2 fraction digits | The served surface is OpenConfig, whose stats groupings mandate 2. Emitting 3 would fail strict schema validation. |
| Pre-FEC BER representation | `string-sci` (scientific notation string) | decimal64, 18 fraction digits | Same reason: OpenConfig types govern the surface nl6 serves. |
| DGD | integer picoseconds | `polarization-mode-dispersion`, decimal64, 2 dp | First-order PMD is DGD; OpenConfig names and types it this way. |
| OSNR | **not in Ciena's modem PM** | served | A real WL5 modem reports electrical SNR. OpenConfig defines OSNR and collectors expect it, so it is served, with `esnr` alongside so the divergence narrows rather than widens. |

## Model provenance

| Layer | Status |
|---|---|
| OpenConfig schema | Pinned: terminal-device 2026-01-14, platform-transceiver 2026-03-25, platform 2025-07-15. Served paths were traced against these. |
| Waveserver native schema | Verified leaf by leaf against the ONOS mirror of `ciena-waveserver-{pm,xcvr-modem}` — **Waveserver Ai vintage, 2017 to 2018**. Newer firmware may differ. |
| Waveserver SNMP MIBs | Publicly mirrored (`kcsinclair/mibs`). The mirror is **unversioned**, so it cannot be tied to a firmware release. |
| Waveserver values | Not public. The Command Reference with real operating values is portal-gated, so no shipped value is derived from documented hardware output. |

Path validation is by an in-repo manifest, not by compiling the YANG. The test
pins served paths against a hand-transcribed table in both directions, so it
catches drift and invented paths, but it does **not** prove the table itself
matches the models. A true schema check would need the YANG vendored plus
ygot.

## What is faithful

Stated so the limitations above are read in proportion, not as a disclaimer on
everything:

- **Paths, types and encodings** come from the pinned models, not from
  invention. A path whose existence could not be confirmed was omitted.
- **The cascade is physically coherent.** OSNR to Q to pre-FEC BER to
  uncorrectable blocks, with the erfc tail's real shallowness at the SD-FEC
  threshold rather than a convenient decade-scale cliff.
- **The two-dial model reproduces the real diagnostic split.** Attenuation
  moves power without moving OSNR; ASE accumulation moves OSNR without moving
  power. Both quadrants are reachable, and off-spine leaves stay flat under a
  receive-side fault.
- **`fec-uncorrectable-blocks` is monotonic** across any sequence of
  degradations and reverts, which is the property a collector actually depends
  on.
- **Cross-surface agreement.** Every surface reads one dispatcher, so two
  reads at the same instant agree.

See [`docs/reference/optical-telemetry.md`](../../../docs/reference/optical-telemetry.md)
for the served surface and a per-use-case validation walkthrough.
