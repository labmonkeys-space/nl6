# Measuring a collector's ingest ceiling

nl6 can tell you what it put on the wire.
It cannot tell you what your collector accepted.
This page is the method for finding that second number, and for not fooling yourself while you do.

The worked example throughout is OpenNMS Horizon syslog ingest, because that is the case the numbers came from.
The method generalises to any push protocol nl6 exports.

## Why a delivered number is not an answer

A load generator reports what it sent.
UDP has no failure signal, so "sent 60,000, failures 0" is true even when the collector received nothing at all.
Every claim about capacity therefore needs a second measurement taken on the collector side, and the gap between the two has to be explained rather than assumed.

The first attempt at this measurement got the shape of the answer right and the mechanism wrong.
It reported a rate and named a Kafka partition count as the likely limiter, on the strength of a config value and a core that was not CPU-bound.
The real mechanism was arithmetic nothing had measured: messages per work unit divided by the time to process one.
The difference matters because the wrong cause implies the wrong fix.

## Vocabulary

One quantity travels under four names, and conflating them is the most common way this measurement goes wrong.

| term | meaning here |
|---|---|
| **work unit** | whatever the collector processes as one indivisible chunk |
| record, batch, dispatch | the same thing, named by whichever layer you are looking at |
| **message** | one datagram nl6 emitted |
| **event** | one row the collector persisted |

A work unit usually holds several messages.
One message does **not** necessarily become one event: a collector may coalesce or expand.
Where the two differ, say so, or the identity check below will fail for a reason you never modelled.

The OpenNMS worked example uses "Core" for the product component and "vCPU" for processor count, because "core" means both.

## Two different numbers, both called "the ceiling"

| number | what it means | how you get it |
|---|---|---|
| **service rate** | how fast the pipeline drains a backlog | offer a burst, then measure the drain |
| **sustained ceiling** | the highest rate the pipeline keeps up with | ramp the offered rate, watch the queue slope |

These are not the same, and the second is almost always the one an operator wants.
"Can my collector keep up with 30,000 devices?" is a question about steady state.

**A result must state which one it measured.**
They are not interchangeable, and a number reported without that label is unusable by anyone who did not run it.

Define the sustained ceiling as **the highest offered rate at which the collector's input queue depth stays bounded over a sustained window**.
Bounded, not zero: queue depth oscillates normally.
The test is the *slope*.
Sample queue depth at a fixed interval across a **15 minute** window and fit a line.
A slope that stays positive across the whole window means the offered rate is above the ceiling; a slope oscillating around zero means it is at or below.

That makes the ceiling a search rather than a single run, and a cell is not finished until its final rate has held flat for the full window.
A rate that holds for 60 seconds and degrades at 10 minutes is not a ceiling.

## Three-point reconciliation

Two measurement points cannot distinguish loss from slowness.
Three can.

```
 (1) nl6 `sent`             what reached the wire
      |  gap = loss between generator and queue
 (2) queue input            what arrived
      |  gap = backlog, or drops inside the collector
 (3) persisted records      what was accepted
```

Point (1) is the report's **`sent`** field, which is `in_window + drain`.
It is deliberately **not** `emitted`: that also counts `send_failures`, `dropped` and `suppressed_pre_window`, none of which reached the wire, so using it would charge nl6-side non-sends to the network.
See the [report schema](./loadtest-report-schema.md), which names `sent` as the loss denominator.

Report all three.
A run that reports only (1) and (3) cannot tell a lossy pipeline from a slow one, and those have opposite fixes.

The (1) to (2) gap covers everything between the generator and the queue: datagrams dropped in the network, a receiver whose buffer overran, and any loss inside the collector's own pre-queue path.
The (2) to (3) gap is backlog or in-collector drops, and a consumer-side drop counter sits on this segment, not the first.

### When zero loss is required, and when it is not

Loss instruments must read zero on runs that **claim a rate**: the loss-isolation control and every at-or-below-ceiling cell.

They will **not** read zero while searching above the ceiling, and that is expected.
Probing above the ceiling is how the search finds it, and on a UDP path an overrun receiver is the signal you are looking for.
An above-ceiling probe with loss is a valid probe; it is simply not a result.

### The loss-isolation control

Run at roughly half the measured ceiling, sustained, with the queue flat throughout.
There (1) and (3) must agree within the reconciliation tolerance nl6 itself uses (`nl6-reconcile` defaults to 0.5%), not bit-exactly: (3) is a database count and carries its own noise.

If they do not agree, the pipeline is lossy at **any** rate.
That **invalidates the ceiling**, rather than annotating it.

## Instrumentation

Find the collector's equivalents of these before running anything.
Without them you are measuring a black box and guessing at the mechanism.

| you need | OpenNMS Horizon equivalent |
|---|---|
| **arrival count**, point (2) | producer-side offset delta on the sink topic |
| queue depth over time | Kafka consumer-group `LAG` for the sink topic |
| work-unit service time | `..._sink_consumer_syslog_dispatchtime_*` |
| messages per work unit | `..._sink_consumer_syslog_messagesize_*`, plus offset delta versus messages sent |
| drop counter | `..._sink_consumer_syslog_dropped_count` |
| **accepted count**, point (3) | windowed, filtered count of the run's events |

Two cautions on the OpenNMS names, both of which will cost you a matrix if you skip them.

They are one deployment's rendering, not canonical: the all-lowercase `dispatchtime` and `messagesize` appear that way only when the Prometheus JMX exporter runs with `lowercaseOutputName: true`.
Confirm the names on your build before trusting a run, since a rename between versions invalidates a whole session silently.

The accepted count must be **windowed and filtered**.
An unqualified `select count(*) from events` is a lifetime total across every event source, including the collector's own internal events, so it can never match an offered rate.
Take a delta across the run window and restrict it to the events the run produced.

### Making the identity reproduce

```
throughput = (messages per work unit / service time per work unit) × concurrent workers
```

The worker term matters: on a single-consumer pipeline it is 1 and disappears, but any run that varies parallelism must carry it or the identity under-predicts by exactly the worker count.

**Service time is wall clock, not CPU**, and the difference decides how the identity scales.
Where the per-message cost is dominated by waiting (database round trips, network), adding workers overlaps those waits and throughput rises without CPU rising with it.
Measured here, 4 workers took ~130/s to ~320/s, a 2.4x gain from 4x the workers, while the collector used only 1.2 of 4 available vCPU.
Expect sub-linear scaling, and treat a large gap between predicted and measured as a pointer to the *next* constraint rather than a broken model: in this case the database, the most loaded component at that rate.

State which statistic you used.
The mean and the median give different answers (`4 / 0.030 = 133`, `4 / 0.0294 = 136`), so a reader replicating your check needs to know which one you meant.

If the identity does not reproduce the measured rate, something is missing from the picture, and the ceiling number is not yet understood.

## Before any run: silence the generator

Background emission inflates (3) without touching (1).
It is the one failure mode three-point reconciliation cannot self-detect, because it makes the pipeline look like it is running *ahead* of the load.

nl6's per-device `interval` and `tick_interval` are accepted, echoed back, and **not honored** ([nl6#445](https://github.com/labmonkeys-space/nl6/issues/445)): every device fires at the simulator-wide cadence regardless.
A long per-device interval therefore does not silence anything, and reading the value back confirms a setting that is not in force.

Start nl6 with `-fidelity`, then verify the generator is actually silent before offering load: its sent counter must not move while idle.
A measurement that skips this check is measuring its own background noise.

## Staged gates

Run the cheapest test that can invalidate the most work first.
Each gate can end the investigation early, which is a successful outcome.

```
G1  Is service time FIXED per work unit, or proportional to its contents?
     vary the work-unit size, plot service time
     |- proportional  -> batching is not a lever, drop that axis
     '- mostly fixed  -> batching is the lever

G2  Does the collector parallelise when given more partitions?
     add partitions, re-read the consumer-group assignment
     |- consumer count unchanged -> that axis is inert, drop it
     '- consumer count rises     -> the axis is real
```

The matrix that follows is not a gate; it is the work these two gates decide the shape of.

**G2 has two traps, and the second one loses data.**

First, on Kafka `num.partitions` only affects newly created topics.
Raising it without an explicit `--alter` on the existing topic changes nothing, which looks exactly like the collector failing to parallelise and would retire a live axis on no evidence.

Second, and more serious: **the producer starts using new partitions immediately, while a running consumer may never discover them.**
Measured on Horizon 36.0.3, going from 1 to 4 partitions left the new three carrying thousands of records that did not appear in the consumer group at all, with no consumer, no committed offset and no lag tracked.
They were never processed until the collector was restarted.

So a reader who alters a live topic and then checks the assignment gets **both** a data-stranding incident and a false "inert" reading, because the assignment is still what it was.
Restart the collector after altering, re-read the assignment, and only then judge the axis.
Then confirm the added consumers are distinct instances doing real work rather than one consumer holding several partitions.

Do not perform this on a production topic without planning for the restart.
Partition counts also cannot be reduced, so the change is one-way.

If both gates fail, the honest answer is "this collector's ceiling is X and only a code change moves it".
That is worth knowing and costs about an hour.

## Load shape is a variable, not a detail

An aggregate rate does not determine the work the collector sees.

Where the collector aggregates **per source** and flushes on an interval, batch size follows the PER-DEVICE rate:

```
   batch size  ~  per_device_rate x flush_interval
```

Measured on Horizon 36.0.3, whose syslog sink keys aggregation per host and flushes at roughly 500 ms, at one fixed aggregate rate of ~3000/s:

| devices | per-device rate | messages per work unit |
|---|---|---|
| 500 | 6/s | 4.0 |
| 63 | 47/s | 24.0 |

**More devices at the same aggregate rate makes the collector slower**, because it shreds the batches.
That is the opposite of the intuition that a fleet is just a rate.

Two consequences for any result:

- A ceiling figure is meaningless without the **device count and per-device rate** that produced it. Report them beside the number, and carry them in the manifest as controls.
- Comparing two runs at the same aggregate rate but different fleet sizes compares two different workloads, not two configurations.

## The matrix

Declare exactly one independent variable per run.
The axes are whichever gates survived, so the cell count follows from them.

| axis | levels (OpenNMS example) | survives if |
|---|---|---|
| **A** work-unit size | the sink's batch-size setting, at three levels | G1 passed |
| **B** consumer parallelism | partitions and consumers: 1, 4 | G2 passed |

Both axes gives six cells, one axis gives three, neither gives none.
The **baseline cell** is the untouched configuration, and it is run twice: once first, once last, so drift across the session is visible rather than assumed absent.

Discard any cell whose observed messages-per-work-unit drifted materially from its declared level.
That cell is not the configuration it claims to be.
Note that a queue's batch-size setting is often a soft target rather than a hard cap, so decide and record what "materially" means before running, instead of adjudicating it afterwards.

Everything else is a control, and controls belong in the manifest so two runs can be compared: generator version and device count, protocol and message format, collector version, VM sizes, JVM and GC flags, database durability settings, and whether devices are provisioned as nodes.
Two runs are comparable only when every control matches and exactly one axis differs.

## The manifest

Gather at run time, never reconstruct afterwards.
It must be able to express the result the method demands, which means carrying the three reconciliation counts and the correctness check, not only the tuning:

```json
{
  "measured_quantity": "sustained_ceiling",
  "sut": {
    "queue": { "partitions": 1, "batch_setting": "<property>=<value>" },
    "consumers": { "count": 1, "assignment": ["syslog-0"] }
  },
  "controls": { "generator_version": "...", "devices": 500, "collector_version": "..." },
  "reconciliation": {
    "sent": 0, "arrived": 0, "persisted": 0,
    "drop_counters": { "consumer_dropped": 0 },
    "loss_isolation_run": { "sent": 0, "persisted": 0, "within_tolerance": true }
  },
  "observed": {
    "service_time_ms": { "statistic_used": "mean", "p50": 0, "mean": 0, "min": 0, "max": 0 },
    "work_unit_size_bytes": { "mean": 0, "max": 0 },
    "messages_per_work_unit": 0,
    "concurrent_workers": 1,
    "queue_slope": "flat|positive",
    "ordering_preserved": true
  }
}
```

`messages_per_work_unit` and `service_time_ms` are **derived controls**.
If a cell's observed values drifted from its declared level, that cell must be discarded rather than reported.

## Correctness confounds

If a tuning change can alter the collector's *output*, throughput alone is not a result.

**Parallelism can reorder events.**
Message queues typically guarantee order only within a partition.
Unless records are keyed by device, raising the partition count lets two messages from one device be processed out of order.

For a monitoring system that is semantically loaded, not cosmetic.
A `linkDown` and `linkUp` pair delivered inverted leaves an interface latched down that is actually up.

So the parallelism axis carries a mandatory ordering check: emit a known-ordered per-device sequence and assert the order survives.
A result showing higher throughput with broken ordering is **reported as a regression**, not as a gain.

Work-unit size changes alter packing rather than order, so that axis carries no equivalent confound, which is a further reason to test it first.

## Worked example: OpenNMS Horizon 36.0.3

Measured on the `opennms-benchmark` KVM lab: single Minion, 4 vCPU Core, single-partition sink.

**This example reports a service rate, not a sustained ceiling.**
It was obtained by offering a burst far above capacity and measuring the drain, with queue depth growing throughout.
It is shown because it is where the mechanism came from, and it is exactly the substitution this page tells you to avoid.

```
 nl6 --UDP--> Minion --produce--> Kafka --consume--> Core --> Postgres
  40,003/s sent                   LAG growing         |
                                                      '- the constraint

 service time   p50 29.4 ms | mean 30.0 ms | min 23.6 ms | max 54.5 ms
 work unit      ~4 messages per record, ~994 B mean, 1069 B max
 model          (4 messages / 0.030 s mean) x 1 worker  =  133 msg/s
 measured       ~130 events/s drained
```

The model reproduces the measurement, so the mechanism is understood: one consumer thread, roughly four messages per record, about 30 ms per dispatch.
The example assumes one message persists as one event; a collector that coalesces would break that step.

Two honest limits on this example.

The per-message figure of about 248 bytes is `994 / 4`, a **queue-side** number that includes record framing.
nl6's syslog datagrams are smaller on the wire, roughly 130 to 210 bytes depending on the catalog entry, so 248 must not be read as a datagram size.

The batching is a **count cap plus an interval flush**, not a byte cap, and the interval is what actually binds here.
`SyslogSinkModule` exposes an aggregation policy with `getBatchSize()` (a count) and `getBatchIntervalMs()`; neither is configured in this lab, so both run at defaults, and the observed batch tracks per-device rate rather than record size.
An earlier draft of this page called it a byte cap on the strength of `994 / 4`, which was the same mistake it warns about elsewhere: reasoning from a derived average instead of measuring.

**This is one topology's number.**
A single Minion and a 4 vCPU Core with a single-partition sink is not a tuned production deployment, and a manifest has to say so as plainly as the number does.

## Related

- [Runbooks](./loadtest-runbooks.md) for the scenario mechanics each run is built from, including how the offered rate is set
- [Scenarios](./loadtest-scenarios.md) for the lifecycle and fidelity mode
- [Report schema](./loadtest-report-schema.md) for `sent` versus `emitted`, and what nl6 reports about its own side of the measurement
