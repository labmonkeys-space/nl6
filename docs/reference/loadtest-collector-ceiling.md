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
It reported a ceiling and attributed it to a Kafka partition count, on the strength of a config value and a not-CPU-bound core.
The real cause was arithmetic that nothing had measured: batch size divided by per-dispatch cost.
The difference matters because the wrong cause implies the wrong fix.

## Two different numbers, both called "the ceiling"

| number | what it means | how you get it |
|---|---|---|
| **service rate** | how fast the pipeline drains a backlog | offer a burst, then measure the drain |
| **sustained ceiling** | the highest rate the pipeline keeps up with | ramp the offered rate, watch the queue slope |

These are not the same, and the second is almost always the one an operator wants.
"Can my collector keep up with 30,000 devices?" is a question about steady state.

Define the sustained ceiling as **the highest offered rate at which the collector's input queue depth stays bounded over a sustained window**.
Bounded, not zero: queue depth oscillates normally.
The test is the *slope*.
Fit queue depth over the window; a persistently positive slope means the offered rate is above the ceiling.

That makes the ceiling a search rather than a single run.

## Three-point reconciliation

Two measurement points cannot distinguish loss from slowness.
Three can.

```
 (1) nl6 send ledger            what the simulator emitted
        |
        |   gap = loss before the queue (UDP drops, receiver overrun)
        v
 (2) collector queue input      what actually arrived
        |
        |   gap = backlog, or drops inside the collector
        v
 (3) persisted records          what was accepted
```

Report all three.
A run that reports only (1) and (3) cannot tell a lossy pipeline from a slow one, and those have opposite fixes.

**Every loss instrument the collector exposes must read zero**, and the run is invalid otherwise.
For OpenNMS that is `org_opennms_core_ipc_sink_consumer_syslog_dropped_count` plus the (1) to (2) gap.

Add a **loss-isolation run** at roughly half the measured ceiling, sustained, with the queue flat throughout.
There, (1) and (3) must match exactly.
If they do not, the pipeline is lossy at *any* rate and every other number in the report is suspect.

## Instrumentation

Find the collector's equivalents of these before running anything.
Without them you are measuring a black box and guessing at the mechanism.

| you need | OpenNMS Horizon equivalent |
|---|---|
| queue depth over time | Kafka consumer-group `LAG` for the sink topic |
| work-unit service time | `..._sink_consumer_syslog_dispatchtime_*` (JMX exporter, port 9299) |
| work-unit size | `..._sink_consumer_syslog_messagesize_*`, plus offset delta versus messages sent |
| drop counter | `..._sink_consumer_syslog_dropped_count` |
| accepted count | `select count(*) from events` |

The service-time and work-unit-size pair is what turns a measured rate into a *model*:

```
throughput = messages per work unit / service time per work unit
```

If that identity does not reproduce the measured rate, something is missing from the picture, and the ceiling number is not yet understood.

## Staged gates

Run the cheapest test that can invalidate the most work first.
Each gate can end the investigation early, which is a successful outcome.

```
G1  Is service time FIXED per work unit, or proportional to its contents?
     vary the batch size, plot service time
     |- proportional  -> batching is not a lever
     '- mostly fixed  -> batching is the lever

G2  Does the collector parallelise when given more partitions?
     add partitions, re-read the consumer-group assignment
     |- consumer count unchanged -> that axis is inert, drop it
     '- consumer count rises     -> the axis is real

          only then
             v
G3  The matrix
```

If both gates fail, the honest answer is "this collector's ceiling is X and only a code change moves it".
That is worth knowing and costs an hour.

## The matrix

Declare exactly one independent variable per run.

| axis | levels (OpenNMS example) |
|---|---|
| **A** work-unit size | sink batch bytes: 1 KB (default), 16 KB, 64 KB |
| **B** consumer parallelism | partitions and consumers: 1, 4 |

Six cells, plus a **repeat of the baseline cell at the end** to detect drift across the session.
Each cell is a ceiling search, not a single rate.

Everything else is a control and belongs in the comparability key: generator version and device count, protocol and message format, collector version, VM sizes, JVM and GC flags, database durability settings, and whether devices are provisioned as nodes.

## The manifest

Gather at run time, never reconstruct afterwards.
Beyond the usual environment fields, a ceiling run needs the tuning it varied and the model it observed:

```json
{
  "sut": {
    "queue": { "partitions": 1, "batch_bytes": 1024 },
    "consumers": { "count": 1, "assignment": ["syslog-0"] }
  },
  "observed": {
    "service_time_ms": { "p50": 29.4, "mean": 30.0, "min": 23.6, "max": 54.5 },
    "work_unit_size_bytes": { "mean": 994, "max": 1069 },
    "messages_per_work_unit": 4.0,
    "dropped_count": 0,
    "queue_slope_per_s": 0.0
  }
}
```

`messages_per_work_unit` and `service_time_ms` are **derived controls**.
If a cell's observed batch size drifted from its declared level, that cell is not the configuration it claims to be, and it must be discarded rather than reported.

## Correctness confounds

If a tuning change can alter the collector's *output*, throughput alone is not a result.

**Parallelism can reorder events.**
Message queues typically guarantee order only within a partition.
Unless records are keyed by device, raising the partition count lets two messages from one device be processed out of order.

For a monitoring system that is semantically loaded, not cosmetic.
A `linkDown` and `linkUp` pair delivered inverted leaves an interface latched down that is actually up.

So the parallelism axis carries a mandatory ordering check: emit a known-ordered per-device sequence and assert the order survives.
A throughput gain that reorders events is not a gain.

Batch-size changes alter packing rather than order, so that axis carries no equivalent confound.

## Worked example: OpenNMS Horizon 36.0.3

Measured on the `opennms-benchmark` KVM lab, single Minion, 4-vCPU core, single-partition sink.

```
 nl6 --UDP--> Minion --produce--> Kafka --consume--> Core --> Postgres
  40,003/s      4 msgs/record      LAG growing         |
                ~994 B/record                          '- the constraint

 service time  p50 29.4 ms | mean 30.0 ms | min 23.6 ms | max 54.5 ms
 model         4 messages / 0.030 s  =  133 msg/s
 measured      ~130 events/s
```

The model reproduces the measurement, so the mechanism is understood: one consumer thread, roughly four messages per record, about 30 ms per dispatch.

The four-messages-per-record figure is a *byte* cap, not a count cap.
At around 248 bytes per message on the wire, five messages would exceed the observed 1069-byte maximum record size.

**This is one topology's ceiling.**
A single Minion and a 4-vCPU core with a single-partition sink is not a tuned production deployment, and the manifest has to say so as plainly as the number does.

## Related

- [Runbooks](./loadtest-runbooks.md) for the scenario mechanics each run is built from
- [Scenarios](./loadtest-scenarios.md) for the lifecycle and fidelity mode
- [Report schema](./loadtest-report-schema.md) for what nl6 reports about its own side of the measurement
