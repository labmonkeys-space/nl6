# Load-test scenarios

The load-test scenario subsystem is a **telemetry-fidelity instrument**. You arm
a bounded experiment over a set of simulated devices, run it for a fixed window,
and get back an exact, machine-readable [report](./loadtest-report-schema.md) of
what nl6 **sent**. Diff that sent-ledger against what your monitor **received**
and any delta localizes missed *or* duplicated telemetry — fidelity in both
directions.

nl6 owns the ground truth: its send count is exact and, with a fixed `seed`,
reproducible. So the report is the **authority** — a shortfall is real
wire/collector loss, not measurement noise.

## The idea

```
      arm                    run [T0,T1)                 stop
 connect, stay silent   →   gated push only        →   finalize report
      │                          │                          │
 nothing on the wire      exactly what nl6            immutable sent-ledger
 (measurement pre-roll)   emits, counted at send      you diff vs received
```

- **Bounded window.** A scenario suppresses background telemetry for its
  participants, emits only during `[T0,T1)`, then finalizes an immutable report.
- **A sent-ledger, not a guess.** Every record is counted at the send site into
  exactly one bucket (`in_window` / `drain` / `send_failures` / `dropped` /
  `suppressed_pre_window`); `sent = in_window + drain` is the reconciliation
  denominator.
- **Seven protocols, one shape.** Any one of **syslog · SNMP trap/inform ·
  NetFlow v5/v9 · IPFIX · sFlow · gNMI dial-out** — one active scenario at a
  time. Each device opts in via its own export config; the scenario gates
  whichever protocol it targets.
- **Localize, don't just total.** The report splits in-window sends into equal
  time sub-windows (loss localization) and tags each run per protocol so you can
  isolate it on a shared collector.

## Where to go next

| Page | What it covers |
|------|----------------|
| [REST API](./loadtest-api.md) | Every endpoint, request/response shape, and error code. |
| [Scenarios](./loadtest-scenarios.md) | The operating guide — lifecycle, fidelity mode, run tagging, reconciliation, troubleshooting. |
| [Runbooks](./loadtest-runbooks.md) | Copy-pasteable worked recipes, one per use case. |
| [Report schema](./loadtest-report-schema.md) | Every field, the ledger identity, loss localization, and the semver policy. |

New to it? Walk the [lifecycle](./loadtest-scenarios.md#run-a-fidelity-check),
then pick a matching [runbook](./loadtest-runbooks.md). There is a runnable
end-to-end example under `examples/scenario-syslog-fidelity/` — a compose stack
(nl6 + a counting collector) and a `run.sh` that reproduces a documented known
result.

## Limits

- **One active scenario at a time**.
- **In-memory only** — a scenario, its ledger, and its report do not survive a
  restart; fetch the report before restarting. See
  [Scenarios → Non-goal](./loadtest-scenarios.md#non-goal-scenarios-are-in-memory).
