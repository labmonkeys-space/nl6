---
sidebar_label: "nl6-ci"
description: "The nl6-ci command: its five verbs, flags and defaults, the state directory, exit codes and the preflight checks."
---

# nl6-ci

`nl6-ci` drives nl6 as a test fixture in a CI pipeline or on a lab host.
It starts nl6, creates devices from a manifest, runs one scenario window and compares what the devices sent with what your tool received.
For a worked pipeline, see [Test a collector in CI](../ops/ci-fixture.md).

## Synopsis

```text
nl6-ci [-state <dir>] <verb> [verb flags]
nl6-ci -version
```

The global flags go before the verb.
`nl6-ci` ships in the nl6 `.deb` and `.rpm` as **`/usr/bin/nl6-ci`**, next to **`nl6-reconcile`**.

| Global flag | Type | Default | Description |
| --- | --- | --- | --- |
| **`-state`** | string | `$NL6_CI_STATE`, else `./.nl6-ci` | State directory shared by all verbs. `sudo` drops the variable, see [State directory](#state-directory). |
| **`-version`** | bool | `false` | Print the `nl6-ci` version and exit 0. |

## Verbs

| Verb | What it does |
| --- | --- |
| [`preflight`](#preflight) | Check that this runner can run nl6. |
| [`up`](#up) | Start nl6 and create the devices. |
| [`run`](#run) | Drive one scenario window and save the report. |
| [`check`](#check) | Compare sent with received. |
| [`down`](#down) | Stop nl6. |

### preflight

```bash
sudo nl6-ci preflight
```

`preflight` has no flags.
It prints `preflight: ok` to stdout and exits 0 when every check passes.
Otherwise it prints one line per failed check to stderr and exits 1:

```text
preflight: FAIL <id>: <problem>. Fix: <fix>
```

`up` runs the same checks and refuses to start when one fails.

#### Preflight checks

| ID | Problem | Fix |
| --- | --- | --- |
| `linux` | nl6 needs Linux, this is `<GOOS>`. | Run the job on a Linux runner. |
| `root` | `nl6-ci up` must run as root. | Call it with `sudo`. |
| `caps` | The capability set could not be read: `<error>`. | Check that `/proc` is mounted and readable. |
| `cap_net_admin` | `CAP_NET_ADMIN` is missing. | Forgejo runner in Docker mode: set `container.privileged: true` in the runner config. `docker run`: add `--cap-add NET_ADMIN`. |
| `cap_sys_admin` | `CAP_SYS_ADMIN` is missing. | Forgejo runner in Docker mode: set `container.privileged: true` in the runner config. `docker run`: add `--cap-add SYS_ADMIN`. |
| `tun` | `/dev/net/tun` cannot be opened: `<error>`. | Forgejo runner in Docker mode: set `container.privileged: true`. `docker run`: add `--device /dev/net/tun`. |
| `ip` | The `ip` command is missing. | Install the `iproute2` package. |

On a system that is not Linux, `preflight` reports only `linux` and stops.
Without root, `preflight` reports `root` and skips the capability checks.
A process that is not root holds no capabilities, whatever the runner grants root.
The `caps` check replaces `cap_net_admin` and `cap_sys_admin` when the capability set cannot be read.
`preflight` opens `/dev/net/tun` to test it and never creates the node.

### up

```bash
sudo nl6-ci up -manifest <file> [-port 18080] [-nl6 /usr/bin/nl6] [-workdir /usr/share/nl6] [-create-timeout 5m] [-- <nl6 flags>]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| **`-manifest`** | path | required | Device manifest. A JSON array of batches. |
| **`-port`** | int | `18080` | nl6 API port. From 1 to 65535. |
| **`-nl6`** | path | `/usr/bin/nl6` | The nl6 binary itself, not a wrapper script. |
| **`-create-timeout`** | duration | `5m` | Budget for creating all devices. Above 0. Raise it for a fleet that needs longer. |
| **`-workdir`** | path | `/usr/share/nl6` | Directory that holds `resources/`, `web/` and `worldcities/`. nl6 starts there. |
| `-- <nl6 flags>` | flags | none | Everything after `--` is passed to nl6 unchanged. An argument that is not a flag of `up` and comes before `--` is a usage error. |

Each batch in the manifest needs **`start_ip`** and a **`device_count`** above 0.
`up` posts each batch to `POST /api/v1/devices`, so the other fields follow the [web API](./web-api.md).
The export block of a batch names the collector, for example `"syslog": {"collector": "10.254.0.1:5514"}` or `"flow": {"collector": "10.254.0.1:4739", "protocol": "ipfix"}`.

`up` does this, in order:

1. Refuses to start when a fixture in the state directory is alive.
   Deletes a stale `state.json` and an earlier `report.json` there.
2. Reads the manifest and counts the devices it declares.
3. Refuses to start in any of the other cases in the table below.
4. Runs the [preflight checks](#preflight-checks).
5. Creates the state directory and starts nl6 detached with `-port <port> -fidelity` and the flags after `--`.
   Output goes to a new **`nl6.log`**, which replaces the log of an earlier fixture.
   A relative `-nl6` path is resolved in the directory `up` runs in, not in `-workdir`.
   The pid and its start time go to **`state.json`** at once, so `down` can stop nl6 when `up` is interrupted.
6. Waits up to 60 seconds for the API.
7. Creates the devices and waits for creation to finish.
   All batches and the wait share one budget, **`-create-timeout`**.
8. Fails unless the created count equals the declared count.
9. Writes the device count to **`state.json`** and prints `up: <n> devices, api http://127.0.0.1:<port>, state <dir>`.

On any failure after nl6 started, `up` stops nl6, deletes `state.json`, prints the last 40 lines of `nl6.log` and exits 1.
When nl6 does not stop within 90 seconds, `up` kills it with SIGKILL and prints `up: nl6 (pid <pid>) did not stop in time and was killed`.
A killed nl6 leaves its network namespace behind, so `up` removes it and adds `Its network namespace nl6sim was removed` to that line.
When that fails, the line ends with `remove it with: sudo ip netns delete nl6sim`.
Do that before the next `up`.
An nl6 that exits by itself during `up`, for example on an API port it cannot bind, leaves its network namespace behind too.
`up` removes it and prints `up: nl6 (pid <pid>) left its network namespace behind`, followed by one of the same two endings.
When a wait runs out, the message reads `not ready after <budget>: <last error>`.
The last error is the one the API returned on the final poll, when there was one.

| Refusal | Message starts with | Recovery |
| --- | --- | --- |
| A fixture in this state directory is alive. | `nl6 already running (pid <pid>, state dir <dir>)` | Run `sudo nl6-ci down`. |
| The API port answers. | `an nl6 instance already runs on this host` | Stop the other nl6 instance or pick another `-port`. |
| The `nl6sim` network namespace exists and the API port does not answer. | `found a leftover network namespace nl6sim` | If no other nl6 runs on this host, remove it with `sudo ip netns delete nl6sim`. |
| A preflight check fails. | `preflight failed:` | Apply the fix in the message. |
| `-workdir` is missing or not a directory. | `start nl6: -workdir` | Pass the directory that holds `resources/`. |
| `-nl6` names a script. | `start nl6: -nl6 <path> is a script` | Pass the nl6 binary itself. |

A script keeps the pid while nl6 runs as its child, so `down` would stop the script and leave nl6.
The `nl6` of the Nix package is such a script, which starts `.nl6-wrapped`.
`up` also fails when the started process runs under another command name than the `-nl6` path.
The message reads `pid <pid> does not run as "<name>"`.
A compiled wrapper that starts nl6 under another name does that.
`down` identifies nl6 by that name, so `up` stops the process and exits 1.

When `state.json` names a process that is dead, `up` prints `up: replacing stale state for dead pid <pid> in <dir>` and continues.
When the pid now belongs to another process, `up` prints `up: replacing stale state in <dir>, pid <pid> now belongs to another process` and continues.
In both cases `up` deletes the stale `state.json` at once, so a later refusal does not leave it behind.
`up` judges the pid as [`down`](#down) does.

Once it knows that no fixture is alive in the state directory, `up` deletes a `report.json` there.
That report is from an earlier fixture.
This happens before the manifest is read, so an `up` that fails on its manifest removes the report too.
A report at another `-report` path stays, and `check` refuses it by its window start while `state.json` exists.

`up` needs root.
Run it as `sudo nl6-ci up`.
When `SUDO_UID` and `SUDO_GID` are set, `up` hands the state directory, `state.json` and `nl6.log` to the user who called `sudo`.
The other verbs then run without root and write `report.json` there.
The directory and `nl6.log` change hands as soon as nl6 has started, so an interrupted or failed `up` leaves nothing that only root can remove.
`state.json` follows at the end of `up`.
Missing parent directories that `up` created change hands as well.
A state directory that an earlier run left changes hands too: it holds `nl6.log`, `report.json` or `state.json` and nothing else.
Any other directory that existed before `up` keeps its owner, and `up` prints `up: <dir> was not made by nl6-ci and keeps its owner`.
That covers a shared directory such as `/tmp` and an empty directory.
Only `state.json` and `nl6.log` change hands then, and `run` needs a `-report` path it can write to.
Without `sudo`, for example in a root login or a root container, every verb runs as root and ownership does not matter.

As root, every verb reads `state.json` only when root or the user who called `sudo` owns it.
Root signals the pid and prints the log that the file names, so a file that another user planted in a shared directory must not steer it.
The verb exits 1 with `load state <path>: the file belongs to uid <uid>, not to root or the sudo caller. Remove it if no nl6-ci up wrote it`.
No verb follows a symlink at the `state.json` path.

### run

```bash
nl6-ci run -protocol <protocol> -rate <n> -window <duration> [-seed <n>] [-report <path>] [-request-timeout 10s]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| **`-protocol`** | string | required | Push protocol: `syslog`, `snmp-trap`, `netflow5`, `netflow9`, `ipfix`, `sflow` or `gnmi-dialout`. |
| **`-rate`** | float | required | Events per second per device. A finite number above 0. |
| **`-window`** | duration | required | Measurement window as a Go duration, for example `30s`. Above 0. |
| **`-seed`** | int | `0` | Seed of the scenario's random draws. Runs with the same seed draw the same values. |
| **`-report`** | path | `<state dir>/report.json` | Where to save the report. |
| **`-request-timeout`** | duration | `10s` | Budget of one API call: list devices, submit, arm, start and status. Above 0. Raise it for a fleet that takes longer to arm. |

`run` takes every device the fixture created as a participant and sets `expect_participants` to that count.
It deletes an existing report first, so a failed `run` never leaves the report of an earlier run for `check`.
It then writes and removes an empty file at the report path, so a path it cannot write fails before the window.
It fails before it submits when the number of devices nl6 lists differs from the number `up` created.
It submits, arms and starts the scenario, then waits for the window plus 60 seconds of grace.
A status call that fails while nl6 still runs does not end the run.
`run` polls on until the window and the grace are over.
When nl6 is gone, `run` fails at once.
When it gives up on the window and nl6 still answers, it asks nl6 to stop the scenario, so the devices are free for the next `run`.
When the last status call failed, `run` sends no stop and fails at once.
nl6 reports `stopped` when the window closes and hands out the report once it has finalized the scenario.
`run` waits up to 75 seconds for that report, or **`-request-timeout`** when that is longer.
It saves the report and prints `run: sent <n> records from <m> devices, report <path>`.
`run` saves the report before it verifies it.
A report that fails the checks below stays on disk for diagnosis, and `check` refuses it.

`run` exits 1 in these cases:

| Case | Message |
| --- | --- |
| No `state.json`. | `no running fixture, run nl6-ci up first` |
| The report path cannot be written. | `the report path is not writable: <error>` |
| nl6 lists another number of devices than `up` created. | `the fixture has <n> devices, up created <m>` |
| Arm excluded a device. | `run: excluded <device>: <reason>. <hint>` per device, then `<n> of <m> devices were excluded from scenario <id>` |
| The scenario did not reach `stopped` in time, nl6 did not answer in time, or nl6 is gone. | `nl6 did not finish the window: <why>`, after the last 40 lines of `nl6.log` |
| The scenario aborted. | `scenario aborted` |
| nl6 ran out of its finalize budget, so the report carries `drain_stragglers` or `incomplete_joins`. | `nl6 cut its finalize short (drain_stragglers <n>, incomplete_joins [<names>]), so the counters are a lower bound. Run nl6-ci run again` |
| Another number of devices took part than the fixture created. | `<n> devices took part, the fixture has <m>` |
| The report's `sent` total is 0. | `nothing was sent` |
| The report has no counter rows. | `the report has no counters` |
| One device sent 0. | `device <ip> sent nothing. Either the device is faulty, or the window is shorter than its export interval` |

A healthy device sends 0 when the window is shorter than its own export interval.
gNMI dial-out samples every 10 seconds by default and ignores `-rate`.
A flow exporter ticks every 5 seconds by default.
Pick a window of several intervals for these protocols.

A flow protocol has a per-device rate ceiling.
A higher `-rate` excludes every device at arm.
See [the ceiling](../ops/loadtest-scenarios.md#choose-participant-cardinality-and-rate) for the figures.

### check

```bash
nl6-ci check -received <csv> [-report <path>] [-tolerance <ratio>]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| **`-received`** | path | required | CSV of received counts. Columns `protocol,source_ip,collector,received`. |
| **`-report`** | path | `<state dir>/report.json` | The JSON report `run` saved. |
| **`-tolerance`** | float | `0` | Loss ratio allowed per device. `0.01` is 1%. A finite number of 0 or above. |

`check` takes only the JSON report that `run` writes.
It never runs `nl6-reconcile` on a report it has not verified.
This stops a pipeline from passing on zero sent and zero received after a failed `run`.

| Report | Exit | Message |
| --- | --- | --- |
| Missing or unreadable. | 2 | `cannot read report <path>: <error>. Run nl6-ci run first` |
| Not JSON, for example the CSV projection of a report, an empty file or a broken file. | 2 | `report <path> is not JSON. check needs the JSON report that nl6-ci run writes. Call nl6-reconcile directly for other inputs, such as the CSV projection` |
| JSON with a field of the wrong type, for example a negative or a quoted `sent`. | 1 | `report <path> is refused: not an nl6 scenario report: <decode error>` |
| JSON without the report fields, for example `{}` or `null`. | 1 | `report <path> is refused: report phase is "", want stopped` |
| A scenario report that fails the checks below. | 1 | `report <path> is refused: <reason>` |

`check` verifies the report with the same checks as `run`.
The report phase must be `stopped`, the `sent` total above 0 and every device's `sent` above 0.
The report must hold at least one counter row.
A report with `drain_stragglers` or `incomplete_joins` is refused, because nl6 took it while sends were still moving ([drain barrier](./loadtest-report-schema.md#the-drain-barrier-is-bounded)).
When `state.json` exists, the number of devices that took part must also equal the number `up` created.
The window must also have started after `up` started nl6.
A report that an earlier fixture left behind is refused with `the report is not from this fixture`, whatever `-report` names.
After `down` there is no `state.json`, and these two checks are skipped.
The default `report.json` is then still from this fixture, because `up` deleted the earlier one.
A report at another `-report` path has no such guard after `down`.
To reconcile the CSV projection of a report, call `nl6-reconcile` directly.
It has no guard against a report that sent nothing.

Only a report that passed these checks reaches `nl6-reconcile`.
`check` then runs `nl6-reconcile -report <report> -received <csv> -tolerance <ratio> -drained`.
It finds `nl6-reconcile` through `PATH`.
`-drained` is always set, so any shortfall reads as loss.
The tolerance applies to each `(protocol, source_ip, collector)` row, not to the fleet total.
A row that exceeds it fails the check even when the fleet average stays inside it.

`check` then exits with the exit code of `nl6-reconcile`: 0 when every row is `OK`, 1 when any row is flagged.
`nl6-reconcile` exits 2 when the `-received` file is missing, unreadable or malformed.
`nl6-ci check` then exits 2 too.
`check` itself exits 2 for a `-tolerance` that is negative, `NaN` or infinite, before it reads the report.
It prints the `nl6-reconcile` table, which shows sent, received and delta per device.
It also exits 1 when it cannot run `nl6-reconcile` at all, or when a signal stops `nl6-reconcile`.
See [Reconcile with nl6-reconcile](../ops/loadtest-scenarios.md#reconcile-with-nl6-reconcile) for the table and its statuses.

### down

```bash
sudo nl6-ci down [-log-tail]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| **`-log-tail`** | bool | `false` | Print the last 40 lines of `nl6.log` before stopping. |

`down` needs root, because nl6 runs as root.
It sends SIGTERM to nl6, waits up to 90 seconds for it to exit and deletes `state.json`.
nl6 acts on one signal only, so `down` sends SIGKILL to an nl6 that still runs after that time.
nl6 usually exits within a few seconds.
It takes longer when a scenario still runs or when a gNMI client is still connected.
It leaves `nl6.log` and `report.json` in place, so a pipeline can upload them.

Before it sends a signal, `down` reads `/proc/<pid>/stat` for the pid in `state.json`.
A pid that is gone or a zombie counts as stopped.
A pid that now belongs to another process is never signalled.
`down` tells by the command name and by the start time `up` recorded.
The start time catches another nl6 that got the pid, such as the packaged `nl6.service`.

| Case | Output | Exit | `state.json` |
| --- | --- | --- | --- |
| nl6 stopped within 90 seconds. | `down: stopped pid <pid>` | 0 | Deleted. |
| No `state.json`. | `down: nothing running` | 0 | None. |
| The pid is gone or a zombie, or nl6 exits before the signal arrives. | `down: nl6 (pid <pid>) was not running, removed stale state` | 0 | Deleted. |
| The pid belongs to another process. | `down: pid <pid> is not nl6 any more, removed stale state` | 0 | Deleted. |
| The caller may not signal nl6. | `no permission to stop nl6 (pid <pid>), call it with sudo: sudo nl6-ci down. state.json is kept` | 1 | Kept. |
| nl6 still runs after 90 seconds and is killed. | `nl6 (pid <pid>) did not stop in time and was killed. Its network namespace nl6sim was removed` | 1 | Deleted. |

A killed nl6 cannot remove its network namespace, so `down` removes it.
When that fails, the message ends with `remove it with: sudo ip netns delete nl6sim`.
An nl6 that crashed before `down` leaves its namespace behind too.
`down` did not end that nl6, so it leaves the namespace and prints `down: the network namespace nl6sim still exists`, followed by the command that removes it.
The next `up` refuses to start while the namespace exists.
With `state.json` kept, run `sudo nl6-ci down` again once the cause is fixed.

## State directory

The directory is **`-state`**, else **`$NL6_CI_STATE`**, else **`./.nl6-ci`** in the working directory.
Pass the same directory to every verb.

`sudo` drops `$NL6_CI_STATE` by default.
`sudo nl6-ci up` then uses `./.nl6-ci` while `run` and `check` use the variable, and `sudo nl6-ci down` prints `down: nothing running`.
Pass **`-state`** to every verb, or call `sudo --preserve-env=NL6_CI_STATE nl6-ci up` and the same for `down`.

| File | Written by | Contents |
| --- | --- | --- |
| **`state.json`** | `up` | `pid`, `start_ticks`, `api`, `log`, `devices`, the `nl6` binary path and the `started` time of the running fixture. `log` is an absolute path. `start_ticks` is the start time of the pid from `/proc/<pid>/stat`. `up` replaces the file with a rename, so it is never half written. `down` deletes it. |
| **`nl6.log`** | `up` | Output of nl6. |
| **`report.json`** | `run` | The scenario report. Its schema is in the [report schema](./loadtest-report-schema.md). |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The verb succeeded. |
| 1 | The verb ran and failed: a preflight finding, a refusal, a failed run, a flagged row or an error. |
| 2 | Usage error: an unknown verb, a missing required flag, a flag that does not parse, a flag value out of range or an argument left after the flags. Also from `check`, when the report is missing, unreadable or not JSON, or when `nl6-reconcile` cannot read or parse the received CSV. |
