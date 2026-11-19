---
sidebar_label: "Test a collector in CI"
description: "Use nl6 as a CI fixture: devices send to your collector, and the pipeline fails when your tool processed fewer records than the devices sent."
---

# Test a collector in CI

Add `nl6-ci` steps to a pipeline and a pull request to your collector meets device-shaped traffic before it merges.
nl6 states exactly what the simulated devices sent.
Your tool states what it processed correctly.
`nl6-ci check` compares the two counts per device and fails on any difference.

A red run means the change would have lost or mishandled data from a real device.
A green run means every record the devices sent was processed.
The fixture compares counts only.
Whether a decoded record is right stays with your tool.

The command and its flags are in the [nl6-ci reference](../reference/nl6-ci.md).
The first version supports Debian and Ubuntu runners on amd64.

## Check the runner

| Runner | Works | Needs | Evidence |
| --- | --- | --- | --- |
| GitHub-hosted Ubuntu | yes | nothing | Tested on `ubuntu-24.04` with nl6 v0.40.2: install, start, two devices, SNMP poll and IPFIX receive. The interop gate for `nl6-ci` itself is configured for `ubuntu-26.04`. |
| Forgejo runner, Docker mode, `container.privileged: true` | yes | `container.privileged: true` in the runner config | Tested. |
| Forgejo runner, Docker mode, default config | no | | Tested. The job container lacks `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` and `/dev/net/tun`. Per-job `container.options` are dropped while `privileged` is false. `nl6-ci preflight` reports it. |
| Forgejo runner, LXC or host mode | unknown | | Untested. |

To check a runner, run `sudo nl6-ci preflight` on it.
It names each missing privilege and what to change.
Without root it prints the `root` finding and skips the capability checks, so it says nothing about the runner.
The checks are listed in the [reference](../reference/nl6-ci.md#preflight-checks).

## Write the pipeline

The steps are: start the fixture, start your tool, run a window, write the received counts, compare.

```yaml
steps:
  - uses: actions/checkout@<sha>  # vX.Y.Z

  - uses: labmonkeys-space/nl6-action@<sha>  # vX.Y.Z
    with:
      command: up
      manifest: test/e2e/devices.json

  - run: make e2e-start        # your tool, listening on 10.254.0.1:4739

  - uses: labmonkeys-space/nl6-action@<sha>  # vX.Y.Z
    with:
      command: run
      protocol: ipfix
      rate: 5
      window: 30s

  - run: make e2e-received     # your code writes received.csv

  - uses: labmonkeys-space/nl6-action@<sha>  # vX.Y.Z
    with:
      command: check
      received: received.csv   # tolerance defaults to 0
```

The action follows in its own repository, `labmonkeys-space/nl6-action`.
Replace the `<sha>` and `vX.Y.Z` placeholders with a commit SHA and its release version when it is published.
On Forgejo the `uses:` line carries the full URL of the action repository.
Add `tolerance: 0.01` to the last step for a load test that allows 1% loss per device.

The action wraps the verbs of `nl6-ci`.
A project that calls only make targets from CI can use the action for `up` and call `nl6-ci run` and `nl6-ci check` from its own Makefile.

### Write the device manifest

The manifest is a JSON array of batches.
Each batch needs `start_ip` and `device_count` and names the collector.
This one creates two IPFIX devices that send to `10.254.0.1:4739`:

```json
[
  {
    "start_ip": "10.42.0.1",
    "device_count": 2,
    "flow": {"collector": "10.254.0.1:4739", "protocol": "ipfix"}
  }
]
```

The other fields of a batch are in the [web API](../reference/web-api.md).
A syslog fleet uses `"syslog": {"collector": "10.254.0.1:5514"}` instead of `flow`.

### Set a rate that a flow device can reach

Flow protocols have a per-device rate ceiling.
A `rate` above it excludes every device at arm, and `run` fails and prints the reason.
The example uses `rate: 5`.
The figures and the effect of a longer tick are in [Choose participant cardinality and rate](./loadtest-scenarios.md#choose-participant-cardinality-and-rate).

## Listen where the devices can reach your tool

Your tool must listen on `10.254.0.1` or on `0.0.0.0`.
`10.254.0.1` is the host end of the link to the simulated devices.
It exists only after `up`, so start a tool that binds to it after `up`.

A tool that runs as a separate container must share the network of the job.
On a GitHub runner, use host networking.

## Write the received counts

The step after the window writes a CSV with one row per device.
The counts below are examples:

```text
protocol,source_ip,collector,received
ipfix,10.42.0.1,10.254.0.1:4739,150
ipfix,10.42.0.2,10.254.0.1:4739,150
```

- `protocol` is the protocol you passed to `run`.
- `source_ip` is the device address from the manifest.
- `collector` is the collector address from the manifest.
- `received` is the number of records your tool counts as correctly processed.

Where the number comes from is up to your tool: a Kafka count, a database query or a metrics scrape.
Wait until the tool has drained its input before you write the file.
`check` treats any shortfall as loss, so a count taken while records are still queued fails the run.

## Run the same steps on a lab host

Install the nl6 package, then run the verbs.
`up` needs root, so call it with `sudo`.
`up` hands the state directory to your user, so `run` and `check` run without root.
`down` stops nl6, which runs as root, so it needs `sudo` too.

```bash
cd "$(mktemp -d)"
cat > devices.json <<'EOF'
[{"start_ip": "10.42.0.1", "device_count": 4, "syslog": {"collector": "10.254.0.1:5514"}}]
EOF
sudo nl6-ci up -manifest devices.json
```

Expected output:

```text
up: 4 devices, api http://127.0.0.1:18080, state .nl6-ci
```

Start your tool on `10.254.0.1:5514` or `0.0.0.0:5514`, then run a window:

```bash
nl6-ci run -protocol syslog -rate 5 -window 10s
```

Expected output, where `<n>` is the number of records sent:

```text
run: sent <n> records from 4 devices, report .nl6-ci/report.json
```

Write `received.csv` from your tool, then compare:

```bash
nl6-ci check -received received.csv
```

`check` prints one row per device with sent, received and delta, and exits 0 when every row matches.
It exits 1 and names the devices that differ otherwise.
Stop the fixture when you are done:

```bash
sudo nl6-ci down -log-tail
```

Expected output ends with:

```text
down: stopped pid <pid>
```

`down` waits up to 90 seconds for nl6 to exit.
When nl6 does not exit in time, `down` kills it and exits 1.
A killed nl6 leaves its network namespace behind, so run `sudo ip netns delete nl6sim` before the next `up`.
When you forget `sudo`, `down` exits 1 and keeps `.nl6-ci/state.json`.
Run `sudo nl6-ci down` again.

`down` keeps `.nl6-ci/nl6.log` and `.nl6-ci/report.json`.
Upload them as pipeline artifacts when a run fails.

Without `sudo`, for example in a root login or a root container such as a privileged Forgejo job container, every verb runs as root and ownership does not matter.
Drop `sudo` from the commands.

## Fix a failed run

| Symptom | Cause | Fix |
| --- | --- | --- |
| `up` prints `preflight failed: ...` | The runner lacks a privilege. | Apply the fix in the message. On Forgejo, set `container.privileged: true` in the runner config. |
| `up` prints `an nl6 instance already runs on this host` | Another nl6 answers on the API port. | Stop it. One fixture runs per host. |
| `up` prints `found a leftover network namespace nl6sim` | A crashed or killed nl6 left its namespace behind, or another nl6 uses another port. | If no other nl6 runs, remove it with `sudo ip netns delete nl6sim`. |
| `run` prints `excluded <device>: ...` | The rate is above the device's ceiling. | Lower `rate`. See [the ceiling](#set-a-rate-that-a-flow-device-can-reach). |
| `run` prints `device <ip> sent nothing` | The device is faulty, or the window is shorter than its export interval. | For gNMI dial-out and flow protocols, use a window of at least 30 seconds. Else read `nl6.log`. |
| `run` prints `nothing was sent` | No device sent a record. | Read `nl6.log` in the state directory. |
| `check` prints `report <path> is refused` | `run` failed, and the pipeline ran `check` anyway. | Fix the `run` step first. `check` never passes a report that `run` refused. |
| `check` prints `the report is not from this fixture` | `-report` names a report that is left from an earlier fixture, and no `run` wrote a new one. | Run `nl6-ci run` before `check`. |
| `sudo nl6-ci down` prints `down: nothing running` while nl6 runs | `sudo` dropped `$NL6_CI_STATE`, so `down` looks in `./.nl6-ci`. | Pass `-state <dir>` to every verb. |
| `down` prints `no permission to stop nl6` | `down` ran without `sudo`. | Run `sudo nl6-ci down`. |
| `check` flags every row with `LOSS` | The tool had not drained its input, or it did not listen on `10.254.0.1` or `0.0.0.0`. | Wait for the drain before writing the CSV. Check the listen address. |
| `check` flags one row | One device lost records, or the tolerance is lower than its loss. | Read the delta for that `source_ip`. Raise `tolerance` only for a load test. |
