# SNMP trap / INFORM export (operator guide)

nl6 can emit SNMPv2c notifications — both fire-and-forget **TRAP**s (PDU
`0xA7`) and acknowledged **INFORM**s (PDU `0xA6`) — from every simulated device
to a single collector such as `snmptrapd` or an NMS trap daemon. Each device
generates its own notifications with its own IP as the UDP source, so
collectors that key on the agent source IP attribute correctly without extra
work.

This page is the operator-facing setup guide. For the CLI flags see
[CLI flags → SNMP trap / INFORM export](../reference/cli-flags.md#snmp-trap--inform-export-flags);
for wire format, catalog JSON, and HTTP endpoints see
[SNMP trap reference](../reference/snmp-traps.md).

## Enabling trap export

The feature is off by default. Pass `-trap-collector <host:port>` to enable
it; the other eight flags have sensible defaults for common trap collectors.

```bash
# 100 devices firing a random catalog trap every ~30s (Poisson-distributed)
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -trap-collector 192.168.1.10:162

# Tighter interval + global rate cap (≤ 200 trap packets/s across all devices)
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 1000 \
  -trap-collector 192.168.1.10:162 \
  -trap-interval 5s -trap-global-cap 200

# INFORM mode — requires per-device source binding (the default)
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -trap-collector 192.168.1.10:162 -trap-mode inform \
  -trap-inform-timeout 3s -trap-inform-retries 1

# Custom catalog
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -trap-collector 192.168.1.10:162 \
  -trap-catalog /etc/nl6/my-traps.json
```

## TRAP vs INFORM

| Mode | PDU tag | Delivery | Collector ack | Retries | Best for |
|------|---------|----------|---------------|---------|----------|
| `trap` (default) | `0xA7` | Fire-and-forget | None | n/a | Sustained load testing at high rates. Simplest to reason about. |
| `inform` | `0xA6` | Acknowledged | GetResponse-PDU (`0xA2`) | `-trap-inform-retries` (default 2) | Exercising the collector's ack path and retry semantics. |

**INFORM requires `-trap-source-per-device=true`** (the default). The
simulator uses each device's per-device UDP socket to demultiplex ack
traffic back to the originating device — there is no single shared
request-id table. If you explicitly set `-trap-source-per-device=false`
while in INFORM mode, startup fails with a clear error.

## Pending informs and retries

Each device keeps up to **100 outstanding INFORMs** waiting for a collector
ack. On overflow, the oldest pending entry is dropped (and counted as
`informs_dropped` in `/api/v1/traps/status`). This bounds memory when the
collector is unreachable.

When the collector ack doesn't arrive within `-trap-inform-timeout`
(default 5s), the simulator retransmits the INFORM up to
`-trap-inform-retries` times (default 2). **Retransmissions consume global
rate-cap tokens** — by design, so a collector outage can't amplify wire
traffic via retry storms. After all retries expire without ack, the
pending entry is removed and counted as `informs_failed`.

## Rate cap and scheduling

Per-device firing follows a **Poisson process** with mean
`-trap-interval` (default 30s) rather than fixed periodic ticks — each
device draws an exponential inter-arrival offset after every fire.
Naïve periodic scheduling causes synchronised-burst artefacts at tick
boundaries that stress the collector's ingest queue without reflecting
real-world trap shapes. Poisson produces the clustered-but-not-synchronous
pattern that misbehaving device fleets actually look like.

`-trap-global-cap <tps>` adds a hard ceiling across all devices. Sizing
guidance:

- **Steady-state estimate:** `devices / trap_interval_seconds`.
  30,000 devices at `-trap-interval 30s` ≈ 1000 tps average.
- **Under-cap deliberately** to leave headroom for INFORM retransmissions
  and for any on-demand fires you inject through the HTTP endpoint.
- `-trap-global-cap 0` (the default) means unlimited.

## Prerequisites inherited from flow export

Per-device source IP binding reuses the same `nl6sim` network namespace
plumbing as flow export — no new `iptables` rules and no new netns setup.
In TRAP mode, a per-device bind failure for any device is survivable: the
simulator logs a warning and that device falls back to the shared UDP
socket (its traps arrive at the collector with the simulator host's IP as
the source). In INFORM mode, the same failure is fatal for that device —
no ack demux without a per-device socket. The same three conditions apply:

- **`iptables FORWARD` rule.** At startup the simulator inserts
  `FORWARD -i veth-sim-host -j ACCEPT` so Docker-present hosts (which
  default FORWARD to drop) allow per-device egress. Walkthrough:
  [Flow export → Prerequisites](flow-export.md#prerequisites-for-per-device-source-ip).
- **Route to the collector from inside the namespace.** Same default route
  via `veth-sim-host` (`10.254.0.1`); if you've customised host routing,
  verify with `sudo ip netns exec nl6sim ip route get <collector-ip>`.
- **Collector-side `rp_filter`.** Reverse-path filtering on the collector
  host may drop UDP/162 packets whose source IP (`10.0.0.x`, `10.42.0.x`,
  whatever subnet your devices live in) isn't reachable back through the
  receiving interface. Loose mode fixes it:
  ```bash
  sudo sysctl -w net.ipv4.conf.all.rp_filter=2
  sudo sysctl -w net.ipv4.conf.<iface>.rp_filter=2
  ```

## Smoke test with snmptrapd

The simplest end-to-end check uses `snmptrapd` in foreground mode with
formatted logging to stdout:

```bash
# In one terminal — log every received trap to stdout
sudo snmptrapd -f -Of -Lo -c /etc/snmp/snmptrapd.conf 162

# In another terminal — point the simulator at it
sudo ./nl6 -auto-start-ip 127.0.0.1 -auto-count 5 \
  -trap-collector 127.0.0.1:162 -trap-interval 2s
```

You should see lines arriving every few seconds tagged with the simulated
device IP as the sender and an OID from the universal catalog
(`linkDown` / `linkUp` dominate; `coldStart` / `warmStart` /
`authenticationFailure` appear less often).

For vendor-flavoured content (e.g., Cisco `ciscoConfigManEvent` or
Juniper `jnxPowerSupplyFailure`), select a device type with a per-type
overlay — see
[SNMP trap reference → Per-type catalog overlays](../reference/snmp-traps.md#per-type-catalog-overlays).
`cisco_ios` devices fire from 12 merged entries (universal 5 + 7 Cisco),
`juniper_mx240` devices fire from a comparable 12-entry Juniper set.

If you need it sooner on demand:

```bash
# Fire a specific trap immediately via the HTTP API
curl -X POST http://localhost:8080/api/v1/devices/127.0.0.1/trap \
  -H "Content-Type: application/json" \
  -d '{"name":"linkDown","varbindOverrides":{"IfIndex":"3"}}'
```

See [Web API → Fire a trap on demand](../reference/web-api.md#fire-a-trap-on-demand)
for the full request / response shape.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `enabled: false` in `/api/v1/traps/status` | `-trap-collector` not set | Pass the flag; verify port |
| `enabled: true`, `sent` is 0 | Scheduler idle (no devices yet) | Wait for device creation to finish |
| Traps sent but collector sees nothing | FORWARD rule missing or `rp_filter` blocking | See [Flow export → Flow troubleshooting](flow-export.md#flow-troubleshooting) — the netns diagnostic steps apply verbatim |
| Source IP on the wire is the host, not the device | Per-device bind failed for that device | Check simulator logs for `per-device bind failed`. TRAP mode falls back to shared socket with a warning; INFORM mode refuses to start |
| `informs_failed` climbing, `informs_acked` flat | Collector not ack'ing (down, firewall, misconfigured) | Verify collector ingest; relax `rp_filter`; check collector logs |
| `informs_dropped` climbing | Per-device pending cap (100) exhausted — collector unreachable long enough that old entries are being aged out | Collector-side issue; fix there. Simulator is doing the right thing |
| Startup error about INFORM + per-device binding | `-trap-mode inform` with `-trap-source-per-device=false` | Remove the `-trap-source-per-device` override; INFORM requires per-device sockets |

For generic bring-up failures (TUN module missing, `sudo` required, port
conflicts) see [Troubleshooting](troubleshooting.md).

## Related

- [SNMP trap reference](../reference/snmp-traps.md) — wire format, catalog JSON, HTTP endpoints, per-type catalog overlays
- [CLI flags → SNMP trap / INFORM export flags](../reference/cli-flags.md#snmp-trap--inform-export-flags)
- [UDP syslog export (operator guide)](syslog-export.md) — sibling feature; shares overlay loader and template vocabulary
- [Flow export (operator guide)](flow-export.md) — shared `nl6sim` namespace plumbing
- [Web API → Fire a trap on demand](../reference/web-api.md#fire-a-trap-on-demand)
