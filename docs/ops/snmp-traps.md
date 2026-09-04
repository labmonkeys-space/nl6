# SNMP trap / INFORM export (operator guide)

nl6 emits notifications from every simulated device to a single collector such
as `snmptrapd` or an NMS trap daemon, in whichever SNMP version
`-trap-snmp-version` selects — **v2c** (the default), **v1** RFC 1157 Trap-PDUs,
or **v3** with RFC 3414 USM authentication and privacy. One version per fleet.
Both fire-and-forget **TRAP**s (PDU `0xA7`) and acknowledged **INFORM**s (PDU
`0xA6`) are available under v2c; INFORM is v2c only.

Each device generates its own notifications with its own IP as the UDP source,
so collectors that key on the agent source IP attribute correctly without extra
work.

This page is the operator-facing setup guide. For the CLI flags see
[CLI flags → SNMP trap / INFORM export](../reference/cli-flags.md#snmp-trap--inform-export-flags);
for wire format, catalog JSON, and HTTP endpoints see
[SNMP trap reference](../reference/snmp-traps.md).

## Enabling trap export

The feature is off by default. Pass `-trap-collector <host:port>` to enable
it; every other `-trap-*` flag has a sensible default for common trap
collectors.

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

### SNMPv3 notifications

`-trap-snmp-version v3` needs a USM user, and the receiver needs to be told
which **engine** to expect — a trap carries no discovery exchange, so
`snmptrapd` cannot learn the engine ID by asking.

Each device's engine ID is **derived from its IPv4 address** and is not
configurable: `80007ed9` (IANA's documentation PEN 32473) + `03` (RFC 3411 §5
MAC format) + `0242` + the address in hex. `10.42.0.9` is therefore
`0x80007ed90302420a2a0009`. You do not have to compute it —
`GET /api/v1/traps/status` reports `snmpv3.engine_ids_by_device` for every
exporting device.

```bash
# 1. A scratch persistent dir. net-snmp MOVES each createUser line into its own
#    store on first read and DELETES it from your file, so a second run with a
#    corrected password silently keeps the stale user.
export SNMP_PERSISTENT_DIR=/tmp/nl6-trapd
rm -rf "$SNMP_PERSISTENT_DIR" && mkdir -p "$SNMP_PERSISTENT_DIR"

# 2. One createUser per device engine ID, then the receiver.
cat > /tmp/nl6-trapd.conf <<'CONF'
disableAuthorization yes
createUser -e 0x80007ed903024201000001 trapuser SHA "authpass" AES "privpass"
authUser log trapuser priv
CONF
snmptrapd -f -Lo -On -C -c /tmp/nl6-trapd.conf udp:127.0.0.1:1162

# 3. The simulator, in another terminal.
sudo ./nl6 -auto-start-ip 1.0.0.1 -auto-count 1 \
  -trap-collector 127.0.0.1:1162 -trap-interval 2s \
  -trap-snmp-version v3 -trap-snmpv3-user trapuser \
  -trap-snmpv3-auth sha1 -trap-snmpv3-password authpass \
  -trap-snmpv3-priv aes128 -trap-snmpv3-priv-password privpass
```

`-C -c` makes `snmptrapd` read only that file, so a host
`/etc/snmp/snmptrapd.conf` cannot change the result; `-On` prints numeric OIDs
so no MIBs need to be installed.

:::danger[The USM passwords are visible in `ps`]

`-trap-snmpv3-password` and `-trap-snmpv3-priv-password` are the only secrets
nl6 takes on the command line. They are readable by every user on the host via
`ps` and `/proc/<pid>/cmdline`, land in shell history, and are echoed by
`docker inspect`. Use lab credentials only.
:::

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
| Startup error naming `-trap-snmp-version` and `-trap-mode` together | `inform` asked for under `v1` or `v3` | SNMPv1 defines no InformRequest; an SNMPv3 one is receiver-authoritative and needs engine discovery nl6 does not implement. Use `-trap-mode trap`, or `v2c` |
| `WARNING: -trap-snmpv3-* set but IGNORED` at startup | The credentials were passed without `-trap-snmp-version=v3` | Add it. The fleet is otherwise emitting **unauthenticated** v2c |
| v3 fleet, `sent` climbing, `snmptrapd` logs nothing | The receiver's `createUser` engine ID does not match the device's, or a stale user survived in `SNMP_PERSISTENT_DIR` | Take the engine ID from `snmpv3.engine_ids_by_device` in `/api/v1/traps/status`; clear the persistent dir and restart the receiver |
| v3 fleet stopped being accepted after an nl6 restart | `msgAuthoritativeEngineBoots` is always 1 and engine time restarts at 0, and a trap has no discovery, so the receiver's cached `(boots, time)` puts the new traps outside RFC 3414 §3.2's 150-second window | Clear the receiver's persistent USM state and restart it, or wait the window out |
| Optical alarms went quiet after lowering `-datagram-mtu` on a v3 fleet | The USM envelope adds ~91 bytes, so the Ciena 39-varbind entries cross the budget ~91 B sooner under v3 | The startup log names each disabled entry with its size and the MTU that would admit it; raise `-datagram-mtu` |

For generic bring-up failures (TUN module missing, `sudo` required, port
conflicts) see [Troubleshooting](troubleshooting.md).

## Related

- [SNMP trap reference](../reference/snmp-traps.md) — wire format, catalog JSON, HTTP endpoints, per-type catalog overlays
- [CLI flags → SNMP trap / INFORM export flags](../reference/cli-flags.md#snmp-trap--inform-export-flags)
- [UDP syslog export (operator guide)](syslog-export.md) — sibling feature; shares overlay loader and template vocabulary
- [Flow export (operator guide)](flow-export.md) — shared `nl6sim` namespace plumbing
- [Web API → Fire a trap on demand](../reference/web-api.md#fire-a-trap-on-demand)
