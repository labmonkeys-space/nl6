# UDP syslog export (operator guide)

nl6 can emit UDP syslog messages in either **RFC 5424** (the modern
structured format with `[SD-PARAM]` blocks) or **RFC 3164** (the legacy
BSD format most network gear still defaults to) from every simulated
device to a single collector such as `rsyslog`, `syslog-ng`, or an
NMS syslog daemon. Each device uses its own IP as the UDP source by
default, so collectors that key on source-IP → node mapping attribute
messages correctly without extra work.

This page is the operator-facing setup guide. For the CLI flags see
[CLI flags → UDP syslog export](../reference/cli-flags.md#udp-syslog-export-flags);
for wire format, catalog JSON, and HTTP endpoints see
[Syslog export reference](../reference/syslog-export.md).

## Enabling syslog export

The feature is off by default. Pass `-syslog-collector <host:port>` to
enable it; the other flags have sensible defaults for modern collectors.

```bash
# 100 devices, RFC 5424, one message every ~10s per device (Poisson-distributed)
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -syslog-collector 192.168.1.10:514

# Legacy BSD format (required by some older collectors + network gear that still
# auto-detects based on leading '<PRI>Mmm DD' shape)
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -syslog-collector 192.168.1.10:514 \
  -syslog-format 3164

# Tighter interval + global rate cap (≤ 500 messages/s across all devices)
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 1000 \
  -syslog-collector 192.168.1.10:514 \
  -syslog-interval 1s -syslog-global-cap 500

# Custom catalog (overrides universal + disables per-type overlays)
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -syslog-collector 192.168.1.10:514 \
  -syslog-catalog /etc/nl6/my-syslog.json
```

## 5424 vs 3164

Only **one format is active per simulator process** — the two coexist
poorly on a single UDP socket because auto-detecting collectors can
mis-parse the other form.

| Aspect | RFC 5424 (`-syslog-format 5424`, default) | RFC 3164 (`-syslog-format 3164`) |
|--------|-------------------------------------------|----------------------------------|
| Timestamp | ISO 8601 with fractional seconds (`2026-04-21T13:30:45.123Z`) | BSD-style (`Apr 21 13:30:45`) |
| HOSTNAME | Explicit field | Explicit field |
| APP-NAME / TAG | `APP-NAME` required; `PROCID` and `MSGID` distinct | Single `TAG` only, no structured MSGID |
| Structured data | `[key="value" ...]` SD-PARAM blocks | Not supported — `structuredData` in catalog entries is dropped |
| Max message size | 1400 bytes (enforced at load time via dry-render) | Same |
| Year in timestamp | Included | Absent (RFC 3164 omits the year) |

Choose 5424 for new deployments and anything that consumes structured
data. Choose 3164 for downstream testing against legacy collectors or
when the message sink auto-detects format from the leading characters.

## Per-device source IP binding

`-syslog-source-per-device=true` (the default) binds a UDP socket per
device inside the `nl6sim` network namespace so the UDP source address
on the wire matches the simulated device's IP. Per-device bind failures
are **non-fatal** — unlike trap export's INFORM mode, syslog has no ack
path that depends on symmetric source IPs. When a bind fails:

1. The simulator logs a warning naming the device IP and the bind error.
2. That device's exporter falls back to the shared simulator-process
   UDP socket.
3. The collector sees the simulator host's IP as the source for that
   device's messages (breaks source-IP → node mapping for the affected
   device only).

Setting `-syslog-source-per-device=false` skips per-device binding
entirely — every device's messages arrive with the simulator host's IP
as the source. Use this if the collector side doesn't care about source
IP (e.g., it keys on `HOSTNAME` field or `structuredData` instead).

## Rate cap and scheduling

Per-device firing follows a **Poisson process** with mean
`-syslog-interval` (default 10s) — the same design as trap export, for
the same reason: naïve periodic scheduling causes synchronised-burst
artefacts that don't reflect real-world syslog traffic shapes.

`-syslog-global-cap <rate>` adds a hard ceiling across all devices.
Sizing guidance:

- **Steady-state estimate:** `devices / syslog_interval_seconds`.
  30,000 devices at `-syslog-interval 10s` ≈ 3000 msg/s average.
- **Under-cap deliberately** to leave headroom for on-demand HTTP-API
  fires you inject for fault injection. On-demand fires **bypass the
  global cap** (test-harness use case).
- `-syslog-global-cap 0` (the default) means unlimited.

## Prerequisites inherited from flow / trap export

Per-device source IP binding reuses the same `nl6sim` network namespace
plumbing as flow and trap export — no new `iptables` rules and no new
netns setup. Three conditions apply:

- **`iptables FORWARD` rule.** At startup the simulator inserts
  `FORWARD -i veth-sim-host -j ACCEPT` so Docker-present hosts (which
  default FORWARD to drop) allow per-device egress. Walkthrough:
  [Flow export → Prerequisites](flow-export.md#prerequisites-for-per-device-source-ip).
- **Route to the collector from inside the namespace.** Same default
  route via `veth-sim-host` (`10.254.0.1`); if you've customised host
  routing, verify with
  `sudo ip netns exec nl6sim ip route get <collector-ip>`.
- **Collector-side `rp_filter`.** Reverse-path filtering on the
  collector host may drop UDP/514 packets whose source IP
  (`10.0.0.x`, `10.42.0.x`, whatever subnet your devices live in)
  isn't reachable back through the receiving interface. Loose mode
  fixes it:
  ```bash
  sudo sysctl -w net.ipv4.conf.all.rp_filter=2
  sudo sysctl -w net.ipv4.conf.<iface>.rp_filter=2
  ```

## Smoke test

The simplest end-to-end check uses `netcat` (or `socat`) as a trivial
UDP sink:

```bash
# In one terminal — dump every received datagram to stdout
nc -ul 514 | sed -u 's/^/recv: /'

# In another terminal — point the simulator at it
sudo ./nl6 -auto-start-ip 127.0.0.1 -auto-count 5 \
  -syslog-collector 127.0.0.1:514 -syslog-interval 2s
```

You should see lines arriving every few seconds. The universal catalog
dominates with `interface-up` / `interface-down` (together 60% of
fires by weight); `auth-success` / `auth-failure` sit at 30%, and
`config-change` / `system-restart` round out the remainder.

For vendor-flavoured content (e.g., Cisco `%LINK-3-UPDOWN:` or Juniper
`MIB2D_IFD_IFL_ENCAPS_MISMATCH:`), select a device type with a per-type
overlay — see
[Syslog reference → Per-type catalogs](../reference/syslog-export.md#per-type-catalog-overlays).

If you need a specific message on demand:

```bash
# Fire a named catalog entry immediately via the HTTP API
curl -X POST http://localhost:8080/api/v1/devices/127.0.0.1/syslog \
  -H "Content-Type: application/json" \
  -d '{"name":"interface-down","templateOverrides":{"IfIndex":"3"}}'
```

See [Web API → Fire a syslog message on demand](../reference/web-api.md#fire-a-syslog-message-on-demand)
for the full request / response shape.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `enabled: false` in `/api/v1/syslog/status` | `-syslog-collector` not set | Pass the flag; verify port |
| `enabled: true`, `sent` is 0 | Scheduler idle (no devices yet) | Wait for device creation to finish |
| Messages sent but collector sees nothing | FORWARD rule missing or `rp_filter` blocking | See [Flow export → Flow troubleshooting](flow-export.md#flow-troubleshooting) — the netns diagnostic steps apply verbatim |
| Source IP on the wire is the host, not the device | Per-device bind failed for that device (non-fatal) | Check simulator logs for `per-device bind failed`; expected when run without netns (`-no-namespace`) |
| Collector parser chokes on the message format | Collector and simulator disagree on 5424 vs 3164 | Match `-syslog-format` to the collector's expected form |
| `structuredData` missing from emitted messages | Running `-syslog-format 3164` — RFC 3164 doesn't support SD | Switch to 5424 or accept the loss |
| `send_failures` climbing | Collector unreachable or firewalled | Verify collector listening on UDP/514; check firewall rules |
| Catalog load fails at startup naming a `resources/<slug>/syslog.json` | Malformed per-type JSON or a reserved template field | See [Syslog reference → Per-type catalogs](../reference/syslog-export.md#per-type-catalog-overlays) for the schema and vocabulary |

For generic bring-up failures (TUN module missing, `sudo` required,
port conflicts) see [Troubleshooting](troubleshooting.md).

## Related

- [Syslog export reference](../reference/syslog-export.md) — wire format, catalog JSON, HTTP endpoints, per-type catalog overlays
- [CLI flags → UDP syslog export](../reference/cli-flags.md#udp-syslog-export-flags)
- [SNMP trap export (operator guide)](snmp-traps.md) — sibling feature; shared overlay loader and template vocabulary
- [Flow export (operator guide)](flow-export.md) — shared `nl6sim` namespace plumbing
- [Web API → Fire a syslog message on demand](../reference/web-api.md#fire-a-syslog-message-on-demand)
