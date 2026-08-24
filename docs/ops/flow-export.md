# Flow export (operator guide)

nl6 can emit synthetic flow telemetry to any NetFlow v5 (Cisco), NetFlow
v9 (RFC 3954), IPFIX (RFC 7011), or sFlow v5 collector. Each device generates
flows appropriate to its role — an edge router emits different traffic shapes
than a firewall or a data-center switch.

This page is the operator-facing setup guide. For the CLI flags see
[CLI flags → Flow export](../reference/cli-flags.md#flow-export-flags); for
protocol-level details and the sFlow caveat see
[Flow export reference](../reference/flow-export.md).

## Per-device source IPs

By default, each device binds its **own** UDP socket inside the `nl6sim`
namespace, so the collector sees flow packets arriving from the device's IP
rather than the simulator host's. This is what makes per-device attribution
work on collectors that key on the exporter source IP (OpenNMS, Elastiflow,
nfcapd, etc.).

Disable by setting `-flow-source-per-device=false` — that falls back to a
single shared socket bound in the host namespace.

## Starting flow export

```bash
# NetFlow v9 to a local collector on port 2055
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -flow-collector 192.168.1.10:2055

# IPFIX instead (port 4739 is the IPFIX default)
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -flow-collector 192.168.1.10:4739 -flow-protocol ipfix

# NetFlow v5 (Cisco — 30 records per PDU, no template)
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -flow-collector 192.168.1.10:2055 -flow-protocol netflow5

# sFlow v5 (default UDP port 6343). See the sFlow caveat in the reference.
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -flow-collector 192.168.1.10:6343 -flow-protocol sflow

# Faster ticks for high-fidelity testing
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 10 \
  -flow-collector 127.0.0.1:9999 -flow-tick-interval 1

# Fall back to the host IP as the source (shared socket)
sudo ./nl6 -auto-start-ip 10.0.0.1 -auto-count 100 \
  -flow-collector 192.168.1.10:2055 -flow-source-per-device=false
```

## Heterogeneous-fleet operation (multiple collectors / protocols)

The `-flow-*` CLI flags seed a **single** collector / protocol for the
auto-start batch. To stand up a fleet that points at more than one
collector — or mixes protocols — start the simulator with just the
global flags and drive device creation via
[`POST /api/v1/devices`](../reference/web-api.md#per-device-export-blocks),
one batch per collector / protocol.

### Example: two collectors, three protocols

```bash
# 1. Boot with NO flow seed — only the global knobs (tick cadence,
#    template cadence, source-per-device policy).
sudo ./nl6 \
  -flow-tick-interval 1 \
  -flow-template-interval 300 \
  -flow-source-per-device=true

# 2. Batch A → NetFlow v9 to collector A.
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.0.1",
    "device_count": 50,
    "flow": {"collector": "192.168.1.10:2055", "protocol": "netflow9"}
  }'

# 3. Batch B → IPFIX to collector A (different protocol, same host).
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.1.1",
    "device_count": 30,
    "flow": {"collector": "192.168.1.10:4739", "protocol": "ipfix"}
  }'

# 4. Batch C → sFlow to collector B.
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.2.1",
    "device_count": 20,
    "flow": {"collector": "192.168.1.20:6343", "protocol": "sflow"}
  }'
```

`GET /api/v1/flows/status` then reports three collector records, one
per `(collector, protocol)` tuple:

```json
{
  "subsystem_active": true,
  "collectors": [
    {"collector": "192.168.1.10:2055", "protocol": "netflow9", "devices": 50, "..." },
    {"collector": "192.168.1.10:4739", "protocol": "ipfix",    "devices": 30, "..." },
    {"collector": "192.168.1.20:6343", "protocol": "sflow",    "devices": 20, "..." }
  ],
  "devices_exporting": 100
}
```

### Notes

- The same device IP can belong to only one flow config (one `flow` block
  per device). If you need the same device to appear on multiple
  collectors, run multiple simulator processes — the `nl6sim` netns +
  per-device-source-IP scheme isn't designed to multicast.
- `-flow-template-interval` is simulator-wide — every exporter ticks at the
  same cadence regardless of batch. Per-device `tick_interval` in the REST body
  is accepted and validated but **not honored**; a single warning is logged per
  subsystem lifecycle the first time any device SETS it (not only when it
  diverges), and the create response carries the same disclosure
  ([nl6#445](https://github.com/labmonkeys-space/nl6/issues/445)).
- `-flow-tick-interval` sets the simulator-wide cadence and **is** honored
  ([nl6#446](https://github.com/labmonkeys-space/nl6/issues/446) fixed). It
  controls **batching, not volume**: a slower tick puts more records in each
  datagram rather than proportionally reducing the record rate. Volume is set
  by the profile's concurrent-flow count and the expiry timeouts. Values
  outside `(0, 1h]` are rejected with a log line and the 5s default applies.
  `effective_intervals.flow_tick_interval` in the device read-back reports the
  period actually latched.
- Collector-side `rp_filter` tuning applies per collector host, not
  per protocol — see the next section.

## Prerequisites for per-device source IP

When `-flow-source-per-device` is enabled (the default), flow packets
originate from inside the `nl6sim` namespace and must traverse the
`veth-sim-host` ↔ `veth-sim-ns` pair to reach the collector. Three things
have to be in place:

- **`iptables` installed on the simulator host.** At startup the simulator
  inserts `iptables -I FORWARD 1 -i veth-sim-host -j ACCEPT` so that hosts
  with a default-DROP `FORWARD` policy (common when Docker is installed)
  allow per-device egress. The rule is removed on clean shutdown. Without
  `iptables` a warning is logged and flows are silently dropped on such
  hosts. See [Network namespace](network-namespace.md).
- **Route to the collector from the namespace.** The namespace has a default
  route via `veth-sim-host` (`10.254.0.1`), so any collector reachable from
  the host via its normal routing table is reachable from the namespace. If
  you've customised host routing verify with:
  ```bash
  sudo ip netns exec nl6sim ip route get <collector-ip>
  ```
- **Collector-side `rp_filter`.** Reverse-path filtering on the collector
  machine may drop flow packets whose source IP (e.g. `10.0.0.x`) isn't
  reachable back through the receiving interface:
  ```bash
  sudo sysctl -w net.ipv4.conf.all.rp_filter=2
  sudo sysctl -w net.ipv4.conf.<iface>.rp_filter=2
  ```
  `2` is loose mode; `0` disables filtering entirely. The simulator
  auto-configures its own `rp_filter` sysctls — no user action needed there.

## Flow troubleshooting

If the collector isn't seeing flows, walk through these in order:

1. **Confirm export is enabled and running.**
   ```bash
   curl http://localhost:8080/api/v1/flows/status
   ```
   Expect `enabled: true`, `devices_exporting > 0`, and
   `total_packets_sent` steadily increasing.
2. **Sniff on the simulator host.** Packets should appear with device IPs
   as sources:
   ```bash
   sudo tcpdump -ni any udp port <collector-port>
   ```
3. **Check the FORWARD rule.** Its packet counter should be non-zero:
   ```bash
   sudo iptables -L FORWARD -v -n
   ```
4. **Sniff on the collector host.** If packets arrive but the collector
   doesn't count them, the problem is `rp_filter` or a firewall rule on
   that host, not the simulator.
5. **As a diagnostic, restart with `-flow-source-per-device=false`.** That
   uses the host IP as the source and rules out namespace / forwarding
   issues entirely. If that works and per-device doesn't, the problem is
   somewhere in the netns bridge.

For generic bring-up failures (TUN module missing, `sudo` required, port
conflicts) see [Troubleshooting](troubleshooting.md).
