# onms-minion-stack — nl6 + OpenNMS Minion, telemetry into an existing core

A self-contained compose stack that gets realistic monitoring data from a
simulated network into your **existing** OpenNMS deployment. It runs [nl6](../../README.md)
and an OpenNMS Minion side by side, deploys the 14-device
[5-stage Clos](../5-stage-clos/) fabric, points every device's IPFIX / syslog /
SNMP-trap exporter at the Minion, and the Minion relays everything to your core
over Kafka and polls the devices on the core's behalf.

```
                 ┌──────────── your EXISTING OpenNMS core ──────────────┐
                 │      (Horizon/Meridian + Kafka broker, running)      │
                 └──────────────▲──────────────────────▲────────────────┘
                       Kafka IPC │            REST import │ (location nl6-Lab)
   ┌──────────── compose: onms-minion-stack ─┼───────────┼──────────────────────┐
   │  ┌─────────────────────────┐            │           │                      │
   │  │  nl6 (simulator)        │   ┌─────────┴───────────┴──────┐               │
   │  │  web :8080  gNMI :9339  │   │  OpenNMS Minion             │               │
   │  │                         │   │   id=nl6-Minion-01          │               │
   │  │  opensim netns          │   │   location=nl6-Lab          │               │
   │  │   10.42.0.x  (5-stage)  │──▶│   IPFIX :4739               │ telemetry     │
   │  │   veth host 10.254.0.1  │◀──│   syslog:1514  trap:1162    │ (UDP)         │
   │  └─────────────────────────┘   └────────────────────────────┘               │
   │            ▲  network_mode: service:nl6 (Minion SHARES nl6's netns)          │
   │            │                                                                 │
   │     provisioner (one-shot): create fabric w/ exports + topology + node import │
   └──────────────────────────────────────────────────────────────────────────────┘
```

## What you provide (two inputs)

| `.env` key | What it is |
|---|---|
| `KAFKA_BOOTSTRAP` | Your core's Kafka brokers — the Minion↔core IPC (`host:port,host:port`). |
| `OPENNMS_BASE_URL` (+ `OPENNMS_USER` / `OPENNMS_PASS`) | Your core's REST endpoint — used to import the 14 nodes at location `nl6-Lab` so the core dispatches their polling to this Minion. |

Bring-up **fails fast** if either is unset — neither is silently defaulted.

## Quick start

```bash
cd examples/onms-minion-stack
cp .env.example .env
# edit .env: set KAFKA_BOOTSTRAP and OPENNMS_BASE_URL (+ creds)
docker compose up -d
```

That's it. After a minute: flows, syslog events, and traps appear in your core,
and the 14 fabric nodes show up under location **nl6-Lab** being polled by
**nl6-Minion-01**.

## Defaults you can override (in `.env`)

| Key | Default | Notes |
|---|---|---|
| `MINION_ID` | `nl6-Minion-01` | Minion identity. |
| `MINION_LOCATION` | `nl6-Lab` | Both the Minion location and the imported nodes' location. |
| `MINION_IMAGE` | `opennms/minion:latest` | **Pin to the same major version as your core** (e.g. `opennms/minion:33.1.6`); `latest` may mismatch. |
| `NL6_IMAGE` | `ghcr.io/labmonkeys-space/nl6:latest` | Pin a release if you prefer. |
| Optional `KAFKA_SECURITY_PROTOCOL` / `KAFKA_SASL_*` | unset (PLAINTEXT) | For SASL_SSL Kafka — also uncomment the matching `KAFKA_IPC_*` lines in `compose.yml`. |

## Why the Minion shares nl6's network namespace

The Minion runs with `network_mode: "service:nl6"`. nl6 already configures, inside
its own container, everything a collector + poller needs for the simulated fabric:
a host route to each device subnet via the namespace, `rp_filter=0`, IP forwarding,
and a `FORWARD` accept rule. By sharing that namespace the Minion gets all of it for
free:

- **Device → Minion telemetry** lands on the veth (`10.254.0.1`) with the device's
  real source IP (`10.42.0.x`); `rp_filter=0` accepts it.
- **Minion → device SNMP/ICMP polling** is routed straight into the `opensim`
  namespace — no static routes, no `rp_filter` tuning on your part.
- **Minion → Kafka** uses nl6's `eth0` to reach your broker.

**Consequence:** the Minion has no network stack of its own. To reach its Karaf
shell (`8201`) or HTTP (`8181`), publish those ports on the **`nl6`** service
(commented examples are in `compose.yml`).

## Verifying

```bash
# nl6 sees 14 devices, all exporting to the Minion:
curl -s localhost:8080/api/v1/flows/status  | jq '.data.collectors'
curl -s localhost:8080/api/v1/traps/status  | jq '.collectors'
curl -s localhost:8080/api/v1/syslog/status | jq '.collectors'
curl -s localhost:8080/api/v1/topology/status | jq   # 18 configured links

# Minion health (shares nl6's netns; reach the shell via the nl6 service):
docker compose logs minion | grep -i 'awesome\|health'

# In your OpenNMS core: location nl6-Lab exists, nl6-Minion-01 is up, and the
# 14 nodes are being polled; flows/events arrive within a poll cycle.
```

## Notes & caveats

- **Clock skew** shifts IPFIX timestamps (absolute epoch ms) — keep the docker
  host on NTP.
- **Minion config keys** (`telemetry.flows.listeners`, `netmgt.syslog`,
  `netmgt.traps`, `KAFKA_IPC_*`) follow the OpenNMS confd / env conventions and
  are version-sensitive — confirm against your pinned `MINION_IMAGE` if a
  listener doesn't come up.
- **Core adapters:** your core must have the flows (IPFIX/Netflow) telemetry
  adapter enabled to process the relayed flows — this is on by default in the
  OpenNMS flows feature set.
- **Whole-instance import:** `onms-provision.sh` builds the requisition from
  `GET /api/v1/devices`, i.e. everything nl6 is running — here that's exactly the
  14-device fabric, since the stack starts nl6 empty.

## Teardown

```bash
docker compose down          # stop + remove containers (nl6 tears down its netns)
```

The imported nodes remain in your core; remove the `nl6-inventory` requisition
there if you want them gone.

## Files

| File | Purpose |
|---|---|
| `compose.yml` | The three services (nl6 / minion / provisioner). |
| `.env.example` | Copy to `.env`; the two required inputs + overridable defaults. |
| `minion-config.yaml` | Minion IPFIX/syslog/trap listener config (confd). |
| `provision.sh` | One-shot: fabric + exports + topology + node import. |
| [`../onms-provision.sh`](../onms-provision.sh) | Shared requisition import (reused). |
| [`../5-stage-clos/clos.json`](../5-stage-clos/clos.json) | The LLDP link graph (reused). |
