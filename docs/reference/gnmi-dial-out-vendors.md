# gNMI dial-out: vendor landscape

A one-page survey of how network vendors do **dial-out telemetry** (device pushes
to a collector), for context on nl6's own dial-out. For nl6's implementation see
[gNMI dial-out](gnmi-dial-out.md).

## The one thing to know

**gNMI's spec defines only dial-in** — `Subscribe`, where the collector is the
client and the device is the server. *Dial-out is not in gNMI.* Every "gNMI
dial-out" is a bolt-on that reverses the roles, and they sort into **three
families**:

| Family | Vendors | How it works |
|--------|---------|--------------|
| **Reverse-gNMI service** | Arista `gNMIReverse`, Nokia `Publish` | Custom gRPC service that reuses gNMI's own `SubscribeResponse` message; device is the client. Best collector interop (any gNMI-aware collector decodes it). |
| **MDT opaque-envelope** | Cisco (XR/NX-OS), Huawei, H3C | Custom service carries a vendor `Telemetry` blob in an opaque `bytes` field; needs vendor `.proto`s to decode. |
| **Generic gRPC tunnel** | OpenConfig standard, Cisco IOS-XE 17.11.1+ | No telemetry RPC — a generic tunnel reverses the *TCP* direction; an unmodified gNMI `Subscribe` runs back through it. Also carries gNOI + SSH. |

Juniper JTI is a historical fourth shape: config-driven proprietary export
(`services analytics`, `native-grpc-gpb` / UDP), not message reuse.

## At a glance

| Vendor / flavor | Family | RPC / mechanism | Transport | Encodings | Identity |
|-----------------|--------|-----------------|-----------|-----------|----------|
| **Arista `gNMIReverse`** | reverse-gNMI | `Publish(stream SubscribeResponse) → Empty` | gRPC/TLS | JSON_IETF, PROTO | in-band `Prefix.Target` (`-target_value`) |
| **Cisco MDT** (XR/NX-OS) | MDT envelope | `gRPCMdtDialout.MdtDialout(stream MdtDialoutArgs)` | gRPC, **TCP**, **UDP** | compact-GPB, **KV-GPB**, JSON | session / MDT header |
| **Cisco IOS-XE** | gRPC tunnel | tunnel + unmodified gNMI | gRPC tunnel/TLS | JSON_IETF, PROTO | tunnel target registration |
| **Juniper JTI** | proprietary export | `[edit services analytics]` `dialout-type` | gRPC/TCP, **UDP** | gpb-gnmi, native udp-gpb/compact | source / session |
| **Nokia SR OS** | reverse-gNMI | `Publish` (reuses `SubscribeResponse`) | gRPC/TLS `:57400` | GPB (OC or NOKIA-YANG) | session |
| **OpenConfig** (standard) | gRPC tunnel | `tunnel.proto` register-target | gRPC/TLS | negotiated gNMI | tunnel target |

## Distinctions that matter operationally

- **Transport:** only **Cisco XR and Juniper** offer UDP dial-out (lowest overhead,
  no TLS, no delivery guarantee). Everyone else is gRPC/HTTP2/TLS.
- **Encoding:** *self-describing* (KV-GPB, JSON_IETF) needs no per-path `.proto`
  at the collector; *compact GPB* is smaller but requires exact proto alignment.
  Cisco recommends **KV-GPB** as the midpoint.
- **Subscription lifecycle:** dial-out subs are **persistent** (configured on the
  device, survive session loss, **device** reconnects — Cisco retries ~30s) vs
  dial-in's **dynamic** subs (die with the session, collector recovers).
- **Scaling ceiling:** HTTP/2 `MAX_CONCURRENT_STREAMS` defaults to **100**; exceed
  it and calls *silently queue*. Correct pattern is **one connection + one stream
  per device** (what nl6 does). Nokia caps on-device at 8 sessions / 225 channels.
- **HA:** dial-out uniquely enables **anycast collector VIP + BFD** (devices
  re-home to the nearest healthy collector) — a dial-in topology can't do this.
- **Security:** TLS on all gRPC paths; mTLS client cert authenticates the *device*
  but can't verify the collector (still need a CA bundle). UDP paths carry no TLS.

## Maturity & ecosystem

- Production-mature across Cisco, Juniper, Arista, Nokia (+ Huawei, H3C,
  Palo Alto, SONiC); broadly displacing SNMP polling, accelerated by AI/GPU
  fabrics needing sub-second / on-change data.
- **The gap is interoperability, not availability**: uneven OpenConfig model
  coverage, differing `origin`/`prefix`/`path` interpretation, GPB proto/encoding
  mismatches. Top field pitfalls: gRPC `Unavailable` (code 14) → encoding
  mismatch → proto misalignment → **internal MDT headers** (IOS-XR 12 B / NX-OS
  6 B must be stripped before protobuf decode).
- **Collectors:** [gNMIc](https://gnmic.openconfig.net/) is the most vendor-neutral
  (dial-in, tunnel dial-out, multivendor decode); Telegraf `cisco_telemetry_mdt`
  for Cisco; Arista `gnmireverse/server`; Netflix `gnmi-gateway` for HA.
  Downstream is typically TSDB (InfluxDB/Prometheus) → Grafana.

## On the horizon

The IETF's **YANG-Push over UDP-Notif** (`draft-ietf-netconf-distributed-notif`)
streams YANG-modeled data over UDP from line cards/NPUs, IPFIX-style, with rich
metadata (timestamp, sender ID, sequence, module revision). It's the most credible
standards-based alternative to the OpenConfig gRPC dial-out approach — a different
transport paradigm rather than another gRPC variant.

## Where nl6 sits

nl6 ships the **Arista `gNMIReverse`** flavor — the most interoperable family. Its
design decisions match vendor behaviour: one `ClientConn`/stream per device,
drop-on-outage with capped backoff, in-band `Prefix.Target` identity, and
mTLS-client-cert + CA verification. Natural future flavors: **Nokia `Publish`**
(nearly identical) or **Cisco MDT KV-GPB** (a genuinely different envelope +
encoding, higher effort).
