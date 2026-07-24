<img src="./assets/nl6-logo-with-text.svg" width="200" />

[![CI](https://github.com/labmonkeys-space/nl6/actions/workflows/ci.yml/badge.svg)](https://github.com/labmonkeys-space/nl6/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-labmonkeys--space.github.io-blue?logo=docusaurus)](https://labmonkeys-space.github.io/nl6/)
[![Go Version](https://img.shields.io/github/go-mod/go-version/labmonkeys-space/nl6?filename=go%2Fgo.mod)](https://github.com/labmonkeys-space/nl6/blob/main/go/go.mod)
[![License](https://img.shields.io/github/license/labmonkeys-space/nl6)](https://github.com/labmonkeys-space/nl6/blob/main/LICENSE)
[![Container Image](https://img.shields.io/badge/ghcr.io-nl6-blue?logo=docker)](https://github.com/labmonkeys-space/nl6/pkgs/container/nl6)
[![Latest Release](https://img.shields.io/github/v/release/labmonkeys-space/nl6?include_prereleases&sort=semver)](https://github.com/labmonkeys-space/nl6/releases)

![nl6 Logo](assets/screenshot-v0.9.0.png)

**📖 Documentation: <https://labmonkeys-space.github.io/nl6/>**

A scalable network and infrastructure simulator that exposes realistic
SNMP v2c/v3, SSH, and HTTPS REST interfaces for testing network management
software, monitoring systems, and automation tools. nl6 can simulate
tens of thousands of network devices, GPU servers, storage systems, and
Linux servers — each with its own IP address via Linux TUN interfaces and
network namespaces.

## Highlights

- **Runs 30,000+ simulated devices on a single host** — see [Scaling](https://labmonkeys-space.github.io/nl6/ops/scaling/).
- **28 device types across 8 categories** (core / edge routers, DC and
  campus switches, firewalls, servers, NVIDIA DGX/HGX GPU servers, and
  enterprise storage) — see [Device types](https://labmonkeys-space.github.io/nl6/reference/device-types/).
- **Multi-protocol per device:** SNMP v2c/v3 (MD5/SHA1 auth, DES/AES128
  privacy), SSH with VT100 terminal emulation, and HTTPS REST — see
  [SNMP reference](https://labmonkeys-space.github.io/nl6/reference/snmp/)
  and [Web API](https://labmonkeys-space.github.io/nl6/reference/web-api/).
- **Realistic dynamic metrics:** CPU / memory / temperature on 100-point
  sine waves; full IF-MIB counter cycling (octets plus per-direction
  unicast / multicast / broadcast packet counts, errors, discards) with
  per-device error-scenario tuning (`clean` / `typical` / `degraded` /
  `failing`); per-GPU DCGM metrics — see
  [SNMP reference → Dynamic IF-MIB counters](https://labmonkeys-space.github.io/nl6/reference/snmp/#dynamic-if-mib-counters)
  and [GPU simulation](https://labmonkeys-space.github.io/nl6/reference/gpu/).
- **Self-reporting version:** `./nl6 -version`, `GET /api/v1/version`,
  and a hero-kicker `(vX.Y.Z)` in the web UI all report the running build
  — no source checkout needed to identify a deployed simulator.
- **Per-device flow export** (NetFlow v5 / v9, IPFIX, sFlow v5) with
  per-device source IPs — see
  [Flow export](https://labmonkeys-space.github.io/nl6/ops/flow-export/).
- **Per-device SNMPv2c trap / INFORM export** — central Poisson scheduler
  with a global rate cap, a user-overridable JSON catalog, and per-device
  UDP source IPs. Suited to trap-daemon scale testing. Configure with
  `-trap-collector <host:port>`; full flag list and catalog schema in
  [CLAUDE.md](CLAUDE.md) → "SNMP trap export".
- **Per-device UDP syslog export** (RFC 5424 / RFC 3164) — central
  Poisson scheduler with a global rate cap, user-overridable JSON
  catalog, and per-device UDP source IPs. Ships six generic entries
  (interface up/down, auth success/failure, config change, system
  restart) spanning `local7` and `authpriv`; select format with
  `-syslog-format 5424|3164`. Suited to syslog-collector scale
  testing — configure with `-syslog-collector <host:port>`; full flag
  list and catalog schema in [CLAUDE.md](CLAUDE.md) →
  "UDP syslog export".
- **gNMI streaming telemetry** — every device serves a read-only
  OpenConfig dial-in target (gRPC + TLS on `:9339`, SAMPLE / ON_CHANGE /
  ONCE), and can additionally **push** telemetry to a collector via
  gNMI dial-out (Arista `gNMIReverse`, per-device opt-in, mixed fleets
  supported) — see
  [gNMI target](https://labmonkeys-space.github.io/nl6/reference/gnmi/)
  and
  [gNMI dial-out](https://labmonkeys-space.github.io/nl6/reference/gnmi-dial-out/).

## Status & scale

**Stable** — SNMP v2c/v3, SSH, HTTPS REST (storage APIs), NetFlow v5/v9 and
IPFIX, TUN-per-device scaling with `nl6sim` network-namespace isolation,
web UI, REST control plane.

**Experimental** — sFlow v5 (synthesised from `FlowCache` records with a
fixed `sampling_rate`; suitable for collector-plumbing validation, not
link-utilisation benchmarking — see
[Flow export reference → sFlow caveat](https://labmonkeys-space.github.io/nl6/reference/flow-export/#sflow-caveat)).

**Tested scale** — up to 30,000 concurrent simulated devices on a single
host. **Toolchain** — Go 1.26 or later; canonical version pinned in
[`go/go.mod`](go/go.mod).

## Quick start

```bash
git clone https://github.com/labmonkeys-space/nl6.git
cd nl6/go/nl6 && go build -o nl6 .

# Auto-create 5 devices starting at 192.168.100.1
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 5
```

Then query any device:

```bash
snmpget -v2c -c public 192.168.100.1 1.3.6.1.2.1.1.1.0
ssh simadmin@192.168.100.1                            # password: simadmin
gnmic -a 192.168.100.1:9339 --skip-verify capabilities
```

Per-device exports (flow + trap + syslog in a single create call):

```bash
# Boot without any export CLI flags — the subsystems are always-on.
sudo ./nl6

# Create 10 devices that all emit IPFIX flows, SNMPv2c traps, and
# RFC 5424 syslog to one collector. Any of the three blocks is optional.
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.0.0.1",
    "device_count": 10,
    "flow":   {"collector": "192.168.1.10:4739", "protocol": "ipfix"},
    "traps":  {"collector": "192.168.1.10:162",  "mode":     "trap"},
    "syslog": {"collector": "192.168.1.10:514",  "format":   "5424"}
  }'

# Inspect what each subsystem has attached.
curl http://localhost:8080/api/v1/flows/status   | jq '.data.collectors'
curl http://localhost:8080/api/v1/traps/status   | jq '.collectors'
curl http://localhost:8080/api/v1/syslog/status  | jq '.collectors'
```

Inter-device topology (LLDP). Link two devices and the neighbor table plus a
`to_<peer>_<port>` `ifAlias` appear on both ends — point your NMS's LLDP
discovery at the LLDP root (`1.0.8802.1.1.2`) to discover the topology:

```bash
curl -X POST http://localhost:8080/api/v1/topology \
  -H 'Content-Type: application/json' \
  -d '{"links":[{"a":{"ip":"10.0.0.1","ifindex":1},"b":{"ip":"10.0.0.2","ifindex":2}}]}'

snmpwalk -v2c -c public 10.0.0.1 1.0.8802.1.1.2        # LLDP local + neighbor tables
snmpget  -v2c -c public 10.0.0.1 1.3.6.1.2.1.31.1.1.1.18.1   # ifAlias = to_<peer>_<port>
curl http://localhost:8080/api/v1/topology/status | jq   # {subsystem_active, configured_links, active_links}
```

Full walkthrough: [Getting started → Quick start](https://labmonkeys-space.github.io/nl6/getting-started/quick-start/).
Prebuilt packages (`.deb` / `.rpm` / NixOS): [Getting started → Install packages](https://labmonkeys-space.github.io/nl6/getting-started/install-packages/) — packaging reference in [`deploy/packages/`](deploy/packages/README.md).
Container deployment: [Getting started → Docker](https://labmonkeys-space.github.io/nl6/getting-started/docker/).
Deployment recipes & worked examples: [`examples/`](examples/) — Clos fabrics and a ready-to-run OpenNMS Minion (`docker compose`) stack.

## Documentation map

The docs site has four top-level sections:

- [Getting Started](https://labmonkeys-space.github.io/nl6/getting-started/quick-start/) — build, first run, package install, Docker.
- [Operations](https://labmonkeys-space.github.io/nl6/ops/scaling/) — scaling, network namespace, flow export, troubleshooting.
- [Reference](https://labmonkeys-space.github.io/nl6/reference/architecture/) — architecture, CLI flags, web API, device types, SNMP, flow export, resource files, GPU simulation.
- [GPU simulation](https://labmonkeys-space.github.io/nl6/reference/gpu/) — NVIDIA DCGM OID layout, per-GPU metrics, and the pollaris / parser integration notes (formerly `plans/`).

Reference content that used to live in this README now lives in the docs
site. A bare `README.md` on GitHub is intentional: the site is the canonical
home.

## Contributing

Contributions are welcome. Two project policies apply to every patch:

**1. Sign off every commit (Developer Certificate of Origin).** All commits
must carry a `Signed-off-by:` trailer certifying the
[DCO](https://developercertificate.org/). Use `-s` on every commit:

```bash
git commit -s -m "your commit message"
```

A DCO-check gate will fail any PR whose commits are missing the sign-off
trailer.

**Suggested workflow**

1. Fork `labmonkeys-space/nl6`.
2. Create a feature branch.
3. Make your changes and add / update tests.
4. Run `make check-tidy && make build && make test` locally.
5. `git commit -s` each commit.
6. `gh pr create --repo labmonkeys-space/nl6 --base main`.

**Cutting a release.** Maintainers: see [`RELEASING.md`](RELEASING.md) for the
tag-driven release workflow and the short post-tag verification checklist.

## Support

nl6 is free and open source under the **Apache-2.0** license — an open network
simulator that stands in for a lab full of hardware (30,000+ devices, real
SNMP / NetFlow / IPFIX / sFlow / Syslog / gNMI). If it saved you a test rig, a
one-time donation helps keep it maintained: releases, new device types, and
protocol upkeep.

- **GitHub Sponsors:** https://github.com/sponsors/indigo423

No tiers, no gated features — the simulator stays free for everyone. A ⭐ or a
good issue helps just as much, and there's a spot on [SPONSORS.md](SPONSORS.md)
if you'd like one. 🙏

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
details.

## Heritage

Originally forked from [`saichler/l8opensim`](https://github.com/saichler/l8opensim); see commit history for upstream attribution.

---

**nl6** — simulate networks, test at scale, develop with confidence.
