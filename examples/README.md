# nl6 examples

Worked examples and deployment recipes built on [nl6](../README.md). Each
directory is self-contained with its own README.

| Example | What it does |
|---------|--------------|
| [`5-stage-clos/`](5-stage-clos/) | Hand-authored **14-device** 5-stage folded Clos fabric (devices + LLDP links), imported into OpenNMS. |
| [`large-clos/`](large-clos/) | `gen-clos.py` — generate a **k-ary fat-tree at scale** (e.g. 20-ary = 2500 devices / 6000 links). |
| [`onms-minion-stack/`](onms-minion-stack/) | `docker compose` stack: nl6 + an **OpenNMS Minion** (shared network namespace) that monitors a pre-built fabric and ships flow / trap / syslog telemetry to your OpenNMS core over Kafka. Two inputs: Kafka `bootstrap.servers` + core REST creds. |
| [`coredns-sidecar/`](coredns-sidecar/) | `docker compose` stack: nl6 (hidden DNS primary) + a **CoreDNS** secondary, so the fleet is resolvable by name — forward `<device>.nl6.local` and reverse PTRs, auto-updated on device create/delete via NOTIFY + AXFR. |

[`onms-provision.sh`](onms-provision.sh) is a generic helper: it reads whatever
devices the running nl6 instance currently exposes and imports them into OpenNMS
as a requisition — run it after an example's own `nl6-provision.sh`.
