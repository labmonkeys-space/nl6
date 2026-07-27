<!--
Copyright 2026 Ronny Trommer <ronny@no42.org>
SPDX-License-Identifier: Apache-2.0
-->
# nl6-minion Helm chart

Deploys the **nl6** network-device simulator with an **OpenNMS Minion sidecar**
in a single pod, so the Minion can poll the simulated devices directly. The
Minion talks back to the OpenNMS core over **Kafka**.

> [!WARNING]
> Kubernetes is **not an officially supported** nl6 target. See
> [`docs/ops/kubernetes.md`](../../../docs/ops/kubernetes.md) for the full list
> of reasons (privileges, host-network mutation, singleton host resources,
> non-routable device CIDR). This chart is a **single-node lab convenience**,
> not a production deployment. `replicas` is fixed at 1.

## How it works

```
┌──────────────────────── Pod (hostNetwork: true) ───────────────────────┐
│  ┌───────────────┐                         ┌──────────────────────────┐ │
│  │  nl6          │  creates nl6sim netns,  │  OpenNMS Minion          │ │
│  │  simulator    │  veth, host routes for  │  (Kafka transport)       │ │
│  │  (privileged) │  10.42.0.0/16 devices   │  polls 10.42.0.x devices │ │
│  └───────┬───────┘                         └────────────┬─────────────┘ │
└──────────┼──────────────── shared host net ────────────┼───────────────┘
           │                                              │
   node's network stack:                         Kafka  ◀┘  (sink/RPC/twin)
   route 10.42.0.0/24 via 10.254.0.2  ──▶ devices         OpenNMS core
```

The sidecar pattern works **because** the pod uses `hostNetwork: true`. nl6
installs `/24` host routes toward the `nl6sim` namespace (`AddRouteForDevices`
in `go/nl6/netns.go`); since the Minion shares the node's network namespace, it
inherits those routes and reaches the device IPs with no extra `ip route` of its
own. This is "Option A" (co-location) from `docs/ops/kubernetes.md` §4.

## Prerequisites

- A node you can pin the pod to (`nodeSelector`) that allows **privileged**
  pods. Label the target namespace:
  `kubectl label ns <ns> pod-security.kubernetes.io/enforce=privileged`.
- `/dev/net/tun` present on that node (standard on Linux).
- A **Kafka** broker reachable from the node's host network (external or
  in-cluster Service — both work because of `hostNetwork`).
- An OpenNMS core with a **Monitoring Location** matching `minion.location`.

## Install

```bash
helm install nl6-lab deploy/helm/nl6-minion \
  --namespace nl6 --create-namespace \
  --set nodeSelector."kubernetes\.io/hostname"=lab-node-01 \
  --set minion.kafka.bootstrapServers=kafka.kafka.svc.cluster.local:9092 \
  --set minion.httpUrl=http://opennms-core.opennms.svc.cluster.local:8980/opennms \
  --set minion.location=nl6-lab \
  --set minion.credentials.username=minion \
  --set minion.credentials.password='s3cret'
```

Or with your own values file:

```bash
helm install nl6-lab deploy/helm/nl6-minion -n nl6 --create-namespace -f my-values.yaml
```

## Key values

| Value | Default | Notes |
|-------|---------|-------|
| `nodeSelector` | `{}` | **Set this.** Pins the pod to the node whose network stack nl6 mutates. |
| `nl6.args` | `-auto-start-ip 10.42.0.1 -auto-count 50 ...` | Device batch + HTTP port. |
| `nl6.securityContext.privileged` | `true` | Simplest grant for `/dev/net/tun` + caps. Set `false` to rely on the capability list only. |
| `minion.id` / `minion.location` | `nl6-minion-01` / `nl6-lab` | Must match an OpenNMS Monitoring Location. |
| `minion.httpUrl` | in-cluster Service | External URL or cluster DNS — both reachable under `hostNetwork`. |
| `minion.kafka.bootstrapServers` | in-cluster Service | Kafka broker `host:port`. |
| `minion.kafka.extraProperties` | `{}` | Merged into `ipc.kafka` (e.g. SASL/TLS). |
| `minion.credentials.*` | `minion`/`minion` | Stored in a chart Secret, or point `existingSecret` at your own. |

The Minion config is rendered into `minion-config.yaml` (the confd-driven config
the `opennms/minion` image reads at `/opt/minion/minion-config.yaml`). The
`ipc.kafka` block selects the Kafka strategy for sink + RPC + twin channels.

## Verifying

```bash
# nl6 came up and created devices
kubectl -n nl6 exec deploy/nl6-lab-nl6-minion -c nl6 -- \
  wget -qO- http://127.0.0.1:8080/api/v1/version

# Minion registered (in OpenNMS UI: Admin > Manage Minions, or REST):
curl -u minion:s3cret http://<core>:8980/opennms/rest/minions
```

Then provision a device (e.g. `10.42.0.1`) against location `nl6-lab` and watch
the Minion collect SNMP from the simulated fleet.

## Caveats / version notes

- **Minion image version.** Pin `minion.image.tag` to **your** OpenNMS
  Horizon/Meridian version — Minion and core must be compatible.
- **Credential injection.** This chart passes REST credentials via the
  `OPENNMS_HTTP_USER` / `OPENNMS_HTTP_PASS` env vars. Some Minion versions
  instead expect credentials seeded into the secure-credentials vault via
  `bin/scvcli`. If auth fails, exec into the `minion` container and run:
  `/opt/minion/bin/scvcli set opennms.http <user> <pass>` — then verify which
  mechanism your image build honours.
- **Kafka topics.** Ensure the core and Minion agree on the Kafka topic prefix
  (`org.opennms.instance.id`); set it under `minion.kafka.extraProperties` or
  `minion.extraConfig` if your core uses a non-default instance id.
- **Cleanup on evict.** A non-graceful pod kill can leave the host `nl6sim`
  netns / veth / FORWARD rule behind (see `docs/ops/troubleshooting.md`).
  Prefer `helm uninstall` + graceful pod termination.

## Uninstall

```bash
helm uninstall nl6-lab -n nl6
```
