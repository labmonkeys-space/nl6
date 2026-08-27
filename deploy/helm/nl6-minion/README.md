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

> [!CAUTION]
> **SECURITY WARNING:** This chart deploys a privileged pod with `hostNetwork: true`
> that can affect the Kubernetes node's network stack. It is intended **ONLY** for
> dedicated lab/test nodes, **NOT** for production clusters or shared multi-tenant
> environments. See the [Security Considerations](#security-considerations) section
> below for required mitigations.

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

## Security Considerations

This deployment requires dangerous privileges that weaken Kubernetes node isolation:

### Risks

1. **`hostNetwork: true`** — The pod shares the node's network namespace. Network
   operations performed by nl6 (route installation, sysctl writes, iptables rules,
   namespace creation) affect the **node**, not just the pod. An attacker with code
   execution in the simulator can interfere with node networking.

2. **`privileged: true`** — Grants unrestricted access to the host, including the
   ability to load kernel modules, access all devices, and bypass most security
   restrictions. Provides a plausible path to container escape and node compromise.

3. **`CAP_SYS_ADMIN` + `CAP_NET_ADMIN`** — Administrative capabilities that allow
   network namespace manipulation, iptables rules, and sysctls. `CAP_SYS_ADMIN` is
   effectively "new root" and can be used for privilege escalation.

4. **Unauthenticated HTTP API** — The nl6 HTTP API (default port 8080) has **no
   built-in authentication**. With `hostNetwork: true`, this port is exposed on
   the node's IP. Any client that can reach the node can trigger mutating operations
   including device creation, route manipulation, and network namespace changes.

5. **Host device access** — The `/dev/net/tun` hostPath mount provides direct
   access to the host's TUN/TAP device, which can be used for network manipulation
   independently of other privileges.

### Required Mitigations

**DO NOT deploy this chart without implementing ALL of the following:**

1. **Dedicated, isolated node** — Deploy only on a node that runs no other workloads.
   Use a separate node pool or dedicated lab machine. Set `nodeSelector` to pin the
   pod to this specific node (REQUIRED — the chart will fail without it).

2. **Node taints** — Apply a taint to the target node to prevent other pods from
   scheduling there:
   ```bash
   kubectl taint nodes <node> nl6-simulator=true:NoSchedule
   ```
   Then set `security.tolerations` in values.yaml to allow this pod to tolerate it.

3. **NetworkPolicy** — Enable `security.networkPolicy.enabled: true` and configure
   `security.networkPolicy.ingress` to restrict access to the nl6 API port (8080)
   to only authorized clients (e.g., your monitoring namespace). Requires a CNI
   that enforces NetworkPolicy (Calico, Cilium, Weave, etc.).

4. **Namespace isolation** — Deploy in a dedicated namespace with PodSecurity
   admission set to `privileged`:
   ```bash
   kubectl label namespace nl6 pod-security.kubernetes.io/enforce=privileged
   ```

5. **No external exposure** — Do NOT create a Service, Ingress, or LoadBalancer
   that exposes the nl6 API to networks outside the cluster. If external access
   is required, deploy an authenticating reverse proxy (e.g., oauth2-proxy, Pomerium)
   in front of it.

6. **Risk acknowledgment** — Set `security.acknowledgeRisks: true` in values.yaml
   to confirm you understand these risks. The deployment will fail without this
   explicit acknowledgment.

### Alternative: Non-privileged Mode (Experimental)

For environments that cannot tolerate `privileged: true`, you can try:
- Set `nl6.securityContext.privileged: false`
- Rely on explicit capabilities only (`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_NET_BIND_SERVICE`)
- Ensure your kernel and PodSecurity policy allow `/dev/net/tun` access via capabilities

This is not guaranteed to work in all environments and is not the tested configuration.

## Prerequisites

- A **dedicated node** you can pin the pod to (`nodeSelector`) that allows
  **privileged** pods and is isolated from other workloads. Label the target
  namespace:
  ```bash
  kubectl label ns <ns> pod-security.kubernetes.io/enforce=privileged
  ```
- `/dev/net/tun` present on that node (standard on Linux).
- A **Kafka** broker reachable from the node's host network (external or
  in-cluster Service — both work because of `hostNetwork`).
- An OpenNMS core with a **Monitoring Location** matching `minion.location`.
- A CNI that enforces **NetworkPolicy** (Calico, Cilium, Weave) if you want
  to restrict API access (recommended).

## Install

**Step 1:** Prepare the target node (replace `lab-node-01` with your node name):

```bash
# Taint the node to prevent other workloads from co-locating
kubectl taint nodes lab-node-01 nl6-simulator=true:NoSchedule

# Label the node for easy selection (optional but recommended)
kubectl label nodes lab-node-01 node-role.kubernetes.io/nl6-simulator=true
```

**Step 2:** Create a values file (`my-values.yaml`) with security acknowledgment:

```yaml
# REQUIRED: Acknowledge security risks
security:
  acknowledgeRisks: true  # I understand this deploys a privileged pod on a dedicated node
  
  # RECOMMENDED: Enable NetworkPolicy to restrict API access
  networkPolicy:
    enabled: true
    ingress:
      # Example: Allow only from monitoring namespace
      - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring

# REQUIRED: Pin to the dedicated node
nodeSelector:
  kubernetes.io/hostname: lab-node-01
  # Or use the role label:
  # node-role.kubernetes.io/nl6-simulator: "true"

# RECOMMENDED: Tolerate the node taint
tolerations:
  - key: nl6-simulator
    operator: Equal
    value: "true"
    effect: NoSchedule

# Configure Minion connection to OpenNMS core
minion:
  id: nl6-minion-01
  location: nl6-lab
  httpUrl: http://opennms-core.opennms.svc.cluster.local:8980/opennms
  kafka:
    bootstrapServers: kafka.kafka.svc.cluster.local:9092
  credentials:
    username: minion
    password: s3cret  # Use a real secret in production
```

**Step 3:** Install the chart:

```bash
helm install nl6-lab deploy/helm/nl6-minion \
  --namespace nl6 --create-namespace \
  -f my-values.yaml
```

Or with inline values (minimal example, **not recommended** — use a values file):

```bash
helm install nl6-lab deploy/helm/nl6-minion \
  --namespace nl6 --create-namespace \
  --set security.acknowledgeRisks=true \
  --set nodeSelector."kubernetes\.io/hostname"=lab-node-01 \
  --set minion.kafka.bootstrapServers=kafka.kafka.svc.cluster.local:9092 \
  --set minion.httpUrl=http://opennms-core.opennms.svc.cluster.local:8980/opennms \
  --set minion.location=nl6-lab \
  --set minion.credentials.username=minion \
  --set minion.credentials.password='s3cret'
```

## Key values

| Value | Default | Notes |
|-------|---------|-------|
| **`security.acknowledgeRisks`** | `false` | **REQUIRED.** Must be `true` to deploy. Confirms you understand the security risks. |
| **`security.networkPolicy.enabled`** | `false` | **RECOMMENDED.** Deploy a NetworkPolicy to restrict API access. |
| `security.networkPolicy.ingress` | `[]` | Ingress rules for the nl6 API. Default: deny all. See example above. |
| **`nodeSelector`** | `{}` | **REQUIRED.** Pins the pod to a dedicated node. Deployment fails if empty. |
| `tolerations` | `[]` | **RECOMMENDED.** Tolerate node taints (e.g., `nl6-simulator=true:NoSchedule`). |
| `nl6.args` | `-auto-start-ip 10.42.0.1 -auto-count 50 ...` | Device batch + HTTP port. |
| `nl6.securityContext.privileged` | `true` | Simplest grant for `/dev/net/tun` + caps. Set `false` for explicit-caps-only mode (experimental). |
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
curl -u ****cret http://<core>:8980/opennms/rest/minions
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
