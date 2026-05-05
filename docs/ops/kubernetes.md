# Kubernetes (not supported)

nl6 does not currently ship a supported Kubernetes deployment. This
page is the honest accounting of *why* — the simulator's design fights
Kubernetes' isolation model in several places, and the workarounds shift
the risk onto cluster operators rather than removing it.

If you need to run the simulator today, use bare-metal or
[Docker](../getting-started/docker.md) on a single host. Both are
documented and tested up to 30,000 devices.

## Why Kubernetes is out of scope

The simulator behaves more like a hypervisor than an application. It owns
host-level resources by name, mutates the host network stack, and has no
horizontal scaling story. Kubernetes pods, by contrast, are designed to be
isolated, replicable, and free to land on any node.

The conflicts fall into four buckets.

### 1. Privileges that approach `privileged: true`

Out of the box the simulator needs:

- `CAP_NET_ADMIN` — TUN device creation, link configuration, route
  installation.
- `CAP_SYS_ADMIN` — `setns(CLONE_NEWNET)` to enter the `opensim`
  namespace, plus the `ip netns` operations that depend on it.
- `CAP_NET_BIND_SERVICE` (or root) — bind UDP/161, UDP/162, UDP/514,
  TCP/22 on every device IP.
- `/dev/net/tun` mounted into the container.

`CAP_SYS_ADMIN` is effectively the "new root". Restricted-profile
PodSecurity admission will refuse this combination, so the namespace
hosting the simulator must be labelled `pod-security.kubernetes.io/enforce:
privileged`. On clusters where that label is centrally controlled (most
shared clusters), the simulator simply cannot run.

### 2. Host network mutation

The simulator does not just live inside a pod sandbox — it reaches out and
edits the host's network stack:

- Creates and removes the `opensim` network namespace.
- Installs a veth pair (`veth-sim-host` / `veth-sim-ns`) with a hardcoded
  CIDR (`10.254.0.0/30`).
- Inserts an iptables rule: `iptables -I FORWARD 1 -i veth-sim-host -j
  ACCEPT` (and removes it on clean shutdown).
- Writes sysctls: `net.ipv4.ip_forward=1`, `net.ipv4.conf.*.rp_filter=0`,
  `net.ipv4.conf.veth-sim-host.forwarding=1`.

Under `hostNetwork: true` (the only mode that makes device IPs reachable —
see point 4) those edits land on the **node**, not on a pod-local network
stack. They co-exist with kube-proxy's iptables chains and the CNI's
sysctls. The interaction is brittle: a CNI upgrade, a kube-proxy mode
switch, or another DaemonSet that resets sysctls on the node can silently
break per-device flow / trap / syslog egress without surfacing an error.

### 3. Singleton-on-node by design

Several names and addresses are hardcoded:

- Network namespace name: `opensim`
  (`go/nl6/netns.go` → `NETNS_NAME`).
- veth pair names: `veth-sim-host`, `veth-sim-ns`.
- veth bridge CIDR: `10.254.0.0/30`.

Two simulator instances on the same node will collide on all three. There
is no per-instance discriminator today, so a Deployment or StatefulSet with
`replicas: > 1` only works if every replica lands on a different node, and
even then they share the FORWARD-rule global side-effect.

That makes the workload effectively "this node *is* the simulator" —
which is at odds with the typical reason to use Kubernetes (workload
density, reschedulability, replicas).

### 4. Device CIDR is not cluster-routable

Each simulated device gets its own IP — by default in `10.42.0.0/16` — on
a TUN interface inside the `opensim` namespace on one node. From the
**host** of that node, traffic to those IPs routes via veth into the
namespace and reaches the device. From **any other pod or node** on the
cluster, `10.42.0.0/16` is unknown and unreachable.

The pollers and collectors that talk to simulated devices (OpenNMS,
Prometheus, flow / trap / syslog receivers) usually live elsewhere on the
cluster network. To make device IPs reachable from them you need one of:

- **Pin the consumer to the same node** with `nodeAffinity` and
  `hostNetwork: true`, so it shares the host's view. Works, but defeats
  most of the reason to put either workload in Kubernetes.
- **Multus** with a second pod NIC on a network that carries the device
  CIDR. Requires Multus installed and a bridge / VLAN configured at the
  node level.
- **Calico BGP** advertising the device CIDR from the simulator's node.
  Requires Calico in BGP mode, peering with the cluster's router, and
  cluster-admin coordination.

All three are real network engineering on the cluster operator's side —
not configuration the simulator can ship as a Helm chart.

## What it would take to make Kubernetes a first-class target

For completeness, the work that would put Kubernetes back on the roadmap:

| Area | Change |
|------|--------|
| Singleton names | Make `NETNS_NAME`, veth pair names, and bridge CIDR configurable per instance, so multiple simulators can co-exist on a node. |
| Host mutation | Move iptables / sysctl / netns setup into a separate init phase that can be done by a host-DaemonSet (or skipped when the host is pre-prepared), so the runtime container does not need `CAP_SYS_ADMIN`. |
| Routing story | Ship a tested recipe for one of Multus / Calico-BGP / hostNetwork co-location, with worked examples and reachability tests. |
| Lifecycle | Reconcile `terminationGracePeriodSeconds` against the FORWARD-rule and netns cleanup so a pod evict does not leak host state. |
| Manifest | A Helm chart and / or Kustomize base that declares the privileges, sysctls, fd limits, and node taints needed. |

None of this is conceptually hard. It is several weeks of focused work and
a non-trivial test surface — and the value depends on whether anyone
actually wants to run a hypervisor-shaped workload in Kubernetes rather
than on a dedicated lab host.

## What to use instead

- **Bare-metal Linux** — the canonical environment.
  [Quick start](../getting-started/quick-start.md),
  [Scaling](scaling.md).
- **Docker on a single host** — same privileges, isolated filesystem.
  [Docker](../getting-started/docker.md).

Both reach the documented 30k-device scale and exercise the same code
paths as a Kubernetes deployment would.
