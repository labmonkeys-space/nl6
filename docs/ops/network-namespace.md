# Network namespace

By default, nl6 runs every simulated device inside a dedicated Linux
network namespace named `opensim`. This page covers what that namespace
contains, why the simulator prefers it over the root namespace, and the
`rp_filter` / `FORWARD` knobs you may need to tune.

> **Note on the namespace name.** The literal `opensim` is intentionally
> stable across the project rename from `l8opensim` to `nl6`. Renaming the
> namespace would break operator scripts and rescue tooling that grep
> `ip netns list` for `opensim`, and would force every running deployment
> to migrate at upgrade time. Treat `opensim` as an operational identifier
> divorced from project branding.

## Why the namespace?

Running TUN interfaces directly in the host namespace leaks every simulated
device into `systemd-networkd`, `NetworkManager`, and any firewalld / UFW /
nftables policy that's installed. At 30k interfaces the overhead is not
subtle. The `opensim` namespace gives the simulator a clean room with a
single controlled bridge back to the host.

## Anatomy

- **Namespace:** `opensim` (created and torn down by the simulator).
- **Bridge:** a veth pair — `veth-sim-host` in the host namespace,
  `veth-sim-ns` inside `opensim`.
- **Host end:** `veth-sim-host` carries `10.254.0.1/30`.
- **Namespace end:** `veth-sim-ns` carries `10.254.0.2/30` and the
  namespace's default route points at `10.254.0.1`.
- **Per-device TUNs:** each simulated device gets a TUN interface inside
  the namespace with its configured IP address.

## iptables FORWARD rule

At startup the simulator runs:

```bash
iptables -I FORWARD 1 -i veth-sim-host -j ACCEPT
```

…and removes it on clean shutdown. The rule exists because hosts with
Docker installed default the `FORWARD` chain to `DROP`, which silently
blocks per-device flow-export UDP from reaching the collector. Without the
rule the simulator logs a warning and flows disappear on such hosts.

:::note[iptables is required on the host]
The container image ships `iptables` for this reason. Bare-metal
hosts need `iptables` (or `iptables-nft`) available and on the
simulator's `PATH`.
:::

See [Flow export (operator guide)](flow-export.md#prerequisites-for-per-device-source-ip)
for the full context — per-device source IPs route out of the namespace via
this FORWARD rule.

## Escape hatch: `-no-namespace`

Pass [`-no-namespace`](../reference/cli-flags.md#core-flags) to run
everything in the root namespace. Useful for one-off debugging. Don't use
this at scale — `systemd-networkd` interference will destroy throughput.

## Inspecting the namespace

```bash
# List namespaces
ip netns list

# Interface inventory inside the namespace
sudo ip netns exec opensim ip addr

# Routing table inside the namespace
sudo ip netns exec opensim ip route

# Verify reachability to a collector from inside the namespace
sudo ip netns exec opensim ip route get 192.168.1.10

# ICMP reachability (useful while debugging flow export)
sudo ip netns exec opensim ping -c 1 192.168.1.10
```

## `rp_filter`

Reverse-path filtering in the kernel can silently drop packets whose source
IP isn't reachable back through the receiving interface. Two sides are
relevant:

- **Simulator side.** The simulator auto-configures `rp_filter` and
  `forwarding` sysctls inside the namespace and on `veth-sim-host`. No user
  action needed.
- **Collector side.** On the machine receiving flow packets, `rp_filter`
  may need to be relaxed per-interface because the packets carry
  simulator-device source IPs (e.g. `10.0.0.x`) that the collector has no
  route back to:

```bash
sudo sysctl -w net.ipv4.conf.all.rp_filter=2
sudo sysctl -w net.ipv4.conf.<iface>.rp_filter=2
```

`2` is loose mode; `0` disables filtering entirely.

## When bring-up fails

See [Troubleshooting](troubleshooting.md) for common failures — missing
`iptables` binary, TUN module not loaded, namespace already present from a
previous run, and veth-pair cleanup edge cases.
