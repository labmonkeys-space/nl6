# Troubleshooting

Common failures during bring-up and how to recover. Flow-export-specific
issues live on their own page —
[Flow export (operator guide) → Flow troubleshooting](flow-export.md#flow-troubleshooting)
— because they cross into collector-side `rp_filter` and FORWARD-chain
territory.

## Common issues

### Permission denied
The simulator creates TUN interfaces and manages the `opensim` network
namespace; both require privileges. Run with `sudo` or use a container that
grants `CAP_NET_ADMIN` plus access to `/dev/net/tun` — see
[Docker](../getting-started/docker.md).

### Port conflicts
Something else is listening on `:8080` (the default control plane). Pick an
alternative with [`-port`](../reference/cli-flags.md#core-flags), e.g.
`-port 9090`.

### Privileged SNMP port
Port `161` requires root or `CAP_NET_BIND_SERVICE`. If you can't grant
either, run the simulator on a non-privileged port:

```bash
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 5 -snmp-port 1161
```

Then query it with `snmpwalk -v2c -c public -p 1161 …`.

### TUN module missing

```bash
sudo modprobe tun
```

If `modprobe` fails the host kernel may be missing TUN support entirely
(some minimal cloud images). Switch kernels or use a container host.

### High resource usage / file descriptors
Large fleets burn through the default `nofile` limit fast. Raise it well
above your device count before bring-up (each device opens several sockets):

```bash
ulimit -n 1048576          # current shell
# persistent: raise LimitNOFILE on the systemd unit, or nofile in
# /etc/security/limits.conf
```

Keep the `opensim` namespace enabled (default); running in the root
namespace with `-no-namespace` at scale drags `systemd-networkd` into
every interface change. See [Scaling](scaling.md).

### SNMP integer-encoding panics
Historical regression — fixed. If you see panics in ASN.1 encoding of
negative integer values on a tagged release, upgrade to a newer build.

## Debug commands

```bash
# Check TUN interfaces
ip addr show | grep sim
sudo ip netns exec opensim ip addr | grep sim

# Verify device processes (adjust port if using -snmp-port)
ss -tulpn | grep -E "(161|1161|22)"

# Monitor system resources
htop
```

## Log files

- **Application logs** — stdout / stderr. Redirect with shell plumbing when
  daemonising.
- **System logs** — `journalctl -u <service-name>` when run under systemd.
- **Web access logs** — built into the application and visible in the
  stdout stream.

## When the namespace is stuck

If the simulator dies without cleaning up (e.g. `kill -9`), the `opensim`
namespace and `veth-sim-host` / `veth-sim-ns` may linger. Tear them down
by hand:

```bash
sudo ip netns delete opensim
sudo ip link delete veth-sim-host
# iptables rule, if still present
sudo iptables -D FORWARD -i veth-sim-host -j ACCEPT 2>/dev/null
```

See [Network namespace](network-namespace.md) for the full bridge anatomy.
