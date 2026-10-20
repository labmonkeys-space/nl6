<!--
Copyright 2026 Ronny Trommer <ronny@no42.org>
SPDX-License-Identifier: Apache-2.0
-->
# nl6 role

Installs nl6 from the native release package and runs the packaged `nl6.service`.
The role downloads `nl6_<version>_<arch>.deb` from the GitHub release, verifies it against the release `checksums.txt` and installs it with apt, so `iproute2`, `iptables` and `procps` resolve as package dependencies.
It then writes `/etc/nl6/nl6.conf` and enables the service.
Targets Ubuntu 24.04 and 26.04 on amd64 and arm64.

## Variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `nl6_version` | `0.36.0` | nl6 release without the `v`. Matches the collection version. |
| `nl6_package_url` | `""` | Download URL of the `.deb`, for an air-gapped host or a local mirror. Replaces the GitHub release URL. |
| `nl6_package_checksum` | `""` | `sha256:<hex digest>` of the `.deb`. Required when `nl6_package_url` is set, ignored otherwise. |
| `nl6_web_port` | `8080` | REST API port. |
| `nl6_gnmi_tls` | `true` | The gNMI dial-in listener (port 9339) is TLS-only. Set `false` for a plaintext collector. |
| `nl6_net_interface` | `""` | Required. Host NIC facing the simulated network. The role fails if it does not exist. |
| `nl6_pyroscope_url` | `""` | Adds `-profiling-pyroscope=<url>` when set. |
| `nl6_extra_args` | `[]` | Extra CLI flags appended to `NL6_OPTS`. One flag or value per element. |

## Example

```yaml
- hosts: simulator
  become: true
  roles:
    - role: labmonkeys.nl6.nl6
      nl6_net_interface: enp2s0
```

## What the role guards against

- **Wrong interface.** With a bad `nl6_net_interface` the sysctls below land on nothing and device traffic is dropped silently. The role asserts the interface exists.
- **Unverified download.** The package is checked against the release `checksums.txt`. A custom `nl6_package_url` needs an explicit `nl6_package_checksum`.
- **Reverse-path filtering.** The role sets `net.ipv4.ip_forward=1` and `rp_filter=0` for `all` and for `nl6_net_interface`.
- **Crash loop.** `Restart=on-failure` turns a rejected argument into a restart loop while systemd reports "started". The role polls `/api/v1/version` for up to 60 s and fails if nl6 does not answer.
- **Unusable extra args.** See the `NL6_OPTS` limitation below.
- **Version bump.** See below.

## Things to know

### A version bump wipes the fleet

nl6 keeps devices in memory only.
The package postinstall runs `systemctl try-restart nl6.service`, so installing a different version restarts nl6 and every simulated device disappears.
The role reads the installed version with `dpkg-query` and prints a warning when nl6 is installed and active and the version differs from `nl6_version`.
Recreate the fleet through the API after a bump.

### Firewall rules

nl6 inserts `iptables -I FORWARD 1 -i <veth-host> -j ACCEPT` itself when it sets up its network namespace (`go/nl6/netns.go`, `addForwardAcceptRule`).
That covers traffic leaving the simulator namespace only.
Traffic from a collector to the devices relies on the FORWARD chain policy being ACCEPT, which is true on a stock Ubuntu cloud image.
Docker and ufw set the policy to DROP.
The role reads `iptables -S FORWARD` and fails when the policy is not ACCEPT.
On such a host, allow forwarding to and from the simulated network yourself, or set the policy, before running the role.
The role installs no firewall rules and no routes, so routing into the simulated network is up to you.

### Internet access

Each run fetches `checksums.txt` from github.com, so the host needs internet access.
Set `nl6_package_url` and `nl6_package_checksum` to use a mirror instead.

### Upgrading from the Docker-based role

The role removes `/etc/systemd/system/nl6.service` and `/etc/systemd/system/nl6-forward.service` when they exist, because they override the packaged unit.
It stops the old services first, which also wipes the fleet.
Remove the leftover container and image yourself if you want them gone.

### Check mode

The package install, the FORWARD policy check and the assert are skipped in check mode.

### `NL6_OPTS` word-splitting

The unit runs `nl6 $NL6_OPTS` with `EnvironmentFile=-/etc/nl6/nl6.conf`.
systemd splits the value on whitespace and has no quoting or escaping there.
An element of `nl6_extra_args` therefore cannot contain whitespace, and the role also rejects `"`, `$` and `%`, which break the quoted assignment or get expanded.
Pass each flag and each value as its own list element, for example `["-auto-count", "5"]`.
`nl6_pyroscope_url` is checked the same way.

### Config changes restart nl6

A change to `/etc/nl6/nl6.conf` restarts nl6 through a handler, which also wipes the fleet.

### Profiling

Push mode only.
Go allows one CPU profile at a time, so while the SDK pushes, a puller asking `/debug/pprof/profile` gets a 500.
