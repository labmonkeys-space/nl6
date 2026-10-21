# Install with Ansible

The `labmonkeys.nl6` Ansible collection installs nl6 from its native `.deb` package and runs it under systemd.
Its one role, `nl6`, downloads `nl6_<version>_<arch>.deb` from the GitHub release and verifies it against the release `checksums.txt`.
It installs the package with apt, so `iproute2`, `iptables` and `procps` resolve as package dependencies.
It then sets the sysctls, writes `/etc/nl6/nl6.conf` and enables the packaged `nl6.service`.

The role targets Ubuntu 24.04 and 26.04 on amd64 and arm64.
It installs the same package as [Install packages](./install-packages.md).
It also sets the sysctls and runs the checks below, which the manual install leaves to you.

## Before you start

- **Pick the simulator interface.**
  `nl6_net_interface` is required.
  It names the host NIC that faces the simulated network, and the role fails if it does not exist.
- **Check the FORWARD policy.**
  Traffic from a collector to the simulated devices needs the iptables FORWARD policy to be ACCEPT.
  Docker and ufw set it to DROP, and the role fails then.
  See [Firewall rules](#firewall-rules).
- **Allow internet access, or use a mirror.**
  Each run fetches `checksums.txt` from github.com.
  See [Internet access](#internet-access).

## Install the collection

The collection lives in the nl6 repository under `deploy/ansible`.
Install it by git tag:

```bash
ansible-galaxy collection install 'git+https://github.com/labmonkeys-space/nl6.git#/deploy/ansible,vX.Y.Z'
```

Or list it in `requirements.yml`:

```yaml
collections:
  - name: https://github.com/labmonkeys-space/nl6.git#/deploy/ansible
    type: git
    version: vX.Y.Z
```

The collection version always equals the nl6 release.
Collection `X.Y.Z` runs nl6 `vX.Y.Z` by default.

Releases older than the collection have no `deploy/ansible` directory.
If `ansible-galaxy` reports that the path does not exist at your tag, that release predates the collection.
Install from `main` instead by replacing `vX.Y.Z` with `main`.

## Run the role

```yaml
- hosts: simulator
  become: true
  roles:
    - role: labmonkeys.nl6.nl6
      nl6_net_interface: enp2s0
```

The play ends by polling the nl6 API and prints the version that answered.

## Variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `nl6_version` | the collection version | nl6 release without the `v`. |
| `nl6_package_url` | `""` | Download URL of the `.deb`, for an air-gapped host or a local mirror. Replaces the GitHub release URL. |
| `nl6_package_checksum` | `""` | `sha256:<hex digest>` of the `.deb`. Required when `nl6_package_url` is set, ignored otherwise. |
| `nl6_web_port` | `8080` | REST API port. |
| `nl6_gnmi_tls` | `true` | The gNMI dial-in listener (port 9339) is TLS-only. Set `false` for a plaintext collector. |
| `nl6_net_interface` | `""` | Required. Host NIC facing the simulated network. The role fails if it does not exist. |
| `nl6_pyroscope_url` | `""` | Adds `-profiling-pyroscope=<url>` when set. |
| `nl6_extra_args` | `[]` | Extra [CLI flags](../reference/cli-flags.md) appended to `NL6_OPTS`. One flag or value per element. |

## What the role guards against

- **Wrong interface.**
  With a bad `nl6_net_interface` the sysctls below land on nothing and device traffic is dropped silently.
  The role asserts the interface exists.
- **Unverified download.**
  The package is checked against the release `checksums.txt`.
  A custom `nl6_package_url` needs an explicit `nl6_package_checksum`.
- **Reverse-path filtering.**
  The role sets `net.ipv4.ip_forward=1` and `rp_filter=0` for `all` and for `nl6_net_interface`.
- **Crash loop.**
  `Restart=on-failure` turns a rejected argument into a restart loop while systemd reports "started".
  The role polls `/api/v1/version` for up to 60 s and fails if nl6 does not answer.
- **Unusable extra args.**
  See [`NL6_OPTS` word-splitting](#nl6_opts-word-splitting).
- **Version bump.**
  See [A version bump wipes the fleet](#a-version-bump-wipes-the-fleet).

## Things to know

### A version bump wipes the fleet

nl6 keeps devices in memory only.
The package postinstall runs `systemctl try-restart nl6.service`, so installing a different version restarts nl6 and every simulated device disappears.
The role reads the installed version with `dpkg-query` and prints a warning when nl6 is installed and active and the version differs from `nl6_version`.
To keep the fleet, save it with [`fleet.sh export`](./fleet.md) before you change `nl6_version`.
Replay it with `fleet.sh import` after the play finishes.

### Config changes restart nl6

A change to `/etc/nl6/nl6.conf` restarts nl6 through a handler, which also wipes the fleet.

### Firewall rules

nl6 inserts a FORWARD ACCEPT rule for its own veth when it sets up its network namespace.
That rule covers traffic leaving the namespace only.
See [Network namespace](../ops/network-namespace.md#iptables-forward-rule) for the rule itself.
Traffic from a collector to the devices relies on the FORWARD chain policy being ACCEPT, which is true on a stock Ubuntu cloud image.
Docker and ufw set the policy to DROP.
The role reads `iptables -S FORWARD` and fails when the policy is not ACCEPT.
On such a host, allow forwarding to and from the simulated network yourself, or set the policy, before running the role.
The role installs no firewall rules and no routes, so routing into the simulated network is up to you.

### Internet access

Each run fetches `checksums.txt` from github.com, so the host needs internet access.
Set `nl6_package_url` and `nl6_package_checksum` to use a mirror instead.

### Check mode

In check mode the role skips the package install, the FORWARD policy read and the FORWARD policy assert.
The other asserts still run.

### `NL6_OPTS` word-splitting

The unit runs `nl6 $NL6_OPTS` with `EnvironmentFile=-/etc/nl6/nl6.conf`.
systemd splits the value on whitespace and has no quoting or escaping there.
An element of `nl6_extra_args` therefore cannot contain whitespace, and the role also rejects `"`, `$` and `%`, which break the quoted assignment or get expanded.
Pass each flag and each value as its own list element, for example `["-auto-count", "5"]`.
`nl6_pyroscope_url` is checked the same way.

### Profiling

The role configures push mode only.
Go allows one CPU profile at a time, so while the SDK pushes, a puller asking `/debug/pprof/profile` gets a 500.
See [Profiling](../ops/profiling.md).

## See also

- [Install packages](./install-packages.md) to install the same package by hand.
- [Fleet](./fleet.md) to export and replay a fleet across restarts.
- [CLI flags](../reference/cli-flags.md) for everything you can put in `nl6_extra_args`.
