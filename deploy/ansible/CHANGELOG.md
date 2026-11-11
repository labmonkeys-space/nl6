# Changelog

## 0.40.2

- No role changes. The collection version follows the nl6 0.40.2 release.

## 0.40.1

- No role changes. The collection version follows the nl6 0.40.1 release.

## 0.40.0

- No role changes. The collection version follows the nl6 0.40.0 release.

## 0.39.0

- **Breaking:** the role refuses every platform it is not tested on.
  It installs the `.deb` only on Debian 13, Ubuntu 24.04 and Ubuntu 26.04, and the `.rpm` only on CentOS Stream, Rocky Linux and AlmaLinux 10.
  Debian 12, Ubuntu 22.04, interim Ubuntu releases such as 24.10, and derivatives such as Linux Mint and Oracle Linux now fail before the download.
  Install the package by hand on those hosts.
- The role metadata lists Debian 13 (`trixie`) next to Ubuntu 24.04 and 26.04, matching the docs, and the unsupported-platform message names Debian 13, Ubuntu 24.04 and 26.04, and EL 10.

## 0.38.1

- No role changes. The collection version follows the nl6 0.38.1 release.

## 0.38.0

- No role changes. The collection version follows the nl6 0.38.0 release.

## 0.37.1

- No role changes. The collection version follows the nl6 0.37.1 release.

## 0.37.0

- Add the `nl6` role. It installs nl6 from the release `.deb` (checksum verified against `checksums.txt`), sets the sysctls, writes `/etc/nl6/nl6.conf` and runs the packaged `nl6.service`.
- The role fails when the iptables FORWARD policy is not ACCEPT. nl6 inserts a FORWARD ACCEPT rule for traffic leaving its veth and none for inbound traffic. Docker and ufw set the policy to DROP.
- Add `nl6_package_url` and `nl6_package_checksum` for an air-gapped host or a local mirror.
- `nl6_extra_args` elements may not contain whitespace, `"`, `$` or `%`, because systemd splits `NL6_OPTS` on whitespace without quoting.
- The collection version is kept in lockstep with the nl6 release.
- The role also installs on CentOS Stream 10, Rocky Linux 10 and AlmaLinux 10, from the release `.rpm` with dnf. A RedHat-family host other than EL 10, or a host outside the Debian and RedHat families, fails before the download.
- The role prints a WARNING when firewalld is active, because the iptables FORWARD check cannot see firewalld's policy.
