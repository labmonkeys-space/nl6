# Changelog

## Unreleased

- Add the `nl6` role. It installs nl6 from the release `.deb` (checksum verified against `checksums.txt`), sets the sysctls, writes `/etc/nl6/nl6.conf` and runs the packaged `nl6.service`.
- The role fails when the iptables FORWARD policy is not ACCEPT. nl6 inserts a FORWARD ACCEPT rule for traffic leaving its veth and none for inbound traffic. Docker and ufw set the policy to DROP.
- Add `nl6_package_url` and `nl6_package_checksum` for an air-gapped host or a local mirror.
- `nl6_extra_args` elements may not contain whitespace, `"`, `$` or `%`, because systemd splits `NL6_OPTS` on whitespace without quoting.
- The collection version is kept in lockstep with the nl6 release.
