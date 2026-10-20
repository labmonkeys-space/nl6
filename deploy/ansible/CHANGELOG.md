# Changelog

## Unreleased

- Add the `nl6` role. It installs nl6 from the release `.deb` (checksum verified against `checksums.txt`), sets the sysctls, writes `/etc/nl6/nl6.conf` and runs the packaged `nl6.service`.
- BREAKING: nl6 no longer runs in Docker. The variables `nl6_image`, `nl6_install_docker` and `nl6_sim_network` are removed, and `nl6-forward.service` is gone. nl6 inserts only an outbound FORWARD ACCEPT rule for its veth. Inbound traffic needs the FORWARD policy to be ACCEPT, and the role fails when it is not (Docker and ufw set DROP).
- The role removes legacy `/etc/systemd/system/nl6.service` and `nl6-forward.service` left by the Docker-based role, after stopping them.
- Add `nl6_package_url` and `nl6_package_checksum` for an air-gapped host or a local mirror.
- `nl6_extra_args` elements may not contain whitespace, `"`, `$` or `%`, because systemd splits `NL6_OPTS` on whitespace without quoting.
- The collection version is kept in lockstep with the nl6 release.
