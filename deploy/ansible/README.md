# labmonkeys.nl6

Ansible collection to install and run the [nl6](https://github.com/labmonkeys-space/nl6) network simulator from its native `.deb` package under systemd.

## Roles

- `nl6`: downloads and verifies the release package, installs it with apt, sets the sysctls, writes `/etc/nl6/nl6.conf` and runs `nl6.service`. See [roles/nl6/README.md](roles/nl6/README.md).

## Install

Install by git tag:

```bash
ansible-galaxy collection install 'git+https://github.com/labmonkeys-space/nl6.git#/deploy/ansible,vX.Y.Z'
```

Or in `requirements.yml`:

```yaml
collections:
  - name: https://github.com/labmonkeys-space/nl6.git#/deploy/ansible
    type: git
    version: vX.Y.Z
```

The collection version always equals the nl6 release. Collection `0.36.0` runs nl6 `v0.36.0` by default.

## Development

Lint the collection and run the role checks from the repository root:

```bash
make check-ansible
```

If the default `python3` is newer than ansible-core 2.21 supports, pick another interpreter:

```bash
make check-ansible ANSIBLE_PYTHON=python3.12
```
