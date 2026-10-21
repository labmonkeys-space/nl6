# labmonkeys.nl6

Ansible collection to install and run the [nl6](https://github.com/labmonkeys-space/nl6) network simulator from its native `.deb` package under systemd.
Its `nl6` role downloads and verifies the release package, installs it with apt, sets the sysctls, writes `/etc/nl6/nl6.conf` and runs `nl6.service`.

Install by git tag:

```bash
ansible-galaxy collection install 'git+https://github.com/labmonkeys-space/nl6.git#/deploy/ansible,vX.Y.Z'
```

The collection version always equals the nl6 release.
For `requirements.yml`, the role variables, an example play and the caveats, see [Install with Ansible](https://nl6.eu/getting-started/ansible).

## Development

Lint the collection and run the role checks from the repository root:

```bash
make check-ansible
```

If the default `python3` is newer than ansible-core 2.21 supports, pick another interpreter:

```bash
make check-ansible ANSIBLE_PYTHON=python3.12
```
