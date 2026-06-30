# Install packages

Prebuilt native packages let you install nl6 with your system package manager
and run it as a managed `systemd` service — no Go toolchain or source checkout
required.

| Platform | Format | Package manager |
| --- | --- | --- |
| Debian, Ubuntu | `.deb` | `apt` |
| CentOS Stream, Rocky Linux, AlmaLinux | `.rpm` | `dnf` |
| NixOS | flake | `nix` |

Both `amd64` and `arm64` builds are published. The `.deb`/`.rpm` packages are
attached to each [GitHub Release](https://github.com/labmonkeys-space/nl6/releases/latest);
NixOS consumes the flake directly from the repository.

## What the package installs

| Path | Contents |
| --- | --- |
| `/usr/bin/nl6` | the simulator binary |
| `/usr/share/nl6/resources/` | device resource data (SNMP/SSH/REST) |
| `/usr/share/nl6/web/` | web console assets |
| `/usr/lib/systemd/system/nl6.service` | the systemd unit |
| `/etc/nl6/nl6.conf` | flag file (`NL6_OPTS`), preserved across upgrades |

:::info[Runtime requirements]
The simulator runs as **root** — it creates TUN interfaces, manages the
`nl6sim` network namespace, and installs an iptables rule. The `iproute2`
(`ip`), `iptables`, and `procps` (`sysctl`) dependencies are pulled in
automatically by `apt`/`dnf`.
:::

## Debian / Ubuntu (`.deb`)

Tested on Debian 13 and Ubuntu 26.04 LTS (`amd64` and `arm64`).

1. Download the `.deb` for your architecture from the
   [latest release](https://github.com/labmonkeys-space/nl6/releases/latest) —
   `nl6_<version>_amd64.deb` or `nl6_<version>_arm64.deb`.

2. Install it (the leading `./` tells `apt` it is a local file, so it still
   resolves dependencies):

   ```bash
   sudo apt install ./nl6_<version>_amd64.deb
   ```

3. Continue with [Configure and start the service](#configure-and-start-the-service).

## CentOS Stream / Rocky / AlmaLinux (`.rpm`)

Tested on CentOS Stream 10, Rocky Linux 10, and AlmaLinux 10 (`amd64` and
`arm64`).

1. Download the `.rpm` for your architecture from the
   [latest release](https://github.com/labmonkeys-space/nl6/releases/latest) —
   `nl6-<version>-1.x86_64.rpm` or `nl6-<version>-1.aarch64.rpm`.

2. Install it:

   ```bash
   sudo dnf install ./nl6-<version>-1.x86_64.rpm
   ```

3. Continue with [Configure and start the service](#configure-and-start-the-service).

## Configure and start the service

The package installs the `nl6` systemd unit but does **not** enable or start it
automatically — the simulator needs root and operator-chosen flags first. These
steps are the same on Debian/Ubuntu and the RHEL family.

1. Set the flags. `NL6_OPTS` is passed verbatim to `nl6`; see the
   [CLI flags reference](../reference/cli-flags.md) for the full list.

   ```bash
   sudoedit /etc/nl6/nl6.conf
   ```

   ```ini
   # /etc/nl6/nl6.conf
   NL6_OPTS="-port 8080 -auto-start-ip 10.42.0.1 -auto-count 100"
   ```

2. Enable on boot and start now:

   ```bash
   sudo systemctl enable --now nl6
   ```

3. Verify it is running:

   ```bash
   systemctl status nl6
   journalctl -u nl6 -f                 # follow logs
   nl6 -version                         # prints the installed version
   curl -s localhost:8080/api/v1/version
   ```

After editing `/etc/nl6/nl6.conf`, apply changes with
`sudo systemctl restart nl6`.

:::tip[Running without the service]
`nl6` loads `resources/` and `web/` relative to its working directory, so to run
it by hand (instead of via the service) start it from the data directory:

```bash
cd /usr/share/nl6 && sudo nl6 -port 8080
```
:::

### Upgrading and removing

```bash
# Upgrade (a running service is restarted automatically onto the new binary)
sudo apt install ./nl6_<new-version>_amd64.deb     # Debian/Ubuntu
sudo dnf upgrade ./nl6-<new-version>-1.x86_64.rpm   # RHEL family

# Remove (your /etc/nl6/nl6.conf is left in place)
sudo apt remove nl6                                 # Debian/Ubuntu
sudo dnf remove nl6                                 # RHEL family
```

## NixOS (flake)

nl6 ships a flake exposing a package and a NixOS module. The recommended way to
run it on NixOS is the **module**, which wires up the service with the correct
working directory and runtime tools.

1. Add the flake input and enable the service in your system flake:

   ```nix
   {
     inputs.nl6.url = "github:labmonkeys-space/nl6?dir=deploy/packages/nix";

     outputs = { self, nixpkgs, nl6 }: {
       nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
         system = "x86_64-linux";
         modules = [
           nl6.nixosModules.nl6
           {
             services.nl6 = {
               enable = true;
               extraFlags = [ "-port" "8080" "-auto-start-ip" "10.42.0.1" "-auto-count" "100" ];
             };
           }
         ];
       };
     };
   }
   ```

2. Rebuild: `sudo nixos-rebuild switch`. The service is now managed by systemd
   (`systemctl status nl6`).

To build just the binary (for example to test it), enable the prebuilt
[binary cache](https://app.cachix.org/cache/nl6) first so Nix substitutes
instead of compiling:

```bash
cachix use nl6
nix build "github:labmonkeys-space/nl6?dir=deploy/packages/nix#nl6"
```

## Building the packages yourself

If a release does not yet carry packages for your platform, or you want to build
from a specific commit, produce them locally with `make packages` (needs Go;
nfpm is fetched automatically):

```bash
make packages          # → dist/*.deb and dist/*.rpm for amd64 + arm64
```

Full packaging reference — layout, `nfpm.yaml`, the NixOS flake/module, the
Cachix cache, and the container-based install smoke test — lives in
[`deploy/packages/README.md`](https://github.com/labmonkeys-space/nl6/blob/main/deploy/packages/README.md).

## See also

- [Docker](./docker.md) — run the published container image instead.
- [Quick start](./quick-start.md) — build and run from source.
- [CLI flags](../reference/cli-flags.md) — everything you can put in `NL6_OPTS`.
