<!--
Copyright 2026 Ronny Trommer <ronny@no42.org>
SPDX-License-Identifier: Apache-2.0
-->
# nl6 OS packages

Native install packages for nl6:

| Distro family                         | Format  | Built by                  |
| ------------------------------------- | ------- | ------------------------- |
| Debian, Ubuntu                        | `.deb`  | nfpm (`make packages`)    |
| CentOS, Rocky Linux, AlmaLinux        | `.rpm`  | nfpm (`make packages`)    |
| NixOS                                 | flake   | `nix build` (`./nix/`)    |

Each `.deb` / `.rpm` is built for both `amd64` and `arm64`.

## What gets installed

| Path                                | Contents                                              |
| ----------------------------------- | ----------------------------------------------------- |
| `/usr/bin/nl6`                      | the simulator binary                                  |
| `/usr/share/nl6/resources/`         | device resource JSON (SNMP/SSH/REST response data)    |
| `/usr/share/nl6/web/`               | web console assets                                    |
| `/usr/lib/systemd/system/nl6.service` | systemd unit (runs as root, `WorkingDirectory` set) |
| `/etc/nl6/nl6.conf`                 | `NL6_OPTS` flag file (preserved across upgrades)      |

> **Why `/usr/share/nl6`?** nl6 loads `resources/` and `web/` from paths
> relative to its working directory, so the unit sets
> `WorkingDirectory=/usr/share/nl6`.

### Runtime requirements

- **root** — the simulator creates TUN interfaces, manages the `nl6sim`
  network namespace, and installs iptables rules.
- `iproute2` (`ip`), `iptables`, and `procps` (`sysctl`) — declared as package
  dependencies (`iproute` / `procps-ng` on the RHEL family).

## Building the deb/rpm packages

```sh
# Requires Go (to fetch the pinned nfpm) — no dpkg/rpmbuild toolchain needed.
make packages          # → dist/nl6_<version>_amd64.deb, ...arm64.rpm, etc.
```

`make packages` cross-compiles the release binaries (`make dist`), installs the
pinned nfpm, then runs it once per (arch, format) against
[`nfpm.yaml`](nfpm.yaml). The version is `APP_VERSION` (defaults to
`git describe --tags`); override it explicitly with `make packages APP_VERSION=v1.2.3`.

In CI, `.github/workflows/release.yml` runs `make packages` on every
`vX.Y.Z` tag and attaches the `.deb` / `.rpm` files to the GitHub Release.

## Smoke-testing the packages

`make smoke` builds the packages, then installs the host-arch `.deb` / `.rpm`
in clean distro containers and asserts the result — dependencies resolve, the
binary runs (`nl6 -version`), `resources/` + `web/` + the unit + config land in
the right paths, and the systemd unit parses. Requires Docker.

```sh
make smoke
# Override the matrix if needed:
make smoke SMOKE_DEB_IMAGES="debian:12" SMOKE_RPM_IMAGES="rockylinux:9"
```

Default matrix: `debian:13`, `ubuntu:26.04` (deb) and
`quay.io/rockylinux/rockylinux:10`, `almalinux:10`,
`quay.io/centos/centos:stream10` (rpm). The
[`smoke-test.sh`](smoke-test.sh) helper can also be run against a single
package + image directly. CI runs `make smoke` (amd64) via
`.github/workflows/packages.yml` on packaging changes.

> The smoke test covers **installation**, not a full simulator run — nl6 needs
> root + TUN + network namespaces, which a throwaway container does not provide.
> `nl6 -version` exits before any of that, so it is the right liveness probe.

## Installing

```sh
# Debian / Ubuntu
sudo apt install ./nl6_<version>_amd64.deb

# CentOS / Rocky / Alma
sudo dnf install ./nl6-<version>.x86_64.rpm
```

Then configure flags and start the service:

```sh
sudoedit /etc/nl6/nl6.conf          # set NL6_OPTS
sudo systemctl enable --now nl6
systemctl status nl6
journalctl -u nl6 -f
```

The service is **not** auto-enabled on install — it needs root and operator-chosen
flags first.

### Running manually (without the service)

Because `resources/` and `web/` are resolved relative to the working directory:

```sh
cd /usr/share/nl6 && sudo nl6 -port 8080
```

## NixOS

The flake under [`nix/`](nix/) exposes a package and a NixOS module.

```nix
# flake.nix
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

Or build the binary directly:

```sh
nix build github:labmonkeys-space/nl6?dir=deploy/packages/nix#nl6
```

### Binary cache (Cachix)

The flake builds from source, which is slow. A [Cachix](https://www.cachix.org/)
binary cache lets `nix build` substitute prebuilt paths instead of compiling.
`.github/workflows/nix-cache.yml` builds the `nl6` closure for `x86_64-linux`
and `aarch64-linux` on every push to `main`/tags and pushes it to the cache.

**Consumer** — once the cache is live, opt in either way:

```sh
cachix use nl6                    # writes substituter + public key to nix.conf
# ...then the normal build is now cache-accelerated:
nix build github:labmonkeys-space/nl6?dir=deploy/packages/nix#nl6
```

Or, with the `nixConfig` block in `flake.nix` uncommented, pass
`--accept-flake-config` and Nix uses the cache automatically.

**Maintainer one-time setup** (the CI job skips with a notice until this is done):

1. Create a cache at [app.cachix.org](https://app.cachix.org) (e.g. `nl6`).
2. `cachix authtoken` → add the value as the repo secret **`CACHIX_AUTH_TOKEN`**
   (Settings → Secrets and variables → Actions). The workflow pushes only on
   `main`/tags, never on fork PRs, so the write token is never exposed.
3. Copy the cache's **public key** from the Cachix UI, then:
   - uncomment the `nixConfig` block in [`nix/flake.nix`](nix/flake.nix) and
     paste the cache name + public key, and
   - if you named the cache something other than `nl6`, update `CACHIX_NAME` in
     `nix-cache.yml`.

Cachix's free open-source tier (5 GB) is ample — only nl6's own built paths are
stored; everything else comes from `cache.nixos.org`.

### Maintaining `vendorHash` and `version`

[`nix/package.nix`](nix/package.nix) pins a concrete `vendorHash` for the
vendored Go modules, so a clean checkout builds without extra steps. **Recompute
it whenever `go.mod` / `go.sum` changes**: set `vendorHash = lib.fakeHash`, run
`nix build`, and copy the printed `got:` value back in.

Bump the `version` argument in `package.nix` on each release so `nl6 -version`
and the store path track the tag.
