# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
{
  description = "nl6 — network device simulator (SNMP/SSH/HTTPS/gNMI/NetFlow/syslog)";

  # Binary cache (Cachix) — see deploy/packages/README.md "Binary cache".
  # `nix build` substitutes prebuilt paths from here instead of compiling.
  # Consumers opt in with `--accept-flake-config` or `cachix use nl6`.
  nixConfig = {
    extra-substituters = [ "https://nl6.cachix.org" ];
    extra-trusted-public-keys = [ "nl6.cachix.org-1:nfaq8JEbMcARjzc/oPyNIrcQrXKe13phUtMg0RucnLA=" ];
  };

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          # Surface the real source revision so `nl6 -version` is honest rather
          # than a stale hardcoded tag. Falls back to package.nix's default when
          # built from a non-git source (e.g. a plain tarball).
          nl6 = pkgs.callPackage ./package.nix {
            version = self.shortRev or self.dirtyShortRev or "0.13.0-dev";
          };
          default = self.packages.${system}.nl6;
        });

      # NixOS module: import this and set `services.nl6.enable = true;`.
      nixosModules.nl6 = import ./module.nix;
      nixosModules.default = self.nixosModules.nl6;
    };
}
