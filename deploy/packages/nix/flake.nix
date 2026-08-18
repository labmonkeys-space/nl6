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
        let
          pkgs = nixpkgs.legacyPackages.${system};
          # TEMPORARY toolchain override: go.mod requires Go >= 1.26.6
          # (GO-2026-6089/6090 net/http + crypto/tls fixes), but nixpkgs still
          # lags behind. Build the toolchain from the official source tarball
          # (checksum from go.dev/dl) until nixpkgs catches up, then DELETE
          # this override and pass plain pkgs.buildGo126Module to package.nix
          # again. The first build compiles Go itself (~10 min); Cachix caches
          # it afterwards.
          go_1_26_6 = pkgs.go_1_26.overrideAttrs (old: {
            version = "1.26.6";
            src = pkgs.fetchurl {
              url = "https://go.dev/dl/go1.26.6.src.tar.gz";
              hash = "sha256-oHIcVMaIkBRI13rZs+x+p8R0cwdV/4kTgukuy5P/LLE=";
            };
          });
          buildGo126Module = pkgs.buildGo126Module.override { go = go_1_26_6; };
        in {
          # The version lives in package.nix and is bumped per release (see
          # RELEASING.md), so the Nix build reports the same X.Y.Z as the
          # deb/rpm/Docker artifacts at a tagged release. A flake cannot derive
          # the git tag itself (no `self.tag`), so this is a hardcoded string;
          # release.yml asserts it matches the tag.
          nl6 = pkgs.callPackage ./package.nix { inherit buildGo126Module; };
          default = self.packages.${system}.nl6;
        });

      # NixOS module: import this and set `services.nl6.enable = true;`.
      nixosModules.nl6 = import ./module.nix;
      nixosModules.default = self.nixosModules.nl6;
    };
}
