# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
{ lib
, buildGo127Module  # go.mod requires Go >= 1.27.0
, makeWrapper
, iproute2
, iptables
, procps
  # Single source of truth for the Nix package version. Bump on each release
  # (see RELEASING.md "Before you tag"); release.yml asserts it equals the tag.
, version ? "0.28.0"
}:

buildGo127Module {
  pname = "nl6";
  inherit version;

  # Only the Go module (./go) feeds the build — scoping the source here keeps
  # node_modules/.git/dist out of the store and avoids rebuilds on doc-only
  # changes. Root is the repo (three levels up from deploy/packages/nix).
  src = lib.fileset.toSource {
    root = ../../..;
    fileset = ../../../go;
  };

  # The Go module lives in ./go and the main package in ./go/nl6.
  modRoot = "go";
  subPackages = [ "nl6" ];

  # Hash of the vendored Go module set. MUST be recomputed after any
  # go.mod/go.sum change — a stale hash makes Nix substitute the previous
  # cached vendor tree, which then fails the build with "inconsistent
  # vendoring" (this is what a Dependabot go.mod bump breaks). Refresh with
  # `make nix-vendor-hash` (works via Docker, no local Nix needed), or set
  # this to lib.fakeHash, run `nix build`, and copy the printed "got:" value.
  # The Nix Cache workflow also prints the expected hash when its PR build
  # fails for this reason, and both its legs are required status checks on
  # main, so a stale hash blocks the merge. On a Dependabot go_modules PR the
  # Dependabot vendorHash workflow pushes the corrected value onto the branch
  # by itself.
  vendorHash = "sha256-K1ArQV36fzvZddFO9LTeiF7tFKLgSqGzuMhfN3WlA7U=";

  ldflags = [ "-s" "-w" "-X main.Version=v${version}" ];

  # The simulator uses Linux-only syscalls (TUN, network namespaces); its
  # tests require root and a live netns, so they cannot run in the sandbox.
  doCheck = false;

  nativeBuildInputs = [ makeWrapper ];

  # nl6 loads resources/ and web/ relative to its working directory. Ship them
  # under share/nl6 (the NixOS module sets WorkingDirectory there), and put
  # `ip`, `iptables`, and `sysctl` on the binary's PATH.
  # Paths are relative to modRoot (go/), which is the cwd in this phase.
  postInstall = ''
    mkdir -p $out/share/nl6
    cp -r nl6/resources $out/share/nl6/resources
    cp -r nl6/web $out/share/nl6/web

    wrapProgram $out/bin/nl6 \
      --prefix PATH : ${lib.makeBinPath [ iproute2 iptables procps ]}
  '';

  meta = with lib; {
    description = "Network device simulator (SNMP/SSH/HTTPS/gNMI/NetFlow/syslog)";
    homepage = "https://nl6.eu";
    license = licenses.asl20;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "nl6";
  };
}
