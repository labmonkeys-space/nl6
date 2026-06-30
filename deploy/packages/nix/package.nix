# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
{ lib
, buildGo126Module  # go.mod requires Go >= 1.26.4
, makeWrapper
, iproute2
, iptables
, procps
  # Single source of truth for the Nix package version. Bump on each release
  # (see RELEASING.md "Before you tag"); release.yml asserts it equals the tag.
, version ? "0.13.0"
}:

buildGo126Module {
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

  # Hash of the vendored Go module set. Recompute after any go.mod/go.sum
  # change: set this to lib.fakeHash, run `nix build`, copy the printed
  # "got:" value back here.
  vendorHash = "sha256-OqP7IeUiIg3vGJuGyvdykBWiHQBtOP41VTw8IhHOuZI=";

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
    homepage = "https://github.com/labmonkeys-space/nl6";
    license = licenses.asl20;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "nl6";
  };
}
