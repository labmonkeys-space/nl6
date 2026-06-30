# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
{ config, lib, pkgs, ... }:

let
  cfg = config.services.nl6;
in
{
  options.services.nl6 = {
    enable = lib.mkEnableOption "the nl6 network device simulator";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The nl6 package to run.";
    };

    extraFlags = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "-port" "8080" ];
      example = [ "-port" "8080" "-auto-start-ip" "10.42.0.1" "-auto-count" "100" ];
      description = "Command-line flags passed to nl6. See `nl6 -help`.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.nl6 = {
      description = "nl6 network device simulator";
      documentation = [ "https://github.com/labmonkeys-space/nl6" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      # `ip`, `iptables`, and `sysctl` are invoked by the simulator.
      path = [ pkgs.iproute2 pkgs.iptables pkgs.procps ];

      serviceConfig = {
        # Root is required for TUN interfaces, the nl6sim netns, and iptables.
        ExecStart = "${lib.getExe cfg.package} ${lib.escapeShellArgs cfg.extraFlags}";
        # resources/ and web/ are resolved relative to the working directory.
        WorkingDirectory = "${cfg.package}/share/nl6";
        Restart = "on-failure";
        RestartSec = 5;
        LimitNOFILE = 1048576;
      };
    };
  };
}
