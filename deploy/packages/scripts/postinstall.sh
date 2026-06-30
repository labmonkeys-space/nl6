#!/bin/sh
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# Runs after install/upgrade on both Debian (postinst) and RHEL (post).
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # On upgrade, pick up the new binary if the service is already running.
    # try-restart is a no-op when the unit is stopped, so fresh installs are
    # unaffected — only a running instance is restarted.
    systemctl try-restart nl6.service >/dev/null 2>&1 || true
fi

# The service is not enabled or started automatically: it requires root and
# operator-chosen flags in /etc/nl6/nl6.conf. Enable it when ready:
#   sudo systemctl enable --now nl6
exit 0
