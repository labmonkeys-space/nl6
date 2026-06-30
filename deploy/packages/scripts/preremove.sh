#!/bin/sh
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# Runs before removal on both Debian (prerm) and RHEL (preun). Stop and
# disable the service only on a true removal, never on an upgrade — Debian
# passes "upgrade" as $1, RHEL passes the remaining-version count (1 on
# upgrade, 0 on final removal).
set -e

if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop nl6.service >/dev/null 2>&1 || true
        systemctl disable nl6.service >/dev/null 2>&1 || true
    fi
fi

exit 0
