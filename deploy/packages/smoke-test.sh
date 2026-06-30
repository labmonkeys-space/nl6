#!/usr/bin/env bash
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# Install a built nl6 package in a clean distro container and assert that the
# install is sane: dependencies resolved, binary runs, data and unit files land
# in the expected paths, and the systemd unit parses.
#
# Usage:
#   deploy/packages/smoke-test.sh <package-file> <docker-image>
#
# Examples:
#   deploy/packages/smoke-test.sh dist/nl6_0.13.0_arm64.deb       debian:12
#   deploy/packages/smoke-test.sh dist/nl6-0.13.0-1.aarch64.rpm   rockylinux:9
#
# The package arch must match the container arch (the host runs native
# containers; cross-arch needs emulation and is out of scope here).
set -euo pipefail

PKG="${1:?usage: smoke-test.sh <package-file> <docker-image>}"
IMAGE="${2:?usage: smoke-test.sh <package-file> <docker-image>}"

[ -f "$PKG" ] || { echo "smoke: package not found: $PKG" >&2; exit 1; }

PKG_DIR="$(cd "$(dirname "$PKG")" && pwd)"
PKG_BASE="$(basename "$PKG")"

echo "==> smoke: ${PKG_BASE} on ${IMAGE}"

# In-container assertions. $1 is the package basename under /work.
# shellcheck disable=SC2016
CONTAINER_SCRIPT='
set -eu
pkg="/work/$1"
. /etc/os-release

case "$pkg" in
  *.deb)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq "$pkg"
    ;;
  *.rpm)
    dnf install -y -q "$pkg"
    ;;
  *) echo "FAIL: unknown package type: $pkg"; exit 1 ;;
esac

fail() { echo "FAIL [$PRETTY_NAME]: $1"; exit 1; }

# Declared runtime dependencies must be pulled in by the package manager.
command -v ip       >/dev/null 2>&1 || fail "iproute2/iproute not installed (ip missing)"
command -v iptables >/dev/null 2>&1 || fail "iptables not installed"
command -v sysctl   >/dev/null 2>&1 || fail "procps/procps-ng not installed (sysctl missing)"

# Binary present, executable, and self-reports a version (no root, no side effects).
[ -x /usr/bin/nl6 ] || fail "/usr/bin/nl6 missing or not executable"
ver="$(/usr/bin/nl6 -version)"
[ -n "$ver" ] || fail "nl6 -version printed nothing"
echo "    nl6 -version => $ver"

# Runtime data and config in the expected layout.
[ -f /usr/lib/systemd/system/nl6.service ] || fail "systemd unit not installed"
[ -f /etc/nl6/nl6.conf ]                   || fail "/etc/nl6/nl6.conf not installed"
[ -d /usr/share/nl6/web ]                  || fail "web/ data not installed"
json="$(find /usr/share/nl6/resources -name "*.json" 2>/dev/null | wc -l)"
[ "$json" -gt 0 ] || fail "no resource JSON under /usr/share/nl6/resources"
echo "    resources: $json JSON files, web/ present"

# Best-effort unit-syntax check (systemd-analyze is absent on minimal images).
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify /usr/lib/systemd/system/nl6.service \
    || fail "systemd-analyze verify reported errors"
  echo "    systemd unit verified"
fi

echo "PASS [$PRETTY_NAME]: $1"
'

docker run --rm \
  -v "${PKG_DIR}:/work:ro" \
  "${IMAGE}" \
  bash -c "${CONTAINER_SCRIPT}" _ "${PKG_BASE}"
