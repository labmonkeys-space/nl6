#!/usr/bin/env bash
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# Version lockstep check for the labmonkeys.nl6 collection. Run from the repo root:
#   bash deploy/ansible/tests/check-version.sh
# galaxy.yml `version` must equal the role default `nl6_version`.
# With CHECK_RELEASE=1 both must also equal the nl6 release version:
#   CHECK_RELEASE=1 APP_VERSION=vX.Y.Z bash deploy/ansible/tests/check-version.sh
set -euo pipefail

galaxy=deploy/ansible/galaxy.yml
defaults=deploy/ansible/roles/nl6/defaults/main.yml

galaxy_version=$(sed -nE 's/^version:[[:space:]]*"?([^"[:space:]]+)"?[[:space:]]*$/\1/p' "$galaxy")
role_version=$(sed -nE 's/^nl6_version:[[:space:]]*"?([^"[:space:]]+)"?[[:space:]]*$/\1/p' "$defaults")

[ -n "$galaxy_version" ] || { echo "check-version: no version found in $galaxy"; exit 1; }
[ -n "$role_version" ] || { echo "check-version: no nl6_version found in $defaults"; exit 1; }

fail=0
if [ "$galaxy_version" != "$role_version" ]; then
  echo "check-version: galaxy.yml version '$galaxy_version' != nl6_version default '$role_version'"
  echo "               fix with: make set-ansible-version APP_VERSION=v$galaxy_version"
  fail=1
fi

if [ "${CHECK_RELEASE:-}" = 1 ]; then
  release=$(make --no-print-directory version)
  release=${release#v}
  for pair in "galaxy.yml version:$galaxy_version" "nl6_version default:$role_version"; do
    if [ "${pair#*:}" != "$release" ]; then
      echo "check-version: ${pair%%:*} '${pair#*:}' != nl6 release version '$release'"
      fail=1
    fi
  done
fi

[ "$fail" = 0 ] || exit 1
echo "check-version: collection version $galaxy_version in lockstep"
