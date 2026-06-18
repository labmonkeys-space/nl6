#!/usr/bin/env bash
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# nl6-provision.sh — stand up a large k-ary fat-tree (folded 3-tier Clos) in a
# running nl6 instance. Defaults to k=20 → 2500 devices, 6000 LLDP links.
#
# Device tiers and the inter-device link graph both come from gen-clos.py (the
# single source of truth), so they can never drift. Override the fabric size
# with CLOS_K=<even int>.
#
# Usage:
#   ./nl6-provision.sh                          # provision against $NL6_URL
#   NL6_URL=http://my-nl6:8080 ./nl6-provision.sh
#   CLOS_K=8 ./nl6-provision.sh                 # a smaller fat-tree (208 devices)
set -euo pipefail

NL6_URL="${NL6_URL:-http://localhost:8080}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN="${SCRIPT_DIR}/gen-clos.py"

# create_tier <start_ip> <count> <resource_file> <label>. Uses a /16 netmask so
# the multi-/24 host range stays in one subnet.
create_tier() {
  local start_ip="$1" count="$2" resource="$3" label="$4"
  echo "  ${label}: ${count}× ${resource} starting at ${start_ip}"
  curl -fsS -X POST "${NL6_URL}/api/v1/devices" \
    -H 'Content-Type: application/json' \
    -d "{\"start_ip\":\"${start_ip}\",\"device_count\":${count},\"netmask\":\"16\",\"resource_file\":\"${resource}\"}" \
    -o /dev/null
}

# Run the generator up front and capture its output. A bare assignment from a
# failing command substitution trips `set -e`, so an invalid CLOS_K (or any
# generator error) aborts here — unlike a `< <(...)` process substitution, whose
# exit code the `while` loop would silently swallow, reporting "Done" with no
# devices created.
summary="$(python3 "${GEN}" summary)"
tiers="$(python3 "${GEN}" tiers)"

echo "Provisioning ${NL6_URL} — ${summary}"
echo "Creating device tiers (this can take a minute at 2500 devices) ..."
while IFS=$'\t' read -r start count resource label; do
  create_tier "${start}" "${count}" "${resource}" "${label}"
done <<< "${tiers}"

echo "Loading topology (POST /api/v1/topology) ..."
python3 "${GEN}" topology | curl -fsS -X POST "${NL6_URL}/api/v1/topology" \
  -H 'Content-Type: application/json' --data @- -o /dev/null

echo "Done. Verify with: curl -s ${NL6_URL}/api/v1/topology/status"
