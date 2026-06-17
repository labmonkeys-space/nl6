#!/usr/bin/env bash
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# provision.sh — stand up the 5-stage Clos fabric in a running nl6 instance.
#
# Creates the 12 fabric devices + 2 hosts, then loads the inter-device LLDP
# link graph from clos.json. Idempotency is nl6's concern: re-running re-POSTs
# the same IPs (nl6 rejects duplicates) and replaces the topology.
#
# Usage:
#   ./provision.sh                       # provision against $NL6_URL
#   NL6_URL=http://my-nl6:8080 ./provision.sh
#
# Topology (5-stage folded Clos / 3-tier fat-tree, two pods):
#   Tier 1  superspine  .100-.101  cisco_crs_x          (full mesh to all spines)
#   Tier 2  spine       .120-.123  arista_7280r3
#   Tier 3  leaf        .130-.133  cisco_catalyst_9500
#   hosts               .140-.141  linux_server
set -euo pipefail

NL6_URL="${NL6_URL:-http://localhost:8080}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOS_JSON="${SCRIPT_DIR}/clos.json"

# create_tier <start_ip> <count> <resource_file> <label>
create_tier() {
  local start_ip="$1" count="$2" resource="$3" label="$4"
  echo "  ${label}: ${count}× ${resource} starting at ${start_ip}"
  curl -fsS -X POST "${NL6_URL}/api/v1/devices" \
    -H 'Content-Type: application/json' \
    -d "{\"start_ip\":\"${start_ip}\",\"device_count\":${count},\"netmask\":\"24\",\"resource_file\":\"${resource}\"}"
  echo
}

echo "Provisioning 5-stage Clos fabric against ${NL6_URL} ..."
create_tier 10.42.0.100 2 cisco_crs_x.json          "superspines (Tier 1)"
create_tier 10.42.0.120 4 arista_7280r3.json        "spines      (Tier 2)"
create_tier 10.42.0.130 4 cisco_catalyst_9500.json  "leaves      (Tier 3)"
create_tier 10.42.0.140 2 linux_server.json         "hosts       "

echo "Loading topology from ${CLOS_JSON} ..."
curl -fsS -X POST "${NL6_URL}/api/v1/topology" \
  -H 'Content-Type: application/json' --data "@${CLOS_JSON}"
echo

echo "Done. Verify with: curl -s ${NL6_URL}/api/v1/topology/status"
