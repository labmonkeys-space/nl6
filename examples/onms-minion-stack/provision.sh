#!/usr/bin/env bash
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# provision.sh — one-shot bring-up for the onms-minion-stack:
#   1. wait for nl6's API
#   2. create the 5-stage Clos fabric WITH flow/trap/syslog exporters aimed at
#      the Minion (10.254.0.1, the veth host end inside nl6's shared namespace)
#   3. load the inter-device LLDP topology (reuses ../5-stage-clos/clos.json)
#   4. import the nodes into the OpenNMS core at location nl6-Lab (reuses
#      ../onms-provision.sh)
#
# Idempotent: nl6 rejects duplicate IPs and replaces the topology on re-POST.
set -euo pipefail

NL6_URL="${NL6_URL:-http://nl6:8080}"
COLLECTOR="${COLLECTOR:-10.254.0.1}"   # nl6 veth host end (Minion shares this netns)
FLOW_PORT="${FLOW_PORT:-4739}"
SYSLOG_PORT="${SYSLOG_PORT:-1514}"
TRAP_PORT="${TRAP_PORT:-1162}"
export NL6_URL

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CLOS_JSON="${EXAMPLES_DIR}/5-stage-clos/clos.json"
ONMS_PROVISION="${EXAMPLES_DIR}/onms-provision.sh"

# 1. Wait for nl6 (depends_on already gates on health; this is belt-and-suspenders).
echo "Waiting for nl6 at ${NL6_URL} ..."
for i in $(seq 1 60); do
  if curl -fsS "${NL6_URL}/api/v1/version" >/dev/null 2>&1; then
    echo "  nl6 is up."
    break
  fi
  if [ "${i}" -eq 60 ]; then
    echo "ERROR: nl6 did not become ready at ${NL6_URL}" >&2
    exit 1
  fi
  sleep 2
done

# 2. Create the four fabric tiers, each device exporting to the Minion.
create_tier() {
  local start_ip="$1" count="$2" resource="$3" label="$4"
  echo "  ${label}: ${count}x ${resource} @ ${start_ip} -> exports to ${COLLECTOR}"
  curl -fsS -X POST "${NL6_URL}/api/v1/devices" \
    -H 'Content-Type: application/json' \
    -d "$(cat <<JSON
{
  "start_ip": "${start_ip}",
  "device_count": ${count},
  "netmask": "24",
  "resource_file": "${resource}",
  "flow":   {"collector": "${COLLECTOR}:${FLOW_PORT}",   "protocol": "ipfix"},
  "traps":  {"collector": "${COLLECTOR}:${TRAP_PORT}",   "mode": "trap"},
  "syslog": {"collector": "${COLLECTOR}:${SYSLOG_PORT}", "format": "5424"}
}
JSON
)" -o /dev/null
}

echo "Creating the 5-stage Clos fabric (exports -> Minion @ ${COLLECTOR}) ..."
create_tier 10.42.0.100 2 cisco_crs_x.json          "superspines (Tier 1)"
create_tier 10.42.0.120 4 arista_7280r3.json        "spines      (Tier 2)"
create_tier 10.42.0.130 4 cisco_catalyst_9500.json  "leaves      (Tier 3)"
create_tier 10.42.0.140 2 linux_server.json         "hosts"

# 3. Load the inter-device LLDP topology.
echo "Loading topology from ${CLOS_JSON} ..."
curl -fsS -X POST "${NL6_URL}/api/v1/topology" \
  -H 'Content-Type: application/json' --data "@${CLOS_JSON}" -o /dev/null

# 4. Import the nodes into the OpenNMS core at location nl6-Lab (required).
: "${OPENNMS_BASE_URL:?OPENNMS_BASE_URL is required for node import (set it in .env)}"
export MINION_LOCATION="${MINION_LOCATION:-nl6-Lab}"
echo "Importing nodes into OpenNMS core ${OPENNMS_BASE_URL} (location ${MINION_LOCATION}) ..."
"${ONMS_PROVISION}" --import

echo "Provisioning complete: 14 devices exporting to the Minion, topology loaded, nodes imported."
