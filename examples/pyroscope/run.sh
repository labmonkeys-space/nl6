#!/usr/bin/env bash
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — check that nl6's profiles reach Pyroscope, and that the
# `subsystem` label is filterable. Requires: curl, jq. Bring the stack up
# first:  docker compose up -d   (add --profile alloy for the scrape variant)
set -euo pipefail

NL6="${NL6:-http://localhost:8080}"
PYRO="${PYRO:-http://localhost:4040}"
CPU='process_cpu:cpu:nanoseconds:cpu:nanoseconds'

ticks() { # ticks <selector>   e.g. '{service_name="nl6"}'   -> a non-negative integer, 0 on any failure
  local n
  n=$(curl -sf -G "${PYRO}/pyroscope/render" --data-urlencode "query=${CPU}${1}" \
    --data-urlencode 'from=now-5m' --data-urlencode 'until=now' --data-urlencode 'format=json' \
    | jq -r '.flamebearer.numTicks // 0' 2>/dev/null)
  case "${n}" in
    ''|*[!0-9]*) echo 0 ;;
    *) echo "${n}" ;;
  esac
}

echo "==> waiting for nl6 ..."
for _ in $(seq 1 30); do
  curl -sf "${NL6}/api/v1/version" >/dev/null 2>&1 && break || sleep 2
done

echo "==> profiling state"
curl -sf "${NL6}/api/v1/profiling" | jq -c .data

if docker compose ps --services --filter status=running 2>/dev/null | grep -qx alloy; then
  echo "==> alloy profile active: switching nl6 to pull-only so Alloy can take the CPU profile"
  # An explicit empty server_address: omitting it would KEEP the push.
  curl -sf -X POST "${NL6}/api/v1/profiling" -H 'Content-Type: application/json' \
    -d '{"enabled": true, "server_address": ""}' | jq -c .data
  SERVICE='nl6-interop-scrape'
else
  SERVICE='nl6'
fi

echo "==> waiting for profiles under service_name=${SERVICE} (up to 90 s) ..."
N=0
for _ in $(seq 1 45); do
  N=$(ticks "{service_name=\"${SERVICE}\"}")
  [ "${N}" -gt 0 ] && break
  sleep 2
done
echo "    CPU ticks: ${N}"
if [ "${N}" -eq 0 ]; then
  echo "    FAIL: no CPU profile for service_name=${SERVICE}"; exit 1
fi

echo "==> subsystem label (SNMP read loops are labelled at birth; a label is a sample label, so it survives a scrape too)"
S=0
for _ in $(seq 1 30); do
  S=$(ticks "{service_name=\"${SERVICE}\",subsystem=\"snmp\"}")
  [ "${S}" -gt 0 ] && break
  sleep 2
done
Z=$(ticks "{service_name=\"${SERVICE}\",subsystem=\"no-such-subsystem\"}")
echo "    subsystem=snmp: ${S}   subsystem=no-such-subsystem: ${Z}"
if [ "${Z}" -ne 0 ]; then echo "    FAIL: an absent label matched"; exit 1; fi
if [ "${S}" -eq 0 ]; then
  echo "    FAIL: no CPU samples under subsystem=snmp; the SNMP read loops only burn CPU when polled."
  echo "          Poll the fleet (e.g. snmpwalk -v2c -c public 10.42.0.1 system) and re-run."
  exit 1
fi

echo "    PASS: open ${PYRO} and filter by subsystem"
