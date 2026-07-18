#!/usr/bin/env bash
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — drive one syslog fidelity scenario over the nl6 REST API and
# assert the reported `sent` equals the collector's observed `received`.
# Requires: curl, jq. Bring the stack up first:  docker compose up -d --build
set -euo pipefail

NL6="${NL6:-http://localhost:8080}"
COLL="${COLL:-http://localhost:9000}"

# The scenario: all 5 auto-started devices, 10 events/s over a 2 s window.
# Expected in-window fires = 5 devices x 10/s x 2 s = 100 (documented result).
REQUEST='{
  "participants": ["10.42.0.1","10.42.0.2","10.42.0.3","10.42.0.4","10.42.0.5"],
  "protocol": "syslog",
  "rate": 10,
  "window": "2s",
  "drain": "500ms",
  "seed": 42
}'

echo "==> waiting for nl6 ..."
for _ in $(seq 1 30); do
  curl -sf "${NL6}/api/v1/version" >/dev/null 2>&1 && break || sleep 2
done

echo "==> submit"
ID=$(curl -sf -X POST "${NL6}/api/v1/scenarios" -H 'Content-Type: application/json' -d "${REQUEST}" | jq -r .id)
echo "    scenario ${ID}"

echo "==> arm"
curl -sf -X POST "${NL6}/api/v1/scenarios/${ID}/arm" | jq -c '{phase, participants_armed, excluded}'

echo "==> reset collector (clears any pre-window background traffic)"
curl -sf -X POST "${COLL}/reset" >/dev/null

echo "==> start"
curl -sf -X POST "${NL6}/api/v1/scenarios/${ID}/start" | jq -c '{phase}'

echo "==> running the 2 s window ..."
sleep 3   # window (2s) + drain (0.5s) + margin; the scenario self-closes at T1

echo "==> stop / fetch report"
REPORT=$(curl -sf -X POST "${NL6}/api/v1/scenarios/${ID}/stop")
SENT=$(echo "${REPORT}" | jq '[.counters[] | .in_window + .drain] | add')
echo "    nl6 report sent = ${SENT}"

# Give the collector a moment to drain in-flight datagrams, then read it.
sleep 1
RECEIVED=$(curl -sf "${COLL}/count" | jq .received)
echo "    collector received = ${RECEIVED}"

echo "==> reconciliation"
if [ "${SENT}" = "${RECEIVED}" ]; then
  echo "    PASS: sent == received (${SENT}) — zero missed, zero duplicated"
  exit 0
else
  echo "    FAIL: sent=${SENT} received=${RECEIVED} (delta $((SENT - RECEIVED)))"
  echo "    (a non-zero delta localizes loss/duplication in the path under test)"
  exit 1
fi
