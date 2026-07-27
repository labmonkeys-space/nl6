#!/bin/sh
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# Compose bootstrapper entry point: replays the device manifest against a
# freshly started simulator, then exits. All the import logic lives in
# fleet.sh — this wrapper only decides whether there is a manifest to
# replay. A missing manifest is a valid state, not an error: a fresh
# checkout ships no inventory/devices.json, and `compose up` must still
# come up clean instead of crash-looping the bootstrapper.

set -eu

MANIFEST="${MANIFEST:-/inventory/devices.json}"
# Base URL only — fleet.sh appends /api/v1/... itself.
API="${API:-http://simulator:8080}"

if [ ! -f "$MANIFEST" ]; then
    echo "inventory-bootstrap: no manifest at $MANIFEST — nothing to replay."
    echo "inventory-bootstrap: to auto-provision devices on 'compose up':"
    echo "inventory-bootstrap:   cp inventory/devices.example.json inventory/devices.json"
    exit 0
fi

exec fleet.sh import "$API" "$MANIFEST"
