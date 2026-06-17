#!/usr/bin/env bash
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# import.sh — import the nl6 devices into OpenNMS as a requisition.
#
# Thin wrapper around the vendored nl6-requisition.sh: it forwards NL6_URL and
# every argument through. All other knobs (OPENNMS_HOST/PORT/USER/PASS,
# FOREIGN_SOURCE, gNMI/OpenConfig metadata) are read straight from the
# environment by the wrapped script — see ./nl6-requisition.sh --help.
#
# NOTE: the requisition pulls EVERY device from the nl6 instance, not just this
# fabric. Point NL6_URL at an nl6 dedicated to the Clos example.
#
# Usage:
#   ./import.sh                                  # print requisition XML to stdout
#   ./import.sh --import                         # upload + trigger import in OpenNMS
#   ./import.sh --import --dry-run               # preview XML without uploading
#   NL6_URL=http://my-nl6:8080 OPENNMS_HOST=onms ./import.sh --import
set -euo pipefail

NL6_URL="${NL6_URL:-http://localhost:8080}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NL6_URL="${NL6_URL}" exec "${SCRIPT_DIR}/nl6-requisition.sh" "$@"
