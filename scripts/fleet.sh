#!/bin/sh
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# nl6 fleet inventory tool — export and import device inventories
# between nl6 simulator instances.
#
# See docs/getting-started/fleet.md for the full guide.

set -eu

# POST /api/v1/devices answers 409 while another creation batch holds the
# simulator's one-batch-at-a-time gate (nl6#565). import waits it out instead of
# aborting. The default delay matches the server's Retry-After; the default
# budget (60 x 5s = 5 minutes) covers a large auto-start batch at boot. Raise
# RETRY_409_LIMIT for a fleet whose startup batch takes longer.
RETRY_409_LIMIT="${RETRY_409_LIMIT:-60}"
RETRY_409_DELAY="${RETRY_409_DELAY:-5}"

usage() {
    cat >&2 <<EOF
Usage:
  $0 export <url> [file]
  $0 import <url> [file] [--netmask PREFIX]

Commands:
  export   Capture the device inventory from a running nl6 simulator.
           Default file: nl6-inventory.json
  import   Replay an inventory file into another nl6 simulator.
           Default file:    nl6-inventory.json
           Default netmask: 16  (prefix length; the API accepts 8, 16, or 24)

import auto-detects the file shape:
  {data:[{ip,...},...]}  GET-response shape, one POST per device
  [{start_ip,...},...]   batch-manifest shape, one POST per batch

Reference: https://nl6.eu/getting-started/fleet
EOF
    exit 2
}

cmd="${1:-}"
[ -n "$cmd" ] || usage
shift

case "$cmd" in
    export)
        URL="${1:-}"
        [ -n "$URL" ] || usage
        FILE="${2:-nl6-inventory.json}"
        URL="${URL%/}"

        printf 'Probing nl6 version at %s ... ' "$URL"
        VERSION_JSON="$(curl -fsS "$URL/api/v1/version")"
        printf '%s\n' "$VERSION_JSON"

        printf 'Fetching device inventory ... '
        curl -fsS -H 'Accept: application/json' "$URL/api/v1/devices" \
            | jq '.' > "$FILE"

        COUNT="$(jq '(.data // .devices // (if type=="array" then . else [] end)) | length' "$FILE")"
        printf '%s devices written to %s\n' "$COUNT" "$FILE"
        ;;

    import)
        URL=""
        FILE=""
        # Prefix length, not a dotted mask: POST /api/v1/devices takes a prefix
        # and rejects anything other than 8/16/24 with 400. The fleet is a flat
        # /16 management plane, so 16 is the default.
        NETMASK="16"
        while [ $# -gt 0 ]; do
            case "$1" in
                --netmask)
                    [ $# -ge 2 ] || { echo "--netmask requires a value" >&2; usage; }
                    NETMASK="$2"; shift 2
                    ;;
                --netmask=*)
                    NETMASK="${1#--netmask=}"; shift
                    ;;
                -*)
                    echo "unknown option: $1" >&2; usage
                    ;;
                *)
                    if [ -z "$URL" ]; then URL="$1"
                    elif [ -z "$FILE" ]; then FILE="$1"
                    else echo "unexpected argument: $1" >&2; usage
                    fi
                    shift
                    ;;
            esac
        done
        [ -n "$URL" ] || usage
        case "$NETMASK" in
            8|16|24) ;;
            *) echo "--netmask must be 8, 16, or 24 (prefix length, not a dotted mask)" >&2; usage ;;
        esac
        FILE="${FILE:-nl6-inventory.json}"
        URL="${URL%/}"

        [ -f "$FILE" ] || { echo "input file not found: $FILE" >&2; exit 1; }

        SHAPE="$(jq -r '
            if type == "object" and (.data | type) == "array" then "get-response"
            elif type == "array" then "batch-manifest"
            else "unknown"
            end
        ' "$FILE")"

        case "$SHAPE" in
            get-response)
                PAYLOADS="$(jq -c --arg netmask "$NETMASK" '
                    .data[]
                    | {
                        start_ip: .ip,
                        device_count: 1,
                        netmask: $netmask,
                        resource_file,
                        snmp_port,
                        flow,
                        traps,
                        syslog
                      }
                ' "$FILE")"
                ;;
            batch-manifest)
                PAYLOADS="$(jq -c '.[]' "$FILE")"
                ;;
            *)
                echo "unrecognized file shape in $FILE: expected GET-response object or batch-manifest array" >&2
                exit 1
                ;;
        esac

        TOTAL="$(printf '%s\n' "$PAYLOADS" | jq -s 'length')"
        [ "$TOTAL" -gt 0 ] || { echo "no devices found in $FILE" >&2; exit 1; }

        printf 'Importing %s entries (shape: %s) to %s/api/v1/devices\n' "$TOTAL" "$SHAPE" "$URL"

        i=0
        while IFS= read -r payload; do
            i=$((i + 1))
            label="$(printf '%s' "$payload" | jq -r '.start_ip // "?"')"
            attempt=1
            while : ; do
                tmp="$(mktemp)"
                http_code="$(curl -sS -o "$tmp" -w '%{http_code}' \
                    -X POST -H 'Content-Type: application/json' \
                    -d "$payload" \
                    "$URL/api/v1/devices")"
                body="$(cat "$tmp")"
                rm -f "$tmp"
                ok="$(printf '%s' "$body" | jq -r 'try .success catch false')"
                case "$http_code" in
                    2*)
                        if [ "$ok" != "true" ]; then
                            echo "  [$i/$TOTAL] FAIL $label (HTTP $http_code, success=$ok): $body" >&2
                            exit 1
                        fi
                        ;;
                    409)
                        # The simulator runs ONE creation batch at a time and
                        # refuses a concurrent one (nl6#565). This is a wait, not
                        # a failure, and it is reachable on a normal boot: the
                        # `-auto-start-ip` batch holds the gate while
                        # GET /api/v1/status already answers 200, so `compose up`
                        # starts this import mid-batch and aborting here would
                        # leave a partially imported fleet.
                        if [ "$attempt" -ge "$RETRY_409_LIMIT" ]; then
                            echo "  [$i/$TOTAL] FAIL $label (HTTP 409 after $attempt attempts): $body" >&2
                            exit 1
                        fi
                        echo "  [$i/$TOTAL] BUSY $label — another creation batch is running; retrying in ${RETRY_409_DELAY}s (attempt $attempt/$RETRY_409_LIMIT)" >&2
                        attempt=$((attempt + 1))
                        sleep "$RETRY_409_DELAY"
                        continue
                        ;;
                    *)
                        echo "  [$i/$TOTAL] FAIL $label (HTTP $http_code): $body" >&2
                        exit 1
                        ;;
                esac
                break
            done
        done <<HEREDOC
$PAYLOADS
HEREDOC

        echo "Done. $TOTAL entries imported."
        ;;

    -h|--help|help)
        usage
        ;;

    *)
        echo "unknown command: $cmd" >&2
        usage
        ;;
esac
