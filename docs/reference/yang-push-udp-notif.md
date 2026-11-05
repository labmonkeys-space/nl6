---
sidebar_label: "YANG-Push over UDP-notif"
description: "How huawei_ne8000 devices stream YANG-Push over UDP-notif to a collector, the three subscriptions they serve, and the NETCONF login a collector uses to fetch the YANG library."
---

# YANG-Push over UDP-notif

A `huawei_ne8000` device can stream interface telemetry to a collector as YANG-Push over UDP-notif.
It models Huawei VRP R025C00.
The transport is RFC 9187 (UDP-notif version 1, JSON).
The subscriptions follow RFC 8641.
Opt in per device.
Devices of other types never stream.

NetGauze v0.13.0 is the collector nl6 is checked against.
The collector learns the schema by logging in to the device over NETCONF, so NETCONF must be on too.

```
   device ── UDP-notif (JSON, segmented) ──▶ collector
   device ◀── NETCONF over SSH (YANG library, get-schema, get) ── collector
```

## Enable it

NETCONF needs `-netconf-enable`.
A collector such as NetGauze logs in with a key, so also pass an `authorized_keys` file.

```bash
sudo ./nl6 -netconf-enable -netconf-authorized-keys ~/.ssh/authorized_keys
```

`-netconf-authorized-keys` lets those keys log in as `simadmin` on every NETCONF SSH listener and on call home.
The password login stays.
Key options in the file are ignored.
nl6 reads the file at startup even without `-netconf-enable`.
See [NETCONF](netconf.md#flags) for the flags.
A `yang_push` block sent while `-netconf-enable` is off is accepted, with one warning in the log per process.
The collector then cannot fetch the YANG library or the modules.
A collector must be an IPv4 address or a hostname.
An IPv6 literal gets `400`, the same as `-yang-push-collector`.

Then opt devices in.

```bash
curl -X POST http://localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{
    "start_ip": "10.42.0.1",
    "device_count": 3,
    "resource_file": "huawei_ne8000.json",
    "yang_push": { "collector": "10.254.0.1:10000" }
  }'
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `collector` | string | required | UDP target as `host:port`. |
| `segment_size` | int | `1436` | Maximum UDP-notif segment size in bytes, `512` to `65507`. It counts the whole UDP payload including the 16-byte header. |

A request whose devices cannot stream is rejected with `400`.
A mixed round-robin batch is accepted, and the other types are skipped with one log line per profile per process.

The auto-start batch takes the seed flag `-yang-push-collector host:port`.
It applies only with `-auto-start-ip`.
See [CLI flags](cli-flags.md).

Each device sends from a UDP socket connected to the collector and bound to the device IP.
A failed bind fails the opt-in for that device, with no fallback to another source address.
The connection lets the device see ICMP port-unreachable when no collector listens.

## What a device sends

Three subscriptions start when the device starts.

| ID | Mode | Subtree | Filter reference |
|----|------|---------|------------------|
| 8 | periodic, 60 s | `/ietf-interfaces:interfaces/interface/statistics` | `STATEINTERFACE2` |
| 9 | periodic, 60 s | `/ietf-interfaces:interfaces/interface` | `STATSINTERFACE2` |
| 10 | on-change, dampening 0, sync on start | `oper-status` and `admin-status` of every interface | `ONCHANGEINTERFACE` |

The periodic subscriptions anchor at `2025-01-01T00:00:30Z`.
Subscription 9 sends three seconds after subscription 8.
Every device fires at the same wall-clock second.
A large fleet therefore produces one synchronized burst a minute on the host and on the collector.
nl6 gives every device the same anchor, so the whole fleet bursts together.
A real fleet does only if every device is configured with one anchor.

Subscription 10 sends a `push-update` once at start with `name`, `admin-status` and `oper-status` of every interface.
Its `point-in-time` is `initial-state`.
After that it sends a `push-change-update` for each `oper-status` or `admin-status` change, with `point-in-time` `state-changed`.
Subscriptions 8 and 9 use `current-accounting`.
Take an interface down with [the interface state API](interface-state.md) and the change arrives within a second.

The start of each subscription sends a `subscription-started` notification first.
Message IDs and the envelope `sequence-number` count per subscription and start at 0 on `subscription-started`.

Every message is JSON in the VRP envelope `ietf-yp-notification:envelope`.
It carries `event-time`, `hostname` (the device sysName), `sequence-number` and `contents`.
A statistics push for a whole device is larger than one datagram.
nl6 splits it at `segment_size` using the UDP-notif segment option, and the last segment has the low bit set.
The first segment of a message is 9 bytes shorter than the rest, as on a real NE8000.

The device IPv4 address as a big-endian unsigned integer is both the header observation domain ID and the `message-publisher-id` in the payload.
`10.42.0.1` is `170524673`.

## What a collector can fetch

NETCONF over SSH on `-netconf-port` serves the VRP dialect.
A collector can read the YANG library with `yang-library-content-id`, the module list, and the modules with `get-schema`.
Only IETF and IANA modules ship.
The library lists `augmented-by` entries so NetGauze can load the envelope, observation, distributed-notification, push-revision and UDP-notif transport modules.
`ietf-netconf-monitoring` is served because the device lists it.
The library lists each implemented module's features, in both `yang-library` and `modules-state`.
The `content-id` is the FNV-32a hash of the module list and the features, as a decimal string.

`get` returns the three subscriptions and their filters.
The filters are answered by reference.
The dialect serves only `get`, `get-schema`, `close-session` and `kill-session`.
A `get` on one subscription by ID also returns its `receiver-instances`.
An unknown ID returns an empty `<data/>`, and NetGauze reports that as a parse error.

## Status

`GET /api/v1/yangpush/status`:

```json
{
  "subsystem_active": true,
  "devices_exporting": 3,
  "collectors": [
    {
      "collector": "10.254.0.1:10000",
      "devices": 3,
      "messages_sent": 27,
      "segments_sent": 61,
      "send_failures": 0,
      "state_events_dropped": 0,
      "fidelity_suppressed": 0
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `messages_sent` | UDP-notif messages, each one a notification. |
| `segments_sent` | Datagrams. It is above `messages_sent` when anything was segmented. |
| `send_failures` | Datagrams the socket refused. |
| `state_events_dropped` | Interface events lost because the exporter fell behind. Its queue drops the oldest, so the latest transition still goes out. |
| `fidelity_suppressed` | Messages muted by `-fidelity`. |

The same drops also count in `state_events_dropped` of `GET /api/v1/gnmi/status`, which gNMI and NETCONF share.

## Fidelity

`-fidelity` mutes all three subscriptions.
The `subscription-started` notification waits for the first unmuted activity.
The subscriptions do not join a load-test scenario window.
That participation is not implemented.

## What is not modelled

nl6 follows a real NE8000 on VRP R025C00.
These differences are deliberate.

- Subscription 10 is not verified against a real device. The NE8000 advertises on-change; nl6 builds the subscription from RFC 8641 and the same envelope.
- Every interface appears in subscription 8. The real device sent statistics for a subset.
- The `ietf-udp-client` module revision `2025-05-14` is a guess. The device library lists none.
- `ietf-yang-push-revision` is served at revision `2025-08-29`, the copy NetGauze bundles. The NE library does not list the module. Its payload keys `module-version` by `name`, which only 2025-08-29 defines (2024-12-17 used `module-name`).
- Two `augmented-by` rows under `ietf-subscribed-notifications` (`ietf-yang-push-revision` and `ietf-udp-notif-transport`) follow a Huawei MA5800T, not the NE8000.
- Features follow the NE8000. nl6 adds `encode-json` under `ietf-subscribed-notifications` and `yang-push-revision-supported` under `ietf-yang-push-revision`, because the payloads it sends sit behind them.
- The NE lists only `ietf-notification-capabilities` as augmenting `ietf-system-capabilities`. nl6 also lists `ietf-yang-push-revision`, `ietf-yp-notification` and `ietf-yp-observation`, because their YANG text augments `/sysc:system-capabilities`.
- A `get` on a subscription by ID returns `receiver-instances`, which strict subtree filtering would not.
- Hostnames, addresses and interface names are synthetic.

See the [limitations](https://github.com/labmonkeys-space/nl6/blob/main/go/nl6/resources/huawei_ne8000_limitations.md) for the full list.

## Test it against NetGauze

`make test-interop-yangpush` runs three devices against a real NetGauze v0.13.0 and Redpanda in Docker, on a Linux host.
NetGauze v0.13.0 validates the messages with libyang and finds none invalid.
It checks the YANG library fetch, the Kafka output for subscriptions 8, 9 and 10, segmentation, and an interface going down.
The stack is in `examples/netgauze/`.
