---
sidebar_label: "NMOP test chain"
description: "Where nl6 sits in the IETF NMOP YANG-Push message broker test chain, which captures its simulated Huawei NE8000 follows, and what a run through NetCalyx, Kafka and a schema registry shows today."
---

# nl6 in the NMOP YANG-Push test chain

nl6 is a live YANG-Push publisher for the message broker chain of [draft-ietf-nmop-yang-message-broker-integration](https://datatracker.ietf.org/doc/draft-ietf-nmop-yang-message-broker-integration/).
It takes the place of the packet capture replay used in the IETF hackathon tests.
The publisher is a simulated Huawei NE8000 whose messages follow published captures of a real router.

This page is for readers who know the draft and have not used nl6.
The flags and the API are on the [YANG-Push reference page](../reference/yang-push-udp-notif.md).

## Components

```
nl6 (simulated NE8000)  ──UDP-notif──▶  YANG-Push receiver  ──▶  message broker producer
        ▲                                     │                          │
        └────── NETCONF: YANG library ────────┘                          ▼
                                                    Kafka + YANG schema registry
                                                                         │
                                                                         ▼
                                                    message broker consumer  ──▶  time series database
```

| Role in the draft | In the tested chain | Talks to |
| --- | --- | --- |
| YANG-Push publisher | nl6, device type `huawei_ne8000` | Receiver over UDP-notif, RFC 9187 |
| YANG-Push receiver | NetCalyx v0.4.0 | Publisher over NETCONF for the YANG library, the modules and the subscriptions |
| Message broker producer | NetCalyx v0.4.0 | Kafka and the schema registry |
| YANG schema registry | Confluent Schema Registry with `yang-schema-registry-plugin` v0.0.5 | Producer and consumer |
| Message broker consumer | A libyang 6.4.13 consumer that validates by Schema ID | Schema registry and ClickHouse |

nl6 is only the publisher.
Everything to the right of it is the software under test.

## What nl6 changes compared with a capture replay

| Capture replay | nl6 |
| --- | --- |
| The same messages on every run | Interface counters move between push-updates |
| Events are the ones in the capture | An API call takes an interface down and triggers an on-change update |
| The receiver needs a prepared YANG cache | The receiver logs in over NETCONF and fetches the YANG library and the modules from the device |
| One router | A fleet, with the device count as a parameter |
| Bytes from a real router | Bytes built by nl6 from a model of that router |

The last row is the cost.
A replay is the router.
nl6 is a model of it, and the next section says how close the model is.

## What the simulated router sends

Each device starts three subscriptions on `ietf-interfaces`.

| ID | Mode | Filter |
| --- | --- | --- |
| 8 | periodic, 60 s | `/ietf-interfaces:interfaces/interface/statistics` |
| 9 | periodic, 60 s | `/ietf-interfaces:interfaces/interface` |
| 10 | on-change, dampening 5 s | `/ietf-interfaces:interfaces/interface` |

Every behaviour on the wire is copied from a capture in [network-analytics/ietf-network-analytics-document-status](https://github.com/network-analytics/ietf-network-analytics-document-status).

| Behaviour | Capture |
| --- | --- |
| YANG library, module sets and features | IETF 123 |
| Subscriptions 8 and 9: `subscription-started`, push-update leaves and their order, segment sizes | IETF 125, `yangpush-publisher/huawei-vrp-ip` |
| Subscription 10: `subscription-started`, the sync push-update, the YANG Patch target and value of a `push-change-update` | IETF 127, `mb-alive-test-result`, the router's subscription 11 |
| One message counter per publisher for the UDP-notif message ID and the envelope `sequence-number`, starting at 1 | IETF 127 packet capture, all 2446 messages |
| `subscription-started` with `module-version` and `yang-library-content-id` | IETF 125 and IETF 127 |

nl6 differs from the captures in these points:

- The subscription IDs are 8, 9 and 10. The IETF 127 router uses 6, 11 and 12 for its interface subscriptions and has no statistics subscription.
- `higher-layer-if` and `lower-layer-if` are not sent.
- The sync push-update of subscription 10 follows `subscription-started` at once. The router sends it 5 seconds later.
- `patch-id` is a counter per device. The capture holds one change-update and cannot confirm that.
- Changes inside a dampening period are collected into one update, as RFC 8641 describes. The capture cannot confirm that either.
- The served YANG library holds only IETF and IANA modules. nl6 adds two features and a few `augmented-by` rows that the router's library does not list, because the payloads it sends depend on them.
- Every interface appears in subscription 8. The router sent statistics for a subset.
- The values are simulated. Interface names, counters, addresses and descriptions come from the nl6 device profile.

The [limitations file](https://github.com/labmonkeys-space/nl6/blob/main/go/nl6/resources/huawei_ne8000_limitations.md) has the full list.

## Run the chain

[yang-push-clickhouse-e2e](https://github.com/labmonkeys-space/yang-push-clickhouse-e2e) holds the whole chain as one Compose stack.
Its README has the steps.
It needs a Linux Docker engine, starts three devices by default and ends with a count of the messages at four points in the chain.

## What a run shows today

Result of 18 November 2026, three devices, about three minutes of traffic:

| Point in the chain | Messages |
| --- | --- |
| Sent by nl6 | 32 |
| Decoded by the receiver | 32 |
| Produced to Kafka | 32 |
| Stored by the consumer | 32 |
| Valid at the consumer | 18 |

No message is lost.
The 14 invalid messages fail strict validation at the consumer for two reasons, and the captured router sends both shapes too.

1. **An identity module is not in the registered schema.**
   Interface entries carry `type` values such as `iana-if-type:ethernetCsmacd`.
   `subscription-started` names only `ietf-interfaces` in `module-version`.
   `iana-if-type` is not reachable from it through imports, augments, deviations or features, which is the dependency rule of section 4.3 of the draft.
   The consumer validates by Schema ID, as section 4.7 describes, and cannot resolve the identity.
2. **The YANG Patch value of an on-change update is not rooted at a top-level node.**
   The router writes the value as `{"interface":[...]}` for the target `/ietf-interfaces:interfaces/interface[name=...]`.
   libyang rejects it with `Node "interface" not found`.

The first finding was measured with a changed device.
When the device names `iana-if-type` in `module-version`, the consumer validates every interface push-update.
A receiver with strict validation still drops them, because the device lists the module as import-only and the receiver keeps that marking.
Receiver and consumer then validate against different contexts built from the same library.

The receiver in this chain runs with `anydata_strict_validation` off.
That is why it forwards all 32 messages.

## What nl6 does not cover

- Only `ietf-interfaces`. The IETF 127 capture also has hardware, LLDP, alarm and Huawei native subscriptions.
- Three fixed subscriptions per device. A subscription cannot be configured over NETCONF, and the dialect serves only `get`, `get-schema`, `close-session` and `kill-session`.
- One vendor. Only `huawei_ne8000` streams YANG-Push.
- JSON over UDP-notif only.
- No loss ratio per device. The chain compares totals. Reconciliation per device needs YANG-Push as a load-test protocol, which nl6 does not have yet.

## Related pages

- [YANG-Push over UDP-notif](../reference/yang-push-udp-notif.md): flags, API, message details and the interop gate.
- [NETCONF](../reference/netconf.md): what a receiver can fetch.
- [Interface state API](../reference/interface-state.md): how to trigger an on-change update.
