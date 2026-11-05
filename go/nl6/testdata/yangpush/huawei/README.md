# YANG-Push fixtures for huawei_ne8000

`subscription-started-8`, `subscription-started-9`, `push-update-8` and `push-update-9` derive from the NMOP hackathon capture of a Huawei VRP device.
Source: `network-analytics/ietf-network-analytics-document-status`, `125/Hackathon/yangpush-publisher/huawei-vrp-ip/yp-notifications/`.
Permission from Thomas Graf is pending.

Anonymisation:
- The JSON is compact, with the capture key order kept.
- The hostname is `ne8000-sim-1`.
- Each push-update is trimmed to two interfaces, renamed `GigabitEthernet0/1/0` and `GigabitEthernet0/1/1`.
- Subscription 9 drops `last-change` and `phys-address`, and uses synthetic if-index and speed values.
- The event time and observation time are fixed test values.
- `yang-library-content-id` holds the id of the module set nl6 serves.

Subscription 10 (on-change) has no capture.
`subscription-started-10`, `push-update-10` and `push-change-update-10` are nl6's own shape, written from the RFC 8641 JSON encoding.
`push-update-10` is the sync-on-start update: per interface only `name`, `admin-status` and `oper-status`, the leaves the subscription's filter selects.
The observation fields in `push-change-update-10` follow the order of push-update.

`segments-8.hex` holds the segment headers and lengths of `8-yp-subscripton.pcap`.
The captured publisher id is replaced with the documentation address 192.0.2.13 (0xC000020D).
Segment numbers, flags and lengths are unchanged.

The JSON fixtures use publisher id 3221225997 (192.0.2.13, 0xC000020D) instead of the captured value.
