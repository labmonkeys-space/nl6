# YANG-Push fixtures for huawei_ne8000

`subscription-started-8`, `subscription-started-9`, `push-update-8` and `push-update-9` derive from the NMOP hackathon capture of a Huawei VRP device.
Source: `network-analytics/ietf-network-analytics-document-status`, `125/Hackathon/yangpush-publisher/huawei-vrp-ip/yp-notifications/`.

Anonymisation:
- The JSON is compact, with the capture key order kept.
- The hostname is `ne8000-sim-1`.
- Each push-update is trimmed to two interfaces, renamed `GigabitEthernet0/1/0` and `GigabitEthernet0/1/1`.
- Subscription 9 uses synthetic `description`, `last-change`, `phys-address`, if-index and speed values. The addresses come from the documentation range 00:00:5E:00:53:00/24.
- The event time and observation time are fixed test values.
- `yang-library-content-id` holds the id of the module set nl6 serves.

`subscription-started-10`, `push-update-10` and `push-change-update-10` derive from the IETF 127 capture of a Huawei VRP router.
Source: the same repository, `127/Hackathon/mb-alive-test-result/netcalyx/netcalyx-yangpush-receiver/`, files `yp-s11-subscription-started.json`, `yp-s11-push-update.json` and `yp-s11-push-change-update.json`.
The same anonymisation applies, and the subscription ID is 10 instead of the captured 11.
`push-update-10` is the sync update with two whole interface entries.
`push-change-update-10` is one merge edit for one interface. Its `higher-layer-if` leaf-list is dropped, and its `phys-address` is upper case as captured.

`segments-8.hex` holds the segment headers and lengths of `8-yp-subscripton.pcap`.
The captured publisher id is replaced with the documentation address 192.0.2.13 (0xC000020D).
Segment numbers, flags and lengths are unchanged.

The JSON fixtures use publisher id 3221225997 (192.0.2.13, 0xC000020D) instead of the captured value.
