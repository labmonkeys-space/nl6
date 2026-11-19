# YANG-Push over UDP-notif (huawei_ne8000)

Engineering record for the YANG-Push exporter.
Files: `go/nl6/yangpush_*.go`, the VRP NETCONF dialect in `go/nl6/netconf_vrp.go`.
Operator reference: `docs/reference/yang-push-udp-notif.md`.
Limitations: `go/nl6/resources/huawei_ne8000_limitations.md`.
Interop gate: `make test-interop-yangpush`, `examples/netcalyx/`, `go/nl6/yangpush_interop_test.go`.

## Sources

- Captures from `network-analytics/ietf-network-analytics-document-status`.
  - `125/Hackathon/yangpush-publisher/huawei-vrp-ip` holds the wire, the payloads and the subscription config.
  - `123/Hackathon/ipf-zbl1243-r-daisy-21_huawei_vrp_ne_20250717_141629` holds the YANG library and modules.
  - `127/Hackathon/mb-alive-test-result/netcalyx/netcalyx-yangpush-receiver` holds the on-change subscription of a VRP router: `yp-s11-subscription-started.json`, `yp-s11-push-update.json` and `yp-s11-push-change-update.json`.
- The capture repo has no licence.
  Permission to use derived fixtures was requested from Thomas Graf and is pending.
  If it is refused, replace the derived fixtures with synthetic ones of the same byte layout before merge.
- Fixtures are anonymised.
  The hostname is `ne8000-sim-1`, interface names are synthetic and the publisher ID is `192.0.2.13` (`0xC000020D`).
- The referee is NetCalyx v0.4.0 (`network-analytics/NetCalyx`, tag `v0.4.0`, commit `90e364e`), the Swisscom fork of NetGauze that the IETF NMOP test chain runs, since 2026-11-10.
  Until then it was NetGauze v0.13.0, behaviour read at commit `e13b74f`. The VRP dialect was written against NetGauze's parsers; NetCalyx inherits them.
- Vendor survey.
  Among nl6 types, only Huawei VRP R025C00 and later and Cisco IOS XR 25.3.1 and later ship YANG-Push over UDP-notif.
  Catalyst 9500 and Junos MX do not.
  Cisco IOS XR is the planned next profile.

## Wire behaviour copied from the device

- UDP-notif version 1, JSON, segmentation at `max-segment-size` 1436.
  That size counts the whole UDP payload, including the 16-byte header.
- The first segment is 9 bytes shorter (1427).
  Both captured subscriptions show it with identical headers.
  The cause is unknown, so nl6 copies it.
- The publisher ID is the device IPv4 address as a big-endian uint32.
  It is the header observation domain and the payload `message-publisher-id`.
  The capture value `16843789` is `0x0101040D`, which is `1.1.4.13`.
- The message ID and the envelope `sequence-number` are one counter per publisher over all its subscriptions.
  It starts at 1 and steps by 1, as in all 2446 messages of the IETF 127 capture.
  The IETF 125 capture counted per subscription from 0. nl6 follows the newer capture.
- Subscriptions 8 (statistics) and 9 (interface) are periodic at 60 s with anchor `2025-01-01T00:00:30Z`.
  Subscription 9 runs three seconds after subscription 8.
  Their filters are by reference (`STATEINTERFACE2`, `STATSINTERFACE2`), answered through `get` on `filters`.
- A link-down interface reports `oper-status` `down`.
  The capture has 49 interfaces admin up and oper down, and none `lower-layer-down`.
- Subscription 10 is the captured on-change subscription (the router's subscription 11).
  Its filter is `/ietf-interfaces:interfaces/interface` and its `on-change` container carries `dampening-period` 500 and no `sync-on-start` leaf.
  The sync `push-update` carries every interface entry with `point-in-time` `initial-state`.
- A `push-change-update` carries one YANG Patch edit per interface.
  The target is `/ietf-interfaces:interfaces/interface[name=<name>]` with the name as it is.
  The value is the whole entry under `interface`, without a module prefix.
  `point-in-time` is `state-changed`.
- An interface entry has the leaves `name`, `description`, `type`, `enabled`, `link-up-down-trap-enable`, `admin-status`, `oper-status`, `last-change`, `if-index`, `phys-address` and `speed`, in that order, for subscriptions 9 and 10.
  `description` is the `ifAlias` that SNMP serves: the topology link label, else the value in the device profile.
  Subscription 10 writes it on every entry, empty or not, as the IETF 127 capture does.
  Subscription 9 leaves an empty `description` out, as the IETF 125 capture does.
  `phys-address` is upper case in a periodic `push-update` and in a `push-change-update`, and lower case in the sync `push-update` of the on-change subscription, as captured.
- The YANG library carries `augmented-by` entries (draft-ietf-netmod-yang-library-augmentedby).
  They let NetCalyx load the envelope, observation, distributed-notification, push-revision and UDP-notif transport modules.
- `ietf-netconf-monitoring` is served because the NE lists it.
- The library lists the features of each implemented module, copied from the NE capture.
- `content-id` is the FNV-32a hash of the module list and the features, as a decimal string.

## Where nl6 goes beyond the captures

- Subscription 10 keeps the ID 10 and the filter reference `ONCHANGEINTERFACE`.
  The captured router uses ID 11, and its filter reference is not in the capture.
- `higher-layer-if` and `lower-layer-if` are not sent.
  The captured router lists each on one interface, between `phys-address` and `speed`.
- The sync `push-update` goes out right after `subscription-started`.
  The captured router sends it 5 seconds later.
- `patch-id` counts the change-updates of a device from 0.
  The capture has one change-update, with `patch-id` 2.
- Dampening follows RFC 8641.
  The first change goes out at once.
  Changes in the next 5 seconds are collected and sent as one update when the period ends, one edit per interface in ifIndex order, each with the entry as it is then.
  The capture has one change-update and cannot confirm this.
- An admin change that also moves oper-status broadcasts two events, one per leaf.
  Subscription 10 sends the whole entry on the first and drops the second through `operTwins`.
  The check is kept per interface, because producers broadcast after the mutator returns and two admin changes on different interfaces can interleave their events.
  Two producers that change the same interface inside that window can still cause one extra update with correct state.
- Both captured message shapes fail strict validation in the NMOP chain, on the real router as on nl6.
  See nl6#1062.
- The NE lacks the features `encode-json` (`ietf-subscribed-notifications`) and `yang-push-revision-supported` (`ietf-yang-push-revision`).
  nl6 adds them, because its payloads sit behind them.
- The NE lists only `ietf-notification-capabilities` as augmenting `ietf-system-capabilities`.
  nl6 also lists `ietf-yang-push-revision`, `ietf-yp-notification` and `ietf-yp-observation`, taken from their augment targets.
- Every interface appears in subscription 8.
  The device sent statistics for a subset.
- `ietf-udp-client` revision `2025-05-14` is a guess.
- `ietf-yang-push-revision` is served at revision `2025-08-29`, the revision NetGauze v0.13.0 bundled when the fixtures were written. The NE library does not list the module. Its payload keys `module-version` by `name`, which only 2025-08-29 defines (2024-12-17 used `module-name`).
  NetCalyx v0.4.0 bundles `2025-12-07` under `assets/yang/`. Whether that revision keeps the `name` key is not yet checked.
- The `augmented-by` rows for `ietf-yang-push-revision` and `ietf-udp-notif-transport` under `ietf-subscribed-notifications` come from the MA5800T capture, not the NE.
- A `get` on a subscription by ID also returns `receiver-instances`.
  Strict subtree filtering would not.
  An unknown ID returns an empty `<data/>`, and NetCalyx reports that as a parse error.
- Scenario participation gates the device's own schedule, as gNMI dial-out does.
  There is no scenario emitter, and the scenario rate is ignored.

## Operational decisions

- Opt-in per device through the REST `yang_push` block, `collector` and `segment_size` (default 1436, 512 to 65507).
  The seed flag is `-yang-push-collector`.
  Only `huawei_ne8000` streams.
  An all-incapable request gets `400`.
  A mixed batch skips the others with one log line per profile per process.
- NetCalyx needs NETCONF, so `-netconf-enable` is required.
  `-netconf-authorized-keys <authorized_keys file>` enables key login for `simadmin` on every NETCONF SSH listener and on call home.
  Password login stays.
  Key options in the file are ignored.
  The file is read even without `-netconf-enable`.
  A `yang_push` block accepted while `-netconf-enable` is off logs one warning per process.
  An IPv6 collector gets `400`.
- The socket is a connected UDP socket bound to the device IP.
  Connecting is what lets the device see ICMP port-unreachable.
  A failed bind fails the opt-in for that device, with no fallback.
- `-fidelity` mutes all three subscriptions through `fidelityMutesBackground(sourceBackground)`.
  `subscription-started` is deferred until the first unmuted activity.
- A `yang-push` scenario installs `scenPart` on the exporter.
  `gate` then decides per message: `backgroundSuppressed` outside the window, else `emitted` and one of `inWindow`, `drain`, `sendFailures` or `dropped`.
  One record is one message.
  The drain admit is held across all segments and the bucket is chosen after the last write, as syslog does.
  A refused message is not built, so it consumes no message ID.
  The two dampening collection sites use `gateEvent`: a state change outside the window is dropped and counts `backgroundSuppressed`.
  `ensureStarted` sets `started` only when the first announcement passes the gate.
  `ypInWindow` closes the gate at the millisecond of T1, because the report and the envelope `event-time` both have millisecond precision.
- Status is `GET /api/v1/yangpush/status` with `messages_sent`, `segments_sent`, `send_failures`, `state_events_dropped` and `fidelity_suppressed`.
  `state_events_dropped` counts the exporter's own listener channel, which drops the oldest (`AddListenerCounting`).
  The same drops also count in the shared gNMI `state_events_dropped`.
  There is no second queue: an earlier one hid every drop that happened while the exporter was busy sending.
- Load profile.
  Every device fires subscription 8 at the same wall-clock anchor and subscription 9 three seconds later.
  A large fleet produces a synchronized burst each minute on the host and the collector.
  nl6 gives every device the captured anchor, so the fleet bursts together.
  A real fleet does only if every device is configured with one anchor.
  nl6 does not jitter it.
- Known limitation, not fixed: when the host clock is set back, the devices send no `push-update` for the two periodic subscriptions (IDs 8 and 9) for about as long as the clock went back.
  Example: the clock goes back 5 minutes, and the collector receives no periodic update for about 5 minutes.
  The subscriptions stay active. nl6 sends no `subscription-terminated` or `subscription-suspended`, and the updates start again on their own.
  - What happens.
    The update that was already scheduled still goes out on time.
    After that, nl6 waits until the clock is past the time of the last update it sent.
    The on-change subscription (ID 10) is not affected. It has no schedule and sends a `push-change-update` when an interface changes state, so those updates keep arriving the whole time.
  - Why.
    `periodic` in `yangpush_exporter.go` picks the next send time with `later(obs, e.clock())`.
    After the clock goes back, the old send time is the later of the two, so the next send is planned one period after it.
    `ResetAt` then sleeps until the clock reaches that time.
  - A clock set forward loses no update.
    The update already scheduled goes out late, by at most the size of the jump, and the next one is back on schedule.
    This comes from reading the code and was not measured.

## Interop gate

`make test-interop-yangpush` (Linux only) does the following.

1. Builds NetCalyx v0.4.0 from its release `.deb` (`examples/netcalyx/Dockerfile`, base and `.deb` pinned by digest) and starts it with Redpanda on the host network (`examples/netcalyx/compose.yml`).
2. Generates a throwaway ed25519 key.
   NetCalyx uses the private key and nl6 gets the public key through `-netconf-authorized-keys`.
3. Starts nl6 and creates three `huawei_ne8000` devices with a `yang_push` block.
   The collector address is `10.254.0.1:10000`, the host end of the nl6sim veth.
4. Waits 150 s, then asserts the following.
   - NetCalyx logged `YANG Library fetched from device` for each device.
   - NetCalyx's own counters, read through an OpenTelemetry Collector (OTLP gRPC in on 4317, Prometheus text out on 8889), show 0 for `netcalyx_yang_push_validation_dropped` (summed over its `reason` label), `netcalyx_yang_push_validation_yang_context_failed`, `netcalyx_yang_push_validation_yang_context_empty`, `netcalyx_collector_yang_push_caching_device_fetch_response_failed`, `netcalyx_udp_notif_decoder_malformed` and `netcalyx_udp_notif_reassembly_max_segments_exceeded`, and more than 0 for `netcalyx_collector_yang_push_caching_device_fetch_response_succeeded`, `netcalyx_yang_push_validation_yang_context_loaded` and `netcalyx_yang_push_validation_validated`.
   - The Kafka JSON topic holds messages for subscriptions 8, 9 and 10 from each device.
   - A subscription 8 Kafka record has a payload above 1436 bytes, which only reassembly can deliver.
     nl6's `segments_sent` above `messages_sent` and `send_failures` 0 (summed over collectors) are a secondary check.
   - An interface taken down through the REST API produces a subscription 10 message with `oper-status` `down` within 10 s.

The collector config is NetCalyx's `config_udpnotif_telemetry.yaml` with the Kafka JSON endpoint, `netconf.username: simadmin` and the generated key.
NetCalyx v0.4.0 renamed `telemetry.id` to `telemetry.service_name`, the log targets to `netcalyx_collector` and `netcalyx_yang_push`, and the metric prefix to `netcalyx.`.
The counter names are from NetCalyx v0.4.0 (`crates/yang-push/src/validation/stats.rs`, `crates/udp-notif-service/src/actor.rs`, `crates/collector/src/yang_push/`).
Unlike NetGauze v0.13.0, NetCalyx increments a real `validation.validated` counter, so the test no longer derives it from `sent` minus `skipped`.
Redpanda has a healthcheck and NetCalyx waits for it.

## Interop record

`make test-interop-yangpush` passed on 2026-11-10 on an Ubuntu 26.04 guest (Proxmox, 8 vCPU, 16 GB; Docker 29.1.3, Compose 2.40.3, Go 1.27.3) against NetCalyx v0.4.0 and Redpanda v26.2.6, branch `netcalyx-referee` at `764acf1e`.
Result: `--- PASS: TestYangPushInterop (157.46s)`.
NetCalyx fetched the YANG library from all three devices (32 schemas each), built a context, validated 24 of 24 messages and skipped none.
Kafka held subscriptions 8, 9 and 10 for every device, 9 reassembled subscription 8 records, and the on-change `down` within 5 s.
nl6 reported `messages_sent=27 segments_sent=372 send_failures=0`.

The same day, three runs with `anydata_strict_validation: true` failed and produced two findings. Both apply to the captured NE8000 as much as to nl6:

- NetCalyx seeds the library load from subscription-started's `module-version` (only `ietf-interfaces`, as the NE sends it) plus transitive imports.
  `iana-if-type` is imported by nothing, so libyang never sees it and rejects `iana-if-type:ethernetCsmacd` in every subscription 9 and subscription 10 update. nl6 now serves `iana-if-type@2017-01-19` as import-only, which the NE library lists and nl6 had missed; serving it, and even listing it as implemented, does not make NetCalyx load it.
- NetCalyx parses the whole payload with libyang `ANYDATA_STRICT`.
  Before the IETF 127 capture landed, subscription 10's RFC 8072 patch value `{"ietf-interfaces:interface":[...]}` failed with `Node "interface" not found in the "ietf-interfaces" module`.
  With the captured unprefixed value `{"interface":[...]}`, it fails with `Node "interface" not found in the "ietf-yang-push" module` (nl6#1062).

The gate therefore runs with strict anydata validation off, which is what NetGauze v0.13.0 checked. Follow-up and the options are in nl6#1017.

The last NetGauze run, for comparison: `make test-interop-yangpush` passed on 2026-11-05 on an Ubuntu 26.04 VM (Docker 2.40 compose, Go 1.27.3) against NetGauze v0.13.0, Redpanda v25.3.1 and yanglint 3.13.6.
Result: `--- PASS: TestYangPushInterop (157.41s)`.
NetGauze fetched the YANG library from all three devices, built a YANG context from it and validated 27 of 30 messages with no invalid one.
It skipped validation for 3 messages, one per device: the subscription 10 sync push-update, which arrives before NetGauze has built the context.
Kafka held subscriptions 8, 9 and 10 for every device, 9 reassembled subscription 8 records, and the on-change `down` within 5 s.
nl6 reported `messages_sent=30 segments_sent=411 send_failures=0`.
`TestYangPushPayloadsValidateWithYanglint` passes with yanglint 3.13.6.

What the NetGauze runs taught, now built into the stack and test (kept for NetCalyx unless a run shows otherwise):

- The collector does not create its `cache_location`. The image creates `/tmp/netcalyx-udpnotif-cache`.
- The collector listens on `[::]`, so Kafka `export-address` and the metric `network_peer_address` read `::ffff:10.42.0.x`. The test strips the prefix.
- NetGauze v0.13.0 declared `validation.success`, `validation.messages.decode.success` and `validation.malformed` but never incremented them, so the test derived validated messages from `sent` minus `skipped`. NetCalyx v0.4.0 counts `validation.validated` and the test reads it directly.
- The collector puts the subscription target, which can hold `}`, in a metric label. The test does not parse labels.
- `rpk topic consume` on v25.3.1 has no `--timeout`. The test reads with `--offset :end`.
- libyang needs `<modules-state>` in the library file, because `module-set-id` is mandatory.
- The NE sends `module-version` keyed by `name`, which only `ietf-yang-push-revision@2025-08-29` defines.

## Not yet proven

- The netns `DialContextInNamespace` path is not covered by the interop run.
