# YANG-Push over UDP-notif (huawei_ne8000)

Engineering record for the YANG-Push exporter.
Files: `go/nl6/yangpush_*.go`, the VRP NETCONF dialect in `go/nl6/netconf_vrp.go`.
Operator reference: `docs/reference/yang-push-udp-notif.md`.
Limitations: `go/nl6/resources/huawei_ne8000_limitations.md`.
Interop gate: `make test-interop-yangpush`, `examples/netgauze/`, `go/nl6/yangpush_interop_test.go`.

## Sources

- Captures from `network-analytics/ietf-network-analytics-document-status`.
  - `125/Hackathon/yangpush-publisher/huawei-vrp-ip` holds the wire, the payloads and the subscription config.
  - `123/Hackathon/ipf-zbl1243-r-daisy-21_huawei_vrp_ne_20250717_141629` holds the YANG library and modules.
- The capture repo has no licence.
  Permission to use derived fixtures was requested from Thomas Graf and is pending.
  If it is refused, replace the derived fixtures with synthetic ones of the same byte layout before merge.
- Fixtures are anonymised.
  The hostname is `ne8000-sim-1`, interface names are synthetic and the publisher ID is `192.0.2.13` (`0xC000020D`).
- The referee is NetGauze v0.13.0, behaviour read at commit `e13b74f`.
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
- The message ID and the envelope `sequence-number` count per subscription.
  They are 0 on `subscription-started`.
- Subscriptions 8 (statistics) and 9 (interface) are periodic at 60 s with anchor `2025-01-01T00:00:30Z`.
  Subscription 9 runs three seconds after subscription 8.
  Their filters are by reference (`STATEINTERFACE2`, `STATSINTERFACE2`), answered through `get` on `filters`.
- A link-down interface reports `oper-status` `down`.
  The capture has 49 interfaces admin up and oper down, and none `lower-layer-down`.
- The YANG library carries `augmented-by` entries (draft-ietf-netmod-yang-library-augmentedby).
  They let NetGauze load the envelope, observation, distributed-notification, push-revision and UDP-notif transport modules.
- `ietf-netconf-monitoring` is served because the NE lists it.
- `content-id` is the FNV-32a hash of the module list, as a decimal string.

## Where nl6 goes beyond the captures

- Subscription 10 has no capture.
  It is on-change for `oper-status | admin-status`, dampening 0, `sync-on-start` true, filter reference `ONCHANGEINTERFACE`.
  The NE advertises on-change, but no capture shows it on the wire.
  Its sync-on-start `push-update` carries only `name`, `admin-status` and `oper-status`.
- Every interface appears in subscription 8.
  The device sent statistics for a subset.
- `ietf-udp-client` revision `2025-05-14` is a guess.
  The NE library lists none.
- The `augmented-by` rows for `ietf-yang-push-revision` and `ietf-udp-notif-transport` under `ietf-subscribed-notifications` come from the MA5800T capture, not the NE.
- A `get` on a subscription by ID also returns `receiver-instances`.
  Strict subtree filtering would not.
  An unknown ID returns an empty `<data/>`, and NetGauze reports that as a parse error.
- Scenario-window participation is not implemented.

## Operational decisions

- Opt-in per device through the REST `yang_push` block, `collector` and `segment_size` (default 1436, 512 to 65507).
  The seed flag is `-yang-push-collector`.
  Only `huawei_ne8000` streams.
  An all-incapable request gets `400`.
  A mixed batch skips the others with one log line per profile per process.
- NetGauze needs NETCONF, so `-netconf-enable` is required.
  `-netconf-authorized-keys <authorized_keys file>` enables key login for `simadmin` on every NETCONF SSH listener and on call home.
  Password login stays.
  Key options in the file are ignored.
  The file is read even without `-netconf-enable`.
- The socket is a connected UDP socket bound to the device IP.
  Connecting is what lets the device see ICMP port-unreachable.
  A failed bind fails the opt-in for that device, with no fallback.
- `-fidelity` mutes all three subscriptions through `fidelityMutesBackground(sourceBackground)`.
  `subscription-started` is deferred until the first unmuted activity.
- Status is `GET /api/v1/yangpush/status` with `messages_sent`, `segments_sent`, `send_failures`, `state_events_dropped` and `fidelity_suppressed`.
  `state_events_dropped` is the exporter queue, which drops the oldest.
  Drops inside `InterfaceState`'s own broadcast channel are counted in the shared gNMI `state_events_dropped`, not per exporter.
- Load profile.
  Every device fires subscription 8 at the same wall-clock anchor and subscription 9 three seconds later.
  A large fleet produces a synchronized burst each minute on the host and the collector.
  This is the device's real behaviour, so nl6 does not jitter it.

## Interop gate

`make test-interop-yangpush` (Linux only) does the following.

1. Builds NetGauze v0.13.0 from its release `.deb` (`examples/netgauze/Dockerfile`, base and `.deb` pinned by digest) and starts it with Redpanda on the host network (`examples/netgauze/compose.yml`).
2. Generates a throwaway ed25519 key.
   NetGauze uses the private key and nl6 gets the public key through `-netconf-authorized-keys`.
3. Starts nl6 and creates three `huawei_ne8000` devices with a `yang_push` block.
   The collector address is `10.254.0.1:10000`, the host end of the nl6sim veth.
4. Waits 150 s, then asserts the following.
   - NetGauze logged `YANG Library fetched from device` for each device and no `WARN` or `ERROR` line.
   - The Kafka JSON topic holds messages for subscriptions 8, 9 and 10 from each device.
   - nl6's `segments_sent` is above `messages_sent` and `send_failures` is 0, so segmented messages reached NetGauze and decoded.
   - An interface taken down through the REST API produces a subscription 10 message with `oper-status` `down` within 5 s.

The collector config is NetGauze's `config_udpnotif_telemetry.yaml` with the Kafka JSON endpoint, `netconf.username: simadmin` and the generated key.
The plan asked for the OTLP or Prometheus decode and validation counters.
The stack has no OTLP receiver, so the gate reads NetGauze's log level instead.

## Not yet proven

- The live NetGauze run (`make test-interop-yangpush`) is pending on a Linux host.
  This work was built on macOS, where nl6 devices cannot run.
  Only these were checked locally: the compose file parses, the test compiles and skips without its env var and `make -n` parses the target.
  Record the PASS output here when the run happens.
- `yanglint` validation of the payloads has not run anywhere.
- The exact Kafka JSON field names the test reads (`collection-timestamp`, `export-address`, the `yang-push-subscription` `id`) come from reading NetGauze `crates/yang-push/src/model/telemetry.rs`, not from a live run.
- The `rpk topic consume` flags in the test are unverified against Redpanda v25.3.1.
