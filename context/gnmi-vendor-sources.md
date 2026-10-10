# gNMI vendor profiles from public sources: Juniper MX10004 and Cisco ASR 9902

Research spike of 2026-10-09.
Question: can nl6 serve a credible gNMI target for a Juniper MX10004 and a Cisco ASR 9902 built only from public information, with no data from a customer network?
Answer: yes for the schema, the chassis layout, the notification shape and the vocabulary; no for exact leaf sets of a few vendor-native sensors, which stay marked as YANG-derived supersets.
Every claim below carries the URL it was read from.
UNVERIFIED marks a claim no fetched page confirmed.
Values are never sourced from anywhere; nl6 generates them.

## Verdict per element

| Element | Juniper MX10004 | Cisco ASR 9902 |
|---|---|---|
| OpenConfig leaf catalogue | Juniper/yang, Apache-2.0 | YangModels/yang vendor/cisco/xr/2442, vendor licence unstated |
| Vendor-native oper catalogue | partial: fabric yes, packet/usage proto only | full: every asr9k and oper module present |
| Notification shape | observed on vJunos-router, free | JSON_IETF observed on xrdocs; PROTO per-leaf UNVERIFIED |
| Chassis layout | hardware guide, complete | hardware guide and data sheet, complete |
| Sensor and error vocabulary | CLI reference samples | TAC docs and command references |
| Free virtual device | vJunos-router | none; XRd needs a service contract and lacks asr9k models |

## OpenConfig models

openconfig/public is Apache-2.0. https://github.com/openconfig/public
Versions on 2026-10-09: openconfig-interfaces 3.11.1, openconfig-platform 0.33.0, openconfig-system 3.3.0, openconfig-network-instance 4.8.0, openconfig-bgp 9.9.1. https://raw.githubusercontent.com/openconfig/public/master/release/models/interfaces/openconfig-interfaces.yang https://raw.githubusercontent.com/openconfig/public/master/release/models/platform/openconfig-platform.yang https://raw.githubusercontent.com/openconfig/public/master/release/models/system/openconfig-system.yang https://raw.githubusercontent.com/openconfig/public/master/release/models/network-instance/openconfig-network-instance.yang https://raw.githubusercontent.com/openconfig/public/master/release/models/bgp/openconfig-bgp.yang
`release/models/platform/` carries the transceiver, cpu, psu and fan augmentations. https://github.com/openconfig/public/tree/master/release/models/platform
The repo ships no instance data beyond three network-instance examples in `doc/examples/`. https://github.com/openconfig/public/tree/master/doc/examples
Each vendor ships its own copy of the OpenConfig modules with deviation files, and the catalogue must be built from the vendor copy so unsupported leaves drop out.

## Juniper MX10004

### Models

Juniper/yang is Apache-2.0 with one folder per release from 14.2 to 25.4. https://raw.githubusercontent.com/Juniper/yang/master/LICENSE https://api.github.com/repos/Juniper/yang/contents/24.2
`24.2/24.2R1.17/` holds `ietf`, `native/{conf-and-rpcs,jti,state}` and `openconfig/models/{augments,deviations/jnx-openconfig-dev.yang}`. https://api.github.com/repos/Juniper/yang/contents/24.2/24.2R1.17 https://api.github.com/repos/Juniper/yang/contents/24.2/24.2R1.17/native
`native/jti/models/junos-fabric.yang` models `/junos/system/linecard/fabric/` with src and dst type, slot and pfe, packets, bytes, per-second rates, drop counters and queue-depth average, current and peak. https://raw.githubusercontent.com/Juniper/yang/master/24.2/24.2R1.17/native/jti/models/junos-fabric.yang
`junos-fpc-env.yang` models `/junos/system/linecard/environment` with power, voltage and temperature records. https://raw.githubusercontent.com/Juniper/yang/master/24.2/24.2R1.17/native/jti/models/junos-fpc-env.yang
No YANG module covers `/junos/system/linecard/packet/usage/`; the field list exists only as `packet_stats.proto` in Juniper/telemetry, Apache-2.0. https://api.github.com/repos/Juniper/yang/contents/24.2/24.2R1.17/native/jti/models https://raw.githubusercontent.com/Juniper/telemetry/master/24.4/24.4R2/protos/junos-telemetry-interface/packet_stats.proto
The `sensor` statement documents both paths as supported sensors. https://www.juniper.net/documentation/us/en/software/junos/interfaces-telemetry/topics/ref/statement/sensor-edit-services-analytics.html
A resolved 22.4R3 issue proves `/junos/system/linecard/packet/usage/` is gNMI-subscribable on MX hardware. https://www.juniper.net/documentation/us/en/software/junos/release-notes/22.4/junos-release-notes-22.4r3/topics/resolved-issues/mx-resolved-issues-cover.html
The Telemetry Explorer sits behind Okta login, so its leaf lists are UNVERIFIED. https://apps.juniper.net/telemetry-explorer/home

### Notification shape

A vJunos-router 24.2R1-S2.5 notification carries prefix origin `gnmi`, elems `interfaces` and `interface[name=ge-0/0/0]` with no module prefix, one interface per notification, and a `registered_ext id 1` extension. https://blog.no42.org/article/gnmi-hpe-juniper/
gnmic issues 261 and 503 show the same shape on MX960 hardware and note one event per line card for logical interfaces spanning line cards. https://github.com/openconfig/gnmic/issues/261 https://github.com/openconfig/gnmic/issues/503
The extension is `GnmiJuniperTelemetryHeaderExtension` with 14 fields including system_id, component_id, sensor_name, subscribed_path, streamed_path, component, sequence_number and export_timestamp, registered as `EID_JUNIPER_TELEMETRY_HEADER = 1`. https://github.com/Juniper/telemetry/blob/master/20.3/20.3R1/protos/GnmiJuniperTelemetryHeaderExtension.proto https://raw.githubusercontent.com/Juniper/telemetry/master/20.3/20.3R1/protos/gnmi_ext.proto
Juniper's dial-in page says the header is exported as an extension from 19.4. https://www.juniper.net/documentation/us/en/software/junos/interfaces-telemetry/topics/concept/dial-in-telemetry.html
Configuration paths use PROTO only and carry no prefix. https://www.juniper.net/documentation/us/en/software/junos/interfaces-telemetry/topics/concept/subscribe-rpc.html

### Virtual device

vJunos-router is free for non-production use with no time limit and no JTAC support; containerlab says no Juniper account is needed. https://www.juniper.net/us/en/dm/vjunos-labs.html https://containerlab.dev/manual/kinds/vr-vjunosrouter/
It is one VM with one RE and one FPC built from vMX, 4 cores and 5 GB RAM. https://www.juniper.net/documentation/us/en/software/vjunos-router/vjunos-router-kvm/topics/vjunos-router-overview-understanding.html https://www.juniper.net/documentation/us/en/software/vjunos-router/vjunos-router-kvm/topics/vjunos-router-kvm-hw-requirements.html
containerlab kind `juniper_vjunosrouter` boots in 5 to 10 minutes with gNMI pre-enabled. https://containerlab.dev/manual/kinds/vr-vjunosrouter/
gnmic capabilities report gNMI 0.7.0 with JSON, PROTO, ASCII and JSON_IETF. https://blog.no42.org/article/gnmi-hpe-juniper/
Whether the virtual PFE streams the fabric and packet/usage sensors or component temperatures is UNVERIFIED and is the first thing to test.
The EULA text on redistributing captures was not reachable; captures are treated as a private oracle until it is read.

### Chassis layout

CLI mapping: FPC 0 to 3, PIC 0 to 5, PEM 0 to 2, RE 0 to 1, SFB 0 to 5, Fan Tray 0 and 1 with Fan 0 to 11, two RCB slots, six SFB slots, three PSU slots. https://www.juniper.net/documentation/us/en/hardware/mx10004/topics/topic-map/mx10004-system-overview.html
JNP10K-PWR-AC2 is the 5500 W dual-feed AC, HVAC or HVDC unit; AC3 is 7800 W. https://www.juniper.net/documentation/us/en/hardware/mx10004/topics/topic-map/mx10004-system-overview.html
JNP10004-FAN3 holds six modules with two counter-rotating fans each. https://www.juniper.net/documentation/us/en/hardware/mx10004/topics/topic-map/mx10004-cooling-system.html
JNP10K-LC480 has 48 SFP and SFP+ 1/10G ports numbered 0/0 to 1/23 across MIC0 and MIC1. https://www.juniper.net/documentation/us/en/hardware/mx10008/topics/concept/mx10k-lc480-line-card-descripion.html
`show chassis hardware` has a public MX10008 sample with Control Board, PIC, PEM, Fan Controller, Fan Tray and SFB rows; no MX10004 sample exists, UNVERIFIED description strings for LC480 PICs. https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-hardware.html
Sensor names: `show chassis environment` for MX10008 lists CB intake, exhaust and middle sensors and FPC EA and HMC die sensors; `environment fan`, `environment pem 0` and `show chassis fpc` have MX10004 samples. https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-environment.html https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-environment-fan.html https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-environment-pem.html https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-fpc.html

## Cisco ASR 9902

### Models

YangModels/yang has no LICENSE file and the API reports no licence; the README places `vendor/cisco` under a vendor-specified licence and the files say "All rights reserved". https://raw.githubusercontent.com/YangModels/yang/main/README.md https://api.github.com/repos/YangModels/yang
nl6 therefore derives a catalogue from the files and never redistributes them.
IOS-XR 24.x releases are under `vendor/cisco/xr/{2411,...,2442}`; 2442 is IOS-XR 24.4.2 with 2280 entries, 154 openconfig modules and 49 deviation files. https://api.github.com/repos/YangModels/yang/contents/vendor/cisco/xr https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xr/2442/README.md
Present in 2442 and advertised by `capabilities-asr9k-x64.xml`: asr9k-fab-health-oper, asic-errors-oper, asic-error-oper, asr9k-np-oper, controller-optics-oper, ipv4-arp-oper, fib-common-oper, lpts-pre-ifib-oper, lpts-ifib-oper, sysadmin-asr9k-envmon-ui, asr9k-xbar-oper, asr9k-fsi-oper, invmgr-oper, platform-oper. https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xr/2442/capabilities-asr9k-x64.xml https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xr/2442/Cisco-IOS-XR-asr9k-np-oper.yang
There is no asr9k-misc-oper module; the only misc-oper is nto-misc-oper, and environment data lives in envmon-oper and sysadmin-asr9k-envmon-ui. https://api.github.com/repos/YangModels/yang/git/trees/d9c686b1cfa0b0a85f4cf1bee5a40a0f642f1329?recursive=1
Structure worth knowing: asic-errors is `asic-errors/nodes/node/asic-information/instances/instance/error-path/{single-bit-soft-errors, multiple-bit-soft-errors, asic-error-parity-soft, crc-hard-errors, back-pressure-hard-errors, link-hard-errors, reset-soft-errors}` with name, leaf-id, count, last-cleared, thresh-hi and period-hi leaves. https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xr/2442/Cisco-IOS-XR-asic-errors-oper.yang
fab-health is `fabric-health-stats/nodes/node/fab-health-stats/{drop-counters, qdepth-stats, s1-counters, s2-counters, s3-counters, credits, stuck-vqi-info, arb-info}`. https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xr/2442/Cisco-IOS-XR-asr9k-fab-health-oper-sub1.yang
np-oper is `hardware-module-np/nodes/node/nps/np/{fast-drop, load-utilization, np-summary, np-fabric-counters, fabric-flow-control}` with interface-name and counter-value leaves. https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xr/2442/Cisco-IOS-XR-asr9k-np-oper.yang
lpts-pre-ifib is `lpts-pifib/nodes/node/{dynamic-flows-stats, punt-policer-stats, pifib-hw-flow-policer-stats}`. https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xr/2442/Cisco-IOS-XR-lpts-pre-ifib-oper.yang

### Notification shape

xrdocs shows gnmic capabilities on XR with gNMI 0.7.0 and encodings JSON_IETF, ASCII and PROTO. https://xrdocs.io/programmability/blogs/OpenConfig-gNMI
With JSON_IETF the module name sits in `prefix` as `openconfig-interfaces:` and one update carries the whole container as nested values. https://xrdocs.io/programmability/blogs/OpenConfig-gNMI
A 6.5.3 gist shows `Path: openconfig-interfaces:interfaces/interface` on Get. https://gist.github.com/hellt/333b10e0ade32b73d388e4f996ad387e
No public page shows PROTO-encoded subscribe output from XR, so the per-leaf update layout with PROTO is UNVERIFIED and must be confirmed on a live XR before nl6 claims it. https://community.cisco.com/t5/service-providers-knowledge-base/understanding-gnmi-on-ios-xr-with-python/ta-p/4014205
The 24.x programmability guide documents update bundling, off by default at 32768 bytes, and shows `origin:"openconfig-interfaces"` subscriptions. https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/24xx/programmability/configuration/guide/b-programmability-cg-asr9000-24xx/use-grpc-protocol-to-define-network-operation-with-data-models.html
The 24.x telemetry guide shows a native subscription with `prefix.origin` `Cisco-IOS-XR-infra-statsd-oper` and encoding PROTO, and adds openconfig pipeline-counters errors from 24.2.11. https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/24xx/telemetry/configuration/guide/b-telemetry-cg-asr9000-24xx/enhancememts-to-telemetry.html

### Virtual device

XRd needs a cisco.com account with a service contract and Smart Licensing per instance. https://xrdocs.io/virtual-routing/tutorials/2022-08-22-xrd-images-where-can-one-get-them https://www.cisco.com/c/en/us/products/collateral/routers/ios-xrd/ios-xrd-ds.html
`capabilities-xrd-vrouter.xml` for 24.4.2 lacks fab-health, asr9k-np, asic-errors, controller-optics and invmgr, so XRd cannot produce the asr9k-native shapes. https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xr/2442/capabilities-xrd-vrouter.xml
containerlab's xrv9k kind needs 14 GB RAM and 25 minutes to boot and names no free image. https://containerlab.dev/manual/kinds/vr-xrv9k/
The DevNet sandbox docs list no XR always-on target; the hostname and gNMI status seen in community threads are UNVERIFIED. https://developer.cisco.com/docs/sandbox/ https://community.cisco.com/t5/devnet-sandbox/ios-xr-programmabilty-unable-to-connect-via-grpc/td-p/5229855

### Chassis layout

Hardware guide table: A99-RP-F x2, PWR-1.6KW-AC or DC x2, ASR-9902-FAN x3, ASR-9902-LC x1. https://www.cisco.com/c/en/us/td/docs/iosxr/asr9000/hardware-install/9001-hig/b-asr9001-hardware-installation-guide/b-asr9001-hardware-installation-guide_chapter_01.html
Ports: 48 across slice 0 and slice 1 as 2 QSFP-DD 100GE, 6 QSFP28 100GE, 16 SFP28 25/10GE and 24 SFP+ 10GE. https://www.cisco.com/c/en/us/td/docs/iosxr/asr9000/hardware-install/9001-hig/b-asr9001-hardware-installation-guide/b-asr9001-hardware-installation-guide_chapter_01.html
Data sheet PID descriptions: "ASR 9902 Chassis, 2RU", "ASR 9900 Fixed Chassis Route Processor", "ASR 9900 Fixed Chassis AC Power Supply", "ASR 9902 Fan Tray". https://www.cisco.com/c/en/us/products/collateral/routers/asr-9000-series-aggregation-services-routers/datasheet-c78-744663.html
`show environment` sample lists 0/FT0 to 0/FT2 ASR-9902-FAN and 0/PT0-PM0 and PM1 PWR-1.6KW-AC; the `show inventory power` sample is an ASR 9903 with ASR-9900-AC-PEM. https://www.cisco.com/c/en/us/td/docs/iosxr/asr9000/hardware-install/9001-hig/b-asr9001-hardware-installation-guide/b-asr9001-hardware-installation-guide_chapter_0111.html
A cisco-nsp post shows `show hw-module fpd` with 0/RP0 and 0/RP1 A99-RP-F and 0/0 ASR-9902-LC. https://www.mail-archive.com/cisco-nsp@puck.nether.net/msg69271.html
No full `show inventory` or `show platform` for an ASR 9902 is public; component names in nl6 come from the location grammar and the data sheet descriptions.

### Vocabulary

TAC document 220131 shows `show asic-errors` banners Single Bit Errors, Multiple Bit Errors, Parity Errors and Generic Errors with Name, Leaf ID, Error count and Last clearing, and `show controller np fast-drop` rows per interface and priority. https://www.cisco.com/c/en/us/support/docs/routers/asr-9000-series-aggregation-services-routers/220131-troubleshoot-punt-fabric-data-path-failu.html
xrdocs documents the np fast-drop, load-utilization, fsi fabric-stats and xbar cross-bar-stats sensor paths. https://xrdocs.io/telemetry/tutorials/packet-drop-identification-mdt
The Advanced System command reference documents `show controller fabric {arbiter | fia link-status | crossbar}` columns. https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/adv-sys/command/reference/b-advsys-cr-asr9000/b-advsys-cr-asr9000_chapter_00.html
The System Management command reference documents `show inventory`, `show platform` and `show environment` fields. https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/system_management/command/reference/b-system-managment-cr-asr9000/hardware-redundancy-and-node-administration-commands.html
The Cisco Community sensor-list article returned 403 to every fetch and is UNVERIFIED. https://community.cisco.com/t5/service-providers-knowledge-base/asr9k-and-ncs55xx-telemetry-sensors-for-system-health/ta-p/4859672

## Tooling

goyang is Apache-2.0; `yang.Entry` exposes Dir, Kind, Type, Key and Config, applies deviations through `ApplyDeviate`, and `EnumType` gives names and values. https://github.com/openconfig/goyang https://raw.githubusercontent.com/openconfig/goyang/master/pkg/yang/entry.go https://raw.githubusercontent.com/openconfig/goyang/master/pkg/yang/types_builtin.go
The goyang CLI has only `-f tree` and `-f types` and no deviation flag; whether it parses IOS-XR and Junos native trees cleanly is UNVERIFIED. https://raw.githubusercontent.com/openconfig/goyang/master/yang.go
pyang is ISC; `-f flatten` emits CSV with xpath and optional keyword, primitive_type, flag, type, key and deviated columns but no enum values; `--deviation-module` applies deviations. https://github.com/mbj4668/pyang https://raw.githubusercontent.com/mbj4668/pyang/master/pyang/plugins/flatten.py https://raw.githubusercontent.com/mbj4668/pyang/master/man/man1/pyang.1
gnmic `--format json` fields are source, subscription-name, timestamp, time, prefix, target, updates with Path and values, deletes and extensions, all omitempty; scalar proto values copy through and json_ietf bytes are unmarshalled. https://github.com/openconfig/gnmic/blob/main/pkg/formatters/msg.go
openconfig/gnmi `testing/fake` replays `fake.proto` Value lists with no YANG awareness, and lemming is OpenConfig-only, so neither replaces an nl6 extension. https://raw.githubusercontent.com/openconfig/gnmi/master/testing/fake/proto/fake.proto https://raw.githubusercontent.com/openconfig/lemming/main/README.md
Synthetic identifiers use RFC 5737 IPv4, RFC 3849 IPv6, RFC 5398 ASNs and RFC 9542 MAC ranges. https://www.rfc-editor.org/rfc/rfc5737 https://www.rfc-editor.org/rfc/rfc3849 https://www.rfc-editor.org/rfc/rfc5398 https://www.rfc-editor.org/rfc/rfc9542

## Open gaps, ranked

1. XR PROTO per-leaf subscribe layout has no public sample; confirm on any XR, since the convention is model-independent.
2. Whether vJunos-router streams the native fabric and packet/usage sensors and component temperatures; boot it and subscribe.
3. `/junos/system/linecard/packet/usage/` leaf names as streamed over gNMI; only the proto is public.
4. MX10004 and ASR 9902 inventory description strings for PICs, line cards and PSUs; no public `show chassis hardware` or `show inventory` for either model.
5. Redistribution terms for vJunos-router captures and for catalogues derived from Cisco YANG.

## What this means for nl6

Build the catalogue generator on goyang inside the nl6 Go module, fed by vendor copies of the models with deviations applied, and cross-check with pyang flatten.
Model the two chassis from the hardware guides as component trees, with nl6's existing counter, sine-wave and optical engines bound to the leaves.
Reproduce the two notification styles: Juniper per-interface prefix with the header extension, Cisco module-prefixed prefix with per-container JSON_IETF and a PROTO per-leaf mode once gap 1 is closed.
Mark every vendor-native subtree as YANG-derived in the device-type reference so consumers know the leaf set may be a superset of what hardware emits.

## Lab host and first capture (2026-10-09)

A lab VM on the Proxmox host runs Ubuntu 24.04 with Docker 29, containerlab 0.79.0, gnmic 0.49.0 and KVM acceleration, reached over SSH through a jump host.
Nokia SR Linux (ghcr.io/nokia/srlinux:latest, free) runs there as `clab-srl-srl1` with OpenConfig enabled through `/system/management/openconfig/admin-state`.
Against it, `gnmic subscribe --mode once -e json_ietf` returns one update per subscribed container with the module name in `Path` and nested string-typed values, while `-e proto` returns one update per leaf with no module name and native numeric types.
This is the encoding rule from the gNMI specification, which allows only scalar `TypedValue` in PROTO, so the per-leaf layout is expected on every vendor and gap 1 reduces to confirming XR's key and prefix placement. https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md
SR Linux names components `Chassis`, `ControlA`, `CPU-ControlA`, `Ethernet-1/1-Port` and `Ethernet-1/1-transceiver`, which is a third naming scheme to support next to Junos and XR.
The vJunos-router qcow2 is still missing because the Juniper portal is a browser-only download; vrnetlab is cloned at `~/vrnetlab` on the VM ready for `make` once the image is in `juniper/vjunosrouter/`.

## vJunos-router on Proxmox (2026-10-09)

vJunos-router inside containerlab inside a Proxmox VM is three hypervisor levels deep and the inner Junos VM crawled through its boot loader at minutes per second; Juniper states the product is unsupported in any setup that runs it inside a VM "due to the constraints of deeply nested virtualization". https://www.juniper.net/documentation/us/en/software/vjunos-router/vjunos-router-kvm/topics/vjunos-router-kvm-hw-requirements.html
Running the qcow2 directly as a second lab VM on the Proxmox host (4 cores, `cpu: host`, 5120 MB, machine `pc`, SMBIOS product `VM-VMX` family `lab`) boots the vCP in under a minute.
The image is a Linux wrapper that spawns a nested FreeBSD vCP (1 vCPU, 2 GB) and a nested Linux vFP running `riot`; the vFP only came online after the VM got data NICs beyond the management NIC, so attach at least one extra virtio NIC.
The vmm-data config disk was ignored both as a virtio disk and as USB storage attached through `args`, so the base config went in over the serial socket; lines over about 70 columns crash the console CLI, and ZTP must be removed first with `delete chassis auto-image-upgrade`.
vJunos-router 26.2R1.7 cannot serve gNMI Subscribe: it answers `Unimplemented`, `na-grpcd` dies with "drend directory init failed", and both `junos-decoupled-rendering` and `junos-openconfig` are installed as empty package mounts with no `contents.izo` in `/packages/db`.
Capabilities, Get for config and NETCONF work, so the image is usable for everything except telemetry.
Next step is an earlier image; a public capture shows Subscribe working on 24.2R1-S2.5. https://blog.no42.org/article/gnmi-hpe-juniper/

## vJunos-router 25.4R1.12 capture (2026-10-09)

The 25.4R1.12 qcow2 honoured the vmm-data config disk on the USB bus, booted to SSH in under two minutes, and serves gNMI Subscribe in ONCE mode with the `openconfig` and `juniper` origins.
Subscribe accepts only PROTO and JSON on this release; JSON_IETF is refused with "Encoding 4 not supported, Only PROTO/JSON encoding supported", and JSON produces the same one-update-per-leaf layout as PROTO.
Each notification carries the prefix at the list entry, for example `openconfig:/interfaces/interface[name=ge-0/0/0]`, with leaf-relative update paths and the Juniper header extension whose decoded fields include system_id `vjunos-mx`, sensor_name `sensor_1015_3_1`, the subscribed and streamed paths and component `xmlproxyd_TM_Thread_1`.
Gap 2 is closed: component temperature streams for `FPC0` and `Routing Engine0`, and component inventory streams for CB0, Chassis, FPC0, FPC0:CPU and FPC0:MEZZ0 with the full openconfig-platform state leaf set.
A `/components/component/state` subscription renders one notification per component, with `state/temperature/instant` inside the notification of the two components that have a sensor (10 components, 10 notifications).
nl6 first shipped the temperature leaf as a second subtree on the same entry path, so FPC0 and Routing Engine0 rendered twice (16 notifications for 14 components, nl6#765); the leaf is now a filtered leaf of the inventory subtree and the loader refuses same-path subtrees with overlapping entries.
Gap 3 is closed: `/junos/system/linecard/packet/usage/` renders as `juniper:/components/component[name=FPC0:NPU0]/properties/property[name=<counter>]/state/value` with counters such as `ts-input-packets`, `ts-output-packets-pps`, `ts-fabric-input-packets` and `lts-sw-input-high-drops`, plus `FPC0:CC0` and `FPC0:CPU0` components.
The native `/junos/system/linecard/fabric/` and `/environment/` sensors return no notifications on the virtual PFE, so their leaf sets stay YANG-derived from junos-fabric.yang and junos-fpc-env.yang.
The native `/junos/system/linecard/interface/` sensor renders per-queue counters under `juniper:/interfaces/interface[name=ge-0/0/x]/state/counters/out-queue[queue-number=N]/`.
The 31 capture files (PROTO and JSON per subtree, about 1.6 MB) live in the session scratchpad and on the lab VM; they are lab output under Juniper's non-production licence and are the seed for the nl6 Juniper profile.
