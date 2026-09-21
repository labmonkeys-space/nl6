# NBAR2 export: how the claims were verified (nl6#672 to nl6#683)

Moved here from `docs/reference/flow-export.md`, which keeps the operator-facing facts and points here.
This is the long-form record: which check has detection power, what the captures showed, and which mistakes are easy to reintroduce.

## The claim and its evidence rule

The export is **conformant and interop-tested against open decoders**.
It is not Cisco-faithful.
The design spec for the feature carried an evidence rule: the encoder may claim fidelity to Cisco's layout only on the strength of a Cisco document or a capture from a real router.
A contradicting capture makes the encoder follow or the claim downgrade.
The IOS-XE 26.01.02 capture of 2026-09-21 contradicted the encoder on six points.
One point was a correctness defect and the encoder followed (nl6#679).
For the other five the claim was downgraded (nl6#680).
The feature exists so collectors can be tested against layer-7 records at scale.
Every open decoder tried reads nl6's records correctly.
Following the router on the remaining five would be several wire changes plus a generation change to transaction-end aging, for a fidelity no consumer has asked for.
The differences are recorded rather than filed.
An item is filed individually when a consumer needs it.

## The independent-collector gate

`make test-interop-ipfix` is the check with detection power for this feature.
Every other IPFIX and AVC test decodes nl6's bytes with nl6's own decoder.
A shared misreading of RFC 7011 section 7 or of Cisco's PEN 9 numbers would pass all of them.
The reference capture test is the other external reading, but it reads Cisco's bytes, not nl6's.

The target builds `examples/ipfixcol2/`.
That image is Debian forky's `ipfixcol2` 2.8.0 package with libfds's own `cisco.xml`.
Ubuntu 24.04 does not package it.
The target starts CESNET IPFIXcol2 on the host network and runs two tests that read the collector's own NDJSON output.

The first test drives a real exporter through `Tick` and asserts, against the collector's output:

- IEs 12235 and 9357 under PEN 9 resolve **by name**, as `cisco:appHTTPHost` and `cisco:appHTTPUriStatistics`. The `en9:idNNNN` form is the failure signal. The test names both causes: the collector lacks the element definitions, or nl6 sent the wrong enterprise number or id.
- `applicationId` decodes to an id in the device's catalog, and the record's protocol and port match that entry.
- The host and URI values are catalog values.
- The application table (template 259) arrives with a name and description for every id seen in a data record.
- The RFC 7011 section 3.1 sequence arithmetic holds per observation domain.
- A plain IPFIX control device shows none of the above.

The second test runs a real scenario over three NBAR2 participants and one plain one.
It reconciles the report's `applications[]` and `l7_values[]` against sums over the collector's decoded records per key, with no tolerance band.

Both tests were verified by mutation.
Disabling the host fold fails the second by name.
Never resolving the id fails the first by name.

### The non-printable-bytes lesson

libfds types IEs 12235 and 9357 as strings.
IPFIXcol2's JSON output DROPS non-printable bytes from a string unless `nonPrintableChar` is on.
With the flag off, the collector showed the URI statistics as the URI alone, because the NUL and the two count bytes were dropped.
A Cisco-layout host appeared as `P4www.example.com`.
`0x50` is `P` and `0x34` is `4`, the two printable bytes of the six-byte prefix.
An earlier version of the reference doc said the collector "cuts the value at its NUL".
That reading looks the same on a URI and hides four of the six prefix bytes on a host.
The shipped `examples/ipfixcol2/ipfixcol2.xml` has the flag on.
Every byte arrives as a `\u00XX` escape, and the gate asserts the six-byte host prefix and the URI's NUL and big-endian hit count byte for byte.

The gate runs in CI beside the SNMPv3 and Pyroscope interop steps.
It fails rather than skips when docker is missing.

## The IOS-XE 26.01.02 reference capture

A real Cisco Catalyst 8000V running IOS-XE 26.01.02 exported AVC records through containerlab on 2026-09-21.
The capture, the router's configuration and the files that regenerate it are in `go/nl6/testdata/cisco-avc/capture/`.
`cisco_avc_capture_test.go` decodes the pcap with its own template parser and pins each fact below.
`capture/README.md` says how to regenerate the capture in about five minutes against a vrnetlab-built `cisco_c8000v` image.
`go/nl6/testdata/cisco-avc/NOTES.md` says which facts are Cisco-sourced and which are nl6 decisions.

### What the capture confirmed

- The IE 9357 layout: URI, NUL, big-endian 2-byte hit count, no trailing delimiter. `uriStatsValue` reproduces the router's bytes exactly. Pinned by `TestCiscoAVCCapture_URIStatisticsLayout`.
- The application table string lengths of 24 and 55, and the engine-3 `http` id `0x03000050`. Pinned by `TestCiscoAVCCapture_OptionsTemplates`.
- Sequence numbers that count option data records.
- A maximum datagram of 1420 bytes with no fragmentation. Pinned by `TestCiscoAVCCapture_MessageShape`.

### What the capture contradicted

1. **HTTP host (IE 12235) carries a constant prefix. Resolved in v0.30.0 (nl6#679).** Every router record starts the field with `03 00 00 50 34 02` and then the hostname. A record with no host carries exactly the six bytes. nl6 emitted the bare hostname before nl6#679, so a decoder written to Cisco's layout misread the value. nl6 now emits the prefix from the single constant `avcHostPrefix`. The wire change moved `plan-b-nbar2.tsv`. The interop gate asserts the prefix on every record the collector decodes. Pinned by `TestCiscoAVCCapture_HTTPHostCarriesConstantPrefix`, which compares the capture against the production constant.
2. **The record is a connection record with a different field order.** IOS-XE refuses to bind a monitor that collects URI statistics without `match connection id`. That is PEN 9 IE 12242, 4 bytes, zero on ICMP. It refuses that without `cache timeout event transaction-end`. The router's template 258 has 17 fields. Match fields come first. The two variable-length fields sit before the counters. URI statistics come before the host. nl6's record is the 54-byte unidirectional prefix followed by applicationId, host and URI statistics, with no connection id. This is the one item that would change what a collector computes, because it is a generation model and not an encoding. Pinned by `TestCiscoAVCCapture_DataTemplateFieldOrder`.
3. **Host and URI appear on ingress records only.** The router puts them on the ingress-direction record of an HTTP request. The reverse-direction record carries the six-byte host prefix and an empty URI field. nl6 puts host and URI on every AVC record. Pinned by `TestCiscoAVCCapture_LayerSevenValuesAreIngressHTTPOnly`.
4. **URI statistics record the first path segment only.** `/api/v1` arrives as `/api` and `/static/app.js` as `/static`. nl6's shipped catalogs carry multi-segment URIs such as `/api/v1/items`. Pinned by `TestCiscoAVCCapture_URIStatisticsLayout`.
5. **A real application table is two-thirds engine 13.** The router's table has 1560 rows: 127 in engine 1, 748 in engine 3 and 685 in engine 13. NBAR2 reclassified half the plain HTTP transactions mid-connection to `binary-over-http` (`0x0d0001af`) and emitted a second record per request. Every nl6 catalog entry is engine 3 and no engine-13 application exists. Ids the capture sourced: `unknown` `0x0d000001`, `binary-over-http` `0x0d0001af`, `ping` `0x0d0001df`. Pinned by `TestCiscoAVCCapture_OptionsTemplates`.
6. **The interface option table differs in width, fields and template ids.** The router sends scope ingressInterface, then interfaceName at 33 bytes, interfaceDescription at 65 bytes and egressInterface, under template 256. Cisco numbers the tables 256 interface, 257 application, 258 data. nl6's `if-scoped` shape is 32 and 32 with no egressInterface under 257, and its application table is 259. Pinned by `TestCiscoAVCCapture_OptionsTemplates`.

## Digests

Every device not using NBAR2 emits byte-identical output to the Plan A merge.
`testdata/flow-digests/pre-nbar2.tsv` pins it over every shipped type and protocol.
The NBAR2 stream is pinned by `testdata/flow-digests/plan-b-nbar2.tsv`, taken at the Plan B merge and regenerated once for nl6#679.
Regenerate either only for an intended wire change and say so in the commit.

## Size budget

The shipped catalogs were measured at the 528-byte payload budget, which is what a 576-byte frame leaves an IPv6 collector and the budget production loads against.
All 7 universal, 8 `cisco_ios` and 9 `cisco_catalyst_9500` entries fit.
`TestNbar2ShippedCatalogsLoad` pins zero oversized entries at the default MTU's IPv4 budget only.
A pin at the 528-byte floor is deferred work.
