# Cisco AVC extract: notes

This directory is the evidence base for the NBAR2 IPFIX encoder.
Read `docs/superpowers/specs/2026-09-18-nbar2-ipfix-l7-export-design.md`, section 1, before editing.
`elements.tsv` is a factual table of IE numbers.
It is not a copy of any Cisco document.

## Reference policy

Primary: Cisco documentation and RFCs, cited by title, revision and URL.
Corroborating: CESNET libfds `cisco.xml`, a BSD-licensed data file, never copied here.
libfds and IPFIXcol2 C sources are not read.
Excluded: ElastiFlow, on licence grounds (object-code EULA; legacy repo under a non-OSI commercial-use restriction).
The 2015 Cisco guide was read from its HTML chapters throughout because the PDF does not decode through the tools available, and the two are believed, not verified, to be identical.

## Status column

`verified`: a Cisco document or an RFC names the IE number for at least one platform; layout sub-facts and encoder decisions live in the note and may still be open.
`contested`: sources disagree on the number and at least two are cited.
`unresolved`: no authoritative source names the number.
The note column, not the status, says whether the layout is complete enough to encode.

## Contested (resolved)

### HTTP Host: 45003 and 12235 are the same element (resolved)

45003 and 12235 are the same element: 45003 = 0x8000 | 12235.
Cisco's "Export Field ID" column quotes the template field specifier with the enterprise bit already set, not a second IE number; RFC 7011 section 3.2's Information Element identifier, the low 15 bits, is 12235, and that is what libfds names and what a decoder reports beside PEN 9.

Cisco's 2015 Field Definition Guide (ISR G2, ASR 1000) gives 45003 (`cisco-avc-fdg-2015`).
Its option-template table lists HTTP host as a variable-length string field, IPFIX only, max 512 chars on IOS and 2 KB on IOS XE.
libfds defines appHTTPHost as IE 12235 with data type string, with no source tag and no comment attached to that element (`libfds-cisco-xml`).
Task 3 checked four IOS-XE 17.x / Catalyst-era Cisco documents for either number: the Network Services Configuration Guide, Cisco IOS XE 17.x Flexible NetFlow overview (`cisco-fnf-ntw-servs-17x`), the Flexible NetFlow Configuration Guide, Cisco IOS XE 17 (`cisco-fnf-xe17-book`), the Catalyst 9500 System Management Configuration Guide's AVC chapter (`cisco-cat9500-avc`), and the Catalyst 9800 WLC AVC chapter (`cisco-cat9800-wlc-avc`).
The Network Services Configuration Guide, Cisco IOS XE 17.x Flexible NetFlow overview (`cisco-fnf-ntw-servs-17x`) does not name an exported field ID for HTTP host.
The Flexible NetFlow Configuration Guide, Cisco IOS XE 17 (`cisco-fnf-xe17-book`) does not name an exported field ID for HTTP host either.
The Catalyst 9500 chapter documents the `option application-table [ timeout seconds ]` CLI but has no field-ID table.
The nearest standalone AVC configuration guide found, the Cisco IOS XE 16 book (`cisco-avc-cfg-xe39s`; its page names Release 3.9S only in a related-document link), predates the 17.x train and also names neither number.
Resolution: row `9/12235` is `verified`; Cisco's 45003 is the wire specifier 0x8000 | 12235 and libfds's 12235 is the IE id, the same element.
45003 is confirmed only for ISR G2 and ASR 1000, by the 2015 guide.
Catalyst 9500 (and Catalyst 9000 generally) support for HTTP host export, and which IE number it would use, remains unconfirmed by any Cisco document read for this task.

## Unverified: TLS SNI / common name

Searched on 2026-09-18 (sources: cisco-avc-fdg-2015, cisco-avc-fdg-2015-exported-fields, cisco-fnf-ntw-servs-17x, cisco-fnf-xe17-book, cisco-cat9500-avc, cisco-cat9800-wlc-avc, cisco-cat9800-eta, cisco-nbar-extracted-fields-xe16-6, cisco-nbar-pp68, cisco-nbar-pp74, libfds-cisco-xml).
No Cisco PEN 9 element exporting a TLS SNI or certificate common name as a string was found on ISR G2, ASR 1000, IOS-XE 17.x, Catalyst 9000 or Catalyst 9800.
The Catalyst 9500 AVC chapter (`cisco-cat9500-avc`) is the one document read for this task that names SNI and CN at all: its SSL customization section states "Customization can be done for SSL encrypted traffic using information extracted from the SSL Server Name Indication (SNI) or Common Name (CN)", in the context of the `ip nbar custom ... ssl unique-name` classification CLI, not an export field.
The 2015 Field Definition Guide's "New Exported Fields" chapter (`cisco-avc-fdg-2015-exported-fields`) documents over 50 Flexible NetFlow fields by ID but names neither SSL, TLS, SNI, nor a certificate common name among them.
The Catalyst 9800 Encrypted Traffic Analytics chapter (`cisco-cat9800-eta`) exports flow metadata (IDP, SPLT, SALT, BD and TLS record statistics) used to infer TLS handshake shape, but names no SNI or certificate common name field, and gives no IPFIX Information Element numbers at all.
The "Reporting Extracted Fields Through Flexible NetFlow" chapter (`cisco-nbar-extracted-fields-xe16-6`) covers NBAR sub-application field reporting but names no SSL/TLS field.
The xe-16-9 PDF variant of the same chapter, https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/qos_nbar/configuration/xe-16-9/qos-nbar-xe-16-9-book/reporting-extracted-fields-through-flexible-netflow.pdf, was fetched but did not decode through the fetch tool and is not recorded as a source row; the xe-16-6 HTML reading above answers the question.
Cisco Protocol Pack release notes 68.0.0 (`cisco-nbar-pp68`) and 74.0.0 (`cisco-nbar-pp74`, the current pack found as of this search) name neither SSL/TLS nor an exported field ID.
libfds `cisco.xml` (`libfds-cisco-xml`) defines no element matching ssl, tls, sni or commonName; corroboration only, per this file's reference policy.
NBAR2 consumes SNI and CN for classification (`ip nbar custom ... ssl unique-name`); the export product is an applicationId selector.
Consequence for the spec: TLS-classified traffic is represented by applicationId and the application table, with no SNI string on the wire.

## Application table options template (RFC 6759 section 4.3)

Scope field: `applicationId` (IE 95).
Non-scope fields: `applicationName` (IE 96), `applicationDescription` (IE 94).
Cisco's 2015 guide gives `applicationName` a fixed length of 24 bytes in `option application-table`.
Task 3 checked every Cisco document read for the HTTP host question for this same fact, one sentence per document.
Cisco's 2015 guide (`cisco-avc-fdg-2015`) lists `application description` (IE 94) in the same option-table field list, at offset 28 with a length of 55 bytes, immediately after `application name` (offset 4, length 24).
RFC 6759 sections 7.1.1 and 7.1.3 (`rfc6759`, `testdata/rfc/rfc6759-application-information.txt`) register `applicationDescription` and `applicationName` with Abstract Data Type `string` and no fixed length.
The Network Services Configuration Guide, Cisco IOS XE 17.x Flexible NetFlow overview (`cisco-fnf-ntw-servs-17x`) does not mention `applicationDescription` or `option application-table`.
The Flexible NetFlow Configuration Guide, Cisco IOS XE 17 (`cisco-fnf-xe17-book`) does not mention `applicationDescription` or `option application-table`.
The Catalyst 9500 AVC chapter (`cisco-cat9500-avc`) documents the `option application-table [ timeout seconds ]` CLI but does not mention `applicationDescription`.
The Catalyst 9800 WLC AVC chapter (`cisco-cat9800-wlc-avc`) does not mention `applicationDescription` or `option application-table`.
The Cisco IOS XE 16 AVC configuration guide (`cisco-avc-cfg-xe39s`) does not mention `applicationDescription` or `option application-table`.

## HTTP URI statistics (42125) layout

42125 = 0x8000 | 9357, the same identity resolved for HTTP host above; libfds's 9357 (`appHTTPUriStatistics`) is the same element as Cisco's 42125, not a second candidate.
Cisco's 2015 guide states, verbatim: "NULL (\0) is the delimiter." (`cisco-avc-fdg-2015`, table row for field 42125).
In my own words, restated from the same table row: the field is a repeating sequence of URI-then-count pairs, one pair per tracked URI, concatenated back to back with no separate leading or trailing element.
Element order: within each pair the URI comes first, followed immediately by its hit count.
Delimiter versus length prefix: each URI is terminated by a NUL byte rather than preceded by a length field, so the field is delimiter-terminated, not length-prefixed.
The guide's prose format line `uri <delimiter> count <delimiter> uri <delimiter> count <delimiter>...` shows a delimiter after each count, while its encoding example `{URI\0countURI\0count}` shows none.
nl6 records the encoding example as governing because it is the byte-level statement; unit 2 stated that choice beside the byte-order decision, and the reference capture confirmed it (see below).
Hit count width and byte order: the guide sizes the hit count at two bytes and calls it an integer, but it does not say which byte order that integer uses, so byte order is unstated by Cisco.
Maximum URI length: the guide caps a single URI at 512 characters for IOS, truncating anything longer; for IOS XE it gives no URI-specific number, only the same generic 2 KB ceiling it applies to every IOS XE extracted variable-length field, the same pattern already recorded for HTTP host at row `9/12235`.
Maximum hit count: the guide puts the ceiling at 65535, the natural limit of an unsigned two-byte field.
Cisco's text gives no byte order for the 2-byte hit count, and no other source consulted for this row supplies one either.
Unit 2 decided it explicitly at `uriStatsValue` (big-endian, RFC 7011 section 6.1.1's network byte order; encoding example governs, so no trailing delimiter), and the IOS-XE 26.01.02 reference capture confirmed both decisions on 2026-09-21: all 400 values are URI, NUL, big-endian count, nothing after (`TestCiscoAVCCapture_URIStatisticsLayout`).
Neither is an open assumption any more; both are capture-confirmed facts, though still not stated in any Cisco document.
The full PDF of this guide, https://www.cisco.com/c/en/us/td/docs/routers/access/ISRG2/AVC/api/guide/AVC_Metric_Definition_Guide.pdf, returned only its table-of-contents/landing content through the fetch tool and not the chapter body, the same non-decoding outcome already recorded for the xe-16-9 PDF above, so this section relies on the HTML chapter (`cisco-avc-fdg-2015`), which is already a cited source and was refetched for this task.

### libfds appHTTPUriStatistics (9357)

libfds defines appHTTPUriStatistics as IE 9357 with data type string (`libfds-cisco-xml`).
libfds states string and Cisco states no type, so the only stated type is string.
nl6 records octetArray as its own encoder decision for the reason above, and unit 2 inherits that decision explicitly rather than as a sourced fact.

Layout pinned: row `9/9357` stays `verified`; its note now carries the one-line layout summary above.

## applicationId engine ids (RFC 6759 section 4.1)

| engine id | name | selector | nl6 use |
|-----------|------|----------|---------|
| 3 | IANA-L4 | 2 bytes, well-known port | port-based catalog entries |
| 6 | USER-Defined | 3 bytes | custom applications |
| 13 | PANA-L7 | 3 bytes | NBAR2 layer-7 applications |

The selector values for PANA-L7 are Cisco's NBAR2 registry and are not published as a table; a catalog entry records the selector it uses and the reading it came from.

## Reference capture: IOS-XE 26.01.02 on a Catalyst 8000V (2026-09-21)

`capture/c8000v-26.01.02-avc.pcap` is the first Cisco-originated wire reading in this evidence base; `capture/README.md` says how it was taken and how to regenerate it, and `cisco_avc_capture_test.go` pins every fact below by decoding the file with its own template parser.
Source row: `c8000v-26.01.02-capture`.
The design spec's exit rule said a Cisco document or a capture would settle the two open encoder residuals; this capture settles both, one for nl6 and one against it.

### What IOS-XE will and will not export

IOS-XE refused to bind a monitor whose record collects URI statistics without a connection id: "'uri statistics' must have 'connection id' or 'transaction-id'".
It refused `collect connection id` with "must be defined as a match field", and refused `match connection id` until the monitor carried `cache timeout event transaction-end`.
So the record a real router exports with URI statistics is a connection record aged at transaction end, and nl6's shape, a unidirectional flow record with URI statistics and no connection id, cannot be produced by IOS-XE.
The connection id is PEN 9 IE 12242, 4 bytes, zero on ICMP flows (row `9/12242`).
This is the fidelity decision in nl6#680.

### Data template 258, 17 fields, in wire order

sourceIPv4Address (8, 4), destinationIPv4Address (12, 4), ipVersion (60, 1), protocolIdentifier (4, 1), sourceTransportPort (7, 2), destinationTransportPort (11, 2), ingressInterface (10, 4), PEN 9 connection id (12242, 4), applicationId (95, 4), egressInterface (14, 4), flowDirection (61, 1), PEN 9 HTTP URI statistics (9357, var), PEN 9 HTTP host (12235, var), octetDeltaCount (1, 8), packetDeltaCount (2, 8), flowStartMilliseconds (152, 8), flowEndMilliseconds (153, 8).
Match fields come first, the two variable-length fields sit before the counters, and URI statistics precede host.
nl6's template 258 is its 54-byte unidirectional prefix followed by applicationId, host, URI statistics.

### IE 12235, HTTP host: not a bare string (nl6#679)

Every one of the 1302 records starts the field with the constant six bytes `03 00 00 50 34 02`, then the hostname.
That is applicationId 0x03000050 (engine 3, selector 80, http) followed by sub-application id 0x3402, the "Subapplication ID for the host" sentence in `cisco-avc-fdg-2015` that the earlier reading recorded as prose rather than as a wire layout.
A record with no host carries exactly the six bytes; the field is never empty; the prefix is constant regardless of the flow's own applicationId (a DNS flow carries it too).
nl6 emits the bare hostname, so a decoder written to Cisco's layout reads nl6's value wrongly, and libfds, which types the element as string, shows nl6's `www.example.com` where a real box shows six binary bytes and then the name.

### IE 9357, HTTP URI statistics: layout confirmed

All 400 values are `URI` then NUL then a 2-byte big-endian hit count with no trailing delimiter, for example `2f 00 00 01` for `/`.
Both encoder decisions recorded above (big-endian, encoding example governs) are confirmed; `uriStatsValue` reproduces the router's bytes exactly.
The router records the first path segment only: `/api/v1` and `/api/login` both arrive as `/api`, `/static/app.js` as `/static`.
nl6's shipped catalogs carry multi-segment URIs, which a real box would never emit; that is part of nl6#680.

### Direction and classification

Host and URI statistics appear only on the ingress-direction (flowDirection 0) record of an http-classified request; the reverse-direction record carries the six-byte host prefix and an empty URI field.
The 400 requests produced 400 `http` (0x03000050) ingress records with host and URI, 400 `http` egress records without, and 400 records classified `binary-over-http` (0x0d0001af, engine 13): NBAR2 reclassified half the plain `python3 -m http.server` transactions mid-connection and, with transaction-end aging, emitted a second record for them.
Every nl6 catalog entry is engine 3; the router's application table has 1560 rows, 127 on engine 1, 748 on engine 3 and 685 on engine 13.
Ids read from the table: http 0x03000050, dns 0x03000035, ssh 0x03000016, icmp 0x01000001, unknown 0x0d000001, binary-over-http 0x0d0001af, ping 0x0d0001df.

### Options templates

Template 256, interface table: scope ingressInterface (10, 4), then interfaceName (82, 33), interfaceDescription (83, 65), egressInterface (14, 4).
nl6's `if-scoped` shape sends 82 and 83 at 32 bytes each with no egressInterface, under template id 257.
Template 257, application table: scope applicationId (95, 4), then applicationName (96, 24), applicationDescription (94, 55), exactly nl6's constants, under nl6's template id 259.
Cisco numbers them 256 interface table, 257 application table, 258 data.

### Message shape

395 messages; the largest IP datagram is 1420 bytes and none is fragmented.
The sequence number counts data records including option data records, as nl6 does.

### Cisco-sourced versus nl6 decision, after the capture

The fidelity decision (nl6#680) kept the encoder and downgraded the claim to "conformant and interop-tested against open decoders"; `docs/reference/flow-export.md` lists the six differences.
This is the ledger of what each shipped fact rests on now.

Cisco-sourced (a document or the capture): IE numbers 12235, 9357, 12242 and their PEN; the 9357 layout including byte order and the absent trailing delimiter (capture); the 12235 six-byte host prefix that nl6 does not yet emit (capture, nl6#679); applicationName 24 and applicationDescription 55 (2015 guide and capture); the engine-3 `http` id and the engine-13 ids `unknown`, `binary-over-http`, `ping` (capture); RFC 6759 engine ids 3, 6, 13 (RFC); the router's 17-field connection record, ingress-only layer-7 values, first-segment URIs and 33/65-byte interface table (capture, recorded as differences).

nl6 decisions, labelled as such and not to be read as Cisco facts: the octetArray type for IE 9357 (libfds says string, Cisco names no type); engine 3 with the IANA port as selector for every shipped catalog entry; the unidirectional flow-record shape with no connection id; option template ids 257 (interface) and 259 (application) against Cisco's 256 and 257; the 32-byte interfaceName and interfaceDescription widths; host and URI on every AVC record; multi-segment URIs in the shipped catalogs.
