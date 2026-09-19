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

## Contested

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
Resolution: row `9/45003` stays `contested` per Task 3's decision rule, since no Cisco IOS-XE 17.x or Catalyst 9000 document names either number.
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
nl6 records the encoding example as governing because it is the byte-level statement, and unit 2 must state that choice beside the byte-order assumption.
Hit count width and byte order: the guide sizes the hit count at two bytes and calls it an integer, but it does not say which byte order that integer uses, so byte order is unstated by Cisco.
Maximum URI length: the guide caps a single URI at 512 characters for IOS, truncating anything longer; for IOS XE it gives no URI-specific number, only the same generic 2 KB ceiling it applies to every IOS XE extracted variable-length field, the same pattern already recorded for HTTP host at row `9/45003`.
Maximum hit count: the guide puts the ceiling at 65535, the natural limit of an unsigned two-byte field.
Cisco's text gives no byte order for the 2-byte hit count, and no other source consulted for this row supplies one either.
This is an open encoder assumption: unit 2 must decide it explicitly, naming whether it follows RFC 7011's network byte order convention for IPFIX integers or something else and why, and the spec's fidelity exit rule applies to that assumption until a Cisco document or a packet capture pins it.
The full PDF of this guide, https://www.cisco.com/c/en/us/td/docs/routers/access/ISRG2/AVC/api/guide/AVC_Metric_Definition_Guide.pdf, returned only its table-of-contents/landing content through the fetch tool and not the chapter body, the same non-decoding outcome already recorded for the xe-16-9 PDF above, so this section relies on the HTML chapter (`cisco-avc-fdg-2015`), which is already a cited source and was refetched for this task.

### libfds appHTTPUriStatistics (9357)

libfds defines appHTTPUriStatistics as IE 9357 with data type string (`libfds-cisco-xml`).
libfds states string and Cisco states no type, so the only stated type is string.
nl6 records octetArray as its own encoder decision for the reason above, and unit 2 inherits that decision explicitly rather than as a sourced fact.

Layout pinned: row `9/42125` stays `verified`; its note now carries the one-line layout summary above.

## applicationId engine ids (RFC 6759 section 4.1)

| engine id | name | selector | nl6 use |
|-----------|------|----------|---------|
| 3 | IANA-L4 | 2 bytes, well-known port | port-based catalog entries |
| 6 | USER-Defined | 3 bytes | custom applications |
| 13 | PANA-L7 | 3 bytes | NBAR2 layer-7 applications |

The selector values for PANA-L7 are Cisco's NBAR2 registry and are not published as a table; a catalog entry records the selector it uses and the reading it came from.
