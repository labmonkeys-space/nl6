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

## Contested

### HTTP Host: 45003 or 12235

Cisco's 2015 Field Definition Guide (ISR G2, ASR 1000) gives 45003 (`cisco-avc-fdg-2015`).
Its option-template table lists HTTP host as a variable-length string field, IPFIX only, max 512 chars on IOS and 2 KB on IOS XE.
libfds `cisco.xml` defines `<id>12235</id>`, `<name>appHTTPHost</name>`, `<dataType>string</dataType>` for this field, with no `<source>` tag and no comment attached to that element (`libfds-cisco-xml`).
Task 3 checked four IOS-XE 17.x / Catalyst-era Cisco documents for either number, and none of them names an exported field ID for HTTP host at all.
The four are the Network Services Configuration Guide, Cisco IOS XE 17.x Flexible NetFlow overview (`cisco-fnf-ntw-servs-17x`), the Flexible NetFlow Configuration Guide, Cisco IOS XE 17 (`cisco-fnf-xe17-book`), the Catalyst 9500 System Management Configuration Guide's AVC chapter (`cisco-cat9500-avc`), and the Catalyst 9800 WLC AVC chapter (`cisco-cat9800-wlc-avc`).
The Catalyst 9500 chapter documents the `option application-table [ timeout seconds ]` CLI but has no field-ID table.
The nearest standalone AVC configuration guide found, for the superseded Cisco IOS XE Release 3.9S (`cisco-avc-cfg-xe39s`), predates the 17.x train and also names neither number.
Resolution: row `9/45003` stays `contested` per Task 3's decision rule, since no Cisco IOS-XE 17.x or Catalyst 9000 document names either number.
45003 is confirmed only for ISR G2 and ASR 1000, by the 2015 guide.
Catalyst 9500 (and Catalyst 9000 generally) support for HTTP host export, and which IE number it would use, remains unconfirmed by any Cisco document read for this task.

## Unverified

TLS SNI or certificate common name as an exported string: no Cisco PEN 9 element found yet.
Resolution: pending Task 4.

## Application table options template (RFC 6759 section 4.3)

Scope field: `applicationId` (IE 95).
Non-scope fields: `applicationName` (IE 96), `applicationDescription` (IE 94).
Cisco's 2015 guide gives `applicationName` a fixed length of 24 bytes in `option application-table`.
Task 3 checked every Cisco document read for the HTTP host question for this same fact, one sentence per document.
Cisco's 2015 guide (`cisco-avc-fdg-2015`) lists `application description` (IE 94) in the same option-table field list, at offset 28 with a length of 55 bytes, immediately after `application name` (offset 4, length 24).
The Network Services Configuration Guide, Cisco IOS XE 17.x Flexible NetFlow overview (`cisco-fnf-ntw-servs-17x`) does not mention `applicationDescription` or `option application-table`.
The Flexible NetFlow Configuration Guide, Cisco IOS XE 17 (`cisco-fnf-xe17-book`) does not mention `applicationDescription` or `option application-table`.
The Catalyst 9500 AVC chapter (`cisco-cat9500-avc`) documents the `option application-table [ timeout seconds ]` CLI but does not mention `applicationDescription`.
The Catalyst 9800 WLC AVC chapter (`cisco-cat9800-wlc-avc`) does not mention `applicationDescription` or `option application-table`.
The superseded IOS XE Release 3.9S AVC configuration guide (`cisco-avc-cfg-xe39s`) does not mention `applicationDescription` or `option application-table`.

## applicationId engine ids (RFC 6759 section 4.1)

| engine id | name | selector | nl6 use |
|-----------|------|----------|---------|
| 3 | IANA-L4 | 2 bytes, well-known port | port-based catalog entries |
| 6 | USER-Defined | 3 bytes | custom applications |
| 13 | PANA-L7 | 3 bytes | NBAR2 layer-7 applications |

The selector values for PANA-L7 are Cisco's NBAR2 registry and are not published as a table; a catalog entry records the selector it uses and the reading it came from.
