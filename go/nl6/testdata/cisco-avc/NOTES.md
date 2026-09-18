# Cisco AVC extract: notes

This directory is the evidence base for the NBAR2 IPFIX encoder.
Read `docs/superpowers/specs/2026-09-18-nbar2-ipfix-l7-export-design.md`, section 1, before editing.
`elements.tsv` is a factual table of IE numbers.
It is not a copy of any Cisco document.

## Reference policy

Primary: Cisco documentation and RFCs, cited by title, revision and URL.
Corroborating: CESNET libfds `cisco.xml`, a BSD-licensed data file, never copied here; libfds and IPFIXcol2 C sources are not read.
Excluded: ElastiFlow, on licence grounds (object-code EULA; legacy repo under a non-OSI commercial-use restriction).

## Contested

### HTTP Host: 45003 or 12235

Cisco's 2015 Field Definition Guide (ISR G2, ASR 1000) gives 45003.
libfds gives 12235 under the name `appHTTPHost`.
Resolution: pending Task 3.

## Unverified

TLS SNI or certificate common name as an exported string: no Cisco PEN 9 element found yet.
Resolution: pending Task 4.

## Application table options template (RFC 6759 section 4.3)

Scope field: `applicationId` (IE 95).
Non-scope fields: `applicationName` (IE 96), `applicationDescription` (IE 94).
Cisco's 2015 guide gives `applicationName` a fixed length of 24 bytes in `option application-table`.
Whether `applicationDescription` is emitted by IOS-XE `option application-table`, and at what length, is checked in Task 3 alongside the platform reading.

## applicationId engine ids (RFC 6759 section 4.1)

| engine id | name | selector | nl6 use |
|-----------|------|----------|---------|
| 3 | IANA-L4 | 2 bytes, well-known port | port-based catalog entries |
| 6 | USER-Defined | 3 bytes | custom applications |
| 13 | PANA-L7 | 3 bytes | NBAR2 layer-7 applications |

The selector values for PANA-L7 are Cisco's NBAR2 registry and are not published as a table; a catalog entry records the selector it uses and the reading it came from.
