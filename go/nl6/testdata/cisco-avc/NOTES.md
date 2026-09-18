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
