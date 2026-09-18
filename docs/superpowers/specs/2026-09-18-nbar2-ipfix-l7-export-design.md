# NBAR2 layer-7 export over IPFIX

Date: 2026-09-18
Status: design approved, not implemented
Scope: `go/nl6/` flow export subsystem

## Goal

Let NBAR2-capable simulated devices export Cisco AVC style flow records over IPFIX, carrying the NBAR2 application identity and the layer-7 fields NBAR2 extracts.
The fidelity bar is **Cisco-faithful**: a capture taken from nl6 should match what a real IOS-XE box emits for an equivalent `flow record` configuration.

IPFIX is mandatory for this feature, and that is a property of the platform rather than a design choice.
Cisco's AVC field guide marks `applicationId` (IE 95) as exportable under both NetFlow v9 and IPFIX, but marks the layer-7 string fields as IPFIX only.
NetFlow v9 has neither enterprise-specific information elements nor variable-length encoding, so it cannot carry them.

## 1. Evidence contract

This section gates every other section.

### The problem

IEs 95 (`applicationId`) and 96 (`applicationName`) are IANA registered and safe to cite.
The layer-7 fields are not.
They live under Cisco's PEN 9, and the only authorities are Cisco's AVC documentation and real captures.

This repository has measured what happens when that gap is filled from recall.
The vendor arc audits found Juniper wrong on 13 of 15 OIDs and Palo Alto wrong on 8 of 11, and every one of those passed the load-time encodability guards.
The same failure is available here and is worse in effect: a wrong IE number under PEN 9 produces a capture that decodes cleanly into the wrong field.

### What has been established so far

From Cisco's *Application Visibility and Control Field Definition Guide for Third-Party Customers*, revised 26 March 2015, covering ISR G2 and ASR 1000:

| Field | CLI | Export field ID (IOS and IOS XE) | Type | Export protocol |
|-------|-----|----------------------------------|------|-----------------|
| Application ID | `collect application name` | 95 | 4 bytes: engine-id (8 bits) + selector (24 bits) | v9 and IPFIX |
| Application Name | `option application-table` | 96 | 24 bytes | options template |
| HTTP Host | `collect application http host` | 45003 | variable-length string | IPFIX only |
| HTTP URI statistics | `collect application http uri statistics` | 42125 | concatenated URIs with 2-byte hit counts | IPFIX only |

Source: https://www.cisco.com/c/en/us/td/docs/routers/access/ISRG2/AVC/api/guide/AVC_Metric_Definition_Guide/5_AVC_Metric_Def.html

### Two unresolved findings

**The HTTP host number is contested.**
CESNET's libfds element database defines `appHTTPHost` under PEN 9 as **12235**.
Cisco's own guide gives **45003**.
One of the two is platform-specific or era-specific.
The Cisco guide covers ISR G2 and ASR 1000 in 2015, while `cisco_catalyst_9500` is IOS-XE 17.x, and WLC and Catalyst AVC field numbering is reported to differ from ISR and ASR numbering.
Resolving this is the first task of unit 1.
It is also the reason the cross-check was worth doing: a single-source design would have shipped one of these numbers as fact.

**No TLS string export was found.**
No Cisco PEN 9 element that exports a TLS SNI or certificate common name as a string could be located.
NBAR2 consumes SNI and CN for classification, via `ip nbar custom ... ssl unique-name`, but the export product is an application ID selector rather than the raw name.
Unit 1 widens the search across WLC AVC, Catalyst 9000 on IOS-XE 17.x, ISR 4000 and current protocol packs before TLS scope is fixed.

### Reference policy

**Primary source: Cisco AVC documentation.**
Every IE number, type and length in the implementation derives from a Cisco document, cited by title and revision.

**Corroborating source: CESNET libfds, data files only.**
libfds is dual licensed BSD-3-Clause and GPLv2-or-later.
Its `config/system/elements/cisco.xml` is a data file of PEN 9 definitions that cites the same Cisco guide as its own upstream.
IE numbers are facts rather than expression, so consulting that file to corroborate an independently sourced number is sound.
Three limits apply: it is never the primary source, the file is never copied into this repository, and the IPFIXcol2 and libfds C sources are not read at all.
The GPL option is why reading decoder implementations is a risk that buys nothing the data file does not already give.

**Excluded: ElastiFlow.**
The current collector ships object code only under a EULA forbidding derivative works, so there is no source to consult.
The legacy `robcowart/elastiflow` repository is source-available under a custom non-OSI licence restricting commercial use, and is deprecated and unmaintained.
It is excluded on both licence and value grounds.

### Deliverable

`go/nl6/testdata/cisco-avc/` holds a checked-in extract of what was actually consulted: a table of IE number, name, type, length semantics and citation, carrying source URL, document title, revision and fetch date.
This matches the shape of `testdata/iana/enterprise_numbers.tsv` and `testdata/rfc/`.
The extract is a factual table rather than a copy of Cisco's document, so the vendor-MIB redistribution rule does not apply.
The encoder's IE table derives from that file, and a test asserts the two agree.

### The exit if sourcing fails

If coverage comes back partial, the design does not proceed by guessing.
Either the unverified fields leave scope, or the feature's claim downgrades from "Cisco-faithful" to "conformant and interop-tested against open decoders", stated in those words in `docs/`.
The spec records which happened.

## 2. Wire format

An NBAR2 device sends the AVC data template and nothing else.
It never emits the current 19-IE record, so no device carries a mixed template set.
A device without NBAR2 is byte-identical to today.

Three encoder changes follow.

**Enterprise IEs widen the template.**
`buildIPFIXTemplateSet` writes 4 bytes per field today.
An enterprise-specific IE takes 8: the IE ID with bit 15 set, followed by a 4-byte PEN.
The template set length becomes computed, and `ipfixTemplSetSize` stops being a constant.

**Variable-length fields remove the fixed record size.**
Such fields declare length `0xFFFF` in the template and carry a per-record length prefix on the wire, per RFC 7011 section 7: one byte below 255, otherwise `255` followed by a 2-byte length.
`ipfixRecordSize` does not apply to this template.

**Pagination becomes measured.**
`EncodePacket` currently paginates with `available / ipfixRecordSize` plus a single decrement for pad parity.
That arithmetic is replaced by encode-and-check per record against the remaining budget, backing out the last record when it does not fit.
`FlowEncoder.MaxRecordSize()`, the seam sFlow already uses to give `Tick` a worst-case bound, is what the NBAR2 IPFIX encoder returns non-zero from, so `Tick` needs no new concept.

**Options template.**
The application table maps `applicationId` to `applicationName` in an Options Template (Set ID 3), re-sent on `-flow-template-interval` alongside the data template.
Its scope-field composition is a unit-1 output and is not fixed here.
nl6 already has an options-template path for `options_interface_table`.
Template ID allocation, and the behaviour when a device enables both, are settled in unit 2 by reading that code rather than chosen now from the outside.

**Oversized records.**
A flow whose URI field is long can push a single record past `flowPayloadBudget`, and a record that fits no datagram can never be sent.
This takes the rule the trap catalog already established: bound it at catalog load with a worst-case dry render against the configured budget, mark the entry oversized, exclude it from selection, and name it once at startup with its size and the MTU that would admit it.
Loading does not fail, because the budget follows the operator-settable `-datagram-mtu`.
The fire-time encode check remains the backstop.

**Two details to establish rather than assume.**
Whether options data records count toward the IPFIX sequence number.
And the engine-id semantics inside `applicationId`, meaning which value marks a port-based, an NBAR2 layer-7, and a custom application.
A wrong engine id yields IDs a collector resolves against the wrong classification engine.

## 3. Data model and flow generation

**Selection inverts for NBAR2 devices.**
`syntheticFlow` draws a destination port from `FlowProfile.DstPorts` today.
An NBAR2 device draws the application first, and the application determines protocol and destination port.
Otherwise the exporter emits a record on port 443 tagged `ssh`, which no real device produces.
For NBAR2 devices the catalog supersedes `DstPorts` as the port source.
For every other device `syntheticFlow` is untouched.

**Determinism.**
This changes the per-flow RNG call sequence for NBAR2 devices.
The draw is unconditional within the NBAR2 path, so a seeded run stays reproducible.
This is the `jitter-flow-active-timeout` rule: a branch-dependent draw makes the RNG call count flow-dependent and desynchronises the stream.
Non-NBAR2 devices must be provably unaffected, proved by a digest over emitted bytes rather than by argument.

**Records carry indices, not strings.**
At 30k devices times `MaxFlows` 256 there are roughly 7.7M live records.
A pointer plus two string headers per record is on the order of 300 MB resident for values drawn from a fixed catalog.
`FlowRecord` therefore carries `appIdx`, `hostIdx` and `uriIdx`, about 6 bytes, resolved against the immutable catalog at encode time.

**Catalog entry shape**, mirroring the trap and syslog loaders:
application name, the `applicationId` selector, L4 protocol, destination port, weight, and weighted host and URI lists.

**Catalog sourcing.**
`resources/_common/nbar2.json` embedded via `embed.FS`, overlaid by `resources/<type>/nbar2.json` with the existing `"extends": true` merge semantic, and replaceable wholesale by `-nbar2-catalog <path>`.
This is the third instance of a shape two subsystems already use.
Cardinality is finite by construction, which is what makes the ground-truth commitment in section 5 keepable.

**The application table agrees with what the device emits.**
The options records advertise exactly the catalog entries that device can produce.
A collector never sees an `applicationId` it cannot resolve, and never a table row for an application that never appears.

## 4. Configuration, gating and capability

**Config surface.**
NBAR2 is a property of the flow record format, so it lives in the existing per-device `flow` block as `"nbar2": true`, with a matching seed flag for the auto-start batch.
No per-device catalog path.
The path-injection reasoning that made syslog's and dial-out's `ca_pem` inline-only applies, so an operator catalog arrives only via `-nbar2-catalog`, read once at startup.

**Three rejections, all 400, none silent.**
`DeviceFlowConfig.Validate` already carries the precedent: `options_interface_table` under `netflow5` or `sflow` is refused with an error naming the supported protocols.

1. `nbar2: true` with any protocol other than `ipfix` is rejected, with an error naming `ipfix`.
2. `nbar2: true` on a device type without NBAR2 is rejected, naming the offending resource file, via `nbar2IncapableRequest` built as the third sibling of `flowIncapableRequest` and `opticalIncapableRequest`.
   It inherits their round-robin semantics: a mixed batch is accepted and incapable devices are skipped with a log line, and only an entirely incapable resolved type set fails.
3. An explicit NBAR2 request on a flow-incapable type is already covered by the existing flow rejection and needs no new rule.

**The capability set is curated with a written reason per row.**
A `strings.HasPrefix(rf, "cisco_")` test would admit `cisco_nexus_9500`, which runs NX-OS, and `cisco_crs_x` and `asr9k`, which run IOS-XR.
None of the three has NBAR2.
This is the failure `ownVendorPENs` is curated to avoid, and the reason the vendor-arc guard matches on a sub-identifier boundary rather than a string prefix.
Initial rows: `cisco_ios` and `cisco_catalyst_9500`, each carrying why.

**Completeness enforced, absence reported.**
NBAR2 capability gets the treatment `TestFlowCapabilityCompleteness` already gives flow, so a new Cisco type cannot quietly default into or out of the set.
`GET /api/v1/devices` omits the `nbar2` field for incapable types rather than reporting a knob that does nothing, per the rule `opticalScenarioFieldFor` established.

## 5. Ground truth

**The join key extends, which is a compatibility change.**
A fleet can mix NBAR2 and non-NBAR2 devices, so the same `(tcp, 443)` traffic arrives both with and without an `applicationId`.
The key becomes `(l4_proto, dst_port, application_id)`, with an empty application id for non-NBAR2 records.
`Σ applications[].records == summary.sent` still holds, so totals reconcile as before.
A consumer grouping only on protocol and port now sees two rows where it saw one.
That goes in the schema doc explicitly.

**Layer-7 values get their own block.**
`applications[]` rows gain `application_id` and `application_name`.
Hosts and URIs go in a separate `l7_values[]` block keyed by `(application_id, field, value)`, carrying the same sent-basis `records`, `bytes`, `packets` and `avg_bytes_per_second`.
Cardinality is the catalog's and is known before T0.

**The invariant is an inequality.**
`Σ l7_values[].records ≤ Σ applications[].records`, never equality.
An HTTP host field exists only on HTTP flows, so a TLS or DNS application contributes application rows and no host rows.
Asserting equality would assert something the wire does not carry.

**Mechanism reuses what exists.**
Counting happens at the `scenarioPart.countApps` hook on the Tick write-return ledger point, set at `installScenPart`.
Sent basis.
Drain bytes count in totals and are excluded from `avg_bytes_per_second`, because the denominator is the window.
sFlow is already excluded at that hook, and NBAR2 is IPFIX only, so the question does not arise, but the spec states it rather than leaving it to inference.

**Documentation.**
`docs/reference/loadtest-report-schema.md` gains the new block beside the existing `applications[]` table, carrying the same warning to join on the key rather than the hint.
`application_name` from the options table is resolvable ground truth, but a collector's own classification may still disagree.

## 6. Testing and verification

Ordered by detection power, weakest first.

**The pinned reading.**
A test asserts the encoder's IE constants equal the checked-in `testdata/cisco-avc/` extract.
Narrow but exact: changing 45003 fails by name.
It cannot show the extract is right.
Only unit 1's sourcing can do that.

**Decode round-trip with boundary cases.**
The existing `decodeIPFIXPacket` helper pattern, extended for enterprise IEs and variable length.
Mandatory cases are value lengths 254, 255 and 256.
The 1-byte versus `255`-plus-2-byte escape boundary in RFC 7011 section 7 is where variable-length encoders break, and a suite exercising only short hostnames passes while the encoder is wrong.

**MTU, verified over veth.**
`TestFlowDatagramsFitMTU` gains NBAR2 coverage, but the Go test is not the check with detection power.
Loopback is MTU 65536 and fragmentation is invisible there, which is how the nl6#485 payload-versus-frame bug survived in-process measurement.
The real check is a capture over veth, plus an oversized-record case proving the catalog-load dry render disables rather than fails.

**External interop, the load-bearing check.**
IPFIXcol2 is BSD licensed and packaged, so `make test-interop-ipfix` runs nl6's real exporter against a real collector in a container and asserts it resolves the enterprise IEs and the application table.
This is the direct analogue of `make test-interop` for SNMPv3 USM, whose value was proved when its first run failed all six rows while the Go package was green.
A green in-package suite means very little until this passes.

**Non-NBAR2 byte identity.**
A digest over emitted bytes for every non-NBAR2 protocol and device type, taken at the baseline commit in a worktree and re-derived after.
This is the method the SNMPv1 trap work used to prove v2c output unchanged.

**Ground-truth reconciliation.**
Run a scenario, decode every datagram the collector received, and compare per-key sums against the report.
Not against nl6's internal counters, which would be a parity test over a shared wrong answer.

**Catalog guards.**
The shape the trap and syslog catalogs already have: unique application IDs, value lengths within bounds, load-time dry render for oversized entries.
Every guard asserting zero of something opens with a positive control that plants a violation and requires the rule to fire, per nl6#571.

**Mutation verification.**
Every claim of the form "X is pinned by TestY" is verified by breaking the code and watching the named test fail, before it appears in a commit message or in this spec.

## Work units

Unit 1 gates everything after it.

1. **Sourcing.**
   Resolve 45003 versus 12235 for the platforms in scope.
   Establish `applicationId` engine-id semantics and the application-table options-template shape.
   Widen the TLS search across WLC AVC, Catalyst 9000 on IOS-XE 17.x, ISR 4000 and current protocol packs.
   Produce `testdata/cisco-avc/` and a written record of what stays unverified.
   Produces no shippable code.
   If it fails, the exit in section 1 applies.
2. **Encoder.**
   Enterprise IEs, variable-length encoding, measured pagination, `MaxRecordSize`.
   Reconcile template-ID allocation with the existing options-interface-table path.
   Decode round-trip tests including the length boundary cases.
3. **Application table.**
   Options template, re-send cadence, agreement with the device's catalog.
4. **Catalog.**
   Embedded set, per-type overlay, override flag, load-time guards, oversized dry render.
5. **Generation and config.**
   Application-first selection, index-carrying records, the `nbar2` flow field, the three rejections, the curated capability set, completeness test, byte-identity digest.
6. **Ground truth.**
   Extended join key, `l7_values[]`, schema documentation.
7. **Interop and wire verification.**
   `make test-interop-ipfix` against IPFIXcol2, veth capture, MTU cases.

## Out of scope

- NetFlow v9, NetFlow v5 and sFlow. Unchanged, and cannot carry these fields.
- IOS-XR and NX-OS device types. No NBAR2 on those platforms.
- TLS SNI and certificate common name, pending unit 1.
- Bidirectional or client/server AVC fields such as `clientIPv4Address` and the response-time metrics. Separate feature.
- Protocol-pack emulation. nl6 ships a fixed catalog, not a versioned protocol pack.

## Open questions

1. HTTP host IE number: 45003 or 12235, and on which platform. Unit 1.
2. Does a TLS SNI or common-name string export exist on any Cisco platform. Unit 1.
3. `applicationId` engine-id values and their meanings. Unit 1.
4. Application-table options-template scope fields. Unit 1.
5. Template ID allocation when a device enables both `nbar2` and `options_interface_table`. Unit 2.
6. Whether options data records advance the IPFIX sequence number. Unit 2.
