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
| HTTP Host | `collect application http host` | 45003 | variable-length string | IPFIX only; contested, see "Two unresolved findings" below |
| HTTP URI statistics | `collect application http uri statistics` | 42125 | concatenated URIs with 2-byte hit counts | IPFIX only |
| Application Description | option application-table, non-scope field | 94 | Cisco guide: 55 bytes at offset 28 in its option-table listing. RFC 6759 sections 7.1.1 and 7.1.3: Abstract Data Type string, no fixed length | options template |

Application ID, Application Name, HTTP Host and HTTP URI statistics are cited to the Cisco guide below.
Application Description is cited to RFC 6759, corroborated by the offset and length the Cisco guide gives for the same field in its option-table listing.

Source: https://www.cisco.com/c/en/us/td/docs/routers/access/ISRG2/AVC/api/guide/AVC_Metric_Definition_Guide/5_AVC_Metric_Def.html

A second primary source covers the application identity half.
RFC 6759 (Claise, Aitken, Ben-Dvora, November 2012) is the IETF publication of Cisco's application export.
Section 4.1 defines the `applicationId` classification engine IDs, of which three matter here: 3 IANA-L4 (well-known port, 2-byte selector), 6 USER-Defined (3-byte selector) and 13 PANA-L7 (the NBAR2 layer-7 registry, 3-byte selector).
Section 4.3 gives the application-table options template: scope field `applicationId`, non-scope fields `applicationName` (IE 96) and `applicationDescription` (IE 94).
An RFC extract can be checked in under `testdata/rfc/`, the way RFC 3414 already is, so both the engine-id table and the options-template shape become checkable rather than recalled.

### Two unresolved findings

**The HTTP host number stays contested, and 45003 stays in scope.**
HTTP host is Cisco-sourced at IE 45003 for the IOS and IOS-XE router class (ISR G2, ASR 1000).
No Cisco IOS-XE 17.x or Catalyst 9000 document names either 45003 or libfds' 12235, so the Catalyst 9500 platform's number is unconfirmed and the 12235 discrepancy stays on record.

**No TLS string export was found on any platform checked.**
The search covered the 2015 guide, Catalyst 9500, IOS-XE 17.x, Catalyst 9800 and current protocol packs (PP68, PP74), and NBAR2 consumes SNI and CN for classification only, producing an application ID selector rather than a raw string export.
TLS SNI and certificate common name therefore leave scope: TLS-classified traffic is represented by `applicationId` and the application table only.

### Outcome of unit 1

The following fields are unverified and leave scope: TLS SNI and certificate common name (no Cisco export exists; TLS-classified traffic is represented by applicationId and the application table).
The claim stays "Cisco-faithful" for the remaining fields.
Units 2 to 7 proceed on those.

Two caveats travel with that claim.
The Catalyst 9500 HTTP host IE number is unconfirmed by any Cisco document read for this task, and the exit rule above applies to it until a Cisco document or a capture pins it.
The 42125 hit-count byte order is an encoder assumption unit 2 must state explicitly, and the same exit rule applies to it until a Cisco document or a capture pins that too.

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
An enterprise-specific field specifier takes 8 (RFC 7011 section 3.2): the IE ID with bit 15 set (2 bytes), the field length (2 bytes), then the PEN (4 bytes).
The template set length becomes computed, and `ipfixTemplSetSize` stops being a constant.

**Variable-length fields remove the fixed record size.**
Such fields declare length `0xFFFF` in the template and carry a per-record length prefix on the wire, per RFC 7011 section 7: one byte below 255, otherwise `255` followed by a 2-byte length.
`ipfixRecordSize` does not apply to this template.

**Pagination becomes measured, and the seam moves into `Tick`.**
`EncodePacket` currently paginates with `available / ipfixRecordSize` plus a single decrement for pad parity.
That arithmetic is replaced by encode-and-check per record against the remaining budget, backing out the last record when it does not fit.

The existing `MaxRecordSize()` seam is **not** sufficient, and the first draft of this section said it was.
`Tick` (`flow_exporter.go`) uses `MaxRecordSize()` as a divisor: `cap = (len(buf) - overhead) / perRec`.
With a worst-case NBAR2 record of several hundred bytes, every datagram carries one to three records regardless of the actual sizes, and per-device volume collapses.
Worse, when the worst case exceeds `len(buf) - overhead` on a template tick, `batch` is empty, the loop breaks, and the expired records are dropped without being sent or counted.

Two `Tick` invariants make the fix specific.
`Tick` counts `len(batch)` as sent at datagram write-return, and `EncodePacket` returns only `(n, err)`.
A record the encoder backs out is therefore counted as sent and never re-queued, which breaks `Σ applications[].records == summary.sent` in section 5.
The comment beside the capacity arithmetic names exactly this hazard.

So the measured encoder gets a **consumed-count return**, the shape `EncodeOptionsDatagram` already has: `Tick` hands it the whole `expired` slice, the encoder reports how many records it emitted, and `Tick` counts exactly those and re-queues the remainder for the next datagram.
This is a `Tick` change, not only an encoder change, and unit 2 owns both halves.

**A record that fits no datagram.**
Encode-and-check has a degenerate case: a record larger than an empty datagram.
Backing it out and starting a new datagram produces the same result, so without a rule the loop either spins or emits zero-record datagrams.
The rule is: a record the encoder cannot fit into an empty datagram is **dropped and counted in `send_failures`**, and the first occurrence is logged under the `sync.Once` gate.
The catalog dry render (below) is what keeps this path cold, and the dry render must use the budget **with the template set included**, because a template tick has roughly 100 bytes less room than a data-only tick.

**Options template.**
The application table maps `applicationId` to `applicationName` in an Options Template (Set ID 3), re-sent on `-flow-template-interval` alongside the data template.
Its scope-field composition is a unit-1 output and is not fixed here.
nl6 already has an options-template path for `options_interface_table`.
Template ID allocation, and the behaviour when a device enables both, are settled in unit 2 by reading that code rather than chosen now from the outside.

**Oversized records.**
A flow whose URI field is long can push a single record past `flowPayloadBudget`, and a record that fits no datagram can never be sent.
This takes the rule the trap catalog already established: bound it at catalog load with a worst-case dry render against the configured budget, mark the entry oversized, exclude it from selection **and from the application table**, and name it once at startup with its size and the MTU that would admit it.
Excluding it from selection alone would leave the options table advertising an id the device can never emit, which contradicts the agreement invariant in section 3.
The trap catalog learned the same thing when filtering only `Pick` left an oversized `linkDown` firing from `EntriesByRole`.
Loading does not fail, because the budget follows the operator-settable `-datagram-mtu`.
The fire-time encode check remains the backstop.

**The sequence number is a decision, not a lookup.**
RFC 7011 section 3.1 defines the IPFIX sequence number as the count of **Data Records** sent from the observation domain, options data records included, and never the count of messages.
nl6's `IPFIXEncoder.SeqIncrement` returns 1 per message and its comment cites the RFC for that reading; the reading is wrong, and the options path inherits it as "design D7".
This is a pre-existing conformance divergence in nl6's IPFIX export, independent of NBAR2.
It matters here because a device claiming Cisco fidelity cannot inherit it: IOS-XE advances by record count, and IPFIXcol2 reports sequence gaps, so the interop gate in section 6 will flag it.
Three options were considered; the owner chose the first on 2026-09-18.

1. **Chosen.** Fix `SeqIncrement` for every IPFIX device in its own PR before NBAR2 lands, as an RFC conformance fix with a digest showing the only field that moves is the sequence number. One IPFIX semantic, and the fix is small.
2. Rejected: fix it for NBAR2 devices only. Two IPFIX sequence semantics in one fleet, which is the kind of split this repository has removed elsewhere.
3. Rejected: leave it. The interop gate would need an allowance for a known divergence, and the fidelity claim would carry a documented exception.

The conformance fix is a prerequisite PR, outside this spec's work units, and unit 2 depends on it having landed.
It also covers the options path, whose "design D7" comment inherits the same reading.

**Engine-id semantics** inside `applicationId`, meaning which value marks a port-based, an NBAR2 layer-7, and a custom application, are a unit-1 output.
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

**How the catalog reaches the encoder.**
`IPFIXEncoder` is a shared stateless value and `EncodePacket` carries no device context, but the indices above resolve against the *device's* catalog, which is per type.
sFlow hit the same wall and grew a type-switch special case in `Tick` (`EncodeFlowDatagram`) because the interface carries no profile.
NBAR2 does not add a second special case.
The NBAR2 IPFIX encoder is constructed **per resolved catalog** and holds a pointer to it, so devices sharing a type share an encoder and `Tick` calls the ordinary encoder interface.
The precedent is `SNMPv1Encoder`, which is per device because `agent-addr` is per device, and the v3 trap encoder, which holds its own engine.
An encoder holding an immutable pointer is still safe to share across goroutines.

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
NBAR2 is a property of the flow record format, so it lives in the existing per-device `flow` block as `"nbar2": true`, with a matching `-flow-nbar2` seed flag for the auto-start batch.

**The seed flag is validated at startup, fatally.**
`-flow-protocol` defaults to `netflow9`, so a bare `-flow-nbar2` is the same contradiction rejection 1 below refuses over HTTP, but at startup there is no 400 to return.
It is fatal after `-help` and `-version` and before any subsystem starts, with the same message.
The precedent is `-syslog-framing` under `udp` (nl6#445), refused at startup rather than ignored.
A batch that silently ran without NBAR2 would be the accepted-echoed-ignored failure this repository has removed three times.
No per-device catalog path.
The path-injection reasoning that made syslog's and dial-out's `ca_pem` inline-only applies, so an operator catalog arrives only via `-nbar2-catalog`, read once at startup.

**Three rejections, all 400, none silent.**
`DeviceFlowConfig.Validate` already carries the precedent: `options_interface_table` under `netflow5` or `sflow` is refused with an error naming the supported protocols.

1. `nbar2: true` with any protocol other than `ipfix` is rejected, with an error naming `ipfix`.
2. `nbar2: true` on a device type without NBAR2 is rejected, naming the offending resource file, via `nbar2IncapableRequest` built as the third sibling of `flowIncapableRequest` and `opticalIncapableRequest`.
   It inherits their round-robin semantics: a mixed batch is accepted and incapable devices are skipped with a log line, and only an entirely incapable resolved type set fails.
   "Skipped" means something different here than for flow, and the difference is stated.
   A flow-incapable device in a mixed batch gets **no flow block**.
   An NBAR2-incapable but flow-capable device in a mixed NBAR2 batch gets the **plain IPFIX record** with `nbar2` dropped and logged once per type, because its flow block is otherwise valid.
   The two outcomes differ in byte identity and in what the ground-truth join sees, so the spec names which applies.
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
`application_id` in the key is the **wire selector** (the 32-bit engine-id plus selector value), never `appIdx`.
`addAppBatch` builds `appKey` from `FlowRecord` fields, and an index is only meaningful against one catalog: two per-type overlays can place different applications at the same index, and keying on the index would merge them.
Resolving the selector at ledger time means the ledger, like the encoder, needs the device's catalog.
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
2. **Encoder and `Tick`.**
   Enterprise IEs, variable-length encoding, measured pagination with a consumed-count return, the `Tick` change that counts and re-queues on that count, and the drop-and-count rule for a record that fits no datagram.
   Per-catalog encoder construction.
   Reconcile template-ID allocation with the existing options-interface-table path.
   Decode round-trip tests including the length boundary cases.
   Depends on the sequence-number decision.
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
- TLS SNI and certificate common name. No Cisco export exists; TLS-classified traffic is represented by `applicationId` and the application table.
- Bidirectional or client/server AVC fields such as `clientIPv4Address` and the response-time metrics. Separate feature.
- Protocol-pack emulation. nl6 ships a fixed catalog, not a versioned protocol pack.

## Open questions

1. Resolved: 45003 stays in scope for the IOS and IOS-XE router class (ISR G2, ASR 1000); the Catalyst 9500 number is unconfirmed by any Cisco document read, per `testdata/cisco-avc/NOTES.md`.
2. Resolved: no Cisco PEN 9 export of a TLS SNI or certificate common name string was found on any platform checked, so TLS SNI and certificate common name leave scope, per `testdata/cisco-avc/NOTES.md`.
3. Resolved: engine ids 3 (IANA-L4, port-based), 6 (USER-Defined, custom) and 13 (PANA-L7, NBAR2 layer-7), per RFC 6759 section 4.1, per `testdata/cisco-avc/NOTES.md`.
4. Resolved: scope field `applicationId` (IE 95), non-scope fields `applicationName` (IE 96) and `applicationDescription` (IE 94), per RFC 6759 section 4.3, per `testdata/cisco-avc/NOTES.md`.
5. Template ID allocation when a device enables both `nbar2` and `options_interface_table`. Unit 2.
6. Resolved: the IPFIX sequence number is fixed fleet-wide in a prerequisite PR (section 2, option 1).
