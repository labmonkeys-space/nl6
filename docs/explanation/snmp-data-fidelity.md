---
sidebar_label: "SNMP data fidelity"
description: "What the load-time checks prove about the SNMP data nl6 serves, and which vendor subtrees a human has checked against a published MIB."
---

# SNMP data fidelity

How trustworthy is the SNMP data nl6 actually serves?

This page answers that in two parts.
**Load-time validation** is what nl6 enforces automatically on every resource file, including one you write yourself.
Three rules decide whether a value can go on the wire at its declared type.
**Vendor arc audits** are what a human checked by hand against a published MIB, and, more usefully, what nobody checked.

The distinction matters more than it sounds.
The automatic rules prove only that nl6 will not emit a mistyped BER value.
They say nothing about whether an OID means what the vendor's MIB says it means.
Five vendor subtrees have been read against a MIB.
Fourteen have not, and are labelled as such in the files themselves.

The short version for a collector developer is this.
Standard MIB-2 data, the dynamic interface counters and anything nl6 computes are encoded correctly and agree across protocols.
A vendor enterprise subtree is under the right vendor's number, but unless its arc is listed as audited, nobody has checked that the objects below that number exist or mean what their values suggest.
Treat an unaudited vendor arc as plausible-looking test data, not as a model of the device.

For how the agent answers a request, see the [SNMP reference](../reference/snmp.md).
For writing your own profiles, see [resource files](../reference/resource-files.md).
For the tables of rules, tests and arc dispositions, see [SNMP data validation](../reference/snmp-data-validation.md).

## Resource values are validated at load

`validateSNMPResourceValues` runs three rules over the `snmp` array of every resource file.
It applies them in the order `encodeTypedValue` itself applies them, so the first diagnosis to fire is the one that matches what the wire would do.

The first rule refuses a response exactly equal to `noSuchObject` or `endOfMibView`.
nl6 carries SNMP exceptions internally as those strings, so a resource value spelled like one would turn into an exception on the wire.
The match is exact: `NoSuchObject` or `noSuchObject seen` is ordinary data.

The second rule covers values on OID-typed leaves, today `sysObjectID` and `entPhysicalVendorType`.
The value must be an OID the encoder can represent.

The third rule covers `Counter32`, `Gauge32`, `TimeTicks`, `Counter64` and `IpAddress` leaves.
A value on one of those leaves must encode at that type.
This is the class that once shipped a real bug.
A `freeMem` entry carrying the device's name went out as an OCTET STRING, and a collector that types the OID as a gauge logged a conversion error on every poll.

Every rule decides by calling the production encoder and inspecting what it emits.
None of them re-derives the encoder's rules in a second predicate.
A second predicate drifts from the encoder over time, and then the loader accepts what the wire refuses or the other way round.
Calling the encoder means the loader's verdict and the wire's behaviour cannot disagree.

Rule 3 inherits the encoder's asymmetries rather than tidying them up.
A negative value on a 32-bit unsigned leaf loads with a warning and goes out wrap-cast, so `-1` becomes `4294967295`.
The same `-1` on a `Counter64` is refused, because that type has no signed fallback.
Whitespace, units, hex, fractions and out-of-range values are refused.
The full outcome table is in [SNMP data validation](../reference/snmp-data-validation.md#load-rules).

Rules 2 and 3 reach only leaves the type table types.
A leaf it does not type is served as INTEGER when the value parses as a number and as OCTET STRING otherwise.
Both are legitimate encodings, so there is nothing to compare against.
A mistyped value on an untyped leaf therefore loads and is served.

The rules run on every load path: startup, round-robin creation and REST device creation.
A rejection at startup exits the process.
Over REST it answers HTTP 400 with the file's base name, the OID and the value, and the full path stays in the server log.
A rejection is never downgraded to a log line, and round-robin creation fails the call rather than skipping the offending type.
The response envelope is in [Web API → `resource_file` failures](../reference/web-api.md#resource_file-failures).

`sysName` and `sysLocation` are served outside the resource map, so the rules do not see them.
`sysName` is derived from the device.
`sysLocation` comes from the worldcities dataset, and a location spelled like an exception sentinel is replaced with `Unknown Location` before it is served.

### What the rules prove

The rules prove encodability.
A value that passes all three will go on the wire at the type its leaf declares, as well-formed BER.

They do not prove semantics.
A value that encodes cleanly passes even when the object at that OID is a different object, or does not exist at all.
They do not check the OID key, only the value.
They do not check that a varbind name is a legal instance of its table.
They do not model access modes.
Each of those gaps is covered below, either by a corpus guard, by a hand audit, or by an honest label saying it is open.

## Bare column OIDs

A varbind name has to be an instance, not a column.
An instance has exactly as many trailing sub-identifiers as the table's INDEX clause says.

Both ways of getting that wrong can ship in a resource file, and no load rule can see either.
A bare column has too few sub-identifiers: `1.3.6.1.2.1.25.2.3.1.4` names the `hrStorageAllocationUnits` column, and a value lives at `…1.4.<index>`.
An over-specified instance has too many: `ciscoImageEntry` has a single-arc INDEX, so `…1.2.2` is legal and `…1.2.2.1` is not.
The OIDs are well formed and the values encode cleanly, which is why the encoder-based rules pass them.

A hand audit deleted 61 such entries from the shipped profiles: 57 bare columns and 4 over-specified instances.
Some of those were vendor columns served by profiles of a different vendor, which the vendor-arc guards below now refuse on their own.

Two corpus tests keep the class from growing back.
One reads the JSON and reports any shipped OID that another shipped OID extends.
The other walks every profile and reports any bare column a walk would emit.
Both scan across profiles, not within one, because legality is a property of the OID and not of the profile that carries it.

The detector is a heuristic.
"Some other shipped OID extends it" stands in for "it is a column", and that proxy fails when the extending sibling is the malformed one.
Telling a bare column from a legal instance with an over-specified neighbour needs the table's INDEX arity, and that needs the MIB.
So a hit is a candidate to check against the MIB, never a verdict.

Neither test can see a bare column that nothing in the corpus extends, an over-specified instance whose legal prefix is absent, or a wrong INDEX arity in general.
"The census reads zero" means no shipped entry is an interior node of the shipped set.
It does not mean every shipped name is a legal instance.

Deleting rows can legitimately empty a table.
Four profiles lost their only `hrStorageTable` row in that audit, and now model no storage.
That is the intended outcome.
A collector getting nothing is better than a collector getting one binding whose name is not a legal instance.
Do not restore a row to make a table non-empty.

## A trap and a poll must agree on type

A trap catalog declares each varbind's ASN.1 type.
The resource `snmp` array separately determines the type a GET of the same OID answers.
The two are validated by separate code, so one profile could answer one object at two types depending on how a collector asked.
That happened once, on a Cisco power-supply description that a trap sent as a string and a poll answered as an INTEGER.

A corpus test now joins the two surfaces on the OID, per profile, and requires the tag each production encoder emits to match.
It reads the merged effective catalog, so the universal catalog and per-type overlays are compared as a device would fire them.
A second rule requires one catalog never to declare the same OID at two different types.

The check is internal consistency only.
It asks whether nl6 contradicts itself, never whether nl6 agrees with the vendor.
A catalog that declares a vendor object at the wrong type, on an OID no profile serves, is out of its reach.
Most trap varbinds name notification objects that no profile serves at all, so the join compares only a handful of pairs.
That is expected and is not a coverage claim.

## Semantic faithfulness

The three load rules answer "will nl6 put a mistyped BER value on the wire".
They never answer "is this profile faithful to the MIB".
The Palo Alto audit is the calibration for how much the guards prove.

Of the 11 Palo Alto enterprise OIDs `palo_alto_pa3220` served, 3 were correct, 5 answered a value of the wrong kind, and 3 were not valid OIDs at all.
Every one passed all three load rules.
A collector keyed on `panMgmtPanoramaConnected` got `4194304` where a real PA-3220 answers `connected`.
One keyed on `panChassisType` got `127` where the MIB defines a DisplayString such as `PA-3220`.
A rule that appears to work and validates nothing is the failure a simulator has to avoid above all others.

The same audit found twelve profiles that are not Palo Alto devices serving that subtree too.
Those entries were deleted, not corrected.
An Arista should not answer a Palo Alto enterprise OID at all, and a collector keyed on PAN-COMMON-MIB would read such a device as a firewall.
A vendor enterprise subtree is an identity claim, not an approximation.

That leads to the two separate questions nl6 now answers about every vendor subtree.
The first is whose number the subtree sits under, and a guard enforces it for every profile.
The second is whether the objects under that number mean what the vendor says, and only a human reading the MIB can answer it.

### Every profile serves its own vendor's PEN and no other

A corpus guard walks every shipped profile and requires each enterprise OID it serves to sit under the one IANA private enterprise number its device type belongs to.
It reads both positions where an enterprise OID can appear: an OID name, and an OID-typed value such as `sysObjectID.0` or `entPhysicalVendorType`.
`sysObjectID.0` is a response, and it is the field a collector reads for vendor detection, so a name-only scan would miss the most important case.

The same rule covers the two places enterprise OIDs live outside resource files.
The dynamic metric OIDs served from Go code are checked, and so is the compiled-in fallback a device gets when its named resource file is missing.
That fallback now answers the RFC 5612 documentation PEN instead of claiming to be Cisco hardware.

The map from device type to PEN is curated by hand from the IANA registry, never derived from name matching.
Several correct pairs share no word with their type name: `hpe_proliant_dl380` is Compaq's 232, `dell_emc_unity` is EMC's 1139, `nokia_7750_sr12` is 6527, `netapp_ontap` is 789 (Network Appliance), and `ibm_power_s922` is 2.
The PEN is matched on a sub-identifier boundary, because PEN 2 is a string prefix of Huawei, Check Point, Juniper and Palo Alto numbers.

`aws_s3_storage` answers the documentation PEN 32473.
The profile names a category of S3-compatible gateways that many vendors implement, and AWS's own S3 has no SNMP surface, so naming Amazon would trade one misattribution for a more plausible one.
That exception is allowed for this profile only.

An `entPhysicalVendorType` with no known vendor type answers `zeroDotZero` (`0.0`), as RFC 4133 prescribes.
A value under the reserved PEN 0 fails the guard like any other foreign arc.

What the guard does not cover:

- Whether the objects below a correct PEN mean what the vendor's MIB says, or are readable at all. That is the audit question below.
- An OID-typed value under the right PEN that resolves to no assignment. The guard checks which vendor an OID belongs to, never whether the vendor assigned it. One `sysObjectID` that named no Arista product was found by audit and fixed. The class needs a MIB per arc.
- A missing identity. Nothing requires a profile to identify itself, only to identify itself truthfully.
- gNMI, the REST surface and trap catalog `snmpTrapEnterprise` values. The catalogs were checked by hand and are clean, but no test scans them.

### Vendor arc audits and miss rates

Five arcs have been audited by reading the vendor's MIB.
Each audit is quoted as a miss rate: distinct OIDs found wrong or unresolvable, out of distinct OIDs read.
Quoting the miss rate, and counting each OID once, keeps the numbers comparable across vendors.

| Vendor | PEN | Wrong |
|---|---|---|
| Palo Alto | 25461 | 8 of 11 |
| Cisco | 9 | 11 of 13 |
| Arista | 30065 | 6 of 6 |
| Ciena | 1271 | 0 of 1 |
| Juniper | 2636 | 13 of 15 |

The pattern is the finding.
Four of the five arcs were mostly or entirely wrong.
The Ciena result is what keeps that from becoming a general claim: the corpus is not uniformly fabricated.
It is split between data somebody read a MIB for and data nobody did.

The errors found fall into a few shapes, and an unaudited arc can contain any of them:

- A value of the wrong kind, such as a number where the MIB declares a DisplayString, or a percentage outside its declared range.
- An OID that is not a valid object at all, such as a child hanging under a leaf scalar, or a value on an OBJECT-IDENTITY container.
- A wrong INDEX arity: a table served with a scalar `.0` instance, or with too few index arcs.
- A `sysObjectID` that names the wrong product. One Juniper profile identified itself as a different chassis in the same family. Vendor detection succeeded and was wrong, and nothing downstream could tell.
- An object that exists but is not readable, covered in [Access modes are not modelled](#access-modes-are-not-modelled).
- A whole vendor subtree on the wrong vendor's device, which the PEN guard above now refuses.

Audit fixes either correct a value against the MIB or delete the entry.
An entry is deleted when no correct readable value exists, or when the right sub-identifiers could not be resolved from the MIB.
Inventing them would be the same guessing the audit exists to undo.

Each audit is pinned by a test that records the reading.
That is a record, not a live verification.
No MIB file is checked in, and nothing in CI compares nl6 against a vendor MIB.

NVIDIA's PEN 5703 is in the audited set for a different reason.
NVIDIA publishes no SNMP GPU MIB, so every object below that PEN is nl6's own definition and there is nothing to audit against.
The objects are documented in the [GPU collector OID contract](../reference/gpu/index.md#collector-oid-contract), which is the only vendor-arc polling contract nl6 publishes.

### Every arc is audited, labelled, or explicitly excluded

Every enterprise arc a shipped profile serves is exactly one of three things, and a test fails by name on any arc that is none of them.

An audited arc has had somebody read the vendor's MIB.
A labelled arc has not, and every resource file part that carries it says so with the literal marker `UNAUDITED-ARC(<pen>)` in its `_comment`.
An excluded arc is not a vendor claim at all, such as the documentation PEN on `aws_s3_storage`.

A new device type that serves a vendor subtree and is none of the three fails the suite.
That is what stops the corpus regrowing silent, unchecked vendor data.

Fourteen arcs are labelled rather than audited.
A scope measurement found that nothing in this repository reads them: no published polling rule, no trap varbind and no doc keys on any of them.
At the observed miss rates, auditing them would be weeks of work whose main output is deleting data nothing reads.
A label is cheaper and more honest than silence.
Without it, a reader who opens one of those files sees a vendor subtree and reasonably infers that somebody checked it.

Each label states that the objects under the PEN have not been read against any of the vendor's MIBs.
It states that the PEN itself is checked, so what is unverified is what sits below the number.
It states what "unverified" covers: whether each object is defined, whether the value matches its SYNTAX, and whether the object is readable.
It quotes the audited miss rates so a reader can calibrate.

The marker is per file part, not per profile, so every file a reader might open carries it.
It carries the PEN, so a labelled arc does not excuse a second, unlabelled arc in the same file.
`git grep UNAUDITED-ARC` lists every labelled part.

A staleness check runs the other way.
A marker naming a PEN its part no longer serves fails, and so does a marker on an arc that has since been audited, because the label would then tell a reader the opposite of the truth.

No test can check that a label is true, because no test can read a MIB.
What the test does is refuse the fourth state: a vendor subtree that reads as checked because nothing says otherwise.

Absence of a consumer in this repository is not absence in the world.
If you key a collector on one of the fourteen labelled arcs, that arc is a candidate for an audit.

### Access modes are not modelled

No nl6 rule models MAX-ACCESS.
The load rules check encodability, the PEN guard checks vendor identity, and the audit tests check names, types and values.
None of them can see that an object is `write-only` or `not-accessible`, because an access mode is a property of the MIB and nl6 has no MIB.

One instance has been found and fixed.
Two Cisco profiles served `writeMem` from OLD-CISCO-SYSTEM-MIB as a readable integer.
The object exists, the arc is right, and the value encoded as the declared INTEGER, which is why every guard passed it.
But the object is `write-only`, and it is a command rather than a datum: writing it saves the configuration, and writing `0` erases it.
A collector that discovers it as a readable integer has learned something false about the device.
The entries were deleted, since a write-only object has no correct readable value.

The class is open.
Any unaudited arc may still contain objects a real device would refuse to read.

## Checking a specific OID

To decide how far to trust a particular value, start from where its OID lives.

A standard MIB-2 OID that the type table types has passed the encoder-based rules, so its wire type is right.
Interface counters and state are computed by the interface engine rather than read from the file, and they agree across SNMP, gNMI and sFlow at the same instant.

An OID under a vendor PEN is under the right vendor, because the PEN guard enforces that for every profile.
Whether it means anything depends on the arc's disposition.
Look up the PEN in the [vendor arc disposition tables](../reference/snmp-data-validation.md#vendor-arc-disposition).
If it is audited, the value was read against the MIB.
If it is labelled, the resource file part says `UNAUDITED-ARC(<pen>)` and nobody has checked it.

For what each load rule refuses and which corpus tests guard the shipped profiles, see [SNMP data validation](../reference/snmp-data-validation.md).
If you find an OID that is wrong against its MIB, that is a data defect worth reporting with the MIB name and the object.
