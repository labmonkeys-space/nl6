---
sidebar_label: "SNMP data fidelity"
description: "What the load-time checks prove about the SNMP data nl6 serves, and which vendor subtrees a human has checked against a published MIB."
---

# SNMP data fidelity

How far can you trust a value nl6 serves?
It depends on where its OID lives.

| Data | Proven | Not proven |
|------|--------|------------|
| Standard MIB-2 leaves the type table types | Encoded at the declared type, as well-formed BER, by three load rules | Nothing further is needed: the MIB is public and the objects are standard |
| Interface counters and state, and every metric nl6 computes | Computed by the interface engine, the same value on SNMP, gNMI and sFlow at the same instant | Traffic shapes other than the sine wave |
| Vendor enterprise subtrees, 5 audited arcs | Under the right vendor's number; values read against the vendor's MIB | Access modes |
| Vendor enterprise subtrees, 14 labelled arcs | Under the right vendor's number | Whether the objects below it exist, mean what their values suggest, or are readable. Treat them as plausible-looking test data, not as a model of the device |

The automatic rules prove only that nl6 will not emit a mistyped BER value.
Whether an OID means what the vendor's MIB says is a question only a human reading that MIB can answer.
This page explains both halves.
The tables of rules, tests and arc dispositions are in [SNMP data validation](../reference/snmp-data-validation.md).

## Check a specific OID

1. Find the OID in the [SNMP reference](../reference/snmp.md). A standard leaf the type table types has passed the load rules, so its wire type is right. Interface counters and state come from the interface engine, not the file.
2. For an OID under a vendor PEN, look the PEN up in the [vendor arc disposition tables](../reference/snmp-data-validation.md#vendor-arc-disposition).
3. Audited: the value was read against the MIB.
4. Labelled: the resource file part says `UNAUDITED-ARC(<pen>)` and nobody has checked it.

An OID that is wrong against its MIB is a data defect.
Report it with the MIB name and the object.

## Resource values are validated at load

`validateSNMPResourceValues` runs three rules over the `snmp` array of every resource file, in the order `encodeTypedValue` applies them, so the first diagnosis to fire is the one that matches what the wire would do.

| Rule | Leaves | Refuses | Note |
|------|--------|---------|------|
| **1. Exception sentinels** | All | A value exactly equal to `noSuchObject` or `endOfMibView` | nl6 carries SNMP exceptions internally as those strings. The match is exact: `NoSuchObject` or `noSuchObject seen` is ordinary data |
| **2. OID values** | OID-typed leaves, today `sysObjectID` and `entPhysicalVendorType` | A value the encoder cannot represent as an OID | |
| **3. Numeric types** | `Counter32`, `Gauge32`, `TimeTicks`, `Counter64`, `IpAddress` | A value that does not encode at that type: whitespace, units, hex, fractions, out of range | A negative value on a 32-bit unsigned leaf loads with a warning and goes out wrap-cast, so `-1` becomes `4294967295`. The same `-1` on a `Counter64` is refused, because that type has no signed fallback |

Rule 3 is the class that once shipped a real bug: a `freeMem` entry carrying the device's name went out as an OCTET STRING, and a collector that types the OID as a gauge logged a conversion error on every poll.
The full outcome table is in [SNMP data validation → Load rules](../reference/snmp-data-validation.md#load-rules).

How the rules run:

- Every rule calls the production encoder and inspects what it emits. A second predicate would drift from the encoder, and then the loader would accept what the wire refuses, or the other way round.
- They run on every load path: startup, round-robin creation and REST device creation.
- A rejection at startup exits the process. Over REST it answers HTTP 400 with the file's base name, the OID and the value; the full path stays in the server log. Round-robin creation fails the call rather than skipping the offending type. See [Web API → `resource_file` failures](../reference/web-api.md#resource_file-failures).

What the rules do not reach:

- A leaf the type table does not type. It is served as INTEGER when the value parses as a number and as OCTET STRING otherwise. Both are legitimate encodings, so a mistyped value on an untyped leaf loads and is served.
- The OID key. The rules check the value, never whether the name is a legal instance of its table.
- Semantics. A value that encodes cleanly passes even when the object at that OID is a different object, or does not exist.
- Access modes.
- `sysName` and `sysLocation`, which are served outside the resource map. `sysName` derives from the device. `sysLocation` comes from the worldcities dataset, and a location spelled like an exception sentinel is replaced with `Unknown Location`.

Each of those gaps is covered below by a corpus guard, a hand audit, or a label saying it is open.

## Bare column OIDs

A varbind name has to be an instance, with exactly as many trailing sub-identifiers as the table's INDEX clause says.
Both ways of getting that wrong encode cleanly, so no load rule can see them.

| Shape | Example | Legal form |
|-------|---------|------------|
| **Bare column**, too few sub-identifiers | `1.3.6.1.2.1.25.2.3.1.4`, the `hrStorageAllocationUnits` column | `…1.4.<index>` |
| **Over-specified instance**, too many | `…1.2.2.1` under `ciscoImageEntry`, whose INDEX has one arc | `…1.2.2` |

A hand audit deleted 61 such entries from the shipped profiles: 57 bare columns and 4 over-specified instances.
Some were vendor columns served by profiles of a different vendor, which the PEN guard below now refuses on its own.

Two corpus tests keep the class from growing back:

- One reads the JSON and reports any shipped OID that another shipped OID extends.
- The other walks every profile and reports any bare column a walk would emit.

Both scan across profiles, not within one, because legality is a property of the OID and not of the profile that carries it.

What they cannot see:

- The detector is a heuristic. "Some other shipped OID extends it" stands in for "it is a column", and fails when the extending sibling is the malformed one. A hit is a candidate to check against the MIB, never a verdict.
- A bare column that nothing in the corpus extends, an over-specified instance whose legal prefix is absent, or a wrong INDEX arity in general. "The census reads zero" means no shipped entry is an interior node of the shipped set, not that every shipped name is a legal instance.

Deleting rows can empty a table.
Four profiles lost their only `hrStorageTable` row in that audit and now model no storage.
That is the intended outcome: a collector getting nothing is better than one binding whose name is not a legal instance.
Do not restore a row to make a table non-empty.

## A trap and a poll must agree on type

A trap catalog declares each varbind's ASN.1 type, and the resource `snmp` array separately determines the type a GET of the same OID answers.
One Cisco power-supply description was once sent as a string by a trap and answered as an INTEGER by a poll.

- A corpus test joins the two surfaces on the OID, per profile, and requires the tag each production encoder emits to match. It reads the merged effective catalog, so the universal catalog and per-type overlays are compared as a device would fire them.
- A second rule requires one catalog never to declare the same OID at two types.
- The check is internal consistency only. It asks whether nl6 contradicts itself, never whether nl6 agrees with the vendor. Most trap varbinds name notification objects no profile serves, so the join compares only a handful of pairs.

## Semantic faithfulness

The three load rules answer "will nl6 put a mistyped BER value on the wire".
They never answer "is this profile faithful to the MIB".
The Palo Alto audit calibrates how much the guards prove: of the 11 Palo Alto enterprise OIDs `palo_alto_pa3220` served, 8 were wrong or invalid, and every one passed all three rules.
A collector keyed on `panMgmtPanoramaConnected` got `4194304` where a real PA-3220 answers `connected`.
One keyed on `panChassisType` got `127` where the MIB defines a DisplayString such as `PA-3220`.

The same audit found twelve profiles that are not Palo Alto devices serving that subtree.
Those entries were deleted, not corrected: a vendor enterprise subtree is an identity claim, and a collector keyed on PAN-COMMON-MIB would read an Arista serving it as a firewall.

So nl6 answers two separate questions about every vendor subtree.
Whose number it sits under, which a guard enforces.
Whether the objects under that number mean what the vendor says, which only a human reading the MIB can answer.

### Every profile serves its own vendor's PEN and no other

A corpus guard walks every shipped profile and requires each enterprise OID it serves to sit under the one IANA private enterprise number its device type belongs to.

- It reads both positions an enterprise OID can appear in: an OID name, and an OID-typed value such as `sysObjectID.0` or `entPhysicalVendorType`. `sysObjectID.0` is the field a collector reads for vendor detection, so a name-only scan would miss the most important case.
- It covers the dynamic metric OIDs served from Go code, and the compiled-in fallback a device gets when its named resource file is missing. That fallback answers the RFC 5612 documentation PEN instead of claiming to be Cisco hardware.
- The PEN is matched on a sub-identifier boundary, because PEN 2 is a string prefix of the Huawei, Check Point, Juniper and Palo Alto numbers.
- An `entPhysicalVendorType` with no known vendor type answers `zeroDotZero` (`0.0`), as RFC 4133 prescribes. A value under the reserved PEN 0 fails the guard like any other foreign arc.

The map from device type to PEN is curated by hand from the IANA registry, never derived from name matching.
Several correct pairs share no word with their type name:

| Device type | PEN | Registered to |
|-------------|-----|---------------|
| `hpe_proliant_dl380` | 232 | Compaq |
| `dell_emc_unity` | 1139 | EMC |
| `nokia_7750_sr12` | 6527 | Nokia |
| `netapp_ontap` | 789 | Network Appliance |
| `ibm_power_s922` | 2 | IBM |
| `aws_s3_storage` | 32473 | Documentation PEN. The profile is a category of S3-compatible gateways, and AWS's own S3 has no SNMP surface, so naming Amazon would trade one misattribution for a more plausible one. The exception is allowed for this profile only |

What the guard does not cover:

- Whether the objects below a correct PEN mean what the vendor's MIB says, or are readable at all. That is the audit question below.
- An OID-typed value under the right PEN that resolves to no assignment. One `sysObjectID` that named no Arista product was found by audit and fixed. The class needs a MIB per arc.
- A missing identity. Nothing requires a profile to identify itself, only to identify itself truthfully.
- gNMI, the REST surface and trap catalog `snmpTrapEnterprise` values. The catalogs were checked by hand and are clean, but no test scans them.

### Vendor arc audits and miss rates

Five arcs have been audited by reading the vendor's MIB.
Each audit is quoted as a miss rate: distinct OIDs found wrong or unresolvable, out of distinct OIDs read.

| Vendor | PEN | Wrong |
|---|---|---|
| Palo Alto | 25461 | 8 of 11 |
| Cisco | 9 | 11 of 13 |
| Arista | 30065 | 6 of 6 |
| Ciena | 1271 | 0 of 1 |
| Juniper | 2636 | 13 of 15 |

The pattern is the finding.
Four of the five arcs were mostly or entirely wrong.
The Ciena result keeps that from becoming a general claim: the corpus is split between data somebody read a MIB for and data nobody did.

The errors fall into a few shapes, and an unaudited arc can contain any of them:

- A value of the wrong kind, such as a number where the MIB declares a DisplayString, or a percentage outside its declared range.
- An OID that is not a valid object at all, such as a child under a leaf scalar, or a value on an OBJECT-IDENTITY container.
- A wrong INDEX arity: a table served with a scalar `.0` instance, or with too few index arcs.
- A `sysObjectID` that names the wrong product. One Juniper profile identified itself as a different chassis in the same family, so vendor detection succeeded and was wrong.
- An object that exists but is not readable, covered in [Access modes are not modelled](#access-modes-are-not-modelled).
- A whole vendor subtree on the wrong vendor's device, which the PEN guard refuses.

Audit fixes either correct a value against the MIB or delete the entry.
An entry is deleted when no correct readable value exists, or when the right sub-identifiers could not be resolved from the MIB.
Each audit is pinned by a test that records the reading.
That is a record, not a live verification: no MIB file is checked in, and nothing in CI compares nl6 against a vendor MIB.

NVIDIA's PEN 5703 is in the audited set for a different reason.
NVIDIA publishes no SNMP GPU MIB, so every object below that PEN is nl6's own definition, documented in the [GPU collector OID contract](../reference/gpu/index.md#collector-oid-contract).

### Every arc is audited, labelled, or explicitly excluded

Every enterprise arc a shipped profile serves is exactly one of three things, and a test fails by name on any arc that is none of them.

| State | Meaning | Marker |
|-------|---------|--------|
| **Audited** | Somebody read the vendor's MIB | A test that records the reading |
| **Labelled** | Nobody has | `UNAUDITED-ARC(<pen>)` in the `_comment` of every resource file part that carries the arc |
| **Excluded** | Not a vendor claim, such as the documentation PEN on `aws_s3_storage` | A row in the [excluded pairs](../reference/snmp-data-validation.md#excluded-pairs) table |

That is what stops the corpus regrowing silent, unchecked vendor data: a new device type that serves a vendor subtree and is none of the three fails the suite.

Fourteen arcs are labelled rather than audited.
Nothing in this repository reads them: no published polling rule, no trap varbind and no doc keys on any of them.
At the observed miss rates, auditing them would be weeks of work whose main output is deleting data nothing reads.
If you key a collector on one of them, that arc is a candidate for an audit.

Each label states:

- that the objects under the PEN have not been read against any of the vendor's MIBs,
- that the PEN itself is checked, so what is unverified sits below the number,
- what "unverified" covers: whether each object is defined, whether the value matches its SYNTAX, and whether the object is readable,
- the audited miss rates, so a reader can calibrate.

The marker is per file part and carries the PEN, so every file a reader might open says so, and a labelled arc does not excuse a second, unlabelled arc in the same file.
`git grep UNAUDITED-ARC` lists every labelled part.
A staleness check fails a marker naming a PEN its part no longer serves, and a marker on an arc that has since been audited.
No test can check that a label is true, because no test can read a MIB.
What the test refuses is the fourth state: a vendor subtree that reads as checked because nothing says otherwise.

### Access modes are not modelled

No nl6 rule models MAX-ACCESS.
The load rules check encodability, the PEN guard checks vendor identity, and the audit tests check names, types and values.
None of them can see that an object is `write-only` or `not-accessible`, because an access mode is a property of the MIB and nl6 has no MIB.

One instance has been found and fixed.
Two Cisco profiles served `writeMem` from OLD-CISCO-SYSTEM-MIB as a readable integer: the object exists, the arc is right and the value encoded, so every guard passed it.
It is `write-only`, and a command rather than a datum: writing it saves the configuration, and writing `0` erases it.
The entries were deleted, since a write-only object has no correct readable value.
The class is open: any unaudited arc may still contain objects a real device would refuse to read.

For how the agent answers a request, see the [SNMP reference](../reference/snmp.md).
For writing your own profiles, see [resource files](../reference/resource-files.md).
