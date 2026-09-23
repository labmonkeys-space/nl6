# SNMP data fidelity

How trustworthy is the SNMP data nl6 actually serves?

This page answers that in two parts. **Load-time validation** is what nl6
enforces automatically on every resource file, including one you write
yourself: three rules that decide whether a value can go on the wire at its
declared type. **Vendor arc audits** are what a human checked by hand against
a published MIB, and, more usefully, what nobody checked.

The distinction matters more than it sounds. The automatic rules prove only
that nl6 will not emit a mistyped BER value. They say nothing about whether an
OID means what the vendor's MIB says it means. Five vendor subtrees have been
read against a MIB. Fourteen have not, and are labelled as such in the files
themselves.

For how the agent answers a request, see the [SNMP reference](snmp.md).
For writing your own profiles, see [resource files](resource-files.md).

## Resource values are validated at load

`validateSNMPResourceValues` runs three rules over the `snmp` array of every resource file, in the order `encodeTypedValue` itself applies them, so the first diagnosis to fire is the one that matches what the wire would do.
Every rule decides by **calling the encoder** and inspecting what it emits, never by a second predicate that re-derives the encoder's rules. That is how `trap_catalog.go`'s `validateDottedOID` drifted from `encodeOID` in both directions.

| Rule | What it refuses | Decided by |
|---|---|---|
| 1. Sentinel | a response exactly equal to `noSuchObject` or `endOfMibView` | `isSNMPExceptionValue`, the same exact test the encoder uses |
| 2. OID-typed value | a value on an `OBJECT IDENTIFIER` leaf that `encodeOID` cannot represent | calling `encodeOID` and testing for the degenerate `06 00` |
| 3. Typed class | a value on any leaf the type table types that does not encode at that type | calling `encodeTypedValue` and comparing the emitted tag with the declared one |

Rule 2 cannot be folded into rule 3: the degenerate `06 00` carries the **declared** tag, so a tag comparison is blind to it.

Rule 3 is the class that actually shipped a bug: a `freeMem` entry carrying the device's own name went out as an OCTET STRING, and OpenNMS, which types that OID as a gauge, logged a conversion error on every poll of every device for as long as the fleet ran.
It covers `Counter32`, `Gauge32`, `TimeTicks`, `Counter64` and `IpAddress` leaves, and it inherits the encoder's asymmetries rather than tidying them up:

- A negative on a `Counter32`, `Gauge32` or `TimeTicks` **loads**: the encoder parses it at 32-bit width and wrap-casts, so `-1` goes out as `0xFFFFFFFF` at the declared tag. The asymmetry is inherited from the encoder and has no shipped motivation. All 116 negative values in the shipped set are `-1` on `ipRouteMetric1/2/3/5`, which the table does not type and where RFC 1213 gives `-1` as "not used", and none sit on an unsigned 32-bit leaf. Because a wrapped `4294967295` is invisible to a collector in a way a dropped metric is not, such a value draws a load-time **warning** naming the file, the OID and what will go on the wire. It is not refused, because the encoder encodes it and the guard's verdict is the encoder's.
- The same `-1` on a `Counter64` is **refused**, because that branch has no signed fallback and degrades to an OCTET STRING.
- Surrounding whitespace is **refused** (`" 42"`, `"42 "`), because `strconv` does not trim.
- A value carrying units (`"42 packets"`), hex (`"0x2a"`), a decimal fraction, or anything past the type's width is **refused**.
- An `ipAdEntAddr` or other `IpAddress` leaf needs a dotted-quad IPv4 address; `"host"`, `"1"`, `"10.0.0.256"` and `"::1"` are all refused.

Rules 2 and 3 reach only leaves the type table types.
A leaf it does not type takes the encoder's default branch, where INTEGER for a number and OCTET STRING for anything else are both legitimate, so there is nothing to compare against.
Numeric leaves outside the table, such as the `OLD-CISCO-SYSTEM-MIB` INTEGER leaves, are covered instead by a test over the shipped profiles, which operator-supplied files never reach.

Applying rule 3 to the shipped set for the first time found 45 entries of exactly that class, all corrected in the same change: a bare `ipRouteDest` column OID valued `1` in 14 profiles (deleted, because that column is `IpAddress`-typed and `1` is not an address), 30 `ifInOctets`/`ifOutOctets` entries in the three NVIDIA profiles whose values overflowed `Counter32`, and one `asr9k` `sysUpTime` past the `TimeTicks` wrap (both wrapped modulo 2^32, which is what the real counter does).
Those 30 rewrapped values are now moot: they are among the 1322 static `ifInOctets`/`ifOutOctets` entries deleted when the cycler took both columns over, so nothing serves them any more.
The reversal chains rather than being replaced. It restores the earlier ledger first, reconstructing the tree that change left, and only then reverses its own three tables.

Sixteen further values were edited that rule 3 **never saw**, and it is worth naming the mechanism that did, because that is the one a reader will rely on next time. All sixteen sit on leaves the type table does not type, so all were and remain INTEGER on the wire:

- Values past 2^32, in `hrStorageSize`/`hrStorageUsed` rows and a Palo Alto memory scalar, found by the big-value guard.
- `hrStorageSize.1 = 2147483648`, exactly one over `Integer32`'s ceiling, in two profiles. Found by neither of those, because that guard's threshold is 2^32. A second guard closes the band between 2^31-1 and 2^32 and is what caught it.
- The rest are allocation-unit and `hrStorageUsed` rows rescaled alongside, so each `hrStorage` row stays internally consistent (`hrStorageAllocationUnits` is what makes a large device expressible in an `Integer32` size).

The whole transition is committed as data rather than summarised as a count: a ledger holds the 31 tag changes, 16 rescales and 14 removals, machine-generated from a diff against the parent revision, reverses them against today's corpus and requires the parent digest byte for byte.

The remainder of this section is about rule 1.

`validateSNMPResourceValues` rejects a resource entry whose response is exactly `noSuchObject` or `endOfMibView`.
The error names the file, the OID and the value, because fixing it means editing one line of one file.

The match is exact.
`noSuchObject seen`, `NoSuchObject` and ` noSuchObject` are ordinary data and load normally.

The check runs on every load path, and applies to the `snmp` array only.
SSH, API and optical entries never reach `encodeTypedValue`, and the trap and syslog catalogs use a different encoder.
In a device-type directory each JSON part is validated separately, so the error names the part that is wrong rather than the directory.

It closes the resource-file route, not every route.
`sysName` and `sysLocation` are served outside the resource map, so neither reaches this guard.
`sysLocation` comes from the operator-supplied worldcities CSV, and it is covered at `getRandomLocation`, the single funnel every served location passes through, whatever its source: a name equal to a sentinel is replaced with the coordinate-less `Unknown Location` the empty-dataset branch already uses, and the substitution is logged.
The CSV loader carries the same check on the row, so a defective dataset row is named with its file, but that check cannot fire today: the display string is always composed as `city, country` or `city, admin, country`, so it always contains `", "` and no sentinel does.
It is an invariant guard for a future change to that composition, and a guard fails if the composition changes.
`sysName` is derived from the device rather than from operator data, so there is nothing there to validate.

Where a rejection surfaces matters.
Resource files are also loaded on REST device creation, so a bad operator-supplied file is a failed API call in the middle of a run, not only a refusal at startup.
It answers HTTP 400, with the file's base name in the body, plus the OID and the value when the fault is attributable to one entry. The full path stays in the server log.
A rejection is never downgraded to a log line.
The startup load exits rather than substituting another profile, and round-robin device creation fails the call rather than skipping the offending device type.
An absent file is a different kind of fault: round-robin still skips it, while over REST it is also a 400, because naming a device type that does not exist is an unsatisfiable request rather than a server fault.
The no-path guarantee covers these classified rejections only. An unclassified loader failure still answers 500 with the raw error text.
The full path is logged server-side on every rejection, so base-naming the body loses nothing.
Full detail, including the response envelope, is in [Web API → `resource_file` failures](web-api.md#resource_file-failures).

Rule 2 covers a value on an OID-typed leaf, today only `sysObjectID`: it must be an OID the encoder can represent.
Encodability is decided by calling the encoder and testing for the degenerate `06 00`, not by a second predicate, so the loader cannot drift from the wire. See [The first OID sub-identifier is a varint](snmp.md#the-first-oid-sub-identifier-is-a-varint) above for what the encoder accepts.
The sentinel rule is checked first, matching the order the encoder applies them, so a sentinel on `sysObjectID` is reported as a sentinel collision.

What remains uncovered, stated in one place:

- **OID keys.** Only values are checked; a malformed `oid` key is not.
- **Bare table columns.** No rule sees them. A hand audit deleted **61 entries**: 57 bare columns across 14 distinct OIDs and 13 profiles, plus 4 over-specified instances. And the census reads zero *for what the census can see*, which is not the same as the class being closed. See [Bare column OIDs](#bare-column-oids) below.
- **Semantics.** The rules check ENCODABILITY, not faithfulness to the MIB: a value that encodes cleanly at its declared type passes even when the object at that OID is a different object, or does not exist. `palo_alto_pa3220`'s PAN subtree was the worked example — a number where `panMgmtPanoramaConnected` is a `DisplayString`, and two OIDs hanging under a leaf scalar — and every one of them passed all three rules. That profile was corrected by hand against PAN-COMMON-MIB. The *class* is untouched. Five arcs have since been audited by reading a MIB, at miss rates of Palo Alto 8 of 11, Cisco 11 of 13, Arista 6 of 6, Ciena 0 of 1 and Juniper 13 of 15. The remaining fourteen arcs have had no equivalent review and each now carries an `UNAUDITED-ARC(<pen>)` label saying so in the file, because nothing in this repository reads them. An arc is audited, deliberately labelled, or explicitly excluded, and a new one must be one of the three (see [Every arc is audited, labelled, or explicitly excluded](#every-arc-is-audited-labelled-or-explicitly-excluded)). The Ciena result is what tells the other three apart from a general claim. The corpus is not uniformly fabricated. It is split between data somebody read a MIB for and data nobody did. See [Semantic faithfulness](#semantic-faithfulness).
- **Access modes.** No rule anywhere models MAX-ACCESS. The three load rules check encodability, the PEN guards check vendor identity, and the audit reading tests check names, types and values. None of them can see that an object is `write-only` or `not-accessible`, because an access mode is a property of the MIB and nl6 has no MIB. The one confirmed instance was deleted (`writeMem`). The class is open. See [Access modes are not modelled](#access-modes-are-not-modelled).
- **Leaves the type table does not type.** Rules 2 and 3 are type-directed, so a mistyped value on an untyped leaf, such as an `Integer32` leaf carrying a value past 2^31-1, loads and is served as a wide INTEGER.
- **Vendor 64-bit counters.** A vendor HC column is not typed, so it is served as an INTEGER and SNMPv1 is not diverted for it. The big-value guard fails if a shipped profile grows such a column, which is the reminder that the table is hand-maintained.
- **`sysName`.** Derived from the device, not operator data.
- **Non-`snmp` sections.** SSH, API and optical entries never reach `encodeTypedValue`. The trap and syslog catalogs have their own validation. A trap catalog declaring one type for an OID whose polled value encodes as another is a *cross-surface* disagreement that no load rule can see, because neither side is wrong on its own; it is covered instead by a guard (see [A trap and a poll must agree on type](#a-trap-and-a-poll-must-agree-on-type)).
- **Version-0 GETBULK.** Answered as-is, `0x46` tags included, by decision (see above).

## Bare column OIDs

A varbind name has to be an instance, not a column, and an instance has exactly as many trailing sub-identifiers as the table's INDEX clause says.
Both ways of getting that wrong ship in resource files, and no load guard can see either: the OIDs are well formed and the values encode cleanly at their declared types.

- **Bare column**: too few sub-identifiers. `1.3.6.1.2.1.25.2.3.1.4` names the `hrStorageAllocationUnits` *column*. A value lives at `…1.4.<index>`.
- **Over-specified instance**: too many. `ciscoImageEntry`'s INDEX is `{ ciscoImageIndex }`, a single sub-identifier, so at `ciscoImageString` (`1.3.6.1.4.1.9.9.25.1.1.1.2`) the legal instance is `…1.2.2` and `…1.2.2.1` is one sub-identifier too many.

61 entries were deleted in total: 57 bare columns across 14 distinct OIDs and 13 profiles (bare `entPhysicalTable` columns, bare `ifDescr`/`ifMtu`/`ifSpeed`/`ifOperStatus`, `ciscoImageString`'s over-specified sibling's neighbours, a Juniper `jnxOperatingCPU` column carried by four *Cisco* profiles, a Palo Alto column carried by twelve *non-Palo-Alto* profiles, and a bare `hrStorageAllocationUnits` column), plus the 4 over-specified `ciscoImageString` instances.
The 14 `ipRouteDest` entries removed earlier are the precedent, but that change removed them because the typed-class rule refused the value, not as a sweep of the class.

**The detector is a heuristic, and it inverted on first use.**
"Some other shipped OID extends it" is a proxy for "it is a column", and the proxy fails precisely when the *extending* sibling is the malformed one.
All four Cisco profiles shipped both `ciscoImageString.2` and the over-specified `…2.2.1`; the detector flagged `.2.2`, the **legal** name, and the first cut of this change deleted it and kept the illegal one. Inverting the fix in four profiles.
Telling the two apart requires the table's INDEX arity, which requires the MIB, which nothing in the test suite has.
So a hit is a **candidate to check against the MIB**, never a verdict. The correction is recorded per row in `nl6571DeletedOverSpecifiedInstances`, and the limitation is documented on `bareColumnsAcrossProfiles` itself.

**The scan is corpus-wide, and narrowing it is the regression to guard against.**
A same-profile scan finds only 41 of them: legality is a property of the OID, not of which profile carries it.
Twenty further entries were bare columns whose instantiated sibling lived in a **different** profile, and the per-profile scan was structurally unable to see any of them: sweeping only the 41 would have driven the pinned constant to 0 while 20 bare columns still shipped, with a green suite.
Legality is a property of the OID, not of which profile carries it.

Both guards now share one detector (`bareColumnsAcrossProfiles`) and one comparison (`bareColumnCountViolation`), and both begin by calling `assertBareColumnDetectionIsCorpusWide`. A positive control that plants a bare column in profile A and its instance in profile B and requires it to be reported.
Narrow the scan and that control fails in both guards.
The control it replaces planted the column and its instance in the same set, so it survived a narrowing. That is how a review demonstrated both guards could be reverted to that blind spot with the whole suite green, since a narrowing changes no shipped byte and therefore moves no digest and no ledger.

**Four of the 61 emptied a table, and deleting them was still right.**
The bare `hrStorageAllocationUnits` entry in `cisco_catalyst_9500`, `cisco_nexus_9500`, `juniper_mx960` and `palo_alto_pa3220` was, in each of those profiles, the *only* `hrStorageTable` row of any column. No index, no descriptor, no size.
So deleting it removes the table rather than a duplicate, which is why it was raised as a decision rather than taken silently.
The decision is **delete**: the choice was between a collector getting nothing and a collector getting one binding whose name is not a legal instance OID, and an illegal varbind name is worse than an absent table.
**Those four profiles now model no storage, and that is the correct outcome.**
Do not restore the row to make `hrStorageTable` non-empty. A profile that models no storage should answer nothing for it.
Modelling the table properly (index, descriptor, size, used, allocation units, per row) is separate fidelity work, not a repair of this one.

**Exactly what the two guards cover, and what they do not.**
One guard reads the JSON and says what the corpus *contains*. A second walks every profile through `findNextOIDWithServed` and says what a walk *emits*. Both assert zero. Neither can see:

- **A bare column that nothing in the corpus extends.** Without a MIB it is indistinguishable from a scalar.
- **An over-specified instance whose legal prefix is absent.** Same reason, mirrored: `…1.2.2.1` alone looks like an ordinary leaf.
- **Any wrong INDEX arity**, which is the general form of both. The under-specified `jnxOperating` tranche is closed by a reading of the four-column INDEX clause out of JUNIPER-MIB and corrected or deleted all six rows: see [The Juniper arc audited against its MIBs](#the-juniper-arc-audited-against-its-mibs). The class is still open everywhere else, and deciding any instance needs the arc's MIB.

So "the census reads zero" means *no entry is an interior node of the shipped set*. It does not mean every shipped name is a legal instance, and this page should not be read as claiming that.

## A trap and a poll must agree on type

A trap catalog **declares** a varbind's ASN.1 type (`"type": "octet-string"`).
The resource `snmp` array **separately** determines the type of a GET of that same OID, through `oidTypeTable` plus `encodeTypedValue`'s value heuristics.
The two surfaces are validated by entirely separate code paths, and for a long time nothing joined them. So one profile could answer one object at two different types depending on how a collector asked.

`cisco_ios` shipped exactly that.
Its `ciscoEnvMonSupplyStatusChangeNotif` declared `ciscoEnvMonSupplyStatusDescr.1` as `octet-string`, while a GET of the same OID answered ASN.1 INTEGER: the resource value was the string `1`, that OID is not in `oidTypeTable`, and `encodeTypedValue`'s default branch takes the integer-parseable path.
One object, one profile, two types.
It was found by hand during the Juniper audit and fixed there, and the class is now closed.

A guard joins the two surfaces on the OID, per profile, and requires the tag each **production encoder** emits to match.
Six properties are load-bearing:

- **Both tags come from the encoders**, `encodeVarbindTyped` on the trap side and `encodeTypedValue` on the poll side. A hand-written type map would record today's agreement and then rot silently, which is how `validateDottedOID` drifted from `encodeOID` once. The trap side reads the tag back out of the encoded varbind rather than mirroring the encoder's switch, so a new case there is picked up for free. The catalog's type *vocabulary* is shared for the same reason: `trapVarbindTypes` is the loader's own accept-set and the probe table is driven off it, so a ninth type added to `compileEntry` fails a test instead of silently landing every varbind of that type in the encoder-failure bucket.
- **A templated value is encoded with a probe, and only a templated value.** The tag a trap varbind puts on the wire is a function of its declared type alone, so any value that type accepts resolves it. But falling back to a probe on *any* encode error would launder real defects into agreement. An `integer` varbind whose literal value is `up` fails at every fire, and the catalog loader's dry render disables the whole entry for an unrenderable one. The gate is the value containing `{{`, nothing else, and such a varbind is reported as an encoder failure.
- **`_common/traps.json` is applied to every profile**, because it is merged into every device type's effective catalog. The merge is done by the production resolver (`ScanPerTypeTrapCatalogs` plus the universal fallback), not by re-reading the files, so overlay precedence and `extends` are whatever the fleet gets. **This arm is pinned by the control, not by the counts**, and the difference was measured rather than assumed: a join narrowed to `entry.fromOverlay` — never examining a universal varbind at all — leaves every count in the file unchanged and the package green, because all six real `_common` varbinds are templated and contribute no occurrences. So the control substitutes a *synthetic* universal catalog whose varbind carries a literal OID the planted profiles serve. The same reason the entry comparison is on each universal entry's **varbind set** and not its name: `MergeOverlay` replaces a same-named entry wholesale.
- **The poll side has to be the production poll side.** Two ways it might not be, and both ship. `buildResourceIndexes` calls `oidIndex.Store` in sorted order, so a **duplicated OID** resolves last-wins. And after a non-stable `sort.Slice`, so which of several equal keys wins is unspecified; 111 `(profile, OID)` pairs are duplicated today (64 in `cisco_nexus_9500`, 32 in `juniper_mx960`, 5 in each `nvidia_*`, all `ifHighSpeed` rows carrying identical values, so none diverges yet). And `findResponse` answers **ahead of** `oidIndex` from `sysName.0`/`sysLocation.0` (which `buildResourceIndexes` does not even store), `getMetricValue`, `IfCounterCycler` (which also serves `ifAdminStatus`, `ifOperStatus` and `ifLastChange` from the interface state engine) and the LLDP/`ifAlias` provider, so a resource entry for one of those is dead data. Both are reported rather than resolved silently: there is no single polled value to compare against.
- **A varbind naming an OID the profile does not serve is normal, not a finding.** 182 of the 185 examined varbinds are in that bucket. The claim is only that **the profile serves no resource entry for them**. This guard cannot read a MIB, so it cannot say they are notification-only objects, however likely that is. They are counted so the number is visible when it moves, and never flagged. Flagging them would turn an agreement rule into a coverage rule, which is a different question.
- **The positive control has eight arms.** A planted disagreeing pair must be reported. A planted *agreeing* pair must be silent; a planted unencodable literal must surface as an encoder failure; a planted duplicate entry must be reported; a planted shadowed OID must be reported as shadowed, and its declared type deliberately *agrees* with its resource value so that a rule which stopped honouring shadowing falls silent rather than reporting a different kind; a planted overlay that keeps a universal entry's name while swapping its varbinds must be reported as drift; and a pair covers the typed-leaf rule below, one declaring the wrong type on a leaf `oidTypeTable` types and one declaring the right one. A test asserting zero findings cannot fail on its own, and the silent arms are what stop a rule that reports every joined pair from passing all the others.

The corpus is clean, and every number below is re-derived on each run and pinned to a named constant, because a rule that finds nothing to join reports no findings either:

| Constant | Value | What it counts |
|---|---|---|
| `trapCatalogVarbindsShipped` | 191 | distinct varbinds across the four `traps.json` files |
| `trapVarbindsWithTemplatedOID` | 6 | of those, naming no fixed object, all of `_common`'s |
| `trapPollJoinOccurrences` | 185 | `(profile, varbind)` pairs the join examines |
| `trapPollUnservedVarbinds` | 182 | of those, with no resource entry in that profile |
| `trapPollTypedUnservedVarbinds` | 0 | of *those*, the ones `oidTypeTable` types and so compares anyway |
| `trapPollJoinedPairsShipped` | 3 rows | the joined pairs **by identity**, not by count |
| `trapPollPerCatalogCensus` | 4 rows | the `{templated, examined, joined}` breakdown per catalog file |
| `trapCatalogProfiles` / `trapProfilesCarryingUniversal` | 29 / 29 | device types, and how many carry the universal entries unchanged |
| `trapPrependedJoinedPairs` | 24 | profiles serving one of the encoder-prepended OIDs |

The joined set is pinned by identity rather than by count because a count goes quiet on a swap. Drop one pair, gain another, and the total is unchanged.
The three are `cisco_ios` `1.3.6.1.4.1.9.9.13.1.5.1.2.1` — the OID that carried the defect, and so the regression anchor — and `juniper_mx240` `1.3.6.1.4.1.2636.3.1.2.0` / `.3.1.3.0`, each declared `octet-string` against a non-numeric string.
The per-catalog breakdown exists because `ciena_waveserver5` is 156 of the 185 examined occurrences and joins **zero** of them: summed away, a normalisation bug that de-joined ciena would be indistinguishable from ciena genuinely serving none of its trap OIDs, so that zero is asserted deliberately.
A per-arc reading of the same two Juniper OIDs remains. This guard is the corpus-wide policy.

`trapPrependedJoinedPairs` covers the three varbinds the **encoder** prepends rather than the catalog declaring — `sysUpTime.0`, `snmpTrapOID.0` and, when an entry sets it, `snmpTrapEnterprise.0` — with their tags taken from `encodeVarbindTimeTicks` / `encodeVarbindOID`.
**It finds nothing today and is not expected to**: 24 profiles serve a static `sysUpTime.0`, `oidTypeTable` types `1.3.6.1.2.1.1.3` `TIMETICKS` and the encoder prepends `TIMETICKS`, so the two agree by construction, and no profile serves anything under `1.3.6.1.6.3.1.1.4`.
That is coverage of a surface the catalog does not control, not a near-miss.

**What it cannot see, and it should not be read as broader than it is:**

- **It does not compare either side against a MIB.** Whether nl6 agrees with the *vendor* is the arc audits' question. This asks only whether nl6 contradicts *itself*. `jnxFruFailed` is the worked example: it declares `{ jnxFruEntry 9 }` — `jnxFruTemp`, `SYNTAX Gauge32` — as `timeticks`. That is a catalog-versus-MIB disagreement, no profile serves that OID, so the join can never reach it. It is recorded under [The trap catalog, and the cross-surface check](#the-trap-catalog-and-the-cross-surface-check).
- **It joins against static resource data only.** An OID served analytically has no `snmp` entry at all, so a varbind naming one lands in the unserved bucket. One that has *both* a resource entry and a dynamic answer is reported as shadowed rather than compared. Today the first case is moot: every varbind naming an `ifTable` column is templated on `{{.IfIndex}}`.
- **A templated OID is not joinable at all.** The six `_common` link-trap varbinds name `…2.2.1.7.{{.IfIndex}}`. The OID exists only at fire time. They are counted in their own bucket rather than swept into "unserved", because a template appearing where a literal used to be is a change worth seeing. They are not entirely unchecked, though: the catalog self-consistency rule below reads them, because it needs no resource data.

### Two widenings that need no new data source

Two rules cover it in the same file.
Neither found a defect.
Both increase what is comparable without reading anything new.

**A typed leaf is comparable without a served value.**
`oidTypeTable` types the *leaf*, so for any OID in it the poll-side tag is knowable with no resource entry at all: `encodeTypedValue` dispatches on `snmpTypeTag(oid)`, and the typed-class rule refuses at load any value that would not encode at that tag.
Such a varbind is therefore compared rather than left in the unserved bucket.
The comparison changes shape and the two kinds stay distinguishable in the output: the original rule is *declared type versus the tag the served value emits*, this one is *declared type versus the tag the leaf's declared type emits*, which is a step closer to a MIB check while still being entirely inside nl6.

`trapPollTypedUnservedVarbinds` is **0**, and zero is the expected value.
`oidTypeTable` types standard mib-2 leaves while trap varbinds name vendor notification objects, so the two sets do not currently intersect.
This is a tripwire for a future catalog that declares `octet-string` on an `ifHC*` column, not a rule that found something.
A test asserting zero cannot fail on its own, so what makes it able to fail at all is the control's arm for it.

**A catalog must not contradict itself.**
Two varbinds of one **effective** catalog naming the same OID at different declared types are the same one-object-two-types defect, and the join above cannot see it unless the OID also happens to be served.
The self-consistency rule needs no resource data, which is why it reaches two surfaces nothing else did.
`ciena_waveserver5` is 156 of the 185 examined occurrences and joins **zero**, so its catalog had no internal check of any kind. Its four entries share one trap OID by design, one notification differing only in severity and which condition flag is set, which makes a same-OID-different-type slip both plausible and previously undetectable.
And the universal catalog's entire comparison surface is templated, so the join can never reach any of it.

Three properties are load-bearing:

- **The effective catalog, not the overlay file.** `MergeOverlay` replaces a same-named entry wholesale, and an overlay entry that contradicts a *universal* varbind sits in an overlay file that is internally consistent on its own. The control's third arm plants exactly that, so a rule that read the overlay file passes every other arm and reports nothing here while the device fires both types.
- **Per distinct effective catalog, not per profile.** 26 profiles carry the universal catalog unchanged, so a defect in it is one fact. Reporting it 26 times would bury the three overlay catalogs' findings underneath it.
- **The tag comes from the declared type, through the probe.** What a trap varbind puts in the value slot is a function of its declared type alone, so resolving through the type keeps the rule answering the question it asks. Resolving through the varbind's own value would make an unencodable literal or a templated value into an encoder failure here, which is the join's finding to report and not this one's, and would leave the rule unable to see the universal catalog at all.

`trapCatalogSelfCensus` pins `{entries, distinct varbind OIDs, OIDs carried by more than one varbind}` per effective catalog:

| Effective catalog | Entries | Distinct OIDs | Carried by >1 varbind |
|---|---|---|---|
| the universal one, as 26 profiles carry it | 5 | 3 | 3 |
| `resources/ciena_waveserver5/traps.json` | 9 | 42 | 42 |
| `resources/cisco_ios/traps.json` | 12 | 17 | 3 |
| `resources/juniper_mx240/traps.json` | 12 | 16 | 5 |

The third column is the only one the rule uses.
An OID carried by a single varbind cannot disagree with itself, so that column alone says how much of each catalog is actually under comparison.
A change that collapsed the grouping would drive it to zero while every finding count stayed at zero too, and the guard would be silently worthless.
That is the failure the census exists to make visible.

Neither widening changes what the guard can say about a **MIB**.
`jnxFruFailed` declaring a `Gauge32` object as `timeticks` stays out of reach of both, because no profile serves that OID and the disagreement is with the vendor rather than within nl6.

## Semantic faithfulness

The three load rules answer "will nl6 put a mistyped BER value on the wire", never "is this profile faithful to the MIB".
The Palo Alto audit is the worked example, and it is worth reading as a calibration of how much the guards prove.

Of the 11 Palo Alto enterprise OIDs `palo_alto_pa3220` served, 3 were correct, 5 answered a value of the wrong *kind*, and 3 were not valid OIDs at all. The whole table passed rules 1 to 3.
A collector with a PAN-COMMON-MIB rule keyed on `panMgmtPanoramaConnected` got `4194304` where a real PA-3220 answers `connected`; one keyed on `panChassisType` got `127`.
The rule appears to work and validates nothing, which is the failure mode a simulator has to avoid above all others.

| OID | was | now | object |
|---|---|---|---|
| `…2.1.2.1.6.0` | `55` | `5.2.10` | `panSysVpnClientVersion`, a DisplayString version (`0.0.0` if not installed) |
| `…2.1.2.1.17.0` | `PA3220-001` | `790286-4437636` | `panSysWildfireVersion`, a content version — the old value was a hostname |
| `…2.1.2.2.1.0` | `127` | `PA-3220` | `panChassisType`, a DisplayString |
| `…2.1.2.4.1.0` | `4194304` | `connected` | `panMgmtPanoramaConnected` |
| `…2.1.2.4.2.0` | `DDR4` | `not-connected` | `panMgmtPanorama2Connected` — one Panorama is the ordinary case, and nothing else in the profile models a second |
| `…2.1.2.4.1.3` | `1` | *deleted* | nothing — under a leaf scalar |
| `…2.1.2.4.1.3.1` | `1` | *deleted* | nothing — under a leaf scalar |
| `…2.1.2.5.1.0` | `500` | *deleted* | `panGPGatewayUtilization` is an OBJECT-IDENTITY container, not a leaf |

`panCommonObjs 4` is `panMgmt` and holds exactly two `DisplayString` scalars, so the "management-plane memory" subtree the old data modelled (a byte size at `.4.1.0`, `DDR4` at `.4.2.0`, rows under `.4.1.3`) does not exist at all.
The units question that triggered the audit — 4 GiB versus 4 MiB at `.4.1.0` — is moot: the object is a string, and both numbers were equally wrong.

The three real children of `panGPGatewayUtilization` were **not** added in place of `.5.1.0`.
Their names are known (`panGPGWUtilizationPct`, `…MaxTunnels`, `…ActiveTunnels`) but their sub-identifiers were not resolved out of the MIB in that change, and inventing them is exactly the guessing the fix exists to undo.

**Twelve profiles that are not Palo Alto devices were serving this subtree too**, and that is a second defect the per-profile audit could not see: `panChassisType` = `127` and `panSessionUtilization` = `2500` (whose DESCRIPTION bounds it to 0..100) shipped on `arista_7280r3`, four Cisco profiles, `dell_poweredge_r750`, `fortinet_fortigate_600e`, `hpe_proliant_dl380`, `huawei_ne8000`, two Juniper profiles and `nokia_7750_sr12`.
Those 24 entries are **deleted, not corrected**: an Arista should not answer a Palo Alto enterprise OID at all, and a collector keyed on PAN-COMMON-MIB would read such a device as a firewall.
A vendor enterprise subtree is an identity claim, not an approximation.

The pinned Palo Alto reading pins the eight surviving values and the three absences. A corpus-wide guard is the corpus-wide half, since the first test builds one device from one profile and 24 foreign entries were invisible to it.
Both are a record of a reading, not a verification: nothing in CI compares nl6 against PAN-COMMON-MIB.
**Only this profile was audited.** The other 28 carried vendor enterprise subtrees with no equivalent review, and this profile's hit rate — 8 of 11 wrong — is the reason that was treated as outstanding work rather than an assumption. Four more arcs have been audited since, and the fourteen that remain are labelled rather than assumed correct.

The NVIDIA PEN re-homing closed one more instance of the class and not the class itself.
The three `nvidia_*` profiles served GPU telemetry under `1.3.6.1.4.1.53246`, which IANA allocates to Mailteck, S.A.. The arc was re-homed to NVIDIA's real PEN `1.3.6.1.4.1.5703` with every sub-identifier preserved, and a guard keeps that one arc clean in both the OID-name and the OID-typed-value positions.
The general per-profile own-vendor-enterprise-OID guard was deliberately not built there: it needs an allowlist decision, and it would have failed against the corpus as it stood.

### Every profile serves its own vendor's PEN and no other

The own-vendor PEN guard closed the class.
The own-vendor PEN guard walks every shipped profile and requires each enterprise OID it serves — in an OID **name** or an OID-typed **value** — to sit under the one IANA private enterprise number that profile's device type belongs to.

It covers **three** surfaces, each with its own test and its own positive control, all running one rule over one curated map:

| surface | what it is | test |
|---|---|---|
| resource files | the `snmp` arrays of every shipped profile | The own-vendor PEN guard |
| `vendorOIDs` | dynamic metric OIDs served from Go code, answered by `getMetricValue` and enumerated into walks by `GetSortedMetricOIDs` | a guard |
| `createDefaultResources` | the compiled-in fallback a device gets when its named resource file is absent | a guard |

The second and third surfaces each held a live defect, which is why they are covered rather than excluded.

`vendorOIDs` served `sonicwall_nsa6700` four OIDs under `1.3.6.1.4.1.8714` — **iNOC, Inc.** — where SonicWALL is **8741**.
A digit transposition, and no test in the package had ever read that map.
It was live: `findResponse(".1.3.6.1.4.1.8714.2.1.3.1.1.0")` answered a real CPU reading, all four were enumerated into every walk of that device type, and the profile's own resource files used 8741 throughout. So one simulated device served two vendors' arcs at once.
Fixed to 8741 with every sub-identifier preserved.
It moves no golden digest, because `collectShippedOIDs` walks resource files and these OIDs live in Go code. That is itself the reason this surface needed a guard of its own.

`createDefaultResources` answered `sysObjectID.0` with `1.3.6.1.4.1.9.1.1`, ciscoSystems.
That is a production path — any device whose resource file is missing lands on it — so an unprofiled device identified itself as Cisco hardware.
It now answers the documentation PEN, for the same reason `aws_s3_storage` does.
`sysDescr` still reads "Cisco IOS Software": that is a DisplayString a human reads, not an identity a collector keys rules on, and changing it is a separate behaviour change.

The data fix in the resource files was one row.
`aws_s3_storage` answered `sysObjectID.0` with `1.3.6.1.4.1.9999`, which the registry allocates to **Zerna, Koepper & Partner**, a German engineering firm with no connection to Amazon or to storage. The same shape of defect as 53246/Mailteck, and the last foreign arc in the corpus.
It now answers `1.3.6.1.4.1.32473.1.1`, RFC 5612's *Example Enterprise Number for Documentation Use*, which IANA holds itself.
That was chosen over Amazon's real numbers (4843 `Amazon.com Inc.`, 60099 `Amazon Web Services Inc`) deliberately: "AWS S3 Compatible Object Storage Gateway" names a **category** that MinIO, Ceph RGW and others implement, not a manufacturer, and AWS's own S3 is an HTTP service with no SNMP surface.
Naming Amazon would trade one misattribution for a more plausible one.
The cost is real and accepted — vendor detection now resolves this profile to nobody — and `32473` is allowed for **this profile only**, never generally, or a future profile could dodge the guard by claiming to be documentation.

Four properties of the guard are load-bearing, and each is a defect this repo has already shipped:

- **It reads OID-typed values, not just names.** `sysObjectID.0` is a *response*, and it is the field a collector reads for vendor detection. A name-only scan is structurally blind to it. That blind spot hid this very defect from the research census, and from that census's own first-cut guard. There is one scan of the two positions in the package and both guards go through it.
- **Its positive control plants across profiles.** A Juniper OID name in `cisco_ios`, an NVIDIA `sysObjectID` value in `linux_server`, a Huawei OID name in `ibm_power_s922`. A control that plants and detects inside one profile survives a narrowing of the scan, which is the regression the bare-column audit's review demonstrated with a green suite.
- **The slug-to-PEN map is curated, never derived from name matching.** Six shipped pairs share no word with their slug and are all correct: `hpe_proliant_dl380` → 232 (Compaq), `dell_emc_unity` → 1139 (EMC Corp), `nokia_7750_sr12` → 6527 (Nokia, formerly Alcatel-Lucent), `netapp_ontap` → 789 (Network Appliance Corporation), `arista_7280r3` → 30065 (formerly Arastra), `ibm_power_s922` → 2 (IBM). Every number is looked up in a checked-in extract of the IANA registry, and every row carries a written reason.
- **The PEN is matched on a sub-identifier boundary.** PEN 2 is a string prefix of 2011 (Huawei), 2620 (Check Point), 2636 (Juniper) and 25461 (Palo Alto), and all five ship, so a `HasPrefix` match reports four vendors as IBM.

What the guard does **not** cover, and what remains outstanding:

- **In the value position it sees `sysObjectID` and nothing else.** The gate is the production predicate `snmpTypeTag(oid) == ASN1_OBJECT_ID`, and `oidTypeTable` carries exactly one such row. `entPhysicalVendorType` (`1.3.6.1.2.1.47.1.1.1.1.3.x`) is an OBJECT IDENTIFIER in RFC 4133 and ships with enterprise-arc responses in six profiles, and the main guard reads every one of them as an OCTET STRING and skips it. Reusing the production predicate is deliberate. Nl6 encodes an untyped dotted response as an OCTET STRING, so it never reaches the wire as an OID, and judging values by string shape would report entries no collector can read as an identity. Widening it means adding a row to `oidTypeTable`, which is a wire change. `assertEntPhysicalVendorTypeIsNotCrossVendor` closes the question separately: none of the 224 enterprise-rooted values is cross-vendor today.
- **208 of those `entPhysicalVendorType` responses answer the synthetic `1.3.6.1.4.1.0.0`** (in `cisco_catalyst_9500`, `cisco_nexus_9500`, `juniper_mx960` and `palo_alto_pa3220`). PEN 0 is `Reserved` in the registry, held by IANA. So this is not a misattribution the way 9999 and 8714 were, but it is not a vendor type either: a collector reading it resolves nothing. The count is pinned as a known quantity, not endorsed. Eight further entries answer a bare `1`, which is not a valid OID for that object at all.
- Whether the objects *below* a correct PEN mean what the vendor's MIB says they mean, and whether they are readable at all. Five arcs have been audited against a vendor MIB and every one but Ciena was mostly or entirely wrong — see [Semantic faithfulness](#semantic-faithfulness) for the miss rates and the per-arc sections. The remaining fourteen were closed by decision rather than by audit: each is labelled `UNAUDITED-ARC(<pen>)` in the parts that carry it, and a guard fails by name on any arc that is neither audited, labelled nor explicitly excluded, so a new device type cannot regrow the problem quietly. All three `nvidia_*` profiles pass every guard while every object under `5703` is nl6's own invention. Access mode is a third question no guard asks — see [Access modes are not modelled](#access-modes-are-not-modelled).
- **An OID-typed *value* under a correct PEN that resolves to no assignment.** A subclass the Arista audit surfaced, and the one the guards are structurally blind to: `sysObjectID.0` answered `1.3.6.1.4.1.30065.1.3011.7280.3282.32.4`, which is well formed, under the profile's *own* vendor arc, and names no Arista product. The PEN guards check which vendor an OID belongs to, never whether the vendor assigned it. Rule 2 checks that an OID-typed value is *encodable*, never that it *resolves*. That instance is fixed; the class needs a MIB per arc, exactly as the semantic question does. `entPhysicalVendorType.1` on the same profile still answers an unresolvable `aristaProducts 3082` and is recorded rather than corrected, because it belongs with an ENTITY-MIB sweep. See [The Arista arc audited against its MIBs](#the-arista-arc-audited-against-its-mibs).
- A *missing* arc. Nothing requires a profile to identify itself, only to identify itself truthfully. The closest thing is a per-profile census requiring one OID-typed value under the profile's own PEN.
- The trap catalogs' `snmpTrapEnterprise` values, gNMI and the REST surface. The catalogs were audited by hand for the own-vendor PEN guard and are clean. Scanning them was considered and deliberately not added.
- **Agreement between a trap catalog and the resource data for the same OID.** Found by hand on `cisco_ios`, which fired `ciscoEnvMonSupplyStatusDescr.1` as an `octet-string` while its resource row answered INTEGER `1`. This class is now **closed** by a corpus-wide guard. See [A trap and a poll must agree on type](#a-trap-and-a-poll-must-agree-on-type).

### The Cisco arc audited against its MIBs

The arc programme is the first audit of the class the two guards above cannot see, and it took the Cisco arc because it is the largest (39 shipped entries across five profiles) and the only one whose MIBs are obtainable anonymously from the vendor's own repository, `github.com/cisco/cisco-mibs`.

**The arithmetic is given in two views, because mixing them is how this audit first got it wrong.**
A first cut quoted "3 of 13" while counting `ciscoEnvMonFanStatusDescr.1` twice: once as a deleted OID (it was deleted from `cisco_catalyst_9500`) and once as a kept entry (it survives in three other profiles).
A census guard recomputes both views from the corpus and the ledger, so the numbers below are checkable rather than asserted.

- **Distinct OIDs.** The parent revision shipped 21 distinct Cisco OID keys. 13 sit under `ciscoMgmt` and were audited; 8 sit on the OLD-CISCO arcs and were not. Of the 13, **2 were right as shipped and 11 were wrong** (5 corrected, 6 deleted; `ciscoEnvMonFanStatusDescr.1` counts once, under corrected). Against the Palo Alto audit's 8 of 11 on the Palo Alto subtree that is like for like, both counting distinct OIDs on audited arcs.
- **Entries.** 39 entries name a Cisco OID and 23 of them sit on the 13 audited OIDs: **8 deleted, 10 corrected, 5 left exactly as shipped** (the four `ciscoImageString` rows and the one `cseSysCPUUtilization` row).

| OID | was | now | object, and why |
|---|---|---|---|
| `…9.9.13.1.3.1.2.1` | `Catalyst 9500 Switch` | `Chassis Inlet Temp Sensor` | `ciscoEnvMonTemperatureStatusDescr`, `DisplayString (SIZE (0..32))`. It describes the sensor, not the chassis |
| `…9.9.48.1.1.1.2.1` | `1100` | `Processor` | `ciscoMemoryPoolName`, `DisplayString`. The INDEX is `ciscoMemoryPoolType`: 1 is processor memory |
| `…9.9.48.1.1.1.2.2` | `1100` | `I/O` | same object, index 2 is i/o memory. The old value was a PSU wattage |
| `…9.9.13.1.4.1.2.1` | `1` (×3 profiles) | `Fan 1` | `ciscoEnvMonFanStatusDescr`, `DisplayString (SIZE (0..32))`. A bare `1` encodes as an INTEGER |
| `…9.9.13.1.5.1.2.1` | `1` (×4 profiles) | `Power Supply 1` | `ciscoEnvMonSupplyStatusDescr`, same type, same defect |
| `…9.9.13.1.4.1.2.1` | `C9300-SUP-1` | *deleted* | `ciscoEnvMonFanStatusDescr` in `cisco_catalyst_9500`. A supervisor part number is not a fan |
| `…9.9.13.1.4.1.2.2` | `C9300-48T` | *deleted* | same object. A line card is not a fan |
| `…9.9.13.1.4.1.3.1` | `Supervisor Module` | *deleted* | `ciscoEnvMonFanState`, SYNTAX `CiscoEnvMonState`, an INTEGER enum (`normal(1)`, `warning(2)`, …). A DisplayString here is a type error |
| `…9.9.13.1.4.1.3.2` | `48-Port Gigabit Line Card` | *deleted* | same object |
| `…9.9.48.1.1.1.3.1` | `PWR-C1-1100WAC` | *deleted* | `ciscoMemoryPoolAlternate`, SYNTAX `Integer32 (0..65535)`. A part number on an integer leaf |
| `…9.9.48.1.1.1.3.2` | `PWR-C1-1100WAC` | *deleted* | same object |
| `…9.9.13.1.3.1.3.1` | `CAT9500-001`, `39` | *deleted* | `ciscoEnvMonTemperatureStatusValue`, `Gauge32`, degrees Celsius. See the walk note below |

Every deletion is in `cisco_catalyst_9500` except the second `…13.1.3.1.3.1` row, which is `cisco_nexus_9500`.

**Nine of the ten corrections move the emitted tag, and all nine are one defect: a bare number on a `DisplayString` leaf.**
`encodeTypedValue` emits `1100` and `1` as tag `0x02` INTEGER, so those rows put an INTEGER on a leaf the MIB declares a `DisplayString`.
The seven `1` rows are not legal DisplayStrings, and the reason that is easy to miss is instructive: judging a value by whether it *looks like* a description passes a bare `1`, and the one row in the pinned reading with no tag assertion was exactly the row that carried it.
Every case in that test now asserts the tag.

**The supply correction is settled by evidence inside the profile. The fan correction is not, and the difference is recorded rather than smoothed over.**
`resources/cisco_ios/traps.json` fires `ciscoEnvMonSupplyStatusChangeNotif` carrying `1.3.6.1.4.1.9.9.13.1.5.1.2.1` as an `octet-string` valued `PWR-{{.Serial}}`, with `…13.1.5.1.3.1` as an `integer` beside it.
So one profile modelled one OID as two types, depending on whether you polled it or received its trap.
Deleting the static row would have left a device sending a trap that names an object it refuses to answer when polled, which is worse than either state. Correcting it is what makes poll and trap agree.
No trap references any fan object, so nothing independent says what `ciscoEnvMonFanStatusDescr` should hold: that correction rests on consistency alone, two sibling columns of the same MIB family both declared `DisplayString` and both valued `1`, where a split would need a principle and there is none.

The replacements are generic positional descriptions on purpose, since inventing a part number would be the Palo Alto audit's defect in the other direction.
The trap's own `PWR-{{.Serial}}` is that profile's convention for the same object, and a positional description agrees with it in *type* without copying a templated serial into static data.

**Both tables ship a description column and no state column, and that is recorded rather than fixed.**
After this change no profile serves `ciscoEnvMonFanState` (`…13.1.4.1.3.x`), `ciscoEnvMonSupplyState` (`…13.1.5.1.3.x`) or `ciscoEnvMonTemperatureState` (`…13.1.3.1.6.x`), so a collector can discover that a fan or a supply exists and never read its health.
That is a real gap, lesser than the wire-type error, and it must not be closed by inventing state values: The pinned Cisco reading asserts those three columns as absences so completing the tables has to argue with a reading.
The trap catalog fires two of the three.

**Deleting the four fan rows empties that table**, exactly as the bare-column audit's `hrStorageTable` deletions did for four profiles, and for the same reason.
A collector that gets nothing learns the truth about a profile that models no fans. A collector that gets `C9300-SUP-1` from `ciscoEnvMonFanStatusDescr` is told a supervisor module is a fan.
Do not restore a row to make the table non-empty.

**The two `ciscoEnvMonTemperatureStatusValue` rows were reachable, and the walk is the path this change moved.**
An earlier version of this section called them dead data and unreachable. That was drawn from the GET path alone and it was wrong.
`vendorOIDs` maps the OID to `MetricTemperature` for all five Cisco profiles and `findResponse` consults `getMetricValue` before the static `oidIndex`, so a **GET** was already answered by the cycler and did not change.
A **walk** is a different path: `findNextOIDWithServed` collects candidates and takes the lexicographically smallest with a strict less-than, so when a static row and a metric OID are the same OID the first candidate wins, and the static one is appended first from `precomputedNextOID`.
Measured on a device with a live cycler at the parent revision, `findNextOID` from `…13.1.3.1.2.1` returned `…13.1.3.1.3.1 = "CAT9500-001"` on `cisco_catalyst_9500` and `"39"` on `cisco_nexus_9500`, while `findResponse` on the same devices returned `30` and `31`.
So a GETNEXT or GETBULK across that table returned a chassis name, as an OCTET STRING, on a `Gauge32` leaf.
The deletion is still right, because the static values were wrong on any path, but what it changed is the walk.
A guard now drives `findNextOIDWithServed` and requires a numeric, INTEGER-tagged answer. Before that, nothing in the package walked a Cisco profile at all, so a change to `GetSortedMetricOIDs`' ordering could drop the column from every Cisco walk with only the NVIDIA arc's walk test firing.

**`ciscoEnvMonTemperatureStatusValue` is `STATUS deprecated`** in the revision consulted, superseded by `ciscoEnvMonTemperatureStatusValueRev1` (`ciscoEnvMonTemperatureStatusEntry 7`, `Integer32`, which also carries negative temperatures).
That does not change the deletion, but a collector written against the current MIB polls `…13.1.3.1.7.x`, which nl6 answers with `noSuchObject` because no profile serves it.

**Two OIDs were correct and were left alone**: `ciscoImageString` (a `DisplayString` holding an image-characteristic string, so a version is the right kind of value, with a one-sub-identifier INDEX that `…1.2.2` satisfies) and `cseSysCPUUtilization` (`Gauge32 (0..100)`, answering 28).

**Eight Cisco OIDs are unaudited, and the reason differs per OID.**
An earlier version of this section attributed all eight to `OLD-CISCO-CHASSIS-MIB` being unobtainable, which was wrong: that module is genuinely unobtainable, but it does not define four of them.

| OID | status |
|---|---|
| `…9.3.6.3.0`, `…9.3.6.1.1.4.1.2.1`, `…9.5.1.2.2.1.0`, `…9.5.1.3.1.1.5.1` | genuinely unresolvable here — OLD-CISCO-CHASSIS-MIB was not obtainable |
| `…9.2.1.56.0`, `…9.2.1.58.0` | resolvable and not audited: `busyPer` and `avgBusy5` in OLD-CISCO-CPU-MIB, which *was* obtained. Both ship plausible percentages; neither was checked further |
| `…9.2.1.54.0` | resolvable, and it was a live defect: `writeMem` in OLD-CISCO-SYSTEM-MIB, `ACCESS write-only`, an action object that saves the running configuration. nl6 answered it with a large number. Filed as the access-mode audit and **closed there** — see [Access modes are not modelled](#access-modes-are-not-modelled) |
| `…9.2.1.8.0` | not defined in the OLD-CISCO-SYSTEM-MIB copy obtained (a v2 conversion that drops the deprecated memory objects) |

**No MIB file or extracted fixture is checked in, and that is a decision.**
The checked-in MIB fixtures are IETF standards-track modules. A vendor MIB is a different legal object.
The obtainability research found no published redistribution grant for any of nineteen vendors (Cisco's own header asserts copyright and grants nothing), and LibreNMS, which has shipped vendor MIBs for years, classifies its own MIB tree as a GPL-non-compliant component rather than claiming the right.
So each audit is recorded as a **pinned reading** citing the module and revision consulted, never as a live check.
The asymmetry is the point: if the licensing question later resolves permissively a fixture can be added, and if it resolves restrictively nothing has to be removed.

The modules read for this audit were CISCO-ENVMON-MIB `201803210000Z`, CISCO-MEMORY-POOL-MIB `201309180000Z`, CISCO-IMAGE-MIB `9508150000Z` and CISCO-SYSTEM-EXT-MIB `201606140000Z`, with `ciscoMgmt = 1.3.6.1.4.1.9.9` resolved out of CISCO-SMI.
The pinned Cisco reading pins the surviving values and the deletions as absences.
Like the Palo Alto test it is a record of a reading: nothing in CI compares nl6 against a Cisco MIB, and the claim it supports is "this profile matches those revisions of those modules", never "this profile is correct".

One of those eight has since been resolved: the access-mode audit read `…9.2.1.54.0` and deleted it, leaving seven unaudited on the OLD-CISCO arcs.

### The Arista arc audited against its MIBs

The second arc audited, and **the worst result of the three audited so far: 6 enterprise-arc facts checked, 6 of 6 wrong.**

The count is 6 because that is what there was to check: the 5 OIDs `arista_7280r3` served under `1.3.6.1.4.1.30065` plus the `sysObjectID.0` value, which points into that arc without being an OID *name* in it.
All five OIDs are deleted and the `sysObjectID` value is corrected, so **6 of 6 were wrong**.
This document quotes every audit as a *miss* rate for exactly this reason: mixing "3 correct" with "8 wrong" about the same eleven OIDs is the miscount the Cisco section already had to correct once.
Against the Palo Alto audit's 8 of 11 wrong on Palo Alto and the arc programme's 11 of 13 on Cisco, the trend is the finding: **all three arcs were audited only because someone read a MIB, and all three were mostly or entirely wrong.**
A vacuity guard derives both the numerator and the denominator from the ledger, so this arithmetic is checkable rather than asserted.

The arc, resolved out of ARISTA-SMI-MIB rather than assumed:

| node | OID | what it is |
|---|---|---|
| `arista` | `1.3.6.1.4.1.30065` | assigned by IANA |
| `aristaProducts` | `…30065.1` | "the root object identifier from which **sysObjectID values** are assigned" — and nothing else |
| `aristaMibs` | `…30065.3` | the root for management MIBs |
| `aristaSwIpForwardingMIB` | `…30065.3.1` | `{ aristaMibs 1 }` |
| `aristaSwFwdIp` | `…30065.3.1.1` | its only child is `aristaSwFwdIpStatsTable` at `.1` |

`ARISTA-ENTITY-SENSOR-MIB` sits at `{ aristaMibs 12 }` and `ARISTA-GENERAL-MIB` at `{ aristaMibs 24 }`, so nothing else in the modules read claims `30065.3.1`.

| OID | was | now | object, and why |
|---|---|---|---|
| `…30065.1.3.1.1.0` | `4.29.2F` | *deleted* | nothing. `aristaProducts` holds sysObjectID values only, and no ARISTA-PRODUCTS-MIB assignment has `3` as its first sub-identifier |
| `…30065.3.1.1.1.0` | `AR-7280R3-001` | *deleted* | `aristaSwFwdIpStatsTable` with a bogus `.0`. A table object is `MAX-ACCESS not-accessible`, and a hostname is not an IP-forwarding statistic |
| `…30065.3.1.1.2.0` | `31` | *deleted* | nothing — `aristaSwFwdIp.2` is not defined |
| `…30065.3.1.1.3.0` | `48` | *deleted* | nothing — `aristaSwFwdIp.3` is not defined |
| `…30065.3.1.1.13.0` | `38` | *deleted* | nothing — `aristaSwFwdIp.13` is not defined |
| `1.3.6.1.2.1.1.2.0` | `…30065.1.3011.7280.3282.32.4` | `…30065.1.3011.7280.2727.3.32.2129.4.972` | `sysObjectID`. The old value is shaped like a product OID and is not one |

**Deletion, not correction, for all five.**
Four of them name objects that do not exist and the fifth names one that cannot be read, so there is no correct value to supply.
Inventing one for an object the MIB does not define is the Palo Alto audit's defect with the guessing turned up.
That leaves `arista_7280r3` serving **no object at all** under its own vendor's arc, and the pinned Arista reading asserts it as a **walk** from the PEN root rather than as five named absences, so a sixth invented Arista object fails instead of arriving unguarded.

That walk needs a positive control, and finding out why is worth recording.
OIDs sort as strings, so `1.3.6.1.4.1.30065` sorts *above* every mib-2 OID the profile serves. Once the five Arista rows are gone the arc root has **no successor at all**, and `findNextOIDWithServed` answers with an empty string.
A check written as "the successor is not under the arc" is therefore satisfied by the empty answer *and* by a walk that aborted, which is a guard that cannot fail.
Requiring a non-empty successor instead — the obvious fix — fails on a healthy tree, because the empty answer is the correct verdict here.
So the vacuity is closed the way this repo closes it everywhere else: a positive control plants an object at `…30065.3.1.1.99.0` and requires the walk to reach it, which is what makes the empty answer mean "the arc is empty" rather than "this assertion sees nothing".

**What was actually observed about `aristaProducts`, stated as observed.**
Every one of ARISTA-PRODUCTS-MIB's 373 assignments names a subtree rooted at `aristaProducts` whose *first* sub-identifier is one of sixteen values — 138, 447, 1082, 1362, 1470, 1788, 2546, 2682, 2759, 3011, 3413, 3806, 7289, 7358, 7368, 7388 — and `3` is not among them.
The assignments themselves run several sub-identifiers deep. The correction below is eight deep.
The observation is about the *first* sub-identifier, which is what settles whether `30065.1.3` is a node at all.

**The `sysObjectID` value is the one a collector actually reads.**
`1.3.6.1.4.1.30065.1.3011.7280.3282.32.4` is well formed, under the right PEN and under the right sysObjectID root. No assignment in ARISTA-PRODUCTS-MIB `202603030000Z` uses `3011 7280 3282`.
The module mentions `3011 7280` on 109 lines and the third sub-identifier observed there is one of 312, 877, 1347, 1359, 1964, 2655, 2727, 2899, 2972, 3101, 3232, 3714, 3735 or 3977, never 3282.
`3282` *is* a real Arista sub-identifier — it appears under 7124, 7148, 7050 and, at a different depth, under `7280 2727 3 1810 32 2129 4` — which is exactly why the invented OID looks right.
It now answers `aristaDCS7280CR332P4M`, assigned as `{ aristaProducts 3011 7280 2727 3 32 2129 4 972 }`.

**The product's name is `DCS-7280CR3-32P4-M`.**
`aristaDCS7280CR332P4M` is the ASN.1 *identifier*, which strips punctuation from every product name in that module.
The name is in the comment immediately above the assignment — `-- DCS-7280CR3-32P4-M 32x100GbE (QSFP100) & 4x400GbE (OSFP) Ethernet Switch with SSD` — and again in the module's own revision note ("Revised to include DCS-7280CR3-32P4-M and DCS-7280CR3-32D4-M").
Reading the identifier as the name is exactly the wrong-MIB-reading class this audit exists to eliminate, committed inside the change that exists to eliminate it.
The pinned Arista reading now requires the MIB's spelling and rejects the hyphenless one by name.

**The model-identity rule is profile-wide, not a `sysDescr` rule.**
`grep -c 7280R3 ARISTA-PRODUCTS-MIB` returns 0, so the profile was **already** split between two products that do not exist: `DCS-7280R3-32P4-M` in `sysDescr` and the SSH outputs, `DCS-7280R3-48C6` in the entity table.
(The real 48C6 products are `DCS-7280SR-48C6`, `DCS-7280TR-48C6`, `DCS-7280SRA-48C6` and `DCS-7280TRA-48C6` — SR / TR series, not R3.)
Correcting only `sysDescr` replaced a fake-versus-fake split with a real-versus-fake contradiction across surfaces, which is worse than either.

| where | object / command | was | now |
|---|---|---|---|
| `arista_7280r3_snmp_1.json` | `sysDescr.0` | `…DCS-7280R3-32P4-M` | `…DCS-7280CR3-32P4-M` |
| `arista_7280r3_snmp_6.json` | `entPhysicalDescr.1` | `Arista Networks DCS-7280R3-48C6` | `Arista Networks DCS-7280CR3-32P4-M` |
| `arista_7280r3_snmp_6.json` | `entPhysicalModelName.1` | `DCS-7280R3-48C6` | `DCS-7280CR3-32P4-M` |
| `arista_7280r3_snmp_6.json` | `entPhysicalModelName.2` | `7280R3-48C6` | `7280CR3-32P4-M` |
| `arista_7280r3_snmp_11.json` | `entPhysicalName.1` | `ARISTA-7280R3-CHASSIS-01` | `ARISTA-7280CR3-CHASSIS-01` |
| `arista_7280r3_ssh_1.json` | `show version` | `Arista DCS-7280R3-32P4-M`, serial `AR-7280R3-001` | `Arista DCS-7280CR3-32P4-M`, serial `AR-7280CR3-001` |
| `arista_7280r3_ssh_1.json` | `show running-config` | `(DCS-7280R3-32P4-M, …)` | `(DCS-7280CR3-32P4-M, …)` |

The SSH serial is the same string this audit deleted from `…30065.3.1.1.1.0` as a bogus answer, so renaming it keeps the profile from carrying, on a second surface, the exact value the audit removed from the first.
A model-identity guard scans every part of the profile — SNMP entries through the shared corpus walker, SSH responses read directly, since no walker gathers those — and requires no response to contain `7280R3`.
It carries a positive control and fails if it finds no SSH responses at all, because SSH output is covered by no golden digest and an absence test over an empty set proves nothing.

**One weak call, recorded rather than smoothed over.**
`entPhysicalModelName.2` is the model name of "Module 1", a modelled line card.
The other six rows name the *chassis*, which the `sysObjectID` settles. Nothing says a module has that model name, and `DCS-7280CR3-32P4-M` is a fixed-configuration switch with no pluggable line cards at all.
So the honest residual is that the profile models a module the product does not have. That is a fidelity question about the **entity table**, not about the Arista arc, and it is left open rather than closed by deleting rows this audit read no MIB about.
Same shape as the fan-versus-supply asymmetry in the Cisco section: the stronger call is settled by evidence, the weaker rests on consistency, and both are written down.

**The EOS version `4.29.2F` is deliberately untouched**, and the reading test asserts it so that changing it becomes a decision rather than a side effect of editing the model name in the same string.
It is plausible and it is not checkable against any Arista MIB — no module publishes a software-version registry — so editing it would be exactly the unbacked change this audit exists to undo.

**The `arista_7280r3` profile directory is not renamed.**
The slug is an nl6 identifier, not a claim about hardware, and renaming it would churn every corpus test for no fidelity gain.

**Fleet-visible surface change.**
Stated with counts, per the octet-shadow sweep's convention, because this changes what a collector sees on every `arista_7280r3` device in a running fleet:

- `sysObjectID.0` and `sysDescr.0` both change, so **vendor detection and asset inventory resolve the node differently**. `sysObjectID` was unresolvable and now resolves to a real Arista product. That is the point of the change, not a side effect.
- a walk of the profile returns **five fewer OIDs** and the five that left were the profile's only objects under its own vendor's arc.
- four ENTITY-MIB responses and two SSH command outputs change their model string. No OID is added or removed by those, and no tag moves.
- no other profile is touched: every edit is in `resources/arista_7280r3/`.

**One defect of the same class is recorded and not fixed.**
`entPhysicalVendorType.1` answers `1.3.6.1.4.1.30065.1.3082.7280.3714.3`, and `3082` is not among the sixteen first sub-identifiers either. The same unresolvable-product-OID defect, in the value slot of a different object.
It is a **subclass this audit newly surfaced**: an OID-typed value under a *correct* PEN that resolves to no assignment, which the census and the PEN guards pass by construction and no load rule can see.
It is left alone because it is an ENTITY-MIB question rather than an Arista-arc one: 224 shipped values sit in that column across the corpus, 208 of them the reserved-PEN placeholder, and correcting one profile's while the class goes unexamined would be arbitrary.
The pinned Arista reading asserts its current value as a **presence**, so a later fix has to edit that assertion deliberately.

**Provenance, since no MIB file is checked in.**
The five modules were fetched anonymously from `https://www.arista.com/assets/data/docs/MIBS/<NAME>.txt` on 2026-09-01 and are cited by LAST-UPDATED **and by the SHA-256 of the file read**. A revision string alone does not let a second reader confirm they read the same bytes, and ARISTA-PRODUCTS-MIB in particular gains products continuously.
This is the same provenance convention applied to a file that cannot be checked in: licensing blocks the bytes, not their digest.

| module | LAST-UPDATED | SHA-256 |
|---|---|---|
| ARISTA-SMI-MIB | `201408150000Z` | `3db704a6a977bbad3f5e54b23b5ab6b1a03ebcc7d5049d66c59648a0d71770c0` |
| ARISTA-PRODUCTS-MIB | `202603030000Z` | `f1dff8458987cc9d83327232f850c8e6a77a46c927944dcc06d1f5ce719be409` |
| ARISTA-SW-IP-FORWARDING-MIB | `201408150000Z` | `ba196b5d2e424cf030686b8d76529dd258fa9f69e5468571ec64a7aac80da607` |
| ARISTA-GENERAL-MIB | `201711060000Z` | `49d1f7803683053d01118d28fc54f59c7b7fa21f66dc45b4da943fb984ba55c3` |
| ARISTA-ENTITY-SENSOR-MIB | `202302100000Z` | `c879299d934dea06b4b31f72d815a1b4c2ba5e42fd9c35cabeef1117d0ed1236` |

All five carry a MODULE-IDENTITY, so unlike the access-mode audit's SMIv1 OLD-CISCO-SYSTEM-MIB there is a revision string to quote for each.
Arista's header asserts copyright and grants nothing, so the pinned Arista reading is a record of that reading, never a live check.

### The Ciena arc audited against its MIBs

The third arc audited, and **the first one that found nothing wrong: 1 enterprise-arc fact checked, 0 of 1 wrong.**

That is the headline, and the contrast with the other three is the finding rather than a footnote to it.

| arc | checked | wrong |
|---|---|---|
| Palo Alto | 11 | 8 |
| Cisco | 13 | 11 |
| Arista | 6 | 6 |
| **Ciena** | **1** | **0** |

**There is no data change here, no ledger and no registry entry.**
The deliverable is a pinned reading of the MIB, not a data change.
No golden digest moves and no resource file changes.

**The Ciena audit's own expectation was wrong, and correcting it is the point.**
The issue said "Set expectations from the base rate, not from hope: Palo Alto 8 of 11 wrong, Cisco 11 of 13, Arista 6 of 6. There is no reason to think this arc is better", and told the implementer to plan for deletions.
There *was* a reason, and it was visible before the audit started: this is the only one of the four arcs whose data somebody had already read a MIB for.
`resources/ciena_waveserver5/traps.json` carries a `comment` citing the module, its `LAST-UPDATED`, the non-contiguous severity enum and a self-contradiction inside the MIB.
Every one of those claims re-checks out.
So the conclusion worth writing down is not "the corpus is fabricated" but something narrower and more useful: **the parts someone read a MIB for are right, and the parts nobody did are mostly wrong.**

**The arc, resolved out of CIENA-WS-MIB rather than assumed.**
The module is 72 lines and defines no `OBJECT-TYPE` at all.
It is pure structure:

| node | OID | what it is |
|---|---|---|
| `ciena` | `1.3.6.1.4.1.1271` | the `MODULE-IDENTITY`, `{ enterprises 1271 }` |
| `waveserver` | `…1271.3` | "Root identifier for Ciena's Waveserver product." |
| `cienaWsConfigV1` | `…1271.3.1` | configuration for the Waveserver 1.0 / 1.1 releases |
| `cienaWsNotifications` | `…1271.3.2` | notifications |
| `cienaWsStatistics` | `…1271.3.3` | statistics, `STATUS obsolete` |
| `cienaWsConfig` | `…1271.3.4` | root object for the Waveserver API in 1.2 and beyond |
| `cienaWsPlatformConfig` | `…1271.3.5` | root object for the Waveserver **platform** API in 1.2 and beyond |

**Every child of `waveserver` is a functional area, and the module defines no model-specific product OID.**
There is no `waveserver5` node and no product registry.
Nothing anywhere in the module distinguishes a Waveserver 5 from a Waveserver Ai.
So `waveserver` itself is the most specific identifier available, and `sysObjectID.0 = 1.3.6.1.4.1.1271.3` is right rather than lazy.

**The near miss is the trap, and it is pinned by name.**
`waveserver 5` is `cienaWsPlatformConfig`.
It is not "Waveserver 5 the product".
The profile slug is `ciena_waveserver5` and the arc's fifth child is `5`, and those two facts have nothing to do with each other.
"Correcting" `sysObjectID` to `1.3.6.1.4.1.1271.3.5` to make it look more specific would point a collector's vendor detection at a *configuration subtree*.
That is the same shape of plausible-looking invention the Arista audit found in Arista's `sysObjectID`, where `1.3.6.1.4.1.30065.1.3011.7280.3282.32.4` was well formed, under the right PEN, under the right `sysObjectID` root, and not a product.
The pinned Ciena reading rejects `1271.3.5` by name and says what it is.

**One fact, because the dual-position scan says so.**
`ciena_waveserver5` serves 86 SNMP entries, **zero** OID names under `1.3.6.1.4.1.1271` and **one** OID-typed value.
Reading names only would have reported this arc as absent from the corpus entirely.
That is the blind spot that hid the AWS defect from a name-only scan.
It is also why the value-position guard gates the value position through `snmpTypeTag` rather than by string shape.
The empty *name* half is asserted as a walk from the PEN root with a positive control, for exactly the reason the Arista audit's is: end of MIB is an empty successor, so "the successor is not under the arc" is also satisfied by a walk that sees nothing.

**The trap catalog was audited too, and its reasoning is now pinned.**
the Ciena audit put this arc ahead of the other fifteen on consumer coupling: `1.3.6.1.4.1.1271` carries **165 references from the trap catalogs**, against Juniper's 31 and Cisco's 29, and every other unaudited arc has zero.
Every claim in `traps.json`'s `comment` was re-verified against CIENA-WS-NOTIFICATION-MIB `201611140000Z`:

- `wsLinkStateAlarmNotification` exists, at `{ cienaWsNotifications 12 }` = `1.3.6.1.4.1.1271.3.2.12`. (The module identity `cienaWsNotificationMIB` is `{ cienaWsNotifications 3 }`, a *sibling* of the notifications rather than their parent.)
- The severity enum is non-contiguous: `cleared(1) critical(3) major(4) minor(5) warning(6) info(8)`. 2 and 7 are not members, and renumbering to a contiguous 1..6 would look like cleanup while changing what every shipped optical trap tells a collector.
- **The MIB contradicts itself.** `wsLinkStateAlarmNotification`'s `OBJECTS` clause names `wsLinkStateAlarmNotificationEthEBer` and `…EthPcsLol`, neither of which is defined as an `OBJECT-TYPE`, while `…EthPcsHighBer` and `…EthPmaSool` *are* defined and appear in no `OBJECTS` clause. The catalog took the `OBJECT-TYPE` definitions as source of truth and recorded why.

That choice was the only one available, which the catalog's comment implies and the reading test now states: a name with no definition has no sub-identifier, so following the clause would have meant inventing two numbers.
The consequence is visible on the wire.
The Ethernet defect block is emitted in numeric order `.11.1` … `.11.8`.
Following the clause would have given 7, ?, 5, 6, 3, 2, ?, 4.

Two more transcription facts are pinned because they are the kind a tidy-up erases:

- **`.6` does not exist on this notification.** The definitions run `.1 .2 .3 .4 .5` and jump to `.7`. The `TableId` at `.6` belongs to `wsAlarmNotification`, the sibling notification at `{ cienaWsNotifications 11 }`. Borrowing it would put one notification's object into another's varbind list.
- **39 body varbinds**, one per object in the `OBJECTS` clause. That is 9 scalars + 4 Ptp + 8 Eth + 8 Otu + 10 Odu, derived from the reading's own tables rather than asserted, so editing a table moves the census.

The optical trap overlay guard (shipped with the profile) already pins the four entries' severities and condition flags. The reading test adds the structure those values sit in and does not restate them.

**The trap/poll join's class was checked explicitly and the answer is zero overlap.**
With 165 trap references against one profile's polled data, this is where a trap declaring a type that disagrees with what a GET answers is most likely.
`cisco_ios` demonstrably violated it, declaring `ciscoEnvMonSupplyStatusDescr` as `octet-string` in a trap while a GET answered INTEGER.
Here the polled entries are entirely mib-2 and every trap varbind is under `wsLinkStateAlarmNotification`, so there is no shared OID and nothing to disagree about.
A disjointness guard asserts the disjointness as a **measurement** and says, in its failure message, that the remedy for a future overlap is to compare the types rather than relax the assertion.

**What this audit did not close.**

- Semantic faithfulness of the profile's 85 mib-2 rows. The arc audits are scoped to enterprise arcs by construction.
- The optical values themselves. They come from `optical_cycler.go`, not from a resource file, and no Ciena MIB governs them. The served model is OpenConfig.
- Whether the mirrored modules are what Ciena ships. See the provenance note below.

**Provenance, since no MIB file is checked in.**
Both modules were fetched anonymously on 2026-09-01 and are cited by `LAST-UPDATED` and by the SHA-256 of the file read, per the Arista audit convention.

| module | LAST-UPDATED | SHA-256 | source |
|---|---|---|---|
| CIENA-WS-MIB | `201804270000Z` | `c7fe97de741c4334f23c4cf29644f604dd4bbedbac0bd51686c9ff2fa396ae78` | `raw.githubusercontent.com/librenms/librenms/master/mibs/ciena/CIENA-WS-MIB` |
| CIENA-WS-NOTIFICATION-MIB | `201611140000Z` | `821b50a6ebc7883e3ec3bbf9ababf9efb7e0970a0c774821c8acb38027a8af53` | `raw.githubusercontent.com/kcsinclair/mibs/master/CIENA-WS-NOTIFICATION-MIB.mib` |

**Both copies are third-party mirrors and their provenance is unestablished.**
Ciena serves its MIBs from the gated myCiena portal, which was not tested.
Neither mirrored file carries a copyright header at all.
`CIENA-WS-MIB` opens straight into `CIENA-WS-MIB DEFINITIONS ::= BEGIN`.
That may be how Ciena ships them, or a header may have been stripped in transit.
Nothing here can tell, so the reading is qualified by mirror as well as by revision.
The trap catalog's own comment names the same kcsinclair mirror, so this is a *re-reading* of the source that catalog was transcribed from, not an independent second source.

### The Juniper arc audited against its MIBs

The fourth arc audited, PEN `1.3.6.1.4.1.2636`, across `juniper_mx240` and `juniper_mx960`.

**The result, quoted in both units, because a per-OID rate and a per-entry rate answer different questions.**
The corpus served **13 distinct OID names** under 2636 plus **2 distinct OID-typed values** pointing into it, so 15 distinct facts.
By entry the same surface is **20 name-position entries plus 2 value-position ones**, so 22.

| arc | distinct facts checked | wrong |
|---|---|---|
| Palo Alto | 11 | 8 |
| Cisco | 13 | 11 |
| Arista | 6 | 6 |
| Ciena | 1 | 0 |
| **Juniper** | **15** | **13** |

By entry: **19 of 22 wrong**.
A measurement guard computes both denominators from the corpus by reversing the ledger, so the rate is a measurement rather than a claim about whichever OIDs were looked at.
The two survivors are `jnxBoxSerialNo` and `juniper_mx240`'s `sysObjectID` value.
One of the 13 misses is a **weak call** and is named below, so the strong-call rate is 12 of 15.

**The value-position denominator is 2, not 3, and the missing one is a known coverage gap.**
`juniper_mx240` answers `entPhysicalVendorType.1` with a Juniper product OID too.
The production predicate that decides whether a value reaches the wire as an OID is `snmpTypeTag`, and `oidTypeTable` has exactly one OBJECT IDENTIFIER row (`sysObjectID`), so that value goes out as an OCTET STRING and sits outside every OID-position measurement in the package.
The own-vendor PEN guard recorded the same gap and closed it separately.
The value is pinned anyway, because it was already right.

#### The finding that matters most to a collector

`juniper_mx960` answered `sysObjectID.0` with `1.3.6.1.4.1.2636.1.1.1.2.25`.
That is `jnxProductNameMX480`.
The profile is an MX960, its `sysDescr` says "mx960 internet router", and its own vendor-detection surface identified it as a different chassis in the same family.

**This is a subtler shape than the Arista audit's Arista `sysObjectID`, and it is worse.**
The Arista value was well formed, under the right PEN, under the right registry, and resolved to nothing, so vendor detection failed loudly.
This one resolves, to a real Juniper product nl6 does not model, so vendor detection succeeds and is wrong.
Nothing downstream can tell.
It now answers `1.3.6.1.4.1.2636.1.1.1.2.21`, `jnxProductNameMX960`.

`juniper_mx240` answers `.29`, `jnxProductNameMX240`, and that was already correct.

**The Juniper audit expected this to be unauditable and it was not.**
The issue told the implementer to record both `sysObjectID` values as UNAUDITED if JUNIPER-CHASSIS-DEFINES-MIB could not be obtained, since it 404s from the LibreNMS mirror.
A copy was obtained from `netdisco/netdisco-mibs`, and reading it is what found this.
An UNAUDITED verdict recorded without trying the second mirror would have shipped the defect.

#### Wrong platform inside the right vendor

**Four entries on `juniper_mx240` and one on `juniper_mx960` served `jnxExMibRoot`, the EX-series switch MIB root, from MX-series routers.**

JUNIPER-SMI assigns `jnxExMibRoot ::= { jnxMibs 40 }`, between `jnxJsMibRoot` (39) and `jnxWxMibRoot` (41), so `2636.3.40` is the EX branch by construction.
JUNIPER-EX-SMI puts `jnxExVirtualChassis` at `{ jnxExSwitching 4 }` and JUNIPER-VIRTUALCHASSIS-MIB puts `jnxVirtualChassisMemberTable` under it.

**This is a subclass no guard sees, and it is the reason a per-arc audit is not the same as a PEN check.**
The own-vendor PEN guard passes these by construction: 2636 really is Juniper's.
What is wrong is the platform, one level below the vendor.

| OID | was | object |
|---|---|---|
| `…2636.3.40.1.4.1.1.1.1.0` | `AMCC PowerPC 8544E` | `jnxVirtualChassisMemberId`, `INTEGER (0..31)`, the table's INDEX and therefore `not-accessible` |
| `…2636.3.40.1.4.1.1.1.2.0` | `6` | `jnxVirtualChassisMemberSerialnumber` |
| `…2636.3.40.1.4.1.1.1.3.0` | `3200` | `jnxVirtualChassisMemberRole`, `INTEGER { master(1), backup(2), linecard(3) }` |
| `…2636.3.40.1.4.1.1.1.5` | `21.4R3-S2.3` / `21.2R3-S4.9` | `jnxVirtualChassisMemberSWVersion`, served as a **bare column** with no instance sub-identifier |

The four read as CPU model, core count, clock MHz and software version, which is what the author meant them to be.
No obtainable Juniper module defines a CPU-model object for an MX, so there is nowhere to move them to and **deletion is the only honest answer**.
The `SWVersion` row is the one whose value suits its column, which is exactly why it survived: it looks right.
The bare-column census could not see it, because its heuristic is "some other shipped OID extends it" and nothing extended it.

#### A table served with a scalar instance, again

`2636.3.1.8.0` on **both** profiles is `jnxContentsTable` with a `.0` appended.
Two independent faults, either one fatal: a table object is `MAX-ACCESS not-accessible` so no GET of it can succeed at any name, and `.0` is not a legal instance of a table in the first place.

This is the `aristaSwFwdIpStatsTable.0` defect of the Arista audit repeated verbatim on another vendor.
That is the argument for auditing every arc rather than generalising from one.

#### The `jnxOperating` INDEX arity, closed

`jnxOperatingEntry`'s INDEX clause is `{ jnxOperatingContentsIndex, jnxOperatingL1Index, jnxOperatingL2Index, jnxOperatingL3Index }`: **four** sub-identifiers.
(The Juniper audit's own issue text named the first column `jnxContainersIndex`. The arity is four either way, but a reading is worth what its accuracy is worth.)

**Both shipped spellings were wrong, not one of them.**
The issue observed that most rows used `.5.0.0` while two used `.1.1.0` and `.1.2.0`, and asked which was right.
Neither: every one is three sub-identifiers where the clause requires four.

**What settled the row is nl6's own code, not a guess.**
The corpus already held three spellings of the same table in three surfaces, and only the resource files were wrong:

| surface | instance | legal |
|---|---|---|
| resource files | `5.0.0`, `1.1.0`, `1.2.0` | no, three sub-identifiers |
| `metrics_oids.go` `vendorOIDs` | `9.1.0.0` | yes, and served as **live cycling values** |
| `juniper_mx240/traps.json` | `9.1.1.0`, `4.1.1.0`, `7.1.1.0`, `2.1.1.0` | yes |

**Two columns are deleted rather than renamed, and the reason is the octet-shadow sweep's.**
`findResponse` consults the metrics cycler *before* the static `oidIndex`, so a static `jnxOperatingCPU` row at `9.1.0.0` would never be answered.
It would be dead data that looks authoritative.
`jnxOperatingCPU` and `jnxOperatingBuffer` are cycler-owned on both profiles, so those rows go.
`jnxOperatingDescr`, `jnxOperating1MinLoadAvg` and `jnxOperating5MinLoadAvg` are not, so those are renamed onto the same row and keep answering.

| profile | was | now | object |
|---|---|---|---|
| both | `…13.1.5.5.0.0` = `67` / `34` | `…13.1.5.9.1.0.0` = `Routing Engine 0` | `jnxOperatingDescr` |
| both | `…13.1.8.5.0.0` = `67` / `34` | *deleted* | `jnxOperatingCPU`, already served live at `9.1.0.0` |
| both | `…13.1.11.5.0.0` = `78` / `56` | *deleted* | `jnxOperatingBuffer`, already served live at `9.1.0.0` |
| mx240 | `…13.1.20.5.0.0` = `45` | `…13.1.20.9.1.0.0` = `45` | `jnxOperating1MinLoadAvg` |
| mx240 | `…13.1.21.1.1.0` = `2500` | *deleted* | `jnxOperating5MinLoadAvg`; the MIB says the object is shown as a percentage, which 2500 is not |
| mx240 | `…13.1.21.1.2.0` = `48` | `…13.1.21.9.1.0.0` = `48` | `jnxOperating5MinLoadAvg` |

**The residual, stated rather than glossed.**
Contents index 9 is nl6's own convention and no obtainable module says a Routing Engine lives there.
What the MIB settles is the **arity**.
The row is inherited from code that already shipped, which is the least inventive option available, and it is not a MIB fact.
The same applies to the new `jnxOperatingDescr` value: the MIB says only "The name or detailed description of this subject", and the profile's own trap catalog already calls the `9.x` row a Routing Engine.
`jnxOperatingContentsIndex` points into `jnxContentsTable`, whose contents are a property of a device rather than of a module, and neither profile ships a single `jnxContentsTable` or `jnxContainersTable` row to resolve it against.

An index-arity guard is the guard this leaves behind.
It scans **all three surfaces**, which is the point: a scan of resource files alone would have reported the defect without the evidence that settled it, and the two surfaces that were already right are also the two no golden digest covers.

#### A number on a DisplayString, and the weak call

`2636.3.1.13.1.5.5.0.0` is `jnxOperatingDescr`, `DisplayString (SIZE (0..255))`, and it answered `67` on `juniper_mx240` and `34` on `juniper_mx960`.
`encodeTypedValue` emits a bare numeric string as tag `0x02` INTEGER, so a collector typing the object per the MIB got an INTEGER where a DisplayString belongs.
That is the nine-row defect the Cisco audit corrected on Cisco, and it is also semantically empty: a descriptor that says `67` describes nothing.
The correction is asserted **through the encoder**, because seven of the Cisco audit's rows survived a first cut that asserted the string and not the tag.

**`jnxBoxDescr` is the weak call, and it is recorded as one.**
It answered `JNP-MX240-002` and `JNP-MX960-001`.
Both are legal DisplayStrings and both encode as OCTET STRINGs, so nothing about them is a wire defect.
The MIB's DESCRIPTION is "The name, model, or detailed description of the box, indicating which product the box is about, for example 'M40'", and an asset tag with an instance suffix indicates which *unit* the box is, not which *product*.
The values now name the product each profile's `sysObjectID` identifies, which is the Arista audit's model-identity rule.
A device can be configured to answer anything here. What is not arguable is that the previous value did not indicate a product.
This is the same disposition the Arista audit gave `entPhysicalModelName.2` and the arc programme its fan half.

#### The trap catalog, and the cross-surface check

**The trap/poll join's class was checked and both shared OIDs agree.**
The Juniper trap catalog and the two profiles' polled data share exactly two OIDs, `jnxBoxDescr` and `jnxBoxSerialNo`, and the type a trap declares matches the tag a GET emits for each.
The Ciena audit could only assert *disjointness*, because that profile shared no OID at all. Here there was something to compare, so a guard compares it and pins the shared count so a new shared OID has to be looked at rather than absorbed.
The trap/poll join has since generalised the check to the whole corpus — see [A trap and a poll must agree on type](#a-trap-and-a-poll-must-agree-on-type) — so this test is now the per-arc reading of a rule that holds everywhere.

**Two further findings are recorded and neither is fixed.**
All seven `snmpTrapOID` values resolve to real NOTIFICATION-TYPEs under `jnxChassisTraps`, and every varbind uses a legal four-sub-identifier instance.
But:

1. **Not one of the seven emits the varbind list its own OBJECTS clause names.** The clauses run 5 to 10 objects each and the catalog emits 2 or 3, none of them an index column. The catalog says in its own comment that it is Class-1-vocabulary only, so making it follow the clauses is a rewrite of all seven entries and a Class 2 template epic, not an arc audit.
2. **One varbind declares a type the MIB contradicts.** `jnxFruFailed` carries `2636.3.1.15.1.9.4.1.1.0` as `timeticks`. `{ jnxFruEntry 9 }` is `jnxFruTemp`, `SYNTAX Gauge32`. The author wanted `jnxFruLastPowerOff` (`{ jnxFruEntry 11 }`, `TimeStamp`) or `jnxFruLastPowerOn` (12), neither of which is in `jnxFruFailed`'s OBJECTS clause either. Retyping it would leave it wrong and deleting it opens finding 1 for all seven entries, so it is recorded as a **presence**: a later change that fixes it has to edit the assertion deliberately rather than watch a test go quietly green.

**The provenance difference predicted the result.**
`juniper_mx240/traps.json`'s comment says its OIDs were "verified against oidref.com and Observium's JUNIPER-MIB mirror", which are aggregators rather than the module.
The Ciena catalog cited the module, its `LAST-UPDATED`, the severity enum and an internal contradiction in the MIB, and every one of those claims re-checked out.
The polled data here carries no provenance claim at all.
The catalog's seven notification OIDs all resolve. The polled data missed 13 of 15.
The pinned Juniper trap reading pins the comment's aggregator citation rather than letting it be tidied away, because that difference is the finding.

#### Fleet-visible surface change

- `juniper_mx960`'s `sysObjectID.0` changes, so vendor detection and asset inventory resolve the node differently. It resolved to an MX480 and now resolves to an MX960. `juniper_mx240`'s is unchanged and was already right.
- A walk of the two profiles returns **12 fewer OIDs** and **3 OIDs change name**. An mx240 walk loses eight names and renames three. An mx960 walk loses four and renames one.
- `ownVendorArcNamesShipped` falls from 328 to 316. `ownVendorArcValuesShipped` stays 28, because the mx960 correction moves its value *within* 2636 and a value count that fell would mean a profile had stopped identifying itself.
- Four values change without changing a name: two `jnxBoxDescr` and one `jnxOperatingDescr` per profile.
- No other profile is touched and no SSH response changes.

#### What this audit did not close

- **The trap catalog's OBJECTS-clause fidelity**, and the one misdeclared varbind type. Both are recorded as measurements above.
- **Semantic faithfulness of the mib-2 rows.** `juniper_mx960` answers `entPhysicalModelName.1` with `MODEL123` and `entPhysicalVendorType.1` with `1`, neither of which is under the Juniper arc. Those belong with an ENTITY-MIB sweep, which no arc audit has done. The Arista audit left the same class open for the same reason.
- **Which container index a Routing Engine occupies**, and therefore whether the renamed rows sit on the right row of a right-shaped table.
- **Whether the mirrored modules are what Juniper ships.** See the provenance note below.

#### Provenance, since no MIB file is checked in

Five modules, fetched anonymously on 2026-09-01, cited by `LAST-UPDATED` and by the SHA-256 of the file read, per the Arista audit convention.

| module | LAST-UPDATED | SHA-256 | source |
|---|---|---|---|
| JUNIPER-SMI | `200910290000Z` | `67fab3465f8e2bf1148df7d06361e1246591de9ceb8211bd9dce59becc0285ef` | `raw.githubusercontent.com/librenms/librenms-mibs/master/JUNIPER-SMI` |
| JUNIPER-MIB | `201010220000Z` | `d4c4f40c7a881f7e125c49fa706df973030f2687fd041e8d9fc22d7032bb88ad` | `raw.githubusercontent.com/librenms/librenms-mibs/master/JUNIPER-MIB` |
| JUNIPER-EX-SMI | none | `f2fb4576bd65f1ced716f7f2b2a35ba04add2025f634a4253946d902309ec006` | `raw.githubusercontent.com/librenms/librenms/master/mibs/juniper/junos/JUNIPER-EX-SMI` |
| JUNIPER-VIRTUALCHASSIS-MIB | `201403180000Z` | `5214043efe7412493d5b1581a0502b375752747611b743673db895421bae91f2` | `raw.githubusercontent.com/librenms/librenms/master/mibs/juniper/junos/JUNIPER-VIRTUALCHASSIS-MIB` |
| JUNIPER-CHASSIS-DEFINES-MIB | `201706230000Z` | `d503b145ab01665b1ceacb120f2a607a381db32f9044bd07750e1d540e536aab` | `raw.githubusercontent.com/netdisco/netdisco-mibs/master/juniper/mib-jnx-chas-defines.txt` |

**All five copies are third-party mirrors and their provenance is unestablished.**
Juniper's own entry point is `apps.juniper.net/mib-explorer/`, a JavaScript shell with no server-rendered content, and the Juniper audit recorded two secondary sources that contradict each other on whether a login is required.
Nothing here tested that wall.
Three of the five carry a Juniper copyright header and none grants redistribution, so the reading is qualified by mirror as well as by revision.

**That qualification matters more here than it did for Ciena.**
The Ciena catalog had already been transcribed from a reading, and the Ciena audit's job was to re-check somebody else's work.
Nobody had read these modules before.

**Two provenance oddities are recorded rather than smoothed over.**
JUNIPER-CHASSIS-DEFINES-MIB declares `LAST-UPDATED 201706230000Z` while its own REVISION list runs on to `201711220000Z`, so the module's stated revision is five months behind its newest recorded change.
JUNIPER-EX-SMI has no `MODULE-IDENTITY` at all, only OBJECT IDENTIFIER assignments and a copyright range, so it has no revision string to quote and is cited by digest alone.
That is the same situation the access-mode audit hit with SMIv1 OLD-CISCO-SYSTEM-MIB.

### Every arc is audited, labelled, or explicitly excluded

**The policy, and it is enforced rather than stated.**
Every enterprise arc a shipped profile serves is exactly one of three things, and a guard fails by name on any pair that is none of them.

| disposition | what it means | how a reader sees it |
|---|---|---|
| **audited** | somebody read the vendor's MIB | the PEN is in `auditedArcPENs`, whose every row names the reading test that pins it |
| **labelled** | nobody has read a MIB for it, and the file says so | every part of the profile carrying an entry under that PEN has `UNAUDITED-ARC(<pen>)` in its `_comment` |
| **excluded** | the arc is not a vendor claim at all | the `(profile, PEN)` pair is in `excludedArcPairs` with a written reason |

A new device type that serves a vendor subtree and does none of the three fails the suite, which is the durable half of this change.
Nothing previously stopped the corpus regrowing the problem, and that is how it got here.

**Fourteen arcs were closed by decision rather than by audit, and that is the honest call rather than a shortcut.**
The scope measurement cross-referenced every enterprise arc the corpus serves, in both the OID-name and the OID-typed-value positions, against every consumer in this repository: the polling rules published in the [Pollaris GPU contract](gpu/pollaris.mdx), the trap catalogs (`_common` plus per-type overlays), and the docs.
Of the arcs served, only four have any consumer at all, and all four are now audited or were already correct.
**The remaining arcs are read by nothing here.** No polling rule, no trap varbind, no doc keys on any of them.

At the observed hit rate, auditing them is weeks of work whose main output is deletions of data nothing reads.
A label costs minutes per profile and is **more honest than silence**: today a reader who opens one of those files sees a vendor subtree and reasonably infers that somebody checked it, and nobody did.
So the label states what is known and nothing more, and it says so in the file, next to the data, where the inference is made.

The fourteen, one arc each: `check_point_15600` (2620), `dell_emc_unity` (1139), `dell_poweredge_r750` (674), `dlink_dgs3630` (171), `extreme_vsp4450` (1916), `fortinet_fortigate_600e` (12356), `hpe_proliant_dl380` (232), `huawei_ne8000` (2011), `ibm_power_s922` (2), `nec_ix3315` (119), `netapp_ontap` (789), `nokia_7750_sr12` (6527), `pure_storage_flasharray` (40482), `sonicwall_nsa6700` (8741).

**Fourteen profiles, nineteen parts.**
Five of them carry their arc in two parts, and in each of those five the second part holds a single vendor serial-number object among a page of standard MIB rows.
The marker is therefore **per part**, not per profile: a per-profile marker leaves that second file looking checked, and the label's entire value is that a reader who opens the file sees it.

Each label states five things and claims nothing else:

- the objects under this PEN have not been read against any of the vendor's MIBs;
- the PEN itself **is** checked, by the own-vendor PEN guard, so what is unverified is what sits below the number rather than the number;
- what "unverified" covers: whether each object is defined, whether the value is of the kind its SYNTAX declares, and whether the object is readable at all;
- that nothing in this repository reads the arc, per the scope measurement, which is why it was labelled and not audited;
- the miss rates from the arcs that *were* audited, counting distinct OIDs: Palo Alto 8 of 11, Cisco 11 of 13, Arista 6 of 6, Ciena 0 of 1, Juniper 13 of 15.

No per-vendor detail beyond that is written down, deliberately.
An obtainability survey exists for all nineteen vendors and is summarised in the arc programme, but the point of the label is that it claims only what is known about *this* data.

**The marker is a sentinel, not prose, and it carries the PEN.**
`UNAUDITED-ARC(2620)` is a literal substring the guard looks for. A prose match would fail on a rewording and pass on a label that says nothing.
Binding it to the number is what stops a profile that later gains a **second** arc inheriting the first one's label, so a labelled 2620 does not excuse an unlabelled 1234 in the same file.
It is also what `git grep UNAUDITED-ARC` finds.

**Three exclusions, each for its own reason.**

- `aws_s3_storage` / **32473** is RFC 5612's documentation PEN, chosen deliberately by the own-vendor PEN guard and already documented in that profile's own `_comment`. There is no vendor MIB to audit it against and no vendor claim to label as unchecked.
- **PEN 0** on `cisco_catalyst_9500`, `cisco_nexus_9500`, `juniper_mx960` and `palo_alto_pa3220` is the `1.3.6.1.4.1.0.0` `entPhysicalVendorType` placeholder, 208 responses in total. PEN 0 is `Reserved` in the registry and held by IANA, so it is not a vendor subtree.
- **NVIDIA's 5703** is in the audited set rather than the labelled one, and the reason is that its existing `_comment` says something *stronger* than a label would. NVIDIA publishes no SNMP GPU MIB at all, so the NVIDIA PEN re-homing and the earlier research census recorded that every object below the PEN is nl6's own invention and unresolvable against any published module. There is nothing to audit it against, so `UNAUDITED-ARC` would understate what is known.

The four PEN-0 rows carry `scanVisible: false`, and that flag is checked **both ways**.
`oidTypeTable` does not type `entPhysicalVendorType`, so the production predicate the scan shares with the wire reads those responses as OCTET STRINGs and never reports them. They are covered instead by `assertEntPhysicalVendorTypeIsNotCrossVendor`.
If `oidTypeTable` ever gains that row the four flip to visible, a curation guard says so, and the disposition has to be decided again rather than inherited.
A stale exclusion that describes nothing fails the same test.

**What the guard cannot do: check that a label is true.**
A label claims that nobody read a MIB, and no test can read a MIB.
What it can do, and does, is refuse the fourth state: a vendor subtree that reads as checked because nothing says otherwise.
A staleness guard is the mirror, since the guard says every arc is accounted for and something has to say that every account describes something: a marker naming a PEN its own part serves no entry under is reported, and so is a marker on an arc that has since been audited, because after an audit the label tells a reader the opposite of the truth.

**No shipped OID data changed.**
The label lives in a `_comment` key the decoder ignores, so nothing a device serves changes. As with the Ciena audit, the deliverable is a reading, not a data change.

**The scope measurement's two caveats stand.**
Absence of a consumer *in this repository* is not absence in the world, and the [Pollaris GPU contract](gpu/pollaris.mdx) is simply the only one nl6 publishes: if an operator reports keying on one of the fourteen, that arc moves up.
And the four arcs that do have a consumer are consumed by nl6 *emitting* those OIDs in a trap, not by a collector keying on them, which is what makes disagreement between the two surfaces possible there and nowhere else.

### Access modes are not modelled

**No nl6 rule models MAX-ACCESS.**
The three load rules check encodability, the PEN guards check vendor identity, and the arc programme's reading tests check names, types and values.
None of them models access, and none of them can: an access mode is a property of the MIB, and nl6 has no MIB.

The access-mode audit is the first defect of the class, and it is a different class from everything above rather than one more wrong value.
`1.3.6.1.4.1.9.2.1.54.0` is `writeMem` in OLD-CISCO-SYSTEM-MIB:

```text
writeMem OBJECT-TYPE
    SYNTAX  INTEGER
    ACCESS  write-only
    STATUS  mandatory
    DESCRIPTION
            "Write configuration into non-volatile memory
            / erase config memory if 0."
    ::= { lsystem 54 }
```

The object exists, the arc is right, the instance sub-identifier is right, and the value even encoded as the declared INTEGER. That is exactly why every guard passed it.
What was wrong is that the object is not readable at all.
It is also a *command* rather than a datum: writing to it saves the running configuration, and writing `0` erases config memory.
A collector that discovers it as a readable integer has learned something false about the device in a way that is worse than a wrong number.

| profile | OID | was | now |
|---|---|---|---|
| `cisco_catalyst_9500` | `1.3.6.1.4.1.9.2.1.54.0` | `393084300` | *deleted* |
| `cisco_crs_x` | `1.3.6.1.4.1.9.2.1.54.0` | `1451548800` | *deleted* |

**Deleted, not corrected**: a write-only object has no correct readable value, so correction is not available. The same reasoning that deleted 3 of 11 OIDs in the Palo Alto audit and the fan rows in the arc programme.
A guard pins both absences, and extends the assertion across every Cisco profile to the other write-only objects in the same group (`netConfigSet`, `hostConfigSet`, `writeNet`), none of which ships today.
It also pins the neighbours this change deliberately left alone as *presences*, so the scope boundary is a measurement rather than a sentence.

The reading is cited by **name and form, not by revision**, and the difference is not pedantry: OLD-CISCO-SYSTEM-MIB is SMIv1 — it imports `OBJECT-TYPE` from RFC-1212 and spells access as `ACCESS`, not `MAX-ACCESS` — so it carries no `MODULE-IDENTITY` and therefore no `LAST-UPDATED` to quote.
The only date in the copy read is its header, `Copyright (c) 1994-1995 by cisco Systems, Inc.`
The arc was resolved rather than assumed: CISCO-SMI `201601150000Z` puts `cisco` at `{ enterprises 9 }` and `local` at `{ cisco 2 }`, OLD-CISCO-SYSTEM-MIB puts `lsystem` at `{ local 1 }` and `writeMem` at `{ lsystem 54 }`.
As with every audit on this page, no MIB file or extracted fixture is checked in, and the test is a pinned reading rather than a live check.

**`not-accessible` is the larger half of the class, and it is unswept.**
Every SMIv2 table INDEX column is `not-accessible`, so a profile shipping an index column as a readable row makes the same mistake in the commonest possible place.
Nothing sweeps it, and nothing can sweep it generically: deciding it needs the table's definition, which needs the arc's MIB, which has been read for Palo Alto, Cisco (partially), Arista, Ciena and Juniper only.
The access-mode class therefore advances **with** the arc programme's per-arc audit rather than being closed by the access-mode audit. An arc becomes sweepable for access modes at the same moment it becomes sweepable for wrong INDEX arity, and for the same reason.
The Juniper audit is the demonstration: reading JUNIPER-MIB for the arity question found two `not-accessible` objects in the same pass, `jnxContentsTable` served with a `.0` on both Juniper profiles and `jnxVirtualChassisMemberId`, which is an INDEX column.
