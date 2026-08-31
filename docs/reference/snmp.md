# SNMP reference

nl6 answers SNMP v2c and v3 queries on UDP port 161 (override with
[`-snmp-port`](cli-flags.md#core-flags)) for every simulated device. The
stack is implemented in `go/nl6/snmp*.go` — see
[Architecture](architecture.md) for the component map.

## Protocol coverage

- **SNMP v2c** — `GET`, `GETNEXT`, `GETBULK` against the full per-device OID
  table. Community string is `public` by default.
- **SNMPv3** — enable with [`-snmpv3-engine-id`](cli-flags.md#snmpv3-flags).
  Auth protocols: `none`, `md5`, `sha1`. Privacy protocols: `none`, `des`,
  `aes128`. Auth and priv are implemented in `snmpv3.go` / `snmpv3_crypto.go`.

### SNMPv3 auth / priv matrix

| Auth  | Priv    | Security level  |
|-------|---------|-----------------|
| none  | none    | `noAuthNoPriv`  |
| md5   | none    | `authNoPriv`    |
| sha1  | none    | `authNoPriv`    |
| md5   | des     | `authPriv`      |
| md5   | aes128  | `authPriv`      |
| sha1  | des     | `authPriv`      |
| sha1  | aes128  | `authPriv`      |

Per-device SNMPv3 credentials can be supplied when creating devices via the
REST API — see [Web API → Create devices](web-api.md#create-devices).

### The community string is echoed, never checked

nl6 does not authenticate on the community: it parses the value, answers the request, and echoes the same value back in the response.
There is no ACL and no rejection path, by design.
This is a simulator for collector validation, not an access-control surface.

A **zero-length** community is legal and is parsed as the empty string, not as absent.
Both shipped clients emit one on request: net-snmp and snmp4j each send `04 00` for `-c ""`.
nl6 answers with an empty community rather than substituting `public` (nl6#514).
A community of 128 octets or more encodes its length in BER long form (`04 81 c8`), which is parsed correctly on every path.

Golden fixtures for these cases live in `go/nl6/snmp_golden_packets_test.go`.
They are verbatim bytes captured from net-snmp and snmp4j, which matters.
Every other SNMP test in the package builds its input with nl6's own encoders, so encoder and parser can share a misconception and still agree.
The empty-community defect survived exactly that blind spot.

### Unimplemented OIDs return an exception, not a value

An OID absent from a device's profile is answered with the RFC 3416 `noSuchObject` exception — the context-specific tag `80 00` in the variable binding's value position — not with a string.
`error-status` stays `noError`: the response is a success and the exception is per-varbind (§4.2.1).

Only `noSuchObject` is ever emitted, never `noSuchInstance`.
The standard separates the two by OID prefix registration, and a profile is a flat OID→value map with no MIB registry, so nl6 cannot evaluate that test.
`noSuchObject` is the only answer it can defend.

**SNMPv1 has no exception values.** A v1 request that would produce one gets `error-status = noSuchName(2)` instead, with `error-index` set to the offending variable binding and every requested name echoed with a NULL value, per RFC 3584 §4.2.2.2 (§4.2.2.2.1 for `noSuchObject`, §4.2.2.2.2 for the `endOfMibView` a v1 GETNEXT reaches past the last OID).
The mapping applies to GET and GETNEXT only.
GETBULK does not exist in SNMPv1, so a version-0 GETBULK is malformed and is answered as before rather than mapped: its bindings are walked OIDs, not the request's names, and there can be `max-repetitions × columns` of them.

**SNMPv3 GET and GETNEXT are covered.** Since nl6#518 the v3 encoder (`createScopedPDU`) goes through `encodeTypedValue` as well, so a v3 GET for an absent OID returns the `80 00` tag and a v3 GETNEXT past the last OID returns `82 00`.
The v3 GETBULK handler reaches the same encoder through `createScopedPDUMulti`, so its bindings carry the same tags. It honours `max-repetitions` and `non-repeaters` as sent, and it answers every column the request names; a request for zero repetitions is answered with an empty binding list, not an `endOfMibView`.

The exceptions are carried as sentinel strings (`noSuchObject`, `endOfMibView`) from the lookup to the encoder, where `encodeTypedValue` turns them into tags.
That puts them in the value space: a resource file whose legitimate value were literally `noSuchObject` would encode as an exception, and a v1 manager would get `noSuchName` for a value that is simply a string.
Removing the hazard at the root needs a typed value rather than a string, which is a larger change.
Until then the resource-file route to it is closed at load time.

### The first OID sub-identifier is a varint

X.690 §8.19.4 packs the first two arcs of an OID into a single sub-identifier valued `40*first + second`, encoded as a base-128 varint like every other one.
nl6 used to emit that sub-identifier as one byte, and to read it back as one, so the encoder and decoder agreed with each other while both disagreed with the standard.

The round-trip held only while the second arc stayed below 40, and fabricated silently above it:

| OID | went out as | since nl6#529 |
|---|---|---|
| `3.40.1` | `.4.0.1` | degenerate `06 00`, first arc 3 is not representable |
| `2.87.1` | `.4.7.1` | round-trips |
| `2.175.1` | `.6.15.1` | round-trips |
| `2.999` | `.1.15` | round-trips |

That is valid-looking BER carrying an OID nobody wrote, which a collector has no way to detect. `2.999` is the ITU test arc and is perfectly legal; it simply could not be expressed before.

An OID the encoder cannot represent faithfully now takes a degenerate encoding, `06 00`, rather than becoming a different OID.
That encoding is itself non-conformant: X.690 §8.19.1 requires at least one sub-identifier, so nl6 emits bytes its own decoder refuses.
The trade is deliberate and worth stating plainly. A wrong-but-well-formed OID is undetectable and gets recorded as fact; a malformed one is visible to any decoder, and in a `snmpTrapOID.0` or `sysObjectID` position a collector will reject the message rather than believe it.
Refusing to build the message at all would be better still, but that needs an error return through seven varbind-name call sites and is not this change; it is tracked in `deferred-work.md`.
The OCTET STRING fallback nl6#529 asks for in a value slot (the way `encodeIPAddress` already degrades an unparseable address) is also still open: `encodeTypedValue`'s OID branch returns the same `06 00`, so a `sysObjectID` of `unknown` still goes out as a degenerate OID rather than as a string. That covers a first arc above 2, a second arc above 39 when the first is 0 or 1 (a wider one would be indistinguishable from a higher first arc, since `1.40` and `2.0` both compute 80), a combined first sub-identifier or any later arc above 2^32-1, and any component that is not a number.

The decoder is stricter too, because it parses bytes that arrive from the network.
A sub-identifier whose final byte still sets the continuation bit is truncated and is now refused, where it used to be accepted at face value.
A sub-identifier wider than 2^32-1 is refused, where it used to wrap and could produce a negative arc.
A non-minimal sub-identifier, one whose leading octet is `0x80` (X.690 §8.19.2), is refused too; otherwise an attacker could pad any OID with continuation bytes and produce unbounded distinct byte strings that all decode to one OID.

Nothing that ships with nl6 changes on the wire: all 5,676 distinct OIDs across the resource files and trap catalogs encode to exactly the same bytes as before.

### SNMPv3 authPriv requests are served (fixed in nl6#527)

Until nl6#527 an SNMPv3 request sent with privacy was answered with `sysDescr.0`, whatever OID it asked for and whatever PDU type it used, carrying request-id 1.

The cause was a shape mismatch rather than anything cryptographic. A scoped PDU appears in two forms here: the message parser stores its *contents*, with the outer SEQUENCE header stripped, while decryption returns the whole thing including that header. The code that reads the OID and the request id from a scoped PDU expects contents, so on a successful decrypt it failed to parse, and the surrounding decrypt-*failure* fallback took over and substituted `sysDescr.0`.

Nothing reported an error, because the fallback exists precisely to keep the path quiet under adversarial input.
That fallback was left in place by this fix and removed by nl6#547: a request whose scoped PDU genuinely fails to decrypt is now answered with a `usmStatsDecryptionErrors` Report (see the malformed-datagram section).

If you are testing an SNMPv3 collector against a version of nl6 older than this fix, authPriv results are not meaningful: every device answers `sysDescr.0`. authNoPriv and noAuthNoPriv were unaffected.

The discovery Report also now carries `usmStatsUnknownEngineIDs.0` as a Counter32, which is the type RFC 3414 §5 gives it. It previously went out as an INTEGER.
Only the type changed: the value is a fixed `1` and does not count unknown-engine-ID events.

### SNMPv1 never returns a Counter64

Counter64 does not exist in SNMPv1, and the response encoder picks the ASN.1 tag from the OID alone, so a v1 request for an `ifHC*` column used to answer tag `0x46` under `error-status = noError` (nl6#524).

RFC 3584 §4.2.2.1 prescribes two different behaviours, and the difference matters more than it first looks:

- A **GET** answers `error-status = noSuchName`, with `error-index` at the first offending binding and every requested name echoed with a NULL value.
- A **GETNEXT** **skips** the object and continues to the next lexicographic successor.

A GETNEXT names a position rather than an object, so answering it with an error would stop a v1 walk at the first HC column and truncate the table with nothing to explain why.
A v1 walk over `ifXTable` therefore returns every non-Counter64 column and steps silently over the Counter64 block.

The diversion is keyed on the OID's declared MIB type, not on what its value happens to encode as.
A Counter64 column holding a non-numeric value would have gone out as an OCTET STRING, which is legal in v1, and it still diverts: the object's type is what a v1 manager cannot represent, and a bad stored value should not quietly soften protocol semantics.

SNMPv2c and SNMPv3 are unaffected, and SNMPv3 is never v1.

A walk that skips its way past the last non-Counter64 OID ends in `noSuchName`, which is how v1 signals end-of-MIB here.

If the skip runs into a resource-file defect (a successor that does not advance, or the step cap), the walk is answered as end-of-MIB and one log line per device names the OID, because from the manager's side that walk is indistinguishable from a short table.

Two limitations are worth stating plainly:

- **GETBULK is deliberately untouched.** SNMPv1 has no GETBULK, but nl6 answers a version-0 GETBULK anyway, and it will hand a v1 manager raw `0x46` tags. This is the same decision the exception mapping makes above: a GETBULK's bindings are walked OIDs rather than the request's names, so the RFC 1157 echo does not apply to them.
- **Coverage is bounded by the type table.** nl6#541 widened it: the Counter64 objects nl6 recognises are now the eight `ifXTable` HC columns, the fourteen HC columns of each of the two RFC 4293 IP statistics tables (`ipSystemStatsTable`, `ipIfStatsTable`) and all six columns of the RFC 3635 `dot3HCStatsTable` — 42 columns in total. The column numbers were read out of the shipped IP-MIB and EtherLike-MIB with `snmptranslate`, not recalled. A 64-bit counter served under any OID still outside that set — a **vendor** HC column above all — is not recognised as Counter64, and a v1 request for it is answered with a value rather than diverted.
  Widening a type table changes what goes on the wire for every OID matching a new row, so it was measured rather than argued: `TestShippedTagsUnchangedByTableWidening` hashes the (profile, OID, emitted tag) triples of all 27,318 shipped resource entries, and the digest taken before the widening still matches after it. **The effect on the shipped fleet is exactly zero** — no shipped profile serves any newly typed column, so the widening's value is entirely for operator-supplied files and for a future profile.
  The digest is keyed on the profile as well as the OID because a fleet-wide key hides a per-profile change: keyed by OID alone, the 31 tag changes this same change made to shipped data vanish entirely, since other profiles already produced those pairs. It hashes tags rather than encoded bytes, which is what keeps it stable across ordinary value edits.
  Every corpus test walks `resources/` recursively through one shared collector, and the two views of the tree cross-check each other. They used to glob `resources/*/*.json`, which is two path segments and therefore blind to the single-file `resources/<slug>.json` layout that all four loaders accept: a vendor 64-bit column in such a profile passed the sentinel guard, this digest and the Counter64 pin, and the only test that fired pointed the maintainer at re-pinning a golden digest — which would have absorbed the defect rather than reporting it.

### A GETNEXT answers every variable binding

RFC 3416 §4.2.2 defines GETNEXT over the whole variable-bindings list, and nl6 answers it that way (nl6#542).
Each binding carries the lexicographic successor of its own name, in request order.
A binding with nothing after it carries `endOfMibView` named with the OID that was asked for, so a walker fetching several columns per round trip can tell which column ended.
Until nl6#542 the dispatcher read one OID and answered one binding, so such a walker got the first column and no signal that the rest had been dropped.

Two of the three behaviours below differ by version; the third is the same either way and is listed with them because all three are decided in one place.
The SNMPv1 Counter64 rule is the one that matters most.

| Case | SNMPv1 | SNMPv2c |
|---|---|---|
| The successor is a Counter64 object | that binding SKIPS it and continues to the next successor (RFC 3584 §4.2.2.1) | returned normally |
| Nothing follows the requested OID | the response diverts to `noSuchName` with `error-index` at the first such binding, and the request's own names echoed with NULL values | `endOfMibView`, named with the requested OID |
| The response will not fit the datagram | `tooBig` with an empty binding list | `tooBig` with an empty binding list |

The Counter64 asymmetry is described canonically in the section immediately above; the row here is a summary, not a second definition.
A GETNEXT names a position, not an object, so diverting on a Counter64 successor would stop a v1 walk dead at the first `ifHC*` column and truncate the table with no signal.
A GET does divert there, because it names the object.
The two rules share one response encoder, so which one applies is an explicit argument at the call site (`v1DiversionRule`) rather than something the encoder infers.

Overflow is `tooBig` rather than truncation for the same reason it is on a GET: the manager named N positions and has no resume point for a binding a shorter response would drop.
**This changed the answer for a single-binding GETNEXT.** Before nl6#542 that path applied no size bound at all and emitted an over-budget datagram; it now answers `tooBig`.
The change is not reachable with shipped resources, where no value approaches the budget, but it is reachable with an operator resource file carrying a value over roughly 1400 bytes.
The empty binding list under SNMPv1 is nl6's choice, not something RFC 1157 settles: §4.1.2 and §4.1.3 describe a `tooBig` response as "of identical form", which reads as echoing the request's bindings.
nl6 sends none, so a `tooBig` cannot be mistaken for an answer.

The whole request takes ONE LLDP served-OID snapshot, shared across every binding and every step of a Counter64 skip run, so no two steps of one request can straddle a topology generation bump.

A version integer that is neither 0 nor 1 is served with SNMPv2c semantics rather than discarded, matching the leniency of the rest of this path.

#### The cost of a wide multi-binding GETNEXT

Answering every binding multiplies the walk, and on a wide profile that is measurable.
Timed through `handleSNMPv2cRequest` on `cisco_crs_x` with a live counter cycler, an SNMPv1 GETNEXT repeating one name just before the `ifHC*` block:

| Bindings | Request size | Time |
|---|---|---|
| 1 | 44 B | 2.9 ms |
| 10 | 209 B | 27.2 ms |
| 40 | 752 B | 104.3 ms |
| 68 | 1256 B (over the 1024 B read buffer) | 176.8 ms |

This runs inline on the shared UDP handler. Two bounds contain it, and neither removes it:

- The binding count is clamped to what a response could ever fit (`maxSNMPResponseSize / minVarbindSize`, 98 at the default MTU). Above that the request is answered `tooBig` **without walking at all**, so no work is spent on a response that would be discarded. This is also the backstop that stops a larger read buffer from raising the work linearly.
- The SNMPv1 Counter64 skip steps of one datagram share a single budget, so the cost does not scale with a per-binding allowance. The budget is derived, not hand-set: `maxGetNextBindings × longestShippedCounter64Run`, which is exactly what the widest legitimate request needs, so it cannot truncate a real table. An operator resource file with a wider Counter64 run than any shipped profile is the one case it does not cover; such a request is truncated and logged once per device.

`longestShippedCounter64Run` is 1152 — eight `ifHC*` columns across 144 interfaces on `cisco_crs_x` — and it is measured by WALKING, not by scanning the static resource index.
The distinction is worth 4x: that profile ships static rows for `ifXTable` columns 1, 6, 10, 15 and 18 only, and `IfCounterCycler` serves the rest analytically, so the static index reports 288 while the walk crosses 1152.

### Resource values are validated at load

`validateSNMPResourceValues` runs three rules over the `snmp` array of every resource file, in the order `encodeTypedValue` itself applies them, so the first diagnosis to fire is the one that matches what the wire would do.
Every rule decides by **calling the encoder** and inspecting what it emits, never by a second predicate that re-derives the encoder's rules — that is how `trap_catalog.go`'s `validateDottedOID` drifted from `encodeOID` in both directions (nl6#539).

| Rule | What it refuses | Decided by |
|---|---|---|
| 1. Sentinel (nl6#523) | a response exactly equal to `noSuchObject` or `endOfMibView` | `isSNMPExceptionValue`, the same exact test the encoder uses |
| 2. OID-typed value (nl6#529) | a value on an `OBJECT IDENTIFIER` leaf that `encodeOID` cannot represent | calling `encodeOID` and testing for the degenerate `06 00` |
| 3. Typed class (nl6#541) | a value on any leaf the type table types that does not encode at that type | calling `encodeTypedValue` and comparing the emitted tag with the declared one |

Rule 2 cannot be folded into rule 3: the degenerate `06 00` carries the **declared** tag, so a tag comparison is blind to it.

Rule 3 is the class that actually shipped a bug (nl6#515): a `freeMem` entry carrying the device's own name went out as an OCTET STRING, and OpenNMS, which types that OID as a gauge, logged a conversion error on every poll of every device for as long as the fleet ran.
It covers `Counter32`, `Gauge32`, `TimeTicks`, `Counter64` and `IpAddress` leaves, and it inherits the encoder's asymmetries rather than tidying them up:

- A negative on a `Counter32`, `Gauge32` or `TimeTicks` **loads**: the encoder parses it at 32-bit width and wrap-casts, so `-1` goes out as `0xFFFFFFFF` at the declared tag. The asymmetry is inherited from the encoder and has no shipped motivation — all 116 negative values in the shipped set are `-1` on `ipRouteMetric1/2/3/5`, which the table does not type and where RFC 1213 gives `-1` as "not used", and none sit on an unsigned 32-bit leaf. Because a wrapped `4294967295` is invisible to a collector in a way a dropped metric is not, such a value draws a load-time **warning** naming the file, the OID and what will go on the wire. It is not refused, because the encoder encodes it and the guard's verdict is the encoder's.
- The same `-1` on a `Counter64` is **refused**, because that branch has no signed fallback and degrades to an OCTET STRING.
- Surrounding whitespace is **refused** (`" 42"`, `"42 "`), because `strconv` does not trim.
- A value carrying units (`"42 packets"`), hex (`"0x2a"`), a decimal fraction, or anything past the type's width is **refused**.
- An `ipAdEntAddr` or other `IpAddress` leaf needs a dotted-quad IPv4 address; `"host"`, `"1"`, `"10.0.0.256"` and `"::1"` are all refused.

Rules 2 and 3 reach only leaves the type table types.
A leaf it does not type takes the encoder's default branch, where INTEGER for a number and OCTET STRING for anything else are both legitimate, so there is nothing to compare against.
Numeric leaves outside the table — the `OLD-CISCO-SYSTEM-MIB` INTEGER leaves, for instance — are covered instead by a test over the shipped profiles (`resource_numeric_oids_test.go`), which operator-supplied files never reach.

Applying rule 3 to the shipped set for the first time found 45 entries of exactly the nl6#515 class, all corrected in the same change: a bare `ipRouteDest` column OID valued `1` in 14 profiles (deleted, because that column is `IpAddress`-typed and `1` is not an address), 30 `ifInOctets`/`ifOutOctets` entries in the three NVIDIA profiles whose values overflowed `Counter32`, and one `asr9k` `sysUpTime` past the `TimeTicks` wrap (both wrapped modulo 2^32, which is what the real counter does).
Those 30 rewrapped values are moot as of nl6#570: they are among the 1322 static `ifInOctets`/`ifOutOctets` entries deleted when the cycler took both columns over, so nothing serves them any more.
The reversal chains rather than being replaced — `snmp_shipped_data_ledger_test.go` restores nl6#570's ledger first, reconstructing the tree nl6#541 left, and only then reverses its own three tables.

Sixteen further values were edited that rule 3 **never saw**, and it is worth naming the mechanism that did, because that is the one a reader will rely on next time. All sixteen sit on leaves the type table does not type, so all were and remain INTEGER on the wire:

- Five values past 2^32 — three `hrStorageSize`/`hrStorageUsed` rows and a Palo Alto memory scalar — found by `TestShippedBigValuesSitOnCounter64Leaves`.
- `hrStorageSize.1 = 2147483648`, exactly one over `Integer32`'s ceiling, in two profiles — found by neither of those, because that test's threshold is 2^32. `TestShippedUntypedValuesFitInteger32` closes the band between 2^31-1 and 2^32 and is what caught it.
- The rest are allocation-unit and `hrStorageUsed` rows rescaled alongside, so each `hrStorage` row stays internally consistent (`hrStorageAllocationUnits` is what makes a large device expressible in an `Integer32` size).

The whole transition is committed as data rather than summarised as a count: `snmp_shipped_data_ledger_test.go` holds the 31 tag changes, 16 rescales and 14 removals, machine-generated from a diff against the parent revision, reverses them against today's corpus and requires the parent digest byte for byte.

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
`sysLocation` comes from the operator-supplied worldcities CSV, and since nl6#541 it is covered at `getRandomLocation` instead — the single funnel every served location passes through, whatever its source: a name equal to a sentinel is replaced with the coordinate-less `Unknown Location` the empty-dataset branch already uses, and the substitution is logged.
The CSV loader carries the same check on the row, so a defective dataset row is named with its file, but that check cannot fire today: the display string is always composed as `city, country` or `city, admin, country`, so it always contains `", "` and no sentinel does.
It is an invariant guard for a future change to that composition, and `TestWorldCitiesLocationCannotComposeToASentinel` is what fails if the composition changes.
`sysName` is derived from the device rather than from operator data, so there is nothing there to validate.

Where a rejection surfaces matters.
Resource files are also loaded on REST device creation, so a bad operator-supplied file is a failed API call in the middle of a run, not only a refusal at startup.
It answers HTTP 400, with the file's base name in the body, plus the OID and the value when the fault is attributable to one entry; the full path stays in the server log.
A rejection is never downgraded to a log line (nl6#538).
The startup load exits rather than substituting another profile, and round-robin device creation fails the call rather than skipping the offending device type.
An absent file is a different kind of fault: round-robin still skips it, while over REST it is also a 400, because naming a device type that does not exist is an unsatisfiable request rather than a server fault.
The no-path guarantee covers these classified rejections only — an unclassified loader failure still answers 500 with the raw error text.
The full path is logged server-side on every rejection, so base-naming the body loses nothing.
Full detail, including the response envelope, is in [Web API → `resource_file` failures](web-api.md#resource_file-failures).

Rule 2 (nl6#529) covers a value on an OID-typed leaf, today only `sysObjectID`: it must be an OID the encoder can represent.
Encodability is decided by calling the encoder and testing for the degenerate `06 00`, not by a second predicate, so the loader cannot drift from the wire; see [The first OID sub-identifier is a varint](#the-first-oid-sub-identifier-is-a-varint) above for what the encoder accepts.
The sentinel rule is checked first, matching the order the encoder applies them, so a sentinel on `sysObjectID` is reported as a sentinel collision.

What remains uncovered, stated in one place:

- **OID keys.** Only values are checked; a malformed `oid` key is not.
- **Bare table columns.** The 14 deleted `ipRouteDest` entries were removed because rule 3 refused them, not as a sweep of the class: **41 bare-column entries still ship across 6 profiles** (bare `entPhysicalTable` columns, bare `ifDescr`/`ifMtu`/`ifSpeed`/`ifOperStatus`, a Cisco environment column, and four `hrStorageAllocationUnits` columns with no instantiated siblings). A walk emits a binding named with a column OID, which is not a legal varbind name. `TestBareColumnCensusHasNotGrown` pins the count so the class cannot grow while the sweep is pending.
- **Semantics.** The rules check ENCODABILITY, not faithfulness to the MIB: a value that encodes cleanly at its declared type passes even when the object at that OID is a different object, or does not exist. `palo_alto_pa3220`'s PAN subtree is the worked example — a number where `panMgmtPanoramaConnected` is a `DisplayString`, and two OIDs hanging under a leaf scalar — and it passes all three rules (filed as nl6#569).
- **Leaves the type table does not type.** Rules 2 and 3 are type-directed, so a mistyped value on an untyped leaf — an `Integer32` leaf carrying a value past 2^31-1, say — loads and is served as a wide INTEGER.
- **Vendor 64-bit counters.** A vendor HC column is not typed, so it is served as an INTEGER and SNMPv1 is not diverted for it. `TestShippedBigValuesSitOnCounter64Leaves` fails if a shipped profile grows such a column, which is the reminder that the table is hand-maintained.
- **`sysName`.** Derived from the device, not operator data.
- **Non-`snmp` sections.** SSH, API and optical entries never reach `encodeTypedValue`; the trap and syslog catalogs have their own validation.
- **Version-0 GETBULK.** Answered as-is, `0x46` tags included, by decision (see above).

## Response size, `max-repetitions` and truncation

An SNMP response is bounded so the resulting UDP **frame** fits the link: the payload ceiling is the MTU minus the IPv4 and UDP headers, 1472 bytes at the default MTU, and it moves with `-datagram-mtu`. See the flow-export reference for that flag.

**GETBULK truncates.** A response carrying more variable bindings than fit is cut to what fits, per RFC 3416 §4.2.3, with `error-status` left at `noError`. The collector resumes the walk from the last OID returned — which is how a walk already works, so nothing is lost and no data is skipped.

**GET does not truncate.** A GET response that will not fit is replaced by `error-status = tooBig(1)` with an empty variable-binding list, per RFC 3416 §4.2.1. A GET requester asked for specific bindings and has no resume point, so a partial answer would be a wrong answer it could not detect. nl6 supports multi-binding GETs (a collector may bundle several OIDs in one request) and returns every binding in request order when they fit.

### How response size scales

Size grows as `columns × repetitions`. Measured against a device with 64 interfaces, walking the ten ifTable/ifXTable columns a collector typically requests:

| columns | max-repetitions | bindings | response | frame |
|---|---|---|---|---|
| 10 | 2 | 20 | 500 B | 528 B |
| 30 | 2 | 60 | 1436 B | 1464 B |
| 10 | 10 | 61 | 1470 B | 1498 B |
| 10 | 127 | 61 | 1470 B | 1498 B |
| 10 | 1000 | 61 | 1470 B | 1498 B |

Past roughly 60 bindings the response is truncated to fit, so raising `max-repetitions` further changes nothing about the datagram — it only means the walk completes in fewer requests up to that point.

The 30 × 2 row is the OpenNMS collector default (`max-vars-per-pdu` 30, `max-repetitions` 2). It fits with 36 bytes to spare, which is why nothing fragments out of the box and why a slightly larger configuration used to.

### `max-repetitions` is honoured as sent

Any value is accepted and used. Before nl6#489 the parser read only single-byte BER content, which looks like a 255 ceiling but is really a 127 one — BER encodes any value from 128 upward in two bytes, because the leading `0x00` is what keeps it positive. Everything above 127 silently fell back to the default of 10.

That mattered for benchmarking more than for correctness: an operator setting `max-repetitions=200` got 10, the collector performed twenty times the round-trips, and the result described a configuration nobody chose. **Numbers gathered against nl6 before this change, with `max-repetitions` above 127, are not comparable with numbers gathered after it.**

A negative value is treated as 0, per RFC 3416's definition of the field as non-negative.

### SNMPv3 values are typed like v2c

Both versions encode a value through `encodeTypedValue`, so the same OID carries the same ASN.1 type whichever version answered.
That was not always true: the v3 scoped-PDU builder used to branch on `strconv.Atoi` and emit only INTEGER or OCTET STRING, which meant v3 had no Counter32/Gauge32/TimeTicks/IpAddress typing and sent `endOfMibView` as literal text rather than as an exception, so a GETNEXT-driven v3 walk did not terminate where the protocol says it should (nl6#518).
**Measurements of SNMPv3 responses taken before that change are not comparable with measurements after it.** The wire types differ.

### SNMPv3 GETBULK answers every column

`handleSNMPv3GetBulk` parses every variable-binding name from the scoped PDU and applies the RFC 3416 §4.2.3 split: the first `non-repeaters` columns get one successor each, and the rest are walked `max-repetitions` times, interleaved one binding per column per repetition.
It used to serve a single starting OID: the first binding, and the only one `extractOIDAndTypeFromScopedPDU` validates.
A manager bundling `ifDescr`/`ifName`/`ifAlias` in one GETBULK therefore got successors of `ifDescr` and nothing at all for the rest, a wrong answer rather than merely a small one (nl6#535).
That single-column shape also forced `non-repeaters` to collapse into `max-repetitions = 1`, which is not what the field means: with non-repeaters present and `max-repetitions` zero, the non-repeater bindings are now returned rather than an empty list.

A column that reaches the end of its MIB view is padded with its OWN requested OID and `endOfMibView`, so the interleave stays aligned and a manager can still tell which column a slot belongs to.
The order and the padding match the v2c `handleGetBulk`, and the two paths are pinned against each other rather than each being separately plausible (`TestV3GetBulkOrderMatchesV2c`).

**A multi-column response is byte-identical to v2c, tail included.**
The padding continues for every remaining repetition, exactly as v2c pads.
An earlier cut of this change stopped once every column was exhausted and reported the difference as an unavoidable divergence; it was not.
nl6#526's stop-instead-of-pad rule is keyed on LOOP SHAPE, not on protocol version, and it constrains the single-column loop only.

**The single-column loop still stops.**
A v3 walk on one column that runs out mid-response ships what it collected, and the next request, collecting nothing, receives the exception on its own.
A first repetition that produced nothing is still emitted, so a single column already past the end of the MIB is answered with its own OID and `endOfMibView` rather than with an empty list.
Applying either rule to the other loop is pinned as a mutation (`TestV3GetBulkSingleColumnStopIsNotAppliedToMultiColumn`).

One thing does still differ from v2c, and only on data that cannot load: a v3 column also ends on the `endOfMibView` sentinel and on a non-advancing successor, and names that binding with the requested OID, where v2c's non-repeater loop tests only for an absent successor.
Both extra exits are nl6#526 and nl6#524 properties that a shared walk must not lose.
`validateSNMPResourceValues` rejects the sentinel at load, and a non-advancing `oidNextMap` is a resource-file defect.

The walk clamp divides its ceiling by the repeater-column count, because a repetition costs one walk step per column and the guard bounds the TOTAL work, which is what it bounded when there was only ever one column.
A malformed variable-bindings list discards the datagram exactly as on the v1/v2c path; the multi-column parse can only add discards (a LATER binding being the malformed one), never relax the nl6#547 rule.
It has its own log gate, separate from the dispatcher's malformed-scoped-PDU discard, so neither fault can silence the other.

**A declared container length that overruns what contains it is malformed, not absent.**
That distinction is load-bearing rather than pedantic.
It used to be classified absent, so adding 8 to one length byte of a well-formed three-column GETBULK made the parser report that there was no list, the handler fall back to the single OID the dispatcher validated, and the response carry ten bindings from the first column: the defect this change fixes, restored by a one-byte lie, with no discard and no log line.
Shortening the same byte was already treated as malformed, so one lie had opposite verdicts in its two directions.
Every container is now checked the same way, bytes between the end of the list and the end of the PDU are refused, and every bound is written so that a four-octet BER length cannot wrap an addition negative on a 32-bit build.

The column count itself has no explicit cap.
The repeater walk is bounded regardless, since the clamp divides by the column count, but the non-repeater loop is one walk step per column, and what bounds that is the 1024-byte read buffer.
The coupling is asserted in a test so a larger buffer has to acknowledge it.

### Known limitations

**An SNMPv3 GET or GETNEXT answers its first variable binding only.** `extractOIDAndTypeFromScopedPDU` validates and returns the first name in the scoped PDU's variable-bindings list, and the v3 handlers build a single-binding response from it. So a v3 manager fetching several columns per round trip gets the first, as every version did before nl6#542 fixed the v1/v2c path. A v3 GETNEXT also calls `findNextOID` per request rather than sharing a served-OID snapshot across bindings, since there is only one. Analogous to the v3 GETBULK gaps below, and tracked with them.

**SNMPv3 GETBULK is bounded by measurement, not arithmetic** (nl6#535). The v2c path computes its response length from fixed prefixes, which it can because its envelope is fixed. A v3 message cannot: its `msgGlobalData` and `msgSecurityParameters` sizes depend on the engine ID, the user name and the privacy parameters, and under privacy the scoped PDU is encrypted and PADDED to a cipher block. So the GETBULK builder assembles the candidate response through the real encoder and measures it, dropping bindings from the end until it fits. RFC 3416 §4.2.3 makes that correct: a truncated GETBULK is resumable, since the walker continues from the last OID returned. As on the v2c path, at least one binding is always emitted even when it does not fit, because an empty binding list with no error stalls a walk forever with no signal.

**SNMPv3 `msgMaxSize`.** A v3 GETBULK response fits the smaller of the link-MTU-derived budget and the `msgMaxSize` the requester declared (RFC 3412 §7.1). A declaration below 484, the floor RFC 3412 §7.2 sets, is malformed and is ignored. Single-binding v3 GET and GETNEXT responses do not consult `msgMaxSize`; they cannot approach either bound.

### A malformed variable-bindings list discards the request

A variable-bindings list that is not a valid ASN.1 encoding makes the whole PDU malformed, and RFC 1157 §4.1 (step 1) and RFC 3412 §7.2 discard such a datagram rather than answering it. nl6 does the same for SNMPv1 and v2c GET, GETNEXT and GETBULK: no response datagram is sent at all.
Once the list header has been read, the parser checks the list length against the datagram, each binding's framing, the name's tag, length and content, and that exactly one value follows the name; any of those failing discards the request.
The first such discard on a device is logged once; RFC 3412 would count it in `snmpInASNParseErrs`, which nl6 does not serve.

Until nl6#537 the offending binding was silently dropped and the rest of the request was answered, so a GET carrying three bindings came back with two. RFC 3416 requires the response's bindings to correspond to the request's, and a collector had no way to tell which one had gone missing.
A GETNEXT with a malformed name was answered as a walk restart from `sysDescr.0`, an OID the requester never sent.

A PDU whose variable-bindings list is empty, or whose envelope cannot be read as far as the list, is a different case and is still answered.
The general request parser falls back to `sysDescr.0` for it, so what comes back is one binding the requester did not name; that behaviour predates nl6#537 and is unchanged.

The SNMPv3 path behaves the same way since nl6#547.
A malformed scoped PDU is discarded there too, and a request that fails to DECRYPT — which used to share the same fallback and be answered with `sysDescr.0` — is answered with a `usmStatsDecryptionErrors` Report, as RFC 3414 §3.2 step 8 requires.
The two faults take opposite answers, discard against answer, which is why they had to be told apart before either could be right.
Two differences from the v1/v2c rule are worth knowing.
The v3 gate is broader: a PDU type nl6 does not serve (SET, INFORM, TRAP, Report) and an empty variable-bindings list are discarded too, where v1/v2c answers the empty list from its default OID, and only the first binding's name is validated.
And a PRIV-flagged request to a device configured without privacy is neither malformed nor a decryption failure; it is answered with a `usmStatsUnsupportedSecLevels` Report (RFC 3414 §3.2 step 5).
Every Report goes out unauthenticated with request-id 1 and the request's `msgID` echoed; on a decryption failure the real request-id is inside the ciphertext.

## Malformed-datagram handling

Every simulated device answers from one process, and the request path is a hand-written BER parser rather than `encoding/asn1`.
A panic in it is therefore not a per-device fault — it unwinds the listener goroutine and takes the whole fleet down mid-run.
The parsers are consequently required to be **total**: any byte sequence must produce a value or an error, never a panic.

There is deliberately **no `recover()`** on the request path.
A blanket recover would convert a parser defect into a silently dropped datagram, which is indistinguishable from a network drop and hides the bug for as long as it exists.
The fuzz targets in `snmp_parser_robustness_test.go` hold the guarantee instead, each seeded with the input that previously crashed it.
`go test` replays every seed on an ordinary run, so a regression fails the normal suite rather than only a fuzzing session.

That guarantee was measured rather than assumed ([nl6#513](https://github.com/labmonkeys-space/nl6/issues/513)).
The spike's figures were 21 targets over all 57 `parseLength` / `skipLength` call sites on seed replay alone, up from five, so an ordinary `go test` reaches every one of them.
Both numbers have since moved and are kept as the spike's historical record rather than as current counts: the census is 68 call sites and the package defines 24 targets, re-counted mechanically (`grep -h "^func Fuzz" *_test.go | wc -l`, and occurrences of `\b(parseLength|skipLength)\(` in the non-test files less the two definitions).
The nl6#527 unwrap added a 58th site on the decrypt branch, reachable only with privacy configured; a twenty-second target, `FuzzHandleSNMPv3RequestPriv`, seeds it with a genuinely encrypted GET per privacy protocol and a ciphertext whose plaintext carries a bad SEQUENCE length.
55 minutes of fuzzing across 80.6 million executions produced no panic.
That includes the INFORM acknowledgement parser, which had never been fuzzed and which any host that can reach a device's per-device UDP socket can feed: `readerLoop` does not check the source address, so no collector-address spoofing is needed.
The fuzz corpus those runs built is committed under `testdata/fuzz/`, so CI replays it too.

The no-`recover()` position above rests on that null result, and the result is **provisional**: the pre-registered rule asked for ten minutes of fuzzing per target, and 5 of the targets that existed then got that budget.
The verdict is strongest for the request path, the INFORM-ack path and the v3 scoped-PDU path, which are the five, and rests on seed replay alone for the other sixteen.

`parseLength` keeps its `-1` failure sentinel on the same evidence: 22.3 million executions confirmed it returns `-1` and never any other negative value, so screening for `< 0` at a call site is sufficient as well as necessary.

Two traps this parser family has fallen into, both worth knowing before editing it:

- **`parseLength` signals failure with `-1`, and `-1` passes an upper-bound check.** `if pos+n > len(buf)` is false when `n` is `-1`, so the guard admits the value and the slice expression that follows panics on an inverted range. Length checks need the `n < 0` arm as well.
- **A short-circuiting guard does not short-circuit its own error message.** `if pos >= len(data) || data[pos] != tag { return fmt.Errorf("... got 0x%02X", data[pos]) }` evaluates `data[pos]` whenever the branch is taken — including on the out-of-range case the check exists to catch.

### The envelope-parser defects

Panics are not the only failure a parser has.
A silent mis-parse has no oracle, so the fuzz targets also assert that the four readers of the v1/v2c envelope agree with one another ([nl6#534](https://github.com/labmonkeys-space/nl6/issues/534)).
`getPDUType`, `parseIncomingRequest`, `parseAllOIDsFromRequest` and `parseGetBulkParams` each walk the same version and community fields with their own code, so when two of them disagree at least one is wrong and no reference implementation is needed to say so.
Those assertions found three defects, all fixed here, and a fourth site was found by auditing for the same root assumption.
The assumption in every case is the same one: that the encoder was minimal.

[nl6#559](https://github.com/labmonkeys-space/nl6/issues/559) was served.
`getPDUType` stepped over the version INTEGER as a length skip plus a bare `pos++`, which assumes exactly one content octet.
SNMP is BER, not DER, so `02 02 00 01` is a legal encoding of version 1.
The cursor landed one octet short, the byte read as the PDU tag was the version's own content octet `0x01`, and `handleSNMPv2cRequest` dispatches on that byte — so a GETNEXT or a GETBULK carrying a non-minimally encoded version was answered from the GET branch while every other parser read the datagram correctly.
It now reads the declared length, in the same shape `parseIncomingRequest` uses.

The same assumption stood in three more places, and each was fixed with it.
The version VALUE was assigned only at `versionLen == 1`, so a padded v1 request parsed as v2c and silently lost every v1-specific behaviour: the Counter64 GET-divert and GETNEXT-skip (nl6#524) and the `noSuchName` sentinel diversion (nl6#517).
`isSNMPv3Request` and `parseSNMPv3Message` required the same one octet, so a padded v3 message was classified as v2c and read with `msgGlobalData` where a community belongs.
And the COMMUNITY length was read differently by the two readers: `getPDUType` bailed on an unreadable one while `parseIncomingRequest` stepped over it and carried on, which reproduced nl6#559's symptom one field later — a GETNEXT with real varbind names, dispatched from the GET branch.
All four now read each envelope field the same way, which is the rule this family is held to rather than any single fix.

[nl6#562](https://github.com/labmonkeys-space/nl6/issues/562) is the same assumption on the request-id, and it was found by the live-fuzz campaign these fixes exist to unblock.
`parseIncomingRequest` documented a 1..4 content-octet bound and did not advance past a wider field, and a padded five-octet request-id is legal BER and is what an encoder emits for any value at or above 2^31.
The cost is not the request-id: every field after it is read from the wrong offset, and on the datagram the fuzzer found that decodes an OBJECT IDENTIFIER sitting inside the PDU as the first varbind name.
It is now read with `parseBERInt` at any width, which also makes it signed, as RFC 3416's Integer32 requires.

[nl6#560](https://github.com/labmonkeys-space/nl6/issues/560) is the `-1` trap above, in the `parseGetBulkParams` envelope walk.
Three declared lengths were added to the cursor with no `< 0` arm, so a failed length read moved it BACKWARD onto a byte already consumed.
On the reproducer that byte is a community length octet of `0xa5`, which is also the GETBULK tag, and the function reported non-repeaters 12336 for a datagram that carries no GETBULK PDU at all.
All seven of its length reads now test the sign, the two container lengths additionally BOUND the walk to what they declare (the nl6#537 rule), and the same fault one message layer up in `extractRequestIDFromScopedPDU` was fixed with them.

Three of those seven guards have a behavioural witness and four do not, and the reason is structural rather than a missing test.
On a failed read `parseLength` leaves the cursor on the offending length octet, so for the next branch to misfire that octet must both fail `parseLength` and equal the tag the branch expects.
That is possible only at the community field, whose next branch tests for `0xA5` — a byte that declares 37 length octets and is also the GETBULK tag, which is exactly why the defect was found there.
`TestParseGetBulkParamsBailsOnEveryUnreadableLength` states this per guard; the four without a witness are defence-in-depth and are kept so the rule needs no exceptions.

A note on `02 00`, a version INTEGER with no content octets: it is NOT legal BER (X.690 §8.3.1 requires one or more content octets).
It is served anyway, leniently, because all four readers step over zero octets and agree on where the PDU begins; discarding it under RFC 3412 §7.2 would also be defensible.
The consequence is that no version value is read, so such a request is answered as v2c.

Exposure is hardening rather than a field report: net-snmp and snmp4j both emit minimal versions and request-ids below 2^31, so no shipped manager is known to produce any of these encodings.
What did produce them is nl6's own fuzzer, and the two committed corpora had been replaying instances of nl6#560 on every CI run without noticing, because the targets measured panics only.

All five reproducers are committed fuzz seeds, so an ordinary `go test` replays them.
The nine fuzz targets that read a v1/v2c datagram were then run live for 180 seconds each, 43.5 million executions in total, with no find.
That campaign predates nl6#542, which changed the serve path for GETNEXT — one of the three PDU types those targets reach — so its executions do not cover the multi-binding walk; seeds for that shape were committed with the change and replay on every ordinary `go test`.
The campaign before nl6#562 was fixed had been recorded as clean and was not: one target failed an agreement assertion 33 seconds in, on an input that then failed deterministically on replay, and two shorter runs had missed it.
`TestWellFormedResponsesUnchangedOnTheWire` pins the other side: responses to well-formed minimal datagrams hash to a digest computed against the pre-change tree, so the fixes are observable only on the encodings that were mis-parsed.
The corpus is 432 datagrams; the digest covers 360 of them, because nl6#542 made a multi-binding GETNEXT answer every binding and its response changed by design.
That shape is excluded and the digest was re-derived against the nl6#542 baseline rather than updated in place, so it is still a pre-change measurement.
Everything else — GET and GETBULK at any binding count, and the single-binding GETNEXT that is essentially all real GETNEXT traffic — is still byte-identical, including the single-binding Counter64 and past-the-end corners that nl6#542 touched.
The 72 excluded datagrams are not left unpinned: `TestMultiBindingGetNextResponsesArePinned` freezes them against the new behaviour, so a further move of that shape has to be deliberate.

## OID lookup internals

OIDs are stored per-device in a `sync.Map` for lock-free O(1) reads under
concurrent load. Pre-computed next-OID mappings avoid scanning the table for
`GETNEXT` / `GETBULK` — each OID has a direct pointer to its lexicographic
successor. Request buffers come from a shared pool to reduce GC pressure on
SNMP-heavy workloads.

OIDs in resource files may be written with or without a leading dot — the
loader normalises them to the net-snmp convention (`.1.3.6.1…`) at startup.

## Dynamic IF-MIB counters

Every per-interface counter listed below is generated dynamically by
`go/nl6/if_counters.go:IfCounterCycler`:

**ifXTable Counter64 HC columns** (`.1.3.6.1.2.1.31.1.1.1.X`):

| Column | OID column | Derivation |
|--------|-----------|------------|
| `ifHCInOctets` | `.6` | master dial (sine wave, 60 – 100 % of `ifHighSpeed` / `ifSpeed`, 1 h period) |
| `ifHCInUcastPkts` | `.7` | `baseInUcast + (inDeltaOctets / pktSizeIn) × ucastRatioIn` |
| `ifHCInMulticastPkts` | `.8` | same shape, `mcastRatioIn` |
| `ifHCInBroadcastPkts` | `.9` | same shape, `bcastRatioIn` |
| `ifHCOutOctets` | `.10` | outbound master dial |
| `ifHCOutUcastPkts` | `.11` | `baseOutUcast + (outDeltaOctets / pktSizeOut) × ucastRatioOut` |
| `ifHCOutMulticastPkts` | `.12` | same shape, `mcastRatioOut` |
| `ifHCOutBroadcastPkts` | `.13` | same shape, `bcastRatioOut` |

**ifXTable Counter32 shadow columns** — always equal to `uint32(HC_value & 0xFFFFFFFF)`:

| Column | OID column | Shadow of |
|--------|-----------|-----------|
| `ifInMulticastPkts` | `.2` | `ifHCInMulticastPkts` (`.8`) |
| `ifInBroadcastPkts` | `.3` | `ifHCInBroadcastPkts` (`.9`) |
| `ifOutMulticastPkts` | `.4` | `ifHCOutMulticastPkts` (`.12`) |
| `ifOutBroadcastPkts` | `.5` | `ifHCOutBroadcastPkts` (`.13`) |

**ifTable Counter32 columns** (`.1.3.6.1.2.1.2.2.1.X`):

| Column | OID column | Derivation |
|--------|-----------|------------|
| `ifInOctets` | `.10` | shadow of `ifHCInOctets` (ifXTable `.6`) |
| `ifInUcastPkts` | `.11` | shadow of `ifHCInUcastPkts` (`.7`) |
| `ifInDiscards` | `.13` | `baseInDisc + inDeltaPkts × discPpmIn / 1e6` |
| `ifInErrors` | `.14` | `baseInErr + inDeltaPkts × errPpmIn / 1e6` |
| `ifOutOctets` | `.16` | shadow of `ifHCOutOctets` (ifXTable `.10`) |
| `ifOutUcastPkts` | `.17` | shadow of `ifHCOutUcastPkts` (`.11`) |
| `ifOutDiscards` | `.19` | `baseOutDisc + outDeltaPkts × discPpmOut / 1e6` |
| `ifOutErrors` | `.20` | `baseOutErr + outDeltaPkts × errPpmOut / 1e6` |

`ifInOctets` and `ifOutOctets` became cycler-driven in nl6#570.
Before that they were the only IF-MIB counter columns served from the profile JSON, frozen, while their HC columns climbed from `ifSpeed` — so a rate computed from them was 0 bps forever, and they contradicted the 64-bit columns on the same interface.
The 1322 static entries the cycler now shadows (661 `ifInOctets` + 661 `ifOutOctets`, across 20 profiles) were deleted in the same change, because `findResponse` consults the cycler before the static map and an unreachable entry that looks authoritative is what let the defect survive.
`snmp_shipped_octet_shadow_ledger_test.go` records every deleted row and reverses it to reproduce the parent corpus digest.

**What the RFC actually says, and what is nl6's choice.**
RFC 2863 does not define `ifInOctets` as the low 32 bits of `ifHCInOctets`, and an earlier version of this page said it did.
The ifXTable DESCRIPTION of `ifHCInOctets` calls it "a 64-bit version of `ifInOctets`", and §3.1.6 mandates only which *width* an agent must serve at which speed: 32-bit octet counters at or below 20 Mb/s, 64-bit octet counters above it, and 64-bit packet counters at or above 650 Mb/s.
A conforming agent may hold the two counters independently.
Deriving one from the other is nl6's deliberate choice — it is the de-facto convention real agents follow, and it makes the two columns unable to contradict each other, which is what a collector cross-checking them assumes.

**The identity is exact for a shared evaluation instant, and only then.**
`IfCounterCycler.GetDynamicAt(oid, t)` takes the instant from the caller, so a caller that passes one `t` across several columns gets values that satisfy `shadow == uint32(HC & 0xFFFFFFFF)` byte for byte.
The sFlow `counter_sample` path and gNMI both do that.
The per-OID SNMP path does **not**: `findResponse` calls `GetDynamic`, which reads the clock itself, and `NextDynamicOID` re-reads it per walk step.
So a multi-varbind GET, or a GETNEXT/GETBULK spanning `ifInOctets` and `ifHCInOctets`, evaluates the dial once per varbind and the two values differ by whatever accrued in between — at 400 Gb/s roughly 5×10⁷ octets per millisecond of drift.
That is a property of the read API, not of the derivation.
Capturing one instant per SNMP request would remove it and is a larger change than nl6#570 took on; the scope is stated here rather than claimed away.

**The compiled-in fallback profile.**
`createDefaultResources` is written whenever a named resource file is absent, and it used to ship static `ifInOctets.1` / `ifOutOctets.1` with no `ifHCInOctets` row — so no cycler was published for it and both values were served frozen, the defect this change removes, on a production path the corpus guard cannot see because it reads only `resources/`.
It now ships `ifHCInOctets.1` / `ifHCOutOctets.1` instead and derives all four octet columns.
Do not add a static `.10` / `.16` row back to that set: with the HC rows present it would be unreachable.

**What fires if a profile loses the columns.**
`TestEveryInterfaceAnswersBothOctetColumns` walks every shipped profile, builds a device with a live cycler, and requires the serve path to answer both columns for every ifIndex the profile describes via `ifDescr` — 1774 instances today (the 1322 formerly static rows plus the 452 newly served).
The cycler's ifIndex set comes only from `ifHCInOctets` rows, so a profile edit that adds interfaces without one drops both columns for those interfaces.
That test names the missing `ifHCInOctets.<N>` row; the corpus digests would only tell you to re-pin them, which would absorb the regression.

**Fleet-visible surface change.**
28 profiles ship `ifHCInOctets` rows but only 20 shipped static `ifInOctets`/`ifOutOctets`, so 8 profiles *gain* two columns per interface — **452 OIDs that no profile served before**: `cisco_catalyst_9500` +96, `cisco_nexus_9500` +128, `juniper_mx960` +160, `palo_alto_pa3220` +32, `dell_emc_unity` +10, `netapp_ontap` +10, `pure_storage_flasharray` +10, `linux_server` +6.
On the other 20 the columns moved from static to dynamic with no change in count, because every one of them shipped exactly one static row per HC row — so an `ifTable` walk of `cisco_crs_x`, the widest profile at 144 interfaces, returns the same number of OIDs as before and walk-step and SNMP-walk CPU figures taken on it stay comparable.
Figures taken on any of the 8 profiles above do not (nl6#517's convention).

Properties common to every dynamic counter:

- **Monotonic.** The underlying octet integral never decreases (rate
  floor is 60 % of `ifSpeed`), and every derivation is
  base-plus-growth, so Counter64 columns are strictly increasing.
  Counter32 shadow columns wrap naturally at 2³²; `ifCounterDiscontinuityTime`
  stays at 0 — wrap is inherent, not a discontinuity.
- **Pre-seeded.** Each counter starts at a base derived from ~24 h
  of traffic, ratios, and the active error scenario (see below) so a
  fresh device doesn't look unrealistically pristine.
- **Per-interface variance.** Packet-size divisor jitters ±20 % around
  500 B; mix ratios jitter ±3 % around 85 / 10 / 5 (in) and 90 / 8 / 2
  (out); error / discard ppm values are drawn once from the scenario
  band — all deterministic from the device seed.
- **Sine-driven correlation.** All derived counters share the master
  octet sine wave, so when a link is "quiet" (60 % of `ifSpeed`) the
  full counter family slows together — matching how real hardware
  behaves under reduced traffic.
- **SNMP ↔ sFlow agreement.** Both read paths resolve the same
  `IfCounterCycler` dispatcher, so an sFlow `counter_sample` and an SNMP
  GET evaluated at the same instant carry the same values. "The same
  instant" is exact for the sFlow path, which captures one `t` and passes
  it to every column; the SNMP path reads the clock per OID, so two
  varbinds in one response are two instants (see above).
- **Zero-goroutine cost.** Every counter is computed on-demand from
  the current time against analytic formulas — no per-interface
  goroutine, no polling loop.
- Values are visible on both `GET` and `GETNEXT` / `GETBULK`.

**Counter32 wrap guidance.** The fastest-wrapping objects on the device are the
two octet columns, and they are the first a collector trips over: `ifInOctets` /
`ifOutOctets` cover 2³² octets in about **3.4 s at 10 Gb/s** and about **86 ms at
400 Gb/s** (line rate; the dial's 60–100 % duty cycle stretches that by at most
two thirds). No poll interval makes a 32-bit octet counter usable at those
speeds, which is exactly why RFC 2863 §3.1.6 requires the 64-bit octet counters
above 20 Mb/s — poll `ifHCInOctets` / `ifHCOutOctets` instead. nl6 serves the
32-bit columns for fidelity, not because they are useful there.

The packet columns wrap more slowly: at 10 Gbps / 80 % util / 500 B avg
packet size, `ifInUcastPkts` wraps every ~26 minutes. At 100 Gbps
the same column wraps every ~2.6 minutes. Collectors handle the wrap
via the existing delta-modulo convention; but when your link is
≥1 Gbps you should prefer the Counter64 HC columns
(`ifHCInUcastPkts` etc.) to avoid missing a wrap on a slow poll cycle.

### Per-device error scenario

The `ifInErrors` / `ifOutErrors` / `ifInDiscards` / `ifOutDiscards`
rates are driven by a per-device scenario carried in `DeviceSimulator.IfErrorScenario`:

| Scenario | `errPpm` | `discPpm` | Typical dashboard appearance |
|----------|----------|-----------|------------------------------|
| `clean` *(default)* | `0` | `0` | Flat line at the baseline |
| `typical` | `10 – 100` | `20 – 200` | Faint steady slope (good production gear) |
| `degraded` | `1 000 – 10 000` | `2 000 – 20 000` | Visible error-rate alert candidates (0.1 – 1 %) |
| `failing` | `10 000 – 100 000` | `20 000 – 200 000` | Link-flap / bad-cable alarms (1 – 10 %) |

Set for the auto-start batch via the CLI flag `-if-error-scenario <name>`,
or per-device via `if_error_scenario` in the `POST /api/v1/devices` body.
See [CLI flags reference](cli-flags.md#interface-state-scenarios) and
[Web API reference](web-api.md#create-devices).

### Example walks

```bash
# Walk ifXTable — covers all HC counters, Counter32 shadows, and ifHighSpeed
snmpwalk -v2c -c public 192.168.100.1 1.3.6.1.2.1.31.1.1

# Walk ifTable — covers ifInOctets, ifInUcastPkts, ifInDiscards, ifInErrors,
# ifOutOctets, ifOutUcastPkts, ifOutDiscards, ifOutErrors
# (.10 and .16 are cycler-driven since nl6#570; before that they were frozen)
snmpwalk -v2c -c public 192.168.100.1 1.3.6.1.2.1.2.2.1

# Fetch HC in/out for interface 1 directly
snmpget -v2c -c public 192.168.100.1 \
  1.3.6.1.2.1.31.1.1.1.6.1 \
  1.3.6.1.2.1.31.1.1.1.10.1

# Continuous rate monitoring (poll every 10 s)
watch -n 10 "snmpget -v2c -c public 192.168.100.1 \
  1.3.6.1.2.1.31.1.1.1.6.1 1.3.6.1.2.1.31.1.1.1.10.1"

# Watch error / discard growth on a device deployed with -if-error-scenario failing
watch -n 5 "snmpget -v2c -c public 192.168.100.1 \
  1.3.6.1.2.1.2.2.1.14.1 1.3.6.1.2.1.2.2.1.13.1"
```

## Dynamic CPU / memory / temperature metrics

CPU, memory, and temperature OIDs cycle through a 100-point pre-generated
sine-wave pattern per device, driven by `metrics_cycler.go`. Per-category
device profiles define the baseline ranges and spike amplitudes; see
`device_profiles.go`. GPU servers add per-GPU metric cycling on top of this —
see [GPU simulation](gpu/index.md).

## Interface-state scenarios

The [`-if-scenario`](cli-flags.md#interface-state-scenarios) flag controls
the *initial* `ifAdminStatus` / `ifOperStatus` values reported across every
simulated interface. Scenario 4 uses a deterministic `ifIndex % 100 < n`
rule so results are reproducible across restarts.

```bash
# Spot-check admin status (should all be "1" in scenarios 2/3/4)
snmpwalk -v2c -c public 192.168.100.1 1.3.6.1.2.1.2.2.1.7

# Verify oper status after scenario 3 (all-failure)
snmpwalk -v2c -c public 192.168.100.1 1.3.6.1.2.1.2.2.1.8
```

**Dynamic state engine (post-v0.8.0).** `ifOperStatus.<N>` (`.8`),
`ifAdminStatus.<N>` (`.7`), and `ifLastChange.<N>` (`.9`) are now served
live from the per-device interface state engine — not from the cached
JSON value. Two mutation sources update them at runtime:

- **Flap scheduler** — `-if-flap-scenario {clean|rare|typical|aggressive}`
  drives Poisson-distributed link flaps per (device, ifIndex). See the
  [interface state engine reference](interface-state.md).
- **REST control plane** — `POST /api/v1/devices/{ip}/interfaces/{N}/{oper,admin}-status`
  flips state for test-harness use.

Cross-protocol consistency: SNMP `ifOperStatus.<N>` and gNMI
`/interfaces/interface[name=*]/state/oper-status` read from the same
slot table and agree byte-for-byte at every instant. The trap and
syslog catalog firings remain decoupled (Tier C follow-up).

**RFC 2863 note on `ifLastChange`.** Strict reading of RFC 2863 specifies
`ifLastChange` as "value of sysUpTime at the time the interface entered
its current operational state". The simulator computes the value relative
to the per-device state-engine construction time, not the SNMP agent's
`sysUpTime`. Today these epochs coincide (state engine constructs once,
during device boot, guarded against re-init by a panic). If a future
"reload scenario" feature is added, this divergence must be re-examined.

**SNMP / gNMI timestamp resolution divergence on `ifLastChange`.** SNMP
encodes `ifLastChange` as `TimeTicks` (centiseconds of sysUpTime), so two
transitions less than 10 ms apart collide to the same wire value. The
gNMI `state/last-change` leaf exports the engine's nanosecond timestamp
directly, so the same two transitions are distinguishable there. Under
the `aggressive` flap scenario (mean ≈1 min) the collision is
statistically irrelevant, but a custom test harness driving back-to-back
REST POSTs against the same `(device, ifIndex)` can observe the
divergence: SNMP `ifLastChange` returns the same TimeTicks value across
both transitions while the gNMI leaf separates them by their actual
nanosecond delta.

## Entity MIB and vendor OIDs

Every network device ships with a properly aligned Entity MIB: chassis, line
cards, power supplies, fans, and temperature sensors — plus the
`entAliasMappingTable` linking physical ports to logical interfaces.
Vendor-specific OIDs (Cisco, Juniper, Arista, NVIDIA, etc.) are provided per
device type under `go/nl6/resources/<device>/`. See
[Resource files](resource-files.md) for the JSON schema and
[Device types](device-types.md) for the catalog.

## Notifications (trap / INFORM)

SNMP defines both a request/response path — the GET / GETNEXT / GETBULK /
SET operations documented above — and a push path where a device initiates
a notification to a monitoring collector. nl6 implements the push
path for SNMPv2c only: fire-and-forget TRAPs (PDU `0xA7`) and
acknowledged INFORMs (PDU `0xA6`). SNMPv1 traps and SNMPv3 notifications
are deferred.

See [SNMP trap reference](snmp-traps.md) for wire format, the JSON
catalog schema, and the HTTP endpoints, and
[SNMP trap / INFORM export (operator guide)](../ops/snmp-traps.md) for
enabling the feature and the `snmptrapd` smoke test.
