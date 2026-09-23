# SNMP reference

nl6 answers SNMP v1, v2c and v3 queries on UDP port 161 (override with [`-snmp-port`](cli-flags.md#core-flags)) for every simulated device.
See [Architecture](../explanation/architecture.md) for the component map.

## Protocol coverage

- **SNMP v2c**: `GET`, `GETNEXT`, `GETBULK` against the full per-device OID table, and `SET` on one writable object, `ifAdminStatus.<N>` (see [SetRequest](#setrequest)). Community string is `public` by default.
- **SNMPv1**: `GET`, `GETNEXT` and `SET`. No `GETBULK`, no Counter64 and no exceptions: where v2c returns an exception, v1 returns `noSuchName`, and a `GETNEXT` skips Counter64 columns rather than failing. See [SNMPv1 never returns a Counter64](#snmpv1-never-returns-a-counter64).
- **SNMPv3**: enable with [`-snmpv3-engine-id`](cli-flags.md#snmpv3-flags). Auth protocols: `none`, `md5`, `sha1`. Privacy protocols: `none`, `des`, `aes128`. All three security levels work and are verified against net-snmp, see below.

### Verified against net-snmp, not only against nl6's own parser

**Why this check counts for more than the rest of the suite.**
Every security level below was polled with `snmpget` from net-snmp, which discovers the engine, derives its own key from the password and the engine ID it received, verifies nl6's digest, and builds its own decryption IV.
That check runs on every push, against net-snmp 5.9.4.
To run it yourself:

```
make test-interop
```

It matters more than the rest of the suite put together.
Every other v3 test reads nl6's output with nl6's own parser, so a shared misreading of RFC 3414 passes all of them.
Only an outside manager can catch that class of fault.

### SNMPv3 USM conformance

USM is implemented per RFC 3414:

- **Key derivation** is §A.2's password-to-key followed by localization `H(Ku || engineID || Ku)`, against the raw engine-ID **octets**. The four RFC 3414 Appendix A.3 vectors are asserted from a checked-in extract of the RFC, not from nl6's own output.
- **Authentication** is HMAC-MD5-96 or HMAC-SHA-96 over the whole message with `msgAuthenticationParameters` zero-filled, truncated to 12 octets (§6.3.1). A `noAuthNoPriv` message carries a zero-**length** field.
- **Privacy keys** are derived from `priv_password`, falling back to `password`, and localized with the **authentication protocol's** hash (§2.6).
- **DES** builds `IV = salt XOR pre-IV` from the last 8 octets of the 16-octet localized key (§8.1.1.1). **AES128** builds its IV from the engine boots and time carried in the message (RFC 3826 §3.1.2.1).
- **Inbound messages are verified**: a wrong digest is answered with a Report naming `usmStatsWrongDigests`, a stale one with `usmStatsNotInTimeWindows` (the §3.2 150-second window), and an authenticated request to a device configured without auth with `usmStatsUnsupportedSecLevels`.

So nl6 can be used to test a collector's wrong-credential handling.

**What is still not implemented:** SNMPv3 **INFORM**, and the SHA-2 auth protocols and AES-192/256 privacy of RFC 7860 / RFC 3826 §3.1.2.2.

SNMPv3 *traps* are served.
See [notifications](#notifications-trap--inform).
An INFORM is authoritative at the receiver, so nl6 refuses a v3 INFORM rather than sending one it cannot answer for.


### SNMPv3 auth / priv matrix

"Verified" means a real `snmpget` from net-snmp completed against nl6.
Every row is polled on every CI run.

| Auth  | Priv    | Security level  | Status |
|-------|---------|-----------------|--------|
| none  | none    | `noAuthNoPriv`  | verified |
| md5   | none    | `authNoPriv`    | verified |
| sha1  | none    | `authNoPriv`    | verified |
| md5   | des     | `authPriv`      | verified |
| sha1  | des     | `authPriv`      | verified |
| md5   | aes128  | `authPriv`      | verified |
| sha1  | aes128  | `authPriv`      | verified |

Both hashes are polled against both privacy protocols deliberately: the localized privacy key is 16 octets under MD5 and 20 under SHA1, and the DES and AES paths slice it at fixed indices, so a mistake there is invisible under one hash and fatal under the other.

`-snmpv3-priv` requires `-snmpv3-auth`.
USM defines no privacy-without-authentication level, and since the privacy key is localized with the authentication protocol's hash there is no key to derive without one.
A device created over REST with that combination is refused with a 400. The CLI flags are **not** validated together, so `-snmpv3-priv aes128` with `-snmpv3-auth none` starts and then fails on every encrypted request.

### Two engine-identity limitations

Neither affects a single-device poll, and both are worth knowing before pointing a manager at a large fleet.

- **`snmpEngineID` is fleet-wide.** `-snmpv3-engine-id` gives every device the same value, while `msgAuthoritativeEngineBoots` and `msgAuthoritativeEngineTime` are per device. RFC 3411 wants the engine ID unique per engine, so a manager that caches `(boots, time)` keyed on engine ID will see its estimate move as it polls devices started at different instants.
- **`msgAuthoritativeEngineBoots` is always 1 and is not persisted.** After a restart nl6 advertises `boots=1` again with the time back near zero, where RFC 3414 §2.2.3 would increment boots. A manager holding a cached estimate sees time move backwards under unchanged boots and has to rediscover. The `usmStatsNotInTimeWindows` Report nl6 sends is authenticated precisely so that recovery is possible.

Per-device SNMPv3 credentials can be supplied when creating devices via the REST API.
See [Web API → Create devices](web-api.md#create-devices).

### On a read, the community string is echoed and never checked

nl6 does not authenticate a poll on the community: it parses the value, answers the request, and echoes the same value back in the response.
There is no ACL and no rejection path for a read, by design.
This is a simulator for collector validation, not an access-control surface.
The boundary is the network namespace the devices live in.

**A `SET` is different, and the asymmetry is deliberate.** A write requires the device's configured write community, which defaults to empty and therefore admits nothing.
See [write admission](#write-admission-for-a-set) for the whole rule.

nl6 will check a community on a write and not on a read, which is not how any real agent behaves.
That is a scope boundary rather than an oversight: a `SET` mutates state, fires link traps and syslog and is visible to gNMI, while a poll returns simulated data to whoever asked.
Gating reads would change every collector-validation workflow the simulator exists for.
Gating writes changes only the workflows that write.

A **zero-length** community is legal and is parsed as the empty string, not as absent.
Both shipped clients emit one on request: net-snmp and snmp4j each send `04 00` for `-c ""`. nl6 answers with an empty community rather than substituting `public`.
A community of 128 octets or more encodes its length in BER long form (`04 81 c8`), which is parsed correctly on every path.

Golden fixtures for these cases are verbatim bytes captured from net-snmp and snmp4j, which matters.
Every other SNMP test in the package builds its input with nl6's own encoders, so encoder and parser can share a misconception and still agree.
The empty-community defect survived exactly that blind spot.

### Unimplemented OIDs return an exception, not a value

An OID absent from a device's profile is answered with the RFC 3416 `noSuchObject` exception, not with a string.
The exception is the context-specific tag `80 00` in the variable binding's value position.
`error-status` stays `noError`: the response is a success and the exception is per-varbind (§4.2.1).

Only `noSuchObject` is ever emitted, never `noSuchInstance`.
The standard separates the two by OID prefix registration, and a profile is a flat OID→value map with no MIB registry, so nl6 cannot evaluate that test.
`noSuchObject` is the only answer it can defend.

**SNMPv1 has no exception values.** A v1 request that would produce one gets `error-status = noSuchName(2)` instead, with `error-index` set to the offending variable binding and every requested name echoed with a NULL value, per RFC 3584 §4.2.2.2 (§4.2.2.2.1 for `noSuchObject`, §4.2.2.2.2 for the `endOfMibView` a v1 GETNEXT reaches past the last OID).
The mapping applies to GET and GETNEXT only.
GETBULK does not exist in SNMPv1, so a version-0 GETBULK is malformed and is answered as before rather than mapped: its bindings are walked OIDs, not the request's names, and there can be `max-repetitions × columns` of them.

**SNMPv3 GET and GETNEXT are covered.** The v3 encoder goes through `encodeTypedValue` too, so a v3 GET for an absent OID returns the `80 00` tag and a v3 GETNEXT past the last OID returns `82 00`.
The v3 GETBULK handler reaches the same encoder through `createScopedPDUMulti`, so its bindings carry the same tags.
It honours `max-repetitions` and `non-repeaters` as sent, and it answers every column the request names.
A request for zero repetitions is answered with an empty binding list, not an `endOfMibView`.

The exceptions are carried as sentinel strings (`noSuchObject`, `endOfMibView`) from the lookup to the encoder, where `encodeTypedValue` turns them into tags.
That puts them in the value space: a resource file whose legitimate value were literally `noSuchObject` would encode as an exception, and a v1 manager would get `noSuchName` for a value that is a plain string.
Removing the hazard at the root needs a typed value rather than a string, which is a larger change.
Until then the resource-file route to it is closed at load time.

### The first OID sub-identifier is a varint

X.690 §8.19.4 packs the first two arcs of an OID into a single sub-identifier valued `40*first + second`, encoded as a base-128 varint like every other one.

The round-trip held only while the second arc stayed below 40, and fabricated silently above it:

| OID | went out as | now |
|---|---|---|
| `3.40.1` | `.4.0.1` | degenerate `06 00`, first arc 3 is not representable |
| `2.87.1` | `.4.7.1` | round-trips |
| `2.175.1` | `.6.15.1` | round-trips |
| `2.999` | `.1.15` | round-trips |

That is valid-looking BER carrying an OID nobody wrote, which a collector has no way to detect.
`2.999` is the ITU test arc and is perfectly legal.
It could not be expressed before.

An OID the encoder cannot represent faithfully now takes a degenerate encoding, `06 00`, rather than becoming a different OID.
That encoding is itself non-conformant: X.690 §8.19.1 requires at least one sub-identifier, so nl6 emits bytes its own decoder refuses.
The trade is deliberate and worth stating plainly.
A wrong-but-well-formed OID is undetectable and gets recorded as fact.
A malformed one is visible to any decoder, and in a `snmpTrapOID.0` or `sysObjectID` position a collector will reject the message rather than believe it.
Refusing to build the message at all would be better still, but that needs an error return through seven varbind-name call sites.
It is not implemented yet.
The OCTET STRING fallback asked for in a value slot (the way `encodeIPAddress` already degrades an unparseable address) is also still open: `encodeTypedValue`'s OID branch returns the same `06 00`, so a `sysObjectID` of `unknown` still goes out as a degenerate OID rather than as a string.
That covers a first arc above 2, a second arc above 39 when the first is 0 or 1 (a wider one would be indistinguishable from a higher first arc, since `1.40` and `2.0` both compute 80), a combined first sub-identifier or any later arc above 2^32-1, and any component that is not a number.

The decoder is stricter too, because it parses bytes that arrive from the network.
A sub-identifier whose final byte still sets the continuation bit is truncated, and is refused.
A sub-identifier wider than 2^32-1 is refused.
A non-minimal sub-identifier, one whose leading octet is `0x80` (X.690 §8.19.2), is refused too.
Otherwise an attacker could pad any OID with continuation bytes and produce unbounded distinct byte strings that all decode to one OID.

Nothing that ships with nl6 changes on the wire: every OID across the resource files and trap catalogs encodes to exactly the same bytes as before.

### SNMPv3 authPriv requests are served

An authPriv request is answered for the OID and PDU type it asks for, and net-snmp drives every authPriv row end to end.
See [the auth/priv matrix](#snmpv3-auth--priv-matrix).

A request whose scoped PDU genuinely fails to decrypt is answered with a `usmStatsDecryptionErrors` Report (see [malformed datagrams](#malformed-datagram-handling)).

The discovery Report carries `usmStatsUnknownEngineIDs.0` as a Counter32, the type RFC 3414 §5 gives it.
The value is a fixed `1` and does not count unknown-engine-ID events.

### SNMPv1 never returns a Counter64

Counter64 does not exist in SNMPv1, and the response encoder picks the ASN.1 tag from the OID alone, so a v1 request for an `ifHC*` column needs diverting rather than encoding.

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
- **Coverage is bounded by the type table.** It has been widened: the Counter64 objects nl6 recognises are now the eight `ifXTable` HC columns, the fourteen HC columns of each of the two RFC 4293 IP statistics tables (`ipSystemStatsTable`, `ipIfStatsTable`) and all six columns of the RFC 3635 `dot3HCStatsTable`, 42 columns in total. The column numbers were read out of the shipped IP-MIB and EtherLike-MIB with `snmptranslate`, not recalled. A 64-bit counter served under any OID outside that set is not recognised as Counter64. A v1 request for it is answered with a value rather than diverted. A **vendor** HC column is the case that matters. Widening a type table changes what goes on the wire for every OID matching a new row, so it was measured rather than argued: a digest hashes the (profile, OID, emitted tag) triple of every shipped resource entry, and the digest taken before the widening still matches after it. **The effect on the shipped fleet is exactly zero.** No shipped profile serves any newly typed column, so the widening's value is entirely for operator-supplied files and for a future profile. The digest is keyed on the profile as well as the OID because a fleet-wide key hides a per-profile change: keyed by OID alone, the 31 tag changes this same change made to shipped data vanish entirely, since other profiles already produced those pairs. It hashes tags rather than encoded bytes, which is what keeps it stable across ordinary value edits. Every corpus test walks `resources/` recursively through one shared collector, and the two views of the tree cross-check each other. A single-file profile is seen by the same walk as a directory profile. That matters because a profile can ship either way. A walk that saw only directories would miss the single-file `resources/<slug>.json` layout all four loaders accept, so a vendor 64-bit column in such a profile could pass the sentinel guard, this digest and the Counter64 pin. The only test that fired would then point the maintainer at re-pinning a golden digest, which absorbs a defect rather than reporting it.

### A GETNEXT answers every variable binding

RFC 3416 §4.2.2 defines GETNEXT over the whole variable-bindings list, and nl6 answers it that way.
Each binding carries the lexicographic successor of its own name, in request order.
A binding with nothing after it carries `endOfMibView` named with the OID that was asked for, so a walker fetching several columns per round trip can tell which column ended.

Two of the three behaviours below differ by version.
The third is the same either way, and is listed with them because all three are decided in one place.
The SNMPv1 Counter64 rule is the one that matters most.

| Case | SNMPv1 | SNMPv2c |
|---|---|---|
| The successor is a Counter64 object | that binding SKIPS it and continues to the next successor (RFC 3584 §4.2.2.1) | returned normally |
| Nothing follows the requested OID | the response diverts to `noSuchName` with `error-index` at the first such binding, and the request's own names echoed with NULL values | `endOfMibView`, named with the requested OID |
| The response will not fit the datagram | `tooBig` with an empty binding list | `tooBig` with an empty binding list |

The Counter64 asymmetry is described canonically in the section immediately above.
The row here is a summary, not a second definition.
A GETNEXT names a position, not an object, so diverting on a Counter64 successor would stop a v1 walk dead at the first `ifHC*` column and truncate the table with no signal.
A GET does divert there, because it names the object.
The two rules share one response encoder, so which one applies is an explicit argument at the call site (`v1DiversionRule`) rather than something the encoder infers.

Overflow is `tooBig` rather than truncation for the same reason it is on a GET: the manager named N positions and has no resume point for a binding a shorter response would drop.
A single-binding GETNEXT is bounded the same way and answers `tooBig` rather than emitting an over-budget datagram.
The change is not reachable with shipped resources, where no value approaches the budget, but it is reachable with an operator resource file carrying a value over roughly 1400 bytes.
The empty binding list under SNMPv1 is nl6's choice, not something RFC 1157 settles: §4.1.2 and §4.1.3 describe a `tooBig` response as "of identical form", which reads as echoing the request's bindings. nl6 sends none, so a `tooBig` cannot be mistaken for an answer.

The whole request takes ONE LLDP served-OID snapshot, shared across every binding and every step of a Counter64 skip run, so no two steps of one request can straddle a topology generation bump.

A version integer that is neither 0 nor 1 is served with SNMPv2c semantics rather than discarded, matching the leniency of the rest of this path.

#### The cost of a wide multi-binding GETNEXT

Answering every binding multiplies the walk, and on a wide profile that is measurable.
Timed on one machine through `handleSNMPv2cRequest` on `cisco_crs_x` with a live counter cycler, an SNMPv1 GETNEXT repeating one name just before the `ifHC*` block.
The **shape** is the point, not the absolute milliseconds, which do not travel between machines.
Cost grows with the binding count:

| Bindings | Request size | Time |
|---|---|---|
| 1 | 44 B | 2.9 ms |
| 10 | 209 B | 27.2 ms |
| 40 | 752 B | 104.3 ms |
| 68 | 1256 B (over the 1024 B read buffer) | 176.8 ms |

This runs inline on the shared UDP handler.
Two bounds contain it, and neither removes it:

- The binding count is clamped to what a response could ever fit (`maxSNMPResponseSize / minVarbindSize`, 98 at the default MTU). Above that the request is answered `tooBig` **without walking at all**, so no work is spent on a response that would be discarded. This is also the backstop that stops a larger read buffer from raising the work linearly.
- The SNMPv1 Counter64 skip steps of one datagram share a single budget, so the cost does not scale with a per-binding allowance. The budget is derived, not hand-set: `maxGetNextBindings × longestShippedCounter64Run`, which is exactly what the widest legitimate request needs, so it cannot truncate a real table. An operator resource file with a wider Counter64 run than any shipped profile is the one case it does not cover. Such a request is truncated and logged once per device.

`longestShippedCounter64Run` is 1152, eight `ifHC*` columns across 144 interfaces on `cisco_crs_x`.
It is measured by walking, not by scanning the static resource index.
The distinction is worth 4x: that profile ships static rows for `ifXTable` columns 1, 6, 10, 15 and 18 only, and `IfCounterCycler` serves the rest analytically, so the static index reports 288 while the walk crosses 1152.

### Shipped data fidelity

Whether a value is *encodable* is checked at load.
Whether it is *faithful to the vendor's MIB* is a separate question with a separate answer.
Both are on the [SNMP data fidelity](../explanation/snmp-data-fidelity.md) page.

## Response size, `max-repetitions` and truncation

An SNMP response is bounded so the resulting UDP **frame** fits the link: the payload ceiling is the MTU minus the IPv4 and UDP headers, 1472 bytes at the default MTU, and it moves with `-datagram-mtu`.
See [`-datagram-mtu`](cli-flags.md) for that flag.

**GETBULK truncates.** A response carrying more variable bindings than fit is cut to what fits, per RFC 3416 §4.2.3, with `error-status` left at `noError`.
The collector resumes the walk from the last OID returned.
That is how a walk already works, so nothing is lost and no data is skipped.

**GET does not truncate.** A GET response that will not fit is replaced by `error-status = tooBig(1)` with an empty variable-binding list, per RFC 3416 §4.2.1. A GET requester asked for specific bindings and has no resume point, so a partial answer would be a wrong answer it could not detect. nl6 supports multi-binding GETs (a collector may bundle several OIDs in one request) and returns every binding in request order when they fit.

### How response size scales

Size grows as `columns × repetitions`.
Measured against a device with 64 interfaces, walking the ten ifTable/ifXTable columns a collector typically requests:

| columns | max-repetitions | bindings | response | frame |
|---|---|---|---|---|
| 10 | 2 | 20 | 500 B | 528 B |
| 30 | 2 | 60 | 1436 B | 1464 B |
| 10 | 10 | 61 | 1470 B | 1498 B |
| 10 | 127 | 61 | 1470 B | 1498 B |
| 10 | 1000 | 61 | 1470 B | 1498 B |

Past roughly 60 bindings the response is truncated to fit, so raising `max-repetitions` further changes nothing about the datagram.
It only means the walk completes in fewer requests up to that point.

These byte figures were measured at the default MTU and are indicative.
What is enforced is the bound itself: a response always fits one un-fragmented frame.
Re-measure against your own `-datagram-mtu` before sizing a collector to the last byte.

The 30 × 2 row is the OpenNMS collector default (`max-vars-per-pdu` 30, `max-repetitions` 2).
It fits with 36 bytes to spare, which is why nothing fragments out of the box and why a slightly larger configuration used to.

### `max-repetitions` is honoured as sent

Any value is accepted and used, at any BER width.

A negative value is treated as 0, per RFC 3416's definition of the field as non-negative.

### SNMPv3 values are typed like v2c

Both versions encode a value through `encodeTypedValue`, so the same OID carries the same ASN.1 type whichever version answered.

### SNMPv3 GETBULK answers every column

`handleSNMPv3GetBulk` parses every variable-binding name from the scoped PDU and applies the RFC 3416 §4.2.3 split: the first `non-repeaters` columns get one successor each, and the rest are walked `max-repetitions` times, interleaved one binding per column per repetition.
A manager bundling `ifDescr`/`ifName`/`ifAlias` in one GETBULK gets successors for all three.
That single-column shape also forced `non-repeaters` to collapse into `max-repetitions = 1`, which is not what the field means: with non-repeaters present and `max-repetitions` zero, the non-repeater bindings are now returned rather than an empty list.

A column that reaches the end of its MIB view is padded with its OWN requested OID and `endOfMibView`, so the interleave stays aligned and a manager can still tell which column a slot belongs to.
The order and the padding match the v2c path, and the two are pinned against each other rather than each being separately plausible.

**A multi-column response is byte-identical to v2c, tail included.** The padding continues for every remaining repetition, exactly as v2c pads.
An earlier cut of this change stopped once every column was exhausted and reported the difference as an unavoidable divergence.
It was not.
The stop-instead-of-pad rule is keyed on LOOP SHAPE, not on protocol version, and it constrains the single-column loop only.

**The single-column loop still stops.** A v3 walk on one column that runs out mid-response ships what it collected, and the next request, collecting nothing, receives the exception on its own.
A first repetition that produced nothing is still emitted, so a single column already past the end of the MIB is answered with its own OID and `endOfMibView` rather than with an empty list.
Applying either rule to the other loop is pinned as a mutation.

One thing does still differ from v2c, and only on data that cannot load: a v3 column also ends on the `endOfMibView` sentinel and on a non-advancing successor, and names that binding with the requested OID, where v2c's non-repeater loop tests only for an absent successor.
Both extra exits are properties a shared walk must not lose.
`validateSNMPResourceValues` rejects the sentinel at load, and a non-advancing `oidNextMap` is a resource-file defect.

The walk clamp divides its ceiling by the repeater-column count, because a repetition costs one walk step per column and the guard bounds the TOTAL work, which is what it bounded when there was only ever one column.
A malformed variable-bindings list discards the datagram exactly as on the v1/v2c path.
The multi-column parse can only add discards (a LATER binding being the malformed one), never relax the discard rule.
It has its own log gate, separate from the dispatcher's malformed-scoped-PDU discard, so neither fault can silence the other.

**A declared container length that overruns what contains it is malformed, not absent.** That distinction is load-bearing rather than pedantic.
Classifying an overrun as *absent* would let one altered length byte silently shrink a well-formed three-column GETBULK to a single binding, while shortening the same byte was already malformed.
One lie, opposite verdicts in its two directions.
Every container is checked the same way, bytes between the end of the list and the end of the PDU are refused, and every bound is written so that a four-octet BER length cannot wrap an addition negative on a 32-bit build.

The column count itself has no explicit cap.
The repeater walk is bounded regardless, since the clamp divides by the column count, but the non-repeater loop is one walk step per column, and what bounds that is the 1024-byte read buffer.
The coupling is asserted in a test so a larger buffer has to acknowledge it.

### Known limitations

**An SNMPv3 GET or GETNEXT answers its first variable binding only.** `extractOIDAndTypeFromScopedPDU` validates and returns the first name in the scoped PDU's variable-bindings list, and the v3 handlers build a single-binding response from it.
So a v3 manager fetching several columns per round trip gets the first, as every version once did.
A v3 GETNEXT also calls `findNextOID` per request rather than sharing a served-OID snapshot across bindings, since there is only one.
Analogous to the v3 GETBULK gaps below, and tracked with them.

**SNMPv3 GETBULK is bounded by measurement, not arithmetic**.
The v2c path computes its response length from fixed prefixes, which it can because its envelope is fixed.
A v3 message cannot: its `msgGlobalData` and `msgSecurityParameters` sizes depend on the engine ID, the user name and the privacy parameters, and under privacy the scoped PDU is encrypted and PADDED to a cipher block.
So the GETBULK builder assembles the candidate response through the real encoder and measures it, dropping bindings from the end until it fits.
RFC 3416 §4.2.3 makes that correct: a truncated GETBULK is resumable, since the walker continues from the last OID returned.
As on the v2c path, at least one binding is always emitted even when it does not fit, because an empty binding list with no error stalls a walk forever with no signal.

**SNMPv3 `msgMaxSize`.** A v3 GETBULK response fits the smaller of the link-MTU-derived budget and the `msgMaxSize` the requester declared (RFC 3412 §7.1).
A declaration below 484, the floor RFC 3412 §7.2 sets, is malformed and is ignored.
Single-binding v3 GET and GETNEXT responses do not consult `msgMaxSize`.
They cannot approach either bound.

### A malformed variable-bindings list discards the request

A variable-bindings list that is not a valid ASN.1 encoding makes the whole PDU malformed, and RFC 1157 §4.1 (step 1) and RFC 3412 §7.2 discard such a datagram rather than answering it. nl6 does the same for SNMPv1 and v2c GET, GETNEXT and GETBULK: no response datagram is sent at all.
Once the list header has been read, the parser checks the list length against the datagram, each binding's framing, the name's tag, length and content, and that exactly one value follows the name.
Any of those failing discards the request.
The first such discard on a device is logged once.
RFC 3412 would count it in `snmpInASNParseErrs`, which nl6 does not serve.

RFC 3416 requires the response's bindings to correspond to the request's, and a collector had no way to tell which one had gone missing.

A PDU whose variable-bindings list is empty, or whose envelope cannot be read as far as the list, is a different case and is still answered.
The general request parser falls back to `sysDescr.0` for it, so what comes back is one binding the requester did not name.
That behaviour is older still and is unchanged.

The SNMPv3 path behaves the same way.
A malformed scoped PDU is discarded there too, and a request that fails to DECRYPT is answered with a `usmStatsDecryptionErrors` Report, as RFC 3414 §3.2 step 8 requires.
The two faults take opposite answers, discard against answer, which is why they had to be told apart before either could be right.
Two differences from the v1/v2c rule are worth knowing.
The v3 gate is broader: a PDU type nl6 does not serve (INFORM, TRAP, Report) and an empty variable-bindings list are discarded too, where v1/v2c answers the empty list from its default OID, and only the first binding's name is validated.
A `SET` is served at every version since the change that added it, and a malformed `SET` list is discarded under the same rule.
And a PRIV-flagged request to a device configured without privacy is neither malformed nor a decryption failure.
It is answered with a `usmStatsUnsupportedSecLevels` Report (RFC 3414 §3.2 step 5).
A Report carries request-id 1 and the request's `msgID` echoed.
On a decryption failure the real request-id is inside the ciphertext.

Two Reports are **authenticated**, and the rest are not.
A `usmStatsNotInTimeWindows` Report is signed so a manager can trust the engine time it carries and resynchronise, and a `usmStatsUnsupportedSecLevels` Report refusing a `SET` is signed when the request itself authenticated.
The others cannot usefully be signed: on a wrong digest or an unknown user there is no agreed key to sign with.

## SetRequest

Every `SetRequest` is answered with a `Response-PDU`, at SNMPv1, v2c and v3.

### The writable set

One object is writable: `ifAdminStatus.<N>` (`1.3.6.1.2.1.2.2.1.7.<N>`), INTEGER, values `up(1)`, `down(2)` and `testing(3)`.
A `SET` on it goes through the same interface-state funnel the REST `admin-status` POST uses.

`ifOperStatus.<N>` is **derived**, and the rule is asymmetric:

| `SET ifAdminStatus` | `ifOperStatus` becomes |
|---|---|
| `down(2)` | `down(2)`, forced |
| `testing(3)` | `testing(3)`, forced |
| `up(1)` | whatever the link state is: **released, not forced** |

So on an interface whose link is down, a `SET` of `up(1)` succeeds and `ifOperStatus` stays `2`.
That is not a rejected write: `ifAdminStatus` reads back `1`.
An administrative bounce does not repair a simulated link fault.

When the derived oper value does move, `ifLastChange.<N>` moves with it, a gNMI ON_CHANGE subscriber sees the admin update and then the oper update, and the transition fires the device's role-tagged link trap and syslog.
A following `GET` reads the new `ifAdminStatus`, and gNMI reads the same engine.
A `SET` to the value the interface already holds succeeds with `noError` and moves nothing.

Nothing else is writable: not `ifOperStatus` (read-only in RFC 2863), not the `system` group, not any counter the cycler serves.
The set is a curated table with a reason per row (`writableColumns` in `snmp_set.go`), never derived from a type table, because writability is a MAX-ACCESS property no nl6 rule models.

### The error ladder

Each binding is tested in RFC 3416 §4.2.5's order and the first failure names the binding in `error-index` (1-based).
Every binding is validated before any is applied, so a request in which one binding fails changes nothing.
In success and in every error case the response's variable bindings are the request's own bytes, values included, which is what §4.2.5 means by "identical to the request".

| Condition | v2c / v3 | v1 (RFC 3584 §4.3) |
|---|---|---|
| name is not `ifAdminStatus.<N>` and shares no writable prefix | `notWritable(17)` | `noSuchName(2)` |
| value tag is not INTEGER | `wrongType(7)` | `badValue(3)` |
| INTEGER content is not a valid encoding | `wrongEncoding(9)` | `badValue(3)` |
| value outside 1..3 | `wrongValue(10)` | `badValue(3)` |
| `<N>` is not an ifIndex the device owns, or the name has the wrong arity under the column | `noCreation(11)` | `noSuchName(2)` |

Two rows are worth reading twice.
The value tests run before the instance test, so `ifAdminStatus.999 = 7` is `wrongValue`, not `noCreation`.
And a name under the column with the wrong arity, the bare column or `...7.1.2`, is `noCreation` rather than `notWritable`: it shares the writable prefix but names a variable that could never be created.

The v1 answer is the RFC 3584 §4.3 mapping of the v2 verdict, computed once (`v1SetErrorStatus`), and `readOnly(4)` is never emitted.
A v3 `SET` produces the same `Response-PDU` bytes as a v2c `SET` of the same bindings.
Only the envelope differs.

### Write admission for a `SET`

:::caution[Writes are off by default]

A fleet booted with no `-snmp-write-community` answers **no** `SET` at v1 or v2c, and the default v3 minimum security level of `authNoPriv` refuses a `noAuthNoPriv` write.
`snmpset` against a default fleet does not work until you configure one of the two knobs below.

:::

A `SET` is admitted only when the request clears the gate for its version.
Reads are untouched at every version.

**SNMPv1 and SNMPv2c: the write community.**

| Setting | Where |
|---------|-------|
| `-snmp-write-community <string>` | seeds the `-auto-start-ip` batch |
| `write_community` | top level of the `POST /api/v1/devices` body |

The default is empty, which admits nothing.
A `SET` whose community does not match is **discarded**.
No datagram at all, which `snmpset` reports as `Timeout: No Response`.

That silence is what real hardware does, and it is the reason the device logs the cause once:

```
SNMP <device>: discarded a SetRequest: community does not match the configured write community (further refusals suppressed for this device)
SNMP <device>: discarded a SetRequest: no write community is configured, so no v1/v2c write is admitted (set -snmp-write-community, or write_community on the REST create body) (further refusals suppressed for this device)
```

The line is emitted at most once per device, because the condition is attacker-controlled and an ungated line is a log-flood primitive at 30k devices.
If `snmpset` times out against a device that answers `snmpget`, that log line is the answer.

**SNMPv3: the minimum security level.**

| Setting | Where |
|---------|-------|
| `-snmp-set-min-security-level none\|auth\|priv` | seeds the `-auto-start-ip` batch, default `auth` |
| `snmpv3.set_min_security_level` | the `snmpv3` block of the `POST /api/v1/devices` body |

`none` is `noAuthNoPriv`, `auth` is `authNoPriv`, `priv` is `authPriv`.
A `SET` below the minimum is answered with a `usmStatsUnsupportedSecLevels` Report, which is what RFC 3414 §3.2 step 5 prescribes and the same Report a privacy-flagged request to a no-privacy device already receives.

The two refusals have different shapes because the two protocols do, not because the decision drifted: v2c has no Report to send, and v3 has a prescribed one.

The Report is **signed when the request authenticated**, following the same request-driven rule USM verification follows.
A manager that got its key right and only its level wrong can therefore verify the refusal.
An unsigned Report carries the discovery shape, with no user name and no digest.
A strict manager discards that, turning a refusal the operator could act on into a timeout they cannot.
A `noAuthNoPriv` refusal is unsigned, because such a request demonstrates no key agreement to sign against.

The v3 user check and the USM verification a `GET` receives run **first**, so an unknown user still gets `usmStatsUnknownUserNames` and a wrong digest still gets `usmStatsWrongDigests`.
A manager is told which of those is wrong rather than being told about a security level it did in fact clear.

Every boot prints the policy in one line, so a timed-out `snmpset` has something to check against.
A default fleet:

```
SNMP write admission (auto-start batch; REST-created devices use the create body, not these flags) — v1/v2c SET: refused (no write community configured); v3 SET: minimum security level authNoPriv (SNMPv3 disabled)
```

With a write community set and SNMPv3 on:

```
… — v1/v2c SET: admitted with the configured write community; v3 SET: minimum security level authNoPriv
```

On a fleet with SNMPv3 enabled but `-snmpv3-auth none`, nothing can reach the default minimum, so no v3 `SET` is admitted at all.
The line says so rather than leaving a silent dead end:

```
… — v1/v2c SET: refused (no write community configured); v3 SET: minimum security level authNoPriv — UNREACHABLE: this fleet is configured with no authentication protocol, so no v3 SET can be admitted
```

Two things that line does not tell you, and both bite:

- It describes the **auto-start batch only**. A device created over `POST /api/v1/devices` takes its admission from the request body. Omit `write_community` there and that device refuses every v1/v2c `SET`, even on a fleet started with `-snmp-write-community`.
- The write community itself is never printed, and never appears in an API response. `GET /api/v1/devices` does not echo it.

**To restore the earlier behaviour exactly**, where any manager that could reach the port could write, run with `-snmp-write-community public -snmp-set-min-security-level none`.

**What this is not.** There is no read community, no VACM, no per-user or per-object write privilege, and no second v3 user.
Refusals are not counted anywhere a manager can poll: nl6 serves no part of the SNMP group (`1.3.6.1.2.1.11`), so a GET of `snmpInBadCommunityNames` answers `noSuchObject` like any other unimplemented OID.
A real agent increments that counter. nl6 does not model it.

### Interactions

The link state a `SET` of `up(1)` releases oper to is whatever last moved it: `-if-scenario 3`, a flap, or a REST `oper-status` POST.
No sequence of SETs can produce `ifAdminStatus = down(2)` with `ifOperStatus = up(1)`.

A `SET` is read back under every `-if-scenario`.
The scenario shapes the state engine's initial seed and nothing else, so a `SET`, a REST POST, a flap and the seed all move the same value that `GET`, a walk, gNMI and the REST view read.

### Verified against net-snmp

`make test-interop` drives `snmpset` and `snmpget` against the real dispatchers over a real UDP socket under v1, v2c and v3 authPriv, asserting the round trip and every error-status row by net-snmp's own printed reason, and `snmptrapd` receives the `linkDown` and `linkUp` the derived oper transition fires.
A captured `snmpset` datagram is kept as a golden fixture.
The read paths are unchanged, which the wire digest over well-formed GET, GETNEXT and GETBULK responses pins.

The refusals are asserted by the same target, because an in-package encoder and decoder that share one reading prove nothing about admission: a wrong-community `snmpset`, a `snmpset` against a device with no write community, and a `noAuthNoPriv` `snmpset` below the minimum.
Every one of those rows carries a **positive control on the same listener**.
That is a `snmpget` that must succeed, and where a write is possible at all, a `snmpset` with the right community that must succeed afterwards.
A timeout on its own cannot tell a refusal from a dead socket, so without the control these rows would pass against a build in which `SET` had been deleted entirely.

## Malformed-datagram handling

Every simulated device answers from one process, and the request path is a hand-written BER parser rather than `encoding/asn1`.
A panic in it is therefore not a per-device fault.
It unwinds the listener goroutine and takes the whole fleet down mid-run.
The parsers are consequently required to be **total**: any byte sequence must produce a value or an error, never a panic.

There is deliberately **no `recover()`** on the request path.
A blanket recover would convert a parser defect into a silently dropped datagram, which is indistinguishable from a network drop and hides the bug for as long as it exists.
Fuzz targets hold the guarantee instead, each seeded with an input that once crashed it.
`go test` replays every seed on an ordinary run, so a regression fails the normal suite rather than only a fuzzing session.

That guarantee was measured rather than assumed: seed replay alone reaches every `parseLength` / `skipLength` call site in the package.
The authPriv unwrap added a site on the decrypt branch, reachable only with privacy configured.
A dedicated target seeds it with a genuinely encrypted GET per privacy protocol and a ciphertext whose plaintext carries a bad SEQUENCE length. 55 minutes of fuzzing across 80.6 million executions produced no panic.
That includes the INFORM acknowledgement parser, which had never been fuzzed and which any host that can reach a device's per-device UDP socket can feed: `readerLoop` does not check the source address, so no collector-address spoofing is needed.
The fuzz corpus those runs built is committed under `testdata/fuzz/`, so CI replays it too.

The no-`recover()` position above rests on that null result, and the result is **provisional**: the pre-registered rule asked for ten minutes of fuzzing per target, and 5 of the targets that existed then got that budget.
The verdict is strongest for the request path, the INFORM-ack path and the v3 scoped-PDU path, and rests on seed replay alone for the rest.

`parseLength` keeps its `-1` failure sentinel on the same evidence: 22.3 million executions confirmed it returns `-1` and never any other negative value, so screening for `< 0` at a call site is sufficient as well as necessary.

Two traps this parser family has fallen into, both worth knowing before editing it:

- **`parseLength` signals failure with `-1`, and `-1` passes an upper-bound check.** `if pos+n > len(buf)` is false when `n` is `-1`, so the guard admits the value and the slice expression that follows panics on an inverted range. Length checks need the `n < 0` arm as well.
- **A short-circuiting guard does not short-circuit its own error message.** `if pos >= len(data) || data[pos] != tag { return fmt.Errorf("... got 0x%02X", data[pos]) }` evaluates `data[pos]` whenever the branch is taken, including on the out-of-range case the check exists to catch.

### The envelope-parser defects

Panics are not the only failure a parser has.
A silent mis-parse has no oracle, so the fuzz targets also assert that the four readers of the v1/v2c envelope agree with one another.
`getPDUType`, `parseIncomingRequest`, `parseAllOIDsFromRequest` and `parseGetBulkParams` each walk the same version and community fields with their own code, so when two of them disagree at least one is wrong and no reference implementation is needed to say so.
Those assertions found three defects, all fixed here, and a fourth site was found by auditing for the same root assumption.
The assumption in every case is the same one: that the encoder was minimal.

**A version INTEGER at two octets was served.** `getPDUType` stepped over the version INTEGER as a length skip plus a bare `pos++`, which assumes exactly one content octet.
SNMP is BER, not DER, so `02 02 00 01` is a legal encoding of version 1. The cursor landed one octet short, the byte read as the PDU tag was the version's own content octet `0x01`, and `handleSNMPv2cRequest` dispatches on that byte.
So a GETNEXT or a GETBULK carrying a non-minimally encoded version was answered from the GET branch, while every other parser read the datagram correctly.
It now reads the declared length, in the same shape `parseIncomingRequest` uses.

The same assumption stood in three more places, and each was fixed with it.
The version VALUE was assigned only at `versionLen == 1`, so a padded v1 request parsed as v2c and silently lost every v1-specific behaviour: the Counter64 GET-divert and GETNEXT-skip and the `noSuchName` sentinel diversion.
`isSNMPv3Request` and `parseSNMPv3Message` required the same one octet, so a padded v3 message was classified as v2c and read with `msgGlobalData` where a community belongs.
And the COMMUNITY length was read differently by the two readers: `getPDUType` bailed on an unreadable one while `parseIncomingRequest` stepped over it and carried on, which reproduced the same symptom one field later.
A GETNEXT with real varbind names, dispatched from the GET branch.
All four now read each envelope field the same way, which is the rule this family is held to rather than any single fix.

**The request-id** carried the same assumption, and it was found by the live-fuzz campaign these fixes exist to unblock.
`parseIncomingRequest` documented a 1..4 content-octet bound and did not advance past a wider field, and a padded five-octet request-id is legal BER and is what an encoder emits for any value at or above 2^31. The cost is not the request-id: every field after it is read from the wrong offset, and on the datagram the fuzzer found that decodes an OBJECT IDENTIFIER sitting inside the PDU as the first varbind name.
It is now read with `parseBERInt` at any width, which also makes it signed, as RFC 3416's Integer32 requires.

**A backward cursor** is the `-1` trap above, in the `parseGetBulkParams` envelope walk.
Three declared lengths were added to the cursor with no `< 0` arm, so a failed length read moved it BACKWARD onto a byte already consumed.
On the reproducer that byte is a community length octet of `0xa5`, which is also the GETBULK tag, and the function reported non-repeaters 12336 for a datagram that carries no GETBULK PDU at all.
All seven of its length reads now test the sign, the two container lengths additionally BOUND the walk to what they declare, and the same fault one message layer up in `extractRequestIDFromScopedPDU` was fixed with them.

Three of those seven guards have a behavioural witness and four do not, and the reason is structural rather than a missing test.
On a failed read `parseLength` leaves the cursor on the offending length octet, so for the next branch to misfire that octet must both fail `parseLength` and equal the tag the branch expects.
That is possible only at the community field, whose next branch tests for `0xA5`.
That byte declares 37 length octets and is also the GETBULK tag, which is exactly why the defect was found there.
A test states this per guard.
The four without a witness are defence-in-depth and are kept so the rule needs no exceptions.

A note on `02 00`, a version INTEGER with no content octets: it is NOT legal BER (X.690 §8.3.1 requires one or more content octets).
It is served anyway, leniently, because all four readers step over zero octets and agree on where the PDU begins.
Discarding it under RFC 3412 §7.2 would also be defensible.
The consequence is that no version value is read, so such a request is answered as v2c.

Exposure is hardening rather than a field report: net-snmp and snmp4j both emit minimal versions and request-ids below 2^31, so no shipped manager is known to produce any of these encodings.
What did produce them is nl6's own fuzzer, and the two committed corpora had been replaying instances of that defect on every CI run without noticing, because the targets measured panics only.

All five reproducers are committed fuzz seeds, so an ordinary `go test` replays them.
The nine fuzz targets that read a v1/v2c datagram were then run live for 180 seconds each, 43.5 million executions in total, with no find.
Its executions do not cover the multi-binding walk.
Seeds for that shape are committed and replay on every run.
A digest pins the other side: responses to well-formed minimal datagrams hash to a digest computed against the pre-change tree, so the fixes are observable only on the encodings that were mis-parsed.
The corpus is 432 datagrams.
The digest covers 360 of them, because a multi-binding GETNEXT now answers every binding and its response changed by design.
That shape is excluded and the digest was re-derived against the new baseline rather than updated in place, so it is still a pre-change measurement.
Everything else is still byte-identical.
That covers GET and GETBULK at any binding count, the single-binding GETNEXT that is essentially all real GETNEXT traffic, the single-binding Counter64 and the past-the-end corners that change touched.
The 72 excluded datagrams are not left unpinned: a separate digest freezes them against the new behaviour, so a further move of that shape has to be deliberate.

## OID lookup internals

OIDs are stored per-device in a `sync.Map` for lock-free O(1) reads under concurrent load.
Pre-computed next-OID mappings avoid scanning the table for `GETNEXT` / `GETBULK`: each OID has a direct pointer to its lexicographic successor.
Request buffers come from a shared pool to reduce GC pressure on SNMP-heavy workloads.

OIDs in resource files may be written with or without a leading dot.
The loader normalises them to the net-snmp convention (`.1.3.6.1…`) at startup.

## Dynamic IF-MIB counters

Every per-interface counter listed below is generated dynamically, not read from the profile's JSON:

**ifXTable Counter64 HC columns** (`.1.3.6.1.2.1.31.1.1.1.X`):

| Column | OID column | Derivation |
|--------|-----------|------------|
| `ifHCInOctets` | `.6` | master dial (sine wave, 60 to 100 % of `ifHighSpeed` / `ifSpeed`, 1 h period) |
| `ifHCInUcastPkts` | `.7` | `baseInUcast + (inDeltaOctets / pktSizeIn) × ucastRatioIn` |
| `ifHCInMulticastPkts` | `.8` | same shape, `mcastRatioIn` |
| `ifHCInBroadcastPkts` | `.9` | same shape, `bcastRatioIn` |
| `ifHCOutOctets` | `.10` | outbound master dial |
| `ifHCOutUcastPkts` | `.11` | `baseOutUcast + (outDeltaOctets / pktSizeOut) × ucastRatioOut` |
| `ifHCOutMulticastPkts` | `.12` | same shape, `mcastRatioOut` |
| `ifHCOutBroadcastPkts` | `.13` | same shape, `bcastRatioOut` |

**ifXTable Counter32 shadow columns**: always equal to `uint32(HC_value & 0xFFFFFFFF)`:

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

`ifInOctets` and `ifOutOctets` became cycler-driven.
Before that they were the only IF-MIB counter columns served from the profile JSON, frozen, while their HC columns climbed from `ifSpeed`.
A rate computed from them was 0 bps forever, and they contradicted the 64-bit columns on the same interface.
The 1322 static entries the cycler now shadows (661 `ifInOctets` + 661 `ifOutOctets`, across 20 profiles) were deleted in the same change, because `findResponse` consults the cycler before the static map and an unreachable entry that looks authoritative is what let the defect survive.
A ledger records every deleted row and reverses it to reproduce the parent corpus digest.

**The dead-data rule now covers every cycler-owned `ifTable` column.** That change applied it to `.10`/`.16` only, because its own scope forbade touching the other shadows, and a follow-up finished the sweep with **742 further static rows deleted**: `ifLastChange` `.9` (646 rows, 17 profiles), `ifInUcastPkts` `.11` (48, `asr9k`) and `ifOutUcastPkts` `.17` (48, `asr9k`).
`findResponse` consults the cycler first, so all 742 were unreachable.
`staticRowsOnCyclerOwnedIfTableColumns` now reads zero for every cycler-owned column except the two carve-outs below, so a non-zero entry is a regression rather than a backlog.

**`ifAdminStatus` `.7` and `ifOperStatus` `.8` are NOT dead and must not be deleted.** They look exactly like the other shadows, and the cycler answers both.
But `InitIfCountersWithScenario` reads them out of `oidIndex` to *seed* the interface-state engine.
They are live input, and deleting them would change every device's initial state. 887 rows each, across 28 profiles, and the census carries them as a named carve-out rather than a magic number.

A guard builds a real device per profile and requires the serve path to answer all 742 deleted OIDs.
That is the test that fires on the defect.
The corpus digests would only say "re-pin", which is how an unreachable column would become an unanswered one.

**What the RFC actually says, and what is nl6's choice.** RFC 2863 does not define `ifInOctets` as the low 32 bits of `ifHCInOctets`, and an earlier version of this page said it did.
The ifXTable DESCRIPTION of `ifHCInOctets` calls it "a 64-bit version of `ifInOctets`", and §3.1.6 mandates only which *width* an agent must serve at which speed: 32-bit octet counters at or below 20 Mb/s, 64-bit octet counters above it, and 64-bit packet counters at or above 650 Mb/s.
A conforming agent may hold the two counters independently.
Deriving one from the other is nl6's deliberate choice.
It is the de-facto convention real agents follow, and it makes the two columns unable to contradict each other, which is what a collector cross-checking them assumes.

**The identity is exact for a shared evaluation instant, and only then.** `IfCounterCycler.GetDynamicAt(oid, t)` takes the instant from the caller, so a caller that passes one `t` across several columns gets values that satisfy `shadow == uint32(HC & 0xFFFFFFFF)` byte for byte.
The sFlow `counter_sample` path and gNMI both do that.
The per-OID SNMP path does **not**: `findResponse` calls `GetDynamic`, which reads the clock itself, and `NextDynamicOID` re-reads it per walk step.
So a multi-varbind GET, or a GETNEXT/GETBULK spanning `ifInOctets` and `ifHCInOctets`, evaluates the dial once per varbind, and the two values differ by whatever accrued in between.
At 400 Gb/s that is roughly 5×10⁷ octets per millisecond of drift.
That is a property of the read API, not of the derivation.
Capturing one instant per SNMP request would remove it and is a larger change than that one took on.
The scope is stated here rather than claimed away.

**The compiled-in fallback profile.** `createDefaultResources` is written whenever a named resource file is absent.
It ships `ifHCInOctets.1` / `ifHCOutOctets.1` and derives all four octet columns.
Do not add a static `.10` / `.16` row back to that set: with the HC rows present it would be unreachable.

**What fires if a profile loses the columns.** A guard walks every shipped profile, builds a device with a live cycler, and requires the serve path to answer both columns for every ifIndex the profile describes via `ifDescr`.
That is 1774 instances today: the 1322 formerly static rows plus the 452 newly served.
The cycler's ifIndex set comes only from `ifHCInOctets` rows, so a profile edit that adds interfaces without one drops both columns for those interfaces.
That test names the missing `ifHCInOctets.<N>` row.
The corpus digests would only tell you to re-pin them, which would absorb the regression.

**Fleet-visible surface change.** 28 profiles ship `ifHCInOctets` rows but only 20 shipped static `ifInOctets`/`ifOutOctets`, so 8 profiles *gain* two columns per interface, **452 OIDs that no profile served before**: `cisco_catalyst_9500` +96, `cisco_nexus_9500` +128, `juniper_mx960` +160, `palo_alto_pa3220` +32, `dell_emc_unity` +10, `netapp_ontap` +10, `pure_storage_flasharray` +10, `linux_server` +6. On the other 20 the columns moved from static to dynamic with no change in count, because every one of them shipped exactly one static row per HC row.
An `ifTable` walk of `cisco_crs_x`, the widest profile at 144 interfaces, returns the same number of OIDs as before, so walk-step and SNMP-walk CPU figures taken on it stay comparable.
Figures taken on any of the 8 profiles above are not comparable across that change, because the number of OIDs a walk returns moved.

Properties common to every dynamic counter:

- **Monotonic.** The underlying octet integral never decreases (rate floor is 60 % of `ifSpeed`), and every derivation is base-plus-growth, so Counter64 columns are strictly increasing. Counter32 shadow columns wrap naturally at 2³². `ifCounterDiscontinuityTime` (`.19`) is not served: no shipped profile carries it and the cycler does not synthesise it, so a GET answers `noSuchObject`. Wrap is inherent, not a discontinuity.
- **Pre-seeded.** Each counter starts at a base derived from ~24 h of traffic, ratios, and the active error scenario (see below) so a fresh device doesn't look unrealistically pristine.
- **Per-interface variance.** Packet-size divisor jitters ±20 % around 500 B. Mix ratios jitter ±3 % around 85 / 10 / 5 (in) and 90 / 8 / 2 (out). Error and discard ppm values are drawn once from the scenario band, all deterministic from the device seed.
- **Sine-driven correlation.** All derived counters share the master octet sine wave, so when a link is "quiet" (60 % of `ifSpeed`) the full counter family slows together, matching how real hardware behaves under reduced traffic.
- **SNMP ↔ sFlow agreement.** Both read paths resolve the same `IfCounterCycler` dispatcher, so an sFlow `counter_sample` and an SNMP GET evaluated at the same instant carry the same values. "The same instant" is exact for the sFlow path, which captures one `t` and passes it to every column. The SNMP path reads the clock per OID, so two varbinds in one response are two instants (see above).
- **Zero-goroutine cost.** Every counter is computed on-demand from the current time against analytic formulas. There is no per-interface goroutine, no polling loop.
- Values are visible on both `GET` and `GETNEXT` / `GETBULK`.

**Counter32 wrap guidance.** The fastest-wrapping objects on the device are the two octet columns, and they are the first a collector trips over: `ifInOctets` / `ifOutOctets` cover 2³² octets in about **3.4 s at 10 Gb/s** and about **86 ms at 400 Gb/s** at line rate (the dial's 60 to 100 % duty cycle stretches that by at most two thirds).
No poll interval makes a 32-bit octet counter usable at those speeds, which is exactly why RFC 2863 §3.1.6 requires the 64-bit octet counters above 20 Mb/s.
Poll `ifHCInOctets` / `ifHCOutOctets` instead. nl6 serves the 32-bit columns for fidelity, not because they are useful there.

The packet columns wrap more slowly.
At 10 Gbps / 80 % util / 500 B average packet size, `ifInUcastPkts` wraps every ~26 minutes, and every ~2.6 minutes at 100 Gbps.
The rule is the same one: above 20 Mb/s, poll the HC columns.
Collectors handle a wrap via the delta-modulo convention, which only works if the poll interval is shorter than the wrap.

### Per-device error scenario

The `ifInErrors` / `ifOutErrors` / `ifInDiscards` / `ifOutDiscards` rates are driven by a per-device scenario carried in `DeviceSimulator.IfErrorScenario`:

| Scenario | `errPpm` | `discPpm` | Typical dashboard appearance |
|----------|----------|-----------|------------------------------|
| `clean` *(default)* | `0` | `0` | Flat line at the baseline |
| `typical` | `10 to 100` | `20 to 200` | Faint steady slope (good production gear) |
| `degraded` | `1 000 to 10 000` | `2 000 to 20 000` | Visible error-rate alert candidates (0.1 to 1 %) |
| `failing` | `10 000 to 100 000` | `20 000 to 200 000` | Link-flap / bad-cable alarms (1 to 10 %) |

Set for the auto-start batch via the CLI flag `-if-error-scenario <name>`, or per-device via `if_error_scenario` in the `POST /api/v1/devices` body.
See [CLI flags reference](cli-flags.md#interface-state-scenarios) and [Web API reference](web-api.md#create-devices).

### Example walks

```bash
# Walk ifXTable: covers all HC counters, Counter32 shadows, and ifHighSpeed
snmpwalk -v2c -c public 10.42.0.1 1.3.6.1.2.1.31.1.1

# Walk ifTable: covers ifInOctets, ifInUcastPkts, ifInDiscards, ifInErrors,
# ifOutOctets, ifOutUcastPkts, ifOutDiscards, ifOutErrors
# (.10 and .16 are cycler-driven, not frozen JSON values)
snmpwalk -v2c -c public 10.42.0.1 1.3.6.1.2.1.2.2.1

# Fetch HC in/out for interface 1 directly
snmpget -v2c -c public 10.42.0.1 \
  1.3.6.1.2.1.31.1.1.1.6.1 \
  1.3.6.1.2.1.31.1.1.1.10.1

# Continuous rate monitoring (poll every 10 s)
watch -n 10 "snmpget -v2c -c public 10.42.0.1 \
  1.3.6.1.2.1.31.1.1.1.6.1 1.3.6.1.2.1.31.1.1.1.10.1"

# Watch error / discard growth on a device deployed with -if-error-scenario failing
watch -n 5 "snmpget -v2c -c public 10.42.0.1 \
  1.3.6.1.2.1.2.2.1.14.1 1.3.6.1.2.1.2.2.1.13.1"
```

## Dynamic CPU / memory / temperature metrics

CPU, memory, and temperature OIDs cycle through a 100-point pre-generated sine-wave pattern per device, driven by `metrics_cycler.go`.
Per-category device profiles define the baseline ranges and spike amplitudes.
See `device_profiles.go`.
GPU servers add per-GPU metric cycling on top of this.
See [GPU simulation](gpu/index.md).

## Interface-state scenarios

The [`-if-scenario`](cli-flags.md#interface-state-scenarios) flag seeds the state engine's `ifAdminStatus` and link state once per interface.
`ifOperStatus` is never seeded; it is derived from admin and link.
Scenario 1 seeds admin `down(2)` and preserves the link the profile declares, so unshutting a port restores it.
Scenario 2 is the identity and serves whatever the profile declares.
Scenario 3 seeds admin `up(1)` and link down on every interface.
Scenario 4 seeds admin `up(1)` on every interface, with link down where `ifIndex % 100 < n` and link up elsewhere, so results are reproducible across restarts.

The scenario is applied once per device, when the state engine below is built, and there is no read-time override anywhere on the SNMP path.
So a `SET`, a REST POST or a flap is read back by the next `GET` or walk under every scenario, and a seeded interface reports `ifLastChange = 0` because a seed is not a transition.

```bash
# Spot-check admin status. All "1" under scenarios 3 and 4, which force it.
# Scenario 2 is the identity and serves whatever the profile ships, so a "2"
# here is not a fault: cisco_nexus_9500 ships 32 of its 64 interfaces
# administratively down (ifIndex 33-64).
snmpwalk -v2c -c public 10.42.0.1 1.3.6.1.2.1.2.2.1.7

# Verify oper status after scenario 3 (all-failure)
snmpwalk -v2c -c public 10.42.0.1 1.3.6.1.2.1.2.2.1.8
```

**Dynamic state engine.** `ifOperStatus.<N>` (`.8`), `ifAdminStatus.<N>` (`.7`), and `ifLastChange.<N>` (`.9`) are served from the per-device interface state engine.
The JSON rows are read once as the engine's seed.
Three mutation sources update them at runtime:

- **Flap scheduler**: `-if-flap-scenario {clean|rare|typical|aggressive}` drives Poisson-distributed link flaps per (device, ifIndex). See the [interface state engine reference](interface-state.md).
- **REST control plane**: `POST /api/v1/devices/{ip}/interfaces/{N}/{oper,admin}-status` flips state for test-harness use.
- **SNMP SET**: a `SetRequest` of `ifAdminStatus.<N>` through the same funnel. `ifOperStatus` follows by derivation, asymmetrically: `down(2)` and `testing(3)` force it, `up(1)` releases it to the link. See [SetRequest](#setrequest).

Cross-protocol consistency: SNMP `ifOperStatus.<N>` and gNMI `/interfaces/interface[name=*]/state/oper-status` read from the same slot table and agree byte-for-byte at every instant.
An oper-status transition also fires the device's role-tagged link trap and syslog for that interface.

**RFC 2863 note on `ifLastChange`.** Strict reading of RFC 2863 specifies `ifLastChange` as "value of sysUpTime at the time the interface entered its current operational state".
The simulator computes the value relative to the per-device state-engine construction time, not the SNMP agent's `sysUpTime`.
Today these epochs coincide (state engine constructs once, during device boot, guarded against re-init by a panic).
If a future "reload scenario" feature is added, this divergence must be re-examined.

**SNMP / gNMI timestamp resolution divergence on `ifLastChange`.** SNMP encodes `ifLastChange` as `TimeTicks` (centiseconds of sysUpTime), so two transitions less than 10 ms apart collide to the same wire value.
The gNMI `state/last-change` leaf exports the engine's nanosecond timestamp directly, so the same two transitions are distinguishable there.
Under the `aggressive` flap scenario (mean ≈1 min) the collision is statistically irrelevant, but a custom test harness driving back-to-back REST POSTs against the same `(device, ifIndex)` can observe the divergence: SNMP `ifLastChange` returns the same TimeTicks value across both transitions while the gNMI leaf separates them by their actual nanosecond delta.

## Entity MIB and vendor OIDs

Every network device ships with a properly aligned Entity MIB: chassis, line cards, power supplies, fans, and temperature sensors, plus the `entAliasMappingTable` linking physical ports to logical interfaces.
Vendor-specific OIDs (Cisco, Juniper, Arista, NVIDIA, etc.) are provided per device type under `go/nl6/resources/<device>/`.
See [Resource files](resource-files.md) for the JSON schema and [Device types](device-types.md) for the catalog.

## Notifications (trap / INFORM)

SNMP defines two paths.
One is request/response: the GET, GETNEXT, GETBULK and SET operations documented above.
The other is a push path, where a device initiates a notification to a monitoring collector.

nl6 serves the push path at all three versions, one wire format per fleet via `-trap-snmp-version`:

| Version | Notification | INFORM |
|---|---|---|
| `v2c` (default) | TRAP, PDU `0xA7` | yes, PDU `0xA6` |
| `v1` | RFC 1157 Trap-PDU | no, RFC 1157 defines none |
| `v3` | RFC 3414 USM, PDU `0xA7` | no, see below |

A v3 INFORM is refused: an INFORM is authoritative at the *receiver*, which nl6 cannot act as.
A v3 fleet needs `-trap-snmpv3-user` and the USM password flags.

One thing that reads as a defect and is not: a polled device and a trap from that device report **different** `snmpEngineID` values.
The poll path's engine ID is fleet-wide.
Each notification originator derives its own from its IPv4, per RFC 3411 §5.

See [SNMP trap reference](snmp-traps.md) for wire format, the JSON catalog schema, and the HTTP endpoints, and [SNMP trap / INFORM export (operator guide)](../ops/snmp-traps.md) for enabling the feature and the `snmptrapd` smoke test.
