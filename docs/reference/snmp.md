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
The v3 GETBULK handler is the exception; see the known limitations below.

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

If you are testing an SNMPv3 collector against a version of nl6 older than this fix, authPriv results are not meaningful: every device answers `sysDescr.0`. authNoPriv and noAuthNoPriv were unaffected.

The discovery Report also now carries `usmStatsUnknownEngineIDs.0` as a Counter32, which is the type RFC 3414 §5 gives it. It previously went out as an INTEGER.

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
- **Coverage is bounded by the type table.** The eight `ifXTable` HC columns are the Counter64 objects nl6 recognises. A 64-bit counter served from a resource file under any other OID (a vendor HC column, `ipIfStatsHC*`, `dot3HC*`) is not recognised as Counter64, so a v1 request for it still returns `0x46`.

### A resource value that collides with a sentinel is rejected at load

`validateSNMPResourceValues` rejects a resource entry whose response is exactly `noSuchObject` or `endOfMibView`.
The error names the file, the OID and the value, because fixing it means editing one line of one file.

The match is exact.
`noSuchObject seen`, `NoSuchObject` and ` noSuchObject` are ordinary data and load normally.

The check runs on every load path, and applies to the `snmp` array only.
SSH, API and optical entries never reach `encodeTypedValue`, and the trap and syslog catalogs use a different encoder.
In a device-type directory each JSON part is validated separately, so the error names the part that is wrong rather than the directory.

It closes the resource-file route, not every route.
`sysName` and `sysLocation` are served outside the resource map, and `sysLocation` comes from the operator-supplied worldcities CSV, so a sentinel-valued entry there is still served as an exception.

Where a rejection surfaces matters.
Resource files are also loaded on REST device creation, so a bad operator-supplied file is a failed API call (HTTP 500, carrying the same error text) in the middle of a run, not only a refusal at startup.
Two call sites downgrade the rejection to a log line rather than failing: the startup load in `simulator.go` falls back to the `cisco_ios` profile, and round-robin device creation skips the offending device type.
At those two sites the guard is advisory.

The same guard carries a second rule (nl6#529): a value on an OID-typed leaf, today only `sysObjectID`, must be an OID the encoder can represent.
Encodability is decided by calling the encoder and testing for the degenerate `06 00`, not by a second predicate, so the loader cannot drift from the wire; see [The first OID sub-identifier is a varint](#the-first-oid-sub-identifier-is-a-varint) above for what the encoder accepts.
The sentinel rule is checked first, matching the order the encoder applies them, so a sentinel on `sysObjectID` is reported as a sentinel collision.
OID keys are not checked.
A non-numeric `Counter32`, `Gauge32` or `TimeTicks` value, or an unparseable `ipAdEntAddr`, is likewise still accepted at load and degrades to an OCTET STRING when served.

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

### Known limitations

**A GETNEXT processes only its first variable binding.** The v1/v2c GETNEXT dispatcher reads one OID from the request and answers one successor. A multi-binding GETNEXT (as some walkers send to fetch several columns per round trip) gets an answer for the first binding only. Pre-existing; the SNMPv1 Counter64 skip inherits it.

**SNMPv3 GETBULK ships one variable binding** (nl6#535). The handler collects up to `max-repetitions` successors and the response builder returns only the first, so a bulk walk progresses one OID per request. It is worse than it sounds: the discarded walk steps were still *performed*, so per delivered binding a v3 GETBULK costs roughly ten times the server work of a GETNEXT, on the walk path the v2c side clamps explicitly. A multi-column GETBULK is also answered with the first column only, which is a wrong answer under RFC 3416 rather than merely a small one. (Until nl6#526 the same builder answered end-of-MIB with a placeholder `sysDescr.0` binding whose OID sorted *before* the request, which stopped a v3 bulk walk terminating at all; it now answers the `endOfMibView` exception named with the requested OID. A GETBULK whose scoped PDU fails to decrypt is still rewritten to a GET of `sysDescr.0` and so does not terminate.)

**SNMPv3 GETBULK is not bounded.** Everything above about response sizing describes the SNMPv2c path. The v3 GETBULK handler builds its response through a separate encoder that consults no size ceiling, and `parseSNMPv3GetBulkParams` hardcodes `max-repetitions` to 10 and discards `non-repeaters`. Combined with the one-binding limitation above, an oversized v3 response is unreachable today — but by accident, not by design, and the accident is doing the work: honouring a real `max-repetitions` without adding the bound first would make it reachable. All of these are nl6#535 and must land together.

**SNMPv3 `msgMaxSize`**

— the bound is the link-MTU-derived budget, and an SNMPv3 request declaring a smaller `msgMaxSize` does not further reduce the response. This is a deliberate omission rather than an oversight — the MTU bound is the binding constraint in every configuration measured — and a future change honouring `msgMaxSize` would refine a stated position rather than correct a gap.

## Malformed-datagram handling

Every simulated device answers from one process, and the request path is a hand-written BER parser rather than `encoding/asn1`.
A panic in it is therefore not a per-device fault — it unwinds the listener goroutine and takes the whole fleet down mid-run.
The parsers are consequently required to be **total**: any byte sequence must produce a value or an error, never a panic.

There is deliberately **no `recover()`** on the request path.
A blanket recover would convert a parser defect into a silently dropped datagram, which is indistinguishable from a network drop and hides the bug for as long as it exists.
The fuzz targets in `snmp_parser_robustness_test.go` hold the guarantee instead, each seeded with the input that previously crashed it.
`go test` replays every seed on an ordinary run, so a regression fails the normal suite rather than only a fuzzing session.

That guarantee was measured rather than assumed ([nl6#513](https://github.com/labmonkeys-space/nl6/issues/513)).
Twenty-one targets execute all 57 `parseLength` / `skipLength` call sites on seed replay alone, up from five, so an ordinary `go test` reaches every one of them.
55 minutes of fuzzing across 80.6 million executions produced no panic.
That includes the INFORM acknowledgement parser, which had never been fuzzed and which any host that can reach a device's per-device UDP socket can feed: `readerLoop` does not check the source address, so no collector-address spoofing is needed.
The fuzz corpus those runs built is committed under `testdata/fuzz/`, so CI replays it too.

The no-`recover()` position above rests on that null result, and the result is **provisional**: the pre-registered rule asked for ten minutes of fuzzing per target, and 5 of the 21 targets got that budget.
The verdict is strongest for the request path, the INFORM-ack path and the v3 scoped-PDU path, which are the five, and rests on seed replay alone for the other sixteen.

`parseLength` keeps its `-1` failure sentinel on the same evidence: 22.3 million executions confirmed it returns `-1` and never any other negative value, so screening for `< 0` at a call site is sufficient as well as necessary.

Two traps this parser family has fallen into, both worth knowing before editing it:

- **`parseLength` signals failure with `-1`, and `-1` passes an upper-bound check.** `if pos+n > len(buf)` is false when `n` is `-1`, so the guard admits the value and the slice expression that follows panics on an inverted range. Length checks need the `n < 0` arm as well.
- **A short-circuiting guard does not short-circuit its own error message.** `if pos >= len(data) || data[pos] != tag { return fmt.Errorf("... got 0x%02X", data[pos]) }` evaluates `data[pos]` whenever the branch is taken — including on the out-of-range case the check exists to catch.

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
| `ifInUcastPkts` | `.11` | shadow of `ifHCInUcastPkts` (`.7`) |
| `ifInDiscards` | `.13` | `baseInDisc + inDeltaPkts × discPpmIn / 1e6` |
| `ifInErrors` | `.14` | `baseInErr + inDeltaPkts × errPpmIn / 1e6` |
| `ifOutUcastPkts` | `.17` | shadow of `ifHCOutUcastPkts` (`.11`) |
| `ifOutDiscards` | `.19` | `baseOutDisc + outDeltaPkts × discPpmOut / 1e6` |
| `ifOutErrors` | `.20` | `baseOutErr + outDeltaPkts × errPpmOut / 1e6` |

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
  `IfCounterCycler` dispatcher, so concurrent SNMP GETs and sFlow
  `counter_sample` bodies carry matching values at the same instant.
- **Zero-goroutine cost.** Every counter is computed on-demand from
  the current time against analytic formulas — no per-interface
  goroutine, no polling loop.
- Values are visible on both `GET` and `GETNEXT` / `GETBULK`.

**Counter32 wrap guidance.** At 10 Gbps / 80 % util / 500 B avg
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

# Walk ifTable — covers ifInUcastPkts, ifInDiscards, ifInErrors,
# ifOutUcastPkts, ifOutDiscards, ifOutErrors
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
