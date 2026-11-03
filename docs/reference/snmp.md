---
sidebar_label: "SNMP"
description: "What nl6 answers over SNMP v1, v2c and v3, with operations, community and USM handling, GETBULK sizing, exceptions and SET."
---

# SNMP

nl6 answers SNMP v1, v2c and v3 queries on UDP port 161 (override with [`-snmp-port`](cli-flags.md#core-flags)) for every simulated device.
See [Architecture](../explanation/architecture.md) for the component map.

## Protocol coverage

- **SNMP v2c**: `GET`, `GETNEXT`, `GETBULK` against the full per-device OID table, and `SET` on one writable object, `ifAdminStatus.<N>` (see [SetRequest](#setrequest)).
  A read answers any community string and echoes it back (see [On a read, the community string is echoed and never checked](#on-a-read-the-community-string-is-echoed-and-never-checked)).
  The examples on this page use `public`.
- **SNMPv1**: `GET`, `GETNEXT` and `SET`.
  The protocol has no `GETBULK`, but nl6 still answers a version-0 `GETBULK` as it answers v2c, unmapped.
  Apart from that `GETBULK`, no Counter64 and no exceptions: where v2c returns an exception, v1 returns `noSuchName`, and a `GETNEXT` skips Counter64 columns rather than failing.
  See [SNMPv1 never returns a Counter64](#snmpv1-never-returns-a-counter64).
- **SNMPv3**: enable with [`-snmpv3-engine-id`](cli-flags.md#snmpv3-flags).
  Auth protocols: `none`, `md5`, `sha1`.
  Privacy protocols: `none`, `des`, `aes128`.
  All three security levels work and are verified against net-snmp, see below.
  The auto-start batch uses the v3 user `simadmin`, with `simadmin` as both the authentication and the privacy password.
  A REST-created device takes its user and passwords from the `snmpv3` block of the request (`username`, `password`, `priv_password`).

A request whose version is 3 takes the SNMPv3 path above.
A request with any other version than 0, 1 or 3 is served as SNMPv2c rather than discarded.

### Verified against net-snmp, not only against nl6's own parser

Every security level below is polled with `snmpget` from net-snmp 5.9.4 on every push.
net-snmp discovers the engine, derives its own key from the password and the engine ID it received, verifies nl6's digest, and builds its own decryption IV.
To run it yourself:

```
make test-interop
```

Every other v3 test reads nl6's output with nl6's own parser.
Only an outside manager can catch a misreading of RFC 3414 that both sides share.

### SNMPv3 USM conformance

USM is implemented per RFC 3414:

- **Key derivation** is §A.2's password-to-key followed by localization `H(Ku || engineID || Ku)`, against the raw engine-ID **octets**. The four RFC 3414 Appendix A.3 vectors are asserted from a checked-in extract of the RFC, not from nl6's own output.
- **Authentication** is HMAC-MD5-96 or HMAC-SHA-96 over the whole message with `msgAuthenticationParameters` zero-filled, truncated to 12 octets (§6.3.1). A `noAuthNoPriv` message carries a zero-**length** field.
- **Privacy keys** are derived from `priv_password`, falling back to `password`, and localized with the **authentication protocol's** hash (§2.6).
- **DES** builds `IV = salt XOR pre-IV` from the last 8 octets of the 16-octet localized key (§8.1.1.1). **AES128** builds its IV from the engine boots and time carried in the message (RFC 3826 §3.1.2.1).
- **Inbound messages are verified**: a wrong digest is answered with a Report naming `usmStatsWrongDigests`, a stale one with `usmStatsNotInTimeWindows` (the §3.2 150-second window), and an authenticated request to a device configured without auth with `usmStatsUnsupportedSecLevels`.
- **authPriv requests** are answered for the OID and PDU type they ask for. A request whose scoped PDU fails to decrypt is answered with a `usmStatsDecryptionErrors` Report.
- **The discovery Report** carries `usmStatsUnknownEngineIDs.0` as a Counter32, the type RFC 3414 §5 gives it. The value is a fixed `1` and does not count events.

So nl6 can be used to test a collector's wrong-credential handling.

**What is not implemented:** SNMPv3 **INFORM**, and the SHA-2 auth protocols and AES-192/256 privacy of RFC 7860 / RFC 3826 §3.1.2.2.

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

`-snmpv3-priv` requires `-snmpv3-auth`.
USM defines no privacy-without-authentication level, and the privacy key is localized with the authentication protocol's hash.
A device created over REST with that combination is refused with a 400.
The CLI flags are **not** validated together, so `-snmpv3-priv aes128` with `-snmpv3-auth none` starts and then fails on every encrypted request.

### Two engine-identity limitations

Neither affects a single-device poll, and both are worth knowing before pointing a manager at a large fleet.

- **`snmpEngineID` is fleet-wide.** `-snmpv3-engine-id` gives every device the same value, while `msgAuthoritativeEngineBoots` and `msgAuthoritativeEngineTime` are per device. RFC 3411 wants the engine ID unique per engine, so a manager that caches `(boots, time)` keyed on engine ID will see its estimate move as it polls devices started at different instants.
- **`msgAuthoritativeEngineBoots` is always 1 and is not persisted.** After a restart nl6 advertises `boots=1` again with the time back near zero, where RFC 3414 §2.2.3 would increment boots. A manager holding a cached estimate sees time move backwards under unchanged boots and has to rediscover. The `usmStatsNotInTimeWindows` Report nl6 sends is authenticated so that recovery is possible.

Per-device SNMPv3 credentials can be supplied when creating devices via the REST API.
See [Web API → Create devices](web-api.md#create-devices).

### On a read, the community string is echoed and never checked

nl6 does not authenticate a poll on the community: it parses the value, answers the request, and echoes the same value back in the response.
There is no ACL and no rejection path for a read, by design.
The boundary is the network namespace the devices live in.

**A `SET` is different.** A write requires the device's configured write community, which defaults to empty and therefore admits nothing.
See [write admission](#write-admission-for-a-set) for the whole rule.
No real agent checks a community on a write and not on a read.
nl6 does because a `SET` mutates state, fires link traps and syslog and is visible to gNMI, while a poll only returns simulated data.

A **zero-length** community is legal and is parsed as the empty string, not as absent.
net-snmp and snmp4j each send `04 00` for `-c ""`, and nl6 answers with an empty community rather than substituting `public`.
A community of 128 octets or more encodes its length in BER long form (`04 81 c8`), which is parsed correctly on every path.

### Unimplemented OIDs return an exception, not a value

An OID absent from a device's profile is answered with the RFC 3416 `noSuchObject` exception, not with a string.
The exception is the context-specific tag `80 00` in the variable binding's value position.
`error-status` stays `noError`: the response is a success and the exception is per-varbind (§4.2.1).

Only `noSuchObject` is ever emitted, never `noSuchInstance`.
The standard separates the two by OID prefix registration, and a profile is a flat OID→value map with no MIB registry.

**SNMPv1 has no exception values.** A v1 request that would produce one gets `error-status = noSuchName(2)` instead, with `error-index` set to the offending variable binding and every requested name echoed with a NULL value, per RFC 3584 §4.2.2.2 (§4.2.2.2.1 for `noSuchObject`, §4.2.2.2.2 for the `endOfMibView` a v1 GETNEXT reaches past the last OID).
The mapping applies to GET and GETNEXT only.
A version-0 GETBULK is not mapped: its bindings are walked OIDs, not the request's names, and there can be `max-repetitions × columns` of them.

**SNMPv3** returns the same tags: a v3 GET for an absent OID returns `80 00`, a v3 GETNEXT past the last OID returns `82 00`, and v3 GETBULK bindings carry the same tags.

The exceptions travel from the lookup to the encoder as the strings `noSuchObject` and `endOfMibView`.
A resource file value spelled exactly like one would encode as an exception, so the loader refuses such a value at load time.

### The first OID sub-identifier is a varint

X.690 §8.19.4 packs the first two arcs of an OID into a single sub-identifier valued `40*first + second`, encoded as a base-128 varint like every other one.
So `2.999`, the ITU test arc, round-trips.

An OID the encoder cannot represent faithfully takes the degenerate encoding `06 00` rather than becoming a different OID.
That covers:

- a first arc above 2,
- a second arc above 39 when the first is 0 or 1 (`1.40` and `2.0` would both compute 80),
- a combined first sub-identifier or any later arc above 2^32-1,
- any component that is not a number.

`06 00` is itself non-conformant, since X.690 §8.19.1 requires at least one sub-identifier.
That is deliberate: a malformed OID is visible to any decoder, and in a `snmpTrapOID.0` or `sysObjectID` position a collector rejects the message rather than recording a wrong OID as fact.
A value slot typed as an OID gets the same `06 00`, so a `sysObjectID` of `unknown` goes out as a degenerate OID rather than as a string.

The decoder refuses three things in an inbound OID:

- a sub-identifier whose final byte still sets the continuation bit (truncated),
- a sub-identifier wider than 2^32-1,
- a non-minimal sub-identifier, one whose leading octet is `0x80` (X.690 §8.19.2).

### SNMPv1 never returns a Counter64

Counter64 does not exist in SNMPv1.
RFC 3584 §4.2.2.1 prescribes two different behaviours for a v1 request that reaches one:

- A **GET** answers `error-status = noSuchName`, with `error-index` at the first offending binding and every requested name echoed with a NULL value.
- A **GETNEXT** **skips** the object and continues to the next lexicographic successor.

A GETNEXT names a position rather than an object, so an error would stop a v1 walk at the first HC column.
A v1 walk over `ifXTable` therefore returns every non-Counter64 column and steps silently over the Counter64 block.
A walk that skips its way past the last non-Counter64 OID ends in `noSuchName`, which is how v1 signals end-of-MIB.

The diversion is keyed on the OID's declared MIB type, not on what its value encodes as.
A Counter64 column holding a non-numeric value still diverts.

If the skip runs into a resource-file defect (a successor that does not advance, or the step cap), the walk is answered as end-of-MIB and one log line per device names the OID.

SNMPv2c and SNMPv3 are unaffected.

Two limitations:

- **GETBULK is untouched.** nl6 answers a version-0 GETBULK anyway, and it will hand a v1 manager raw `0x46` tags.
- **Coverage is bounded by the type table.** The Counter64 objects nl6 recognises are the eight `ifXTable` HC columns, the fourteen HC columns of each of the two RFC 4293 IP statistics tables (`ipSystemStatsTable`, `ipIfStatsTable`) and all six columns of the RFC 3635 `dot3HCStatsTable`, 42 columns in total. A 64-bit counter served under any other OID, such as a vendor HC column in an operator resource file, is not recognised as Counter64, and a v1 request for it is answered with a value.

### A GETNEXT answers every variable binding

RFC 3416 §4.2.2 defines GETNEXT over the whole variable-bindings list, and nl6 answers it that way.
Each binding carries the lexicographic successor of its own name, in request order.
A binding with nothing after it carries `endOfMibView` named with the OID that was asked for, so a walker fetching several columns per round trip can tell which column ended.

| Case | SNMPv1 | SNMPv2c |
|---|---|---|
| The successor is a Counter64 object | that binding SKIPS it and continues to the next successor (RFC 3584 §4.2.2.1) | returned normally |
| Nothing follows the requested OID | the response diverts to `noSuchName` with `error-index` at the first such binding, and the request's own names echoed with NULL values | `endOfMibView`, named with the requested OID |
| The response will not fit the datagram | `tooBig` with an empty binding list | `tooBig` with an empty binding list |

Overflow is `tooBig` rather than truncation for the same reason it is on a GET: the manager named N positions and has no resume point for a binding a shorter response would drop.
A single-binding GETNEXT is bounded the same way.
Only an operator resource file carrying a value over roughly 1400 bytes can reach it.
Under SNMPv1 the empty binding list is nl6's choice, since RFC 1157 does not settle it, so a `tooBig` cannot be mistaken for an answer.

Two bounds keep a wide request cheap:

- The binding count is capped at what a response could ever fit (`maxSNMPResponseSize / minVarbindSize`, 98 at the default MTU). A request with more bindings is answered `tooBig` without walking at all. The 1024-byte read buffer is a second bound on the binding count.
- The SNMPv1 Counter64 skip steps of one datagram share one budget, `maxGetNextBindings × longestShippedCounter64Run`. `longestShippedCounter64Run` is 1152, eight `ifHC*` columns across 144 interfaces on `cisco_crs_x`, so the budget cannot truncate a shipped table. An operator resource file with a wider Counter64 run is truncated and logged once per device.

The two bounds contain the cost of a wide request; they do not remove it.
A multi-binding GETNEXT still runs inline on the shared UDP handler.
A 40-binding SNMPv1 GETNEXT on `cisco_crs_x` takes about 104 ms, and a 68-binding one about 177 ms.

One request sees one LLDP topology generation across all its bindings.

### Shipped data fidelity

Whether a value is *encodable* is checked at load.
Whether it is *faithful to the vendor's MIB* is a separate question with a separate answer.
Both are on the [SNMP data fidelity](../explanation/snmp-data-fidelity.md) page.

## Response size, `max-repetitions` and truncation

An SNMP response is bounded so the resulting UDP **frame** fits the link: the payload ceiling is the MTU minus the IPv4 and UDP headers, 1472 bytes at the default MTU, and it moves with `-datagram-mtu`.
See [`-datagram-mtu`](cli-flags.md) for that flag.

**GETBULK truncates.** A response carrying more variable bindings than fit is cut to what fits, per RFC 3416 §4.2.3, with `error-status` left at `noError`.
The collector resumes the walk from the last OID returned, so no data is skipped.
At least one binding is always emitted, even when it does not fit, because an empty binding list with no error stalls a walk.

**GET does not truncate.** A GET response that will not fit is replaced by `error-status = tooBig(1)` with an empty variable-binding list, per RFC 3416 §4.2.1.
A GET requester asked for specific bindings and has no resume point, so a partial answer would be a wrong answer it could not detect.
nl6 supports multi-binding GETs and returns every binding in request order when they fit.

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
These byte figures are indicative at the default MTU.
What is enforced is the bound itself: a response always fits one un-fragmented frame.

The 30 × 2 row is the OpenNMS collector default (`max-vars-per-pdu` 30, `max-repetitions` 2).
It fits with 36 bytes to spare.

### `max-repetitions` is honoured as sent

Any value is accepted and used, at any BER width.
A negative value is treated as 0, per RFC 3416's definition of the field as non-negative.

### SNMPv3 values are typed like v2c

The same OID carries the same ASN.1 type whichever version answered.

### SNMPv3 GETBULK answers every column

A v3 GETBULK applies the RFC 3416 §4.2.3 split to every name in the scoped PDU: the first `non-repeaters` columns get one successor each, and the rest are walked `max-repetitions` times, interleaved one binding per column per repetition.
With non-repeaters present and `max-repetitions` zero, the non-repeater bindings are returned.
A request for zero repetitions and no non-repeaters is answered with an empty binding list, not an `endOfMibView`.

A column that reaches the end of its MIB view is padded with its own requested OID and `endOfMibView`, so the interleave stays aligned.
**A multi-column response is byte-identical to v2c**, tail padding included.

**A single-column v3 walk stops instead.** A walk on one column that runs out mid-response ships what it collected, and the next request receives the exception on its own.
A single column already past the end of the MIB is answered with its own OID and `endOfMibView` rather than with an empty list.

A malformed variable-bindings list discards the datagram exactly as on the v1/v2c path.
A declared container length that overruns what contains it is malformed, not absent.

### Known limitations

**An SNMPv3 GET or GETNEXT answers its first variable binding only.**
A v3 manager fetching several columns per round trip gets the first.

**SNMPv3 GETBULK is bounded by measurement, not arithmetic.**
A v3 envelope's size depends on the engine ID, the user name and the privacy padding, so the response is built through the real encoder and bindings are dropped from the end until it fits.

**SNMPv3 `msgMaxSize`.** A v3 GETBULK response fits the smaller of the link-MTU-derived budget and the `msgMaxSize` the requester declared (RFC 3412 §7.1).
A declaration below 484, the floor RFC 3412 §7.2 sets, is malformed and is ignored.
Single-binding v3 GET and GETNEXT responses do not consult `msgMaxSize`, since they cannot approach either bound.

### A malformed variable-bindings list discards the request

A variable-bindings list that is not a valid ASN.1 encoding makes the whole PDU malformed, and RFC 1157 §4.1 (step 1) and RFC 3412 §7.2 discard such a datagram rather than answering it.
nl6 does the same for SNMPv1 and v2c GET, GETNEXT and GETBULK: no response datagram is sent at all.
The parser checks the list length against the datagram, each binding's framing, the name's tag, length and content, and that exactly one value follows the name.
The first such discard on a device is logged once.
nl6 does not serve `snmpInASNParseErrs`, so the discard is not counted anywhere a manager can poll.

A PDU whose variable-bindings list is empty, or whose envelope cannot be read as far as the list, is still answered.
The request parser falls back to `sysDescr.0`, so what comes back is one binding the requester did not name.

On SNMPv3:

- A malformed scoped PDU is discarded.
- A request that fails to decrypt is answered with a `usmStatsDecryptionErrors` Report, as RFC 3414 §3.2 step 8 requires.
- A PDU type nl6 does not serve (INFORM, TRAP, Report) and an empty variable-bindings list are discarded too, and only the first binding's name is validated.
- A malformed `SET` list is discarded under the same rule at every version.
- A PRIV-flagged request to a device configured without privacy is answered with a `usmStatsUnsupportedSecLevels` Report (RFC 3414 §3.2 step 5).

A Report carries request-id 1 and the request's `msgID` echoed.

Two Reports are **authenticated**, and the rest are not.
A `usmStatsNotInTimeWindows` Report is signed so a manager can trust the engine time it carries and resynchronise, and a `usmStatsUnsupportedSecLevels` Report refusing a `SET` is signed when the request itself authenticated.
On a wrong digest or an unknown user there is no agreed key to sign with.

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

### The error ladder

Each binding is tested in RFC 3416 §4.2.5's order and the first failure names the binding in `error-index` (1-based).
Every binding is validated before any is applied, so a request in which one binding fails changes nothing.
In success and in every error case the response's variable bindings are the request's own bytes, values included.

| Condition | v2c / v3 | v1 (RFC 3584 §4.3) |
|---|---|---|
| name is not `ifAdminStatus.<N>` and shares no writable prefix | `notWritable(17)` | `noSuchName(2)` |
| value tag is not INTEGER | `wrongType(7)` | `badValue(3)` |
| INTEGER content is not a valid encoding | `wrongEncoding(9)` | `badValue(3)` |
| value outside 1..3 | `wrongValue(10)` | `badValue(3)` |
| `<N>` is not an ifIndex the device owns, or the name has the wrong arity under the column | `noCreation(11)` | `noSuchName(2)` |

The value tests run before the instance test, so `ifAdminStatus.999 = 7` is `wrongValue`, not `noCreation`.
A name under the column with the wrong arity, the bare column or `...7.1.2`, is `noCreation` rather than `notWritable`.

`readOnly(4)` is never emitted.
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

That silence is what real hardware does, so the device logs the cause once:

```
SNMP <device>: discarded a SetRequest: community does not match the configured write community (further refusals suppressed for this device)
SNMP <device>: discarded a SetRequest: no write community is configured, so no v1/v2c write is admitted (set -snmp-write-community, or write_community on the REST create body) (further refusals suppressed for this device)
```

The line is emitted at most once per device, because the condition is attacker-controlled.
If `snmpset` times out against a device that answers `snmpget`, that log line is the answer.

**SNMPv3: the minimum security level.**

| Setting | Where |
|---------|-------|
| `-snmp-set-min-security-level none\|auth\|priv` | seeds the `-auto-start-ip` batch, default `auth` |
| `snmpv3.set_min_security_level` | the `snmpv3` block of the `POST /api/v1/devices` body |

An unrecognised `-snmp-set-min-security-level` is fatal at startup, after `-help` and `-version` and before any subsystem starts.
An unrecognised `set_min_security_level` on the create body is rejected with 400.

`none` is `noAuthNoPriv`, `auth` is `authNoPriv`, `priv` is `authPriv`.
A `SET` below the minimum is answered with a `usmStatsUnsupportedSecLevels` Report, which is what RFC 3414 §3.2 step 5 prescribes.

The Report is **signed when the request authenticated**, so a manager that got its key right and only its level wrong can verify the refusal.
A `noAuthNoPriv` refusal is unsigned and carries the discovery shape, with no user name and no digest.

The v3 user check and the USM verification a `GET` receives run **first**, so an unknown user still gets `usmStatsUnknownUserNames` and a wrong digest still gets `usmStatsWrongDigests`.

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
The line says so:

```
… — v1/v2c SET: refused (no write community configured); v3 SET: minimum security level authNoPriv — UNREACHABLE: this fleet is configured with no authentication protocol, so no v3 SET can be admitted
```

Two things that line does not tell you:

- It describes the **auto-start batch only**. A device created over `POST /api/v1/devices` takes its admission from the request body. Omit `write_community` there and that device refuses every v1/v2c `SET`, even on a fleet started with `-snmp-write-community`.
- The write community itself is never printed, and never appears in an API response. `GET /api/v1/devices` does not echo it.

To let any manager that can reach the port write, run with `-snmp-write-community public -snmp-set-min-security-level none`.

**What this is not.** There is no read community, no VACM, no per-user or per-object write privilege, and no second v3 user.
Refusals are not counted anywhere a manager can poll: nl6 serves no part of the SNMP group (`1.3.6.1.2.1.11`), so a GET of `snmpInBadCommunityNames` answers `noSuchObject` like any other unimplemented OID.

### Interactions

The link state a `SET` of `up(1)` releases oper to is whatever last moved it: `-if-scenario 3`, a flap, or a REST `oper-status` POST.
No sequence of SETs can produce `ifAdminStatus = down(2)` with `ifOperStatus = up(1)`.

A `SET` is read back under every `-if-scenario`.
The scenario shapes the state engine's initial seed and nothing else, so a `SET`, a REST POST, a flap and the seed all move the same value that `GET`, a walk, gNMI and the REST view read.

### Verified against net-snmp

`make test-interop` drives `snmpset` and `snmpget` over a real UDP socket under v1, v2c and v3 authPriv.
It asserts the round trip, every error-status row by net-snmp's own printed reason, and the `linkDown` and `linkUp` that `snmptrapd` receives.
It also asserts the three refusals: a wrong community, no write community, and a `noAuthNoPriv` `snmpset` below the minimum.
Each refusal has a positive control on the same listener, so a dead socket cannot pass as a refusal.

## Malformed-datagram handling

All devices answer from one process, so the request parsers are required to be **total**: any byte sequence produces a value or an error, never a panic.
There is no `recover()` on the request path.
Fuzz targets hold the guarantee, and `go test` replays their committed corpus under `testdata/fuzz/` on every run.

The envelope is parsed as BER, not DER.
A non-minimal version INTEGER such as `02 02 00 01`, and a request-id of up to five octets, are read correctly.
A version INTEGER with no content octets (`02 00`) is not legal BER but is served leniently, as v2c.

## OID lookup internals

OIDs are stored per device in a lock-free map, and each OID has a pre-computed pointer to its lexicographic successor, so `GETNEXT` and `GETBULK` never scan the table.

OIDs in resource files may be written with or without a leading dot.
The loader normalises them to the net-snmp convention (`.1.3.6.1…`) at startup.

## ifStackTable

`ifStackTable` (`1.3.6.1.2.1.31.1.2`) says which interface runs over which: `ifStackStatus.<higher>.<lower>` reads `active(1)`.
Only `ifStackStatus` is served.
Three profiles carry the table, and on each it is complete in the RFC 2863 sense: every interface is in at least two rows, with `0` standing for "nothing above" (`ifStackStatus.0.<I>`) or "nothing below" (`ifStackStatus.<I>.0`).

- `juniper_mx10004`: each logical unit over its port (`ifStackStatus.73.1` is `xe-0/0/0.0` over `xe-0/0/0`, `ifStackStatus.78.77` is `fxp0.0` over the management port `fxp0`), generated from the chassis model.
- `cisco_asr9902`: each VLAN subinterface over its port or bundle, and `Bundle-Ether1` over its two members, generated from the chassis model.
- `nokia_7750_sr12`: the router interface `toWAN` over `port 1/1/1`.

So a port that carries units has a `<port>.0` row and no `0.<port>` row, a unit has `0.<unit>` and `<unit>.<port>`, and a bundle with members below and a subinterface above has neither marker.
A collector that builds the interface hierarchy from IF-MIB finds the same parents here that gNMI shows by nesting each subinterface under its port, and bundle membership, which no name encodes.
The interface state engine reads the same rows: a row with one lower layer makes the higher layer follow it, two or more make it an aggregate whose counters sum its members, and the `0` markers are ignored.
Other profiles serve no `ifStackTable`.

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

An interface whose profile declares `ifHighSpeed` 0 (or `ifSpeed` 0 without an `ifHighSpeed` row) carries no traffic: every column above stays 0.
Every column on this page holds while the interface's derived `ifOperStatus` is not `up(1)` and resumes from the held value when it returns; see [Interface state](./interface-state.md).
A subinterface or a stacked interface serves a fixed share of its parent's served delta, and an interface with two or more `ifStackTable` lower layers serves the sum of its members', so a parent is at least the sum of its children and a bundle equals the sum of its members on the octet columns.
A missing or unparsable speed row still means 1 Gbit/s.
The cisco_asr9902 Loopback0 and Null0 use this.

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

The interfaces that get these columns are the ones with an `ifHCInOctets` row in the profile.
An interface without one has no dynamic counters.
A static row in a profile for any of these columns is never served, because the counter engine answers first.
The exceptions are `ifAdminStatus` (`.7`) and `ifOperStatus` (`.8`): their static rows are read once to seed the interface state engine, so they must stay in the profile.

**The shadow identity is nl6's choice.** RFC 2863 does not define `ifInOctets` as the low 32 bits of `ifHCInOctets`, and §3.1.6 mandates only which width an agent must serve at which speed.
Deriving one from the other is the convention real agents follow, and it keeps the two columns from contradicting each other.

**The identity is exact only at one evaluation instant.** The sFlow `counter_sample` path and gNMI evaluate every column at one instant, so their values satisfy `shadow == uint32(HC & 0xFFFFFFFF)` byte for byte.
The SNMP path reads the clock per variable binding and per walk step.
So a multi-varbind GET, or a GETNEXT/GETBULK spanning `ifInOctets` and `ifHCInOctets`, returns two values that differ by whatever accrued in between.
At 400 Gb/s that is roughly 5×10⁷ octets per millisecond.

Properties common to every dynamic counter:

- **Monotonic.** The underlying octet integral never decreases (rate floor is 60 % of `ifSpeed`), and every derivation is base-plus-growth, so Counter64 columns are strictly increasing. Counter32 shadow columns wrap naturally at 2³². `ifCounterDiscontinuityTime` (`.19`) is not served: no shipped profile carries it and the cycler does not synthesise it, so a GET answers `noSuchObject`. Wrap is inherent, not a discontinuity.
- **Pre-seeded.** Each counter starts at a base derived from ~24 h of traffic, ratios, and the active error scenario (see below) so a fresh device doesn't look unrealistically pristine.
- **Per-interface variance.** Packet-size divisor jitters ±20 % around 500 B. Mix ratios jitter ±3 % around 85 / 10 / 5 (in) and 90 / 8 / 2 (out). Error and discard ppm values are drawn once from the scenario band, all deterministic from the device seed.
- **Sine-driven correlation.** All derived counters share the master octet sine wave, so when a link is "quiet" (60 % of `ifSpeed`) the full counter family slows together, matching how real hardware behaves under reduced traffic.
- **SNMP ↔ sFlow agreement.** Both read paths resolve the same counter engine, so an sFlow `counter_sample` and an SNMP GET evaluated at the same instant carry the same values. Two varbinds in one SNMP response are two instants (see above).
- **Zero-goroutine cost.** Every counter is computed on-demand from the current time against analytic formulas. There is no per-interface goroutine, no polling loop.
- Values are visible on both `GET` and `GETNEXT` / `GETBULK`.

**Counter32 wrap guidance.** The fastest-wrapping objects on the device are the two octet columns: `ifInOctets` / `ifOutOctets` cover 2³² octets in about **3.4 s at 10 Gb/s** and about **86 ms at 400 Gb/s** at line rate (the dial's 60 to 100 % duty cycle stretches that by at most two thirds).
No poll interval makes a 32-bit octet counter usable at those speeds, which is why RFC 2863 §3.1.6 requires the 64-bit octet counters above 20 Mb/s.
Poll `ifHCInOctets` / `ifHCOutOctets` instead.

The packet columns wrap more slowly.
At 10 Gbps / 80 % util / 500 B average packet size, `ifInUcastPkts` wraps every ~26 minutes, and every ~2.6 minutes at 100 Gbps.
The rule is the same one: above 20 Mb/s, poll the HC columns.
Collectors handle a wrap via the delta-modulo convention, which only works if the poll interval is shorter than the wrap.

### Per-device error scenario

The `ifInErrors` / `ifOutErrors` / `ifInDiscards` / `ifOutDiscards` rates are driven by a per-device scenario:

| Scenario | `errPpm` | `discPpm` | Typical dashboard appearance |
|----------|----------|-----------|------------------------------|
| `clean` *(default)* | `0` | `0` | Flat line at the baseline |
| `typical` | `10 to 100` | `20 to 200` | Faint steady slope (good production gear) |
| `degraded` | `1 000 to 10 000` | `2 000 to 20 000` | Visible error-rate alert candidates (0.1 to 1 %) |
| `failing` | `10 000 to 100 000` | `20 000 to 200 000` | Link-flap / bad-cable alarms (1 to 10 %) |

Set for the auto-start batch via the CLI flag `-if-error-scenario <name>`, or per-device via `if_error_scenario` in the `POST /api/v1/devices` body.
See [CLI flags reference](cli-flags.md#error--discard-scenario) and [Web API reference](web-api.md#create-devices).

### Example walks

```bash
# Walk ifXTable: covers all HC counters, Counter32 shadows, and ifHighSpeed
snmpwalk -v2c -c public 10.42.0.1 1.3.6.1.2.1.31.1.1

# Walk ifTable: covers ifInOctets, ifInUcastPkts, ifInDiscards, ifInErrors,
# ifOutOctets, ifOutUcastPkts, ifOutDiscards, ifOutErrors
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

CPU, memory, and temperature OIDs cycle through a 100-point pre-generated sine-wave pattern per device.
The point served depends on the time since the device was created, one point per minute, and reading an OID does not move it.
All of a device's metrics read the same point at the same instant.
One SNMP request reads the point once, so every OID in a GET, GETNEXT or GETBULK comes from the same point, even across a minute boundary.
Memory used plus memory free read in one request is the total on every profile that serves both.
Per-category device profiles define the baseline ranges and spike amplitudes.
GPU servers add per-GPU metric cycling on top of this.
See [GPU simulation](gpu/index.md).

## Interface state

`-if-scenario` seeds `ifAdminStatus` and the link state once per interface.
What each scenario seeds is in [Interface state → Interface-state scenarios](interface-state.md#interface-state-scenarios).

**Dynamic state engine.** `ifOperStatus.<N>` (`.8`), `ifAdminStatus.<N>` (`.7`), and `ifLastChange.<N>` (`.9`) are served from the per-device interface state engine.
The JSON rows are read once as the engine's seed.
Three mutation sources update them at runtime:

- **Flap scheduler**: `-if-flap-scenario {clean|rare|typical|aggressive}` drives Poisson-distributed link flaps per (device, ifIndex). See the [interface state engine reference](interface-state.md).
- **REST control plane**: `POST /api/v1/devices/{ip}/interfaces/{N}/{oper,admin}-status` flips state for test-harness use.
- **SNMP SET**: a `SetRequest` of `ifAdminStatus.<N>` through the same funnel. `ifOperStatus` follows by derivation, asymmetrically: `down(2)` and `testing(3)` force it, `up(1)` releases it to the link. See [SetRequest](#setrequest).

SNMP `ifOperStatus.<N>` and gNMI `/interfaces/interface[name=*]/state/oper-status` read from the same slot table and agree byte-for-byte at every instant.
An oper-status transition also fires the device's role-tagged link trap and syslog for that interface.

**`ifLastChange` epoch.** RFC 2863 defines `ifLastChange` relative to `sysUpTime`.
nl6 computes it relative to the device's state-engine construction time, which is the same instant as device boot.

**`ifLastChange` resolution.** SNMP encodes `ifLastChange` as `TimeTicks` (centiseconds), so two transitions less than 10 ms apart collide to the same wire value.
The gNMI `state/last-change` leaf carries nanoseconds, so the same two transitions are distinguishable there.
Only a harness driving back-to-back REST POSTs against the same `(device, ifIndex)` is likely to see this.

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

A polled device and a trap from that device report **different** `snmpEngineID` values.
This is not a defect.
The poll path's engine ID is fleet-wide.
Each notification originator derives its own from its IPv4, per RFC 3411 §5.

See [SNMP trap reference](snmp-traps.md) for wire format, the JSON catalog schema, and the HTTP endpoints, and [SNMP trap export how-to](../ops/snmp-traps.md) for enabling the feature and the `snmptrapd` smoke test.
