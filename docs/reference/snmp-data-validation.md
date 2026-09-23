# SNMP data validation

What nl6 checks about a resource file's `snmp` array at load, and which vendor subtrees a human has read against a MIB.
The reasoning behind each rule, and the audit findings, are on [SNMP data fidelity](../explanation/snmp-data-fidelity.md).

## Load rules

`validateSNMPResourceValues` runs three rules over every `snmp` entry, in the order the encoder applies them.
Each rule decides by calling the production encoder, never by a second predicate.

| Rule | Refuses | Decided by |
|---|---|---|
| 1. Sentinel | a response exactly equal to `noSuchObject` or `endOfMibView` | `isSNMPExceptionValue`, the encoder's own exact test |
| 2. OID-typed value | a value on an `OBJECT IDENTIFIER` leaf that `encodeOID` cannot represent | calling `encodeOID` and testing for the degenerate `06 00` |
| 3. Typed class | a value on a leaf the type table types that does not encode at that type | calling `encodeTypedValue` and comparing the emitted tag with the declared one |

Rule 3 covers `Counter32`, `Gauge32`, `TimeTicks`, `Counter64` and `IpAddress` leaves.

| Value on a typed leaf | Outcome |
|---|---|
| negative on `Counter32`, `Gauge32`, `TimeTicks` | loads with a warning; wrap-cast to 32 bits on the wire |
| negative on `Counter64` | refused |
| surrounding whitespace (`" 42"`) | refused |
| units, hex, fraction, or past the type's width | refused |
| `IpAddress` leaf not a dotted-quad IPv4 | refused |

A rejection at startup exits the process.
A rejection over REST answers `400` with the file's base name, the OID and the value.
See [Web API → `resource_file` failures](web-api.md#resource_file-failures).

## What the rules do not cover

| Surface | Status |
|---|---|
| OID keys | unchecked; only values are validated |
| Bare table columns and wrong INDEX arity | no rule; needs the MIB. A hand audit deleted 61 entries |
| Semantic faithfulness to the MIB | no rule; five arcs audited by hand, fourteen labelled `UNAUDITED-ARC(<pen>)` |
| MAX-ACCESS (`write-only`, `not-accessible`) | no rule; one confirmed `write-only` object (`writeMem`) deleted |
| Leaves the type table does not type | served as INTEGER or OCTET STRING, whatever the value parses as |
| Vendor 64-bit counters | untyped, served as INTEGER, not diverted for SNMPv1 |
| `sysName`, `sysLocation` | served outside the resource map; `sysLocation` is filtered once at load |
| SSH, API, optical sections; trap and syslog catalogs | never reach `encodeTypedValue`; the catalogs have their own validation |
| Version-0 GETBULK | answered as-is, `0x46` tags included |

## Vendor arc disposition

Every enterprise arc a shipped profile serves is exactly one of three things.
A new device type that serves a vendor subtree and is none of them fails `TestEveryVendorArcIsAuditedLabelledOrExcluded` by name.

| Disposition | Meaning | Where it is recorded |
|---|---|---|
| audited | somebody read the vendor's MIB | the PEN is in `auditedArcPENs`, each row naming its reading test |
| labelled | nobody has read a MIB for it | every part carrying the arc has `UNAUDITED-ARC(<pen>)` in its `_comment` |
| excluded | the arc is not a vendor claim | the `(profile, PEN)` pair is in `excludedArcPairs` with a reason |

### Audited arcs

Counts are distinct OIDs found wrong or unresolvable, out of distinct OIDs read.

| Vendor | PEN | Wrong |
|---|---|---|
| Palo Alto | 25461 | 8 of 11 |
| Cisco | 9 | 11 of 13 |
| Arista | 30065 | 6 of 6 |
| Ciena | 1271 | 0 of 1 |
| Juniper | 2636 | 13 of 15 (19 of 22 entries) |
| NVIDIA | 5703 | not applicable: NVIDIA publishes no SNMP GPU MIB, so every object below the PEN is nl6's own definition |

### Labelled arcs

Fourteen profiles, one arc each, nineteen parts carrying the marker.

| Profile | PEN |
|---|---|
| `check_point_15600` | 2620 |
| `dell_emc_unity` | 1139 |
| `dell_poweredge_r750` | 674 |
| `dlink_dgs3630` | 171 |
| `extreme_vsp4450` | 1916 |
| `fortinet_fortigate_600e` | 12356 |
| `hpe_proliant_dl380` | 232 |
| `huawei_ne8000` | 2011 |
| `ibm_power_s922` | 2 |
| `nec_ix3315` | 119 |
| `netapp_ontap` | 789 |
| `nokia_7750_sr12` | 6527 |
| `pure_storage_flasharray` | 40482 |
| `sonicwall_nsa6700` | 8741 |

### Excluded pairs

| Profile | PEN | Reason |
|---|---|---|
| `aws_s3_storage` | 32473 | RFC 5612 documentation PEN; no vendor MIB exists to audit against |
| `cisco_catalyst_9500`, `cisco_nexus_9500`, `juniper_mx960`, `palo_alto_pa3220` | 0 | `1.3.6.1.4.1.0.0` is the `entPhysicalVendorType` placeholder; PEN 0 is IANA-reserved |
