/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// nl6#593. ONE OID, ONE TYPE, PER PROFILE.
//
// A trap catalog DECLARES a varbind's ASN.1 type ("type": "octet-string"). The
// resource `snmp` array SEPARATELY determines the type of a GET of that same
// OID, via oidTypeTable plus encodeTypedValue's value heuristics. The two
// surfaces are validated by entirely separate code paths and nothing joined
// them, so one profile could answer one object at two different types depending
// on how it was asked.
//
// cisco_ios shipped exactly that: ciscoEnvMonSupplyStatusDescr.1
// (1.3.6.1.4.1.9.9.13.1.5.1.2.1) was declared octet-string by its trap and
// answered ASN.1 INTEGER by a poll, because the resource value was the string
// "1" and that OID is not in oidTypeTable, so encodeTypedValue's
// integer-parseable branch took it. Found by hand during nl6#592 and fixed
// there. That OID is the regression anchor and is pinned BY NAME below.
//
// THE RULE, and why it is shaped the way it is:
//
//  1. BOTH TAGS COME FROM THE PRODUCTION ENCODERS. The trap side is
//     encodeVarbindTyped (and, for the three varbinds the encoder prepends,
//     encodeVarbindTimeTicks / encodeVarbindOID); the poll side is
//     encodeTypedValue. A hand-written type map would encode today's agreement
//     between the two and then rot silently, which is precisely how
//     trap_catalog.go's validateDottedOID drifted from the encoder in nl6#539.
//     The trap tag is READ BACK OUT of the encoded varbind rather than mirrored
//     from the encoder's switch, so a new case there is picked up for free.
//
//  2. _common/traps.json IS APPLIED TO EVERY PROFILE, because it is merged into
//     every device type's effective catalog. The merge is done by the
//     PRODUCTION resolver (ScanPerTypeTrapCatalogs plus the universal
//     fallback), not by re-reading the files.
//
//     THIS ARM IS PINNED BY THE CONTROL, NOT BY THE COUNTS, and the difference
//     was demonstrated rather than assumed. Inserting `if !entry.fromOverlay {
//     continue }` just before the occurrence counter — never joining a
//     universal varbind at all — leaves EVERY count in this file unchanged and
//     the package green, because all six of _common's varbinds are templated
//     and therefore contribute zero occurrences. So the control passes a
//     SYNTHETIC universal whose varbind has a literal OID the planted profiles
//     serve, and requires a finding per planted profile. That is the
//     assertBareColumnDetectionIsCorpusWide lesson: a narrowing changes no
//     shipped byte, so no digest and no census can see it.
//
//  3. THE POLL SIDE MUST BE THE PRODUCTION POLL SIDE, not "some resource entry
//     with this OID". Two ways that can be false, and both ship today:
//
//     - DUPLICATE ENTRIES. 111 (profile, OID) pairs are served twice — 64 in
//     cisco_nexus_9500, 32 in juniper_mx960, 5 in each nvidia_* — all
//     ifHighSpeed rows, all currently carrying identical values, so nothing
//     diverges yet. buildResourceIndexes does oidIndex.Store in sorted order,
//     so production is LAST-wins, and after a NON-STABLE sort.Slice which of
//     several equal keys wins is unspecified. A joined OID with more than one
//     entry is therefore REPORTED, never silently resolved.
//     - SHADOWED OIDS. findResponse answers ahead of oidIndex from
//     sysName.0/sysLocation.0 (which buildResourceIndexes skips outright),
//     getMetricValue, IfCounterCycler.GetDynamic, the interface-state
//     override and the LLDP / ifAlias provider. A resource value for such an
//     OID is dead data, so comparing against it compares against something no
//     collector ever sees. Reported, not compared.
//
//  4. A VARBIND NAMING AN OID THE PROFILE DOES NOT SERVE IS NORMAL. 182 of the
//     185 joinable varbinds are in that bucket. THE CLAIM IS ONLY THAT THE
//     PROFILE SERVES NO RESOURCE ENTRY FOR THEM — this guard cannot read a MIB
//     and so cannot say they are notification-only objects, however likely that
//     is. They are COUNTED so the number is visible when it moves, and never
//     flagged. Flagging them would turn an agreement rule into a coverage rule,
//     which is a different question and not this one.
//
//  5. THE POSITIVE CONTROL HAS EIGHT ARMS (the nl6#605 lesson, extended). A test
//     asserting ZERO findings cannot fail on its own, and a rule that reported
//     EVERY joined pair would pass a one-armed control. The arms: a planted
//     disagreeing pair must be reported; a planted AGREEING pair must be
//     silent; a planted UNENCODABLE literal must surface as an encoder failure
//     rather than be laundered into agreement; a planted DUPLICATE resource
//     entry must be reported; and a planted SHADOWED OID must be reported as
//     shadowed — that fifth arm declares a type that AGREES with the resource
//     value, so a rule that stopped honouring shadowing falls silent rather
//     than reporting a different kind; and a planted overlay that KEEPS a
//     universal entry's NAME while swapping its varbinds must be reported as
//     drift, because MergeOverlay replaces a same-named entry wholesale and no
//     shipped overlay does that today. Arms seven and eight are rule 6's pair,
//     one declaring the wrong type on a leaf oidTypeTable types and one
//     declaring the right one; the shipped count of typed unserved varbinds is
//     ZERO, so that pair is the only thing that can make rule 6 fail at all.
//     The universal-catalog arm of (2) rides on the first two.
//
//     RULE 7 HAS ITS OWN THREE-ARMED CONTROL, in assertCatalogSelfDetectionWorks,
//     because it reads catalogs rather than joins and so shares no fixture with
//     these eight.
//
//  6. A TYPED LEAF IS COMPARABLE WITHOUT A SERVED VALUE (nl6#607, widening 1).
//     oidTypeTable types the LEAF, so for any OID in it the poll-side tag is
//     knowable with no resource entry at all: encodeTypedValue dispatches on
//     snmpTypeTag(oid), and nl6#541's typed-class rule refuses at load any value
//     that would not encode at its declared tag. Such a varbind is therefore
//     compared instead of landing in the unserved bucket.
//
//     THE COMPARISON CHANGES SHAPE AND THE TWO KINDS STAY DISTINGUISHABLE. Rule
//     1 is "declared type versus the tag the SERVED VALUE emits". This is
//     "declared type versus the tag the LEAF'S DECLARED TYPE emits", which is a
//     step closer to a MIB check while still being entirely inside nl6. They are
//     separate finding kinds, and the census counts them separately, because
//     conflating them would make the numbers mean nothing.
//
//     IT COVERS ZERO OCCURRENCES TODAY AND THAT IS EXPECTED, NOT A DEFECT.
//     oidTypeTable types standard mib-2 leaves (system, ifTable / ifXTable, the
//     RFC 4293 IP statistics tables, dot3HCStats, some LLDP columns) while trap
//     varbinds name vendor notification objects, so the two sets do not
//     currently intersect. This is a tripwire for a future catalog that declares
//     octet-string on an ifHC* column, not a rule that found something. The
//     count is pinned at 0 and the control is what makes a zero able to fail.
//
//  7. A CATALOG MUST NOT CONTRADICT ITSELF (nl6#607, widening 2). Two varbinds
//     in one EFFECTIVE catalog naming the same OID at different declared types
//     are the same "one object, two types" defect, and rule 1 cannot see it
//     unless the OID also happens to be served.
//
//     IT NEEDS NO RESOURCE DATA, WHICH IS WHY IT REACHES WHAT NOTHING ELSE DOES.
//     Two surfaces were entirely unchecked before it. ciena_waveserver5 is 156
//     of the 185 examined occurrences and joins ZERO, so its catalog had no
//     internal check of any kind; its four entries share one trap OID by design
//     (one notification differing only in severity and which condition flag is
//     set), which makes a same-OID-different-type slip both plausible and
//     previously undetectable. And the UNIVERSAL catalog's whole comparison
//     surface is TEMPLATED, so rule 1 can never reach any of it. A templated
//     OID names no fixed object and is not joinable. Two entries declaring one
//     at two types still fire at two types.
//
//     CHECKED PER DISTINCT EFFECTIVE CATALOG, not per profile. 26 profiles carry
//     the universal catalog unchanged, so a defect in it is ONE fact; reporting
//     it 26 times would bury the three overlay catalogs' findings under it.
//
//     THE TAG COMES FROM THE DECLARED TYPE, VIA THE PROBE, not from the varbind's
//     own value. What a trap varbind puts in the value slot is a function of its
//     declared TYPE alone (the last bullet below), so resolving through the type
//     keeps this rule answering the question it asks. Resolving through the value
//     instead would make an unencodable literal or a templated value into an
//     encoder failure here, which is rule 1's finding to report, not this one's.
//
// WHAT THIS GUARD CANNOT SEE, and it should not be read as broader than it is:
//
//   - IT DOES NOT COMPARE EITHER SIDE AGAINST A MIB. Whether nl6 agrees with the
//     vendor is nl6#590's question. This asks only whether nl6 contradicts
//     ITSELF. jnxFruFailed is the worked example: it declares { jnxFruEntry 9 }
//     — jnxFruTemp, a Gauge32 — as "timeticks". That is a catalog-versus-MIB
//     disagreement, no profile serves that OID, so the join can never reach it
//     and this file would stay green if it were the only guard.
//   - IT JOINS AGAINST STATIC RESOURCE DATA ONLY. An OID served analytically has
//     no `snmp` entry at all, so a varbind naming one lands in the unserved
//     bucket; one that has BOTH a resource entry and a dynamic answer is
//     reported as shadowed (rule 3) rather than compared.
//   - A TEMPLATED OID IS NOT JOINABLE AT ALL. Six varbinds (all of _common's)
//     name "…2.2.1.7.{{.IfIndex}}"; the OID exists only at fire time. Counted in
//     their own bucket rather than swept into "unserved", because the two are
//     different facts and merging them would hide a template appearing where a
//     literal used to be.
//   - A TEMPLATED VALUE IS ENCODED WITH A PROBE, and ONLY a templated value.
//     The tag a trap varbind puts on the wire is a function of its declared TYPE
//     alone, so any value the type accepts resolves it; but falling back to a
//     probe on ANY encode error would launder real defects into agreement — an
//     integer varbind valued "up" fails at every fire, and ApplySizeBudget
//     disables the whole entry for one. The gate is on the value containing
//     "{{", nothing else.

// ── the census, RE-DERIVED on every run ─────────────────────────────────────
//
// Pinned rather than only logged because a rule that finds nothing to join
// reports no findings either, and a silent collapse of the join is the failure
// mode that would make this file worthless while staying green.

const (
	// trapCatalogVarbindsShipped is the distinct catalog varbinds across every
	// shipped traps.json, counted as they appear in the profiles' EFFECTIVE
	// catalogs: _common's 6, ciena's 156, cisco_ios's 14, juniper_mx240's 15.
	trapCatalogVarbindsShipped = 191

	// trapVarbindsWithTemplatedOID is how many of those name no fixed object.
	// All six are _common's link-trap ifTable varbinds.
	trapVarbindsWithTemplatedOID = 6

	// trapPollJoinOccurrences is the (profile, varbind) pairs the join examines:
	// every template-free varbind of every profile's effective catalog. It
	// equals the non-_common total only because all six _common varbinds are
	// templated; a literal one would be examined 29 times, once per profile.
	trapPollJoinOccurrences = 185

	// trapPollUnservedVarbinds is the rest: the profile serves no resource entry
	// for them. Counted, never flagged (rule 4).
	trapPollUnservedVarbinds = 182

	// trapPollTypedUnservedVarbinds is the subset of those that oidTypeTable
	// nonetheless types, and which rule 6 therefore compares against the leaf's
	// declared tag rather than leaving uncompared.
	//
	// IT IS ZERO, AND ZERO IS THE EXPECTED VALUE. oidTypeTable types standard
	// mib-2 leaves; trap varbinds name vendor notification objects; the two sets
	// do not intersect in the shipped corpus. The rule is a tripwire for a future
	// catalog declaring a type on a leaf the table already types, so this
	// constant RISING is not by itself a defect. It means such a varbind now
	// exists and is being compared. What would be a defect is a disagreement,
	// which is reported separately. A zero cannot fail on its own, so what makes
	// this assertion able to fail at all is the control's rule-6 arm.
	trapPollTypedUnservedVarbinds = 0

	// trapCatalogProfiles is every shipped device type, and
	// trapProfilesCarryingUniversal how many carry the universal catalog's
	// entries UNCHANGED in their effective catalog. A profile declaring
	// `extends: false`, or an overlay that overrides a universal entry name with
	// different varbinds, would legitimately move the second number.
	trapCatalogProfiles           = 29
	trapProfilesCarryingUniversal = 29
)

// trapPollJoinedPairsShipped is the joined set BY IDENTITY, not by count.
// A count alone goes quiet on a swap: drop one pair, gain another, and the
// total is unchanged. The first row is nl6#592's regression anchor — the OID
// that actually carried the defect this whole file exists for.
var trapPollJoinedPairsShipped = [][2]string{
	{"cisco_ios.json", ".1.3.6.1.4.1.9.9.13.1.5.1.2.1"}, // ciscoEnvMonSupplyStatusDescr.1, nl6#592
	{"juniper_mx240.json", ".1.3.6.1.4.1.2636.3.1.2.0"}, // jnxBoxDescr
	{"juniper_mx240.json", ".1.3.6.1.4.1.2636.3.1.3.0"}, // jnxBoxSerialNo
}

// trapPollPerCatalogCensus is the {examined, joined} breakdown PER CATALOG FILE.
//
// The aggregate hides the shape: ciena_waveserver5 is 156 of the 185 examined
// occurrences and joins ZERO of them, so a normalisation or path bug that
// de-joined ciena would be indistinguishable from ciena genuinely serving none
// of its trap OIDs. Ciena's zero is therefore asserted deliberately rather than
// summed away — that catalog is 39 optical alarm varbinds per entry over four
// entries, naming CIENA-WS alarm objects the profile's resource files do not
// carry, and nl6#601's audit of the same arc reported the two surfaces disjoint.
var trapPollPerCatalogCensus = map[string][3]int{
	"resources/_common/traps.json":           {6, 0, 0}, // all six varbinds templated
	"resources/ciena_waveserver5/traps.json": {0, 156, 0},
	"resources/cisco_ios/traps.json":         {0, 14, 1},
	"resources/juniper_mx240/traps.json":     {0, 15, 2},
}

// trapCatalogSelfCensus is rule 7's comparison surface, per DISTINCT effective
// catalog: {entries, distinct varbind OIDs, OIDs carried by MORE THAN ONE
// varbind}.
//
// THE THIRD NUMBER IS THE ONLY ONE THAT MATTERS TO THE RULE. An OID carried by a
// single varbind cannot disagree with itself, so it is the third column that
// says how much of each catalog is actually under comparison. A change that
// collapsed the grouping, by normalising OIDs differently or by reading the
// overlay file instead of the merged catalog, would drive it to zero while every
// finding count stayed at zero too, and the guard would be silently worthless.
// That is the failure this census exists to make visible.
//
// The universal catalog's 3 are ALL TEMPLATED, which is the point of rule 7:
// they are unreachable to rule 1 by construction, so before nl6#607 nothing
// compared them at all. ciena's 42 of 42 is the other half. Every one of its
// distinct OIDs is carried by several varbinds, and it joins nothing.
var trapCatalogSelfCensus = map[string][3]int{
	trapUniversalCatalogLabel:                {5, 3, 3},
	"resources/ciena_waveserver5/traps.json": {9, 42, 42},
	"resources/cisco_ios/traps.json":         {12, 17, 3},
	"resources/juniper_mx240/traps.json":     {12, 16, 5},
}

// trapUniversalCatalogLabel names the effective catalog carried by every profile
// with no overlay of its own. It is not a path, because it is not a file: it is
// the embedded universal catalog as 26 profiles see it.
const trapUniversalCatalogLabel = "<universal, as carried by profiles with no overlay>"

// trapPrependedJoinedPairs is the coverage of the three varbinds the trap
// ENCODER prepends rather than the catalog declaring (nl6#593 P10):
// sysUpTime.0, snmpTrapOID.0 and, when an entry sets it, snmpTrapEnterprise.0.
//
// IT FINDS NOTHING TODAY AND IT IS NOT EXPECTED TO. 24 profiles serve a static
// sysUpTime.0; oidTypeTable types 1.3.6.1.2.1.1.3 TIMETICKS and the encoder
// prepends TIMETICKS, so the two agree by construction. No profile serves
// anything under 1.3.6.1.6.3.1.1.4, so the two OID-valued prepends never join.
// This is coverage of a surface the catalog does not control, not a near-miss.
const (
	trapPrependedJoinedPairs   = 24
	trapPrependedUnservedPairs = 37 // 29x2 prepends + 3 profiles whose catalog sets snmpTrapEnterprise, less the 24
)

// ── the type vocabulary, driven off the PRODUCTION accept-set ───────────────

// trapTypeProbeValue is a value encodeVarbindTyped accepts for each declared
// type, used ONLY when the catalog value is a template ("{{.IfIndex}}") that no
// encoder can take literally. A template-free value is always encoded as
// written; see the header's last bullet for why the gate is not "any error".
//
// Keyed off trapVarbindTypes, the loader's own accept-set, so a ninth type
// added to trap_catalog.go fails TestEveryTrapVarbindTypeIsProbeable instead of
// silently landing every varbind of that type in the encoder-failure bucket.
var trapTypeProbeValue = map[TrapVarbindType]string{
	TrapVTInteger:     "1",
	TrapVTOctetString: "probe",
	TrapVTOID:         "1.3.6.1.4.1.99997.1",
	TrapVTCounter32:   "1",
	TrapVTGauge32:     "1",
	TrapVTTimeTicks:   "1",
	TrapVTCounter64:   "1",
	TrapVTIPAddress:   "10.0.0.1",
}

// trapDeclaredTagFor asks the PRODUCTION trap encoder what tag this varbind
// puts in the value slot.
func trapDeclaredTagFor(oid string, typ TrapVarbindType, value string) (byte, error) {
	encodeValue := value
	if strings.Contains(value, "{{") {
		probe, ok := trapTypeProbeValue[typ]
		if !ok {
			return 0, fmt.Errorf("value %q is a template and type %q has no probe value, so the "+
				"declared tag cannot be resolved", value, typ)
		}
		encodeValue = probe
	}
	enc, err := encodeVarbindTyped(Varbind{OID: oid, Type: typ, Value: encodeValue})
	if err != nil {
		return 0, err
	}
	return varbindValueTag(enc)
}

// varbindValueTag walks a SEQUENCE { OID, value } and returns the value's tag.
//
// Every bound is written subtractively (`n > len(buf)-pos`), never `pos+n >
// len(buf)`: parseLength accepts a four-octet long form whose ADDITION can wrap
// negative on a 32-bit build and slip through an upper-bound test. That is the
// nl6#547 convention, and it applies here even though the input is produced by
// nl6's own encoder — a bound that is right for the wrong reason is one refactor
// away from being wrong.
func varbindValueTag(enc []byte) (byte, error) {
	if len(enc) == 0 || enc[0] != ASN1_SEQUENCE {
		return 0, fmt.Errorf("varbind is not a SEQUENCE: % x", enc)
	}
	seqLen, pos := parseLength(enc, 1)
	if seqLen < 0 || pos <= 0 || pos >= len(enc) || seqLen > len(enc)-pos {
		return 0, fmt.Errorf("varbind SEQUENCE length is unreadable or overruns: % x", enc)
	}
	end := pos + seqLen
	if enc[pos] != ASN1_OBJECT_ID {
		return 0, fmt.Errorf("varbind does not open with an OID: % x", enc)
	}
	pos++
	oidLen, pos := parseLength(enc, pos)
	if oidLen < 0 || pos <= 0 || pos > end || oidLen >= end-pos {
		return 0, fmt.Errorf("varbind OID length is unreadable or overruns: % x", enc)
	}
	return enc[pos+oidLen], nil
}

// pollTagFor asks the PRODUCTION poll encoder what tag a GET of this OID would
// carry. encodeTypedValue writes the value slot directly, so the tag is byte 0.
func pollTagFor(oid, value string) (byte, error) {
	enc := encodeTypedValue(oid, value)
	if len(enc) == 0 {
		return 0, fmt.Errorf("encodeTypedValue(%q, %q) produced nothing", oid, value)
	}
	return enc[0], nil
}

// ── the poll side's fidelity: what findResponse answers ahead of oidIndex ────

// trapPollShadowedBy names the source that answers this OID BEFORE the static
// oidIndex, or "" when a GET really is answered from the resource entry.
//
// The order mirrors findResponse (snmp_handlers.go) exactly. It is a pure
// function of (profile, OID) so the rule stays testable without a live device,
// and it takes the profile because the metric-OID map is per resource file.
func trapPollShadowedBy(profile, oid string) string {
	switch oid {
	case ".1.3.6.1.2.1.1.6.0":
		return "sysLocation.0 is served from the device (worldcities draw), and buildResourceIndexes " +
			"does not even store it"
	case ".1.3.6.1.2.1.1.5.0":
		return "sysName.0 is served from the device, and buildResourceIndexes does not even store it"
	}
	if m := GetMetricOIDs(profile); m != nil {
		if _, ok := m[oid]; ok {
			return "the metrics cycler answers it (getMetricValue)"
		}
	}
	if ifCyclerOwnsOID(oid) {
		return "IfCounterCycler answers it analytically (ifTable / ifXTable column the cycler owns, " +
			"which since nl6#570/#574 includes the interface-state and octet-shadow columns)"
	}
	if isLLDPOID(oid) || isIfAliasOID(oid) {
		return "the LLDP / ifAlias provider answers it, deliberately ahead of the static entry"
	}
	return ""
}

// ifCyclerOwnsOID reports whether the OID names a column IfCounterCycler serves.
// Driven off ifCyclerColumns, the cycler's own enumeration, so a column added
// there is picked up here rather than needing a second list.
func ifCyclerOwnsOID(oid string) bool {
	for _, c := range ifCyclerColumns {
		if strings.HasPrefix(oid, fmt.Sprintf("%s%d.", c.prefix, c.col)) {
			return true
		}
	}
	return false
}

// ── the join, and the rule over it ──────────────────────────────────────────

// trapPollJoin is one (profile, OID) pair that BOTH a trap catalog varbind and
// at least one resource entry name.
type trapPollJoin struct {
	profile   string // "cisco_ios.json"
	oid       string // normalised, leading dot
	entry     string // catalog entry name
	catalog   string // the traps.json the varbind came from
	trapType  TrapVarbindType
	trapValue string

	// prependedTag is non-zero for the three varbinds the trap ENCODER prepends
	// (sysUpTime.0, snmpTrapOID.0, snmpTrapEnterprise.0). Those carry no catalog
	// "type" at all, so their declared tag comes from calling the production
	// prepend encoder rather than encodeVarbindTyped. Zero means "ask
	// trapDeclaredTagFor", which is what every catalog varbind does.
	prependedTag byte

	// typedLeafTag is non-zero for a varbind the profile serves NO resource entry
	// for, whose OID oidTypeTable nonetheless types (rule 6). The poll-side tag
	// then comes from the leaf's declared type rather than from a served value,
	// and polledValues is empty. Zero means the ordinary case: either the pair is
	// joined against a real value, or the varbind is unserved and untyped and
	// never becomes a join at all.
	typedLeafTag byte

	// Every resource entry the profile carries for this OID, in corpus-walk
	// order. More than one is a finding, not a value to pick from.
	parts        []string
	polledValues []string

	// shadowedBy is non-empty when findResponse answers this OID ahead of the
	// static index, making the resource entry dead data.
	shadowedBy string
}

type trapPollFindingKind string

const (
	findingTypeDisagreement trapPollFindingKind = "type-disagreement"
	findingDuplicateEntry   trapPollFindingKind = "duplicate-resource-entry"
	findingShadowedOID      trapPollFindingKind = "shadowed-poll-value"
	findingEncodeFailure    trapPollFindingKind = "encode-failure"

	// Rule 6. Deliberately a DISTINCT kind from findingTypeDisagreement even
	// though both report two tags: this one compares against the leaf's declared
	// type with no served value behind it, and the remedy differs. Conflating
	// them would make the census meaningless (nl6#607).
	findingTypedLeafDisagreement trapPollFindingKind = "typed-leaf-disagreement"
)

// trapPollFinding is one thing wrong with a joined pair.
type trapPollFinding struct {
	join    trapPollJoin
	kind    trapPollFindingKind
	trapTag byte
	pollTag byte
	detail  string
}

// trapPollFindings is THE RULE, as a pure function over the join, so the
// positive control can require it to REPORT rather than only to stay silent —
// an inline `if` inside the corpus test could not be asked to do that. The
// lesson is bareColumnCountViolation's, in snmp_shipped_corpus_test.go.
func trapPollFindings(joins []trapPollJoin) []trapPollFinding {
	var out []trapPollFinding
	for _, j := range joins {
		switch {
		// Shadowing first: the resource value is not what a GET answers, so
		// every comparison below it would be against data no collector sees.
		case j.shadowedBy != "":
			out = append(out, trapPollFinding{join: j, kind: findingShadowedOID, detail: j.shadowedBy})
			continue
		// Then ambiguity: production is last-wins after a non-stable sort, so
		// there is no single poll value to compare against.
		case len(j.polledValues) > 1:
			out = append(out, trapPollFinding{join: j, kind: findingDuplicateEntry,
				detail: fmt.Sprintf("%d entries: %q in %s", len(j.polledValues),
					strings.Join(j.polledValues, "\", \""), strings.Join(j.parts, ", "))})
			continue
		}

		trapTag := j.prependedTag
		if trapTag == 0 {
			var err error
			trapTag, err = trapDeclaredTagFor(strings.TrimPrefix(j.oid, "."), j.trapType, j.trapValue)
			if err != nil {
				out = append(out, trapPollFinding{join: j, kind: findingEncodeFailure,
					detail: fmt.Sprintf("trap side: %v", err)})
				continue
			}
		}
		// Rule 6: no served value, but oidTypeTable types the leaf, so the
		// poll-side tag is the one encodeTypedValue would dispatch on. Reported
		// under its own kind because it answers a different question from a
		// comparison against a value the profile actually ships.
		if len(j.polledValues) == 0 {
			if j.typedLeafTag != 0 && trapTag != j.typedLeafTag {
				out = append(out, trapPollFinding{join: j, kind: findingTypedLeafDisagreement,
					trapTag: trapTag, pollTag: j.typedLeafTag})
			}
			continue
		}

		pollTag, err := pollTagFor(j.oid, j.polledValues[0])
		if err != nil {
			out = append(out, trapPollFinding{join: j, kind: findingEncodeFailure,
				detail: fmt.Sprintf("poll side: %v", err)})
			continue
		}
		if trapTag != pollTag {
			out = append(out, trapPollFinding{join: j, kind: findingTypeDisagreement,
				trapTag: trapTag, pollTag: pollTag})
		}
	}
	sortTrapPollFindings(out)
	return out
}

// sortTrapPollFindings orders findings on the FULL key, and stably. Two
// varbinds of two entries in one profile can name the same OID, so
// (profile, oid) alone is not a total order and an unstable sort would make the
// failure output differ run to run.
func sortTrapPollFindings(f []trapPollFinding) {
	sort.SliceStable(f, func(a, b int) bool {
		x, y := f[a], f[b]
		if x.join.profile != y.join.profile {
			return x.join.profile < y.join.profile
		}
		if x.join.oid != y.join.oid {
			return x.join.oid < y.join.oid
		}
		if x.join.entry != y.join.entry {
			return x.join.entry < y.join.entry
		}
		return x.kind < y.kind
	})
}

// trapPollCensus is what the corpus walk produces beside the join: the counts
// the constants above pin.
type trapPollCensus struct {
	catalogVarbinds int // distinct across the traps.json files
	templatedOIDs   int // of those, not joinable
	occurrences     int // (profile, template-free varbind) pairs examined
	joined          int
	unserved        int

	// typedUnserved is the subset of unserved that oidTypeTable types, and which
	// rule 6 compares anyway. It is a SUBSET of unserved, not a fourth bucket, so
	// the joined + unserved == occurrences invariant is untouched by it.
	typedUnserved int

	// Per catalog FILE, so ciena's 156-examined / 0-joined cannot hide inside
	// the aggregate. [0] templated (distinct, not joinable), [1] examined,
	// [2] joined. The templated slot is what keeps _common a REAL row: it
	// contributes no occurrence at all, so an {examined, joined} pair alone
	// would be satisfied by the catalog having vanished from the walk.
	perCatalog map[string][3]int

	profiles          int // shipped device types
	carryingUniversal int // ...whose effective catalog holds the universal entries UNCHANGED
	universalDrift    []string

	prependedJoined   int
	prependedUnserved int
}

// collectTrapPollJoins reads every shipped profile's EFFECTIVE trap catalog
// (the supplied universal merged with the per-type overlay, by the production
// resolver) and joins its template-free varbinds against the OIDs that profile
// serves.
//
// universal is a PARAMETER rather than a call to LoadEmbeddedCatalog, and that
// is load-bearing: production passes the embedded catalog, and the control
// passes a synthetic one so that "the universal catalog is applied to every
// profile" is pinned by an observable finding instead of by a count that cannot
// see it. See rule 2 in the header.
func collectTrapPollJoins(t *testing.T, universal *Catalog) ([]trapPollJoin, trapPollCensus) {
	t.Helper()

	perType, err := ScanPerTypeTrapCatalogs(universal, "resources")
	if err != nil {
		t.Fatalf("scan per-type trap catalogs: %v", err)
	}

	// Per-profile served OIDs, from the shared corpus walk. EVERY entry is
	// kept, not the first: a duplicated OID is a finding (rule 3), and picking
	// one silently is the defect.
	served := map[string]map[string][]shippedSNMPEntry{}
	for _, e := range shippedSNMPEntries(t) {
		if served[e.Profile] == nil {
			served[e.Profile] = map[string][]shippedSNMPEntry{}
		}
		served[e.Profile][e.OID] = append(served[e.Profile][e.OID], e)
	}

	var joins []trapPollJoin
	census := trapPollCensus{perCatalog: map[string][3]int{}}
	// Distinct catalog varbinds are counted by their SOURCE FILE, not by the
	// profile that ends up carrying them: _common's six appear in all 29
	// effective catalogs and are one fact, not 29.
	distinct := map[[3]string]struct{}{}
	distinctTemplated := map[[3]string]struct{}{}

	for _, profile := range shippedProfileNames(t) {
		census.profiles++
		slug := strings.TrimSuffix(profile, ".json")
		catalog, ok := perType[slug]
		if !ok {
			catalog = universal // no overlay: the universal catalog is the whole of it
		}

		// Rule 2, checked per profile. The comparison is on each universal
		// entry's VARBIND SET, not on its name: MergeOverlay replaces a
		// same-named entry wholesale, so a name check would pass an overlay
		// that kept the name and swapped every varbind underneath it.
		var drift []string
		for _, u := range universal.Entries {
			got := catalog.ByName[u.Name]
			switch {
			case got == nil:
				drift = append(drift, fmt.Sprintf("%q is absent", u.Name))
			case catalogEntrySignature(got) != catalogEntrySignature(u):
				drift = append(drift, fmt.Sprintf("%q carries %s where the universal catalog has %s",
					u.Name, catalogEntrySignature(got), catalogEntrySignature(u)))
			}
		}
		if len(drift) == 0 {
			census.carryingUniversal++
		} else {
			census.universalDrift = append(census.universalDrift,
				fmt.Sprintf("%s: %s", profile, strings.Join(drift, "; ")))
		}

		// The three encoder-prepended varbinds, joined once per profile (P10).
		for _, p := range prependedVarbindJoins(t, profile, catalog) {
			if entries := served[profile][p.oid]; len(entries) > 0 {
				census.prependedJoined++
				for _, e := range entries {
					p.parts = append(p.parts, e.Part)
					p.polledValues = append(p.polledValues, e.Value)
				}
				p.shadowedBy = trapPollShadowedBy(profile, p.oid)
				joins = append(joins, p)
			} else {
				census.prependedUnserved++
			}
		}

		for _, entry := range catalog.Entries {
			source := embeddedCatalogPath
			if entry.fromOverlay {
				source = filepath.Join("resources", slug, "traps.json")
			}
			for i, vb := range entry.Varbinds {
				key := [3]string{source, entry.Name, fmt.Sprint(i)}
				distinct[key] = struct{}{}

				if strings.Contains(vb.rawOID, "{{") {
					// Names no fixed object; see the header. Counted once per
					// distinct varbind, not once per profile.
					distinctTemplated[key] = struct{}{}
					continue
				}
				census.occurrences++
				row := census.perCatalog[source]
				row[1]++

				oid := normaliseResourceOID(vb.rawOID)
				entries := served[profile][oid]
				if len(entries) == 0 {
					census.unserved++
					census.perCatalog[source] = row
					// Rule 6: unserved, but oidTypeTable types the leaf, so the
					// poll-side tag is knowable without a resource entry and the
					// varbind is comparable after all. It stays counted as
					// unserved, because it IS unserved, and becomes a join carrying the
					// leaf's tag instead of a polled value.
					//
					// shadowedBy is deliberately NOT set. Shadowing means a
					// resource entry exists and findResponse answers ahead of it,
					// making that entry dead data; with no entry there is nothing
					// dead to report. An OID that IS cycler-owned and typed is
					// still compared correctly here, because the cycler answers
					// it at the same tag oidTypeTable declares.
					if tag := snmpTypeTag(oid); tag != 0 {
						census.typedUnserved++
						joins = append(joins, trapPollJoin{
							profile: profile, oid: oid, entry: entry.Name, catalog: source,
							trapType: vb.Type, trapValue: vb.rawValue, typedLeafTag: tag,
						})
					}
					continue
				}
				census.joined++
				row[2]++
				census.perCatalog[source] = row

				j := trapPollJoin{
					profile:    profile,
					oid:        oid,
					entry:      entry.Name,
					catalog:    source,
					trapType:   vb.Type,
					trapValue:  vb.rawValue,
					shadowedBy: trapPollShadowedBy(profile, oid),
				}
				for _, e := range entries {
					j.parts = append(j.parts, e.Part)
					j.polledValues = append(j.polledValues, e.Value)
				}
				joins = append(joins, j)
			}
		}
	}

	census.catalogVarbinds = len(distinct)
	// Counted on the same distinct-per-source-file basis, so the two figures
	// are comparable rather than one being per-profile and the other not.
	census.templatedOIDs = len(distinctTemplated)
	// On the distinct basis too, so _common's six show up under _common rather
	// than 29 times under whichever profile happened to carry them.
	for key := range distinctTemplated {
		row := census.perCatalog[key[0]]
		row[0]++
		census.perCatalog[key[0]] = row
	}

	sort.SliceStable(joins, func(a, b int) bool {
		if joins[a].profile != joins[b].profile {
			return joins[a].profile < joins[b].profile
		}
		if joins[a].oid != joins[b].oid {
			return joins[a].oid < joins[b].oid
		}
		return joins[a].entry < joins[b].entry
	})
	return joins, census
}

// catalogEntrySignature renders an entry's varbind set as a stable string, for
// the rule-2 comparison. Names alone are not enough — see the call site.
func catalogEntrySignature(e *CatalogEntry) string {
	parts := make([]string, 0, len(e.Varbinds))
	for _, vb := range e.Varbinds {
		parts = append(parts, fmt.Sprintf("%s=%s", vb.rawOID, vb.Type))
	}
	sort.Strings(parts)
	return "[" + strings.Join(parts, " ") + "]"
}

// prependedVarbindJoins builds the joins for the three varbinds the ENCODER
// prepends to every notification, whose tags therefore come from the prepend
// encoders rather than from any catalog "type" (nl6#593 P10).
//
// snmpTrapEnterprise.0 is emitted only when an entry sets the optional
// entry-level field, so it is included only when some entry in this catalog
// does — otherwise the join would assert over a varbind the profile never
// sends.
func prependedVarbindJoins(t *testing.T, profile string, catalog *Catalog) []trapPollJoin {
	t.Helper()

	mk := func(oid string, enc []byte, label string) trapPollJoin {
		tag, err := varbindValueTag(enc)
		if err != nil {
			t.Fatalf("%s: reading the prepended %s varbind's tag: %v", profile, label, err)
		}
		return trapPollJoin{
			profile: profile, oid: normaliseResourceOID(oid),
			entry: "<encoder-prepended>", catalog: "trap_v2c.go " + label,
			prependedTag: tag,
		}
	}

	out := []trapPollJoin{
		mk(oidSysUpTime0, encodeVarbindTimeTicks(oidSysUpTime0, 0), "encodeVarbindTimeTicks"),
		mk(oidSnmpTrapOID0, encodeVarbindOID(oidSnmpTrapOID0, "1.3.6.1"), "encodeVarbindOID"),
	}
	for _, e := range catalog.Entries {
		if e.SnmpTrapEnterprise != "" {
			out = append(out, mk(oidSnmpTrapEnterprise0,
				encodeVarbindOID(oidSnmpTrapEnterprise0, e.SnmpTrapEnterprise), "encodeVarbindOID"))
			break
		}
	}
	return out
}

// ── rule 7: a catalog must not contradict itself (nl6#607) ──────────────────

// trapTagProbeOID is any encodable OID. The tag rule 7 compares lives in the
// varbind's VALUE slot and does not depend on its name, and rule 7 must resolve
// a tag for varbinds whose own OID is a TEMPLATE that no encoder can take
// literally, which is every varbind of the universal catalog.
const trapTagProbeOID = "1.3.6.1.4.1.99997.9.9.0"

// trapTagForDeclaredType resolves, through the PRODUCTION encoder, the tag a
// declared type puts in the value slot.
//
// It resolves from the TYPE, never from the varbind's own value. The tag a trap
// varbind emits is a function of its declared type alone, so this asks the
// question rule 7 actually poses; resolving through the value would turn an
// unencodable literal or a templated value into an encoder failure here, which
// is rule 1's finding to report and not this one's, and would leave rule 7
// unable to see the universal catalog at all.
func trapTagForDeclaredType(typ TrapVarbindType) (byte, error) {
	probe, ok := trapTypeProbeValue[typ]
	if !ok {
		return 0, fmt.Errorf("the loader accepts type %q and trapTypeProbeValue has no probe for it", typ)
	}
	return trapDeclaredTagFor(trapTagProbeOID, typ, probe)
}

// catalogSelfFinding is one OID that a single effective catalog declares at more
// than one type.
type catalogSelfFinding struct {
	catalog string // the effective catalog's label
	oid     string // as written in the catalog, template and all
	byType  map[TrapVarbindType][]string
	err     string // set when a declared type could not be resolved to a tag
}

// trapCatalogSelfFindings is RULE 7 as a pure function, so the control can
// require it to REPORT and not merely to stay silent.
//
// Keyed by EFFECTIVE catalog rather than by profile: 26 profiles carry the
// universal catalog unchanged, so a defect in it is one fact and reporting it 26
// times would bury the overlay catalogs' findings underneath it.
func trapCatalogSelfFindings(catalogs map[string]*Catalog) []catalogSelfFinding {
	var out []catalogSelfFinding
	for label, cat := range catalogs {
		for oid, byType := range trapCatalogVarbindsByOID(cat) {
			if len(byType) < 2 {
				continue // one declared type cannot disagree with itself
			}
			// Two declared types are only a wire-level disagreement if they
			// encode at two tags. They always do today, and
			// TestEveryTrapVarbindTypeIsProbeable pins that; asking the encoder
			// rather than assuming it is what keeps this rule from becoming a
			// second enumeration that drifts (nl6#539).
			tags := map[byte]struct{}{}
			var failure string
			for typ := range byType {
				tag, err := trapTagForDeclaredType(typ)
				if err != nil {
					failure = err.Error()
					continue
				}
				tags[tag] = struct{}{}
			}
			if failure == "" && len(tags) < 2 {
				continue
			}
			out = append(out, catalogSelfFinding{catalog: label, oid: oid, byType: byType, err: failure})
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].catalog != out[b].catalog {
			return out[a].catalog < out[b].catalog
		}
		return out[a].oid < out[b].oid
	})
	return out
}

// trapCatalogVarbindsByOID groups a catalog's varbinds by the OID as WRITTEN,
// including templated ones. Templates are kept deliberately: a templated OID
// names no fixed object and so is not joinable against resource data, but two
// entries declaring one at two types still fire at two types, and rule 7 is the
// only check that reaches them.
func trapCatalogVarbindsByOID(cat *Catalog) map[string]map[TrapVarbindType][]string {
	byOID := map[string]map[TrapVarbindType][]string{}
	for _, e := range cat.Entries {
		for _, vb := range e.Varbinds {
			if byOID[vb.rawOID] == nil {
				byOID[vb.rawOID] = map[TrapVarbindType][]string{}
			}
			byOID[vb.rawOID][vb.Type] = append(byOID[vb.rawOID][vb.Type], e.Name)
		}
	}
	for _, byType := range byOID {
		for typ := range byType {
			sort.Strings(byType[typ])
		}
	}
	return byOID
}

// effectiveTrapCatalogs returns every DISTINCT effective catalog in the corpus:
// the universal one, as carried by every profile with no overlay, plus one per
// overlay file (already merged with the universal by the production resolver).
func effectiveTrapCatalogs(t *testing.T, universal *Catalog) map[string]*Catalog {
	t.Helper()

	perType, err := ScanPerTypeTrapCatalogs(universal, "resources")
	if err != nil {
		t.Fatalf("scan per-type trap catalogs: %v", err)
	}
	out := map[string]*Catalog{trapUniversalCatalogLabel: universal}
	for slug, cat := range perType {
		out[filepath.Join("resources", slug, "traps.json")] = cat
	}
	return out
}

// TestTrapCatalogDoesNotContradictItself is nl6#607's widening 2. Two varbinds
// of one effective catalog naming one OID at two declared types is the same
// "one object, two types" defect TestTrapAndPollAgreeOnType guards, but visible
// without any resource data, and therefore reaching two surfaces that guard
// cannot: ciena_waveserver5, which joins nothing at all, and every templated
// varbind, which is not joinable by construction.
func TestTrapCatalogDoesNotContradictItself(t *testing.T) {
	t.Run("positive control", func(t *testing.T) { assertCatalogSelfDetectionWorks(t) })

	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("load the universal trap catalog: %v", err)
	}
	catalogs := effectiveTrapCatalogs(t, universal)

	for _, f := range trapCatalogSelfFindings(catalogs) {
		if f.err != "" {
			t.Errorf("%s declares %s at types this test cannot resolve to a tag: %s",
				f.catalog, f.oid, f.err)
			continue
		}
		var parts []string
		for _, typ := range sortedTrapTypes(f.byType) {
			parts = append(parts, fmt.Sprintf("%q in entry(s) %s", typ, strings.Join(f.byType[typ], ", ")))
		}
		t.Errorf("%s declares %s at MORE THAN ONE type: %s.\n"+
			"Every entry of one effective catalog fires from the same device, so this is one object "+
			"answered at two types depending on which notification carried it. It is the nl6#593 defect "+
			"without needing a poll to see it. The effective catalog is the universal one merged with "+
			"the per-type overlay, which is what actually fires; MergeOverlay replaces a same-named "+
			"entry wholesale, so check the merged result rather than the overlay file. Fix the "+
			"declared types to agree, against the vendor's MIB.",
			f.catalog, f.oid, strings.Join(parts, "; "))
	}

	assertTrapCatalogSelfCensus(t, catalogs)
}

// sortedTrapTypes orders a finding's declared types so the failure output is
// stable run to run.
func sortedTrapTypes(byType map[TrapVarbindType][]string) []TrapVarbindType {
	out := make([]TrapVarbindType, 0, len(byType))
	for typ := range byType {
		out = append(out, typ)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// assertTrapCatalogSelfCensus pins rule 7's comparison surface. The third
// column is the load-bearing one: an OID carried by a single varbind cannot
// disagree with itself, so it alone says how much of each catalog is under
// comparison, and a collapse there would leave the rule reporting nothing for
// the wrong reason.
func assertTrapCatalogSelfCensus(t *testing.T, catalogs map[string]*Catalog) {
	t.Helper()

	got := map[string][3]int{}
	for label, cat := range catalogs {
		byOID := trapCatalogVarbindsByOID(cat)
		shared := 0
		for _, byType := range byOID {
			n := 0
			for _, entries := range byType {
				n += len(entries)
			}
			if n > 1 {
				shared++
			}
		}
		got[label] = [3]int{len(cat.Entries), len(byOID), shared}
	}

	for label, want := range trapCatalogSelfCensus {
		if got[label] != want {
			t.Errorf("%s: %d entries, %d distinct varbind OIDs, %d carried by more than one varbind; "+
				"recorded as %d / %d / %d in trapCatalogSelfCensus.\nThe THIRD number is rule 7's "+
				"whole comparison surface, since an OID carried by one varbind cannot disagree "+
				"with itself, so a fall there makes this guard report nothing for the wrong reason",
				label, got[label][0], got[label][1], got[label][2], want[0], want[1], want[2])
		}
	}
	for label, row := range got {
		if _, known := trapCatalogSelfCensus[label]; !known {
			t.Errorf("%s is an effective trap catalog with %d entries / %d distinct varbind OIDs / "+
				"%d carried by more than one varbind, and it is not in trapCatalogSelfCensus. A new "+
				"trap catalog needs a row, or its comparison surface is unpinned", label, row[0], row[1], row[2])
		}
	}

	labels := make([]string, 0, len(got))
	for label := range got {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		t.Logf("  %-52s %2d entries, %2d distinct OIDs, %2d carried by >1 varbind",
			label, got[label][0], got[label][1], got[label][2])
	}
}

// ── the positive control ────────────────────────────────────────────────────

// The control's OIDs. PEN 99997 is used by no shipped profile, so no plant can
// collide with real data.
const (
	controlOIDOverlay     = "1.3.6.1.4.1.99997.1.1.0"
	controlOIDUniversal   = "1.3.6.1.4.1.99997.2.1.0"
	controlOIDUnencodable = "1.3.6.1.4.1.99997.3.1.0"
	controlOIDDuplicate   = "1.3.6.1.4.1.99997.4.1.0"

	// Rule 6's arms. Real ifHCInOctets instances, because the whole point is
	// that oidTypeTable types the leaf: it must be an OID the PRODUCTION table
	// knows, not one the control can invent. Instances .77 / .78 are served by no
	// shipped profile and by neither plant, so both stay in the unserved bucket
	// and are compared against the leaf's declared tag rather than a value.
	controlOIDTypedLeafDisagree = "1.3.6.1.2.1.31.1.1.1.6.77"
	controlOIDTypedLeafAgree    = "1.3.6.1.2.1.31.1.1.1.6.78"

	// A real cycler-owned column: IfCounterCycler.GetDynamic answers
	// ifHCInOctets.1 ahead of the static index, so a resource entry for it is
	// dead data. It is deliberately NOT under PEN 99997 — the whole point of
	// this arm is that the shadowing is production behaviour, not something the
	// control can invent.
	controlOIDShadowed = "1.3.6.1.2.1.31.1.1.1.6.1"

	// The synthetic universal's entry name, shared with arm 6, which overrides
	// it from an overlay.
	controlUniversalEntryName = "zzUniversalControl"
)

// controlUniversalCatalog is the SYNTHETIC universal the control substitutes for
// the embedded one. Its single varbind carries a LITERAL OID, which is the whole
// point: every real _common varbind is templated, so a universal catalog that
// never reached the join would be invisible to every count in this file.
func controlUniversalCatalog(t *testing.T) *Catalog {
	t.Helper()

	c, err := parseCatalog([]byte(`{"traps":[{"name":"`+controlUniversalEntryName+`",`+
		`"snmpTrapOID":"1.3.6.1.4.1.99997.0.2","weight":1,"varbinds":[`+
		`{"oid":"`+controlOIDUniversal+`","type":"octet-string","value":"placeholder"}]}]}`),
		"<control universal>")
	if err != nil {
		t.Fatalf("the control's synthetic universal catalog does not parse: %v", err)
	}
	return c
}

// trapPollControlPlants are the control's synthetic profiles. Each ships a
// traps.json and a resource part; what differs is the defect each plants.
func trapPollControlPlants() []struct{ dir, trapsJSON, snmpJSON string } {
	trapsNamed := func(name, oid, typ, value string) string {
		return `{"traps":[{"name":"` + name + `","snmpTrapOID":"1.3.6.1.4.1.99997.0.1","weight":1,` +
			`"varbinds":[{"oid":"` + oid + `","type":"` + typ + `","value":"` + value + `"}]}]}`
	}
	traps := func(oid, typ, value string) string {
		return trapsNamed("zzControl", oid, typ, value)
	}
	entry := func(oid, value string) string {
		return `{"oid":"` + oid + `","response":"` + value + `"}`
	}
	snmp := func(entries ...string) string { return `{"snmp":[` + strings.Join(entries, ",") + `]}` }

	return []struct{ dir, trapsJSON, snmpJSON string }{
		// ARM 1. Declared octet-string, served "1" → the poll emits INTEGER.
		// The cisco_ios defect verbatim. Reported.
		// It also serves the SYNTHETIC UNIVERSAL's OID at a disagreeing value,
		// which is the arm that pins "_common reaches every profile".
		{"zztypedisagree",
			traps(controlOIDOverlay, "octet-string", "placeholder"),
			snmp(entry(controlOIDOverlay, "1"), entry(controlOIDUniversal, "1"))},

		// ARM 2. Same OID, same declared type, a NON-numeric value → both
		// encoders emit OCTET STRING. Silent. This arm is what stops a rule
		// that reports every joined pair from passing arm 1.
		// Its universal-OID entry still disagrees, so the universal arm is
		// pinned in a profile whose own overlay varbind is clean.
		{"zztypeagree",
			traps(controlOIDOverlay, "octet-string", "placeholder"),
			snmp(entry(controlOIDOverlay, "a description"), entry(controlOIDUniversal, "1"))},

		// ARM 3. A LITERAL value the declared type cannot encode. Must surface
		// as an encoder failure, never be re-encoded with the probe and
		// reported as agreement — that fire fails every time, and
		// ApplySizeBudget disables the whole entry for an unrenderable one.
		{"zztypeunencodable",
			traps(controlOIDUnencodable, "integer", "up"),
			snmp(entry(controlOIDUnencodable, "7"))},

		// ARM 4. TWO resource entries for one OID. Production is last-wins
		// after a non-stable sort, so there is no single poll value; the guard
		// must say so rather than pick.
		{"zzduplicateoid",
			traps(controlOIDDuplicate, "octet-string", "placeholder"),
			snmp(entry(controlOIDDuplicate, "1"), entry(controlOIDDuplicate, "a description"))},

		// ARM 5. An OID findResponse answers ahead of the static index. The
		// declared type AGREES with what encodeTypedValue would emit for the
		// resource value (both Counter64), so a rule that stopped honouring
		// shadowing would fall silent rather than report the wrong kind — which
		// is what makes this arm discriminating rather than decorative.
		{"zzshadowedoid",
			// The VALUE has to be a legal counter64 literal, or this arm detects
			// through the encoder-failure branch instead and its whole point —
			// that a rule which stopped honouring shadowing goes SILENT — would
			// be untrue. Verified by mutation: with the shadow branch disabled
			// and a non-numeric value here, the arm failed with kind
			// "encode-failure", which is a pass for the wrong reason.
			traps(controlOIDShadowed, "counter64", "12345"),
			snmp(entry(controlOIDShadowed, "12345"))},

		// ARM 7 (rule 6). A varbind on a leaf oidTypeTable types Counter64,
		// declared octet-string, and the profile serves NO resource entry for it.
		// Before nl6#607 this landed in the 182-strong unserved bucket and was
		// never compared; the poll-side tag is knowable from the leaf alone, so
		// it is comparable after all. Reported under its OWN kind, because
		// conflating it with a comparison against a served value would make both
		// censuses meaningless.
		{"zztypedleafdisagree",
			traps(controlOIDTypedLeafDisagree, "octet-string", "placeholder"),
			snmp(entry(controlOIDOverlay, "a description"))},

		// ARM 8 (rule 6, the silent half). The SAME shape, declared at the type
		// the table gives the leaf. Without this arm a rule that reported every
		// typed unserved varbind would pass arm 7 and mean nothing. And since
		// the shipped count of these is ZERO, the corpus assertion can never
		// catch that on its own.
		{"zztypedleafagree",
			traps(controlOIDTypedLeafAgree, "counter64", "12345"),
			snmp(entry(controlOIDOverlay, "a description"))},

		// ARM 6. An overlay that KEEPS a universal entry's name and swaps every
		// varbind under it. MergeOverlay replaces a same-named entry wholesale,
		// so a rule-2 check on entry NAMES alone passes this silently while the
		// profile sends something the universal catalog never described. The
		// varbind OID is templated so this plant contributes drift and nothing
		// else — no occurrence, no join, no finding.
		{"zzuniversaloverride",
			trapsNamed(controlUniversalEntryName, "1.3.6.1.4.1.99997.5.1.{{.IfIndex}}",
				"integer", "{{.IfIndex}}"),
			snmp(entry("1.3.6.1.4.1.99997.5.9.0", "unrelated"))},
	}
}

// assertTrapPollDetectionWorks plants every arm into a temp copy of resources/
// and requires the SAME join and the SAME rule to classify each one. It runs the
// whole path — the production catalog resolver, the corpus walk, the join and
// both encoders — so a break anywhere in the chain fails here rather than making
// the corpus assertion vacuous.
func assertTrapPollDetectionWorks(t *testing.T) {
	t.Helper()

	tmp := t.TempDir()
	if err := os.CopyFS(filepath.Join(tmp, "resources"), os.DirFS("resources")); err != nil {
		t.Fatalf("copy resources: %v", err)
	}
	for _, p := range trapPollControlPlants() {
		dir := filepath.Join(tmp, "resources", p.dir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("plant %s: %v", p.dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "traps.json"), []byte(p.trapsJSON), 0o644); err != nil {
			t.Fatalf("plant %s traps.json: %v", p.dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, p.dir+"_snmp.json"), []byte(p.snmpJSON), 0o644); err != nil {
			t.Fatalf("plant %s snmp part: %v", p.dir, err)
		}
	}
	t.Chdir(tmp)

	joins, census := collectTrapPollJoins(t, controlUniversalCatalog(t))
	got := map[[2]string]trapPollFinding{}
	for _, f := range trapPollFindings(joins) {
		got[[2]string{f.join.profile, f.join.oid}] = f
	}

	// SCOPED TO THE PLANTED PROFILES, not to a corpus-wide total: an exact
	// total would make the control fail whenever a REAL finding exists, which
	// is precisely when the guard is working and the control still has to be
	// trustworthy.
	want := []struct {
		profile, oid string
		kind         trapPollFindingKind
		why          string
	}{
		{"zztypedisagree.json", "." + controlOIDOverlay, findingTypeDisagreement,
			"an overlay varbind declared octet-string against a resource value of \"1\" is the " +
				"cisco_ios defect verbatim. Without it the zero the corpus test asserts is vacuous: " +
				"one object could answer two types in one profile and nothing would fail"},
		{"zztypedisagree.json", "." + controlOIDUniversal, findingTypeDisagreement,
			"this varbind comes from the SYNTHETIC UNIVERSAL catalog, not from the profile's own " +
				"overlay. It is the only pin on \"_common is applied to every profile\": inserting " +
				"`if !entry.fromOverlay { continue }` in the join leaves every count in this file " +
				"unchanged, because all six real _common varbinds are templated and contribute no " +
				"occurrences at all"},
		{"zztypeagree.json", "." + controlOIDUniversal, findingTypeDisagreement,
			"the universal varbind must be joined for EVERY profile, including one whose own overlay " +
				"varbind agrees"},
		{"zztypeunencodable.json", "." + controlOIDUnencodable, findingEncodeFailure,
			"an integer varbind valued \"up\" is a LITERAL the encoder refuses, and it fails at every " +
				"fire. Falling back to the probe value here would re-encode it as a well-formed " +
				"INTEGER and report AGREEMENT, laundering a real defect into a pass. The probe is for " +
				"templated values and nothing else"},
		{"zzshadowedoid.json", "." + controlOIDShadowed, findingShadowedOID,
			"IfCounterCycler answers ifHCInOctets.1 ahead of the static index, so the resource entry " +
				"is dead data and comparing against it compares against something no collector sees. " +
				"The declared type AGREES with the resource value here (both Counter64), so a rule " +
				"that stopped honouring shadowing goes SILENT rather than reporting the wrong kind"},
		{"zztypedleafdisagree.json", "." + controlOIDTypedLeafDisagree, findingTypedLeafDisagreement,
			"rule 6. The profile serves NO resource entry for this OID, so before nl6#607 it sat in " +
				"the unserved bucket uncompared. oidTypeTable types the LEAF Counter64, so the " +
				"poll-side tag is knowable without any value, and a varbind declaring octet-string on " +
				"it contradicts what a GET would answer. The shipped count of typed unserved varbinds " +
				"is ZERO, so this arm is the ONLY thing that can make rule 6 fail at all"},
		{"zzduplicateoid.json", "." + controlOIDDuplicate, findingDuplicateEntry,
			"two resource entries name one OID. buildResourceIndexes stores in sorted order so " +
				"production is last-wins, and after a non-stable sort.Slice which equal key wins is " +
				"unspecified — so there is no single poll value to compare and the guard must say so " +
				"rather than pick one"},
	}
	for _, w := range want {
		f, ok := got[[2]string{w.profile, w.oid}]
		if !ok {
			t.Errorf("the control plants %s / %s and the rule reported NOTHING for it.\n%s",
				w.profile, w.oid, w.why)
			continue
		}
		if f.kind != w.kind {
			t.Errorf("the control's %s / %s was reported as %q, want %q (%s)",
				w.profile, w.oid, f.kind, w.kind, f.detail)
		}
	}

	// The silent arm. Its own overlay varbind agrees, so nothing may be
	// reported for THAT OID even though the same profile has a universal-OID
	// finding above.
	if stray, ok := got[[2]string{"zztypeagree.json", "." + controlOIDOverlay}]; ok {
		t.Errorf("the control's SILENT arm plants the same OID and the same declared type against a "+
			"NON-numeric value, where both encoders emit OCTET STRING, and the rule reported it "+
			"anyway: %+v.\nA rule that reports every joined pair passes every other arm and is "+
			"worthless, so this arm is what makes the others mean something.", stray)
	}

	// Rule 6's silent half. Same shape as arm 7, declared at the type the table
	// gives the leaf, so nothing may be reported. The shipped typed-unserved
	// count is ZERO, so without this arm a rule that reported EVERY typed
	// unserved varbind would satisfy arm 7 and no corpus assertion could tell.
	if stray, ok := got[[2]string{"zztypedleafagree.json", "." + controlOIDTypedLeafAgree}]; ok {
		t.Errorf("the control's rule-6 SILENT arm declares counter64 on a leaf oidTypeTable types "+
			"Counter64, and the rule reported it anyway: %+v.\nA rule that reports every typed "+
			"unserved varbind passes the disagreeing arm and is worthless", stray)
	}

	// And the tags on the disagreeing arm really are the two encoders' output,
	// not merely "different".
	if f := got[[2]string{"zztypedisagree.json", "." + controlOIDOverlay}]; f.trapTag != ASN1_OCTET_STRING ||
		f.pollTag != ASN1_INTEGER {
		t.Errorf("the disagreeing arm reported trap tag 0x%02X / poll tag 0x%02X, want 0x%02X / 0x%02X. "+
			"The rule is reporting, but not on the tags the two encoders emit",
			f.trapTag, f.pollTag, ASN1_OCTET_STRING, ASN1_INTEGER)
	}

	// And rule 6's tags are the trap encoder's output against oidTypeTable's
	// declared tag for the leaf, not merely two different bytes.
	if f := got[[2]string{"zztypedleafdisagree.json", "." + controlOIDTypedLeafDisagree}]; f.trapTag != ASN1_OCTET_STRING ||
		f.pollTag != ASN1_COUNTER64 {
		t.Errorf("rule 6's arm reported trap tag 0x%02X / poll tag 0x%02X, want 0x%02X / 0x%02X. The "+
			"poll side must be the tag oidTypeTable gives the LEAF, which is what makes the varbind "+
			"comparable with no served value at all",
			f.trapTag, f.pollTag, ASN1_OCTET_STRING, ASN1_COUNTER64)
	}

	// ARM 6, read off the census rather than the findings: rule 2's verdict is a
	// property of the CATALOG, not of any joined pair.
	var overrideDrift, strayDrift []string
	for _, d := range census.universalDrift {
		if strings.HasPrefix(d, "zzuniversaloverride.json:") {
			overrideDrift = append(overrideDrift, d)
		} else {
			strayDrift = append(strayDrift, d)
		}
	}
	if len(overrideDrift) != 1 {
		t.Errorf("the control plants an overlay that keeps the universal entry name %q and swaps its "+
			"varbinds, and rule 2 reported %d drift rows for it: %v.\nMergeOverlay replaces a "+
			"same-named entry WHOLESALE, so a check on entry names alone passes that silently while "+
			"the profile sends something the universal catalog never described — and no shipped "+
			"overlay overrides a universal name today, so nothing else can catch it.",
			controlUniversalEntryName, len(overrideDrift), overrideDrift)
	}
	if len(strayDrift) != 0 {
		t.Errorf("rule 2 reported drift for profiles it should not: %v. A check that fires on every "+
			"profile would pass the arm above and mean nothing", strayDrift)
	}

	// The shadow PREDICATE, asked directly as well as through arm 5, because the
	// arm exercises one source (the cycler) and the predicate models five.
	if trapPollShadowedBy("cisco_ios.json", ".1.3.6.1.2.1.1.5.0") == "" {
		t.Error("trapPollShadowedBy does not report sysName.0, which buildResourceIndexes never even " +
			"stores. Every shadow assertion below is then vacuous")
	}
	if trapPollShadowedBy("cisco_ios.json", ".1.3.6.1.2.1.31.1.1.1.6.1") == "" {
		t.Error("trapPollShadowedBy does not report ifHCInOctets.1, which IfCounterCycler answers " +
			"ahead of the static index")
	}
	if got := trapPollShadowedBy("cisco_ios.json", "."+controlOIDOverlay); got != "" {
		t.Errorf("trapPollShadowedBy reported %q for an ordinary vendor OID, so it would exclude "+
			"every joined pair from comparison", got)
	}
}

// assertCatalogSelfDetectionWorks is rule 7's positive control. Three arms, and
// the third is the one that pins the EFFECTIVE catalog: an overlay entry that
// contradicts a UNIVERSAL varbind is invisible to anything that reads the
// overlay file alone, and reading the overlay file alone is the obvious wrong
// implementation of this rule.
func assertCatalogSelfDetectionWorks(t *testing.T) {
	t.Helper()

	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("load the universal trap catalog: %v", err)
	}

	// Arm 3 contradicts a REAL universal varbind, read out of the catalog rather
	// than hardcoded, so the arm survives an edit to _common/traps.json instead
	// of silently ceasing to test anything.
	var universalOID string
	var universalType TrapVarbindType
	for _, e := range universal.Entries {
		if len(e.Varbinds) > 0 {
			universalOID, universalType = e.Varbinds[0].rawOID, e.Varbinds[0].Type
			break
		}
	}
	if universalOID == "" {
		t.Fatal("the universal catalog ships no varbind, so rule 7's overlay arm has nothing to " +
			"contradict and would pass vacuously")
	}
	contradicting := TrapVTOctetString
	if universalType == TrapVTOctetString {
		contradicting = TrapVTInteger
	}

	const selfOID = "1.3.6.1.4.1.99997.7.1.0"
	twoEntries := func(oid, typeA, typeB string) string {
		return `{"traps":[` +
			`{"name":"zzSelfA","snmpTrapOID":"1.3.6.1.4.1.99997.0.7","weight":1,"varbinds":[` +
			`{"oid":"` + oid + `","type":"` + typeA + `","value":"1"}]},` +
			`{"name":"zzSelfB","snmpTrapOID":"1.3.6.1.4.1.99997.0.8","weight":1,"varbinds":[` +
			`{"oid":"` + oid + `","type":"` + typeB + `","value":"1"}]}]}`
	}

	plants := []struct{ dir, trapsJSON string }{
		// ARM 1. One catalog, one OID, two declared types. Reported.
		{"zzselfdisagree", twoEntries(selfOID, "integer", "octet-string")},

		// ARM 2. The silent half: one OID, two entries, ONE declared type. A rule
		// that reported every OID carried by more than one varbind would pass arm
		// 1 and flag all 42 of ciena's, so this arm is what makes arm 1 mean
		// something.
		{"zzselfagree", twoEntries(selfOID, "octet-string", "octet-string")},

		// ARM 3. An overlay entry that contradicts a varbind of the UNIVERSAL
		// catalog. The overlay FILE is internally consistent, having one entry,
		// so a rule that read the overlay file instead of the merged effective
		// catalog reports nothing here while the device fires both.
		{"zzselfoverlay", `{"traps":[{"name":"zzSelfOverlay",` +
			`"snmpTrapOID":"1.3.6.1.4.1.99997.0.9","weight":1,"varbinds":[` +
			`{"oid":"` + universalOID + `","type":"` + string(contradicting) + `","value":"1"}]}]}`},
	}

	tmp := t.TempDir()
	if err := os.CopyFS(filepath.Join(tmp, "resources"), os.DirFS("resources")); err != nil {
		t.Fatalf("copy resources: %v", err)
	}
	for _, p := range plants {
		dir := filepath.Join(tmp, "resources", p.dir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("plant %s: %v", p.dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "traps.json"), []byte(p.trapsJSON), 0o644); err != nil {
			t.Fatalf("plant %s traps.json: %v", p.dir, err)
		}
	}
	t.Chdir(tmp)

	got := map[[2]string]catalogSelfFinding{}
	for _, f := range trapCatalogSelfFindings(effectiveTrapCatalogs(t, universal)) {
		got[[2]string{f.catalog, f.oid}] = f
	}

	disagreeing := filepath.Join("resources", "zzselfdisagree", "traps.json")
	if f, ok := got[[2]string{disagreeing, selfOID}]; !ok {
		t.Error("the control plants one catalog declaring one OID as both integer and octet-string, " +
			"and rule 7 reported NOTHING. Without this arm the zero the corpus assertion reports is " +
			"vacuous: a catalog could contradict itself and nothing would fail")
	} else if len(f.byType) != 2 {
		t.Errorf("rule 7 reported the disagreeing arm with %d declared types, want 2: %v", len(f.byType), f.byType)
	}

	overlay := filepath.Join("resources", "zzselfoverlay", "traps.json")
	if _, ok := got[[2]string{overlay, universalOID}]; !ok {
		t.Errorf("the control plants an overlay whose single entry declares the universal catalog's "+
			"%s as %q where the universal declares it %q, and rule 7 reported NOTHING.\nThe overlay "+
			"FILE is internally consistent, so a rule that read the overlay file rather than the "+
			"merged EFFECTIVE catalog passes this silently while the device fires both types",
			universalOID, contradicting, universalType)
	}

	agreeing := filepath.Join("resources", "zzselfagree", "traps.json")
	if stray, ok := got[[2]string{agreeing, selfOID}]; ok {
		t.Errorf("the control plants two entries naming one OID at the SAME declared type and rule 7 "+
			"reported it anyway: %+v.\nA rule that flagged every OID carried by more than one varbind "+
			"would report all 42 of ciena's and pass every other arm, so this is the arm that makes "+
			"the others mean something", stray)
	}

	// And the planted catalogs are the ONLY ones reported, scoped that way rather
	// than by a corpus-wide total so the control stays trustworthy at the moment
	// a real finding exists, which is exactly when it matters (the nl6#593 lesson).
	for key := range got {
		if !strings.HasPrefix(key[0], filepath.Join("resources", "zzself")) {
			t.Errorf("rule 7 reported %s / %s, which the control did not plant. Either the corpus has "+
				"a real finding, which should be fixed, or the rule fires on catalogs that do not contradict "+
				"themselves, in which case every arm above passes for the wrong reason", key[0], key[1])
		}
	}
}

// TestTrapAndPollAgreeOnType is nl6#593's deliverable: for every OID that both a
// profile's trap catalog and its resource files name, the trap encoder and the
// poll encoder must put the same ASN.1 tag on the wire.
func TestTrapAndPollAgreeOnType(t *testing.T) {
	// The control runs first and in its own scope, because it t.Chdir()s.
	t.Run("positive control", func(t *testing.T) { assertTrapPollDetectionWorks(t) })

	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("load the universal trap catalog: %v", err)
	}
	joins, census := collectTrapPollJoins(t, universal)

	for _, f := range trapPollFindings(joins) {
		switch f.kind {
		case findingTypeDisagreement:
			t.Errorf("%s answers %s at TWO types.\n"+
				"  trap: %s declares it %q in entry %q → the trap encoder emits %s\n"+
				"  poll: %s serves %q → encodeTypedValue emits %s\n"+
				"One object, one profile, two types depending on how a collector asks. cisco_ios "+
				"shipped this at ciscoEnvMonSupplyStatusDescr.1 (1.3.6.1.4.1.9.9.13.1.5.1.2.1, "+
				"declared octet-string, polled INTEGER because the resource value was the string "+
				"\"1\" and the OID is not in oidTypeTable); nl6#592 fixed it by hand and nl6#593 "+
				"added this guard.\n"+
				"Fix the side that is wrong AGAINST THE VENDOR'S MIB — this guard only knows the two "+
				"disagree, not which one is right. Changing the resource VALUE (a non-numeric string "+
				"stops encodeTypedValue taking the integer branch) or adding the OID to oidTypeTable "+
				"both move the poll side; changing the catalog \"type\" moves the trap side.",
				f.join.profile, f.join.oid,
				f.join.catalog, f.join.trapType, f.join.entry, snmpTypeNameOrInteger(f.trapTag),
				strings.Join(f.join.parts, ", "), f.join.polledValues[0], snmpTypeNameOrInteger(f.pollTag))

		case findingTypedLeafDisagreement:
			t.Errorf("%s declares %s as %q in entry %q, and oidTypeTable types that leaf %s.\n"+
				"  trap: the trap encoder emits %s\n"+
				"  poll: a GET is answered at %s, because encodeTypedValue dispatches on "+
				"snmpTypeTag(oid) and nl6#541's typed-class rule refuses at load any value that would "+
				"not encode at that tag\n"+
				"The profile serves no resource entry for this OID, so there is no value to look at: "+
				"the poll-side tag comes from the LEAF'S declared type. That makes this a stronger "+
				"finding than an ordinary type disagreement, not a weaker one. The two sides cannot "+
				"be reconciled by editing a resource value, because there is none. Fix the catalog "+
				"\"type\", or the oidTypeTable row, against the vendor's MIB.",
				f.join.profile, f.join.oid, f.join.trapType, f.join.entry, snmpTypeName(f.pollTag),
				snmpTypeNameOrInteger(f.trapTag), snmpTypeName(f.pollTag))

		case findingEncodeFailure:
			t.Errorf("%s %s (entry %q, declared %q) reaches neither encoder: %s.\n"+
				"This is not agreement and must never be reported as such — a varbind whose LITERAL "+
				"value its declared type cannot encode fails at every fire, and the catalog loader's "+
				"dry render disables the whole entry for one. Fix the value or the declared type.",
				f.join.profile, f.join.oid, f.join.entry, f.join.trapType, f.detail)

		case findingDuplicateEntry:
			t.Errorf("%s serves %s from MORE THAN ONE resource entry, so there is no single polled "+
				"value to compare the trap's declared type against: %s.\n"+
				"buildResourceIndexes calls oidIndex.Store in sorted order, so production is "+
				"LAST-wins — and the sort is a non-stable sort.Slice, so which of several equal keys "+
				"wins is unspecified. 111 (profile, OID) pairs are duplicated today (64 in "+
				"cisco_nexus_9500, 32 in juniper_mx960, 5 in each nvidia_*), all ifHighSpeed rows "+
				"carrying identical values, so none of them diverges yet. Delete the duplicate.",
				f.join.profile, f.join.oid, f.detail)

		case findingShadowedOID:
			t.Errorf("%s serves a resource entry for %s, but a GET of it never reads that entry: %s.\n"+
				"Comparing the trap's declared type against dead data would be comparing against "+
				"something no collector ever sees. Either the resource entry should go, or this "+
				"guard's model of findResponse's precedence (trapPollShadowedBy) is out of date with "+
				"snmp_handlers.go.",
				f.join.profile, f.join.oid, f.detail)
		}
	}

	// ── the census ──
	for _, j := range joins {
		switch {
		case len(j.polledValues) > 0:
			t.Logf("joined %-24s %-32s trap %-12s poll %q", j.profile, j.oid, j.trapType, j.polledValues[0])
		case j.typedLeafTag != 0:
			t.Logf("joined %-24s %-32s trap %-12s poll <typed leaf: %s>",
				j.profile, j.oid, j.trapType, snmpTypeName(j.typedLeafTag))
		}
	}

	assertTrapPollCensus(t, census)
	assertJoinedPairIdentities(t, joins)
}

// assertTrapPollCensus pins every count the walk produces.
func assertTrapPollCensus(t *testing.T, census trapPollCensus) {
	t.Helper()

	if census.catalogVarbinds != trapCatalogVarbindsShipped {
		t.Errorf("%d distinct catalog varbinds ship, recorded as %d in trapCatalogVarbindsShipped. "+
			"Move the constant and say why in the commit", census.catalogVarbinds, trapCatalogVarbindsShipped)
	}
	if census.templatedOIDs != trapVarbindsWithTemplatedOID {
		t.Errorf("%d catalog varbinds carry a templated OID, recorded as %d in "+
			"trapVarbindsWithTemplatedOID. A literal that became a template left the join; a template "+
			"that became a literal joined it", census.templatedOIDs, trapVarbindsWithTemplatedOID)
	}
	if census.occurrences != trapPollJoinOccurrences {
		t.Errorf("the join examined %d (profile, varbind) occurrences, recorded as %d in "+
			"trapPollJoinOccurrences. A count that FELL is how this guard goes quiet without failing",
			census.occurrences, trapPollJoinOccurrences)
	}
	if census.unserved != trapPollUnservedVarbinds {
		t.Errorf("%d varbinds name an OID their profile serves no resource entry for, recorded as %d "+
			"in trapPollUnservedVarbinds. This is NOT a defect — a trap naming an object the profile "+
			"does not model is the normal case — but the number is pinned so it is visible when it "+
			"moves", census.unserved, trapPollUnservedVarbinds)
	}
	if census.joined+census.unserved != census.occurrences {
		t.Errorf("%d joined + %d unserved != %d examined: an occurrence fell out of both buckets",
			census.joined, census.unserved, census.occurrences)
	}
	if census.typedUnserved != trapPollTypedUnservedVarbinds {
		t.Errorf("%d unserved varbinds name an OID oidTypeTable types, recorded as %d in "+
			"trapPollTypedUnservedVarbinds. Rule 6 compares these against the LEAF'S declared tag "+
			"rather than leaving them uncompared. A RISE is not a defect by itself: it means such a "+
			"varbind now exists and is being compared, and a disagreement would be reported "+
			"separately. A FALL to zero from a non-zero value means the comparison stopped happening",
			census.typedUnserved, trapPollTypedUnservedVarbinds)
	}
	if census.typedUnserved > census.unserved {
		t.Errorf("%d typed-unserved exceeds %d unserved: rule 6's set is a SUBSET of the unserved "+
			"bucket, not a fourth bucket", census.typedUnserved, census.unserved)
	}

	// Per catalog, so ciena's 156-examined / 0-joined cannot hide in the total.
	for source, want := range trapPollPerCatalogCensus {
		got := census.perCatalog[source]
		if got != want {
			t.Errorf("%s: %d templated, %d examined, %d joined; recorded as %d / %d / %d in "+
				"trapPollPerCatalogCensus. ciena_waveserver5 alone is 156 of the 185 examined and "+
				"joins none of them, so the aggregate cannot tell a genuinely disjoint catalog from "+
				"a normalisation bug that de-joined one", source, got[0], got[1], got[2],
				want[0], want[1], want[2])
		}
	}
	for source, got := range census.perCatalog {
		if _, known := trapPollPerCatalogCensus[source]; !known {
			t.Errorf("%s contributes %d templated / %d examined / %d joined varbinds and is not in "+
				"trapPollPerCatalogCensus. A new trap catalog needs a row, or its shape is unpinned",
				source, got[0], got[1], got[2])
		}
	}

	for _, d := range census.universalDrift {
		t.Errorf("%s.\n_common/traps.json is merged into EVERY device type, so its varbinds are "+
			"joined for every profile. An entry that is absent, or that kept the universal name while "+
			"swapping its varbinds, means this guard examines something other than what the fleet "+
			"sends", d)
	}
	if census.profiles != trapCatalogProfiles {
		t.Errorf("%d shipped device types, recorded as %d in trapCatalogProfiles. Adding a device "+
			"type is routine: move the constant, and move trapProfilesCarryingUniversal with it "+
			"unless the new type declares `extends: false`", census.profiles, trapCatalogProfiles)
	}
	if census.carryingUniversal != trapProfilesCarryingUniversal {
		t.Errorf("%d of %d profiles carry the universal catalog's entries unchanged, recorded as %d "+
			"in trapProfilesCarryingUniversal", census.carryingUniversal, census.profiles,
			trapProfilesCarryingUniversal)
	}

	if census.prependedJoined != trapPrependedJoinedPairs {
		t.Errorf("%d profiles serve one of the three encoder-prepended OIDs, recorded as %d in "+
			"trapPrependedJoinedPairs. All of them are sysUpTime.0, which oidTypeTable types "+
			"TIMETICKS and the encoder prepends as TIMETICKS, so they agree by construction — this "+
			"is coverage of a surface the catalog does not control, not a near-miss",
			census.prependedJoined, trapPrependedJoinedPairs)
	}
	if census.prependedUnserved != trapPrependedUnservedPairs {
		t.Errorf("%d encoder-prepended (profile, OID) pairs are unserved, recorded as %d in "+
			"trapPrependedUnservedPairs. The total is two per profile plus one for each catalog that "+
			"sets snmpTrapEnterprise, so a fall here means a profile stopped being walked",
			census.prependedUnserved, trapPrependedUnservedPairs)
	}

	t.Logf("%d catalog varbinds (%d templated, not joinable); %d occurrences examined: %d joined, "+
		"%d with no resource entry. Encoder-prepended varbinds: %d joined, %d unserved",
		census.catalogVarbinds, census.templatedOIDs, census.occurrences, census.joined,
		census.unserved, census.prependedJoined, census.prependedUnserved)
	sources := make([]string, 0, len(census.perCatalog))
	for source := range census.perCatalog {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, source := range sources {
		row := census.perCatalog[source]
		t.Logf("  %-40s %3d templated, %3d examined, %d joined", source, row[0], row[1], row[2])
	}
}

// assertJoinedPairIdentities pins WHICH pairs are joined, not how many. A count
// alone goes quiet on a swap — drop one pair, gain another, and the total is
// unchanged, which is the failure mode every other constant here exists to stop.
func assertJoinedPairIdentities(t *testing.T, joins []trapPollJoin) {
	t.Helper()

	got := map[[2]string]struct{}{}
	for _, j := range joins {
		if j.prependedTag != 0 {
			continue // counted separately; see trapPrependedJoinedPairs
		}
		if j.typedLeafTag != 0 {
			// Rule 6's joins carry no resource entry, so they are not "pairs the
			// profile serves on two surfaces". Counted by
			// trapPollTypedUnservedVarbinds instead.
			continue
		}
		got[[2]string{j.profile, j.oid}] = struct{}{}
	}
	want := map[[2]string]struct{}{}
	for _, p := range trapPollJoinedPairsShipped {
		want[p] = struct{}{}
	}
	for p := range want {
		if _, ok := got[p]; !ok {
			t.Errorf("%s / %s is recorded in trapPollJoinedPairsShipped and the join no longer finds "+
				"it. The first row is nl6#592's regression anchor: 1.3.6.1.4.1.9.9.13.1.5.1.2.1 is "+
				"the OID that carried the defect, and a guard that stopped joining it would pass "+
				"while the class re-opened", p[0], p[1])
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("%s / %s is joined and is not in trapPollJoinedPairsShipped. A new pair is a "+
				"new object served on two surfaces: check it against the vendor's MIB and add the row",
				p[0], p[1])
		}
	}
	if len(got) != len(trapPollJoinedPairsShipped) {
		t.Errorf("%d joined (profile, OID) pairs, %d recorded", len(got), len(trapPollJoinedPairsShipped))
	}
}

// TestEveryTrapVarbindTypeIsProbeable pins the probe table to the LOADER'S OWN
// accept-set (trapVarbindTypes), not to the four types the corpus happens to
// use. Without it, a ninth type added to trap_catalog.go leaves the probe table
// short and every varbind of that type is reported as an encoder failure instead
// of being compared — the validateDottedOID / encodeOID drift of nl6#539, one
// file over.
//
// It also pins the tag each declared type emits, which is the mapping the whole
// guard rests on: if encodeVarbindTyped's dispatch changed, every comparison
// would silently change with it. Membership is asserted PER TYPE rather than by
// cardinality, because a duplicate plus an omission keeps the lengths equal.
func TestEveryTrapVarbindTypeIsProbeable(t *testing.T) {
	want := map[TrapVarbindType]byte{
		TrapVTInteger:     ASN1_INTEGER,
		TrapVTOctetString: ASN1_OCTET_STRING,
		TrapVTOID:         ASN1_OBJECT_ID,
		TrapVTCounter32:   ASN1_COUNTER32,
		TrapVTGauge32:     ASN1_GAUGE32,
		TrapVTTimeTicks:   ASN1_TIMETICKS,
		TrapVTCounter64:   ASN1_COUNTER64,
		TrapVTIPAddress:   ASN1_IPADDRESS,
	}
	seenTag := map[byte]TrapVarbindType{}
	for _, typ := range trapVarbindTypes {
		probe, ok := trapTypeProbeValue[typ]
		if !ok {
			t.Errorf("the loader accepts type %q and trapTypeProbeValue has no probe for it, so a "+
				"catalog declaring it with a TEMPLATED value would be reported as an encoder failure "+
				"instead of compared", typ)
			continue
		}
		expected, ok := want[typ]
		if !ok {
			t.Errorf("the loader accepts type %q and this test records no expected tag for it", typ)
			continue
		}
		got, err := trapDeclaredTagFor(controlOIDOverlay, typ, probe)
		if err != nil {
			t.Errorf("type %q with probe %q does not encode: %v — the loader accepts a type "+
				"encodeVarbindTyped has no case for", typ, probe, err)
			continue
		}
		if got != expected {
			t.Errorf("type %q encodes at tag 0x%02X, want 0x%02X", typ, got, expected)
		}
		if prev, dup := seenTag[got]; dup {
			t.Errorf("types %q and %q both encode at tag 0x%02X", prev, typ, got)
		}
		seenTag[got] = typ
	}
	// And no stale rows on either side: a probe or an expectation for a type the
	// loader no longer accepts is a row nothing checks.
	for typ := range trapTypeProbeValue {
		if !validTrapVarbindType(typ) {
			t.Errorf("trapTypeProbeValue carries %q, which the loader does not accept", typ)
		}
	}
	for typ := range want {
		if !validTrapVarbindType(typ) {
			t.Errorf("this test records an expected tag for %q, which the loader does not accept", typ)
		}
	}

	// A TEMPLATED value falls back to the probe, or every templated-value
	// varbind would be reported as an encoder failure.
	got, err := trapDeclaredTagFor(controlOIDOverlay, TrapVTInteger, "{{.IfIndex}}")
	if err != nil {
		t.Fatalf("a templated value must fall back to the probe: %v", err)
	}
	if got != ASN1_INTEGER {
		t.Errorf("the probe fallback emitted 0x%02X for an integer varbind, want 0x%02X", got, ASN1_INTEGER)
	}

	// A LITERAL value the type cannot encode must NOT fall back. This is the
	// laundering the fallback would otherwise do: "up" would come back as a
	// well-formed INTEGER and the pair would be reported as agreeing.
	if _, err := trapDeclaredTagFor(controlOIDOverlay, TrapVTInteger, "up"); err == nil {
		t.Error("an integer varbind whose LITERAL value is \"up\" resolved to a tag. The probe " +
			"fallback is gated on the value being a template for exactly this reason: that varbind " +
			"fails at every fire, and re-encoding it with a probe reports a real defect as agreement")
	}
	if _, err := trapDeclaredTagFor(controlOIDOverlay, TrapVTIPAddress, "not-an-ip"); err == nil {
		t.Error("an ipaddress varbind with an unparseable literal resolved to a tag")
	}

	// And an unknown type stays an error rather than defaulting to something.
	if _, err := trapDeclaredTagFor(controlOIDOverlay, TrapVarbindType("no-such-type"), "1"); err == nil {
		t.Error("an unknown varbind type must not resolve to a tag")
	}
}

// TestVarbindValueTagRejectsMalformedInput pins the reader the whole trap side
// depends on. It is fed nl6's own encoder output in production, which is exactly
// why the bounds are worth testing directly: nothing else would notice them
// being wrong.
func TestVarbindValueTagRejectsMalformedInput(t *testing.T) {
	good, err := encodeVarbindTyped(Varbind{OID: controlOIDOverlay, Type: TrapVTOctetString, Value: "x"})
	if err != nil {
		t.Fatalf("encoding a well-formed varbind: %v", err)
	}
	if tag, err := varbindValueTag(good); err != nil || tag != ASN1_OCTET_STRING {
		t.Fatalf("varbindValueTag on a well-formed varbind = 0x%02X, %v", tag, err)
	}

	for name, input := range map[string][]byte{
		"empty":                {},
		"not a sequence":       {0x04, 0x02, 0x01, 0x02},
		"sequence, no content": {ASN1_SEQUENCE, 0x00},
		"sequence length overruns": append([]byte{ASN1_SEQUENCE, 0x7f},
			good[2:]...),
		"value slot absent":                {ASN1_SEQUENCE, 0x03, ASN1_OBJECT_ID, 0x01, 0x2b},
		"oid length overruns the sequence": {ASN1_SEQUENCE, 0x04, ASN1_OBJECT_ID, 0x7f, 0x2b, 0x06},
		"does not open with an OID":        {ASN1_SEQUENCE, 0x04, ASN1_INTEGER, 0x01, 0x01, 0x05},
	} {
		if _, err := varbindValueTag(input); err == nil {
			t.Errorf("%s: varbindValueTag accepted % x", name, input)
		}
	}
}

// snmpTypeNameOrInteger names a tag for the failure message. snmpTypeName covers
// the tags oidTypeTable can declare; INTEGER is not one of them and is exactly
// the tag the cisco_ios defect produced, so naming it by hex would bury the
// point of the message.
func snmpTypeNameOrInteger(tag byte) string {
	if tag == ASN1_INTEGER {
		return "INTEGER"
	}
	return snmpTypeName(tag)
}
