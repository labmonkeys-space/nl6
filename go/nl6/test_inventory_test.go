/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// nl6#577. A DELETED TEST IS INVISIBLE, AND THIS PACKAGE IS THE WRONG PLACE FOR
// THAT TO BE TRUE.
//
// `go test` reports nothing when a test function stops existing. No count anyone
// reads changes, CI stays green, and the diff that did it looks like an edit to a
// test file. It has already happened here: during nl6#569/#571/#574 the tail of a
// test file was rewritten and TestEveryDeletedDeadRowIsAnsweredByTheCycler and
// TestPaloAltoPANSubtreeMatchesTheMIB went with it. Both were recovered only
// because a targeted `-run` printed "no tests to run".
//
// The asymmetry is the reason this file exists. The package carries ledgers that
// reverse a shipped-data transition and require a parent revision's digest byte
// for byte, corpus censuses that assert a zero, and wiring tests whose entire
// value is that they exist. Every one of them could be deleted with a green suite.
//
// THREE HALVES, WHICH IS ONE MORE THAN THE ISSUE ASKED FOR BECAUSE A TEST CAN
// STOP RUNNING WITHOUT BEING DELETED.
//
//  1. A FLOOR. minimumTestFunctions is a committed minimum on the number of test
//     functions this package declares. It catches a deletion in bulk and says
//     nothing about which one. It is a FLOOR and not an equality on purpose:
//     adding tests must not break the build, while removing one must. Its decay
//     is bounded rather than merely noted, see maximumHeadroom.
//
//  2. A MANIFEST. loadBearingGuards names the tests whose absence would silently
//     un-guard something, each with the file it lives in and the reason it
//     qualifies. The floor knows a test went missing; the manifest knows which
//     ones matter, and it also refuses a guard that has been gutted or skipped
//     rather than removed.
//
//  3. A BUILD-CONSTRAINT CENSUS. A file that stops building on a platform still
//     declares every test it did before, so the floor cannot see it. The tests
//     exist and stop running.
//
// THE MECHANISM IS A SOURCE PARSE, NOT `go test -list`, AND THAT WAS MEASURED
// RATHER THAN PREFERRED. Three test files in this package do not build on
// anything but Linux, so `go test -list` counts 1375 on macOS against a higher
// number on Linux, and `GOOS=linux go test -list` fails outright because listing
// requires executing the test binary. The gap is exactly the 29 tests those three
// files declare, which is why the parse count is 1404 and the listed count is
// 1375. A count captured on one platform is wrong on the other, so a committed
// constant could not be checked anywhere except CI. go/parser reads the sources
// as text: platform independent, no build, a few milliseconds, and it sees
// constrained files too.
//
// CONSTRAINTS ARE RESOLVED THROUGH go/build, NOT BY READING COMMENTS. Go
// constrains a file by its NAME as well as by a directive: `foo_windows_test.go`
// and `foo_amd64_test.go` never build elsewhere and carry no `//go:build` line at
// all. A comment scan missed that entirely, and a file RENAMED to a GOOS suffix
// was counted toward the floor while running nowhere. build.Context.MatchFile
// answers the whole question in one place: filename suffixes, `//go:build`, and
// the legacy `// +build` form the toolchain still honours. One visible
// consequence: datagram_mtu_gate_linux_test.go is already Linux-only by NAME, so
// its `//go:build linux` comment is redundant and deleting it changes nothing
// here, where a comment scan would have reported a false alarm.
//
// WHAT COUNTS. The toolchain's own rule, not an approximation of it: `func
// TestXxx(*testing.T)` where the rune after "Test" is not lower case, taking
// EXACTLY one parameter of that type, in a file ending `_test.go` whose name does
// not begin with `_` or `.`. A helper like `func TestHelper(t *testing.T, want
// int)` is not a test to the toolchain and is not counted here either, or the
// floor would move on a helper rename. The `testing` package is resolved through
// the file's own imports, so `import tst "testing"` is counted rather than lost.
//
// Fuzz targets get their OWN floor: `go test` runs each one's seed corpus, so a
// deleted target is a deleted assertion, but they are a different population and
// folding them into one number would let a fuzz target pay for a deleted test.
// Benchmarks are counted and LOGGED but not floored: a benchmark asserts nothing,
// so its deletion loses a measurement rather than a guard. Examples are neither
// floored nor logged because this package declares none, and a floor of zero
// asserts nothing.
//
// WHAT NONE OF THE THREE CAN SEE, stated here rather than left to be discovered:
// a rename from TestFoo to TestBar keeps the count (the manifest covers the named
// guards, nothing covers the rest); a deleted `t.Run` subtest or a deleted table
// row costs assertions at zero count movement; and the manifest's
// gutted-or-skipped check reads a call graph three levels deep, so a guard that
// asserts through a deeper chain of helpers would read as gutted, and one that
// keeps a single vestigial assertion while losing the rest reads as intact.
//
// AND THE ONE LEVEL UP: this file is itself deletable with a green suite, which
// is nl6#577's own asymmetry applied to nl6#577's fix. The anchor is outside the
// package, in the Makefile: `make check-guard-file` fails if this file or any of
// its four guards is gone, and `test` and `test-race` both depend on it. The
// Makefile was chosen over a CI-only grep because CLAUDE.md's convention is that
// CI invokes Makefile targets, so the check runs identically on a laptop, and
// over CODEOWNERS because that asks a human to notice rather than failing.

// minimumTestFunctions is the committed floor on `func TestXxx(*testing.T)` in
// this package. It was the exact count when nl6#577 landed, so the headroom was
// zero and any deletion failed.
//
// RAISE IT when you add tests. maximumHeadroom is what makes that happen rather
// than hoping: a floor whose headroom is 40 is a floor that lets 40 tests be
// deleted, and the reminder used to be a t.Logf on a passing test, which
// `go test ./...` without -v never prints.
//
// Lower it ONLY when tests were removed on purpose, and say so in the commit.
const minimumTestFunctions = 1495

// minimumFuzzTargets is the same floor for `func FuzzXxx(*testing.F)`.
const minimumFuzzTargets = 25

// maximumHeadroom bounds how far the real count may drift above a floor before
// the floor has to be raised.
//
// It is a BAND rather than an equality because the point of a floor is that
// adding tests does not break the build. Twenty five is roughly a large feature
// branch's worth of tests: enough that no ordinary change trips it, small enough
// that the floor cannot quietly stop detecting anything. The repair is one line
// and the failure message names the number to write.
const maximumHeadroom = 25

// buildConstrainedTestFiles is every test file in this package that does not
// build somewhere, with WHERE it does not build.
//
// This is the half the count cannot reach. A file that gains a constraint still
// declares its tests, so the parse count does not move, but the tests stop
// running wherever the constraint excludes them. The three rows below are Linux
// only for good reasons and that is a decision. A fourth appearing, or one of the
// three widening, has to be one too.
//
// The values are derived from build.Context.MatchFile over constraintProbes, so
// they describe the EFFECT rather than the spelling: a file constrained by its
// name and a file constrained by a directive read identically here, which is what
// makes the census blind to the difference in the right way.
var buildConstrainedTestFiles = map[string]string{
	"datagram_mtu_gate_linux_test.go": "does not build on darwin/arm64, freebsd/amd64, windows/amd64",
	"snmp_getbulk_test.go":            "does not build on darwin/arm64, freebsd/amd64, windows/amd64",
	"snmp_response_size_test.go":      "does not build on darwin/arm64, freebsd/amd64, windows/amd64",
}

// constraintProbes are the (GOOS, GOARCH) pairs the census evaluates each file
// against. They are a SAMPLE and the census says so: a file excluded only on, say,
// plan9 reads as unconstrained here. The five below cover the platforms this
// project is built or developed on plus one that shares neither the OS nor the
// libc of the others, which is what makes a GOOS-suffix rename visible.
var constraintProbes = []struct{ goos, goarch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "arm64"},
	{"freebsd", "amd64"},
	{"windows", "amd64"},
}

// loadBearingGuard is one manifest row: a test name, the file that declares it,
// and the reason its absence would be dangerous rather than merely regrettable.
//
// THE FILE IS NOT DECORATION. Without it a row is satisfied by any test of that
// name anywhere in the package, so moving a guard's name onto an unrelated
// function keeps the row green. It also gives the failure messages somewhere to
// point, and it is what lets the wiring control below find a real guard to delete
// from a copy of the tree.
type loadBearingGuard struct {
	name string
	file string
	why  string
}

// loadBearingGuards is the manifest.
//
// THE ADMISSION CRITERION IS NARROW ON PURPOSE: a test qualifies when its
// deletion would let a previously-fixed defect return with a green suite. That is
// what separates this list from a second count floor. Ordinary unit tests are
// covered by minimumTestFunctions and are deliberately absent, because a manifest
// of everything is a maintenance burden that names nothing.
//
// The nine ledger reversals are here one apiece: each is the test that reproduces
// a parent revision's digest byte for byte, and without it a shipped-data
// transition is no longer reversible. Their sibling vacuity and value-pin tests
// are left to the floor, so that the manifest stays a list a reader can read.
var loadBearingGuards = []loadBearingGuard{
	// The two nl6#577 names. Both were actually deleted with a green suite.
	{"TestEveryDeletedDeadRowIsAnsweredByTheCycler", "snmp_shipped_resource_defect_ledger_test.go",
		"nl6#574, deleted once already. The only guard that the 742 deleted static ifTable rows are " +
			"still answered by the cycler. The corpus digests' documented remedy is to RE-PIN, so " +
			"without this an unreachable column becomes an unanswered one and the re-pin absorbs it"},
	{"TestPaloAltoPANSubtreeMatchesTheMIB", "snmp_shipped_resource_defect_ledger_test.go",
		"nl6#569, deleted once already. The record of the PAN-COMMON-MIB reading that corrected 8 of " +
			"11 OIDs. Nothing in CI compares nl6 against that MIB, so the test IS the reading"},

	// The resource-value guard: three rules, four loaders, and the wiring.
	{"TestGuardIsWiredIntoLoaders", "snmp_resource_guard_test.go",
		"nl6#523/#529/#541. validateSNMPResourceValues is called at four loaders and wiring is per " +
			"RULE. Deleting this lets a call site be dropped, or a rule reach only some loaders, with " +
			"every value assertion still passing"},
	{"TestShippedResourcesLoadClean", "snmp_resource_guard_test.go",
		"nl6#523. The positive control that the whole shipped set passes the value guard. Without it " +
			"the guard could be narrowed to nothing and no shipped file would notice"},
	{"TestGuardAgreesWithTheEncoder", "snmp_resource_guard_test.go",
		"nl6#529. Pins the OID-encodability rule to encodeTypedValue and appendOID rather than to a " +
			"second predicate. A second predicate that agreed on the day it was written is exactly how " +
			"trap_catalog.go's validateDottedOID drifted from the encoder"},

	// The bare-column and octet-shadow sweeps, whose guards each inverted or
	// narrowed once during development.
	{"TestBareColumnCensusHasNotGrown", "snmp_shipped_corpus_test.go",
		"nl6#571. The census is CORPUS-WIDE and narrowing it back to one profile passed the whole " +
			"suite once, with 20 bare columns still shipping. Legality is a property of the OID, not " +
			"of which profile carries it"},
	{"TestNoShippedWalkEmitsABareColumnOID", "snmp_shipped_resource_defect_ledger_test.go",
		"nl6#571, the walk-side half of the same rule. A bare column can reach a collector through a " +
			"GETNEXT successor without ever being asked for by name"},
	{"TestEveryInterfaceAnswersBothOctetColumns", "if_counters_octet_shadow_test.go",
		"nl6#570/#574. The one guard that fires on the DEFECT rather than on a digest: a later profile " +
			"edit adding interfaces without an HC row would drop both octet columns for them, and the " +
			"only other tests to fire are digests whose remedy is to re-pin"},
	{"TestStaticRowsOnCyclerOwnedIfTableColumnsMatchTheCensus", "if_counters_octet_shadow_test.go",
		"nl6#574. Keeps the .7/.8 carve-out visible as a census row rather than as a comment. Those " +
			"887 rows look exactly like the dead shadows and are live seed input to the state engine"},

	// The corpus walk itself, and the digests that ride on it.
	{"TestShippedCorpusViewsAgree", "snmp_shipped_corpus_test.go",
		"The cross-check that both resource layouts are seen. The walkers globbed two path segments " +
			"once, which made a single-file profile invisible to the sentinel guard, the tag digest " +
			"and the Counter64 pin at the same time"},
	{"TestShippedTagsUnchangedByTableWidening", "snmp_hc_counter_table_test.go",
		"The (profile, OID, emitted tag) digest over all shipped entries. It is what makes widening " +
			"oidTypeTable a measured wire change rather than an asserted one"},
	{"TestWellFormedResponsesUnchangedOnTheWire", "snmp_parser_robustness_test.go",
		"nl6#542. The wire digest whose baseline was RE-DERIVED against 5f3ca99 rather than updated " +
			"from the new code. Deleting it removes the only evidence that single-binding GETNEXT, " +
			"which is essentially all real traffic, is byte-identical"},
	{"TestMultiBindingGetNextResponsesArePinned", "snmp_parser_robustness_test.go",
		"nl6#542. Freezes the 72 datagrams the wire digest deliberately excludes, so the exclusion " +
			"does not become an unexecuted hole"},
	{"TestLongestCounter64RunAcrossShippedProfiles", "snmp_counter64_run_pin_test.go",
		"nl6#524/#542. Its constant is the NUMERATOR of counter64SkipBudgetSteps(), so an unmeasured " +
			"long HC run under-sizes a serve-path budget and truncates v1 tables"},
	{"TestStaticIndexUnderCountsTheCounter64Run", "snmp_counter64_run_pin_test.go",
		"nl6#524. Asserts that the static-index and walk measurements DISAGREE, so a future " +
			"convergence has to be a decision rather than a measurement quietly agreeing with itself"},
	{"TestOidTypeTableAgreesWithTheMIBs", "snmp_mib_agreement_test.go",
		"nl6#541. Compares oidTypeTable against MIB facts extracted with net-snmp and checked in. The " +
			"test-side column lists are a RESTATEMENT of the same reading, so this is the only " +
			"independent verification the table has"},
	{"TestShippedBigValuesSitOnCounter64Leaves", "snmp_hc_counter_table_test.go",
		"nl6#541. The tripwire for a vendor 64-bit column on a leaf oidTypeTable does not type, which " +
			"is the class rule 3 cannot see"},
	{"TestShippedUntypedValuesFitInteger32", "snmp_hc_counter_table_test.go",
		"nl6#541. Closes the band below 2^32 that the big-value test's threshold leaves open, and it " +
			"is what caught hrStorageSize.1 sitting exactly one over Integer32"},

	// Vendor arcs: the PEN guard, the labelling policy, and its curation.
	{"TestEveryProfileServesOnlyItsOwnVendorArc", "snmp_own_vendor_pen_test.go",
		"nl6#588. The cross-vendor contamination guard. Twelve non-PAN profiles served Palo Alto OIDs " +
			"and four Cisco profiles served a Juniper column before it existed"},
	{"TestOwnVendorPENMapIsCuratedAndComplete", "snmp_own_vendor_pen_test.go",
		"nl6#588. Pins the PEN registry the guard reads. A stale or incomplete map makes the guard " +
			"silent about exactly the profiles it does not cover"},
	{"TestEveryVendorArcIsAuditedLabelledOrExcluded", "snmp_unaudited_arc_label_test.go",
		"nl6#590. The policy itself: every (profile, PEN) pair is audited, labelled unaudited, or " +
			"excluded with a reason. Without it a new device type can ship a vendor subtree that " +
			"reads as checked because nothing says otherwise"},
	{"TestNoStaleUnauditedArcLabel", "snmp_unaudited_arc_label_test.go",
		"nl6#590, the mirror. A label left behind after an audit tells a reader the opposite of the " +
			"truth, and the policy guard alone cannot see it"},
	{"TestUnauditedArcRegistriesAreCurated", "snmp_unaudited_arc_label_test.go",
		"nl6#590. Requires every auditedArcPENs row's reading test to EXIST, which is the same " +
			"class of hole this whole file addresses: a renamed audit would leave the map excusing " +
			"an arc on the strength of a function that is gone"},
	{"TestNoForeignPANOIDsShip", "snmp_shipped_resource_defect_ledger_test.go",
		"nl6#569. Keeps the Palo Alto arc clean after 24 entries were deleted from twelve foreign " +
			"profiles"},
	{"TestTrapAndPollAgreeOnType", "snmp_trap_poll_type_agreement_test.go",
		"nl6#606. One OID must not answer with one type when polled and another when it arrives as a " +
			"trap varbind. Nothing else compares the two encoders"},
	{"TestScenarioDrain_CeilingBoundsAStalledWrite", "scenario_drain_ceiling_test.go",
		"nl6#567. A stalled transport write must not outlast the drain BARRIER, which runs on the " +
			"graceful-shutdown path. Deliberately not phrased as bounding shutdown: finish() joins " +
			"the scheduler and tickers ahead of the barrier and those joins are unbounded"},
	{"TestAuthProtocolReachesEveryDerivation", "snmpv3_usm_conformance_test.go",
		"nl6#624. -snmpv3-auth was parsed, stored and consulted by nothing, and the two privacy " +
			"derivations hardcoded OPPOSITE hashes, so md5+des happened to match RFC 3414 while " +
			"sha1+des did not. Asserted through derived KEYS, not through an AST scan for reads: a " +
			"scan proves the identifier appears, only the keys prove it changes anything"},
	{"TestInboundV3RequestsAreAuthenticated", "snmpv3_usm_conformance_test.go",
		"nl6#624. nl6 answered a v3 request carrying any digest, so a collector's wrong-credential " +
			"and replay handling could not be tested against it. Driven through the DISPATCHER and " +
			"asserting the usmStats OID per row, because a verifier returning false is worth nothing " +
			"if nothing calls it, and a rejection for the wrong reason misdirects the operator"},
	{"TestAESIVIsBuiltFromTheAdvertisedEngineTime", "snmpv3_usm_wire_test.go",
		"nl6#624. Decrypts with the standard library using ONLY what the response carries, because " +
			"every round trip in the package encrypts and decrypts with nl6's own code and an IV " +
			"that is wrong but SYMMETRIC passes all of them. Advertising a time 1000s from the one " +
			"the IV was built from left the whole suite green until this landed"},
	{"TestDESIVIsSaltXorPreIV", "snmpv3_usm_wire_test.go",
		"nl6#624. RFC 3414 §8.1.1.1. nl6 emitted one random value as BOTH the CBC IV and privParams. " +
			"Runs under MD5 and SHA1 because the localized key is 16 octets under one and 20 under " +
			"the other while the pre-IV is sliced at a fixed index, so 'the last 8 octets' is right " +
			"for MD5 and wrong for SHA1 — and sha1+des was exercised by nothing at all"},
	{"TestNoAuthNoPrivWireDeltaIsRecorded", "snmpv3_usm_wire_test.go",
		"nl6#624's one explicit proof obligation was that noAuthNoPriv stay byte-identical, and it " +
			"CANNOT be met: three of the defects are in the envelope every security level shares. " +
			"This records the three fields that moved instead of asserting an identity that would " +
			"require keeping the defects"},
	{"TestUnknownUserIsAnsweredNotIgnored", "snmpv3_usm_wire_test.go",
		"nl6#624. RFC 3414 §3.2 step 4. A wrong USER was a silent drop while a wrong DIGEST got a " +
			"Report, so a collector could not tell an unknown user from an unreachable device"},
	{"TestTimeWindowReportIsSignedAndWrongDigestReportIsNot", "snmpv3_usm_wire_test.go",
		"nl6#624. The asymmetry that makes engine time recoverable: §3.2 step 7 signs the " +
			"notInTimeWindows Report so a manager can trust the (boots, time) it carries, while a " +
			"wrongDigests Report is deliberately unsigned because the peer's key disagrees with ours"},
	{"TestTwelveZeroByteValueDoesNotBreakSigning", "snmpv3_usm_test.go",
		"nl6#624. A REGRESSION FOR A DEFECT THIS CHANGE SHIPPED. substituteAuthParams located the " +
			"auth field by searching for `04 0C` plus twelve zeros — byte-for-byte how an OCTET " +
			"STRING value of twelve zero bytes encodes — so a device serving one made the pattern " +
			"ambiguous and the whole response failed to assemble, returning NOTHING with no log " +
			"line, reachable from an ordinary operator resource file. Now located structurally"},
	{"TestEveryEmitterAgreesOnTheEngineIdentity", "snmpv3_usm_conformance_test.go",
		"nl6#624. FOUR paths emit msgAuthoritativeEngineID and the first cut corrected one, leaving " +
			"three sending the hex SPELLING and a UNIX epoch. A manager discovers the engine from one " +
			"and authenticates against another, so it derived a different key and rejected everything " +
			"— with the whole package green. Found by net-snmp, not by any in-package test"},
	{"TestUSMKeyDerivationMatchesRFC3414Vectors", "snmpv3_usm_test.go",
		"nl6#624. The ONLY check here that does not read nl6's output with nl6's own parser: the four " +
			"localized keys are compared against RFC 3414 A.3's published values, parsed from a " +
			"checked-in extract of the RFC. A shared misunderstanding passes every other v3 test"},
	{"TestSNMPv3TrapInteropWithSnmptrapd", "snmpv3_usm_interop_test.go",
		"nl6#98. The ONLY check that an emitted SNMPv3 notification is acceptable to something other " +
			"than nl6. snmpget structurally cannot cover it — nothing polls a trap — so without this " +
			"the whole v3 trap path is verified by nl6 reading its own bytes, which is precisely the " +
			"state nl6#624 shipped for years with a green suite"},
	{"TestV3TrapOutputIsPinned", "trap_v3_test.go",
		"nl6#98. The ONLY byte-level pin on the v3 notification path. Every other test in that file " +
			"re-derives its expectation through the same code, so a refactor of the shared v3 " +
			"envelope moves every emitted byte while satisfying all of them; the four " +
			"trap_pdu_extraction_test.go digests cover the poll path and v1/v2c, not this one"},
	{"TestSNMPv3TrapInteropRejectsAWrongPassword", "snmpv3_usm_interop_test.go",
		"nl6#98. The control for the seven interop rows. Without it a receiver that logged " +
			"unauthenticated notifications would pass all seven, so they would prove reachability " +
			"rather than authentication — the exact gap nl6#625 found on the poll side"},
	{"TestV3TrapDoesNotTouchThePollEngine", "trap_v3_test.go",
		"nl6#98. The trap engine identity must NOT be usmState()'s, whose engine ID is fleet-wide by " +
			"decision. Keying a trap on it makes every device's notification identity and localized " +
			"key identical — the nl6#588/#599 shared-identity defect — while every single-message " +
			"assertion in the package still passes"},
	{"TestV3TrapRefusesAnUnderivableEngineIdentity", "trap_v3_test.go",
		"nl6#98. The DECIDED half of nl6#627's open question. wrapInScopedPDU accepts a nil engine ID " +
			"and usmState substitutes defaultSNMPv3EngineID for an empty one, so without this refusal " +
			"a device with no derivable IPv4 silently joins a fleet that all shares one engine identity"},
	{"TestV1MappingEnterpriseSpecificIgnoresTheDeclaredEnterprise", "trap_v1_test.go",
		"nl6#97. RFC 3584 3.2 honours a declared snmpTrapEnterprise ONLY for a standard trap; a " +
			"non-standard one always derives it from snmpTrapOID. The spec had this backwards, and " +
			"honouring the declared value would put an enterprise on the wire no proxy produces"},
	{"TestV1DropsTheV2cPrependedVarbinds", "trap_v1_test.go",
		"nl6#97. sysUpTime.0, snmpTrapOID.0 and snmpTrapEnterprise.0 became PDU fields in v1; " +
			"emitting them as varbinds produces a trap no real agent sends"},
	{"TestV2cOutputUnchangedByV1Encoder", "trap_v1_test.go",
		"nl6#97. Adding a second encoder must not perturb the first. Digest over every shipped " +
			"catalog entry, verified equal at the baseline commit rather than merely recorded"},
	// nl6#98's four unchanged-output digests. Same admission criterion as the
	// nl6#97 row above them: each is measured at the baseline commit in a
	// worktree, so deleting one removes the only evidence that a seam lifted out
	// of a shipped encoder changed no byte, and the extraction becomes
	// unfalsifiable rather than merely unproven.
	{"TestV2cNotificationOutputUnchangedByPDUExtraction", "trap_pdu_extraction_test.go",
		"nl6#98. The SNMPv2c reference encoder's output over every effective shipped catalog, TRAP " +
			"and INFORM. encodeNotificationPDU was lifted out of encodeV2cNotification underneath it"},
	{"TestFastV2cNotificationOutputUnchangedByPDUExtraction", "trap_pdu_extraction_test.go",
		"nl6#98. The fast encoder is READ-ONLY in that change, so a move here is a shared primitive " +
			"moving beneath it. Parity with the reference is not enough on its own: both sides moving " +
			"together keeps parity green, and only the pair of pinned digests rules that out"},
	{"TestV1NotificationOutputUnchangedByPDUExtraction", "trap_pdu_extraction_test.go",
		"nl6#98. The v1 encoder builds its own PDU and calls none of the lifted code, but shares " +
			"encodeVarbindTyped and the OID encoder with it"},
	{"TestV3PollOutputUnchangedByEnvelopeExtraction", "trap_pdu_extraction_test.go",
		"nl6#98. The riskiest digest: wrapInScopedPDU and wrapScopedPDUInV3MessageWith sit directly " +
			"on the shipped poll path. It is also the SOLE guard that the Report path's scoped PDU " +
			"still agrees with the response path's — the two drifted once already (nl6#624, the " +
			"engine ID's hex spelling against its octets) with the whole package green"},
	// nl6#98's structural and seam guards. A byte digest CANNOT see a call site
	// reverted to an exact local copy — the copy emits the same bytes, every
	// digest above stays green, and it becomes visible only the day one of the
	// two drifts, which is the day it is a defect rather than the day it was
	// introduced. These are the only cover for that class.
	{"TestExtractedSeamsHaveExactlyOneImplementation", "trap_pdu_extraction_test.go",
		"nl6#98, the forward half: the four named callers still CALL the lifted helpers. Deleting it " +
			"lets encodeV2cNotification, createScopedPDUMulti, createDiscoveryScopedPDU or " +
			"wrapScopedPDUInV3Message grow a private copy of the seam back, with all four digests " +
			"green, and the nl6#98 notification encoder then builds on a second implementation"},
	{"TestNothingReimplementsTheExtractedSeams", "trap_pdu_extraction_test.go",
		"nl6#98, the complementary half, and it exists because the forward scan MISSED A LIVE " +
			"re-implementation: createDiscoveryScopedPDU hand-built the scoped-PDU envelope while " +
			"not being a named caller. Its rule is STRUCTURAL rather than by name because a reviewer " +
			"defeated the by-name version with a complete second copy whose local was called `eid`, " +
			"and both scans stayed green. Deleting it re-opens both holes"},
	{"TestPrivSaltSeamIsInitialisedFromCryptoRand", "trap_pdu_extraction_test.go",
		"nl6#98. The ONLY pin that the SNMPv3 privacy salt is crypto/rand in production. Pointing " +
			"usmPrivSaltRead at ONE seeded math/rand generator left the ENTIRE package green — every " +
			"digest (they all pin the salt and overwrite the default first), the race suite, the " +
			"net-snmp interop gate, and the behavioural test below — while the DES IV became " +
			"predictable and identical plaintext encrypted identically. gosec cannot cover it either: " +
			"the repo excludes G404 on the written rationale that crypto/rand is used where it matters"},
	{"TestPrivSaltDefaultsToCryptoRand", "trap_pdu_extraction_test.go",
		"nl6#98, the behavioural half of the same seam. A reviewer replaced the default with a " +
			"zero-filler and the whole package stayed green, because every authPriv digest pins the " +
			"salt itself and none of them can see the default at all"},
	{"TestInterfaceStateInjectedClockIsUsedEverywhere", "interface_state_clock_test.go",
		"nl6#575. All THREE of the engine's clock reads must move together: a boot time from the real " +
			"clock and transitions from an injected one subtract a real timestamp from a fake one. " +
			"Asserts MAGNITUDE as well as ordering, because without that the SetOperStatus mutation " +
			"is caught only by clock granularity and survives on a ns-resolution Linux clock"},
	{"TestInterfaceStateClockSampleStaysInsideTheCASLoop", "interface_state_clock_test.go",
		"nl6#575. The clock is sampled inside the CAS loop so a retry stamps the winning attempt. " +
			"Hoisting it reads as a refactor and makes ifLastChange go backwards under contention; " +
			"review demonstrated the whole package stayed green with it hoisted"},
	{"TestInterfaceStateInjectedClockCanStepBackwards", "interface_state_clock_test.go",
		"nl6#575. The only exercise of the rewind sentinel in the package. The flap test could reach " +
			"it by luck before this change and cannot by construction after it"},
	{"TestInterfaceStateClockDefaultsToWallClock", "interface_state_clock_test.go",
		"nl6#575. The only pin that production stays on the real wall clock: the seam must expose " +
			"which clock is read without changing what an un-injected engine does"},
	{"TestFinalizeIsBoundedWhenTheSchedulerStalls", "scenario_finalize_join_test.go",
		"nl6#618. The COMMON stalled-write case. The syslog scheduler fires inline, so a stalled " +
			"write parks its run loop and finish() blocks joining it, with nl6#567's barrier ceiling " +
			"never armed. Without the bound this test hangs rather than fails"},
	{"TestFinalizeIsBoundedWhenAFlowTickStalls", "scenario_finalize_join_test.go",
		"nl6#618. The flow ticker join runs under c.mu, so a parked Tick write blocked Phase, Result " +
			"and LiveCounts as well as finalize. Untestable before this change added a write seam to " +
			"FlowExporter"},
	{"TestScenarioDrain_CeilingCountsEveryStraggler", "scenario_drain_ceiling_test.go",
		"nl6#567. Pins the straggler count AS A COUNT. Review demonstrated that replacing it with " +
			"the constant 1 left the whole package green, because every give-up test admitted one " +
			"fire; the number sizes the uncertainty in every total on the report"},
	{"TestReportHTML_TruncatedRun", "scenario_report_html_test.go",
		"nl6#567. The HTML view is the only operator-facing surface showing a truncated finalize " +
			"without reading raw JSON. Review demonstrated that deleting the banner left the package " +
			"green, since every other HTML test renders a report with no stragglers"},
	{"TestScenarioFinishCarriesTheStragglerCount", "scenario_drain_ceiling_test.go",
		"nl6#567. finish() is the only production site turning closeAndWait's count into report " +
			"data. Discarding it left the whole package green while a truncated finalize reported " +
			"as clean, which review demonstrated by mutation"},
	{"TestTrapCatalogDoesNotContradictItself", "snmp_trap_poll_type_agreement_test.go",
		"nl6#607. The same one-object-two-types defect, found without any resource data. It is the " +
			"ONLY check that reaches ciena_waveserver5's catalog, which joins nothing at all, and the " +
			"only one that reaches a templated varbind, which is not joinable by construction"},

	// Capability and contract completeness.
	{"TestFlowCapabilityCompleteness", "flow_capability_completeness_test.go",
		"Every repo device type must be in flowProfileMap XOR flowIncapableTypes. A type absent from " +
			"both silently inherits edge-router flow ground truth, which is a collector-visible lie"},
	{"TestOpticalPathManifest", "gnmi_optical_test.go",
		"Pins served == manifest in BOTH directions, and pins the deliberate absence of post-fec-ber. " +
			"Deleting it lets an invented or dropped gNMI optical path ship"},

	// The nine ledger reversals. One per ledger: the test that reproduces a parent
	// revision's digest byte for byte.
	{"TestShippedDataEditsReproduceTheParentCorpus", "snmp_shipped_data_ledger_test.go",
		"nl6#541's ledger reversal against 44ef67f. Without it the 31 tag changes, 16 rescales and 14 " +
			"removals are a summary rather than a transition anyone can re-derive"},
	{"TestOctetShadowDeletionReproducesTheParentCorpus", "snmp_shipped_octet_shadow_ledger_test.go",
		"nl6#570's ledger reversal. It is also the chain link nl6#541's reversal starts from"},
	{"TestResourceDataDefectsReproduceTheParentCorpus", "snmp_shipped_resource_defect_ledger_test.go",
		"The nl6#574 + nl6#571 + nl6#569 ledger reversal: 829 deletions and 5 corrections chained " +
			"through three revisions"},
	{"TestNvidiaArcRehomeReproducesTheParentCorpus", "snmp_shipped_nvidia_arc_ledger_test.go",
		"nl6#576/#587's ledger reversal for the NVIDIA arc re-homing"},
	{"TestAWSPENRePinIsOnlyTheRehoming", "snmp_shipped_aws_pen_ledger_test.go",
		"nl6#588's AWS reversal. This ledger has only a name-view reversal, so it is the sole test " +
			"that reproduces 87c642d's OID-encoding digest"},
	{"TestCiscoArcAuditReproducesTheParentCorpus", "snmp_shipped_cisco_arc_ledger_test.go",
		"nl6#590's Cisco arc audit reversal, 11 of 13 ciscoMgmt OIDs corrected"},
	{"TestWriteMemRemovalReproducesTheParentCorpus", "snmp_shipped_cisco_writeonly_ledger_test.go",
		"The Cisco write-only object removal reversal"},
	{"TestAristaArcAuditReproducesTheParentCorpus", "snmp_shipped_arista_arc_ledger_test.go",
		"nl6#590's Arista arc audit reversal, the 6 of 6 result"},
	{"TestJuniperArcAuditReproducesTheParentCorpus", "snmp_shipped_juniper_arc_ledger_test.go",
		"nl6#602's Juniper arc audit reversal, 13 of 15 OIDs corrected"},
}

// ── the parse ───────────────────────────────────────────────────────────────

// funcKey identifies a declared function by FILE as well as by name.
//
// Keying by name alone collapsed a name declared in both `package main` and
// `package main_test`, so deleting one of the two was invisible. It also let a
// manifest row be satisfied by a same-named test somewhere else entirely.
type funcKey struct {
	File string
	Name string
}

// funcFacts is what the manifest's gutted-or-skipped check reads: whether a
// function asserts anything itself, whether it opens by skipping, and which
// package-level functions it calls so an assertion can be found one or two
// helpers away.
type funcFacts struct {
	asserts bool     // calls .Error, .Errorf, .Fatal or .Fatalf somewhere in its body
	skips   bool     // a TOP-LEVEL statement calls .Skip, .Skipf or .SkipNow
	calls   []string // package-level identifiers it calls
}

// testInventory is what one parse of a package directory's test sources yields.
type testInventory struct {
	Tests       map[funcKey]bool
	Fuzz        map[funcKey]bool
	Benchmarks  map[funcKey]bool
	Constrained map[string]string    // file -> where it does not build
	Facts       map[string]funcFacts // every top-level func in the test sources, by name
	Files       int
}

// parseTestInventory reads every eligible *_test.go in dir with go/parser,
// classifies the top-level functions it declares, and resolves each file's build
// constraints through go/build.
//
// It is a pure function of the directory so the wiring control can hand it a COPY
// of this package with one guard removed, which is what lets a floor assertion be
// shown to fail against the real committed numbers.
func parseTestInventory(dir string) (testInventory, error) {
	inv := testInventory{
		Tests:       map[funcKey]bool{},
		Fuzz:        map[funcKey]bool{},
		Benchmarks:  map[funcKey]bool{},
		Constrained: map[string]string{},
		Facts:       map[string]funcFacts{},
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return inv, fmt.Errorf("read %s: %w", dir, err)
	}

	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		// go/build ignores files whose names begin with _ or . and so does the
		// compiler, so counting them would inflate the floor with code that never
		// builds.
		if strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") {
			continue
		}

		path := filepath.Join(dir, name)
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return inv, fmt.Errorf("parse %s: %w", path, perr)
		}
		inv.Files++

		where, cerr := buildConstraintOf(dir, name)
		if cerr != nil {
			return inv, cerr
		}
		if where != "" {
			inv.Constrained[name] = where
		}

		testingPkg := testingIdents(f)
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			inv.Facts[fn.Name.Name] = factsOf(fn)

			key := funcKey{File: name, Name: fn.Name.Name}
			switch kind := testingParamKind(fn, testingPkg); {
			case kind == "T" && isToolchainName(fn.Name.Name, "Test"):
				inv.Tests[key] = true
			case kind == "F" && isToolchainName(fn.Name.Name, "Fuzz"):
				inv.Fuzz[key] = true
			case kind == "B" && isToolchainName(fn.Name.Name, "Benchmark"):
				inv.Benchmarks[key] = true
			}
		}
	}
	return inv, nil
}

// isToolchainName applies `go test`'s own naming rule rather than an
// approximation of it: the name must start with the prefix AND the rune that
// follows must not be lower case, so `Testlowercase` is not a test. Counting it
// would put a function in the floor that the toolchain never runs.
func isToolchainName(name, prefix string) bool {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok {
		return false
	}
	if rest == "" {
		return true // `func Test(t *testing.T)` is a test.
	}
	r, _ := utf8.DecodeRuneInString(rest)
	return !unicode.IsLower(r)
}

// testingIdents returns the identifiers that refer to the testing package in f.
//
// Resolving `testing` syntactically was wrong: `import tst "testing"` made every
// test in that file uncountable, which is a silent floor drop with no deletion
// behind it. A dot-import of testing would make the parameter type a bare *T and
// is not handled, which is recorded here rather than pretended away. No file in
// this package does either today.
func testingIdents(f *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, imp := range f.Imports {
		if imp.Path == nil || imp.Path.Value != `"testing"` {
			continue
		}
		switch {
		case imp.Name == nil:
			out["testing"] = true
		case imp.Name.Name != "_" && imp.Name.Name != ".":
			out[imp.Name.Name] = true
		}
	}
	return out
}

// testingParamKind returns "T", "F" or "B" when fn takes EXACTLY one parameter of
// type *testing.T, *testing.F or *testing.B, under the file's own spelling of the
// testing package.
//
// The exactly-one part is the point. `func TestHelper(t *testing.T, want int)` is
// a helper, not a test, and the toolchain does not run it. Counting it would make
// the floor move on a helper rename, which is noise the guard cannot afford: a
// floor that fails for uninteresting reasons gets lowered without being read.
func testingParamKind(fn *ast.FuncDecl, testingPkg map[string]bool) string {
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return ""
	}
	field := fn.Type.Params.List[0]
	if len(field.Names) > 1 {
		return "" // func Test(a, b *testing.T) is two parameters in one field.
	}
	star, ok := field.Type.(*ast.StarExpr)
	if !ok {
		return ""
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || !testingPkg[pkg.Name] {
		return ""
	}
	switch sel.Sel.Name {
	case "T", "F", "B":
		return sel.Sel.Name
	}
	return ""
}

// factsOf reads one function body for the manifest's gutted-or-skipped check.
func factsOf(fn *ast.FuncDecl) funcFacts {
	var f funcFacts
	if fn.Body == nil {
		return f
	}

	// A skip only counts when it is a TOP-LEVEL statement. A t.Skip inside a
	// conditional is a legitimate environment guard (about thirty files here use
	// one), while a t.Skip as the first thing a guard does has disabled it.
	for _, stmt := range fn.Body.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		if call, ok := expr.X.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "Skip", "Skipf", "SkipNow":
					f.skips = true
				}
			}
		}
	}

	seen := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			name := fun.Sel.Name
			if strings.HasPrefix(name, "Error") || strings.HasPrefix(name, "Fatal") {
				f.asserts = true
			}
		case *ast.Ident:
			if !seen[fun.Name] {
				seen[fun.Name] = true
				f.calls = append(f.calls, fun.Name)
			}
		}
		return true
	})
	sort.Strings(f.calls)
	return f
}

// assertsWithin reports whether name asserts, directly or through helpers up to
// depth levels away.
//
// Depth-limited rather than unbounded because a test's call graph reaches most of
// the package: two or three hops finds `assertFooDetectionWorks` style helpers,
// which is the shape this package actually uses, without concluding that
// everything asserts because something eventually does.
func (inv testInventory) assertsWithin(name string, depth int) bool {
	facts, ok := inv.Facts[name]
	if !ok {
		return false
	}
	if facts.asserts {
		return true
	}
	if depth <= 0 {
		return false
	}
	for _, callee := range facts.calls {
		if callee == name {
			continue
		}
		if inv.assertsWithin(callee, depth-1) {
			return true
		}
	}
	return false
}

// testFilesByName inverts the (file, name) keying so the manifest rule can ask
// where a name is declared, and can see that it is declared twice.
func (inv testInventory) testFilesByName() map[string][]string {
	out := map[string][]string{}
	for k := range inv.Tests {
		out[k.Name] = append(out[k.Name], k.File)
	}
	for name := range out {
		sort.Strings(out[name])
	}
	return out
}

// buildConstraintOf reports where a file does NOT build, as go/build sees it.
//
// build.Context.MatchFile is the whole reason this is not a comment scan: it
// applies the filename suffix rule (foo_windows_test.go), the `//go:build`
// directive and the legacy `// +build` form together, which is exactly the set a
// comment scan got two thirds wrong.
func buildConstraintOf(dir, file string) (string, error) {
	var excluded []string
	for _, probe := range constraintProbes {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH = probe.goos, probe.goarch
		ctx.CgoEnabled = false
		ok, err := ctx.MatchFile(dir, file)
		if err != nil {
			return "", fmt.Errorf("resolve build constraints of %s for %s/%s: %w",
				file, probe.goos, probe.goarch, err)
		}
		if !ok {
			excluded = append(excluded, probe.goos+"/"+probe.goarch)
		}
	}
	if len(excluded) == 0 {
		return "", nil
	}
	sort.Strings(excluded)
	return "does not build on " + strings.Join(excluded, ", "), nil
}

// ── the rules, as pure functions ────────────────────────────────────────────

// inventoryFinding is one population that fell below its floor, or drifted so far
// above it that the floor has stopped detecting anything.
type inventoryFinding struct {
	population string
	kind       string // "below-floor" | "stale-floor"
	got, floor int
}

// inventoryFindings is the floor rule. It is a function rather than an inline
// comparison so a control can require it to REPORT, which is the lesson
// bareColumnCountViolation records: an assertion that only ever passes cannot be
// shown to work.
func inventoryFindings(inv testInventory, testFloor, fuzzFloor, slack int) []inventoryFinding {
	var out []inventoryFinding
	check := func(population string, got, floor int) {
		switch {
		case got < floor:
			out = append(out, inventoryFinding{population, "below-floor", got, floor})
		case got-floor > slack:
			out = append(out, inventoryFinding{population, "stale-floor", got, floor})
		}
	}
	check("Test functions", len(inv.Tests), testFloor)
	check("Fuzz targets", len(inv.Fuzz), fuzzFloor)
	return out
}

// guardRenameAffinity is how many leading or trailing characters a declared test
// name must share with a missing manifest entry to be offered as a rename
// candidate.
//
// Twelve, because every test name opens with the four characters "Test", so a
// prefix match of twelve is eight characters of real agreement. A suffix match
// gets no such freebie and twelve is simply a long tail. Both directions are
// checked because a rename moves either end: TestPaloAltoPANSubtreeMatchesTheMIB
// to TestPaloAltoPANArcMatchesTheMIB keeps the head, and to
// TestPANSubtreeMatchesTheMIB keeps the tail.
const guardRenameAffinity = 12

// guardAssertionDepth is how far the gutted check follows helper calls.
const guardAssertionDepth = 3

// guardFinding is one manifest entry that is not present and working.
//
// The kind matters more than the fact, because the repairs are different and in
// two cases opposite. "deleted" restores a test; "renamed" edits a row in this
// file; "moved" edits a row too but for a different reason; "gutted" and
// "skipped" mean the name is there and the assertions are not, which no count of
// any kind can see.
type guardFinding struct {
	name       string
	file       string
	kind       string // "deleted" | "renamed" | "moved" | "ambiguous" | "gutted" | "skipped"
	detail     string
	candidates []string
}

// missingGuardFindings is THE manifest rule.
func missingGuardFindings(manifest []loadBearingGuard, inv testInventory) []guardFinding {
	claimed := make(map[string]struct{}, len(manifest))
	for _, g := range manifest {
		claimed[g.name] = struct{}{}
	}
	byName := inv.testFilesByName()

	var out []guardFinding
	for _, g := range manifest {
		files := byName[g.name]
		switch {
		case len(files) == 0:
			cands := renameCandidates(g.name, byName, claimed)
			kind := "deleted"
			if len(cands) > 0 {
				kind = "renamed"
			}
			out = append(out, guardFinding{name: g.name, file: g.file, kind: kind, candidates: cands})
			continue
		case len(files) > 1:
			out = append(out, guardFinding{name: g.name, file: g.file, kind: "ambiguous",
				detail: "declared in " + strings.Join(files, " and ")})
			continue
		case files[0] != g.file:
			out = append(out, guardFinding{name: g.name, file: g.file, kind: "moved",
				detail: "declared in " + files[0]})
			continue
		}

		facts := inv.Facts[g.name]
		switch {
		case facts.skips:
			out = append(out, guardFinding{name: g.name, file: g.file, kind: "skipped"})
		case !inv.assertsWithin(g.name, guardAssertionDepth):
			out = append(out, guardFinding{name: g.name, file: g.file, kind: "gutted"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// renameCandidates offers the declared test names that look like the missing one
// under a new spelling. Names the manifest already claims are excluded: a test
// that is itself manifested is not a rename of another manifest entry.
//
// ONLY THE BEST-SCORING NAMES ARE RETURNED, and that is not tidiness. The bare
// threshold offered five candidates for a renamed
// TestPaloAltoPANSubtreeMatchesTheMIB, because "MatchesTheMIB" is thirteen
// characters and four other audits end in it. A candidate list that names
// everything is the same as naming nothing, and the reader has to go and look
// anyway. The true rename scored 33 against their 13, so keeping the maximum and
// its ties leaves exactly the one name worth reading.
func renameCandidates(missing string, byName map[string][]string, claimed map[string]struct{}) []string {
	best := 0
	var out []string
	for name := range byName {
		if _, isClaimed := claimed[name]; isClaimed {
			continue
		}
		score := commonPrefixLen(missing, name)
		if n := commonSuffixLen(missing, name); n > score {
			score = n
		}
		switch {
		case score < guardRenameAffinity || score < best:
			continue
		case score > best:
			best, out = score, []string{name}
		default:
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func commonPrefixLen(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

func commonSuffixLen(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[len(a)-1-n] == b[len(b)-1-n] {
		n++
	}
	return n
}

// constraintFinding is one disagreement between the census and the tree.
type constraintFinding struct {
	file      string
	kind      string // "unrecorded" | "changed" | "stale"
	got, want string
}

// constraintCensusFindings is the census rule, extracted for the same reason the
// other two are: both of its arms survived being disabled, because an inline `if`
// inside a test can only be observed passing.
func constraintCensusFindings(actual, committed map[string]string) []constraintFinding {
	var out []constraintFinding
	for file, where := range actual {
		want, ok := committed[file]
		switch {
		case !ok:
			out = append(out, constraintFinding{file, "unrecorded", where, ""})
		case want != where:
			out = append(out, constraintFinding{file, "changed", where, want})
		}
	}
	for file, want := range committed {
		if _, ok := actual[file]; !ok {
			out = append(out, constraintFinding{file, "stale", "", want})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].file < out[j].file })
	return out
}

// manifestCurationFinding is one defective manifest row.
type manifestCurationFinding struct {
	name   string
	kind   string // "duplicate" | "no-reason" | "no-file" | "not-a-test-name"
	detail string
}

// manifestCurationFindings pins the manifest itself, extracted for the same
// reason: the duplicate check and the empty-reason check both survived being
// disabled while every test stayed green.
func manifestCurationFindings(manifest []loadBearingGuard) []manifestCurationFinding {
	var out []manifestCurationFinding
	seen := map[string]int{}
	for _, g := range manifest {
		seen[g.name]++
		if strings.TrimSpace(g.why) == "" {
			out = append(out, manifestCurationFinding{g.name, "no-reason", ""})
		}
		if strings.TrimSpace(g.file) == "" {
			out = append(out, manifestCurationFinding{g.name, "no-file", ""})
		} else if !strings.HasSuffix(g.file, "_test.go") {
			out = append(out, manifestCurationFinding{g.name, "no-file",
				fmt.Sprintf("%q is not a test file", g.file)})
		}
		if !isToolchainName(g.name, "Test") {
			out = append(out, manifestCurationFinding{g.name, "not-a-test-name", ""})
		}
	}
	for name, n := range seen {
		if n > 1 {
			out = append(out, manifestCurationFinding{name, "duplicate",
				fmt.Sprintf("appears %d times", n)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].kind < out[j].kind
	})
	return out
}

// ── the one place the real manifest and the real floors are read ────────────

// guardReport is the whole verdict for one package directory.
type guardReport struct {
	inv         testInventory
	inventory   []inventoryFinding
	guards      []guardFinding
	constraints []constraintFinding
}

// packageGuardReport applies every rule to dir USING THE REAL COMMITTED VALUES.
//
// THIS FUNCTION EXISTS SO THE WIRING CANNOT BE CUT. Before it, each guard passed
// its own arguments at its own call site, and replacing loadBearingGuards with
// nil or minimumTestFunctions with 0 left the entire package green while the
// manifest still sat in the file with 36 reasons attached, guarding nothing. That
// is precisely the "looks like coverage while guarding nothing" state the rename
// message below warns a reader about, one level up.
//
// Now the guards and their controls read the SAME function. A control that
// deletes a real guard from a COPY of this package and requires a report is
// therefore a pin on the arguments as well as on the rules: cut them here and the
// control fails.
func packageGuardReport(dir string) (guardReport, error) {
	inv, err := parseTestInventory(dir)
	if err != nil {
		return guardReport{}, err
	}
	return guardReport{
		inv:         inv,
		inventory:   inventoryFindings(inv, minimumTestFunctions, minimumFuzzTargets, maximumHeadroom),
		guards:      missingGuardFindings(loadBearingGuards, inv),
		constraints: constraintCensusFindings(inv.Constrained, buildConstrainedTestFiles),
	}, nil
}

// ── the positive controls ───────────────────────────────────────────────────

// copyPackageTestSources copies this package's test sources into a fresh temp
// directory, so a control can mutate them without touching the working tree.
//
// Only *_test.go is copied and nothing is compiled, so the copy is a parse target
// rather than a package. It is about 180 small files and costs a few milliseconds.
func copyPackageTestSources(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	copied := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, rerr := os.ReadFile(e.Name()) // #nosec G304 -- test-only, name from a package-dir read
		if rerr != nil {
			t.Fatalf("read %s: %v", e.Name(), rerr)
		}
		if werr := os.WriteFile(filepath.Join(dir, e.Name()), raw, 0o600); werr != nil {
			t.Fatalf("copy %s: %v", e.Name(), werr)
		}
		copied++
	}
	if copied == 0 {
		t.Fatal("copied no test sources. Is the test running from go/nl6?")
	}
	return dir
}

// removeFuncFromFile cuts one top-level function out of a copied source file.
//
// It works on bytes taken from the parse rather than on a text match, so it
// removes the whole declaration and cannot half-delete one whose name appears in
// a comment or a string. The result need only PARSE, never compile: nothing in
// this file builds the copy.
func removeFuncFromFile(t *testing.T, path, name string) {
	t.Helper()

	raw, err := os.ReadFile(path) // #nosec G304 -- test-only, path built from a manifest row
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, raw, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		from := fset.Position(fn.Pos()).Offset
		to := fset.Position(fn.End()).Offset
		cut := append([]byte{}, raw[:from]...)
		cut = append(cut, raw[to:]...)
		if werr := os.WriteFile(path, cut, 0o600); werr != nil {
			t.Fatalf("rewrite %s: %v", path, werr)
		}
		return
	}
	t.Fatalf("%s declares no func %s, so the control could not delete it", path, name)
}

// assertRealGuardWiringDetectsADeletion is the control that pins the REAL
// manifest and the REAL floors into the REAL rules.
//
// It copies this package, deletes one manifested guard from the copy, and drives
// packageGuardReport over it. Both halves must fire: the floor because the count
// dropped, and the manifest because that specific name is gone. Cutting either
// argument inside packageGuardReport, which is a mutation the whole package
// survived before, now fails here.
//
// The victim is taken from the manifest itself rather than hard-coded, so the
// control cannot outlive the row it depends on.
func assertRealGuardWiringDetectsADeletion(t *testing.T) {
	t.Helper()

	if len(loadBearingGuards) == 0 {
		t.Fatal("the manifest is empty, so nothing below asserts anything")
	}
	victim := loadBearingGuards[0]

	dir := copyPackageTestSources(t)
	removeFuncFromFile(t, filepath.Join(dir, victim.file), victim.name)

	report, err := packageGuardReport(dir)
	if err != nil {
		t.Fatalf("run the real rules over the mutated copy: %v", err)
	}

	var below *inventoryFinding
	for i := range report.inventory {
		if report.inventory[i].kind == "below-floor" &&
			report.inventory[i].population == "Test functions" {
			below = &report.inventory[i]
		}
	}
	if below == nil {
		t.Fatalf("one manifested guard was deleted from a copy of this package and the floor rule "+
			"reported %+v, with no shortfall in Test functions.\nThe floor asserted below is "+
			"therefore not wired to minimumTestFunctions = %d: replacing that constant with 0 at "+
			"the call site would leave the whole package green while the number still sat in the "+
			"file looking like a guard", report.inventory, minimumTestFunctions)
	}
	if below.floor != minimumTestFunctions {
		t.Fatalf("the floor rule ran against %d rather than the committed %d",
			below.floor, minimumTestFunctions)
	}

	// Either "deleted" or "renamed" is a pass here. Which of the two the rule
	// picks depends on whether some OTHER test in the package happens to look like
	// the victim, and it does: deleting TestEveryDeletedDeadRowIsAnsweredByTheCycler
	// leaves TestCiscoTemperatureStatusValueIsServedByTheCycler sharing a
	// thirteen-character tail. That is the rename heuristic working as designed and
	// it is not what this control is about, which is only that the rule NOTICED.
	var named bool
	for _, f := range report.guards {
		if f.name == victim.name && (f.kind == "deleted" || f.kind == "renamed") {
			named = true
		}
	}
	if !named {
		t.Fatalf("%s was deleted from a copy of this package and the manifest rule reported %+v, "+
			"never naming it.\nThe manifest asserted below is therefore not wired to "+
			"loadBearingGuards: replacing it with nil at the call site would leave all %d rows in "+
			"the file, each with its reason text, guarding nothing",
			victim.name, report.guards, len(loadBearingGuards))
	}

	// And the unmutated copy must be silent, or the arm above proves nothing: a
	// rule that reported on every tree would pass it.
	clean, err := packageGuardReport(copyPackageTestSources(t))
	if err != nil {
		t.Fatalf("run the real rules over a clean copy: %v", err)
	}
	if len(clean.guards) != 0 {
		t.Fatalf("the real manifest reported %+v against an UNMUTATED copy of this package. The "+
			"deletion arm above is meaningless if the rule reports on everything", clean.guards)
	}
}

// syntheticTestSources is the parse control's plant: a small package of test
// sources covering every classification decision parseTestInventory makes.
//
// "tagged_linux_test.go" and "probe_windows_test.go" are the two constraint arms,
// and they are different mechanisms on purpose. The first carries a directive.
// The second carries NOTHING but a GOOS suffix in its name, which is how Go
// constrains a file with no comment at all, and it is the case a comment scan
// counted toward the floor while it ran nowhere.
func syntheticTestSources() map[string]string {
	return map[string]string{
		"alpha_test.go": `package p

import "testing"

func TestAlphaOne(t *testing.T) { t.Errorf("x") }
func TestAlphaTwo(t *testing.T) { t.Fatalf("x") }

// A helper whose name starts with Test. The toolchain does not run it and
// neither does the count.
func TestAlphaHelper(t *testing.T, want int) {}

// Test-prefixed but the wrong parameter type entirely.
func TestAlphaNotATest(b *testing.B) {}

// Test-prefixed with a LOWER-CASE rune after the prefix, which go test does not
// treat as a test either.
func Testlowercase(t *testing.T) {}

func FuzzAlpha(f *testing.F)              {}
func BenchmarkAlpha(b *testing.B)         {}
func helperWithNoTestPrefix(t *testing.T) {}
`,
		// An aliased import of testing. Resolving the package name syntactically
		// made every test in a file like this uncountable.
		"aliased_test.go": `package p

import tst "testing"

func TestAliasedImport(t *tst.T) { t.Errorf("x") }
`,
		"tagged_linux_test.go": `//go:build linux

package p

import "testing"

func TestTaggedThree(t *testing.T) { t.Errorf("x") }
`,
		// Constrained by NAME alone, with no directive anywhere in the file.
		"probe_windows_test.go": `package p

import "testing"

func TestWindowsOnly(t *testing.T) { t.Errorf("x") }
`,
		// go/build ignores a leading underscore, so neither does the count.
		"_ignored_test.go": `package p

import "testing"

func TestUnderscoreIgnored(t *testing.T) {}
`,
		"notatest.go": `package p

import "testing"

func TestNotInATestFile(t *testing.T) {}
`,
	}
}

// writeSyntheticPackage materialises a set of sources into a fresh temp dir.
func writeSyntheticPackage(t *testing.T, sources map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for name, body := range sources {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("plant %s: %v", name, err)
		}
	}
	return dir
}

// assertParseAndFloorDetectionWork is the control for the parse's classification
// rules and for both arms of the floor rule.
func assertParseAndFloorDetectionWork(t *testing.T) {
	t.Helper()

	sources := syntheticTestSources()
	inv, err := parseTestInventory(writeSyntheticPackage(t, sources))
	if err != nil {
		t.Fatalf("parse the synthetic package: %v", err)
	}

	want := []string{"TestAliasedImport", "TestAlphaOne", "TestAlphaTwo", "TestTaggedThree", "TestWindowsOnly"}
	byName := inv.testFilesByName()
	for _, n := range want {
		if len(byName[n]) == 0 {
			t.Fatalf("the parse missed %s in the control's synthetic package (saw %v).\n"+
				"TestTaggedThree missing means the parse has stopped reading constrained files, "+
				"which is the whole reason this guard parses instead of calling `go test -list`: "+
				"three files here are Linux-only and a count taken on macOS would not include "+
				"their 29 tests. TestAliasedImport missing means `import tst \"testing\"` has "+
				"become invisible, which is a silent floor drop with no deletion behind it",
				n, sortedNames(byName))
		}
	}
	if len(inv.Tests) != len(want) {
		t.Fatalf("the parse counted %d tests in the control's synthetic package, want %d: %v.\n"+
			"The ones that must NOT count are a Test-prefixed helper taking an extra parameter, a "+
			"Test-prefixed function taking *testing.B, a Testlowercase that go test never runs, a "+
			"test in an _-prefixed file that go/build ignores, and a test in a file that does not "+
			"end in _test.go", len(inv.Tests), len(want), sortedNames(byName))
	}
	if len(inv.Fuzz) != 1 || len(inv.Benchmarks) != 1 {
		t.Fatalf("the parse counted %d fuzz targets and %d benchmarks in the control's synthetic "+
			"package, want 1 and 1", len(inv.Fuzz), len(inv.Benchmarks))
	}

	// Both constraint mechanisms, and only those two files.
	for _, f := range []string{"tagged_linux_test.go", "probe_windows_test.go"} {
		if inv.Constrained[f] == "" {
			t.Fatalf("the constraint census read %s as unconstrained. probe_windows_test.go is the "+
				"one that matters: it carries NO directive and is constrained by its NAME alone, "+
				"which a comment scan counted toward the floor while it ran nowhere", f)
		}
	}
	if len(inv.Constrained) != 2 {
		t.Fatalf("the constraint census reported %d constrained files in the control's synthetic "+
			"package, want 2: %v", len(inv.Constrained), inv.Constrained)
	}

	// The floor's two arms, on an intact tree first.
	if found := inventoryFindings(inv, len(want), 1, 0); len(found) != 0 {
		t.Fatalf("the floor rule reported %+v on an intact tree at its exact counts", found)
	}

	// Arm one: a deleted TEST must report below-floor.
	cutTests := syntheticTestSources()
	delete(cutTests, "tagged_linux_test.go")
	inv, err = parseTestInventory(writeSyntheticPackage(t, cutTests))
	if err != nil {
		t.Fatalf("parse the cut synthetic package: %v", err)
	}
	found := inventoryFindings(inv, len(want), 1, 0)
	if len(found) != 1 || found[0].kind != "below-floor" || found[0].population != "Test functions" {
		t.Fatalf("the control deleted one test function and the floor rule reported %+v.\nThe "+
			"floor is therefore vacuous: a load-bearing guard could be deleted and nothing would "+
			"fail, which is the state nl6#577 exists to leave behind", found)
	}

	// Arm two: a deleted FUZZ TARGET must report against ITS OWN floor. Both arms
	// of the control used to pass a fuzz floor of 1 against exactly 1 target, so
	// the whole fuzz branch could be deleted with the package green.
	cutFuzz := syntheticTestSources()
	cutFuzz["alpha_test.go"] = strings.ReplaceAll(cutFuzz["alpha_test.go"],
		"func FuzzAlpha(f *testing.F)", "func fuzzAlphaRemoved(f *testing.F)")
	inv, err = parseTestInventory(writeSyntheticPackage(t, cutFuzz))
	if err != nil {
		t.Fatalf("parse the fuzz-cut synthetic package: %v", err)
	}
	found = inventoryFindings(inv, len(want), 1, 0)
	if len(found) != 1 || found[0].kind != "below-floor" || found[0].population != "Fuzz targets" {
		t.Fatalf("the control deleted the only fuzz target and the floor rule reported %+v, with "+
			"no Fuzz targets shortfall.\nThe fuzz floor is a separate population precisely so a "+
			"deleted fuzz target cannot be paid for by an added test, and %d fuzz targets ship",
			found, minimumFuzzTargets)
	}

	// Arm three: headroom past the slack band must report a stale floor, which is
	// the only thing that stops the floor decaying into a number that detects
	// nothing.
	found = inventoryFindings(inv, 1, 0, 1)
	var stale bool
	for _, f := range found {
		if f.kind == "stale-floor" && f.population == "Test functions" {
			stale = true
		}
	}
	if !stale {
		t.Fatalf("a floor %d below the real count with a slack of 1 reported %+v and no stale "+
			"floor. Without that arm the only mitigation for floor decay is a t.Logf on a passing "+
			"test, which `go test ./...` never prints", len(inv.Tests)-1, found)
	}
}

// assertGuardManifestDetectionWorks is the control for the manifest rule, and it
// needs five arms rather than two.
//
// A present entry must be silent; an absent one must be reported; an absent one
// whose test looks renamed must be reported AS RENAMED; a name declared in the
// wrong file must be reported as MOVED; and a guard that still exists but asserts
// nothing, or opens with a skip, must be reported too. The last pair is the class
// no count of any kind can see.
func assertGuardManifestDetectionWorks(t *testing.T) {
	t.Helper()

	inv := testInventory{
		Tests: map[funcKey]bool{
			{"a_test.go", "TestKeptGuardIsPresent"}:            true,
			{"b_test.go", "TestRenamedGuardNowCalledThis"}:     true,
			{"c_test.go", "TestSomethingEntirelyUnrelatedYes"}: true,
			// A decoy over the affinity threshold on its TAIL alone. It is what
			// the best-score filter exists for: a shared twelve-character ending
			// is common in this package, so without the filter this name would be
			// offered beside the real rename and the list would say nothing.
			{"d_test.go", "TestAnotherThingUsedToBeThis"}: true,
			{"WRONG_test.go", "TestGuardThatMoved"}:       true,
			{"e_test.go", "TestGuardThatWasGutted"}:       true,
			{"f_test.go", "TestGuardThatWasSkipped"}:      true,
		},
		Facts: map[string]funcFacts{
			"TestKeptGuardIsPresent":  {asserts: true},
			"TestGuardThatMoved":      {asserts: true},
			"TestGuardThatWasGutted":  {calls: []string{"fmt"}},
			"TestGuardThatWasSkipped": {asserts: true, skips: true},
		},
	}
	manifest := []loadBearingGuard{
		{"TestKeptGuardIsPresent", "a_test.go", "present and asserting, must be silent"},
		{"TestVanishedGuardWithNoLookalike", "g_test.go", "absent with nothing similar"},
		{"TestRenamedGuardUsedToBeThis", "b_test.go", "absent with a lookalike"},
		{"TestGuardThatMoved", "RIGHT_test.go", "declared somewhere the manifest does not record"},
		{"TestGuardThatWasGutted", "e_test.go", "present, asserts nothing"},
		{"TestGuardThatWasSkipped", "f_test.go", "present, opens with a skip"},
	}

	found := missingGuardFindings(manifest, inv)
	byName := map[string]guardFinding{}
	for _, f := range found {
		byName[f.name] = f
	}
	if len(found) != 5 {
		t.Fatalf("the manifest rule reported %d findings over a manifest with one healthy row and "+
			"five defective ones, want 5: %+v.\nIf it reported 6, a PRESENT and asserting guard is "+
			"being reported and the rule is worthless. If it reported fewer, a defective one is "+
			"not", len(found), found)
	}
	for name, want := range map[string]string{
		"TestVanishedGuardWithNoLookalike": "deleted",
		"TestRenamedGuardUsedToBeThis":     "renamed",
		"TestGuardThatMoved":               "moved",
		"TestGuardThatWasGutted":           "gutted",
		"TestGuardThatWasSkipped":          "skipped",
	} {
		if got := byName[name].kind; got != want {
			t.Fatalf("%s read as %q, want %q. The kinds call for different repairs, and two of "+
				"them are opposite: restoring a test against editing a row in this file",
				name, got, want)
		}
	}
	renamed := byName["TestRenamedGuardUsedToBeThis"]
	if len(renamed.candidates) != 1 || renamed.candidates[0] != "TestRenamedGuardNowCalledThis" {
		t.Fatalf("the rename candidates for a missing guard were %v, want exactly the lookalike. "+
			"A candidate list that names everything is the same as naming nothing",
			renamed.candidates)
	}

	// A name declared in two files is ambiguous, which is what keying the
	// inventory by (file, name) is for: keyed by name alone, deleting one of the
	// two was invisible.
	dup := inv
	dup.Tests = map[funcKey]bool{}
	for k, v := range inv.Tests {
		dup.Tests[k] = v
	}
	dup.Tests[funcKey{"z_test.go", "TestKeptGuardIsPresent"}] = true
	var sawAmbiguous bool
	for _, f := range missingGuardFindings(manifest, dup) {
		if f.name == "TestKeptGuardIsPresent" && f.kind == "ambiguous" {
			sawAmbiguous = true
		}
	}
	if !sawAmbiguous {
		t.Fatal("a manifested name declared in two files was not reported as ambiguous. Keyed by " +
			"name alone the two collapse into one entry and deleting either is invisible")
	}

	// The helper-resolution arm: a guard that asserts through a helper is intact,
	// and it is the shape this package actually uses.
	viaHelper := inv
	viaHelper.Facts = map[string]funcFacts{
		"TestGuardThatWasGutted": {calls: []string{"assertSomethingViaAHelper"}},
		"assertSomethingViaAHelper": {
			asserts: true,
		},
	}
	for _, f := range missingGuardFindings(manifest, viaHelper) {
		if f.name == "TestGuardThatWasGutted" && f.kind == "gutted" {
			t.Fatal("a guard whose only assertions live in a helper it calls read as gutted. " +
				"Nearly every corpus guard in this package delegates to an assertXDetectionWorks " +
				"helper, so this rule has to follow calls or it reports them all")
		}
	}
}

// assertConstraintCensusDetectionWorks is the control for the census rule. Both
// of its arms survived being disabled before it was extracted from the test body.
func assertConstraintCensusDetectionWorks(t *testing.T) {
	t.Helper()

	committed := map[string]string{
		"known_test.go":    "does not build on windows/amd64",
		"vanished_test.go": "does not build on windows/amd64",
	}
	actual := map[string]string{
		"known_test.go":      "does not build on windows/amd64",
		"unrecorded_test.go": "does not build on darwin/arm64",
		// A constraint that widened: the same file, excluded from more places.
		"changed_test.go": "does not build on darwin/arm64, windows/amd64",
	}
	committed["changed_test.go"] = "does not build on windows/amd64"

	byFile := map[string]constraintFinding{}
	for _, f := range constraintCensusFindings(actual, committed) {
		byFile[f.file] = f
	}
	if len(byFile) != 3 {
		t.Fatalf("the census rule reported %d findings over one agreeing file, one unrecorded, one "+
			"widened and one vanished, want 3: %+v", len(byFile), byFile)
	}
	for file, want := range map[string]string{
		"unrecorded_test.go": "unrecorded",
		"changed_test.go":    "changed",
		"vanished_test.go":   "stale",
	} {
		if got := byFile[file].kind; got != want {
			t.Fatalf("%s read as %q, want %q", file, got, want)
		}
	}
	if _, reported := byFile["known_test.go"]; reported {
		t.Fatal("the census rule reported a file whose constraint matches its committed value. A " +
			"rule that reports everything is the same as a rule that reports nothing")
	}
}

// assertManifestCurationDetectionWorks is the control for the curation rule.
func assertManifestCurationDetectionWorks(t *testing.T) {
	t.Helper()

	planted := []loadBearingGuard{
		{"TestHealthyRow", "a_test.go", "a reason"},
		{"TestDuplicatedRow", "b_test.go", "a reason"},
		{"TestDuplicatedRow", "b_test.go", "a reason"},
		{"TestReasonlessRow", "c_test.go", "   "},
		{"TestFilelessRow", "", "a reason"},
		{"notATestName", "d_test.go", "a reason"},
	}

	kinds := map[string][]string{}
	for _, f := range manifestCurationFindings(planted) {
		kinds[f.name] = append(kinds[f.name], f.kind)
	}
	for name, want := range map[string]string{
		"TestDuplicatedRow": "duplicate",
		"TestReasonlessRow": "no-reason",
		"TestFilelessRow":   "no-file",
		"notATestName":      "not-a-test-name",
	} {
		var seen bool
		for _, k := range kinds[name] {
			if k == want {
				seen = true
			}
		}
		if !seen {
			t.Fatalf("a planted %s row was not reported as %q; the rule reported %v for it.\nA "+
				"duplicate row in particular is the specific hole this guard describes: remove one "+
				"copy and the manifest still claims the name", want, want, kinds[name])
		}
	}
	if len(kinds["TestHealthyRow"]) != 0 {
		t.Fatalf("a healthy manifest row was reported as %v", kinds["TestHealthyRow"])
	}
}

// ── the guards ──────────────────────────────────────────────────────────────

// TestPackageTestInventoryHasNotShrunk is nl6#577's first half: the floor.
func TestPackageTestInventoryHasNotShrunk(t *testing.T) {
	t.Run("parse and floor control", func(t *testing.T) { assertParseAndFloorDetectionWork(t) })
	t.Run("real wiring control", func(t *testing.T) { assertRealGuardWiringDetectsADeletion(t) })

	report, err := packageGuardReport(".")
	if err != nil {
		t.Fatalf("parse this package's test sources: %v", err)
	}

	for _, s := range report.inventory {
		switch s.kind {
		case "below-floor":
			t.Errorf("this package declares %d %s and the committed floor is %d, so AT LEAST %d "+
				"went missing (at least, because the floor may have been standing below the real "+
				"count already).\nCheck, in this order:\n"+
				"  DELETED.   A test function was removed, most likely as collateral in a larger "+
				"edit to a test file. That is exactly how TestEveryDeletedDeadRowIsAnsweredByTheCycler "+
				"and TestPaloAltoPANSubtreeMatchesTheMIB were lost, with the whole suite green. "+
				"`git diff --stat` on the test files, then "+
				"`git show HEAD -- <file> | grep '^-func Test'`.\n"+
				"  RENAMED.   Renamed out of the Test prefix, given a lower-case rune after it, or "+
				"given a signature that is no longer exactly one *testing.T. Each of those makes it "+
				"stop being a test to the toolchain as well as to this count.\n"+
				"  MOVED.     Moved to another package, to a file whose name does not end in "+
				"_test.go, or to one beginning with _ or . which go/build ignores. It still "+
				"compiles and it no longer runs.\n"+
				"A build-constraint change is NOT a cause of this failure: the parse reads "+
				"constrained files, so the count does not move. That failure mode is covered by "+
				"TestBuildConstrainedTestFilesAreTheCommittedSet instead.\n"+
				"LOWERING the floor is correct ONLY when tests were removed on purpose. Doing it to "+
				"make a red build green restores the exact blindness this guard exists to remove, "+
				"and the number is in the diff for a reviewer to ask about.",
				s.got, s.population, s.floor, s.floor-s.got)
		case "stale-floor":
			t.Errorf("this package declares %d %s against a floor of %d, which is %d of headroom "+
				"and the band is %d.\nHeadroom is how many tests can be deleted before the floor "+
				"notices, so a floor left far below the real count stops detecting anything. Raise "+
				"it to %d.\nThis is a bookkeeping failure, not a defect: the repair is one "+
				"constant, and it exists because the previous reminder was a t.Logf on a PASSING "+
				"test, which `go test ./...` without -v never prints.",
				s.got, s.population, s.floor, s.got-s.floor, maximumHeadroom, s.got)
		}
	}

	t.Logf("%d test functions (floor %d), %d fuzz targets (floor %d) and %d benchmarks across %d "+
		"test files", len(report.inv.Tests), minimumTestFunctions, len(report.inv.Fuzz),
		minimumFuzzTargets, len(report.inv.Benchmarks), report.inv.Files)
}

// TestLoadBearingGuardsArePresent is nl6#577's second half: the manifest.
func TestLoadBearingGuardsArePresent(t *testing.T) {
	t.Run("manifest control", func(t *testing.T) { assertGuardManifestDetectionWorks(t) })
	t.Run("real wiring control", func(t *testing.T) { assertRealGuardWiringDetectsADeletion(t) })

	report, err := packageGuardReport(".")
	if err != nil {
		t.Fatalf("parse this package's test sources: %v", err)
	}

	for _, f := range report.guards {
		switch f.kind {
		case "renamed":
			t.Errorf("the manifest names %s, recorded in %s, which this package does not declare, "+
				"but it DOES declare %s.\nThat reads as a RENAME, not a deletion. Update the row in "+
				"loadBearingGuards to the new name and file. Leaving it is worse than having no "+
				"row: the entry keeps its reason text and looks like coverage while guarding "+
				"nothing, which is how auditedArcPENs would have drifted without "+
				"TestUnauditedArcRegistriesAreCurated.",
				f.name, f.file, strings.Join(f.candidates, " or "))
		case "moved":
			t.Errorf("the manifest names %s in %s and this package declares it %s.\nUpdate the row "+
				"rather than dropping the file field: without it the row is satisfied by any test "+
				"of that name anywhere, so moving a guard's name onto an unrelated function keeps "+
				"the row green.", f.name, f.file, f.detail)
		case "ambiguous":
			t.Errorf("the manifest names %s and this package declares it more than once (%s).\nThe "+
				"row cannot say which one it means, and deleting either leaves the other satisfying "+
				"it. Rename one.", f.name, f.detail)
		case "skipped":
			t.Errorf("%s in %s exists and its FIRST action is to skip.\nThat is a deleted guard "+
				"that kept its name: the count does not move, the manifest row still matches, and "+
				"the assertions do not run. If the skip is a genuine environment gate, put it "+
				"behind the condition rather than at the top of the body. This is a load-bearing "+
				"guard: %s", f.name, f.file, manifestReasonFor(f.name))
		case "gutted":
			t.Errorf("%s in %s exists and reaches no t.Error or t.Fatal within %d levels of helper "+
				"calls.\nA guard whose body was emptied is invisible to every count, which is the "+
				"same silent-loss class as a deletion. If it really does assert through a deeper "+
				"chain, that is a limit of this check and the chain is worth shortening. This is a "+
				"load-bearing guard: %s",
				f.name, f.file, guardAssertionDepth, manifestReasonFor(f.name))
		default:
			t.Errorf("the manifest names %s in %s and this package declares no test by that name, "+
				"and nothing that looks like it renamed.\nThat reads as a DELETION. This is a "+
				"load-bearing guard: %s\nRestore it from the parent revision "+
				"(`git show HEAD~1 -- go/nl6/`). Before you do, check by hand that it was not "+
				"renamed beyond this rule's similarity threshold: restoring a test that still "+
				"exists under another name leaves the package with two copies of it. If it was "+
				"removed on purpose, delete the row here and say in the commit what covers the "+
				"defect now.",
				f.name, f.file, manifestReasonFor(f.name))
		}
	}

	t.Logf("%d load-bearing guards, all present and asserting among %d test functions",
		len(loadBearingGuards), len(report.inv.Tests))
}

// TestBuildConstrainedTestFilesAreTheCommittedSet is nl6#577's third half: the
// failure mode neither count can see.
//
// A file that gains a constraint still declares every test it did before, so
// minimumTestFunctions does not move, and the tests simply stop running wherever
// the constraint excludes them. Three files in this package are Linux-only for
// good reasons and that is a decision. A fourth appearing has to be one too.
func TestBuildConstrainedTestFilesAreTheCommittedSet(t *testing.T) {
	t.Run("census control", func(t *testing.T) { assertConstraintCensusDetectionWorks(t) })

	report, err := packageGuardReport(".")
	if err != nil {
		t.Fatalf("parse this package's test sources: %v", err)
	}

	for _, f := range report.constraints {
		switch f.kind {
		case "unrecorded":
			t.Errorf("%s %s and is not in buildConstrainedTestFiles.\nEvery test it declares still "+
				"counts toward minimumTestFunctions, so the floor cannot see this: the tests exist "+
				"and stop running. A file is constrained by its NAME as well as by a directive, so "+
				"a rename to a GOOS or GOARCH suffix does this with no comment anywhere in the "+
				"file. If the constraint is intended, add the file here with the value above",
				f.file, f.got)
		case "changed":
			t.Errorf("%s %s, recorded as %q. A widened or narrowed constraint changes where these "+
				"tests run", f.file, f.got, f.want)
		case "stale":
			t.Errorf("buildConstrainedTestFiles records that %s %q and it now builds everywhere "+
				"probed. Either the file was renamed or deleted, or the constraint was dropped on "+
				"purpose and this row is stale", f.file, f.want)
		}
	}

	files := sortedKeys(report.inv.Constrained)
	t.Logf("%d build-constrained test files across %d probes: %s",
		len(files), len(constraintProbes), strings.Join(files, ", "))
}

// TestGuardManifestIsCurated pins the manifest itself, in the shape
// TestUnauditedArcRegistriesAreCurated established.
//
// A duplicate row hides a deletion, since removing one copy leaves the guard
// still claiming the name, and a row with no reason is a name nobody can decide
// about later.
func TestGuardManifestIsCurated(t *testing.T) {
	t.Run("curation control", func(t *testing.T) { assertManifestCurationDetectionWorks(t) })

	for _, f := range manifestCurationFindings(loadBearingGuards) {
		switch f.kind {
		case "duplicate":
			t.Errorf("%s %s in the manifest. A duplicate row hides a deletion: remove one copy and "+
				"the guard still claims the name", f.name, f.detail)
		case "no-reason":
			t.Errorf("the manifest row for %s carries no reason. Every row needs one: this list is "+
				"the argument that a test is load-bearing, and without it the next reader cannot "+
				"tell a guard from an ordinary unit test and will not know whether removing it is "+
				"safe", f.name)
		case "no-file":
			t.Errorf("the manifest row for %s names no test file %s. Without it the row is "+
				"satisfied by any test of that name anywhere in the package", f.name, f.detail)
		case "not-a-test-name":
			t.Errorf("the manifest names %q, which `go test` would not run as a test", f.name)
		}
	}

	if len(loadBearingGuards) == 0 {
		t.Fatal("the manifest is empty, so TestLoadBearingGuardsArePresent asserts nothing")
	}
	t.Logf("%d curated manifest rows", len(loadBearingGuards))
}

// manifestReasonFor looks a name's reason back up for the failure message. The
// reason is the most useful thing to print at the moment a guard is found
// missing, since it is the argument for restoring it.
func manifestReasonFor(name string) string {
	for _, g := range loadBearingGuards {
		if g.name == name {
			return g.why
		}
	}
	return "(no reason recorded)"
}

// sortedKeys and sortedNames are small ordering helpers for the log lines and
// failure messages, so their output is stable across runs.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedNames(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
