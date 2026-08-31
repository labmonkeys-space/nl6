/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// guardResources builds a DeviceResources carrying exactly the supplied
// OID→value pairs, in the given order, so a validator error can be asserted
// against a known entry.
func guardResources(pairs ...[2]string) *DeviceResources {
	res := &DeviceResources{SNMP: make([]SNMPResource, 0, len(pairs))}
	for _, p := range pairs {
		res.SNMP = append(res.SNMP, SNMPResource{OID: p[0], Response: p[1]})
	}
	return res
}

// ── validateSNMPResourceValues ─────────────────────────────────────────────

func TestValidateSNMPResourceValues_SentinelRejected(t *testing.T) {
	for _, sentinel := range []string{valueNoSuchObject, valueEndOfMibView} {
		res := guardResources(
			[2]string{".1.3.6.1.2.1.1.5.0", "router-1"},
			[2]string{".1.3.6.1.2.1.1.1.0", sentinel},
		)
		err := validateSNMPResourceValues("cisco_ios_snmp_system.json", res)
		if err == nil {
			t.Fatalf("value %q: want rejection, got nil", sentinel)
		}
		// The message must name the file, the OID and the value: fixing this
		// means editing one line of one file.
		for _, want := range []string{"cisco_ios_snmp_system.json", ".1.3.6.1.2.1.1.1.0", sentinel, "sentinel"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("value %q: error %q does not mention %q", sentinel, err, want)
			}
		}
	}
}

// TestValidateSNMPResourceValues_MatchIsExact covers the three "is data" rows
// of the matrix. isSNMPExceptionValue is an exact string test, and this pins
// that the guard did not widen it into a substring or case-folding match.
func TestValidateSNMPResourceValues_MatchIsExact(t *testing.T) {
	for _, val := range []string{
		"noSuchObject seen",
		"endOfMibView reached",
		"NoSuchObject",
		"NOSUCHOBJECT",
		"EndOfMibView",
		" noSuchObject",
		"noSuchObject ",
		"noSuchInstance",
	} {
		res := guardResources([2]string{".1.3.6.1.2.1.1.1.0", val})
		if err := validateSNMPResourceValues("f.json", res); err != nil {
			t.Errorf("value %q must load (exact match only), got: %v", val, err)
		}
	}
}

// TestValidateSNMPResourceValues_SentinelOnAnyOID pins that the rule is on the
// VALUE and not on a particular leaf: the sentinels are position-independent.
func TestValidateSNMPResourceValues_SentinelOnAnyOID(t *testing.T) {
	for _, oid := range []string{
		".1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.1.2.0",
		".1.3.6.1.2.1.2.2.1.2.7",
		".1.3.6.1.4.1.9.9.999.1",
	} {
		res := guardResources([2]string{oid, valueEndOfMibView})
		if err := validateSNMPResourceValues("f.json", res); err == nil {
			t.Errorf("OID %s carrying a sentinel value was accepted, want rejection", oid)
		}
	}
}

func TestValidateSNMPResourceValues_CleanInputAccepted(t *testing.T) {
	res := guardResources(
		[2]string{".1.3.6.1.2.1.1.1.0", "Cisco IOS Software"},
		[2]string{".1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.9.1.1"},
		[2]string{".1.3.6.1.2.1.1.5.0", "router-1"},
	)
	if err := validateSNMPResourceValues("f.json", res); err != nil {
		t.Errorf("clean resources must load, got: %v", err)
	}
	if err := validateSNMPResourceValues("f.json", nil); err != nil {
		t.Errorf("nil resources must be a no-op, got: %v", err)
	}
	if err := validateSNMPResourceValues("f.json", &DeviceResources{}); err != nil {
		t.Errorf("empty resources must be a no-op, got: %v", err)
	}
}

// ── wiring: the loaders must actually call the guard ───────────────────────

// TestSentinelValueWouldReachTheWireAsAnException is why the predicate must be
// EXACT rather than trimmed or case-folded: it pins the harm the load guard
// prevents. A value equal to a sentinel encodes to the RFC 3416 exception tag,
// so it is not merely mistyped, it changes the meaning of the answer. A value
// that merely contains or case-varies a sentinel encodes as the string it is,
// which is why those forms must keep loading.
func TestSentinelValueWouldReachTheWireAsAnException(t *testing.T) {
	const anyOID = ".1.3.6.1.2.1.1.1.0"

	// The strings and tags are LITERALS, not the predicate's constants, so this
	// is the encoder's view of the sentinel set. If encodeTypedValue learns a
	// third exception (noSuchInstance, 0x81, is the obvious candidate) without
	// isSNMPExceptionValue learning it too, the second loop below fails: the
	// encoder-only sentinel encodes as an exception but loads as data, which is
	// exactly the hazard the guard exists to close.
	encoderSentinels := map[string]byte{
		"noSuchObject": 0x80, // [0] IMPLICIT NULL
		"endOfMibView": 0x82, // [2] IMPLICIT NULL
	}
	for v, tag := range encoderSentinels {
		got := encodeTypedValue(anyOID, v)
		if len(got) != 2 || got[0] != tag || got[1] != 0x00 {
			t.Errorf("encodeTypedValue(%q) = % x, want %02x 00; "+
				"if this fails the guard is rejecting values that are no longer hazardous", v, got, tag)
		}
		if !isSNMPExceptionValue(v) {
			t.Errorf("isSNMPExceptionValue(%q) = false, but the encoder treats it as an exception; "+
				"the load guard is blind to any sentinel the encoder knows and this predicate does not", v)
		}
	}

	// Near-miss forms, plus the exception the encoder does NOT emit. Any string
	// that encodes as data must load as data, and any string that encodes as a
	// 2-byte exception tag must appear in encoderSentinels above.
	for _, v := range []string{"noSuchObject seen", "NoSuchObject", " noSuchObject", "endOfMibView reached", "noSuchInstance"} {
		got := encodeTypedValue(anyOID, v)
		if len(got) == 0 || got[0] != ASN1_OCTET_STRING {
			t.Errorf("encodeTypedValue(%q) = % x, want OCTET STRING; a near-miss form is data, "+
				"which is what makes the exact predicate correct", v, got)
		}
		if isSNMPExceptionValue(v) {
			t.Errorf("isSNMPExceptionValue(%q) = true, but the encoder emits it as data", v)
		}
	}
}

// TestGuardIsWiredIntoLoaders is the test that fails if a
// validateSNMPResourceValues call is deleted from a loader. Calling the
// validator directly cannot detect that, which is the gap this closes.
//
// It covers all four loaders that can read an operator-supplied file: the two
// directory loaders and the two legacy single-file loaders, reached by writing
// the fixture as a directory or as a bare <slug>.json respectively.
// createDefaultResources writes compiled-in constants that no fixture can
// invalidate, so it is not guarded and not covered here.
//
// Every case carries a POSITIVE CONTROL: the same fixture with a clean value
// must load and yield exactly the fixture's entry count. Without it a loader
// that errored unconditionally, or one broken so that nothing decodes or that
// dropped a part on merge, would pass.
//
// Fixtures live in a temp directory, never in the tracked resources/ tree. The
// loaders resolve "resources/<slug>" relative to the working directory, so the
// test chdirs. t.Chdir restores it on cleanup and refuses to run if THIS test
// (or an ancestor) is parallel. It does not exclude unrelated parallel tests,
// and other tests in this package resolve resources/ relative to cwd, so do
// not add t.Parallel() here.
func TestGuardIsWiredIntoLoaders(t *testing.T) {
	const (
		badEntry   = `{"oid":"1.3.6.1.2.1.1.1.0","response":"noSuchObject"}`
		cleanEntry = `{"oid":"1.3.6.1.2.1.1.1.0","response":"noSuchObject seen"}`
		// A non-OID value on the OID-typed sysObjectID leaf: the nl6#529 rule.
		// Wiring is per RULE, not per guard: a rule added to
		// validateSNMPResourceValues but reached by only some loaders would
		// pass a sentinel-only wiring test.
		badOIDEntry = `{"oid":"1.3.6.1.2.1.1.2.0","response":"3.40.1"}`
		// A non-numeric value on the Counter32-typed ifInOctets.1: the
		// nl6#541 rule, and the class that shipped nl6#515. Wiring is per
		// RULE, so this needs its own case at every loader.
		badTypedEntry = `{"oid":"1.3.6.1.2.1.2.2.1.10.1","response":"n/a"}`
	)

	for _, layout := range []string{"directory", "single-file"} {
		for _, loader := range []string{"LoadResources", "LoadSpecificResources"} {
			t.Run(layout+"/"+loader, func(t *testing.T) {
				t.Run("rejects-sentinel", func(t *testing.T) {
					wantNamed, load := guardFixture(t, layout, loader, badEntry)
					res, err := load()
					if err == nil {
						t.Fatalf("%s (%s layout) loaded a sentinel value (%d entries). "+
							"is the guard still wired in?", loader, layout, snmpCount(res))
					}
					if !strings.Contains(err.Error(), wantNamed) {
						t.Errorf("error %q does not name the offending file %q", err, wantNamed)
					}
					for _, want := range []string{"1.3.6.1.2.1.1.1.0", "noSuchObject", "sentinel"} {
						if !strings.Contains(err.Error(), want) {
							t.Errorf("error %q does not mention %q", err, want)
						}
					}
				})

				t.Run("rejects-non-oid-on-oid-typed-leaf", func(t *testing.T) {
					wantNamed, load := guardFixture(t, layout, loader, badOIDEntry)
					res, err := load()
					if err == nil {
						t.Fatalf("%s (%s layout) loaded %q on sysObjectID (%d entries); "+
							"encodeOID cannot represent it, so it would go out as 06 00",
							loader, layout, "3.40.1", snmpCount(res))
					}
					if !strings.Contains(err.Error(), wantNamed) {
						t.Errorf("error %q does not name the offending file %q", err, wantNamed)
					}
					for _, want := range []string{"1.3.6.1.2.1.1.2.0", "3.40.1", "OID-typed"} {
						if !strings.Contains(err.Error(), want) {
							t.Errorf("error %q does not mention %q", err, want)
						}
					}
				})

				t.Run("rejects-degraded-typed-value", func(t *testing.T) {
					wantNamed, load := guardFixture(t, layout, loader, badTypedEntry)
					res, err := load()
					if err == nil {
						t.Fatalf("%s (%s layout) loaded %q on the Counter32-typed ifInOctets.1 (%d entries); "+
							"the encoder degrades it to an OCTET STRING and a collector typing the OID "+
							"per its MIB drops the metric", loader, layout, "n/a", snmpCount(res))
					}
					if !strings.Contains(err.Error(), wantNamed) {
						t.Errorf("error %q does not name the offending file %q", err, wantNamed)
					}
					for _, want := range []string{"1.3.6.1.2.1.2.2.1.10.1", "n/a", "Counter32"} {
						if !strings.Contains(err.Error(), want) {
							t.Errorf("error %q does not mention %q", err, want)
						}
					}
				})

				// Positive control: same shape, value one character different.
				// The directory fixture carries a clean sibling part, so the
				// exact count also proves both parts were merged.
				t.Run("accepts-clean", func(t *testing.T) {
					_, load := guardFixture(t, layout, loader, cleanEntry)
					res, err := load()
					if err != nil {
						t.Fatalf("%s (%s layout) rejected a clean fixture: %v", loader, layout, err)
					}
					want := 1
					if layout == "directory" {
						want = 2
					}
					if n := snmpCount(res); n != want {
						t.Fatalf("%s (%s layout) loaded %d SNMP entries, want %d. The negative case "+
							"above would pass even on a loader that decodes nothing", loader, layout, n, want)
					}
				})
			})
		}
	}
}

// guardFixture writes a resource fixture into a temp directory, chdirs there,
// and returns the file name the loader's error must name plus a closure that
// runs the requested loader over it.
func guardFixture(t *testing.T, layout, loader, entry string) (wantNamed string, load func() (*DeviceResources, error)) {
	t.Helper()
	t.Chdir(t.TempDir())

	const slug = "zzguardfixture"
	if err := os.MkdirAll("resources", 0o755); err != nil {
		t.Fatalf("mkdir resources: %v", err)
	}
	file := filepath.Join("resources", slug+".json")

	switch layout {
	case "directory":
		dir := filepath.Join("resources", slug)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		// A clean part alongside the interesting one, so the per-part label is
		// what makes the error name the right file.
		writeGuardPart(t, filepath.Join(dir, slug+"_snmp_other.json"),
			`{"oid":"1.3.6.1.2.1.1.5.0","response":"router-1"}`)
		wantNamed = slug + "_snmp_main.json"
		writeGuardPart(t, filepath.Join(dir, wantNamed), entry)
	case "single-file":
		wantNamed = slug + ".json"
		writeGuardPart(t, file, entry)
	default:
		t.Fatalf("unknown layout %q", layout)
	}

	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	switch loader {
	case "LoadResources":
		return wantNamed, func() (*DeviceResources, error) {
			err := sm.LoadResources(file)
			return sm.deviceResources, err
		}
	case "LoadSpecificResources":
		return wantNamed, func() (*DeviceResources, error) {
			return sm.LoadSpecificResources(slug + ".json")
		}
	default:
		t.Fatalf("unknown loader %q", loader)
		return "", nil
	}
}

func writeGuardPart(t *testing.T, path, entry string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"snmp":[`+entry+`]}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func snmpCount(res *DeviceResources) int {
	if res == nil {
		return 0
	}
	return len(res.SNMP)
}

// ── the shipped set must load clean ────────────────────────────────────────

// TestShippedResourcesLoadClean walks every device-type directory under
// resources/ through the real loader. "Reject" is only a safe policy while the
// shipped set passes; without this, a later resource edit becomes a load-time
// landmine instead of a failing build.
//
// The entry count is asserted non-zero so a decode regression that silently
// produced empty resources could not make this pass vacuously.
func TestShippedResourcesLoadClean(t *testing.T) {
	// shippedProfileNames covers BOTH layouts (a directory of parts, and a bare
	// resources/<slug>.json). The old os.ReadDir loop skipped every
	// non-directory, so a single-file profile was never load-tested at all.
	dirs, inspected := 0, 0
	for _, name := range shippedProfileNames(t) {
		sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
		res, err := sm.LoadSpecificResources(name)
		if err != nil {
			t.Errorf("LoadSpecificResources(%s): %v", name, err)
			continue
		}
		dirs++
		inspected += len(res.SNMP)
	}
	if dirs == 0 {
		t.Fatal("no resource profiles loaded. Is the test running from go/nl6?")
	}
	if inspected == 0 {
		t.Fatalf("loaded %d profiles but zero SNMP entries, so the assertion would be vacuous", dirs)
	}
	t.Logf("loaded %d resource profiles, %d SNMP entries inspected", dirs, inspected)
}

// ── nl6#529: OID-typed values ───────────────────────────────────────────────

// TestValidateSNMPResourceValues_NonOIDOnOIDLeafRejected closes the second half
// of nl6#529. The encoder half (PR #532) stopped encodeOID fabricating an OID
// for input it cannot represent; this stops a resource file supplying such a
// value in the first place, on a leaf whose declared type is OBJECT IDENTIFIER.
//
// The cases below are exactly the ones the varint change made refusable:
// non-numeric components, a first arc above 2, and a second arc above 39 when
// the first is 0 or 1 (which would ALIAS a higher first arc, since 1.40 and 2.0
// both encode to 80).
func TestValidateSNMPResourceValues_NonOIDOnOIDLeafRejected(t *testing.T) {
	const sysObjectID = "1.3.6.1.2.1.1.2.0"

	overLongOID := "1.3" + strings.Repeat(".4294967295", maxOIDBodyBytes/5)
	if encodableAsOID(overLongOID) {
		t.Fatalf("fixture is not over maxOIDBodyBytes (%d); a changed constant would make "+
			"this case test an accepted value", maxOIDBodyBytes)
	}

	for _, bad := range []string{
		"unknown", "1.3.x.7", "", "1", "1.3..7", "1.3.-1",
		"3.40.1",         // first arc 3
		"1.40.1",         // second arc 40 with first arc 1: would alias 2.0.1
		"2.0.4294967296", // arc past the SMI maximum
		// Legal arcs, but the encoded body EXCEEDS maxOIDBodyBytes: the
		// encoder's third refusal route, and the guard must follow it too.
		// Each max arc is a 5-byte varint, so (maxOIDBodyBytes/5)*5 bytes plus
		// the 1-byte first sub-identifier is one over the bound.
		overLongOID,
	} {
		name := bad
		if len(name) > 32 {
			name = name[:32] + "..."
		}
		// Both key spellings: resource files may carry a leading dot, and the
		// rule is type-directed through snmpTypeTag, which expects one. The
		// undotted key exercises the prepend in normaliseResourceOID, the
		// dotted key its pass-through arm.
		for _, key := range []string{sysObjectID, "." + sysObjectID} {
			t.Run(key+"="+name, func(t *testing.T) {
				res := &DeviceResources{SNMP: []SNMPResource{{OID: key, Response: bad}}}
				err := validateSNMPResourceValues("probe.json", res)
				if err == nil {
					t.Fatalf("value %q accepted on OID-typed key %q; encodeOID cannot represent it, "+
						"so it would go out as a degenerate 06 00", name, key)
				}
				for _, want := range []string{"probe.json", key, fmt.Sprintf("%q", bad)} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error does not name %q: %v", want, err)
					}
				}
			})
		}
	}
}

// TestValidateSNMPResourceValues_SentinelWinsOnOIDLeaf pins rule order. A
// sentinel on sysObjectID trips BOTH rules; encodeTypedValue tests the
// sentinel first, so the diagnosis must match the wire and keep the
// "omit the entry" remediation that only the sentinel error carries.
func TestValidateSNMPResourceValues_SentinelWinsOnOIDLeaf(t *testing.T) {
	res := &DeviceResources{SNMP: []SNMPResource{{OID: "1.3.6.1.2.1.1.2.0", Response: valueNoSuchObject}}}
	err := validateSNMPResourceValues("probe.json", res)
	if err == nil {
		t.Fatal("sentinel on sysObjectID accepted")
	}
	if !strings.Contains(err.Error(), "sentinel") || strings.Contains(err.Error(), "OID-typed") {
		t.Errorf("sentinel on an OID-typed leaf must be reported as a sentinel collision, got: %v", err)
	}
}

func TestValidateSNMPResourceValues_ValidOIDAccepted(t *testing.T) {
	const sysObjectID = "1.3.6.1.2.1.1.2.0"

	for _, good := range []string{
		"1.3.6.1.4.1.9.1.1", ".1.3.6.1.4.1.9.1.1", // both spellings
		"2.999",       // the legal ITU test arc, expressible since PR #532
		"1.39", "2.0", // arc-range boundaries
		"1.2.4294967295", // the SMI maximum
	} {
		for _, key := range []string{sysObjectID, "." + sysObjectID} {
			res := &DeviceResources{SNMP: []SNMPResource{{OID: key, Response: good}}}
			if err := validateSNMPResourceValues("probe.json", res); err != nil {
				t.Errorf("valid OID %q on key %q rejected: %v", good, key, err)
			}
		}
	}
}

// TestValidateSNMPResourceValues_OIDRuleIsTypeDirected pins that the rule fires
// on the leaf's DECLARED type rather than on the value's shape. A non-OID value
// is ordinary data on a leaf that is not OID-typed and must load.
//
// The two typed leaves this test used to carry (ipAdEntAddr and ifInOctets)
// were moved out by nl6#541: they ARE claimed now, by the typed-class rule,
// which refuses a value that does not encode at the declared type. The
// untyped-leaf property they stood for lives in
// TestTypedClassRuleIsTypeDirected.
func TestValidateSNMPResourceValues_OIDRuleIsTypeDirected(t *testing.T) {
	for _, oid := range []string{
		"1.3.6.1.2.1.1.1.0",       // sysDescr, untyped here (OCTET STRING by MIB)
		"1.3.6.1.4.1.9.2.1.58.0",  // avgBusy5, untyped (INTEGER by MIB)
		"1.3.6.1.4.1.9.9.999.1.0", // a vendor leaf the table has never heard of
	} {
		res := &DeviceResources{SNMP: []SNMPResource{{OID: oid, Response: "not an oid at all"}}}
		if err := validateSNMPResourceValues("probe.json", res); err != nil {
			t.Errorf("leaf %s is not OID-typed, so %q is ordinary data, but it was rejected: %v",
				oid, "not an oid at all", err)
		}
	}
}

// TestGuardAgreesWithTheEncoder is the anti-drift assertion. The guard asks
// encodeOID rather than re-deriving the rules, precisely so a second predicate
// cannot disagree with the encoder the way trap_catalog.go's validateDottedOID
// does (nl6#539). This pins that property rather than trusting the comment.
func TestGuardAgreesWithTheEncoder(t *testing.T) {
	const sysObjectID = "1.3.6.1.2.1.1.2.0"

	for _, v := range []string{
		"1.3.6.1.4.1.9.1.1", "2.999", "3.40.1", "1.40.1", "unknown", "1.3.x.7",
		"", "1", "2.0", "1.39", "1.2.4294967295", "1.2.4294967296", "0.39", "0.40",
	} {
		res := &DeviceResources{SNMP: []SNMPResource{{OID: sysObjectID, Response: v}}}
		guardAccepts := validateSNMPResourceValues("probe.json", res) == nil
		encoderAccepts := encodableAsOID(v)

		if guardAccepts != encoderAccepts {
			t.Errorf("guard and encoder disagree about %q: guard accepts=%v, encoder accepts=%v. "+
				"They must not drift; that is why the guard asks the encoder", v, guardAccepts, encoderAccepts)
		}

		// The claim is about the WIRE, not only encodeOID: the value must take
		// the same path a GET would, through encodeTypedValue's type dispatch on
		// the same key spelling the loader normalises to.
		wire := encodeTypedValue("."+sysObjectID, v)
		wireAccepts := !bytes.Equal(wire, []byte{ASN1_OID, 0x00})
		if guardAccepts != wireAccepts {
			t.Errorf("guard and wire disagree about %q: guard accepts=%v, encodeTypedValue emits %x",
				v, guardAccepts, wire)
		}

		// And the trap encoder refuses the same set.
		trapAccepts := !bytes.Equal(appendOID(nil, v), []byte{ASN1_OID, 0x00})
		if guardAccepts != trapAccepts {
			t.Errorf("guard and appendOID disagree about %q: guard accepts=%v, appendOID accepts=%v",
				v, guardAccepts, trapAccepts)
		}
	}
}

// ── nl6#541: every typed class ──────────────────────────────────────────────

// typedClassCase is an (OID, value) pair on a leaf oidTypeTable types. The
// expectation is deliberately NOT written down as a want-bool: every case is
// checked against what encodeTypedValue actually emits, so a case cannot
// encode an author's belief about the encoder. `why` only documents the row.
type typedClassCase struct {
	oid   string
	value string
	why   string
}

// typedClassCases covers every class the table can declare, at the boundaries
// the encoder's branches actually turn on: parse success, parse failure,
// signedness, width and surrounding whitespace.
var typedClassCases = []typedClassCase{
	// Counter32 (ifInOctets.1)
	{".1.3.6.1.2.1.2.2.1.10.1", "0", "zero"},
	{".1.3.6.1.2.1.2.2.1.10.1", "4294967295", "the 32-bit maximum"},
	{".1.3.6.1.2.1.2.2.1.10.1", "4294967296", "one past the 32-bit maximum"},
	{".1.3.6.1.2.1.2.2.1.10.1", "-1", "negative on an unsigned 32-bit type: loads, warns"},
	{".1.3.6.1.2.1.2.2.1.10.1", "-2147483649", "one past the negative 32-bit bound"},
	{".1.3.6.1.2.1.2.2.1.10.1", " 42", "leading whitespace"},
	{".1.3.6.1.2.1.2.2.1.10.1", "42 ", "trailing whitespace"},
	{".1.3.6.1.2.1.2.2.1.10.1", "42 packets", "a value carrying units"},
	{".1.3.6.1.2.1.2.2.1.10.1", "n/a", "the nl6#515 shape"},
	{".1.3.6.1.2.1.2.2.1.10.1", "", "empty"},
	{".1.3.6.1.2.1.2.2.1.10.1", "0x2a", "hex"},
	{".1.3.6.1.2.1.2.2.1.10.1", "4.2", "a decimal fraction"},
	// Gauge32 (ifSpeed.1) and the OLD-CISCO-MEMORY-MIB freeMem of nl6#515
	{".1.3.6.1.2.1.2.2.1.5.1", "1000000000", "a plain gauge"},
	{".1.3.6.1.4.1.9.2.1.8.0", "1073741824", "freeMem, correct"},
	{".1.3.6.1.4.1.9.2.1.8.0", "CRS-X-001", "freeMem carrying the device name: nl6#515 itself"},
	// TimeTicks (sysUpTime.0)
	{".1.3.6.1.2.1.1.3.0", "123456789", "a plain uptime"},
	{".1.3.6.1.2.1.1.3.0", "4567890123", "past the TimeTicks wrap"},
	{".1.3.6.1.2.1.1.3.0", "up 5 days", "prose"},
	// Counter64 (ifHCInOctets.1)
	{".1.3.6.1.2.1.31.1.1.1.6.1", "9876543210", "a 64-bit counter"},
	{".1.3.6.1.2.1.31.1.1.1.6.1", "18446744073709551615", "the 64-bit maximum"},
	{".1.3.6.1.2.1.31.1.1.1.6.1", "18446744073709551616", "one past it"},
	{".1.3.6.1.2.1.31.1.1.1.6.1", "-1", "negative on a Counter64"},
	{".1.3.6.1.2.1.31.1.1.1.6.1", "n/a", "non-numeric"},
	// IpAddress (ipAdEntAddr, ipRouteDest)
	{".1.3.6.1.2.1.4.20.1.1.10.0.0.1", "10.0.0.1", "a dotted quad"},
	{".1.3.6.1.2.1.4.20.1.1.10.0.0.1", "host", "the matrix's unparseable ipAdEntAddr"},
	{".1.3.6.1.2.1.4.20.1.1.10.0.0.1", "1", "an integer where an address belongs"},
	{".1.3.6.1.2.1.4.20.1.1.10.0.0.1", "10.0.0.256", "an out-of-range octet"},
	{".1.3.6.1.2.1.4.20.1.1.10.0.0.1", "::1", "IPv6 in an IpAddress slot"},
	{".1.3.6.1.2.1.4.21.1.1", "0.0.0.0", "ipRouteDest, the default route"},
	// OCTET STRING-forced leaves: the rule must never fire here, whatever the
	// value looks like, because the encoder always emits the declared tag.
	{".1.3.6.1.2.1.31.1.1.1.18.1", "42", "a numeric ifAlias stays a string"},
	{".1.0.8802.1.1.2.1.3.3", "switch-1", "lldpLocSysName"},
}

// TestTypedClassRuleAgreesWithTheEncoder is the anti-drift assertion for the
// nl6#541 rule, the shape nl6#544 established and nl6#539 is the warning
// about: the guard must refuse exactly what encodeTypedValue degrades, and it
// must decide that by asking the encoder rather than by a parallel predicate.
//
// The oracle here is the WIRE: the first byte encodeTypedValue emits, compared
// with the tag snmpTypeTag declares. No row states an expected verdict, so this
// test cannot drift from the encoder even if a row's comment is wrong.
func TestTypedClassRuleAgreesWithTheEncoder(t *testing.T) {
	for _, tc := range typedClassCases {
		t.Run(tc.oid+"="+tc.value, func(t *testing.T) {
			declared := snmpTypeTag(tc.oid)
			if declared == 0 {
				t.Fatalf("fixture error: %s is not typed by oidTypeTable, so the rule cannot apply", tc.oid)
			}
			emitted := encodeTypedValue(tc.oid, tc.value)
			if len(emitted) == 0 {
				t.Fatalf("encodeTypedValue(%s, %q) returned nothing", tc.oid, tc.value)
			}
			wireDegraded := emitted[0] != declared

			res := &DeviceResources{SNMP: []SNMPResource{{OID: tc.oid, Response: tc.value}}}
			err := validateSNMPResourceValues("probe.json", res)

			if wireDegraded && err == nil {
				t.Fatalf("%s (%s): the encoder emits tag 0x%02X where the MIB declares 0x%02X (%s), "+
					"but the guard accepted the value — the degradation the guard exists to catch",
					tc.value, tc.why, emitted[0], declared, snmpTypeName(declared))
			}
			if !wireDegraded && err != nil {
				t.Fatalf("%s (%s): the encoder emits the declared tag 0x%02X, but the guard rejected it: %v",
					tc.value, tc.why, declared, err)
			}
			if err != nil {
				// The rejection must be actionable: file, OID, declared type, value.
				for _, want := range []string{"probe.json", tc.oid, snmpTypeName(declared), fmt.Sprintf("%q", tc.value)} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("rejection does not name %q: %v", want, err)
					}
				}
			}
		})
	}
}

// TestTypedClassRuleDecidedCases records the matrix rows the spec asked to be
// decided explicitly rather than left to a reader. Each expectation here is
// INHERITED from the encoder (asserted alongside), so the row states what nl6
// promises AND why.
func TestTypedClassRuleDecidedCases(t *testing.T) {
	cases := []struct {
		name       string
		oid, value string
		wantReject bool
	}{
		// Decided: a negative on Counter32/Gauge32/TimeTicks LOADS. The
		// encoder parses it at 32-bit width and wrap-casts, so -1 goes out as
		// 0xFFFFFFFF at the declared tag — mistyped data, but not the
		// OCTET-STRING degradation this rule is about. No shipped profile does
		// this (TestNegativesOnUnsignedLeavesAreAbsent), so the reason to allow
		// it is only that the encoder encodes it; it draws a warning.
		{"negative on Counter32 is clamped by the encoder, so it loads", ".1.3.6.1.2.1.2.2.1.10.1", "-1", false},
		// Decided: the same value on a Counter64 is REFUSED, because
		// encodeTypedValue has no signed fallback on that branch and degrades
		// to OCTET STRING. The asymmetry is the encoder's, and asking the
		// encoder is what makes the guard inherit it instead of guessing.
		{"negative on Counter64 degrades, so it is refused", ".1.3.6.1.2.1.31.1.1.1.6.1", "-1", true},
		// Decided: whitespace is REFUSED. strconv does not trim, so " 42"
		// degrades on the wire; the guard must follow the encoder, not tidy up.
		{"leading whitespace is refused", ".1.3.6.1.2.1.2.2.1.10.1", " 42", true},
		{"trailing whitespace is refused", ".1.3.6.1.2.1.2.2.1.10.1", "42 ", true},
		// Decided: an unparseable IpAddress is REFUSED.
		{"unparseable ipAdEntAddr is refused", ".1.3.6.1.2.1.4.20.1.1.10.0.0.1", "host", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &DeviceResources{SNMP: []SNMPResource{{OID: tc.oid, Response: tc.value}}}
			gotReject := validateSNMPResourceValues("probe.json", res) != nil
			if gotReject != tc.wantReject {
				t.Errorf("value %q on %s: rejected=%v, want %v", tc.value, tc.oid, gotReject, tc.wantReject)
			}
			// And the reason, from the encoder itself.
			emitted := encodeTypedValue(tc.oid, tc.value)
			degraded := emitted[0] != snmpTypeTag(tc.oid)
			if degraded != tc.wantReject {
				t.Errorf("value %q on %s: encoder degrades=%v but the case expects rejected=%v; "+
					"the guard's verdict is the encoder's, so one of the two is now wrong",
					tc.value, tc.oid, degraded, tc.wantReject)
			}
		})
	}
}

// TestTypedClassRuleIsTypeDirected pins that a leaf the table does not type is
// left alone. The default encoder branch emits INTEGER for a number and OCTET
// STRING for anything else, and both are legitimate for an untyped leaf, so
// there is nothing to compare against and nothing to refuse.
func TestTypedClassRuleIsTypeDirected(t *testing.T) {
	for _, oid := range []string{
		".1.3.6.1.2.1.1.1.0",       // sysDescr, OCTET STRING by MIB but untyped here
		".1.3.6.1.4.1.9.2.1.58.0",  // avgBusy5, INTEGER
		".1.3.6.1.4.1.9.9.999.1.0", // a vendor leaf the table has never heard of
	} {
		if snmpTypeTag(oid) != 0 && snmpTypeTag(oid) != ASN1_OCTET_STRING {
			t.Fatalf("fixture error: %s is typed 0x%02X, so it is not an untyped leaf", oid, snmpTypeTag(oid))
		}
		res := &DeviceResources{SNMP: []SNMPResource{{OID: oid, Response: "n/a"}}}
		if err := validateSNMPResourceValues("probe.json", res); err != nil {
			t.Errorf("untyped leaf %s must accept any value, got: %v", oid, err)
		}
	}
}

// TestTypedClassRuleOrderedAfterTheOthers pins rule order. A sentinel on a
// typed leaf trips both rule 1 and rule 3 (a sentinel encodes to an exception
// tag, which is not the declared one), and encodeTypedValue tests the sentinel
// FIRST, so the diagnosis must be the sentinel collision — that is the only
// message carrying the "omit the entry" remediation.
func TestTypedClassRuleOrderedAfterTheOthers(t *testing.T) {
	for _, oid := range []string{".1.3.6.1.2.1.2.2.1.10.1", ".1.3.6.1.2.1.31.1.1.1.6.1", ".1.3.6.1.2.1.1.3.0"} {
		res := &DeviceResources{SNMP: []SNMPResource{{OID: oid, Response: valueNoSuchObject}}}
		err := validateSNMPResourceValues("probe.json", res)
		if err == nil {
			t.Fatalf("sentinel on %s accepted", oid)
		}
		if !strings.Contains(err.Error(), "sentinel") {
			t.Errorf("sentinel on typed leaf %s must be reported as a sentinel collision, got: %v", oid, err)
		}
	}
}

// TestTypedClassRuleNeverFiresOnAnOIDTypedLeaf is why rule 2 still exists.
// encodeOID answers a value it cannot represent with the degenerate 06 00,
// whose TAG is the declared one, so the tag comparison of rule 3 is blind to
// it. Deleting rule 2 in favour of rule 3 would silently reopen nl6#529.
func TestTypedClassRuleNeverFiresOnAnOIDTypedLeaf(t *testing.T) {
	const sysObjectID = ".1.3.6.1.2.1.1.2.0"
	for _, bad := range []string{"unknown", "3.40.1", "1.3.x.7", ""} {
		emitted := encodeTypedValue(sysObjectID, bad)
		if len(emitted) == 0 || emitted[0] != ASN1_OBJECT_ID {
			t.Fatalf("premise changed: encodeTypedValue(%s, %q) = % x, no longer the declared tag; "+
				"rule 3 would now cover this and rule 2's justification needs revisiting", sysObjectID, bad, emitted)
		}
		err := validateSNMPResourceValues("probe.json", &DeviceResources{
			SNMP: []SNMPResource{{OID: sysObjectID, Response: bad}}})
		if err == nil {
			t.Fatalf("value %q on sysObjectID accepted", bad)
		}
		if !strings.Contains(err.Error(), "OID-typed") {
			t.Errorf("value %q must be diagnosed by the OID rule, got: %v", bad, err)
		}
	}
}

// TestTypedClassSkippedBranchesCannotDegrade pins the two declared types rule 3
// skips for cost. The skip is only safe while those branches always emit the
// declared tag, and "always" is a claim about the encoder, so it is asserted
// against the encoder rather than left in a comment.
//
// The OCTET STRING branch must never degrade, over adversarial values. The
// OBJECT IDENTIFIER branch must emit the declared tag EVEN for a value it
// cannot represent — that is why it needs a rule of its own (nl6#529), and if
// this ever stops being true, rule 3 covers it and rule 2 can be reconsidered.
func TestTypedClassSkippedBranchesCannotDegrade(t *testing.T) {
	adversarial := []string{
		"", " ", "42", "-1", "0x2a", "n/a", "noSuchObject seen",
		"1.3.6.1.4.1.9.1.1", "3.40.1", strings.Repeat("x", 4096), "\x00\x01",
	}

	stringLeaves := []string{".1.3.6.1.2.1.31.1.1.1.18.1", ".1.0.8802.1.1.2.1.3.3"}
	for _, oid := range stringLeaves {
		if snmpTypeTag(oid) != ASN1_OCTET_STRING {
			t.Fatalf("fixture error: %s is not OCTET STRING-typed", oid)
		}
		for _, v := range adversarial {
			got := encodeTypedValue(oid, v)
			if len(got) == 0 || got[0] != ASN1_OCTET_STRING {
				t.Errorf("encodeTypedValue(%s, %q) = % x: the OCTET STRING branch CAN degrade, so "+
					"rule 3 must stop skipping it", oid, v, got[:min(len(got), 8)])
			}
		}
	}

	const sysObjectID = ".1.3.6.1.2.1.1.2.0"
	for _, v := range adversarial {
		got := encodeTypedValue(sysObjectID, v)
		if len(got) == 0 || got[0] != ASN1_OBJECT_ID {
			t.Errorf("encodeTypedValue(%s, %q) = % x: the OID branch now emits a different tag, so "+
				"rule 3 would catch what rule 2 exists for", sysObjectID, v, got[:min(len(got), 8)])
		}
	}
}

// TestTypedClassRuleUsesTheSameEncoderAsTheWire pins the seam introduced for
// cost: the guard calls encodeTypedValueAtTag with a tag it already has, and
// that must be the same answer encodeTypedValue gives. A divergence here is the
// nl6#539 failure by another route — a second entry point rather than a second
// predicate.
func TestTypedClassRuleUsesTheSameEncoderAsTheWire(t *testing.T) {
	for _, tc := range typedClassCases {
		wire := encodeTypedValue(tc.oid, tc.value)
		seam := encodeTypedValueAtTag(tc.oid, tc.value, snmpTypeTag(tc.oid))
		if !bytes.Equal(wire, seam) {
			t.Errorf("%s = %q: encodeTypedValue gives % x, encodeTypedValueAtTag gives % x",
				tc.oid, tc.value, wire, seam)
		}
	}
	// And the sentinel, which is the one thing the seam does NOT handle: it sits
	// above the tag in encodeTypedValue, which is why rule 1 runs first.
	if got := encodeTypedValueAtTag(".1.3.6.1.2.1.1.1.0", valueNoSuchObject, 0); got[0] == 0x80 {
		t.Error("encodeTypedValueAtTag handles the sentinel; if it does, rule ordering in " +
			"validateSNMPResourceValues no longer matters and the comment there is wrong")
	}
}

// TestNegativesOnUnsignedLeavesAreAbsent pins the corpus fact that replaced a
// fabricated justification. The first cut of nl6#541 said in four places that
// "several resource files use -1 as a not-measured placeholder" on the unsigned
// 32-bit types. They do not: all 116 negative values in the shipped set are -1
// on ipRouteMetric1/2/3/5, which oidTypeTable does not type (RFC 1213 gives -1
// as "not used" there, so they are correct data on an INTEGER leaf).
//
// So the Counter32-loads / Counter64-refuses asymmetry has no shipped
// motivation. It is inherited from encodeTypedValue, and that is the honest
// reason — which this test keeps honest.
func TestNegativesOnUnsignedLeavesAreAbsent(t *testing.T) {
	negatives, onUnsigned, onUntyped := 0, 0, 0
	for _, e := range shippedSNMPEntries(t) {
		if !strings.HasPrefix(e.Value, "-") {
			continue
		}
		if _, err := strconv.ParseInt(e.Value, 10, 64); err != nil {
			continue
		}
		negatives++
		switch snmpTypeTag(e.OID) {
		case ASN1_COUNTER32, ASN1_GAUGE32, ASN1_TIMETICKS:
			onUnsigned++
			t.Errorf("%s: %s = %s sits on an unsigned 32-bit leaf. The encoder wrap-casts it, so "+
				"it is served as a plausible-looking large number rather than being refused. If "+
				"this is intentional, the docs' claim that no shipped profile does this must change",
				e.Part, e.OID, e.Value)
		case 0:
			onUntyped++
		}
	}
	if negatives == 0 {
		t.Fatal("no negative shipped value found, so this test asserted nothing")
	}
	t.Logf("%d negative shipped values: %d on unsigned 32-bit leaves, %d on untyped leaves",
		negatives, onUnsigned, onUntyped)
}

// TestNegativeOnUnsignedLeafLoadsWithAWarning pins the DECISION: a negative on
// an unsigned 32-bit leaf is not refused, because the encoder encodes it at the
// declared tag and the guard's verdict is the encoder's. What it gets instead is
// a log line, since a wrapped 4294967295 is invisible to a collector in a way a
// dropped metric is not.
func TestNegativeOnUnsignedLeafLoadsWithAWarning(t *testing.T) {
	var logged bytes.Buffer
	restore := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(restore) })

	res := guardResources([2]string{".1.3.6.1.2.1.2.2.1.10.1", "-1"})
	if err := validateSNMPResourceValues("neg.json", res); err != nil {
		t.Fatalf("a negative on a Counter32 must LOAD (the encoder wrap-casts it), got: %v", err)
	}
	out := logged.String()
	for _, want := range []string{"neg.json", "1.3.6.1.2.1.2.2.1.10.1", "Counter32", "-1", "4294967295"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning %q does not mention %q", out, want)
		}
	}

	// And it is the WIRE it describes.
	if got := encodeTypedValue(".1.3.6.1.2.1.2.2.1.10.1", "-1"); !bytes.Equal(got, []byte{ASN1_COUNTER32, 0x04, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Errorf("encodeTypedValue(ifInOctets.1, -1) = % x, so the warning's 4294967295 is wrong", got)
	}

	// A negative on a Counter64 is a different answer: refused, because that
	// branch degrades. No warning, because there is nothing to warn about.
	logged.Reset()
	res = guardResources([2]string{".1.3.6.1.2.1.31.1.1.1.6.1", "-1"})
	if err := validateSNMPResourceValues("neg.json", res); err == nil {
		t.Error("a negative on a Counter64 must be REFUSED: the encoder degrades it to an OCTET STRING")
	}
	if strings.Contains(logged.String(), "wrap-casts") {
		t.Error("a refused value must not also be warned about")
	}
}
