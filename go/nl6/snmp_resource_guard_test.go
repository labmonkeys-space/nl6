/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
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
	entries, err := os.ReadDir("resources")
	if err != nil {
		t.Fatalf("read resources dir: %v", err)
	}
	dirs, inspected := 0, 0
	for _, e := range entries {
		// _-prefixed directories are not device types: _common holds the
		// shared trap/syslog catalogs and has no snmp part.
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		name := e.Name() + ".json"
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
		t.Fatal("no resource directories loaded. Is the test running from go/nl6?")
	}
	if inspected == 0 {
		t.Fatalf("loaded %d directories but zero SNMP entries, so the assertion would be vacuous", dirs)
	}
	t.Logf("loaded %d resource directories, %d SNMP entries inspected", dirs, inspected)
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
// is ordinary data on an ordinary leaf and must load.
func TestValidateSNMPResourceValues_OIDRuleIsTypeDirected(t *testing.T) {
	for _, oid := range []string{
		"1.3.6.1.2.1.1.1.0",      // sysDescr, OCTET STRING
		"1.3.6.1.2.1.4.20.1.1.1", // ipAdEntAddr, IpAddress
		"1.3.6.1.2.1.2.2.1.10.1", // ifInOctets, Counter32
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
