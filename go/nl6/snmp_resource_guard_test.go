/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
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
