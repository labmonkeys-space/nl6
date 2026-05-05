/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEmbeddedCatalog_UniversalEntries(t *testing.T) {
	cat, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedCatalog: %v", err)
	}
	want := map[string]string{
		"linkDown":              "1.3.6.1.6.3.1.1.5.3",
		"linkUp":                "1.3.6.1.6.3.1.1.5.4",
		"authenticationFailure": "1.3.6.1.6.3.1.1.5.5",
		"coldStart":             "1.3.6.1.6.3.1.1.5.1",
		"warmStart":             "1.3.6.1.6.3.1.1.5.2",
	}
	if len(cat.Entries) != len(want) {
		t.Fatalf("want %d entries, got %d", len(want), len(cat.Entries))
	}
	for name, oid := range want {
		e, ok := cat.ByName[name]
		if !ok {
			t.Errorf("missing catalog entry %q", name)
			continue
		}
		if e.SnmpTrapOID != oid {
			t.Errorf("entry %q: OID = %q, want %q", name, e.SnmpTrapOID, oid)
		}
	}
}

func TestLoadCatalogFromFile_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{ not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalogFromFile(path); err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestLoadCatalogFromFile_ReservedOIDRejected(t *testing.T) {
	cases := []struct {
		name string
		oid  string
	}{
		{"sysUpTime with dot prefix", ".1.3.6.1.2.1.1.3.0"},
		{"sysUpTime no prefix", "1.3.6.1.2.1.1.3.0"},
		{"snmpTrapOID with dot prefix", ".1.3.6.1.6.3.1.1.4.1.0"},
		{"snmpTrapOID no prefix", "1.3.6.1.6.3.1.1.4.1.0"},
		{"snmpTrapEnterprise with dot prefix", ".1.3.6.1.6.3.1.1.4.3.0"},
		{"snmpTrapEnterprise no prefix", "1.3.6.1.6.3.1.1.4.3.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"traps":[{"name":"x","snmpTrapOID":"1.2.3","varbinds":[{"oid":"` +
				tc.oid + `","type":"integer","value":"1"}]}]}`
			path := filepath.Join(t.TempDir(), "c.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadCatalogFromFile(path)
			if err == nil {
				t.Fatal("expected reserved-OID rejection, got nil error")
			}
			if !strings.Contains(err.Error(), "reserved") {
				t.Errorf("error should mention 'reserved': %v", err)
			}
		})
	}
}

// TestLoadCatalogFromFile_EnterpriseField_Valid confirms an entry with a
// legitimate snmpTrapEnterprise OID loads correctly and stores it on the
// parsed CatalogEntry.
func TestLoadCatalogFromFile_EnterpriseField_Valid(t *testing.T) {
	body := `{"traps":[{"name":"x","snmpTrapOID":"1.3.6.1.6.3.1.1.5.3","snmpTrapEnterprise":"1.3.6.1.4.1.9.1","varbinds":[]}]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadCatalogFromFile(path)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if got := cat.Entries[0].SnmpTrapEnterprise; got != "1.3.6.1.4.1.9.1" {
		t.Errorf("SnmpTrapEnterprise: got %q, want %q", got, "1.3.6.1.4.1.9.1")
	}
}

// TestLoadCatalogFromFile_EnterpriseField_StripsLeadingDot exercises the
// same TrimPrefix normalisation used for snmpTrapOID.
func TestLoadCatalogFromFile_EnterpriseField_StripsLeadingDot(t *testing.T) {
	body := `{"traps":[{"name":"x","snmpTrapOID":"1.3.6.1.6.3.1.1.5.3","snmpTrapEnterprise":".1.3.6.1.4.1.9.1","varbinds":[]}]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadCatalogFromFile(path)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if got := cat.Entries[0].SnmpTrapEnterprise; got != "1.3.6.1.4.1.9.1" {
		t.Errorf("SnmpTrapEnterprise not dot-stripped: got %q, want %q", got, "1.3.6.1.4.1.9.1")
	}
}

// TestLoadCatalogFromFile_EnterpriseField_RejectsReserved makes sure the
// entry-level snmpTrapEnterprise field itself cannot hold one of the three
// reserved OIDs (sysUpTime.0, snmpTrapOID.0, snmpTrapEnterprise.0), in both
// no-prefix and leading-dot forms — the leading-dot variant is the evasion
// path (TrimPrefix happens before the reserved-OID comparison).
func TestLoadCatalogFromFile_EnterpriseField_RejectsReserved(t *testing.T) {
	cases := []string{
		"1.3.6.1.2.1.1.3.0",
		"1.3.6.1.6.3.1.1.4.1.0",
		"1.3.6.1.6.3.1.1.4.3.0",
		".1.3.6.1.2.1.1.3.0",
		".1.3.6.1.6.3.1.1.4.1.0",
		".1.3.6.1.6.3.1.1.4.3.0",
	}
	for _, oid := range cases {
		t.Run(oid, func(t *testing.T) {
			body := `{"traps":[{"name":"x","snmpTrapOID":"1.2.3","snmpTrapEnterprise":"` +
				oid + `","varbinds":[]}]}`
			path := filepath.Join(t.TempDir(), "c.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadCatalogFromFile(path)
			if err == nil {
				t.Fatal("expected reserved-OID rejection, got nil")
			}
			if !strings.Contains(err.Error(), "reserved") {
				t.Errorf("error should mention 'reserved': %v", err)
			}
		})
	}
}

// TestLoadCatalogFromFile_EnterpriseField_RejectsMalformed exercises the
// dotted-OID format validator: single-dot / single-arc / trailing-dot /
// embedded empty arc / non-numeric / whitespace-only inputs must all be
// rejected at catalog load rather than silently producing broken wire bytes.
func TestLoadCatalogFromFile_EnterpriseField_RejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		oid  string
	}{
		{"single_dot", "."},
		{"whitespace_only", "   "},
		{"single_arc", "12345"},
		{"trailing_dot", "1.3.6.1.4.1.9.1."},
		{"empty_arc_middle", "1.3..6"},
		{"non_numeric_character", "1.3.6.1.4.1.abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"traps":[{"name":"x","snmpTrapOID":"1.2.3","snmpTrapEnterprise":"` +
				tc.oid + `","varbinds":[]}]}`
			path := filepath.Join(t.TempDir(), "c.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadCatalogFromFile(path)
			if err == nil {
				t.Fatalf("expected malformed-OID rejection for %q, got nil", tc.oid)
			}
			if !strings.Contains(err.Error(), "snmpTrapEnterprise") {
				t.Errorf("error should name the field: %v", err)
			}
		})
	}
}

// TestLoadCatalogFromFile_EnterpriseField_RejectsOverLength pins the
// maxDottedOIDLen cap. A 257-char OID must be rejected even though it's
// otherwise well-formed digits-and-dots — bounds the enterprise varbind's
// contribution to the UDP MTU budget.
func TestLoadCatalogFromFile_EnterpriseField_RejectsOverLength(t *testing.T) {
	// Build an OID of length 257: "1" + (".1" * 128) = 1 + 256 = 257 chars.
	oid := "1" + strings.Repeat(".1", 128)
	if len(oid) != 257 {
		t.Fatalf("setup: want len 257, got %d", len(oid))
	}
	body := `{"traps":[{"name":"x","snmpTrapOID":"1.2.3","snmpTrapEnterprise":"` +
		oid + `","varbinds":[]}]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCatalogFromFile(path)
	if err == nil {
		t.Fatal("expected over-length rejection, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("error should mention the length cap: %v", err)
	}
}

// TestLoadCatalogFromFile_EnterpriseField_DefaultEmpty confirms that an
// entry without the snmpTrapEnterprise field produces an empty string on
// the parsed entry — backward-compatibility anchor for pre-issue-#100
// catalogs.
func TestLoadCatalogFromFile_EnterpriseField_DefaultEmpty(t *testing.T) {
	body := `{"traps":[{"name":"x","snmpTrapOID":"1.3.6.1.6.3.1.1.5.3","varbinds":[]}]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadCatalogFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cat.Entries[0].SnmpTrapEnterprise; got != "" {
		t.Errorf("SnmpTrapEnterprise: got %q, want empty (field absent in JSON)", got)
	}
}

func TestLoadCatalogFromFile_UnknownTemplateField(t *testing.T) {
	body := `{"traps":[{"name":"x","snmpTrapOID":"1.2.3","varbinds":[` +
		`{"oid":"1.2.3.{{.NotAField}}","type":"integer","value":"1"}]}]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCatalogFromFile(path)
	if err == nil {
		t.Fatal("expected unknown-field rejection")
	}
	if !strings.Contains(err.Error(), "NotAField") {
		t.Errorf("error should name the bad field: %v", err)
	}
}

func TestLoadCatalogFromFile_UnknownType(t *testing.T) {
	body := `{"traps":[{"name":"x","snmpTrapOID":"1.2.3","varbinds":[` +
		`{"oid":"1.2.3","type":"quantum","value":"1"}]}]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCatalogFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("expected unknown-type error, got %v", err)
	}
}

func TestLoadCatalogFromFile_EmptyTraps(t *testing.T) {
	body := `{"traps":[]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalogFromFile(path); err == nil {
		t.Fatal("expected empty-catalog error")
	}
}

func TestLoadCatalogFromFile_WeightDefaultsToOne(t *testing.T) {
	body := `{"traps":[
		{"name":"a","snmpTrapOID":"1.1","varbinds":[]},
		{"name":"b","snmpTrapOID":"1.2","weight":0,"varbinds":[]}
	]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadCatalogFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range cat.Entries {
		if e.Weight != 1 {
			t.Errorf("entry %q: weight = %d, want default 1", e.Name, e.Weight)
		}
	}
}

func TestCatalog_Pick_WeightDistribution(t *testing.T) {
	cat, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	// Sample many draws; assert each entry's frequency is within a tolerance
	// of its weight share. 10k draws, weights totalling 100, tolerance ±3%
	// absolute. Uses fixed seed for reproducibility.
	const draws = 10000
	const absTol = 0.03
	rnd := rand.New(rand.NewSource(42))
	counts := make(map[string]int)
	for i := 0; i < draws; i++ {
		e := cat.Pick(rnd)
		counts[e.Name]++
	}
	for _, e := range cat.Entries {
		want := float64(e.Weight) / float64(cat.totalWeight)
		got := float64(counts[e.Name]) / float64(draws)
		if math.Abs(got-want) > absTol {
			t.Errorf("%s: pick fraction = %.3f, want %.3f ± %.2f",
				e.Name, got, want, absTol)
		}
	}
}

func TestCatalogEntry_Resolve_TemplatesEvaluated(t *testing.T) {
	cat, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	entry := cat.ByName["linkDown"]
	if entry == nil {
		t.Fatal("linkDown missing")
	}
	ctx := TemplateCtx{IfIndex: 7, Uptime: 1234, Now: 1700000000, DeviceIP: "10.42.0.1"}
	vbs, err := entry.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vbs) != 3 {
		t.Fatalf("linkDown resolve: want 3 varbinds, got %d", len(vbs))
	}
	// First varbind OID should be "1.3.6.1.2.1.2.2.1.1.7" (ifIndex.7),
	// value "7" (also ifIndex).
	if vbs[0].OID != "1.3.6.1.2.1.2.2.1.1.7" {
		t.Errorf("varbind[0].OID = %q, want 1.3.6.1.2.1.2.2.1.1.7", vbs[0].OID)
	}
	if vbs[0].Value != "7" {
		t.Errorf("varbind[0].Value = %q, want 7", vbs[0].Value)
	}
}

func TestCatalogEntry_Resolve_OverridesWin(t *testing.T) {
	cat, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	entry := cat.ByName["linkDown"]
	ctx := TemplateCtx{IfIndex: 7}
	vbs, err := entry.Resolve(ctx, map[string]string{"IfIndex": "42"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vbs[0].OID, ".42") {
		t.Errorf("override IfIndex=42 should win; got OID %q", vbs[0].OID)
	}
	if vbs[0].Value != "42" {
		t.Errorf("override IfIndex=42 should win; got Value %q", vbs[0].Value)
	}
}

func TestCatalogEntry_Resolve_UnknownOverrideRejected(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	entry := cat.ByName["linkDown"]
	_, err := entry.Resolve(TemplateCtx{IfIndex: 1}, map[string]string{"Foo": "bar"})
	if err == nil || !strings.Contains(err.Error(), "Foo") {
		t.Fatalf("want rejection naming Foo, got %v", err)
	}
}

func TestCatalogEntry_Resolve_Fast(t *testing.T) {
	// design.md Risks: benchmark-adjacent assertion that per-fire Resolve is
	// well under a millisecond (the 50µs target in the spec is bench-only).
	cat, _ := LoadEmbeddedCatalog()
	entry := cat.ByName["linkDown"]
	ctx := TemplateCtx{IfIndex: 3, Uptime: 100, Now: 1700000000, DeviceIP: "10.42.0.1"}
	// Just exercise; the bench test would go in a separate _bench_test.go.
	for i := 0; i < 1000; i++ {
		if _, err := entry.Resolve(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCatalog_To_Wire_IntegrationWithEnterprise exercises the full pipeline:
// catalog JSON with snmpTrapEnterprise + body varbinds → LoadCatalogFromFile
// → Resolve → EncodeTrap → BER decode. Confirms the enterprise OID survives
// from catalog source to the wire in the correct position (slot 2, after
// sysUpTime.0 and snmpTrapOID.0) alongside a template-resolved body varbind.
func TestCatalog_To_Wire_IntegrationWithEnterprise(t *testing.T) {
	body := `{"traps":[{
		"name": "enterpriseLink",
		"snmpTrapOID": "1.3.6.1.6.3.1.1.5.3",
		"snmpTrapEnterprise": "1.3.6.1.4.1.9.1",
		"varbinds": [
			{"oid":"1.3.6.1.2.1.2.2.1.1.{{.IfIndex}}","type":"integer","value":"{{.IfIndex}}"}
		]
	}]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadCatalogFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	entry := cat.ByName["enterpriseLink"]
	if entry == nil {
		t.Fatal("enterpriseLink entry missing after load")
	}
	ctx := TemplateCtx{IfIndex: 5, Uptime: 100, Now: 1700000000, DeviceIP: "10.42.0.1"}
	vbs, err := entry.Resolve(ctx, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodeTrap("public", 7, entry.SnmpTrapOID, entry.SnmpTrapEnterprise, 100, vbs, buf)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	dec := decodeV2cNotification(t, buf[:n])
	if len(dec.Varbinds) != 4 {
		t.Fatalf("varbind count: got %d, want 4 (sysUpTime + snmpTrapOID + enterprise + body)",
			len(dec.Varbinds))
	}
	// Slot 0: sysUpTime.0
	if dec.Varbinds[0].OID != "."+oidSysUpTime0 {
		t.Errorf("vb[0].OID: got %s, want .%s", dec.Varbinds[0].OID, oidSysUpTime0)
	}
	// Slot 1: snmpTrapOID.0 value = catalog's snmpTrapOID
	if dec.Varbinds[1].OID != "."+oidSnmpTrapOID0 {
		t.Errorf("vb[1].OID: got %s, want .%s", dec.Varbinds[1].OID, oidSnmpTrapOID0)
	}
	if got := decodeOID(dec.Varbinds[1].RawValue); got != ".1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("vb[1] snmpTrapOID value: got %s, want .1.3.6.1.6.3.1.1.5.3", got)
	}
	// Slot 2: snmpTrapEnterprise.0 value = catalog's snmpTrapEnterprise
	if dec.Varbinds[2].OID != "."+oidSnmpTrapEnterprise0 {
		t.Errorf("vb[2].OID: got %s, want .%s", dec.Varbinds[2].OID, oidSnmpTrapEnterprise0)
	}
	if got := decodeOID(dec.Varbinds[2].RawValue); got != ".1.3.6.1.4.1.9.1" {
		t.Errorf("vb[2] enterprise OID value: got %s, want .1.3.6.1.4.1.9.1", got)
	}
	// Slot 3: body varbind with IfIndex=5 resolved into both OID and value
	if dec.Varbinds[3].OID != ".1.3.6.1.2.1.2.2.1.1.5" {
		t.Errorf("vb[3].OID: got %s, want .1.3.6.1.2.1.2.2.1.1.5 (IfIndex=5)", dec.Varbinds[3].OID)
	}
}
