/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The trap catalog validated OIDs with its own predicate, weaker than and
// divergent from the encoder's (nl6#539). It accepted values encodeOID refuses
// — a first arc above 2, a second above 39 when the first is 0 or 1, arcs past
// 2^32-1 — so an entry could load and then go on the wire as the degenerate
// 06 00. And it rejected a leading dot the encoder accepts, so the divergence
// ran both ways.
//
// The fix is the one nl6#544 used for the resource loader: ask the encoder.
// The property these tests pin is ONE-DIRECTIONAL: the catalog never accepts
// what the encoder refuses. The catalog stays deliberately stricter the other
// way (digits-only spelling, maxDottedOIDLen), so two-way agreement is not
// the contract; see validateDottedOID's comment.

func TestCatalogOIDValidationAgreesWithTheEncoder(t *testing.T) {
	// Spellings both sides accept. Asserted as accepted below, so the safety
	// property cannot be satisfied by a validator that rejects everything.
	acceptedByBoth := []string{
		"1.3.6.1.4.1.9.1.1", ".1.3.6.1.4.1.9.1.1", "2.999", "1.39", "2.0",
		"1.2.4294967295", "1.0.8802.1.1.2.1.3.2",
	}
	// The encoder refuses these; the old catalog predicate accepted the first
	// five, which is the drift nl6#539 closed. 2.4294967290 has every arc in
	// range and is still refused, because the bound is the COMBINED
	// 40*first+second of the first pair, not the raw arc.
	encoderRefuses := []string{
		"3.40.1", "1.40.1", "0.40.1", "2.7000000000", "1.2.4294967296",
		"2.4294967290",
		"1", "", "1.3.x.7", "1.3..7", "..1.3.6",
	}
	// The encoder accepts these and the catalog refuses them, DELIBERATELY:
	// strconv.Atoi parses a sign where the digits-only walk does not, and
	// maxDottedOIDLen caps a length the encoder can carry. They are here so
	// the one-directional property is exercised exactly where a two-way
	// agreement assertion would fail.
	catalogStricter := []string{
		"+1.3", "1.+3",
		"1." + strings.Repeat("3.", 140) + "6", // valid arcs, over maxDottedOIDLen
	}

	// The safety property, over every group: whatever the catalog accepts,
	// the encoder must be able to represent.
	for _, group := range [][]string{acceptedByBoth, encoderRefuses, catalogStricter} {
		for _, oid := range group {
			t.Run(fmt.Sprintf("%.24q", oid), func(t *testing.T) {
				if validateDottedOID(oid, "e", "f") == nil && !encodableAsOID(oid) {
					t.Errorf("catalog accepts %q, which the encoder refuses: the entry "+
						"would ship a degenerate 06 00", oid)
				}
			})
		}
	}

	// The common spellings must actually load, or "stricter" would be
	// satisfiable by rejecting everything.
	for _, oid := range acceptedByBoth {
		if err := validateDottedOID(oid, "e", "f"); err != nil {
			t.Errorf("catalog rejects %q, a spelling both sides must accept: %v", oid, err)
		}
	}
	// And the rows must stay in their groups, or they stop guarding anything:
	// a row that silently moved sides is an encoder or validator change this
	// test needs to surface.
	for _, oid := range encoderRefuses {
		if encodableAsOID(oid) {
			t.Errorf("the encoder now accepts %q; move the row and re-check the catalog verdict", oid)
		}
	}
	for _, oid := range catalogStricter {
		if !encodableAsOID(oid) {
			t.Errorf("the encoder now refuses %q; the row no longer exercises the stricter direction", oid)
		}
		if validateDottedOID(oid, "e", "f") == nil {
			t.Errorf("the catalog now accepts %q; the row no longer exercises the stricter direction", oid)
		}
	}
}

// FuzzCatalogOIDAgreement pins the one-directional property over arbitrary
// input: whatever the catalog accepts, the encoder must be able to represent.
// A fixed case list is how the two predicates drifted for years, and the fuzz
// shape is what caught 2.7000000000 on the encoder pair (FuzzOIDRoundTrip).
// Seeds replay on an ordinary go test, like every fuzz target in this package.
func FuzzCatalogOIDAgreement(f *testing.F) {
	for _, seed := range []string{
		"1.3.6.1.4.1.9.1.1", ".1.3.6.1.4.1.9.1.1", "2.999", "3.40.1", "1.40.1",
		"2.7000000000", "1.2.4294967296", "2.4294967290", "+1.3", "",
		"1.3..7", "..1.3.6",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, oid string) {
		if validateDottedOID(oid, "e", "f") == nil && !encodableAsOID(oid) {
			t.Errorf("catalog accepts %q, which the encoder refuses: the entry "+
				"would ship a degenerate 06 00", oid)
		}
	})
}

// TestCatalogAcceptsLeadingDot pins the half of the divergence that ran the
// other way: the catalog rejected a spelling the encoder accepts, and which
// compileEntry already normalises before storing.
func TestCatalogAcceptsLeadingDot(t *testing.T) {
	if err := validateDottedOID(".1.3.6.1.4.1.9.1.1", "e", "f"); err != nil {
		t.Errorf("a leading dot was rejected: %v. encodeOID strips it, resource files accept "+
			"both spellings, and compileEntry normalises this field anyway", err)
	}

	// And through the real loader, which is the path an operator's catalog
	// actually takes.
	if _, err := loadCatalogFromBytes(t, catalogJSON("probe", ".1.3.6.1.6.3.1.1.5.1", nil)); err != nil {
		t.Errorf("a catalog whose snmpTrapOID has a leading dot failed to load: %v", err)
	}
}

// TestSnmpTrapOIDIsStructurallyValidated covers the field that had no check at
// all beyond emptiness. It becomes the snmpTrapOID.0 varbind, so an
// unencodable value makes every trap from the entry unidentifiable.
func TestSnmpTrapOIDIsStructurallyValidated(t *testing.T) {
	for _, bad := range []string{"3.40.1", "1.40.1", "not-an-oid", "1", "1.2.4294967296"} {
		t.Run(bad, func(t *testing.T) {
			_, err := loadCatalogFromBytes(t, catalogJSON("probe", bad, nil))
			if err == nil {
				t.Fatalf("snmpTrapOID %q loaded; it would be emitted as a degenerate OID, so "+
					"every trap from this entry would be unidentifiable", bad)
			}
			if !strings.Contains(err.Error(), "snmpTrapOID") {
				t.Errorf("error does not name the field: %v", err)
			}
		})
	}

	if _, err := loadCatalogFromBytes(t, catalogJSON("probe", "1.3.6.1.6.3.1.1.5.1", nil)); err != nil {
		t.Errorf("a valid snmpTrapOID was rejected: %v", err)
	}
}

// TestSnmpTrapEnterpriseIsRefusedThroughTheLoader drives the encoder check on
// the third literal field through the real loader. Its shape check predates
// nl6#539 and missed everything the encoder refuses, the same as the others.
func TestSnmpTrapEnterpriseIsRefusedThroughTheLoader(t *testing.T) {
	entry := map[string]any{
		"name": "probe", "snmpTrapOID": "1.3.6.1.6.3.1.1.5.1", "weight": 1,
		"snmpTrapEnterprise": "3.40.1",
	}
	b, err := json.Marshal(map[string]any{"traps": []any{entry}})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	_, err = loadCatalogFromBytes(t, b)
	if err == nil {
		t.Fatal("an snmpTrapEnterprise the encoder refuses was accepted; the enterprise " +
			"varbind would go out as a degenerate 06 00")
	}
	if !strings.Contains(err.Error(), "snmpTrapEnterprise") {
		t.Errorf("error does not name the field: %v", err)
	}
}

// TestLiteralVarbindOIDIsStructurallyValidated covers the other unchecked
// field. A templated OID is still allowed through, because it is rendered per
// fire and a REST override can make it unencodable at that point regardless.
func TestLiteralVarbindOIDIsStructurallyValidated(t *testing.T) {
	// "" is a CHANGED rule, not merely another bad spelling: an empty literal
	// varbind OID loaded before nl6#539 and fired the same degenerate empty
	// NAME this test exists to keep off the wire.
	for _, bad := range []string{"3.40.1", ""} {
		t.Run(fmt.Sprintf("%q", bad), func(t *testing.T) {
			_, err := loadCatalogFromBytes(t, catalogJSON("probe", "1.3.6.1.6.3.1.1.5.1",
				[]map[string]string{{"oid": bad, "type": "octet-string", "value": "x"}}))
			if err == nil {
				t.Fatalf("a literal varbind OID the encoder refuses (%q) was accepted; it "+
					"would go out as a degenerate empty NAME, which no manager can match", bad)
			}
			if !strings.Contains(err.Error(), "varbind") {
				t.Errorf("error does not name the varbind: %v", err)
			}
		})
	}

	// A templated one still loads: it cannot be checked until it renders.
	if _, err := loadCatalogFromBytes(t, catalogJSON("probe", "1.3.6.1.6.3.1.1.5.1",
		[]map[string]string{{"oid": "1.3.6.1.2.1.2.2.1.7.{{.IfIndex}}", "type": "integer", "value": "1"}})); err != nil {
		t.Errorf("a templated varbind OID was rejected at load: %v. It is rendered per fire, so "+
			"load time cannot decide it", err)
	}
}

// TestShippedCatalogsSatisfyTheEncoder is the compatibility proof: every OID
// field in every shipped catalog must still load. Tightening a validator is
// only safe while that holds. The floor guards against a walk that silently
// stops finding fields; the exact count is logged, not pinned, because it
// moves with every catalog addition.
func TestShippedCatalogsSatisfyTheEncoder(t *testing.T) {
	checked := 0
	err := filepath.Walk("resources", func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Base(p) != "traps.json" {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var doc struct {
			Traps []struct {
				Name               string `json:"name"`
				SnmpTrapOID        string `json:"snmpTrapOID"`
				SnmpTrapEnterprise string `json:"snmpTrapEnterprise"`
				Varbinds           []struct {
					OID string `json:"oid"`
				} `json:"varbinds"`
			} `json:"traps"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		for _, e := range doc.Traps {
			for field, oid := range map[string]string{
				"snmpTrapOID":        e.SnmpTrapOID,
				"snmpTrapEnterprise": e.SnmpTrapEnterprise,
			} {
				if oid == "" {
					continue
				}
				checked++
				if verr := validateDottedOID(oid, e.Name, field); verr != nil {
					t.Errorf("%s: %v", p, verr)
				}
			}
			for i, vb := range e.Varbinds {
				if vb.OID == "" || strings.Contains(vb.OID, "{{") {
					continue
				}
				checked++
				if verr := validateDottedOID(vb.OID, e.Name, fmt.Sprintf("varbind %d", i)); verr != nil {
					t.Errorf("%s: %v", p, verr)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking catalogs: %v", err)
	}
	if checked < 50 {
		t.Fatalf("only %d shipped catalog OIDs checked; the walk is not finding them", checked)
	}
	t.Logf("%d shipped catalog OID fields satisfy the encoder", checked)
}

// ── helpers ─────────────────────────────────────────────────────────────────

func catalogJSON(name, trapOID string, varbinds []map[string]string) []byte {
	entry := map[string]any{"name": name, "snmpTrapOID": trapOID, "weight": 1}
	if varbinds != nil {
		entry["varbinds"] = varbinds
	}
	b, _ := json.Marshal(map[string]any{"traps": []any{entry}})
	return b
}

func loadCatalogFromBytes(t *testing.T, b []byte) (*Catalog, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "traps.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return LoadCatalogFromFile(path)
}
