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
// These tests pin that the two agree, rather than pinning a list of cases that
// would drift again.

func TestCatalogOIDValidationAgreesWithTheEncoder(t *testing.T) {
	for _, oid := range []string{
		// Accepted by both.
		"1.3.6.1.4.1.9.1.1", ".1.3.6.1.4.1.9.1.1", "2.999", "1.39", "2.0",
		"1.2.4294967295", "1.0.8802.1.1.2.1.3.2",
		// The encoder refuses these; the old catalog predicate did not.
		"3.40.1", "1.40.1", "0.40.1", "2.7000000000", "1.2.4294967296",
		// Both refuse.
		"1", "", "1.3.x.7", "1.3..7",
	} {
		t.Run(oid, func(t *testing.T) {
			catalogAccepts := validateDottedOID(oid, "e", "f") == nil
			encoderAccepts := oid != "" && encodableAsOID(oid)

			if catalogAccepts != encoderAccepts {
				t.Errorf("catalog accepts=%v, encoder accepts=%v for %q. They must not drift: a "+
					"catalog that loads an OID the encoder refuses ships a degenerate 06 00",
					catalogAccepts, encoderAccepts, oid)
			}
		})
	}
}

// TestCatalogAcceptsLeadingDot pins the half of the divergence that ran the
// other way: the catalog rejected a spelling the encoder accepts, and which
// compileEntry already normalises before storing.
func TestCatalogAcceptsLeadingDot(t *testing.T) {
	if err := validateDottedOID(".1.3.6.1.4.1.9.1.1", "e", "f"); err != nil {
		t.Errorf("a leading dot was rejected: %v. encodeOID strips it, resource files accept "+
			"both spellings, and compileEntry normalises this field anyway", err)
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

	if _, err := loadCatalogFromBytes(t, catalogJSON("probe", "1.3.6.1.6.3.1.1.5.3", nil)); err != nil {
		t.Errorf("a valid snmpTrapOID was rejected: %v", err)
	}
}

// TestLiteralVarbindOIDIsStructurallyValidated covers the other unchecked
// field. A templated OID is still allowed through, because it is rendered per
// fire and a REST override can make it unencodable at that point regardless.
func TestLiteralVarbindOIDIsStructurallyValidated(t *testing.T) {
	_, err := loadCatalogFromBytes(t, catalogJSON("probe", "1.3.6.1.6.3.1.1.5.3",
		[]map[string]string{{"oid": "3.40.1", "type": "octet-string", "value": "x"}}))
	if err == nil {
		t.Fatal("a literal varbind OID the encoder refuses was accepted; it would go out as a " +
			"degenerate empty NAME, which no manager can match")
	}

	// A templated one still loads: it cannot be checked until it renders.
	if _, err := loadCatalogFromBytes(t, catalogJSON("probe", "1.3.6.1.6.3.1.1.5.3",
		[]map[string]string{{"oid": "1.3.6.1.2.1.2.2.1.7.{{.IfIndex}}", "type": "integer", "value": "1"}})); err != nil {
		t.Errorf("a templated varbind OID was rejected at load: %v. It is rendered per fire, so "+
			"load time cannot decide it", err)
	}
}

// TestShippedCatalogsSatisfyTheEncoder is the compatibility proof: every OID
// field in every shipped catalog must still load. Tightening a validator is
// only safe while that holds.
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
