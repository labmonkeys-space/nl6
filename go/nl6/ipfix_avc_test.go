/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strconv"
	"testing"
)

// The encoder's IE table is DERIVED from testdata/cisco-avc/elements.tsv
// (spec section 1): a constant that disagrees with the extract fails by
// name here. This test cannot show the extract is right; it shows the code
// did not drift from it.
func TestIPFIXAVCConstantsMatchEvidence(t *testing.T) {
	_, elements := loadCiscoAVCExtract(t)
	want := map[string]struct {
		pen, id int
		got     int
	}{
		"applicationId":          {0, 95, ipfixApplicationID},
		"applicationName":        {0, 96, ipfixApplicationName},
		"applicationDescription": {0, 94, ipfixApplicationDescription},
		"HTTP Host":              {9, 45003, ciscoHTTPHost},
		"HTTP URI statistics":    {9, 42125, ciscoHTTPURIStatistics},
	}
	seen := map[string]bool{}
	for _, e := range elements {
		w, ok := want[e.Name]
		if !ok {
			continue
		}
		seen[e.Name] = true
		pen, _ := strconv.Atoi(e.PEN)
		id, _ := strconv.Atoi(e.ID)
		if pen != w.pen || id != w.id {
			t.Fatalf("test table for %q says pen=%d id=%d, extract says pen=%d id=%d: fix the test table only if the extract changed", e.Name, w.pen, w.id, pen, id)
		}
		if w.got != id {
			t.Errorf("constant for %q = %d, extract says %d", e.Name, w.got, id)
		}
		if e.Status == "unresolved" {
			t.Errorf("%q is unresolved in the extract and must not be encoded", e.Name)
		}
		switch e.Name {
		case "applicationName":
			if n, _ := strconv.Atoi(e.Length); n != ipfixApplicationNameLen {
				t.Errorf("applicationName length constant = %d, extract says %d", ipfixApplicationNameLen, n)
			}
		case "applicationDescription":
			if n, _ := strconv.Atoi(e.Length); n != ipfixApplicationDescriptionLen {
				t.Errorf("applicationDescription length constant = %d, extract says %d", ipfixApplicationDescriptionLen, n)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("extract has no row named %q", name)
		}
	}
	if ciscoPEN != 9 {
		t.Errorf("ciscoPEN = %d, want 9", ciscoPEN)
	}
	if ipfixAVCTemplateID != 258 || ipfixAppTableTemplateID != 259 {
		t.Errorf("template ids = %d/%d, want 258/259 (plan A global constraint)", ipfixAVCTemplateID, ipfixAppTableTemplateID)
	}
}
