/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"strings"
	"testing"
)

// TestFlowCapabilityCompleteness enforces the flow-capability doctrine
// mechanically (#364): every device type shipped in resources/ must be in
// flowProfileMap XOR flowIncapableTypes.
//
// Why this is a TEST and not a load-time check: device types are not
// repo-static at runtime — operators can drop custom <type>.json files into
// the installed resources directory, and for those the compiled-in maps are
// unreachable, so a runtime XOR check would reject every custom type and
// delete that capability. The invariant is only enforceable where both maps
// are editable: the repo. So it lives in CI, and fails the PR that adds a
// device type without deciding its flow story — the silent alternative being
// edge-router flow ground truth for a type that may export no flow at all
// (the false pass the capability doctrine exists to prevent).
func TestFlowCapabilityCompleteness(t *testing.T) {
	entries, err := os.ReadDir("resources")
	if err != nil {
		t.Fatalf("read resources dir: %v", err)
	}
	types := 0
	for _, e := range entries {
		// Device types are directories; _common is shared catalog data, and
		// top-level files (limitations docs) are not types.
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		types++
		rf := e.Name() + ".json"
		_, mapped := flowProfileMap[rf]
		incapable := !SupportsFlowExport(rf)
		switch {
		case mapped && incapable:
			t.Errorf("%s is in BOTH flowProfileMap and flowIncapableTypes; pick one — "+
				"a capability cannot be simultaneously profiled and absent", rf)
		case !mapped && !incapable:
			t.Errorf("%s is in NEITHER flowProfileMap nor flowIncapableTypes. Decide its "+
				"flow story: add a realistic profile to flowProfileMap, or list it in "+
				"flowIncapableTypes if the real platform exports no flow records. Without "+
				"this it silently inherits edge-router flow ground truth (#364)", rf)
		}
	}
	if types == 0 {
		t.Fatal("enumerated zero device types; the resources layout changed and this test is checking nothing")
	}
}
