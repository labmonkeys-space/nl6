/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// numericOIDSubtrees are MIB subtrees whose every leaf is defined numerically.
// A string response under one of these is a data defect: nl6 encodes it as an
// OCTET STRING, and a collector that types the OID per its MIB — as OpenNMS
// does for `freeMem`, `type="gauge"` in the stock cisco-router group — cannot
// convert it and drops the attribute on every poll of every device.
//
// nl6#515 is why this test exists. `freeMem` (.1.3.6.1.4.1.9.2.1.8.0) carried
// the device's own name in TWO profiles, copied from the neighbouring
// chassisId entry where a string is correct. It was invisible until a
// 2,150-device benchmark turned it into a sustained error rate.
//
// Keep this list conservative. An entry belongs here only when every leaf
// beneath it is numeric in the MIB — a subtree with mixed types would make
// this test reject legitimate data.
var numericOIDSubtrees = []struct {
	prefix string
	mib    string
}{
	// OLD-CISCO-SYSTEM-MIB / OLD-CISCO-MEMORY-MIB: memory sizes, CPU busy
	// percentages and buffer counters. All Integer32 or Gauge.
	{"1.3.6.1.4.1.9.2.1.", "OLD-CISCO-SYSTEM-MIB"},
}

func TestResourceProfiles_NumericSubtreesHoldNumbers(t *testing.T) {
	roots, err := filepath.Glob("resources/*")
	if err != nil {
		t.Fatalf("glob resources: %v", err)
	}
	if len(roots) == 0 {
		t.Fatal("no resource directories found — has the layout changed?")
	}

	scanned := 0

	for _, root := range roots {
		files, err := filepath.Glob(filepath.Join(root, "*.json"))
		if err != nil {
			t.Fatalf("glob %s: %v", root, err)
		}
		for _, f := range files {
			raw, err := os.ReadFile(f) // #nosec G304 -- test-only, path from a repo glob
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			var doc any
			if err := json.Unmarshal(raw, &doc); err != nil {
				// Not every file under resources/ is an OID map (traps.json,
				// syslog.json, optical inventories). Malformed JSON is caught
				// by the loader; this test only cares about OID/response pairs.
				continue
			}
			scanned++
			walkOIDPairs(doc, func(oid, response string) {
				for _, sub := range numericOIDSubtrees {
					if !strings.HasPrefix(oid, sub.prefix) {
						continue
					}
					if _, err := strconv.ParseInt(strings.TrimSpace(response), 10, 64); err != nil {
						t.Errorf("%s: .%s (%s) has non-numeric response %q — "+
							"every leaf under %s is numeric, so this encodes as an "+
							"OCTET STRING and a collector typing it per the MIB drops it",
							f, oid, sub.mib, response, sub.prefix)
					}
				}
			})
		}
	}

	if scanned == 0 {
		t.Fatal("scanned no JSON resource files — the glob is wrong")
	}
}

// walkOIDPairs visits every {"oid": ..., "response": ...} object in a decoded
// resource document, whatever nesting the file uses. The resource files are
// not uniformly shaped, so this walks rather than assuming a schema.
func walkOIDPairs(node any, visit func(oid, response string)) {
	switch v := node.(type) {
	case map[string]any:
		oid, oidOK := v["oid"].(string)
		resp, respOK := v["response"].(string)
		if oidOK && respOK {
			visit(oid, resp)
		}
		for _, child := range v {
			walkOIDPairs(child, visit)
		}
	case []any:
		for _, child := range v {
			walkOIDPairs(child, visit)
		}
	}
}
