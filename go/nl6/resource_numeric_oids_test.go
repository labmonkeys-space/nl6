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

// numericLeafOIDs are scalar MIB leaves whose value is numeric by definition.
// A string response for one of these is a data defect: nl6 encodes it as an
// OCTET STRING, and a collector that types the OID per its MIB (as OpenNMS
// does for `freeMem`, `type="gauge"` in the stock cisco-router group) cannot
// convert it and drops the attribute on every poll of every device.
//
// nl6#515 is why this test exists. `freeMem` (.1.3.6.1.4.1.9.2.1.8.0) carried
// the device's own name in TWO profiles, copied from the neighbouring
// chassisId entry where a string is correct. It was invisible until a
// 2,150-device benchmark turned it into a sustained error rate.
//
// The list names exact leaves, not subtrees. The obvious subtree here,
// OLD-CISCO-SYSTEM-MIB lsystem (1.3.6.1.4.1.9.2.1), also holds DisplayString
// and IpAddress leaves (hostName .3, whyReload .2, authAddr .5, ...), so a
// prefix match would reject legitimate data the moment a profile gains one.
//
// Width follows the MIB SYNTAX and the encoder (`encodeTypedValue`): a Gauge
// leaf must be in the `oidTypeTable` and parses as uint32; an INTEGER leaf
// takes the default branch and must fit int32.
var numericLeafOIDs = []struct {
	oid      string
	name     string
	unsigned bool
}{
	{"1.3.6.1.4.1.9.2.1.8", "OLD-CISCO-MEMORY-MIB::freeMem", true},
	{"1.3.6.1.4.1.9.2.1.54", "OLD-CISCO-SYSTEM-MIB::writeMem", false},
	{"1.3.6.1.4.1.9.2.1.56", "OLD-CISCO-SYSTEM-MIB::busyPer", false},
	{"1.3.6.1.4.1.9.2.1.57", "OLD-CISCO-SYSTEM-MIB::avgBusy1", false},
	{"1.3.6.1.4.1.9.2.1.58", "OLD-CISCO-SYSTEM-MIB::avgBusy5", false},
}

func TestResourceProfiles_NumericLeavesHoldNumbers(t *testing.T) {
	// One level deep, like the loader (loadSpecificResourcesFromDir uses a
	// non-recursive ReadDir).
	files, err := filepath.Glob("resources/*/*.json")
	if err != nil {
		t.Fatalf("glob resources: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no resource files found — has the layout changed?")
	}

	matched := 0

	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- test-only, path from a repo glob
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// Decode into the loader's own type so this test rejects exactly what
		// the loader rejects (a non-string "response" included). Catalog and
		// optical files decode too; they simply carry no "snmp" part.
		var doc DeviceResources
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: does not decode as a resource file: %v", f, err)
		}
		for _, r := range doc.SNMP {
			oid := strings.TrimPrefix(r.OID, ".")
			for _, leaf := range numericLeafOIDs {
				if oid != leaf.oid && !strings.HasPrefix(oid, leaf.oid+".") {
					continue
				}
				matched++
				// No TrimSpace: the encoder does not trim either, so a
				// padded value would go out as an OCTET STRING.
				var perr error
				if leaf.unsigned {
					_, perr = strconv.ParseUint(r.Response, 10, 32)
				} else {
					_, perr = strconv.ParseInt(r.Response, 10, 32)
				}
				if perr != nil {
					t.Errorf("%s: .%s (%s) has non-numeric response %q: "+
						"the leaf is numeric in the MIB, so this encodes as an "+
						"OCTET STRING and a collector typing it per the MIB drops it",
						f, oid, leaf.name, r.Response)
				}
			}
		}
	}

	if matched == 0 {
		t.Fatal("no resource entry matched a guarded leaf — the test asserted nothing")
	}
}
