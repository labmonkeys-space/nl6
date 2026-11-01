/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
)

// TestCatalogUnknownRoleErrorListsEveryRole loads one unknown-role entry into
// each loader and checks that the error names every accepted role. The
// expectation is spelled from the role constants, not from catalogRoles, so a
// role dropped from that list fails here instead of passing on a shared answer.
func TestCatalogUnknownRoleErrorListsEveryRole(t *testing.T) {
	want := []string{
		roleLinkDown, roleLinkUp,
		roleOpticalSDRaise, roleOpticalSDClear, roleOpticalSFRaise, roleOpticalSFClear,
	}
	trapBody := `{"traps":[{"name":"x","snmpTrapOID":"1.3.6.1.6.3.1.1.5.3","role":"flap"}]}`
	syslogBody := `{"entries":[{"name":"x","facility":"daemon","severity":"info","appName":"a","template":"m","role":"flap"}]}`

	_, trapErr := parseCatalog([]byte(trapBody), "<test>")
	_, syslogErr := parseSyslogCatalog([]byte(syslogBody), "<test>")

	for name, err := range map[string]error{"trap": trapErr, "syslog": syslogErr} {
		if err == nil {
			t.Fatalf("%s: expected an unknown-role error, got nil", name)
		}
		if !strings.Contains(err.Error(), `unknown role "flap"`) {
			t.Errorf("%s: error %q does not name the invalid role", name, err)
		}
		for _, role := range want {
			if !strings.Contains(err.Error(), role) {
				t.Errorf("%s: error %q does not list accepted role %q", name, err, role)
			}
		}
	}
}
