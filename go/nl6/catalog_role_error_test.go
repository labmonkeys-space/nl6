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
// each loader and checks that the load fails and the error names every accepted
// role. The expectation is spelled from the role constants, not from
// catalogRoles, so a role dropped from that list fails here instead of passing
// on a shared answer.
func TestCatalogUnknownRoleErrorListsEveryRole(t *testing.T) {
	want := []string{
		roleLinkDown, roleLinkUp,
		roleOpticalSDRaise, roleOpticalSDClear, roleOpticalSFRaise, roleOpticalSFClear,
	}
	cases := []struct {
		name string
		load func() error
	}{
		{"trap", func() error {
			_, err := parseCatalog([]byte(`{"traps":[{"name":"x","snmpTrapOID":"1.3.6.1.6.3.1.1.5.3","role":"flap"}]}`), "<test>")
			return err
		}},
		{"syslog", func() error {
			_, err := parseSyslogCatalog([]byte(`{"entries":[{"name":"x","facility":"daemon","severity":"info","appName":"a","template":"m","role":"flap"}]}`), "<test>")
			return err
		}},
	}
	for _, tc := range cases {
		err := tc.load()
		if err == nil {
			t.Errorf("%s: expected an unknown-role error, got nil", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), `unknown role "flap"`) {
			t.Errorf("%s: error %q does not name the invalid role", tc.name, err)
		}
		for _, role := range want {
			if !strings.Contains(err.Error(), role) {
				t.Errorf("%s: error %q does not list accepted role %q", tc.name, err, role)
			}
		}
	}
}

// TestCatalogRolesAcceptEveryOpticalRole drives opticalRoleFor over every
// condition and direction and checks that the catalog accepts the role it
// returns. A new optical role wired into the evaluator but left out of
// catalogRoles would make every entry tagged with it fail to load.
func TestCatalogRolesAcceptEveryOpticalRole(t *testing.T) {
	for _, cond := range []opticalCondition{opticalCondSD, opticalCondSF} {
		for _, raised := range []bool{true, false} {
			role := opticalRoleFor(cond, raised)
			if !validRole(role) {
				t.Errorf("opticalRoleFor(%v, %v) = %q, which the catalog loaders reject", cond, raised, role)
			}
		}
	}
}
