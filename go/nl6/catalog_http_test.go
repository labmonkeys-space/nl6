/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"errors"
	"sort"
	"testing"
)

// TestFireTrapOnDevice_UnknownEntryIncludesAvailableEntries confirms that
// the error returned for an unknown entry name is a TrapEntryNotFoundError
// whose Entries slice lists the device's resolved catalog's entries.
// The HTTP handler uses this list to build a 400-response JSON body.
func TestFireTrapOnDevice_UnknownEntryIncludesAvailableEntries(t *testing.T) {
	sm, _, device := startTrapForTest(t, TrapModeTrap)
	_, err := sm.FireTrapOnDevice(device.IP.String(), "doesNotExist", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var entryErr *TrapEntryNotFoundError
	if !errors.As(err, &entryErr) {
		t.Fatalf("expected *TrapEntryNotFoundError, got %T: %v", err, err)
	}
	if entryErr.Catalog != universalCatalogKey {
		t.Errorf("catalog label: got %q, want %q (no per-type for 127.0.0.1)",
			entryErr.Catalog, universalCatalogKey)
	}
	if !sort.StringsAreSorted(entryErr.Entries) {
		t.Errorf("availableEntries should be sorted alphabetically: got %v", entryErr.Entries)
	}
	found := false
	for _, e := range entryErr.Entries {
		if e == "linkDown" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("availableEntries missing 'linkDown' (universal catalog entry): got %v", entryErr.Entries)
	}
}

// TestGetTrapStatus_CatalogsByTypePresent confirms GetTrapStatus emits a
// CatalogsByType field with the _universal entry populated from the
// embedded universal catalog. Per-type keys aren't exercised here because
// the test harness doesn't ship vendor catalog resources; a later PR's
// integration test covers that path.
func TestGetTrapStatus_CatalogsByTypePresent(t *testing.T) {
	sm, _, _ := startTrapForTest(t, TrapModeTrap)
	status := sm.GetTrapStatus()
	if len(status.Collectors) == 0 {
		t.Fatal("status.Collectors: empty, want at least one entry for the test harness device")
	}
	if status.CatalogsByType == nil {
		t.Fatal("status.CatalogsByType: nil, want populated")
	}
	fallback, ok := status.CatalogsByType[universalCatalogKey]
	if !ok {
		t.Fatalf("CatalogsByType missing %q key: got %v", universalCatalogKey, status.CatalogsByType)
	}
	if fallback.Entries < 5 {
		t.Errorf("fallback catalog entries: got %d, want >=5 (universal ships 5)", fallback.Entries)
	}
	if fallback.Source != "embedded" {
		t.Errorf("fallback source: got %q, want \"embedded\"", fallback.Source)
	}
}

// TestTrapCatalogSource_PathMatrix pins the three-path source string
// logic (embedded / file / override) so the status endpoint output is
// stable across refactors.
func TestTrapCatalogSource_PathMatrix(t *testing.T) {
	cases := []struct {
		name            string
		slug            string
		catalogFlagPath string
		want            string
	}{
		{"embedded_fallback", universalCatalogKey, "", "embedded"},
		{"file_per_type", "cisco_ios", "", "file:resources/cisco_ios/traps.json"},
		{"override_wins_over_per_type", "cisco_ios", "/tmp/custom.json", "override:/tmp/custom.json"},
		{"override_wins_over_fallback", universalCatalogKey, "/tmp/custom.json", "override:/tmp/custom.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := trapCatalogSource(tc.slug, tc.catalogFlagPath); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSyslogCatalogSource_PathMatrix is the symmetric syslog test.
func TestSyslogCatalogSource_PathMatrix(t *testing.T) {
	cases := []struct {
		name            string
		slug            string
		catalogFlagPath string
		want            string
	}{
		{"embedded_fallback", universalCatalogKey, "", "embedded"},
		{"file_per_type", "juniper_mx240", "", "file:resources/juniper_mx240/syslog.json"},
		{"override_wins", "juniper_mx240", "/tmp/mine.json", "override:/tmp/mine.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := syslogCatalogSource(tc.slug, tc.catalogFlagPath); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
