/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// worldcities CSV column layout, as processCSVFile reads it: city, city_ascii,
// lat, lng, country, iso2, iso3, admin_name, ...
func cityRow(city, admin, country, lat, lng string) string {
	return fmt.Sprintf("%s,%s,%s,%s,%s,XX,XXX,%s\n", city, city, lat, lng, country, admin)
}

// TestGetRandomLocationNeverServesASentinel is the enforcement point of
// nl6#541 part 3. sysLocation is served outside the resource map, so
// validateSNMPResourceValues cannot see it; getRandomLocation is the single
// funnel every served location passes through, whatever its source.
func TestGetRandomLocationNeverServesASentinel(t *testing.T) {
	saved := worldCities
	t.Cleanup(func() { worldCities = saved })

	// Only sentinels in the list: every draw must be diverted, so the test
	// does not depend on which index the RNG picks.
	worldCities = []WorldCity{
		{Name: valueNoSuchObject, Latitude: 1, Longitude: 2},
		{Name: valueEndOfMibView, Latitude: 3, Longitude: 4},
	}
	for i := 0; i < 50; i++ {
		got := getRandomLocation()
		if isSNMPExceptionValue(got.Name) {
			t.Fatalf("getRandomLocation returned %q, which encodes as an RFC 3416 exception "+
				"rather than a sysLocation string", got.Name)
		}
		if got.Name != unknownLocationName {
			t.Fatalf("getRandomLocation returned %q, want %q", got.Name, unknownLocationName)
		}
	}

	// Positive control: an ordinary name is served untouched, coordinates and
	// all, so the diversion above is not a blanket rewrite.
	want := WorldCity{Name: "Amsterdam, Netherlands", Latitude: 52.3676, Longitude: 4.9041}
	worldCities = []WorldCity{want}
	if got := getRandomLocation(); got != want {
		t.Errorf("getRandomLocation() = %+v, want %+v", got, want)
	}
}

// TestWorldCitiesRejectsSentinelRows covers the CSV loader's own row skip. It
// drives processCSVFile with a row whose CITY and COUNTRY fields are both a
// sentinel, and asserts what actually happens: the composed display string is
// "noSuchObject, noSuchObject", which is NOT a sentinel, so the row loads. That
// is the documented state of part 3 — see
// TestWorldCitiesLocationCannotComposeToASentinel for why, and
// TestGetRandomLocationNeverServesASentinel for where the rule bites.
func TestWorldCitiesRejectsSentinelRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "1.csv")

	csv := cityRow("noSuchObject", "", "noSuchObject", "1.0", "2.0") +
		cityRow("noSuchObject seen", "", "Atlantis", "5.0", "6.0") +
		cityRow("Amsterdam", "", "Netherlands", "52.3676", "4.9041")
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	loaded := map[string]WorldCity{}
	if err := processCSVFile(path, loaded); err != nil {
		t.Fatalf("processCSVFile: %v", err)
	}
	for n := range loaded {
		if isSNMPExceptionValue(n) {
			t.Errorf("city %q was loaded; it would be served as an RFC 3416 exception "+
				"instead of a sysLocation string", n)
		}
	}
	// The file is not refused over a bad row, and ordinary rows survive.
	if len(loaded) != 3 {
		t.Errorf("loaded %d cities, want 3: a bad row must not cost the file", len(loaded))
	}
}

// TestWorldCitiesLocationCannotComposeToASentinel pins WHY the CSV-side check
// cannot be exercised: processCSVFile always composes "city, country" or
// "city, admin, country", so every display string it can produce contains a
// comma and a space, and no sentinel does. The check there is an invariant
// guard for a future change to the composition, not a live fix — and this test
// is what fails if that composition changes, pointing at the guard.
func TestWorldCitiesLocationCannotComposeToASentinel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "1.csv")

	// Adversarial rows: sentinels in every field, alone and combined, plus the
	// empty-admin and admin==city cases that select the two-field form.
	var csv string
	for _, s := range []string{valueNoSuchObject, valueEndOfMibView} {
		csv += cityRow(s, "", s, "1.0", "2.0")
		csv += cityRow(s, s, s, "1.0", "2.0")
		csv += cityRow(s, "State", s, "1.0", "2.0")
		csv += cityRow(s, "", "", "1.0", "2.0")
		csv += cityRow("", "", s, "1.0", "2.0")
	}
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	loaded := map[string]WorldCity{}
	if err := processCSVFile(path, loaded); err != nil {
		t.Fatalf("processCSVFile: %v", err)
	}
	if len(loaded) == 0 {
		t.Fatal("no row loaded, so the composition was not exercised")
	}
	for n := range loaded {
		if !strings.Contains(n, ", ") {
			t.Errorf("composed location %q has no \", \" separator; a row can now compose to a "+
				"bare field, so the sentinel check in processCSVFile has become reachable and "+
				"needs a test that fires it", n)
		}
		if isSNMPExceptionValue(n) {
			t.Errorf("composed location %q is a sentinel and was loaded", n)
		}
	}

	// And the shipped dataset, for the same property over real data.
	shipped, err := filepath.Glob(filepath.Join("worldcities", "[0-9]*.csv"))
	if err != nil {
		t.Fatalf("glob worldcities: %v", err)
	}
	if len(shipped) == 0 {
		t.Skip("no shipped worldcities dataset in this checkout")
	}
	all := map[string]WorldCity{}
	for _, f := range shipped {
		if err := processCSVFile(f, all); err != nil {
			t.Fatalf("processCSVFile(%s): %v", f, err)
		}
	}
	if len(all) == 0 {
		t.Fatal("shipped dataset loaded no cities")
	}
	for n := range all {
		if isSNMPExceptionValue(n) {
			t.Errorf("shipped city %q collides with an SNMP exception sentinel", n)
		}
	}
	t.Logf("%d shipped locations checked", len(all))
}

// TestWorldCitiesSentinelWouldReachTheWire pins the harm, the way
// TestSentinelValueWouldReachTheWireAsAnException does for resource files: the
// check is worth having only because such a name encodes as an exception tag.
// If encodeTypedValue stops doing that, this test says so.
func TestWorldCitiesSentinelWouldReachTheWire(t *testing.T) {
	const sysLocation = ".1.3.6.1.2.1.1.6.0"

	for v, tag := range map[string]byte{"noSuchObject": 0x80, "endOfMibView": 0x82} {
		got := encodeTypedValue(sysLocation, v)
		if len(got) != 2 || got[0] != tag || got[1] != 0x00 {
			t.Errorf("encodeTypedValue(sysLocation, %q) = % x, want %02x 00", v, got, tag)
		}
	}
	// The fallback list the loader uses when the dataset is absent is
	// compiled-in, so it cannot carry a sentinel; assert it anyway, since it is
	// the one location source no CSV check covers.
	saved := worldCities
	t.Cleanup(func() { worldCities = saved })
	worldCities = nil
	if err := loadWorldCitiesFromMissingDir(t); err != nil {
		t.Fatalf("fallback load: %v", err)
	}
	for _, c := range worldCities {
		if isSNMPExceptionValue(c.Name) {
			t.Errorf("compiled-in fallback city %q collides with a sentinel", c.Name)
		}
	}
	if isSNMPExceptionValue(unknownLocationName) {
		t.Errorf("unknownLocationName %q collides with a sentinel", unknownLocationName)
	}
}

// loadWorldCitiesFromMissingDir runs loadWorldCities from a directory with no
// worldcities/ in it, which is the fallback branch.
func loadWorldCitiesFromMissingDir(t *testing.T) error {
	t.Helper()
	t.Chdir(t.TempDir())
	return loadWorldCities()
}
