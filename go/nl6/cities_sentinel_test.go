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

// TestSentinelLocationsAreDroppedAtLoad is the enforcement point of nl6#541
// part 3. sysLocation is served outside the resource map, so
// validateSNMPResourceValues cannot see it; the rule is applied once, at load,
// over the assembled slice — which covers the CSV dataset, the compiled-in
// fallback and any source added later, and costs nothing per device.
func TestSentinelLocationsAreDroppedAtLoad(t *testing.T) {
	saved := worldCities
	t.Cleanup(func() { worldCities = saved })

	keep := WorldCity{Name: "Amsterdam, Netherlands", Latitude: 52.3676, Longitude: 4.9041}
	worldCities = []WorldCity{
		{Name: valueNoSuchObject, Latitude: 1, Longitude: 2},
		keep,
		{Name: valueEndOfMibView, Latitude: 3, Longitude: 4},
		{Name: "noSuchObject seen, Atlantis", Latitude: 5, Longitude: 6},
	}
	if dropped := dropSentinelLocations(); dropped != 2 {
		t.Errorf("dropSentinelLocations() = %d, want 2", dropped)
	}
	if len(worldCities) != 2 {
		t.Fatalf("worldCities has %d entries after the filter, want 2: %+v", len(worldCities), worldCities)
	}
	for _, c := range worldCities {
		if isSNMPExceptionValue(c.Name) {
			t.Errorf("city %q survived the filter", c.Name)
		}
	}
	// The near-miss form is ordinary data and must survive, and the ordinary
	// city must keep its COORDINATES — the reason the rule filters at load
	// rather than diverting a draw to the coordinate-less "Unknown Location".
	var found bool
	for _, c := range worldCities {
		if c == keep {
			found = true
		}
	}
	if !found {
		t.Errorf("the ordinary city lost its coordinates or was dropped: %+v", worldCities)
	}
}

// TestGetRandomLocationNeverServesASentinel pins the funnel assertion that
// backs the load-time filter: getRandomLocation is the single path every served
// sysLocation takes, so even a slice populated by some future route cannot get a
// sentinel onto the wire through it.
func TestGetRandomLocationNeverServesASentinel(t *testing.T) {
	saved := worldCities
	t.Cleanup(func() { worldCities = saved })

	// Only sentinels: the bounded retry must give up and fall back, so the test
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

	// One good row among sentinels: the draw must RE-DRAW to it rather than
	// substituting the coordinate-less fallback, since that would cost a device
	// its position over an unrelated row. The retry is BOUNDED (8 attempts), so
	// the assertion is that the good row dominates and that a sentinel never
	// escapes — not that the fallback is unreachable. With one good row in three
	// the bound is missed about (2/3)^8 = 3.9% of the time, so 200 draws expect
	// ~8 fallbacks and the floor below has a wide margin.
	want := WorldCity{Name: "Amsterdam, Netherlands", Latitude: 52.3676, Longitude: 4.9041}
	worldCities = []WorldCity{
		{Name: valueNoSuchObject}, want, {Name: valueEndOfMibView},
	}
	redrawn, fellBack := 0, 0
	for i := 0; i < 200; i++ {
		switch got := getRandomLocation(); {
		case got == want:
			redrawn++
		case got.Name == unknownLocationName:
			fellBack++
		default:
			t.Fatalf("getRandomLocation() = %+v, want either %+v or the %q fallback",
				got, want, unknownLocationName)
		}
	}
	if redrawn < 150 {
		t.Errorf("only %d of 200 draws re-drew to the one good row (%d fell back); a bounded retry "+
			"should reach it about 96%% of the time, so this looks like no retry at all",
			redrawn, fellBack)
	}
	t.Logf("200 draws with 1 good row in 3: %d re-drew, %d fell back to %q",
		redrawn, fellBack, unknownLocationName)

	// Positive control: an ordinary name is served untouched.
	worldCities = []WorldCity{want}
	if got := getRandomLocation(); got != want {
		t.Errorf("getRandomLocation() = %+v, want %+v", got, want)
	}
}

// TestWorldCitiesCSVRowsWithSentinelFieldsStillLoad says what it does, which the
// name TestWorldCitiesRejectsSentinelRows did not: nothing is rejected here. A
// row whose CITY and COUNTRY fields are both a sentinel composes to
// "noSuchObject, noSuchObject", which is not a sentinel, so it loads as ordinary
// data — and that is correct, because it IS ordinary data on the wire.
//
// The rule bites at load over the assembled slice (dropSentinelLocations) and is
// asserted by TestSentinelLocationsAreDroppedAtLoad;
// TestWorldCitiesLocationCannotComposeToASentinel explains why no CSV row can
// reach it.
func TestWorldCitiesCSVRowsWithSentinelFieldsStillLoad(t *testing.T) {
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

// TestSysNameCannotComposeToASentinel is the symmetric test for the other value
// served outside the resource map. The first cut of nl6#541 dismissed sysName as
// "derived from the device, not operator data" — not quite true: the device-name
// generator appends typeSlug, which comes from the caller's `resource_file`.
//
// It is still safe, for two independent structural reasons, and this pins BOTH
// so that losing one is not silently survivable:
//
//  1. Every pattern embeds "-", and no sentinel contains one — the same property
//     TestWorldCitiesLocationCannotComposeToASentinel pins for locations.
//  2. The result is lower-cased, and both sentinels are camelCase, so the
//     strings cannot be equal whatever the slug is.
func TestSysNameCannotComposeToASentinel(t *testing.T) {
	// Adversarial slugs, including the sentinels themselves and the forms a
	// resource_file could legitimately carry.
	slugs := []string{
		"", "cisco_ios", valueNoSuchObject, valueEndOfMibView,
		"nosuchobject", "endofmibview", "NOSUCHOBJECT",
	}

	sawHyphen, sawLower := 0, 0
	for _, slug := range slugs {
		for i := 0; i < 400; i++ {
			name := getRandomDeviceName(slug)
			if isSNMPExceptionValue(name) {
				t.Fatalf("getRandomDeviceName(%q) = %q, which would be served as an RFC 3416 "+
					"exception instead of a sysName string", slug, name)
			}
			if strings.Contains(name, "-") {
				sawHyphen++
			}
			if name == strings.ToLower(name) {
				sawLower++
			}
		}
	}
	want := len(slugs) * 400
	if sawHyphen != want {
		t.Errorf("%d of %d generated names contain no \"-\"; property 1 no longer holds, so the "+
			"only thing keeping a sysName off the exception path is the lower-casing", want-sawHyphen, want)
	}
	if sawLower != want {
		t.Errorf("%d of %d generated names are not lower-cased; property 2 no longer holds", want-sawLower, want)
	}

	// Property 2 stated directly: a sentinel is not lower-case, so no
	// lower-cased string can equal it.
	for _, s := range []string{valueNoSuchObject, valueEndOfMibView} {
		if s == strings.ToLower(s) {
			t.Errorf("sentinel %q is lower-case, so the lower-casing in getRandomDeviceName no "+
				"longer separates it from a device name", s)
		}
	}
}

// TestLoadWorldCitiesPublishesNoSentinel pins the POST-CONDITION of the load
// path over the real shipped dataset: nothing in worldCities may be a sentinel
// after a load.
//
// The WIRING of the filter — that loadWorldCities actually calls it — is pinned
// by TestLoadWorldCitiesFiltersTheFallbackSet below. It could not be, until
// fallbackCities became a package-level var: no CSV row can compose to a
// sentinel (every display string embeds ", ", see
// TestWorldCitiesLocationCannotComposeToASentinel), so the fallback branch is
// the only input a test can drive one through.
//
// What this test adds: if the shipped dataset ever gains a row that DOES compose
// to a sentinel, it fails here rather than at a device's sysLocation.
func TestLoadWorldCitiesPublishesNoSentinel(t *testing.T) {
	saved := worldCities
	t.Cleanup(func() { worldCities = saved })

	worldCities = nil
	if err := loadWorldCities(); err != nil {
		t.Fatalf("loadWorldCities: %v", err)
	}
	if len(worldCities) == 0 {
		t.Fatal("loadWorldCities published nothing, so the post-condition is vacuous")
	}
	for _, c := range worldCities {
		if isSNMPExceptionValue(c.Name) {
			t.Errorf("loadWorldCities published %q, which encodes as an RFC 3416 exception", c.Name)
		}
	}
	t.Logf("%d locations published, none a sentinel", len(worldCities))
}

// TestLoadWorldCitiesFiltersTheFallbackSet pins the WIRING of the load-time
// filter, which nothing could reach before fallbackCities was extracted from
// the body of loadWorldCities: deleting the dropSentinelLocations call used to
// fail no test at all.
//
// The fallback branch is taken when no worldcities/ directory exists, so a
// temp cwd plus a swapped fallback set drives the whole real load path.
func TestLoadWorldCitiesFiltersTheFallbackSet(t *testing.T) {
	savedCities, savedFallback := worldCities, fallbackCities
	t.Cleanup(func() { worldCities, fallbackCities = savedCities, savedFallback })

	keep := WorldCity{Name: "Reykjavik, Iceland", Latitude: 64.1466, Longitude: -21.9426}
	fallbackCities = []WorldCity{
		{Name: valueNoSuchObject, Latitude: 1, Longitude: 2},
		keep,
		{Name: valueEndOfMibView, Latitude: 3, Longitude: 4},
		{Name: "noSuchObject seen, Atlantis", Latitude: 5, Longitude: 6},
	}
	worldCities = nil

	// No worldcities/ here, so loadWorldCities takes the fallback branch.
	t.Chdir(t.TempDir())
	if err := loadWorldCities(); err != nil {
		t.Fatalf("loadWorldCities: %v", err)
	}

	if len(worldCities) != 2 {
		t.Fatalf("loadWorldCities published %d locations, want 2 (two sentinels filtered): %+v",
			len(worldCities), worldCities)
	}
	for _, c := range worldCities {
		if isSNMPExceptionValue(c.Name) {
			t.Errorf("loadWorldCities published %q: the sentinel filter is not wired into the "+
				"load path", c.Name)
		}
	}
	// Coordinates survive, which is why the rule filters here rather than
	// diverting a draw to the coordinate-less fallback name.
	var found bool
	for _, c := range worldCities {
		if c == keep {
			found = true
		}
	}
	if !found {
		t.Errorf("the ordinary city lost its coordinates or was dropped: %+v", worldCities)
	}

	// The filter must not mutate the compiled-in set itself. Its CONTENTS are
	// what to check, not its length: dropSentinelLocations filters in place via
	// worldCities[:0], so an aliased slice keeps its length while its elements
	// are overwritten — a load in the same process would then see a different
	// fleet, with a row duplicated.
	wantFallback := []WorldCity{
		{Name: valueNoSuchObject, Latitude: 1, Longitude: 2},
		keep,
		{Name: valueEndOfMibView, Latitude: 3, Longitude: 4},
		{Name: "noSuchObject seen, Atlantis", Latitude: 5, Longitude: 6},
	}
	if len(fallbackCities) != len(wantFallback) {
		t.Fatalf("fallbackCities has %d rows after the load, want %d", len(fallbackCities), len(wantFallback))
	}
	for i, want := range wantFallback {
		if fallbackCities[i] != want {
			t.Errorf("fallbackCities[%d] = %+v after the load, want %+v: the load path must COPY "+
				"the compiled-in set, not filter it in place", i, fallbackCities[i], want)
		}
	}
}
