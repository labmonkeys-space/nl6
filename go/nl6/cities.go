/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"encoding/csv"
	"fmt"
	"log"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// WorldCity is a loaded location: the display string served as sysLocation
// plus the coordinates retained from the source dataset.
type WorldCity struct {
	Name      string  // display string, e.g. "Amsterdam, Netherlands"
	Latitude  float64 // decimal degrees
	Longitude float64 // decimal degrees
}

// unknownLocationName is the sentinel display string used when no dataset is
// available. It carries no coordinates, so consumers omit lat/lng for it.
const unknownLocationName = "Unknown Location"

// Global list of world cities loaded from CSV file
var worldCities []WorldCity

// loadWorldCities loads cities from worldcities directory (split CSV files)
func loadWorldCities() error {
	dirPath := "worldcities"

	// Check if directory exists
	info, err := os.Stat(dirPath)
	if err != nil || !info.IsDir() {
		log.Printf("Failed to open worldcities directory, using fallback cities: %v", err)
		// Fallback to a smaller set of cities if directory is not available
		worldCities = []WorldCity{
			{"Tokyo, Japan", 35.6870, 139.7495},
			{"New York, NY, USA", 40.6943, -73.9249},
			{"London, England, UK", 51.5072, -0.1275},
			{"Paris, France", 48.8566, 2.3522},
			{"Sydney, Australia", -33.8678, 151.2100},
			{"Berlin, Germany", 52.5167, 13.3833},
			{"Singapore, Singapore", 1.3000, 103.8000},
			{"Mumbai, India", 19.0758, 72.8775},
			{"São Paulo, Brazil", -23.5500, -46.6333},
		}
		// Compiled-in constants, so this can never fire — but the filter is
		// applied to the slice rather than to a source, and running it on both
		// branches is what makes that true of every branch.
		dropSentinelLocations()
		return nil
	}

	// Find all numbered CSV files in the directory
	files, err := filepath.Glob(filepath.Join(dirPath, "[0-9]*.csv"))
	if err != nil {
		return fmt.Errorf("failed to list CSV files: %v", err)
	}

	// Sort files to ensure consistent ordering
	sort.Strings(files)

	// Use a map to ensure uniqueness and avoid duplicate city-country combinations
	uniqueLocations := make(map[string]WorldCity)

	// Process each CSV file
	for _, filePath := range files {
		if err := processCSVFile(filePath, uniqueLocations); err != nil {
			log.Printf("Warning: failed to process %s: %v", filePath, err)
			continue
		}
	}

	// Convert map values to slice
	worldCities = make([]WorldCity, 0, len(uniqueLocations))
	for _, city := range uniqueLocations {
		worldCities = append(worldCities, city)
	}
	dropped := dropSentinelLocations()

	log.Printf("Loaded %d cities from worldcities directory (%d files)", len(worldCities), len(files))
	if dropped > 0 {
		log.Printf("Warning: dropped %d city name(s) colliding with an SNMP exception sentinel", dropped)
	}
	return nil
}

// dropSentinelLocations removes any loaded location whose display string is
// exactly an RFC 3416 exception sentinel, and returns how many it removed.
//
// This is the ONE place the rule costs anything: it runs once per load, over the
// whole dataset, rather than on the per-device draw. The first cut of nl6#541
// put the check in getRandomLocation only, which is a per-device path — up to
// 30,000 log lines at fleet start, one per draw, with the offending row still in
// the slice to be drawn again. Filtering here also keeps the drawn city's
// COORDINATES: diverting at draw time returned the coordinate-less "Unknown
// Location", so one bad row silently cost a device its lat/lng.
//
// It covers both branches of loadWorldCities — the CSV dataset and the
// compiled-in fallback list — because both feed the same slice.
func dropSentinelLocations() int {
	kept := worldCities[:0]
	dropped := 0
	for _, c := range worldCities {
		if isSNMPExceptionValue(c.Name) {
			log.Printf("Warning: dropping location %q: the name collides with an SNMP exception "+
				"sentinel and would be served as an RFC 3416 exception instead of a sysLocation "+
				"string", c.Name)
			dropped++
			continue
		}
		kept = append(kept, c)
	}
	worldCities = kept
	return dropped
}

// processCSVFile reads a single CSV file and adds cities to the uniqueLocations map
func processCSVFile(filePath string, uniqueLocations map[string]WorldCity) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read CSV: %v", err)
	}

	for _, record := range records {
		if len(record) < 5 {
			continue // Skip malformed rows
		}

		// Coordinates live in cols 2 (lat) / 3 (lng); skip rows whose
		// coordinates don't parse, mirroring the malformed-row skip above.
		lat, latErr := strconv.ParseFloat(record[2], 64)
		lng, lngErr := strconv.ParseFloat(record[3], 64)
		if latErr != nil || lngErr != nil {
			continue
		}

		city := record[0]    // city name
		country := record[4] // country name
		adminName := ""
		if len(record) > 7 {
			adminName = record[7] // admin_name (state/province)
		}

		// Create location string with more detail for disambiguation
		var location string
		if adminName != "" && adminName != city && adminName != country {
			// Include state/province for better distinction (e.g., "Boston, Massachusetts, United States")
			location = fmt.Sprintf("%s, %s, %s", city, adminName, country)
		} else {
			// Simple city, country format
			location = fmt.Sprintf("%s, %s", city, country)
		}

		// nl6#541 part 3: sysLocation is served through encodeTypedValue, and
		// the RFC 3416 exceptions travel to that encoder as strings in the
		// VALUE space, so a display string exactly equal to one of them would
		// be answered as an exception tag rather than as the string it is —
		// the hazard validateSNMPResourceValues refuses for resource files,
		// reaching the wire by a different route.
		//
		// The ROW is rejected rather than the file, unlike the resource-file
		// guard: this dataset is tens of thousands of operator-supplied rows
		// that the loader already skips individually when they are malformed,
		// and one unusable city name is not a reason to leave a fleet with no
		// locations at all. The skip is logged, because a silently dropped row
		// is indistinguishable from a city the dataset never had.
		//
		// Not reachable with today's composition: every display string above
		// embeds ", ", so no row can compose to a sentinel
		// (TestWorldCitiesLocationCannotComposeToASentinel pins that, and is
		// the reason this is an invariant guard rather than a live fix). The
		// enforcement point a served value actually passes through is
		// getRandomLocation; this check exists so the diagnosis names the file
		// and the row if the composition ever changes.
		if isSNMPExceptionValue(location) {
			log.Printf("Warning: %s: skipping city row %q: the name collides with an SNMP "+
				"exception sentinel and would be served as an RFC 3416 exception instead of "+
				"a sysLocation string", filePath, location)
			continue
		}

		// Only add if we haven't seen this exact location before
		if _, seen := uniqueLocations[location]; !seen {
			uniqueLocations[location] = WorldCity{Name: location, Latitude: lat, Longitude: lng}
		}
	}

	return nil
}

// getRandomLocation returns a random world city (name + coordinates) from the
// loaded list. When the dataset is empty it returns a coordinate-less
// "Unknown Location" sentinel so callers always get a usable display string.
func getRandomLocation() WorldCity {
	// Ensure cities are loaded
	if len(worldCities) == 0 {
		log.Printf("Warning: worldCities not loaded, loading fallback cities")
		err := loadWorldCities()
		if err != nil {
			log.Printf("Error loading cities: %v", err)
		}
	}

	if len(worldCities) == 0 {
		return WorldCity{Name: unknownLocationName}
	}

	// The rule is ENFORCED at load (dropSentinelLocations), so by here the slice
	// cannot hold a sentinel. This is the last-line assertion on the single
	// funnel every served sysLocation passes through — cheap, because it is one
	// string comparison per device rather than a scan, and silent, because a
	// per-draw log line on a 30,000-device path is a worse failure than the one
	// it reports.
	//
	// It RE-DRAWS rather than substituting "Unknown Location": that name carries
	// no coordinates (manager.go omits lat/lng for it), so substituting would
	// cost the device its position over an unrelated row's defect. The bounded
	// retry then falls back, since a slice of nothing but sentinels has no
	// answer to give.
	for attempt := 0; attempt < 8; attempt++ {
		city := worldCities[mathrand.Intn(len(worldCities))]
		if !isSNMPExceptionValue(city.Name) {
			return city
		}
	}
	return WorldCity{Name: unknownLocationName}
}
