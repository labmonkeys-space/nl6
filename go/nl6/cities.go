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

	log.Printf("Loaded %d cities from worldcities directory (%d files)", len(worldCities), len(files))
	return nil
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

	return worldCities[mathrand.Intn(len(worldCities))]
}
