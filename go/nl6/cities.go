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
)

// Global list of world cities loaded from CSV file
var worldCities []string

// loadWorldCities loads cities from worldcities directory (split CSV files)
func loadWorldCities() error {
	dirPath := "worldcities"

	// Check if directory exists
	info, err := os.Stat(dirPath)
	if err != nil || !info.IsDir() {
		log.Printf("Failed to open worldcities directory, using fallback cities: %v", err)
		// Fallback to a smaller set of cities if directory is not available
		worldCities = []string{
			"Tokyo, Japan",
			"New York, NY, USA",
			"London, England, UK",
			"Paris, France",
			"Sydney, Australia",
			"Berlin, Germany",
			"Singapore, Singapore",
			"Mumbai, India",
			"São Paulo, Brazil",
			"Moscow, Russia",
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
	uniqueLocations := make(map[string]bool)

	// Process each CSV file
	for _, filePath := range files {
		if err := processCSVFile(filePath, uniqueLocations); err != nil {
			log.Printf("Warning: failed to process %s: %v", filePath, err)
			continue
		}
	}

	// Convert map keys to slice
	worldCities = make([]string, 0, len(uniqueLocations))
	for location := range uniqueLocations {
		worldCities = append(worldCities, location)
	}

	log.Printf("Loaded %d cities from worldcities directory (%d files)", len(worldCities), len(files))
	return nil
}

// processCSVFile reads a single CSV file and adds cities to the uniqueLocations map
func processCSVFile(filePath string, uniqueLocations map[string]bool) error {
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
		if !uniqueLocations[location] {
			uniqueLocations[location] = true
		}
	}

	return nil
}

// getRandomCity returns a random city from the world cities list
func getRandomCity() string {
	// Ensure cities are loaded
	if len(worldCities) == 0 {
		log.Printf("Warning: worldCities not loaded, loading fallback cities")
		err := loadWorldCities()
		if err != nil {
			log.Printf("Error loading cities: %v", err)
		}
	}

	if len(worldCities) == 0 {
		return "Unknown Location"
	}

	return worldCities[mathrand.Intn(len(worldCities))]
}
