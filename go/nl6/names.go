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
	"fmt"
	mathrand "math/rand"
	"path/filepath"
	"strings"
)

// resourceDirName turns a resource filename (e.g. "cisco_catalyst_9500.json")
// into the per-device-type directory name as it appears on disk under
// `resources/` (e.g. "cisco_catalyst_9500"). Underscores are preserved — this
// is the key used for per-type catalog overlays (trap / syslog) and must
// match the resource-tree layout exactly. Returns "" for empty input.
func resourceDirName(resourceFile string) string {
	if resourceFile == "" {
		return ""
	}
	name := strings.ToLower(filepath.Base(resourceFile))
	return strings.TrimSuffix(name, ".json")
}

// slugifyDeviceType turns a resource filename (e.g. "cisco_catalyst_9500.json")
// into a lowercase, URL-/hostname-safe slug (e.g. "cisco-catalyst-9500").
// Any character outside [a-z0-9-] becomes '-', consecutive hyphens collapse,
// and leading/trailing hyphens are trimmed. Returns "" when resourceFile is
// empty or the result would be empty.
func slugifyDeviceType(resourceFile string) string {
	if resourceFile == "" {
		return ""
	}
	name := strings.ToLower(filepath.Base(resourceFile))
	name = strings.TrimSuffix(name, ".json")
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	result := b.String()
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	return strings.Trim(result, "-")
}

// Global lists for generating random device names
var devicePrefixes = []string{
	"CORE", "EDGE", "ACCESS", "DIST", "AGG", "LEAF", "SPINE", "BORDER", "PE", "CE",
	"WAN", "LAN", "DMZ", "MGMT", "OOB", "BACKUP", "PRIMARY", "SECONDARY", "MAIN", "AUX",
	"HQ", "DC", "BR", "SITE", "CAMPUS", "BLDG", "FLOOR", "RACK", "ROW", "ZONE",
	"NORTH", "SOUTH", "EAST", "WEST", "CENTRAL", "UPPER", "LOWER", "FRONT", "REAR", "MID",
	"PROD", "DEV", "TEST", "STAGE", "LAB", "DEMO", "PILOT", "TRAIN", "TEMP", "MAINT",
}

var deviceTypes = []string{
	"RTR", "SWH", "FWL", "LB", "AP", "GW", "PX", "SRV", "HOST", "NODE",
	"ROUTER", "SWITCH", "FIREWALL", "PROXY", "GATEWAY", "BRIDGE", "HUB", "REPEATER", "MODEM", "ADAPTER",
}

var deviceLocations = []string{
	"NYC", "LAX", "CHI", "MIA", "SEA", "DEN", "ATL", "BOS", "PHX", "DAL",
	"LON", "PAR", "FRA", "AMS", "MAD", "ROM", "BER", "VIE", "ZUR", "MIL",
	"TOK", "SIN", "HKG", "SYD", "MEL", "BOM", "DEL", "BLR", "HYD", "CHE",
	"TOR", "VAN", "MTL", "CAL", "EDM", "WPG", "HAL", "OTT", "QUE", "SAS",
}

var animalNames = []string{
	"WOLF", "TIGER", "EAGLE", "HAWK", "LION", "BEAR", "SHARK", "FALCON", "LYNX", "PANTHER",
	"COBRA", "VIPER", "PYTHON", "MAMBA", "DRAGON", "PHOENIX", "GRIFFIN", "PEGASUS", "HYDRA", "KRAKEN",
	"RHINO", "BUFFALO", "BISON", "MOOSE", "STAG", "BUCK", "RAM", "BULL", "STALLION", "MUSTANG",
}

var mythNames = []string{
	"ATLAS", "TITAN", "HERCULES", "APOLLO", "ARES", "ZEUS", "THOR", "ODIN", "LOKI", "FREYA",
	"ARTEMIS", "ATHENA", "DIANA", "MARS", "VENUS", "NEPTUNE", "PLUTO", "MERCURY", "SATURN", "JUPITER",
	"ORION", "ANDROMEDA", "CASSIOPEIA", "VEGA", "ALTAIR", "SIRIUS", "RIGEL", "BETELGEUSE", "POLARIS", "ANTARES",
}

// getRandomDeviceName generates a random device name using various patterns.
// When typeSlug is non-empty it is appended as a suffix (e.g. "-cisco-catalyst-9500").
// The result is always lowercase.
func getRandomDeviceName(typeSlug string) string {

	// Choose a random pattern for the device name
	patterns := []func() string{
		// Pattern 1: PREFIX-TYPE-NUMBER (e.g., CORE-RTR-01)
		func() string {
			prefix := devicePrefixes[mathrand.Intn(len(devicePrefixes))]
			devType := deviceTypes[mathrand.Intn(len(deviceTypes))]
			number := mathrand.Intn(99) + 1
			return fmt.Sprintf("%s-%s-%02d", prefix, devType, number)
		},
		// Pattern 2: LOCATION-PREFIX-NUMBER (e.g., NYC-CORE-03)
		func() string {
			location := deviceLocations[mathrand.Intn(len(deviceLocations))]
			prefix := devicePrefixes[mathrand.Intn(len(devicePrefixes))]
			number := mathrand.Intn(99) + 1
			return fmt.Sprintf("%s-%s-%02d", location, prefix, number)
		},
		// Pattern 3: ANIMAL-NUMBER (e.g., WOLF-07)
		func() string {
			animal := animalNames[mathrand.Intn(len(animalNames))]
			number := mathrand.Intn(99) + 1
			return fmt.Sprintf("%s-%02d", animal, number)
		},
		// Pattern 4: MYTH-LOCATION (e.g., ATLAS-NYC)
		func() string {
			myth := mythNames[mathrand.Intn(len(mythNames))]
			location := deviceLocations[mathrand.Intn(len(deviceLocations))]
			return fmt.Sprintf("%s-%s", myth, location)
		},
		// Pattern 5: PREFIX-LOCATION-TYPE (e.g., CORE-NYC-SWH)
		func() string {
			prefix := devicePrefixes[mathrand.Intn(len(devicePrefixes))]
			location := deviceLocations[mathrand.Intn(len(deviceLocations))]
			devType := deviceTypes[mathrand.Intn(len(deviceTypes))]
			return fmt.Sprintf("%s-%s-%s", prefix, location, devType)
		},
		// Pattern 6: TYPE-ANIMAL-NUMBER (e.g., RTR-HAWK-12)
		func() string {
			devType := deviceTypes[mathrand.Intn(len(deviceTypes))]
			animal := animalNames[mathrand.Intn(len(animalNames))]
			number := mathrand.Intn(99) + 1
			return fmt.Sprintf("%s-%s-%02d", devType, animal, number)
		},
	}

	// Select a random pattern and generate the name
	pattern := patterns[mathrand.Intn(len(patterns))]
	name := pattern()
	if typeSlug != "" {
		name = name + "-" + typeSlug
	}
	return strings.ToLower(name)
}
