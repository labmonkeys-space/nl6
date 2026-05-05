/*
 * © 2025 Labmonkeys Space
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

// FieldResolver provides the Class 1 device-context template fields
// (SysName, Model, Serial, ChassisID, IfName) consumed by the unified
// trap and syslog template vocabulary (design.md §D3/D4).
//
// Class 1 fields are device-scoped and either constant for a device's
// lifetime (SysName, Model, Serial, ChassisID — captured at exporter
// construction) or computed per fire from the drawn IfIndex (IfName,
// which today synthesises a generic name and will swap to live ifDescr
// lookup in PR 3). Class 2 random-per-fire fields (PeerIP, User,
// SourceIP, RuleName, …) are deferred to a follow-up change.
//
// The interface is narrow so tests can inject a stub FieldResolver
// without building a full SimulatorManager.

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// FieldResolver resolves device-context template fields for a single
// fire. Implementations MUST be safe for concurrent use.
type FieldResolver interface {
	// SysName returns the device's sysName.0 value as captured at device
	// construction, or empty string when the device is unknown.
	SysName(deviceIP string) string

	// Model returns a human-readable model string derived from the
	// device's type slug (e.g. `cisco_ios` → `Cisco IOS`). Unknown
	// slugs fall back to a title-cased slug.
	Model(deviceIP string) string

	// Serial returns a deterministic serial synthesised from the
	// device's IPv4 (stable for the device's lifetime, distinct across
	// devices). Format: `SN` + 8 hex digits.
	Serial(deviceIP string) string

	// ChassisID returns a deterministic MAC-style chassis identifier
	// synthesised from the device's IPv4 (02:xx:xx:xx:xx:xx where the
	// last 4 octets encode the IPv4). Stable per device.
	ChassisID(deviceIP string) string

	// IfName returns the interface name for the given ifIndex. PR 2
	// keeps the pre-existing synthesis (`GigabitEthernet0/<N>`); PR 3
	// swaps this to a live lookup against the device's SNMP OID table
	// at `ifDescr.<N>` with synthesis as fallback.
	IfName(deviceIP string, ifIndex int) string
}

// synthSerial produces a deterministic, stable-per-device serial from
// the device's IPv4. `SN` + 8 hex digits; collision-free across the
// entire IPv4 space. Broken into its own function so tests can pin the
// exact format without constructing a full SimulatorManager.
func synthSerial(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("SN%08X", binary.BigEndian.Uint32(v4))
}

// synthChassisID produces a deterministic, stable-per-device MAC-style
// chassis identifier from the device's IPv4. Prefix `02` marks the
// address as locally-administered (RFC 7042 §2.1) so it never collides
// with any real hardware OUI; the remaining 5 octets encode a constant
// byte plus the IPv4 so different simulator instances don't produce
// identical chassis IDs on different subnets.
func synthChassisID(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("02:42:%02x:%02x:%02x:%02x", v4[0], v4[1], v4[2], v4[3])
}

// synthIfName is the fallback interface name used when a real
// `ifDescr.<IfIndex>` lookup is unavailable (PR 2) or misses (PR 3+).
// Format matches the pre-per-type-catalog syslog synthesis so
// byte-identity pins for existing catalogs remain green.
func synthIfName(ifIndex int) string {
	return fmt.Sprintf("GigabitEthernet0/%d", ifIndex)
}

// deviceTypeLabels maps known device-type slugs (the lowercase
// directory names under `resources/`) to their human-readable model
// strings used for `{{.Model}}` template resolution. Slugs not present
// here fall back to a title-cased version of the slug.
//
// Kept in lockstep with `resources/<slug>/` directories — adding a new
// device type should add an entry here so `{{.Model}}` renders a clean
// marketing-style name rather than the raw slug.
var deviceTypeLabels = map[string]string{
	"arista_7280r3":             "Arista 7280R3",
	"asr9k":                     "Cisco ASR 9000",
	"aws_s3_storage":            "AWS S3",
	"check_point_15600":         "Check Point 15600",
	"cisco_catalyst_9500":       "Cisco Catalyst 9500",
	"cisco_crs_x":               "Cisco CRS-X",
	"cisco_ios":                 "Cisco IOS",
	"cisco_nexus_9500":          "Cisco Nexus 9500",
	"dell_emc_unity":            "Dell EMC Unity",
	"dell_poweredge_r750":       "Dell PowerEdge R750",
	"dlink_dgs3630":             "D-Link DGS-3630",
	"extreme_vsp4450":           "Extreme VSP 4450",
	"fortinet_fortigate_600e":   "Fortinet FortiGate 600E",
	"hpe_proliant_dl380":        "HPE ProLiant DL380",
	"huawei_ne8000":             "Huawei NE8000",
	"ibm_power_s922":            "IBM Power S922",
	"juniper_mx240":             "Juniper MX240",
	"juniper_mx960":             "Juniper MX960",
	"linux_server":              "Linux Server",
	"nec_ix3315":                "NEC IX3315",
	"netapp_ontap":              "NetApp ONTAP",
	"nokia_7750_sr12":           "Nokia 7750 SR-12",
	"nvidia_dgx_a100":           "NVIDIA DGX A100",
	"nvidia_dgx_h100":           "NVIDIA DGX H100",
	"nvidia_hgx_h200":           "NVIDIA HGX H200",
	"palo_alto_pa3220":          "Palo Alto PA-3220",
	"pure_storage_flasharray":   "Pure Storage FlashArray",
	"sonicwall_nsa6700":         "SonicWall NSA 6700",
}

// modelLabelForSlug returns the human-readable model string for a
// device-type slug. Falls back to a title-cased transformation of the
// slug when no entry is registered — this keeps `{{.Model}}` non-empty
// for test fixtures that invent new slugs.
func modelLabelForSlug(slug string) string {
	if slug == "" {
		return ""
	}
	if label, ok := deviceTypeLabels[slug]; ok {
		return label
	}
	// Fallback: replace `_` with space and title-case each word. Not
	// perfect for acronyms but good enough for unknowns.
	words := strings.Split(slug, "_")
	for i, w := range words {
		if len(w) == 0 {
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}

// Compile-time check: SimulatorManager satisfies FieldResolver. If a
// method is renamed or removed the build breaks here rather than
// silently at a future call site.
var _ FieldResolver = (*SimulatorManager)(nil)

// SimulatorManager implements FieldResolver. Methods are safe for
// concurrent use — they read device state under `sm.mu.RLock` and call
// only deterministic synth helpers otherwise.

// SysName returns the SysName captured at device construction for the
// device at the given IP, or "" when unknown.
func (sm *SimulatorManager) SysName(deviceIP string) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, d := range sm.devices {
		if d.IP.String() == deviceIP {
			return d.sysName
		}
	}
	return ""
}

// Model returns a human-readable model string for the device at the
// given IP. Uses `deviceTypesByIP` (populated at device construction)
// for O(1) slug lookup; falls back to an empty string for unknown IPs.
func (sm *SimulatorManager) Model(deviceIP string) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	slug, ok := sm.deviceTypesByIP[deviceIP]
	if !ok {
		return ""
	}
	return modelLabelForSlug(slug)
}

// Serial — see FieldResolver.
func (sm *SimulatorManager) Serial(deviceIP string) string {
	ip := net.ParseIP(deviceIP)
	if ip == nil {
		return ""
	}
	return synthSerial(ip)
}

// ChassisID — see FieldResolver.
func (sm *SimulatorManager) ChassisID(deviceIP string) string {
	ip := net.ParseIP(deviceIP)
	if ip == nil {
		return ""
	}
	return synthChassisID(ip)
}

// IfName — see FieldResolver. Live-lookup path: resolves the device by
// IP, reads `ifDescr.<ifIndex>` (OID `1.3.6.1.2.1.2.2.1.2.N`) from the
// device's SNMP OID table, and falls back to `synthIfName` when the
// OID is absent. The exporter hot path uses `deviceIfNameFn` directly
// (which also wraps `lookupIfDescr`); this method exists mostly for
// test injection and future callers that want a single resolver
// surface.
//
// Lookup is O(N) in the device map because `sm.devices` is keyed by
// device ID, not IP — this is not the exporter hot path, so the cost is
// acceptable here (see deviceIfNameFn for the hot-path companion).
func (sm *SimulatorManager) IfName(deviceIP string, ifIndex int) string {
	if ifIndex <= 0 {
		return ""
	}
	sm.mu.RLock()
	var device *DeviceSimulator
	for _, d := range sm.devices {
		if d.IP.String() == deviceIP {
			device = d
			break
		}
	}
	sm.mu.RUnlock()
	if name := lookupIfDescr(device, ifIndex); name != "" {
		return name
	}
	return synthIfName(ifIndex)
}
