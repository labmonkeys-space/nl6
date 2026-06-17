/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProcessCSVFileRetainsCoordinates pins two things at once:
//   - the sysLocation display-string contract (assembly is byte-for-byte the
//     same as before coordinates were retained), and
//   - that latitude/longitude are parsed from CSV cols 2/3, with rows whose
//     coordinates don't parse skipped (same posture as the malformed-row skip).
func TestProcessCSVFileRetainsCoordinates(t *testing.T) {
	// simplemaps-shaped rows: city, ascii, lat, lng, country, iso2, iso3, admin, ...
	csv := strings.Join([]string{
		`"Tokyo","Tokyo","35.6870","139.7495","Japan","JP","JPN","Tokyo","primary","37785000","1392685764"`, // admin==city → simple "City, Country" form
		`"Boston","Boston","42.3601","-71.0589","United States","US","USA","Massachusetts","","675647","1840000455"`,
		`"Bad","Bad","notanumber","0.0","Nowhere","XX","XXX","","","0","0"`, // skipped: lat won't parse
	}, "\n") + "\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "00000.csv")
	if err := os.WriteFile(path, []byte(csv), 0o600); err != nil {
		t.Fatalf("write temp csv: %v", err)
	}

	got := make(map[string]WorldCity)
	if err := processCSVFile(path, got); err != nil {
		t.Fatalf("processCSVFile: %v", err)
	}

	// Display string: simple "City, Country" form, unchanged.
	tok, ok := got["Tokyo, Japan"]
	if !ok {
		t.Fatalf("expected key %q, got %v", "Tokyo, Japan", keysOfWorldCity(got))
	}
	if tok.Latitude != 35.6870 || tok.Longitude != 139.7495 {
		t.Errorf("Tokyo coords = (%v,%v), want (35.6870,139.7495)", tok.Latitude, tok.Longitude)
	}

	// Display string: admin-disambiguated "City, Admin, Country" form, unchanged.
	bos, ok := got["Boston, Massachusetts, United States"]
	if !ok {
		t.Fatalf("expected key %q, got %v", "Boston, Massachusetts, United States", keysOfWorldCity(got))
	}
	if bos.Latitude != 42.3601 || bos.Longitude != -71.0589 {
		t.Errorf("Boston coords = (%v,%v), want (42.3601,-71.0589)", bos.Latitude, bos.Longitude)
	}

	if len(got) != 2 {
		t.Errorf("retained %d cities, want 2 (the unparseable-coord row must be skipped)", len(got))
	}
}

// TestListDevicesGeolocation pins the GET /api/v1/devices geolocation
// contract: a resolved location emits location+lat+lng; a true 0,0 is
// reported (not dropped); the unknown sentinel and an unset location omit
// the coordinate pair.
func TestListDevicesGeolocation(t *testing.T) {
	sm := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
	}

	mk := func(id string, ipLast byte, loc *WorldCity) *DeviceSimulator {
		d := &DeviceSimulator{ID: id, IP: net.IPv4(10, 42, 0, ipLast), SNMPPort: 161, SSHPort: 22}
		if loc != nil {
			d.cachedLocation.Store(*loc)
		}
		return d
	}
	sm.devices["real"] = mk("real", 1, &WorldCity{Name: "Amsterdam, Netherlands", Latitude: 52.3676, Longitude: 4.9041})
	sm.devices["zero"] = mk("zero", 2, &WorldCity{Name: "Null Island, Nowhere", Latitude: 0, Longitude: 0})
	sm.devices["unknown"] = mk("unknown", 3, &WorldCity{Name: unknownLocationName})
	sm.devices["unset"] = mk("unset", 4, nil)

	byID := map[string]DeviceInfo{}
	for _, info := range sm.ListDevices() {
		byID[info.ID] = info
	}

	// Resolved location: all three fields present and correct.
	if d := byID["real"]; d.Location != "Amsterdam, Netherlands" ||
		d.Latitude == nil || d.Longitude == nil || *d.Latitude != 52.3676 || *d.Longitude != 4.9041 {
		t.Errorf("real device geolocation = %+v (lat/lng deref), want Amsterdam 52.3676/4.9041", d)
	}

	// True 0,0 must be reported as present, not omitted.
	if d := byID["zero"]; d.Latitude == nil || d.Longitude == nil || *d.Latitude != 0 || *d.Longitude != 0 {
		t.Errorf("zero device must report coordinates 0,0 as present, got lat=%v lng=%v", d.Latitude, d.Longitude)
	}

	// Unknown sentinel: location string present, coordinates omitted.
	if d := byID["unknown"]; d.Location != unknownLocationName || d.Latitude != nil || d.Longitude != nil {
		t.Errorf("unknown device should carry name without coords, got %+v", d)
	}

	// Unset: nothing emitted, and JSON omits the keys.
	d := byID["unset"]
	if d.Location != "" || d.Latitude != nil || d.Longitude != nil {
		t.Errorf("unset device should have empty location and nil coords, got %+v", d)
	}
	body, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"location", "latitude", "longitude"} {
		if _, present := raw[k]; present {
			t.Errorf("key %q must be omitted for unset location, body=%s", k, body)
		}
	}
}

// TestBothCreationPathsCacheLocation guards the device-creation-path
// divergence documented in feedback_device_creation_paths: the sequential
// (CreateDevicesWithOptions) and parallel (createSingleDevice) paths have
// drifted before. Every site that caches sysLocation MUST also cache the
// WorldCity, so the device API never reports a location string without its
// coordinates. Source-level because the real paths require root/netns.
func TestBothCreationPathsCacheLocation(t *testing.T) {
	src, err := os.ReadFile("device.go")
	if err != nil {
		t.Fatalf("read device.go: %v", err)
	}
	sysLoc := strings.Count(string(src), "cachedSysLocation.Store(")
	loc := strings.Count(string(src), "cachedLocation.Store(")
	if sysLoc < 2 {
		t.Fatalf("expected ≥2 cachedSysLocation.Store sites (both creation paths), found %d", sysLoc)
	}
	if loc != sysLoc {
		t.Errorf("cachedLocation.Store sites (%d) must match cachedSysLocation.Store sites (%d): "+
			"a creation path caches sysLocation without caching coordinates", loc, sysLoc)
	}
}

func keysOfWorldCity(m map[string]WorldCity) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
