/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/csv"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDeviceInfoEmitsResourceFile pins the GET /api/v1/devices JSON
// contract: every POST-created device record carries the canonical
// resource_file identifier that POST /api/v1/devices accepts. Without
// this, replaying an exported inventory requires reverse-deriving the
// filename from `device_type`, which is a many-to-one display label.
func TestDeviceInfoEmitsResourceFile(t *testing.T) {
	info := DeviceInfo{
		ID:           "asr9k-10.42.0.3",
		IP:           "10.42.0.3",
		SNMPPort:     161,
		SSHPort:      22,
		Running:      true,
		ResourceFile: "asr9k.json",
		DeviceType:   "Cisco ASR9K",
	}

	body, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal DeviceInfo: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal DeviceInfo: %v", err)
	}

	raw, ok := got["resource_file"]
	if !ok {
		t.Fatalf("expected resource_file key in JSON, got keys: %v", keysOf(got))
	}
	var val string
	if err := json.Unmarshal(raw, &val); err != nil {
		t.Fatalf("resource_file is not a JSON string: %v", err)
	}
	if val != "asr9k.json" {
		t.Errorf("resource_file = %q, want %q", val, "asr9k.json")
	}
}

// TestDeviceInfoOmitsEmptyResourceFile guards the omitempty contract.
// Devices created via the -auto-start-ip CLI path carry an empty
// resource_file (no -resource-file flag exists); the JSON must omit
// the key rather than emit "resource_file": "". The docs note this
// carve-out — keep the two in sync.
func TestDeviceInfoOmitsEmptyResourceFile(t *testing.T) {
	info := DeviceInfo{ID: "x", IP: "10.42.0.3", SNMPPort: 161, SSHPort: 22}

	body, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal DeviceInfo: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal DeviceInfo: %v", err)
	}
	if _, present := got["resource_file"]; present {
		t.Errorf("resource_file should be omitted when empty, got: %s", string(body))
	}
}

// TestExportDevicesCSV pins the CSV column order — header AND data
// rows — so any downstream consumer that indexes columns positionally
// (`awk -F,`, spreadsheets, parsers keyed by position) does not break
// silently. "Resource File" is the last column by design (additive at
// the end, not inserted mid-row). The data-row assertions catch a
// future regression where headers stay correct but the row writer
// swaps two adjacent values.
//
// Uses `swapGlobalManager` (interface_state_api_test.go) rather than
// an inline swap so this test serializes correctly with any other
// test that mutates the package-level `manager` global.
func TestExportDevicesCSV(t *testing.T) {
	sm := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
	}
	// Two fixtures: one with an explicit resource file, one with an
	// empty one (mirrors the auto-start path) to exercise the "N/A"
	// fallback.
	sm.devices["asr"] = &DeviceSimulator{
		ID: "asr9k-10.42.0.3", IP: net.IPv4(10, 42, 0, 3),
		SNMPPort: 161, SSHPort: 22, resourceFile: "asr9k.json",
	}
	sm.devices["def"] = &DeviceSimulator{
		ID: "default-10.42.0.4", IP: net.IPv4(10, 42, 0, 4),
		SNMPPort: 161, SSHPort: 22, // resourceFile == "" → N/A
	}
	t.Cleanup(swapGlobalManager(sm))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/export", nil)
	exportDevicesCSVHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	records, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}

	wantHeader := []string{"Device ID", "IP Address", "Interface", "SNMP Port", "SSH Port", "Status", "Resource File"}
	if len(records) != 1+len(sm.devices) {
		t.Fatalf("row count = %d, want %d (header + %d devices)", len(records), 1+len(sm.devices), len(sm.devices))
	}
	for i, col := range wantHeader {
		if records[0][i] != col {
			t.Errorf("header[%d] = %q, want %q", i, records[0][i], col)
		}
	}

	// Map iteration order in ListDevices is undefined; index data
	// rows by Device ID before asserting positional content.
	rowsByID := map[string][]string{}
	for _, row := range records[1:] {
		if len(row) != len(wantHeader) {
			t.Errorf("row %q has %d columns, want %d", row[0], len(row), len(wantHeader))
		}
		rowsByID[row[0]] = row
	}

	wantRows := map[string][]string{
		"asr9k-10.42.0.3":   {"asr9k-10.42.0.3", "10.42.0.3", "N/A", "161", "22", "Stopped", "asr9k.json"},
		"default-10.42.0.4": {"default-10.42.0.4", "10.42.0.4", "N/A", "161", "22", "Stopped", "N/A"},
	}
	for id, want := range wantRows {
		got, ok := rowsByID[id]
		if !ok {
			t.Errorf("missing row for %q", id)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("row %q column[%d] = %q, want %q", id, i, got[i], want[i])
			}
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
