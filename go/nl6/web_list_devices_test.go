/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/csv"
	"encoding/json"
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

// TestExportDevicesCSVHeaderOrder pins the CSV column order so any
// downstream consumer that indexes columns positionally
// (`cut -f2`, spreadsheets, parsers keyed by position) does not break
// silently on a future column addition. "Resource File" is the last
// column by design (additive at the end, not inserted mid-row).
func TestExportDevicesCSVHeaderOrder(t *testing.T) {
	prev := manager
	manager = &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
	}
	t.Cleanup(func() { manager = prev })

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
	if len(records) == 0 {
		t.Fatalf("expected at least a header row, got empty CSV")
	}

	want := []string{"Device ID", "IP Address", "Interface", "SNMP Port", "SSH Port", "Status", "Resource File"}
	got := records[0]
	if len(got) != len(want) {
		t.Fatalf("header column count = %d, want %d; got=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("header[%d] = %q, want %q", i, got[i], want[i])
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
