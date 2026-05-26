/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDeviceInfoEmitsResourceFile pins the GET /api/v1/devices JSON
// contract: every device record carries the canonical resource_file
// identifier that POST /api/v1/devices accepts. Without this, replaying
// an exported inventory requires reverse-deriving the filename from
// `device_type`, which is a many-to-one display label.
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

	got := string(body)
	if !strings.Contains(got, `"resource_file":"asr9k.json"`) {
		t.Errorf("expected resource_file in JSON, got: %s", got)
	}
}

// TestDeviceInfoOmitsEmptyResourceFile guards the omitempty contract so
// devices without a resolved resource file (theoretical edge case) don't
// emit a noisy "resource_file":"" key.
func TestDeviceInfoOmitsEmptyResourceFile(t *testing.T) {
	info := DeviceInfo{ID: "x", IP: "10.42.0.3", SNMPPort: 161, SSHPort: 22}

	body, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal DeviceInfo: %v", err)
	}

	if strings.Contains(string(body), "resource_file") {
		t.Errorf("expected resource_file to be omitted when empty, got: %s", string(body))
	}
}
