/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// createDevicesHandler validates if_error_scenario BEFORE touching
// manager state. An unknown value must atomically reject the batch
// with 400 and leave the manager untouched — we don't even need a
// real manager for this test.
// Covers spec Requirement 4 "Unknown scenario rejects the batch".
func TestCreateDevicesHandler_RejectsUnknownIfErrorScenario(t *testing.T) {
	// manager is deliberately left at whatever state it was in; the
	// test path never reaches any manager method.
	body, _ := json.Marshal(CreateDevicesRequest{
		StartIP:         "10.0.0.1",
		DeviceCount:     1,
		Netmask:         "24",
		IfErrorScenario: "banana",
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
	w := httptest.NewRecorder()

	createDevicesHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown scenario", w.Code)
	}

	var resp APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Success {
		t.Error("APIResponse.Success = true; want false on 400")
	}
	if resp.Message == "" {
		t.Error("APIResponse.Message empty; should name the accepted scenarios for self-service debugging")
	}
}
