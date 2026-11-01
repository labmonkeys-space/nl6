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

// postCreateDevices drives createDevicesHandler against sm and returns the
// recorded response. The euid is faked to a non-root user so a request that
// gets past the handler stops at the privilege check instead of creating TUN
// interfaces on a root CI container.
func postCreateDevices(t *testing.T, sm *SimulatorManager, body string) *httptest.ResponseRecorder {
	t.Helper()
	silenceCreateGateLogs(t)
	withFakeEuid(t, 1000)
	prev := manager
	manager = sm
	t.Cleanup(func() { manager = prev })

	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	createDevicesHandler(w, r)
	return w
}

// An unparseable start_ip is caller data and gets 400 from the handler, before
// the creation batch starts (nl6#940). It used to reach the batch, whose plain
// error createDevicesErrorResponse maps to 500. deviceCreateTotal is written
// only inside the batch, so its staying 0 is what shows the batch never ran.
func TestCreateDevicesHandler_RejectsInvalidStartIPWith400(t *testing.T) {
	for _, startIP := range []string{"not-an-ip", "", "10.42.0.3 cisco_ios.json", "10.42.0.256"} {
		t.Run(startIP, func(t *testing.T) {
			sm := newCreateGateManager()
			body, _ := json.Marshal(CreateDevicesRequest{StartIP: startIP, DeviceCount: 1})
			w := postCreateDevices(t, sm, string(body))

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
			}
			var resp APIResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if want := "invalid start IP address: " + startIP; resp.Success || resp.Message != want {
				t.Errorf("response = {success:%v message:%q}, want {success:false message:%q}", resp.Success, resp.Message, want)
			}
			if got := sm.deviceCreateTotal.Load(); got != 0 {
				t.Errorf("deviceCreateTotal = %v, want 0: the request reached the creation batch", got)
			}
		})
	}
}

// Positive control: a valid start_ip passes the handler's check and reaches the
// batch, so the check above refuses the bad addresses and not every address.
func TestCreateDevicesHandler_ValidStartIPReachesTheBatch(t *testing.T) {
	sm := newCreateGateManager()
	w := postCreateDevices(t, sm, `{"start_ip":"10.42.0.3","device_count":1}`)

	if got := sm.deviceCreateTotal.Load(); got != 1 {
		t.Fatalf("deviceCreateTotal = %v, want 1: a valid start_ip did not reach the batch (status %d, body %s)", got, w.Code, w.Body.String())
	}
}
