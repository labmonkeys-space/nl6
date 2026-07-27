/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// optical_api_test.go — POST /api/v1/devices/{ip}/optical/{component}/degrade
// (#334, task 5.4 / 5.6-5.7 REST halves).

type degradeFixture struct {
	mgr     *SimulatorManager
	optical *DeviceSimulator
	packet  *DeviceSimulator
	router  http.Handler
}

// newDegradeFixture wires one optical device (10.42.0.1) and one packet
// device (10.42.0.2) behind the real router, so the tests exercise routing
// and status codes rather than the handler in isolation.
func newDegradeFixture(t *testing.T) *degradeFixture {
	t.Helper()

	omc := &MetricsCycler{}
	omc.InitOpticalCycler(twoChannelInventory(), 5, opticalBandFor(OpticalClean))
	optical := &DeviceSimulator{
		ID: "optical-device", IP: net.IPv4(10, 42, 0, 1),
		resourceFile: opticalResourceFile, metricsCycler: omc,
	}

	packet := &DeviceSimulator{
		ID: "packet-device", IP: net.IPv4(10, 42, 0, 2),
		resourceFile: "cisco_ios.json", metricsCycler: &MetricsCycler{},
	}

	mgr := &SimulatorManager{
		devices: map[string]*DeviceSimulator{
			optical.ID: optical,
			packet.ID:  packet,
		},
		deviceIPs: map[string]struct{}{
			optical.IP.String(): {},
			packet.IP.String():  {},
		},
		deviceTypesByIP:  map[string]string{},
		resourcesCache:   map[string]*DeviceResources{},
		tunInterfacePool: map[string]*TunInterface{},
	}
	mgr.indexDeviceByIP(optical)
	mgr.indexDeviceByIP(packet)
	t.Cleanup(swapGlobalManager(mgr))

	return &degradeFixture{mgr: mgr, optical: optical, packet: packet, router: setupRoutes()}
}

func (f *degradeFixture) post(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

func TestDegradeAPI_HappyPath(t *testing.T) {
	f := newDegradeFixture(t)
	rr := f.post(t, "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade",
		`{"input_power_drop_db":8,"duration":"30s"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp degradeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Component != "OCH-1-1" || resp.InputPowerDropDB != 8 || resp.Duration != "30s" {
		t.Errorf("response echoes %+v, want the requested episode", resp)
	}
	// And it is actually in force on the engine.
	oc := f.optical.metricsCycler.OpticalCyclerOf()
	if sag, _, ok := oc.ActiveDegradation("OCH-1-1"); !ok || sag != 8 {
		t.Errorf("active sag = %v (ok=%v), want 8", sag, ok)
	}
	// The sibling channel is untouched.
	if sag, rise, _ := oc.ActiveDegradation("OCH-1-2"); sag != 0 || rise != 0 {
		t.Errorf("sibling channel degraded: (%v, %v)", sag, rise)
	}
}

func TestDegradeAPI_ClearAndSupersede(t *testing.T) {
	f := newDegradeFixture(t)
	oc := f.optical.metricsCycler.OpticalCyclerOf()

	f.post(t, "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", `{"noise_rise_db":5}`)
	if _, rise, _ := oc.ActiveDegradation("OCH-1-1"); rise != 5 {
		t.Fatalf("noise rise = %v, want 5", rise)
	}
	// A second POST supersedes rather than accumulating.
	f.post(t, "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", `{"noise_rise_db":2}`)
	if _, rise, _ := oc.ActiveDegradation("OCH-1-1"); rise != 2 {
		t.Errorf("after supersede noise rise = %v, want 2 (not summed)", rise)
	}
	// An empty body clears.
	rr := f.post(t, "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", ``)
	if rr.Code != http.StatusOK {
		t.Fatalf("clear status %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if sag, rise, _ := oc.ActiveDegradation("OCH-1-1"); sag != 0 || rise != 0 {
		t.Errorf("after clear offsets = (%v, %v), want (0, 0)", sag, rise)
	}
}

func TestDegradeAPI_Rejections(t *testing.T) {
	f := newDegradeFixture(t)
	tests := []struct {
		name string
		path string
		body string
		want int
	}{
		{"unknown device", "/api/v1/devices/10.42.9.9/optical/OCH-1-1/degrade", `{"noise_rise_db":1}`, http.StatusNotFound},
		{"packet device has no channels", "/api/v1/devices/10.42.0.2/optical/OCH-1-1/degrade", `{"noise_rise_db":1}`, http.StatusNotFound},
		{"unknown component", "/api/v1/devices/10.42.0.1/optical/OCH-9-9/degrade", `{"noise_rise_db":1}`, http.StatusNotFound},
		{"over-cap duration", "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", `{"noise_rise_db":1,"duration":"25h"}`, http.StatusBadRequest},
		{"non-positive duration", "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", `{"noise_rise_db":1,"duration":"0s"}`, http.StatusBadRequest},
		{"unparseable duration", "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", `{"noise_rise_db":1,"duration":"soon"}`, http.StatusBadRequest},
		{"unknown field", "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", `{"noise_rize_db":1}`, http.StatusBadRequest},
		{"negative offset", "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", `{"noise_rise_db":-3}`, http.StatusBadRequest},
		{"over-cap offset", "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", `{"input_power_drop_db":100}`, http.StatusBadRequest},
		{"trailing data", "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", `{"noise_rise_db":1} EXTRA`, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := f.post(t, tc.path, tc.body)
			if rr.Code != tc.want {
				t.Errorf("status %d, want %d; body=%s", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

// TestDegradeAPI_UnknownComponentListsAvailable: a 404 on the component name
// carries the channel list, so an operator can self-service the right name
// instead of guessing — same convention as the trap/syslog catalog 400s.
func TestDegradeAPI_UnknownComponentListsAvailable(t *testing.T) {
	f := newDegradeFixture(t)
	rr := f.post(t, "/api/v1/devices/10.42.0.1/optical/OCH-9-9/degrade", `{"noise_rise_db":1}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rr.Code)
	}
	var body struct {
		Error      string   `json:"error"`
		Components []string `json:"availableComponents"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Components) != 2 {
		t.Errorf("availableComponents = %v, want both channels", body.Components)
	}
}

// TestDegradeAPI_PacketDeviceMessageNamesTheType: the 404 for a packet device
// must say WHY (no optical channels on this type) rather than looking like a
// missing device, so an operator does not go hunting for a provisioning bug.
func TestDegradeAPI_PacketDeviceMessageNamesTheType(t *testing.T) {
	f := newDegradeFixture(t)
	rr := f.post(t, "/api/v1/devices/10.42.0.2/optical/OCH-1-1/degrade", `{"noise_rise_db":1}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "no optical channels") || !strings.Contains(body, "cisco_ios") {
		t.Errorf("message should explain the type has no channels and name it; got %s", body)
	}
}

// TestDegradeAPI_StatusGet pairs the POST with a readable status, so a second
// operator (or a caller that lost its response) can discover what is in force.
func TestDegradeAPI_StatusGet(t *testing.T) {
	f := newDegradeFixture(t)
	f.post(t, "/api/v1/devices/10.42.0.1/optical/OCH-1-2/degrade", `{"input_power_drop_db":4,"noise_rise_db":1}`)

	req := httptest.NewRequest("GET", "/api/v1/devices/10.42.0.1/optical", nil)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Device   string `json:"device"`
		Channels []struct {
			Component        string  `json:"component"`
			InputPowerDropDB float64 `json:"input_power_drop_db"`
			NoiseRiseDB      float64 `json:"noise_rise_db"`
			Degraded         bool    `json:"degraded"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Channels) != 2 {
		t.Fatalf("got %d channels, want 2", len(body.Channels))
	}
	for _, c := range body.Channels {
		switch c.Component {
		case "OCH-1-2":
			if !c.Degraded || c.InputPowerDropDB != 4 || c.NoiseRiseDB != 1 {
				t.Errorf("OCH-1-2 status = %+v, want the degradation just applied", c)
			}
		case "OCH-1-1":
			if c.Degraded {
				t.Errorf("OCH-1-1 reported degraded; only OCH-1-2 was")
			}
		default:
			t.Errorf("unexpected component %q", c.Component)
		}
	}
}

// TestDegradeAPI_NotReadyIs503: "still initialising" is transient. A 404 there
// tells a client to stop retrying something that is about to work, so it gets
// 503 like every other subsystem's not-ready path.
func TestDegradeAPI_NotReadyIs503(t *testing.T) {
	f := newDegradeFixture(t)
	// An optical device TYPE whose engine has not been published yet.
	initialising := &DeviceSimulator{
		ID: "optical-initialising", IP: net.IPv4(10, 42, 0, 3),
		resourceFile: opticalResourceFile, metricsCycler: &MetricsCycler{},
	}
	f.mgr.devices[initialising.ID] = initialising
	f.mgr.deviceIPs[initialising.IP.String()] = struct{}{}
	f.mgr.indexDeviceByIP(initialising)

	rr := f.post(t, "/api/v1/devices/10.42.0.3/optical/OCH-1-1/degrade", `{"noise_rise_db":1}`)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503 for an optical device mid-initialisation; body=%s", rr.Code, rr.Body.String())
	}
	// The permanent case stays 404.
	if rr := f.post(t, "/api/v1/devices/10.42.0.2/optical/OCH-1-1/degrade", `{"noise_rise_db":1}`); rr.Code != http.StatusNotFound {
		t.Errorf("packet device: status %d, want 404 (permanent)", rr.Code)
	}
}

// TestDegradeAPI_ClearDropsDurationEcho: `{"duration":"10m"}` with no offsets
// is an immediate clear, so echoing the duration back would read as "cleared
// in 10 minutes".
func TestDegradeAPI_ClearDropsDurationEcho(t *testing.T) {
	f := newDegradeFixture(t)
	rr := f.post(t, "/api/v1/devices/10.42.0.1/optical/OCH-1-1/degrade", `{"duration":"10m"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr.Code)
	}
	var resp degradeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Cleared {
		t.Error("a body with no offsets must report cleared")
	}
	if resp.Duration != "" {
		t.Errorf("cleared response echoed duration %q; that reads as \"cleared in 10 minutes\"", resp.Duration)
	}
}
