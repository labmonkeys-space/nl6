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
	"strings"
	"testing"
	"time"
)

// export_interval_disclosure_api_test.go — the wiring the pure-helper tests
// cannot reach.
//
// Two review rounds found the same failure mode here: properties asserted at
// the wrong layer. Testing that a pure predicate is pure proves nothing about
// the handler that calls it. These tests drive the real handler via httptest
// (the pattern web_create_devices_scenario_test.go established) or assert on
// the marshalled wire bytes, so they can actually fail when the wiring breaks.
//
// The round trip is the load-bearing one: `scripts/fleet.sh import` re-POSTs
// GET blocks verbatim, so any read-only field nested inside a config block
// breaks a shipped tool.

// TestCreateDevices_AcceptsAReadBackBlock is the round-trip guard, and it
// pins the reversal of decision D3b.
//
// The effective values used to be nested INSIDE the config blocks, which made a
// GET block an invalid POST body under DisallowUnknownFields. That broke every
// read-modify-write client, including the repo's own `scripts/fleet.sh import`,
// which re-POSTs the GET blocks verbatim and whose round trip
// docs/getting-started/fleet.md advertises.
//
// Effective values now live in a sibling `effective_intervals` object, so a
// config block round-trips. If anyone re-nests a read-only field, this fails.
func TestCreateDevices_AcceptsAReadBackBlock(t *testing.T) {
	// Exactly what GET /api/v1/devices emits for a syslog-exporting device.
	dev := &DeviceSimulator{syslogConfig: &DeviceSyslogConfig{
		Collector: "x:514", Format: "5424", Interval: jsonDuration(24 * time.Hour),
	}}
	readBack, err := json.Marshal(DeviceInfo{
		ID: "d", IP: "10.42.0.1",
		Syslog:             dev.syslogConfig,
		EffectiveIntervals: buildEffectiveIntervals2(dev),
	})
	if err != nil {
		t.Fatalf("marshal read-back: %v", err)
	}
	var parsed struct {
		Syslog json.RawMessage `json:"syslog"`
	}
	if err := json.Unmarshal(readBack, &parsed); err != nil {
		t.Fatalf("unmarshal read-back: %v", err)
	}

	// Feed that block straight back into a create request, the way fleet.sh does.
	body := []byte(`{"start_ip":"10.0.0.1","device_count":1,"netmask":"24","syslog":` +
		string(parsed.Syslog) + `}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
	w := httptest.NewRecorder()

	createDevicesHandler(w, r)

	if w.Code == http.StatusBadRequest && strings.Contains(w.Body.String(), "unknown field") {
		t.Fatalf("a GET block was rejected as a POST block: %s — this breaks scripts/fleet.sh import", w.Body.String())
	}
}

// TestCreateDevices_StillRejectsGenuineTypos keeps the strictness that makes
// the round trip safe: dropping the nested read-only fields must not have
// weakened typo detection inside the export blocks.
func TestCreateDevices_StillRejectsGenuineTypos(t *testing.T) {
	body := []byte(`{"start_ip":"10.0.0.1","device_count":1,"netmask":"24",
		"syslog":{"collector":"x:514","intervl":"24h"}}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
	w := httptest.NewRecorder()

	createDevicesHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a typo'd nested field", w.Code)
	}
}

// TestCreateDevicesResult_WarningsSerialize asserts the warning actually
// reaches the wire, under the `data` envelope where the docs say it lives.
//
// The response is built by the handler on success, which needs a real manager,
// so this exercises the payload type directly — the half that is testable
// without root, and the half a scripted client depends on. It pins the field
// path (`.data.warnings`, not `.warnings`), which the docs got wrong once
// already.
func TestCreateDevicesResult_WarningsSerialize(t *testing.T) {
	wrn := intervalDisclosure("syslog.interval", true, 24*time.Hour, 10*time.Second)
	if wrn == nil {
		t.Fatal("expected a warning to embed")
		return
	}
	raw, err := json.Marshal(APIResponse{
		Success: true,
		Message: "Created 1 devices starting from 10.0.0.1",
		Data:    CreateDevicesResult{Created: 1, Requested: 1, Warnings: []exportWarning{*wrn}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var envelope struct {
		Data struct {
			Warnings []struct {
				Field     string `json:"field"`
				Requested string `json:"requested"`
				Effective string `json:"effective"`
				Message   string `json:"message"`
			} `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(envelope.Data.Warnings) != 1 {
		t.Fatalf("data.warnings length = %d, want 1 — a client reading .data.warnings must find it: %s",
			len(envelope.Data.Warnings), raw)
	}
	got := envelope.Data.Warnings[0]
	if got.Field != "syslog.interval" || got.Requested != "24h0m0s" || got.Effective != "10s" {
		t.Errorf("warning = %+v, want field/requested/effective populated", got)
	}
	if got.Message == "" {
		t.Error("message empty; it is the only field a human reads in a raw body")
	}
}

// TestCreateDevicesResult_NoWarningsOmitted keeps the field out of the common
// response entirely, so existing clients see a byte-identical body.
func TestCreateDevicesResult_NoWarningsOmitted(t *testing.T) {
	raw, err := json.Marshal(CreateDevicesResult{Created: 5, Requested: 5})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "warnings") {
		t.Errorf("empty warnings must be omitted, got %s", raw)
	}
}

// TestDisclosureSurvivesApplyDefaults is the ordering guard, rewritten.
//
// The previous version asserted that a PURE FUNCTION is pure, which it is by
// construction, so it could not detect the reordering it claimed to prevent.
// The real invariant is that provenance is captured before ApplyDefaults and
// SURVIVES it — that is what a reordering would break, and it is observable on
// the config object itself.
func TestDisclosureSurvivesApplyDefaults(t *testing.T) {
	const fleetMean = 60 * time.Second // e.g. -syslog-interval 60s

	// A caller who set nothing, handled in handler order.
	omitted := &DeviceSyslogConfig{Collector: "x:514"}
	omitted.markIntervalProvenance() // BEFORE defaults, as createDevicesHandler does
	omitted.ApplyDefaults()

	if omitted.IntervalWasSet() {
		t.Fatal("provenance says the caller set an interval; a reordering (or a value-based " +
			"test) would make every default-interval device warn on a non-default fleet")
	}
	if got := intervalDisclosure("syslog.interval", omitted.IntervalWasSet(),
		time.Duration(omitted.Interval), fleetMean); got != nil {
		t.Fatalf("disclosed against a caller who set nothing: %+v", got)
	}

	// And the marker must survive defaults for a caller who DID set one.
	set := &DeviceSyslogConfig{Collector: "x:514", Interval: jsonDuration(24 * time.Hour)}
	set.markIntervalProvenance()
	set.ApplyDefaults()
	if !set.IntervalWasSet() {
		t.Error("provenance lost across ApplyDefaults")
	}
}

// TestDeviceInfo_EmitsEffectiveIntervals asserts the read-back wire shape at
// the DeviceInfo level, so a change to how ListDevices assembles the response
// cannot silently drop the disclosure.
func TestDeviceInfo_EmitsEffectiveIntervals(t *testing.T) {
	dev := &DeviceSimulator{syslogConfig: &DeviceSyslogConfig{
		Collector: "x:514", Format: "5424", Interval: jsonDuration(24 * time.Hour),
	}}
	raw, err := json.Marshal(DeviceInfo{
		ID: "d", IP: "10.42.0.1",
		Syslog:             dev.syslogConfig,
		EffectiveIntervals: buildEffectiveIntervals2(dev),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		Syslog struct {
			Interval string `json:"interval"`
		} `json:"syslog"`
		Eff *struct {
			SyslogInterval string `json:"syslog_interval"`
		} `json:"effective_intervals"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Syslog.Interval != "24h0m0s" {
		t.Errorf("syslog.interval = %q, want the requested 24h0m0s", got.Syslog.Interval)
	}
	if got.Eff == nil {
		t.Fatal("effective_intervals absent for an exporting device")
	}
	if got.Eff.SyslogInterval != defaultSyslogInterval.String() {
		t.Errorf("syslog_interval = %q, want %s", got.Eff.SyslogInterval, defaultSyslogInterval)
	}
}

// TestWarningSurvivesValidationFailure pins the one-round-trip property.
//
// A request can be invalid AND carry an inert interval. Both facts are known at
// request time, so returning only the error costs the caller a round trip to
// learn the second. The warning rides the 400 in `data.warnings`.
//
// This is only sound because the message makes no claim about the request's
// outcome — it describes the field, so it is equally true on a rejection.
func TestWarningSurvivesValidationFailure(t *testing.T) {
	if manager == nil {
		t.Skip("handler-level disclosure needs a manager; covered by unit tests otherwise")
	}
	// Invalid collector (fails Validate) plus an interval that is inert anyway.
	body := []byte(`{"start_ip":"10.0.0.1","device_count":1,"netmask":"24",
		"syslog":{"collector":"not-a-host-port","interval":"24h"}}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
	w := httptest.NewRecorder()

	createDevicesHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an invalid collector", w.Code)
	}
	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Warnings []exportWarning `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Success {
		t.Error("success = true on a 400")
	}
	if resp.Message == "" {
		t.Error("the validation error itself must still be reported")
	}
	if len(resp.Data.Warnings) != 1 {
		t.Fatalf("data.warnings = %d, want the interval disclosure alongside the error: %s",
			len(resp.Data.Warnings), w.Body.String())
	}
}

// TestErrorResponseUnchangedWithoutWarnings keeps every other error byte-identical.
// `Data` is omitempty, so a rejection carrying no disclosure must not grow a
// `data` key.
func TestErrorResponseUnchangedWithoutWarnings(t *testing.T) {
	body := []byte(`{"start_ip":"10.0.0.1","device_count":0,"netmask":"24"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
	w := httptest.NewRecorder()

	createDevicesHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if strings.Contains(w.Body.String(), `"data"`) {
		t.Errorf("error response grew a data key with no warnings to carry: %s", w.Body.String())
	}
}

// TestWarningMessageMakesNoOutcomeClaim is the invariant that permits the
// warning to ride a rejection at all.
//
// The message used to say "is accepted and stored", true only on the success
// path — which is precisely why it could not be attached to a 400 or to a
// created=0 batch. If someone reintroduces an outcome claim, attaching it
// elsewhere becomes a lie, so this fails.
func TestWarningMessageMakesNoOutcomeClaim(t *testing.T) {
	for _, w := range []*exportWarning{
		intervalDisclosure("syslog.interval", true, 24*time.Hour, 10*time.Second),
		intervalDisclosure("traps.interval", true, 30*time.Second, 30*time.Second),
	} {
		if w == nil {
			t.Fatal("expected a warning")
		}
		for _, claim := range []string{"accepted", "stored", "created", "was applied"} {
			if strings.Contains(strings.ToLower(w.Message), claim) {
				t.Errorf("message claims an outcome (%q), so it cannot ride a 400 or a "+
					"created=0 batch truthfully: %q", claim, w.Message)
			}
		}
		if !strings.Contains(w.Message, "not honored") {
			t.Errorf("message must still say the field is not honored: %q", w.Message)
		}
	}
}
