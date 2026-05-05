/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// --- jsonDuration ----------------------------------------------------------

func TestJSONDuration_Unmarshal_AcceptsDurationString(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{`"10s"`, 10 * time.Second},
		{`"5m"`, 5 * time.Minute},
		{`"1m30s"`, 90 * time.Second},
		{`"500ms"`, 500 * time.Millisecond},
	}
	for _, tc := range cases {
		var d jsonDuration
		if err := json.Unmarshal([]byte(tc.in), &d); err != nil {
			t.Fatalf("Unmarshal(%s): unexpected error: %v", tc.in, err)
		}
		if time.Duration(d) != tc.want {
			t.Errorf("Unmarshal(%s) = %v, want %v", tc.in, time.Duration(d), tc.want)
		}
	}
}

func TestJSONDuration_Unmarshal_RejectsIntegerSeconds(t *testing.T) {
	// Per design §D10: integer seconds are explicitly rejected to avoid
	// ambiguity with the CLI flags that historically accepted
	// seconds-as-integers.
	var d jsonDuration
	err := json.Unmarshal([]byte(`10`), &d)
	if err == nil {
		t.Fatalf("Unmarshal(10): expected error, got duration %v", time.Duration(d))
	}
	if !strings.Contains(err.Error(), "duration must be a JSON string") {
		t.Errorf("error does not mention the string-requirement hint: %v", err)
	}
}

func TestJSONDuration_Unmarshal_RejectsInvalidString(t *testing.T) {
	var d jsonDuration
	err := json.Unmarshal([]byte(`"not a duration"`), &d)
	if err == nil {
		t.Fatalf("Unmarshal(\"not a duration\"): expected error")
	}
}

func TestJSONDuration_Unmarshal_AcceptsNullAsZero(t *testing.T) {
	// P2: null → leave zero, let ApplyDefaults fill.
	var d jsonDuration
	if err := json.Unmarshal([]byte(`null`), &d); err != nil {
		t.Fatalf("Unmarshal(null): unexpected error: %v", err)
	}
	if time.Duration(d) != 0 {
		t.Errorf("Unmarshal(null) = %v, want 0", time.Duration(d))
	}
}

func TestJSONDuration_Marshal_EmitsDurationString(t *testing.T) {
	d := jsonDuration(90 * time.Second)
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal: unexpected error: %v", err)
	}
	if got := string(out); got != `"1m30s"` {
		t.Errorf("Marshal = %s, want \"1m30s\"", got)
	}
}

// --- DeviceFlowConfig ------------------------------------------------------

func TestDeviceFlowConfig_ApplyDefaults_FillsZeroValues(t *testing.T) {
	c := &DeviceFlowConfig{Collector: "x:2055"}
	c.ApplyDefaults()
	if c.Protocol != defaultFlowProtocol {
		t.Errorf("Protocol = %q, want %q", c.Protocol, defaultFlowProtocol)
	}
	if time.Duration(c.TickInterval) != defaultFlowTickInterval {
		t.Errorf("TickInterval = %v, want %v", time.Duration(c.TickInterval), defaultFlowTickInterval)
	}
	if time.Duration(c.ActiveTimeout) != defaultFlowActiveTimeout {
		t.Errorf("ActiveTimeout = %v", time.Duration(c.ActiveTimeout))
	}
	if time.Duration(c.InactiveTimeout) != defaultFlowInactiveTimeout {
		t.Errorf("InactiveTimeout = %v", time.Duration(c.InactiveTimeout))
	}
}

func TestDeviceFlowConfig_ApplyDefaults_NilSafe(t *testing.T) {
	var c *DeviceFlowConfig
	c.ApplyDefaults() // must not panic
}

func TestDeviceFlowConfig_Validate_CanonicalisesProtocol(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"netflow9", "netflow9"},
		{"NF9", "netflow9"},
		{"NetFlow9", "netflow9"},
		{"ipfix", "ipfix"},
		{"IPFIX10", "ipfix"},
		{"netflow5", "netflow5"},
		{"nf5", "netflow5"},
		{"sflow", "sflow"},
		{"sflow5", "sflow"},
	}
	for _, tc := range cases {
		c := &DeviceFlowConfig{Collector: "127.0.0.1:2055", Protocol: tc.in}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate(%q): unexpected error: %v", tc.in, err)
		}
		if c.Protocol != tc.want {
			t.Errorf("Validate(%q) → Protocol = %q, want %q", tc.in, c.Protocol, tc.want)
		}
	}
}

func TestDeviceFlowConfig_Validate_RejectsUnknownProtocol(t *testing.T) {
	c := &DeviceFlowConfig{Collector: "127.0.0.1:2055", Protocol: "junk"}
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate: expected error for unknown protocol")
	}
	msg := err.Error()
	for _, want := range []string{"netflow9", "ipfix", "netflow5", "sflow"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message does not list %q: %s", want, msg)
		}
	}
}

func TestDeviceFlowConfig_Validate_RejectsNonASCIIProtocol(t *testing.T) {
	// P6: non-ASCII input (Unicode casing quirks, fullwidth, etc.)
	// short-circuits to a clean error rather than slipping past ToLower.
	c := &DeviceFlowConfig{Collector: "127.0.0.1:2055", Protocol: "netflowⅠ"}
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate: expected error for non-ASCII protocol")
	}
	if !strings.Contains(err.Error(), "ASCII") {
		t.Errorf("error should mention ASCII requirement: %v", err)
	}
}

func TestDeviceFlowConfig_Validate_ErrorEchoesTrimmedValue(t *testing.T) {
	// P5: error should echo the canonicalised (lowered/trimmed) value
	// so operators see what the parser actually tried to match.
	c := &DeviceFlowConfig{Collector: "127.0.0.1:2055", Protocol: "  JUNK  "}
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate: expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"junk"`) {
		t.Errorf("error should echo trimmed/lowered form %q, got: %s", "junk", msg)
	}
}

func TestDeviceFlowConfig_Validate_RejectsMissingCollector(t *testing.T) {
	c := &DeviceFlowConfig{Protocol: "netflow9"}
	if err := c.Validate(); err == nil {
		t.Fatalf("Validate: expected error for empty collector")
	}
}

func TestDeviceFlowConfig_Validate_RejectsWhitespaceCollector(t *testing.T) {
	// P1: whitespace-only collector must be rejected with a clean
	// "required" error, not a cryptic ResolveUDPAddr error.
	c := &DeviceFlowConfig{Collector: "   ", Protocol: "netflow9"}
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate: expected error for whitespace-only collector")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error should say 'required', got: %v", err)
	}
}

func TestDeviceFlowConfig_Validate_RejectsMissingPort(t *testing.T) {
	// P1: collector without a port should produce a SplitHostPort-style
	// error so the operator can see the problem immediately.
	c := &DeviceFlowConfig{Collector: "10.0.0.1", Protocol: "netflow9"}
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate: expected error for missing port")
	}
	if !strings.Contains(err.Error(), "host:port") {
		t.Errorf("error should mention host:port, got: %v", err)
	}
}

func TestDeviceFlowConfig_Validate_RejectsPortZero(t *testing.T) {
	// P1: port 0 is silently accepted by ResolveUDPAddr but UDP sends
	// go to an ephemeral port — operators would never reach their
	// collector. Reject explicitly.
	c := &DeviceFlowConfig{Collector: "10.0.0.1:0", Protocol: "netflow9"}
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate: expected error for port 0")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Errorf("error should mention port, got: %v", err)
	}
}

func TestDeviceFlowConfig_Validate_AcceptsIPv6Collector(t *testing.T) {
	// P1: the udp4→udp change must let IPv6 literals through.
	c := &DeviceFlowConfig{Collector: "[::1]:2055", Protocol: "netflow9"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate([::1]:2055): unexpected error: %v", err)
	}
}

func TestDeviceFlowConfig_Validate_RejectsUnresolvableCollector(t *testing.T) {
	c := &DeviceFlowConfig{Collector: "definitely-not-a-real-hostname.invalid:2055", Protocol: "netflow9"}
	if err := c.Validate(); err == nil {
		t.Fatalf("Validate: expected error for unresolvable collector")
	}
}

func TestDeviceFlowConfig_Validate_RejectsNegativeDurations(t *testing.T) {
	c := &DeviceFlowConfig{
		Collector:    "127.0.0.1:2055",
		Protocol:     "netflow9",
		TickInterval: jsonDuration(-1 * time.Second),
	}
	if err := c.Validate(); err == nil {
		t.Fatalf("Validate: expected error for negative tick_interval")
	}
}

func TestDeviceFlowConfig_Validate_NegativeDurationDoesNotMutateProtocol(t *testing.T) {
	// P3: range checks run before canonicalisation; a duration-range
	// error must leave Protocol un-canonicalised so callers can rely
	// on "error → struct untouched by this call".
	c := &DeviceFlowConfig{
		Collector:    "127.0.0.1:2055",
		Protocol:     "NF9",
		TickInterval: jsonDuration(-1 * time.Second),
	}
	if err := c.Validate(); err == nil {
		t.Fatalf("Validate: expected error")
	}
	if c.Protocol != "NF9" {
		t.Errorf("Protocol should remain untouched on error path, got %q", c.Protocol)
	}
}

func TestDeviceFlowConfig_Validate_NilSafe(t *testing.T) {
	var c *DeviceFlowConfig
	if err := c.Validate(); err != nil {
		t.Errorf("Validate(nil): unexpected error: %v", err)
	}
}

func TestDeviceFlowConfig_JSONRoundTrip(t *testing.T) {
	orig := &DeviceFlowConfig{
		Collector:       "10.0.0.1:2055",
		Protocol:        "netflow9",
		TickInterval:    jsonDuration(10 * time.Second),
		ActiveTimeout:   jsonDuration(5 * time.Minute),
		InactiveTimeout: jsonDuration(1 * time.Minute),
	}
	encoded, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded DeviceFlowConfig
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(decoded, *orig) {
		t.Errorf("round-trip mismatch\n  got:  %+v\n  want: %+v", decoded, *orig)
	}
}

// --- DeviceTrapConfig ------------------------------------------------------

func TestDeviceTrapConfig_ApplyDefaults_FillsZeroValues(t *testing.T) {
	c := &DeviceTrapConfig{Collector: "x:162"}
	c.ApplyDefaults()
	if c.Mode != defaultTrapMode {
		t.Errorf("Mode = %q, want %q", c.Mode, defaultTrapMode)
	}
	if c.Community != defaultTrapCommunity {
		t.Errorf("Community = %q, want %q", c.Community, defaultTrapCommunity)
	}
	if time.Duration(c.Interval) != defaultTrapInterval {
		t.Errorf("Interval = %v", time.Duration(c.Interval))
	}
	if time.Duration(c.InformTimeout) != defaultTrapInformTimeout {
		t.Errorf("InformTimeout = %v", time.Duration(c.InformTimeout))
	}
	if c.InformRetries != defaultTrapInformRetries {
		t.Errorf("InformRetries = %d, want %d", c.InformRetries, defaultTrapInformRetries)
	}
}

func TestDeviceTrapConfig_ApplyDefaults_NilSafe(t *testing.T) {
	var c *DeviceTrapConfig
	c.ApplyDefaults() // must not panic
}

func TestDeviceTrapConfig_Validate_CanonicalisesMode(t *testing.T) {
	// Empty mode is NOT tested here — it is rejected with a hint, see
	// TestDeviceTrapConfig_Validate_EmptyModeRejected below.
	cases := []struct {
		in, want string
	}{
		{"trap", "trap"},
		{"TRAP", "trap"},
		{"inform", "inform"},
		{"Inform", "inform"},
	}
	for _, tc := range cases {
		c := &DeviceTrapConfig{Collector: "127.0.0.1:162", Mode: tc.in}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate(Mode=%q): unexpected error: %v", tc.in, err)
		}
		if c.Mode != tc.want {
			t.Errorf("Validate(Mode=%q) → Mode = %q, want %q", tc.in, c.Mode, tc.want)
		}
	}
}

func TestDeviceTrapConfig_Validate_EmptyModeRejected(t *testing.T) {
	// P9 / decision D3.b: empty Mode is rejected with a hint pointing
	// at ApplyDefaults; symmetric with DeviceSyslogConfig's empty-Format
	// rejection.
	c := &DeviceTrapConfig{Collector: "127.0.0.1:162"}
	if err := c.Validate(); err == nil {
		t.Fatalf("Validate: expected error for empty Mode (caller must ApplyDefaults first)")
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		t.Errorf("Validate after ApplyDefaults: unexpected error: %v", err)
	}
}

func TestDeviceTrapConfig_Validate_RejectsUnknownMode(t *testing.T) {
	c := &DeviceTrapConfig{Collector: "127.0.0.1:162", Mode: "notAMode"}
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate: expected error for unknown mode")
	}
	if !strings.Contains(err.Error(), "trap") || !strings.Contains(err.Error(), "inform") {
		t.Errorf("error does not name the valid values: %v", err)
	}
}

func TestDeviceTrapConfig_Validate_RejectsMissingCollector(t *testing.T) {
	c := &DeviceTrapConfig{Mode: "trap"}
	if err := c.Validate(); err == nil {
		t.Fatalf("Validate: expected error for empty collector")
	}
}

func TestDeviceTrapConfig_Validate_RejectsNegativeInformRetries(t *testing.T) {
	c := &DeviceTrapConfig{Collector: "127.0.0.1:162", Mode: "inform", InformRetries: -1}
	if err := c.Validate(); err == nil {
		t.Fatalf("Validate: expected error for negative inform_retries")
	}
}

func TestDeviceTrapConfig_Validate_NegativeIntervalDoesNotMutateMode(t *testing.T) {
	// P3: range check on Interval runs before Mode canonicalisation,
	// so error path leaves Mode untouched.
	c := &DeviceTrapConfig{
		Collector: "127.0.0.1:162",
		Mode:      "INFORM",
		Interval:  jsonDuration(-1 * time.Second),
	}
	if err := c.Validate(); err == nil {
		t.Fatalf("Validate: expected error")
	}
	if c.Mode != "INFORM" {
		t.Errorf("Mode should remain untouched on error path, got %q", c.Mode)
	}
}

func TestDeviceTrapConfig_Validate_NilSafe(t *testing.T) {
	var c *DeviceTrapConfig
	if err := c.Validate(); err != nil {
		t.Errorf("Validate(nil): unexpected error: %v", err)
	}
}

func TestDeviceTrapConfig_JSONRoundTrip(t *testing.T) {
	orig := &DeviceTrapConfig{
		Collector:     "10.0.0.1:162",
		Mode:          "inform",
		Community:     "private",
		Interval:      jsonDuration(30 * time.Second),
		InformTimeout: jsonDuration(5 * time.Second),
		InformRetries: 3,
	}
	encoded, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded DeviceTrapConfig
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(decoded, *orig) {
		t.Errorf("round-trip mismatch\n  got:  %+v\n  want: %+v", decoded, *orig)
	}
}

// --- DeviceSyslogConfig ----------------------------------------------------

func TestDeviceSyslogConfig_ApplyDefaults_FillsZeroValues(t *testing.T) {
	c := &DeviceSyslogConfig{Collector: "x:514"}
	c.ApplyDefaults()
	if c.Format != defaultSyslogFormat {
		t.Errorf("Format = %q, want %q", c.Format, defaultSyslogFormat)
	}
	if time.Duration(c.Interval) != defaultSyslogInterval {
		t.Errorf("Interval = %v", time.Duration(c.Interval))
	}
}

func TestDeviceSyslogConfig_ApplyDefaults_NilSafe(t *testing.T) {
	var c *DeviceSyslogConfig
	c.ApplyDefaults() // must not panic
}

func TestDeviceSyslogConfig_Validate_CanonicalisesFormat(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"5424", "5424"},
		{"  5424  ", "5424"}, // whitespace tolerated by ParseSyslogFormat
		{"3164", "3164"},
	}
	for _, tc := range cases {
		c := &DeviceSyslogConfig{Collector: "127.0.0.1:514", Format: tc.in}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate(Format=%q): unexpected error: %v", tc.in, err)
		}
		if c.Format != tc.want {
			t.Errorf("Validate(Format=%q) → Format = %q, want %q", tc.in, c.Format, tc.want)
		}
	}
}

func TestDeviceSyslogConfig_Validate_RejectsUnknownFormat(t *testing.T) {
	c := &DeviceSyslogConfig{Collector: "127.0.0.1:514", Format: "notAFormat"}
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate: expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "5424") || !strings.Contains(err.Error(), "3164") {
		t.Errorf("error does not name the valid values: %v", err)
	}
}

func TestDeviceSyslogConfig_Validate_EmptyFormatRejected(t *testing.T) {
	// Empty format is rejected at Validate() time — callers must call
	// ApplyDefaults first to fill in the default "5424". Symmetric with
	// DeviceTrapConfig's empty-Mode rejection (decision D3.b).
	c := &DeviceSyslogConfig{Collector: "127.0.0.1:514"}
	if err := c.Validate(); err == nil {
		t.Fatalf("Validate: expected error for empty format (caller must ApplyDefaults first)")
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		t.Errorf("Validate after ApplyDefaults: unexpected error: %v", err)
	}
}

func TestDeviceSyslogConfig_Validate_NilSafe(t *testing.T) {
	var c *DeviceSyslogConfig
	if err := c.Validate(); err != nil {
		t.Errorf("Validate(nil): unexpected error: %v", err)
	}
}

func TestDeviceSyslogConfig_JSONRoundTrip(t *testing.T) {
	orig := &DeviceSyslogConfig{
		Collector: "10.0.0.1:514",
		Format:    "5424",
		Interval:  jsonDuration(10 * time.Second),
	}
	encoded, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded DeviceSyslogConfig
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(decoded, *orig) {
		t.Errorf("round-trip mismatch\n  got:  %+v\n  want: %+v", decoded, *orig)
	}
}

// --- CreateDevicesRequest embedding ---------------------------------------

func TestCreateDevicesRequest_AcceptsOmittedExportBlocks(t *testing.T) {
	body := `{"start_ip":"10.0.0.1","device_count":5,"netmask":"24"}`
	var req CreateDevicesRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if req.Flow != nil {
		t.Errorf("Flow should be nil, got %+v", req.Flow)
	}
	if req.Traps != nil {
		t.Errorf("Traps should be nil, got %+v", req.Traps)
	}
	if req.Syslog != nil {
		t.Errorf("Syslog should be nil, got %+v", req.Syslog)
	}
}

func TestCreateDevicesRequest_AcceptsAllThreeExportBlocks(t *testing.T) {
	body := `{
		"start_ip":"10.0.0.1","device_count":5,"netmask":"24",
		"flow":   {"collector":"10.0.0.100:2055","protocol":"netflow9","tick_interval":"10s"},
		"traps":  {"collector":"10.0.0.100:162","mode":"inform","community":"private","interval":"30s"},
		"syslog": {"collector":"10.0.0.100:514","format":"5424","interval":"10s"}
	}`
	var req CreateDevicesRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if req.Flow == nil || req.Flow.Collector != "10.0.0.100:2055" {
		t.Errorf("Flow not parsed: %+v", req.Flow)
	}
	if req.Traps == nil || req.Traps.Mode != "inform" || req.Traps.Community != "private" {
		t.Errorf("Traps not parsed: %+v", req.Traps)
	}
	if req.Syslog == nil || req.Syslog.Format != "5424" {
		t.Errorf("Syslog not parsed: %+v", req.Syslog)
	}
}

func TestCreateDevicesRequest_RejectsIntegerDurations(t *testing.T) {
	// Per design §D10: integer durations are rejected. Assert on the
	// error message substring so future permissive changes to
	// UnmarshalJSON won't silently pass.
	body := `{"start_ip":"10.0.0.1","device_count":1,"netmask":"24",
			  "flow":{"collector":"10.0.0.100:2055","tick_interval":5}}`
	var req CreateDevicesRequest
	err := json.Unmarshal([]byte(body), &req)
	if err == nil {
		t.Fatalf("Unmarshal: expected error for integer duration")
	}
	if !strings.Contains(err.Error(), "duration must be a JSON string") {
		t.Errorf("error does not mention the string-requirement hint: %v", err)
	}
}
