/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"net"
	"regexp"
	"testing"
)

// TestSynthSerial_DeterministicPerIP pins the serial format. The same IP
// must produce the same string every time so downstream correlators can
// use it as a stable device identifier.
func TestSynthSerial_DeterministicPerIP(t *testing.T) {
	ip := net.IPv4(10, 42, 0, 1)
	first := synthSerial(ip)
	second := synthSerial(ip)
	if first != second {
		t.Errorf("same IP produced different serials: %q vs %q", first, second)
	}
	// Format pin: `SN` + 8 hex digits (uppercase). 10.42.0.1 = 0x0A2A0001.
	if first != "SN0A2A0001" {
		t.Errorf("synthSerial(10.42.0.1): got %q, want SN0A2A0001", first)
	}
}

// TestSynthSerial_DistinctAcrossIPs confirms collisions don't happen
// within the simulator's IP range (hashing failures would silently
// merge devices at the correlator).
func TestSynthSerial_DistinctAcrossIPs(t *testing.T) {
	seen := make(map[string]net.IP)
	for i := 1; i <= 256; i++ {
		ip := net.IPv4(10, 42, 0, byte(i))
		s := synthSerial(ip)
		if prev, dup := seen[s]; dup {
			t.Fatalf("serial collision: %q from %s and %s", s, prev, ip)
		}
		seen[s] = ip
	}
}

// TestSynthChassisID_FormatAndDeterminism pins the 02:42:xx:xx:xx:xx
// MAC-style format (locally-administered prefix per RFC 7042 §2.1) and
// asserts stability per device.
func TestSynthChassisID_FormatAndDeterminism(t *testing.T) {
	ip := net.IPv4(10, 42, 0, 1)
	first := synthChassisID(ip)
	second := synthChassisID(ip)
	if first != second {
		t.Errorf("same IP produced different chassis IDs: %q vs %q", first, second)
	}
	re := regexp.MustCompile(`^02:42:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$`)
	if !re.MatchString(first) {
		t.Errorf("chassis ID %q doesn't match expected 02:42:xx:xx:xx:xx format", first)
	}
	// Explicit encoding: 10.42.0.1 → 02:42:0a:2a:00:01
	if first != "02:42:0a:2a:00:01" {
		t.Errorf("synthChassisID(10.42.0.1): got %q, want 02:42:0a:2a:00:01", first)
	}
}

// TestSynthSerial_IPv6Returns empty confirms the synth helpers don't
// panic or produce garbage on IPv6 input — they just return "" and the
// caller's template renders empty.
func TestSynthSerial_IPv6ReturnsEmpty(t *testing.T) {
	if got := synthSerial(net.ParseIP("2001:db8::1")); got != "" {
		t.Errorf("synthSerial(IPv6): got %q, want empty", got)
	}
	if got := synthChassisID(net.ParseIP("2001:db8::1")); got != "" {
		t.Errorf("synthChassisID(IPv6): got %q, want empty", got)
	}
}

// TestModelLabelForSlug_KnownSlugs spot-checks a few entries in
// deviceTypeLabels. Full table coverage is expensive and the table is
// hand-maintained; the fallback path below is what matters most.
func TestModelLabelForSlug_KnownSlugs(t *testing.T) {
	cases := map[string]string{
		"cisco_ios":       "Cisco IOS",
		"juniper_mx240":   "Juniper MX240",
		"arista_7280r3":   "Arista 7280R3",
		"linux_server":    "Linux Server",
		"nvidia_dgx_h100": "NVIDIA DGX H100",
	}
	for slug, want := range cases {
		if got := modelLabelForSlug(slug); got != want {
			t.Errorf("modelLabelForSlug(%q): got %q, want %q", slug, got, want)
		}
	}
}

// TestModelLabelForSlug_UnknownFallsBackToTitleCase confirms unknown
// slugs produce a non-empty string so `{{.Model}}` renders something
// sensible in test fixtures that invent new slugs (or for new
// hardware added before the lookup table is updated).
func TestModelLabelForSlug_UnknownFallsBackToTitleCase(t *testing.T) {
	got := modelLabelForSlug("acme_thinger_5000")
	if got != "Acme Thinger 5000" {
		t.Errorf("unknown slug fallback: got %q, want %q", got, "Acme Thinger 5000")
	}
}

// TestModelLabelForSlug_EmptyReturnsEmpty confirms the no-input case
// doesn't mis-render as `""`-titled garbage.
func TestModelLabelForSlug_EmptyReturnsEmpty(t *testing.T) {
	if got := modelLabelForSlug(""); got != "" {
		t.Errorf("empty slug: got %q, want empty", got)
	}
}

// TestManagerFieldResolver_SysNameFromDeviceState confirms the manager
// resolves SysName via `deviceTypesByIP` + device lookup (the same
// happy path the exporter construction uses).
func TestManagerFieldResolver_SysNameFromDeviceState(t *testing.T) {
	sm := &SimulatorManager{
		devices: map[string]*DeviceSimulator{
			"cisco-ios-0": {
				ID:      "cisco-ios-0",
				IP:      net.IPv4(10, 42, 0, 1),
				sysName: "rtr-dc-01",
			},
		},
		deviceTypesByIP: map[string]string{"10.42.0.1": "cisco_ios"},
	}
	if got := sm.SysName("10.42.0.1"); got != "rtr-dc-01" {
		t.Errorf("SysName: got %q, want %q", got, "rtr-dc-01")
	}
	if got := sm.SysName("10.99.99.99"); got != "" {
		t.Errorf("SysName(unknown): got %q, want empty", got)
	}
}

// TestManagerFieldResolver_ModelFromSlug confirms the manager's Model
// method resolves IP → slug → label correctly.
func TestManagerFieldResolver_ModelFromSlug(t *testing.T) {
	sm := &SimulatorManager{
		deviceTypesByIP: map[string]string{
			"10.42.0.1": "cisco_ios",
			"10.42.0.2": "juniper_mx240",
		},
	}
	if got := sm.Model("10.42.0.1"); got != "Cisco IOS" {
		t.Errorf("Model(cisco): got %q, want Cisco IOS", got)
	}
	if got := sm.Model("10.42.0.2"); got != "Juniper MX240" {
		t.Errorf("Model(juniper): got %q, want Juniper MX240", got)
	}
	if got := sm.Model("10.99.99.99"); got != "" {
		t.Errorf("Model(unknown): got %q, want empty", got)
	}
}

// TestManagerFieldResolver_SerialAndChassisID wires the direct synth
// helpers through the manager's methods (the implementations are
// stateless but tests should cover the integration path).
func TestManagerFieldResolver_SerialAndChassisID(t *testing.T) {
	sm := &SimulatorManager{}
	if got := sm.Serial("10.42.0.1"); got != "SN0A2A0001" {
		t.Errorf("Serial: got %q, want SN0A2A0001", got)
	}
	if got := sm.ChassisID("10.42.0.1"); got != "02:42:0a:2a:00:01" {
		t.Errorf("ChassisID: got %q, want 02:42:0a:2a:00:01", got)
	}
	if got := sm.Serial("not-an-ip"); got != "" {
		t.Errorf("Serial(bad IP): got %q, want empty", got)
	}
}
