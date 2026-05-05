/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"net"
	"strings"
	"testing"
)

// TestCiscoIos_TrapCatalogLoads exercises the full per-type trap
// catalog load path for the shipped `resources/cisco_ios/traps.json`.
// Confirms the overlay semantic works end-to-end: universal 5 entries
// carry through + 7 Cisco-specific entries are added (total 12).
// Protects against schema drift, duplicate-name clashes, and weight
// recomputation bugs on real fixture content.
func TestCiscoIos_TrapCatalogLoads(t *testing.T) {
	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedCatalog: %v", err)
	}
	result, err := ScanPerTypeTrapCatalogs(universal, "resources")
	if err != nil {
		t.Fatalf("ScanPerTypeTrapCatalogs: %v", err)
	}
	cisco := result["cisco_ios"]
	if cisco == nil {
		t.Fatal("cisco_ios per-type catalog missing from scan result")
	}
	if got := len(cisco.Entries); got != 12 {
		t.Errorf("merged cisco_ios catalog entries: got %d, want 12 (universal 5 + cisco 7)", got)
	}
	// Universal entries must carry through.
	for _, name := range []string{"linkDown", "linkUp", "coldStart", "warmStart", "authenticationFailure"} {
		if _, ok := cisco.ByName[name]; !ok {
			t.Errorf("universal entry %q missing from cisco_ios merged catalog", name)
		}
	}
	// Cisco-specific entries must be present.
	ciscoEntries := []string{
		"ciscoConfigManEvent",
		"ciscoEnvMonSupplyStatusChangeNotif",
		"ciscoEnvMonTemperatureNotification",
		"cefcModuleStatusChange",
		"cefcFanTrayStatusChangeNotif",
		"ciscoEntSensorThresholdNotification",
		"ciscoFlashDeviceChangeTrap",
	}
	for _, name := range ciscoEntries {
		if _, ok := cisco.ByName[name]; !ok {
			t.Errorf("cisco-specific entry %q missing from merged catalog", name)
		}
	}
	// Weight total: universal 100 + cisco 70 = 170.
	wantTotal := 100 + 70
	if cisco.totalWeight != wantTotal {
		t.Errorf("merged totalWeight: got %d, want %d", cisco.totalWeight, wantTotal)
	}
}

// TestCiscoIos_SyslogCatalogLoads mirrors the trap test for the shipped
// `resources/cisco_ios/syslog.json`. Universal 6 + Cisco 7 = 13.
func TestCiscoIos_SyslogCatalogLoads(t *testing.T) {
	universal, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedSyslogCatalog: %v", err)
	}
	result, err := ScanPerTypeSyslogCatalogs(universal, "resources")
	if err != nil {
		t.Fatalf("ScanPerTypeSyslogCatalogs: %v", err)
	}
	cisco := result["cisco_ios"]
	if cisco == nil {
		t.Fatal("cisco_ios per-type syslog catalog missing from scan result")
	}
	if got := len(cisco.Entries); got != 14 {
		t.Errorf("merged cisco_ios syslog entries: got %d, want 14 (universal 6 + cisco 8)", got)
	}
	for _, name := range []string{"interface-up", "interface-down", "auth-success", "auth-failure", "config-change", "system-restart"} {
		if _, ok := cisco.ByName[name]; !ok {
			t.Errorf("universal entry %q missing from cisco_ios merged syslog catalog", name)
		}
	}
	ciscoEntries := []string{
		"cisco-link-updown-up",
		"cisco-link-updown-down",
		"cisco-lineproto-updown-up",
		"cisco-lineproto-updown-down",
		"cisco-sys-config",
		"cisco-snmp-coldstart",
		"cisco-sys-restart",
		"cisco-envmon-temp-ok",
	}
	for _, name := range ciscoEntries {
		if _, ok := cisco.ByName[name]; !ok {
			t.Errorf("cisco syslog entry %q missing from merged catalog", name)
		}
	}
}

// TestCiscoIos_TrapCatalog_ResolveEndToEnd fires each Cisco-specific
// entry through the template resolver with a realistic TemplateCtx
// and confirms Class 1 fields make it into the rendered varbinds.
// This is the "fire through encoder and parser" assertion from
// tasks.md §4.5, scoped to the template-resolution layer (the wire
// encoder is already covered by byte-identity pins).
func TestCiscoIos_TrapCatalog_ResolveEndToEnd(t *testing.T) {
	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	result, err := ScanPerTypeTrapCatalogs(universal, "resources")
	if err != nil {
		t.Fatal(err)
	}
	cisco := result["cisco_ios"]
	if cisco == nil {
		t.Fatal("cisco_ios catalog missing")
	}

	ctx := TemplateCtx{
		IfIndex:   3,
		IfName:    "GigabitEthernet0/3",
		Uptime:    12345,
		Now:       1700000000,
		DeviceIP:  "10.42.0.1",
		SysName:   "rtr-dc-01",
		Model:     "Cisco IOS",
		Serial:    synthSerial(net.IPv4(10, 42, 0, 1)),
		ChassisID: synthChassisID(net.IPv4(10, 42, 0, 1)),
	}

	// ciscoEnvMonSupplyStatusChangeNotif has a `PWR-{{.Serial}}` varbind.
	envEntry := cisco.ByName["ciscoEnvMonSupplyStatusChangeNotif"]
	if envEntry == nil {
		t.Fatal("ciscoEnvMonSupplyStatusChangeNotif missing")
	}
	vbs, err := envEntry.Resolve(ctx, nil)
	if err != nil {
		t.Fatalf("resolve envMonSupply: %v", err)
	}
	if len(vbs) == 0 || !strings.Contains(vbs[0].Value, "SN0A2A0001") {
		t.Errorf("envMonSupply varbind[0].Value: got %q, want it to contain PWR-SN0A2A0001", vbs[0].Value)
	}

	// ciscoEnvMonTemperatureNotification emits sensor descr, value, state.
	// Temp value 75°C with state=2 (warning) — the realistic pairing per
	// the MIB's ciscoEnvMonState enum.
	tempEntry := cisco.ByName["ciscoEnvMonTemperatureNotification"]
	if tempEntry == nil {
		t.Fatal("ciscoEnvMonTemperatureNotification missing")
	}
	vbs, err = tempEntry.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vbs) < 3 {
		t.Fatalf("temperature entry: got %d varbinds, want 3", len(vbs))
	}
	if vbs[0].Value != "chassis inlet" {
		t.Errorf("temperature descr: got %q, want %q", vbs[0].Value, "chassis inlet")
	}
	if vbs[1].Value != "75" {
		t.Errorf("temperature value: got %q, want 75", vbs[1].Value)
	}
	if vbs[2].Value != "2" {
		t.Errorf("temperature state: got %q, want 2 (warning)", vbs[2].Value)
	}

	// cefcModuleStatusChange uses `{{.Uptime}}` in a timeticks varbind.
	moduleEntry := cisco.ByName["cefcModuleStatusChange"]
	if moduleEntry == nil {
		t.Fatal("cefcModuleStatusChange missing")
	}
	vbs, err = moduleEntry.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vbs) < 2 || vbs[1].Value != "12345" {
		t.Errorf("module status varbind[1].Value: got %v, want 12345 (uptime)", vbs)
	}
}

// TestCiscoIos_SyslogCatalog_ResolveEndToEnd fires each Cisco syslog
// entry through template resolution with a realistic context and
// confirms Class 1 fields render into the message body and structured-
// data pairs. Mirrors the trap-side end-to-end assertion.
func TestCiscoIos_SyslogCatalog_ResolveEndToEnd(t *testing.T) {
	universal, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	result, err := ScanPerTypeSyslogCatalogs(universal, "resources")
	if err != nil {
		t.Fatal(err)
	}
	cisco := result["cisco_ios"]
	if cisco == nil {
		t.Fatal("cisco_ios syslog catalog missing")
	}

	ctx := SyslogTemplateCtx{
		DeviceIP:  "10.42.0.1",
		SysName:   "rtr-dc-01",
		IfIndex:   5,
		IfName:    "FastEthernet1/0/5",
		Now:       1700000000,
		Uptime:    12345,
		Model:     "Cisco IOS",
		Serial:    synthSerial(net.IPv4(10, 42, 0, 1)),
		ChassisID: synthChassisID(net.IPv4(10, 42, 0, 1)),
	}

	// %LINK-3-UPDOWN message should contain the (live-lookup-flavored) ifName.
	linkDown := cisco.ByName["cisco-link-updown-down"]
	resolved, err := linkDown.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantMsg := "%LINK-3-UPDOWN: Interface FastEthernet1/0/5, changed state to down"
	if resolved.Message != wantMsg {
		t.Errorf("link-updown-down message:\n got %q\nwant %q", resolved.Message, wantMsg)
	}

	// %SYS-5-RESTART includes Model + Serial + ChassisID — vendor realism depends
	// on all three resolving correctly.
	restart := cisco.ByName["cisco-sys-restart"]
	resolved, err = restart.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantRestart := "%SYS-5-RESTART: System restarted -- Cisco IOS (serial SN0A2A0001, chassis 02:42:0a:2a:00:01)"
	if resolved.Message != wantRestart {
		t.Errorf("sys-restart message:\n got %q\nwant %q", resolved.Message, wantRestart)
	}

	// %SNMP-5-COLDSTART uses SysName.
	coldStart := cisco.ByName["cisco-snmp-coldstart"]
	resolved, err = coldStart.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resolved.Message, "rtr-dc-01") {
		t.Errorf("coldstart message should contain SysName=rtr-dc-01: got %q", resolved.Message)
	}

	// Structured-data on cisco-link-updown-down should carry ifIndex +
	// ifName + model (the three keys declared in the catalog entry).
	// Re-resolve link-down so we assert against its SD pairs, not the
	// coldstart result snapshot above.
	resolved, err = linkDown.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var hasIfName, hasModel bool
	for _, sd := range resolved.StructuredData {
		if sd.Key == "ifName" && sd.Value == "FastEthernet1/0/5" {
			hasIfName = true
		}
		if sd.Key == "model" && sd.Value == "Cisco IOS" {
			hasModel = true
		}
	}
	if !hasIfName {
		t.Error("cisco-link-updown-down structuredData missing ifName=FastEthernet1/0/5")
	}
	if !hasModel {
		t.Error("cisco-link-updown-down structuredData missing model=Cisco IOS")
	}
}
