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

// TestJuniperMx240_TrapCatalogLoads mirrors the Cisco-side load test
// for `resources/juniper_mx240/traps.json`. Universal 5 + Juniper 7 = 12
// entries. Weight sum: 100 (universal) + 70 (juniper) = 170.
func TestJuniperMx240_TrapCatalogLoads(t *testing.T) {
	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedCatalog: %v", err)
	}
	result, err := ScanPerTypeTrapCatalogs(universal, "resources")
	if err != nil {
		t.Fatalf("ScanPerTypeTrapCatalogs: %v", err)
	}
	jnx := result["juniper_mx240"]
	if jnx == nil {
		t.Fatal("juniper_mx240 per-type catalog missing from scan result")
	}
	if got := len(jnx.Entries); got != 12 {
		t.Errorf("merged juniper_mx240 trap entries: got %d, want 12 (universal 5 + juniper 7)", got)
	}
	for _, name := range []string{"linkDown", "linkUp", "coldStart", "warmStart", "authenticationFailure"} {
		if _, ok := jnx.ByName[name]; !ok {
			t.Errorf("universal entry %q missing from juniper_mx240 merged catalog", name)
		}
	}
	juniperEntries := []string{
		"jnxPowerSupplyFailure",
		"jnxFanFailure",
		"jnxOverTemperature",
		"jnxFruRemoval",
		"jnxFruInsertion",
		"jnxFruPowerOff",
		"jnxFruFailed",
	}
	for _, name := range juniperEntries {
		if _, ok := jnx.ByName[name]; !ok {
			t.Errorf("juniper-specific entry %q missing from merged catalog", name)
		}
	}
	wantTotal := 100 + 70
	if jnx.totalWeight != wantTotal {
		t.Errorf("merged totalWeight: got %d, want %d", jnx.totalWeight, wantTotal)
	}
}

// TestJuniperMx240_SyslogCatalogLoads mirrors the Cisco-side load test
// for `resources/juniper_mx240/syslog.json`. Universal 6 + Juniper 7 = 13.
func TestJuniperMx240_SyslogCatalogLoads(t *testing.T) {
	universal, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedSyslogCatalog: %v", err)
	}
	result, err := ScanPerTypeSyslogCatalogs(universal, "resources")
	if err != nil {
		t.Fatalf("ScanPerTypeSyslogCatalogs: %v", err)
	}
	jnx := result["juniper_mx240"]
	if jnx == nil {
		t.Fatal("juniper_mx240 per-type syslog catalog missing")
	}
	if got := len(jnx.Entries); got != 13 {
		t.Errorf("merged juniper_mx240 syslog entries: got %d, want 13 (universal 6 + juniper 7)", got)
	}
	// Symmetric with trap-side: pin totalWeight so overlay weight-
	// recompute regressions surface here rather than silently shifting
	// traffic distribution. Universal syslog weights sum to 135
	// (40+40+20+20+10+5); juniper adds 90 (20+20+15+10+10+5+10). Total = 225.
	wantTotal := 135 + 90
	if jnx.totalWeight != wantTotal {
		t.Errorf("merged syslog totalWeight: got %d, want %d", jnx.totalWeight, wantTotal)
	}
	for _, name := range []string{"interface-up", "interface-down", "auth-success", "auth-failure", "config-change", "system-restart"} {
		if _, ok := jnx.ByName[name]; !ok {
			t.Errorf("universal entry %q missing from juniper_mx240 merged syslog catalog", name)
		}
	}
	juniperEntries := []string{
		"juniper-snmp-link-up",
		"juniper-snmp-link-down",
		"juniper-mib2d-encaps-mismatch",
		"juniper-chassisd-temp-critical",
		"juniper-chassisd-eeprom-fail",
		"juniper-license-expired",
		"juniper-ui-commit-complete",
	}
	for _, name := range juniperEntries {
		if _, ok := jnx.ByName[name]; !ok {
			t.Errorf("juniper syslog entry %q missing from merged catalog", name)
		}
	}
}

// TestJuniperMx240_TrapCatalog_ResolveEndToEnd exercises Class 1 field
// substitution through Junos-specific trap entries. Confirms Uptime,
// Serial, and Model make it into the rendered varbinds.
func TestJuniperMx240_TrapCatalog_ResolveEndToEnd(t *testing.T) {
	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	result, err := ScanPerTypeTrapCatalogs(universal, "resources")
	if err != nil {
		t.Fatal(err)
	}
	jnx := result["juniper_mx240"]
	if jnx == nil {
		t.Fatal("juniper_mx240 catalog missing")
	}

	ctx := TemplateCtx{
		IfIndex:   3,
		IfName:    "ge-0/0/3",
		Uptime:    98765,
		Now:       1700000000,
		DeviceIP:  "10.42.0.2",
		SysName:   "rtr-core-01",
		Model:     "Juniper MX240",
		Serial:    synthSerial(net.IPv4(10, 42, 0, 2)),
		ChassisID: synthChassisID(net.IPv4(10, 42, 0, 2)),
	}

	// jnxPowerSupplyFailure uses {{.Model}} + {{.Serial}} in the two
	// chassis-level varbinds (jnxBoxDescr, jnxBoxSerialNo).
	psuEntry := jnx.ByName["jnxPowerSupplyFailure"]
	vbs, err := psuEntry.Resolve(ctx, nil)
	if err != nil {
		t.Fatalf("jnxPowerSupplyFailure resolve: %v", err)
	}
	if len(vbs) < 2 {
		t.Fatalf("PSU failure: got %d varbinds, want 2", len(vbs))
	}
	if vbs[0].Value != "Juniper MX240" {
		t.Errorf("PSU failure jnxBoxDescr: got %q, want 'Juniper MX240'", vbs[0].Value)
	}
	if vbs[1].Value != "SN0A2A0002" {
		t.Errorf("PSU failure jnxBoxSerialNo: got %q, want SN0A2A0002", vbs[1].Value)
	}

	// jnxOverTemperature has a fixed sensor name + temp value 75 (matches
	// the warning threshold used by real MX routers).
	tempEntry := jnx.ByName["jnxOverTemperature"]
	vbs, err = tempEntry.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vbs) < 2 {
		t.Fatalf("over-temperature: got %d varbinds, want 2", len(vbs))
	}
	if vbs[1].Value != "75" {
		t.Errorf("over-temperature value: got %q, want 75", vbs[1].Value)
	}

	// jnxFruPowerOff uses `PEM-{{.Serial}}` in the FRU descriptor.
	pemEntry := jnx.ByName["jnxFruPowerOff"]
	vbs, err = pemEntry.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vbs) == 0 || !strings.Contains(vbs[0].Value, "SN0A2A0002") {
		t.Errorf("FRU power-off descr: got %q, want it to contain PEM-SN0A2A0002", vbs[0].Value)
	}

	// jnxFruFailed uses {{.Model}} in the FRU descriptor AND {{.Uptime}}
	// in the jnxFruLastPowerOff timeticks varbind (.9). Covers the
	// Class 1 template path end-to-end for the most complex entry.
	failedEntry := jnx.ByName["jnxFruFailed"]
	vbs, err = failedEntry.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vbs) < 3 {
		t.Fatalf("FRU failed: got %d varbinds, want 3", len(vbs))
	}
	if !strings.Contains(vbs[0].Value, "Juniper MX240") {
		t.Errorf("FRU failed descr: got %q, want it to contain Juniper MX240", vbs[0].Value)
	}
	if vbs[2].Value != "98765" {
		t.Errorf("FRU failed jnxFruLastPowerOff timeticks: got %q, want 98765 (uptime)", vbs[2].Value)
	}
}

// TestJuniperMx240_SyslogCatalog_ResolveEndToEnd exercises Class 1
// field substitution in Junos syslog entries. Asserts IfName (real
// Junos format ge-0/0/N), Model, Serial, ChassisID, SysName render
// into the message body.
func TestJuniperMx240_SyslogCatalog_ResolveEndToEnd(t *testing.T) {
	universal, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	result, err := ScanPerTypeSyslogCatalogs(universal, "resources")
	if err != nil {
		t.Fatal(err)
	}
	jnx := result["juniper_mx240"]
	if jnx == nil {
		t.Fatal("juniper_mx240 syslog catalog missing")
	}

	ctx := SyslogTemplateCtx{
		DeviceIP:  "10.42.0.2",
		SysName:   "rtr-core-01",
		IfIndex:   7,
		IfName:    "xe-2/0/0",
		Now:       1700000000,
		Uptime:    98765,
		Model:     "Juniper MX240",
		Serial:    synthSerial(net.IPv4(10, 42, 0, 2)),
		ChassisID: synthChassisID(net.IPv4(10, 42, 0, 2)),
	}

	// SNMP_TRAP_LINK_UP renders ifIndex + ifName in Junos's canonical form.
	linkUp := jnx.ByName["juniper-snmp-link-up"]
	resolved, err := linkUp.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantMsg := "SNMP_TRAP_LINK_UP: ifIndex 7, ifAdminStatus up(1), ifOperStatus up(1), ifName xe-2/0/0"
	if resolved.Message != wantMsg {
		t.Errorf("snmp-link-up message:\n got %q\nwant %q", resolved.Message, wantMsg)
	}

	// MIB2D_IFD_IFL_ENCAPS_MISMATCH uses {{.IfName}} in the body.
	mib2d := jnx.ByName["juniper-mib2d-encaps-mismatch"]
	resolved, err = mib2d.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resolved.Message, "xe-2/0/0") {
		t.Errorf("mib2d encaps message should contain IfName=xe-2/0/0: got %q", resolved.Message)
	}

	// CHASSISD_EEPROM_READ_FAIL uses {{.ChassisID}} and {{.Serial}}.
	eeprom := jnx.ByName["juniper-chassisd-eeprom-fail"]
	resolved, err = eeprom.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resolved.Message, "02:42:0a:2a:00:02") {
		t.Errorf("eeprom message should contain ChassisID: got %q", resolved.Message)
	}
	if !strings.Contains(resolved.Message, "SN0A2A0002") {
		t.Errorf("eeprom message should contain Serial: got %q", resolved.Message)
	}

	// CHASSISD_FRU_TEMP_CRITICAL uses {{.Model}}.
	temp := jnx.ByName["juniper-chassisd-temp-critical"]
	resolved, err = temp.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resolved.Message, "Juniper MX240") {
		t.Errorf("temp-critical message should contain Model: got %q", resolved.Message)
	}

	// Structured-data on juniper-snmp-link-down should carry all three
	// declared SD-pairs (ifIndex, ifName, model).
	linkDown := jnx.ByName["juniper-snmp-link-down"]
	resolved, err = linkDown.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var hasIfName, hasModel bool
	for _, sd := range resolved.StructuredData {
		if sd.Key == "ifName" && sd.Value == "xe-2/0/0" {
			hasIfName = true
		}
		if sd.Key == "model" && sd.Value == "Juniper MX240" {
			hasModel = true
		}
	}
	if !hasIfName {
		t.Error("juniper-snmp-link-down structuredData missing ifName=xe-2/0/0")
	}
	if !hasModel {
		t.Error("juniper-snmp-link-down structuredData missing model=Juniper MX240")
	}
}
