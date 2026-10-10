/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// TestJuniperMx10004_TrapCatalogLoads mirrors the Cisco-side load test
// for `resources/juniper_mx10004/traps.json`. Universal 5 + Juniper 7 = 12
// entries. Weight sum: 100 (universal) + 70 (juniper) = 170.
func TestJuniperMx10004_TrapCatalogLoads(t *testing.T) {
	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedCatalog: %v", err)
	}
	result, err := ScanPerTypeTrapCatalogs(universal, "resources")
	if err != nil {
		t.Fatalf("ScanPerTypeTrapCatalogs: %v", err)
	}
	jnx := result["juniper_mx10004"]
	if jnx == nil {
		t.Fatal("juniper_mx10004 per-type catalog missing from scan result")
	}
	if got := len(jnx.Entries); got != 12 {
		t.Errorf("merged juniper_mx10004 trap entries: got %d, want 12 (universal 5 + juniper 7)", got)
	}
	for _, name := range []string{"linkDown", "linkUp", "coldStart", "warmStart", "authenticationFailure"} {
		if _, ok := jnx.ByName[name]; !ok {
			t.Errorf("universal entry %q missing from juniper_mx10004 merged catalog", name)
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

// TestJuniperMx10004_SyslogCatalogLoads mirrors the Cisco-side load test
// for `resources/juniper_mx10004/syslog.json`. Universal 6 + Juniper 7 = 13.
func TestJuniperMx10004_SyslogCatalogLoads(t *testing.T) {
	universal, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedSyslogCatalog: %v", err)
	}
	result, err := ScanPerTypeSyslogCatalogs(universal, "resources")
	if err != nil {
		t.Fatalf("ScanPerTypeSyslogCatalogs: %v", err)
	}
	jnx := result["juniper_mx10004"]
	if jnx == nil {
		t.Fatal("juniper_mx10004 per-type syslog catalog missing")
	}
	if got := len(jnx.Entries); got != 13 {
		t.Errorf("merged juniper_mx10004 syslog entries: got %d, want 13 (universal 6 + juniper 7)", got)
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
			t.Errorf("universal entry %q missing from juniper_mx10004 merged syslog catalog", name)
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

// TestJuniperMx10004_TrapCatalog_ResolveEndToEnd exercises Class 1 field
// substitution through Junos-specific trap entries. Confirms Uptime,
// Serial, and Model make it into the rendered varbinds.
func TestJuniperMx10004_TrapCatalog_ResolveEndToEnd(t *testing.T) {
	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatal(err)
	}
	result, err := ScanPerTypeTrapCatalogs(universal, "resources")
	if err != nil {
		t.Fatal(err)
	}
	jnx := result["juniper_mx10004"]
	if jnx == nil {
		t.Fatal("juniper_mx10004 catalog missing")
	}

	ctx := TemplateCtx{
		IfIndex:   1,
		IfName:    "xe-0/0/0",
		Uptime:    98765,
		Now:       1700000000,
		DeviceIP:  "10.42.0.2",
		SysName:   "rtr-core-01",
		Model:     "Juniper MX10004",
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
	if vbs[0].Value != "Juniper MX10004" {
		t.Errorf("PSU failure jnxBoxDescr: got %q, want 'Juniper MX10004'", vbs[0].Value)
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
	if !strings.Contains(vbs[0].Value, "Juniper MX10004") {
		t.Errorf("FRU failed descr: got %q, want it to contain Juniper MX10004", vbs[0].Value)
	}
	if vbs[2].Value != "98765" {
		t.Errorf("FRU failed jnxFruLastPowerOff timeticks: got %q, want 98765 (uptime)", vbs[2].Value)
	}
}

// TestJuniperMx10004_SyslogCatalog_ResolveEndToEnd exercises Class 1
// field substitution in Junos syslog entries. Asserts IfName (real
// Junos format xe-0/PIC/N), Model, Serial, ChassisID, SysName render
// into the message body.
func TestJuniperMx10004_SyslogCatalog_ResolveEndToEnd(t *testing.T) {
	universal, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	result, err := ScanPerTypeSyslogCatalogs(universal, "resources")
	if err != nil {
		t.Fatal(err)
	}
	jnx := result["juniper_mx10004"]
	if jnx == nil {
		t.Fatal("juniper_mx10004 syslog catalog missing")
	}

	ctx := SyslogTemplateCtx{
		DeviceIP:  "10.42.0.2",
		SysName:   "rtr-core-01",
		IfIndex:   48,
		IfName:    "xe-0/1/23",
		Now:       1700000000,
		Uptime:    98765,
		Model:     "Juniper MX10004",
		Serial:    synthSerial(net.IPv4(10, 42, 0, 2)),
		ChassisID: synthChassisID(net.IPv4(10, 42, 0, 2)),
	}

	// SNMP_TRAP_LINK_UP renders ifIndex + ifName in Junos's canonical form.
	linkUp := jnx.ByName["juniper-snmp-link-up"]
	resolved, err := linkUp.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantMsg := "SNMP_TRAP_LINK_UP: ifIndex 48, ifAdminStatus up(1), ifOperStatus up(1), ifName xe-0/1/23"
	if resolved.Message != wantMsg {
		t.Errorf("snmp-link-up message:\n got %q\nwant %q", resolved.Message, wantMsg)
	}

	// MIB2D_IFD_IFL_ENCAPS_MISMATCH uses {{.IfName}} in the body.
	mib2d := jnx.ByName["juniper-mib2d-encaps-mismatch"]
	resolved, err = mib2d.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resolved.Message, "xe-0/1/23") {
		t.Errorf("mib2d encaps message should contain IfName=xe-0/1/23: got %q", resolved.Message)
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
	if !strings.Contains(resolved.Message, "Juniper MX10004") {
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
		if sd.Key == "ifName" && sd.Value == "xe-0/1/23" {
			hasIfName = true
		}
		if sd.Key == "model" && sd.Value == "Juniper MX10004" {
			hasModel = true
		}
	}
	if !hasIfName {
		t.Error("juniper-snmp-link-down structuredData missing ifName=xe-0/1/23")
	}
	if !hasModel {
		t.Error("juniper-snmp-link-down structuredData missing model=Juniper MX10004")
	}
}

// TestJuniperMx10004_InterfaceTableAndIdentity pins what the clone script
// produced from the MX240 template: 48 LC480 ports xe-0/0/0..xe-0/1/23 at
// ifIndex 1..48, and the identity objects re-pointed at jnxProductNameMX10004.
func TestJuniperMx10004_InterfaceTableAndIdentity(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("juniper_mx10004.json")
	if err != nil {
		t.Fatalf("LoadSpecificResources(juniper_mx10004.json): %v", err)
	}
	got := make(map[string]string, len(res.SNMP))
	for _, e := range res.SNMP {
		got[e.OID] = e.Response
	}
	want := map[string]string{
		"1.3.6.1.2.1.1.1.0":          "Juniper Networks, Inc. mx10004 internet router, kernel JUNOS 24.2R1.17, Build date: 2024-06-18",
		"1.3.6.1.2.1.1.2.0":          "1.3.6.1.4.1.2636.1.1.1.2.168",
		"1.3.6.1.2.1.47.1.1.1.1.3.1": "1.3.6.1.4.1.2636.1.1.1.2.168",
		"1.3.6.1.2.1.2.1.0":          "48",
		"1.3.6.1.2.1.2.2.1.2.1":      "xe-0/0/0",
		"1.3.6.1.2.1.2.2.1.2.48":     "xe-0/1/23",
		"1.3.6.1.2.1.31.1.1.1.1.48":  "xe-0/1/23",
	}
	for oid, v := range want {
		if got[oid] != v {
			t.Errorf("%s: got %q, want %q", oid, got[oid], v)
		}
	}
	for i := 1; i <= 48; i++ {
		name := fmt.Sprintf("xe-0/%d/%d", (i-1)/24, (i-1)%24)
		if d := got[fmt.Sprintf("1.3.6.1.2.1.2.2.1.2.%d", i)]; d != name {
			t.Errorf("ifDescr.%d: got %q, want %q", i, d, name)
		}
	}
	if d, ok := got["1.3.6.1.2.1.2.2.1.2.49"]; ok {
		t.Errorf("ifDescr.49 present (%q); the MX10004 type has exactly 48 ports", d)
	}
}

// TestJuniperMx10004_SSHAgreesWithSNMPAndGNMI: the SSH resource was
// byte-copied from the MX240 and named ge- ports and MPC line cards
// that neither SNMP nor gNMI serve (nl6#769). SSH must name every
// ifDescr SNMP serves, no ge- port, and every part number the gNMI
// inventory carries.
func TestJuniperMx10004_SSHAgreesWithSNMPAndGNMI(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("juniper_mx10004.json")
	if err != nil {
		t.Fatal(err)
	}
	ssh := map[string]string{}
	for _, e := range res.SSH {
		ssh[e.Command] = e.Response
	}
	terse, hw := ssh["show interfaces terse"], ssh["show chassis hardware"]
	if terse == "" || hw == "" {
		t.Fatalf("show interfaces terse / show chassis hardware missing from the SSH resource")
	}
	if strings.Contains(terse, "ge-") || strings.Contains(hw, "MPC Type 2") || strings.Contains(hw, "RE-S-2000") {
		t.Errorf("SSH still carries MX240 content")
	}
	ports := 0
	for _, e := range res.SNMP {
		if strings.HasPrefix(e.OID, "1.3.6.1.2.1.2.2.1.2.") {
			ports++
			if !strings.Contains(terse, e.Response+" ") {
				t.Errorf("ifDescr %s not listed by show interfaces terse", e.Response)
			}
		}
	}
	if ports != 48 {
		t.Fatalf("SNMP serves %d ports, want 48", ports)
	}
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	// Junos prints boards, PICs, transceivers, fan trays and power
	// supplies in show chassis hardware; sensors, single fans and port
	// entries are gNMI-only components.
	printed := func(c gnmiCatalogComponent) bool {
		switch c.Type {
		case "SENSOR":
			return false
		case "FAN":
			return !strings.Contains(c.Name, " Fan ")
		case "PORT":
			return !strings.Contains(c.Name, ":PORT")
		}
		return true
	}
	for _, c := range cats["juniper_mx10004"].Components {
		if printed(c) && (!strings.Contains(hw, c.PartNo) || !strings.Contains(hw, c.SerialNo)) {
			t.Errorf("gNMI component %s (part %s, serial %s) absent from show chassis hardware", c.Name, c.PartNo, c.SerialNo)
		}
	}
	// And the reverse: every serial SSH prints is a gNMI component, so
	// the two inventories agree in both directions.
	gnmiSerials := map[string]bool{}
	for _, c := range cats["juniper_mx10004"].Components {
		gnmiSerials[c.SerialNo] = true
	}
	for _, line := range strings.Split(hw, "\n") {
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "NL6") && !gnmiSerials[f] {
				t.Errorf("SSH serial %s has no gNMI component", f)
			}
		}
	}
}
