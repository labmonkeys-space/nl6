/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
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
// ifIndex 1..48 and 24 LC9600 ports et-1/0/0..et-1/5/3 at 49..72, the one
// configured logical unit xe-0/0/0.0 at 73, and the identity objects
// re-pointed at jnxProductNameMX10004.
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
		"1.3.6.1.2.1.2.1.0":          "73",
		"1.3.6.1.2.1.2.2.1.2.1":      "xe-0/0/0",
		"1.3.6.1.2.1.2.2.1.2.48":     "xe-0/1/23",
		"1.3.6.1.2.1.31.1.1.1.1.48":  "xe-0/1/23",
		"1.3.6.1.2.1.2.2.1.2.49":     "et-1/0/0",
		"1.3.6.1.2.1.2.2.1.2.72":     "et-1/5/3",
		"1.3.6.1.2.1.31.1.1.1.15.49": "400000",
		"1.3.6.1.2.1.2.2.1.2.73":     "xe-0/0/0.0",
		"1.3.6.1.2.1.2.2.1.3.73":     "53",
		"1.3.6.1.2.1.31.1.1.1.1.73":  "xe-0/0/0.0",
	}
	for oid, v := range want {
		if got[oid] != v {
			t.Errorf("%s: got %q, want %q", oid, got[oid], v)
		}
	}
	for i := 1; i <= 72; i++ {
		name := fmt.Sprintf("xe-0/%d/%d", (i-1)/24, (i-1)%24)
		if i > 48 {
			name = fmt.Sprintf("et-1/%d/%d", (i-49)/4, (i-49)%4)
		}
		if d := got[fmt.Sprintf("1.3.6.1.2.1.2.2.1.2.%d", i)]; d != name {
			t.Errorf("ifDescr.%d: got %q, want %q", i, d, name)
		}
	}
	if d, ok := got["1.3.6.1.2.1.2.2.1.2.74"]; ok {
		t.Errorf("ifDescr.74 present (%q); the MX10004 type has 72 ports and one logical unit", d)
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
	ifDescrs := map[string]bool{}
	for _, e := range res.SNMP {
		if strings.HasPrefix(e.OID, "1.3.6.1.2.1.2.2.1.2.") {
			ifDescrs[e.Response] = true
			if !strings.Contains(terse, e.Response+" ") {
				t.Errorf("ifDescr %s not listed by show interfaces terse", e.Response)
			}
		}
	}
	if len(ifDescrs) != 73 {
		t.Fatalf("SNMP serves %d interfaces, want 72 ports and one logical unit", len(ifDescrs))
	}
	// And the reverse for line-card interfaces: every xe- or et- interface
	// or unit the CLI lists is an IF-MIB row. fxp0 and lo0 are CLI-only.
	for _, line := range strings.Split(terse, "\n")[1:] {
		if f := strings.Fields(line); len(f) > 0 && (strings.HasPrefix(f[0], "xe-") || strings.HasPrefix(f[0], "et-")) && !ifDescrs[f[0]] {
			t.Errorf("show interfaces terse lists %s, which IF-MIB does not serve", f[0])
		}
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
			return false // per-port components; the PICs are LINECARD sub-cards and are printed
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

// TestJuniperMx10004_LogicalUnitAgreesAcrossGnmiAndIfMib: gNMI served a unit 0
// under every port with its parent's name and ifIndex while IF-MIB served no
// unit. The subinterfaces are now the device's logical units, each reading its
// own IF-MIB row, and a unit is not also a top-level interface.
func TestJuniperMx10004_LogicalUnitAgreesAcrossGnmiAndIfMib(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("juniper_mx10004.json")
	if err != nil {
		t.Fatal(err)
	}
	mc := &MetricsCycler{}
	mc.InitIfCounters(res, 1)
	dev := &DeviceSimulator{ID: "mx10004", IP: net.IPv4(10, 42, 0, 10), resourceFile: "juniper_mx10004.json", resources: res, metricsCycler: mc}
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(dev, cats["juniper_mx10004"])
	now := time.Now()

	ns, err := r.Resolve(pathFromString(t, "/interfaces/interface/subinterfaces/subinterface/state"), now)
	if err != nil {
		t.Fatal(err)
	}
	type unit struct{ parent, index, name, ifindex string }
	var got []unit
	for _, n := range ns {
		u := unit{}
		for _, e := range n.Prefix.GetElem() {
			switch e.GetName() {
			case "interface":
				u.parent = e.GetKey()["name"]
			case "subinterface":
				u.index = e.GetKey()["index"]
			}
		}
		for _, up := range n.Updates {
			switch pathToString(up.Path) {
			case "/state/name":
				u.name = fmt.Sprint(up.Value)
			case "/state/ifindex":
				u.ifindex = fmt.Sprint(up.Value)
			}
		}
		got = append(got, u)
	}
	want := []unit{{"xe-0/0/0", "0", "xe-0/0/0.0", "73"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("subinterfaces = %+v, want %+v", got, want)
	}

	ns, err = r.Resolve(pathFromString(t, "/interfaces/interface/state/name"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 72 {
		t.Errorf("%d interfaces, want the 72 ports", len(ns))
	}
	for _, n := range ns {
		for _, up := range n.Updates {
			if v := fmt.Sprint(up.Value); strings.Contains(v, ".") {
				t.Errorf("logical unit %s served as a top-level interface", v)
			}
		}
	}
	ns, err = r.Resolve(pathFromString(t, "/interfaces/interface/state/counters/out-queue"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 72*8 {
		t.Errorf("%d out-queues, want 8 for each of the 72 ports", len(ns))
	}
}

// TestJuniperMx10004_DualRoutingEngine: both Routing Engines and both
// control boards appear in gNMI, SNMP and SSH, and the RE serves eight CPUs.
func TestJuniperMx10004_DualRoutingEngine(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("juniper_mx10004.json")
	if err != nil {
		t.Fatal(err)
	}
	snmp := map[string]string{}
	for _, e := range res.SNMP {
		snmp[e.OID] = e.Response
	}
	for slot := 0; slot < 2; slot++ {
		oid := fmt.Sprintf("1.3.6.1.4.1.2636.3.1.13.1.5.9.%d.0.0", slot+1)
		if want := fmt.Sprintf("Routing Engine %d", slot); snmp[oid] != want {
			t.Errorf("jnxOperatingDescr %s = %q, want %q", oid, snmp[oid], want)
		}
	}
	ssh := map[string]string{}
	for _, e := range res.SSH {
		ssh[e.Command] = e.Response
	}
	re := ssh["show chassis routing-engine"]
	if !strings.Contains(re, "Slot 1:") || !strings.Contains(re, "Backup") {
		t.Errorf("show chassis routing-engine lacks a backup in slot 1")
	}
	for _, s := range []string{"Routing Engine 1", "CB 1"} {
		if !strings.Contains(ssh["show chassis hardware"], s) || !strings.Contains(ssh["show chassis environment"], s) {
			t.Errorf("%s missing from show chassis hardware or environment", s)
		}
	}
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	cat := cats["juniper_mx10004"]
	names := map[string]bool{}
	for _, c := range cat.Components {
		names[c.Name] = true
	}
	for _, n := range []string{"Routing Engine0", "Routing Engine1", "ROUTING_ENGINE1:CPU", "CB0", "CB1", "CB1:MIDDLE_TEMP_SENSOR"} {
		if !names[n] {
			t.Errorf("gNMI component %s missing", n)
		}
	}
	cpus := -1
	for _, st := range cat.Subtrees {
		if st.Path == "/system/cpus/cpu[index=*]" {
			cpus = len(st.Keys[0].Names)
		}
	}
	if cpus != 8 {
		t.Errorf("/system/cpus/cpu serves %d indexes, want 8 (what MX10004 hardware reports)", cpus)
	}
}

// TestJuniperMx10004_EntityMIBMatchesInventory: every board gNMI lists and
// SSH prints is an ENTITY-MIB entity with the same serial and part number,
// every port is a port entity, and each port entity's alias points at the
// ifIndex whose ifDescr names the same port.
func TestJuniperMx10004_EntityMIBMatchesInventory(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("juniper_mx10004.json")
	if err != nil {
		t.Fatal(err)
	}
	snmp := map[string]string{}
	for _, e := range res.SNMP {
		snmp[strings.TrimPrefix(e.OID, ".")] = e.Response
	}
	const ent = "1.3.6.1.2.1.47.1.1.1.1."
	bySerial := map[string]string{} // serial -> entity index
	for oid, v := range snmp {
		if rest, ok := strings.CutPrefix(oid, ent+"11."); ok {
			bySerial[v] = rest
		}
	}
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cats["juniper_mx10004"].Components {
		switch {
		case c.Type == "SENSOR" || c.Type == "TRANSCEIVER" || strings.Contains(c.Name, " Fan "):
			continue
		}
		idx, ok := bySerial[c.SerialNo]
		if !ok {
			t.Errorf("%s (serial %s) has no entity", c.Name, c.SerialNo)
			continue
		}
		if c.Type == "PORT" {
			if snmp[ent+"5."+idx] != "10" {
				t.Errorf("port %s entity %s has class %s, want port(10)", c.Name, idx, snmp[ent+"5."+idx])
			}
			alias := snmp["1.3.6.1.2.1.47.1.3.2.1.2."+idx+".0"]
			ifIndex, ok := strings.CutPrefix(alias, "1.3.6.1.2.1.2.2.1.1.")
			if !ok || snmp["1.3.6.1.2.1.2.2.1.2."+ifIndex] != c.Description {
				t.Errorf("port %s entity %s aliases %q, whose ifDescr is not %s", c.Name, idx, alias, c.Description)
			}
			continue
		}
		if c.Name == "Chassis" && idx != "1" {
			t.Errorf("the chassis serial %s names entity %s, want entity 1", c.SerialNo, idx)
		}
		if snmp[ent+"13."+idx] != c.PartNo {
			t.Errorf("%s entity %s model %q, want %q", c.Name, idx, snmp[ent+"13."+idx], c.PartNo)
		}
		// gNMI serves hardware-version REV 06 and software 24.2R1.17 on
		// every component, and `show chassis hardware` prints REV 06.
		if hw, sw := snmp[ent+"8."+idx], snmp[ent+"10."+idx]; hw != "REV 06" || sw != "24.2R1.17" {
			t.Errorf("%s entity %s revisions %q / %q, want REV 06 / 24.2R1.17", c.Name, idx, hw, sw)
		}
	}
	for oid, v := range snmp {
		if strings.HasPrefix(oid, ent+"2.") && (strings.HasPrefix(v, "xe-1/") || strings.HasPrefix(v, "xe-2/") || strings.HasPrefix(v, "MPC")) {
			t.Errorf("MX240 entity %s = %q still served", oid, v)
		}
	}
}

// TestJuniperMx10004_SSHRoutingEngineAndCBMatchModel: every Routing Engine
// and control board the gNMI catalogue lists appears in the SSH
// routing-engine and environment output, with the same serial.
func TestJuniperMx10004_SSHRoutingEngineAndCBMatchModel(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("juniper_mx10004.json")
	if err != nil {
		t.Fatal(err)
	}
	ssh := map[string]string{}
	for _, e := range res.SSH {
		ssh[e.Command] = e.Response
	}
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	reOut, env := ssh["show chassis routing-engine"], ssh["show chassis environment"]
	res0, cbs := 0, 0
	for _, c := range cats["juniper_mx10004"].Components {
		var n int
		if c.Type == "CONTROLLER_CARD" {
			if _, err := fmt.Sscanf(c.Name, "Routing Engine%d", &n); err == nil {
				res0++
				slot := fmt.Sprintf("Slot %d:", n)
				i := strings.Index(reOut, slot)
				if i < 0 {
					t.Errorf("show chassis routing-engine lacks %q", slot)
					continue
				}
				block := reOut[i:]
				if next := strings.Index(block[len(slot):], "Slot "); next >= 0 {
					block = block[:len(slot)+next]
				}
				if !strings.Contains(block, "Serial ID") || !strings.Contains(block, c.SerialNo) {
					t.Errorf("%s: slot block lacks Serial ID %s", c.Name, c.SerialNo)
				}
				if !strings.Contains(env, fmt.Sprintf("Routing Engine %d", n)) {
					t.Errorf("show chassis environment lacks Routing Engine %d", n)
				}
			}
		}
		if _, err := fmt.Sscanf(c.Name, "CB%d", &n); err == nil && !strings.Contains(c.Name, ":") {
			cbs++
			if !strings.Contains(env, fmt.Sprintf("CB %d ", n)) {
				t.Errorf("show chassis environment lacks CB %d", n)
			}
		}
	}
	if res0 != 2 || cbs != 2 {
		t.Errorf("found %d Routing Engines and %d CBs in gNMI, want 2 each", res0, cbs)
	}
}
