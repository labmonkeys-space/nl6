/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// optical_alarm_manager_test.go — publication half of #347 (tasks 6.5-6.8):
// the catalog overlays and the crossing-to-notification wiring.

// TestOpticalTrapOverlayMatchesTheMIB is the transcription guard. Every value
// here was traced from CIENA-WS-NOTIFICATION-MIB.mib; a fabricated OID,
// severity or flag value is the exact false pass this device type exists to
// prevent, and it is invisible until a collector fails against real hardware.
func TestOpticalTrapOverlayMatchesTheMIB(t *testing.T) {
	// Asserted against the JSON rather than the loaded catalog on purpose:
	// this is a transcription guard, and the shipped file is the artifact that
	// has to match the MIB. The loader compiles varbinds into templates and
	// hides the raw OID/value, so it cannot answer the question being asked.
	b, err := os.ReadFile("resources/ciena_waveserver5/traps.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Traps []struct {
			Name        string `json:"name"`
			Role        string `json:"role"`
			SnmpTrapOID string `json:"snmpTrapOID"`
			Varbinds    []struct {
				OID   string `json:"oid"`
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"varbinds"`
		} `json:"traps"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}

	// Varbind OIDs are the INSTANCES (object.0) an SMIv2 agent emits, not
	// the bare object OIDs — a collector matching the exact instance OID a
	// real Waveserver sends would never match the bare form.
	const (
		notifOID = "1.3.6.1.4.1.1271.3.2.12" // wsLinkStateAlarmNotification
		sevOID   = notifOID + ".7.0"         // ...Severity instance
		sfOID    = notifOID + ".12.4.0"      // ...OtuDefects.OtuPreFecSf instance
		sdOID    = notifOID + ".12.5.0"      // ...OtuDefects.OtuPreFecSd instance
		entOID   = notifOID + ".14.0"        // ...EntityType instance
		dateOID  = notifOID + ".5.0"         // ...DateAndTime instance
	)
	want := map[string]struct {
		role     string
		severity string // MIB enum: cleared(1) critical(3) major(4) minor(5) warning(6) info(8)
		sd, sf   string // condition flags: inactive(0) / active(1)
	}{
		"opticalPreFecSdRaise": {roleOpticalSDRaise, "5", "1", "0"},
		"opticalPreFecSdClear": {roleOpticalSDClear, "1", "0", "0"},
		"opticalPreFecSfRaise": {roleOpticalSFRaise, "3", "0", "1"},
		"opticalPreFecSfClear": {roleOpticalSFClear, "1", "0", "0"},
	}
	if len(doc.Traps) != len(want) {
		t.Fatalf("overlay has %d entries, want %d", len(doc.Traps), len(want))
	}

	for _, e := range doc.Traps {
		exp, ok := want[e.Name]
		if !ok {
			t.Errorf("unexpected entry %q", e.Name)
			continue
		}
		if e.Role != exp.role {
			t.Errorf("%s: role %q, want %q", e.Name, e.Role, exp.role)
		}
		// Ciena models raise and clear as ONE notification type whose varbinds
		// carry the state, so all four entries MUST share the trap OID. A
		// distinct OID per direction would be invented.
		if e.SnmpTrapOID != notifOID {
			t.Errorf("%s: trap OID %q, want the shared %q", e.Name, e.SnmpTrapOID, notifOID)
		}
		vb := map[string]string{}
		for _, v := range e.Varbinds {
			if _, dup := vb[v.OID]; dup {
				t.Errorf("%s: duplicate varbind OID %s", e.Name, v.OID)
			}
			vb[v.OID] = v.Value
		}
		if got := vb[sevOID]; got != exp.severity {
			t.Errorf("%s: severity %q, want %q (the MIB enum is non-contiguous)", e.Name, got, exp.severity)
		}
		if got := vb[sdOID]; got != exp.sd {
			t.Errorf("%s: OtuPreFecSd %q, want %q", e.Name, got, exp.sd)
		}
		if got := vb[sfOID]; got != exp.sf {
			t.Errorf("%s: OtuPreFecSf %q, want %q", e.Name, got, exp.sf)
		}
		// Condition flags are inactive(0)/active(1) throughout. A summary
		// claiming active(2)/inactive(1) was wrong; this is where that returns.
		for oid, val := range vb {
			bare := strings.TrimSuffix(oid, ".0")
			if !strings.HasPrefix(bare, notifOID+".1") || len(strings.Split(bare, ".")) != 12 {
				continue
			}
			if bare == strings.TrimSuffix(entOID, ".0") {
				continue // EntityType is an enum, not a condition flag
			}
			if val != "0" && val != "1" {
				t.Errorf("%s: condition flag %s = %q; the MIB enum is inactive(0)/active(1)", e.Name, oid, val)
			}
			if !strings.HasSuffix(oid, ".0") {
				t.Errorf("%s: varbind %s lacks the .0 instance sub-identifier", e.Name, oid)
			}
		}
		// EntityType: line-side alarm => linePort(3), and LAST per the
		// OBJECTS clause so positional parsers see the flags unshifted.
		if got := vb[entOID]; got != "3" {
			t.Errorf("%s: EntityType %q, want linePort(3)", e.Name, got)
		}
		if last := e.Varbinds[len(e.Varbinds)-1].OID; last != entOID {
			t.Errorf("%s: last varbind is %s, want EntityType %s", e.Name, last, entOID)
		}
		// DateAndTime is a DisplayString date, not epoch seconds.
		if got := vb[dateOID]; got != "{{.NowLocal}}" {
			t.Errorf("%s: DateAndTime template %q, want {{.NowLocal}}", e.Name, got)
		}
	}

	// And it must actually load, with the roles intact.
	cat, err := LoadCatalogFromFile("resources/ciena_waveserver5/traps.json")
	if err != nil {
		t.Fatalf("overlay does not load: %v", err)
	}
	for _, e := range cat.Entries {
		if want[e.Name].role != e.Role {
			t.Errorf("loaded %s has role %q", e.Name, e.Role)
		}
	}
}

// TestOpticalSyslogOverlayMirrorsTrapRoles: every trap role must have a syslog
// counterpart, or a crossing produces half a notification and a collector
// correlating the two surfaces sees a gap.
func TestOpticalSyslogOverlayMirrorsTrapRoles(t *testing.T) {
	traps, err := LoadCatalogFromFile("resources/ciena_waveserver5/traps.json")
	if err != nil {
		t.Fatalf("load trap overlay: %v", err)
	}
	logs, err := LoadSyslogCatalogFromFile("resources/ciena_waveserver5/syslog.json")
	if err != nil {
		t.Fatalf("load syslog overlay: %v", err)
	}
	syslogRoles := map[string]bool{}
	for _, e := range logs.Entries {
		syslogRoles[e.Role] = true
	}
	for _, e := range traps.Entries {
		if !syslogRoles[e.Role] {
			t.Errorf("trap role %q has no syslog counterpart", e.Role)
		}
	}
}

// TestOpticalRolesAreValid: the loader must accept the four optical roles.
// Before the enum was extended it rejected them outright, so the overlays
// would not have loaded at all.
func TestOpticalRolesAreValid(t *testing.T) {
	for _, r := range []string{roleOpticalSDRaise, roleOpticalSDClear, roleOpticalSFRaise, roleOpticalSFClear} {
		if !validRole(r) {
			t.Errorf("validRole(%q) = false", r)
		}
	}
	if validRole("optical-sd") {
		t.Error("validRole accepted an unknown optical role")
	}
}

// TestOpticalRoleForMapsEveryTransition covers the 2x2 of condition and
// direction, so no transition can silently map to the empty role (which
// EntriesByRole answers with nil, publishing nothing).
func TestOpticalRoleForMapsEveryTransition(t *testing.T) {
	cases := []struct {
		cond   opticalCondition
		raised bool
		want   string
	}{
		{opticalCondSD, true, roleOpticalSDRaise},
		{opticalCondSD, false, roleOpticalSDClear},
		{opticalCondSF, true, roleOpticalSFRaise},
		{opticalCondSF, false, roleOpticalSFClear},
	}
	for _, tc := range cases {
		if got := opticalRoleFor(tc.cond, tc.raised); got != tc.want {
			t.Errorf("opticalRoleFor(%v, raised=%v) = %q, want %q", tc.cond, tc.raised, got, tc.want)
		}
	}
}

// TestOpticalAlarmReachesTheWire is the end-to-end proof: a crossing published
// by the evaluator must arrive at a real collector as a real datagram. Every
// layer in between (role lookup, overlay entry, exporter, UDP) is exercised.
func TestOpticalAlarmReachesTheWire(t *testing.T) {
	mc := newMockCollector(t, false)
	defer mc.Close()

	omc := &MetricsCycler{}
	omc.InitOpticalCycler(twoChannelInventory(), 51, opticalBandFor(OpticalClean))
	dev := &DeviceSimulator{
		ID: "optical", IP: net.IPv4(127, 0, 0, 1),
		resourceFile: opticalResourceFile, metricsCycler: omc,
	}
	dev.trapExporter = newScenarioTrapExporter(t, TrapModeTrap, mc.addr)
	defer dev.trapExporter.Close()

	mgr := &SimulatorManager{
		devices:          map[string]*DeviceSimulator{dev.ID: dev},
		deviceIPs:        map[string]struct{}{dev.IP.String(): {}},
		deviceTypesByIP:  map[string]string{dev.IP.String(): "ciena_waveserver5"},
		resourcesCache:   map[string]*DeviceResources{},
		tunInterfacePool: map[string]*TunInterface{},
	}
	mgr.indexDeviceByIP(dev)
	t.Cleanup(swapGlobalManager(mgr))
	cat, err := LoadCatalogFromFile("resources/ciena_waveserver5/traps.json")
	if err != nil {
		t.Fatalf("load overlay: %v", err)
	}
	mgr.trapCatalogsByType = map[string]*Catalog{"ciena_waveserver5": cat}

	mgr.publishOpticalAlarm(OpticalAlarmEvent{
		DeviceIP: dev.IP, Component: "OCH-1-1",
		Condition: opticalCondSF, Raised: true, OSNRdB: 11.2,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && mc.received.Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if mc.received.Load() == 0 {
		t.Fatal("crossing published no trap to the collector")
	}
}

// TestOpticalOverlayIsValidJSON guards the generated file against a
// hand-edit that breaks its shape without breaking the loader's tolerance.
func TestOpticalOverlayIsValidJSON(t *testing.T) {
	for _, p := range []string{"resources/ciena_waveserver5/traps.json", "resources/ciena_waveserver5/syslog.json"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		if _, ok := v["extends"]; !ok {
			t.Errorf("%s: missing \"extends\"; a per-type overlay defaults to merge and should say so", p)
		}
	}
}

// TestOpticalAlarmRegisterReplacesStaleCycler pins the fix for the
// delete/re-create family of findings: a re-register on the same
// (ip, component) with the SAME engine keeps the latch (no alarm replay),
// but a DIFFERENT engine — a re-created device — must replace the entry,
// with fresh latches, or the evaluator stays pinned to the dead device's
// band and start time forever.
func TestOpticalAlarmRegisterReplacesStaleCycler(t *testing.T) {
	ev := NewOpticalAlarmEvaluator(OpticalAlarmEvaluatorOptions{})
	ip := net.IPv4(10, 42, 0, 1)
	oc1 := newOpticalCycler(t, 61, opticalBandFor(OpticalClean))
	oc2 := newOpticalCycler(t, 62, opticalBandFor(OpticalFailing))

	ev.Register(ip, oc1)
	ev.mu.Lock()
	key := opticalAlarmKey{ip: "10.42.0.1", component: "OCH-1-1"}
	ev.byKey[key].sd.raised = true // simulate a published alarm on the old device
	ev.mu.Unlock()

	// Same engine: keep the latch.
	ev.Register(ip, oc1)
	ev.mu.Lock()
	if !ev.byKey[key].sd.raised {
		t.Error("re-registering the SAME engine reset the latch; a re-enrol may not replay alarms")
	}
	ev.mu.Unlock()

	// Different engine: replace, fresh latches, heap size unchanged.
	ev.Register(ip, oc2)
	ev.mu.Lock()
	defer ev.mu.Unlock()
	if got := ev.byKey[key].oc; got != oc2 {
		t.Fatal("entry still points at the old device's cycler after re-create")
	}
	if ev.byKey[key].sd.raised {
		t.Error("replacement kept the dead device's alarm state; a new device starts clean")
	}
	if ev.heap.Len() != 2 {
		t.Errorf("heap has %d entries after replacement, want 2 (no leak, no loss)", ev.heap.Len())
	}
}

// TestOpticalAlarmFirstEvalIsStaggered: without phase spreading every channel
// of every device comes due at the same instant and the evaluator processes
// the fleet as one back-to-back burst per cycle.
func TestOpticalAlarmFirstEvalIsStaggered(t *testing.T) {
	ev := NewOpticalAlarmEvaluator(OpticalAlarmEvaluatorOptions{})
	oc := newOpticalCycler(t, 63, opticalBandFor(OpticalClean))
	ev.Register(net.IPv4(10, 42, 0, 1), oc)
	ev.mu.Lock()
	defer ev.mu.Unlock()
	if ev.heap.Len() != 2 {
		t.Fatalf("expected both channels enrolled, got %d", ev.heap.Len())
	}
	if ev.heap[0].nextEval.Equal(ev.heap[1].nextEval) {
		t.Error("both channels share the same first nextEval; first evaluations must be phase-spread")
	}
}

// TestOpticalAlarmDeleteLifecycle covers the two deregistration findings at
// manager level: a freeze-REJECTED delete must NOT silence a live device's
// alarms (the first cut deregistered before the freeze check), and a
// successful delete-all must empty the evaluator.
func TestOpticalAlarmDeleteLifecycle(t *testing.T) {
	omc := &MetricsCycler{}
	omc.InitOpticalCycler(twoChannelInventory(), 64, opticalBandFor(OpticalClean))
	dev := &DeviceSimulator{
		ID: "optical", IP: net.IPv4(10, 42, 0, 1),
		resourceFile: opticalResourceFile, metricsCycler: omc,
	}
	mgr := &SimulatorManager{
		devices:          map[string]*DeviceSimulator{dev.ID: dev},
		deviceIPs:        map[string]struct{}{dev.IP.String(): {}},
		deviceTypesByIP:  map[string]string{},
		resourcesCache:   map[string]*DeviceResources{},
		tunInterfacePool: map[string]*TunInterface{},
	}
	mgr.indexDeviceByIP(dev)
	t.Cleanup(swapGlobalManager(mgr))

	ev := NewOpticalAlarmEvaluator(OpticalAlarmEvaluatorOptions{})
	mgr.mu.Lock()
	mgr.opticalAlarms = ev
	mgr.mu.Unlock()
	mgr.RegisterOpticalDevice(dev)
	if _, _, ok := ev.ActiveAlarms("10.42.0.1", "OCH-1-1"); !ok {
		t.Fatal("device did not enrol")
	}

	// Freeze-rejected delete: device stays alive, and MUST stay enrolled.
	if err := mgr.freezeFleet("s-test"); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if err := mgr.DeleteDevice(dev.ID); err == nil {
		t.Fatal("delete succeeded under freeze; expected rejection")
	}
	if _, _, ok := ev.ActiveAlarms("10.42.0.1", "OCH-1-1"); !ok {
		t.Fatal("freeze-rejected delete silenced a live device's alarms")
	}
	mgr.unfreezeFleet()

	// Successful delete-all: enrolment must be gone.
	if err := mgr.DeleteAllDevices(); err != nil {
		t.Fatalf("delete-all: %v", err)
	}
	if _, _, ok := ev.ActiveAlarms("10.42.0.1", "OCH-1-1"); ok {
		t.Fatal("delete-all left the device enrolled; stale cycler pinned")
	}
}
