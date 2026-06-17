/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Catalog role field: load, validate, scheduler-exclusion --------------

func TestCatalogRole_LoadValidateExclusion(t *testing.T) {
	body := `{"traps":[
		{"name":"down","snmpTrapOID":"1.3.6.1.6.3.1.1.5.3","weight":40,"role":"link-down"},
		{"name":"up","snmpTrapOID":"1.3.6.1.6.3.1.1.5.4","weight":40,"role":"link-up"},
		{"name":"cold","snmpTrapOID":"1.3.6.1.6.3.1.1.5.1","weight":20}
	]}`
	cat, err := parseCatalog([]byte(body), "<test>")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cat.ByName["down"].Role != roleLinkDown || cat.ByName["up"].Role != roleLinkUp {
		t.Fatal("roles not parsed")
	}
	// Schedulable subset excludes role-tagged: only "cold" (weight 20).
	if cat.schedTotalWeight != 20 {
		t.Errorf("schedTotalWeight = %d, want 20 (role-tagged excluded)", cat.schedTotalWeight)
	}
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		if e := cat.Pick(rnd); e != nil && e.Role != "" {
			t.Fatalf("Pick returned role-tagged entry %q", e.Name)
		}
	}
	// EntriesByRole returns the matching entries.
	if got := cat.EntriesByRole(roleLinkDown); len(got) != 1 || got[0].Name != "down" {
		t.Errorf("EntriesByRole(link-down) = %v, want [down]", names(got))
	}
}

func TestCatalogRole_UnknownRejected(t *testing.T) {
	body := `{"traps":[{"name":"x","snmpTrapOID":"1.3.6.1.6.3.1.1.5.3","role":"flap"}]}`
	if _, err := parseCatalog([]byte(body), "<test>"); err == nil {
		t.Fatal("expected error for unknown role, got nil")
	}
}

func TestCatalogRole_AllTaggedLoadsAndPickNil(t *testing.T) {
	// Every entry role-tagged → catalog still LOADS (not the totalWeight<=0
	// load-fatal), and Pick is a no-op (schedulable subset is empty).
	body := `{"traps":[
		{"name":"down","snmpTrapOID":"1.3.6.1.6.3.1.1.5.3","weight":40,"role":"link-down"},
		{"name":"up","snmpTrapOID":"1.3.6.1.6.3.1.1.5.4","weight":40,"role":"link-up"}
	]}`
	cat, err := parseCatalog([]byte(body), "<test>")
	if err != nil {
		t.Fatalf("all-role-tagged catalog must load, got: %v", err)
	}
	if cat.schedTotalWeight != 0 {
		t.Errorf("schedTotalWeight = %d, want 0", cat.schedTotalWeight)
	}
	if e := cat.Pick(rand.New(rand.NewSource(1))); e != nil {
		t.Errorf("Pick = %q, want nil (no untagged entries)", e.Name)
	}
}

// --- Vendor-wins-per-role on the shipped syslog catalogs ------------------

func TestSyslogRole_VendorWins(t *testing.T) {
	universal, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	cisco, err := LoadSyslogCatalogFromFile("resources/cisco_ios/syslog.json")
	if err != nil {
		t.Fatal(err)
	}
	merged := universal.MergeOverlay(cisco)
	got := merged.EntriesByRole(roleLinkDown)
	// Vendor-wins: the cisco %LINK + %LINEPROTO down pair, NOT universal interface-down.
	if len(got) != 2 {
		t.Fatalf("EntriesByRole(link-down) = %v, want the 2 cisco entries", names2(got))
	}
	for _, e := range got {
		if e.Name == "interface-down" {
			t.Errorf("universal interface-down should be suppressed when cisco entries exist")
		}
	}
}

// --- FireForInterface pins the transitioned ifIndex (D4) ------------------

func TestFireForInterface_PinsCtx(t *testing.T) {
	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:  net.IPv4(10, 42, 0, 9),
		Community: "public",
		Mode:      TrapModeTrap,
		IfIndexFn: func() int { return 999 }, // the "random picker" — must be ignored
		IfNameFn:  func(i int) string { return fmt.Sprintf("Gi0/%d", i) },
	})
	ctx := e.buildCtx(7)
	if ctx.IfIndex != 7 {
		t.Errorf("buildCtx ifIndex = %d, want 7 (pinned, not the picker's 999)", ctx.IfIndex)
	}
	if ctx.IfName != "Gi0/7" {
		t.Errorf("buildCtx ifName = %q, want Gi0/7 (consistent with ifIndex)", ctx.IfName)
	}
}

func TestFireForInterface_Delivers(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	mc := newMockCollector(t, false)
	defer mc.Close()
	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:  net.IPv4(127, 0, 0, 1),
		Community: "public",
		Mode:      TrapModeTrap,
		Collector: mc.addr,
		IfNameFn:  func(i int) string { return fmt.Sprintf("Gi0/%d", i) },
	})
	e.SetConn(openTestUDPConn(t))
	e.StartBackgroundLoops(context.Background())
	defer e.Close()

	down := cat.EntriesByRole(roleLinkDown)
	if len(down) != 1 {
		t.Fatalf("embedded catalog link-down entries = %d, want 1", len(down))
	}
	if reqID := e.FireForInterface(down[0], 3); reqID == 0 {
		t.Fatal("FireForInterface returned 0 reqID")
	}
	time.Sleep(100 * time.Millisecond)
	if mc.received.Load() != 1 {
		t.Errorf("collector received = %d, want 1", mc.received.Load())
	}
}

// --- Engine notify hook: oper-only, role direction, nil-safe --------------

func TestStateNotify_OperOnlyAndDirection(t *testing.T) {
	s := NewInterfaceState(4, nil, nil)
	s.Seed(1, OperUp, AdminUp)

	var got []StateChange
	s.SetNotify(func(evt StateChange) { got = append(got, evt) })

	// Oper DOWN → notify fires with the committed (DOWN) value.
	if changed, evt := s.SetOperStatus(1, OperDown); changed {
		s.Broadcast(evt)
	}
	if len(got) != 1 || got[0].Oper != OperDown {
		t.Fatalf("after oper DOWN: got %d events (want 1 with Oper=down)", len(got))
	}

	// Admin change → Broadcast must NOT fire the hook (admin gated out).
	if changed, evt := s.SetAdminStatus(1, AdminDown); changed {
		s.Broadcast(evt)
	}
	if len(got) != 1 {
		t.Fatalf("admin change fired the hook: got %d events, want still 1", len(got))
	}

	// Oper UP → fires again with Oper=up.
	if changed, evt := s.SetOperStatus(1, OperUp); changed {
		s.Broadcast(evt)
	}
	if len(got) != 2 || got[1].Oper != OperUp {
		t.Fatalf("after oper UP: got %d events (want 2nd with Oper=up)", len(got))
	}

	// Clearing the hook makes further transitions a no-op.
	s.SetNotify(nil)
	if changed, evt := s.SetOperStatus(1, OperDown); changed {
		s.Broadcast(evt)
	}
	if len(got) != 2 {
		t.Errorf("after SetNotify(nil): got %d events, want 2 (hook cleared)", len(got))
	}
}

func TestStateNotify_NilSafeBeforeWiring(t *testing.T) {
	s := NewInterfaceState(2, nil, nil)
	s.Seed(1, OperUp, AdminUp)
	// No SetNotify call: a transition before exporter attach must not panic.
	if changed, evt := s.SetOperStatus(1, OperDown); changed {
		s.Broadcast(evt)
	}
}

// --- End-to-end: wireStateNotify drives trap + syslog on a transition ----

func TestWireStateNotify_EndToEnd(t *testing.T) {
	// Real interface-state engine reachable via the device's metricsCycler.
	res := buildTestResources(t, []uint64{1_000_000_000})
	mc := &MetricsCycler{}
	mc.InitIfCountersWithScenario(res, 7, IfErrorClean)
	state := mc.ifCounters.Load().State()
	if state == nil {
		t.Fatal("no interface state")
	}
	state.Seed(1, OperUp, AdminUp)

	// Trap exporter → mock collector.
	trapColl := newMockCollector(t, false)
	defer trapColl.Close()
	trapExp := NewTrapExporter(TrapExporterOptions{
		DeviceIP:  net.IPv4(127, 0, 0, 1),
		Community: "public",
		Mode:      TrapModeTrap,
		Collector: trapColl.addr,
		IfNameFn:  func(i int) string { return fmt.Sprintf("eth%d", i) },
	})
	trapExp.SetConn(openTestUDPConn(t))
	trapExp.StartBackgroundLoops(context.Background())
	defer trapExp.Close()

	// Syslog exporter → UDP collector.
	syslogColl, syslogAddr := newLocalUDPCollector(t)
	syslogExp := NewSyslogExporter(SyslogExporterOptions{
		DeviceIP:   net.IPv4(127, 0, 0, 1),
		Encoder:    &RFC5424Encoder{},
		Collector:  syslogAddr,
		SharedConn: newTestSharedSocket(t),
		SysName:    "rtr-test-1",
		IfNameFn:   func(i int) string { return fmt.Sprintf("eth%d", i) },
	})
	defer syslogExp.Close()

	device := &DeviceSimulator{
		IP:             net.IPv4(127, 0, 0, 1),
		metricsCycler:  mc,
		trapExporter:   trapExp,
		syslogExporter: syslogExp,
	}

	sm := &SimulatorManager{}
	sm.trapCatalog, _ = LoadEmbeddedCatalog()        // linkDown/linkUp role-tagged
	sm.syslogCatalog, _ = LoadEmbeddedSyslogCatalog() // interface-down/up role-tagged

	sm.wireStateNotify(device)

	// Drive an oper DOWN transition → expect a link-down trap + syslog.
	changed, evt := state.SetOperStatus(1, OperDown)
	if !changed {
		t.Fatal("oper DOWN did not change state")
	}
	state.Broadcast(evt)

	// Syslog is synchronous on the same goroutine; trap datagram needs a beat.
	if got := syslogExp.Stats().Sent.Load(); got != 1 {
		t.Errorf("syslog Sent = %d, want 1", got)
	}
	payload, _ := readNextDatagram(t, syslogColl, 500*time.Millisecond)
	if !strings.Contains(string(payload), "eth1") {
		t.Errorf("syslog payload %q does not name the transitioned interface eth1", string(payload))
	}
	time.Sleep(100 * time.Millisecond)
	if got := trapExp.Stats().Sent.Load(); got != 1 {
		t.Errorf("trap Sent = %d, want 1", got)
	}
	if trapColl.received.Load() != 1 {
		t.Errorf("trap collector received = %d, want 1", trapColl.received.Load())
	}
}

// wiredFixture is a device wired through sm.wireStateNotify, with optional
// trap and/or syslog exporters pointed at local collectors.
type wiredFixture struct {
	sm         *SimulatorManager
	device     *DeviceSimulator
	state      *InterfaceState
	trapColl   *mockCollector
	syslogColl *net.UDPConn
	trapExp    *TrapExporter
	syslogExp  *SyslogExporter
}

func buildWired(t *testing.T, withTrap, withSyslog bool) *wiredFixture {
	t.Helper()
	res := buildTestResources(t, []uint64{1_000_000_000})
	mc := &MetricsCycler{}
	mc.InitIfCountersWithScenario(res, 7, IfErrorClean)
	state := mc.ifCounters.Load().State()
	state.Seed(1, OperUp, AdminUp)
	dev := &DeviceSimulator{IP: net.IPv4(127, 0, 0, 1), metricsCycler: mc}
	sm := &SimulatorManager{}
	sm.trapCatalog, _ = LoadEmbeddedCatalog()
	sm.syslogCatalog, _ = LoadEmbeddedSyslogCatalog()
	fx := &wiredFixture{sm: sm, device: dev, state: state}
	ifName := func(i int) string { return fmt.Sprintf("eth%d", i) }
	if withTrap {
		fx.trapColl = newMockCollector(t, false)
		t.Cleanup(fx.trapColl.Close)
		tx := NewTrapExporter(TrapExporterOptions{
			DeviceIP: dev.IP, Community: "public", Mode: TrapModeTrap,
			Collector: fx.trapColl.addr, IfNameFn: ifName,
		})
		tx.SetConn(openTestUDPConn(t))
		tx.StartBackgroundLoops(context.Background())
		t.Cleanup(func() { _ = tx.Close() })
		dev.trapExporter = tx
		fx.trapExp = tx
	}
	if withSyslog {
		var addr *net.UDPAddr
		fx.syslogColl, addr = newLocalUDPCollector(t)
		sx := NewSyslogExporter(SyslogExporterOptions{
			DeviceIP: dev.IP, Encoder: &RFC5424Encoder{}, Collector: addr,
			SharedConn: newTestSharedSocket(t), SysName: "r1", IfNameFn: ifName,
		})
		t.Cleanup(func() { _ = sx.Close() })
		dev.syslogExporter = sx
		fx.syslogExp = sx
	}
	sm.wireStateNotify(dev)
	return fx
}

func (fx *wiredFixture) transition(t *testing.T, oper uint8) {
	t.Helper()
	if changed, evt := fx.state.SetOperStatus(1, oper); changed {
		fx.state.Broadcast(evt)
	}
}

// TESTING (a valid REST oper-status) must NOT fire a spurious linkDown/linkUp.
func TestWireStateNotify_TestingDoesNotFire(t *testing.T) {
	fx := buildWired(t, true, true)
	fx.transition(t, OperTesting)
	time.Sleep(80 * time.Millisecond)
	if got := fx.syslogExp.Stats().Sent.Load(); got != 0 {
		t.Errorf("syslog Sent on TESTING = %d, want 0", got)
	}
	if got := fx.trapExp.Stats().Sent.Load(); got != 0 {
		t.Errorf("trap Sent on TESTING = %d, want 0", got)
	}
}

// A trap-only device fires the trap and attempts no syslog (and vice versa).
func TestWireStateNotify_TrapOnly(t *testing.T) {
	fx := buildWired(t, true, false)
	if fx.device.syslogExporter != nil {
		t.Fatal("fixture should have no syslog exporter")
	}
	fx.transition(t, OperDown) // must not panic on the nil syslog side
	time.Sleep(80 * time.Millisecond)
	if got := fx.trapExp.Stats().Sent.Load(); got != 1 {
		t.Errorf("trap Sent = %d, want 1", got)
	}
}

func TestWireStateNotify_SyslogOnly(t *testing.T) {
	fx := buildWired(t, false, true)
	fx.transition(t, OperDown)
	if got := fx.syslogExp.Stats().Sent.Load(); got != 1 {
		t.Errorf("syslog Sent = %d, want 1", got)
	}
}

// Store-then-notify: the slot is committed before the hook runs, so a reader
// reacting to the notification observes the new value (the coherence guarantee).
func TestStateNotify_StoreCommittedBeforeHook(t *testing.T) {
	s := NewInterfaceState(2, nil, nil)
	s.Seed(1, OperUp, AdminUp)
	var observed uint8
	s.SetNotify(func(evt StateChange) { observed = s.OperStatus(1) })
	if changed, evt := s.SetOperStatus(1, OperDown); changed {
		s.Broadcast(evt)
	}
	if observed != OperDown {
		t.Errorf("OperStatus read inside hook = %d, want OperDown (store must commit first)", observed)
	}
}

// Cisco fire-all: a port-down emits BOTH %LINK and %LINEPROTO (2 datagrams),
// and NOT the generic universal interface-down.
func TestWireStateNotify_CiscoFireAll(t *testing.T) {
	fx := buildWired(t, false, true)
	universal, _ := LoadEmbeddedSyslogCatalog()
	cisco, err := LoadSyslogCatalogFromFile("resources/cisco_ios/syslog.json")
	if err != nil {
		t.Fatal(err)
	}
	fx.sm.syslogCatalogsByType = map[string]*SyslogCatalog{
		universalCatalogKey: universal,
		"cisco_ios":         universal.MergeOverlay(cisco),
	}
	fx.sm.deviceTypesByIP = map[string]string{fx.device.IP.String(): "cisco_ios"}

	fx.transition(t, OperDown)
	if got := fx.syslogExp.Stats().Sent.Load(); got != 2 {
		t.Errorf("syslog Sent = %d, want 2 (the %%LINK + %%LINEPROTO pair)", got)
	}
	// Drain both datagrams; neither should be the generic universal IFMGR line.
	for i := 0; i < 2; i++ {
		payload, _ := readNextDatagram(t, fx.syslogColl, 500*time.Millisecond)
		if strings.Contains(string(payload), "IFMGR") {
			t.Errorf("emitted the generic universal interface-down (IFMGR), want vendor-only: %q", string(payload))
		}
	}
}

// Concurrent mutation + hook attach/teardown must be race-clean (run with -race).
func TestStateNotify_ConcurrentRace(t *testing.T) {
	s := NewInterfaceState(8, nil, nil)
	for i := 1; i <= 8; i++ {
		s.Seed(i, OperUp, AdminUp)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(ifx int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if c, e := s.SetOperStatus(ifx, OperDown); c {
					s.Broadcast(e)
				}
				if c, e := s.SetOperStatus(ifx, OperUp); c {
					s.Broadcast(e)
				}
			}
		}(g + 1)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		fn := func(evt StateChange) { _ = evt.IfIndex }
		for {
			select {
			case <-stop:
				return
			default:
			}
			s.SetNotify(fn)
			s.SetNotify(nil)
		}
	}()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// helpers
func names(es []*CatalogEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Name
	}
	return out
}

func names2(es []*SyslogCatalogEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Name
	}
	return out
}
