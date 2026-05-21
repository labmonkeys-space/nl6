/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
)

// newTestManager builds a minimal SimulatorManager with the device map
// initialised. Mutating it from tests is safe — no goroutines are
// started.
func newTestManager() *SimulatorManager {
	return &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
	}
}

func TestStartGnmiSubsystem_DefaultPort(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{}); err != nil {
		t.Fatalf("StartGnmiSubsystem: %v", err)
	}
	if mgr.gnmiPort != gnmiDefaultPort {
		t.Errorf("port: got %d, want %d", mgr.gnmiPort, gnmiDefaultPort)
	}
	if !mgr.gnmiSubsystemActive.Load() {
		t.Errorf("subsystem inactive after Start")
	}
}

func TestStartGnmiSubsystem_RejectsDoubleStart(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{}); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{}); err == nil {
		t.Fatal("expected double-start to error")
	}
}

func TestStartGnmiSubsystem_InvalidPort(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{Port: 70000}); err == nil {
		t.Fatal("expected invalid-port error")
	}
}

func TestGnmiStatus_DisabledReportsInactive(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{Disabled: true}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st := mgr.GetGnmiStatus()
	if st.SubsystemActive {
		t.Errorf("subsystem_active = true with -gnmi-disable")
	}
	if st.Listeners != 0 {
		t.Errorf("listeners = %d, want 0 when disabled", st.Listeners)
	}
}

func TestGnmiStatus_NeverStartedReportsInactive(t *testing.T) {
	mgr := newTestManager()
	st := mgr.GetGnmiStatus()
	if st.SubsystemActive {
		t.Errorf("subsystem_active = true without StartGnmiSubsystem")
	}
}

func TestGnmiStatus_ListenersMatchDeviceCount(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// P15: Listeners reflects devices with a live gNMI server, not raw
	// device count. Devices without a gnmiServer pointer (e.g. those
	// that haven't reached startGnmiServer yet) are excluded.
	servers := make([]*grpc.Server, 0, 5)
	for i := 0; i < 5; i++ {
		s := grpc.NewServer()
		dev := &DeviceSimulator{ID: fmt.Sprintf("%s-%d", t.Name(), i), gnmiServer: s}
		mgr.devices[t.Name()+string(rune('a'+i))] = dev
		servers = append(servers, s)
	}
	defer func() {
		for _, s := range servers {
			s.Stop()
		}
	}()
	st := mgr.GetGnmiStatus()
	if !st.SubsystemActive {
		t.Errorf("subsystem_active = false")
	}
	if st.Listeners != 5 {
		t.Errorf("listeners: got %d, want 5", st.Listeners)
	}
}

func TestGnmiStatus_CountersAggregate(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	atomic.AddInt64(&mgr.gnmiActiveSubscriptions, 3)
	atomic.AddUint64(&mgr.gnmiUpdatesSent, 1234)
	atomic.AddUint64(&mgr.gnmiUpdatesDropped, 7)
	atomic.AddUint64(&mgr.gnmiStateEventsEmitted, 42)
	atomic.AddUint64(&mgr.gnmiStateEventsDropped, 3)
	st := mgr.GetGnmiStatus()
	if st.ActiveSubscriptions != 3 {
		t.Errorf("active_subscriptions: got %d, want 3", st.ActiveSubscriptions)
	}
	if st.UpdatesSent != 1234 {
		t.Errorf("updates_sent: got %d, want 1234", st.UpdatesSent)
	}
	if st.UpdatesDropped != 7 {
		t.Errorf("updates_dropped: got %d, want 7", st.UpdatesDropped)
	}
	if st.StateEventsEmitted != 42 {
		t.Errorf("state_events_emitted: got %d, want 42", st.StateEventsEmitted)
	}
	if st.StateEventsDropped != 3 {
		t.Errorf("state_events_dropped: got %d, want 3", st.StateEventsDropped)
	}
}

// TestGnmiStatus_JSONShape pins the JSON keys produced by GnmiStatus
// marshalling. Locks in the contract for /api/v1/gnmi/status so a
// future refactor renaming a struct field can't silently change the
// wire shape.
func TestGnmiStatus_JSONShape(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st := mgr.GetGnmiStatus()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	body := string(b)
	for _, key := range []string{
		`"subsystem_active":`,
		`"listeners":`,
		`"active_subscriptions":`,
		`"updates_sent":`,
		`"updates_dropped":`,
		`"tls_handshake_failures":`,
		`"state_events_emitted":`,
		`"state_events_dropped":`,
	} {
		if !strings.Contains(body, key) {
			t.Errorf("JSON body missing expected key %s; got: %s", key, body)
		}
	}
}

func TestStopGnmiSubsystem_FlipsActive(t *testing.T) {
	mgr := newTestManager()
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	mgr.StopGnmiSubsystem()
	if mgr.gnmiSubsystemActive.Load() {
		t.Errorf("subsystem still active after Stop")
	}
}
