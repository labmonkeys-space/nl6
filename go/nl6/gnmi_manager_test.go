/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
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
