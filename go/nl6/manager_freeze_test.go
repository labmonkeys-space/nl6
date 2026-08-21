/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
)

// Freeze-fleet mechanism (scenario PR0, FR35/FR38): while a scenario has
// frozen the fleet, device create/delete must be rejected with an error
// naming the freezing scenario so the REST layer can map it to 409. The
// flag is inert in this story — only the (future) scenario controller and
// these tests set it.

func newFreezeTestManager() *SimulatorManager {
	return &SimulatorManager{
		devices:         make(map[string]*DeviceSimulator),
		deviceIPs:       make(map[string]struct{}),
		deviceTypesByIP: make(map[string]string),
		devicesByIP:     make(map[string]*DeviceSimulator),
	}
}

func mustFreeze(t *testing.T, sm *SimulatorManager, id string) {
	t.Helper()
	if err := sm.freezeFleet(id); err != nil {
		t.Fatalf("freezeFleet(%s): %v", id, err)
	}
}

func TestFleetFreeze_RejectsDelete(t *testing.T) {
	sm := newFreezeTestManager()
	mustFreeze(t, sm, "s-000001")

	err := sm.DeleteDevice("device-10.42.0.7")
	if err == nil {
		t.Fatal("DeleteDevice succeeded while fleet frozen; want rejection")
	}
	if !strings.Contains(err.Error(), "s-000001") {
		t.Errorf("rejection error = %q; want it to name the freezing scenario s-000001", err)
	}
}

func TestFleetFreeze_RejectsDeleteAll(t *testing.T) {
	sm := newFreezeTestManager()
	mustFreeze(t, sm, "s-000001")

	err := sm.DeleteAllDevices()
	if err == nil {
		t.Fatal("DeleteAllDevices succeeded while fleet frozen; want rejection")
	}
	if !strings.Contains(err.Error(), "s-000001") {
		t.Errorf("rejection error = %q; want it to name the freezing scenario s-000001", err)
	}
}

func TestFleetFreeze_RefusedDuringCreationBatch(t *testing.T) {
	sm := newFreezeTestManager()
	sm.isCreatingDevices.Store(true) // simulate an in-flight batch

	if err := sm.freezeFleet("s-000001"); err == nil {
		t.Fatal("freezeFleet succeeded during creation batch; want refusal (interlock)")
	}
	if err := sm.fleetFreezeCheck(); err != nil {
		t.Errorf("fleet must remain unfrozen after refused freeze; check = %v", err)
	}

	sm.isCreatingDevices.Store(false)
	mustFreeze(t, sm, "s-000001") // succeeds once the batch is done
}

func TestFleetFreeze_RejectsCreate(t *testing.T) {
	sm := newFreezeTestManager()
	mustFreeze(t, sm, "s-000001")

	created, err := sm.CreateDevicesWithOptions("10.42.0.1", 1, "16", "", nil, false, 0, false, "", 161, nil)
	if err == nil {
		t.Fatal("CreateDevicesWithOptions succeeded while fleet frozen; want rejection")
	}
	if created != 0 {
		t.Errorf("created = %d devices while fleet frozen; want 0", created)
	}
	if !strings.Contains(err.Error(), "s-000001") {
		t.Errorf("rejection error = %q; want it to name the freezing scenario s-000001", err)
	}
}

func TestFleetFreeze_ClearRestoresNormalBehavior(t *testing.T) {
	sm := newFreezeTestManager()
	mustFreeze(t, sm, "s-000001")
	sm.unfreezeFleet("s-000001")

	// Delete on an unknown device must surface the normal not-found error,
	// not a freeze rejection.
	err := sm.DeleteDevice("device-10.42.0.7")
	if err == nil {
		t.Fatal("DeleteDevice on unknown device returned nil; want not-found error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q; want the pre-existing not-found behavior", err)
	}

	// The freeze check itself must pass when clear (creation would proceed
	// into TUN allocation, which a unit test must not do — the check is the
	// guarded surface).
	if err := sm.fleetFreezeCheck(); err != nil {
		t.Errorf("fleetFreezeCheck() = %v after unfreeze; want nil", err)
	}
}
