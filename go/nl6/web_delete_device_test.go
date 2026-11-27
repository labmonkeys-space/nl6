/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The single-device delete used to answer 404 for every error DeleteDevice
// returned, so a client reading the status was told an existing device was
// missing. These tests pin one status per kind of error, and pin that the
// response body did not change with it.

const freezeMessage = "fleet membership is frozen by running scenario(s) s-000001: device create/delete is rejected until they finish"

// addDeleteTestDevice registers the smallest device DeleteDevice can tear
// down. An empty tunName leaves the device without a TUN interface.
func addDeleteTestDevice(sm *SimulatorManager, id string, ip net.IP, tunName string) {
	device := &DeviceSimulator{ID: id, IP: ip, running: true}
	if tunName != "" {
		device.tunIface = &TunInterface{Name: tunName}
	}
	sm.devices[id] = device
	sm.deviceIPs[ip.String()] = struct{}{}
}

// stubTunDelete replaces the root-namespace TUN delete, so the tests need no
// privileges and can make the teardown fail.
func stubTunDelete(t *testing.T, err error) {
	t.Helper()
	prev := deleteDeviceTunInterfaces
	deleteDeviceTunInterfaces = func(*SimulatorManager, []string) error { return err }
	t.Cleanup(func() { deleteDeviceTunInterfaces = prev })
}

func deleteDeviceReq(t *testing.T, sm *SimulatorManager, path string) *httptest.ResponseRecorder {
	t.Helper()
	silenceCreateGateLogs(t)
	withManager(t, sm)
	return doReq(t, setupRoutes(), http.MethodDelete, path, "")
}

func assertErrorResponse(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantMessage string) {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body %s)", w.Code, wantStatus, w.Body.String())
	}
	resp := decodeAPIResponse(t, w)
	if resp.Success || resp.Message != wantMessage {
		t.Errorf("response = {success:%v message:%q}, want {success:false message:%q}", resp.Success, resp.Message, wantMessage)
	}
}

func TestDeleteDeviceErrorResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"frozen fleet", fmt.Errorf("%w by running scenario(s) s-000001", errFleetFrozen), http.StatusConflict},
		{"unknown device, wrapped twice", fmt.Errorf("outer: %w", fmt.Errorf("device x %w", errDeviceNotFound)), http.StatusNotFound},
		{"teardown failure", fmt.Errorf("delete TUN interface sim1: %w", errors.New("exit status 1")), http.StatusInternalServerError},
		{"unclassified error", errors.New("boom"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message, status := deleteDeviceErrorResponse(tc.err)
			if status != tc.want {
				t.Errorf("status = %d, want %d", status, tc.want)
			}
			if message != tc.err.Error() {
				t.Errorf("message = %q, want the error text %q", message, tc.err.Error())
			}
		})
	}
}

func TestDeleteDeviceHandler_FrozenFleetAnswers409(t *testing.T) {
	sm := newFreezeTestManager()
	addDeleteTestDevice(sm, "device-10.42.0.7", net.IPv4(10, 42, 0, 7), "")
	mustFreeze(t, sm, "s-000001")

	t.Run("existing device", func(t *testing.T) {
		w := deleteDeviceReq(t, sm, "/api/v1/devices/device-10.42.0.7")
		assertErrorResponse(t, w, http.StatusConflict, freezeMessage)
		// The freeze has no known end, so the answer names no retry time.
		if got := w.Header().Get("Retry-After"); got != "" {
			t.Errorf("Retry-After = %q, want none", got)
		}
		if _, exists := sm.devices["device-10.42.0.7"]; !exists {
			t.Error("a refused delete removed the device")
		}
	})

	// The freeze check runs before the lookup, so the refusal does not
	// depend on the target.
	t.Run("unknown device", func(t *testing.T) {
		w := deleteDeviceReq(t, sm, "/api/v1/devices/device-10.42.0.9")
		assertErrorResponse(t, w, http.StatusConflict, freezeMessage)
	})
}

func TestDeleteDeviceHandler_UnknownDeviceAnswers404(t *testing.T) {
	sm := newFreezeTestManager()

	w := deleteDeviceReq(t, sm, "/api/v1/devices/device-10.42.0.9")
	assertErrorResponse(t, w, http.StatusNotFound, "device device-10.42.0.9 not found")
}

func TestDeleteDeviceHandler_TeardownFailureAnswers500(t *testing.T) {
	stubTunDelete(t, errors.New("netlink: device busy"))
	sm := newFreezeTestManager()
	addDeleteTestDevice(sm, "device-busy", net.IPv4(127, 0, 0, 2), "sim456")

	w := deleteDeviceReq(t, sm, "/api/v1/devices/device-busy")
	assertErrorResponse(t, w, http.StatusInternalServerError, "delete TUN interface sim456: netlink: device busy")
	if _, exists := sm.devices["device-busy"]; exists {
		t.Error("device is still listed after a failed teardown")
	}

	// The device is gone, so a retry is told exactly that.
	w = deleteDeviceReq(t, sm, "/api/v1/devices/device-busy")
	assertErrorResponse(t, w, http.StatusNotFound, "device device-busy not found")
}

func TestDeleteDeviceHandler_SuccessAnswers200(t *testing.T) {
	stubTunDelete(t, nil)
	sm := newFreezeTestManager()
	addDeleteTestDevice(sm, "device-1", net.IPv4(127, 0, 0, 1), "sim123")

	w := deleteDeviceReq(t, sm, "/api/v1/devices/device-1")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	resp := decodeAPIResponse(t, w)
	if !resp.Success || resp.Message != "Device device-1 deleted" {
		t.Errorf("response = {success:%v message:%q}, want {success:true message:%q}", resp.Success, resp.Message, "Device device-1 deleted")
	}
	if _, exists := sm.devices["device-1"]; exists {
		t.Error("device is still listed after a successful delete")
	}
}

// assertNoRetryAfter pins that a freeze 409 tells the caller nothing about
// when to retry: the freeze lasts until the scenario finishes or is stopped.
func assertNoRetryAfter(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q on a freeze 409, want none", got)
	}
}

// Create and delete-all carry the same freeze error as the single delete, and
// answer the same 409 (nl6#1115).
func TestDeleteAllDevicesHandler_FrozenFleetAnswers409(t *testing.T) {
	sm := newFreezeTestManager()
	addDeleteTestDevice(sm, "device-10.42.0.7", net.IPv4(10, 42, 0, 7), "")
	mustFreeze(t, sm, "s-000001")

	w := deleteDeviceReq(t, sm, "/api/v1/devices")
	assertErrorResponse(t, w, http.StatusConflict, freezeMessage)
	assertNoRetryAfter(t, w)
	if _, exists := sm.devices["device-10.42.0.7"]; !exists {
		t.Error("a refused delete-all removed the device")
	}
}

func TestCreateDevicesHandler_FrozenFleetAnswers409(t *testing.T) {
	sm := newCreateGateRESTManager(t)
	mustFreeze(t, sm, "s-000001")

	w := postCreateDevices(t, sm, createBody(t, "10.42.0.3"))
	assertErrorResponse(t, w, http.StatusConflict, freezeMessage)
	assertNoRetryAfter(t, w)
}

// The create gate is judged before the freeze, so a batch in flight wins on a
// frozen fleet and the caller gets the retryable 409, Retry-After included.
func TestCreateDevicesHandler_BatchInFlightOnFrozenFleetKeepsRetryAfter(t *testing.T) {
	sm := newCreateGateRESTManager(t)
	mustFreeze(t, sm, "s-000001")
	hold, err := sm.tryEnterCreateBatch(2000)
	if err != nil {
		t.Fatalf("tryEnterCreateBatch: %v", err)
	}
	defer hold()

	w := postCreateDevices(t, sm, createBody(t, "10.42.0.3"))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %s)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got != createConflictRetryAfterSeconds {
		t.Errorf("Retry-After = %q, want %q", got, createConflictRetryAfterSeconds)
	}
	resp := decodeAPIResponse(t, w)
	if !strings.Contains(resp.Message, "2000") || strings.Contains(resp.Message, "frozen") {
		t.Errorf("message = %q, want the batch refusal naming 2000, not the freeze", resp.Message)
	}
}
