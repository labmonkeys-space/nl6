package main

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestDeleteDeviceDeletesTunInterface(t *testing.T) {
	originalDelete := deleteDeviceTunInterfaces
	t.Cleanup(func() { deleteDeviceTunInterfaces = originalDelete })

	var deleted []string
	deleteDeviceTunInterfaces = func(sm *SimulatorManager, interfaceNames []string) error {
		deleted = append([]string(nil), interfaceNames...)
		return nil
	}

	deviceIP := net.IPv4(127, 0, 0, 1)
	device := &DeviceSimulator{
		ID:       "device-1",
		IP:       deviceIP,
		tunIface: &TunInterface{Name: "sim123"},
		running:  true,
	}
	sm := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{device.ID: device},
		deviceIPs:       map[string]struct{}{deviceIP.String(): {}},
		deviceTypesByIP: map[string]string{deviceIP.String(): "cisco_ios"},
	}

	manager = nil
	if err := sm.DeleteDevice(device.ID); err != nil {
		t.Fatalf("DeleteDevice() error = %v", err)
	}

	if !reflect.DeepEqual(deleted, []string{"sim123"}) {
		t.Fatalf("deleted interfaces = %v, want [sim123]", deleted)
	}
	if _, exists := sm.devices[device.ID]; exists {
		t.Fatal("device was not removed from devices map")
	}
	if _, exists := sm.deviceIPs[deviceIP.String()]; exists {
		t.Fatal("device IP was not removed from deviceIPs")
	}
	if _, exists := sm.deviceTypesByIP[deviceIP.String()]; exists {
		t.Fatal("device type was not removed from deviceTypesByIP")
	}
}

// Regression: if the netlink delete fails, DeleteDevice must still remove
// the device from its maps. The device's listeners are already Stop'd and
// the FD is closed; leaving it in sm.devices creates a permanently-wedged
// ghost that reports as alive but can't be interacted with. Pre-fix,
// DeleteDevice returned early on the netlink error, half-deleting the
// device. The surfaced error is still propagated to the caller.
func TestDeleteDeviceCleansMapsEvenOnTunDeleteError(t *testing.T) {
	originalDelete := deleteDeviceTunInterfaces
	t.Cleanup(func() { deleteDeviceTunInterfaces = originalDelete })

	netlinkErr := errors.New("netlink: device busy")
	deleteDeviceTunInterfaces = func(sm *SimulatorManager, interfaceNames []string) error {
		return netlinkErr
	}

	deviceIP := net.IPv4(127, 0, 0, 2)
	device := &DeviceSimulator{
		ID:       "device-busy",
		IP:       deviceIP,
		tunIface: &TunInterface{Name: "sim456"},
		running:  true,
	}
	sm := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{device.ID: device},
		deviceIPs:       map[string]struct{}{deviceIP.String(): {}},
		deviceTypesByIP: map[string]string{deviceIP.String(): "cisco_ios"},
	}

	manager = nil
	err := sm.DeleteDevice(device.ID)
	if err == nil {
		t.Fatal("DeleteDevice() error = nil, want netlink error")
	}
	if !errors.Is(err, netlinkErr) {
		t.Fatalf("DeleteDevice() error = %v, want to wrap %v", err, netlinkErr)
	}

	if _, exists := sm.devices[device.ID]; exists {
		t.Fatal("device was not removed from devices map despite netlink failure")
	}
	if _, exists := sm.deviceIPs[deviceIP.String()]; exists {
		t.Fatal("device IP was not removed from deviceIPs despite netlink failure")
	}
	if _, exists := sm.deviceTypesByIP[deviceIP.String()]; exists {
		t.Fatal("device type was not removed from deviceTypesByIP despite netlink failure")
	}
}

// Regression: DeleteDevice holds sm.mu.Lock() while calling
// device.Stop(), which in turn calls getTrap/SyslogScheduler. If those
// accessors take sm.mu.RLock, the same goroutine holds the write lock
// and self-deadlocks (sync.RWMutex is not reentrant). Symptoms in
// production: delete spinner never resolves, /traps/status and
// /syslog/status hang on RLock, create-devices also blocks. With the
// scheduler stored behind atomic.Pointer the accessors are lock-free.
//
// To prove the bug surface is actually exercised — and not just the
// happy path — the test also runs concurrent GetTrapStatus /
// GetSyslogStatus calls during the delete window and asserts they
// return promptly. Without the fix, those status reads block on
// sm.mu.RLock behind DeleteDevice's held write Lock; with the fix they
// observe a consistent snapshot.
func TestDeleteDeviceDoesNotDeadlockWithLiveTrapAndSyslogSubsystems(t *testing.T) {
	// Register the package-global manager swap-back FIRST so it runs
	// LAST in LIFO Cleanup order — ensuring StopTrap/SyslogExport
	// (registered later, run earlier) still see the test's manager.
	prevManager := manager
	t.Cleanup(func() { manager = prevManager })

	originalDelete := deleteDeviceTunInterfaces
	t.Cleanup(func() { deleteDeviceTunInterfaces = originalDelete })
	deleteDeviceTunInterfaces = func(sm *SimulatorManager, interfaceNames []string) error {
		return nil
	}

	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopTrapExport)
	if err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopSyslogExport)

	manager = sm

	deviceIP := net.IPv4(127, 0, 0, 42)
	device := setupTestDeviceForAttach(t, sm, "dev-deadlock", deviceIP)
	// PreAllocated avoids TunInterface.destroy() running syscall.Close
	// on the zero-value fd in device.Stop (would close stdin of the
	// test runner under -p).
	device.tunIface = &TunInterface{Name: "sim-deadlock", PreAllocated: true}
	device.trapConfig = &DeviceTrapConfig{
		Collector:     "127.0.0.1:16299",
		Mode:          "trap",
		Community:     "public",
		Interval:      jsonDuration(time.Hour), // match scheduler mean — no spurious fires
		InformTimeout: jsonDuration(200 * time.Millisecond),
	}
	device.syslogConfig = &DeviceSyslogConfig{
		Collector: "127.0.0.1:16599",
		Format:    "5424",
		Interval:  jsonDuration(time.Hour),
	}
	if err := sm.startDeviceTrapExporter(device); err != nil {
		t.Fatalf("startDeviceTrapExporter: %v", err)
	}
	if err := sm.startDeviceSyslogExporter(device); err != nil {
		t.Fatalf("startDeviceSyslogExporter: %v", err)
	}
	device.running = true

	// Concurrent status readers — pre-fix these would block on
	// sm.mu.RLock behind DeleteDevice's held write Lock.
	statusDone := make(chan struct{}, 2)
	go func() {
		_ = sm.GetTrapStatus()
		statusDone <- struct{}{}
	}()
	go func() {
		_ = sm.GetSyslogStatus()
		statusDone <- struct{}{}
	}()

	done := make(chan error, 1)
	go func() { done <- sm.DeleteDevice(device.ID) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DeleteDevice: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DeleteDevice did not return within 5s — sm.mu likely self-deadlocked via device.Stop → getTrapScheduler / getSyslogScheduler")
	}

	for i := 0; i < 2; i++ {
		select {
		case <-statusDone:
		case <-time.After(2 * time.Second):
			t.Fatal("status reader did not return within 2s — likely blocked on sm.mu.RLock behind a held write Lock")
		}
	}

	// Post-conditions: device fully removed and no longer running.
	sm.mu.RLock()
	_, stillPresent := sm.devices[device.ID]
	sm.mu.RUnlock()
	if stillPresent {
		t.Errorf("device %s still present in sm.devices after DeleteDevice", device.ID)
	}
	device.mu.RLock()
	stillRunning := device.running
	device.mu.RUnlock()
	if stillRunning {
		t.Errorf("device.running = true after DeleteDevice")
	}
}
