/*
 * © 2025 Labmonkeys Space
 * Apache-2.0 — see LICENSE.
 *
 * Integration-style tests that exercise the REAL
 * `startDeviceTrapExporter` / `startDeviceSyslogExporter` attach paths
 * end-to-end (review decision D3 from phase-4 trap-refactor review).
 *
 * The existing `startTrapForTest` / `startSyslogForTest` helpers
 * construct exporters directly and bypass the attach logic — useful
 * for happy-path behaviour but leaves the shared-pool wiring,
 * first-attach log, scheduler register, and per-device-interval
 * warning uncovered. These tests close that gap.
 */

package main

import (
	"net"
	"testing"
	"time"
)

// setupTestDeviceForAttach returns a DeviceSimulator initialised enough
// for `startDeviceTrapExporter` / `startDeviceSyslogExporter` to run
// end-to-end. Registers the device in `sm.devices` and
// `sm.deviceTypesByIP`. Does NOT start any exporter; the caller wires
// `trapConfig` / `syslogConfig` and then invokes the attach method.
func setupTestDeviceForAttach(t *testing.T, sm *SimulatorManager, id string, ip net.IP) *DeviceSimulator {
	t.Helper()
	device := &DeviceSimulator{
		ID:      id,
		IP:      ip,
		sysName: "test-host-" + id,
	}
	sm.mu.Lock()
	sm.devices[id] = device
	sm.deviceIPs[ip.String()] = struct{}{}
	sm.deviceTypesByIP[ip.String()] = "cisco_ios" // arbitrary but valid slug
	sm.mu.Unlock()
	return device
}

// TestStartDeviceTrapExporter_FullAttachPath exercises the real attach
// path: device config set, startDeviceTrapExporter called, scheduler
// registered, status endpoint reflects the new collector.
func TestStartDeviceTrapExporter_FullAttachPath(t *testing.T) {
	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopTrapExport)

	device := setupTestDeviceForAttach(t, sm, "dev-trap-1", net.IPv4(127, 0, 0, 2))
	device.trapConfig = &DeviceTrapConfig{
		Collector:     "127.0.0.1:16201",
		Mode:          "trap",
		Community:     "public",
		Interval:      jsonDuration(time.Second),
		InformTimeout: jsonDuration(200 * time.Millisecond),
	}

	if err := sm.startDeviceTrapExporter(device); err != nil {
		t.Fatalf("startDeviceTrapExporter: %v", err)
	}

	device.mu.RLock()
	exp := device.trapExporter
	device.mu.RUnlock()
	if exp == nil {
		t.Fatal("device.trapExporter = nil after attach")
	}
	if got := exp.CollectorString(); got != "127.0.0.1:16201" {
		t.Errorf("CollectorString = %q, want %q", got, "127.0.0.1:16201")
	}
	if exp.Mode() != TrapModeTrap {
		t.Errorf("Mode = %v, want TrapModeTrap", exp.Mode())
	}

	st := sm.GetTrapStatus()
	if !st.SubsystemActive {
		t.Error("SubsystemActive = false after attach")
	}
	if len(st.Collectors) != 1 {
		t.Fatalf("Collectors length = %d, want 1: %+v", len(st.Collectors), st.Collectors)
	}
	if st.Collectors[0].Collector != "127.0.0.1:16201" {
		t.Errorf("Collector in status = %q", st.Collectors[0].Collector)
	}
	if st.Collectors[0].Devices != 1 {
		t.Errorf("Devices in status = %d, want 1", st.Collectors[0].Devices)
	}
}

// TestStartDeviceSyslogExporter_FullAttachPath exercises the real
// syslog attach path end-to-end.
func TestStartDeviceSyslogExporter_FullAttachPath(t *testing.T) {
	sm := newTestSyslogManager()
	if err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopSyslogExport)

	device := setupTestDeviceForAttach(t, sm, "dev-syslog-1", net.IPv4(127, 0, 0, 3))
	device.syslogConfig = &DeviceSyslogConfig{
		Collector: "127.0.0.1:16514",
		Format:    "5424",
		Interval:  jsonDuration(time.Second),
	}

	if err := sm.startDeviceSyslogExporter(device); err != nil {
		t.Fatalf("startDeviceSyslogExporter: %v", err)
	}

	device.mu.RLock()
	exp := device.syslogExporter
	device.mu.RUnlock()
	if exp == nil {
		t.Fatal("device.syslogExporter = nil after attach")
	}
	if got := exp.CollectorString(); got != "127.0.0.1:16514" {
		t.Errorf("CollectorString = %q, want %q", got, "127.0.0.1:16514")
	}
	if got := exp.Format(); got != SyslogFormat5424 {
		t.Errorf("Format = %q, want 5424", got)
	}

	st := sm.GetSyslogStatus()
	if !st.SubsystemActive {
		t.Error("SubsystemActive = false after attach")
	}
	if len(st.Collectors) != 1 {
		t.Fatalf("Collectors length = %d, want 1: %+v", len(st.Collectors), st.Collectors)
	}
	c := st.Collectors[0]
	if c.Collector != "127.0.0.1:16514" || c.Format != "5424" || c.Devices != 1 {
		t.Errorf("Collector record = %+v", c)
	}
}

// TestStartDeviceSyslogExporter_MonotonicCountersAcrossDeletion asserts
// that persistSyslogCounters folds deleted devices' counters into the
// status aggregate — mirror of the trap D1.b pattern.
func TestStartDeviceSyslogExporter_MonotonicCountersAcrossDeletion(t *testing.T) {
	sm := newTestSyslogManager()
	if err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopSyslogExport)

	device := setupTestDeviceForAttach(t, sm, "dev-syslog-mono", net.IPv4(127, 0, 0, 4))
	device.syslogConfig = &DeviceSyslogConfig{
		Collector: "127.0.0.1:16515",
		Format:    "5424",
	}
	if err := sm.startDeviceSyslogExporter(device); err != nil {
		t.Fatal(err)
	}

	// Simulate some sends directly into the exporter stats.
	device.syslogExporter.stats.Sent.Add(7)
	device.syslogExporter.stats.SendFailures.Add(2)

	// Persist and close (mirrors device.Stop).
	sm.persistSyslogCounters(device.syslogExporter)
	_ = device.syslogExporter.Close()
	device.mu.Lock()
	device.syslogExporter = nil
	device.mu.Unlock()

	// Remove the device from sm.devices so Collectors is computed from
	// the aggregate alone.
	sm.mu.Lock()
	delete(sm.devices, device.ID)
	sm.mu.Unlock()

	st := sm.GetSyslogStatus()
	if len(st.Collectors) != 1 {
		t.Fatalf("Collectors = %+v, want one record from the persisted aggregate", st.Collectors)
	}
	c := st.Collectors[0]
	if c.Sent != 7 || c.SendFailures != 2 || c.Devices != 0 {
		t.Errorf("persisted counters = %+v, want Sent=7 SendFailures=2 Devices=0", c)
	}
	// Phase-5 review P16: the top-level DevicesExporting should be 0
	// once no live exporters remain, even though the aggregate is
	// populated — it counts live exporters only.
	if st.DevicesExporting != 0 {
		t.Errorf("DevicesExporting = %d, want 0 after device deletion", st.DevicesExporting)
	}
	if !st.SubsystemActive {
		t.Error("SubsystemActive should still be true until StopSyslogExport runs")
	}
}

// TestStartSyslogSubsystem_PostStopShape asserts the observable shape
// after Start → Stop: SubsystemActive=false and Collectors=empty. The
// post-Stop state and the never-started state are distinguishable only
// by SubsystemActive. Phase-5 review P15 gap (comment + test).
func TestStartSyslogSubsystem_PostStopShape(t *testing.T) {
	sm := newTestSyslogManager()
	if err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	st := sm.GetSyslogStatus()
	if !st.SubsystemActive {
		t.Fatal("SubsystemActive should be true after Start")
	}

	sm.StopSyslogExport()

	st = sm.GetSyslogStatus()
	if st.SubsystemActive {
		t.Error("SubsystemActive should be false after Stop")
	}
	if len(st.Collectors) != 0 {
		t.Errorf("Collectors = %+v, want empty after Stop", st.Collectors)
	}
	if st.CatalogsByType != nil {
		t.Errorf("CatalogsByType = %+v, want nil after Stop", st.CatalogsByType)
	}
}

// TestDeviceStop_PersistsSyslogCountersViaRealLifecycle drives
// `device.Stop()` end-to-end (rather than calling persistSyslogCounters
// manually) so a future refactor that drops the persist call from Stop
// regresses this test. Phase-5 review D2 upgrade.
func TestDeviceStop_PersistsSyslogCountersViaRealLifecycle(t *testing.T) {
	sm := newTestSyslogManager()
	if err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopSyslogExport)

	// Install sm as the package-level `manager` so device.Stop can
	// reach persistSyslogCounters.
	withManager(t, sm)

	device := setupTestDeviceForAttach(t, sm, "dev-stop-syslog", net.IPv4(127, 0, 0, 11))
	device.syslogConfig = &DeviceSyslogConfig{
		Collector: "127.0.0.1:16611",
		Format:    "5424",
	}
	if err := sm.startDeviceSyslogExporter(device); err != nil {
		t.Fatal(err)
	}

	// Inject counter values that the Stop path must preserve.
	device.syslogExporter.stats.Sent.Add(11)
	device.syslogExporter.stats.SendFailures.Add(3)

	// `Stop()` early-returns unless d.running is true — mimic a live
	// device. All servers are nil-guarded, so the bare device stops
	// cleanly.
	device.running = true
	if err := device.Stop(); err != nil {
		t.Fatalf("device.Stop: %v", err)
	}
	if device.syslogExporter != nil {
		t.Error("device.syslogExporter should be nil after Stop")
	}
	if device.running {
		t.Error("device.running should be false after Stop")
	}

	// Remove from sm.devices so the aggregate is the sole counter
	// source in the status view.
	sm.mu.Lock()
	delete(sm.devices, device.ID)
	sm.mu.Unlock()

	st := sm.GetSyslogStatus()
	if len(st.Collectors) != 1 {
		t.Fatalf("Collectors = %+v, want one record persisted by device.Stop", st.Collectors)
	}
	c := st.Collectors[0]
	if c.Sent != 11 || c.SendFailures != 3 {
		t.Errorf("persisted counters = %+v, want Sent=11 SendFailures=3", c)
	}
	if c.Devices != 0 {
		t.Errorf("Devices = %d, want 0 after deletion", c.Devices)
	}
}

// TestDeviceStop_PersistsTrapCountersViaRealLifecycle — symmetric trap
// variant so a future refactor dropping persistTrapCounters from
// device.Stop regresses a test.
func TestDeviceStop_PersistsTrapCountersViaRealLifecycle(t *testing.T) {
	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopTrapExport)

	withManager(t, sm)

	device := setupTestDeviceForAttach(t, sm, "dev-stop-trap", net.IPv4(127, 0, 0, 12))
	device.trapConfig = &DeviceTrapConfig{
		Collector:     "127.0.0.1:16612",
		Mode:          "trap",
		Community:     "public",
		Interval:      jsonDuration(time.Second),
		InformTimeout: jsonDuration(200 * time.Millisecond),
	}
	if err := sm.startDeviceTrapExporter(device); err != nil {
		t.Fatal(err)
	}

	// Inject counter values that the Stop path must preserve.
	device.trapExporter.Stats().Sent.Add(13)
	device.trapExporter.Stats().InformsAcked.Add(5)
	device.trapExporter.Stats().InformsFailed.Add(2)

	device.running = true
	if err := device.Stop(); err != nil {
		t.Fatalf("device.Stop: %v", err)
	}
	if device.trapExporter != nil {
		t.Error("device.trapExporter should be nil after Stop")
	}

	sm.mu.Lock()
	delete(sm.devices, device.ID)
	sm.mu.Unlock()

	st := sm.GetTrapStatus()
	if len(st.Collectors) != 1 {
		t.Fatalf("Collectors = %+v, want one record persisted by device.Stop", st.Collectors)
	}
	c := st.Collectors[0]
	if c.Sent != 13 {
		t.Errorf("persisted Sent = %d, want 13", c.Sent)
	}
	// InformsAcked/Failed are TRAP-mode zero (mode=trap), so they should
	// NOT be folded per the mode check in persistTrapCounters. Verify.
	if c.InformsAcked != 0 || c.InformsFailed != 0 {
		t.Errorf("INFORM counters should be 0 for trap-mode aggregate: %+v", c)
	}
}

// TestStartTrapSubsystem_PostStopShape — symmetric test on the trap
// side so the two subsystems stay in lock-step.
func TestStartTrapSubsystem_PostStopShape(t *testing.T) {
	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		MeanSchedulerInterval: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if !sm.GetTrapStatus().SubsystemActive {
		t.Fatal("SubsystemActive should be true after Start")
	}

	sm.StopTrapExport()

	st := sm.GetTrapStatus()
	if st.SubsystemActive {
		t.Error("SubsystemActive should be false after Stop")
	}
	if len(st.Collectors) != 0 {
		t.Errorf("Collectors = %+v, want empty after Stop", st.Collectors)
	}
	if st.CatalogsByType != nil {
		t.Errorf("CatalogsByType = %+v, want nil after Stop", st.CatalogsByType)
	}
}
