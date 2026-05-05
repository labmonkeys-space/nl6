/*
 * © 2025 Labmonkeys Space
 * Apache-2.0 — see LICENSE.
 */

package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Subsystem validation
// ---------------------------------------------------------------------------

// TestStartSyslogSubsystem_RejectsNegativeGlobalCap asserts the subsystem-level
// guard. Per-device-config validation lives in DeviceSyslogConfig.Validate
// and is covered in export_config_test.go.
func TestStartSyslogSubsystem_RejectsNegativeGlobalCap(t *testing.T) {
	sm := newTestSyslogManager()
	err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{GlobalCap: -1})
	if err == nil || !strings.Contains(err.Error(), "global-cap") {
		t.Fatalf("want global-cap error, got %v", err)
	}
}

// TestStartSyslogSubsystem_DoubleStartRejected confirms idempotency: a
// second Start without StopSyslogExport in between returns an error
// instead of silently replacing the scheduler.
func TestStartSyslogSubsystem_DoubleStartRejected(t *testing.T) {
	sm := newTestSyslogManager()
	if err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{MeanSchedulerInterval: time.Second}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopSyslogExport)

	err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{MeanSchedulerInterval: time.Second})
	if err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("want already-started error, got %v", err)
	}
}

// TestStartDeviceSyslogExporter_RejectsBadFormat asserts per-device
// validation at attach-time: a malformed Format in DeviceSyslogConfig
// fails before any socket is opened.
func TestStartDeviceSyslogExporter_RejectsBadFormat(t *testing.T) {
	sm := newTestSyslogManager()
	if err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopSyslogExport)

	device := &DeviceSimulator{
		ID: "test-device",
		IP: net.IPv4(127, 0, 0, 1),
		syslogConfig: &DeviceSyslogConfig{
			Collector: "127.0.0.1:16500",
			Format:    "notAFormat",
			Interval:  jsonDuration(time.Second),
		},
	}
	err := sm.startDeviceSyslogExporter(device)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !strings.Contains(err.Error(), "format") {
		t.Errorf("error should mention format: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetSyslogStatus
// ---------------------------------------------------------------------------

// TestGetSyslogStatus_Disabled asserts the "feature off" shape after
// phase 5: an empty Collectors array and no catalogs_by_type.
func TestGetSyslogStatus_Disabled(t *testing.T) {
	sm := newTestSyslogManager()
	st := sm.GetSyslogStatus()
	if len(st.Collectors) != 0 {
		t.Errorf("Collectors = %v, want empty when subsystem not started", st.Collectors)
	}
	if st.DevicesExporting != 0 {
		t.Errorf("DevicesExporting = %d, want 0", st.DevicesExporting)
	}
	if st.CatalogsByType != nil {
		t.Errorf("CatalogsByType = %v, want nil when subsystem not started", st.CatalogsByType)
	}
}

// TestGetSyslogStatus_EnabledShape asserts Collectors is populated with
// the device's (collector, format) tuple once a device is attached.
func TestGetSyslogStatus_EnabledShape(t *testing.T) {
	sm, _, _ := startSyslogForTest(t, SyslogFormat3164)
	st := sm.GetSyslogStatus()
	if len(st.Collectors) != 1 {
		t.Fatalf("Collectors length = %d, want 1: %+v", len(st.Collectors), st.Collectors)
	}
	c := st.Collectors[0]
	if c.Format != "3164" {
		t.Errorf("Format = %q, want 3164", c.Format)
	}
	if c.Devices != 1 {
		t.Errorf("Devices = %d, want 1", c.Devices)
	}
	if c.Collector == "" {
		t.Error("Collector should be populated")
	}
	if st.DevicesExporting != 1 {
		t.Errorf("DevicesExporting: got %d, want 1", st.DevicesExporting)
	}
}

// ---------------------------------------------------------------------------
// FireSyslogOnDevice
// ---------------------------------------------------------------------------

func TestFireSyslogOnDevice_HappyPath(t *testing.T) {
	sm, collector, device := startSyslogForTest(t, SyslogFormat5424)
	if err := sm.FireSyslogOnDevice(device.IP.String(), "interface-down", nil); err != nil {
		t.Fatal(err)
	}
	// Wait briefly for the datagram.
	_ = collector.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _, err := collector.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("collector did not receive datagram: %v", err)
	}
	wire := string(buf[:n])
	if !strings.HasPrefix(wire, "<187>1 ") {
		t.Errorf("wire did not start with expected PRI+version: %q", wire)
	}
	if !strings.Contains(wire, "LINKDOWN") {
		t.Errorf("wire missing MsgID: %q", wire)
	}
	// Spec: sent counter increments by 1 — verified via the status
	// endpoint's per-collector aggregate.
	st := sm.GetSyslogStatus()
	if len(st.Collectors) == 0 || st.Collectors[0].Sent != 1 {
		t.Errorf("SyslogStatus.Collectors[0].Sent after one Fire: got %+v, want 1", st.Collectors)
	}
}

func TestFireSyslogOnDevice_UnknownCatalogName(t *testing.T) {
	sm, _, device := startSyslogForTest(t, SyslogFormat5424)
	err := sm.FireSyslogOnDevice(device.IP.String(), "notAnEntry", nil)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, ErrSyslogEntryNotFound) {
		t.Errorf("want ErrSyslogEntryNotFound, got %v", err)
	}
}

func TestFireSyslogOnDevice_UnknownDevice(t *testing.T) {
	sm, _, _ := startSyslogForTest(t, SyslogFormat5424)
	err := sm.FireSyslogOnDevice("10.99.99.99", "interface-up", nil)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, ErrSyslogDeviceNotFound) {
		t.Errorf("want ErrSyslogDeviceNotFound, got %v", err)
	}
}

func TestFireSyslogOnDevice_Disabled(t *testing.T) {
	sm := newTestSyslogManager()
	err := sm.FireSyslogOnDevice("10.0.0.1", "interface-up", nil)
	if err == nil || !errors.Is(err, ErrSyslogExportDisabled) {
		t.Errorf("want ErrSyslogExportDisabled, got %v", err)
	}
}

func TestFireSyslogOnDevice_OverridesApplied(t *testing.T) {
	sm, collector, device := startSyslogForTest(t, SyslogFormat5424)
	err := sm.FireSyslogOnDevice(device.IP.String(), "interface-down", map[string]string{
		"IfIndex": "42",
		"IfName":  "GigabitEthernet7/42",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = collector.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _, err := collector.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no datagram: %v", err)
	}
	wire := string(buf[:n])
	if !strings.Contains(wire, "ifIndex=42") {
		t.Errorf("override IfIndex not present: %q", wire)
	}
	if !strings.Contains(wire, "GigabitEthernet7/42") {
		t.Errorf("override IfName not present: %q", wire)
	}
}

// ---------------------------------------------------------------------------
// HTTP handler tests (go through the real mux + handlers)
// ---------------------------------------------------------------------------

// withManager temporarily installs sm as the package-level `manager`
// variable that `fireSyslogHandler` and `syslogStatusHandler` read.
// Restores the previous value on test cleanup.
func withManager(t *testing.T, sm *SimulatorManager) {
	t.Helper()
	prev := manager
	manager = sm
	t.Cleanup(func() { manager = prev })
}

func TestSyslogHTTP_StatusEndpointDisabled(t *testing.T) {
	sm := newTestSyslogManager()
	withManager(t, sm)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/syslog/status", nil)
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code: got %d, want 200", rr.Code)
	}
	var body SyslogStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v — raw=%q", err, rr.Body.String())
	}
	if len(body.Collectors) != 0 {
		t.Errorf("Collectors: got %v, want empty when feature disabled", body.Collectors)
	}
}

func TestSyslogHTTP_StatusEndpointEnabled(t *testing.T) {
	sm, _, _ := startSyslogForTest(t, SyslogFormat5424)
	withManager(t, sm)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/syslog/status", nil)
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code: got %d, want 200", rr.Code)
	}
	var body SyslogStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Collectors) != 1 || body.Collectors[0].Format != "5424" || body.DevicesExporting != 1 {
		t.Errorf("enabled status unexpected: %+v", body)
	}
}

func TestSyslogHTTP_FireEndpoint202(t *testing.T) {
	sm, collector, device := startSyslogForTest(t, SyslogFormat5424)
	withManager(t, sm)

	body := strings.NewReader(`{"name":"interface-down"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+device.IP.String()+"/syslog", body)
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status code: got %d, want 202 — body=%q", rr.Code, rr.Body.String())
	}
	if got := strings.TrimSpace(rr.Body.String()); got != "{}" {
		t.Errorf("body: got %q, want {}", got)
	}
	// Verify the datagram actually reached the collector (end-to-end
	// validation of the manager → exporter → UDP path through the HTTP
	// handler surface).
	_ = collector.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 2048)
	if _, _, err := collector.ReadFromUDP(buf); err != nil {
		t.Errorf("collector did not receive datagram: %v", err)
	}
}

func TestSyslogHTTP_FireEndpoint400UnknownCatalogEntry(t *testing.T) {
	sm, _, device := startSyslogForTest(t, SyslogFormat5424)
	withManager(t, sm)

	body := strings.NewReader(`{"name":"notACatalogEntry"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+device.IP.String()+"/syslog", body)
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code: got %d, want 400 — body=%q", rr.Code, rr.Body.String())
	}
}

func TestSyslogHTTP_FireEndpoint404UnknownDevice(t *testing.T) {
	sm, _, _ := startSyslogForTest(t, SyslogFormat5424)
	withManager(t, sm)

	body := strings.NewReader(`{"name":"interface-up"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/10.99.99.99/syslog", body)
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code: got %d, want 404", rr.Code)
	}
}

func TestSyslogHTTP_FireEndpoint503FeatureDisabled(t *testing.T) {
	sm := newTestSyslogManager()
	withManager(t, sm)

	body := strings.NewReader(`{"name":"interface-up"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/10.0.0.1/syslog", body)
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code: got %d, want 503", rr.Code)
	}
}

func TestSyslogHTTP_FireEndpoint400MissingName(t *testing.T) {
	sm, _, device := startSyslogForTest(t, SyslogFormat5424)
	withManager(t, sm)

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+device.IP.String()+"/syslog", body)
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code: got %d, want 400", rr.Code)
	}
}

func TestSyslogHTTP_FireEndpoint400UnknownField(t *testing.T) {
	// `DisallowUnknownFields` fix: a typo'd key surfaces as 400 instead
	// of being silently dropped.
	sm, _, device := startSyslogForTest(t, SyslogFormat5424)
	withManager(t, sm)

	body := strings.NewReader(`{"name":"interface-down","tempalteOverrides":{"IfIndex":"7"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/"+device.IP.String()+"/syslog", body)
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("typo'd field accepted silently: got %d, want 400", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestSyslogManager builds a minimal SimulatorManager suitable for
// exercising the syslog subsystem. No netns, no real devices.
func newTestSyslogManager() *SimulatorManager {
	return &SimulatorManager{
		devices:          make(map[string]*DeviceSimulator),
		deviceIPs:        make(map[string]struct{}),
		resourcesCache:   make(map[string]*DeviceResources),
		tunInterfacePool: make(map[string]*TunInterface),
		deviceTypesByIP:  make(map[string]string),
	}
}

// startSyslogForTest stands up a SimulatorManager with the syslog
// subsystem running and registers one fake device with a
// SyslogExporter writing via a shared socket (no netns). Returns the
// manager, the collector socket (for reading emitted datagrams), and
// the fake device. Registers t.Cleanup.
func startSyslogForTest(t *testing.T, format SyslogFormat) (*SimulatorManager, *net.UDPConn, *DeviceSimulator) {
	t.Helper()
	sm := newTestSyslogManager()
	collector, collectorAddr := newLocalUDPCollector(t)

	// One hour, not ten seconds: the scheduler's Poisson draw has an
	// unbounded tail, and at 10s the ~1% of runs with a sub-second tail
	// draw made `TestFireSyslogOnDevice_OverridesApplied` read the
	// scheduled datagram instead of the explicit-fire one.
	if err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatalf("StartSyslogSubsystem: %v", err)
	}

	// Build a fake device with a SyslogExporter that writes via a
	// dedicated shared socket (not the manager's pool, so the test
	// owns its lifetime). Mirrors what startDeviceSyslogExporter does
	// but without touching netns.
	sharedConn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("open shared udp: %v", err)
	}
	t.Cleanup(func() { _ = sharedConn.Close() })

	encoder, err := sm.syslogEncoderFor(format)
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}

	device := &DeviceSimulator{
		ID:      "test-device",
		IP:      net.IPv4(127, 0, 0, 1),
		sysName: "test-host",
	}
	exp := NewSyslogExporter(SyslogExporterOptions{
		DeviceIP:     device.IP,
		Encoder:      encoder,
		Collector:    collectorAddr,
		CollectorStr: collectorAddr.String(),
		Format:       format,
		SharedConn:   sharedConn,
		SysName:      device.sysName,
		IfIndexFn:    func() int { return 3 },
		IfNameFn:     func(i int) string { return "GigabitEthernet0/3" },
	})
	device.syslogExporter = exp
	sm.devices[device.ID] = device
	sm.deviceIPs[device.IP.String()] = struct{}{}
	sm.syslogScheduler.Load().Register(device.IP, exp)

	t.Cleanup(func() {
		sm.StopSyslogExport()
	})
	return sm, collector, device
}
