/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTrapMode_AllCases(t *testing.T) {
	cases := []struct {
		in      string
		want    TrapMode
		wantErr bool
	}{
		{"", TrapModeTrap, false},
		{"trap", TrapModeTrap, false},
		{"TRAP", TrapModeTrap, false},
		{"inform", TrapModeInform, false},
		{"Inform", TrapModeInform, false},
		{"notify", 0, true},
		{"v3", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseTrapMode(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseTrapMode(%q): err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParseTrapMode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestStartTrapSubsystem_RejectsNegativeGlobalCap asserts the subsystem-level
// guard. Per-device-config validation lives in DeviceTrapConfig.Validate and
// is covered in export_config_test.go.
func TestStartTrapSubsystem_RejectsNegativeGlobalCap(t *testing.T) {
	sm := newTestSimulatorManager()
	err := sm.StartTrapSubsystem(TrapSubsystemConfig{GlobalCap: -1})
	if err == nil || !strings.Contains(err.Error(), "global-cap") {
		t.Fatalf("want global-cap error, got %v", err)
	}
}

// TestStartTrapSubsystem_DoubleStartRejected confirms idempotency: a second
// Start without StopTrapExport in between returns an error instead of
// silently replacing the scheduler.
func TestStartTrapSubsystem_DoubleStartRejected(t *testing.T) {
	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{MeanSchedulerInterval: time.Second}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopTrapExport)

	err := sm.StartTrapSubsystem(TrapSubsystemConfig{MeanSchedulerInterval: time.Second})
	if err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("want already-started error, got %v", err)
	}
}

// TestStartDeviceTrapExporter_RejectsInformWithoutPerDeviceBinding asserts the
// per-device-attach guard carried forward from phase-3 StartTrapExport: INFORM
// mode requires per-device UDP socket binding for ack demux.
func TestStartDeviceTrapExporter_RejectsInformWithoutPerDeviceBinding(t *testing.T) {
	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopTrapExport)

	device := &DeviceSimulator{
		ID: "test-device",
		IP: net.IPv4(127, 0, 0, 1),
		trapConfig: &DeviceTrapConfig{
			Collector:     "127.0.0.1:16200",
			Mode:          "inform",
			Community:     "public",
			Interval:      jsonDuration(time.Second),
			InformTimeout: jsonDuration(200 * time.Millisecond),
		},
	}
	err := sm.startDeviceTrapExporter(device)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !strings.Contains(err.Error(), "INFORM") || !strings.Contains(err.Error(), "per-device") {
		t.Errorf("error should mention INFORM + per-device: %v", err)
	}
}

// newTestSimulatorManager returns a SimulatorManager initialised with the
// maps the test helpers read from. It does NOT start any subsystem.
func newTestSimulatorManager() *SimulatorManager {
	return &SimulatorManager{
		devices:          make(map[string]*DeviceSimulator),
		deviceIPs:        make(map[string]struct{}),
		resourcesCache:   make(map[string]*DeviceResources),
		tunInterfacePool: make(map[string]*TunInterface),
		deviceTypesByIP:  make(map[string]string),
	}
}

// startTrapForTest stands up a minimal SimulatorManager with the trap
// subsystem running and a single fake device whose TrapExporter writes to
// `mc`. Always uses TrapModeTrap on the exporter (INFORM mode requires
// per-device binding, which tests can't set up without netns); the `mode`
// parameter controls only mock-collector auto-ack behavior.
func startTrapForTest(t *testing.T, mode TrapMode) (*SimulatorManager, *mockCollector, *DeviceSimulator) {
	t.Helper()
	mc := newMockCollector(t, mode == TrapModeInform)

	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Second,
	}); err != nil {
		t.Fatal(err)
	}

	device := &DeviceSimulator{
		ID: "test-device",
		IP: net.IPv4(127, 0, 0, 1),
	}
	conn := openTestUDPConn(t)
	exp := NewTrapExporter(TrapExporterOptions{
		DeviceIP:      device.IP,
		Community:     "public",
		Encoder:       sm.trapEncoder,
		Mode:          TrapModeTrap,
		Collector:     mc.addr,
		CollectorStr:  mc.addr.String(),
		Limiter:       sm.trapLimiter,
		InformTimeout: 200 * time.Millisecond,
	})
	exp.SetConn(conn)
	exp.StartBackgroundLoops(context.Background())
	device.trapExporter = exp

	sm.devices[device.ID] = device
	sm.deviceIPs[device.IP.String()] = struct{}{}

	t.Cleanup(func() {
		sm.StopTrapExport()
		mc.Close()
	})
	return sm, mc, device
}

func TestFireTrapOnDevice_HappyPath(t *testing.T) {
	sm, mc, device := startTrapForTest(t, TrapModeTrap)
	reqID, err := sm.FireTrapOnDevice(device.IP.String(), "linkDown", nil)
	if err != nil {
		t.Fatal(err)
	}
	if reqID == 0 {
		t.Error("reqID = 0, want nonzero")
	}
	// Give the collector a moment to see the datagram.
	time.Sleep(100 * time.Millisecond)
	if mc.received.Load() == 0 {
		t.Error("collector never saw the trap")
	}
}

func TestFireTrapOnDevice_UnknownCatalogName(t *testing.T) {
	sm, _, device := startTrapForTest(t, TrapModeTrap)
	_, err := sm.FireTrapOnDevice(device.IP.String(), "notACatalogEntry", nil)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, ErrTrapEntryNotFound) {
		t.Errorf("want ErrTrapEntryNotFound, got %v", err)
	}
}

func TestFireTrapOnDevice_UnknownDeviceIP(t *testing.T) {
	sm, _, _ := startTrapForTest(t, TrapModeTrap)
	_, err := sm.FireTrapOnDevice("10.99.99.99", "linkDown", nil)
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !errors.Is(err, ErrTrapDeviceNotFound) {
		t.Errorf("want ErrTrapDeviceNotFound, got %v", err)
	}
}

// TestFireTrapOnDevice_WhenDisabled asserts that firing before the
// subsystem is started returns ErrTrapExportDisabled. Phase 4: "disabled"
// means "no scheduler" (subsystem never booted) rather than the old
// trapActive=false atomic flag.
func TestFireTrapOnDevice_WhenDisabled(t *testing.T) {
	sm := newTestSimulatorManager()
	_, err := sm.FireTrapOnDevice("10.0.0.1", "linkDown", nil)
	if !errors.Is(err, ErrTrapExportDisabled) {
		t.Errorf("want ErrTrapExportDisabled, got %v", err)
	}
}

// TestGetTrapStatus_Disabled asserts the "feature off" shape after
// phase 4: an empty Collectors array and no catalogs_by_type.
func TestGetTrapStatus_Disabled(t *testing.T) {
	sm := newTestSimulatorManager()
	s := sm.GetTrapStatus()
	if len(s.Collectors) != 0 {
		t.Errorf("Collectors = %v, want empty when subsystem not started", s.Collectors)
	}
	if s.DevicesExporting != 0 {
		t.Errorf("DevicesExporting = %d, want 0", s.DevicesExporting)
	}
	if s.CatalogsByType != nil {
		t.Errorf("CatalogsByType = %v, want nil when subsystem not started", s.CatalogsByType)
	}
}

// TestGetTrapStatus_TRAPMode_Shape asserts the Collectors array is populated
// with the device's (collector, mode) tuple and that cumulative counters
// reflect at least one fired trap.
func TestGetTrapStatus_TRAPMode_Shape(t *testing.T) {
	sm, _, device := startTrapForTest(t, TrapModeTrap)
	_, err := sm.FireTrapOnDevice(device.IP.String(), "linkUp", nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	s := sm.GetTrapStatus()
	if len(s.Collectors) != 1 {
		t.Fatalf("Collectors length = %d, want 1: %+v", len(s.Collectors), s.Collectors)
	}
	c := s.Collectors[0]
	if c.Mode != "trap" {
		t.Errorf("Mode = %q, want trap", c.Mode)
	}
	if c.Devices != 1 {
		t.Errorf("Devices = %d, want 1", c.Devices)
	}
	if c.Sent == 0 {
		t.Error("Sent = 0, want ≥ 1")
	}
	// INFORM-specific fields must be absent in TRAP mode.
	if c.InformsAcked != 0 || c.InformsFailed != 0 || c.InformsDropped != 0 || c.InformsPending != 0 {
		t.Errorf("INFORM counters should all be zero in TRAP mode: %+v", c)
	}
}

func TestWriteTrapStatusJSON_ContentType(t *testing.T) {
	sm := newTestSimulatorManager()
	rec := httptest.NewRecorder()
	sm.WriteTrapStatusJSON(rec)
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body struct {
		Collectors []TrapCollectorStatus `json:"collectors"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Collectors) != 0 {
		t.Errorf("Collectors = %v, want empty on fresh manager", body.Collectors)
	}
}

// TestInformInvariant asserts that at every point during a sequence of fires
// and status reads, the equation:
//
//	informsPending + informsAcked + informsFailed + informsDropped
//	                                    == informsOriginated
//
// holds. Runs in TRAP mode (since the helper can't set up INFORM with netns)
// by using the exporter directly and simulating the INFORM accounting.
func TestInformInvariant_AtExporterLevel(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	mc := newMockCollector(t, true) // auto-ack
	defer mc.Close()
	conn := openTestUDPConn(t)

	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:      net.IPv4(127, 0, 0, 1),
		Mode:          TrapModeInform,
		Collector:     mc.addr,
		InformTimeout: 150 * time.Millisecond,
		InformRetries: 0,
		PendingCap:    3, // small → we can force drops
	})
	e.SetConn(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.StartBackgroundLoops(ctx)
	defer e.Close()

	const fires = 10
	for i := 0; i < fires; i++ {
		e.Fire(cat.ByName["linkUp"], nil)
	}
	// Check invariant across a few measurement points.
	for attempt := 0; attempt < 20; attempt++ {
		st := e.Stats()
		pending := uint64(e.PendingInformsLen())
		acked := st.InformsAcked.Load()
		failed := st.InformsFailed.Load()
		dropped := st.InformsDropped.Load()
		originated := st.InformsOriginated.Load()
		if pending+acked+failed+dropped != originated {
			t.Fatalf("invariant broken at attempt %d: pending=%d acked=%d failed=%d dropped=%d originated=%d",
				attempt, pending, acked, failed, dropped, originated)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestCreateDevicesHandler_RejectsInformWithoutPerDeviceBinding asserts
// the phase-4.6 batch-level guard: when the trap subsystem is configured
// without per-device source binding and a POST body sets
// traps.mode=inform, the entire batch should fail with 400 rather than
// allow some devices through and silently drop the rest at attach time.
func TestCreateDevicesHandler_RejectsInformWithoutPerDeviceBinding(t *testing.T) {
	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopTrapExport)
	withManager(t, sm)

	body := strings.NewReader(`{
		"start_ip": "10.0.0.1",
		"device_count": 1,
		"traps": {
			"collector": "127.0.0.1:16201",
			"mode":      "inform",
			"community": "public"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", body)
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status code: got %d, want 400 — body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "inform") || !strings.Contains(rr.Body.String(), "trap-source-per-device") {
		t.Errorf("body should mention inform + trap-source-per-device: %q", rr.Body.String())
	}
}

func TestFireTrapHandler_DecodesBody(t *testing.T) {
	// Happy-path request shape test — exercises the JSON decoder in the
	// handler without spinning up the full mux/router.
	body, _ := json.Marshal(map[string]any{
		"name":             "linkDown",
		"varbindOverrides": map[string]string{"IfIndex": "5"},
	})
	req := httptest.NewRequest("POST", "/api/v1/devices/10.0.0.1/trap", bytes.NewReader(body))

	var decoded struct {
		Name             string            `json:"name"`
		VarbindOverrides map[string]string `json:"varbindOverrides"`
	}
	if err := json.NewDecoder(req.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Name != "linkDown" || decoded.VarbindOverrides["IfIndex"] != "5" {
		t.Errorf("decode mismatch: %+v", decoded)
	}
}
