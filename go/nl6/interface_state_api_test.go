/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// stateAPIFixture stands up a SimulatorManager with one device whose
// metricsCycler is initialised so InterfaceState is populated. Returns
// the router so tests can exercise the HTTP surface end-to-end. The
// global `manager` var is swapped to point at this fixture and restored
// on cleanup.
type stateAPIFixture struct {
	mgr    *SimulatorManager
	device *DeviceSimulator
	router *mux.Router
}

func newStateAPIFixture(t *testing.T) *stateAPIFixture {
	t.Helper()

	res := buildTestResources(t, []uint64{1_000_000_000, 1_000_000_000})
	// Seed initial state values via JSON so the InterfaceState boot
	// value is predictable (all interfaces start UP). The JSON stores
	// IF-MIB integer enum: 1=UP for both ifAdminStatus.<N> at .7 and
	// ifOperStatus.<N> at .8. Tests that need DOWN start with a
	// programmatic SetOperStatus or a REST POST.
	res.oidIndex.Store(".1.3.6.1.2.1.2.2.1.7.1", "1")
	res.oidIndex.Store(".1.3.6.1.2.1.2.2.1.8.1", "1")
	res.oidIndex.Store(".1.3.6.1.2.1.2.2.1.7.2", "1")
	res.oidIndex.Store(".1.3.6.1.2.1.2.2.1.8.2", "1")

	device := &DeviceSimulator{
		ID:            "test-device",
		IP:            net.IPv4(10, 42, 0, 1),
		metricsCycler: NewMetricsCycler(0, GetDeviceProfile("")),
	}
	device.metricsCycler.InitIfCountersWithScenario(res, 1, IfErrorClean)

	mgr := &SimulatorManager{
		devices:          map[string]*DeviceSimulator{device.ID: device},
		deviceIPs:        map[string]struct{}{device.IP.String(): {}},
		deviceTypesByIP:  map[string]string{},
		resourcesCache:   map[string]*DeviceResources{},
		tunInterfacePool: map[string]*TunInterface{},
	}
	mgr.indexDeviceByIP(device)

	// Swap the package-level manager so the HTTP handler can reach the
	// fixture. Restored on cleanup so other tests aren't perturbed.
	t.Cleanup(swapGlobalManager(mgr))
	// Registered AFTER the swap cleanup so LIFO ordering drains pending
	// auto-revert goroutines BEFORE `manager` is restored — a fired
	// revert reads that global (invalidateLLDPServedCache), and sleeps
	// in tests give no happens-before edge against the restore (#417).
	t.Cleanup(func() { mgr.awaitAutoRevertsForDevice(device.IP.String()) })

	// Wire the state engine counters to the manager aggregates so the
	// /api/v1/gnmi/status integration test in this file can observe
	// state_events_emitted updates.
	if ic := device.metricsCycler.ifCounters.Load(); ic != nil && ic.State() != nil {
		ic.State().SetCounters(&mgr.gnmiStateEventsEmitted, &mgr.gnmiStateEventsDropped)
	}

	return &stateAPIFixture{mgr: mgr, device: device, router: setupRoutes()}
}

var globalManagerSwapLock sync.Mutex

func swapGlobalManager(replacement *SimulatorManager) func() {
	globalManagerSwapLock.Lock()
	prev := manager
	manager = replacement
	return func() {
		manager = prev
		globalManagerSwapLock.Unlock()
	}
}

func TestSetOperStatus_HappyPath202(t *testing.T) {
	f := newStateAPIFixture(t)
	body := strings.NewReader(`{"status":"DOWN"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202; body=%s", rr.Code, rr.Body.String())
	}

	// State engine must reflect the mutation.
	ic := f.device.metricsCycler.ifCounters.Load()
	if got := ic.State().OperStatus(1); got != OperDown {
		t.Errorf("OperStatus(1) post-mutation: got %d, want OperDown(2)", got)
	}

	// SNMP path via GetDynamic must agree.
	if got := ic.GetDynamic(".1.3.6.1.2.1.2.2.1.8.1"); got != "2" {
		t.Errorf("SNMP ifOperStatus.1 post-mutation: got %q, want \"2\"", got)
	}

	// state_events_emitted bumped by 1 (one mutation; no listeners so
	// the broadcast Range iterates zero entries — emitted only counts
	// successful sends to listeners. With 0 listeners, emitted stays 0.
	// Add a listener and re-run to verify emitted increments.
	ch := make(chan StateChange, 16)
	ic.State().AddListener(ch)
	body = strings.NewReader(`{"status":"UP"}`)
	req = httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr = httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("revert: got %d, want 202", rr.Code)
	}
	select {
	case ev := <-ch:
		if ev.Oper != OperUp {
			t.Errorf("listener event Oper = %d, want OperUp", ev.Oper)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("listener did not receive event")
	}
	if atomic.LoadUint64(&f.mgr.gnmiStateEventsEmitted) == 0 {
		t.Errorf("gnmiStateEventsEmitted: got 0, want >= 1")
	}
}

func TestSetAdminStatus_HappyPath202(t *testing.T) {
	f := newStateAPIFixture(t)
	body := strings.NewReader(`{"status":"DOWN"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/2/admin-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202; body=%s", rr.Code, rr.Body.String())
	}
	ic := f.device.metricsCycler.ifCounters.Load()
	if got := ic.State().AdminStatus(2); got != AdminDown {
		t.Errorf("AdminStatus(2): got %d, want AdminDown(2)", got)
	}
	// oper-status untouched.
	if got := ic.State().OperStatus(2); got != OperUp {
		t.Errorf("OperStatus(2) should be unaffected: got %d, want OperUp", got)
	}
}

func TestSetOperStatus_UnknownDevice404(t *testing.T) {
	f := newStateAPIFixture(t)
	body := strings.NewReader(`{"status":"DOWN"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/192.168.99.99/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetOperStatus_UnknownIfIndex400(t *testing.T) {
	f := newStateAPIFixture(t)
	body := strings.NewReader(`{"status":"DOWN"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/99/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	// Body should include validIfIndexes for self-service.
	var body400 map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body400); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if _, ok := body400["validIfIndexes"]; !ok {
		t.Errorf("400 body missing validIfIndexes key: %v", body400)
	}
}

func TestSetOperStatus_MalformedBody400(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing-status", `{}`},
		{"unknown-field", `{"status":"DOWN","wrong":"foo"}`},
		{"invalid-status", `{"status":"BANANA"}`},
		{"invalid-duration", `{"status":"DOWN","duration":"banana"}`},
		{"negative-duration", `{"status":"DOWN","duration":"-1s"}`},
		{"not-json", `not json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newStateAPIFixture(t)
			req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			f.router.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status: got %d, want 400; body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestSetOperStatus_DurationAutoReverts(t *testing.T) {
	f := newStateAPIFixture(t)
	// Listener so Broadcast counts; otherwise state_events_emitted is
	// unaffected (sync.Map.Range over zero listeners is the no-op path).
	ic := f.device.metricsCycler.ifCounters.Load()
	ch := make(chan StateChange, 16)
	ic.State().AddListener(ch)
	defer ic.State().RemoveListener(ch)
	f.mgr.gnmiSubsystemActive.Store(true)
	beforeEmitted := f.mgr.GetGnmiStatus().StateEventsEmitted

	body := strings.NewReader(`{"status":"DOWN","duration":"100ms"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rr.Code)
	}
	// Immediately after: DOWN.
	if got := ic.State().OperStatus(1); got != OperDown {
		t.Errorf("immediate post-POST: got %d, want OperDown", got)
	}
	// After the duration elapses: back to UP.
	deadline := time.Now().Add(2 * time.Second)
	reverted := false
	for time.Now().Before(deadline) {
		if ic.State().OperStatus(1) == OperUp {
			reverted = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !reverted {
		t.Fatalf("auto-revert never fired: OperStatus(1) = %d after 2s", ic.State().OperStatus(1))
	}
	// Two transitions (DOWN, then auto-revert UP), each with a registered
	// listener, MUST bump state_events_emitted by exactly 2 per spec
	// "Duration field triggers auto-revert". Drain the listener so the
	// goroutine's Broadcast retries don't keep firing.
	for drain := 0; drain < 2; drain++ {
		select {
		case <-ch:
		case <-time.After(100 * time.Millisecond):
		}
	}
	afterEmitted := f.mgr.GetGnmiStatus().StateEventsEmitted
	if afterEmitted-beforeEmitted != 2 {
		t.Errorf("state_events_emitted: got delta %d, want 2 (one for DOWN, one for auto-revert UP)", afterEmitted-beforeEmitted)
	}
}

func TestGnmiStatus_IncludesStateEventCounters(t *testing.T) {
	f := newStateAPIFixture(t)
	// Mark gNMI subsystem active so listeners count is meaningful (the
	// handler short-circuits to 0 when inactive).
	f.mgr.gnmiSubsystemActive.Store(true)

	// Drive a state change so emitted increments. Need a listener so
	// the broadcast actually fans out and bumps the counter.
	ic := f.device.metricsCycler.ifCounters.Load()
	ch := make(chan StateChange, 16)
	ic.State().AddListener(ch)
	body := strings.NewReader(`{"status":"DOWN"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST failed: %d %s", rr.Code, rr.Body.String())
	}
	<-ch // drain

	req = httptest.NewRequest("GET", "/api/v1/gnmi/status", nil)
	rr = httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("gnmi/status GET: got %d", rr.Code)
	}
	var st GnmiStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if st.StateEventsEmitted < 1 {
		t.Errorf("state_events_emitted: got %d, want >= 1", st.StateEventsEmitted)
	}
	if st.StateEventsDropped != 0 {
		t.Errorf("state_events_dropped: got %d, want 0", st.StateEventsDropped)
	}
}

func TestSetOperStatus_TESTINGStatusAccepted(t *testing.T) {
	f := newStateAPIFixture(t)
	body := strings.NewReader(`{"status":"TESTING"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202; body=%s", rr.Code, rr.Body.String())
	}
	ic := f.device.metricsCycler.ifCounters.Load()
	if got := ic.State().OperStatus(1); got != OperTesting {
		t.Errorf("OperStatus: got %d, want OperTesting(3)", got)
	}
}

// TestSetAdminStatus_SNMPCrossProtocol covers the spec scenario
// "Admin-status POST round-trips through SNMP" — assert SNMP
// ifAdminStatus.<N> returns the new value AND ifLastChange.<N> updates.
func TestSetAdminStatus_SNMPCrossProtocol(t *testing.T) {
	f := newStateAPIFixture(t)
	// Sleep past 1 TimeTick so ifLastChange will register a non-zero
	// value after the mutation.
	time.Sleep(25 * time.Millisecond)
	body := strings.NewReader(`{"status":"DOWN"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/2/admin-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202", rr.Code)
	}
	ic := f.device.metricsCycler.ifCounters.Load()
	// SNMP ifAdminStatus.<N> at .7.<N>.
	if got := ic.GetDynamic(".1.3.6.1.2.1.2.2.1.7.2"); got != "2" {
		t.Errorf("SNMP ifAdminStatus.2: got %q, want \"2\" (DOWN)", got)
	}
	// SNMP ifLastChange.<N> at .9.<N> must now be > 0 (a real transition).
	if got := ic.GetDynamic(".1.3.6.1.2.1.2.2.1.9.2"); got == "0" {
		t.Errorf("SNMP ifLastChange.2: got \"0\", want non-zero (real transition happened)")
	}
}

// TestSetOperStatus_NoMetricsCycler503 covers the spec scenario gap
// "device exists but no state engine returns 503". Pre-patch this was
// uncovered.
func TestSetOperStatus_NoMetricsCycler503(t *testing.T) {
	// Build a fixture with a device that has NO metricsCycler.
	device := &DeviceSimulator{
		ID: "no-cycler-device",
		IP: net.IPv4(10, 42, 99, 1),
		// metricsCycler intentionally nil
	}
	mgr := &SimulatorManager{
		devices:          map[string]*DeviceSimulator{device.ID: device},
		deviceIPs:        map[string]struct{}{device.IP.String(): {}},
		deviceTypesByIP:  map[string]string{},
		resourcesCache:   map[string]*DeviceResources{},
		tunInterfacePool: map[string]*TunInterface{},
	}
	mgr.indexDeviceByIP(device)
	t.Cleanup(swapGlobalManager(mgr))
	router := setupRoutes()

	body := strings.NewReader(`{"status":"DOWN"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.99.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
}

// TestSetOperStatus_DurationCapped covers the new maxRevertAfter bound.
// Duration > 24h must reject with 400.
func TestSetOperStatus_DurationCapped(t *testing.T) {
	f := newStateAPIFixture(t)
	body := strings.NewReader(`{"status":"DOWN","duration":"25h"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400 for duration > 24h", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "maximum") {
		t.Errorf("error body should mention max: got %s", rr.Body.String())
	}
}

// TestSetOperStatus_DurationSnapshotsPreState verifies the new
// snapshot-based revert semantics: POST DOWN duration=100ms on an
// already-DOWN slot stays DOWN after the timer fires (no spurious flip
// to UP, which the old flip-to-opposite design would have produced).
func TestSetOperStatus_DurationSnapshotsPreState(t *testing.T) {
	f := newStateAPIFixture(t)
	ic := f.device.metricsCycler.ifCounters.Load()

	// Pre-state: flip ifIndex 1 to DOWN manually so the next POST
	// is an idempotent no-op at the immediate step.
	state := ic.State()
	state.SetOperStatus(1, OperDown)

	// POST DOWN with duration: revert should keep it DOWN (snapshot).
	body := strings.NewReader(`{"status":"DOWN","duration":"100ms"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST: %d %s", rr.Code, rr.Body.String())
	}
	time.Sleep(200 * time.Millisecond)
	if got := state.OperStatus(1); got != OperDown {
		t.Errorf("snapshot revert: got %d, want OperDown (pre-state was DOWN; revert must NOT flip to UP)", got)
	}
}

// TestSetOperStatus_DurationCancelsPriorTimer covers the
// duplicate-POST-cancels-prior contract.
func TestSetOperStatus_DurationCancelsPriorTimer(t *testing.T) {
	f := newStateAPIFixture(t)
	// First POST: DOWN with 200ms duration (will revert to UP).
	body := strings.NewReader(`{"status":"DOWN","duration":"200ms"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("first POST: %d", rr.Code)
	}
	// Second POST 50ms later: TESTING with 200ms duration. Should
	// cancel the first revert AND register a new one whose revert
	// target is "snapshot at time of second POST" = OperDown.
	time.Sleep(50 * time.Millisecond)
	body = strings.NewReader(`{"status":"TESTING","duration":"200ms"}`)
	req = httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr = httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("second POST: %d", rr.Code)
	}
	// After ~300ms total, the second revert should have fired —
	// snapshot at second POST was OperDown → revert back to OperDown.
	// The first revert (would have flipped to UP) MUST have been
	// cancelled.
	time.Sleep(300 * time.Millisecond)
	ic := f.device.metricsCycler.ifCounters.Load()
	state := ic.State()
	if got := state.OperStatus(1); got != OperDown {
		t.Errorf("after second-POST revert: got %d, want OperDown (snapshot before second POST)", got)
	}
}

// TestSetOperStatus_EndpointAvailableUnderAggressiveScenario covers the
// "endpoint available regardless of -if-flap-scenario" requirement.
func TestSetOperStatus_EndpointAvailableUnderAggressiveScenario(t *testing.T) {
	f := newStateAPIFixture(t)
	// Set the device's flap scenario to aggressive (post-creation
	// mutation; production normally sets this at AddDevice time).
	f.device.IfFlapScenario = string(IfFlapAggressive)

	body := strings.NewReader(`{"status":"DOWN"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Errorf("endpoint should work under aggressive scenario: got %d", rr.Code)
	}
}

// TestCancelAutoRevertsForDevice covers the device-lifecycle hook —
// pending revert timers are cancelled when the device is being torn
// down.
func TestCancelAutoRevertsForDevice(t *testing.T) {
	f := newStateAPIFixture(t)
	body := strings.NewReader(`{"status":"DOWN","duration":"1h"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST: %d", rr.Code)
	}
	// Verify timer is registered.
	count := 0
	f.mgr.revertTimers.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Errorf("revertTimers entries: got %d, want 1", count)
	}
	// Cancel as device.Stop would.
	f.mgr.cancelAutoRevertsForDevice("10.42.0.1")
	count = 0
	f.mgr.revertTimers.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Errorf("revertTimers entries after cancel: got %d, want 0", count)
	}
}

// TestAwaitAutoReverts_BlocksUntilFireCompletes pins the #417 drain
// contract: awaitAutoRevertsForDevice must not return while a fired
// revert goroutine is still executing (blocked in the notify hook),
// and must return once it exits. Channel-synchronised, no ordering
// sleeps.
func TestAwaitAutoReverts_BlocksUntilFireCompletes(t *testing.T) {
	f := newStateAPIFixture(t)
	ic := f.device.metricsCycler.ifCounters.Load()
	state := ic.State()

	// The hook fires for the initial POST mutation (call 1) and the
	// revert (call 2); only the revert must block.
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	state.SetNotify(func(StateChange) {
		if calls.Add(1) == 2 {
			close(entered)
			<-release
		}
	})

	body := strings.NewReader(`{"status":"DOWN","duration":"20ms"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST: %d %s", rr.Code, rr.Body.String())
	}

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("revert never reached the notify hook")
	}

	drained := make(chan struct{})
	go func() {
		f.mgr.awaitAutoRevertsForDevice("10.42.0.1")
		close(drained)
	}()

	// Positive-hold: with the revert goroutine blocked in the hook, the
	// drain must not have returned.
	select {
	case <-drained:
		t.Fatal("drain returned while the revert goroutine was still executing")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not return after the revert goroutine exited")
	}
}

// TestAwaitAutoReverts_EmptyReturnsImmediately covers the no-pending
// case, including a pending timer for a DIFFERENT device (key mismatch
// must not be claimed or awaited).
func TestAwaitAutoReverts_EmptyReturnsImmediately(t *testing.T) {
	f := newStateAPIFixture(t)

	// Nothing pending at all.
	done := make(chan struct{})
	go func() {
		f.mgr.awaitAutoRevertsForDevice("10.42.0.1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain blocked with no pending timers")
	}

	// A pending 1h timer for the fixture device must not block a drain
	// for a different IP.
	body := strings.NewReader(`{"status":"DOWN","duration":"1h"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST: %d", rr.Code)
	}
	done = make(chan struct{})
	go func() {
		f.mgr.awaitAutoRevertsForDevice("10.42.0.99")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain for a different device blocked on the fixture device's timer")
	}
	// The fixture cleanup drains the real pending timer.
}

// TestAwaitAutoReverts_SupersededFireIsAwaited pins the review finding
// on the supersede path: a revert goroutine already past its CAS when a
// second POST Swaps its map entry away is claimable by neither the sweep
// nor its own CompareAndDelete — only the per-device counter barrier
// covers it. Sequence: POST1's revert fires and blocks in the notify
// hook (past CAS, mid-Broadcast); POST2 supersedes on the same leaf;
// the drain must not return until the blocked fire completes.
func TestAwaitAutoReverts_SupersededFireIsAwaited(t *testing.T) {
	f := newStateAPIFixture(t)
	ic := f.device.metricsCycler.ifCounters.Load()
	state := ic.State()

	// Block ONLY the revert-to-UP fire; DOWN transitions pass so the
	// POST handlers are never blocked by their own initial mutation.
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	state.SetNotify(func(evt StateChange) {
		if evt.Oper == OperUp {
			once.Do(func() { close(entered) })
			<-release
		}
	})

	body := strings.NewReader(`{"status":"DOWN","duration":"20ms"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST1: %d %s", rr.Code, rr.Body.String())
	}

	// Revert fired: goroutine is past its CAS, blocked in the hook.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("revert never reached the notify hook")
	}

	// POST2 supersedes on the same (ip, ifIndex, leaf): Swap replaces
	// the map entry, so the blocked goroutine is invisible to the sweep.
	body = strings.NewReader(`{"status":"DOWN","duration":"1h"}`)
	req = httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr = httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST2: %d %s", rr.Code, rr.Body.String())
	}

	drained := make(chan struct{})
	go func() {
		f.mgr.awaitAutoRevertsForDevice("10.42.0.1")
		close(drained)
	}()

	// Positive-hold: the superseded fire is still executing; the drain
	// (which claimed only POST2's timer) must not have returned.
	select {
	case <-drained:
		t.Fatal("drain returned while the superseded revert goroutine was still executing")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not return after the superseded goroutine exited")
	}
}

// TestAwaitAutoReverts_CancelledPathSignalsExit pins that the cancelled
// branch (no mutation, no broadcast) also closes `finished`: draining a
// long-duration pending revert returns promptly instead of waiting out
// the timer.
func TestAwaitAutoReverts_CancelledPathSignalsExit(t *testing.T) {
	f := newStateAPIFixture(t)
	body := strings.NewReader(`{"status":"DOWN","duration":"1h"}`)
	req := httptest.NewRequest("POST", "/api/v1/devices/10.42.0.1/interfaces/1/oper-status", body)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST: %d", rr.Code)
	}
	done := make(chan struct{})
	go func() {
		f.mgr.awaitAutoRevertsForDevice("10.42.0.1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not return promptly on the cancelled path")
	}
	// Claimed entry was removed by the drain.
	count := 0
	f.mgr.revertTimers.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Errorf("revertTimers entries after drain: got %d, want 0", count)
	}
}
