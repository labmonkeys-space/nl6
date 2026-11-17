/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fixedClock returns a clock that reads *at, so a test moves time by
// assigning to it.
func fixedClock(at *time.Time) func() time.Time {
	return func() time.Time { return *at }
}

// bootedShippedDevice builds a shipped profile the way both creation paths do,
// through initDeviceCyclers, with the boot instant and the uptime clock pinned.
func bootedShippedDevice(t *testing.T, profile string, boot time.Time, now *time.Time) *SNMPServer {
	t.Helper()
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources(profile)
	if err != nil {
		t.Fatalf("LoadSpecificResources(%s): %v", profile, err)
	}
	device := &DeviceSimulator{
		ID:           "uptime-" + profile,
		IP:           net.IPv4(10, 42, 0, 1),
		resources:    res,
		resourceFile: profile,
		sysName:      "uptime-" + strings.TrimSuffix(profile, ".json"),
		sysLocation:  "Lab",
		bootTime:     boot,
	}
	if now != nil {
		device.now = fixedClock(now)
	}
	initDeviceCyclers(device)
	return &SNMPServer{device: device}
}

// TestSysUpTimeCountsFromTheBootInstant: sysUpTime.0 is the time since the
// device booted, in hundredths of a second (SNMPv2-MIB), read at serve time.
func TestSysUpTimeCountsFromTheBootInstant(t *testing.T) {
	boot := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	now := boot
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "descr"})
	s.device.bootTime = boot
	s.device.now = fixedClock(&now)

	for _, c := range []struct {
		after time.Duration
		want  string
	}{
		{0, "0"},
		{9 * time.Millisecond, "0"},
		{10 * time.Millisecond, "1"},
		{12345 * time.Millisecond, "1234"},
		{31*24*time.Hour + 14*time.Hour, "272880000"},
	} {
		now = boot.Add(c.after)
		if got := s.findResponse(sysUpTimeOID); got != c.want {
			t.Errorf("sysUpTime.0 %v after boot = %q, want %q", c.after, got, c.want)
		}
	}
}

// TestSysUpTimeWrapsLikeTimeTicks: TimeTicks is a 32-bit counter of
// centiseconds, so the value wraps after about 497 days instead of growing
// past 2^32, which the encoder would degrade to an OCTET STRING (nl6#541).
func TestSysUpTimeWrapsLikeTimeTicks(t *testing.T) {
	boot := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := boot.Add(time.Duration(1<<32+7) * 10 * time.Millisecond)
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "descr"})
	s.device.bootTime = boot
	s.device.now = fixedClock(&now)

	if got := s.findResponse(sysUpTimeOID); got != "7" {
		t.Errorf("sysUpTime.0 2^32+7 ticks after boot = %q, want %q", got, "7")
	}
	now = boot.Add(time.Duration(1<<32-1) * 10 * time.Millisecond)
	if got := s.findResponse(sysUpTimeOID); got != strconv.FormatUint(1<<32-1, 10) {
		t.Errorf("sysUpTime.0 one tick before the wrap = %q, want %d", got, uint64(1<<32-1))
	}
}

// TestSysUpTimeBeforeBootReadsZero: a clock that reads before the boot instant
// answers 0, not a wrapped huge value. Only an injected clock can: the real one
// carries Go's monotonic reading, so elapsed time never goes negative.
func TestSysUpTimeBeforeBootReadsZero(t *testing.T) {
	boot := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	now := boot.Add(-5 * time.Second)
	s := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "descr"})
	s.device.bootTime = boot
	s.device.now = fixedClock(&now)

	if got := s.findResponse(sysUpTimeOID); got != "0" {
		t.Errorf("sysUpTime.0 5 s before boot = %q, want %q", got, "0")
	}
}

// TestSysUpTimeLiveValueBeatsAStaticRow: an operator resource file may still
// carry a sysUpTime.0 row. On a booted device the live value answers GET and
// GETNEXT; the row is never served.
func TestSysUpTimeLiveValueBeatsAStaticRow(t *testing.T) {
	boot := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	now := boot.Add(42 * time.Second)
	s := newTestServer(map[string]string{
		".1.3.6.1.2.1.1.1.0": "descr",
		".1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.32473.1.1",
		sysUpTimeOID:         "999",
		".1.3.6.1.2.1.1.4.0": "contact",
	})
	s.device.bootTime = boot
	s.device.now = fixedClock(&now)

	if got := s.findResponse(sysUpTimeOID); got != "4200" {
		t.Errorf("GET sysUpTime.0 = %q, want the live 4200, not the row", got)
	}
	oid, val := s.findNextOID(".1.3.6.1.2.1.1.2.0")
	if oid != sysUpTimeOID || val != "4200" {
		t.Errorf("GETNEXT(sysObjectID.0) = (%s, %q), want (%s, %q)", oid, val, sysUpTimeOID, "4200")
	}
}

// TestSysUpTimeWithoutBootInstantServesTheResources: a device built without a
// boot instant (hand-built test fixtures; every production device gets one in
// initDeviceCyclers) answers sysUpTime.0 from its resources, like any other
// static OID, and noSuchObject when they carry none.
func TestSysUpTimeWithoutBootInstantServesTheResources(t *testing.T) {
	withRow := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "descr", sysUpTimeOID: "999"})
	if got := withRow.findResponse(sysUpTimeOID); got != "999" {
		t.Errorf("unbooted device with a row: sysUpTime.0 = %q, want %q", got, "999")
	}
	withoutRow := newTestServer(map[string]string{".1.3.6.1.2.1.1.1.0": "descr"})
	if got := withoutRow.findResponse(sysUpTimeOID); got != valueNoSuchObject {
		t.Errorf("unbooted device without a row: sysUpTime.0 = %q, want noSuchObject", got)
	}
}

// TestInitDeviceCyclersStampsTheBootInstant: the shared creation helper gives
// every device a boot instant, and keeps one that is already set.
func TestInitDeviceCyclersStampsTheBootInstant(t *testing.T) {
	before := time.Now()
	s := bootedShippedDevice(t, "cisco_ios.json", time.Time{}, nil)
	after := time.Now()
	if b := s.device.bootTime; b.Before(before) || b.After(after) {
		t.Errorf("bootTime = %v, want within [%v, %v]", b, before, after)
	}

	pinned := time.Now().Add(-time.Hour)
	s = bootedShippedDevice(t, "cisco_ios.json", pinned, nil)
	if !s.device.bootTime.Equal(pinned) {
		t.Errorf("bootTime = %v, want the pre-set %v kept", s.device.bootTime, pinned)
	}
}

// TestEveryShippedTypeServesALiveSysUpTime walks the system group of every
// shipped profile. Each must answer sysUpTime.0 live on GET and reach
// sysUpTime.0, sysName.0 and sysLocation.0 on a walk, in increasing order.
// The walk half is the GETNEXT fast-path defect: sysName.0 and sysLocation.0
// are left out of sortedOIDs, so the precomputed successor of sysContact.0
// jumped straight to sysServices.0 and a walk skipped both.
func TestEveryShippedTypeServesALiveSysUpTime(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	now := boot.Add(77 * time.Second)
	profiles := shippedProfileNames(t)
	if len(profiles) == 0 {
		t.Fatal("no shipped profiles found")
	}
	for _, profile := range profiles {
		s := bootedShippedDevice(t, profile, boot, &now)
		if got := s.findResponse(sysUpTimeOID); got != "7700" {
			t.Errorf("%s: GET sysUpTime.0 = %q, want %q", profile, got, "7700")
		}

		seen := map[string]string{}
		cur := ".1.3.6.1.2.1.1"
		for steps := 0; steps < 64; steps++ {
			next, val := s.findNextOID(cur)
			if next == "" || !strings.HasPrefix(next, ".1.3.6.1.2.1.1.") {
				break
			}
			if compareOIDs(next, cur) <= 0 {
				t.Fatalf("%s: walk not increasing: %s after %s", profile, next, cur)
			}
			seen[next] = val
			cur = next
		}
		if got := seen[sysUpTimeOID]; got != "7700" {
			t.Errorf("%s: walk sysUpTime.0 = %q, want %q", profile, got, "7700")
		}
		if got := seen[sysNameOID]; got != s.device.sysName {
			t.Errorf("%s: walk sysName.0 = %q, want %q", profile, got, s.device.sysName)
		}
		if got := seen[sysLocationOID]; got != s.device.sysLocation {
			t.Errorf("%s: walk sysLocation.0 = %q, want %q", profile, got, s.device.sysLocation)
		}
	}
}

// TestIfLastChangeAgreesWithSysUpTime: IF-MIB defines ifLastChange as the
// value of sysUpTime when the interface entered its state, so read right
// after a transition the two agree to within a second. The bound is loose
// because the two reads are separate real-clock reads, and a loaded runner can
// pause between them. Before nl6#1031 the state engine counted from its own
// construction while sysUpTime was a static resource value.
func TestIfLastChangeAgreesWithSysUpTime(t *testing.T) {
	boot := time.Now().Add(-90 * time.Second)
	s := bootedShippedDevice(t, "asr9k.json", boot, nil)
	ic := s.device.metricsCycler.ifCounters.Load()
	if ic == nil || ic.State() == nil || len(ic.sortedIfIndexes) == 0 {
		t.Fatal("asr9k has no interface state engine")
	}
	idx := ic.sortedIfIndexes[0]
	ic.State().SetLinkState(idx, OperDown)

	lc, err := strconv.ParseUint(s.findResponse(".1.3.6.1.2.1.2.2.1.9."+strconv.Itoa(idx)), 10, 64)
	if err != nil {
		t.Fatalf("ifLastChange.%d: %v", idx, err)
	}
	up, err := strconv.ParseUint(s.findResponse(sysUpTimeOID), 10, 64)
	if err != nil {
		t.Fatalf("sysUpTime.0: %v", err)
	}
	if lc < 9000 || up < lc || up-lc > 100 {
		t.Errorf("ifLastChange.%d = %d, sysUpTime.0 = %d: want ifLastChange about 9000 and at most a second below sysUpTime", idx, lc, up)
	}
}

// TestIfLastChangeWrapsLikeSysUpTime: past 2^32 ticks (about 497 days)
// ifLastChange wraps with sysUpTime.0, so it still encodes as TimeTicks and
// the two stay comparable.
func TestIfLastChangeWrapsLikeSysUpTime(t *testing.T) {
	boot := time.Now().Add(-500 * 24 * time.Hour)
	s := bootedShippedDevice(t, "asr9k.json", boot, nil)
	ic := s.device.metricsCycler.ifCounters.Load()
	if ic == nil || ic.State() == nil || len(ic.sortedIfIndexes) == 0 {
		t.Fatal("asr9k has no interface state engine")
	}
	idx := ic.sortedIfIndexes[0]
	ic.State().SetLinkState(idx, OperDown)

	raw := s.findResponse(".1.3.6.1.2.1.2.2.1.9." + strconv.Itoa(idx))
	lc, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		t.Fatalf("ifLastChange.%d = %q does not fit TimeTicks: %v", idx, raw, err)
	}
	up, err := strconv.ParseUint(s.findResponse(sysUpTimeOID), 10, 32)
	if err != nil {
		t.Fatalf("sysUpTime.0: %v", err)
	}
	if up < lc || up-lc > 100 {
		t.Errorf("ifLastChange.%d = %d, sysUpTime.0 = %d: want ifLastChange at most a second below sysUpTime", idx, lc, up)
	}
}

// TestCatalogResolverEpochFallsBackToTheBootInstant: a device with no
// interface counter cycler still gives the gNMI catalogue resolver the
// device's boot instant as its time base, not the resolver's construction.
func TestCatalogResolverEpochFallsBackToTheBootInstant(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	r := newCatalogResolver(&DeviceSimulator{bootTime: boot}, nil)
	if got := r.epoch(); !got.Equal(boot) {
		t.Errorf("epoch() = %v, want the boot instant %v", got, boot)
	}
}

// TestDeviceEnginesShareTheBootInstant: the metric, counter, state and optical
// engines all measure from the device's boot instant.
func TestDeviceEnginesShareTheBootInstant(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	s := bootedShippedDevice(t, "asr9k.json", boot, nil)
	mc := s.device.metricsCycler
	if !mc.startTime.Equal(boot) {
		t.Errorf("MetricsCycler.startTime = %v, want %v", mc.startTime, boot)
	}
	ic := mc.ifCounters.Load()
	if ic == nil {
		t.Fatal("asr9k has no IfCounterCycler")
	}
	if !ic.startTime.Equal(boot) {
		t.Errorf("IfCounterCycler.startTime = %v, want %v", ic.startTime, boot)
	}
	if got, want := ic.State().bootTimeUnixNs, uint64(boot.UnixNano()); got != want {
		t.Errorf("InterfaceState.bootTimeUnixNs = %d, want %d", got, want)
	}

	optical := bootedShippedDevice(t, "ciena_waveserver5.json", boot, nil)
	oc := optical.device.metricsCycler.optical.Load()
	if oc == nil {
		t.Fatal("ciena_waveserver5 has no optical engine")
	}
	if !oc.StartTime().Equal(boot) {
		t.Errorf("OpticalCycler.startTime = %v, want %v", oc.StartTime(), boot)
	}
}

// TestExportersCountFromTheBootInstant: the trap and syslog uptime and the
// flow SysUptime count from the device's boot instant, not from the moment the
// exporter is attached.
func TestExportersCountFromTheBootInstant(t *testing.T) {
	boot := time.Now().Add(-12 * time.Second)

	t.Run("trap", func(t *testing.T) {
		sm := newTestSimulatorManager()
		if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
			PDUBudget: maxTrapPDU, SourcePerDevice: false, MeanSchedulerInterval: time.Hour,
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(sm.StopTrapExport)
		device := setupTestDeviceForAttach(t, sm, "dev-uptime-trap", net.IPv4(127, 0, 0, 2))
		device.bootTime = boot
		device.trapConfig = &DeviceTrapConfig{
			Collector: "127.0.0.1:16202", Mode: "trap", Community: "public",
			Interval: jsonDuration(time.Second), InformTimeout: jsonDuration(200 * time.Millisecond),
		}
		if err := sm.startDeviceTrapExporter(device); err != nil {
			t.Fatalf("startDeviceTrapExporter: %v", err)
		}
		device.mu.RLock()
		exp := device.trapExporter
		device.mu.RUnlock()
		if !exp.startTime.Equal(boot) {
			t.Errorf("trap exporter startTime = %v, want the boot instant %v", exp.startTime, boot)
		}
		if up := exp.uptimeHundredths(); up < 1200 || up > 1500 {
			t.Errorf("trap uptime = %d ticks, want about 1200", up)
		}
	})

	t.Run("syslog", func(t *testing.T) {
		sm := newTestSyslogManager()
		if err := sm.StartSyslogSubsystem(SyslogSubsystemConfig{
			SourcePerDevice: false, MeanSchedulerInterval: time.Hour,
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(sm.StopSyslogExport)
		device := setupTestDeviceForAttach(t, sm, "dev-uptime-syslog", net.IPv4(127, 0, 0, 3))
		device.bootTime = boot
		device.syslogConfig = &DeviceSyslogConfig{
			Collector: "127.0.0.1:16515", Format: "5424", Interval: jsonDuration(time.Second),
		}
		if err := sm.startDeviceSyslogExporter(device); err != nil {
			t.Fatalf("startDeviceSyslogExporter: %v", err)
		}
		device.mu.RLock()
		exp := device.syslogExporter
		device.mu.RUnlock()
		if !exp.startTime.Equal(boot) {
			t.Errorf("syslog exporter startTime = %v, want the boot instant %v", exp.startTime, boot)
		}
		if up := exp.uptimeHundredths(); up < 1200 || up > 1500 {
			t.Errorf("syslog uptime = %d ticks, want about 1200", up)
		}
	})

	t.Run("flow", func(t *testing.T) {
		device := testDevice("10.42.0.9")
		device.bootTime = boot
		fe := NewFlowExporter(device, GetFlowProfile("asr9k.json"),
			30*time.Second, 15*time.Second, time.Minute,
			"127.0.0.1:2055", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2055},
			"netflow9", nil, 0)
		if !fe.startTime.Equal(boot) {
			t.Errorf("flow exporter startTime = %v, want the boot instant %v", fe.startTime, boot)
		}
	})
}

// TestUSMEngineTimeCountsFromTheBootInstant: the poll engine's clock starts at
// the device's boot instant, not at its first v3 message. The notification
// engine (no device) keeps its own attach-time clock.
func TestUSMEngineTimeCountsFromTheBootInstant(t *testing.T) {
	boot := time.Now().Add(-100 * time.Second)
	polled := &SNMPServer{
		device:   &DeviceSimulator{bootTime: boot},
		v3Config: &SNMPv3Config{Enabled: true, EngineID: "800000090300AABBCCDD", Username: "u", Password: "password1"},
	}
	u := polled.usmState()
	if !u.bootedAt.Equal(boot) {
		t.Errorf("poll engine bootedAt = %v, want the device boot instant %v", u.bootedAt, boot)
	}
	if et := u.engineTimeSeconds(); et < 100 || et > 160 {
		t.Errorf("engine time on the first v3 message = %d s, want about 100", et)
	}

	before := time.Now()
	notifier := &SNMPServer{v3Config: &SNMPv3Config{Enabled: true, EngineID: "800000090300AABBCCDD", Username: "u", Password: "password1"}}
	if b := notifier.usmState().bootedAt; b.Before(before) {
		t.Errorf("deviceless engine bootedAt = %v, want its own first use (after %v)", b, before)
	}
}

// TestSysUpTimeGoesOnTheWireAsTimeTicks drives real datagrams: a v2c GET, a v1
// GET and a v2c GETBULK from sysObjectID.0 each carry sysUpTime.0 tagged
// TimeTicks (0x43), the type SNMPv2-MIB declares.
func TestSysUpTimeGoesOnTheWireAsTimeTicks(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	now := boot.Add(5 * time.Minute)
	s := bootedShippedDevice(t, "dell_emc_unity.json", boot, &now)

	for _, c := range []struct {
		name string
		req  []byte
	}{
		{"v2c GET", v2cGetRequest(sysUpTimeOID)},
		{"v1 GET", getRequestAtVersion(snmpVersion1, sysUpTimeOID)},
		{"v2c GETBULK", v2cGetBulkRequest(0, 3, []string{".1.3.6.1.2.1.1.2.0"})},
	} {
		resp := s.handleSNMPv2cRequest(c.req)
		if len(resp) == 0 {
			t.Fatalf("%s: no response", c.name)
		}
		oid, tag := v2cFirstVarbind(t, resp)
		if oid != sysUpTimeOID || tag != ASN1_TIMETICKS {
			t.Errorf("%s: first binding %s tagged 0x%02x, want %s tagged TimeTicks 0x%02x",
				c.name, oid, tag, sysUpTimeOID, ASN1_TIMETICKS)
		}
	}
}

// TestSysUpTimeWalkOnAnEmptyResourceMap: a booted device with no static rows
// takes the walk's dynamic-only branch, and that branch reaches sysUpTime.0
// first, then sysName.0.
func TestSysUpTimeWalkOnAnEmptyResourceMap(t *testing.T) {
	boot := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	now := boot.Add(3 * time.Second)
	s := newTestServer(map[string]string{})
	s.device.bootTime = boot
	s.device.now = fixedClock(&now)
	s.device.sysName = "empty"

	if oid, val := s.findNextOID(".1.3.6.1.2.1.1"); oid != sysUpTimeOID || val != "300" {
		t.Errorf("GETNEXT(system) = (%s, %q), want (%s, %q)", oid, val, sysUpTimeOID, "300")
	}
	if oid, val := s.findNextOID(sysUpTimeOID); oid != sysNameOID || val != "empty" {
		t.Errorf("GETNEXT(sysUpTime.0) = (%s, %q), want (%s, %q)", oid, val, sysNameOID, "empty")
	}
}

// TestWalkDoesNotSkipSysNameOrSysLocationAlone pins each half of the GETNEXT
// fast-path term on its own. On a shipped profile sysName.0 and sysLocation.0
// sit next to each other, so an interval holding one holds both and either term
// would cover for the other. A static row between them separates the two cases.
func TestWalkDoesNotSkipSysNameOrSysLocationAlone(t *testing.T) {
	s := newTestServer(map[string]string{
		".1.3.6.1.2.1.1.4.0": "contact",
		".1.3.6.1.2.1.1.5.1": "between",
		".1.3.6.1.2.1.1.7.0": "72",
	})
	s.device.sysName = "name"
	s.device.sysLocation = "location"

	if oid, val := s.findNextOID(".1.3.6.1.2.1.1.4.0"); oid != sysNameOID || val != "name" {
		t.Errorf("GETNEXT(sysContact.0) = (%s, %q), want (%s, %q): the static successor skipped sysName.0",
			oid, val, sysNameOID, "name")
	}
	if oid, val := s.findNextOID(".1.3.6.1.2.1.1.5.1"); oid != sysLocationOID || val != "location" {
		t.Errorf("GETNEXT(1.3.6.1.2.1.1.5.1) = (%s, %q), want (%s, %q): the static successor skipped sysLocation.0",
			oid, val, sysLocationOID, "location")
	}
}
