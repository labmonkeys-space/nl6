/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// ypScenarioManager builds a manager with n devices at 10.42.0.1..n. Each
// device in withExporter (1-based) carries a YANG-Push exporter that is not
// started, which is all the wiring looks at.
func ypScenarioManager(t *testing.T, n int, withExporter ...int) *SimulatorManager {
	t.Helper()
	sm := &SimulatorManager{
		devices: map[string]*DeviceSimulator{}, deviceIPs: map[string]struct{}{},
		deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{},
	}
	for i := 1; i <= n; i++ {
		ip := fmt.Sprintf("10.42.0.%d", i)
		dev := &DeviceSimulator{ID: "device-" + ip, IP: net.ParseIP(ip).To4()}
		sm.devices[dev.ID] = dev
		sm.deviceIPs[ip] = struct{}{}
		sm.devicesByIP[ip] = dev
	}
	for _, i := range withExporter {
		ip := fmt.Sprintf("10.42.0.%d", i)
		sm.devicesByIP[ip].yangPushExporter = &YangPushExporter{collector: "192.0.2.10:10003"}
	}
	return sm
}

func TestScenarioValidate_YangPush(t *testing.T) {
	s := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "yang-push", Rate: 1, Window: 2 * time.Minute}
	if err := s.Validate(); err != nil {
		t.Fatalf("yang-push scenario rejected: %v", err)
	}
	s.Protocol = "no-such-protocol"
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "yang-push") {
		t.Fatalf("unknown-protocol error should list yang-push: %v", err)
	}
}

func TestScenarioYangPush_ArmExcludesDeviceWithoutExporter(t *testing.T) {
	sm := ypScenarioManager(t, 2, 1)
	c := newScenario(t, sm, "s-000001", "yang-push", "10.42.0.1", "10.42.0.2")
	armed, excluded, err := c.Arm()
	if err != nil {
		t.Fatal(err)
	}
	if armed != 1 || len(excluded) != 1 {
		t.Fatalf("armed=%d excluded=%d, want 1 and 1", armed, len(excluded))
	}
	ex := excluded[0]
	if ex.Device != "10.42.0.2" || ex.Reason != "device has no yang-push exporter" ||
		ex.RemediationHint != "opt the device in with a yang_push block (huawei_ne8000 only)" {
		t.Errorf("excluded = %+v", ex)
	}
	if got := sm.devicesByIP["10.42.0.1"].yangPushExporter.scenPart.Load(); got == nil || got.owner != "s-000001" {
		t.Errorf("the device with an exporter was not claimed: %+v", got)
	}
	// Cancel releases the claim, so the device streams on its own again.
	if err := c.Cancel(); err != nil {
		t.Fatal(err)
	}
	if got := sm.devicesByIP["10.42.0.1"].yangPushExporter.scenPart.Load(); got != nil {
		t.Errorf("claim not released at cancel: %+v", got)
	}
}

func TestScenarioYangPush_NotPaced(t *testing.T) {
	sm := ypScenarioManager(t, 1, 1)
	c := newScenario(t, sm, "s-000001", "yang-push", "10.42.0.1")
	if c.pacesRate() {
		t.Error("yang-push must not be paced: the device keeps its own 60 s grid")
	}
	if c.usesScheduler() {
		t.Error("yang-push must not use a scenario scheduler")
	}
}

func TestScenarioYangPush_SlotConflict(t *testing.T) {
	sm := ypScenarioManager(t, 2, 1, 2)
	holder := newScenario(t, sm, "s-000001", "yang-push", "10.42.0.1")
	if _, _, err := holder.Arm(); err != nil {
		t.Fatal(err)
	}
	intruder := newScenario(t, sm, "s-000002", "yang-push", "10.42.0.1", "10.42.0.2")
	_, _, err := intruder.Arm()
	if err == nil {
		t.Fatal("arm over a claimed device should be refused")
	}
	for _, want := range []string{"s-000001", "10.42.0.1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal should name %q: %v", want, err)
		}
	}
	if got := sm.devicesByIP["10.42.0.1"].yangPushExporter.scenPart.Load(); got == nil || got.owner != "s-000001" {
		t.Errorf("holder lost its claim: %+v", got)
	}
	if got := sm.devicesByIP["10.42.0.2"].yangPushExporter.scenPart.Load(); got != nil {
		t.Errorf("refused arm claimed a device anyway: %+v", got)
	}
}

func TestScenarioCollectorFor_YangPush(t *testing.T) {
	sm := ypScenarioManager(t, 2, 1)
	if got := sm.scenarioCollectorFor("10.42.0.1", "yang-push"); got != "192.0.2.10:10003" {
		t.Errorf("collector = %q, want the exporter's", got)
	}
	if got := sm.scenarioCollectorFor("10.42.0.2", "yang-push"); got != "" {
		t.Errorf("collector for a device without exporter = %q, want empty", got)
	}
	if got := sm.scenarioCollectorFor("10.42.0.9", "yang-push"); got != "" {
		t.Errorf("collector for an unknown device = %q, want empty", got)
	}
}

func TestBuildRunTags_YangPush(t *testing.T) {
	rt := buildRunTags("yang-push", 32473, "s-000001")
	if rt.Mechanism != tagWindowSourceIP || rt.Value != "" || rt.Degraded || rt.PENRequired {
		t.Errorf("run tags = %+v, want window and source IP, no value, not degraded", rt)
	}
	if !strings.Contains(rt.Note, "message-publisher-id") {
		t.Errorf("note should name message-publisher-id: %q", rt.Note)
	}
}
