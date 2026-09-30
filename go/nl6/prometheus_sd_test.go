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
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestBuildPrometheusSDTargets_PortAndLabels(t *testing.T) {
	got := buildPrometheusSDTargets([]promSDDevice{
		{IP: "10.42.0.2", SNMPPort: 1161, ResourceFile: "juniper_mx240.json", DeviceType: "Juniper MX240", SysName: "edge-02"},
		{IP: "10.42.0.1", SNMPPort: 161, ResourceFile: "cisco_ios.json", DeviceType: "Cisco IOS", SysName: "core-01"},
	})
	want := []promSDTargetGroup{
		{Targets: []string{"10.42.0.1"}, Labels: map[string]string{
			"__meta_nl6_resource":    "cisco_ios",
			"__meta_nl6_device_type": "Cisco IOS",
			"__meta_nl6_sys_name":    "core-01",
			"__meta_nl6_snmp_port":   "161",
		}},
		{Targets: []string{"10.42.0.2:1161"}, Labels: map[string]string{
			"__meta_nl6_resource":    "juniper_mx240",
			"__meta_nl6_device_type": "Juniper MX240",
			"__meta_nl6_sys_name":    "edge-02",
			"__meta_nl6_snmp_port":   "1161",
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

// Prometheus sorts nothing for us and the device map iterates at random, so
// the order is fixed by IP numerically: 10.42.0.10 must follow 10.42.0.9.
func TestBuildPrometheusSDTargets_SortedByIPNumerically(t *testing.T) {
	got := buildPrometheusSDTargets([]promSDDevice{
		{IP: "10.42.0.10", SNMPPort: 161},
		{IP: "10.42.1.0", SNMPPort: 161},
		{IP: "10.42.0.9", SNMPPort: 161},
	})
	var order []string
	for _, g := range got {
		order = append(order, g.Targets[0])
	}
	if want := []string{"10.42.0.9", "10.42.0.10", "10.42.1.0"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

// Prometheus rejects a JSON null body, so an empty fleet must encode as [].
func TestPrometheusSDHandler_EmptyFleetIsEmptyArray(t *testing.T) {
	t.Cleanup(swapGlobalManager(newTestManager()))
	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/prometheus/sd", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if body := strings.TrimSpace(rr.Body.String()); body != "[]" {
		t.Fatalf("body = %q, want []", body)
	}
}

func TestPrometheusSDHandler_ListsOnlyRunningDevices(t *testing.T) {
	mgr := newTestManager()
	mgr.devices["up"] = &DeviceSimulator{IP: net.ParseIP("10.42.0.1"), SNMPPort: 161, resourceFile: "cisco_ios.json", sysName: "core-01", running: true}
	mgr.devices["down"] = &DeviceSimulator{IP: net.ParseIP("10.42.0.2"), SNMPPort: 161, resourceFile: "cisco_ios.json", sysName: "core-02"}
	mgr.devices["up"].cachedSysName.Store("core-01-live")
	t.Cleanup(swapGlobalManager(mgr))

	rr := httptest.NewRecorder()
	setupRoutes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/prometheus/sd", nil))
	var groups []promSDTargetGroup
	if err := json.Unmarshal(rr.Body.Bytes(), &groups); err != nil {
		t.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
	if len(groups) != 1 || groups[0].Targets[0] != "10.42.0.1" {
		t.Fatalf("groups = %+v, want only the running device", groups)
	}
	if got := groups[0].Labels["__meta_nl6_sys_name"]; got != "core-01-live" {
		t.Errorf("sys_name = %q, want the cached live sysName", got)
	}
}

// The snapshot type is the only input the SD body is built from, so its field
// set is the credential boundary. An SD body is logged and cached by
// Prometheus; a community or USM password must never reach it. Adding a field
// here means deciding it is safe to publish, which is why this list is exact.
func TestPromSDDevice_FieldSetIsExact(t *testing.T) {
	var got []string
	typ := reflect.TypeOf(promSDDevice{})
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	sort.Strings(got)
	if want := []string{"DeviceType", "IP", "ResourceFile", "SNMPPort", "SysName"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("promSDDevice fields = %v, want %v", got, want)
	}
}
