/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestYangPushConfigDefaults(t *testing.T) {
	c := &DeviceYangPushConfig{Collector: "127.0.0.1:9000"}
	c.ApplyDefaults()
	if c.SegmentSize != 1436 {
		t.Errorf("SegmentSize = %d, want 1436", c.SegmentSize)
	}
	c = &DeviceYangPushConfig{Collector: "127.0.0.1:9000", SegmentSize: 900}
	c.ApplyDefaults()
	if c.SegmentSize != 900 {
		t.Errorf("explicit SegmentSize overwritten: %d", c.SegmentSize)
	}
	var nilCfg *DeviceYangPushConfig
	nilCfg.ApplyDefaults() // must not panic
}

func TestYangPushConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     *DeviceYangPushConfig
		wantErr string
	}{
		{"ok", &DeviceYangPushConfig{Collector: "127.0.0.1:9000", SegmentSize: 1436}, ""},
		{"min", &DeviceYangPushConfig{Collector: "127.0.0.1:9000", SegmentSize: 512}, ""},
		{"max", &DeviceYangPushConfig{Collector: "127.0.0.1:9000", SegmentSize: 65507}, ""},
		{"nil", nil, ""},
		{"missing collector", &DeviceYangPushConfig{SegmentSize: 1436}, "collector is required"},
		{"bad host:port", &DeviceYangPushConfig{Collector: "nonsense", SegmentSize: 1436}, "host:port"},
		{"ipv6 collector", &DeviceYangPushConfig{Collector: "[2001:db8::1]:10000", SegmentSize: 1436}, "IPv6"},
		{"too small", &DeviceYangPushConfig{Collector: "127.0.0.1:9000", SegmentSize: 511}, "segment_size"},
		{"too large", &DeviceYangPushConfig{Collector: "127.0.0.1:9000", SegmentSize: 65508}, "segment_size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "yang_push") {
				t.Fatalf("err = %v, want yang_push error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestSupportsYangPush(t *testing.T) {
	for rf, want := range map[string]bool{
		"huawei_ne8000":                true,
		"huawei_ne8000.json":           true,
		"resources/huawei_ne8000.json": true,
		"cisco_ios.json":               false,
		"juniper_mx10004.json":         false,
		"":                             false,
	} {
		if got := SupportsYangPush(rf); got != want {
			t.Errorf("SupportsYangPush(%q) = %v, want %v", rf, got, want)
		}
	}
}

// ypHandlerManager installs a bare manager for createDevicesHandler tests.
func ypHandlerManager(t *testing.T, defaultKey string) {
	t.Helper()
	prev := manager
	manager = &SimulatorManager{defaultResourceKey: defaultKey}
	t.Cleanup(func() { manager = prev })
}

func ypPost(t *testing.T, req CreateDevicesRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	createDevicesHandler(w, httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body)))
	return w
}

func TestYangPushRequestIPv6Collector400(t *testing.T) {
	ypHandlerManager(t, "huawei_ne8000.json")
	w := ypPost(t, CreateDevicesRequest{StartIP: "10.0.0.1", DeviceCount: 1, Netmask: "24",
		ResourceFile: "huawei_ne8000.json", YangPush: &DeviceYangPushConfig{Collector: "[2001:db8::1]:10000"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "IPv6") {
		t.Fatalf("status = %d, body %s; want 400 naming IPv6", w.Code, w.Body.String())
	}
}

func TestYangPushRequestIncapableDefault400(t *testing.T) {
	ypHandlerManager(t, "cisco_ios.json")
	w := ypPost(t, CreateDevicesRequest{StartIP: "10.0.0.1", DeviceCount: 1, Netmask: "24",
		YangPush: &DeviceYangPushConfig{Collector: "127.0.0.1:9000"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "yang_push") {
		t.Fatalf("status = %d, body %s; want 400 naming yang_push", w.Code, w.Body.String())
	}
}

func TestYangPushRequestAllIncapable400(t *testing.T) {
	ypHandlerManager(t, "")
	body, _ := json.Marshal(CreateDevicesRequest{
		StartIP:      "10.0.0.1",
		DeviceCount:  1,
		Netmask:      "24",
		ResourceFile: "cisco_ios.json",
		YangPush:     &DeviceYangPushConfig{Collector: "127.0.0.1:9000"},
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
	w := httptest.NewRecorder()
	createDevicesHandler(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "yang_push") {
		t.Errorf("body does not name yang_push: %s", w.Body.String())
	}
	if _, bad := yangPushIncapableRequest(CreateDevicesRequest{ResourceFile: "huawei_ne8000.json"}, ""); bad {
		t.Error("huawei_ne8000.json must be capable")
	}
}

func TestYangPushMixedBatchSkipsIncapable(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	yangPushUnsupportedLogged.Range(func(k, _ any) bool { yangPushUnsupportedLogged.Delete(k); return true })

	seed := &ExportSeed{YangPush: &DeviceYangPushConfig{Collector: "127.0.0.1:9000", SegmentSize: 1436}}
	capable := &DeviceSimulator{resourceFile: "huawei_ne8000.json"}
	other := &DeviceSimulator{resourceFile: "cisco_ios.json"}
	applyExportSeed(capable, seed)
	applyExportSeed(other, seed)
	if capable.yangPushConfig == nil || capable.yangPushConfig.Collector != "127.0.0.1:9000" {
		t.Fatalf("capable device config = %+v", capable.yangPushConfig)
	}
	if capable.yangPushConfig == seed.YangPush {
		t.Error("device shares the seed pointer; want a copy")
	}
	if other.yangPushConfig != nil {
		t.Errorf("incapable device got config %+v", other.yangPushConfig)
	}
	if !strings.Contains(buf.String(), "yang_push") || !strings.Contains(buf.String(), "cisco_ios") {
		t.Errorf("no skip log line, got %q", buf.String())
	}
}

func TestYangPushListDevicesEcho(t *testing.T) {
	sm := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
	}
	sm.devices["on"] = &DeviceSimulator{ID: "on", IP: net.IPv4(10, 42, 0, 1), resourceFile: "huawei_ne8000.json",
		yangPushConfig: &DeviceYangPushConfig{Collector: "127.0.0.1:9000", SegmentSize: 1436}}
	sm.devices["off"] = &DeviceSimulator{ID: "off", IP: net.IPv4(10, 42, 0, 2), resourceFile: "huawei_ne8000.json"}
	byID := map[string]DeviceInfo{}
	for _, info := range sm.ListDevices() {
		byID[info.ID] = info
	}
	if y := byID["on"].YangPush; y == nil || y.Collector != "127.0.0.1:9000" || y.SegmentSize != 1436 {
		t.Errorf("echo = %+v", y)
	}
	if byID["off"].YangPush != nil {
		t.Error("device without opt-in must echo nil")
	}
	b, _ := json.Marshal(byID["on"])
	if !strings.Contains(string(b), `"yang_push":{"collector":"127.0.0.1:9000","segment_size":1436}`) {
		t.Errorf("json = %s", b)
	}
}

func TestYangPushIncapableRequestDefaultKey(t *testing.T) {
	req := CreateDevicesRequest{}
	if _, bad := yangPushIncapableRequest(req, "cisco_ios.json"); !bad {
		t.Error("incapable default profile must be rejected")
	}
	if _, bad := yangPushIncapableRequest(req, ""); !bad {
		t.Error("the fallback default profile is not huawei_ne8000 and must be rejected")
	}
	if _, bad := yangPushIncapableRequest(req, "huawei_ne8000.json"); bad {
		t.Error("capable default profile must be accepted")
	}
}
