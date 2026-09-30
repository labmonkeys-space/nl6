/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strconv"
)

// Prometheus HTTP service discovery (http_sd_configs). The body is a derived
// view over the live device map, like the DNS zone: no flag, no subsystem, no
// per-device state. Targets are SNMP agents for snmp_exporter's
// __param_target relabel pattern; nl6 devices serve no /metrics themselves.

// promSDDevice is the only input the SD body is built from. Its field set is
// the credential boundary: an SD body is logged and cached by Prometheus, so
// nothing secret may be added here (pinned by TestPromSDDevice_FieldSetIsExact).
type promSDDevice struct {
	IP           string
	SNMPPort     int
	ResourceFile string
	DeviceType   string
	SysName      string
}

type promSDTargetGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// promSDDevices snapshots the running devices under the manager's read lock.
// Stopped devices are left out: listing them would only produce scrape errors.
func (sm *SimulatorManager) promSDDevices() []promSDDevice {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	// A device created with no resource file (the -auto-start-ip batch) serves
	// the startup default profile. defaultResourceKey names it; it is empty
	// only when the compiled-in asr9k default was synthesised.
	defaultRF := sm.defaultResourceKey
	if defaultRF == "" {
		defaultRF = defaultResourceFile
	}
	out := make([]promSDDevice, 0, len(sm.devices))
	for _, d := range sm.devices {
		if !d.running {
			continue
		}
		name := d.sysName
		if v, ok := d.cachedSysName.Load().(string); ok && v != "" {
			name = v
		}
		rf := d.resourceFile
		if rf == "" {
			rf = defaultRF
		}
		out = append(out, promSDDevice{
			IP:           d.IP.String(),
			SNMPPort:     d.SNMPPort,
			ResourceFile: rf,
			DeviceType:   getDeviceTypeFromResourceFile(rf),
			SysName:      name,
		})
	}
	return out
}

// buildPrometheusSDTargets returns one target group per device, sorted by IP
// numerically. The target is the bare IP on port 161 and ip:port otherwise;
// snmp_exporter accepts both. Labels are __meta_* so Prometheus drops them
// after relabeling unless the operator keeps them. No snmp_exporter module is
// chosen here: the operator maps __meta_nl6_resource to __param_module.
func buildPrometheusSDTargets(devices []promSDDevice) []promSDTargetGroup {
	sort.Slice(devices, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(devices[i].IP).To16(), net.ParseIP(devices[j].IP).To16()) < 0
	})
	groups := make([]promSDTargetGroup, 0, len(devices))
	for _, d := range devices {
		port := strconv.Itoa(d.SNMPPort)
		target := d.IP
		if d.SNMPPort != 161 {
			target = net.JoinHostPort(d.IP, port)
		}
		groups = append(groups, promSDTargetGroup{
			Targets: []string{target},
			Labels: map[string]string{
				"__meta_nl6_resource":    resourceDirName(d.ResourceFile),
				"__meta_nl6_device_type": d.DeviceType,
				"__meta_nl6_sys_name":    d.SysName,
				"__meta_nl6_snmp_port":   port,
			},
		})
	}
	return groups
}

func prometheusSDHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(buildPrometheusSDTargets(manager.promSDDevices()))
}
