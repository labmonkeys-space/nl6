/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// plantedDevice builds a device of profile with a static row on oid, the way an
// operator's edited copy of a shipped profile could carry it, and pins the
// metric clock so a GET and a walk read the same point.
func plantedDevice(t *testing.T, profile, oid, value string) *SNMPServer {
	t.Helper()
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	shipped, err := sm.LoadSpecificResources(profile)
	if err != nil {
		t.Fatalf("LoadSpecificResources(%s): %v", profile, err)
	}
	// Replace the OID's row when the profile ships one, rather than adding a
	// second: an operator file carries one row per OID.
	var rows []SNMPResource
	for _, r := range shipped.SNMP {
		if normaliseResourceOID(r.OID) != oid {
			rows = append(rows, r)
		}
	}
	res := &DeviceResources{SNMP: append(rows, SNMPResource{OID: oid, Response: value})}
	sm.buildResourceIndexes(res)
	device := &DeviceSimulator{IP: net.IPv4(10, 42, 0, 1), resources: res, resourceFile: profile, sysName: "planted", bootTime: time.Now().Add(-time.Hour)}
	initDeviceCyclers(device)
	at := device.bootTime.Add(30 * time.Minute)
	device.metricsCycler.now = func() time.Time { return at }
	return &SNMPServer{device: device}
}

// walkValue walks from root and returns the value the walk serves for oid, and
// how many times the walk returned it.
func walkValue(s *SNMPServer, root, oid string) (string, int) {
	cur, val, seen := root, "", 0
	for i := 0; i < 20000; i++ {
		next, v := s.findNextOID(cur)
		if next == "" || !strings.HasPrefix(next, root+".") {
			break
		}
		if next == oid {
			val, seen = v, seen+1
		}
		cur = next
	}
	return val, seen
}

// TestWalkServesTheMetricValueOverAStaticRow: a static row on a metric-owned OID
// must not win the walk. Keeping such rows out of the shipped profiles does not
// close the class on its own: an operator's edited copy of a shipped profile can
// carry one, so the walk lets the metric value win the tie, as it does for
// sysUpTime.0. Both walk routes are covered: extremeCurrentTemperature.0 is
// extreme_vsp4450's first metric OID, so the fast path would return the
// precomputed static successor; hrProcessorLoad.1 on nvidia_dgx_h100 goes
// through the slow path, where the static candidate is listed first.
func TestWalkServesTheMetricValueOverAStaticRow(t *testing.T) {
	for _, tc := range []struct{ name, profile, root, oid string }{
		{"fast path", "extreme_vsp4450.json", ".1.3.6.1.4.1.1916", ".1.3.6.1.4.1.1916.1.1.1.8.0"},
		{"slow path", "nvidia_dgx_h100.json", ".1.3.6.1.2.1.25", ".1.3.6.1.2.1.25.3.3.1.2.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const planted = "999999"
			s := plantedDevice(t, tc.profile, tc.oid, planted)
			if _, ok := s.device.resources.oidIndex.Load(tc.oid); !ok {
				t.Fatalf("fixture: %s carries no static row on %s", tc.profile, tc.oid)
			}
			get := s.findResponse(tc.oid)
			walked, seen := walkValue(s, tc.root, tc.oid)
			if seen != 1 {
				t.Fatalf("%s: the walk returned %s %d times, want once", tc.profile, tc.oid, seen)
			}
			if get == planted || walked != get {
				t.Errorf("%s %s: GET %q, walk %q, want both the metric value, not the static %q",
					tc.profile, tc.oid, get, walked, planted)
			}
		})
	}
}

// TestGetAndWalkAgreeOnEveryMetricOID is the measurement nl6#1056 started from,
// kept as a test: on every shipped profile with a metric map, a GET and a walk
// of every metric-owned OID give the same value at the same metric point.
func TestGetAndWalkAgreeOnEveryMetricOID(t *testing.T) {
	profiles := 0
	for _, profile := range shippedProfileNames(t) {
		m := GetMetricOIDs(profile)
		if len(m) == 0 {
			continue
		}
		profiles++
		s := bootedShippedDevice(t, profile, time.Now().Add(-time.Hour), nil)
		at := s.device.bootTime.Add(30 * time.Minute)
		s.device.metricsCycler.now = func() time.Time { return at }
		walked := map[string]string{}
		cur := ".1"
		for i := 0; i < 100000; i++ {
			next, v := s.findNextOID(cur)
			if next == "" || v == valueEndOfMibView {
				break
			}
			if _, ok := m[next]; ok {
				walked[next] = v
			}
			cur = next
		}
		for oid := range m {
			get := s.findResponse(oid)
			w, ok := walked[oid]
			if !ok {
				t.Errorf("%s: the walk never reached the metric OID %s", profile, oid)
				continue
			}
			if w != get {
				t.Errorf("%s %s: GET %q, walk %q", profile, oid, get, w)
			}
		}
	}
	if profiles < 10 {
		t.Errorf("only %d profiles with a metric map were checked", profiles)
	}
}
