/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newTestPathResolver builds a DeviceSimulator with N synthetic
// interfaces (ifIndex 1..N). Each interface gets its ifDescr stored as
// "TestIf<ifIndex>".
func newTestPathResolver(t *testing.T, ifCount int) *pathResolver {
	t.Helper()
	speeds := make([]uint64, ifCount)
	for i := range speeds {
		speeds[i] = 1_000_000_000
	}
	res := buildTestResources(t, speeds)
	for i := 0; i < ifCount; i++ {
		ifIndex := i + 1
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.2.2.1.2.%d", ifIndex), fmt.Sprintf("TestIf%d", ifIndex))
	}
	mc := &MetricsCycler{}
	mc.InitIfCounters(res, 1)
	device := &DeviceSimulator{
		ID:            "test",
		IP:            net.IPv4(10, 42, 0, 1),
		resources:     res,
		metricsCycler: mc,
	}
	return newPathResolver(device)
}

// pathFromString turns "/interfaces/interface[name=*]/state/counters/in-octets"
// into a *gnmi.Path. Lightweight; only handles the shapes used by the tests.
func pathFromString(t *testing.T, s string) *gnmipb.Path {
	t.Helper()
	p := &gnmipb.Path{}
	if s == "" || s == "/" {
		return p
	}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	for _, part := range parts {
		elem := &gnmipb.PathElem{}
		if i := strings.IndexByte(part, '['); i >= 0 {
			elem.Name = part[:i]
			rest := part[i+1:]
			rest = strings.TrimSuffix(rest, "]")
			eq := strings.IndexByte(rest, '=')
			if eq > 0 {
				elem.Key = map[string]string{rest[:eq]: rest[eq+1:]}
			}
		} else {
			elem.Name = part
		}
		p.Elem = append(p.Elem, elem)
	}
	return p
}

func TestPathResolver_WildcardExpansion(t *testing.T) {
	r := newTestPathResolver(t, 3)
	p := pathFromString(t, "/interfaces/interface[name=*]/state/ifindex")
	updates, err := r.Resolve(p, time.Now())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(updates) != 3 {
		t.Fatalf("expected 3 updates for 3 ifIndices, got %d", len(updates))
	}
	seen := map[uint32]bool{}
	for _, u := range updates {
		v, ok := u.Value.(uint32)
		if !ok {
			t.Errorf("expected uint32 ifindex, got %T", u.Value)
			continue
		}
		seen[v] = true
	}
	for i := uint32(1); i <= 3; i++ {
		if !seen[i] {
			t.Errorf("missing ifindex=%d", i)
		}
	}
}

func TestPathResolver_SingleInterfaceLookup(t *testing.T) {
	r := newTestPathResolver(t, 5)
	p := pathFromString(t, "/interfaces/interface[name=TestIf3]/state/ifindex")
	updates, err := r.Resolve(p, time.Now())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	if v, ok := updates[0].Value.(uint32); !ok || v != 3 {
		t.Errorf("expected uint32 ifindex=3, got %v (%T)", updates[0].Value, updates[0].Value)
	}
}

func TestPathResolver_SubtreeFlatten_Counters(t *testing.T) {
	r := newTestPathResolver(t, 1)
	p := pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters")
	updates, err := r.Resolve(p, time.Now())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// 12 counter leaves × 1 interface
	if len(updates) != 12 {
		t.Fatalf("expected 12 counter leaves, got %d", len(updates))
	}
	// Every value should be uint64 (counters).
	for _, u := range updates {
		if _, ok := u.Value.(uint64); !ok {
			t.Errorf("expected uint64 counter value, got %T", u.Value)
		}
	}
}

func TestPathResolver_SubtreeFlatten_State(t *testing.T) {
	r := newTestPathResolver(t, 1)
	p := pathFromString(t, "/interfaces/interface[name=TestIf1]/state")
	updates, err := r.Resolve(p, time.Now())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// 4 state leaves + 12 counter leaves = 16
	if len(updates) != 16 {
		t.Fatalf("expected 16 leaves under /state, got %d", len(updates))
	}
}

func TestPathResolver_OutOfScope_NotFound(t *testing.T) {
	r := newTestPathResolver(t, 1)
	for _, p := range []string{
		"/system/state/hostname",
		"/interfaces/interface[name=TestIf1]/config/enabled",
		"/interfaces/interface[name=TestIf1]/subinterfaces",
		"/interfaces/interface[name=TestIf1]/state/description",
		"/interfaces/interface[name=TestIf1]/state/counters/unknown-leaf",
	} {
		_, err := r.Resolve(pathFromString(t, p), time.Now())
		if err == nil {
			t.Errorf("path %q: expected error, got nil", p)
			continue
		}
		if status.Code(err) != codes.NotFound {
			t.Errorf("path %q: expected NotFound, got %v", p, status.Code(err))
		}
	}
}

// DF3: non-OpenConfig origin must be rejected with NotFound rather
// than silently returning OpenConfig data labelled as the requested
// origin.
func TestPathResolver_NonOpenconfigOrigin_NotFound(t *testing.T) {
	r := newTestPathResolver(t, 1)
	p := pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets")
	p.Origin = "junos"
	_, err := r.Resolve(p, time.Now())
	if err == nil {
		t.Fatal("expected NotFound for non-openconfig origin, got nil")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", status.Code(err))
	}
}

// DF3: empty origin and explicit "openconfig" origin both resolve
// successfully (empty is the conventional default).
func TestPathResolver_OpenconfigOrigin_Accepted(t *testing.T) {
	r := newTestPathResolver(t, 1)
	for _, origin := range []string{"", "openconfig"} {
		p := pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets")
		p.Origin = origin
		updates, err := r.Resolve(p, time.Now())
		if err != nil {
			t.Errorf("origin %q: unexpected error %v", origin, err)
			continue
		}
		if len(updates) != 1 {
			t.Errorf("origin %q: expected 1 update, got %d", origin, len(updates))
		}
	}
}

func TestPathResolver_UnknownIfDescr_NotFound(t *testing.T) {
	r := newTestPathResolver(t, 2)
	p := pathFromString(t, "/interfaces/interface[name=NoSuchInterface]/state/counters/in-octets")
	_, err := r.Resolve(p, time.Now())
	if err == nil {
		t.Fatal("expected NotFound for unknown ifDescr, got nil")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", status.Code(err))
	}
}

func TestPathResolver_LeafTypes(t *testing.T) {
	r := newTestPathResolver(t, 1)
	cases := []struct {
		path    string
		want    string // "uint32" | "uint64" | "string"
		wantStr string // optional
	}{
		{"/interfaces/interface[name=TestIf1]/state/name", "string", "TestIf1"},
		{"/interfaces/interface[name=TestIf1]/state/ifindex", "uint32", ""},
		{"/interfaces/interface[name=TestIf1]/state/oper-status", "string", "openconfig-interfaces:UP"},
		{"/interfaces/interface[name=TestIf1]/state/admin-status", "string", "openconfig-interfaces:UP"},
		{"/interfaces/interface[name=TestIf1]/state/counters/in-octets", "uint64", ""},
		{"/interfaces/interface[name=TestIf1]/state/counters/out-octets", "uint64", ""},
		{"/interfaces/interface[name=TestIf1]/state/counters/in-errors", "uint64", ""},
	}
	for _, tc := range cases {
		updates, err := r.Resolve(pathFromString(t, tc.path), time.Now())
		if err != nil {
			t.Errorf("%s: %v", tc.path, err)
			continue
		}
		if len(updates) != 1 {
			t.Errorf("%s: expected 1 update, got %d", tc.path, len(updates))
			continue
		}
		switch tc.want {
		case "uint32":
			if _, ok := updates[0].Value.(uint32); !ok {
				t.Errorf("%s: want uint32, got %T", tc.path, updates[0].Value)
			}
		case "uint64":
			if _, ok := updates[0].Value.(uint64); !ok {
				t.Errorf("%s: want uint64, got %T", tc.path, updates[0].Value)
			}
		case "string":
			s, ok := updates[0].Value.(string)
			if !ok {
				t.Errorf("%s: want string, got %T", tc.path, updates[0].Value)
				continue
			}
			if tc.wantStr != "" && s != tc.wantStr {
				t.Errorf("%s: want %q, got %q", tc.path, tc.wantStr, s)
			}
		}
	}
}

func TestPathResolver_Capabilities(t *testing.T) {
	r := &pathResolver{}
	cap := r.Capabilities()
	if cap.GNMIVersion != gnmiVersion {
		t.Errorf("gNMI version: got %q, want %q", cap.GNMIVersion, gnmiVersion)
	}
	// supported_encodings must contain JSON_IETF and PROTO, and nothing
	// else (spec scenario).
	want := map[gnmipb.Encoding]bool{
		gnmipb.Encoding_JSON_IETF: true,
		gnmipb.Encoding_PROTO:     true,
	}
	if len(cap.SupportedEncodings) != len(want) {
		t.Fatalf("supported_encodings: got %d, want %d", len(cap.SupportedEncodings), len(want))
	}
	for _, enc := range cap.SupportedEncodings {
		if !want[enc] {
			t.Errorf("unexpected supported encoding %v", enc)
		}
	}
	// supported_models must contain openconfig-interfaces.
	found := false
	for _, m := range cap.SupportedModels {
		if m.GetName() == "openconfig-interfaces" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("supported_models missing openconfig-interfaces")
	}
}

// TestPathResolver_CounterMatchesSNMPAtSameInstant pins the
// "byte-identity" guarantee: for the same time t, the gNMI in-octets
// value matches the SNMP HC ifInOctets value.
func TestPathResolver_CounterMatchesSNMPAtSameInstant(t *testing.T) {
	r := newTestPathResolver(t, 1)
	now := time.Now()

	// gNMI counter
	updates, err := r.Resolve(pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets"), now)
	if err != nil {
		t.Fatalf("gNMI Resolve: %v", err)
	}
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	gnmiVal, ok := updates[0].Value.(uint64)
	if !ok {
		t.Fatalf("expected uint64, got %T", updates[0].Value)
	}

	// Same instant, SNMP path
	cycler := r.device.metricsCycler.ifCounters.Load()
	tSec := now.Sub(cycler.startTime).Seconds()
	snmpVal := parseUintOrZero(cycler.GetDynamicAt(ifXTablePrefix+"6.1", tSec))

	if gnmiVal != snmpVal {
		t.Errorf("gNMI in-octets %d != SNMP ifHCInOctets %d at the same instant", gnmiVal, snmpVal)
	}
}

// Sanity-check helpers — buildTestResources is in if_counters_test.go,
// reused here. Compile-time check that we link the same sync.Map type.
var _ = sync.Map{}
