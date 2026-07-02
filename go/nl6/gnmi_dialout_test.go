/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aristanetworks/goarista/gnmireverse"
	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

// --- test collector (in-process gNMIReverse server) ---------------------

type testDialoutCollector struct {
	gnmireverse.UnimplementedGNMIReverseServer
	mu       sync.Mutex
	received []*gnmipb.SubscribeResponse
	gotCh    chan struct{}
}

func (c *testDialoutCollector) Publish(stream gnmireverse.GNMIReverse_PublishServer) error {
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&emptypb.Empty{})
		}
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.received = append(c.received, resp)
		c.mu.Unlock()
		select {
		case c.gotCh <- struct{}{}:
		default:
		}
	}
}

func (c *testDialoutCollector) snapshot() []*gnmipb.SubscribeResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*gnmipb.SubscribeResponse, len(c.received))
	copy(out, c.received)
	return out
}

// startTestDialoutCollector starts a gNMIReverse server on 127.0.0.1:0 (or
// a caller-supplied address for reconnect tests) and returns it plus its
// listen address and a stop func. Rebinding a just-freed explicit port can
// transiently fail under parallel test runs, so retry briefly.
func startTestDialoutCollector(t *testing.T, addr string) (*testDialoutCollector, string, func()) {
	t.Helper()
	var lis net.Listener
	var err error
	for i := 0; i < 20; i++ {
		lis, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	col := &testDialoutCollector{gotCh: make(chan struct{}, 64)}
	srv := grpc.NewServer()
	gnmireverse.RegisterGNMIReverseServer(srv, col)
	go func() { _ = srv.Serve(lis) }()
	return col, lis.Addr().String(), func() { srv.Stop() }
}

func newTestDialoutExporter(t *testing.T, device *DeviceSimulator, collector, mode string, pathStrs []string) *GnmiDialoutExporter {
	t.Helper()
	paths := make([]*gnmipb.Path, 0, len(pathStrs))
	for _, ps := range pathStrs {
		p, err := parseGnmiPath(ps)
		if err != nil {
			t.Fatalf("parseGnmiPath(%q): %v", ps, err)
		}
		paths = append(paths, p)
	}
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	return NewGnmiDialoutExporter(device, collector, "gnmireverse", gnmiReverseTransport{},
		gnmipb.Encoding_JSON_IETF, mode, paths, time.Second, dialOpts)
}

// waitForResponses blocks until the collector has at least n responses or
// the deadline expires.
func waitForResponses(t *testing.T, col *testDialoutCollector, n int, within time.Duration) []*gnmipb.SubscribeResponse {
	t.Helper()
	deadline := time.After(within)
	for {
		if got := col.snapshot(); len(got) >= n {
			return got
		}
		select {
		case <-col.gotCh:
		case <-deadline:
			t.Fatalf("timed out waiting for %d responses; got %d", n, len(col.snapshot()))
		}
	}
}

// updatesOf flattens all Notification.Update entries across responses.
func updatesOf(resps []*gnmipb.SubscribeResponse) []*gnmipb.Update {
	var out []*gnmipb.Update
	for _, r := range resps {
		if u := r.GetUpdate(); u != nil {
			out = append(out, u.GetUpdate()...)
		}
	}
	return out
}

// --- tests --------------------------------------------------------------

func TestParseGnmiPath(t *testing.T) {
	// Interface name containing '/' inside the key predicate must parse
	// (Cisco/Juniper names like GigabitEthernet0/1).
	if slashy, err := parseGnmiPath("/interfaces/interface[name=GigabitEthernet0/1]/state/counters/in-octets"); err != nil {
		t.Fatalf("parse name-with-slash: %v", err)
	} else if slashy.Elem[1].GetKey()["name"] != "GigabitEthernet0/1" {
		t.Fatalf("slash in name lost: %q", slashy.Elem[1].GetKey()["name"])
	}
	p, err := parseGnmiPath("/interfaces/interface[name=Eth1]/state/oper-status")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := len(p.GetElem()); got != 4 {
		t.Fatalf("want 4 elems, got %d", got)
	}
	if p.Elem[1].GetName() != "interface" || p.Elem[1].GetKey()["name"] != "Eth1" {
		t.Fatalf("bad interface elem: %+v", p.Elem[1])
	}
	if p.Elem[3].GetName() != "oper-status" {
		t.Fatalf("bad leaf: %s", p.Elem[3].GetName())
	}
	for _, bad := range []string{"", "interfaces/x", "/a//b", "/a[b]"} {
		if _, err := parseGnmiPath(bad); err == nil {
			t.Errorf("parseGnmiPath(%q) expected error", bad)
		}
	}
}

func TestDeviceGnmiDialoutConfigDefaultsAndValidate(t *testing.T) {
	c := &DeviceGnmiDialoutConfig{Collector: "127.0.0.1:9340"}
	c.ApplyDefaults()
	if c.Flavor != "gnmireverse" || c.Encoding != "json_ietf" || c.Mode != "sample" {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if time.Duration(c.SampleInterval) != 10*time.Second {
		t.Fatalf("sample interval default: %s", time.Duration(c.SampleInterval))
	}
	if c.TLS == nil || !c.TLS.Enabled {
		t.Fatalf("tls default should be enabled: %+v", c.TLS)
	}
	if len(c.Paths) == 0 {
		t.Fatalf("default path missing")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Rejections.
	bad := &DeviceGnmiDialoutConfig{Collector: "nope"}
	bad.ApplyDefaults()
	if err := bad.Validate(); err == nil {
		t.Error("expected invalid collector rejection")
	}
	badFlavor := &DeviceGnmiDialoutConfig{Collector: "127.0.0.1:1", Flavor: "sonic"}
	badFlavor.ApplyDefaults()
	badFlavor.Flavor = "sonic"
	if err := badFlavor.Validate(); err == nil {
		t.Error("expected invalid flavor rejection")
	}
	badMode := &DeviceGnmiDialoutConfig{Collector: "127.0.0.1:1", Mode: "poll"}
	badMode.ApplyDefaults()
	badMode.Mode = "poll"
	if err := badMode.Validate(); err == nil {
		t.Error("expected invalid mode rejection")
	}
}

func TestGnmiDialoutSampleStream(t *testing.T) {
	col, addr, stop := startTestDialoutCollector(t, "127.0.0.1:0")
	defer stop()

	device := newTestGnmiDevice(t, 2)
	e := newTestDialoutExporter(t, device, addr, "sample",
		[]string{"/interfaces/interface[name=*]/state/counters/in-octets"})
	e.Start()
	defer e.Close()

	resps := waitForResponses(t, col, 1, 5*time.Second)
	ups := updatesOf(resps)
	if len(ups) == 0 {
		t.Fatal("no updates received")
	}
	// Every update path should end at counters/in-octets.
	for _, u := range ups {
		elems := u.GetPath().GetElem()
		if len(elems) == 0 || elems[len(elems)-1].GetName() != "in-octets" {
			t.Fatalf("unexpected update path: %s", pathToString(u.GetPath()))
		}
	}
}

func TestGnmiDialoutSampleMatchesDialIn(t *testing.T) {
	col, addr, stop := startTestDialoutCollector(t, "127.0.0.1:0")
	defer stop()

	device := newTestGnmiDevice(t, 3)
	// Every deterministic state leaf: name/ifindex are static; oper-status/
	// admin-status are state-engine-backed and stable absent mutation.
	// Counters can't be compared this way — dial-out stamps its own
	// time.Now(), so counter values legitimately differ between reads.
	paths := []string{
		"/interfaces/interface[name=*]/state/name",
		"/interfaces/interface[name=*]/state/ifindex",
		"/interfaces/interface[name=*]/state/oper-status",
		"/interfaces/interface[name=*]/state/admin-status",
	}
	e := newTestDialoutExporter(t, device, addr, "sample", paths)
	e.Start()
	defer e.Close()

	resps := waitForResponses(t, col, 1, 5*time.Second)
	got := map[string]string{}
	for _, u := range updatesOf(resps) {
		got[pathToString(u.GetPath())] = string(u.GetVal().GetJsonIetfVal())
	}

	// Dial-in reference: resolve the same paths directly via a fresh resolver.
	resolver := newPathResolver(device)
	compared := 0
	for _, ps := range paths {
		p, err := parseGnmiPath(ps)
		if err != nil {
			t.Fatalf("parse %q: %v", ps, err)
		}
		updates, err := resolver.Resolve(p, time.Now())
		if err != nil {
			t.Fatalf("dial-in resolve %q: %v", ps, err)
		}
		gnmiUpdates, err := encodeUpdates(updates, gnmipb.Encoding_JSON_IETF)
		if err != nil {
			t.Fatalf("dial-in encode %q: %v", ps, err)
		}
		for _, u := range gnmiUpdates {
			key := pathToString(u.GetPath())
			want := string(u.GetVal().GetJsonIetfVal())
			if got[key] != want {
				t.Errorf("value mismatch for %s: dial-out=%q dial-in=%q", key, got[key], want)
			}
			compared++
		}
	}
	if compared == 0 {
		t.Fatal("dial-in produced no updates to compare")
	}
}

func TestGnmiDialoutReconnect(t *testing.T) {
	col, addr, stop := startTestDialoutCollector(t, "127.0.0.1:0")

	device := newTestGnmiDevice(t, 1)
	e := newTestDialoutExporter(t, device, addr, "sample",
		[]string{"/interfaces/interface[name=*]/state/oper-status"})
	e.Start()
	defer e.Close()

	waitForResponses(t, col, 1, 5*time.Second)

	// Bounce the collector: stop it, then restart on the SAME address.
	stop()
	time.Sleep(200 * time.Millisecond)
	col2, _, stop2 := startTestDialoutCollector(t, addr)
	defer stop2()

	// After reconnect the exporter should resume streaming, and the reconnect
	// counter (feeds /gnmi/dialout/status and the persisted aggregate) must
	// reflect the re-establishment: the increment happens when the first
	// established stream breaks, strictly before the redial that reached the
	// fresh server. Atomic read — the run loop may still be writing it.
	waitForResponses(t, col2, 1, 10*time.Second)
	if got := atomic.LoadUint64(&e.statReconnects); got == 0 {
		t.Error("statReconnects = 0 after an observed reconnection; want >= 1")
	}
}

func TestGnmiDialoutOnChange(t *testing.T) {
	col, addr, stop := startTestDialoutCollector(t, "127.0.0.1:0")
	defer stop()

	device := newTestGnmiDevice(t, 2)
	e := newTestDialoutExporter(t, device, addr, "on-change",
		[]string{"/interfaces/interface[name=*]/state/oper-status"})
	e.Start()
	defer e.Close()

	// Initial snapshot arrives first.
	waitForResponses(t, col, 1, 5*time.Second)
	baseline := len(col.snapshot())

	// Flip oper-status on ifIndex 1 → should push an ON_CHANGE update.
	// No settling sleep: produceOnChange registers the listener BEFORE the
	// initial snapshot, so once the snapshot has been received the listener
	// is guaranteed registered — a sleep here would mask an ordering
	// regression (the exact bug the register-first fix addressed).
	ic := device.metricsCycler.ifCounters.Load()
	if ic == nil || ic.State() == nil {
		t.Fatal("device has no state engine")
	}
	// Mutate then broadcast — mirrors the REST/flap caller contract
	// (SetOperStatus records the change; the caller fans it out).
	if changed, evt := ic.State().SetOperStatus(1, OperDown); changed {
		ic.State().Broadcast(evt)
	} else {
		t.Fatal("SetOperStatus(1, OperDown) reported no change")
	}

	deadline := time.After(5 * time.Second)
	for {
		if len(col.snapshot()) > baseline {
			break
		}
		select {
		case <-col.gotCh:
		case <-deadline:
			t.Fatal("no ON_CHANGE update after oper-status flip")
		}
	}
	// The latest update should carry oper-status DOWN.
	ups := updatesOf(col.snapshot())
	foundDown := false
	for _, u := range ups {
		elems := u.GetPath().GetElem()
		if len(elems) > 0 && elems[len(elems)-1].GetName() == "oper-status" {
			if string(u.GetVal().GetJsonIetfVal()) == `"openconfig-interfaces:DOWN"` {
				foundDown = true
			}
		}
	}
	if !foundDown {
		t.Error("did not observe oper-status DOWN in dial-out stream")
	}
}

// TestGnmiDialoutOnChangeSubtreePath is the regression guard for the
// default-path bug: on-change with the counter-inclusive default subtree
// `/interfaces/interface[name=*]/state` must still attach and emit on an
// oper-status transition (counters are filtered at emit, not rejected).
func TestGnmiDialoutOnChangeSubtreePath(t *testing.T) {
	col, addr, stop := startTestDialoutCollector(t, "127.0.0.1:0")
	defer stop()

	device := newTestGnmiDevice(t, 2)

	// The gate the manager applies: a subtree path must cover at least one
	// state leaf (so it is NOT rejected for on-change).
	resolver := newPathResolver(device)
	p, _ := parseGnmiPath("/interfaces/interface[name=*]/state")
	leaves, err := resolver.ClassifyLeaves(p)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	hasState := false
	for _, l := range leaves {
		if isStateOnlyLeaf(l) {
			hasState = true
		}
	}
	if !hasState {
		t.Fatal("default subtree path covers no state leaf — on-change gate would reject it")
	}

	e := newTestDialoutExporter(t, device, addr, "on-change",
		[]string{"/interfaces/interface[name=*]/state"})
	e.Start()
	defer e.Close()

	waitForResponses(t, col, 1, 5*time.Second)
	baseline := len(col.snapshot())

	// Listener registration precedes the snapshot, so no settling sleep
	// (see TestGnmiDialoutOnChange).
	ic := device.metricsCycler.ifCounters.Load()
	if ic == nil || ic.State() == nil {
		t.Fatal("device has no state engine")
	}
	if changed, evt := ic.State().SetOperStatus(1, OperDown); changed {
		ic.State().Broadcast(evt)
	} else {
		t.Fatal("SetOperStatus reported no change")
	}

	deadline := time.After(5 * time.Second)
	for len(col.snapshot()) <= baseline {
		select {
		case <-col.gotCh:
		case <-deadline:
			t.Fatal("no on-change update for subtree path after oper flip")
		}
	}
	foundDown := false
	for _, u := range updatesOf(col.snapshot()) {
		el := u.GetPath().GetElem()
		if len(el) > 0 && el[len(el)-1].GetName() == "oper-status" &&
			string(u.GetVal().GetJsonIetfVal()) == `"openconfig-interfaces:DOWN"` {
			foundDown = true
		}
	}
	if !foundDown {
		t.Error("subtree on-change did not emit oper-status DOWN")
	}
}

func TestGnmiDialoutStatusAggregatePersist(t *testing.T) {
	sm := &SimulatorManager{}
	e := &GnmiDialoutExporter{collectorStr: "10.0.0.1:9340", flavor: "gnmireverse"}
	e.statUpdatesSent = 42
	e.statReconnects = 3
	sm.persistGnmiDialoutCounters(e)
	// Second call must be a no-op (sync.Once) — no double count.
	sm.persistGnmiDialoutCounters(e)

	st := sm.GetGnmiDialoutStatus()
	if len(st.Collectors) != 1 {
		t.Fatalf("want 1 collector, got %d", len(st.Collectors))
	}
	c := st.Collectors[0]
	if c.UpdatesSent != 42 || c.Reconnects != 3 {
		t.Fatalf("aggregate mismatch: %+v", c)
	}
}

// ensure the transport type satisfies the interface at compile time.
var _ DialoutTransport = gnmiReverseTransport{}
