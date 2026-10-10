/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// startTestCatalogServer is startTestGnmiServer with the minimal
// catalogue attached to the device's type before the listener starts.
func startTestCatalogServer(t *testing.T) (dev *DeviceSimulator, addr string, cleanup func()) {
	t.Helper()
	cat, err := parseGnmiCatalog(readTestCatalog(t), "min")
	if err != nil {
		t.Fatal(err)
	}
	_, dev, addr, cleanup = startTestGnmiServerWithCatalog(t, cat)
	return dev, addr, cleanup
}

func subscribeOnce(t *testing.T, addr string, enc gnmipb.Encoding, path string) ([]*gnmipb.SubscribeResponse, error) {
	t.Helper()
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := gnmipb.NewGNMIClient(conn).Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = stream.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
		Mode: gnmipb.SubscriptionList_ONCE, Encoding: enc,
		Subscription: []*gnmipb.Subscription{{Path: pathFromString(t, path)}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var out []*gnmipb.SubscribeResponse
	for {
		resp, err := stream.Recv()
		if err != nil {
			return out, err
		}
		out = append(out, resp)
		if resp.GetSyncResponse() {
			return out, nil
		}
	}
}

func TestCatalogServer_OncePerEntryWithPrefix(t *testing.T) {
	_, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	resps, err := subscribeOnce(t, addr, gnmipb.Encoding_PROTO, "/interfaces/interface/state/counters")
	if err != nil {
		t.Fatal(err)
	}
	updates := 0
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		updates++
		if n.GetPrefix().GetOrigin() != "openconfig" || !strings.HasPrefix(pathToString(n.GetPrefix()), "/interfaces/interface[name=") {
			t.Errorf("prefix = %v", n.GetPrefix())
		}
		if len(n.GetUpdate()) != 1 || n.GetUpdate()[0].GetVal().GetUintVal() == 0 && n.GetUpdate()[0].GetVal().GetValue() == nil {
			t.Errorf("updates = %v", n.GetUpdate())
		}
	}
	if updates == 0 {
		t.Fatal("no update notifications before sync")
	}
	if !resps[len(resps)-1].GetSyncResponse() {
		t.Fatal("missing sync_response")
	}
}

func TestCatalogServer_LegacyPathStillServedWhenCatalogueDoesNotCover(t *testing.T) {
	_, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	// in-errors is not in the minimal catalogue; the legacy resolver owns it.
	resps, err := subscribeOnce(t, addr, gnmipb.Encoding_PROTO, "/interfaces/interface/state/counters/in-errors")
	if err != nil {
		t.Fatal(err)
	}
	if resps[0].GetUpdate().GetPrefix() != nil {
		t.Fatalf("legacy notification must keep a nil prefix: %v", resps[0])
	}
}

func TestCatalogServer_CataloguePreemptsLegacyForCoveredLeaf(t *testing.T) {
	_, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	// oper-status is served by both; the catalogue wins (Review Focus 1).
	resps, err := subscribeOnce(t, addr, gnmipb.Encoding_PROTO, "/interfaces/interface[name=TestIf1]/state/oper-status")
	if err != nil {
		t.Fatal(err)
	}
	if resps[0].GetUpdate().GetPrefix() == nil {
		t.Fatal("expected catalogue prefix form")
	}
}

func TestCatalogServer_EncodingGateAndJsonVal(t *testing.T) {
	_, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	_, err := subscribeOnce(t, addr, gnmipb.Encoding_JSON_IETF, "/interfaces")
	if status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "Only PROTO/JSON encoding supported") {
		t.Fatalf("JSON_IETF: %v", err)
	}
	// The gate is device-wide: a legacy-only path is refused too.
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = gnmipb.NewGNMIClient(conn).Get(ctx, &gnmipb.GetRequest{Encoding: gnmipb.Encoding_JSON_IETF, Path: []*gnmipb.Path{pathFromString(t, "/interfaces/interface/state/counters/in-errors")}})
	if status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "Encoding 4 not supported, Only PROTO/JSON encoding supported") {
		t.Fatalf("JSON_IETF Get on legacy path: %v", err)
	}
	resps, err := subscribeOnce(t, addr, gnmipb.Encoding_JSON, "/components/component/state/serial-no")
	if err != nil {
		t.Fatal(err)
	}
	if v := resps[0].GetUpdate().GetUpdate()[0].GetVal(); v.GetJsonVal() == nil || string(v.GetJsonVal()) != `"SN000001"` {
		t.Fatalf("JSON must be json_val: %v", v)
	}
}

func TestCatalogServer_OnChangeRefused(t *testing.T) {
	_, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := gnmipb.NewGNMIClient(conn).Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
		Mode: gnmipb.SubscriptionList_STREAM, Encoding: gnmipb.Encoding_PROTO,
		Subscription: []*gnmipb.Subscription{{Path: pathFromString(t, "/components"), Mode: gnmipb.SubscriptionMode_ON_CHANGE}},
	}}})
	_, err = stream.Recv()
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("ON_CHANGE on catalogue path: %v", err)
	}
}

func TestCatalogServer_GetAndCapabilities(t *testing.T) {
	_, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	c := gnmipb.NewGNMIClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	caps, err := c.Capabilities(ctx, &gnmipb.CapabilityRequest{})
	if err != nil {
		t.Fatal(err)
	}
	encs := map[gnmipb.Encoding]bool{}
	for _, e := range caps.GetSupportedEncodings() {
		encs[e] = true
	}
	if !encs[gnmipb.Encoding_PROTO] || !encs[gnmipb.Encoding_JSON] || encs[gnmipb.Encoding_JSON_IETF] {
		t.Fatalf("encodings = %v", caps.GetSupportedEncodings())
	}
	var ifModels []string
	for _, m := range caps.GetSupportedModels() {
		if m.GetName() == "openconfig-interfaces" {
			ifModels = append(ifModels, m.GetVersion())
		}
	}
	if len(ifModels) != 1 || ifModels[0] != "3.11.1" {
		t.Fatalf("openconfig-interfaces must appear once as 3.11.1: %v", caps.GetSupportedModels())
	}
	resp, err := c.Get(ctx, &gnmipb.GetRequest{Encoding: gnmipb.Encoding_PROTO, Path: []*gnmipb.Path{pathFromString(t, "/components/component[name=FPC0]/state/temperature")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetNotification()) != 1 || pathToString(resp.GetNotification()[0].GetPrefix()) != "/components/component[name=FPC0]/state/temperature" {
		t.Fatalf("get = %v", resp)
	}
	// The relative leaf `instant` has no config/state element; a STATE
	// Get must still return it.
	resp, err = c.Get(ctx, &gnmipb.GetRequest{Type: gnmipb.GetRequest_STATE, Encoding: gnmipb.Encoding_PROTO, Path: []*gnmipb.Path{pathFromString(t, "/components/component[name=FPC0]/state/temperature")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetNotification()) != 1 {
		t.Fatalf("STATE get = %v", resp)
	}
}

func TestCatalogServer_StreamSampleTicks(t *testing.T) {
	_, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	stream, err := gnmipb.NewGNMIClient(conn).Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
		Mode: gnmipb.SubscriptionList_STREAM, Encoding: gnmipb.Encoding_PROTO,
		Subscription: []*gnmipb.Subscription{{Path: pathFromString(t, "/components/component/state/temperature"), Mode: gnmipb.SubscriptionMode_SAMPLE, SampleInterval: uint64(time.Second)}},
	}}})
	got := 0
	for got < 2 {
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("after %d updates: %v", got, err)
		}
		if resp.GetUpdate() != nil {
			got++
		}
	}
}

func TestCatalogServer_JuniperHeaderExtension(t *testing.T) {
	data := bytes.Replace(readTestCatalog(t), []byte(`"extension": "none"`), []byte(`"extension": "juniper-header"`), 1)
	cat, err := parseGnmiCatalog(data, "min-juniper")
	if err != nil {
		t.Fatal(err)
	}
	if cat.Notification.Extension != gnmiExtensionJuniperHeader {
		t.Fatal("fixture rewrite did not enable the juniper header")
	}
	_, dev, addr, cleanup := startTestGnmiServerWithCatalog(t, cat)
	defer cleanup()
	dev.cachedSysName.Store("vjunos-test")

	const path = "/interfaces/interface/state/counters"
	for stream := 0; stream < 2; stream++ {
		resps, err := subscribeOnce(t, addr, gnmipb.Encoding_PROTO, path)
		if err != nil {
			t.Fatal(err)
		}
		var lastSeq uint64
		sensor := ""
		for _, r := range resps {
			if r.GetUpdate() == nil {
				continue
			}
			if len(r.GetExtension()) != 1 {
				t.Fatalf("stream %d: extensions = %v", stream, r.GetExtension())
			}
			h, err := decodeJuniperHeader(r.GetExtension()[0].GetRegisteredExt().GetMsg())
			if err != nil {
				t.Fatal(err)
			}
			if h.SystemID != "vjunos-test" || h.ComponentID != 65535 || h.SubscribedPath != path || h.Component != "xmlproxyd_TM_Thread_1" {
				t.Errorf("stream %d: header = %+v", stream, h)
			}
			if lastSeq == 0 && h.SequenceNumber != 1 {
				t.Errorf("stream %d: first sequence = %d, want 1", stream, h.SequenceNumber)
			}
			if h.SequenceNumber <= lastSeq {
				t.Errorf("stream %d: sequence %d after %d", stream, h.SequenceNumber, lastSeq)
			}
			lastSeq = h.SequenceNumber
			if sensor == "" {
				sensor = h.SensorName
			}
			if h.SensorName != sensor {
				t.Errorf("stream %d: sensor %q changed to %q", stream, sensor, h.SensorName)
			}
		}
		if lastSeq < 2 {
			t.Fatalf("stream %d: want at least two update responses, got %d", stream, lastSeq)
		}
	}
}

func TestCatalogServer_MixedOnceOrdering(t *testing.T) {
	_, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := gnmipb.NewGNMIClient(conn).Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Legacy path listed first: the combined legacy notification still
	// follows every catalogue per-entry response.
	err = stream.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
		Mode: gnmipb.SubscriptionList_ONCE, Encoding: gnmipb.Encoding_PROTO,
		Subscription: []*gnmipb.Subscription{
			{Path: pathFromString(t, "/interfaces/interface/state/counters/in-errors")},
			{Path: pathFromString(t, "/components/component/state/serial-no")},
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var resps []*gnmipb.SubscribeResponse
	for {
		r, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		resps = append(resps, r)
		if r.GetSyncResponse() {
			break
		}
	}
	// Two components in the fixture, one legacy notification, one sync.
	if len(resps) != 4 {
		t.Fatalf("got %d responses, want 4: %v", len(resps), resps)
	}
	for i, r := range resps[:2] {
		if r.GetUpdate().GetPrefix() == nil {
			t.Errorf("response %d: want catalogue prefix: %v", i, r)
		}
	}
	if n := resps[2].GetUpdate(); n == nil || n.GetPrefix() != nil || len(n.GetUpdate()) == 0 {
		t.Errorf("response 2: want one combined legacy notification with nil prefix: %v", resps[2])
	}
	if !resps[3].GetSyncResponse() {
		t.Errorf("response 3: want sync_response: %v", resps[3])
	}
}

// TestCatalogServer_StreamDeliversWholeTicks: a STREAM subscription
// whose tick spans far more list entries than the send queue depth
// still delivers every entry. The snapshot is complete before
// sync_response, nothing is dropped across two further ticks, and the
// Juniper header sequence numbers have no gaps.
func TestCatalogServer_StreamDeliversWholeTicks(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	cat := cats["juniper_mx10004"]
	mgr, dev, addr, cleanup := startTestGnmiServerWithCatalogN(t, cat, 50)
	defer cleanup()

	const path = "/interfaces"
	snap, err := newCatalogResolver(dev, cat).Resolve(pathFromString(t, path), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	perTick := len(snap)
	if perTick <= subscribeBufferDepth {
		t.Fatalf("%d entries per tick does not exceed the queue depth %d", perTick, subscribeBufferDepth)
	}

	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := gnmipb.NewGNMIClient(conn).Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
		Mode: gnmipb.SubscriptionList_STREAM, Encoding: gnmipb.Encoding_PROTO,
		Subscription: []*gnmipb.Subscription{{Path: pathFromString(t, path), Mode: gnmipb.SubscriptionMode_SAMPLE, SampleInterval: uint64(time.Second)}},
	}}}); err != nil {
		t.Fatal(err)
	}
	var lastSeq uint64
	beforeSync, updates := 0, 0
	synced := false
	for updates < 3*perTick {
		r, err := stream.Recv()
		if err != nil {
			t.Fatalf("after %d updates: %v", updates, err)
		}
		if r.GetSyncResponse() {
			synced = true
			beforeSync = updates
			continue
		}
		updates++
		h, err := decodeJuniperHeader(r.GetExtension()[0].GetRegisteredExt().GetMsg())
		if err != nil {
			t.Fatal(err)
		}
		if h.SequenceNumber != lastSeq+1 {
			t.Fatalf("sequence %d after %d", h.SequenceNumber, lastSeq)
		}
		lastSeq = h.SequenceNumber
	}
	if !synced || beforeSync != perTick {
		t.Fatalf("snapshot before sync_response: %d entries, want %d (synced=%v)", beforeSync, perTick, synced)
	}
	if d := atomic.LoadUint64(&mgr.gnmiUpdatesDropped); d != 0 {
		t.Fatalf("dropped %d responses", d)
	}
}
