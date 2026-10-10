/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"strings"
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
	found := false
	for _, m := range caps.GetSupportedModels() {
		if m.GetName() == "openconfig-interfaces" && m.GetVersion() == "3.11.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("catalogue model missing: %v", caps.GetSupportedModels())
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
