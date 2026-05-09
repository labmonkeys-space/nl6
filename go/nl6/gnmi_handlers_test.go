/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeSubscribeStream is a minimal gnmipb.GNMI_SubscribeServer
// implementation. The subscribe goroutines write to it; tests read from
// `sent`. recvQueue feeds Recv(); ctx is the stream context.
type fakeSubscribeStream struct {
	ctx       context.Context
	recvQueue chan *gnmipb.SubscribeRequest
	sent      chan *gnmipb.SubscribeResponse
	sendErr   atomic.Value // optional error to return from Send
	closeOnce atomic.Bool
}

func newFakeSubscribeStream(ctx context.Context) *fakeSubscribeStream {
	return &fakeSubscribeStream{
		ctx:       ctx,
		recvQueue: make(chan *gnmipb.SubscribeRequest, 4),
		sent:      make(chan *gnmipb.SubscribeResponse, 256),
	}
}

func (f *fakeSubscribeStream) Send(resp *gnmipb.SubscribeResponse) error {
	if v := f.sendErr.Load(); v != nil {
		return v.(error)
	}
	select {
	case f.sent <- resp:
		return nil
	case <-f.ctx.Done():
		return f.ctx.Err()
	}
}

func (f *fakeSubscribeStream) Recv() (*gnmipb.SubscribeRequest, error) {
	select {
	case req := <-f.recvQueue:
		if req == nil {
			return nil, context.Canceled
		}
		return req, nil
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	}
}

func (f *fakeSubscribeStream) Context() context.Context           { return f.ctx }
func (f *fakeSubscribeStream) SetHeader(metadata.MD) error        { return nil }
func (f *fakeSubscribeStream) SendHeader(metadata.MD) error       { return nil }
func (f *fakeSubscribeStream) SetTrailer(metadata.MD)             {}
func (f *fakeSubscribeStream) SendMsg(m interface{}) error        { return nil }
func (f *fakeSubscribeStream) RecvMsg(m interface{}) error        { return nil }

// newTestGnmiServer wires a server backed by a minimal device. Counter
// pointers are returned so tests can assert on them.
func newTestGnmiServer(t *testing.T, ifCount int) (*gnmiServer, *int64, *uint64, *uint64) {
	t.Helper()
	resolver := newTestPathResolver(t, ifCount)
	var active int64
	var sent, dropped uint64
	srv := newGnmiServer(resolver.device, &active, &sent, &dropped)
	srv.resolver = resolver
	return srv, &active, &sent, &dropped
}

func TestGnmiServer_Capabilities(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	resp, err := srv.Capabilities(context.Background(), &gnmipb.CapabilityRequest{})
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if resp.GetGNMIVersion() != gnmiVersion {
		t.Errorf("gNMI version: got %q, want %q", resp.GetGNMIVersion(), gnmiVersion)
	}
}

func TestGnmiServer_Get_KnownPath(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	resp, err := srv.Get(context.Background(), &gnmipb.GetRequest{
		Path: []*gnmipb.Path{pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets")},
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(resp.GetNotification()) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(resp.GetNotification()))
	}
	updates := resp.GetNotification()[0].GetUpdate()
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	// JSON_IETF (default) wraps uint64 as JSON string.
	if updates[0].GetVal().GetJsonIetfVal() == nil {
		t.Errorf("expected json_ietf_val for JSON_IETF default, got %T", updates[0].GetVal().GetValue())
	}
}

// DF2: GetRequest.Type=CONFIG returns an empty response — the
// simulator exposes only the state subtree, no config tree.
func TestGnmiServer_Get_TypeConfigReturnsEmpty(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	resp, err := srv.Get(context.Background(), &gnmipb.GetRequest{
		Type: gnmipb.GetRequest_CONFIG,
		Path: []*gnmipb.Path{pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets")},
	})
	if err != nil {
		t.Fatalf("Get with Type=CONFIG: %v", err)
	}
	if len(resp.GetNotification()) != 0 {
		t.Errorf("expected 0 notifications for Type=CONFIG, got %d", len(resp.GetNotification()))
	}
}

// DF2: STATE/OPERATIONAL/ALL each resolve the state subtree (the
// simulator does not distinguish them internally).
func TestGnmiServer_Get_StateOperationalAllResolveData(t *testing.T) {
	for _, typ := range []gnmipb.GetRequest_DataType{
		gnmipb.GetRequest_STATE,
		gnmipb.GetRequest_OPERATIONAL,
		gnmipb.GetRequest_ALL,
	} {
		srv, _, _, _ := newTestGnmiServer(t, 1)
		resp, err := srv.Get(context.Background(), &gnmipb.GetRequest{
			Type: typ,
			Path: []*gnmipb.Path{pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets")},
		})
		if err != nil {
			t.Errorf("Type=%v: %v", typ, err)
			continue
		}
		if len(resp.GetNotification()) != 1 {
			t.Errorf("Type=%v: expected 1 notification, got %d", typ, len(resp.GetNotification()))
		}
	}
}

func TestGnmiServer_Get_UnknownPath(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	_, err := srv.Get(context.Background(), &gnmipb.GetRequest{
		Path: []*gnmipb.Path{pathFromString(t, "/system/state/hostname")},
	})
	if err == nil {
		t.Fatal("expected NotFound error, got nil")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", status.Code(err))
	}
}

func TestGnmiServer_Get_PROTOEncoding(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	resp, err := srv.Get(context.Background(), &gnmipb.GetRequest{
		Path:     []*gnmipb.Path{pathFromString(t, "/interfaces/interface[name=TestIf1]/state/ifindex")},
		Encoding: gnmipb.Encoding_PROTO,
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	tv := resp.GetNotification()[0].GetUpdate()[0].GetVal()
	if tv.GetUintVal() != 1 {
		t.Errorf("expected uint_val=1, got %v (oneof %T)", tv.GetUintVal(), tv.GetValue())
	}
}

func TestGnmiServer_Get_UnsupportedEncoding(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	_, err := srv.Get(context.Background(), &gnmipb.GetRequest{
		Path:     []*gnmipb.Path{pathFromString(t, "/interfaces/interface[name=TestIf1]/state/ifindex")},
		Encoding: gnmipb.Encoding_BYTES,
	})
	if err == nil {
		t.Fatal("expected InvalidArgument, got nil")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestGnmiServer_Set_Unimplemented(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	_, err := srv.Set(context.Background(), &gnmipb.SetRequest{})
	if err == nil {
		t.Fatal("expected Unimplemented, got nil")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", status.Code(err))
	}
}

func TestGnmiServer_Subscribe_OnChangeRejected(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{{
					Path: pathFromString(t, "/interfaces/interface[name=*]/state/counters/in-octets"),
					Mode: gnmipb.SubscriptionMode_ON_CHANGE,
				}},
			},
		},
	}
	err := srv.Subscribe(stream)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v: %v", status.Code(err), err)
	}
}

func TestGnmiServer_Subscribe_PollRejected_ListMode(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_POLL,
				Subscription: []*gnmipb.Subscription{{
					Path: pathFromString(t, "/interfaces/interface[name=*]/state/counters/in-octets"),
				}},
			},
		},
	}
	err := srv.Subscribe(stream)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", status.Code(err))
	}
}

func TestGnmiServer_Subscribe_PollRejected_OneofPoll(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Poll{Poll: &gnmipb.Poll{}},
	}
	err := srv.Subscribe(stream)
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", status.Code(err))
	}
}

func TestClampSampleInterval_Clamp(t *testing.T) {
	if got := clampSampleInterval(100 * time.Millisecond); got != minSampleInterval {
		t.Errorf("100ms clamp: got %v, want %v", got, minSampleInterval)
	}
}

func TestClampSampleInterval_Honoured(t *testing.T) {
	if got := clampSampleInterval(10 * time.Second); got != 10*time.Second {
		t.Errorf("10s honor: got %v, want 10s", got)
	}
}

func TestClampSampleInterval_ZeroFallsToMin(t *testing.T) {
	if got := clampSampleInterval(0); got != minSampleInterval {
		t.Errorf("unset interval: got %v, want %v", got, minSampleInterval)
	}
}
