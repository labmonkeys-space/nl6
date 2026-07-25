/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"math"
	"net"
	"strings"
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

func (f *fakeSubscribeStream) Context() context.Context     { return f.ctx }
func (f *fakeSubscribeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeSubscribeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeSubscribeStream) SetTrailer(metadata.MD)       {}
func (f *fakeSubscribeStream) SendMsg(m interface{}) error  { return nil }
func (f *fakeSubscribeStream) RecvMsg(m interface{}) error  { return nil }

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

// TestGnmiServer_Subscribe_OnChange_CounterPathRejected — post
// add-interface-state §D5, ON_CHANGE is supported on static-leaf paths
// but rejected when any path touches a counter leaf. The error names
// the offending leaf and recommends SAMPLE.
func TestGnmiServer_Subscribe_OnChange_CounterPathRejected(t *testing.T) {
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
	if !strings.Contains(err.Error(), "in-octets") {
		t.Errorf("error should name the offending leaf 'in-octets'; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "SAMPLE") {
		t.Errorf("error should recommend SAMPLE; got %q", err.Error())
	}
}

// TestGnmiServer_Subscribe_OnChange_StaticPathAccepted — ON_CHANGE on
// a static-leaf path (oper-status) succeeds: initial batch + sync_response.
func TestGnmiServer_Subscribe_OnChange_StaticPathAccepted(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{{
					Path: pathFromString(t, "/interfaces/interface[name=*]/state/oper-status"),
					Mode: gnmipb.SubscriptionMode_ON_CHANGE,
				}},
			},
		},
	}

	done := make(chan error, 1)
	go func() { done <- srv.Subscribe(stream) }()

	// Initial batch (1 Notification with 2 updates, one per ifIndex).
	resp := drainOne(t, stream, 2*time.Second)
	if resp.GetUpdate() == nil {
		t.Fatalf("first response should be Update, got %T", resp.GetResponse())
	}
	if got := len(resp.GetUpdate().GetUpdate()); got != 2 {
		t.Errorf("initial batch: got %d updates, want 2 (one per ifIndex)", got)
	}
	// sync_response after the initial batch.
	sync := drainOne(t, stream, 2*time.Second)
	if !sync.GetSyncResponse() {
		t.Errorf("second response should be sync_response, got %T", sync.GetResponse())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe goroutine did not exit on cancel")
	}
}

// TestGnmiServer_Subscribe_OnChange_DeliversOnStateChange — after the
// initial batch, a mutation through InterfaceState produces one
// matching SubscribeResponse{update}.
func TestGnmiServer_Subscribe_OnChange_DeliversOnStateChange(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{{
					Path: pathFromString(t, "/interfaces/interface[name=*]/state/oper-status"),
					Mode: gnmipb.SubscriptionMode_ON_CHANGE,
				}},
			},
		},
	}

	done := make(chan error, 1)
	go func() { done <- srv.Subscribe(stream) }()

	// Drain initial batch + sync. By the time sync_response arrives,
	// the handler has already called AddListener (since AddListener
	// happens BEFORE the initial snapshot per the H2 patch). No sleep
	// needed — the sync barrier IS the handshake.
	drainOne(t, stream, 2*time.Second)
	drainOne(t, stream, 2*time.Second)

	state := srv.device.metricsCycler.ifCounters.Load().State()
	changed, evt := state.SetOperStatus(2, OperDown)
	if !changed {
		t.Fatal("SetOperStatus failed")
	}
	state.Broadcast(evt)

	// Expect one Update response carrying oper-status DOWN for ifIndex 2.
	resp := drainOne(t, stream, 2*time.Second)
	if resp.GetUpdate() == nil {
		t.Fatalf("post-mutation response should be Update, got %T", resp.GetResponse())
	}
	updates := resp.GetUpdate().GetUpdate()
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe did not exit on cancel")
	}
}

// TestGnmiServer_Subscribe_OnChange_HeartbeatResendsCurrentValue —
// heartbeat_interval=1s causes the sub to re-emit even without state
// changes. Verify ≥1 heartbeat within ~2.5s of no real changes.
func TestGnmiServer_Subscribe_OnChange_HeartbeatResendsCurrentValue(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{{
					Path:              pathFromString(t, "/interfaces/interface[name=*]/state/oper-status"),
					Mode:              gnmipb.SubscriptionMode_ON_CHANGE,
					HeartbeatInterval: uint64(time.Second),
				}},
			},
		},
	}

	done := make(chan error, 1)
	go func() { done <- srv.Subscribe(stream) }()

	// Drain initial batch + sync.
	drainOne(t, stream, 2*time.Second)
	drainOne(t, stream, 2*time.Second)

	// Within 3.5s we should observe at least one heartbeat emission
	// (the ticker fires at 1s, 2s, 3s). 3.5s gives slack for slow CI
	// runners; 2.5s was timing-fragile under load.
	heartbeat := drainOne(t, stream, 3500*time.Millisecond)
	if heartbeat.GetUpdate() == nil {
		t.Fatalf("expected heartbeat Update response, got %T", heartbeat.GetResponse())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe did not exit on cancel")
	}
}

// TestGnmiServer_Subscribe_OnChange_MixedModeRejected — a request that
// mixes ON_CHANGE and SAMPLE subscriptions is rejected with
// InvalidArgument; the message instructs splitting into two requests.
func TestGnmiServer_Subscribe_OnChange_MixedModeRejected(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{
					{
						Path: pathFromString(t, "/interfaces/interface[name=*]/state/oper-status"),
						Mode: gnmipb.SubscriptionMode_ON_CHANGE,
					},
					{
						Path:           pathFromString(t, "/interfaces/interface[name=*]/state/counters/in-octets"),
						Mode:           gnmipb.SubscriptionMode_SAMPLE,
						SampleInterval: uint64(time.Second),
					},
				},
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
	if !strings.Contains(err.Error(), "split") {
		t.Errorf("error should instruct splitting; got %q", err.Error())
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

// TestGnmiServer_Subscribe_OnChange_MultiStaticLeavesAccepted covers the
// spec scenario "ON_CHANGE accepted on the state subtree's static-only
// sibling": a request with multiple static leaves (oper-status,
// admin-status, last-change) explicitly. The handler must accept and
// emit each sub's initial-snapshot Notification in order.
func TestGnmiServer_Subscribe_OnChange_MultiStaticLeavesAccepted(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{
					{Path: pathFromString(t, "/interfaces/interface[name=TestIf1]/state/oper-status"), Mode: gnmipb.SubscriptionMode_ON_CHANGE},
					{Path: pathFromString(t, "/interfaces/interface[name=TestIf1]/state/admin-status"), Mode: gnmipb.SubscriptionMode_ON_CHANGE},
					{Path: pathFromString(t, "/interfaces/interface[name=TestIf1]/state/last-change"), Mode: gnmipb.SubscriptionMode_ON_CHANGE},
				},
			},
		},
	}
	done := make(chan error, 1)
	go func() { done <- srv.Subscribe(stream) }()

	// Three subs → three initial-snapshot Notifications + sync_response.
	for i := 0; i < 3; i++ {
		resp := drainOne(t, stream, 2*time.Second)
		if resp.GetUpdate() == nil {
			t.Fatalf("response %d should be Update, got %T", i, resp.GetResponse())
		}
	}
	sync := drainOne(t, stream, 2*time.Second)
	if !sync.GetSyncResponse() {
		t.Errorf("expected sync_response after 3 Notifications, got %T", sync.GetResponse())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe goroutine did not exit on cancel")
	}
}

// TestGnmiServer_Subscribe_OnChange_SynthIfNameDelivers covers the H1
// patch: a device whose IfCounterCycler has known ifIndexes but no
// `ifDescr.<N>` JSON entries must still deliver ON_CHANGE events
// (the resolver synthesises `GigabitEthernet0/<N>` as the name and
// the reverse-lookup map needs to know that synth name).
//
// Without the H1 patch, descrToIndex misses the synth name → events
// silently dropped past the initial snapshot.
func TestGnmiServer_Subscribe_OnChange_SynthIfNameDelivers(t *testing.T) {
	// Build a resolver fixture with NO ifDescr entries (synth-name path).
	res := buildTestResources(t, []uint64{1_000_000_000})
	// Deliberately do NOT add `.1.3.6.1.2.1.2.2.1.2.<N>` (ifDescr) entries.
	mc := &MetricsCycler{}
	mc.InitIfCounters(res, 1)
	device := &DeviceSimulator{
		ID:            "test-synth",
		IP:            net.IPv4(10, 42, 0, 99),
		resources:     res,
		metricsCycler: mc,
	}
	var active int64
	var sent, dropped uint64
	srv := newGnmiServer(device, &active, &sent, &dropped)
	srv.resolver = newPathResolver(device)

	// Verify synth name is in descrToIndex.
	synth := synthIfName(1)
	if _, ok := srv.resolver.descrToIndex[synth]; !ok {
		t.Fatalf("descrToIndex missing synth name %q", synth)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{{
					Path: pathFromString(t, "/interfaces/interface[name=*]/state/oper-status"),
					Mode: gnmipb.SubscriptionMode_ON_CHANGE,
				}},
			},
		},
	}
	done := make(chan error, 1)
	go func() { done <- srv.Subscribe(stream) }()

	// Drain initial batch + sync.
	drainOne(t, stream, 2*time.Second)
	drainOne(t, stream, 2*time.Second)

	state := mc.ifCounters.Load().State()
	changed, evt := state.SetOperStatus(1, OperDown)
	if !changed {
		t.Fatal("SetOperStatus failed")
	}
	state.Broadcast(evt)

	// Without the H1 patch this drain times out.
	resp := drainOne(t, stream, 2*time.Second)
	if resp.GetUpdate() == nil {
		t.Fatal("expected Update with synth-name path, got nothing")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe goroutine did not exit on cancel")
	}
}

// TestGnmiEncodeTypedValueAllTypes covers every value type the resolver
// can produce against both advertised encodings. The decimal case is the
// reason this is exhaustive: handing the encoder a pre-formatted Go
// string would silently take the string_val branch under PROTO and
// quietly corrupt an advertised encoding, so each type is checked in both.
func TestGnmiEncodeTypedValueAllTypes(t *testing.T) {
	cases := []struct {
		name     string
		val      interface{}
		wantJSON string // the json_ietf_val bytes
		checkPB  func(*testing.T, *gnmipb.TypedValue)
	}{{
		name:     "string",
		val:      "GigabitEthernet0/1",
		wantJSON: `"GigabitEthernet0/1"`,
		checkPB: func(t *testing.T, tv *gnmipb.TypedValue) {
			if tv.GetStringVal() != "GigabitEthernet0/1" {
				t.Errorf("PROTO string_val = %q", tv.GetStringVal())
			}
		},
	}, {
		name:     "uint32 is a JSON number",
		val:      uint32(7),
		wantJSON: `7`,
		checkPB: func(t *testing.T, tv *gnmipb.TypedValue) {
			if tv.GetUintVal() != 7 {
				t.Errorf("PROTO uint_val = %d", tv.GetUintVal())
			}
		},
	}, {
		name:     "uint64 is an RFC 7951 string",
		val:      uint64(18446744073709551615),
		wantJSON: `"18446744073709551615"`,
		checkPB: func(t *testing.T, tv *gnmipb.TypedValue) {
			if tv.GetUintVal() != 18446744073709551615 {
				t.Errorf("PROTO uint_val = %d", tv.GetUintVal())
			}
		},
	}, {
		name:     "decimal is an RFC 7951 string, not a number",
		val:      gnmiDecimal{val: -8.5, digits: 2},
		wantJSON: `"-8.50"`,
		checkPB: func(t *testing.T, tv *gnmipb.TypedValue) {
			if tv.GetDoubleVal() != -8.5 {
				t.Errorf("PROTO double_val = %v, want -8.5", tv.GetDoubleVal())
			}
			if tv.GetStringVal() != "" {
				t.Error("decimal took the string_val branch under PROTO; that is a type error for clients")
			}
		},
	}, {
		name:     "high-precision decimal keeps its digits under JSON_IETF",
		val:      gnmiDecimal{val: 0.0000980812, digits: 18},
		wantJSON: `"0.000098081200000000"`,
		checkPB: func(t *testing.T, tv *gnmipb.TypedValue) {
			// double_val is inherently lossy at 18 fraction digits; assert it
			// is at least the right magnitude so a mis-wired branch is caught.
			if got := tv.GetDoubleVal(); math.Abs(got-0.0000980812) > 1e-12 {
				t.Errorf("PROTO double_val = %v", got)
			}
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tv, err := gnmiEncodeTypedValue(tc.val, gnmipb.Encoding_JSON_IETF)
			if err != nil {
				t.Fatalf("JSON_IETF: %v", err)
			}
			if got := string(tv.GetJsonIetfVal()); got != tc.wantJSON {
				t.Errorf("JSON_IETF = %s, want %s", got, tc.wantJSON)
			}
			tv, err = gnmiEncodeTypedValue(tc.val, gnmipb.Encoding_PROTO)
			if err != nil {
				t.Fatalf("PROTO: %v", err)
			}
			tc.checkPB(t, tv)
		})
	}

	// An unsupported type must surface as Internal in both encodings
	// rather than silently encoding as something plausible.
	for _, enc := range []gnmipb.Encoding{gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_PROTO} {
		if _, err := gnmiEncodeTypedValue(struct{}{}, enc); err == nil {
			t.Errorf("encoding %v: unsupported type did not error", enc)
		}
	}
}
