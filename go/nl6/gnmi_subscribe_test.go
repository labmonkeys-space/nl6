/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// drainOne pulls one response from the stream's `sent` channel with a
// generous timeout so flaky CI doesn't false-fail.
func drainOne(t *testing.T, stream *fakeSubscribeStream, timeout time.Duration) *gnmipb.SubscribeResponse {
	t.Helper()
	select {
	case resp := <-stream.sent:
		return resp
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for SubscribeResponse")
		return nil
	}
}

func TestSubscribe_OnceDeliversBatchAndSync(t *testing.T) {
	srv, _, sent, _ := newTestGnmiServer(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeSubscribeStream(ctx)

	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_ONCE,
				Subscription: []*gnmipb.Subscription{{
					Path: pathFromString(t, "/interfaces/interface[name=*]/state/counters/in-octets"),
				}},
			},
		},
	}

	if err := srv.Subscribe(stream); err != nil {
		t.Fatalf("Subscribe ONCE: %v", err)
	}

	// Expect: 1 update batch, then 1 sync_response.
	resp := drainOne(t, stream, time.Second)
	if resp.GetUpdate() == nil {
		t.Fatalf("first response should be Update, got %T", resp.GetResponse())
	}
	if got := len(resp.GetUpdate().GetUpdate()); got != 2 {
		t.Errorf("ONCE updates: got %d, want 2 (one per ifIndex)", got)
	}
	resp = drainOne(t, stream, time.Second)
	if !resp.GetSyncResponse() {
		t.Errorf("second response should be sync_response, got %T", resp.GetResponse())
	}
	// updates_sent must reflect the 2 leaves emitted.
	if got := atomic.LoadUint64(sent); got != 2 {
		t.Errorf("updates_sent: got %d, want 2", got)
	}
}

func TestSubscribe_StreamSampleDeliversAtInterval(t *testing.T) {
	// Use a 1s interval (the minimum). One tick + initial batch is
	// enough to validate the loop without making the test slow.
	srv, active, sent, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream := newFakeSubscribeStream(ctx)

	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{{
					Path:           pathFromString(t, "/interfaces/interface[name=*]/state/counters/in-octets"),
					Mode:           gnmipb.SubscriptionMode_SAMPLE,
					SampleInterval: uint64(time.Second),
				}},
			},
		},
	}

	subscribeErr := make(chan error, 1)
	go func() { subscribeErr <- srv.Subscribe(stream) }()

	// Initial batch + sync.
	first := drainOne(t, stream, 2*time.Second)
	if first.GetUpdate() == nil {
		t.Fatalf("first response should be Update, got %T", first.GetResponse())
	}
	sync := drainOne(t, stream, 2*time.Second)
	if !sync.GetSyncResponse() {
		t.Errorf("second response should be sync_response, got %T", sync.GetResponse())
	}

	// Wait for at least one tick.
	tick := drainOne(t, stream, 2*time.Second)
	if tick.GetUpdate() == nil {
		t.Fatalf("ticker response should be Update, got %T", tick.GetResponse())
	}

	// active_subscriptions should reflect the live stream.
	if got := atomic.LoadInt64(active); got != 1 {
		t.Errorf("active_subscriptions: got %d, want 1", got)
	}

	cancel()
	select {
	case <-subscribeErr:
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe goroutine did not exit after context cancel")
	}
	// active_subscriptions must drop back to 0 on exit.
	if got := atomic.LoadInt64(active); got != 0 {
		t.Errorf("active_subscriptions after cancel: got %d, want 0", got)
	}
	// updates_sent should be > 0.
	if got := atomic.LoadUint64(sent); got == 0 {
		t.Errorf("updates_sent: got 0, want > 0")
	}
}

func TestSubscribe_StreamCancelTerminates(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{{
					Path:           pathFromString(t, "/interfaces/interface[name=*]/state/ifindex"),
					Mode:           gnmipb.SubscriptionMode_SAMPLE,
					SampleInterval: uint64(time.Second),
				}},
			},
		},
	}

	done := make(chan error, 1)
	go func() { done <- srv.Subscribe(stream) }()

	// Wait for the initial sync to come through, then cancel.
	drainOne(t, stream, 2*time.Second) // batch
	drainOne(t, stream, 2*time.Second) // sync
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe did not return after context cancel")
	}
}

func TestPushOrDrop_IncrementsDropCounter(t *testing.T) {
	ch := make(chan *gnmipb.SubscribeResponse, 2)
	var dropped uint64
	ctx := context.Background()

	// Fill the buffer.
	pushOrDrop(ctx, ch, &gnmipb.SubscribeResponse{}, &dropped)
	pushOrDrop(ctx, ch, &gnmipb.SubscribeResponse{}, &dropped)
	if atomic.LoadUint64(&dropped) != 0 {
		t.Fatalf("no drops yet, got %d", atomic.LoadUint64(&dropped))
	}
	// Third push must drop the oldest.
	pushOrDrop(ctx, ch, &gnmipb.SubscribeResponse{}, &dropped)
	if atomic.LoadUint64(&dropped) != 1 {
		t.Fatalf("dropped: got %d, want 1", atomic.LoadUint64(&dropped))
	}
	// Verify channel still holds 2 entries.
	if len(ch) != 2 {
		t.Errorf("buffer length: got %d, want 2", len(ch))
	}
}

func TestPushOrDrop_RespectsCtxCancel(t *testing.T) {
	// A cancelled ctx with a full buffer must not block.
	ch := make(chan *gnmipb.SubscribeResponse, 1)
	ch <- &gnmipb.SubscribeResponse{} // pre-fill so first send fails
	var dropped uint64
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the push.
	done := make(chan struct{})
	go func() {
		pushOrDrop(ctx, ch, &gnmipb.SubscribeResponse{}, &dropped)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pushOrDrop blocked on cancelled ctx")
	}
}

// TestSubscribe_StreamPerSubTickers verifies that two subs in one
// SubscriptionList with different sample_intervals fire at their own
// independent cadence (P1 / D1 — per-subscription tickers).
//
// 1s sub fires every second; 3s sub fires every three seconds. Over
// roughly 4 seconds the 1s sub should produce more notifications than
// the 3s sub, and both must terminate on context cancel.
func TestSubscribe_StreamPerSubTickers(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := newFakeSubscribeStream(ctx)

	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{
					{
						Path:           pathFromString(t, "/interfaces/interface[name=*]/state/ifindex"),
						Mode:           gnmipb.SubscriptionMode_SAMPLE,
						SampleInterval: uint64(time.Second),
					},
					{
						Path:           pathFromString(t, "/interfaces/interface[name=*]/state/counters/in-octets"),
						Mode:           gnmipb.SubscriptionMode_SAMPLE,
						SampleInterval: uint64(3 * time.Second),
					},
				},
			},
		},
	}

	done := make(chan error, 1)
	go func() { done <- srv.Subscribe(stream) }()

	// Categorise responses by which subscription emitted them. The
	// first update from each sub identifies the sub via its update
	// path. ifIndex updates carry path /...state/ifindex; in-octets
	// updates carry path /...state/counters/in-octets.
	deadline := time.After(4500 * time.Millisecond)
	var ifindexCount, octetsCount, syncCount int
loop:
	for {
		select {
		case <-deadline:
			break loop
		case resp := <-stream.sent:
			if resp.GetSyncResponse() {
				syncCount++
				continue
			}
			upd := resp.GetUpdate()
			if upd == nil || len(upd.GetUpdate()) == 0 {
				continue
			}
			elems := upd.GetUpdate()[0].GetPath().GetElem()
			last := elems[len(elems)-1].GetName()
			switch last {
			case "ifindex":
				ifindexCount++
			case "in-octets":
				octetsCount++
			}
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe did not return after context cancel")
	}

	// Over ~4.5s: 1s sub should fire ~5 times (initial + 4 ticks).
	// 3s sub should fire ~2 times (initial + 1 tick). Use loose lower
	// bounds to absorb scheduler jitter.
	if ifindexCount < 4 {
		t.Errorf("ifindex (1s sub) updates: got %d, want >=4", ifindexCount)
	}
	if octetsCount < 2 {
		t.Errorf("in-octets (3s sub) updates: got %d, want >=2", octetsCount)
	}
	if ifindexCount <= octetsCount {
		t.Errorf("expected 1s sub to outpace 3s sub: ifindex=%d, octets=%d", ifindexCount, octetsCount)
	}
	if syncCount != 1 {
		t.Errorf("sync_response: got %d, want exactly 1", syncCount)
	}
}

func TestSubscribe_StreamSendError_TerminatesCleanly(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.sendErr.Store(errors.New("simulated send failure"))

	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{{
					Path:           pathFromString(t, "/interfaces/interface[name=*]/state/ifindex"),
					Mode:           gnmipb.SubscriptionMode_SAMPLE,
					SampleInterval: uint64(time.Second),
				}},
			},
		},
	}

	done := make(chan error, 1)
	go func() { done <- srv.Subscribe(stream) }()

	select {
	case err := <-done:
		if err == nil {
			t.Errorf("expected non-nil error from Subscribe on Send failure")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Subscribe did not exit on Send failure")
	}
}
