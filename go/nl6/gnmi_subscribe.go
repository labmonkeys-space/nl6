/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// subscribeBufferDepth is the per-stream send-channel depth. Drop-oldest
// on overflow (design.md §D8) bounds memory at 30k devices × 100 deep
// × ~few KiB per response → at most a handful of MiB even when every
// collector is wedged.
const subscribeBufferDepth = 100

// runOnceSubscribe handles SubscribeRequest with mode=ONCE: assemble
// one batch synchronously, send sync_response, return (gRPC closes the
// stream when this function returns).
//
// Per gNMI §3.5.2.1 the ONCE response is a single Notification whose
// Update slice carries the union of every subscription's resolved
// updates, sharing one timestamp (P24). Earlier revisions emitted one
// SubscribeResponse per subscription which over-counted notifications
// on the client side and broke gnmic's `--format proto` rendering.
func runOnceSubscribe(
	stream gnmipb.GNMI_SubscribeServer,
	resolver *pathResolver,
	subs []*gnmipb.Subscription,
	enc gnmipb.Encoding,
	updatesSent *uint64,
) error {
	now := time.Now()
	combined := make([]*gnmipb.Update, 0, len(subs))
	for _, sub := range subs {
		updates, err := resolver.Resolve(sub.GetPath(), now)
		if err != nil {
			return err
		}
		gnmiUpdates, err := encodeUpdates(updates, enc)
		if err != nil {
			return err
		}
		combined = append(combined, gnmiUpdates...)
	}
	resp := &gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_Update{
			Update: &gnmipb.Notification{
				Timestamp: now.UnixNano(),
				Update:    combined,
			},
		},
	}
	if err := stream.Send(resp); err != nil {
		return err
	}
	atomic.AddUint64(updatesSent, uint64(len(combined)))
	// sync_response signals "initial state delivered".
	return stream.Send(&gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
	})
}

// runStreamSubscribe handles SubscribeRequest with mode=STREAM. Each
// subscription owns its own ticker goroutine pacing at the
// subscription's `sample_interval` (clamped to a 1s floor per §D7), so
// independent cadences inside one SubscriptionList are honoured. A
// shared bounded queue feeds a single send goroutine that drains to the
// gRPC stream.
//
// Channel-close discipline (P8):
//   - Multiple producers (one per subscription ticker) write to `ch`
//     via `pushOrDrop`, which is non-blocking and ctx-aware.
//   - The send goroutine is the sole *consumer*.
//   - `ch` is closed exactly once, by this function, AFTER `wg.Wait()`
//     confirms every ticker has exited. This preserves the
//     "single-writer-of-close-event, multi-writer-of-data-events"
//     invariant Go requires.
//
// Sync semantics: each ticker pushes its first snapshot at goroutine
// start (tick #0), then on every subsequent tick. An atomic counter
// tracks how many subs have published their initial snapshot; once
// every sub has fired once, the sync_response marker is enqueued.
func runStreamSubscribe(
	stream gnmipb.GNMI_SubscribeServer,
	resolver *pathResolver,
	subs []*gnmipb.Subscription,
	enc gnmipb.Encoding,
	updatesSent *uint64,
	updatesDropped *uint64,
) error {
	// Derive a cancellable child context so a send-side error can
	// unwind the ticker goroutines even when the stream context isn't
	// cancelled by the client.
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	ch := make(chan *gnmipb.SubscribeResponse, subscribeBufferDepth)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	var initialFired atomic.Int64
	totalSubs := int64(len(subs))

	// Send goroutine: drain ch, write to stream. Reports outcome to
	// errCh exactly once (capacity 1, single sender). Cancels the
	// shared ctx on exit so the ticker goroutines stop producing.
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case resp, ok := <-ch:
				if !ok {
					errCh <- nil
					return
				}
				if err := stream.Send(resp); err != nil {
					errCh <- err
					return
				}
				if upd := resp.GetUpdate(); upd != nil {
					atomic.AddUint64(updatesSent, uint64(len(upd.GetUpdate())))
				}
			}
		}
	}()

	// One ticker goroutine per subscription. Each honours its own
	// sample_interval clamped at minSampleInterval.
	for _, sub := range subs {
		wg.Add(1)
		go func(sub *gnmipb.Subscription) {
			defer wg.Done()
			interval := clampSampleInterval(time.Duration(sub.GetSampleInterval()))

			// Initial snapshot (tick #0).
			pushSubUpdate(ctx, ch, resolver, sub, enc, updatesDropped)
			if initialFired.Add(1) == totalSubs {
				pushOrDrop(ctx, ch, &gnmipb.SubscribeResponse{
					Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
				}, updatesDropped)
			}

			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					pushSubUpdate(ctx, ch, resolver, sub, enc, updatesDropped)
				}
			}
		}(sub)
	}

	// Wait for ctx cancel, then for tickers to drain. Once every
	// ticker has exited it is safe to close ch — no producer can race
	// the close because none remain.
	<-ctx.Done()
	wg.Wait()
	close(ch)
	return <-errCh
}

// pushSubUpdate resolves a single subscription's path at "now" and
// enqueues one SubscribeResponse{update} via pushOrDrop. Per-subscription
// `codes.NotFound` is *not* fatal (P3): if an interface name disappeared
// between Subscribe-time and this tick we log and skip the tick. Other
// resolver errors (InvalidArgument, Internal, …) are also logged here —
// surfacing them via the stream would require a separate error channel
// per ticker, which is over-engineered for a read-only resolver where
// these errors indicate programming bugs, not transient runtime
// conditions.
func pushSubUpdate(
	ctx context.Context,
	ch chan *gnmipb.SubscribeResponse,
	resolver *pathResolver,
	sub *gnmipb.Subscription,
	enc gnmipb.Encoding,
	updatesDropped *uint64,
) {
	now := time.Now()
	updates, err := resolver.Resolve(sub.GetPath(), now)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Printf("gNMI: subscribe path %s no longer resolvable: %v (skipping tick)", pathToString(sub.GetPath()), err)
			return
		}
		log.Printf("gNMI: subscribe resolve error for %s: %v (skipping tick)", pathToString(sub.GetPath()), err)
		return
	}
	gnmiUpdates, err := encodeUpdates(updates, enc)
	if err != nil {
		log.Printf("gNMI: subscribe encode error for %s: %v (skipping tick)", pathToString(sub.GetPath()), err)
		return
	}
	resp := &gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_Update{
			Update: &gnmipb.Notification{
				Timestamp: now.UnixNano(),
				Update:    gnmiUpdates,
			},
		},
	}
	pushOrDrop(ctx, ch, resp, updatesDropped)
}

// clampSampleInterval applies the §D7 floor: any interval below
// minSampleInterval (and the unset/zero case) is silently bumped to
// minSampleInterval. Used by Subscribe to size each per-subscription
// ticker.
func clampSampleInterval(raw time.Duration) time.Duration {
	if raw < minSampleInterval {
		return minSampleInterval
	}
	return raw
}

// pushOrDrop sends resp on ch. When ch is full, it drains the oldest
// queued entry (drop-oldest policy, §D8) and retries. Multi-producer
// safe — multiple ticker goroutines call this concurrently.
//
// `ctx` is consulted on every iteration so a cancelled stream does not
// trap a producer in a busy retry loop while a slow consumer holds the
// buffer full. The drop counter is incremented per dropped item, not
// per overflow event.
func pushOrDrop(ctx context.Context, ch chan *gnmipb.SubscribeResponse, resp *gnmipb.SubscribeResponse, updatesDropped *uint64) {
	// Fast path: enqueue without dropping.
	select {
	case ch <- resp:
		return
	case <-ctx.Done():
		return
	default:
	}
	// Slow path: drop oldest until the new entry fits, or until ctx
	// cancels. Bounded by buffer size per producer entry.
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			atomic.AddUint64(updatesDropped, 1)
		default:
		}
		select {
		case ch <- resp:
			return
		case <-ctx.Done():
			return
		default:
			// Still full (another sender raced us). Try again.
		}
	}
}
