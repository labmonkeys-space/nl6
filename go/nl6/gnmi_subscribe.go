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
	"github.com/openconfig/gnmi/proto/gnmi_ext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// subscribeBufferDepth is the per-stream send-channel depth. Drop-oldest
// on overflow (design.md §D8) bounds memory at 30k devices × 100 deep
// × ~few KiB per response → at most a handful of MiB even when every
// collector is wedged. On a Subscribe stream one element is one tick:
// a single response for a legacy path, every list entry's response for
// a catalogue path, so a catalogue stream's bound scales with its
// entries per tick.
const subscribeBufferDepth = 100

// catalogSubscription carries what one Subscribe stream needs to serve
// catalogue paths: the resolver, the catalogue-side encoding (client
// JSON already mapped to the json_val sentinel), the extension factory,
// and the stream's response sequence counter. nil on a legacy device.
type catalogSubscription struct {
	resolver *catalogResolver
	enc      gnmipb.Encoding
	extFor   func(subscribed, streamed string, seq uint64, now time.Time) *gnmi_ext.Extension
	seq      atomic.Uint64
}

// serves reports whether the catalogue owns sub's path.
func (c *catalogSubscription) serves(sub *gnmipb.Subscription) bool {
	return c != nil && c.resolver.Match(sub.GetPath())
}

// responses resolves sub through the catalogue and builds one
// SubscribeResponse per list entry, each with its own sequence number.
// The streamed path is the client's path, except for a subtree alias,
// where it is the entry's rendered prefix path.
func (c *catalogSubscription) responses(sub *gnmipb.Subscription, now time.Time) ([]*gnmipb.SubscribeResponse, error) {
	notifs, err := c.resolver.Resolve(sub.GetPath(), now)
	if err != nil {
		return nil, err
	}
	subscribed := pathToString(sub.GetPath())
	alias := len(c.resolver.aliasSubtrees(sub.GetPath())) > 0
	out := make([]*gnmipb.SubscribeResponse, 0, len(notifs))
	for _, n := range notifs {
		streamed := subscribed
		if alias {
			streamed = pathToString(n.Prefix)
		}
		r, err := catalogSubscribeResponses(now, []catalogNotification{n}, c.enc, c.extFor(subscribed, streamed, c.seq.Add(1), now))
		if err != nil {
			return nil, err
		}
		out = append(out, r...)
	}
	return out, nil
}

// catalogSubscribeResponses turns catalogue notifications into one
// SubscribeResponse per list entry, each carrying ext when non-nil.
func catalogSubscribeResponses(now time.Time, notifs []catalogNotification, enc gnmipb.Encoding, ext *gnmi_ext.Extension) ([]*gnmipb.SubscribeResponse, error) {
	out := make([]*gnmipb.SubscribeResponse, 0, len(notifs))
	for _, n := range notifs {
		ups, err := encodeUpdates(n.Updates, enc)
		if err != nil {
			return nil, err
		}
		resp := &gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{
			Timestamp: now.UnixNano(), Prefix: n.Prefix, Update: ups,
		}}}
		if ext != nil {
			resp.Extension = []*gnmi_ext.Extension{ext}
		}
		out = append(out, resp)
	}
	return out, nil
}

// runOnceSubscribe handles SubscribeRequest with mode=ONCE: assemble
// one batch synchronously, send sync_response, return (gRPC closes the
// stream when this function returns).
//
// Per gNMI §3.5.2.1 the ONCE response is a single Notification whose
// Update slice carries the union of every subscription's resolved
// updates, sharing one timestamp (P24). Earlier revisions emitted one
// SubscribeResponse per subscription which over-counted notifications
// on the client side and broke gnmic's `--format proto` rendering.
//
// Catalogue-served subscriptions (cs non-nil and matching) are the
// exception: Junos sends one notification per list entry, so each entry
// is sent as its own SubscribeResponse as soon as it resolves. Legacy
// subscriptions still accumulate into the one combined notification,
// sent only when non-empty or when no catalogue path was served.
func runOnceSubscribe(
	stream gnmipb.GNMI_SubscribeServer,
	resolver *pathResolver,
	cs *catalogSubscription,
	subs []*gnmipb.Subscription,
	enc gnmipb.Encoding,
	updatesSent *uint64,
) error {
	now := time.Now()
	combined := make([]*gnmipb.Update, 0, len(subs))
	catalogServed := false
	for _, sub := range subs {
		if cs.serves(sub) {
			catalogServed = true
			resps, err := cs.responses(sub, now)
			if err != nil {
				return err
			}
			for _, r := range resps {
				if err := stream.Send(r); err != nil {
					return err
				}
				atomic.AddUint64(updatesSent, uint64(len(r.GetUpdate().GetUpdate())))
			}
			continue
		}
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
	if len(combined) > 0 || !catalogServed {
		if err := stream.Send(notificationResponse(now, combined)); err != nil {
			return err
		}
		atomic.AddUint64(updatesSent, uint64(len(combined)))
	}
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
	cs *catalogSubscription,
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

	// Each queue element is one tick's responses: a legacy tick is one
	// response, a catalogue tick is one response per list entry. A tick
	// is therefore dropped whole or delivered whole, and the initial
	// snapshot is complete before sync_response.
	ch := make(chan []*gnmipb.SubscribeResponse, subscribeBufferDepth)
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
			case batch, ok := <-ch:
				if !ok {
					errCh <- nil
					return
				}
				for _, resp := range batch {
					if err := stream.Send(resp); err != nil {
						errCh <- err
						return
					}
					if upd := resp.GetUpdate(); upd != nil {
						atomic.AddUint64(updatesSent, uint64(len(upd.GetUpdate())))
					}
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
			pushSubUpdate(ctx, ch, resolver, cs, sub, enc, updatesDropped)
			if initialFired.Add(1) == totalSubs {
				pushBatchOrDrop(ctx, ch, []*gnmipb.SubscribeResponse{{
					Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
				}}, updatesDropped)
			}

			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					pushSubUpdate(ctx, ch, resolver, cs, sub, enc, updatesDropped)
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
// enqueues one SubscribeResponse{update} via pushBatchOrDrop. Per-subscription
// `codes.NotFound` is *not* fatal (P3): if an interface name disappeared
// between Subscribe-time and this tick we log and skip the tick. Other
// resolver errors (InvalidArgument, Internal, …) are also logged here —
// surfacing them via the stream would require a separate error channel
// per ticker, which is over-engineered for a read-only resolver where
// these errors indicate programming bugs, not transient runtime
// conditions.
//
// A catalogue-served subscription enqueues one response per list entry
// instead of one combined notification, as a single queue element.
func pushSubUpdate(
	ctx context.Context,
	ch chan []*gnmipb.SubscribeResponse,
	resolver *pathResolver,
	cs *catalogSubscription,
	sub *gnmipb.Subscription,
	enc gnmipb.Encoding,
	updatesDropped *uint64,
) {
	now := time.Now()
	if cs.serves(sub) {
		resps, err := cs.responses(sub, now)
		if err != nil {
			log.Printf("gNMI: catalogue subscribe error for %s: %v (skipping tick)", pathToString(sub.GetPath()), err)
			return
		}
		if len(resps) > 0 {
			pushBatchOrDrop(ctx, ch, resps, updatesDropped)
		}
		return
	}
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
	pushBatchOrDrop(ctx, ch, []*gnmipb.SubscribeResponse{notificationResponse(now, gnmiUpdates)}, updatesDropped)
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
	enqueueDropOldest(ctx, ch, resp, func(*gnmipb.SubscribeResponse) uint64 { return 1 }, updatesDropped)
}

// pushBatchOrDrop is pushOrDrop for a queue of whole ticks. A dropped
// batch adds one to the drop counter per response it held.
func pushBatchOrDrop(ctx context.Context, ch chan []*gnmipb.SubscribeResponse, batch []*gnmipb.SubscribeResponse, updatesDropped *uint64) {
	enqueueDropOldest(ctx, ch, batch, func(b []*gnmipb.SubscribeResponse) uint64 { return uint64(len(b)) }, updatesDropped)
}

// enqueueDropOldest implements the drop-oldest policy for pushOrDrop
// and pushBatchOrDrop; weight is what one dropped item adds to the
// drop counter.
func enqueueDropOldest[T any](ctx context.Context, ch chan T, item T, weight func(T) uint64, updatesDropped *uint64) {
	// Fast path: enqueue without dropping.
	select {
	case ch <- item:
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
		case old := <-ch:
			atomic.AddUint64(updatesDropped, weight(old))
		default:
		}
		select {
		case ch <- item:
			return
		case <-ctx.Done():
			return
		default:
			// Still full (another sender raced us). Try again.
		}
	}
}
