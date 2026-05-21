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

// onChangeBufferDepth is the per-subscription listener channel depth
// (§D8). State events are rare (typical: ~1 flap / 15 min / interface),
// so depth=16 covers multi-second collector stalls without invoking
// drop-oldest. SAMPLE's depth=100 stays unchanged; the two shapes have
// different burst profiles.
const onChangeBufferDepth = 16

// maxSubsPerStream caps the number of subscriptions accepted in a
// single SubscribeRequest. A hostile client could otherwise open
// MaxConcurrentStreams streams × thousands of subs each and spawn
// O(streams × subs) heartbeat goroutines. 64 covers realistic
// monitoring fanout (per-interface oper+admin+last-change on a
// large device fits comfortably).
const maxSubsPerStream = 64

// runOnChangeSubscribe handles a SubscribeRequest where every
// subscription has mode=ON_CHANGE. The handler validates that every
// sub's resolved path touches only static (state-engine-backed) leaves;
// counter-path subs are rejected up-front with InvalidArgument naming
// the offending leaf.
//
// Lifecycle:
//  1. Validate every sub's path against the static-leaf set.
//  2. Emit the initial-state snapshot per sub (matching the STREAM/SAMPLE
//     tick #0 contract) and one sync_response after the full batch.
//  3. Register a single chan StateChange on the device's InterfaceState.
//     One channel per Subscribe stream — all subs share the same channel
//     and each event is filtered against every sub's path at fan-out time.
//  4. For each sub with HeartbeatInterval > 0, spawn a heartbeat ticker
//     (clamped to 1s floor) that re-emits the sub's current value on
//     every tick, regardless of whether anything changed. Subs without
//     heartbeat idle on the listener channel only.
//  5. Main loop: drain the listener channel + every heartbeat ticker +
//     the gRPC stream's context.Done(). Each event is filtered against
//     every sub's path; matching subs emit a SubscribeResponse{update}
//     carrying the new value.
//  6. On exit (ctx cancel or stream error): RemoveListener, stop every
//     heartbeat ticker, return.
//
// `device` is the DeviceSimulator the Subscribe is bound to; the
// state-engine pointer is derived from it once at entry. If the engine
// is nil (counters not initialised), every ON_CHANGE sub becomes a
// permanently silent stream that only emits the initial snapshot —
// matches the SAMPLE behavior on the same state.
func runOnChangeSubscribe(
	stream gnmipb.GNMI_SubscribeServer,
	resolver *pathResolver,
	device *DeviceSimulator,
	subs []*gnmipb.Subscription,
	enc gnmipb.Encoding,
	updatesSent *uint64,
) error {
	// Per-stream subscription cap. MaxConcurrentStreams=16 bounds
	// streams per connection but a single stream may carry any number
	// of subscriptions, each spawning a heartbeat goroutine. Bound
	// `len(subs)` so a hostile client (16 streams × 10k subs each =
	// 160k goroutines) can't exhaust the runtime. 64 subs/stream is
	// generous for realistic monitoring topologies.
	if len(subs) > maxSubsPerStream {
		return status.Errorf(codes.ResourceExhausted,
			"subscription_list has %d subscriptions; per-stream maximum is %d. Split into multiple streams or merge paths.",
			len(subs), maxSubsPerStream)
	}

	// Per §D5: every sub's path must resolve to leaves drawn exclusively
	// from the static-leaf set. We validate via `ClassifyLeaves` which
	// walks the path shape without doing wildcard expansion or counter
	// reads — a path-only check, no GetDynamic. Counter-touching paths
	// are rejected up-front with a named-leaf error so the client gets
	// actionable feedback.
	for _, sub := range subs {
		leaves, err := resolver.ClassifyLeaves(sub.GetPath())
		if err != nil {
			return err
		}
		for _, leaf := range leaves {
			if !isStateOnlyLeaf(leaf) {
				return status.Errorf(codes.InvalidArgument,
					"ON_CHANGE rejected for counter leaf %q; counters are continuously varying — use SAMPLE with sample_interval instead",
					leaf)
			}
		}
	}

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	// Resolve the InterfaceState pointer first. Nil-safe: a device
	// without an initialised state engine will simply idle until ctx
	// is done. This matches what the SAMPLE path does when the cycler
	// is empty.
	var state *InterfaceState
	if device != nil && device.metricsCycler != nil {
		if ic := device.metricsCycler.ifCounters.Load(); ic != nil {
			state = ic.State()
		}
	}

	// **Register the listener BEFORE the initial snapshot Resolve.**
	// Otherwise a state mutation that races between the snapshot read
	// and AddListener would be lost (the snapshot might have read the
	// pre-mutation value; the listener wouldn't receive the post-mutation
	// event because it wasn't registered yet). Registering first means
	// mutations during the snapshot window are queued in `ch` and the
	// main loop drains them after sync_response — at worst the client
	// sees a duplicate update carrying the same post-mutation value
	// the snapshot already showed, which is harmless and idempotent.
	ch := make(chan StateChange, onChangeBufferDepth)
	if state != nil {
		state.AddListener(ch)
		defer state.RemoveListener(ch)
	}

	// Send a unified initial snapshot batch (every sub's leaves), then
	// the sync_response marker. Per-sub batching: one SubscribeResponse
	// per sub containing all its expanded leaves; matches the
	// SAMPLE/STREAM convention. Note: overlapping subs (e.g. one on
	// `state/oper-status` and one on `state/last-change`) emit
	// independent Notifications by design — per-sub independence is
	// the cleaner abstraction; client-side dedup is the collector's
	// responsibility.
	now := time.Now()
	for _, sub := range subs {
		updates, err := resolver.Resolve(sub.GetPath(), now)
		if err != nil {
			return err
		}
		gnmiUpdates, err := encodeUpdates(updates, enc)
		if err != nil {
			return err
		}
		if len(gnmiUpdates) == 0 {
			continue
		}
		resp := &gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_Update{
				Update: &gnmipb.Notification{
					Timestamp: now.UnixNano(),
					Update:    gnmiUpdates,
				},
			},
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
		atomic.AddUint64(updatesSent, uint64(len(gnmiUpdates)))
	}
	if err := stream.Send(&gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true},
	}); err != nil {
		return err
	}

	// Heartbeat tickers — one per sub with HeartbeatInterval > 0.
	// We track them in a slice indexed by sub so the main loop can
	// select on every ticker channel via reflect.Select isn't worth
	// the overhead at sub-counts ≤ 16 (the per-device gRPC stream
	// cap). Instead, run each ticker in its own goroutine that pushes
	// its sub-index onto a shared heartbeat channel; the main loop
	// then re-resolves and emits.
	type hbEvent struct{ subIdx int }
	hbCh := make(chan hbEvent, len(subs))
	var hbWg sync.WaitGroup
	for i, sub := range subs {
		raw := sub.GetHeartbeatInterval()
		if raw == 0 {
			// Documented "no heartbeat" signal — skip without log.
			continue
		}
		// Clamp uint64 → int64 to avoid wrap-to-negative on absurd
		// values (e.g. a client typo'd `time.Hour*24*7` nanos cast
		// wrong). The operator probably meant "a very long
		// heartbeat", not "no heartbeat" — preserve intent by
		// clamping to MaxInt64 rather than silently dropping.
		var hb time.Duration
		if raw > uint64(time.Duration(1<<63-1)) {
			log.Printf("gNMI ON_CHANGE: heartbeat_interval=%d exceeds MaxInt64; clamped to %s", raw, time.Duration(1<<63-1))
			hb = time.Duration(1<<63 - 1)
		} else {
			hb = time.Duration(raw)
		}
		if hb < minSampleInterval {
			hb = minSampleInterval
		}
		hbWg.Add(1)
		go func(idx int, interval time.Duration) {
			defer hbWg.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					select {
					case hbCh <- hbEvent{subIdx: idx}:
					case <-ctx.Done():
						return
					}
				}
			}
		}(i, hb)
	}

	// Main loop. Exit on ctx (stream cancel) or stream.Send error.
	for {
		select {
		case <-ctx.Done():
			hbWg.Wait()
			return ctx.Err()

		case evt, ok := <-ch:
			if !ok {
				return nil
			}
			if err := emitMatchingForChange(stream, resolver, subs, evt, enc, updatesSent); err != nil {
				cancel()
				hbWg.Wait()
				return err
			}

		case hbEv := <-hbCh:
			// Heartbeat: re-resolve the sub's path right now and emit
			// every leaf the path resolves to. Per §D4 we re-resolve
			// (don't cache) so the heartbeat carries the value at the
			// tick instant, not a stale snapshot.
			now := time.Now()
			updates, err := resolver.Resolve(subs[hbEv.subIdx].GetPath(), now)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					log.Printf("gNMI ON_CHANGE: heartbeat path no longer resolvable: %v", err)
					continue
				}
				cancel()
				hbWg.Wait()
				return err
			}
			gnmiUpdates, err := encodeUpdates(updates, enc)
			if err != nil {
				// Encoder errors on a heartbeat tick should NOT kill
				// the stream — SAMPLE's tick path logs and skips, and
				// asymmetry between SAMPLE and ON_CHANGE makes
				// operator debugging harder. Log once per tick and
				// continue; the next genuine event still fires.
				log.Printf("gNMI ON_CHANGE: heartbeat encoder error (path=%v, skipping tick): %v", subs[hbEv.subIdx].GetPath(), err)
				continue
			}
			if len(gnmiUpdates) == 0 {
				continue
			}
			resp := &gnmipb.SubscribeResponse{
				Response: &gnmipb.SubscribeResponse_Update{
					Update: &gnmipb.Notification{
						Timestamp: now.UnixNano(),
						Update:    gnmiUpdates,
					},
				},
			}
			if err := stream.Send(resp); err != nil {
				cancel()
				hbWg.Wait()
				return err
			}
			atomic.AddUint64(updatesSent, uint64(len(gnmiUpdates)))
		}
	}
}

// emitMatchingForChange filters a StateChange against every sub's path
// and emits a SubscribeResponse for every sub whose path covers a
// leaf that actually changed. A sub on `state/oper-status` matches only
// LeafOperStatus events; a sub on `state/last-change` matches any
// non-zero change bit (last-change implicitly updates on every state
// mutation). A sub on `state/name` or `state/ifindex` is static-only
// and never matches a real change.
//
// Future-extensibility caveat for `subChangeMatch`: any new `StateLeafBits`
// value silently broadens `last-change` semantics (it matches `changed != 0`).
// A future contributor adding e.g. `LeafSpeed` should explicitly decide
// whether last-change subs should fire on that bit too.
//
// Per-event cost: O(subs) fast-path interface-cover check + O(state-leaf
// per matching sub) leaf-by-leaf resolveLeaf calls. Wildcard expansion
// is bypassed when the sub names a specific ifDescr that doesn't match
// evt.IfIndex.
func emitMatchingForChange(
	stream gnmipb.GNMI_SubscribeServer,
	resolver *pathResolver,
	subs []*gnmipb.Subscription,
	evt StateChange,
	enc gnmipb.Encoding,
	updatesSent *uint64,
) error {
	if evt.Changed == 0 {
		return nil
	}
	if resolver.device == nil || resolver.device.metricsCycler == nil {
		return nil
	}
	ic := resolver.device.metricsCycler.ifCounters.Load()
	if ic == nil {
		return nil
	}
	now := time.Now()
	tSec := now.Sub(ic.startTime).Seconds()

	for _, sub := range subs {
		// Fast path: specific-name subs that don't cover evt.IfIndex
		// skip outright (no Resolve, no leaf walk).
		if !pathCoversIfIndex(sub.GetPath(), evt.IfIndex, resolver) {
			continue
		}
		// Classify the sub's path shape (no counter reads, no wildcard
		// expansion). Filter to leaves that match the changed bits.
		leaves, err := resolver.ClassifyLeaves(sub.GetPath())
		if err != nil {
			if status.Code(err) == codes.NotFound {
				continue
			}
			return err
		}
		filtered := make([]resolvedUpdate, 0, len(leaves))
		for _, leaf := range leaves {
			if !subChangeMatch(leaf, evt.Changed) {
				continue
			}
			upd, ok := resolver.resolveLeaf(ic, evt.IfIndex, leaf, tSec)
			if !ok {
				continue
			}
			filtered = append(filtered, upd)
		}
		if len(filtered) == 0 {
			continue
		}
		gnmiUpdates, err := encodeUpdates(filtered, enc)
		if err != nil {
			return err
		}
		resp := &gnmipb.SubscribeResponse{
			Response: &gnmipb.SubscribeResponse_Update{
				Update: &gnmipb.Notification{
					Timestamp: now.UnixNano(),
					Update:    gnmiUpdates,
				},
			},
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
		atomic.AddUint64(updatesSent, uint64(len(gnmiUpdates)))
	}
	return nil
}

// pathCoversIfIndex returns true when sub's path either uses a wildcard
// (or omits the `name` key entirely → wildcard) OR names the specific
// ifIndex via the resolver's `descrToIndex` reverse lookup. A
// specific-name miss returns false → emit short-circuits.
func pathCoversIfIndex(p *gnmipb.Path, ifIndex int, resolver *pathResolver) bool {
	for _, e := range p.GetElem() {
		if e.GetName() != "interface" {
			continue
		}
		keys := e.GetKey()
		if keys == nil {
			return true // missing key = wildcard
		}
		name, ok := keys["name"]
		if !ok || name == "*" {
			return true
		}
		idx, ok := resolver.descrToIndex[name]
		return ok && idx == ifIndex
	}
	// Path doesn't list `interface` — defer to the resolver's classification.
	return true
}

// subChangeMatch returns true when a leaf is affected by the given
// StateChange bitset. last-change is implicit on every state mutation
// (any non-zero Changed bit). name/ifindex are static — they never
// match a change event (initial snapshot covers them).
func subChangeMatch(leaf string, changed StateLeafBits) bool {
	switch leaf {
	case "oper-status":
		return changed&LeafOperStatus != 0
	case "admin-status":
		return changed&LeafAdminStatus != 0
	case "last-change":
		return changed != 0
	default:
		return false
	}
}

// classifyOnChangeMode walks the subs and returns three flags:
// any-ON_CHANGE, any-SAMPLE-or-TARGET_DEFINED, any-unknown (which
// includes POLL on the per-sub mode field). The Subscribe handler
// uses this to decide whether to route to runOnChangeSubscribe (all
// ON_CHANGE), runStreamSubscribe (all SAMPLE / TARGET_DEFINED), or
// reject as mixed mode / unsupported.
func classifyOnChangeMode(subs []*gnmipb.Subscription) (anyOnChange, anySample, anyUnsupported bool) {
	for _, sub := range subs {
		switch sub.GetMode() {
		case gnmipb.SubscriptionMode_ON_CHANGE:
			anyOnChange = true
		case gnmipb.SubscriptionMode_SAMPLE, gnmipb.SubscriptionMode_TARGET_DEFINED:
			anySample = true
		default: // POLL (per-sub-field) and any future enum value
			anyUnsupported = true
		}
	}
	return anyOnChange, anySample, anyUnsupported
}
