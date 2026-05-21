/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"strconv"
	"sync/atomic"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// minSampleInterval is the floor used by Subscribe when a client
// requests a sub-second sample_interval (design.md §D7).
const minSampleInterval = time.Second

// gnmiServer is the per-device gRPC service implementation. It owns the
// device's path resolver and a back-pointer to the manager-level
// counter aggregates so per-stream activity is reflected in
// `GET /api/v1/gnmi/status`.
type gnmiServer struct {
	gnmipb.UnimplementedGNMIServer
	device   *DeviceSimulator
	resolver *pathResolver
	// Aggregate counters (manager-owned, atomic). gnmiServer is
	// constructed with a pointer to each so increments fan into the
	// status endpoint without a manager round-trip.
	activeSubscriptions *int64
	updatesSent         *uint64
	updatesDropped      *uint64
}

// newGnmiServer wires a server for d. The atomic counters MUST point to
// the manager's gnmiActiveSubscriptions / gnmiUpdatesSent /
// gnmiUpdatesDropped fields.
func newGnmiServer(d *DeviceSimulator, active *int64, sent *uint64, dropped *uint64) *gnmiServer {
	return &gnmiServer{
		device:              d,
		resolver:            newPathResolver(d),
		activeSubscriptions: active,
		updatesSent:         sent,
		updatesDropped:      dropped,
	}
}

// Capabilities — design §D5: implemented; static response from the
// resolver. No state.
func (s *gnmiServer) Capabilities(_ context.Context, _ *gnmipb.CapabilityRequest) (*gnmipb.CapabilityResponse, error) {
	return s.resolver.Capabilities(), nil
}

// Get — design §D5: implemented; returns one Notification per requested
// path. Encoding selects the value form (JSON_IETF default; PROTO
// supported). Any unsupported encoding rejects with InvalidArgument.
//
// `GetRequest.prefix.elem` is prepended to each `path.elem` before
// resolution (P10), matching gNMI §3.5.1.1. We do not validate the
// prefix's `origin` field: the simulator only knows one origin
// (openconfig), and a non-empty origin from a client is silently
// accepted so clients that always set it (gNMIc, mostly) still work.
func (s *gnmiServer) Get(_ context.Context, req *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
	enc := req.GetEncoding()
	if !encodingSupported(enc) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported encoding %v", enc)
	}
	// DF2: honour `GetRequest.type`. The simulator exposes only the
	// `state/` subtree — there is no config tree. Per gNMI §3.3.1, a
	// CONFIG request must therefore return an empty response. STATE,
	// OPERATIONAL, and ALL all map to our state subtree (the simulator
	// does not distinguish operational from state internally).
	if req.GetType() == gnmipb.GetRequest_CONFIG {
		return &gnmipb.GetResponse{}, nil
	}
	prefixElems := req.GetPrefix().GetElem()
	now := time.Now()
	notifs := make([]*gnmipb.Notification, 0, len(req.GetPath()))
	for _, p := range req.GetPath() {
		full := joinPathPrefix(prefixElems, p)
		updates, err := s.resolver.Resolve(full, now)
		if err != nil {
			return nil, err
		}
		gnmiUpdates, err := encodeUpdates(updates, enc)
		if err != nil {
			return nil, err
		}
		notifs = append(notifs, &gnmipb.Notification{
			Timestamp: now.UnixNano(),
			Update:    gnmiUpdates,
		})
	}
	return &gnmipb.GetResponse{Notification: notifs}, nil
}

// joinPathPrefix returns a Path whose Elem slice is `prefix || p.Elem`.
// When prefix is empty the original Path is returned unchanged so the
// resolver receives the same pointer the client sent. Used by Get
// (P10) and Subscribe (P9) to honour `*Request.prefix`.
func joinPathPrefix(prefix []*gnmipb.PathElem, p *gnmipb.Path) *gnmipb.Path {
	if len(prefix) == 0 || p == nil {
		return p
	}
	merged := make([]*gnmipb.PathElem, 0, len(prefix)+len(p.GetElem()))
	merged = append(merged, prefix...)
	merged = append(merged, p.GetElem()...)
	return &gnmipb.Path{Origin: p.GetOrigin(), Elem: merged, Target: p.GetTarget()}
}

// Set — design §D5: read-only simulator. Always returns Unimplemented.
func (s *gnmiServer) Set(_ context.Context, _ *gnmipb.SetRequest) (*gnmipb.SetResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Set is not supported by nl6 (read-only simulator)")
}

// Subscribe — design §D5: STREAM/SAMPLE + ONCE only. ON_CHANGE and POLL
// rejected per spec; TARGET_DEFINED treated as SAMPLE; sub-second
// sample_interval clamped to 1s. Heavy lifting lives in
// gnmi_subscribe.go.
//
// First-Recv slowloris guard (P14): the initial SubscribeRequest must
// arrive within gnmiFirstRecvTimeout. Without this bound a client could
// open the gRPC stream, never send the subscription_list, and tie up
// the server-side handler goroutine indefinitely. stream.Recv has no
// per-call deadline knob, so we do the read in a goroutine and race it
// against a timeout. On timeout we return DeadlineExceeded; the
// goroutine remains parked until the underlying transport closes (gRPC
// owns that lifetime via the keepalive parameters set in
// startGnmiServer).
func (s *gnmiServer) Subscribe(stream gnmipb.GNMI_SubscribeServer) error {
	type firstRecv struct {
		req *gnmipb.SubscribeRequest
		err error
	}
	recvCh := make(chan firstRecv, 1)
	go func() {
		req, err := stream.Recv()
		recvCh <- firstRecv{req: req, err: err}
	}()
	var req *gnmipb.SubscribeRequest
	select {
	case r := <-recvCh:
		if r.err != nil {
			return r.err
		}
		req = r.req
	case <-time.After(gnmiFirstRecvTimeout):
		return status.Errorf(codes.DeadlineExceeded, "no SubscribeRequest received within %v", gnmiFirstRecvTimeout)
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	// POLL message arrives via the `poll` oneof variant.
	if req.GetPoll() != nil {
		return status.Error(codes.Unimplemented, "POLL subscription mode is not supported")
	}
	sl := req.GetSubscribe()
	if sl == nil {
		return status.Error(codes.InvalidArgument, "first SubscribeRequest must include subscription_list")
	}

	enc := sl.GetEncoding()
	if !encodingSupported(enc) {
		return status.Errorf(codes.InvalidArgument, "unsupported encoding %v", enc)
	}

	// Reject POLL via SubscriptionList.mode (separate from the `poll` oneof above).
	switch sl.GetMode() {
	case gnmipb.SubscriptionList_POLL:
		return status.Error(codes.Unimplemented, "POLL subscription mode is not supported")
	case gnmipb.SubscriptionList_STREAM, gnmipb.SubscriptionList_ONCE:
		// supported — fall through
	default:
		return status.Errorf(codes.InvalidArgument, "unknown subscription list mode %v", sl.GetMode())
	}

	// Per-subscription mode classification (post add-interface-state §D5):
	// ON_CHANGE is now supported for static-leaf paths via
	// runOnChangeSubscribe. TARGET_DEFINED is treated as SAMPLE.
	// A SubscribeRequest mixing ON_CHANGE + SAMPLE subscriptions is
	// rejected with InvalidArgument — the two paths have different
	// emission models (event-driven vs ticker-driven) and weaving them
	// in one stream would inflate complexity for negligible value.
	// Clients split into two separate Subscribe streams.
	subs := sl.GetSubscription()
	if len(subs) == 0 {
		return status.Error(codes.InvalidArgument, "subscription_list must contain at least one subscription")
	}

	// Per-subscription tickers: each subscription's `sample_interval`
	// is honoured independently, clamped at minSampleInterval. Sizing
	// happens inside runStreamSubscribe via clampSampleInterval.

	// Honour SubscribeRequest.subscription_list.prefix per gNMI §3.5.1.1
	// by prepending its Elem to each subscription Path before passing
	// to Resolve (P9). Origin on the prefix is accepted but not
	// validated — same rationale as Get.
	prefixElems := sl.GetPrefix().GetElem()
	if len(prefixElems) > 0 {
		merged := make([]*gnmipb.Subscription, 0, len(subs))
		for _, sub := range subs {
			merged = append(merged, &gnmipb.Subscription{
				Path:              joinPathPrefix(prefixElems, sub.GetPath()),
				Mode:              sub.GetMode(),
				SampleInterval:    sub.GetSampleInterval(),
				SuppressRedundant: sub.GetSuppressRedundant(),
				HeartbeatInterval: sub.GetHeartbeatInterval(),
			})
		}
		subs = merged
	}

	// Count both ONCE and STREAM streams in active_subscriptions (P16):
	// from the operator's perspective they're both live gNMI streams
	// that consume server-side resources for the duration of the call.
	atomic.AddInt64(s.activeSubscriptions, 1)
	defer atomic.AddInt64(s.activeSubscriptions, -1)

	// ONCE: send one batch + sync_response, return. ONCE ignores
	// per-sub mode (ON_CHANGE/SAMPLE are STREAM-only concepts).
	if sl.GetMode() == gnmipb.SubscriptionList_ONCE {
		return runOnceSubscribe(stream, s.resolver, subs, enc, s.updatesSent)
	}

	// STREAM: route by per-sub mode. Mixed-mode requests are rejected.
	// Note: ON_CHANGE drops are counted by `InterfaceState.eventsDropped`
	// (per-channel oldest-drop on backpressure), surfaced via
	// `gnmiStateEventsDropped` in /api/v1/gnmi/status — NOT via the
	// `updatesDropped` counter the SAMPLE path uses. So we don't pass
	// `updatesDropped` to runOnChangeSubscribe.
	anyOnChange, anySample, anyUnsupported := classifyOnChangeMode(subs)
	switch {
	case anyUnsupported:
		// POLL on a per-subscription mode field, or any unknown future
		// SubscriptionMode enum value, is not supported. (POLL at the
		// SubscriptionList level is rejected earlier with Unimplemented.)
		return status.Error(codes.Unimplemented,
			"per-subscription mode POLL (or unknown SubscriptionMode value) is not supported; use ON_CHANGE or SAMPLE")
	case anyOnChange && anySample:
		return status.Error(codes.InvalidArgument,
			"subscription_list mixes ON_CHANGE and SAMPLE/TARGET_DEFINED subscriptions; split into two separate SubscribeRequests")
	case anyOnChange:
		return runOnChangeSubscribe(stream, s.resolver, s.device, subs, enc, s.updatesSent)
	default:
		return runStreamSubscribe(stream, s.resolver, subs, enc, s.updatesSent, s.updatesDropped)
	}
}

// encodingSupported reports whether enc is one of the encodings the
// simulator can serve.
//
// Accepted: JSON_IETF, PROTO, JSON. Rejected: BYTES, ASCII (and any
// future encoding the proto adds without us teaching the encoder).
//
// JSON is the proto3 zero value of `gnmi.Encoding`. The wire format is
// indistinguishable between "client explicitly requested JSON" and
// "client omitted the encoding field" (proto3 doesn't carry presence
// bits on scalar enums), so we accept the zero value and treat it as
// JSON_IETF inside `encodeUpdates`. This keeps clients that omit the
// encoding field functional at the cost of silently upgrading anyone
// who genuinely asks for the obsolete JSON encoding (RFC 7159 form,
// no IETF type wrapping). That trade-off is documented for §D5
// reviewers — the alternative (rejecting JSON outright) breaks the
// large class of tools that don't set Encoding on GetRequest.
func encodingSupported(enc gnmipb.Encoding) bool {
	switch enc {
	case gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_PROTO, gnmipb.Encoding_JSON:
		return true
	}
	return false
}

// encodeUpdates converts resolver updates into gNMI Update messages
// using the requested encoding. JSON_IETF wraps each value as a
// json_ietf_val byte string; PROTO uses the matching scalar TypedValue
// field.
func encodeUpdates(updates []resolvedUpdate, enc gnmipb.Encoding) ([]*gnmipb.Update, error) {
	out := make([]*gnmipb.Update, 0, len(updates))
	for _, u := range updates {
		tv, err := gnmiEncodeTypedValue(u.Value, enc)
		if err != nil {
			return nil, err
		}
		out = append(out, &gnmipb.Update{
			Path: u.Path,
			Val:  tv,
		})
	}
	return out, nil
}

// gnmiEncodeTypedValue encodes a single Go value into a gNMI TypedValue.
// Supported Go types: string, uint32, uint64. Other types are a
// programming error in the resolver; surface them as Internal.
//
// Named with a `gnmi` prefix to avoid collision with the SNMP-side
// `encodeTypedValue` in snmp_encoding.go.
func gnmiEncodeTypedValue(v interface{}, enc gnmipb.Encoding) (*gnmipb.TypedValue, error) {
	if enc == gnmipb.Encoding_PROTO {
		switch x := v.(type) {
		case string:
			return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: x}}, nil
		case uint32:
			return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: uint64(x)}}, nil
		case uint64:
			return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: x}}, nil
		default:
			return nil, status.Errorf(codes.Internal, "unsupported value type %T for PROTO encoding", v)
		}
	}
	// JSON_IETF (default). Counter values are encoded as JSON strings
	// per RFC 7951 §6.1 (uint64 doesn't fit JSON number, must be a
	// string); uint32 fits as a number.
	var b []byte
	var err error
	switch x := v.(type) {
	case string:
		b, err = json.Marshal(x)
	case uint32:
		b, err = json.Marshal(x)
	case uint64:
		// RFC 7951: uint64 / int64 are JSON strings.
		b, err = json.Marshal(strconv.FormatUint(x, 10))
	default:
		return nil, status.Errorf(codes.Internal, "unsupported value type %T for JSON_IETF encoding", v)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "json marshal: %v", err)
	}
	return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: b}}, nil
}
