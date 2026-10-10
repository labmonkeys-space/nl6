/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmi/proto/gnmi_ext"
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
	catalog  *catalogResolver // nil when the device type has no catalogue
	// catalogStreams counts catalogue Subscribe streams; it picks each
	// stream's stable Juniper sensor name.
	catalogStreams atomic.Uint64
	// Aggregate counters (manager-owned, atomic). gnmiServer is
	// constructed with a pointer to each so increments fan into the
	// status endpoint without a manager round-trip.
	activeSubscriptions *int64
	updatesSent         *uint64
	updatesDropped      *uint64
}

// newGnmiServer wires a server for d. cat is the device type's gNMI
// catalogue, or nil for the legacy-only surface. The atomic counters
// MUST point to the manager's gnmiActiveSubscriptions / gnmiUpdatesSent /
// gnmiUpdatesDropped fields.
func newGnmiServer(d *DeviceSimulator, cat *gnmiCatalog, active *int64, sent *uint64, dropped *uint64) *gnmiServer {
	s := &gnmiServer{
		device:              d,
		resolver:            newPathResolver(d),
		activeSubscriptions: active,
		updatesSent:         sent,
		updatesDropped:      dropped,
	}
	if cat != nil {
		s.catalog = newCatalogResolver(d, cat)
	}
	return s
}

// Capabilities — design §D5: implemented; static response from the
// resolver. No state. A device with a catalogue also advertises the
// catalogue's models, and only the encodings the catalogue accepts.
func (s *gnmiServer) Capabilities(_ context.Context, _ *gnmipb.CapabilityRequest) (*gnmipb.CapabilityResponse, error) {
	resp := s.resolver.Capabilities()
	if s.catalog == nil {
		return resp, nil
	}
	resp.SupportedModels = mergeModels(resp.SupportedModels, s.catalog.Models())
	resp.SupportedEncodings = resp.SupportedEncodings[:0]
	for _, e := range []gnmipb.Encoding{gnmipb.Encoding_JSON, gnmipb.Encoding_JSON_IETF, gnmipb.Encoding_PROTO} {
		if s.catalog.cat.acceptsEncoding(e) {
			resp.SupportedEncodings = append(resp.SupportedEncodings, e)
		}
	}
	return resp, nil
}

// mergeModels returns legacy with each entry whose name the catalogue
// also lists replaced in place by the catalogue's entry, followed by
// the catalogue-only entries in catalogue order.
func mergeModels(legacy, catalog []*gnmipb.ModelData) []*gnmipb.ModelData {
	byName := make(map[string]*gnmipb.ModelData, len(catalog))
	for _, m := range catalog {
		byName[m.GetName()] = m
	}
	out := make([]*gnmipb.ModelData, 0, len(legacy)+len(catalog))
	used := make(map[string]bool, len(catalog))
	for _, m := range legacy {
		if c, ok := byName[m.GetName()]; ok {
			m = c
			used[m.GetName()] = true
		}
		out = append(out, m)
	}
	for _, m := range catalog {
		if !used[m.GetName()] {
			out = append(out, m)
		}
	}
	return out
}

// catalogEncoding applies the catalogue's encoding gate, which covers
// every path on a catalogue device, and returns the encoding to use for
// catalogue paths: a client JSON request maps to the json_val sentinel.
// Legacy paths on the same device keep the client encoding.
func (s *gnmiServer) catalogEncoding(enc gnmipb.Encoding) (gnmipb.Encoding, error) {
	if !s.catalog.cat.acceptsEncoding(enc) {
		return 0, status.Errorf(codes.Unimplemented, "Encoding %d not supported, Only PROTO/JSON encoding supported", enc)
	}
	if enc == gnmipb.Encoding_JSON {
		return gnmiEncodingJSONVal, nil
	}
	return enc, nil
}

// catalogExtension builds the per-response extension the catalogue
// asks for, or nil. sensor is fixed for the stream; seq counts the
// stream's responses from 1.
func (s *gnmiServer) catalogExtension(sensor, subscribed, streamed string, seq uint64, now time.Time) *gnmi_ext.Extension {
	if s.catalog.cat.Notification.Extension != gnmiExtensionJuniperHeader {
		return nil
	}
	return juniperHeaderExtension(juniperHeader{
		SystemID: gnmiDeviceSysName(s.device), ComponentID: 65535, SensorName: sensor,
		SubscribedPath: subscribed, StreamedPath: streamed, Component: "xmlproxyd_TM_Thread_1",
		SequenceNumber: seq, ExportTimestamp: now.UnixMilli(),
	})
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
func (s *gnmiServer) Get(ctx context.Context, req *gnmipb.GetRequest) (resp *gnmipb.GetResponse, err error) {
	// pprof label for the RPC's duration (nl6#635): gRPC handler goroutines
	// are shared, so the label is scoped to the call.
	withSubsystem(ctx, subsystemGNMI, func(context.Context) {
		resp, err = s.getLabelled(req)
	})
	return resp, err
}

// getLabelled is Get's body; see the wrap above.
func (s *gnmiServer) getLabelled(req *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
	enc := req.GetEncoding()
	catEnc := enc
	if s.catalog != nil {
		var err error
		if catEnc, err = s.catalogEncoding(enc); err != nil {
			return nil, err
		}
	}
	if !encodingSupported(enc) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported encoding %v", enc)
	}
	// DF2: honour `GetRequest.type`. The interface surface is state-only, but
	// the optical surface has a real `config/` subtree (the four optical-channel
	// scalars: frequency, target-output-power, operational-mode, line-port), so
	// the filter cannot be a blanket "CONFIG → empty" any more — that would
	// return nothing for a config path the resolver serves, and would leak the
	// config leaves into a STATE request.
	//
	// STATE and OPERATIONAL keep only state leaves; CONFIG keeps only config
	// leaves; ALL (the default) keeps everything. The simulator does not
	// distinguish operational from state internally.
	prefixElems := req.GetPrefix().GetElem()
	now := time.Now()
	notifs := make([]*gnmipb.Notification, 0, len(req.GetPath()))
	for _, p := range req.GetPath() {
		full := joinPathPrefix(prefixElems, p)
		if s.catalog != nil {
			full = s.catalog.Canonicalize(full)
		}
		if s.catalog != nil && s.catalog.Match(full) {
			cn, err := s.catalog.Resolve(full, now)
			if err != nil {
				return nil, err
			}
			for _, n := range cn {
				ups, err := encodeUpdates(filterByGetType(n.Updates, req.GetType()), catEnc)
				if err != nil {
					return nil, err
				}
				if len(ups) == 0 {
					continue
				}
				notifs = append(notifs, &gnmipb.Notification{Timestamp: now.UnixNano(), Prefix: n.Prefix, Update: ups})
			}
			continue
		}
		updates, err := s.resolver.Resolve(full, now)
		if err != nil {
			return nil, err
		}
		filtered := filterByGetType(updates, req.GetType())
		if len(filtered) == 0 && len(updates) > 0 {
			// The type filter removed everything this path had — e.g. CONFIG
			// against the state-only interface surface. Emit no notification at
			// all rather than an empty one: it carries no information, and it
			// keeps the pre-optical behaviour ("CONFIG returns an empty
			// response") byte-identical for paths with no config leaves.
			continue
		}
		gnmiUpdates, err := encodeUpdates(filtered, enc)
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

// filterByGetType applies `GetRequest.type` (gNMI §3.3.1) to a resolved
// update set. It keys off the `config`/`state` element present in every
// served path — the interface branch always emits `state`, the optical
// branch emits both — so the filter needs no per-leaf table and cannot
// drift from what the resolver serves. A path with neither element is
// state: catalogue leaves under a list-entry prefix are relative, and a
// leaf such as `instant` under a `.../state/temperature` prefix carries
// no `state` element of its own.
//
// ALL (the proto default, value 0) returns everything, so the common
// unfiltered request stays allocation-free.
func filterByGetType(updates []resolvedUpdate, typ gnmipb.GetRequest_DataType) []resolvedUpdate {
	var want string
	switch typ {
	case gnmipb.GetRequest_CONFIG:
		want = "config"
	case gnmipb.GetRequest_STATE, gnmipb.GetRequest_OPERATIONAL:
		want = "state"
	default: // ALL
		return updates
	}
	out := make([]resolvedUpdate, 0, len(updates))
	for _, u := range updates {
		kind := "state"
		for _, e := range u.Path.GetElem() {
			if name := e.GetName(); name == "config" || name == "state" {
				kind = name
				break
			}
		}
		if kind == want {
			out = append(out, u)
		}
	}
	return out
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
func (s *gnmiServer) Subscribe(stream gnmipb.GNMI_SubscribeServer) (err error) {
	// pprof label for the stream's lifetime (nl6#635); see Get.
	withSubsystem(stream.Context(), subsystemGNMI, func(context.Context) {
		err = s.subscribeLabelled(stream)
	})
	return err
}

// subscribeLabelled is Subscribe's body; see the wrap above.
func (s *gnmiServer) subscribeLabelled(stream gnmipb.GNMI_SubscribeServer) error {
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
	// Catalogue gate: a device with a catalogue refuses an encoding the
	// catalogue excludes on every path. Legacy subscriptions keep the
	// client encoding; catalogue ones use catEnc.
	catEnc := enc
	if s.catalog != nil {
		var err error
		if catEnc, err = s.catalogEncoding(enc); err != nil {
			return err
		}
	}
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
	if s.catalog != nil {
		// Rewrite aliased origins once, before any dispatch, so the
		// catalogue and the legacy resolver behind it agree.
		for i, sub := range subs {
			if cp := s.catalog.Canonicalize(sub.GetPath()); cp != sub.GetPath() {
				subs[i] = &gnmipb.Subscription{
					Path:              cp,
					Mode:              sub.GetMode(),
					SampleInterval:    sub.GetSampleInterval(),
					SuppressRedundant: sub.GetSuppressRedundant(),
					HeartbeatInterval: sub.GetHeartbeatInterval(),
				}
			}
		}
	}

	// ON_CHANGE is not served on catalogue paths.
	if s.catalog != nil && sl.GetMode() == gnmipb.SubscriptionList_STREAM {
		for _, sub := range subs {
			if sub.GetMode() == gnmipb.SubscriptionMode_ON_CHANGE && s.catalog.Match(sub.GetPath()) {
				return status.Error(codes.Unimplemented, "ON_CHANGE is not supported for catalogue paths in this release")
			}
		}
	}
	cs := s.catalogStream(catEnc)

	// Count both ONCE and STREAM streams in active_subscriptions (P16):
	// from the operator's perspective they're both live gNMI streams
	// that consume server-side resources for the duration of the call.
	atomic.AddInt64(s.activeSubscriptions, 1)
	defer atomic.AddInt64(s.activeSubscriptions, -1)

	// ONCE: send one batch + sync_response, return. ONCE ignores
	// per-sub mode (ON_CHANGE/SAMPLE are STREAM-only concepts).
	if sl.GetMode() == gnmipb.SubscriptionList_ONCE {
		return runOnceSubscribe(stream, s.resolver, cs, subs, enc, s.updatesSent)
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
		return runStreamSubscribe(stream, s.resolver, cs, subs, enc, s.updatesSent, s.updatesDropped)
	}
}

// catalogStream bundles what the subscribe loops need to serve
// catalogue paths on one stream, or returns nil for a legacy device.
func (s *gnmiServer) catalogStream(enc gnmipb.Encoding) *catalogSubscription {
	if s.catalog == nil {
		return nil
	}
	// One sensor name per stream, as Junos does (every response of a
	// vJunos subscription carried the same sensor_NNNN_3_1).
	sensor := fmt.Sprintf("sensor_%d_1_1", 1000+s.catalogStreams.Add(1)%1000)
	return &catalogSubscription{
		resolver: s.catalog,
		enc:      enc,
		extFor: func(subscribed, streamed string, seq uint64, now time.Time) *gnmi_ext.Extension {
			return s.catalogExtension(sensor, subscribed, streamed, seq, now)
		},
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

// gnmiEncodingJSONVal is an internal sentinel: encode exactly as
// JSON_IETF but carry the bytes in `json_val`, which is what Junos
// returns for a JSON subscription. Never advertised; the catalogue
// server maps a client's Encoding_JSON to it (catalogEncoding).
const gnmiEncodingJSONVal gnmipb.Encoding = -1

// gnmiEncodeTypedValue encodes a single Go value into a gNMI TypedValue.
// Supported Go types: string, uint32, uint64, int64, bool, gnmiDecimal. Other types are a
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
		case bool:
			return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_BoolVal{BoolVal: x}}, nil
		case int64:
			return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: x}}, nil
		case gnmiDecimal:
			// double_val, not string_val: a decimal encoded as a string
			// would be a type error for the client. Not decimal_val
			// either — that field is deprecated in gNMI.
			//
			// Lossy for high-precision values (an 18-fraction-digit BER
			// exceeds a float64 significand); JSON_IETF preserves them.
			return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: x.val}}, nil
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
	case bool:
		b, err = json.Marshal(x)
	case int64:
		// RFC 7951: int64 is a JSON string.
		b, err = json.Marshal(strconv.FormatInt(x, 10))
	case gnmiDecimal:
		// RFC 7951 §6.1: decimal64 is a JSON string, so the full
		// declared precision survives (unlike a JSON number, which a
		// client would parse back through a float64).
		b, err = json.Marshal(x.String())
	default:
		return nil, status.Errorf(codes.Internal, "unsupported value type %T for JSON_IETF encoding", v)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "json marshal: %v", err)
	}
	if enc == gnmiEncodingJSONVal {
		return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonVal{JsonVal: b}}, nil
	}
	return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: b}}, nil
}
