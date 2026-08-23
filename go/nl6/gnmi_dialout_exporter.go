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
	"google.golang.org/grpc"
)

// Dial-out reconnect backoff bounds. A broken Publish stream ends the RPC,
// so the exporter owns its own dial→publish retry loop (gRPC's transport
// backoff is not sufficient). Backoff resets to the floor after a stream
// stays up long enough to be considered established.
const (
	dialoutInitialBackoff = 1 * time.Second
	dialoutMaxBackoff     = 30 * time.Second
	// dialoutBackoffResetDwell is how long a stream must stay up before it
	// counts as "established" and the reconnect backoff is reset to the
	// floor. Without a dwell gate, a collector that accepts the stream then
	// immediately drops it would reset backoff every cycle and hot-reconnect
	// at the 1s floor forever.
	dialoutBackoffResetDwell = 30 * time.Second
)

// GnmiDialoutExporter owns one device's outbound gNMI dial-out session: a
// dedicated grpc.ClientConn and a single Publish stream (never a shared
// pool — one Go ClientConn caps at ~100 concurrent HTTP/2 streams). It runs
// its own goroutine that dials the collector, opens the flavor's stream,
// pumps SAMPLE-paced or ON_CHANGE-driven SubscribeResponses, and reconnects
// with capped backoff when the stream breaks. Telemetry is dropped (never
// buffered) during an outage, and a slow collector cannot stall the device
// (bounded send channel with drop-oldest).
type GnmiDialoutExporter struct {
	device       *DeviceSimulator
	resolver     *pathResolver
	transport    DialoutTransport
	collectorStr string
	flavor       string
	target       string // "passthrough:///<collector>" handed to the dialer
	// prefixTarget is stamped into Notification.Prefix.Target on every
	// pushed message (the device IP). Source-IP attribution works today
	// because each device dials from its own address, but in-band identity
	// makes dial-out usable by collectors that don't key on source address
	// and is the prerequisite for any future shared-transport mode. Same
	// job as the Arista gNMIReverse client's -target_value flag.
	prefixTarget string
	enc          gnmipb.Encoding
	mode         string // "sample" | "on-change"
	paths        []*gnmipb.Path
	sampleEvery  time.Duration
	dialOpts     []grpc.DialOption

	ctx      context.Context
	cancel   context.CancelFunc
	conn     atomic.Pointer[grpc.ClientConn]
	closing  atomic.Bool
	stopOnce sync.Once
	wg       sync.WaitGroup

	// everConnected is touched only by the run goroutine (streamOnce is
	// called from run): true once any stream has been established. Gates
	// statReconnects so the counter ticks at the moment a stream is
	// RE-established — not one stream-lifetime later when it ends.
	everConnected bool

	// countersPersisted guards the single fold of this exporter's counters
	// into the manager-level aggregate (double-count hazard otherwise).
	countersPersisted sync.Once

	// firstResolveLog gates snapshot resolve/encode error logging to once
	// per exporter, so a persistently-failing path can't flood logs at tick
	// cadence × device count (matches flow_exporter's log-once discipline).
	firstResolveLog sync.Once
	// firstDialLog gates dial/stream error logging to once per exporter. A
	// down collector otherwise logs at reconnect-backoff cadence × device
	// count (~1000 lines/s at 30k devices); reconnect progress is observable
	// via the status endpoint's reconnects / streams_active instead.
	firstDialLog sync.Once

	// Stat counters (atomic; house style is plain integers + sync/atomic).
	statUpdatesSent    uint64
	statUpdatesDropped uint64
	statReconnects     uint64
	statSendFailures   uint64
	statStreamsActive  int64

	// scenPart is the load-test scenario participation handle (nil = not
	// participating → byte-for-byte legacy behaviour). When set, both
	// producers (pushSnapshot / pushChange) are gated (FR15/FR17): pre-T0 and
	// post-window notifications are suppressed (no update flows); in-window a
	// notification counts `sent` when the Publish stream is live at produce,
	// or `send_failures` when it is not (a collector blip is visible, never
	// masked — dial-out `sent` = written to a live stream, FR20).
	scenPart atomic.Pointer[scenarioPart]
}

// streamLive reports whether a Publish stream is currently established — the
// dial-out analogue of "a socket to write to".
func (e *GnmiDialoutExporter) streamLive() bool {
	return e.conn.Load() != nil && atomic.LoadInt64(&e.statStreamsActive) > 0
}

// scenarioGate applies the scenario gate to one about-to-be-pushed
// notification (called just before enqueue, once the payload is known so
// resolve-empty pushes are not counted). It returns whether to enqueue and a
// leave() the caller must defer. Counting is synchronous: emitted at produce,
// then sent (stream live) or send_failures (stream down); the brief drain
// admit/leave lets finalize outlast an in-flight produce without waiting on
// the async Send.
func (e *GnmiDialoutExporter) scenarioGate(now time.Time) (enqueue bool, leave func()) {
	part := e.scenPart.Load()
	if part == nil {
		// Fidelity mode: no autonomous dial-out outside a scenario window.
		// Through the shared predicate for the same reason as the flow tick:
		// one rule for all four subsystems. A dial-out push is autonomous (it
		// is a stream, never an operator action), so sourceBackground is the
		// honest classification and behaviour is unchanged.
		if fidelityMutesBackground(sourceBackground) {
			return false, func() {}
		}
		return true, func() {} // non-participant: legacy passthrough
	}
	switch part.decide(sourceScenario, now) {
	case gateSuppressSilent, gateSuppressCounted:
		part.ledger.backgroundSuppressed.Add(1) // no update flows pre-T0/post-window
		return false, func() {}
	}
	if !part.drain.admit() {
		part.ledger.emitted.Add(1)
		part.ledger.dropped.Add(1)
		return false, func() {}
	}
	part.ledger.emitted.Add(1)
	if !e.streamLive() {
		part.ledger.sendFailures.Add(1) // collector down/blip — visible as a failure
		part.drain.leave()
		return false, func() {}
	}
	part.bucketFor(now).Add(1) // written to a live stream
	return true, part.drain.leave
}

// NewGnmiDialoutExporter constructs an exporter. collectorStr is the
// "host:port" used both as the status key and the gRPC target. dialOpts carry
// the transport credentials and (when namespaced) the per-device dialer that
// resolves in the host netns and makes the source IP equal the device IP.
// Callers use SimulatorManager.startDeviceGnmiDialoutExporter.
func NewGnmiDialoutExporter(device *DeviceSimulator, collectorStr, flavor string,
	transport DialoutTransport, enc gnmipb.Encoding, mode string,
	paths []*gnmipb.Path, sampleEvery time.Duration, dialOpts []grpc.DialOption) *GnmiDialoutExporter {
	prefixTarget := ""
	if device != nil && device.IP != nil {
		prefixTarget = device.IP.String()
	}
	return &GnmiDialoutExporter{
		device:       device,
		resolver:     newPathResolver(device),
		transport:    transport,
		collectorStr: collectorStr,
		flavor:       flavor,
		prefixTarget: prefixTarget,
		// passthrough:/// hands the literal host:port to our dialer as the
		// target, keeping the hostname as the gRPC authority (so TLS
		// ServerName verifies against it); the namespace dialer resolves the
		// name in the host netns and connects to the IP.
		target:      "passthrough:///" + collectorStr,
		enc:         enc,
		mode:        mode,
		paths:       paths,
		sampleEvery: sampleEvery,
		dialOpts:    dialOpts,
	}
}

// Start launches the exporter's background dial/publish loop. Safe to call
// once per exporter.
func (e *GnmiDialoutExporter) Start() {
	e.ctx, e.cancel = context.WithCancel(context.Background())
	e.wg.Add(1)
	go e.run()
}

// Close stops the exporter: cancels the loop, waits for the goroutine to
// exit, and closes any live ClientConn. Idempotent and safe to call
// concurrently with the run loop (cancel + atomic Swap).
func (e *GnmiDialoutExporter) Close() error {
	if e == nil {
		return nil
	}
	e.closing.Store(true)
	e.stopOnce.Do(func() {
		if e.cancel != nil {
			e.cancel()
		}
	})
	e.wg.Wait()
	if cc := e.conn.Swap(nil); cc != nil {
		return cc.Close()
	}
	return nil
}

// run is the dial→publish→reconnect loop. It exits only when Close cancels
// the context.
func (e *GnmiDialoutExporter) run() {
	defer e.wg.Done()
	backoff := dialoutInitialBackoff
	for {
		if e.closing.Load() || e.ctx.Err() != nil {
			return
		}

		cc, err := grpc.NewClient(e.target, e.dialOpts...)
		if err != nil {
			e.logDialErr("dial", err)
			if !e.sleep(&backoff) {
				return
			}
			continue
		}
		e.conn.Store(cc)

		openedAt, streamErr := e.streamOnce(cc)
		e.conn.Store(nil)
		_ = cc.Close()

		if e.closing.Load() || e.ctx.Err() != nil {
			return
		}
		if !openedAt.IsZero() {
			// Reset backoff only if the stream stayed up long enough to be
			// considered established. openedAt is stamped AFTER OpenStream
			// succeeds, so dial time and dial-semaphore queueing do not count
			// toward the dwell — otherwise an accept-then-drop collector plus
			// slow dials could keep resetting to the 1s floor.
			// (statReconnects is counted inside streamOnce at stream-open.)
			if time.Since(openedAt) >= dialoutBackoffResetDwell {
				backoff = dialoutInitialBackoff
			}
			e.logDialErr("stream ended, reconnecting", streamErr)
		} else {
			e.logDialErr("open stream", streamErr)
		}
		if !e.sleep(&backoff) {
			return
		}
	}
}

// streamOnce opens the flavor's Publish stream and pumps responses until
// the stream breaks or the context is cancelled. Returns the non-zero time
// the stream was established (so the caller can count a reconnect and
// measure the backoff-reset dwell from stream-open, not dial-start); a zero
// time means the stream never opened. A bounded send channel + drop-oldest
// ensures a slow collector never blocks the producer.
func (e *GnmiDialoutExporter) streamOnce(cc *grpc.ClientConn) (openedAt time.Time, err error) {
	streamCtx, cancel := context.WithCancel(e.ctx)
	defer cancel()

	stream, err := e.transport.OpenStream(streamCtx, cc)
	if err != nil {
		return time.Time{}, err
	}
	openedAt = time.Now()
	// Count a reconnect at the moment a stream is RE-established (not the
	// first stream, not failed opens) so status reflects the reconnection
	// when it happens rather than when the new stream later ends.
	if e.everConnected {
		atomic.AddUint64(&e.statReconnects, 1)
	}
	e.everConnected = true
	atomic.AddInt64(&e.statStreamsActive, 1)
	defer atomic.AddInt64(&e.statStreamsActive, -1)

	ch := make(chan *gnmipb.SubscribeResponse, subscribeBufferDepth)
	var sendErr error
	var sender sync.WaitGroup
	sender.Add(1)
	go func() {
		defer sender.Done()
		// Cancel the stream context when the sender exits so the producer
		// stops enqueuing.
		defer cancel()
		for {
			select {
			case <-streamCtx.Done():
				return
			case resp, ok := <-ch:
				if !ok {
					return
				}
				if serr := stream.Send(resp); serr != nil {
					atomic.AddUint64(&e.statSendFailures, 1)
					sendErr = serr
					return
				}
				if upd := resp.GetUpdate(); upd != nil {
					atomic.AddUint64(&e.statUpdatesSent, uint64(len(upd.GetUpdate())))
				}
			}
		}
	}()

	// Producer runs on this goroutine and blocks until streamCtx is done.
	if e.mode == "on-change" {
		e.produceOnChange(streamCtx, ch)
	} else {
		e.produceSample(streamCtx, ch)
	}
	// Producer is the sole writer; close after it returns so the sender can
	// drain and exit cleanly.
	close(ch)
	sender.Wait()
	_ = stream.CloseSend()
	return openedAt, sendErr
}

// produceSample pushes an initial snapshot then re-resolves every path on a
// fixed ticker (clamped to a 1s floor). Reuses the dial-in resolver so
// values match dial-in byte-for-byte at the same instant.
func (e *GnmiDialoutExporter) produceSample(ctx context.Context, ch chan *gnmipb.SubscribeResponse) {
	interval := clampSampleInterval(e.sampleEvery)
	e.pushSnapshot(ctx, ch)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.pushSnapshot(ctx, ch)
		}
	}
}

// produceOnChange pushes an initial snapshot then emits on interface-state
// transitions via the InterfaceState listener fan-out — the same source
// dial-in ON_CHANGE uses, so the two agree at the same instant.
func (e *GnmiDialoutExporter) produceOnChange(ctx context.Context, ch chan *gnmipb.SubscribeResponse) {
	var state *InterfaceState
	if e.device != nil && e.device.metricsCycler != nil {
		if ic := e.device.metricsCycler.ifCounters.Load(); ic != nil {
			state = ic.State()
		}
	}

	// Register the listener BEFORE the initial snapshot (matching the dial-in
	// ON_CHANGE handler): a transition racing between the snapshot read and
	// AddListener would otherwise be lost, and dial-out never re-polls. At
	// worst the client sees a harmless duplicate of the snapshot value.
	var sc chan StateChange
	if state != nil {
		sc = make(chan StateChange, onChangeBufferDepth)
		state.AddListener(sc)
		defer state.RemoveListener(sc)
	}

	e.pushSnapshot(ctx, ch)

	if state == nil {
		<-ctx.Done()
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-sc:
			e.pushChange(ctx, ch, evt)
		}
	}
}

// pushSnapshot resolves every configured path at "now" into one
// Notification and enqueues it (drop-oldest on a full channel).
func (e *GnmiDialoutExporter) pushSnapshot(ctx context.Context, ch chan *gnmipb.SubscribeResponse) {
	now := time.Now()
	var resolved []resolvedUpdate
	for _, p := range e.paths {
		updates, err := e.resolver.Resolve(p, now)
		if err != nil {
			e.logResolveErr("resolve", p, err)
			continue
		}
		resolved = append(resolved, updates...)
	}
	if len(resolved) == 0 {
		return
	}
	// Encode once across all paths (matches pushChange), then push.
	gu, err := encodeUpdates(resolved, e.enc)
	if err != nil {
		e.logResolveErr("encode", nil, err)
		return
	}
	enqueue, leave := e.scenarioGate(now)
	defer leave()
	if !enqueue {
		return
	}
	pushOrDrop(ctx, ch, e.notification(now, gu), &e.statUpdatesDropped)
}

// notification wraps notificationResponse and stamps the device identity
// into Notification.Prefix.Target. Dial-out only — the dial-in Subscribe
// paths keep the shared prefix-less notificationResponse so their wire
// output is unchanged (servers echo a client-set target, they don't
// invent one).
func (e *GnmiDialoutExporter) notification(now time.Time, updates []*gnmipb.Update) *gnmipb.SubscribeResponse {
	resp := notificationResponse(now, updates)
	if e.prefixTarget != "" {
		resp.GetUpdate().Prefix = &gnmipb.Path{Target: e.prefixTarget}
	}
	return resp
}

// deviceLabel returns the device's IP for log lines — the discriminating
// datum on a 30k-device fleet (every sibling exporter logs device.IP).
func (e *GnmiDialoutExporter) deviceLabel() string {
	if e.device != nil && e.device.IP != nil {
		return e.device.IP.String()
	}
	return "?"
}

// logResolveErr logs a resolve/encode failure at most once per exporter.
// A persistently-failing path (typo'd name, uninitialized counters) would
// otherwise log at the SAMPLE tick cadence × device count.
func (e *GnmiDialoutExporter) logResolveErr(kind string, p *gnmipb.Path, err error) {
	e.firstResolveLog.Do(func() {
		log.Printf("gnmi dial-out: device %s → %s: %s %q failed: %v (skipping; further errors suppressed for this exporter)",
			e.deviceLabel(), e.collectorStr, kind, pathToString(p), err)
	})
}

// pushChange builds and enqueues a Notification for the leaves affected by
// a single state transition, filtered against every configured path.
func (e *GnmiDialoutExporter) pushChange(ctx context.Context, ch chan *gnmipb.SubscribeResponse, evt StateChange) {
	if evt.Changed == 0 || e.device == nil || e.device.metricsCycler == nil {
		return
	}
	ic := e.device.metricsCycler.ifCounters.Load()
	if ic == nil {
		return
	}
	now := time.Now()
	tSec := now.Sub(ic.startTime).Seconds()
	combined := make([]resolvedUpdate, 0, len(e.paths))
	for _, p := range e.paths {
		ups, err := changedUpdatesForPath(e.resolver, ic, p, evt, tSec)
		if err != nil {
			// Skip this path but surface the failure once — a silently
			// erroring path would otherwise stop contributing ON_CHANGE
			// updates for the exporter's lifetime with zero observability.
			e.logResolveErr("on-change resolve", p, err)
			continue
		}
		combined = append(combined, ups...)
	}
	if len(combined) == 0 {
		return
	}
	gu, err := encodeUpdates(combined, e.enc)
	if err != nil {
		e.logResolveErr("on-change encode", nil, err)
		return
	}
	enqueue, leave := e.scenarioGate(now)
	defer leave()
	if !enqueue {
		return
	}
	pushOrDrop(ctx, ch, e.notification(now, gu), &e.statUpdatesDropped)
}

// notificationResponse wraps updates into a SubscribeResponse{update}.
func notificationResponse(now time.Time, updates []*gnmipb.Update) *gnmipb.SubscribeResponse {
	return &gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_Update{
			Update: &gnmipb.Notification{
				Timestamp: now.UnixNano(),
				Update:    updates,
			},
		},
	}
}

// sleep waits for the current backoff or context cancellation, then doubles
// the backoff up to the cap. Returns false if the context was cancelled.
func (e *GnmiDialoutExporter) sleep(backoff *time.Duration) bool {
	t := time.NewTimer(*backoff)
	defer t.Stop()
	select {
	case <-e.ctx.Done():
		return false
	case <-t.C:
	}
	if *backoff < dialoutMaxBackoff {
		*backoff *= 2
		if *backoff > dialoutMaxBackoff {
			*backoff = dialoutMaxBackoff
		}
	}
	return true
}

// logDialErr logs the first dial/stream error per exporter (log-once,
// like the resolve path), so a down collector doesn't flood logs at
// reconnect cadence × device count. Suppressed during teardown.
func (e *GnmiDialoutExporter) logDialErr(what string, err error) {
	if e.closing.Load() {
		return
	}
	e.firstDialLog.Do(func() {
		log.Printf("gnmi dial-out: device %s → %s: %s: %v (further dial errors suppressed for this exporter)",
			e.deviceLabel(), e.collectorStr, what, err)
	})
}
