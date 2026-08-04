/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Per-device SNMP trap / INFORM exporter.
//
// One TrapExporter per DeviceSimulator owns the device's UDP socket, request-id
// counter, pending-inform state, and shares a TrapEncoder with the scheduler.
// The scheduler calls Fire() to emit a scheduled trap; the HTTP endpoint also
// calls Fire() for on-demand traps. INFORM mode additionally starts a reader
// goroutine (for ack demux on the per-device socket) and a retry goroutine
// (wakes on pending-inform timeouts and retransmits).
//
// Design references: design.md §D5 (INFORM demux via per-device socket), §D6
// (bounded pending map with oldest-drop), §D7 (retries consume global-cap
// tokens). See also spec.md for SHALL requirements exercised here.

package main

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// TrapMode selects between fire-and-forget traps and ack'd informs.
type TrapMode int

const (
	TrapModeTrap   TrapMode = iota // SNMPv2-Trap-PDU, no ack
	TrapModeInform                 // InformRequest-PDU, expects GetResponse-PDU
)

// DefaultInformPendingCap is the maximum per-device pending-inform queue size
// before oldest-drop kicks in (design.md §D6). Exposed as a constant so tests
// can drive overflow scenarios predictably.
const DefaultInformPendingCap = 100

// TrapStats holds cumulative counters for the exporter. All fields are atomic
// so they're safe to read concurrently with Fire / retry / reader loops.
type TrapStats struct {
	// Sent counts every datagram written to the wire including retries.
	Sent atomic.Uint64
	// InformsOriginated counts the number of distinct INFORMs ever started
	// (not counting retransmissions). Used for the invariant
	// informsPending + informsAcked + informsFailed + informsDropped ==
	// informsOriginated. Exposed for tests; not part of the public status API.
	InformsOriginated atomic.Uint64
	InformsAcked      atomic.Uint64
	InformsFailed     atomic.Uint64
	InformsDropped    atomic.Uint64
}

// pendingInform is one INFORM awaiting a collector ack.
type pendingInform struct {
	reqID    uint32
	pdu      []byte // retained for retransmission
	sentAt   time.Time
	deadline time.Time
	retries  int // number of retransmissions so far (0 = original send)
}

// TrapExporter is owned by one DeviceSimulator. Construct via NewTrapExporter
// and call StartBackgroundLoops to launch the reader and retry goroutines
// (INFORM mode only). Close shuts down the background loops and the socket.
type TrapExporter struct {
	deviceIP     net.IP
	community    string
	encoder      TrapEncoder
	mode         TrapMode
	collector    *net.UDPAddr
	collectorStr string // canonical "host:port" for status aggregation keying (review fix P1 pattern)

	// firstWriteErr gates at most one log line per exporter on a failed
	// WriteTo (review fix P6 pattern from phase 3).
	firstWriteErr sync.Once

	// countersPersisted ensures SimulatorManager.persistTrapCounters adds
	// this exporter's counters into the simulator-wide aggregate at most
	// once. Both `device.Stop()` / `device.stopListenersOnly()` and
	// `SimulatorManager.StopTrapExport` can invoke persistence; the
	// sync.Once makes the persist hot-path race-free without per-callsite
	// locking.
	countersPersisted sync.Once

	// limiter is the global rate limiter shared by all exporters and the
	// scheduler. Used here for retry-token consumption (design.md §D7).
	// Nil = no cap.
	limiter *rate.Limiter

	// conn is the per-device UDP socket. When non-nil it is used for BOTH
	// transmit and receive (ack demux relies on this — design.md §D5).
	// atomic.Pointer so Close / reader / Fire can observe writes safely.
	conn atomic.Pointer[net.UDPConn]

	// sharedConn is the fallback UDP socket used when per-device bind failed
	// (TRAP mode only; INFORM mode startup rejects this case). Read-only
	// after construction.
	sharedConn *net.UDPConn

	// fastEnc is encoder type-asserted to the allocation-free path, or nil
	// when the injected encoder does not implement it. Resolved once at
	// construction so the fire path does not repeat the assertion.
	fastEnc fastTrapEncoder

	// deviceIPStr is deviceIP.String() memoised at construction. The IP is
	// immutable for the exporter's lifetime, but buildCtx called String() on
	// every fire, which allocated.
	deviceIPStr string

	startTime time.Time
	nextReqID atomic.Uint32

	informTimeout time.Duration
	informRetries int
	pendingCap    int

	// pendingMu guards pending + pendingOrder. ack/retry/fire all contend.
	pendingMu    sync.Mutex
	pending      map[uint32]*pendingInform
	pendingOrder []uint32 // insertion order for oldest-drop on overflow

	stats *TrapStats

	// scenPart is the load-test scenario participation handle (nil = not
	// participating → byte-for-byte legacy behaviour). When set, every fire
	// funnels through fireWithSource and is gated + counted (FR15/FR17-20/23).
	// An INFORM origination counts `sent` at first-transmit (not per retry);
	// ack settlement is bumped onto the scenario ledger in resolveAck.
	scenPart atomic.Pointer[scenarioPart]

	// Template context sources. Class 1 device-context fields (SysName,
	// Model, Serial, ChassisID) are captured once at exporter construction
	// because they're stable for the device's lifetime; IfName varies with
	// IfIndex so it uses a callback (PR 3 swaps synthesis for live lookup).
	ifIndexFn func() int               // returns a random ifIndex from the device's set
	ifNameFn  func(ifIndex int) string // returns ifName for a drawn ifIndex
	sysName   string
	model     string
	serial    string
	chassisID string

	// Lifecycle
	closing  atomic.Bool
	stopCh   chan struct{}
	stopOnce sync.Once
	loopsWG  sync.WaitGroup
}

// TrapExporterOptions bundles per-device exporter configuration.
type TrapExporterOptions struct {
	DeviceIP      net.IP
	Community     string
	Encoder       TrapEncoder
	Mode          TrapMode
	Collector     *net.UDPAddr
	CollectorStr  string // canonical "host:port" string; used for status aggregation key
	Limiter       *rate.Limiter
	SharedConn    *net.UDPConn // fallback; may be nil. Wired post-construction by manager (see startDeviceTrapExporter)
	InformTimeout time.Duration
	InformRetries int
	PendingCap    int // 0 → DefaultInformPendingCap

	// IfIndexFn returns a random ifIndex value for template resolution. If
	// nil a stub returning 1 is used (acceptable for devices without
	// simulated interfaces, and for tests).
	IfIndexFn func() int

	// IfNameFn returns the interface name for a given ifIndex, used by
	// `{{.IfName}}` template resolution. If nil a synthesised
	// `GigabitEthernet0/<N>` is used.
	IfNameFn func(ifIndex int) string

	// Class 1 device-context fields captured at exporter construction.
	// Constant for the device's lifetime; consumed by `{{.SysName}}`,
	// `{{.Model}}`, `{{.Serial}}`, `{{.ChassisID}}` templates.
	SysName   string
	Model     string
	Serial    string
	ChassisID string
}

// NewTrapExporter builds a TrapExporter. The per-device conn is not opened
// here — the caller (device lifecycle) is expected to call SetConn once the
// socket is bound inside the device's network namespace. See also
// openTrapConnForDevice for the helper that performs the bind.
func NewTrapExporter(opts TrapExporterOptions) *TrapExporter {
	if opts.Encoder == nil {
		opts.Encoder = SNMPv2cEncoder{}
	}
	if opts.Community == "" {
		opts.Community = "public"
	}
	if opts.InformTimeout <= 0 {
		opts.InformTimeout = 5 * time.Second
	}
	if opts.InformRetries < 0 {
		opts.InformRetries = 0
	}
	if opts.PendingCap <= 0 {
		opts.PendingCap = DefaultInformPendingCap
	}
	if opts.IfIndexFn == nil {
		opts.IfIndexFn = func() int { return 1 }
	}
	if opts.IfNameFn == nil {
		opts.IfNameFn = synthIfName
	}
	fast, _ := opts.Encoder.(fastTrapEncoder)
	return &TrapExporter{
		deviceIP:      append(net.IP(nil), opts.DeviceIP...),
		deviceIPStr:   opts.DeviceIP.String(),
		fastEnc:       fast,
		community:     opts.Community,
		encoder:       opts.Encoder,
		mode:          opts.Mode,
		collector:     opts.Collector,
		collectorStr:  opts.CollectorStr,
		limiter:       opts.Limiter,
		sharedConn:    opts.SharedConn,
		startTime:     time.Now(),
		informTimeout: opts.InformTimeout,
		informRetries: opts.InformRetries,
		pendingCap:    opts.PendingCap,
		pending:       make(map[uint32]*pendingInform),
		pendingOrder:  make([]uint32, 0, opts.PendingCap+1),
		stats:         &TrapStats{},
		ifIndexFn:     opts.IfIndexFn,
		ifNameFn:      opts.IfNameFn,
		sysName:       opts.SysName,
		model:         opts.Model,
		serial:        opts.Serial,
		chassisID:     opts.ChassisID,
		stopCh:        make(chan struct{}),
	}
}

// SetConn installs the per-device UDP socket. Must be called before
// StartBackgroundLoops in INFORM mode (the reader loop needs it to demux
// acks). Passing nil unsets the socket — callers that need to rotate the
// socket should Close the exporter and create a new one.
func (e *TrapExporter) SetConn(c *net.UDPConn) {
	e.conn.Store(c)
}

// StartBackgroundLoops launches the reader and retry goroutines. In TRAP
// mode they're not needed (no acks to demux, no retries to schedule) so
// this is a no-op. In INFORM mode both goroutines run until Close is called.
// ctx, when cancelled, is an alternative to Close for shutdown (e.g. the
// SimulatorManager's shutdown context).
func (e *TrapExporter) StartBackgroundLoops(ctx context.Context) {
	if e.mode != TrapModeInform {
		return
	}
	e.loopsWG.Add(2)
	go e.readerLoop()
	go e.retryLoop(ctx)
}

// Stats returns a pointer to the exporter's atomic stats. The underlying
// counters are safe to read concurrently; the returned pointer is stable
// for the exporter's lifetime.
func (e *TrapExporter) Stats() *TrapStats { return e.stats }

// CollectorString returns the canonical "host:port" string identifying
// this exporter's destination. Used as the key for the shared-socket
// pool and for the status-endpoint aggregation.
func (e *TrapExporter) CollectorString() string { return e.collectorStr }

// Mode returns the exporter's PDU mode (TRAP or INFORM).
func (e *TrapExporter) Mode() TrapMode { return e.mode }

// logFirstWriteErr emits at most one log line per exporter on a failed
// WriteTo. Gated by fe.firstWriteErr so a down/misconfigured collector
// doesn't flood logs at fire cadence × device count.
func (e *TrapExporter) logFirstWriteErr(err error) {
	if e == nil || err == nil {
		return
	}
	e.firstWriteErr.Do(func() {
		log.Printf("trap export: device %s write to %s failed: %v (further errors suppressed for this exporter)",
			e.deviceIP, e.collectorStr, err)
	})
}

// PendingInformsLen returns the current size of the pending-inform map.
// Used by GET /api/v1/traps/status.
func (e *TrapExporter) PendingInformsLen() int {
	e.pendingMu.Lock()
	defer e.pendingMu.Unlock()
	return len(e.pending)
}

// Fire emits one trap or INFORM for the given catalog entry. Implements
// trapFirer for the scheduler. Safe for concurrent calls and safe to call on
// a closing exporter (silently no-ops). overrides, when non-nil, force
// specific template field values (used by POST /api/v1/devices/{ip}/trap).
//
// Returns the request-id used for this emission (0 on early-return). Callers
// that need the request-id (e.g. the HTTP handler) can record it; the
// scheduler ignores it.
func (e *TrapExporter) Fire(entry *CatalogEntry, overrides map[string]string) uint32 {
	return e.fireWithSource(entry, overrides, sourceOnDemand, -1)
}

// fireBackground / fireScenario are the scheduler entry points: the fleet trap
// scheduler fires background (suppressed for the scenario's lifetime), the
// scenario-owned trap ticker fires scenario (allowed + counted in [T0,T1)).
func (e *TrapExporter) fireBackground(entry *CatalogEntry, overrides map[string]string) uint32 {
	return e.fireWithSource(entry, overrides, sourceBackground, -1)
}

func (e *TrapExporter) fireScenario(entry *CatalogEntry, overrides map[string]string) uint32 {
	return e.fireWithSource(entry, overrides, sourceScenario, -1)
}

// fireWithSource is the single fire funnel carrying the scenario gate-check
// idiom (verbatim shape from syslog): one atomic scenPart load (nil =
// non-participant, byte-for-byte legacy), decide() per the source-flag matrix,
// drain admit, emitted at produce, and outcome bucketing inside fireWithCtx.
// ifIndex < 0 means "use ifIndexFn()".
func (e *TrapExporter) fireWithSource(entry *CatalogEntry, overrides map[string]string, src fireSource, ifIndex int) uint32 {
	if e == nil || entry == nil || e.closing.Load() {
		return 0
	}
	resolveIf := func() int {
		if ifIndex < 0 {
			return e.ifIndexFn()
		}
		return ifIndex
	}
	p := e.scenPart.Load()
	if p == nil {
		// Teardown straggler: same reasoning as SyslogExporter.fireWithSource —
		// a scenario-source fire whose handle is already nil-swapped must not
		// reach the wire uncounted.
		if src == sourceScenario {
			return 0
		}
		// Fidelity mode: silent outside a scenario window (see fidelity.go).
		if fidelityMutesBackground(src) {
			return 0
		}
		return e.fireWithCtx(entry, e.buildCtx(resolveIf(), entry.pre), overrides, nil)
	}
	switch p.decide(src, p.now()) {
	case gateSuppressSilent:
		return 0
	case gateSuppressCounted:
		p.ledger.emitted.Add(1)
		p.ledger.suppressedPreWindow.Add(1)
		return 0
	}
	if !p.drain.admit() {
		p.ledger.emitted.Add(1)
		p.ledger.dropped.Add(1)
		return 0
	}
	defer p.drain.leave()
	p.ledger.emitted.Add(1)
	return e.fireWithCtx(entry, e.buildCtx(resolveIf(), entry.pre), overrides, p)
}

// FireForInterface emits a trap for `entry` pinned to a SPECIFIC ifIndex (and
// its ifName) — used by the state-change notify hook so a correlated linkDown/
// linkUp names the interface that actually transitioned, not a random one.
// Like Fire it is safe on a closing exporter and does not consume a global-cap
// token (state-driven link traps bypass the Poisson cap on initial transmit).
func (e *TrapExporter) FireForInterface(entry *CatalogEntry, ifIndex int) uint32 {
	return e.fireWithSource(entry, nil, sourceStateDriven, ifIndex)
}

// buildCtx assembles the per-fire template context for a given ifIndex.
//
// pre, when non-nil, tells us which optional fields the entry's templates
// actually reference. NowLocal is the only one worth gating: it is a
// time.Time.Format, and almost no catalog entry uses it (CIENA-WS DateAndTime
// varbinds are the motivating case), so formatting it unconditionally spent
// real CPU and allocation on a string that was discarded. Every other field is
// either already memoised or a trivially cheap read.
func (e *TrapExporter) buildCtx(ifIndex int, pre *preEncodedEntry) TemplateCtx {
	now := time.Now()
	ctx := TemplateCtx{
		IfIndex:   ifIndex,
		IfName:    e.ifNameFn(ifIndex),
		Uptime:    e.uptimeHundredths(),
		Now:       now.Unix(),
		DeviceIP:  e.deviceIPStr,
		SysName:   e.sysName,
		Model:     e.model,
		Serial:    e.serial,
		ChassisID: e.chassisID,
	}
	// nil pre means "unknown" (on-demand fires with a hand-built entry, tests):
	// keep the old unconditional behaviour so a template can never see an empty
	// NowLocal it used to see populated.
	if pre == nil || pre.usesNowLocal {
		ctx.NowLocal = now.Format("2006-01-02 15:04:05")
	}
	return ctx
}

// trapBuf is one pooled PDU assembly buffer. Held behind a pointer so putting
// it back does not allocate the interface value on every fire.
type trapBuf struct{ b []byte }

// trapBufPool recycles PDU assembly buffers. The legacy path did
// `make([]byte, 1500)` per fire, which was 52 % of all trap-path allocation and
// the bulk of the GC time observed at saturation. Buffers are handed out to the
// emission workers, so a fire must not retain the slice past writePDU —
// registerPending already takes its own copy for retransmission.
var trapBufPool = sync.Pool{
	New: func() any { return &trapBuf{b: make([]byte, 0, maxTrapPDU)} },
}

// fireWithCtx is the shared encode/transmit body of Fire and FireForInterface,
// including the INFORM register-pending-before-write ordering and write-failure
// undo. Returns the request-id (0 on early return).
func (e *TrapExporter) fireWithCtx(entry *CatalogEntry, ctx TemplateCtx, overrides map[string]string, p *scenarioPart) uint32 {
	varbinds, err := entry.Resolve(ctx, overrides)
	if err != nil {
		log.Printf("trap: resolve %s for %s: %v", entry.Name, e.deviceIP, err)
		if p != nil {
			p.ledger.sendFailures.Add(1)
		}
		return 0
	}

	reqID := e.nextRequestID()

	// The buffer is pooled and the PDU slice aliases it, so it must be returned
	// only after the last read of pdu (writePDU, and registerPending's copy).
	buf := trapBufPool.Get().(*trapBuf)
	defer trapBufPool.Put(buf)

	var pdu []byte
	if e.fastEnc != nil {
		pdu, err = e.fastEnc.EncodeNotificationFast(buf.b, e.mode, e.community, reqID,
			entry.pre, entry.SnmpTrapOID, entry.SnmpTrapEnterprise, ctx.Uptime, varbinds)
		if err == nil {
			buf.b = pdu[:0] // retain the grown capacity for the next fire
		}
	} else {
		// Injected encoder without the fast path: assemble via the reference
		// encoder into the same pooled storage.
		scratch := buf.b[:cap(buf.b)]
		if len(scratch) < maxTrapPDU {
			scratch = make([]byte, maxTrapPDU)
			buf.b = scratch[:0]
		}
		// Clamp to maxTrapPDU: the pool is shared with the fast path, whose
		// transient growth can park a larger-capacity buffer here. Without the
		// clamp the reference encoder's "fits in buf" check would accept PDUs
		// past the documented 1500-byte limit, non-deterministically.
		scratch = scratch[:maxTrapPDU]
		var n int
		if e.mode == TrapModeInform {
			n, err = e.encoder.EncodeInform(e.community, reqID, entry.SnmpTrapOID, entry.SnmpTrapEnterprise, ctx.Uptime, varbinds, scratch)
		} else {
			n, err = e.encoder.EncodeTrap(e.community, reqID, entry.SnmpTrapOID, entry.SnmpTrapEnterprise, ctx.Uptime, varbinds, scratch)
		}
		pdu = scratch[:n]
	}
	if err != nil {
		log.Printf("trap: encode %s for %s: %v", entry.Name, e.deviceIP, err)
		if p != nil {
			p.ledger.sendFailures.Add(1)
		}
		return 0
	}

	// INFORM: register pending state BEFORE transmit so an ack that races
	// in between write and insert isn't lost.
	if e.mode == TrapModeInform {
		e.registerPending(reqID, pdu)
	}

	if !e.writePDU(pdu) {
		// Write failed; undo pending insert so counters stay coherent.
		if e.mode == TrapModeInform {
			e.pendingMu.Lock()
			if _, ok := e.pending[reqID]; ok {
				delete(e.pending, reqID)
				e.removeFromOrder(reqID)
				// Two's-complement decrement: adding (2^64 - 1) is equivalent
				// to subtracting 1 on uint64, which is the atomic decrement
				// idiom. Keeps the invariant
				//   pending + acked + failed + dropped == originated
				// coherent when the original Fire never made it to the wire.
				e.stats.InformsOriginated.Add(^uint64(0))
			}
			e.pendingMu.Unlock()
		}
		if p != nil {
			p.ledger.sendFailures.Add(1)
		}
		return 0
	}
	e.stats.Sent.Add(1)
	// Scenario accounting: count `sent` at write-return. For INFORM this is the
	// first-transmit origination (retries happen in the reader goroutine and
	// never re-enter fireWithCtx), so originations count exactly once.
	if p != nil {
		p.bucketFor(time.Now()).Add(1)
		if e.mode == TrapModeInform {
			p.ledger.informsOriginated.Add(1)
		}
	}
	return reqID
}

// writePDU sends pdu to the collector using the per-device socket (preferred)
// or the shared fallback. Returns true on success. On failure the last error
// observed is reported at most once per exporter via logFirstWriteErr so a
// down or misconfigured collector cannot flood logs at fire cadence × device
// count (review fix P8, mirrors flow-export phase-3 P6).
func (e *TrapExporter) writePDU(pdu []byte) bool {
	var lastErr error
	conn := e.conn.Load()
	if conn != nil {
		if _, err := conn.WriteToUDP(pdu, e.collector); err == nil {
			return true
		} else {
			lastErr = err
		}
		// Per-device write failed; try shared fallback.
	}
	if e.sharedConn != nil {
		if _, err := e.sharedConn.WriteToUDP(pdu, e.collector); err == nil {
			return true
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		e.logFirstWriteErr(lastErr)
	}
	return false
}

// registerPending inserts a pending-inform record and enforces the size cap.
// When the map is at capacity the OLDEST entry is dropped (design.md §D6).
func (e *TrapExporter) registerPending(reqID uint32, pdu []byte) {
	p := &pendingInform{
		reqID:    reqID,
		pdu:      append([]byte(nil), pdu...),
		sentAt:   time.Now(),
		deadline: time.Now().Add(e.informTimeout),
	}
	e.pendingMu.Lock()
	defer e.pendingMu.Unlock()
	// Overflow: drop oldest before insert.
	for len(e.pending) >= e.pendingCap && len(e.pendingOrder) > 0 {
		oldest := e.pendingOrder[0]
		e.pendingOrder = e.pendingOrder[1:]
		if _, ok := e.pending[oldest]; ok {
			delete(e.pending, oldest)
			e.stats.InformsDropped.Add(1)
		}
	}
	e.pending[reqID] = p
	e.pendingOrder = append(e.pendingOrder, reqID)
	e.stats.InformsOriginated.Add(1)
}

// removeFromOrder strips reqID from pendingOrder. O(n) — fine at pendingCap=100.
// Caller must hold pendingMu.
func (e *TrapExporter) removeFromOrder(reqID uint32) {
	for i, v := range e.pendingOrder {
		if v == reqID {
			e.pendingOrder = append(e.pendingOrder[:i], e.pendingOrder[i+1:]...)
			return
		}
	}
}

// nextRequestID allocates a non-zero request-id unique within this exporter's
// pending window (wraps on overflow, skipping zero).
func (e *TrapExporter) nextRequestID() uint32 {
	for {
		id := e.nextReqID.Add(1)
		if id != 0 {
			return id
		}
	}
}

// uptimeHundredths returns device uptime in 1/100-second ticks, matching
// SNMP TimeTicks semantics.
func (e *TrapExporter) uptimeHundredths() uint32 {
	return uint32(time.Since(e.startTime) / (10 * time.Millisecond))
}

// readerLoop demuxes inbound ack datagrams on the per-device socket. Exits
// on net.ErrClosed (Close) or on repeated unknown errors.
func (e *TrapExporter) readerLoop() {
	defer e.loopsWG.Done()
	conn := e.conn.Load()
	if conn == nil {
		return
	}
	buf := make([]byte, 1500)
	for {
		if e.closing.Load() {
			return
		}
		// Short read deadline so the loop can observe closing without
		// relying solely on net.ErrClosed (which a test exporter using an
		// unclosed conn wouldn't see).
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// ErrClosed etc.
			return
		}
		reqID, _, perr := e.encoder.ParseAck(buf[:n])
		if perr != nil {
			continue
		}
		e.resolveAck(reqID)
	}
}

// resolveAck marks the matching pending inform acknowledged, if one exists.
// Non-matching reqIDs (duplicate acks, stale responses) are silently ignored.
func (e *TrapExporter) resolveAck(reqID uint32) {
	e.pendingMu.Lock()
	defer e.pendingMu.Unlock()
	if _, ok := e.pending[reqID]; ok {
		delete(e.pending, reqID)
		e.removeFromOrder(reqID)
		e.stats.InformsAcked.Add(1)
		// Best-effort scenario ack settlement (FR: INFORM ack bucket). Bumped
		// only while a scenario owns this exporter; an ack that lands after
		// detach is simply not attributed (still-pending in the report).
		if p := e.scenPart.Load(); p != nil {
			p.ledger.informsAcked.Add(1)
		}
	}
}

// retryLoop wakes on informTimeout / 2 cadence, retransmits pending-inform
// records past their deadline (consuming limiter tokens — design.md §D7),
// and fails records that exhausted retry budget.
func (e *TrapExporter) retryLoop(ctx context.Context) {
	defer e.loopsWG.Done()
	// Tick at half the timeout so pending checks happen with reasonable
	// resolution without burning CPU.
	tickInterval := e.informTimeout / 2
	if tickInterval <= 0 {
		tickInterval = time.Second
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.checkPending(ctx)
		}
	}
}

// checkPending scans the pending-inform map, retries timed-out entries (up to
// informRetries times), and fails entries that exhausted the budget.
func (e *TrapExporter) checkPending(ctx context.Context) {
	if e.closing.Load() {
		return
	}
	now := time.Now()

	var toRetry []uint32
	var toFail []uint32
	e.pendingMu.Lock()
	for reqID, p := range e.pending {
		if now.Before(p.deadline) {
			continue
		}
		if p.retries < e.informRetries {
			toRetry = append(toRetry, reqID)
		} else {
			toFail = append(toFail, reqID)
		}
	}
	e.pendingMu.Unlock()

	// Fail first so we don't hand tokens to retries that are about to expire.
	for _, reqID := range toFail {
		e.pendingMu.Lock()
		if _, ok := e.pending[reqID]; ok {
			delete(e.pending, reqID)
			e.removeFromOrder(reqID)
			e.stats.InformsFailed.Add(1)
		}
		e.pendingMu.Unlock()
	}

	// Retry: consume one token per retransmission (design.md §D7).
	for _, reqID := range toRetry {
		if e.closing.Load() {
			return
		}
		if e.limiter != nil {
			if err := e.limiter.Wait(ctx); err != nil {
				return
			}
		}
		e.pendingMu.Lock()
		p, ok := e.pending[reqID]
		if !ok {
			// Acked between scan and retry.
			e.pendingMu.Unlock()
			continue
		}
		p.retries++
		p.sentAt = now
		p.deadline = now.Add(e.informTimeout)
		pdu := append([]byte(nil), p.pdu...)
		e.pendingMu.Unlock()

		if e.writePDU(pdu) {
			e.stats.Sent.Add(1)
		}
	}
}

// Close shuts down the reader and retry loops, closes the per-device socket,
// and waits for both goroutines to exit. Safe for concurrent Close / Fire.
func (e *TrapExporter) Close() error {
	if e == nil {
		return nil
	}
	e.closing.Store(true)
	e.stopOnce.Do(func() { close(e.stopCh) })

	conn := e.conn.Swap(nil)
	if conn != nil {
		_ = conn.Close() // unblocks ReadFromUDP in readerLoop
	}
	e.loopsWG.Wait()
	return nil
}

// openTrapConnForDevice opens a per-device UDP socket bound to the device's
// IP inside the nl6sim netns. Modeled on openFlowConnForDevice (see
// flow_exporter.go). Returns nil + logs on failure; the caller decides
// whether that's fatal (INFORM mode) or recoverable (TRAP mode falls back
// to the shared socket).
//
// Duplicated-not-shared with the flow equivalent per the pre-flight task 1.2
// decision: each subsystem owns its own socket lifecycle; sharing a helper
// would require adding subsystem-kind parameters and would still result in
// two separate sockets in practice.
func openTrapConnForDevice(device *DeviceSimulator) *net.UDPConn {
	if device == nil || device.netNamespace == nil {
		return nil
	}
	addr := &net.UDPAddr{IP: device.IP, Port: 0}
	conn, err := device.netNamespace.ListenUDPInNamespace(addr)
	if err != nil {
		log.Printf("trap export: device %s per-device bind failed: %v", device.IP, err)
		return nil
	}
	_ = conn.SetWriteBuffer(65536)
	_ = conn.SetReadBuffer(65536)
	return conn
}
