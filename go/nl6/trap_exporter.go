/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
	return &TrapExporter{
		deviceIP:      append(net.IP(nil), opts.DeviceIP...),
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
	if e == nil || entry == nil || e.closing.Load() {
		return 0
	}

	ifIndex := e.ifIndexFn()
	ctx := TemplateCtx{
		IfIndex:   ifIndex,
		IfName:    e.ifNameFn(ifIndex),
		Uptime:    e.uptimeHundredths(),
		Now:       time.Now().Unix(),
		DeviceIP:  e.deviceIP.String(),
		SysName:   e.sysName,
		Model:     e.model,
		Serial:    e.serial,
		ChassisID: e.chassisID,
	}
	varbinds, err := entry.Resolve(ctx, overrides)
	if err != nil {
		log.Printf("trap: resolve %s for %s: %v", entry.Name, e.deviceIP, err)
		return 0
	}

	reqID := e.nextRequestID()
	buf := make([]byte, 1500)

	var n int
	if e.mode == TrapModeInform {
		n, err = e.encoder.EncodeInform(e.community, reqID, entry.SnmpTrapOID, entry.SnmpTrapEnterprise, ctx.Uptime, varbinds, buf)
	} else {
		n, err = e.encoder.EncodeTrap(e.community, reqID, entry.SnmpTrapOID, entry.SnmpTrapEnterprise, ctx.Uptime, varbinds, buf)
	}
	if err != nil {
		log.Printf("trap: encode %s for %s: %v", entry.Name, e.deviceIP, err)
		return 0
	}
	pdu := buf[:n]

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
		return 0
	}
	e.stats.Sent.Add(1)
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
// IP inside the opensim netns. Modeled on openFlowConnForDevice (see
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
