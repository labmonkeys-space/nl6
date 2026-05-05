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

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FlowEncoder is the protocol-agnostic interface satisfied by the NetFlow v5,
// NetFlow v9, IPFIX, and sFlow encoders. uptimeMs is the device uptime in
// milliseconds at export time; IPFIX encoders may use it to compute absolute
// timestamps.
type FlowEncoder interface {
	EncodePacket(domainID uint32, seqNo uint32, uptimeMs uint32,
		records []FlowRecord, includeTemplate bool, buf []byte) (int, error)
	// PacketSizes returns the three per-packet size constants that Tick() needs
	// to compute batch capacity correctly for fixed-size record protocols:
	//   baseOverhead — message/packet header + data-set/flowset header (bytes)
	//   templateSize — template set/flowset byte length
	//   recordSize   — bytes per flow record on the wire
	//
	// For encoders that produce variable-length records (e.g. sFlow), recordSize
	// is advisory — Tick() consults MaxRecordSize() to pick a safe worst-case
	// paginator bound instead of dividing buffer space by recordSize.
	PacketSizes() (baseOverhead int, templateSize int, recordSize int)
	// SeqIncrement returns how much to advance the flow-sequence counter after
	// a packet carrying packetRecordCount data records. NetFlow v9 and IPFIX
	// return 1 (RFC 3954 "sequence number of all export packets" / RFC 7011
	// "per-SCTP-stream message count"). NetFlow v5 returns packetRecordCount
	// because Cisco v5 defines flow_sequence as the cumulative count of
	// records, not packets.
	SeqIncrement(packetRecordCount int) int
	// MaxRecordSize returns the worst-case on-wire byte size of a single record
	// for variable-length protocols. Fixed-size encoders (NetFlow v5 / v9,
	// IPFIX) return 0 and keep the existing PacketSizes()-driven pagination.
	// A non-zero return opts into variable-length pagination in Tick().
	MaxRecordSize() int
}

// FlowTickStats holds per-tick export counters returned by Tick.
// tickAllFlowExporters sums these across all devices and adds them to the
// cumulative atomic counters on SimulatorManager.
type FlowTickStats struct {
	PacketsSent    uint64
	BytesSent      uint64
	RecordsSent    uint64
	LastTemplateMs int64 // unix ms of the most-recent template send this tick; 0 if none
}

// FlowExporter is owned by one DeviceSimulator. It ties the FlowCache and
// encoder together and is driven by the shared SimulatorManager ticker goroutine.
// It has no goroutines of its own — see SimulatorManager.startFlowTicker.
//
// The optional per-device conn (set by the device lifecycle when
// flowSourcePerDevice is enabled) lets each exporter send UDP packets with
// a source IP matching the simulated device, so collectors like OpenNMS
// Telemetryd can attribute flows to the correct node. When conn is nil,
// Tick falls back to the shared-socket pool (one entry per (collector,
// protocol) tuple) via `SimulatorManager.flowConnFor`.
//
// As of the per-device-export-config refactor, the exporter owns its
// protocol / encoder / collector address and cumulative stat counters
// instead of pulling them from the manager at tick time. That keeps
// heterogeneous fleets coherent: devices pointing at different collectors
// or using different protocols tick independently through the same
// goroutine.
type FlowExporter struct {
	cache            *FlowCache
	profile          *FlowProfile
	rng              *rand.Rand
	seqNo            uint32
	domainID         uint32    // device IPv4 as uint32 (RFC 7011 §3.1)
	startTime        time.Time // reference point for SysUptime
	lastTempl        time.Time // last template transmission time
	templateInterval time.Duration

	// Per-device wire configuration (owned by the exporter, not the manager).
	// collectorStr keeps the human-readable "host:port" for status reporting;
	// collectorAddr is the resolved *net.UDPAddr used for WriteTo. protocol
	// is the canonicalised name ("netflow9" / "ipfix" / "netflow5" / "sflow").
	collectorStr  string
	collectorAddr *net.UDPAddr
	protocol      string
	encoder       FlowEncoder

	// Per-exporter cumulative counters. Summed at status-endpoint read
	// time and persisted into the simulator-wide per-collector aggregate
	// when the device is deleted, so /api/v1/flows/status exposes
	// monotonic totals even as devices come and go.
	statPackets atomic.Uint64
	statBytes   atomic.Uint64
	statRecords atomic.Uint64

	// firstWriteErr ensures we log at most one write-failure message per
	// exporter; silent swallowing of WriteTo errors was an observability
	// hole flagged in the phase 3 review (P6).
	firstWriteErr sync.Once

	// conn is the per-device UDP socket (nil = use shared pool). atomic.Pointer
	// so Tick (ticker goroutine) and Close (device-shutdown paths) can read and
	// clear it without racing. Callers must use Load/Store/Swap — never touch
	// the field by address.
	conn atomic.Pointer[net.UDPConn]
	// counterSources is consulted on each sFlow tick to emit COUNTERS_SAMPLE
	// records alongside FLOW_SAMPLEs. Written once at device init and read-only
	// thereafter, so no locking is required for the read path in Tick.
	// Under NetFlow/IPFIX exporters the slice is non-nil but ignored.
	counterSources []CounterSource
}

// NewFlowExporter creates a FlowExporter for device, using profile to drive
// synthetic flow generation. The RNG is seeded from the device's domainID so
// each device produces distinct but deterministic traffic patterns.
//
// collectorStr is the "host:port" the device exports to; collectorAddr is the
// resolved form (the caller must pre-resolve so construction is cheap);
// protocol is the canonical protocol name; encoder is the matching encoder
// instance. Callers typically use `SimulatorManager.attachFlowExporter`
// rather than calling this constructor directly.
func NewFlowExporter(device *DeviceSimulator, profile *FlowProfile,
	activeTimeout, inactiveTimeout, templateInterval time.Duration,
	collectorStr string, collectorAddr *net.UDPAddr,
	protocol string, encoder FlowEncoder) *FlowExporter {
	var domainID uint32
	if ip4 := device.IP.To4(); ip4 != nil {
		domainID = binary.BigEndian.Uint32(ip4)
	}
	return &FlowExporter{
		cache:            NewFlowCache(activeTimeout, inactiveTimeout, profile.MaxFlows),
		profile:          profile,
		rng:              rand.New(rand.NewSource(int64(domainID))),
		domainID:         domainID,
		startTime:        time.Now(),
		templateInterval: templateInterval,
		collectorStr:     collectorStr,
		collectorAddr:    collectorAddr,
		protocol:         protocol,
		encoder:          encoder,
	}
}

// Close releases the per-device UDP socket, if one was opened. Safe to call
// on a nil or already-closed FlowExporter; safe to call multiple times and
// concurrently with Tick (Swap atomically claims the conn so only one caller
// ever observes it non-nil).
func (fe *FlowExporter) Close() error {
	if fe == nil {
		return nil
	}
	conn := fe.conn.Swap(nil)
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// logFirstWriteErr emits at most one log line per exporter on a failed
// WriteTo. Gated by fe.firstWriteErr so a down/misconfigured collector
// doesn't flood logs at tick cadence × device count.
func (fe *FlowExporter) logFirstWriteErr(err error) {
	if fe == nil {
		return
	}
	fe.firstWriteErr.Do(func() {
		log.Printf("flow export: device %s write to %s failed: %v (further errors suppressed for this exporter)",
			domainIDtoIP(fe.domainID), fe.collectorStr, err)
	})
}

// Tick is called by the shared SimulatorManager ticker goroutine on every
// flowTickInterval. It replenishes the flow cache to ConcurrentFlows, expires
// aged records, and emits one or more UDP datagrams to `fe.collectorAddr`
// using `fe.encoder`.
//
// When fe.conn is non-nil (per-device mode) it is used for the WriteTo; the
// passed-in sharedConn is the shared-pool fallback (keyed by collector +
// protocol) used when the per-device socket could not be opened or
// per-device mode is disabled. sharedConn may be nil when the pool
// could not open a socket for this exporter's (collector, protocol) tuple.
//
// bufPool must supply []byte slices of at least 1500 bytes.
// Write errors are ignored (best-effort delivery; collector may be down).
// The returned FlowTickStats are summed by tickAllFlowExporters into the
// per-exporter atomic counters and aggregated at status-endpoint read time.
func (fe *FlowExporter) Tick(now time.Time, sharedConn *net.UDPConn, bufPool *sync.Pool) FlowTickStats {
	uptimeMs := uint32(now.Sub(fe.startTime).Milliseconds())
	deviceIP := domainIDtoIP(fe.domainID)
	encoder := fe.encoder
	collectorAddr := fe.collectorAddr

	// Prefer the per-device socket (source IP = device IP) when set; fall back
	// to the shared-pool socket so callers that don't use per-device binding
	// (tests, ns-disabled deployments) still work.
	// atomic Load pairs with Swap in Close — Tick never observes a torn pointer.
	writeConn := fe.conn.Load()
	if writeConn == nil {
		writeConn = sharedConn
	}
	if writeConn == nil || collectorAddr == nil || encoder == nil {
		return FlowTickStats{}
	}

	// Replenish cache to the configured ConcurrentFlows level.
	fe.cache.GenerateFlows(fe.profile, deviceIP, fe.rng, now, uptimeMs)

	// Collect all records that crossed an active or inactive timeout boundary.
	expired := fe.cache.Expire(now)

	sendTemplate := fe.seqNo == 0 || now.Sub(fe.lastTempl) >= fe.templateInterval
	if len(expired) == 0 && !sendTemplate {
		return FlowTickStats{}
	}

	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	var stats FlowTickStats

	// Paginate: send as many records as fit in each 1500-byte UDP datagram.
	// Capacity depends on the active encoder's protocol (NF9: 45B/record,
	// IPFIX: 53B/record), so we ask the encoder for its sizes rather than
	// hard-coding NF9 constants here.
	//
	// Variable-length encoders (sFlow) return a non-zero MaxRecordSize and we
	// bound batches by that worst-case; fixed-size encoders return 0 and keep
	// the original (len(buf) - overhead) / recSize division unchanged so
	// existing NetFlow/IPFIX datagram framing is preserved byte-for-byte.
	baseOverhead, templSize, recSize := encoder.PacketSizes()
	maxRecSize := encoder.MaxRecordSize()
	for {
		overhead := baseOverhead
		if sendTemplate {
			overhead += templSize
		}
		var batch []FlowRecord
		perRec := recSize
		if maxRecSize > 0 {
			perRec = maxRecSize
		}
		if len(buf) >= overhead+perRec {
			cap := (len(buf) - overhead) / perRec
			if cap >= len(expired) {
				batch = expired
				expired = nil
			} else {
				batch = expired[:cap]
				expired = expired[cap:]
			}
		}

		if len(batch) == 0 && !sendTemplate {
			break
		}

		var n int
		var err error
		if sfe, ok := encoder.(SFlowEncoder); ok {
			// sFlow routes through EncodeFlowDatagram so sampling_rate can be
			// derived from the device's FlowProfile — the FlowEncoder interface
			// doesn't carry the profile, and a shared encoder can't hold state.
			rate := uint32(fe.profile.ConcurrentFlows * SyntheticSamplingRateMultiplier)
			if rate == 0 {
				rate = 1
			}
			n, err = sfe.EncodeFlowDatagram(fe.domainID, fe.seqNo, uptimeMs, batch, rate, buf)
		} else {
			n, err = encoder.EncodePacket(fe.domainID, fe.seqNo, uptimeMs, batch, sendTemplate, buf)
		}
		if err != nil || n == 0 {
			break
		}

		if _, err := writeConn.WriteTo(buf[:n], collectorAddr); err != nil {
			fe.logFirstWriteErr(err)
		}
		stats.PacketsSent++
		stats.BytesSent += uint64(n)
		stats.RecordsSent += uint64(len(batch))
		// Advance flow_sequence per the protocol's semantics. NF9/IPFIX advance
		// by 1 per packet; NF5 advances by the record count of this packet.
		fe.seqNo += uint32(encoder.SeqIncrement(len(batch)))
		if sendTemplate {
			fe.lastTempl = now
			stats.LastTemplateMs = now.UnixMilli()
			sendTemplate = false
		}

		if len(expired) == 0 {
			break
		}
	}

	// Phase 2: after the flow-sample loop, sFlow emits one COUNTERS_SAMPLE
	// datagram per tick aggregating all registered CounterSources. Each source's
	// Snapshot is called once; records are concatenated into a single datagram
	// bounded by sflowMaxCountersSampleSize * recordCount. Datagrams that would
	// exceed the buffer are split — EncodeCounterDatagram is called repeatedly
	// with remaining records until the batch is drained.
	if sfe, ok := encoder.(SFlowEncoder); ok && len(fe.counterSources) > 0 {
		var allRecords []CounterRecord
		for _, src := range fe.counterSources {
			allRecords = append(allRecords, src.Snapshot(now)...)
		}
		for len(allRecords) > 0 {
			batch := allRecords
			// Pick the largest batch that fits in a 1500-byte buf. Each record
			// occupies at most sflowMaxCountersSampleSize bytes once wrapped,
			// and each counters_sample wrapper contributes
			// sflowCountersSampleHeaderSize bytes of overhead on top of the
			// datagram header.
			maxBatch := (len(buf) - sflowDatagramHeaderSize - sflowCountersSampleHeaderSize) / sflowMaxCountersSampleSize
			if maxBatch < 1 {
				break
			}
			if len(batch) > maxBatch {
				batch = batch[:maxBatch]
				allRecords = allRecords[maxBatch:]
			} else {
				allRecords = nil
			}
			n, err := sfe.EncodeCounterDatagram(fe.domainID, fe.seqNo, uptimeMs, batch, buf)
			if err != nil || n == 0 {
				break
			}
			if _, err := writeConn.WriteTo(buf[:n], collectorAddr); err != nil {
				fe.logFirstWriteErr(err)
			}
			stats.PacketsSent++
			stats.BytesSent += uint64(n)
			fe.seqNo++
		}
	}

	return stats
}

// SetFlowSourcePerDevice toggles per-device UDP source IP binding. When true,
// each device opens its own UDP socket inside the opensim namespace bound to
// the device's IP, so collectors see per-device exporter IPs rather than the
// container host IP. Read at per-device attach time; call before the
// first call to `CreateDevices` that carries a flow seed.
func (sm *SimulatorManager) SetFlowSourcePerDevice(enabled bool) {
	sm.flowSourcePerDevice = enabled
}

// registerSFlowCounterSources wires per-device CounterSource instances onto
// the FlowExporter, but only when the device's protocol is sFlow. Under
// NetFlow/IPFIX/NF5 the sources are never consulted, so skipping registration
// avoids per-device allocations for the 30,000+ device workloads this
// simulator is built for.
func (sm *SimulatorManager) registerSFlowCounterSources(device *DeviceSimulator) {
	if device.flowExporter == nil || device.flowExporter.protocol != "sflow" {
		return
	}
	var sources []CounterSource
	if device.metricsCycler != nil {
		if ic := device.metricsCycler.ifCounters.Load(); ic != nil {
			if s := NewInterfaceCounterSource(ic); s != nil {
				sources = append(sources, s)
			}
		}
	}
	// CPUCounterSource's processor_information record already carries
	// total_memory and free_memory — a separate memory counter source would
	// emit a non-standard sFlow format ID that strict collectors drop.
	sources = append(sources, NewCPUCounterSource(device))
	device.flowExporter.counterSources = sources
}

// openFlowConnForDevice opens a per-device UDP socket bound to the device's
// IP (ephemeral source port) and assigns it to device.flowExporter.conn.
// Silently falls through to the shared-pool socket when:
//   - per-device mode is disabled,
//   - namespace isolation is off (device.netNamespace == nil),
//   - or the bind fails (typically because the opensim ns has no route to
//     the collector — see issue #36).
//
// Best-effort: a failed per-device bind logs once and the exporter keeps
// working via the shared-pool socket.
func (sm *SimulatorManager) openFlowConnForDevice(device *DeviceSimulator) {
	if !sm.flowSourcePerDevice || device.flowExporter == nil {
		return
	}
	if device.netNamespace == nil {
		return
	}
	addr := &net.UDPAddr{IP: device.IP, Port: 0}
	conn, err := device.netNamespace.ListenUDPInNamespace(addr)
	if err != nil {
		if device.flowExporter.protocol == "sflow" {
			log.Printf("flow export: device %s per-device bind failed, falling back to shared socket: %v (sFlow agent_address may not match UDP source IP observed by collector)", device.IP, err)
		} else {
			log.Printf("flow export: device %s per-device bind failed, falling back to shared socket: %v", device.IP, err)
		}
		return
	}
	conn.SetWriteBuffer(65536)
	device.flowExporter.conn.Store(conn)
}

// flowConnFor returns the shared-pool UDP socket for a (collector, protocol)
// tuple. First caller for a key opens the socket; subsequent callers reuse
// it. Returns nil if the socket can't be opened. Safe for concurrent use.
func (sm *SimulatorManager) flowConnFor(key flowConnKey) *net.UDPConn {
	if cached, ok := sm.flowConns.Load(key); ok {
		return cached.(*net.UDPConn)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		log.Printf("flow export: failed to open shared socket for %s/%s: %v", key.collector, key.protocol, err)
		return nil
	}
	actual, loaded := sm.flowConns.LoadOrStore(key, conn)
	if loaded {
		// Another goroutine opened a socket for this key first. Close ours.
		_ = conn.Close()
		return actual.(*net.UDPConn)
	}
	return conn
}

// closeFlowConnPool closes every pooled shared socket. Called from
// Shutdown after the ticker goroutine has exited. Does NOT reassign
// `sm.flowConns` — the manager is being torn down, the map value goes
// out of scope with it, and reassigning a concurrent sync.Map field is
// racy by itself.
func (sm *SimulatorManager) closeFlowConnPool() {
	sm.flowConns.Range(func(_, v interface{}) bool {
		if conn, ok := v.(*net.UDPConn); ok {
			_ = conn.Close()
		}
		return true
	})
}

// flowCollectorAggregate holds monotonic counters for a
// (collector, protocol) tuple that survive device deletion. Written
// by `persistFlowCounters` on device Stop; read by `GetFlowStatus` and
// merged with live-exporter counters to produce cumulative totals.
type flowCollectorAggregate struct {
	packets atomic.Uint64
	bytes   atomic.Uint64
	records atomic.Uint64
}

// persistFlowCounters snapshots a FlowExporter's cumulative counters
// into the simulator-wide per-collector aggregate so /flows/status
// reports monotonic totals even as devices come and go (review
// decision D1.b). Called from the device lifecycle immediately before
// `FlowExporter.Close()`. Safe to call with nil exporter; idempotent
// only in the sense that calling it twice will DOUBLE the persisted
// counters — callers MUST invoke it at most once per exporter.
func (sm *SimulatorManager) persistFlowCounters(fe *FlowExporter) {
	if fe == nil || fe.collectorStr == "" {
		return
	}
	key := flowConnKey{collector: fe.collectorStr, protocol: fe.protocol}
	v, _ := sm.flowAggregates.LoadOrStore(key, &flowCollectorAggregate{})
	agg := v.(*flowCollectorAggregate)
	agg.packets.Add(fe.statPackets.Load())
	agg.bytes.Add(fe.statBytes.Load())
	agg.records.Add(fe.statRecords.Load())
}

// buildFlowEncoder returns the encoder + canonical protocol name for a
// configured protocol string. Caller must have already canonicalised via
// `DeviceFlowConfig.Validate` — this function is strict and returns an
// error for anything it doesn't recognise. Centralised so the
// `attachFlowExporter` path and any future REST-validation path share one
// source of truth.
func buildFlowEncoder(protocol string) (FlowEncoder, string, error) {
	switch strings.ToLower(protocol) {
	case "netflow9", "nf9", "":
		return NetFlow9Encoder{}, "netflow9", nil
	case "ipfix", "ipfix10":
		return IPFIXEncoder{}, "ipfix", nil
	case "netflow5", "nf5":
		return &NetFlow5Encoder{}, "netflow5", nil
	case "sflow", "sflow5":
		return SFlowEncoder{}, "sflow", nil
	default:
		return nil, "", fmt.Errorf("unknown flow protocol %q (supported: netflow9, ipfix, netflow5, sflow)", protocol)
	}
}

// attachFlowExporter constructs and wires a FlowExporter for a device that
// already has `device.flowConfig` populated. Opens the per-device UDP
// socket if `flowSourcePerDevice` is enabled; registers sFlow counter
// sources if the device is exporting sFlow. On failure, logs and leaves
// `device.flowExporter == nil` so the device participates in the
// simulator but without flow export.
//
// The collector string stored on the exporter is the canonicalised form
// returned by `net.ResolveUDPAddr` so that devices configured with
// equivalent-but-different-spelling collectors (e.g. "localhost:2055"
// vs "127.0.0.1:2055") aggregate into one pool entry and one
// FlowCollectorStatus row (review fix P1).
func (sm *SimulatorManager) attachFlowExporter(device *DeviceSimulator, flowProfile *FlowProfile) error {
	cfg := device.flowConfig
	if cfg == nil {
		return nil
	}
	encoder, canonical, err := buildFlowEncoder(cfg.Protocol)
	if err != nil {
		return err
	}
	collectorAddr, err := net.ResolveUDPAddr("udp", cfg.Collector)
	if err != nil {
		return fmt.Errorf("resolve collector %q: %w", cfg.Collector, err)
	}
	canonicalCollector := collectorAddr.String()

	// Per-device TickInterval is stored on cfg but not honored by the
	// single global ticker (design debt documented in the change). Warn
	// once per device at attach so operators aren't silently surprised
	// when they set a distinct value (review fix P2).
	if time.Duration(cfg.TickInterval) != 0 && time.Duration(cfg.TickInterval) != sm.flowTickInterval {
		log.Printf("flow export: device %s configured tick_interval=%s but the simulator-wide ticker runs at %s; per-device tick rates are not yet honored",
			device.IP, time.Duration(cfg.TickInterval), sm.flowTickInterval)
	}

	device.flowExporter = NewFlowExporter(device, flowProfile,
		time.Duration(cfg.ActiveTimeout),
		time.Duration(cfg.InactiveTimeout),
		sm.flowTemplateInterval,
		canonicalCollector, collectorAddr, canonical, encoder)
	sm.openFlowConnForDevice(device)
	sm.registerSFlowCounterSources(device)
	sm.flowFirstAttachLog.Do(func() {
		log.Printf("flow export: active; first device %s → %s (protocol=%s)",
			device.IP, canonicalCollector, canonical)
	})
	return nil
}

// domainIDtoIP converts a uint32 ObservationDomainID back to a net.IP.
func domainIDtoIP(id uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, id)
	return ip
}

// initFlowSubsystem sets up the simulator-wide flow export infrastructure
// that's always live: the 1500-byte buffer pool, the stop channel, and
// the ticker goroutine. After this runs, per-device attach via
// `attachFlowExporter` wires up individual exporters; the ticker walks
// them on every tick interval and no-ops when the list is empty.
//
// Called unconditionally from `NewSimulatorManagerWithOptions` (design
// §D9: always-on scheduler). The simulator-wide tick / template interval
// defaults are set here; operators override them via SetFlowTickInterval
// / SetFlowTemplateInterval before creating devices. Safe to call once.
func (sm *SimulatorManager) initFlowSubsystem() {
	sm.flowBufPool.New = func() interface{} {
		buf := make([]byte, 1500)
		return buf
	}
	sm.flowStopCh = make(chan struct{})
	sm.flowStopOnce = sync.Once{}
	if sm.flowTickInterval == 0 {
		sm.flowTickInterval = defaultFlowTickInterval
	}
	if sm.flowTemplateInterval == 0 {
		sm.flowTemplateInterval = 60 * time.Second
	}
	sm.startFlowTicker()
}

// SetFlowTickInterval overrides the simulator-wide flow ticker cadence.
// Call before device creation. Per-device `TickInterval` fields are
// stored on DeviceFlowConfig but not yet honored (design debt documented
// in the per-device-export-config change).
func (sm *SimulatorManager) SetFlowTickInterval(d time.Duration) {
	if d > 0 {
		sm.flowTickInterval = d
	}
}

// SetFlowTemplateInterval overrides the simulator-wide template refresh
// interval (applies to NetFlow v9 / IPFIX). Call before device creation.
// `template_interval` is global per design §D5.
func (sm *SimulatorManager) SetFlowTemplateInterval(d time.Duration) {
	if d > 0 {
		sm.flowTemplateInterval = d
	}
}

// startFlowTicker launches a single background goroutine that calls Tick on
// every active device's FlowExporter at flowTickInterval. The goroutine exits
// when flowStopCh is closed.
func (sm *SimulatorManager) startFlowTicker() {
	sm.flowWg.Add(1)
	go func() {
		defer sm.flowWg.Done()
		ticker := time.NewTicker(sm.flowTickInterval)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				sm.tickAllFlowExporters(now)
			case <-sm.flowStopCh:
				return
			}
		}
	}()
}

// tickAllFlowExporters calls Tick on every device that has a FlowExporter.
// Each exporter supplies its own encoder / collectorAddr; the manager
// supplies the shared-pool fallback socket (looked up by the exporter's
// (collector, protocol) key). Stats are accumulated per-exporter and
// aggregated at status-endpoint read time.
func (sm *SimulatorManager) tickAllFlowExporters(now time.Time) {
	sm.mu.RLock()
	exporters := make([]*FlowExporter, 0, len(sm.devices))
	for _, d := range sm.devices {
		if d.flowExporter != nil {
			exporters = append(exporters, d.flowExporter)
		}
	}
	sm.mu.RUnlock()

	var lastTemplMs int64
	for _, fe := range exporters {
		var sharedConn *net.UDPConn
		if fe.conn.Load() == nil {
			sharedConn = sm.flowConnFor(flowConnKey{collector: fe.collectorStr, protocol: fe.protocol})
		}
		s := fe.Tick(now, sharedConn, &sm.flowBufPool)
		if s.PacketsSent > 0 {
			fe.statPackets.Add(s.PacketsSent)
			fe.statBytes.Add(s.BytesSent)
			fe.statRecords.Add(s.RecordsSent)
		}
		if s.LastTemplateMs > lastTemplMs {
			lastTemplMs = s.LastTemplateMs
		}
	}
	if lastTemplMs > 0 {
		sm.flowStatLastTmpl.Store(lastTemplMs)
	}
}

// GetFlowStatus returns the aggregated flow-export snapshot. Devices
// sharing the same (collector, protocol) tuple collapse into one record
// in the `Collectors` array. Counters are MONOTONIC since simulator
// start: live exporters' per-tick counters are summed with the
// per-collector aggregates persisted when earlier devices were deleted
// (review decision D1.b), so Prometheus-style consumers never see
// counter resets mid-run.
//
// BREAKING (per-device-export-config phase 3): returns the new
// array-of-collectors shape. The legacy scalar fields are retired;
// callers detect "feature off" via `len(collectors) == 0`.
func (sm *SimulatorManager) GetFlowStatus() FlowStatus {
	agg := make(map[flowConnKey]*FlowCollectorStatus)

	sm.mu.RLock()
	for _, d := range sm.devices {
		fe := d.flowExporter
		if fe == nil {
			continue
		}
		k := flowConnKey{collector: fe.collectorStr, protocol: fe.protocol}
		rec, ok := agg[k]
		if !ok {
			rec = &FlowCollectorStatus{
				Collector: fe.collectorStr,
				Protocol:  fe.protocol,
			}
			agg[k] = rec
		}
		rec.Devices++
		rec.SentPackets += fe.statPackets.Load()
		rec.SentBytes += fe.statBytes.Load()
		rec.SentRecords += fe.statRecords.Load()
	}
	sm.mu.RUnlock()

	// Fold persisted counters for tuples whose devices have since been
	// deleted (or that have a live device AND historical deletions).
	// A tuple with no live exporters still shows up in the output with
	// Devices=0 so the monotonic totals remain visible.
	sm.flowAggregates.Range(func(k, v interface{}) bool {
		key := k.(flowConnKey)
		pers := v.(*flowCollectorAggregate)
		rec, ok := agg[key]
		if !ok {
			rec = &FlowCollectorStatus{
				Collector: key.collector,
				Protocol:  key.protocol,
			}
			agg[key] = rec
		}
		rec.SentPackets += pers.packets.Load()
		rec.SentBytes += pers.bytes.Load()
		rec.SentRecords += pers.records.Load()
		return true
	})

	collectors := make([]FlowCollectorStatus, 0, len(agg))
	totalDevices := 0
	for _, rec := range agg {
		collectors = append(collectors, *rec)
		totalDevices += rec.Devices
	}

	var lastTemplate string
	if ms := sm.flowStatLastTmpl.Load(); ms > 0 {
		lastTemplate = time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
	}

	return FlowStatus{
		Collectors:       collectors,
		DevicesExporting: totalDevices,
		LastTemplateSend: lastTemplate,
	}
}
