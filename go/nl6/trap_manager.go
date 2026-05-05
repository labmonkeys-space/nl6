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

// SimulatorManager-level SNMP trap export lifecycle.
//
// `StartTrapSubsystem` loads the catalog (embedded or file override), creates
// the shared TrapScheduler + TrapEncoder, and starts the scheduler goroutine.
// Per-device TrapExporters are wired in from device startup/teardown (see
// trap_exporter.go) against each device's `DeviceTrapConfig`. GetTrapStatus
// exposes the aggregated per-(collector, mode) counters to the HTTP API.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// ParseTrapMode converts a case-insensitive string to TrapMode. Empty defaults
// to TrapModeTrap so operators that pass -trap-collector without -trap-mode
// get the common case.
func ParseTrapMode(s string) (TrapMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "trap":
		return TrapModeTrap, nil
	case "inform":
		return TrapModeInform, nil
	default:
		return 0, fmt.Errorf("invalid -trap-mode %q (valid: trap, inform)", s)
	}
}

// TrapStatus is the JSON body returned by GET /api/v1/traps/status.
//
// BREAKING (per-device-export-config phase 4): the response is now an
// array-of-collectors aggregated across devices. Legacy scalar fields
// (enabled/mode/collector/community/sent/informs_*) retired. Use
// `SubsystemActive` to distinguish "never started" from "started with
// zero devices"; `len(collectors) == 0` no longer implies feature off.
//
// CatalogsByType surfaces the per-device-type overlay map — unchanged
// from phase-4-prior behaviour.
type TrapStatus struct {
	SubsystemActive            bool                         `json:"subsystem_active"`
	Collectors                 []TrapCollectorStatus        `json:"collectors"`
	DevicesExporting           int                          `json:"devices_exporting"`
	RateLimiterTokensAvailable int                          `json:"rate_limiter_tokens_available,omitempty"`
	CatalogsByType             map[string]CatalogSourceInfo `json:"catalogs_by_type,omitempty"`
}

// TrapCollectorStatus is one aggregate record in TrapStatus.Collectors.
// Devices with the same (collector, mode) tuple collapse into one
// record; counters are cumulative since simulator start (monotonic —
// persisted counters from deleted devices are merged at read time).
type TrapCollectorStatus struct {
	Collector      string `json:"collector"`
	Mode           string `json:"mode"`
	Devices        int    `json:"devices"`
	Sent           uint64 `json:"sent"`
	InformsPending uint64 `json:"informs_pending,omitempty"`
	InformsAcked   uint64 `json:"informs_acked,omitempty"`
	InformsFailed  uint64 `json:"informs_failed,omitempty"`
	InformsDropped uint64 `json:"informs_dropped,omitempty"`
}

// trapAggKey identifies a (collector, mode) tuple for the shared-socket
// pool and the monotonic counter aggregate.
type trapAggKey struct {
	collector string
	mode      TrapMode
}

// trapCollectorAggregate holds monotonic counters for a (collector, mode)
// tuple that survive device deletion (review decision D1.b pattern).
type trapCollectorAggregate struct {
	sent           atomic.Uint64
	informsAcked   atomic.Uint64
	informsFailed  atomic.Uint64
	informsDropped atomic.Uint64
}

// CatalogSourceInfo describes one entry in TrapStatus.CatalogsByType /
// SyslogStatus.CatalogsByType. Shared between trap and syslog since their
// observability shape is identical.
type CatalogSourceInfo struct {
	Entries int    `json:"entries"`
	Source  string `json:"source"` // "embedded", "file:<path>", or "override:<path>"
}

// TrapSubsystemConfig bundles the simulator-wide knobs still owned by
// the manager after the per-device-export-config refactor. Per-device
// knobs (collector / mode / community / interval / inform-*) live on
// each `DeviceTrapConfig`.
type TrapSubsystemConfig struct {
	CatalogPath     string
	GlobalCap       int  // 0 = unlimited
	SourcePerDevice bool // bind per-device UDP socket in opensim ns
	// MeanSchedulerInterval seeds the scheduler's Poisson draw when no
	// device-specific intervals are known. Individual devices still
	// register with their own per-device interval on the heap.
	MeanSchedulerInterval time.Duration
}

// StartTrapSubsystem loads the catalog, creates the shared scheduler
// and optional rate limiter, and starts the scheduler goroutine. The
// subsystem is always-on after this runs — per-device attach via
// `startDeviceTrapExporter` later wires individual exporters in.
//
// Replaces pre-phase-4 `StartTrapExport`: the per-device collector /
// mode / community / interval settings are now on each
// `DeviceTrapConfig`. The manager no longer holds those values
// simulator-wide.
func (sm *SimulatorManager) StartTrapSubsystem(cfg TrapSubsystemConfig) error {
	if sm.trapScheduler.Load() != nil {
		return fmt.Errorf("trap export: subsystem already started")
	}
	if cfg.GlobalCap < 0 {
		return fmt.Errorf("trap export: -trap-global-cap must be non-negative, got %d", cfg.GlobalCap)
	}
	if cfg.MeanSchedulerInterval <= 0 {
		log.Printf("trap export: MeanSchedulerInterval <= 0, defaulting to 30s (phase-5 review P12)")
		cfg.MeanSchedulerInterval = 30 * time.Second
	}

	var catalog *Catalog
	var err error
	if cfg.CatalogPath == "" {
		catalog, err = LoadEmbeddedCatalog()
	} else {
		catalog, err = LoadCatalogFromFile(cfg.CatalogPath)
	}
	if err != nil {
		return err
	}

	catalogsByType := map[string]*Catalog{
		universalCatalogKey: catalog,
	}
	if cfg.CatalogPath == "" {
		perType, scanErr := ScanPerTypeTrapCatalogs(catalog, trapCatalogResourceDir)
		if scanErr != nil {
			return fmt.Errorf("trap export: scanning per-type catalogs: %w", scanErr)
		}
		for slug, c := range perType {
			catalogsByType[slug] = c
		}
	}

	var limiter *rate.Limiter
	if cfg.GlobalCap > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.GlobalCap), cfg.GlobalCap)
	}

	scheduler := NewTrapScheduler(SchedulerOptions{
		CatalogFor:         func(ip net.IP) *Catalog { return sm.CatalogFor(ip.String()) },
		MeanInterval:       cfg.MeanSchedulerInterval,
		GlobalCapPerSecond: cfg.GlobalCap,
	})

	sm.mu.Lock()
	sm.trapCatalog = catalog
	sm.trapCatalogsByType = catalogsByType
	sm.trapEncoder = SNMPv2cEncoder{}
	sm.trapLimiter = limiter
	sm.trapGlobalCap = cfg.GlobalCap
	sm.trapSourcePerDevice = cfg.SourcePerDevice
	sm.trapCatalogPath = cfg.CatalogPath
	// Publish the scheduler under sm.mu.Lock alongside the dependent
	// fields so any reader holding sm.mu.RLock sees a consistent
	// snapshot (scheduler-non-nil ⇔ deps populated). The atomic.Pointer
	// only exists to give getTrapScheduler a lock-free Load — that
	// closes the DeleteDevice self-deadlock without sacrificing the
	// consistency that the RLock-protected readers rely on.
	sm.trapScheduler.Store(scheduler)
	sm.mu.Unlock()

	capStr := "unlimited"
	if cfg.GlobalCap > 0 {
		capStr = fmt.Sprintf("%d/s", cfg.GlobalCap)
	}
	catStr := "<embedded>"
	if cfg.CatalogPath != "" {
		catStr = cfg.CatalogPath
	}
	log.Printf("Trap subsystem: ready (cap=%s, catalog=%s, per-device-source=%v) — awaiting per-device config",
		capStr, catStr, cfg.SourcePerDevice)

	go scheduler.Run(context.Background())

	return nil
}

// trapConnFor returns the shared-pool UDP socket for a collector.
// First caller for a key opens the socket; subsequent callers reuse
// it. Returns nil if the socket can't be opened. Safe for concurrent use.
// Only used for TRAP mode — INFORM requires per-device binding so
// callers must reject that combination at create-time.
func (sm *SimulatorManager) trapConnFor(collector string) *net.UDPConn {
	if cached, ok := sm.trapConns.Load(collector); ok {
		return cached.(*net.UDPConn)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		log.Printf("trap export: failed to open shared socket for %s: %v", collector, err)
		return nil
	}
	actual, loaded := sm.trapConns.LoadOrStore(collector, conn)
	if loaded {
		_ = conn.Close()
		return actual.(*net.UDPConn)
	}
	return conn
}

// closeTrapConnPool closes every pooled shared socket and removes its map
// entry so a subsequent `trapConnFor` after `StartTrapSubsystem` cannot
// return a closed *net.UDPConn (review fix P2).
func (sm *SimulatorManager) closeTrapConnPool() {
	sm.trapConns.Range(func(k, v interface{}) bool {
		if conn, ok := v.(*net.UDPConn); ok {
			_ = conn.Close()
		}
		sm.trapConns.Delete(k)
		return true
	})
}

// TrapSourcePerDevice returns the simulator-wide
// `-trap-source-per-device` flag. Exposed so HTTP handlers can pre-flight
// reject INFORM-mode batches when per-device binding is disabled
// (phase 4.6) — keeping the access read-locked so a concurrent Stop /
// Start cannot mid-flight a partial value.
func (sm *SimulatorManager) TrapSourcePerDevice() bool {
	if sm == nil {
		return false
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.trapSourcePerDevice
}

// getTrapScheduler returns the manager's trap scheduler pointer via a
// lock-free atomic Load so callers (notably device.Stop, which runs
// under sm.mu.Lock from the DeleteDevice path) cannot self-deadlock by
// re-entering sm.mu. The atomic also closes the original D3 race
// against a concurrent StopTrapExport. Safe with nil manager.
func getTrapScheduler(sm *SimulatorManager) *TrapScheduler {
	if sm == nil {
		return nil
	}
	return sm.trapScheduler.Load()
}

// persistTrapCounters snapshots a TrapExporter's cumulative counters
// into the simulator-wide per-(collector, mode) aggregate so
// /traps/status reports monotonic totals across DEVICE CHURN WITHIN
// ONE SUBSYSTEM LIFECYCLE (review decision D1.b applied to trap). A
// Stop→Start cycle resets sm.trapAggregates and starts from zero by
// design (phase-5 review P2 scope clarification). Called from the
// device lifecycle immediately before `TrapExporter.Close()`. Safe to
// call with nil exporter; idempotent per exporter (countersPersisted
// sync.Once) so concurrent Stop paths cannot double-count.
func (sm *SimulatorManager) persistTrapCounters(fe *TrapExporter) {
	if fe == nil {
		return
	}
	collector := fe.CollectorString()
	if collector == "" {
		return
	}
	// Use the exporter's countersPersisted sync.Once so concurrent
	// StopTrapExport + device.Stop paths can both call us safely without
	// double-counting (review fix P3).
	fe.countersPersisted.Do(func() {
		key := trapAggKey{collector: collector, mode: fe.Mode()}
		v, _ := sm.trapAggregates.LoadOrStore(key, &trapCollectorAggregate{})
		agg := v.(*trapCollectorAggregate)
		stats := fe.Stats()
		agg.sent.Add(stats.Sent.Load())
		agg.informsAcked.Add(stats.InformsAcked.Load())
		agg.informsFailed.Add(stats.InformsFailed.Load())
		agg.informsDropped.Add(stats.InformsDropped.Load())
	})
}

// StopTrapExport stops the scheduler, closes every pooled shared
// socket, and closes every device's TrapExporter. Safe to call when
// the subsystem was never started (no-op).
//
// CONSTRAINT — process-shutdown only (phase-5 review D1):
// StopTrapExport is NOT safe to race concurrent device creation.
// `startDeviceTrapExporter` captures scheduler / pool / encoder
// pointers under a short RLock and uses them outside that lock; a
// concurrent StopTrapExport can leave orphan exporters or closed
// sockets in that window. Today StopTrapExport is only called from
// the process-exit signal handler (Shutdown), so no live attach can
// race it. Do not introduce a runtime "restart trap subsystem" path
// without first tightening the attach-path lock discipline (see the
// deferred D1 follow-up in the per-device-export-config change).
func (sm *SimulatorManager) StopTrapExport() {
	scheduler := sm.trapScheduler.Load()
	if scheduler == nil {
		return // subsystem never started
	}

	sm.mu.RLock()
	devices := make([]*DeviceSimulator, 0, len(sm.devices))
	for _, d := range sm.devices {
		if d.trapExporter != nil {
			devices = append(devices, d)
		}
	}
	sm.mu.RUnlock()
	scheduler.Stop()
	for _, d := range devices {
		// Take d.mu to synchronise with a concurrent device.Stop path.
		// persistTrapCounters is sync.Once-gated so it's safe either
		// way, but nil-ing d.trapExporter here without the lock would
		// race with device.Stop()'s own nil-write.
		d.mu.Lock()
		te := d.trapExporter
		d.trapExporter = nil
		d.mu.Unlock()
		if te != nil {
			sm.persistTrapCounters(te)
			_ = te.Close()
		}
	}
	sm.closeTrapConnPool()

	sm.mu.Lock()
	// Clear the scheduler under sm.mu.Lock alongside the dependent
	// fields so any reader holding sm.mu.RLock sees a consistent
	// snapshot (scheduler-nil ⇔ deps cleared).
	sm.trapScheduler.Store(nil)
	sm.trapCatalog = nil
	sm.trapCatalogsByType = nil
	sm.trapCatalogPath = ""
	// Reset monotonic counter aggregates so a subsequent
	// StartTrapSubsystem starts from zero rather than inheriting totals
	// from the previous lifecycle (review fix P2).
	sm.trapAggregates = sync.Map{}
	// Reset the first-attach log gate so the "trap export active" line
	// fires again on the next Start→first-device cycle. atomic.Bool
	// Store is race-free against concurrent CAS readers — replaces the
	// earlier sync.Once{} reassignment which was a data race with the
	// Do() call in startDeviceTrapExporter (phase-5 review P3).
	sm.trapFirstAttachLog.Store(false)
	sm.trapIntervalWarned.Store(false)
	// Reset subsystem-scalar state so a subsequent StartTrapSubsystem
	// starts from a clean slate (phase-5 review P-E1).
	sm.trapLimiter = nil
	sm.trapGlobalCap = 0
	sm.trapSourcePerDevice = false
	sm.mu.Unlock()
}

// startDeviceTrapExporter creates a TrapExporter for a device that
// already has `device.trapConfig` populated. Opens a per-device UDP
// socket when `-trap-source-per-device=true`, falls back to the
// shared-pool socket keyed by collector otherwise. Registers the
// exporter with the central scheduler carrying the device's own
// per-device Poisson mean interval.
//
// Returns an error if INFORM mode is requested but the simulator-wide
// `-trap-source-per-device` is false, or if per-device bind fails in
// INFORM mode (spec: INFORM requires per-device binding).
//
// Must be called only after `StartTrapSubsystem` — caller enforces.
func (sm *SimulatorManager) startDeviceTrapExporter(device *DeviceSimulator) error {
	if device == nil || device.trapConfig == nil {
		return nil
	}
	cfg := device.trapConfig

	mode, err := ParseTrapMode(cfg.Mode)
	if err != nil {
		return fmt.Errorf("trap export: parse mode: %w", err)
	}

	// Snapshot scheduler + dependent fields under one RLock so a
	// concurrent Stop cannot interleave between the scheduler nil-check
	// and the encoder/limiter reads. With the Start/Stop fix that puts
	// Store inside sm.mu.Lock, the RLock window is the consistent unit.
	sm.mu.RLock()
	scheduler := sm.trapScheduler.Load()
	sourcePerDevice := sm.trapSourcePerDevice
	encoder := sm.trapEncoder
	limiter := sm.trapLimiter
	deviceIPStr := device.IP.String()
	modelLabel := modelLabelForSlug(sm.deviceTypesByIP[deviceIPStr])
	sm.mu.RUnlock()

	if scheduler == nil {
		return fmt.Errorf("trap export: subsystem not started; call StartTrapSubsystem first")
	}
	if mode == TrapModeInform && !sourcePerDevice {
		return fmt.Errorf("trap export: INFORM mode requires -trap-source-per-device=true")
	}

	collectorAddr, err := net.ResolveUDPAddr("udp4", cfg.Collector)
	if err != nil {
		return fmt.Errorf("resolve collector %q: %w", cfg.Collector, err)
	}
	canonicalCollector := collectorAddr.String()

	// Open the per-device UDP socket first (if enabled) so we know whether
	// we need the shared-pool fallback before constructing the exporter.
	// Wiring SharedConn at construction avoids an unsynchronised post-hoc
	// write to `exporter.sharedConn` that Fire-path goroutines could
	// observe (review fix: pass via Options).
	var perDeviceConn *net.UDPConn
	if sourcePerDevice {
		perDeviceConn = openTrapConnForDevice(device)
		if perDeviceConn == nil && mode == TrapModeInform {
			return fmt.Errorf("trap export: per-device bind failed for %s (required by INFORM mode)", device.IP)
		}
		if perDeviceConn == nil {
			log.Printf("trap export: device %s per-device bind failed, falling back to shared-pool socket", device.IP)
		}
	}
	var sharedConn *net.UDPConn
	if perDeviceConn == nil && mode != TrapModeInform {
		sharedConn = sm.trapConnFor(canonicalCollector)
	}

	opts := TrapExporterOptions{
		DeviceIP:      device.IP,
		Community:     cfg.Community,
		Encoder:       encoder,
		Mode:          mode,
		Collector:     collectorAddr,
		CollectorStr:  canonicalCollector,
		Limiter:       limiter,
		SharedConn:    sharedConn,
		InformTimeout: time.Duration(cfg.InformTimeout),
		InformRetries: cfg.InformRetries,
		IfIndexFn:     deviceIfIndexFn(device),
		IfNameFn:      deviceIfNameFn(device),
		SysName:       device.sysName,
		Model:         modelLabel,
		Serial:        synthSerial(device.IP),
		ChassisID:     synthChassisID(device.IP),
	}

	exporter := NewTrapExporter(opts)
	if perDeviceConn != nil {
		exporter.SetConn(perDeviceConn)
	}

	exporter.StartBackgroundLoops(context.Background())

	device.mu.Lock()
	device.trapExporter = exporter
	device.mu.Unlock()

	// Per-device Interval is stored on cfg but not honored by the
	// scheduler today — the scheduler draws Poisson fires from its
	// simulator-wide MeanInterval (design debt, same pattern as flow's
	// TickInterval). Warn ONCE per subsystem lifecycle at the first
	// divergent attach — per-device logging floods at fleet scale
	// (phase-5 review P13).
	if time.Duration(cfg.Interval) != 0 && time.Duration(cfg.Interval) != scheduler.MeanInterval() {
		if sm.trapIntervalWarned.CompareAndSwap(false, true) {
			log.Printf("trap export: device %s configured interval=%s but the scheduler runs at mean=%s; per-device intervals are not yet honored (further divergences suppressed this lifecycle)",
				device.IP, time.Duration(cfg.Interval), scheduler.MeanInterval())
		}
	}

	scheduler.Register(device.IP, exporter)

	// CAS-gated first-attach log; race-free vs. StopTrapExport's reset
	// to false (phase-5 review P3). If the per-device Interval diverges
	// from the scheduler mean, warn once per subsystem lifecycle instead
	// of per-device — 30k near-identical lines at scale was noisy
	// (phase-5 review P13).
	if sm.trapFirstAttachLog.CompareAndSwap(false, true) {
		log.Printf("trap export: active; first device %s → %s (mode=%s)",
			device.IP, canonicalCollector, cfg.Mode)
	}
	return nil
}

// deviceIfIndexFn builds a template-field callback returning a random ifIndex
// drawn from the device's simulated interface set. Falls back to 1 when the
// device has no indexed interfaces (fresh device, or a device type without
// ifTable resources).
func deviceIfIndexFn(device *DeviceSimulator) func() int {
	return func() int {
		if device == nil || device.metricsCycler == nil {
			return 1
		}
		ic := device.metricsCycler.ifCounters.Load()
		if ic == nil {
			return 1
		}
		indices := ic.IfIndices()
		if len(indices) == 0 {
			return 1
		}
		// Use math/rand global — we don't need crypto-quality randomness here.
		return indices[rand.Intn(len(indices))]
	}
}

// GetTrapStatus returns a JSON-serializable snapshot of the trap export
// state. Exposed via GET /api/v1/traps/status.
//
// Shape matches GetFlowStatus: live per-device exporters are aggregated by
// (collector, mode) tuple; counters from deleted devices persisted in
// sm.trapAggregates are folded in so totals remain monotonic across the
// device lifecycle. A tuple with no live exporters still appears in the
// array — its `Devices` field is 0 but cumulative counters survive.
//
// When the subsystem was never started the returned status has an empty
// Collectors slice and no catalogs; callers detect "feature off" via
// `len(status.Collectors) == 0`.
func (sm *SimulatorManager) GetTrapStatus() TrapStatus {
	agg := make(map[trapAggKey]*TrapCollectorStatus)

	sm.mu.RLock()
	limiter := sm.trapLimiter
	status := TrapStatus{SubsystemActive: sm.trapScheduler.Load() != nil}

	if len(sm.trapCatalogsByType) > 0 {
		status.CatalogsByType = make(map[string]CatalogSourceInfo, len(sm.trapCatalogsByType))
		for slug, cat := range sm.trapCatalogsByType {
			status.CatalogsByType[slug] = CatalogSourceInfo{
				Entries: len(cat.Entries),
				Source:  trapCatalogSource(slug, sm.trapCatalogPath),
			}
		}
	}

	for _, d := range sm.devices {
		te := d.trapExporter
		if te == nil {
			continue
		}
		key := trapAggKey{collector: te.CollectorString(), mode: te.Mode()}
		rec, ok := agg[key]
		if !ok {
			rec = &TrapCollectorStatus{
				Collector: te.CollectorString(),
				Mode:      trapModeString(te.Mode()),
			}
			agg[key] = rec
		}
		rec.Devices++
		st := te.Stats()
		rec.Sent += st.Sent.Load()
		if te.Mode() == TrapModeInform {
			rec.InformsPending += uint64(te.PendingInformsLen())
			rec.InformsAcked += st.InformsAcked.Load()
			rec.InformsFailed += st.InformsFailed.Load()
			rec.InformsDropped += st.InformsDropped.Load()
		}
	}

	var tokens int
	if limiter != nil {
		tokens = int(limiter.Tokens())
	}
	sm.mu.RUnlock()

	// Fold persisted counters for tuples whose devices have since been
	// deleted. A tuple with no live exporters still surfaces so operators
	// keep seeing cumulative totals.
	sm.trapAggregates.Range(func(k, v interface{}) bool {
		key := k.(trapAggKey)
		pers := v.(*trapCollectorAggregate)
		rec, ok := agg[key]
		if !ok {
			rec = &TrapCollectorStatus{
				Collector: key.collector,
				Mode:      trapModeString(key.mode),
			}
			agg[key] = rec
		}
		rec.Sent += pers.sent.Load()
		if key.mode == TrapModeInform {
			rec.InformsAcked += pers.informsAcked.Load()
			rec.InformsFailed += pers.informsFailed.Load()
			rec.InformsDropped += pers.informsDropped.Load()
		}
		return true
	})

	collectors := make([]TrapCollectorStatus, 0, len(agg))
	devicesExporting := 0
	for _, rec := range agg {
		collectors = append(collectors, *rec)
		devicesExporting += rec.Devices
	}
	sort.Slice(collectors, func(i, j int) bool {
		if collectors[i].Collector != collectors[j].Collector {
			return collectors[i].Collector < collectors[j].Collector
		}
		return collectors[i].Mode < collectors[j].Mode
	})

	status.Collectors = collectors
	status.DevicesExporting = devicesExporting
	if limiter != nil {
		status.RateLimiterTokensAvailable = tokens
	}
	return status
}

// trapModeString maps TrapMode to the canonical lowercase string used on
// the wire-config JSON (status endpoint, device create/list bodies).
func trapModeString(m TrapMode) string {
	if m == TrapModeInform {
		return "inform"
	}
	return "trap"
}

// FindDeviceByIP returns the first device with the given IP, or nil if none
// match. Linear scan — trap endpoints are admin-plane so O(N) per request is
// acceptable at 30k-device scale.
func (sm *SimulatorManager) FindDeviceByIP(ip string) *DeviceSimulator {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, d := range sm.devices {
		if d.IP.String() == ip {
			return d
		}
	}
	return nil
}

// CatalogFor returns the trap catalog to use for the device with the given
// IP. Resolution order: device-IP → type-slug → `trapCatalogsByType[slug]`
// → `trapCatalogsByType["_universal"]` (the universal). Safe for concurrent
// use; the hot path is O(1) (two map reads). Returns nil only when trap
// export has never been initialised.
func (sm *SimulatorManager) CatalogFor(ip string) *Catalog {
	cat, _ := sm.catalogWithLabelFor(ip)
	return cat
}

// catalogWithLabelFor returns the resolved catalog and its `catalogsByType`
// key under a single RLock. Collapses what used to be three separate
// RLock acquisitions in `FireTrapOnDevice`'s 400-error path (find-device +
// CatalogFor + resolvedCatalogLabel) so a concurrent DeleteDevice cannot
// split-brain the returned pair.
//
// Label is the key the status endpoint reports (device-type slug or the
// reserved `_universal`). Catalog is the resolved *Catalog the hot path
// uses.
func (sm *SimulatorManager) catalogWithLabelFor(ip string) (*Catalog, string) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.trapCatalogsByType == nil {
		return sm.trapCatalog, universalCatalogKey
	}
	if slug, ok := sm.deviceTypesByIP[ip]; ok {
		if cat, found := sm.trapCatalogsByType[slug]; found {
			return cat, slug
		}
	}
	if cat := sm.trapCatalogsByType[universalCatalogKey]; cat != nil {
		return cat, universalCatalogKey
	}
	return sm.trapCatalog, universalCatalogKey
}

// universalCatalogKey is the reserved slug used in trapCatalogsByType and
// syslogCatalogsByType for the universal (non-per-type) catalog. The
// constant value appears verbatim in observability output
// (GET /api/v1/traps/status, POST 400 error bodies) so the name is
// operator-facing, not just an internal detail.
const universalCatalogKey = "_universal"

// trapCatalogResourceDir is the root of the per-device-type resource tree.
// Must match the path used by the SNMP/SSH/REST resource loader in
// resources.go so per-type trap catalogs live alongside their siblings.
const trapCatalogResourceDir = "resources"

// trapCatalogSource returns the `source` string for a CatalogSourceInfo,
// distinguishing the three paths that can populate an entry: the
// `-trap-catalog` flag override (`override:<path>`), the per-type file on
// disk (`file:resources/<slug>/traps.json`), or the embedded universal
// catalog (`embedded`). `catalogFlagPath` is the value of `-trap-catalog`;
// empty means the flag was not set.
func trapCatalogSource(slug, catalogFlagPath string) string {
	if catalogFlagPath != "" {
		return "override:" + catalogFlagPath
	}
	if slug == universalCatalogKey {
		return "embedded"
	}
	return fmt.Sprintf("file:%s/%s/traps.json", trapCatalogResourceDir, slug)
}

// FireTrapOnDevice implements POST /api/v1/devices/{ip}/trap by looking up the
// device's TrapExporter and invoking Fire with the given catalog name.
// Returns the request-id and nil on success; HTTP status codes are chosen by
// the caller based on the error (see web.go / api.go).
//
// Name resolution uses the DEVICE'S catalog (via CatalogFor), not the
// universal catalog — entries defined only in a per-type overlay are
// reachable here for devices of that type. Unknown entries return
// ErrTrapEntryNotFound wrapped in a TrapEntryNotFoundError carrying the
// resolved-catalog identifier and available entry names so the handler
// can render an actionable 400 body.
//
// Returns errors tagged so the HTTP layer can map them:
//   - ErrTrapExportDisabled → 503 Service Unavailable
//   - ErrTrapDeviceNotFound → 404
//   - ErrTrapEntryNotFound  → 400
func (sm *SimulatorManager) FireTrapOnDevice(ip, trapName string, overrides map[string]string) (uint32, error) {
	if sm.trapScheduler.Load() == nil {
		return 0, ErrTrapExportDisabled
	}
	device := sm.FindDeviceByIP(ip)
	if device == nil {
		return 0, fmt.Errorf("%w: %q", ErrTrapDeviceNotFound, ip)
	}
	// Resolve the catalog and its label under ONE RLock so a concurrent
	// DeleteDevice cannot split-brain the 400-error fields (label says
	// `cisco_ios` but catalog came from `_universal`). Previously this
	// acquired RLock three times (FindDeviceByIP + CatalogFor +
	// resolvedCatalogLabel).
	cat, catLabel := sm.catalogWithLabelFor(ip)
	if cat == nil {
		return 0, fmt.Errorf("%w: catalog resolution failed for %s", ErrTrapCatalogUnavailable, ip)
	}
	entry, ok := cat.ByName[trapName]
	if !ok {
		return 0, &TrapEntryNotFoundError{
			Name:    trapName,
			Catalog: catLabel,
			Entries: sortedTrapEntryNames(cat),
		}
	}
	if device.trapExporter == nil {
		return 0, fmt.Errorf("%w: device %s has no trap exporter", ErrTrapExportDisabled, ip)
	}
	id := device.trapExporter.Fire(entry, overrides)
	if id == 0 {
		return 0, fmt.Errorf("trap fire for %s returned 0 reqID (resolve or write failure)", ip)
	}
	return id, nil
}

// sortedTrapEntryNames returns the catalog's entry names in stable
// alphabetical order — useful for deterministic HTTP 400 bodies that
// tests can assert against.
func sortedTrapEntryNames(cat *Catalog) []string {
	if cat == nil {
		return nil
	}
	out := make([]string, 0, len(cat.Entries))
	for _, e := range cat.Entries {
		out = append(out, e.Name)
	}
	sort.Strings(out)
	return out
}

// TrapEntryNotFoundError is returned when POST /trap references a catalog
// entry name that isn't in the device's resolved catalog. Embeds the
// standard ErrTrapEntryNotFound so existing errors.Is checks keep working.
type TrapEntryNotFoundError struct {
	Name    string
	Catalog string
	Entries []string
}

func (e *TrapEntryNotFoundError) Error() string {
	return fmt.Sprintf("%s: %q (catalog: %s)", ErrTrapEntryNotFound.Error(), e.Name, e.Catalog)
}
func (e *TrapEntryNotFoundError) Unwrap() error { return ErrTrapEntryNotFound }

// Sentinel errors returned by FireTrapOnDevice for HTTP status mapping.
//
// ErrTrapCatalogUnavailable signals a pathological internal state where
// the trap subsystem is started (scheduler non-nil) but neither the
// per-type catalog map nor the legacy single-catalog pointer resolves
// to a catalog. This cannot happen under normal operation — it would
// mean the manager is mid-reinitialisation or something overwrote the
// catalog state after Start. The handler maps this to 500, not 503,
// because "try again later" is misleading for a broken invariant.
var (
	ErrTrapExportDisabled     = fmt.Errorf("trap export disabled")
	ErrTrapDeviceNotFound     = fmt.Errorf("device not found")
	ErrTrapEntryNotFound      = fmt.Errorf("trap catalog entry not found")
	ErrTrapCatalogUnavailable = fmt.Errorf("trap catalog unavailable (manager state broken)")
)

// WriteTrapStatusJSON writes GetTrapStatus as JSON to w. Extracted for
// testability and because the api.go pattern in this codebase is thin handlers.
func (sm *SimulatorManager) WriteTrapStatusJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sm.GetTrapStatus())
}
