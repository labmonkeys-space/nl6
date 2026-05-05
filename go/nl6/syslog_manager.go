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

// SimulatorManager-level UDP syslog export lifecycle.
//
// `StartSyslogSubsystem` loads the catalog (embedded or file override), creates
// the shared SyslogScheduler and optional rate limiter, and starts the
// scheduler goroutine. Per-device SyslogExporters are wired in from device
// startup/teardown (see device.go) against each device's `DeviceSyslogConfig`.
// GetSyslogStatus exposes the aggregated per-(collector, format) counters to
// the HTTP API.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// SyslogStatus is the JSON body returned by GET /api/v1/syslog/status.
//
// Shape matches TrapStatus: per-device-export-config phase 5 returns an
// array-of-collectors aggregated across devices. Legacy scalar fields
// (enabled/format/collector/sent/send_failures) retired. Use
// `SubsystemActive` to distinguish "never started" from "started with
// zero devices"; `len(collectors) == 0` no longer implies feature off.
//
// `CatalogsByType` and `RateLimiterTokensAvailable` remain top-level.
type SyslogStatus struct {
	SubsystemActive            bool                         `json:"subsystem_active"`
	Collectors                 []SyslogCollectorStatus      `json:"collectors"`
	DevicesExporting           int                          `json:"devices_exporting"`
	RateLimiterTokensAvailable int                          `json:"rate_limiter_tokens_available,omitempty"`
	CatalogsByType             map[string]CatalogSourceInfo `json:"catalogs_by_type,omitempty"`
}

// SyslogCollectorStatus is one aggregate record in SyslogStatus.Collectors.
// Devices with the same (collector, format) tuple collapse into one record;
// counters are cumulative since simulator start (monotonic — persisted
// counters from deleted devices are merged at read time).
type SyslogCollectorStatus struct {
	Collector    string `json:"collector"`
	Format       string `json:"format"`
	Devices      int    `json:"devices"`
	Sent         uint64 `json:"sent"`
	SendFailures uint64 `json:"send_failures"`
}

// syslogConnKey identifies a (collector, format) tuple for the shared-socket
// pool and the monotonic counter aggregate. Format is included because the
// encoder is per-format — one socket per format-collector pair isolates
// wire-format interleave on a shared socket.
type syslogConnKey struct {
	collector string
	format    SyslogFormat
}

// syslogCollectorAggregate holds monotonic counters for a (collector, format)
// tuple that survive device deletion. Mirror of flowCollectorAggregate /
// trapCollectorAggregate.
type syslogCollectorAggregate struct {
	sent         atomic.Uint64
	sendFailures atomic.Uint64
}

// Sentinel errors returned by FireSyslogOnDevice for HTTP status mapping.
// See ErrTrapCatalogUnavailable for the rationale behind the
// "catalog unavailable" sentinel — mirror it here so the syslog handler
// can return 500 (not 503) when the manager is in a broken invariant.
var (
	ErrSyslogExportDisabled     = fmt.Errorf("syslog export disabled")
	ErrSyslogDeviceNotFound     = fmt.Errorf("device not found")
	ErrSyslogEntryNotFound      = fmt.Errorf("syslog catalog entry not found")
	ErrSyslogCatalogUnavailable = fmt.Errorf("syslog catalog unavailable (manager state broken)")
)

// SyslogEntryNotFoundError is returned by FireSyslogOnDevice when the
// catalog entry name is unknown for the device's resolved catalog. Shape
// mirrors TrapEntryNotFoundError.
type SyslogEntryNotFoundError struct {
	Name    string
	Catalog string
	Entries []string
}

func (e *SyslogEntryNotFoundError) Error() string {
	return fmt.Sprintf("%s: %q (catalog: %s)", ErrSyslogEntryNotFound.Error(), e.Name, e.Catalog)
}
func (e *SyslogEntryNotFoundError) Unwrap() error { return ErrSyslogEntryNotFound }

// syslogCatalogSource returns the `source` string for a CatalogSourceInfo
// on the syslog side (mirror of trapCatalogSource).
func syslogCatalogSource(slug, catalogFlagPath string) string {
	if catalogFlagPath != "" {
		return "override:" + catalogFlagPath
	}
	if slug == universalCatalogKey {
		return "embedded"
	}
	return fmt.Sprintf("file:%s/%s/syslog.json", trapCatalogResourceDir, slug)
}

// syslogCatalogWithLabelFor mirrors `catalogWithLabelFor` on the trap
// side — returns both the resolved catalog and its label under a single
// RLock so the 400-error path can't split-brain between them.
func (sm *SimulatorManager) syslogCatalogWithLabelFor(ip string) (*SyslogCatalog, string) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.syslogCatalogsByType == nil {
		return sm.syslogCatalog, universalCatalogKey
	}
	if slug, ok := sm.deviceTypesByIP[ip]; ok {
		if cat, found := sm.syslogCatalogsByType[slug]; found {
			return cat, slug
		}
	}
	if cat := sm.syslogCatalogsByType[universalCatalogKey]; cat != nil {
		return cat, universalCatalogKey
	}
	return sm.syslogCatalog, universalCatalogKey
}

// sortedSyslogEntryNames returns the catalog's entry names alphabetically.
func sortedSyslogEntryNames(cat *SyslogCatalog) []string {
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

// SyslogSubsystemConfig bundles the simulator-wide knobs still owned by the
// manager after the per-device-export-config refactor. Per-device knobs
// (collector / format / interval) live on each `DeviceSyslogConfig`.
type SyslogSubsystemConfig struct {
	CatalogPath     string
	GlobalCap       int  // 0 = unlimited
	SourcePerDevice bool // bind per-device UDP socket in opensim ns
	// MeanSchedulerInterval seeds the scheduler's Poisson draw when no
	// device-specific intervals are known. Individual devices still
	// register with their own per-device interval on the heap.
	MeanSchedulerInterval time.Duration
}

// StartSyslogSubsystem loads the catalog, creates the shared scheduler
// and optional rate limiter, and starts the scheduler goroutine. The
// subsystem is always-on after this runs — per-device attach via
// `startDeviceSyslogExporter` later wires individual exporters in.
//
// Replaces pre-phase-5 `StartSyslogExport`: the per-device collector /
// format / interval settings are now on each `DeviceSyslogConfig`. The
// manager no longer holds those values simulator-wide.
func (sm *SimulatorManager) StartSyslogSubsystem(cfg SyslogSubsystemConfig) error {
	if sm.syslogScheduler.Load() != nil {
		return fmt.Errorf("syslog export: subsystem already started")
	}
	if cfg.GlobalCap < 0 {
		return fmt.Errorf("syslog export: -syslog-global-cap must be non-negative, got %d", cfg.GlobalCap)
	}
	if cfg.MeanSchedulerInterval <= 0 {
		log.Printf("syslog export: MeanSchedulerInterval <= 0, defaulting to 10s (phase-5 review P12)")
		cfg.MeanSchedulerInterval = 10 * time.Second
	}
	// Mirror the scheduler's sub-millisecond floor — sub-ms intervals
	// busy-loop when no global cap is set.
	if cfg.MeanSchedulerInterval < time.Millisecond {
		return fmt.Errorf("syslog export: MeanSchedulerInterval must be >= 1ms, got %s", cfg.MeanSchedulerInterval)
	}

	var catalog *SyslogCatalog
	var err error
	if cfg.CatalogPath == "" {
		catalog, err = LoadEmbeddedSyslogCatalog()
	} else {
		catalog, err = LoadSyslogCatalogFromFile(cfg.CatalogPath)
	}
	if err != nil {
		return err
	}

	catalogsByType := map[string]*SyslogCatalog{
		universalCatalogKey: catalog,
	}
	if cfg.CatalogPath == "" {
		perType, scanErr := ScanPerTypeSyslogCatalogs(catalog, trapCatalogResourceDir)
		if scanErr != nil {
			return fmt.Errorf("syslog export: scanning per-type catalogs: %w", scanErr)
		}
		for slug, c := range perType {
			catalogsByType[slug] = c
		}
	}

	var limiter *rate.Limiter
	if cfg.GlobalCap > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.GlobalCap), cfg.GlobalCap)
	}

	scheduler := NewSyslogScheduler(SyslogSchedulerOptions{
		CatalogFor:         func(ip net.IP) *SyslogCatalog { return sm.SyslogCatalogFor(ip.String()) },
		MeanInterval:       cfg.MeanSchedulerInterval,
		GlobalCapPerSecond: cfg.GlobalCap,
	})

	sm.mu.Lock()
	sm.syslogCatalog = catalog
	sm.syslogCatalogsByType = catalogsByType
	sm.syslogEncodersByFmt = map[SyslogFormat]SyslogEncoder{}
	sm.syslogLimiter = limiter
	sm.syslogGlobalCap = cfg.GlobalCap
	sm.syslogSourcePerDevice = cfg.SourcePerDevice
	sm.syslogCatalogPath = cfg.CatalogPath
	// Publish the scheduler under sm.mu.Lock alongside the dependent
	// fields so any reader holding sm.mu.RLock sees a consistent
	// snapshot (scheduler-non-nil ⇔ deps populated). atomic.Pointer is
	// only here so getSyslogScheduler can Load lock-free from the
	// DeleteDevice path.
	sm.syslogScheduler.Store(scheduler)
	sm.mu.Unlock()

	capStr := "unlimited"
	if cfg.GlobalCap > 0 {
		capStr = fmt.Sprintf("%d/s", cfg.GlobalCap)
	}
	catStr := "<embedded>"
	if cfg.CatalogPath != "" {
		catStr = cfg.CatalogPath
	}
	log.Printf("Syslog subsystem: ready (cap=%s, catalog=%s, per-device-source=%v) — awaiting per-device config",
		capStr, catStr, cfg.SourcePerDevice)

	go scheduler.Run(context.Background())

	return nil
}

// syslogEncoderFor returns the shared encoder for a given wire format.
// Lazily constructs and caches so StartSyslogSubsystem doesn't need to
// know which formats will be used at boot. Safe for concurrent use.
func (sm *SimulatorManager) syslogEncoderFor(format SyslogFormat) (SyslogEncoder, error) {
	sm.mu.RLock()
	if enc, ok := sm.syslogEncodersByFmt[format]; ok {
		sm.mu.RUnlock()
		return enc, nil
	}
	sm.mu.RUnlock()
	enc, err := NewSyslogEncoder(format)
	if err != nil {
		return nil, err
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	// Double-check after re-acquiring the write lock in case another
	// goroutine raced us.
	if existing, ok := sm.syslogEncodersByFmt[format]; ok {
		return existing, nil
	}
	sm.syslogEncodersByFmt[format] = enc
	return enc, nil
}

// syslogConnFor returns the shared-pool UDP socket for a (collector, format)
// tuple. First caller for a key opens the socket; subsequent callers reuse
// it. Returns nil if the socket can't be opened. Safe for concurrent use.
func (sm *SimulatorManager) syslogConnFor(key syslogConnKey) *net.UDPConn {
	if cached, ok := sm.syslogConns.Load(key); ok {
		return cached.(*net.UDPConn)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		log.Printf("syslog export: failed to open shared socket for %s (format=%s): %v",
			key.collector, key.format, err)
		return nil
	}
	actual, loaded := sm.syslogConns.LoadOrStore(key, conn)
	if loaded {
		_ = conn.Close()
		return actual.(*net.UDPConn)
	}
	return conn
}

// closeSyslogConnPool closes every pooled shared socket and removes its
// map entry so a subsequent `syslogConnFor` after `StartSyslogSubsystem`
// cannot return a closed *net.UDPConn.
func (sm *SimulatorManager) closeSyslogConnPool() {
	sm.syslogConns.Range(func(k, v interface{}) bool {
		if conn, ok := v.(*net.UDPConn); ok {
			_ = conn.Close()
		}
		sm.syslogConns.Delete(k)
		return true
	})
}

// getSyslogScheduler returns the manager's syslog scheduler pointer
// via a lock-free atomic Load so callers (notably device.Stop, which
// runs under sm.mu.Lock from the DeleteDevice path) cannot
// self-deadlock by re-entering sm.mu. The atomic also closes the
// original D3 race against a concurrent StopSyslogExport. Safe with
// nil manager.
func getSyslogScheduler(sm *SimulatorManager) *SyslogScheduler {
	if sm == nil {
		return nil
	}
	return sm.syslogScheduler.Load()
}

// persistSyslogCounters snapshots a SyslogExporter's cumulative counters
// into the simulator-wide per-(collector, format) aggregate so
// /syslog/status reports monotonic totals across DEVICE CHURN WITHIN
// ONE SUBSYSTEM LIFECYCLE (create/delete a device — counters persist).
// A Stop→Start cycle resets sm.syslogAggregates and starts from zero by
// design (phase-5 review P2 scope clarification).
//
// Idempotent per exporter via countersPersisted sync.Once, so
// concurrent Stop paths cannot double-count. Safe to call with nil
// exporter.
func (sm *SimulatorManager) persistSyslogCounters(fe *SyslogExporter) {
	if fe == nil {
		return
	}
	collector := fe.CollectorString()
	if collector == "" {
		return
	}
	fe.countersPersisted.Do(func() {
		key := syslogConnKey{collector: collector, format: fe.Format()}
		v, _ := sm.syslogAggregates.LoadOrStore(key, &syslogCollectorAggregate{})
		agg := v.(*syslogCollectorAggregate)
		stats := fe.Stats()
		agg.sent.Add(stats.Sent.Load())
		agg.sendFailures.Add(stats.SendFailures.Load())
	})
}

// StopSyslogExport stops the scheduler, closes every pooled shared socket,
// and closes every device's SyslogExporter. Safe to call when the subsystem
// was never started (no-op).
//
// CONSTRAINT — process-shutdown only (phase-5 review D1):
// StopSyslogExport is NOT safe to race concurrent device creation. See
// the equivalent note on StopTrapExport. Today it is only called from
// the process-exit signal handler (Shutdown). Do not introduce a
// runtime "restart syslog subsystem" path without first tightening the
// attach-path lock discipline (deferred D1 follow-up in the
// per-device-export-config change).
func (sm *SimulatorManager) StopSyslogExport() {
	scheduler := sm.syslogScheduler.Load()
	if scheduler == nil {
		return // subsystem never started
	}

	// Snapshot per-device exporters under each device's own mutex so we
	// don't race `startDeviceSyslogExporter` (which writes under d.mu).
	sm.mu.RLock()
	type devExp struct {
		d   *DeviceSimulator
		exp *SyslogExporter
	}
	captured := make([]devExp, 0, len(sm.devices))
	for _, d := range sm.devices {
		d.mu.Lock()
		exp := d.syslogExporter
		d.syslogExporter = nil
		d.mu.Unlock()
		if exp != nil {
			captured = append(captured, devExp{d: d, exp: exp})
		}
	}
	sm.mu.RUnlock()

	scheduler.Stop()
	for _, ce := range captured {
		sm.persistSyslogCounters(ce.exp)
		_ = ce.exp.Close()
	}
	sm.closeSyslogConnPool()

	sm.mu.Lock()
	// Clear the scheduler under sm.mu.Lock alongside the dependent
	// fields so any reader holding sm.mu.RLock sees a consistent
	// snapshot (scheduler-nil ⇔ deps cleared).
	sm.syslogScheduler.Store(nil)
	sm.syslogCatalog = nil
	sm.syslogCatalogsByType = nil
	sm.syslogCatalogPath = ""
	sm.syslogEncodersByFmt = nil
	// Reset monotonic counter aggregates + first-attach log so a
	// subsequent StartSyslogSubsystem starts from zero and logs the
	// first attach again. atomic.Bool Store is race-free against
	// concurrent CAS readers — replaces the earlier sync.Once{}
	// reassignment which was a data race with the Do() call in
	// startDeviceSyslogExporter (phase-5 review P3).
	sm.syslogAggregates = sync.Map{}
	sm.syslogFirstAttachLog.Store(false)
	sm.syslogIntervalWarned.Store(false)
	// Reset subsystem-scalar state so a subsequent StartSyslogSubsystem
	// starts from a clean slate (phase-5 review P-E1).
	sm.syslogLimiter = nil
	sm.syslogGlobalCap = 0
	sm.syslogSourcePerDevice = false
	sm.mu.Unlock()
}

// startDeviceSyslogExporter creates a SyslogExporter for a device that
// already has `device.syslogConfig` populated. Opens a per-device UDP
// socket when `-syslog-source-per-device=true`, falls back to the
// shared-pool socket keyed by (collector, format) otherwise. Registers
// the exporter with the central scheduler.
//
// Per-device bind failure is NEVER fatal for syslog — the device falls
// back to the shared socket and a warning is logged (preserves the
// existing syslog bind-failure semantic per spec). Other error paths —
// subsystem not started, bad format, unresolvable collector — return an
// error so the caller can clear `device.syslogConfig` and skip the
// device cleanly.
//
// Must be called only after `StartSyslogSubsystem` — caller enforces.
func (sm *SimulatorManager) startDeviceSyslogExporter(device *DeviceSimulator) error {
	if device == nil || device.syslogConfig == nil {
		return nil
	}
	cfg := device.syslogConfig

	format, err := ParseSyslogFormat(cfg.Format)
	if err != nil {
		return fmt.Errorf("syslog export: parse format: %w", err)
	}

	// Snapshot scheduler + dependent fields under one RLock so a
	// concurrent Stop cannot interleave between the scheduler nil-check
	// and the rest of the snapshot. With Store inside sm.mu.Lock the
	// RLock window is the consistent unit.
	sm.mu.RLock()
	scheduler := sm.syslogScheduler.Load()
	sourcePerDevice := sm.syslogSourcePerDevice
	deviceIPStr := device.IP.String()
	modelLabel := modelLabelForSlug(sm.deviceTypesByIP[deviceIPStr])
	sm.mu.RUnlock()

	if scheduler == nil {
		return fmt.Errorf("syslog export: subsystem not started; call StartSyslogSubsystem first")
	}

	encoder, err := sm.syslogEncoderFor(format)
	if err != nil {
		return fmt.Errorf("syslog export: encoder: %w", err)
	}

	collectorAddr, err := net.ResolveUDPAddr("udp4", cfg.Collector)
	if err != nil {
		return fmt.Errorf("syslog export: resolve collector %q: %w", cfg.Collector, err)
	}
	canonicalCollector := collectorAddr.String()

	// Open per-device socket first (when enabled) so we know whether to
	// wire in the shared-pool fallback; passing SharedConn at
	// construction avoids an unsynchronised post-hoc field write.
	var perDeviceConn *net.UDPConn
	if sourcePerDevice {
		perDeviceConn = openSyslogConnForDevice(device)
		if perDeviceConn == nil {
			log.Printf("syslog export: device %s per-device bind failed, falling back to shared-pool socket", device.IP)
		}
	}
	var sharedConn *net.UDPConn
	if perDeviceConn == nil {
		sharedConn = sm.syslogConnFor(syslogConnKey{collector: canonicalCollector, format: format})
		if sharedConn == nil {
			// Both per-device bind and shared-pool open failed — refuse
			// the attach so the caller clears device.syslogConfig.
			// Constructing an exporter with nil sockets would silently
			// drop every fire via errNoSyslogSocket (phase-5 review P10).
			return fmt.Errorf("syslog export: no UDP socket available for device %s → %s", device.IP, canonicalCollector)
		}
	}

	opts := SyslogExporterOptions{
		DeviceIP:     device.IP,
		Encoder:      encoder,
		Collector:    collectorAddr,
		CollectorStr: canonicalCollector,
		Format:       format,
		SharedConn:   sharedConn,
		SysName:      device.sysName,
		Model:        modelLabel,
		Serial:       synthSerial(device.IP),
		ChassisID:    synthChassisID(device.IP),
		IfIndexFn:    deviceIfIndexFn(device),
		IfNameFn:     deviceIfNameFn(device),
	}

	exporter := NewSyslogExporter(opts)
	if perDeviceConn != nil {
		exporter.SetConn(perDeviceConn)
	}

	device.mu.Lock()
	device.syslogExporter = exporter
	device.mu.Unlock()

	// Per-device Interval is stored on cfg but not honored by the
	// scheduler today — the scheduler draws Poisson fires from its
	// simulator-wide MeanInterval (design debt, same pattern as trap
	// Interval and flow TickInterval). Warn ONCE per subsystem
	// lifecycle — per-device logging floods at fleet scale (phase-5
	// review P13).
	if time.Duration(cfg.Interval) != 0 && time.Duration(cfg.Interval) != scheduler.MeanInterval() {
		if sm.syslogIntervalWarned.CompareAndSwap(false, true) {
			log.Printf("syslog export: device %s configured interval=%s but the scheduler runs at mean=%s; per-device intervals are not yet honored (further divergences suppressed this lifecycle)",
				device.IP, time.Duration(cfg.Interval), scheduler.MeanInterval())
		}
	}

	scheduler.Register(device.IP, exporter)

	// CAS-gated first-attach log; race-free vs. StopSyslogExport's
	// reset to false (phase-5 review P3).
	if sm.syslogFirstAttachLog.CompareAndSwap(false, true) {
		log.Printf("syslog export: active; first device %s → %s (format=%s)",
			device.IP, canonicalCollector, format)
	}
	return nil
}

// deviceIfNameFn returns the ifName for a given ifIndex on the device.
//
// Live-lookup path: reads `ifDescr.<ifIndex>` (OID `1.3.6.1.2.1.2.2.1.2.N`)
// from the device's SNMP OID table. When present, this yields vendor-
// flavoured interface names like `TenGigE0/0/0/5` for Cisco IOS-XR or
// `ge-0/0/5` for Juniper — exactly what vendor catalog realism needs
// (design.md §D4, closes epic #103 task 3.2). When the OID is absent
// (e.g. for a device type that doesn't ship an ifTable, or for an
// ifIndex outside the loaded resource set) the fallback is the pre-PR-3
// synthesised `GigabitEthernet0/<N>` so old fixtures continue to render.
//
// Zero or negative ifIndex returns "" — matches the pre-existing guard
// and keeps the exporter's default safe for devices with no interfaces.
func deviceIfNameFn(device *DeviceSimulator) func(int) string {
	return func(ifIndex int) string {
		if ifIndex <= 0 {
			return ""
		}
		if name := lookupIfDescr(device, ifIndex); name != "" {
			return name
		}
		return synthIfName(ifIndex)
	}
}

// lookupIfDescr returns the device's `ifDescr.<ifIndex>` value from the
// SNMP OID table, or "" when the OID is absent. Factored out so the
// `FieldResolver.IfName` path and `deviceIfNameFn` share one lookup.
//
// The OID key format is dot-prefixed (e.g. `.1.3.6.1.2.1.2.2.1.2.5`) to
// match `resources.go` normalisation (all OID keys get a leading dot
// when loaded). sync.Map read is lock-free and constant-time.
func lookupIfDescr(device *DeviceSimulator, ifIndex int) string {
	if device == nil || device.resources == nil || device.resources.oidIndex == nil {
		return ""
	}
	key := fmt.Sprintf(".1.3.6.1.2.1.2.2.1.2.%d", ifIndex)
	v, ok := device.resources.oidIndex.Load(key)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// GetSyslogStatus returns a JSON-serializable snapshot of the syslog
// export state. Exposed via GET /api/v1/syslog/status.
//
// Shape matches GetFlowStatus / GetTrapStatus: live per-device exporters
// aggregated by (collector, format); counters from deleted devices
// persisted in sm.syslogAggregates are folded in so totals remain
// monotonic within the current subsystem lifecycle.
//
// `SubsystemActive` is the authoritative "is the feature live?" signal —
// true when StartSyslogSubsystem has run and StopSyslogExport has not.
// `len(Collectors) == 0` is NOT sufficient on its own: it also occurs
// when the subsystem is running but no device has opted in, or after a
// Stop (which clears the catalog + aggregate maps). After Stop, this
// function returns `{SubsystemActive: false, Collectors: [], …}`.
func (sm *SimulatorManager) GetSyslogStatus() SyslogStatus {
	agg := make(map[syslogConnKey]*SyslogCollectorStatus)

	sm.mu.RLock()
	limiter := sm.syslogLimiter
	status := SyslogStatus{SubsystemActive: sm.syslogScheduler.Load() != nil}

	if len(sm.syslogCatalogsByType) > 0 {
		status.CatalogsByType = make(map[string]CatalogSourceInfo, len(sm.syslogCatalogsByType))
		for slug, cat := range sm.syslogCatalogsByType {
			status.CatalogsByType[slug] = CatalogSourceInfo{
				Entries: len(cat.Entries),
				Source:  syslogCatalogSource(slug, sm.syslogCatalogPath),
			}
		}
	}

	for _, d := range sm.devices {
		// Snapshot the exporter pointer under d.mu so a concurrent Stop
		// path can't race this read.
		d.mu.RLock()
		exp := d.syslogExporter
		d.mu.RUnlock()
		if exp == nil {
			continue
		}
		key := syslogConnKey{collector: exp.CollectorString(), format: exp.Format()}
		rec, ok := agg[key]
		if !ok {
			rec = &SyslogCollectorStatus{
				Collector: exp.CollectorString(),
				Format:    string(exp.Format()),
			}
			agg[key] = rec
		}
		rec.Devices++
		st := exp.Stats()
		rec.Sent += st.Sent.Load()
		rec.SendFailures += st.SendFailures.Load()
	}

	var tokens int
	if limiter != nil {
		tokens = int(limiter.Tokens())
	}
	sm.mu.RUnlock()

	// Fold persisted counters for tuples whose devices have since been
	// deleted. A tuple with no live exporters still surfaces so operators
	// keep seeing cumulative totals.
	sm.syslogAggregates.Range(func(k, v interface{}) bool {
		key := k.(syslogConnKey)
		pers := v.(*syslogCollectorAggregate)
		rec, ok := agg[key]
		if !ok {
			rec = &SyslogCollectorStatus{
				Collector: key.collector,
				Format:    string(key.format),
			}
			agg[key] = rec
		}
		rec.Sent += pers.sent.Load()
		rec.SendFailures += pers.sendFailures.Load()
		return true
	})

	collectors := make([]SyslogCollectorStatus, 0, len(agg))
	devicesExporting := 0
	for _, rec := range agg {
		collectors = append(collectors, *rec)
		devicesExporting += rec.Devices
	}
	sort.Slice(collectors, func(i, j int) bool {
		if collectors[i].Collector != collectors[j].Collector {
			return collectors[i].Collector < collectors[j].Collector
		}
		return collectors[i].Format < collectors[j].Format
	})

	status.Collectors = collectors
	status.DevicesExporting = devicesExporting
	if limiter != nil {
		status.RateLimiterTokensAvailable = tokens
	}
	return status
}

// FireSyslogOnDevice implements POST /api/v1/devices/{ip}/syslog by looking
// up the device's SyslogExporter and invoking Fire with the given catalog
// name. On-demand fires bypass the global rate limiter (pre-flight 1.4
// resolution) — the scheduler is the only consumer of the limiter; direct
// Fire calls write immediately.
//
// Returns errors tagged so the HTTP layer can map them:
//   - ErrSyslogExportDisabled → 503 Service Unavailable
//   - ErrSyslogDeviceNotFound → 404
//   - ErrSyslogEntryNotFound  → 400
func (sm *SimulatorManager) FireSyslogOnDevice(ip, entryName string, overrides map[string]string) error {
	if sm.syslogScheduler.Load() == nil {
		return ErrSyslogExportDisabled
	}
	device := sm.FindDeviceByIP(ip)
	if device == nil {
		return fmt.Errorf("%w: %q", ErrSyslogDeviceNotFound, ip)
	}
	// One RLock for catalog + label — see catalogWithLabelFor on the
	// trap side for rationale.
	cat, catLabel := sm.syslogCatalogWithLabelFor(ip)
	if cat == nil {
		return fmt.Errorf("%w: catalog resolution failed for %s", ErrSyslogCatalogUnavailable, ip)
	}
	entry, ok := cat.ByName[entryName]
	if !ok {
		return &SyslogEntryNotFoundError{
			Name:    entryName,
			Catalog: catLabel,
			Entries: sortedSyslogEntryNames(cat),
		}
	}
	// Snapshot the exporter pointer under d.mu so a concurrent Stop can't
	// nil it between the guard check and the Fire call (TOCTOU).
	device.mu.RLock()
	exp := device.syslogExporter
	device.mu.RUnlock()
	if exp == nil {
		return fmt.Errorf("%w: device %s has no syslog exporter", ErrSyslogExportDisabled, ip)
	}
	return exp.Fire(entry, overrides)
}

// WriteSyslogStatusJSON writes GetSyslogStatus as JSON to w. Extracted for
// testability and because the api.go pattern in this codebase is thin handlers.
func (sm *SimulatorManager) WriteSyslogStatusJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sm.GetSyslogStatus())
}

// SyslogCatalogFor returns the syslog catalog to use for the device with the
// given IP. Resolution order: device-IP → type-slug → syslogCatalogsByType
// → syslogCatalogsByType["_universal"] (the universal). Symmetric with
// `CatalogFor` on the trap side.
func (sm *SimulatorManager) SyslogCatalogFor(ip string) *SyslogCatalog {
	cat, _ := sm.syslogCatalogWithLabelFor(ip)
	return cat
}
