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

// Per-device syslog exporter.
//
// One SyslogExporter per DeviceSimulator owns the device's UDP socket and a
// shared SyslogEncoder. The scheduler calls Fire() to emit a scheduled
// message; the HTTP endpoint also calls Fire() for on-demand sends.
//
// This is intentionally simpler than TrapExporter: UDP syslog is fire-and-
// forget (no INFORM analog), so there is no pending-state map, no ack
// reader goroutine, no retry loop, and no request-id counter. Everything
// happens inline on the Fire() call path.
//
// Design references: design.md §D7 (per-device UDP source), §D8 (encoder
// interface). See specs/syslog-export/spec.md for SHALL requirements.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SyslogStats holds cumulative counters for a SyslogExporter. Fields are
// atomic so they're safe to read concurrently with Fire.
type SyslogStats struct {
	// Sent counts every datagram successfully written to the wire.
	Sent atomic.Uint64
	// SendFailures counts Fire invocations that failed to write (encoder
	// error, UDP write error, closed socket, etc.).
	SendFailures atomic.Uint64
}

// SyslogExporter is owned by one DeviceSimulator. Construct via
// NewSyslogExporter and call SetConn once the per-device UDP socket has
// been bound inside the device's network namespace. Close releases the
// socket and marks the exporter as closing (subsequent Fire calls no-op).
type SyslogExporter struct {
	deviceIP     net.IP
	encoder      SyslogEncoder
	collector    *net.UDPAddr
	collectorStr string       // canonical "host:port" for status aggregation keying
	format       SyslogFormat // wire format this exporter is emitting

	// firstWriteErr gates at most one log line per exporter on a failed
	// write (review fix pattern from trap phase 4 P8).
	firstWriteErr sync.Once

	// countersPersisted ensures SimulatorManager.persistSyslogCounters adds
	// this exporter's counters into the simulator-wide aggregate at most
	// once. Both device.Stop / stopListenersOnly and StopSyslogExport can
	// invoke persistence; the sync.Once makes it race-free without
	// per-callsite locking.
	countersPersisted sync.Once

	// conn is the per-device UDP socket. Nil when per-device binding was
	// disabled or failed and the fallback shared socket is used. Stored as
	// atomic.Pointer so Close / Fire can observe writes safely without
	// holding a mutex in the hot path.
	conn atomic.Pointer[net.UDPConn]

	// sharedConn is the fallback UDP socket used when per-device bind is
	// disabled or failed. Read-only after construction.
	sharedConn *net.UDPConn

	// sysName is the device's SNMP sysName.0 value, captured once at
	// construction. Pre-flight 1.2 deferred the catalog-level caching
	// question to PR3 (device lifecycle wiring); for PR2 the value is
	// injected by the caller so the exporter never touches the SNMP stack.
	sysName string

	// model / serial / chassisID are Class 1 device-context fields
	// captured at construction (stable for the device's lifetime).
	// Consumed by `{{.Model}}` / `{{.Serial}}` / `{{.ChassisID}}`
	// templates from the unified vocabulary.
	model     string
	serial    string
	chassisID string

	// ifIndexFn / ifNameFn return template-context values per fire.
	// ifIndexFn may be nil — in that case IfIndex = 0. ifNameFn receives
	// the index returned by ifIndexFn and yields the matching interface
	// name (empty if no mapping exists).
	ifIndexFn func() int
	ifNameFn  func(ifIndex int) string

	startTime time.Time
	stats     *SyslogStats

	closing atomic.Bool
}

// SyslogExporterOptions bundles per-device exporter configuration.
type SyslogExporterOptions struct {
	DeviceIP     net.IP
	Encoder      SyslogEncoder
	Collector    *net.UDPAddr
	CollectorStr string       // canonical "host:port"; used for status aggregation key
	Format       SyslogFormat // wire format; used for status aggregation key
	SharedConn   *net.UDPConn // fallback; may be nil
	SysName      string       // device's sysName.0 value — empty falls back to DeviceIP at encode time
	// Class 1 device-context fields. Constant for the device's lifetime;
	// consumed by `{{.Model}}` / `{{.Serial}}` / `{{.ChassisID}}` in the
	// unified template vocabulary.
	Model     string
	Serial    string
	ChassisID string
	IfIndexFn func() int
	IfNameFn  func(ifIndex int) string
}

// NewSyslogExporter builds a SyslogExporter. The per-device conn is not
// opened here — callers call SetConn once the socket is bound inside the
// device's netns (see openSyslogConnForDevice below).
//
// Panics on invalid options (nil/zero DeviceIP, nil Collector). Matches the
// panic-on-misconfiguration style of NewSyslogScheduler and NewTrapScheduler:
// these are programmer errors at construction time, not runtime faults.
func NewSyslogExporter(opts SyslogExporterOptions) *SyslogExporter {
	if len(opts.DeviceIP) == 0 {
		panic("NewSyslogExporter: DeviceIP required")
	}
	if opts.Collector == nil {
		panic("NewSyslogExporter: Collector required")
	}
	if opts.Encoder == nil {
		// Default to RFC 5424 so a constructor typo doesn't ship RFC 3164
		// by accident. In practice the manager always passes one explicitly.
		opts.Encoder = &RFC5424Encoder{}
	}
	if opts.IfIndexFn == nil {
		opts.IfIndexFn = func() int { return 0 }
	}
	if opts.IfNameFn == nil {
		opts.IfNameFn = func(int) string { return "" }
	}
	return &SyslogExporter{
		deviceIP:     append(net.IP(nil), opts.DeviceIP...),
		encoder:      opts.Encoder,
		collector:    opts.Collector,
		collectorStr: opts.CollectorStr,
		format:       opts.Format,
		sharedConn:   opts.SharedConn,
		sysName:      opts.SysName,
		model:        opts.Model,
		serial:       opts.Serial,
		chassisID:    opts.ChassisID,
		ifIndexFn:    opts.IfIndexFn,
		ifNameFn:     opts.IfNameFn,
		startTime:    time.Now(),
		stats:        &SyslogStats{},
	}
}

// CollectorString returns the canonical "host:port" string identifying
// this exporter's destination. Used as the (collector, format) key for
// the shared-socket pool and the status-endpoint aggregate.
func (e *SyslogExporter) CollectorString() string { return e.collectorStr }

// Format returns the exporter's wire format (5424 or 3164). Used as the
// (collector, format) key for the status-endpoint aggregate.
func (e *SyslogExporter) Format() SyslogFormat { return e.format }

// logFirstWriteErr emits at most one log line per exporter on a failed
// write. Gated by e.firstWriteErr so a down/misconfigured collector
// doesn't flood logs at fire cadence × device count (mirror of
// TrapExporter.logFirstWriteErr from trap phase 4 P8).
func (e *SyslogExporter) logFirstWriteErr(err error) {
	if e == nil || err == nil {
		return
	}
	e.firstWriteErr.Do(func() {
		log.Printf("syslog export: device %s write to %s failed: %v (further errors suppressed for this exporter)",
			e.deviceIP, e.collectorStr, err)
	})
}

// SetConn installs the per-device UDP socket. Must be called before the
// exporter is registered with the scheduler if per-device source IPs are
// desired. Passing nil unsets the socket; subsequent Fire calls fall back
// to the shared socket if one was configured.
//
// If a previous conn was installed, it is closed here — callers do not
// need to close it themselves, and forgetting to would leak a file
// descriptor per rebind.
func (e *SyslogExporter) SetConn(c *net.UDPConn) {
	old := e.conn.Swap(c)
	if old != nil && old != c {
		_ = old.Close()
	}
}

// Stats returns a pointer to the exporter's atomic stats. The underlying
// counters are safe to read concurrently; the pointer is stable for the
// exporter's lifetime.
func (e *SyslogExporter) Stats() *SyslogStats { return e.stats }

// Fire emits one syslog message for the given catalog entry. Implements
// syslogFirer for the scheduler. Safe for concurrent calls and safe to
// call on a closing exporter (silently no-ops).
//
// overrides, when non-nil, force specific template field values (used by
// POST /api/v1/devices/{ip}/syslog). Returns an error only on encode or
// write failure; nil return implies a datagram reached the socket's
// send path (UDP transmission beyond that point is fire-and-forget).
func (e *SyslogExporter) Fire(entry *SyslogCatalogEntry, overrides map[string]string) error {
	if e == nil || entry == nil || e.closing.Load() {
		return nil
	}

	ifIndex := e.ifIndexFn()
	ctx := SyslogTemplateCtx{
		DeviceIP:  e.deviceIP.String(),
		SysName:   e.sysName,
		IfIndex:   ifIndex,
		IfName:    e.ifNameFn(ifIndex),
		Now:       time.Now().Unix(),
		Uptime:    e.uptimeHundredths(),
		Model:     e.model,
		Serial:    e.serial,
		ChassisID: e.chassisID,
	}
	resolved, err := entry.Resolve(ctx, overrides)
	if err != nil {
		e.stats.SendFailures.Add(1)
		log.Printf("syslog: resolve %s for %s: %v", entry.Name, e.deviceIP, err)
		return err
	}

	// Hostname fallback per design.md §D5: catalog template (if any) wins,
	// otherwise sysName, otherwise DeviceIP. The catalog-template case has
	// already filled resolved.Hostname inside entry.Resolve.
	if resolved.Hostname == "" {
		if ctx.SysName != "" {
			resolved.Hostname = ctx.SysName
		} else {
			resolved.Hostname = ctx.DeviceIP
		}
	}

	var buf bytes.Buffer
	buf.Grow(e.encoder.MaxMessageSize())
	if err := e.encoder.Encode(&buf, resolved, time.Now()); err != nil {
		e.stats.SendFailures.Add(1)
		log.Printf("syslog: encode %s for %s: %v", entry.Name, e.deviceIP, err)
		return err
	}

	if err := e.writeDatagram(buf.Bytes()); err != nil {
		// Shutdown race: Close may have invalidated the socket we captured
		// before the write. The message was lost, but not because of an
		// actual send failure — attributing it to SendFailures confuses
		// operator dashboards. Silently drop.
		if e.closing.Load() {
			return nil
		}
		e.stats.SendFailures.Add(1)
		return err
	}
	e.stats.Sent.Add(1)
	return nil
}

// writeDatagram sends pdu to the collector using the per-device socket
// (preferred) or the shared fallback.
//
// Error reporting: on fallback, if the per-device write fails but the
// shared write succeeds, the per-device error is LOGGED (so operators can
// debug the primary failure) but nil is returned so the caller's counter
// treats it as a successful send. If both writes fail, a joined error is
// returned carrying both causes so callers don't lose the primary
// diagnostic.
func (e *SyslogExporter) writeDatagram(pdu []byte) error {
	var primaryErr error
	conn := e.conn.Load()
	if conn != nil {
		if _, err := conn.WriteToUDP(pdu, e.collector); err == nil {
			return nil
		} else {
			primaryErr = fmt.Errorf("per-device socket: %w", err)
		}
	}
	if e.sharedConn == nil {
		if primaryErr != nil {
			e.logFirstWriteErr(primaryErr)
			return primaryErr
		}
		e.logFirstWriteErr(errNoSyslogSocket)
		return errNoSyslogSocket
	}
	_, err := e.sharedConn.WriteToUDP(pdu, e.collector)
	if err == nil {
		if primaryErr != nil {
			// Fallback succeeded — log the primary failure so the operator
			// can diagnose why the per-device path stopped working.
			log.Printf("syslog: %s per-device write failed, sent via shared socket: %v",
				e.deviceIP, primaryErr)
		}
		return nil
	}
	sharedErr := fmt.Errorf("shared socket: %w", err)
	var finalErr error
	if primaryErr != nil {
		finalErr = errors.Join(primaryErr, sharedErr)
	} else {
		finalErr = sharedErr
	}
	e.logFirstWriteErr(finalErr)
	return finalErr
}

// uptimeHundredths returns device uptime in 1/100-second ticks, matching
// SNMP TimeTicks semantics so templates can share `{{.Uptime}}` with the
// trap capability.
func (e *SyslogExporter) uptimeHundredths() uint32 {
	return uint32(time.Since(e.startTime) / (10 * time.Millisecond))
}

// Close marks the exporter as closing and releases the per-device socket.
// Safe for concurrent Close / Fire; idempotent.
func (e *SyslogExporter) Close() error {
	if e == nil {
		return nil
	}
	e.closing.Store(true)
	conn := e.conn.Swap(nil)
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// errNoSyslogSocket is returned by Fire when neither a per-device nor a
// shared UDP socket is configured.
var errNoSyslogSocket = newSyslogErr("no UDP socket configured for syslog export")

// syslogErr is a typed error so callers can branch on it if needed.
type syslogErr struct{ msg string }

func (e *syslogErr) Error() string { return e.msg }
func newSyslogErr(m string) error  { return &syslogErr{msg: m} }

// openSyslogConnForDevice opens a per-device UDP socket bound to the
// device's IP inside the opensim netns. Mirrors openTrapConnForDevice:
// per design.md §D1 each subsystem owns its own socket lifecycle — sharing
// a helper would require subsystem-kind parameters and would still result
// in two sockets at runtime.
//
// Returns nil + logs on failure; the caller decides whether that's fatal
// (it isn't for syslog — fall back to the shared socket per design §D7).
func openSyslogConnForDevice(device *DeviceSimulator) *net.UDPConn {
	if device == nil || device.netNamespace == nil {
		return nil
	}
	addr := &net.UDPAddr{IP: device.IP, Port: 0}
	conn, err := device.netNamespace.ListenUDPInNamespace(addr)
	if err != nil {
		log.Printf("syslog export: device %s per-device bind failed: %v", device.IP, err)
		return nil
	}
	_ = conn.SetWriteBuffer(65536)
	return conn
}
