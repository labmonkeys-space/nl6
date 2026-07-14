/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Per-device export configuration DTOs.
//
// These structs are the JSON shape of the optional `flow`, `traps`, and
// `syslog` blocks in `POST /api/v1/devices`, and they double as the runtime
// state stored on each `DeviceSimulator`. A nil pointer means "this export
// type is disabled for this device".
//
// Validation and default-fill live here. The actual wiring to exporter
// lifecycles lands in phases 3–5 of the `per-device-export-config` change.
//
// Integer / duration fields that default to non-zero values treat the Go
// zero value as "use default" — there is no way to express "explicitly
// zero" for `InformRetries`, `TickInterval`, `ActiveTimeout`,
// `InactiveTimeout`, `Interval`, or `InformTimeout`. Review decision D2.a
// (per-device-export-config change) accepted this limitation; see
// `design.md` for the pointer-field alternative if demand emerges.
//
// Caller contract:
//   1. Deserialize JSON → zero-filled struct
//   2. Call `ApplyDefaults()` to fill zero-valued fields with the
//      simulator-wide defaults historically supplied by CLI flags
//   3. Call `Validate()` to check shape, resolve collector, and canonicalise
//      string enums (Protocol / Mode / Format)
// Skipping step 2 causes step 3 to reject empty-string Mode/Format with a
// hint to call ApplyDefaults first.

// jsonDuration is a time.Duration wrapper that marshals/unmarshals as a
// Go duration string ("10s", "5m", "1m30s") rather than a nanosecond
// integer. Operators write REST bodies by hand; integer nanoseconds are
// unreadable and conflict with the CLI flags that historically accepted
// seconds-as-integers.
//
// JSON `null` is accepted and leaves the receiver at zero (so the field
// can later be filled by ApplyDefaults).
type jsonDuration time.Duration

func (d jsonDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *jsonDuration) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		// Leave zero; ApplyDefaults fills.
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a JSON string like \"10s\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = jsonDuration(parsed)
	return nil
}

// DeviceFlowConfig is the per-device flow-export configuration.
//
// Zero values on `TickInterval` / `ActiveTimeout` / `InactiveTimeout` are
// treated as "use default" by `ApplyDefaults` (review decision D2.a).
type DeviceFlowConfig struct {
	Collector       string       `json:"collector"`
	Protocol        string       `json:"protocol,omitempty"`
	TickInterval    jsonDuration `json:"tick_interval,omitempty"`
	ActiveTimeout   jsonDuration `json:"active_timeout,omitempty"`
	InactiveTimeout jsonDuration `json:"inactive_timeout,omitempty"`
	// SubAgentID is the sFlow v5 sub_agent_id emitted in every datagram
	// header (both FLOW_SAMPLE and COUNTERS_SAMPLE). Default 0 preserves the
	// historical single-agent wire output. Ignored by non-sFlow protocols.
	SubAgentID uint32 `json:"sub_agent_id,omitempty"`
}

// DeviceTrapConfig is the per-device SNMP trap/INFORM configuration.
//
// Zero values on `InformRetries` / `Interval` / `InformTimeout` are
// treated as "use default" by `ApplyDefaults` (review decision D2.a).
type DeviceTrapConfig struct {
	Collector     string       `json:"collector"`
	Mode          string       `json:"mode,omitempty"`
	Community     string       `json:"community,omitempty"`
	Interval      jsonDuration `json:"interval,omitempty"`
	InformTimeout jsonDuration `json:"inform_timeout,omitempty"`
	InformRetries int          `json:"inform_retries,omitempty"`
}

// DeviceSyslogConfig is the per-device UDP syslog configuration.
//
// Zero value on `Interval` is treated as "use default" by `ApplyDefaults`
// (review decision D2.a).
type DeviceSyslogConfig struct {
	Collector string       `json:"collector"`
	Format    string       `json:"format,omitempty"`
	Interval  jsonDuration `json:"interval,omitempty"`
}

// DialoutTLSConfig is the TLS/transport-security block of a dial-out
// config. `Enabled=false` selects a plaintext gRPC connection (matching
// the Arista `-collector_tls=false` default and the goarista reference
// collector's plaintext mode). When enabled, `InsecureSkipVerify` skips
// collector-certificate verification (dev only), `CAFile` supplies a
// PEM CA bundle to verify the collector against (empty → system roots),
// and `MTLS` presents the simulator's shared certificate as a client
// cert for mutual TLS.
//
// This block lives as a pointer on DeviceGnmiDialoutConfig so that an
// omitted `tls` object is distinguishable from an explicit
// `{"enabled": false}` — ApplyDefaults installs the secure default only
// when the whole block is absent.
type DialoutTLSConfig struct {
	Enabled            bool   `json:"enabled"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	CAFile             string `json:"ca_file,omitempty"`
	MTLS               bool   `json:"mtls,omitempty"`
}

// DeviceGnmiDialoutConfig is the per-device gNMI dial-out (telemetry
// push) configuration. A nil pointer on the device means dial-out is
// disabled — the device serves dial-in only. Dial-out and dial-in are
// independent per device, so the fleet may run mixed.
//
// Collector is the gRPC target (host:port). Flavor selects the dial-out
// wire protocol (only "gnmireverse" is shipped). Encoding is "json_ietf"
// (default) or "proto". Mode is "sample" (fixed-interval push) or
// "on-change" (push on interface-state transitions). Paths are the gNMI
// subscription paths under /interfaces/interface[name=*]/state/... .
// SampleInterval is the SAMPLE-mode cadence (clamped to a 1s floor).
type DeviceGnmiDialoutConfig struct {
	Collector      string            `json:"collector"`
	Flavor         string            `json:"flavor,omitempty"`
	Encoding       string            `json:"encoding,omitempty"`
	Mode           string            `json:"mode,omitempty"`
	Paths          []string          `json:"paths,omitempty"`
	SampleInterval jsonDuration      `json:"sample_interval,omitempty"`
	TLS            *DialoutTLSConfig `json:"tls,omitempty"`
}

// Defaults applied by ApplyDefaults. Sourced from `simulator.go` flag
// defaults (review decision D1.a — simulator.go is authoritative over
// CLAUDE.md documentation drift).
const (
	defaultFlowProtocol        = "netflow9"
	defaultFlowTickInterval    = 5 * time.Second
	defaultFlowActiveTimeout   = 30 * time.Second
	defaultFlowInactiveTimeout = 15 * time.Second

	defaultTrapMode          = "trap"
	defaultTrapCommunity     = "public"
	defaultTrapInterval      = 30 * time.Second
	defaultTrapInformTimeout = 5 * time.Second
	defaultTrapInformRetries = 2

	defaultSyslogFormat   = "5424"
	defaultSyslogInterval = 10 * time.Second

	defaultDialoutFlavor         = "gnmireverse"
	defaultDialoutEncoding       = "json_ietf"
	defaultDialoutMode           = "sample"
	defaultDialoutSampleInterval = 10 * time.Second
)

// Default subscription path used when a dial-out config supplies no
// explicit paths: the full interface-state subtree (state leaves +
// counters) for every interface — the dial-out equivalent of a
// dial-in wildcard subtree subscribe.
var defaultDialoutPaths = []string{"/interfaces/interface[name=*]/state"}

// ApplyDefaults fills in zero-valued fields with the simulator-wide
// defaults. Safe to call on a nil receiver (no-op). Callers MUST invoke
// ApplyDefaults before Validate — Validate rejects empty Mode / Format
// with a hint to call ApplyDefaults first.
func (c *DeviceFlowConfig) ApplyDefaults() {
	if c == nil {
		return
	}
	if c.Protocol == "" {
		c.Protocol = defaultFlowProtocol
	}
	if time.Duration(c.TickInterval) == 0 {
		c.TickInterval = jsonDuration(defaultFlowTickInterval)
	}
	if time.Duration(c.ActiveTimeout) == 0 {
		c.ActiveTimeout = jsonDuration(defaultFlowActiveTimeout)
	}
	if time.Duration(c.InactiveTimeout) == 0 {
		c.InactiveTimeout = jsonDuration(defaultFlowInactiveTimeout)
	}
	// SubAgentID intentionally has no default: 0 is the valid single-agent
	// value, and every uint32 is a legal sFlow sub_agent_id (no Validate check).
}

// Validate checks the config and canonicalises Protocol to its stable
// form (e.g. "nf9" → "netflow9"). Range checks run before canonicalisation
// so an error path does not leave partial mutations on the struct.
// Safe on nil.
func (c *DeviceFlowConfig) Validate() error {
	if c == nil {
		return nil
	}
	// Range checks first so canonicalisation never runs on invalid input.
	if time.Duration(c.TickInterval) < 0 {
		return fmt.Errorf("flow: tick_interval must be >= 0, got %s", time.Duration(c.TickInterval))
	}
	if time.Duration(c.ActiveTimeout) < 0 {
		return fmt.Errorf("flow: active_timeout must be >= 0, got %s", time.Duration(c.ActiveTimeout))
	}
	if time.Duration(c.InactiveTimeout) < 0 {
		return fmt.Errorf("flow: inactive_timeout must be >= 0, got %s", time.Duration(c.InactiveTimeout))
	}
	if err := validateCollector("flow", c.Collector); err != nil {
		return err
	}
	lowered := strings.ToLower(strings.TrimSpace(c.Protocol))
	if !isASCII(lowered) {
		return fmt.Errorf("flow: protocol must be ASCII, got %q", c.Protocol)
	}
	switch lowered {
	case "netflow9", "nf9", "":
		c.Protocol = "netflow9"
	case "ipfix", "ipfix10":
		c.Protocol = "ipfix"
	case "netflow5", "nf5":
		c.Protocol = "netflow5"
	case "sflow", "sflow5":
		c.Protocol = "sflow"
	default:
		return fmt.Errorf("flow: invalid protocol %q (valid: netflow9, ipfix, netflow5, sflow)", lowered)
	}
	return nil
}

// ApplyDefaults fills zero-valued fields. Safe on nil.
func (c *DeviceTrapConfig) ApplyDefaults() {
	if c == nil {
		return
	}
	if c.Mode == "" {
		c.Mode = defaultTrapMode
	}
	if c.Community == "" {
		c.Community = defaultTrapCommunity
	}
	if time.Duration(c.Interval) == 0 {
		c.Interval = jsonDuration(defaultTrapInterval)
	}
	if time.Duration(c.InformTimeout) == 0 {
		c.InformTimeout = jsonDuration(defaultTrapInformTimeout)
	}
	if c.InformRetries == 0 {
		c.InformRetries = defaultTrapInformRetries
	}
}

// Validate checks the config and canonicalises Mode. Rejects empty Mode
// with a hint to call ApplyDefaults first (review decision D3.b —
// symmetric with `DeviceSyslogConfig.Validate` rejecting empty Format).
// Range checks run before canonicalisation. Safe on nil.
func (c *DeviceTrapConfig) Validate() error {
	if c == nil {
		return nil
	}
	// Range checks first.
	if c.InformRetries < 0 {
		return fmt.Errorf("traps: inform_retries must be >= 0, got %d", c.InformRetries)
	}
	if time.Duration(c.Interval) < 0 {
		return fmt.Errorf("traps: interval must be >= 0, got %s", time.Duration(c.Interval))
	}
	if time.Duration(c.InformTimeout) < 0 {
		return fmt.Errorf("traps: inform_timeout must be >= 0, got %s", time.Duration(c.InformTimeout))
	}
	if err := validateCollector("traps", c.Collector); err != nil {
		return err
	}
	if strings.TrimSpace(c.Mode) == "" {
		return fmt.Errorf("traps: mode is required (caller must call ApplyDefaults() first)")
	}
	mode, err := ParseTrapMode(c.Mode)
	if err != nil {
		return fmt.Errorf("traps: %w", err)
	}
	switch mode {
	case TrapModeTrap:
		c.Mode = "trap"
	case TrapModeInform:
		c.Mode = "inform"
	}
	return nil
}

// ApplyDefaults fills zero-valued fields. Safe on nil.
func (c *DeviceSyslogConfig) ApplyDefaults() {
	if c == nil {
		return
	}
	if c.Format == "" {
		c.Format = defaultSyslogFormat
	}
	if time.Duration(c.Interval) == 0 {
		c.Interval = jsonDuration(defaultSyslogInterval)
	}
}

// Validate checks the config and canonicalises Format. Rejects empty
// Format with a hint to call ApplyDefaults first. Range checks run
// before canonicalisation. Safe on nil.
func (c *DeviceSyslogConfig) Validate() error {
	if c == nil {
		return nil
	}
	if time.Duration(c.Interval) < 0 {
		return fmt.Errorf("syslog: interval must be >= 0, got %s", time.Duration(c.Interval))
	}
	if err := validateCollector("syslog", c.Collector); err != nil {
		return err
	}
	if strings.TrimSpace(c.Format) == "" {
		return fmt.Errorf("syslog: format is required (caller must call ApplyDefaults() first)")
	}
	fm, err := ParseSyslogFormat(c.Format)
	if err != nil {
		return fmt.Errorf("syslog: %w", err)
	}
	c.Format = string(fm)
	return nil
}

// ApplyDefaults fills zero-valued fields with the dial-out defaults. Safe
// on nil. When the whole TLS block is omitted it installs the secure
// default (TLS on, collector verified against system roots).
func (c *DeviceGnmiDialoutConfig) ApplyDefaults() {
	if c == nil {
		return
	}
	if c.Flavor == "" {
		c.Flavor = defaultDialoutFlavor
	}
	if c.Encoding == "" {
		c.Encoding = defaultDialoutEncoding
	}
	if c.Mode == "" {
		c.Mode = defaultDialoutMode
	}
	if time.Duration(c.SampleInterval) == 0 {
		c.SampleInterval = jsonDuration(defaultDialoutSampleInterval)
	}
	if len(c.Paths) == 0 {
		c.Paths = append([]string(nil), defaultDialoutPaths...)
	}
	if c.TLS == nil {
		c.TLS = &DialoutTLSConfig{Enabled: true}
	}
}

// Validate checks the dial-out config and canonicalises Flavor / Encoding
// / Mode. Rejects empty enums with a hint to call ApplyDefaults first.
// Path strings are parsed for syntax so malformed paths are rejected at
// request time; per-path leaf-scope (state-only for ON_CHANGE) is checked
// at exporter-attach time against the device's resolver. Safe on nil.
func (c *DeviceGnmiDialoutConfig) Validate() error {
	if c == nil {
		return nil
	}
	if time.Duration(c.SampleInterval) < 0 {
		return fmt.Errorf("gnmi_dialout: sample_interval must be >= 0, got %s", time.Duration(c.SampleInterval))
	}
	if err := validateCollector("gnmi_dialout", c.Collector); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(c.Flavor)) {
	case "", "gnmireverse":
		c.Flavor = "gnmireverse"
	default:
		return fmt.Errorf("gnmi_dialout: invalid flavor %q (valid: gnmireverse)", c.Flavor)
	}
	switch strings.ToLower(strings.TrimSpace(c.Encoding)) {
	case "", "json_ietf", "json-ietf":
		c.Encoding = "json_ietf"
	case "proto":
		c.Encoding = "proto"
	default:
		return fmt.Errorf("gnmi_dialout: invalid encoding %q (valid: json_ietf, proto)", c.Encoding)
	}
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case "":
		return fmt.Errorf("gnmi_dialout: mode is required (caller must call ApplyDefaults() first)")
	case "sample":
		c.Mode = "sample"
	case "on-change", "on_change", "onchange":
		c.Mode = "on-change"
	default:
		return fmt.Errorf("gnmi_dialout: invalid mode %q (valid: sample, on-change)", c.Mode)
	}
	if len(c.Paths) == 0 {
		return fmt.Errorf("gnmi_dialout: at least one path is required (caller must call ApplyDefaults() first)")
	}
	for _, p := range c.Paths {
		if _, err := parseGnmiPath(p); err != nil {
			return fmt.Errorf("gnmi_dialout: invalid path %q: %w", p, err)
		}
	}
	if c.TLS != nil && !c.TLS.Enabled && (c.TLS.CAFile != "" || c.TLS.MTLS || c.TLS.InsecureSkipVerify) {
		return fmt.Errorf("gnmi_dialout: tls.enabled is false but ca_file/mtls/insecure_skip_verify is set (a plaintext connection ignores them)")
	}
	return nil
}

// validateCollector is the shared host:port validation used by all three
// export configs. Rejects empty / whitespace-only inputs, requires a
// port in the 1–65535 range, and resolves the host over both IPv4 and
// IPv6 (use "udp" network, not "udp4"). Host resolution remains
// synchronous here; deferring to exporter dial time (or adding a
// `context.WithTimeout`) is filed for phase 3+ when the HTTP handler
// actually invokes this function.
func validateCollector(subsystem, collector string) error {
	if strings.TrimSpace(collector) == "" {
		return fmt.Errorf("%s: collector is required", subsystem)
	}
	host, portStr, err := net.SplitHostPort(collector)
	if err != nil {
		return fmt.Errorf("%s: collector %q must be host:port: %w", subsystem, collector, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%s: collector %q has empty host", subsystem, collector)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("%s: collector %q has invalid port %q: %w", subsystem, collector, portStr, err)
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%s: collector %q port must be 1–65535, got %d", subsystem, collector, port)
	}
	if _, err := net.ResolveUDPAddr("udp", collector); err != nil {
		return fmt.Errorf("%s: collector %q: %w", subsystem, collector, err)
	}
	return nil
}

// isASCII reports whether every byte is < 0x80. Used as an early
// rejection for non-ASCII input to the Protocol switch so Unicode
// casing quirks (Turkish dotted I, fullwidth letters, etc.) surface
// as a clean "must be ASCII" error rather than slipping through.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// applyExportSeed copies a batch-level ExportSeed onto a newly-constructed
// device. Each non-nil block in the seed is copied so every device in the
// batch gets its own pointer; downstream mutations don't leak across
// devices in the fleet. Safe to call with a nil seed (no-op) or nil
// blocks (partial seed).
func applyExportSeed(device *DeviceSimulator, seed *ExportSeed) {
	if device == nil || seed == nil {
		return
	}
	if seed.Flow != nil {
		f := *seed.Flow
		device.flowConfig = &f
	}
	if seed.Traps != nil {
		t := *seed.Traps
		device.trapConfig = &t
	}
	if seed.Syslog != nil {
		s := *seed.Syslog
		device.syslogConfig = &s
	}
	if seed.GnmiDialout != nil {
		g := *seed.GnmiDialout
		// Deep-copy the slices/pointer so per-device mutations don't leak
		// across the fleet.
		g.Paths = append([]string(nil), seed.GnmiDialout.Paths...)
		if seed.GnmiDialout.TLS != nil {
			t := *seed.GnmiDialout.TLS
			g.TLS = &t
		}
		device.gnmiDialoutConfig = &g
	}
	// IfErrorScenario has value semantics; copy directly. Empty string
	// on the seed maps to "" on the device, which InitIfCounters later
	// canonicalises via ParseIfErrorScenario ("" → "clean").
	if seed.IfErrorScenario != "" {
		device.IfErrorScenario = string(seed.IfErrorScenario)
	}
	if seed.IfFlapScenario != "" {
		device.IfFlapScenario = string(seed.IfFlapScenario)
	}
}

// Compile-time safety: ensure jsonDuration satisfies the json
// (Un)Marshaler interfaces. Catches accidental signature drift.
var (
	_ json.Marshaler   = jsonDuration(0)
	_ json.Unmarshaler = (*jsonDuration)(nil)
)
