/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

// gnmiDefaultPort is the IANA-assigned TCP port for gNMI (design.md §D3).
const gnmiDefaultPort = 9339

// GnmiSubsystemConfig captures the simulator-wide knobs for the gNMI
// subsystem. Per design.md §D2 there is no per-device opt-in;
// `Disabled=true` is the only off-switch in v1.
type GnmiSubsystemConfig struct {
	Port     int
	Disabled bool
}

// GnmiStatus is the JSON body returned by GET /api/v1/gnmi/status. The
// shape is locked in design.md §D11: simulator-wide aggregates only,
// no per-collector array (gNMI has no collector concept).
//
// `tls_handshake_failures` (P17) is a coarse counter of `Accept`
// errors on the per-device gRPC listener — a TLS handshake that fails
// surfaces as Accept returning an error in gRPC, so this approximates
// "TLS handshakes that didn't complete" without integrating a custom
// credentials wrapper.
type GnmiStatus struct {
	SubsystemActive      bool   `json:"subsystem_active"`
	Listeners            int    `json:"listeners"`
	ActiveSubscriptions  int64  `json:"active_subscriptions"`
	UpdatesSent          uint64 `json:"updates_sent"`
	UpdatesDropped       uint64 `json:"updates_dropped"`
	TLSHandshakeFailures uint64 `json:"tls_handshake_failures"`
}

// StartGnmiSubsystem records the subsystem-wide knobs on the manager.
// Idempotent at start; calling it twice is a programming error and
// returns an error.
func (sm *SimulatorManager) StartGnmiSubsystem(cfg GnmiSubsystemConfig) error {
	if sm.gnmiSubsystemActive.Load() {
		return fmt.Errorf("gnmi: subsystem already started")
	}
	port := cfg.Port
	if port == 0 {
		port = gnmiDefaultPort
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("gnmi: invalid port %d (must be 1..65535)", port)
	}
	sm.gnmiPort = port
	sm.gnmiSubsystemDisabled.Store(cfg.Disabled)
	sm.gnmiSubsystemActive.Store(true)
	if cfg.Disabled {
		log.Printf("gNMI subsystem disabled via -gnmi-disable")
	} else {
		log.Printf("gNMI subsystem enabled on port %d", port)
	}
	return nil
}

// StopGnmiSubsystem walks every device and gracefully stops its gNMI
// server. Shutdown-only, matching trap/syslog Stop semantics — see
// `Stop*Export` in trap_manager.go / syslog_manager.go for the
// rationale: the per-device attach path (startGnmiServer) captures the
// subsystem state under a short read-lock and uses it outside that
// lock, so a runtime "restart" path would race. Today this is only
// called from the process-exit signal handler.
//
// P7: device shutdown happens *before* `gnmiSubsystemActive` flips to
// false. The earlier ordering (flip then walk) created a brief window
// where `GetGnmiStatus` reported `subsystem_active=false` while
// per-device listeners were still draining in-flight RPCs — the new
// ordering keeps the status snapshot honest until every server is
// stopped.
func (sm *SimulatorManager) StopGnmiSubsystem() {
	if !sm.gnmiSubsystemActive.Load() {
		return
	}
	sm.mu.RLock()
	devices := make([]*DeviceSimulator, 0, len(sm.devices))
	for _, d := range sm.devices {
		devices = append(devices, d)
	}
	sm.mu.RUnlock()
	for _, d := range devices {
		d.mu.Lock()
		d.stopGnmiServer()
		d.mu.Unlock()
	}
	sm.gnmiSubsystemActive.Store(false)
}

// GetGnmiStatus snapshots the subsystem state for the status endpoint.
// `subsystem_active=false` means the subsystem was never started or has
// been stopped.
//
// P15: `Listeners` counts devices whose `gnmiServer` pointer is
// non-nil (i.e., `startGnmiServer` succeeded and `stopGnmiServer` has
// not run). Using `len(sm.devices)` was inaccurate whenever a device
// had been added but not yet started, or had been stopped without
// removal. The cost is one map walk per status call, which is
// acceptable on a status endpoint.
func (sm *SimulatorManager) GetGnmiStatus() GnmiStatus {
	active := sm.gnmiSubsystemActive.Load() && !sm.gnmiSubsystemDisabled.Load()
	listeners := 0
	if active {
		sm.mu.RLock()
		for _, d := range sm.devices {
			d.mu.RLock()
			if d.gnmiServer != nil {
				listeners++
			}
			d.mu.RUnlock()
		}
		sm.mu.RUnlock()
	}
	return GnmiStatus{
		SubsystemActive:       active,
		Listeners:             listeners,
		ActiveSubscriptions:   atomic.LoadInt64(&sm.gnmiActiveSubscriptions),
		UpdatesSent:           atomic.LoadUint64(&sm.gnmiUpdatesSent),
		UpdatesDropped:        atomic.LoadUint64(&sm.gnmiUpdatesDropped),
		TLSHandshakeFailures:  atomic.LoadUint64(&sm.gnmiTLSHandshakeFailures),
	}
}

// WriteGnmiStatusJSON encodes the status to w. Mirrors the trap/syslog
// thin-handler pattern.
func (sm *SimulatorManager) WriteGnmiStatusJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sm.GetGnmiStatus())
}

// gnmiStatusHandler serves GET /api/v1/gnmi/status. Registered in web.go.
func gnmiStatusHandler(w http.ResponseWriter, _ *http.Request) {
	manager.WriteGnmiStatusJSON(w)
}
