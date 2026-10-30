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

// netconfDefaultPort is the IANA port for NETCONF over SSH.
const netconfDefaultPort = 830

// NetconfSubsystemConfig holds the simulator-wide NETCONF settings.
type NetconfSubsystemConfig struct {
	Enabled bool
	Port    int
}

// NetconfStatus is the body of GET /api/v1/netconf/status.
//
// Listeners and Sessions count every transport. ListenersTLS is the number
// of devices that also serve the TLS transport, SessionsTLS the sessions
// running over it, and TLSHandshakeFailures the TLS connections that failed
// before a NETCONF session started.
type NetconfStatus struct {
	SubsystemActive      bool   `json:"subsystem_active"`
	Listeners            int    `json:"listeners"`
	Sessions             int    `json:"sessions"`
	Subscriptions        int    `json:"subscriptions"`
	NotificationsSent    uint64 `json:"notifications_sent"`
	NotificationsDropped uint64 `json:"notifications_dropped"`
	ListenersTLS         int    `json:"listeners_tls"`
	SessionsTLS          int    `json:"sessions_tls"`
	TLSHandshakeFailures uint64 `json:"tls_handshake_failures"`
}

// StartNetconfSubsystem records the NETCONF settings. A disabled config
// leaves the subsystem off. Port 0 means 830. Starting twice is an error.
func (sm *SimulatorManager) StartNetconfSubsystem(cfg NetconfSubsystemConfig) error {
	if sm.netconfSubsystemActive.Load() {
		return fmt.Errorf("netconf: subsystem already started")
	}
	// The port is checked before the Enabled test, so a bad -netconf-port
	// fails at startup even while the subsystem is off.
	port := cfg.Port
	if port == 0 {
		port = netconfDefaultPort
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("netconf: invalid port %d (must be 1..65535)", port)
	}
	if !cfg.Enabled {
		return nil
	}
	sm.netconfPort = port
	sm.netconfSubsystemActive.Store(true)
	log.Printf("NETCONF subsystem enabled on port %d (cisco_catalyst_9500 over SSH, juniper_mx10004 over SSH and TLS)", port)
	return nil
}

// GetNetconfStatus snapshots the subsystem for the status endpoint.
func (sm *SimulatorManager) GetNetconfStatus() NetconfStatus {
	st := NetconfStatus{
		SubsystemActive:      sm.netconfSubsystemActive.Load(),
		NotificationsSent:    atomic.LoadUint64(&sm.netconfNotificationsSent),
		NotificationsDropped: atomic.LoadUint64(&sm.netconfNotificationsDropped),
	}
	if !st.SubsystemActive {
		return st
	}
	sm.mu.RLock()
	for _, d := range sm.devices {
		d.mu.RLock()
		hasListener, reg := d.netconfListener != nil, d.netconfSessions
		d.mu.RUnlock()
		if hasListener {
			st.Listeners++
		}
		if reg != nil {
			sessions, tlsSessions, subs := reg.counts()
			st.Sessions += sessions
			st.SessionsTLS += tlsSessions
			st.Subscriptions += subs
		}
	}
	sm.mu.RUnlock()
	return st
}

// counts returns the number of sessions, how many of them run over TLS, and
// the number of their subscriptions.
func (g *netconfSessionRegistry) counts() (sessions, tlsSessions, subs int) {
	g.mu.Lock()
	all := make([]*netconfSession, 0, len(g.sessions))
	for _, s := range g.sessions {
		all = append(all, s)
	}
	g.mu.Unlock()
	for _, s := range all {
		subs += len(s.Subs())
		if s.tls {
			tlsSessions++
		}
	}
	return len(all), tlsSessions, subs
}

// netconfStatusHandler serves GET /api/v1/netconf/status.
func netconfStatusHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(manager.GetNetconfStatus())
}
