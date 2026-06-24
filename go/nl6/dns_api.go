/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

// dns_api.go is the observability + flag-plumbing surface for the DNS
// service-discovery subsystem: the GET /api/v1/dns/status handler, the status
// snapshot it serialises, the -dns-domain validator, and the comma-list flag
// splitter.

// DnsZoneStatus reports one served zone and its current SOA serial.
type DnsZoneStatus struct {
	Origin string `json:"origin"`
	Kind   string `json:"kind"` // "forward" | "reverse"
	Serial uint32 `json:"serial"`
}

// DnsStatus is the JSON body of GET /api/v1/dns/status. When the subsystem is
// off, only SubsystemActive (false) is meaningful.
type DnsStatus struct {
	SubsystemActive    bool            `json:"subsystem_active"`
	Domain             string          `json:"domain,omitempty"`
	Listen             string          `json:"listen,omitempty"`
	Zones              []DnsZoneStatus `json:"zones,omitempty"`
	Secondaries        []string        `json:"secondaries,omitempty"`
	DevicesPublished   int             `json:"devices_published"`
	PTRsEmitted        int             `json:"ptrs_emitted"`
	PTRsOmitted        int             `json:"ptrs_omitted"`
	NamesDisambiguated int             `json:"names_disambiguated"`
	ZoneBumps          uint64          `json:"zone_bumps"`
	NotifiesSent       uint64          `json:"notifies_sent"`
	NotifyErrors       uint64          `json:"notify_errors"`
}

// GetDnsStatus snapshots the subsystem state for the status endpoint. Rebuilds
// the zone view once to report the publish counters (devices, PTRs, omissions,
// disambiguations) — acceptable on a status endpoint, not the query hot path.
func (sm *SimulatorManager) GetDnsStatus() DnsStatus {
	// Read dnsServer only after observing active==true: Start writes dnsServer
	// before storing the flag, so an atomic Load that sees true establishes the
	// happens-before edge for that write (and the field is otherwise immutable
	// after Start). Reading it unconditionally would be an unsynchronised read.
	if !sm.dnsSubsystemActive.Load() {
		return DnsStatus{SubsystemActive: false}
	}
	st := DnsStatus{SubsystemActive: true}
	srv := sm.dnsServer
	if srv == nil {
		return st
	}

	st.Domain = srv.cfg.Domain
	st.Listen = srv.cfg.Listen
	st.Secondaries = srv.cfg.Secondaries

	view := buildZoneView(sm.DNSDevices(), srv.cfg.Domain, srv.cfg.ReverseZones)
	st.DevicesPublished = view.DevicesPublished
	st.PTRsEmitted = view.PTRsEmitted
	st.PTRsOmitted = view.PTRsOmitted
	st.NamesDisambiguated = view.NamesDisambiguated

	serial := sm.dnsSerial.Load()
	st.Zones = append(st.Zones, DnsZoneStatus{Origin: view.Domain, Kind: "forward", Serial: serial})
	for _, name := range srv.cfg.ReverseZones {
		if z, ok := parseReverseZone(name); ok {
			st.Zones = append(st.Zones, DnsZoneStatus{Origin: z.Origin, Kind: "reverse", Serial: serial})
		}
	}

	st.ZoneBumps = atomic.LoadUint64(&sm.dnsZoneBumps)
	st.NotifiesSent = atomic.LoadUint64(&sm.dnsNotifiesSent)
	st.NotifyErrors = atomic.LoadUint64(&sm.dnsNotifyErrors)
	return st
}

// dnsStatusHandler implements GET /api/v1/dns/status. Encoded raw (not wrapped)
// so the documented top-level shape `{subsystem_active, ...}` is preserved,
// matching the gNMI / trap / syslog status endpoints.
func dnsStatusHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(manager.GetDnsStatus())
}

// maxDNSDomainLen is the longest -dns-domain (dotted, no trailing dot) that
// still lets the longest generated owner name — "ip4.mgmt." + a 63-octet label
// + "." + <domain> + "." — fit within the 255-octet DNS name limit.
const maxDNSDomainLen = 255 - len("ip4.mgmt.") - 63 - 1 - 1

// validateDNSDomain rejects a forward domain that is empty, over-long (so the
// generated names can't exceed the 255-octet DNS name limit), or carries a
// label that is empty or longer than the 63-octet DNS label limit.
func validateDNSDomain(domain string) error {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return fmt.Errorf("domain must not be empty")
	}
	if len(domain) > maxDNSDomainLen {
		return fmt.Errorf("domain %q too long (%d > %d octets): generated names would exceed the 255-octet DNS limit",
			domain, len(domain), maxDNSDomainLen)
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return fmt.Errorf("domain %q has an empty label", domain)
		}
		if len(label) > dnsLabelMax {
			return fmt.Errorf("domain %q has a label longer than %d octets", domain, dnsLabelMax)
		}
	}
	return nil
}

// splitCommaList splits a comma-separated flag value into trimmed, non-empty
// entries. An empty or all-whitespace input yields nil.
func splitCommaList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
