/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// dns_server.go is the hidden-primary authoritative DNS server. It serves the
// derived forward/reverse zones (built by dns_zone.go) over UDP+TCP, answers
// SOA / NS / A / PTR directly (so it is a usable standalone primary), streams
// AXFR (and answers IXFR with a full AXFR), and sends outbound NOTIFY to the
// configured CoreDNS secondaries. It binds in the container's default network
// namespace — never the nl6sim device namespace.
//
// The zone content is rebuilt on demand from the live device set via the
// zoneDataProvider, so there is no stored per-device DNS state; the manager
// (dns_manager.go) supplies the provider and the per-zone SOA serials.

// axfrChunkRecords bounds how many resource records ride in one AXFR envelope
// so each transfer message stays well under the 64 KiB TCP-DNS message limit.
// 256 records of worst-case normal size (~100 B each) is ~26 KiB — a generous
// margin even before name compression.
const axfrChunkRecords = 256

// zoneDataProvider is the server's window onto the live fleet. The manager
// implements it; tests supply a fake. DNSDevices returns the current device
// snapshot; ZoneSerial returns the current SOA serial for a zone origin (FQDN).
type zoneDataProvider interface {
	DNSDevices() []deviceDNS
	ZoneSerial(origin string) uint32
}

// dnsServerConfig is the static configuration of the DNS server. The manager
// fills it from the -dns-* flags; defaults are applied by withDefaults.
type dnsServerConfig struct {
	Domain       string   // forward apex (e.g. "nl6.local")
	ReverseZones []string // in-addr.arpa zone names served authoritatively
	Listen       string   // bind address (e.g. ":5353")
	NS           string   // primary NS name (SOA MNAME / NS RDATA)
	Mbox         string   // SOA RNAME (responsible mailbox)
	TTL          uint32   // record TTL
	Refresh      uint32   // SOA refresh
	Retry        uint32   // SOA retry
	Expire       uint32   // SOA expire
	MinTTL       uint32   // SOA negative-cache TTL
	Secondaries  []string // NOTIFY targets (host:port)
}

// withDefaults returns a copy with empty fields filled with sensible defaults.
func (c dnsServerConfig) withDefaults() dnsServerConfig {
	if c.Domain == "" {
		c.Domain = "nl6.local"
	}
	if c.Listen == "" {
		c.Listen = ":5353"
	}
	domainFQDN := fqdn(c.Domain)
	if c.NS == "" {
		c.NS = "ns." + domainFQDN
	} else {
		c.NS = fqdn(c.NS)
	}
	if c.Mbox == "" {
		c.Mbox = "hostmaster." + domainFQDN
	} else {
		c.Mbox = fqdn(c.Mbox)
	}
	if c.TTL == 0 {
		c.TTL = 300
	}
	if c.Refresh == 0 {
		c.Refresh = 3600
	}
	if c.Retry == 0 {
		c.Retry = 600
	}
	if c.Expire == 0 {
		c.Expire = 604800
	}
	if c.MinTTL == 0 {
		c.MinTTL = 300
	}
	return c
}

// dnsServer is the running authoritative server. Construct with newDNSServer
// and drive with start / stop.
type dnsServer struct {
	cfg      dnsServerConfig
	provider zoneDataProvider

	udp, tcp         *dns.Server
	udpAddr, tcpAddr net.Addr
}

func newDNSServer(cfg dnsServerConfig, provider zoneDataProvider) *dnsServer {
	return &dnsServer{cfg: cfg.withDefaults(), provider: provider}
}

// start binds the UDP and TCP listeners and begins serving. Both bind to the
// configured address; with a ":0" test address each gets its own ephemeral
// port (read back via udpAddr / tcpAddr).
func (s *dnsServer) start() error {
	udpConn, err := net.ListenPacket("udp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("dns: udp listen %s: %w", s.cfg.Listen, err)
	}
	tcpL, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("dns: tcp listen %s: %w", s.cfg.Listen, err)
	}
	s.udpAddr = udpConn.LocalAddr()
	s.tcpAddr = tcpL.Addr()
	s.udp = &dns.Server{PacketConn: udpConn, Handler: s}
	s.tcp = &dns.Server{Listener: tcpL, Handler: s}
	go func() {
		if err := s.udp.ActivateAndServe(); err != nil {
			log.Printf("dns: udp server stopped: %v", err)
		}
	}()
	go func() {
		if err := s.tcp.ActivateAndServe(); err != nil {
			log.Printf("dns: tcp server stopped: %v", err)
		}
	}()
	return nil
}

// stop shuts both listeners down. Safe to call once after start.
func (s *dnsServer) stop() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
}

// ServeDNS is the dns.Handler entry point.
func (s *dnsServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// We are a read-only authoritative primary: anything other than a standard
	// query (UPDATE, inbound NOTIFY, …) is not implemented; a malformed
	// question count is a format error.
	if r.Opcode != dns.OpcodeQuery {
		s.respond(w, r, dns.RcodeNotImplemented)
		return
	}
	if len(r.Question) != 1 {
		s.respond(w, r, dns.RcodeFormatError)
		return
	}
	q := r.Question[0]
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		s.handleTransfer(w, r)
	default:
		s.handleQuery(w, r)
	}
}

func (s *dnsServer) respond(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	_ = w.WriteMsg(m)
}

// servedOrigins returns the FQDN origins this server is authoritative for
// (forward apex + parsed reverse zones), without building any records.
func (s *dnsServer) servedOrigins() []string {
	origins := []string{fqdn(s.cfg.Domain)}
	for _, name := range s.cfg.ReverseZones {
		if z, ok := parseReverseZone(name); ok {
			origins = append(origins, z.Origin)
		}
	}
	return origins
}

// handleQuery answers SOA / NS / A / PTR (and ANY) directly from the built zone.
func (s *dnsServer) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	qname := strings.ToLower(dns.Fqdn(q.Name))

	// Fast path: apex SOA / NS need no zone rebuild. A secondary's refresh poll
	// (SOA query, frequent) hits this and avoids an O(devices) rebuild per poll
	// — the per-request-rebuild amplification that bites the LLDP walk path.
	if q.Qtype == dns.TypeSOA || q.Qtype == dns.TypeNS {
		for _, origin := range s.servedOrigins() {
			if qname == origin {
				m := new(dns.Msg)
				m.SetReply(r)
				m.Authoritative = true
				if q.Qtype == dns.TypeSOA {
					m.Answer = append(m.Answer, s.soaFor(origin))
				} else {
					m.Answer = append(m.Answer, s.nsFor(origin))
				}
				_ = w.WriteMsg(m)
				return
			}
		}
	}

	zones := s.buildZones()
	bz := zoneForName(zones, qname)
	if bz == nil {
		// Not authoritative for this name.
		s.respond(w, r, dns.RcodeRefused)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Apex meta-records.
	if qname == bz.origin {
		switch q.Qtype {
		case dns.TypeSOA, dns.TypeANY:
			m.Answer = append(m.Answer, bz.soa)
		}
		switch q.Qtype {
		case dns.TypeNS, dns.TypeANY:
			m.Answer = append(m.Answer, bz.ns)
		}
	}

	for _, rr := range bz.byName[qname] {
		if q.Qtype == dns.TypeANY || rr.Header().Rrtype == q.Qtype {
			m.Answer = append(m.Answer, rr)
		}
	}

	if len(m.Answer) == 0 {
		// NXDOMAIN when the name is unknown; NODATA (NOERROR + SOA) when the
		// name exists but carries no record of the requested type.
		if !bz.names[qname] && qname != bz.origin {
			m.Rcode = dns.RcodeNameError
		}
		m.Ns = append(m.Ns, bz.soa)
	}
	_ = w.WriteMsg(m)
}

// handleTransfer streams a full AXFR for the requested zone. IXFR requests are
// answered with a full AXFR (RFC 1995 §4 fallback).
func (s *dnsServer) handleTransfer(w dns.ResponseWriter, r *dns.Msg) {
	origin := strings.ToLower(dns.Fqdn(r.Question[0].Name))
	zones := s.buildZones()
	bz, ok := zones[origin]
	if !ok {
		s.respond(w, r, dns.RcodeRefused)
		return
	}

	// AXFR framing: SOA, NS, body..., closing SOA.
	all := make([]dns.RR, 0, len(bz.records)+3)
	all = append(all, bz.soa, bz.ns)
	all = append(all, bz.records...)
	all = append(all, bz.soa)

	// done lets the producer exit if Out() stops draining early (client
	// disconnect mid-transfer), so the goroutine never blocks forever on send.
	ch := make(chan *dns.Envelope)
	done := make(chan struct{})
	go func() {
		defer close(ch)
		for start := 0; start < len(all); start += axfrChunkRecords {
			end := min(start+axfrChunkRecords, len(all))
			select {
			case ch <- &dns.Envelope{RR: all[start:end]}:
			case <-done:
				return
			}
		}
	}()

	tr := new(dns.Transfer)
	err := tr.Out(w, r, ch)
	close(done)
	if err != nil {
		log.Printf("dns: AXFR %s failed: %v", origin, err)
	}
}

// sendNotify sends a DNS NOTIFY for origin to every configured secondary and
// returns one result per secondary that responded before ctx was cancelled.
// Sends run concurrently so one slow/unreachable secondary cannot serialise a
// per-retry timeout onto the others. The collector returns as soon as ctx is
// cancelled (shutdown) even if some Exchanges are still in flight — those
// stragglers drain into the buffered result channel and exit within their own
// timeout, so neither the caller (the debounce worker, hence Stop) blocks nor a
// goroutine leaks.
func (s *dnsServer) sendNotify(ctx context.Context, origin string) []notifyResult {
	origin = fqdn(origin)
	soa := s.soaFor(origin)
	resCh := make(chan notifyResult, len(s.cfg.Secondaries))
	for _, sec := range s.cfg.Secondaries {
		go func(sec string) {
			client := &dns.Client{Timeout: 3 * time.Second}
			m := new(dns.Msg)
			m.SetNotify(origin)
			if soa != nil {
				m.Answer = []dns.RR{soa}
			}
			_, _, err := client.ExchangeContext(ctx, m, sec)
			resCh <- notifyResult{Secondary: sec, Err: err}
		}(sec)
	}

	results := make([]notifyResult, 0, len(s.cfg.Secondaries))
	for range s.cfg.Secondaries {
		select {
		case r := <-resCh:
			results = append(results, r)
		case <-ctx.Done():
			return results
		}
	}
	return results
}

// notifyResult records the outcome of a single NOTIFY send.
type notifyResult struct {
	Secondary string
	Err       error
}

// builtZone is a fully-realised zone ready to answer queries and transfers.
type builtZone struct {
	origin  string
	soa     *dns.SOA
	ns      *dns.NS
	records []dns.RR            // body records (A / PTR), AXFR order
	byName  map[string][]dns.RR // owner name -> its records
	names   map[string]bool     // owner names that exist (for NXDOMAIN vs NODATA)
}

func (b *builtZone) add(rr dns.RR) {
	b.records = append(b.records, rr)
	name := strings.ToLower(rr.Header().Name)
	b.byName[name] = append(b.byName[name], rr)
	b.names[name] = true
}

// buildZones rebuilds every served zone from the current device snapshot.
func (s *dnsServer) buildZones() map[string]*builtZone {
	view := buildZoneView(s.provider.DNSDevices(), s.cfg.Domain, s.cfg.ReverseZones)

	zones := make(map[string]*builtZone)
	fwd := s.newBuiltZone(view.Domain)
	for _, rec := range view.Forward {
		if rr := s.toRR(rec); rr != nil {
			fwd.add(rr)
		}
	}
	zones[view.Domain] = fwd

	for origin, recs := range view.Reverse {
		bz := s.newBuiltZone(origin)
		for _, rec := range recs {
			if rr := s.toRR(rec); rr != nil {
				bz.add(rr)
			}
		}
		zones[origin] = bz
	}

	// A configured reverse zone with no devices in it still exists
	// authoritatively (so SOA queries and AXFR succeed, just empty).
	for _, name := range s.cfg.ReverseZones {
		if z, ok := parseReverseZone(name); ok {
			if _, exists := zones[z.Origin]; !exists {
				zones[z.Origin] = s.newBuiltZone(z.Origin)
			}
		}
	}

	// Stable AXFR ordering within each zone.
	for _, bz := range zones {
		sort.SliceStable(bz.records, func(i, j int) bool {
			ni, nj := bz.records[i].Header().Name, bz.records[j].Header().Name
			if ni != nj {
				return ni < nj
			}
			return bz.records[i].Header().Rrtype < bz.records[j].Header().Rrtype
		})
	}
	return zones
}

func (s *dnsServer) newBuiltZone(origin string) *builtZone {
	return &builtZone{
		origin: origin,
		soa:    s.soaFor(origin),
		ns:     s.nsFor(origin),
		byName: make(map[string][]dns.RR),
		names:  make(map[string]bool),
	}
}

func (s *dnsServer) soaFor(origin string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: origin, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.cfg.TTL},
		Ns:      s.cfg.NS,
		Mbox:    s.cfg.Mbox,
		Serial:  s.provider.ZoneSerial(origin),
		Refresh: s.cfg.Refresh,
		Retry:   s.cfg.Retry,
		Expire:  s.cfg.Expire,
		Minttl:  s.cfg.MinTTL,
	}
}

func (s *dnsServer) nsFor(origin string) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: s.cfg.TTL},
		Ns:  s.cfg.NS,
	}
}

// toRR converts a zone-model record into a miekg/dns RR. Returns nil for a
// malformed value or unknown kind so the caller can skip it rather than build a
// broken RR (a nil A address or a nil RR would later panic in add/encode).
func (s *dnsServer) toRR(rec dnsRecord) dns.RR {
	switch rec.Kind {
	case recA:
		ip := net.ParseIP(rec.Value).To4()
		if ip == nil {
			return nil
		}
		return &dns.A{
			Hdr: dns.RR_Header{Name: rec.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.cfg.TTL},
			A:   ip,
		}
	case recPTR:
		return &dns.PTR{
			Hdr: dns.RR_Header{Name: rec.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: s.cfg.TTL},
			Ptr: rec.Value,
		}
	default:
		return nil
	}
}

// zoneForName returns the most-specific served zone that is a parent of (or
// equal to) qname, or nil when none is authoritative.
func zoneForName(zones map[string]*builtZone, qname string) *builtZone {
	var best *builtZone
	for origin, bz := range zones {
		if dns.IsSubDomain(origin, qname) {
			if best == nil || len(origin) > len(best.origin) {
				best = bz
			}
		}
	}
	return best
}
