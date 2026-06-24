/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeProvider struct {
	devices []deviceDNS
	serial  uint32
}

func (f *fakeProvider) DNSDevices() []deviceDNS         { return f.devices }
func (f *fakeProvider) ZoneSerial(origin string) uint32 { return f.serial }

func testServer(t *testing.T, secondaries ...string) *dnsServer {
	t.Helper()
	prov := &fakeProvider{
		devices: []deviceDNS{{IP: net.ParseIP("10.42.0.5"), SysName: "core-rtr-01"}},
		serial:  2026010100,
	}
	cfg := dnsServerConfig{
		Domain:       "nl6.local",
		ReverseZones: []string{"42.10.in-addr.arpa"},
		Listen:       "127.0.0.1:0",
		Secondaries:  secondaries,
	}
	s := newDNSServer(cfg, prov)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(s.stop)
	return s
}

func query(t *testing.T, addr, name string, qtype uint16, network string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Net: network, Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("exchange %s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return resp
}

func TestDNSServer_ForwardA(t *testing.T) {
	s := testServer(t)
	resp := query(t, s.udpAddr.String(), "core-rtr-01.nl6.local", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "10.42.0.5" {
		t.Fatalf("A = %v", resp.Answer[0])
	}
	if !resp.Authoritative {
		t.Errorf("answer must be authoritative (AA bit)")
	}
}

func TestDNSServer_RoundTrip(t *testing.T) {
	s := testServer(t)
	addr := s.udpAddr.String()

	// PTR resolves to the ip4.mgmt name...
	resp := query(t, addr, "5.0.42.10.in-addr.arpa", dns.TypePTR, "udp")
	if len(resp.Answer) != 1 {
		t.Fatalf("PTR answers=%d", len(resp.Answer))
	}
	ptr, ok := resp.Answer[0].(*dns.PTR)
	if !ok || ptr.Ptr != "ip4.mgmt.core-rtr-01.nl6.local." {
		t.Fatalf("PTR = %v", resp.Answer[0])
	}
	// ...and that name resolves forward back to the same IP.
	resp = query(t, addr, ptr.Ptr, dns.TypeA, "udp")
	if len(resp.Answer) != 1 {
		t.Fatalf("ip4.mgmt A answers=%d", len(resp.Answer))
	}
	if a := resp.Answer[0].(*dns.A); a.A.String() != "10.42.0.5" {
		t.Fatalf("round-trip A = %s", a.A)
	}
}

func TestDNSServer_SOAandNS(t *testing.T) {
	s := testServer(t)
	addr := s.udpAddr.String()

	resp := query(t, addr, "nl6.local", dns.TypeSOA, "udp")
	if len(resp.Answer) != 1 {
		t.Fatalf("SOA answers=%d", len(resp.Answer))
	}
	soa := resp.Answer[0].(*dns.SOA)
	if soa.Serial != 2026010100 {
		t.Errorf("serial=%d want 2026010100", soa.Serial)
	}
	if soa.Ns != "ns.nl6.local." {
		t.Errorf("MNAME=%q", soa.Ns)
	}

	resp = query(t, addr, "nl6.local", dns.TypeNS, "udp")
	if len(resp.Answer) != 1 {
		t.Fatalf("NS answers=%d", len(resp.Answer))
	}
}

func TestDNSServer_NXDOMAINandRefused(t *testing.T) {
	s := testServer(t)
	addr := s.udpAddr.String()

	// Unknown name inside an authoritative zone -> NXDOMAIN + SOA in authority.
	resp := query(t, addr, "nope.nl6.local", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode=%d want NXDOMAIN", resp.Rcode)
	}
	if len(resp.Ns) != 1 {
		t.Errorf("expected SOA in authority section")
	}

	// Name outside any served zone -> REFUSED (not authoritative).
	resp = query(t, addr, "example.com", dns.TypeA, "udp")
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode=%d want REFUSED", resp.Rcode)
	}
}

func TestDNSServer_UnsupportedOpcode(t *testing.T) {
	s := testServer(t)
	m := new(dns.Msg)
	m.SetUpdate("nl6.local.") // OpcodeUpdate — not implemented by a read-only primary
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, s.udpAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Errorf("rcode=%d want NOTIMP for UPDATE opcode", resp.Rcode)
	}
}

func TestDNSServer_NODATA(t *testing.T) {
	// Name exists (it has an A) but no MX -> NOERROR + authority SOA, not NXDOMAIN.
	s := testServer(t)
	resp := query(t, s.udpAddr.String(), "core-rtr-01.nl6.local", dns.TypeMX, "udp")
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode=%d want NOERROR (NODATA)", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("NODATA must carry no answers, got %d", len(resp.Answer))
	}
	if len(resp.Ns) != 1 {
		t.Errorf("NODATA must carry the authority SOA")
	}
}

func TestDNSServer_EmptyReverseZone(t *testing.T) {
	// A configured reverse zone with no devices in it is still authoritative.
	prov := &fakeProvider{devices: nil, serial: 7}
	cfg := dnsServerConfig{
		Domain:       "nl6.local",
		ReverseZones: []string{"42.10.in-addr.arpa"},
		Listen:       "127.0.0.1:0",
	}
	s := newDNSServer(cfg, prov)
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.stop)

	resp := query(t, s.udpAddr.String(), "42.10.in-addr.arpa", dns.TypeSOA, "udp")
	if len(resp.Answer) != 1 {
		t.Fatalf("empty reverse zone must still answer SOA, got %d", len(resp.Answer))
	}
	m := new(dns.Msg)
	m.SetAxfr("42.10.in-addr.arpa.")
	rrs := transfer(t, s.tcpAddr.String(), m)
	// SOA, NS, closing SOA — no PTRs.
	if len(rrs) != 3 {
		t.Fatalf("empty reverse zone AXFR = %d records, want 3 (SOA/NS/SOA)", len(rrs))
	}
}

func transfer(t *testing.T, tcpAddr string, msg *dns.Msg) []dns.RR {
	t.Helper()
	tr := new(dns.Transfer)
	ch, err := tr.In(msg, tcpAddr)
	if err != nil {
		t.Fatalf("transfer in: %v", err)
	}
	var rrs []dns.RR
	for env := range ch {
		if env.Error != nil {
			t.Fatalf("transfer envelope error: %v", env.Error)
		}
		rrs = append(rrs, env.RR...)
	}
	return rrs
}

func TestDNSServer_AXFR(t *testing.T) {
	s := testServer(t)
	m := new(dns.Msg)
	m.SetAxfr("nl6.local.")
	rrs := transfer(t, s.tcpAddr.String(), m)

	// Framing: first and last record are the SOA; NS present; both A records.
	if len(rrs) < 4 {
		t.Fatalf("AXFR too short: %d records", len(rrs))
	}
	if _, ok := rrs[0].(*dns.SOA); !ok {
		t.Errorf("AXFR must open with SOA, got %T", rrs[0])
	}
	if _, ok := rrs[len(rrs)-1].(*dns.SOA); !ok {
		t.Errorf("AXFR must close with SOA, got %T", rrs[len(rrs)-1])
	}
	var ns, aCount int
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.NS:
			ns++
		case *dns.A:
			aCount++
		}
	}
	if ns != 1 {
		t.Errorf("NS count=%d want 1", ns)
	}
	if aCount != 2 {
		t.Errorf("A count=%d want 2 (device + ip4.mgmt)", aCount)
	}
}

func TestDNSServer_IXFRFallsBackToAXFR(t *testing.T) {
	s := testServer(t)
	m := new(dns.Msg)
	m.SetIxfr("nl6.local.", 1, "ns.nl6.local.", "hostmaster.nl6.local.")
	rrs := transfer(t, s.tcpAddr.String(), m)
	if len(rrs) < 4 {
		t.Fatalf("IXFR->AXFR too short: %d", len(rrs))
	}
	if _, ok := rrs[0].(*dns.SOA); !ok {
		t.Errorf("IXFR->AXFR must open with SOA")
	}
}

func TestDNSServer_AXFRReverseZone(t *testing.T) {
	s := testServer(t)
	m := new(dns.Msg)
	m.SetAxfr("42.10.in-addr.arpa.")
	rrs := transfer(t, s.tcpAddr.String(), m)
	var ptr int
	for _, rr := range rrs {
		if _, ok := rr.(*dns.PTR); ok {
			ptr++
		}
	}
	if ptr != 1 {
		t.Errorf("reverse AXFR PTR count=%d want 1", ptr)
	}
}

func TestDNSServer_SendNotify(t *testing.T) {
	// Stand up a capturing secondary on UDP.
	captured := make(chan *dns.Msg, 1)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sec := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Opcode == dns.OpcodeNotify {
			select {
			case captured <- r:
			default:
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = sec.ActivateAndServe() }()
	defer func() { _ = sec.Shutdown() }()

	s := testServer(t, pc.LocalAddr().String())
	results := s.sendNotify(context.Background(), "nl6.local")
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("notify results=%+v", results)
	}
	select {
	case got := <-captured:
		if got.Question[0].Name != "nl6.local." || got.Opcode != dns.OpcodeNotify {
			t.Errorf("captured NOTIFY = %+v", got.Question)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("secondary never received NOTIFY")
	}
}
