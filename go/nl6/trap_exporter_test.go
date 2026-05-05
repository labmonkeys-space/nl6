/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockCollector opens a UDP socket, optionally responds to incoming INFORMs
// with GetResponse-PDU acks. Shut down with Close.
type mockCollector struct {
	conn     *net.UDPConn
	addr     *net.UDPAddr
	received atomic.Uint64
	auto     bool // auto-respond to INFORMs
	mu       sync.Mutex
	lastReq  uint32
	wg       sync.WaitGroup
}

func newMockCollector(t *testing.T, autoAck bool) *mockCollector {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("mockCollector listen: %v", err)
	}
	m := &mockCollector{
		conn: conn,
		addr: conn.LocalAddr().(*net.UDPAddr),
		auto: autoAck,
	}
	m.wg.Add(1)
	go m.loop(t)
	return m
}

func (m *mockCollector) loop(t *testing.T) {
	defer m.wg.Done()
	buf := make([]byte, 2048)
	for {
		_ = m.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, from, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// check closed
				if m.isClosed() {
					return
				}
				continue
			}
			return
		}
		m.received.Add(1)
		// Sniff the PDU tag to decide whether to ack.
		tag, reqID, ok := sniffPDUTagAndReqID(buf[:n])
		if !ok {
			continue
		}
		m.mu.Lock()
		m.lastReq = reqID
		m.mu.Unlock()
		if m.auto && tag == ASN1_INFORM_REQUEST {
			ack := buildAckDatagramRaw("public", reqID, 0)
			_, _ = m.conn.WriteToUDP(ack, from)
		}
	}
}

func (m *mockCollector) isClosed() bool {
	// Probe by setting a far-future deadline; if that errors we're closed.
	err := m.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	return err != nil
}

func (m *mockCollector) Close() {
	_ = m.conn.Close()
	m.wg.Wait()
}

// sniffPDUTagAndReqID reaches into an SNMPv2c message just enough to return
// the PDU tag byte (0xA6 / 0xA7) and the request-id, or (_,_,false) on parse
// failure. Dedicated implementation to avoid pulling the full test decoder.
func sniffPDUTagAndReqID(data []byte) (byte, uint32, bool) {
	pos := 0
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return 0, 0, false
	}
	pos++
	_, np := parseLength(data, pos)
	pos = np
	// version
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return 0, 0, false
	}
	pos++
	vl, np := parseLength(data, pos)
	if vl < 0 {
		return 0, 0, false
	}
	pos = np + vl
	// community
	if pos >= len(data) || data[pos] != ASN1_OCTET_STRING {
		return 0, 0, false
	}
	pos++
	cl, np := parseLength(data, pos)
	if cl < 0 {
		return 0, 0, false
	}
	pos = np + cl
	if pos >= len(data) {
		return 0, 0, false
	}
	tag := data[pos]
	pos++
	_, np = parseLength(data, pos)
	pos = np
	// request-id
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return 0, 0, false
	}
	pos++
	rl, np := parseLength(data, pos)
	if rl < 0 {
		return 0, 0, false
	}
	rid := uint32(parseUintBE(data[np : np+rl]))
	return tag, rid, true
}

// buildAckDatagramRaw is the non-test-helper equivalent of buildAckDatagram.
func buildAckDatagramRaw(community string, reqID uint32, errorStatus int) []byte {
	var pduContents []byte
	pduContents = append(pduContents, encodeInteger(int(reqID))...)
	pduContents = append(pduContents, encodeInteger(errorStatus)...)
	pduContents = append(pduContents, encodeInteger(0)...)
	pduContents = append(pduContents, encodeSequence(nil)...)
	var pdu []byte
	pdu = append(pdu, ASN1_GET_RESPONSE)
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)
	var outer []byte
	outer = append(outer, encodeInteger(1)...)
	outer = append(outer, encodeOctetString(community)...)
	outer = append(outer, pdu...)
	return encodeSequence(outer)
}

// openTestUDPConn opens a loopback UDP socket bound to an ephemeral port.
// Substitutes for the per-device netns socket in tests.
func openTestUDPConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("openTestUDPConn: %v", err)
	}
	return conn
}

func TestTrapExporter_TRAP_FireIncrementsSent(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	mc := newMockCollector(t, false)
	defer mc.Close()
	conn := openTestUDPConn(t)

	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:  net.IPv4(127, 0, 0, 1),
		Community: "public",
		Mode:      TrapModeTrap,
		Collector: mc.addr,
	})
	e.SetConn(conn)
	e.StartBackgroundLoops(context.Background())
	defer e.Close()

	reqID := e.Fire(cat.ByName["linkDown"], nil)
	if reqID == 0 {
		t.Fatal("Fire returned 0 reqID")
	}
	// Wait briefly for the datagram to land.
	time.Sleep(100 * time.Millisecond)
	if e.stats.Sent.Load() != 1 {
		t.Errorf("Sent = %d, want 1", e.stats.Sent.Load())
	}
	if mc.received.Load() != 1 {
		t.Errorf("collector received = %d, want 1", mc.received.Load())
	}
}

func TestTrapExporter_INFORM_AckResolvesPending(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	mc := newMockCollector(t, true) // auto-ack
	defer mc.Close()
	conn := openTestUDPConn(t)

	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:      net.IPv4(127, 0, 0, 1),
		Community:     "public",
		Mode:          TrapModeInform,
		Collector:     mc.addr,
		InformTimeout: 300 * time.Millisecond,
		InformRetries: 1,
	})
	e.SetConn(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.StartBackgroundLoops(ctx)
	defer e.Close()

	e.Fire(cat.ByName["linkUp"], nil)
	// Wait up to 2s for the ack to resolve the pending record.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.PendingInformsLen() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.PendingInformsLen() != 0 {
		t.Fatalf("pending informs still %d", e.PendingInformsLen())
	}
	if e.stats.InformsAcked.Load() != 1 {
		t.Errorf("InformsAcked = %d, want 1", e.stats.InformsAcked.Load())
	}
}

func TestTrapExporter_INFORM_TimeoutIncrementsFailed(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	// Collector that swallows INFORMs without responding.
	mc := newMockCollector(t, false)
	defer mc.Close()
	conn := openTestUDPConn(t)

	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:      net.IPv4(127, 0, 0, 1),
		Community:     "public",
		Mode:          TrapModeInform,
		Collector:     mc.addr,
		InformTimeout: 100 * time.Millisecond,
		InformRetries: 1, // 1 retry → 2 sends total, then fail
	})
	e.SetConn(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.StartBackgroundLoops(ctx)
	defer e.Close()

	e.Fire(cat.ByName["linkUp"], nil)
	// After ~350ms the inform should have timed out, retried once, and then
	// been marked failed.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.stats.InformsFailed.Load() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.stats.InformsFailed.Load() != 1 {
		t.Errorf("InformsFailed = %d, want 1 (Sent=%d, Pending=%d)",
			e.stats.InformsFailed.Load(), e.stats.Sent.Load(), e.PendingInformsLen())
	}
	// We should see 2 sends: original + 1 retry.
	if got := e.stats.Sent.Load(); got < 2 {
		t.Errorf("Sent = %d, want ≥ 2 (original + 1 retry)", got)
	}
}

func TestTrapExporter_INFORM_PendingOverflowDropsOldest(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	mc := newMockCollector(t, false)
	defer mc.Close()
	conn := openTestUDPConn(t)

	const cap = 5
	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:      net.IPv4(127, 0, 0, 1),
		Community:     "public",
		Mode:          TrapModeInform,
		Collector:     mc.addr,
		InformTimeout: 10 * time.Second, // long — we don't want retries interfering
		InformRetries: 0,
		PendingCap:    cap,
	})
	e.SetConn(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.StartBackgroundLoops(ctx)
	defer e.Close()

	// Fire cap+3 informs; 3 should be dropped.
	for i := 0; i < cap+3; i++ {
		e.Fire(cat.ByName["linkUp"], nil)
	}
	// Allow in-flight writes to settle.
	time.Sleep(50 * time.Millisecond)

	if got := e.PendingInformsLen(); got != cap {
		t.Errorf("PendingInformsLen = %d, want %d", got, cap)
	}
	if got := e.stats.InformsDropped.Load(); got != 3 {
		t.Errorf("InformsDropped = %d, want 3", got)
	}
	if got := e.stats.InformsOriginated.Load(); got != uint64(cap+3) {
		t.Errorf("InformsOriginated = %d, want %d", got, cap+3)
	}
}

func TestTrapExporter_Close_NoGoroutineLeak(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	mc := newMockCollector(t, true)
	defer mc.Close()

	before := runtime.NumGoroutine()

	const N = 20
	for i := 0; i < N; i++ {
		conn := openTestUDPConn(t)
		e := NewTrapExporter(TrapExporterOptions{
			DeviceIP:      net.IPv4(127, 0, 0, 1),
			Mode:          TrapModeInform,
			Collector:     mc.addr,
			InformTimeout: 50 * time.Millisecond,
		})
		e.SetConn(conn)
		ctx, cancel := context.WithCancel(context.Background())
		e.StartBackgroundLoops(ctx)
		e.Fire(cat.ByName["linkUp"], nil)
		// Give the goroutines a moment to start.
		time.Sleep(20 * time.Millisecond)
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}
		cancel()
	}
	// Allow straggler goroutines to wind down.
	time.Sleep(300 * time.Millisecond)

	after := runtime.NumGoroutine()
	// Some ambient goroutines are legitimate (runtime, test harness). Assert
	// we didn't leak one-per-exporter.
	if after-before > N/2 {
		t.Errorf("goroutine leak: before=%d after=%d (N=%d exporters closed)",
			before, after, N)
	}
}

func TestTrapExporter_Fire_OnClosingExporterIsNoOp(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	mc := newMockCollector(t, false)
	defer mc.Close()

	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:  net.IPv4(127, 0, 0, 1),
		Mode:      TrapModeTrap,
		Collector: mc.addr,
	})
	e.SetConn(openTestUDPConn(t))
	// Immediately close without firing.
	_ = e.Close()

	reqID := e.Fire(cat.ByName["linkDown"], nil)
	if reqID != 0 {
		t.Errorf("Fire on closed exporter returned reqID %d, want 0", reqID)
	}
	if e.stats.Sent.Load() != 0 {
		t.Errorf("Sent = %d, want 0", e.stats.Sent.Load())
	}
}
