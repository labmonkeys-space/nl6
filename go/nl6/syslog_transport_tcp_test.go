/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// tcpCollector is a stand-in syslog collector. `stall` makes it accept and then
// never read, which is the condition the whole backpressure design exists for.
type tcpCollector struct {
	ln       net.Listener
	got      chan string
	accepted atomic.Int64
}

func newTCPCollector(t *testing.T, framing SyslogFraming, stall bool) *tcpCollector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &tcpCollector{ln: ln, got: make(chan string, 64)}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.accepted.Add(1)
			if stall {
				continue // hold it open, read nothing
			}
			go func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					msg, err := readFramed(r, framing)
					if err != nil {
						return
					}
					c.got <- msg
				}
			}(conn)
		}
	}()
	return c
}

// readFramed decodes one message, so the test asserts against a real decoder
// rather than against the encoder's own output.
func readFramed(r *bufio.Reader, framing SyslogFraming) (string, error) {
	if framing == SyslogFramingNonTransparent {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		return line[:len(line)-1], nil
	}
	// octet-counting: <len> SP <msg>
	lenStr, err := r.ReadString(' ')
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(lenStr[:len(lenStr)-1])
	if err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func dialerTo(addr string) syslogTCPDialer {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func waitConnected(t *testing.T, tr *tcpTransport) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if tr.conn.Load() != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("transport never connected")
}

// TestSyslogTCP_Framing decodes what actually landed on the wire, in both RFC
// 6587 framings. Asserting the transport's own frame() output would only prove
// the function equals itself.
func TestSyslogTCP_Framing(t *testing.T) {
	for _, framing := range []SyslogFraming{SyslogFramingOctetCounting, SyslogFramingNonTransparent} {
		t.Run(string(framing), func(t *testing.T) {
			col := newTCPCollector(t, framing, false)
			tr := newTCPTransport(net.ParseIP("10.42.0.1"), col.ln.Addr().String(), framing, dialerTo(col.ln.Addr().String()))
			tr.start()
			t.Cleanup(func() { _ = tr.Close() })
			waitConnected(t, tr)

			const msg = "<134>1 2026-08-25T00:00:00Z host app - - - interface down"
			if err := tr.Send([]byte(msg)); err != nil {
				t.Fatalf("Send: %v", err)
			}
			select {
			case got := <-col.got:
				if got != msg {
					t.Errorf("collector decoded %q, want %q", got, msg)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("collector never decoded a message")
			}
		})
	}
}

// TestSyslogTCP_DefaultFramingIsOctetCounting pins the default. Octet-counting
// is safe for any payload; LF framing is only safe because sanitiseMessageBody
// strips CR/LF. Defaulting to the one with a precondition would make the
// precondition load-bearing by accident.
func TestSyslogTCP_DefaultFramingIsOctetCounting(t *testing.T) {
	tr := newTCPTransport(net.ParseIP("10.42.0.1"), "x:514", "", nil)
	if tr.framing != SyslogFramingOctetCounting {
		t.Errorf("default framing = %q, want %q", tr.framing, SyslogFramingOctetCounting)
	}
	framed := string(tr.frame([]byte("abc")))
	if framed != "3 abc" {
		t.Errorf("frame(abc) = %q, want %q", framed, "3 abc")
	}
}

// TestSyslogTCP_SendWhileDisconnectedDoesNotBlock is the fleet-isolation
// property in miniature.
//
// Fires are INLINE on ONE fleet-wide scheduler, so a Send that blocked while
// the collector was unreachable would stop every device from emitting, not just
// this one. Send must therefore fail fast and leave dialing to the background
// loop.
func TestSyslogTCP_SendWhileDisconnectedDoesNotBlock(t *testing.T) {
	// Port 1 on loopback: nothing listens, so dials fail and the transport
	// stays disconnected for the whole test.
	tr := newTCPTransport(net.ParseIP("10.42.0.1"), "127.0.0.1:1", SyslogFramingOctetCounting, dialerTo("127.0.0.1:1"))
	tr.start()
	t.Cleanup(func() { _ = tr.Close() })

	done := make(chan error, 1)
	go func() { done <- tr.Send([]byte("<134>1 - - - - - x")) }()

	select {
	case err := <-done:
		if !errors.Is(err, errSyslogTCPNotConnected) {
			t.Errorf("Send while disconnected returned %v, want errSyslogTCPNotConnected", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send BLOCKED while disconnected — one unreachable collector would stall the fleet's inline scheduler")
	}
}

// TestSyslogTCP_ReconnectsAfterCollectorBounce: a collector restart must not
// permanently silence a device.
//
// The bounce closes the ACCEPTED CONNECTION, not just the listener. Closing a
// listener leaves established connections open, so a "bounce" that only closes
// the listener is not one — the transport is still validly connected and has
// nothing to recover from. An earlier version of this test did that and blamed
// the transport for the silence.
//
// It also does NOT touch tr.conn. Reaching into the transport to clear the
// pointer steals the only reference run() has, which is a state the production
// path never reaches.
func TestSyslogTCP_ReconnectsAfterCollectorBounce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	var accepted atomic.Int64
	conns := make(chan net.Conn, 8)
	serve := func(l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conns <- c
			go func(c net.Conn) { _, _ = io.Copy(io.Discard, c) }(c)
		}
	}
	go serve(ln)

	tr := newTCPTransport(net.ParseIP("10.42.0.1"), addr, SyslogFramingOctetCounting, dialerTo(addr))
	tr.start()
	t.Cleanup(func() { _ = tr.Close() })
	waitConnected(t, tr)

	first := accepted.Load()

	// The bounce: drop the listener AND the live connection, which is what a
	// collector restart actually does.
	_ = ln.Close()
	select {
	case c := <-conns:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("fixture: never captured the accepted connection")
	}

	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("could not rebind %s for the bounce: %v", addr, err)
	}
	defer ln2.Close()
	go serve(ln2)

	// Reconnect is asserted by a NEW accept on the restarted collector, not by
	// the transport's own pointer: what matters is that the collector sees the
	// device again.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if accepted.Load() > first && tr.conn.Load() != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no reconnect after the collector bounced (accepts: %d, was %d)", accepted.Load(), first)
}

// TestSyslogTCP_CloseJoinsTheDialLoop pins that Close means "no goroutine is
// still dialing", not merely "cancel requested". Same contract the flow ticker
// and trap drain work established: a cancelled goroutine is not a stopped one.
func TestSyslogTCP_CloseJoinsTheDialLoop(t *testing.T) {
	tr := newTCPTransport(net.ParseIP("10.42.0.1"), "127.0.0.1:1", SyslogFramingOctetCounting,
		func(ctx context.Context) (net.Conn, error) {
			<-ctx.Done() // a collector that never answers
			return nil, ctx.Err()
		})
	tr.start()

	done := make(chan struct{})
	go func() { _ = tr.Close(); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return — it must cancel AND join the dial loop")
	}
	if err := tr.Close(); err != nil {
		t.Errorf("second Close returned %v, want nil (must be idempotent)", err)
	}
}

// TestSyslogTCP_SendBufferIsCapped guards a feasibility constraint, not a
// preference: at the Linux default of ~4 MiB per connection, 30,000 devices
// would ask for ~117 GiB of kernel send buffer (design D10).
func TestSyslogTCP_SendBufferIsCapped(t *testing.T) {
	if syslogTCPSendBuffer > 64<<10 {
		t.Errorf("send buffer %d exceeds 64 KiB; at fleet scale this is the difference "+
			"between the feature working and exhausting kernel memory", syslogTCPSendBuffer)
	}
	col := newTCPCollector(t, SyslogFramingOctetCounting, true) // stalls: never reads
	tr := newTCPTransport(net.ParseIP("10.42.0.1"), col.ln.Addr().String(), SyslogFramingOctetCounting,
		dialerTo(col.ln.Addr().String()))
	tr.start()
	t.Cleanup(func() { _ = tr.Close() })
	waitConnected(t, tr)

	// Against a collector that never reads, the buffer must fill in bounded
	// time rather than absorbing an unbounded backlog.
	msg := make([]byte, 200)
	var sent int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cp := tr.conn.Load(); cp != nil {
			if tc, ok := (*cp).(*net.TCPConn); ok {
				_ = tc.SetWriteDeadline(time.Now().Add(time.Second))
			}
		}
		if err := tr.Send(msg); err != nil {
			t.Logf("write stopped making progress after %d messages (~%d KiB)", sent, sent*200/1024)
			return
		}
		sent++
		if sent > 200_000 {
			t.Fatalf("absorbed %d messages without pushing back — the send buffer is not capped", sent)
		}
	}
	t.Logf("sent %d messages before the deadline", sent)
}
