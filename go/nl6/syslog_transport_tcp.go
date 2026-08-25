/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// RFC 6587 syslog over TCP.
//
// Two things here are not obvious and are load-bearing.
//
// The send buffer is capped explicitly rather than inherited. Linux auto-tunes
// SO_SNDBUF up to tcp_wmem's ceiling, measured at ~4 MiB per connection against
// a collector that has stopped reading. This transport opens one connection per
// device, so at 30,000 devices the default would ask for ~117 GiB of kernel
// buffer — the feature simply would not exist at that scale. Capping also pulls
// backpressure in from ~161s to ~6s at a collector accepting ~130 msg/s, so
// memory feasibility and measurement latency want the same thing. See
// add-syslog-tcp design D10.
//
// Dialing is throttled by a package-wide semaphore with a hard per-dial
// timeout, because DialContextInNamespace pins an OS thread for the duration of
// the connect. Without the cap, a fleet re-dialing a blackholed collector pins
// enough threads to hit Go's 10k-thread limit and crash the process. gNMI
// dial-out hit this first; the constants here are deliberately its constants.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// SyslogFraming selects an RFC 6587 framing.
type SyslogFraming string

const (
	// SyslogFramingOctetCounting is `<byteCount> SP <msg>` (RFC 6587 §3.4.1).
	// The default: rsyslog emits it, and it is unambiguous for ANY payload,
	// unlike LF framing which depends on the message containing no bare LF.
	SyslogFramingOctetCounting SyslogFraming = "octet-counting"
	// SyslogFramingNonTransparent is LF-terminated (RFC 6587 §3.4.2). Some
	// Cisco platforms speak only this.
	SyslogFramingNonTransparent SyslogFraming = "non-transparent"
)

const (
	// syslogTCPInitialBackoff / syslogTCPMaxBackoff bound reconnect attempts.
	// Same values as gNMI dial-out: a collector bounce should be recovered
	// from in about a second, a collector that is gone should not be dialled
	// in a tight loop.
	syslogTCPInitialBackoff = 1 * time.Second
	syslogTCPMaxBackoff     = 30 * time.Second

	// syslogTCPDialTimeout hard-bounds one dial so a blackholed collector
	// cannot hold a pinned OS thread indefinitely.
	syslogTCPDialTimeout = 10 * time.Second

	// syslogTCPMaxConcurrentDials caps in-namespace dials across ALL devices.
	syslogTCPMaxConcurrentDials = 64

	// syslogTCPStableConnection is how long a connection must survive before
	// it is treated as working. Below it, the backoff keeps growing, so an
	// accept-then-immediately-close collector backs off instead of being
	// re-dialled every second by every device.
	syslogTCPStableConnection = 10 * time.Second

	// syslogTCPWriteTimeout bounds ONE write. Without it a collector that
	// accepts and stops reading blocks Send once the send buffer fills
	// (measured: ~2100 messages), and because the syslog scheduler fires
	// INLINE that blocks the whole fleet, not one device. The blocked call
	// also holds writeMu, so on-demand HTTP fires and state-notify goroutines
	// for the device queue behind it, and inside a scenario it holds the drain
	// barrier open and stalls finalize.
	//
	// A timeout here is a DROP, not an error to retry: syslog has no
	// application ack, so a partially-written frame has desynchronised the
	// stream and the connection has to be replaced either way.
	syslogTCPWriteTimeout = 2 * time.Second

	// syslogTCPKeepAlive is the TCP keepalive period. Without it a collector
	// that dies WITHOUT closing (host crash, network partition) is
	// undetectable on an otherwise idle connection: the read that detects
	// peer close never returns, so the transport neither notices nor
	// reconnects. Writes alone do not save it — a device may be idle for
	// minutes between fires.
	syslogTCPKeepAlive = 30 * time.Second

	// syslogTCPSendBuffer is the per-connection SO_SNDBUF. See the file
	// comment: this is a feasibility constraint, not a tuning knob. Below
	// roughly 64 KiB the receiver's default tcp_rmem dominates the total
	// anyway, so lowering it further buys nothing.
	syslogTCPSendBuffer = 16 << 10
)

var syslogTCPDialSem = make(chan struct{}, syslogTCPMaxConcurrentDials)

// errSyslogTCPNotConnected is returned by Send while no connection is
// established. It is a normal condition during a collector outage, not a fault.
var errSyslogTCPNotConnected = newSyslogErr("syslog tcp: not connected")

// syslogTCPDialer dials the collector. Injected so tests can exercise framing
// and reconnect without a network namespace.
type syslogTCPDialer func(ctx context.Context) (net.Conn, error)

// tcpTransport carries syslog over a per-device TCP connection.
//
// Unlike udpTransport it has NO shared-socket fallback. A shared connection
// would multiplex several devices into one framed byte stream carrying no field
// to demultiplex on, so the collector would see a single client and per-device
// identity would be destroyed rather than degraded (design D2).
type tcpTransport struct {
	deviceIP     net.IP
	collectorStr string
	framing      SyslogFraming
	dial         syslogTCPDialer

	conn    atomic.Pointer[net.Conn]
	ctx     context.Context
	cancel  context.CancelFunc
	closing atomic.Bool
	once    sync.Once
	wg      sync.WaitGroup

	// writeMu serialises writes. A framed stream has no datagram boundaries,
	// so two concurrent writes would interleave and corrupt both messages.
	writeMu sync.Mutex

	firstWriteErr sync.Once
}

func newTCPTransport(deviceIP net.IP, collectorStr string, framing SyslogFraming, dial syslogTCPDialer) *tcpTransport {
	if framing == "" {
		framing = SyslogFramingOctetCounting
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &tcpTransport{
		deviceIP:     deviceIP,
		collectorStr: collectorStr,
		framing:      framing,
		dial:         dial,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// start launches the connect/reconnect loop. Dialing happens here rather than
// in Send so a slow or blackholed collector never blocks the caller — the
// syslog scheduler fires inline, so a blocking dial would stall the whole fleet.
func (t *tcpTransport) start() {
	t.wg.Add(1)
	go t.run()
}

func (t *tcpTransport) run() {
	defer t.wg.Done()
	backoff := syslogTCPInitialBackoff
	for {
		if t.closing.Load() || t.ctx.Err() != nil {
			return
		}
		c, err := t.dialOnce()
		if err != nil {
			if !t.sleep(&backoff) {
				return
			}
			continue
		}
		t.conn.Store(&c)
		connectedAt := time.Now()

		// Close this connection when the transport shuts down. run holds its
		// OWN reference deliberately: Send may have already swapped the
		// pointer away after a write error, and then Close would have nothing
		// to close while this goroutine sat blocked in Read forever — Close
		// joins, so that hangs shutdown rather than merely leaking.
		watchDone := make(chan struct{})
		go func() {
			select {
			case <-t.ctx.Done():
				_ = c.Close()
			case <-watchDone:
			}
		}()

		// Hold the connection until it BREAKS. Only an error counts: a read
		// that returns bytes is a collector or middlebox sending a banner or
		// probe, and treating that as loss would drop a perfectly good
		// connection and re-dial in a loop forever. Syslog is unidirectional,
		// so inbound data is simply discarded.
		var rerr error
		buf := make([]byte, 256)
		for {
			if _, err := c.Read(buf); err != nil {
				rerr = err
				break
			}
		}
		close(watchDone)

		t.conn.CompareAndSwap(&c, nil)
		_ = c.Close()
		if t.closing.Load() || t.ctx.Err() != nil {
			return
		}
		if rerr != nil {
			t.logFirstWriteErr(fmt.Errorf("connection lost: %w", rerr))
		}
		// Reset the backoff only if the connection STAYED UP long enough to
		// count as working. A collector that accepts and immediately closes
		// (an ACL reject) would otherwise be re-dialled once per second
		// forever — and at fleet scale each dial pins an OS thread. Same rule
		// gNMI dial-out applies to its stream.
		if time.Since(connectedAt) >= syslogTCPStableConnection {
			backoff = syslogTCPInitialBackoff
		}
		if !t.sleep(&backoff) {
			return
		}
	}
}

// dialOnce performs one bounded, throttled dial.
func (t *tcpTransport) dialOnce() (net.Conn, error) {
	select {
	case syslogTCPDialSem <- struct{}{}:
		defer func() { <-syslogTCPDialSem }()
	case <-t.ctx.Done():
		return nil, t.ctx.Err()
	}
	ctx, cancel := context.WithTimeout(t.ctx, syslogTCPDialTimeout)
	defer cancel()

	c, err := t.dial(ctx)
	if err != nil {
		return nil, err
	}
	// Cap the send buffer. See the file comment — at fleet scale the
	// inherited default is the difference between working and not.
	//
	// This assertion CANNOT see through a *tls.Conn, which is why the TLS
	// dialer applies these to the underlying socket itself before handshaking.
	// Left to this branch alone, a TLS device would silently inherit the ~4 MiB
	// default and no keepalives.
	if tc, ok := c.(*net.TCPConn); ok {
		applySyslogTCPSocketOptions(tc, t.deviceIP)
	}
	return c, nil
}

// sleep waits out the backoff, doubling it up to the cap. Reports false when
// the transport is shutting down.
func (t *tcpTransport) sleep(backoff *time.Duration) bool {
	timer := time.NewTimer(*backoff)
	defer timer.Stop()
	select {
	case <-timer.C:
		if *backoff < syslogTCPMaxBackoff {
			*backoff *= 2
			if *backoff > syslogTCPMaxBackoff {
				*backoff = syslogTCPMaxBackoff
			}
		}
		return true
	case <-t.ctx.Done():
		return false
	}
}

func (t *tcpTransport) logFirstWriteErr(err error) {
	if t == nil || err == nil {
		return
	}
	t.firstWriteErr.Do(func() {
		log.Printf("syslog export: device %s tcp to %s failed: %v (further errors suppressed for this exporter)",
			t.deviceIP, t.collectorStr, err)
	})
}

// frame wraps an encoded message per RFC 6587.
func (t *tcpTransport) frame(pdu []byte) []byte {
	if t.framing == SyslogFramingNonTransparent {
		// LF termination is only unambiguous because sanitiseMessageBody
		// removes CR/LF/NUL from the message body. That control exists to
		// stop <PRI> injection; framing now depends on it too.
		out := make([]byte, 0, len(pdu)+1)
		out = append(out, pdu...)
		return append(out, '\n')
	}
	prefix := strconv.Itoa(len(pdu))
	out := make([]byte, 0, len(prefix)+1+len(pdu))
	out = append(out, prefix...)
	out = append(out, ' ')
	return append(out, pdu...)
}

// Send writes one framed message to the current connection.
//
// It does NOT dial: while disconnected it returns errSyslogTCPNotConnected
// immediately and lets the reconnect loop do its work. Blocking here would
// stall the fleet-wide scheduler, which fires inline.
//
// A nil return means the bytes were accepted by the kernel, NOT that the
// collector processed them — under load those differ by however deep the send
// buffer is. SyslogStats.Sent therefore means "handed to the kernel" on this
// transport, where on the datagram path it approximates "on the wire". The
// separate offered/written counters that would have made the gap visible were
// cut with the rest of the backpressure work (add-syslog-tcp §1.4), so this
// caveat lives in the docs rather than in a metric.
func (t *tcpTransport) Send(pdu []byte) error {
	cp := t.conn.Load()
	if cp == nil {
		return errSyslogTCPNotConnected
	}
	c := *cp

	t.writeMu.Lock()
	// Bound the write. See syslogTCPWriteTimeout: unbounded, one stalled
	// collector stops the entire fleet's inline scheduler.
	_ = c.SetWriteDeadline(time.Now().Add(syslogTCPWriteTimeout))
	_, err := c.Write(t.frame(pdu))
	t.writeMu.Unlock()

	if err != nil {
		werr := fmt.Errorf("syslog tcp write: %w", err)
		t.logFirstWriteErr(werr)
		// Drop the connection so the reconnect loop reestablishes it. A
		// half-written framed message has desynchronised the stream, so
		// continuing on it would corrupt every subsequent message.
		if t.conn.CompareAndSwap(cp, nil) {
			_ = c.Close()
		}
		return werr
	}
	return nil
}

// Close stops the reconnect loop and waits for it to return, so "closed" means
// no goroutine is still dialing. Idempotent.
func (t *tcpTransport) Close() error {
	if t == nil {
		return nil
	}
	var err error
	t.once.Do(func() {
		t.closing.Store(true)
		t.cancel()
		if cp := t.conn.Swap(nil); cp != nil {
			err = (*cp).Close()
		}
		t.wg.Wait()
	})
	if err != nil && errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// applySyslogTCPSocketOptions caps the send buffer and enables keepalives.
//
// Split out because it must be reachable from the TLS dialer, which holds the
// raw socket only briefly before wrapping it — once wrapped, the connection is
// a *tls.Conn and these settings are unreachable.
func applySyslogTCPSocketOptions(tc *net.TCPConn, deviceIP net.IP) {
	if err := tc.SetWriteBuffer(syslogTCPSendBuffer); err != nil {
		log.Printf("syslog tcp: device %s could not set send buffer: %v", deviceIP, err)
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(syslogTCPKeepAlive)
}

// newSyslogTCPDialerForDevice builds the production dialer: connect from inside
// the device's netns with source IP = the device's own address, so the
// collector attributes the stream to the right device.
//
// Same mechanism UDP already uses, over the same veth pair and
// `FORWARD -i veth-sim-host -j ACCEPT` rule — no new netns or iptables surface.
// nl6#92 listed per-device source IP over TCP as "feasibility TBD"; it is not.
//
// When namespaces are off (tests, -no-namespace) this falls back to the default
// dialer, which connects from the host address with no source binding.
func newSyslogTCPDialerForDevice(device *DeviceSimulator, collector string) syslogTCPDialer {
	if device == nil || device.netNamespace == nil {
		return func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", collector)
		}
	}
	ns := device.netNamespace
	localIP := append(net.IP(nil), device.IP...)
	return func(ctx context.Context) (net.Conn, error) {
		return ns.DialContextInNamespace(ctx, "tcp", collector, &net.TCPAddr{IP: localIP})
	}
}
