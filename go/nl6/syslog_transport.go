/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// The wire boundary for syslog export.
//
// Everything above this seam is transport-independent and stays in one place:
// catalog resolution, the template vocabulary, the scenario-part gate, ledger
// accounting, counter persistence. Everything below it is how bytes reach a
// collector.
//
// The seam exists because syslog's transport used to be its types —
// SyslogExporter held a *net.UDPAddr and an atomic.Pointer[net.UDPConn], so
// "add TCP" had nowhere to go. Same shape as DialoutTransport in
// gnmi_dialout_transport.go: a narrow interface at the boundary, with payload
// generation reused verbatim above it.

package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// SyslogTransportKind names a transport in configuration.
type SyslogTransportKind string

const (
	SyslogTransportUDP SyslogTransportKind = "udp"
	SyslogTransportTCP SyslogTransportKind = "tcp"
	// SyslogTransportTLS is RFC 5425: RFC 6587 framing inside a TLS session.
	// It is not a separate transport type — see syslog_transport_tls.go.
	SyslogTransportTLS SyslogTransportKind = "tls"
)

// SyslogTransport carries an already-encoded syslog message to a collector.
//
// Send receives the complete wire message. A stream transport that needs
// framing (RFC 6587) applies it here — framing is a property of the transport,
// not of the message, which is why SyslogEncoder does not know about it.
type SyslogTransport interface {
	// Send delivers one encoded message. A nil error means the transport
	// accepted it; what "accepted" guarantees is transport-specific and is
	// documented per implementation.
	Send(pdu []byte) error
	// Close releases the transport's resources. Idempotent.
	Close() error
}

// udpTransport is the datagram path, and is deliberately byte-for-byte what
// SyslogExporter did before the seam existed.
//
// It keeps the two-socket ladder: a per-device socket bound to the device's own
// IP (so the collector sees the device as the source), falling back to a shared
// socket when per-device binding was disabled or failed. That fallback is
// specific to datagrams — it costs only source-address attribution, because a
// datagram socket is stateless and one socket can serve any number of devices.
// A stream transport has no equivalent rung; see add-syslog-tcp design D2.
type udpTransport struct {
	deviceIP     net.IP
	collector    *net.UDPAddr
	collectorStr string

	// conn is the per-device socket. Nil when per-device binding was disabled
	// or failed and the shared socket is used. atomic.Pointer so Close and
	// Send race safely without a mutex in the hot path.
	conn atomic.Pointer[net.UDPConn]

	// sharedConn is the fallback. Read-only after construction.
	sharedConn *net.UDPConn

	// firstWriteErr gates at most one log line per transport on a failed
	// write, so a down collector cannot flood logs at fire cadence x device
	// count (mirror of TrapExporter.logFirstWriteErr, trap phase 4 P8).
	firstWriteErr sync.Once
}

func newUDPTransport(deviceIP net.IP, collector *net.UDPAddr, collectorStr string, shared *net.UDPConn) *udpTransport {
	return &udpTransport{
		deviceIP:     deviceIP,
		collector:    collector,
		collectorStr: collectorStr,
		sharedConn:   shared,
	}
}

// setConn installs the per-device socket, closing any socket it replaces.
// Callers do not close the old one themselves, and forgetting to would leak a
// descriptor per rebind.
func (t *udpTransport) setConn(c *net.UDPConn) {
	old := t.conn.Swap(c)
	if old != nil && old != c {
		_ = old.Close()
	}
}

// logFirstWriteErr emits at most one log line per transport on a failed write.
func (t *udpTransport) logFirstWriteErr(err error) {
	if t == nil || err == nil {
		return
	}
	t.firstWriteErr.Do(func() {
		log.Printf("syslog export: device %s write to %s failed: %v (further errors suppressed for this exporter)",
			t.deviceIP, t.collectorStr, err)
	})
}

// Send transmits via the per-device socket when one is installed, otherwise via
// the shared fallback.
//
// Error reporting, unchanged from the pre-seam behaviour: when the per-device
// write fails but the shared write succeeds, the per-device error is LOGGED so
// an operator can debug the primary failure, but nil is returned so the
// caller's counter treats the send as successful. When both fail, a joined
// error carries both causes so the primary diagnostic is not lost.
func (t *udpTransport) Send(pdu []byte) error {
	var primaryErr error
	conn := t.conn.Load()
	if conn != nil {
		if _, err := conn.WriteToUDP(pdu, t.collector); err == nil {
			return nil
		} else {
			primaryErr = fmt.Errorf("per-device socket: %w", err)
		}
	}
	if t.sharedConn == nil {
		if primaryErr != nil {
			t.logFirstWriteErr(primaryErr)
			return primaryErr
		}
		t.logFirstWriteErr(errNoSyslogSocket)
		return errNoSyslogSocket
	}
	_, err := t.sharedConn.WriteToUDP(pdu, t.collector)
	if err == nil {
		if primaryErr != nil {
			// Fallback succeeded — log the primary failure so the operator
			// can diagnose why the per-device path stopped working.
			log.Printf("syslog: %s per-device write failed, sent via shared socket: %v",
				t.deviceIP, primaryErr)
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
	t.logFirstWriteErr(finalErr)
	return finalErr
}

// Close releases the per-device socket. The shared socket belongs to the
// manager's pool and is not closed here.
func (t *udpTransport) Close() error {
	conn := t.conn.Swap(nil)
	if conn != nil {
		return conn.Close()
	}
	return nil
}
