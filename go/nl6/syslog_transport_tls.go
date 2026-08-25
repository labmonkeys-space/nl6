/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// RFC 5425 syslog over TLS.
//
// There is no tlsTransport type, and that is the design rather than an
// omission. RFC 5425 syslog IS RFC 6587 syslog inside a TLS session, so
// everything tcpTransport owns — framing, the reconnect loop, the write
// deadline, per-device connection ownership, the join-on-close discipline —
// is identical. The only thing that differs is what a successful dial returns.
//
// So TLS decorates the dialer. See add-syslog-tls design D1.
//
// The trap this creates, and the reason applySyslogTCPSocketOptions is called
// here rather than left to dialOnce: once the socket is wrapped, the connection
// is a *tls.Conn, and dialOnce's `c.(*net.TCPConn)` assertion silently skips
// it. A TLS device would then inherit Linux's ~4 MiB auto-tuned send buffer and
// no keepalives — the exact fleet-scale problem the cap exists to prevent,
// reintroduced invisibly for one transport.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
)

// syslogTLSDefaultPort is the RFC 5425 §4.1 registered port for syslog over
// TLS. Plain syslog uses 514; a collector configured without a port therefore
// resolves differently depending on the transport, which is correct and
// surprising enough to be documented (design D4).
const syslogTLSDefaultPort = "6514"

// SyslogTLSConfig configures verification of the COLLECTOR.
//
// Note the direction. nl6#93 asked which certificate nl6 should present —
// reuse the shared one, bundle a dedicated one, or take the operator's. All
// three answer "who is connecting", and on this path nl6 is the client dialling
// out: what it needs is a trust root for the collector's certificate, which no
// certificate of nl6's own can supply (design D3).
//
// Deliberately the same vocabulary as DialoutTLSConfig, so the two subsystems
// do not grow different words for the same job.
type SyslogTLSConfig struct {
	// CAFile is a PEM bundle used to verify the collector. Empty means the
	// host's root store.
	CAFile string `json:"ca_file,omitempty"`
	// InsecureSkipVerify disables verification entirely. Named explicitly so a
	// deployment cannot lose verification by omitting something.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	// MTLS would present nl6's shared certificate as a CLIENT certificate.
	// nl6#93 puts client-cert auth out of scope; the field exists so its
	// successor does not have to reopen this config, and is rejected at
	// validation until implemented.
	MTLS bool `json:"mtls,omitempty"`
}

// buildSyslogTLSConfig turns the per-device config into a *tls.Config.
//
// MinVersion is TLS 1.2 and is not configurable: a simulator that can be
// negotiated down to TLS 1.0 is a worse stand-in for a real fleet than one that
// cannot.
func buildSyslogTLSConfig(cfg *SyslogTLSConfig, serverName string) (*tls.Config, error) {
	out := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if cfg == nil {
		return out, nil
	}
	if cfg.InsecureSkipVerify {
		out.InsecureSkipVerify = true
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file %q: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %q: no PEM certificates found", cfg.CAFile)
		}
		out.RootCAs = pool
	}
	return out, nil
}

// newSyslogTLSDialerForDevice wraps the netns TCP dialer in a TLS handshake.
//
// The handshake runs under the caller's context, so a collector that accepts
// and then stalls mid-handshake is bounded by the same per-dial timeout as a
// plain TCP dial rather than holding a pinned OS thread indefinitely.
func newSyslogTLSDialerForDevice(device *DeviceSimulator, collector string, tlsCfg *tls.Config) syslogTCPDialer {
	inner := newSyslogTCPDialerForDevice(device, collector)
	var deviceIP net.IP
	if device != nil {
		deviceIP = device.IP
	}
	return func(ctx context.Context) (net.Conn, error) {
		raw, err := inner(ctx)
		if err != nil {
			return nil, err
		}
		// Socket options FIRST: after the wrap these are unreachable, because
		// dialOnce cannot assert through a *tls.Conn. See the file comment.
		if tc, ok := raw.(*net.TCPConn); ok {
			applySyslogTCPSocketOptions(tc, deviceIP)
		}
		conn := tls.Client(raw, tlsCfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("syslog tls handshake with %s: %w", collector, err)
		}
		return conn, nil
	}
}

// syslogCollectorWithDefaultPort appends the transport's registered default
// port when the collector carries none.
//
// RFC 5425 assigns 6514 to syslog over TLS where plain syslog uses 514, so the
// same bare hostname resolves to a different port depending on the transport.
func syslogCollectorWithDefaultPort(collector string, transport SyslogTransportKind) string {
	if collector == "" {
		return collector
	}
	if _, _, err := net.SplitHostPort(collector); err == nil {
		return collector // already carries a port
	}
	if transport == SyslogTransportTLS {
		return net.JoinHostPort(collector, syslogTLSDefaultPort)
	}
	return net.JoinHostPort(collector, "514")
}
