/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// netconfTLSConfig returns the server TLS config of a device's NETCONF TLS
// listener. The device pins TLS 1.2 and requires a client certificate. The
// client CA is read from the identity table per handshake, so a REST PUT
// applies to the next connection without touching the listener. With no CA
// the pool is empty and every handshake fails verification, as on a device
// with no CA configured. Every device serves the shared certificate.
func (sm *SimulatorManager) netconfTLSConfig() *tls.Config {
	base := &tls.Config{ // #nosec G402 -- the emulated Junos serves TLS 1.2 only; a 1.3 client is refused as the device refuses it
		Certificates: []tls.Certificate{*sm.sharedTLSCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	cfg := base.Clone()
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.ClientCAs = sm.netconfTLSClientCAs()
		return c, nil
	}
	return cfg
}

// netconfTLSClientCAs returns the current client CA pool, an empty one when
// the table holds no CA.
func (sm *SimulatorManager) netconfTLSClientCAs() *x509.CertPool {
	if id := sm.netconfTLSIdentity.Load(); id != nil {
		if p := id.pool(); p != nil {
			return p
		}
	}
	return x509.NewCertPool()
}

// startNetconfTLSServer binds the device's NETCONF over TLS listener on
// -netconf-tls-port. It is a no-op unless the manager exists, the subsystem
// is active and the profile's dialect is served over TLS. The listener is
// bound with or without a client CA.
//
// Caller MUST hold d.mu.
func (d *DeviceSimulator) startNetconfTLSServer() error {
	if d == nil || d.netconfTLSListener != nil {
		return nil
	}
	mgr := manager
	if mgr == nil || !mgr.netconfSubsystemActive.Load() {
		return nil
	}
	dia, ok := netconfDialectFor(d)
	if !ok || !dia.TLS {
		return nil
	}
	if mgr.sharedTLSCert == nil {
		return fmt.Errorf("no shared TLS certificate available for NETCONF on %s", d.IP)
	}

	addr := fmt.Sprintf("%s:%d", d.IP.String(), mgr.netconfTLSPort)
	l, err := deviceListenTCP(d, addr)
	if err != nil {
		return fmt.Errorf("failed to start NETCONF TLS server on %s: %v", addr, err)
	}

	srv := d.newNetconfServer(l, mgr, dia)
	srv.tlsCfg = mgr.netconfTLSConfig()
	d.netconfTLSListener = srv
	srv.wg.Add(1)
	go srv.acceptLoop()
	return nil
}

// serveTLS runs one NETCONF over TLS connection: the handshake, the mapping
// of the client certificate to a user, and one session. There is no
// subsystem step: the hello follows the handshake. serveConn closes conn.
func (s *netconfServer) serveTLS(conn net.Conn) {
	// The SSH idle deadline bounds the handshake, as on the SSH listener.
	_ = conn.SetDeadline(time.Now().Add(sshIdleTimeout()))
	tc := tls.Server(conn, s.tlsCfg)
	defer tc.Close()
	if err := tc.HandshakeContext(s.ctx); err != nil {
		s.mgr.countNetconfTLSHandshakeFailure(s.dev, conn, err)
		return
	}
	// RequireAndVerifyClientCert guarantees a verified peer certificate.
	user, ok := s.mgr.netconfTLSIdentity.Load().userFor(tc.ConnectionState().PeerCertificates[0])
	if !ok {
		// The device completes the handshake, then closes before any hello.
		return
	}
	if raw, ok := conn.(*net.TCPConn); ok {
		_ = raw.SetKeepAlive(true)
		_ = raw.SetKeepAlivePeriod(netconfKeepAlivePeriod)
	}
	_ = conn.SetDeadline(time.Time{})
	if s.ctx.Err() != nil {
		return
	}
	sess := s.dia.NewSession(s.reg.sessionSeq.Add(1), s.dev, tc, s.reg, user)
	sess.tls = true
	sess.conn = tc
	if err := sess.Serve(s.ctx); err != nil {
		log.Printf("NETCONF session on %s ended: %v", s.dev.IP, err)
	}
	_ = tc.Close()
	// The connection is down, so a writer blocked on it returns. Waiting
	// here keeps Close from returning while the session's listener or
	// writer still runs.
	sess.waitEvents()
}

// countNetconfTLSHandshakeFailure counts a failed handshake and logs the
// first one per process. One misconfigured client against a large fleet
// would otherwise flood the log with one fault.
func (sm *SimulatorManager) countNetconfTLSHandshakeFailure(d *DeviceSimulator, conn net.Conn, err error) {
	atomic.AddUint64(&sm.netconfTLSHandshakeFailures, 1)
	sm.netconfTLSFirstHandshakeErrOnce.Do(func() {
		log.Printf("NETCONF TLS handshake failed on %s from %s: %v "+
			"(for example, the client needs a certificate signed by the client CA; with no client CA set, "+
			"every handshake is refused. Further handshake errors are suppressed; see "+
			"tls_handshake_failures on GET /api/v1/netconf/status)", d.IP, conn.RemoteAddr(), err)
	})
}
