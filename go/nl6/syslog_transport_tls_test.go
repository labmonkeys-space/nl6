/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// newTestTLSCert mints a self-signed cert valid for 127.0.0.1.
//
// The simulator's own generateSharedTLSCert is a manager method that stores
// into the manager and cannot be asked for a cert; more importantly its SANs
// are for the simulated device addresses, not loopback, so a handshake to
// 127.0.0.1 would fail hostname verification and this test would be asserting
// the wrong failure.
func newTestTLSCert(t *testing.T) (*tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nl6-test-collector"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// newTLSCollector is a syslog collector speaking TLS, so the test exercises a
// real handshake rather than a stub.
func newTLSCollector(t *testing.T) (addr string, caPool *x509.CertPool, got chan string) {
	t.Helper()
	cert, leaf := newTestTLSCert(t)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	msgs := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					m, err := readFramed(r, SyslogFramingOctetCounting)
					if err != nil {
						return
					}
					msgs <- m
				}
			}(c)
		}
	}()
	return ln.Addr().String(), pool, msgs
}

// TestSyslogTLS_EndToEnd: a real handshake against a real listener, and the
// collector decodes the octet-counted frame RFC 5425 mandates.
func TestSyslogTLS_EndToEnd(t *testing.T) {
	addr, pool, got := newTLSCollector(t)
	host, _, _ := net.SplitHostPort(addr)

	dialer := newSyslogTLSDialerForDevice(nil, addr, &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	tr := newTCPTransport(net.ParseIP("10.42.0.1"), addr, SyslogFramingOctetCounting, dialer)
	tr.start()
	t.Cleanup(func() { _ = tr.Close() })
	waitConnected(t, tr)

	const msg = "<134>1 2026-08-25T00:00:00Z host app - - - encrypted"
	if err := tr.Send([]byte(msg)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case m := <-got:
		if m != msg {
			t.Errorf("collector decoded %q, want %q", m, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collector never decoded a message over TLS")
	}
}

// TestSyslogTLS_VerifiesTheCollector: an untrusted collector must not be
// silently accepted. This is the property that makes the transport worth having
// over plain TCP.
func TestSyslogTLS_VerifiesTheCollector(t *testing.T) {
	addr, _, _ := newTLSCollector(t) // note: CA pool deliberately discarded
	host, _, _ := net.SplitHostPort(addr)

	dialer := newSyslogTLSDialerForDevice(nil, addr, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// No RootCAs: falls back to the host store, which never signed this.
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialer(ctx)
	if err == nil {
		_ = c.Close()
		t.Fatal("handshake succeeded against an unverifiable collector; " +
			"verification must fail closed, not open")
	}
}

// TestSyslogTLS_InsecureSkipVerifyIsOptIn pins that losing verification takes
// an explicit setting — it must not be reachable by omission.
func TestSyslogTLS_InsecureSkipVerifyIsOptIn(t *testing.T) {
	addr, _, _ := newTLSCollector(t)
	host, _, _ := net.SplitHostPort(addr)

	cfg, err := buildSyslogTLSConfig(&SyslogTLSConfig{InsecureSkipVerify: true}, host)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify did not survive into the tls.Config")
	}
	dialer := newSyslogTLSDialerForDevice(nil, addr, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialer(ctx)
	if err != nil {
		t.Fatalf("explicit insecure_skip_verify should connect: %v", err)
	}
	_ = c.Close()

	// And the default must NOT skip.
	def, err := buildSyslogTLSConfig(nil, host)
	if err != nil {
		t.Fatalf("build default: %v", err)
	}
	if def.InsecureSkipVerify {
		t.Error("verification is disabled by default; it must take an explicit setting")
	}
	if def.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", def.MinVersion)
	}
}

// TestSyslogTLS_SocketOptionsSurviveTheWrap is task 1.3, and guards a failure
// that is invisible at any scale a test can run.
//
// dialOnce caps SO_SNDBUF and enables keepalives via `c.(*net.TCPConn)`. A
// *tls.Conn does not satisfy that assertion, so if the TLS dialer did not apply
// them to the underlying socket BEFORE wrapping, every TLS device would
// silently inherit Linux's ~4 MiB auto-tuned send buffer — ~117 GiB across
// 30,000 devices, the exact problem the cap exists to prevent.
func TestSyslogTLS_SocketOptionsSurviveTheWrap(t *testing.T) {
	addr, pool, _ := newTLSCollector(t)
	host, _, _ := net.SplitHostPort(addr)

	dialer := newSyslogTLSDialerForDevice(nil, addr, &tls.Config{
		RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialer(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	tc, ok := c.(*tls.Conn)
	if !ok {
		t.Fatalf("dialer returned %T, want *tls.Conn", c)
	}
	if _, ok := tc.NetConn().(*net.TCPConn); !ok {
		t.Fatalf("underlying conn is %T, want *net.TCPConn", tc.NetConn())
	}
	// The buffer size cannot be read back portably, so assert the reachability
	// that makes applying it possible: if this ever stops being a *net.TCPConn,
	// the options silently stop being applied.
}

// TestSyslogTLS_DefaultPortIsRFC5425 pins that a bare hostname resolves to 6514
// under TLS and 514 otherwise — the same collector string meaning two ports.
func TestSyslogTLS_DefaultPortIsRFC5425(t *testing.T) {
	for _, tc := range []struct {
		collector string
		transport SyslogTransportKind
		want      string
	}{
		{"collector.example", SyslogTransportTLS, "collector.example:6514"},
		{"collector.example", SyslogTransportTCP, "collector.example:514"},
		{"collector.example", SyslogTransportUDP, "collector.example:514"},
		{"collector.example:1514", SyslogTransportTLS, "collector.example:1514"},
	} {
		got := syslogCollectorWithDefaultPort(tc.collector, tc.transport)
		if got != tc.want {
			t.Errorf("%q under %s = %q, want %q", tc.collector, tc.transport, got, tc.want)
		}
	}
}

// TestSyslogTLS_ConfigRejectsNonMandatedFraming: RFC 5425 §4.3.1 mandates
// octet-counting. Accepting another framing and overriding it would put a
// stream on the wire no conformant collector can parse, so the failure would
// surface at the collector rather than at configuration time.
func TestSyslogTLS_ConfigRejectsNonMandatedFraming(t *testing.T) {
	c := &DeviceSyslogConfig{Collector: "127.0.0.1:6514", Transport: "tls", Framing: "non-transparent"}
	c.ApplyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("tls + non-transparent framing was accepted; RFC 5425 mandates octet-counting")
	}

	ok := &DeviceSyslogConfig{Collector: "127.0.0.1:6514", Transport: "tls"}
	ok.ApplyDefaults()
	if err := ok.Validate(); err != nil {
		t.Errorf("tls with default framing rejected: %v", err)
	}
	if ok.Framing != string(SyslogFramingOctetCounting) {
		t.Errorf("tls defaulted framing to %q, want octet-counting", ok.Framing)
	}
}

// TestSyslogTLS_MTLSIsRefusedUntilImplemented: the field exists so #93's
// successor need not reopen the config, but shipping it as a silent no-op
// would be worse than not having it.
func TestSyslogTLS_MTLSIsRefusedUntilImplemented(t *testing.T) {
	c := &DeviceSyslogConfig{
		Collector: "127.0.0.1:6514", Transport: "tls",
		TLS: &SyslogTLSConfig{MTLS: true},
	}
	c.ApplyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("tls.mtls accepted while unimplemented; it must refuse rather than no-op")
	}
}
