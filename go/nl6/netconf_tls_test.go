/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	netconfTLSTestCertOnce sync.Once
	netconfTLSTestCert     *tls.Certificate
	netconfTLSTestCAPEM    []byte
)

// useNetconfTLSTestManager is useNetconfTestManager with the shared server
// certificate in place and the TLS listener on a free port. The certificate
// is generated once per test binary.
func useNetconfTLSTestManager(t *testing.T) *SimulatorManager {
	t.Helper()
	mgr := useNetconfTestManager(t, true)
	netconfTLSTestCertOnce.Do(func() {
		gen := &SimulatorManager{}
		gen.generateSharedTLSCert()
		netconfTLSTestCert, netconfTLSTestCAPEM = gen.sharedTLSCert, gen.sharedTLSCAPEM
	})
	if netconfTLSTestCert == nil {
		t.Fatal("no shared TLS certificate")
	}
	mgr.sharedTLSCert, mgr.sharedTLSCAPEM = netconfTLSTestCert, netconfTLSTestCAPEM
	mgr.netconfTLSPort = 0
	return mgr
}

// netconfTLSTestCA is an in-test client CA.
type netconfTLSTestCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  string
}

func newNetconfTLSTestCA(t *testing.T) *netconfTLSTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "netconf-client-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &netconfTLSTestCA{cert: c, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// client issues a client certificate, RSA 2048 or ECDSA P-256, and returns
// it with its Junos fingerprint.
func (ca *netconfTLSTestCA) client(t *testing.T, useECDSA bool) (tls.Certificate, string) {
	t.Helper()
	var key crypto.Signer
	var err error
	if useECDSA {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "netconf-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, certSHA256Fingerprint(leaf)
}

// newJunosTLSDevice builds a juniper_mx10004 on 127.0.0.1, registers it with
// mgr and starts its NETCONF TLS listener on a free port.
func newJunosTLSDevice(t *testing.T, mgr *SimulatorManager) (*DeviceSimulator, *InterfaceState, string) {
	t.Helper()
	dev := newJunosTestDevice(t)
	dev.ID = "mx10004-tls-test"
	dev.IP = net.IPv4(127, 0, 0, 1)
	dev.resourceFile = "juniper_mx10004.json"
	dev.sysName = "NY-CORE-01"
	mgr.devices[dev.ID] = dev
	dev.mu.Lock()
	err := dev.startNetconfTLSServer()
	dev.mu.Unlock()
	if err != nil {
		t.Fatalf("startNetconfTLSServer: %v", err)
	}
	if dev.netconfTLSListener == nil {
		t.Fatal("mx10004 has no NETCONF TLS listener")
	}
	t.Cleanup(func() {
		dev.mu.Lock()
		dev.stopNetconfServer()
		dev.mu.Unlock()
	})
	return dev, netconfIfCounters(dev).State(), dev.netconfTLSListener.Addr().String()
}

// dialNetconfTLS runs a TLS handshake against addr. cert may be nil for a
// client that presents none; mod may adjust the client config.
func dialNetconfTLS(t *testing.T, addr string, cert *tls.Certificate, mod func(*tls.Config)) (*tls.Conn, error) {
	t.Helper()
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // the shared server cert has only a 0.0.0.0 SAN
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	if mod != nil {
		mod(cfg)
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c, nil
}

// openNetconfOverTLS dials, checks the server hello against the Junos hello
// for wantUser and sends the client hello.
func openNetconfOverTLS(t *testing.T, addr string, cert *tls.Certificate, sessionID uint32, wantUser string) (*tls.Conn, *netconfFramer) {
	t.Helper()
	c, err := dialNetconfTLS(t, addr, cert, nil)
	if err != nil {
		t.Fatalf("tls dial %s: %v", addr, err)
	}
	f := newNetconfFramer(c, c)
	h, err := f.ReadMessage()
	if err != nil {
		t.Fatalf("server hello: %v", err)
	}
	if want := string(junosServerHello(sessionID, wantUser)); string(h) != want {
		t.Fatalf("server hello:\n%s\nwant:\n%s", h, want)
	}
	hello := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>`
	if err := f.WriteMessage([]byte(hello)); err != nil {
		t.Fatalf("client hello: %v", err)
	}
	return c, f
}

func setNetconfTLSIdentity(mgr *SimulatorManager, ca *netconfTLSTestCA, ids map[string]string, def string) {
	id := &NetconfTLSIdentity{Identities: ids, DefaultUsername: def}
	if ca != nil {
		id.CAPEM = ca.pem
	}
	if id.Identities == nil {
		id.Identities = map[string]string{}
	}
	mgr.netconfTLSIdentity.Store(id.normalised())
}

func junosTLSSubscribe(t *testing.T, f *netconfFramer) {
	t.Helper()
	r, err := netconfRPCWithin(f, "1", `<create-subscription xmlns="`+junosNotificationNS+`"/>`, 5*time.Second)
	if err != nil || !strings.Contains(r, "<ok/>") {
		t.Fatalf("create-subscription: %q %v", r, err)
	}
}

// readJunosLinkPair reads the state-form and event-form notification of one
// link event on ifName.
func readJunosLinkPair(t *testing.T, f *netconfFramer, id, ifName string) {
	t.Helper()
	for i, want := range []string{"<state-system-syslog>", "<junos>"} {
		m, err := f.ReadMessage()
		if err != nil {
			t.Fatalf("notification %d: %v", i, err)
		}
		for _, w := range []string{want, "<id>" + id + "</id>", "ifName " + ifName + "</"} {
			if !strings.Contains(string(m), w) {
				t.Fatalf("notification %d lacks %q:\n%s", i, w, m)
			}
		}
	}
}

// expectNetconfTLSEOF checks that the server closes c without sending a byte.
func expectNetconfTLSEOF(t *testing.T, c *tls.Conn) {
	t.Helper()
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read = %d bytes %q, %v; want 0 bytes and EOF", n, buf[:n], err)
	}
}

func TestNetconfTLSHelloWithKnownFingerprint(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	cert, fp := ca.client(t, false)
	setNetconfTLSIdentity(mgr, ca, map[string]string{fp: "ncuser"}, "")
	_, _, addr := newJunosTLSDevice(t, mgr)

	c, f := openNetconfOverTLS(t, addr, &cert, 1, "ncuser")
	cs := c.ConnectionState()
	if cs.Version != tls.VersionTLS12 {
		t.Errorf("TLS version %x, want TLS 1.2", cs.Version)
	}
	if cs.CipherSuite != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Errorf("cipher suite %s, want TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls.CipherSuiteName(cs.CipherSuite))
	}
	if r, err := netconfRPCWithin(f, "2", "<get-software-information/>", 5*time.Second); err != nil || !strings.Contains(r, `message-id="2"`) {
		t.Fatalf("rpc over TLS: %q %v", r, err)
	}
}

func TestNetconfTLSDefaultUsername(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	cert, _ := ca.client(t, false)
	setNetconfTLSIdentity(mgr, ca, nil, "fallback")
	_, _, addr := newJunosTLSDevice(t, mgr)
	openNetconfOverTLS(t, addr, &cert, 1, "fallback")
}

func TestNetconfTLSUnknownFingerprintClosesWithoutHello(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	known, fp := ca.client(t, false)
	_ = known
	unknown, _ := ca.client(t, false)
	setNetconfTLSIdentity(mgr, ca, map[string]string{fp: "ncuser"}, "")
	_, _, addr := newJunosTLSDevice(t, mgr)

	c, err := dialNetconfTLS(t, addr, &unknown, nil)
	if err != nil {
		t.Fatalf("handshake with a CA-signed but unmapped cert failed: %v", err)
	}
	expectNetconfTLSEOF(t, c)
	if n := atomic.LoadUint64(&mgr.netconfTLSHandshakeFailures); n != 0 {
		t.Errorf("an unmapped certificate counted as a handshake failure (%d)", n)
	}
}

// netconfTLSRefused dials addr and expects the handshake to fail, then waits
// for the server to count it.
func netconfTLSRefused(t *testing.T, mgr *SimulatorManager, addr string, cert *tls.Certificate, mod func(*tls.Config)) {
	t.Helper()
	before := atomic.LoadUint64(&mgr.netconfTLSHandshakeFailures)
	c, err := dialNetconfTLS(t, addr, cert, mod)
	if err == nil {
		// A TLS 1.2 client learns of a refused certificate only on its
		// first read.
		buf := make([]byte, 1)
		if _, err = c.Read(buf); err == nil {
			t.Fatal("handshake accepted")
		}
	}
	waitNetconf(t, "handshake failure counted", func() bool {
		return atomic.LoadUint64(&mgr.netconfTLSHandshakeFailures) == before+1
	})
}

func TestNetconfTLSRefusesNoClientCert(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	setNetconfTLSIdentity(mgr, ca, nil, "fallback")
	_, _, addr := newJunosTLSDevice(t, mgr)
	netconfTLSRefused(t, mgr, addr, nil, nil)
}

func TestNetconfTLSRefusesUnknownCA(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	trusted := newNetconfTLSTestCA(t)
	other := newNetconfTLSTestCA(t)
	cert, fp := other.client(t, false)
	setNetconfTLSIdentity(mgr, trusted, map[string]string{fp: "ncuser"}, "fallback")
	_, _, addr := newJunosTLSDevice(t, mgr)
	netconfTLSRefused(t, mgr, addr, &cert, nil)
}

func TestNetconfTLSRefusesTLS13Only(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	cert, fp := ca.client(t, false)
	setNetconfTLSIdentity(mgr, ca, map[string]string{fp: "ncuser"}, "")
	_, _, addr := newJunosTLSDevice(t, mgr)
	netconfTLSRefused(t, mgr, addr, &cert, func(c *tls.Config) { c.MinVersion = tls.VersionTLS13 })
}

func TestNetconfTLSRefusesWithoutClientCA(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	cert, fp := ca.client(t, false)
	setNetconfTLSIdentity(mgr, nil, map[string]string{fp: "ncuser"}, "fallback")
	_, _, addr := newJunosTLSDevice(t, mgr)
	netconfTLSRefused(t, mgr, addr, &cert, nil)
}

func TestNetconfTLSAcceptsECDSAClientCert(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	cert, fp := ca.client(t, true)
	setNetconfTLSIdentity(mgr, ca, map[string]string{fp: "ecuser"}, "")
	_, _, addr := newJunosTLSDevice(t, mgr)
	openNetconfOverTLS(t, addr, &cert, 1, "ecuser")
}

func TestNetconfTLSCountsHandshakeFailures(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	trusted := newNetconfTLSTestCA(t)
	good, fp := trusted.client(t, false)
	stranger, _ := newNetconfTLSTestCA(t).client(t, false)
	setNetconfTLSIdentity(mgr, trusted, map[string]string{fp: "ncuser"}, "")
	_, _, addr := newJunosTLSDevice(t, mgr)

	netconfTLSRefused(t, mgr, addr, nil, nil)
	netconfTLSRefused(t, mgr, addr, &stranger, nil)
	netconfTLSRefused(t, mgr, addr, &good, func(c *tls.Config) { c.MinVersion = tls.VersionTLS13 })

	rec := httptest.NewRecorder()
	netconfStatusHandler(rec, httptest.NewRequest("GET", "/api/v1/netconf/status", nil))
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["tls_handshake_failures"] != float64(3) || got["listeners_tls"] != float64(1) {
		t.Fatalf("status = %s, want tls_handshake_failures 3 and listeners_tls 1", rec.Body)
	}
}

func TestNetconfTLSIdentityPutAppliesToNextConnection(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	cert, fp := ca.client(t, false)
	setNetconfTLSIdentity(mgr, ca, map[string]string{fp: "ncuser"}, "")
	_, st, addr := newJunosTLSDevice(t, mgr)

	_, f := openNetconfOverTLS(t, addr, &cert, 1, "ncuser")
	junosTLSSubscribe(t, f)

	body := `{"ca_pem":` + jsonString(ca.pem) + `,"identities":{}}`
	if rec := netconfTLSDo(t, netconfTLSPutHandler, "PUT", body); rec.Code != 200 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}

	ncLink(st, 1, OperDown)
	readJunosLinkPair(t, f, "SNMP_TRAP_LINK_DOWN", "xe-0/0/0")

	c, err := dialNetconfTLS(t, addr, &cert, nil)
	if err != nil {
		t.Fatalf("handshake after the PUT: %v", err)
	}
	expectNetconfTLSEOF(t, c)
}

func TestNetconfTLSSubscriptionDeliversLinkEvents(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	cert, fp := ca.client(t, false)
	setNetconfTLSIdentity(mgr, ca, map[string]string{fp: "ncuser"}, "")
	_, st, addr := newJunosTLSDevice(t, mgr)

	_, f := openNetconfOverTLS(t, addr, &cert, 1, "ncuser")
	junosTLSSubscribe(t, f)
	ncLink(st, 1, OperDown)
	readJunosLinkPair(t, f, "SNMP_TRAP_LINK_DOWN", "xe-0/0/0")
	ncLink(st, 1, OperUp)
	readJunosLinkPair(t, f, "SNMP_TRAP_LINK_UP", "xe-0/0/0")

	status := mgr.GetNetconfStatus()
	if status.Sessions != 1 || status.SessionsTLS != 1 || status.Subscriptions != 1 || status.ListenersTLS != 1 || status.Listeners != 0 {
		t.Fatalf("status = %+v", status)
	}
}

func TestNetconfTLSNotOnIOSXE(t *testing.T) {
	useNetconfTLSTestManager(t)
	dev, _ := newNetconfTestDevice(t)
	dev.ID, dev.IP, dev.resourceFile = "cat9500-tls", net.IPv4(127, 0, 0, 1), "cisco_catalyst_9500.json"
	dev.mu.Lock()
	err := dev.startNetconfTLSServer()
	dev.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if dev.netconfTLSListener != nil || dev.netconfSessions != nil {
		t.Fatal("cisco_catalyst_9500 got a NETCONF TLS listener")
	}
}

func TestNetconfDeviceStopClosesTLSSessions(t *testing.T) {
	for name, stop := range map[string]func(*DeviceSimulator){
		"Stop":              func(d *DeviceSimulator) { _ = d.Stop() },
		"stopListenersOnly": func(d *DeviceSimulator) { d.stopListenersOnly() },
	} {
		t.Run(name, func(t *testing.T) {
			mgr := useNetconfTLSTestManager(t)
			ca := newNetconfTLSTestCA(t)
			cert, fp := ca.client(t, false)
			setNetconfTLSIdentity(mgr, ca, map[string]string{fp: "ncuser"}, "")
			dev, st, tlsAddr := newJunosTLSDevice(t, mgr)
			dev.mu.Lock()
			err := dev.startNetconfServer()
			dev.mu.Unlock()
			if err != nil || dev.netconfListener == nil {
				t.Fatalf("SSH listener beside TLS: %v", err)
			}
			dev.running = true

			// Both transports share one session registry, so ids do not
			// collide and both sessions count on the device.
			fs, _ := openNetconfOverSSH(t, dialNetconfTestSSH(t, dev.netconfListener.Addr().String()))
			junosTLSSubscribe(t, fs)
			_, ft := openNetconfOverTLS(t, tlsAddr, &cert, 2, "ncuser")
			junosTLSSubscribe(t, ft)
			if s := mgr.GetNetconfStatus(); s.Sessions != 2 || s.SessionsTLS != 1 {
				t.Fatalf("status before stop = %+v", s)
			}

			stop(dev)

			for name, f := range map[string]*netconfFramer{"ssh": fs, "tls": ft} {
				if _, err := netconfRPCWithin(f, "m2", "<get-software-information/>", 5*time.Second); err == nil {
					t.Fatalf("%s session still answers after the device stopped", name)
				}
			}
			waitNetconf(t, "state listener removal", func() bool { return netconfStateListeners(st) == 0 })
			dev.mu.RLock()
			l, lt, reg := dev.netconfListener, dev.netconfTLSListener, dev.netconfSessions
			dev.mu.RUnlock()
			if l != nil || lt != nil || reg != nil {
				t.Fatal("device keeps NETCONF state after stop")
			}
			if conn, err := net.DialTimeout("tcp", tlsAddr, time.Second); err == nil {
				_ = conn.Close()
				t.Fatal("NETCONF TLS port still accepts after stop")
			}
		})
	}
}

// An idle subscribed TLS session costs one nl6 goroutine, the connection's
// goroutine that runs the session reader, plus the device's shared
// dispatcher. There is no SSH dispatch loop.
func TestNetconfTLSIdleSessionGoroutines(t *testing.T) {
	const sessions, perSession, perDevice = 5, 1, 1
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	cert, _ := ca.client(t, false)
	setNetconfTLSIdentity(mgr, ca, nil, "ncuser")
	_, st, addr := newJunosTLSDevice(t, mgr)
	base := netconfAppGoroutines()
	for i := 0; i < sessions; i++ {
		c, f := openNetconfOverTLS(t, addr, &cert, uint32(i+1), "ncuser")
		junosTLSSubscribe(t, f)
		_ = c.SetDeadline(time.Time{})
		go func() {
			for {
				if _, err := f.ReadMessage(); err != nil {
					return
				}
			}
		}()
	}
	want := base + perDevice + sessions*perSession
	waitNetconf(t, "idle goroutine count", func() bool { return netconfAppGoroutines() == want })

	ncLink(st, 1, OperDown)
	ncLink(st, 1, OperUp)
	waitNetconf(t, "every push sent", func() bool { return atomic.LoadUint64(&mgr.netconfNotificationsSent) >= 4*sessions })
	waitNetconf(t, "idle goroutine count after pushes", func() bool { return netconfAppGoroutines() == want })
}

// With no CA in the table the client CA pool must be empty, not nil: a nil
// ClientCAs makes crypto/tls verify client certificates against the system
// roots.
func TestNetconfTLSEmptyTableUsesEmptyClientCAPool(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	setNetconfTLSIdentity(mgr, nil, nil, "fallback")
	base := mgr.netconfTLSConfig()
	if base.ClientAuth != tls.RequireAndVerifyClientCert || base.MinVersion != tls.VersionTLS12 || base.MaxVersion != tls.VersionTLS12 {
		t.Fatalf("base config: ClientAuth %v, versions %x..%x", base.ClientAuth, base.MinVersion, base.MaxVersion)
	}
	c, err := base.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientCAs == nil {
		t.Fatal("no CA gives a nil ClientCAs; crypto/tls would fall back to the system roots")
	}
	if c.ClientAuth != tls.RequireAndVerifyClientCert || c.MinVersion != tls.VersionTLS12 || c.MaxVersion != tls.VersionTLS12 {
		t.Fatalf("per-client config: ClientAuth %v, versions %x..%x", c.ClientAuth, c.MinVersion, c.MaxVersion)
	}

	ca := newNetconfTLSTestCA(t)
	setNetconfTLSIdentity(mgr, ca, nil, "fallback")
	c, err = base.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientCAs == nil || c.ClientCAs != mgr.netconfTLSIdentity.Load().pool() {
		t.Fatal("with a CA set the handshake does not use the table's cached pool")
	}
}

// kill-session from an SSH session ends a TLS session on the same device.
func TestNetconfTLSKillSessionAcrossTransports(t *testing.T) {
	mgr := useNetconfTLSTestManager(t)
	ca := newNetconfTLSTestCA(t)
	cert, fp := ca.client(t, false)
	setNetconfTLSIdentity(mgr, ca, map[string]string{fp: "ncuser"}, "")
	dev, _, tlsAddr := newJunosTLSDevice(t, mgr)
	dev.mu.Lock()
	err := dev.startNetconfServer()
	dev.mu.Unlock()
	if err != nil || dev.netconfListener == nil {
		t.Fatalf("SSH listener beside TLS: %v", err)
	}

	victim, _ := openNetconfOverTLS(t, tlsAddr, &cert, 1, "ncuser")
	killer, _ := openNetconfOverSSH(t, dialNetconfTestSSH(t, dev.netconfListener.Addr().String()))
	r, err := netconfRPCWithin(killer, "k1", "<kill-session><session-id>1</session-id></kill-session>", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if want := string(junosOKReply(junosVersion(dev), "k1")); r != want {
		t.Fatalf("kill reply\n got: %q\nwant: %q", r, want)
	}
	expectNetconfTLSEOF(t, victim)
}
