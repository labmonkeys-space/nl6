/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// withCallHomeTiming shortens the call-home cycle and keepalive for one
// test. Exporters copy the values when they are built.
func withCallHomeTiming(t *testing.T, cycle, keepAlive time.Duration) {
	t.Helper()
	pc, pk := netconfCallHomeCycle, netconfCallHomeKeepAlive
	netconfCallHomeCycle, netconfCallHomeKeepAlive = cycle, keepAlive
	t.Cleanup(func() { netconfCallHomeCycle, netconfCallHomeKeepAlive = pc, pk })
}

func newCallHomeListener(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.(*net.TCPListener)
}

// startCallHome configures and starts call home on dev to client, and stops
// it when the test ends.
func startCallHome(t *testing.T, mgr *SimulatorManager, dev *DeviceSimulator, client, deviceID string) *netconfCallHomeExporter {
	t.Helper()
	dev.netconfCallHomeConfig = &DeviceNetconfCallHomeConfig{Client: client, DeviceID: deviceID}
	if err := mgr.startDeviceNetconfCallHome(dev); err != nil {
		t.Fatalf("startDeviceNetconfCallHome: %v", err)
	}
	dev.mu.RLock()
	e := dev.netconfCallHome
	dev.mu.RUnlock()
	if e == nil {
		t.Fatal("no call-home exporter")
	}
	t.Cleanup(func() {
		dev.mu.Lock()
		dev.stopNetconfCallHome()
		dev.mu.Unlock()
	})
	return e
}

// acceptCallHome waits up to d for the device to dial ln.
func acceptCallHome(t *testing.T, ln *net.TCPListener, d time.Duration) net.Conn {
	t.Helper()
	_ = ln.SetDeadline(time.Now().Add(d))
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("no call-home connection within %s: %v", d, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// noCallHome asserts the device does not dial ln within d.
func noCallHome(t *testing.T, ln *net.TCPListener, d time.Duration) {
	t.Helper()
	_ = ln.SetDeadline(time.Now().Add(d))
	c, err := ln.Accept()
	if err == nil {
		_ = c.Close()
		t.Fatalf("unexpected call-home connection within %s", d)
	}
}

func readPreamble(t *testing.T, c net.Conn, n int) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("preamble: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	return string(b)
}

// callHomeSSH runs the SSH client handshake on a call-home connection whose
// preamble was read, and returns the client and the device host key.
func callHomeSSH(t *testing.T, c net.Conn) (*ssh.Client, ssh.PublicKey) {
	t.Helper()
	var hostKey ssh.PublicKey
	sc, chans, reqs, err := ssh.NewClientConn(c, c.RemoteAddr().String(), &ssh.ClientConfig{
		User: USERNAME,
		Auth: []ssh.AuthMethod{ssh.Password(PASSWORD)},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			hostKey = k
			return nil
		},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh handshake over call home: %v", err)
	}
	client := ssh.NewClient(sc, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client, hostKey
}

// netconfHello opens the netconf subsystem, returns the server hello, and
// sends a base:1.0 client hello.
func netconfHello(t *testing.T, c *ssh.Client) (*netconfFramer, string) {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	if err := s.RequestSubsystem("netconf"); err != nil {
		t.Fatalf("netconf subsystem refused: %v", err)
	}
	f := newNetconfFramer(out, in)
	h, err := f.ReadMessage()
	if err != nil {
		t.Fatalf("server hello: %v", err)
	}
	hello := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>`
	if err := f.WriteMessage([]byte(hello)); err != nil {
		t.Fatal(err)
	}
	return f, string(h)
}

// callHomeSession accepts the next call-home connection and returns a
// NETCONF framer on it after the hello exchange.
func callHomeSession(t *testing.T, ln *net.TCPListener, dev *DeviceSimulator, within time.Duration) (net.Conn, *netconfFramer, string) {
	t.Helper()
	c := acceptCallHome(t, ln, within)
	readPreamble(t, c, len(junosCallHomePreamble(dev.sysName)))
	client, _ := callHomeSSH(t, c)
	f, hello := netconfHello(t, client)
	return c, f, hello
}

func TestNetconfCallHomeConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		cfg  DeviceNetconfCallHomeConfig
		fail bool
	}{
		{DeviceNetconfCallHomeConfig{Client: "192.0.2.10:4334"}, false},
		{DeviceNetconfCallHomeConfig{Client: "nms.example.net:4334", DeviceID: "vj-r1"}, false},
		{DeviceNetconfCallHomeConfig{Client: "[2001:db8::1]:4334"}, false},
		{DeviceNetconfCallHomeConfig{}, true},
		{DeviceNetconfCallHomeConfig{Client: "192.0.2.10"}, true},
		{DeviceNetconfCallHomeConfig{Client: ":4334"}, true},
		{DeviceNetconfCallHomeConfig{Client: "192.0.2.10:0"}, true},
		{DeviceNetconfCallHomeConfig{Client: "192.0.2.10:ssh"}, true},
		{DeviceNetconfCallHomeConfig{Client: "192.0.2.10:4334", DeviceID: "has space"}, true},
		{DeviceNetconfCallHomeConfig{Client: "192.0.2.10:4334", DeviceID: "crlf\r\nMSG-ID: X"}, true},
		{DeviceNetconfCallHomeConfig{Client: "192.0.2.10:4334", DeviceID: strings.Repeat("a", 256)}, true},
	} {
		if err := tc.cfg.Validate(); (err != nil) != tc.fail {
			t.Errorf("Validate(%+v) = %v, want failure %v", tc.cfg, err, tc.fail)
		}
	}
	var nilCfg *DeviceNetconfCallHomeConfig
	if err := nilCfg.Validate(); err != nil {
		t.Errorf("nil Validate = %v", err)
	}
}

func TestNetconfCallHomeSeedFromFlags(t *testing.T) {
	if c, err := netconfCallHomeSeedFromFlags("", "", false, 1); c != nil || err != nil {
		t.Errorf("no client = %+v, %v; want nil, nil", c, err)
	}
	if _, err := netconfCallHomeSeedFromFlags("", "vj-r1", true, 1); err == nil {
		t.Error("device id without client accepted")
	}
	if _, err := netconfCallHomeSeedFromFlags("192.0.2.10:4334", "", false, 1); err == nil || !strings.Contains(err.Error(), "-netconf-enable") {
		t.Errorf("client without -netconf-enable = %v, want an error naming -netconf-enable", err)
	}
	if _, err := netconfCallHomeSeedFromFlags("192.0.2.10", "", true, 1); err == nil {
		t.Error("client without port accepted")
	}
	if _, err := netconfCallHomeSeedFromFlags("192.0.2.10:4334", "vj-r1", true, 5); err == nil {
		t.Error("one device id accepted for an auto-start batch of 5")
	}
	if c, err := netconfCallHomeSeedFromFlags("192.0.2.10:4334", "", true, 5); err != nil || c == nil {
		t.Errorf("batch of 5 without device id = %+v, %v", c, err)
	}
	c, err := netconfCallHomeSeedFromFlags("192.0.2.10:4334", "vj-r1", true, 1)
	if err != nil || c == nil || c.Client != "192.0.2.10:4334" || c.DeviceID != "vj-r1" {
		t.Errorf("valid flags = %+v, %v", c, err)
	}

	// applyExportSeed gives every device its own copy.
	a, b := &DeviceSimulator{}, &DeviceSimulator{}
	seed := &ExportSeed{NetconfCallHome: c}
	applyExportSeed(a, seed)
	applyExportSeed(b, seed)
	if a.netconfCallHomeConfig == nil || a.netconfCallHomeConfig == b.netconfCallHomeConfig || a.netconfCallHomeConfig == c {
		t.Error("devices share the seed's call-home block")
	}
}

func TestCreateDevicesHandlerRejectsBadCallHome(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		block   string
		want    string
	}{
		{"subsystem off", false, `{"client":"192.0.2.10:4334"}`, "-netconf-enable"},
		{"unknown field", true, `{"client":"192.0.2.10:4334","secret":"x"}`, "unknown field"},
		{"bad client", true, `{"client":"192.0.2.10"}`, "host:port"},
		{"device id for a batch", true, `{"client":"192.0.2.10:4334","device_id":"lab"}`, "device_id names one device"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useNetconfTestManager(t, tc.enabled)
			body := `{"start_ip":"10.0.0.1","device_count":3,"netmask":"24","netconf_callhome":` + tc.block + `}`
			w := httptest.NewRecorder()
			createDevicesHandler(w, httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(body)))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("status %d body %s; want 400 naming %q", w.Code, w.Body.String(), tc.want)
			}
		})
	}
}

func TestNetconfCallHomeDialsWithPreambleAndServesJunos(t *testing.T) {
	withCallHomeTiming(t, 100*time.Millisecond, time.Hour)
	mgr := useNetconfTestManager(t, true)
	dev, _, _ := newJunosListenDevice(t, mgr)
	ln := newCallHomeListener(t)
	startCallHome(t, mgr, dev, ln.Addr().String(), "")

	c := acceptCallHome(t, ln, 2*time.Second)
	want := "MSG-ID: DEVICE-CONN-INFO\r\nMSG-VER: V1\r\nDEVICE-ID: NY-CORE-01\r\n\r\n"
	if got := readPreamble(t, c, len(want)); got != want {
		t.Fatalf("preamble = %q, want %q", got, want)
	}
	client, hostKey := callHomeSSH(t, c)
	if !bytes.Equal(hostKey.Marshal(), mgr.sharedSSHSigner.PublicKey().Marshal()) {
		t.Error("call-home host key differs from the listener's shared key")
	}
	_, hello := netconfHello(t, client)
	if !strings.Contains(hello, "<!-- user "+USERNAME+", class j-super-user -->") {
		t.Fatalf("not the Junos hello:\n%s", hello)
	}
}

func TestNetconfCallHomeConfiguredDeviceID(t *testing.T) {
	withCallHomeTiming(t, 100*time.Millisecond, time.Hour)
	mgr := useNetconfTestManager(t, true)
	dev, _, _ := newJunosListenDevice(t, mgr)
	ln := newCallHomeListener(t)
	startCallHome(t, mgr, dev, ln.Addr().String(), "vj-r1")
	c := acceptCallHome(t, ln, 2*time.Second)
	if got := readPreamble(t, c, 59); got != string(junosCallHomePreamble("vj-r1")) {
		t.Fatalf("preamble = %q", got)
	}
}

func TestNetconfCallHomeRefusesShell(t *testing.T) {
	withCallHomeTiming(t, 100*time.Millisecond, time.Hour)
	mgr := useNetconfTestManager(t, true)
	dev, _, _ := newJunosListenDevice(t, mgr)
	ln := newCallHomeListener(t)
	startCallHome(t, mgr, dev, ln.Addr().String(), "")
	c := acceptCallHome(t, ln, 2*time.Second)
	readPreamble(t, c, len(junosCallHomePreamble(dev.sysName)))
	client, _ := callHomeSSH(t, c)
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Shell(); err == nil {
		t.Fatal("shell accepted on a call-home connection")
	}
}

func TestNetconfCallHomeRedial(t *testing.T) {
	cycle := 100 * time.Millisecond
	withCallHomeTiming(t, cycle, time.Hour)
	mgr := useNetconfTestManager(t, true)
	dev, _, _ := newJunosListenDevice(t, mgr)
	ln := newCallHomeListener(t)
	addr := ln.Addr().String()
	e := startCallHome(t, mgr, dev, addr, "")
	within := 3 * cycle

	// close-session ends the session; the device dials again.
	_, f, _ := callHomeSession(t, ln, dev, 2*time.Second)
	if r, err := netconfRPCWithin(f, "1", "<close-session/>", 5*time.Second); err != nil || !strings.Contains(r, "<ok/>") {
		t.Fatalf("close-session: %q %v", r, err)
	}
	// A dropped TCP connection: the device dials again.
	c2, _, _ := callHomeSession(t, ln, dev, within)
	_ = c2.Close()
	// A session that stays up blocks further dials.
	callHomeSession(t, ln, dev, within)
	noCallHome(t, ln, 4*cycle)
	if !e.sessionUp.Load() {
		t.Fatal("session not reported up")
	}

	// Client down: attempts keep failing every cycle, then succeed again.
	_ = ln.Close()
	e.srv.mu.Lock()
	for c := range e.srv.conns {
		_ = c.Close()
	}
	e.srv.mu.Unlock()
	before := e.agg.connectFailures.Load()
	time.Sleep(5 * cycle)
	if n := e.agg.connectFailures.Load() - before; n < 3 {
		t.Fatalf("%d failed attempts in 5 cycles while the client was down, want at least 3", n)
	}
	l2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot rebind %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = l2.Close() })
	acceptCallHome(t, l2.(*net.TCPListener), within)
}

func TestNetconfCallHomeKeepAlive(t *testing.T) {
	ka := 50 * time.Millisecond
	withCallHomeTiming(t, 100*time.Millisecond, ka)
	mgr := useNetconfTestManager(t, true)
	dev, _, _ := newJunosListenDevice(t, mgr)
	ln := newCallHomeListener(t)
	e := startCallHome(t, mgr, dev, ln.Addr().String(), "")

	// A client that answers keepalives keeps the session over 8 intervals.
	c, f, _ := callHomeSession(t, ln, dev, 2*time.Second)
	time.Sleep(8 * ka)
	if r, err := netconfRPCWithin(f, "1", "<get/>", 5*time.Second); err != nil || !strings.Contains(r, "<rpc-reply") {
		t.Fatalf("session died with an answering client: %q %v", r, err)
	}
	if n := e.agg.sessionsEnded.Load(); n != 0 {
		t.Fatalf("%d sessions ended with an answering client", n)
	}
	_ = c.Close()

	// A client that completes SSH and then never reads gets closed after 3
	// missed keepalives.
	c2 := acceptCallHome(t, ln, 2*time.Second)
	readPreamble(t, c2, len(junosCallHomePreamble(dev.sysName)))
	if _, _, _, err := ssh.NewClientConn(c2, "", &ssh.ClientConfig{
		User:            USERNAME,
		Auth:            []ssh.AuthMethod{ssh.Password(PASSWORD)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client
	}); err != nil {
		t.Fatal(err)
	}
	ended := e.agg.sessionsEnded.Load()
	waitNetconf(t, "the unresponsive session to close", func() bool { return e.agg.sessionsEnded.Load() > ended })
}

func TestNetconfCallHomeSessionParity(t *testing.T) {
	withCallHomeTiming(t, 100*time.Millisecond, time.Hour)
	mgr := useNetconfTestManager(t, true)
	dev, st, listenAddr := newJunosListenDevice(t, mgr)
	ln := newCallHomeListener(t)
	startCallHome(t, mgr, dev, ln.Addr().String(), "")

	chConn, chF, chHello := callHomeSession(t, ln, dev, 2*time.Second)
	lsF, lsHello := netconfHello(t, dialNetconfTestSSH(t, listenAddr))
	sid := regexp.MustCompile(`<session-id>\d+</session-id>`)
	if sid.ReplaceAllString(chHello, "") != sid.ReplaceAllString(lsHello, "") {
		t.Fatalf("hellos differ beyond session-id\ncall home: %s\nlistener:  %s", chHello, lsHello)
	}

	for _, f := range []*netconfFramer{chF, lsF} {
		if r, err := netconfRPCWithin(f, "1", `<create-subscription xmlns="`+junosNotificationNS+`"/>`, 5*time.Second); err != nil || !strings.Contains(r, "<ok/>") {
			t.Fatalf("create-subscription: %q %v", r, err)
		}
	}
	ncLink(st, 1, OperDown)
	for name, f := range map[string]*netconfFramer{"call home": chF, "listener": lsF} {
		for i, want := range []string{"<state-system-syslog>", "<junos>"} {
			m, err := f.ReadMessage()
			if err != nil || !strings.Contains(string(m), want) || !strings.Contains(string(m), "ifName xe-0/0/0") {
				t.Fatalf("%s notification %d: %v\n%s", name, i, err, m)
			}
		}
	}

	// kill-session from the listener ends the call-home session.
	id := strings.TrimSuffix(strings.TrimPrefix(sid.FindString(chHello), "<session-id>"), "</session-id>")
	if r, err := netconfRPCWithin(lsF, "2", "<kill-session><session-id>"+id+"</session-id></kill-session>", 5*time.Second); err != nil || !strings.Contains(r, "<ok/>") {
		t.Fatalf("kill-session: %q %v", r, err)
	}
	_ = chConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(chConn); err != nil && !errors.Is(err, net.ErrClosed) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("call-home connection still open after kill-session")
		}
	}
}

func TestNetconfCallHomeStopsOnDeviceStop(t *testing.T) {
	cycle := 100 * time.Millisecond
	withCallHomeTiming(t, cycle, time.Hour)
	mgr := useNetconfTestManager(t, true)
	dev, _, _ := newJunosListenDevice(t, mgr)
	ln := newCallHomeListener(t)
	startCallHome(t, mgr, dev, ln.Addr().String(), "")
	c, _, _ := callHomeSession(t, ln, dev, 2*time.Second)

	dev.mu.Lock()
	dev.stopNetconfServer()
	dev.mu.Unlock()
	if dev.netconfCallHome != nil {
		t.Fatal("exporter still set after stop")
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("call-home connection still open after stop")
		}
	}
	noCallHome(t, ln, 4*cycle)
}

func TestNetconfCallHomeUnsupportedAndDisabled(t *testing.T) {
	mgr := useNetconfTestManager(t, true)
	cat, _, _ := newNetconfListenDevice(t, mgr)
	cat.netconfCallHomeConfig = &DeviceNetconfCallHomeConfig{Client: "127.0.0.1:4334"}
	if err := mgr.startDeviceNetconfCallHome(cat); err != nil {
		t.Fatalf("unsupported profile: %v", err)
	}
	if cat.netconfCallHome != nil || cat.netconfCallHomeConfig != nil {
		t.Fatal("catalyst 9500 got call home")
	}
	st := mgr.GetNetconfCallHomeStatus()
	if len(st.Clients) != 1 || st.Clients[0].DevicesUnsupported != 1 || st.Clients[0].Devices != 0 {
		t.Fatalf("status = %+v, want one unsupported device", st)
	}

	off := useNetconfTestManager(t, false)
	mx := newJunosTestDevice(t)
	mx.resourceFile = "juniper_mx10004.json"
	mx.netconfCallHomeConfig = &DeviceNetconfCallHomeConfig{Client: "127.0.0.1:4334"}
	if err := off.startDeviceNetconfCallHome(mx); err == nil {
		t.Fatal("call home started with the NETCONF subsystem off")
	}
}

func TestNetconfCallHomeStatus(t *testing.T) {
	withCallHomeTiming(t, 100*time.Millisecond, time.Hour)
	mgr := useNetconfTestManager(t, true)
	dev, _, _ := newJunosListenDevice(t, mgr)
	ln := newCallHomeListener(t)
	client := ln.Addr().String()
	e := startCallHome(t, mgr, dev, client, "")
	callHomeSession(t, ln, dev, 2*time.Second)
	waitNetconf(t, "session up", e.sessionUp.Load)

	get := func() NetconfCallHomeClientStatus {
		t.Helper()
		w := httptest.NewRecorder()
		netconfCallHomeStatusHandler(w, httptest.NewRequest(http.MethodGet, "/api/v1/netconf/callhome/status", nil))
		var st NetconfCallHomeStatus
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		if !st.SubsystemActive || len(st.Clients) != 1 || st.Clients[0].Client != client {
			t.Fatalf("status = %s", w.Body.String())
		}
		return st.Clients[0]
	}
	live := get()
	if live.Devices != 1 || live.SessionsUp != 1 || live.ConnectAttempts < 1 {
		t.Fatalf("live status = %+v", live)
	}

	dev.mu.Lock()
	dev.stopNetconfServer()
	dev.mu.Unlock()
	after := get()
	if after.Devices != 0 || after.SessionsUp != 0 || after.ConnectAttempts < live.ConnectAttempts || after.SessionsEnded < 1 {
		t.Fatalf("status after stop = %+v, live was %+v", after, live)
	}
}

func TestNetconfCallHomePhaseSpread(t *testing.T) {
	cycle := 15 * time.Second
	const n, buckets = 1000, 10
	var count [buckets]int
	for i := 0; i < n; i++ {
		p := netconfCallHomePhase(cycle)
		if p < 0 || p >= cycle {
			t.Fatalf("phase %s outside [0, %s)", p, cycle)
		}
		count[int(p*buckets/cycle)]++
	}
	// Uniform gives 100 per 1.5 s bucket; 150 is five standard deviations.
	for i, c := range count {
		if c > n*15/100 {
			t.Errorf("bucket %d holds %d of %d phases", i, c, n)
		}
	}
}

func TestNetconfCallHomeDefaultIDFromSysName(t *testing.T) {
	for in, want := range map[string]string{
		"NY-CORE-01":        "NY-CORE-01",
		"core 01":           "core-01",
		"evil\r\nMSG-ID: X": "evil--MSG-ID:-X",
		"r\u00e9seau":       "r--seau",
	} {
		if got := netconfCallHomeDefaultID(in); got != want {
			t.Errorf("netconfCallHomeDefaultID(%q) = %q, want %q", in, got, want)
		}
		cfg := DeviceNetconfCallHomeConfig{Client: "192.0.2.10:4334", DeviceID: netconfCallHomeDefaultID(in)}
		if err := cfg.Validate(); err != nil {
			t.Errorf("sanitised %q fails Validate: %v", in, err)
		}
	}
	if got := netconfCallHomeDefaultID(strings.Repeat("a", 300)); len(got) != netconfCallHomeMaxDeviceID {
		t.Errorf("long sysName gives %d bytes, want %d", len(got), netconfCallHomeMaxDeviceID)
	}
}
