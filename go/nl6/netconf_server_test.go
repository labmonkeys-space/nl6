/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// netconfTestIdleProbe stands in for the 5-minute SSH idle deadline so the
// idle test runs in well under a second.
var netconfTestIdleProbe = 300 * time.Millisecond

func newNetconfTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// useNetconfTestManager installs a manager as the package global, with the
// NETCONF subsystem started when enabled is true.
func useNetconfTestManager(t *testing.T, enabled bool) *SimulatorManager {
	t.Helper()
	mgr := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
		sharedSSHSigner: newNetconfTestSigner(t),
	}
	if err := mgr.StartNetconfSubsystem(NetconfSubsystemConfig{Enabled: enabled}); err != nil {
		t.Fatalf("StartNetconfSubsystem: %v", err)
	}
	// Port 0 binds a free port, so tests never need the real 830.
	mgr.netconfPort = 0
	prev := manager
	manager = mgr
	t.Cleanup(func() { manager = prev })
	return mgr
}

// newNetconfListenDevice builds a catalyst 9500 on 127.0.0.1, registers it
// with mgr and starts its NETCONF listener on a free port.
func newNetconfListenDevice(t *testing.T, mgr *SimulatorManager) (*DeviceSimulator, *InterfaceState, string) {
	t.Helper()
	dev, st := newNetconfTestDevice(t)
	dev.ID = "cat9500-test"
	dev.IP = net.IPv4(127, 0, 0, 1)
	dev.resourceFile = "cisco_catalyst_9500.json"
	mgr.devices[dev.ID] = dev
	dev.mu.Lock()
	err := dev.startNetconfServer()
	dev.mu.Unlock()
	if err != nil {
		t.Fatalf("startNetconfServer: %v", err)
	}
	if dev.netconfListener == nil {
		t.Fatal("catalyst 9500 has no NETCONF listener")
	}
	t.Cleanup(func() {
		dev.mu.Lock()
		dev.stopNetconfServer()
		dev.mu.Unlock()
	})
	return dev, st, dev.netconfListener.Addr().String()
}

func dialNetconfTestSSH(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            USERNAME,
		Auth:            []ssh.AuthMethod{ssh.Password(PASSWORD)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test server
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// openNetconfOverSSH opens the netconf subsystem and completes the hello.
func openNetconfOverSSH(t *testing.T, c *ssh.Client) (*netconfFramer, *ssh.Session) {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	in, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	if err := s.RequestSubsystem("netconf"); err != nil {
		t.Fatalf("netconf subsystem refused: %v", err)
	}
	f := newNetconfFramer(out, in)
	h, err := f.ReadMessage()
	if err != nil || !strings.Contains(string(h), "<session-id>") {
		t.Fatalf("server hello: %q %v", h, err)
	}
	hello := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>`
	if err := f.WriteMessage([]byte(hello)); err != nil {
		t.Fatalf("client hello: %v", err)
	}
	return f, s
}

// netconfRPCWithin sends op and waits up to d for a reply.
func netconfRPCWithin(f *netconfFramer, id, op string, d time.Duration) (string, error) {
	msg := `<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="` + id + `">` + op + `</rpc>`
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		if err := f.WriteMessage([]byte(msg)); err != nil {
			ch <- res{nil, err}
			return
		}
		b, err := f.ReadMessage()
		ch <- res{b, err}
	}()
	select {
	case r := <-ch:
		return string(r.b), r.err
	case <-time.After(d):
		return "", io.ErrNoProgress
	}
}

func netconfStateListeners(st *InterfaceState) int {
	n := 0
	st.listeners.Range(func(_, _ any) bool { n++; return true })
	return n
}

func waitNetconf(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNetconfListenerOnlyOnCatalyst9500(t *testing.T) {
	mgr := useNetconfTestManager(t, true)
	_, _, addr := newNetconfListenDevice(t, mgr)
	c := dialNetconfTestSSH(t, addr)
	f, _ := openNetconfOverSSH(t, c)
	if r, err := netconfRPCWithin(f, "m1", "<get/>", 5*time.Second); err != nil || !strings.Contains(r, `message-id="m1"`) {
		t.Fatalf("rpc over the listener: %q %v", r, err)
	}

	other, _ := newNetconfTestDevice(t)
	other.ID, other.IP, other.resourceFile = "asr9k-test", net.IPv4(127, 0, 0, 1), "asr9k.json"
	other.mu.Lock()
	err := other.startNetconfServer()
	other.mu.Unlock()
	if err != nil {
		t.Fatalf("startNetconfServer on another type must be a no-op, got %v", err)
	}
	if other.netconfListener != nil || other.netconfSessions != nil {
		t.Fatal("a non catalyst 9500 device got a NETCONF listener")
	}
}

func TestNetconfRejectsShellAndExec(t *testing.T) {
	mgr := useNetconfTestManager(t, true)
	_, _, addr := newNetconfListenDevice(t, mgr)
	c := dialNetconfTestSSH(t, addr)

	for name, req := range map[string]func(*ssh.Session) error{
		"shell":     func(s *ssh.Session) error { return s.Shell() },
		"exec":      func(s *ssh.Session) error { return s.Start("show version") },
		"sftp":      func(s *ssh.Session) error { return s.RequestSubsystem("sftp") },
		"pty-req":   func(s *ssh.Session) error { return s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}) },
		"netconfX":  func(s *ssh.Session) error { return s.RequestSubsystem("netconfX") },
		"empty-sub": func(s *ssh.Session) error { return s.RequestSubsystem("") },
	} {
		s, err := c.NewSession()
		if err != nil {
			t.Fatalf("%s: new session: %v", name, err)
		}
		if err := req(s); err == nil {
			t.Errorf("%s request accepted on the NETCONF port", name)
		}
		_ = s.Close()
	}
	if ch, _, err := c.OpenChannel("direct-tcpip", nil); err == nil {
		_ = ch.Close()
		t.Error("non-session channel accepted")
	}
	// The connection still serves NETCONF after the refusals.
	f, _ := openNetconfOverSSH(t, c)
	if _, err := netconfRPCWithin(f, "m1", "<get/>", 5*time.Second); err != nil {
		t.Fatalf("netconf after refusals: %v", err)
	}
}

func TestNetconfSessionOutlivesSSHIdleDeadline(t *testing.T) {
	sshIdleTimeoutOverride.Store(int64(netconfTestIdleProbe))
	defer sshIdleTimeoutOverride.Store(0)

	mgr := useNetconfTestManager(t, true)
	dev, _, addr := newNetconfListenDevice(t, mgr)

	// Port 22 on the same device, with the same (shortened) idle deadline.
	ssh22 := &SSHServer{device: &DeviceSimulator{ID: dev.ID, IP: dev.IP}, signer: mgr.sharedSSHSigner}
	if err := ssh22.Start(); err != nil {
		t.Fatalf("ssh start: %v", err)
	}
	t.Cleanup(func() { _ = ssh22.Stop() })
	shellClient := dialNetconfTestSSH(t, ssh22.listener.Addr().String())
	shell, err := shellClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	shellOut, _ := shell.StdoutPipe()
	if err := shell.Shell(); err != nil {
		t.Fatalf("port 22 shell: %v", err)
	}

	f, _ := openNetconfOverSSH(t, dialNetconfTestSSH(t, addr))
	time.Sleep(3 * netconfTestIdleProbe)

	// Control: the port-22 connection is gone, so the probe has teeth.
	shellDead := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, shellOut); close(shellDead) }()
	select {
	case <-shellDead:
	case <-time.After(5 * time.Second):
		t.Fatal("port 22 shell outlived the idle deadline; the probe proves nothing")
	}

	r, err := netconfRPCWithin(f, "m1", "<get/>", 5*time.Second)
	if err != nil || !strings.Contains(r, `message-id="m1"`) {
		t.Fatalf("NETCONF session died at the SSH idle deadline: %q %v", r, err)
	}
}

func TestNetconfDeviceStopClosesSessions(t *testing.T) {
	for name, stop := range map[string]func(*DeviceSimulator){
		"Stop":              func(d *DeviceSimulator) { _ = d.Stop() },
		"stopListenersOnly": func(d *DeviceSimulator) { d.stopListenersOnly() },
	} {
		t.Run(name, func(t *testing.T) {
			mgr := useNetconfTestManager(t, true)
			dev, st, addr := newNetconfListenDevice(t, mgr)
			dev.running = true
			c := dialNetconfTestSSH(t, addr)
			f, _ := openNetconfOverSSH(t, c)
			if _, err := netconfRPCWithin(f, "m1", "<get/>", 5*time.Second); err != nil {
				t.Fatal(err)
			}
			if n := netconfStateListeners(st); n != 1 {
				t.Fatalf("state listeners before stop = %d, want 1", n)
			}

			stop(dev)

			if _, err := netconfRPCWithin(f, "m2", "<get/>", 5*time.Second); err == nil {
				t.Fatal("session still answers after the device stopped")
			}
			waitNetconf(t, "state listener removal", func() bool { return netconfStateListeners(st) == 0 })
			dev.mu.RLock()
			l, reg := dev.netconfListener, dev.netconfSessions
			dev.mu.RUnlock()
			if l != nil || reg != nil {
				t.Fatal("device keeps NETCONF state after stop")
			}
			if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
				_ = conn.Close()
				t.Fatal("NETCONF port still accepts after stop")
			}
		})
	}
}

func TestNetconfStatusEndpoint(t *testing.T) {
	mgr := useNetconfTestManager(t, true)
	_, _, addr := newNetconfListenDevice(t, mgr)
	f, _ := openNetconfOverSSH(t, dialNetconfTestSSH(t, addr))
	r, err := netconfRPCWithin(f, "m1", netconfTestSub(netconfTestOperXPath), 5*time.Second)
	if err != nil || !ncSubIDRe.MatchString(r) {
		t.Fatalf("subscribe: %q %v", r, err)
	}

	rec := httptest.NewRecorder()
	netconfStatusHandler(rec, httptest.NewRequest("GET", "/api/v1/netconf/status", nil))
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"subsystem_active": true,
		"listeners":        float64(1),
		"sessions":         float64(1),
		"subscriptions":    float64(1),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (body %s)", k, got[k], v, rec.Body)
		}
	}
	for _, k := range []string{"notifications_sent", "notifications_dropped"} {
		if _, ok := got[k]; !ok {
			t.Errorf("status lacks %s", k)
		}
	}
	if len(got) != 9 {
		t.Errorf("status has %d keys, want 9: %s", len(got), rec.Body)
	}
}

func TestNetconfDisabledByDefault(t *testing.T) {
	mgr := useNetconfTestManager(t, false)
	if mgr.netconfSubsystemActive.Load() {
		t.Fatal("zero config activated the subsystem")
	}
	dev, _ := newNetconfTestDevice(t)
	dev.ID, dev.IP, dev.resourceFile = "cat", net.IPv4(127, 0, 0, 1), "cisco_catalyst_9500.json"
	mgr.devices[dev.ID] = dev
	dev.mu.Lock()
	err := dev.startNetconfServer()
	dev.mu.Unlock()
	if err != nil || dev.netconfListener != nil {
		t.Fatalf("disabled subsystem started a listener (err %v)", err)
	}
	st := mgr.GetNetconfStatus()
	if st.SubsystemActive || st.Listeners != 0 {
		t.Fatalf("status %+v, want inactive with no listeners", st)
	}

	// Enabling: port 0 means 830, the range is checked, a second start fails.
	en := &SimulatorManager{}
	if err := en.StartNetconfSubsystem(NetconfSubsystemConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if en.netconfPort != 830 {
		t.Fatalf("default port %d, want 830", en.netconfPort)
	}
	if err := en.StartNetconfSubsystem(NetconfSubsystemConfig{Enabled: true}); err == nil {
		t.Fatal("second start accepted")
	}
	if err := (&SimulatorManager{}).StartNetconfSubsystem(NetconfSubsystemConfig{Enabled: true, Port: 65536}); err == nil {
		t.Fatal("port 65536 accepted")
	}
}

func TestNetconfSSHPort22Unchanged(t *testing.T) {
	signer := newNetconfTestSigner(t)
	dev := &DeviceSimulator{ID: "dev-22", IP: net.IPv4(127, 0, 0, 1)}
	srv := &SSHServer{device: dev, signer: signer}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	c := dialNetconfTestSSH(t, srv.listener.Addr().String())

	// Port 22 does not serve NETCONF.
	ns, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := ns.RequestSubsystem("netconf"); err == nil {
		t.Fatal("port 22 accepted the netconf subsystem")
	}
	_ = ns.Close()

	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := s.StdoutPipe()
	if err := s.Shell(); err != nil {
		t.Fatalf("port 22 refused shell: %v", err)
	}
	want := "\r\nWelcome to dev-22\r\nDevice Simulator SSH Server\r\n\r\n"
	buf := make([]byte, len(want))
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(out, buf); done <- err }()
	select {
	case err := <-done:
		if err != nil || string(buf) != want {
			t.Fatalf("welcome %q %v, want %q", buf, err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no welcome on port 22")
	}
}

// waitSSHClosed reports whether the server closed c's connection within d.
func waitSSHClosed(c *ssh.Client, d time.Duration) bool {
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func TestNetconfSessionEndClosesConnection(t *testing.T) {
	mgr := useNetconfTestManager(t, true)
	_, _, addr := newNetconfListenDevice(t, mgr)

	// Session ids are per device and start at 1, so the victim opened
	// first is session 1.
	victim := dialNetconfTestSSH(t, addr)
	openNetconfOverSSH(t, victim)
	killer := dialNetconfTestSSH(t, addr)
	fk, _ := openNetconfOverSSH(t, killer)
	r, err := netconfRPCWithin(fk, "m1", "<kill-session><session-id>1</session-id></kill-session>", 5*time.Second)
	if err != nil || !strings.Contains(r, "<ok/>") {
		t.Fatalf("kill-session: %q %v", r, err)
	}
	if !waitSSHClosed(victim, 5*time.Second) {
		t.Fatal("killed session left its SSH connection open")
	}

	r, err = netconfRPCWithin(fk, "m2", "<close-session/>", 5*time.Second)
	if err != nil || !strings.Contains(r, "<ok/>") {
		t.Fatalf("close-session: %q %v", r, err)
	}
	if !waitSSHClosed(killer, 5*time.Second) {
		t.Fatal("close-session left the SSH connection open")
	}
}

// An authenticated connection that never starts the netconf subsystem is
// closed at the SSH idle deadline, with or without an open session channel.
func TestNetconfDeadlineUntilSubsystem(t *testing.T) {
	sshIdleTimeoutOverride.Store(int64(netconfTestIdleProbe))
	defer sshIdleTimeoutOverride.Store(0)

	mgr := useNetconfTestManager(t, true)
	_, _, addr := newNetconfListenDevice(t, mgr)
	idle := dialNetconfTestSSH(t, addr)
	pending := dialNetconfTestSSH(t, addr)
	if _, err := pending.NewSession(); err != nil {
		t.Fatal(err)
	}
	// Well below netconfSubsystemWait, so only the deadline can close them.
	for name, c := range map[string]*ssh.Client{"no channel": idle, "channel without subsystem": pending} {
		if !waitSSHClosed(c, 10*netconfTestIdleProbe) {
			t.Errorf("%s: connection outlived the SSH idle deadline", name)
		}
	}
}

// netconfAppGoroutines counts the goroutines running nl6 NETCONF server or
// session code, the accept loop aside. The x/crypto/ssh goroutines are not
// counted: the client half runs in this process too and shares their code.
func netconfAppGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, ".(*netconfServer).acceptLoop(") {
			continue
		}
		if strings.Contains(g, ".(*netconfServer).") || strings.Contains(g, ".(*netconfSession).") ||
			strings.Contains(g, ".(*netconfDispatcher).") {
			count++
		}
	}
	return count
}

// An idle subscribed session costs two nl6 goroutines, the connection's
// dispatch loop and the session reader, plus one state-change dispatcher per
// device shared by every session. A push starts a writer that exits once the
// queue is empty.
func TestNetconfIdleSessionGoroutines(t *testing.T) {
	const sessions, perSession, perDevice = 5, 2, 1
	mgr := useNetconfTestManager(t, true)
	_, st, addr := newNetconfListenDevice(t, mgr)
	base := netconfAppGoroutines()
	for i := 0; i < sessions; i++ {
		f, _ := openNetconfOverSSH(t, dialNetconfTestSSH(t, addr))
		if r, err := netconfRPCWithin(f, "m1", netconfTestSub(iosxeTestIfaceNm+"/oper-status"), 5*time.Second); err != nil || !ncSubIDRe.MatchString(r) {
			t.Fatalf("subscribe %d: %q %v", i, r, err)
		}
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

	// Every session gets a push. Its writer must not outlive the queue.
	ncLink(st, 24, OperDown)
	ncLink(st, 24, OperUp)
	waitNetconf(t, "every push sent", func() bool { return atomic.LoadUint64(&mgr.netconfNotificationsSent) >= 2*sessions })
	waitNetconf(t, "idle goroutine count after pushes", func() bool { return netconfAppGoroutines() == want })
}

// A client opens channel A, then B, which replaces A before A asked for the
// subsystem, and keeps sending requests on A. The SSH mux blocks on a full
// request stream, so A's stream must be drained after it is dropped, or
// server Close never returns.
func TestNetconfDroppedPendingChannelDoesNotStallClose(t *testing.T) {
	mgr := useNetconfTestManager(t, true)
	dev, _, addr := newNetconfListenDevice(t, mgr)
	c := dialNetconfTestSSH(t, addr)
	a, _, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _, _ = c.OpenChannel("session", nil) }()
	env := ssh.Marshal(struct{ Name, Value string }{"x", "y"})
	for i := 0; i < 200; i++ {
		if _, err := a.SendRequest("env", false, env); err != nil {
			break
		}
	}
	time.Sleep(500 * time.Millisecond)
	_ = c.Close()

	// Detach the server first, so the cleanup does not call Close again
	// and a hang fails here, not at the -timeout.
	dev.mu.Lock()
	srv := dev.netconfListener
	dev.netconfListener, dev.netconfSessions = nil, nil
	dev.mu.Unlock()
	done := make(chan struct{})
	go func() { _ = srv.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server Close hung: a dropped channel's requests stalled the SSH mux")
	}
}

// TestNetconfPortCheckedWhenDisabled: a bad -netconf-port fails startup even
// when -netconf-enable is not set.
func TestNetconfPortCheckedWhenDisabled(t *testing.T) {
	for _, port := range []int{-1, 65536} {
		sm := &SimulatorManager{}
		if err := sm.StartNetconfSubsystem(NetconfSubsystemConfig{Port: port}); err == nil {
			t.Errorf("disabled subsystem accepted port %d", port)
		}
		if sm.netconfSubsystemActive.Load() {
			t.Errorf("port %d activated the subsystem", port)
		}
	}
	if err := (&SimulatorManager{}).StartNetconfSubsystem(NetconfSubsystemConfig{}); err != nil {
		t.Fatalf("zero config refused: %v", err)
	}
}

// newJunosListenDevice builds a juniper_mx10004 on 127.0.0.1, registers it
// with mgr and starts its NETCONF listener on a free port.
func newJunosListenDevice(t *testing.T, mgr *SimulatorManager) (*DeviceSimulator, *InterfaceState, string) {
	t.Helper()
	dev := newJunosTestDevice(t)
	dev.ID = "mx10004-test"
	dev.IP = net.IPv4(127, 0, 0, 1)
	dev.resourceFile = "juniper_mx10004.json"
	dev.sysName = "NY-CORE-01"
	mgr.devices[dev.ID] = dev
	dev.mu.Lock()
	err := dev.startNetconfServer()
	dev.mu.Unlock()
	if err != nil {
		t.Fatalf("startNetconfServer: %v", err)
	}
	if dev.netconfListener == nil {
		t.Fatal("mx10004 has no NETCONF listener")
	}
	t.Cleanup(func() {
		dev.mu.Lock()
		dev.stopNetconfServer()
		dev.mu.Unlock()
	})
	return dev, netconfIfCounters(dev).State(), dev.netconfListener.Addr().String()
}

func TestNetconfSSHServesJunosProfile(t *testing.T) {
	mgr := useNetconfTestManager(t, true)
	_, st, addr := newJunosListenDevice(t, mgr)
	c := dialNetconfTestSSH(t, addr)
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
		t.Fatal(err)
	}
	if !strings.Contains(string(h), "<!-- user "+USERNAME+", class j-super-user -->") {
		t.Fatalf("not the Junos hello for %s:\n%s", USERNAME, h)
	}
	hello := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>`
	if err := f.WriteMessage([]byte(hello)); err != nil {
		t.Fatal(err)
	}
	r, err := netconfRPCWithin(f, "1", `<create-subscription xmlns="`+junosNotificationNS+`"/>`, 5*time.Second)
	if err != nil || !strings.Contains(r, "<ok/>") {
		t.Fatalf("create-subscription: %q %v", r, err)
	}
	ncLink(st, 1, OperDown)
	for i, want := range []string{"<state-system-syslog>", "<junos>"} {
		m, err := f.ReadMessage()
		if err != nil {
			t.Fatalf("notification %d: %v", i, err)
		}
		if !strings.Contains(string(m), want) || !strings.Contains(string(m), "ifName xe-0/0/0") {
			t.Fatalf("notification %d lacks %s or xe-0/0/0:\n%s", i, want, m)
		}
	}
}

func TestNetconfSSHStillRefusesOtherProfiles(t *testing.T) {
	useNetconfTestManager(t, true)
	other := newJunosTestDevice(t)
	other.ID, other.IP, other.resourceFile = "mx960-test", net.IPv4(127, 0, 0, 1), "juniper_mx960.json"
	other.mu.Lock()
	err := other.startNetconfServer()
	other.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if other.netconfListener != nil || other.netconfSessions != nil {
		t.Fatal("juniper_mx960 got a NETCONF listener")
	}
}

func TestNetconfStatusCountsTransports(t *testing.T) {
	mgr := useNetconfTestManager(t, true)
	_, _, addr := newJunosListenDevice(t, mgr)
	f, _ := openNetconfOverSSH(t, dialNetconfTestSSH(t, addr))
	if r, err := netconfRPCWithin(f, "1", `<create-subscription xmlns="`+junosNotificationNS+`"/>`, 5*time.Second); err != nil || !strings.Contains(r, "<ok/>") {
		t.Fatalf("create-subscription: %q %v", r, err)
	}
	st := mgr.GetNetconfStatus()
	if st.Listeners != 1 || st.Sessions != 1 || st.SessionsTLS != 0 || st.ListenersTLS != 0 || st.TLSHandshakeFailures != 0 {
		t.Fatalf("status = %+v", st)
	}
	if st.Subscriptions != 1 {
		t.Fatalf("subscriptions = %d, want 1", st.Subscriptions)
	}
}

func TestNetconfSubsystemRefusesSamePorts(t *testing.T) {
	sm := &SimulatorManager{}
	err := sm.StartNetconfSubsystem(NetconfSubsystemConfig{Enabled: true, Port: 7000, TLSPort: 7000})
	if err == nil || !strings.Contains(err.Error(), "-netconf-port") || !strings.Contains(err.Error(), "-netconf-tls-port") {
		t.Fatalf("same ports error = %v", err)
	}
	if sm.netconfSubsystemActive.Load() {
		t.Error("subsystem active after a refused start")
	}
}
