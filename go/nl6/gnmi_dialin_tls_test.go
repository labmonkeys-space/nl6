/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Tests for the gNMI dial-in transport mode and its observability
// counters (nl6#663).
//
// These tests drive the REAL `startGnmiServer` rather than the inline
// mirror in `startTestGnmiServer`. That is deliberate and load-bearing:
// the defect this file pins is *in* `startGnmiServer`'s credentials
// wiring, and a test that rebuilds that wiring by hand pins its own
// copy, not the production path. `startGnmiServer` binds `d.IP:port`,
// so each test overrides `dev.IP` to loopback and passes port 0, then
// reads the bound address back off `dev.gnmiListener`.
//
// They mutate the package-level `manager` global and therefore cannot
// use `t.Parallel()`, same constraint as gnmi_server_test.go.

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// http2ClientPreface is the exact byte sequence every gRPC client opens
// a connection with (RFC 7540 §3.5 preface + an empty SETTINGS frame).
// Against a TLS listener it is a malformed ClientHello, which is the
// whole of nl6#663.
var http2ClientPreface = append(
	[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
)

// startRealGnmiServer wires a per-test manager + device and starts the
// device's gNMI listener through the production `startGnmiServer`.
// `tlsEnabled` selects the transport; `withCert` controls whether the
// manager has a shared TLS certificate at all.
func startRealGnmiServer(t *testing.T, tlsEnabled, withCert bool) (mgr *SimulatorManager, dev *DeviceSimulator, addr string) {
	t.Helper()

	mgr = &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
	}
	if withCert {
		mgr.sharedTLSCert = generateTestTLSCert(t)
	}
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{
		Port:       gnmiDefaultPort,
		Disabled:   false,
		TLSEnabled: tlsEnabled,
	}); err != nil {
		t.Fatalf("StartGnmiSubsystem: %v", err)
	}

	prev := manager
	manager = mgr
	t.Cleanup(func() { manager = prev })

	dev = newTestGnmiDevice(t, 2)
	dev.IP = net.IPv4(127, 0, 0, 1) // startGnmiServer binds d.IP
	mgr.devices["test"] = dev

	dev.mu.Lock()
	err := dev.startGnmiServer(0) // port 0 → ephemeral
	dev.mu.Unlock()
	if err != nil {
		t.Fatalf("startGnmiServer: %v", err)
	}
	t.Cleanup(func() {
		dev.mu.Lock()
		dev.stopGnmiServer()
		dev.mu.Unlock()
	})

	return mgr, dev, dev.gnmiListener.Addr().String()
}

// sendPlaintextPreface opens a raw TCP connection, writes the HTTP/2
// client preface without TLS, and reports how many bytes came back.
func sendPlaintextPreface(t *testing.T, addr string) (int, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write(http2ClientPreface); err != nil {
		return 0, err
	}
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	n, rerr := c.Read(buf)
	return n, rerr
}

// TestGnmiDialinTLSRejectsPlaintextClient reproduces nl6#663: a
// plaintext client gets a completed TCP connection and zero bytes back.
// The TLS control on the SAME listener is what makes it a diagnosis
// rather than an observation — it proves the gRPC service is registered
// and serving, so the difference is entirely the client's transport.
// Without the control this test is equally satisfied by a listener with
// no service behind it, which is precisely the conclusion the issue
// reporter drew.
func TestGnmiDialinTLSRejectsPlaintextClient(t *testing.T) {
	_, _, addr := startRealGnmiServer(t, true, true)

	n, rerr := sendPlaintextPreface(t, addr)
	if n != 0 {
		t.Fatalf("plaintext preface against TLS listener: got %d bytes back, want 0", n)
	}
	t.Logf("plaintext preface: bytes_back=%d err=%v (nl6#663 symptom)", n, rerr)

	// Control: the same listener completes a TLS handshake and answers gNMI.
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := gnmipb.NewGNMIClient(conn).Capabilities(ctx, &gnmipb.CapabilityRequest{}); err != nil {
		t.Fatalf("TLS control: Capabilities failed, so the listener is not serving gNMI at all: %v", err)
	}
}

// TestGnmiTLSHandshakeFailureIncrementsCounter pins the counter to the
// event its name claims. Before nl6#663 this counted `Accept` errors,
// and gRPC runs the TLS handshake AFTER `Accept` returns — so a failed
// handshake left it at 0 while docs told operators to read it as
// exactly this signal.
func TestGnmiTLSHandshakeFailureIncrementsCounter(t *testing.T) {
	mgr, _, addr := startRealGnmiServer(t, true, true)

	if got := atomic.LoadUint64(&mgr.gnmiTLSHandshakeFailures); got != 0 {
		t.Fatalf("precondition: handshake failures = %d, want 0", got)
	}
	if _, err := sendPlaintextPreface(t, addr); err == nil {
		t.Log("plaintext read returned no error; connection still expected to have failed the handshake")
	}

	waitForCounter(t, &mgr.gnmiTLSHandshakeFailures, 1)

	if got := atomic.LoadUint64(&mgr.gnmiListenerAcceptFailures); got != 0 {
		t.Errorf("listener_accept_failures = %d after a handshake failure, want 0: "+
			"a failed handshake is not an Accept error", got)
	}
}

// TestGnmiSuccessfulHandshakeDoesNotCount is the negative control for
// the test above. A counter that increments on every connection would
// pass that one and be useless.
func TestGnmiSuccessfulHandshakeDoesNotCount(t *testing.T) {
	mgr, _, addr := startRealGnmiServer(t, true, true)

	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := gnmipb.NewGNMIClient(conn).Capabilities(ctx, &gnmipb.CapabilityRequest{}); err != nil {
		t.Fatalf("Capabilities over TLS: %v", err)
	}

	if got := atomic.LoadUint64(&mgr.gnmiTLSHandshakeFailures); got != 0 {
		t.Errorf("tls_handshake_failures = %d after a SUCCESSFUL handshake, want 0", got)
	}
}

// failingListener returns a fixed error from Accept exactly once, then
// blocks until closed. It exercises the Accept-error bucket without
// needing a real fd-exhaustion scenario.
type failingListener struct {
	net.Listener
	err   error
	fired atomic.Bool
	done  chan struct{}
}

func (l *failingListener) Accept() (net.Conn, error) {
	if l.fired.CompareAndSwap(false, true) {
		return nil, l.err
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *failingListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

// TestGnmiAcceptErrorsCountSeparately pins the split introduced by
// nl6#663: an Accept error is a listener fault (fd exhaustion at 30k
// listeners is the realistic one) and must not land in the counter that
// reports client transport mismatches.
func TestGnmiAcceptErrorsCountSeparately(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantAccept   uint64
		wantHandshak uint64
	}{
		{"non-closed error counts", errors.New("too many open files"), 1, 0},
		{"ErrClosed counts nothing", net.ErrClosed, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var acceptFailures, handshakeFailures uint64
			inner := &failingListener{err: tc.err, done: make(chan struct{})}
			defer inner.Close()

			l := newGnmiFailureCountingListener(inner, &acceptFailures)
			if _, err := l.Accept(); err == nil {
				t.Fatal("Accept returned no error")
			}

			if got := atomic.LoadUint64(&acceptFailures); got != tc.wantAccept {
				t.Errorf("listener_accept_failures = %d, want %d", got, tc.wantAccept)
			}
			if got := atomic.LoadUint64(&handshakeFailures); got != tc.wantHandshak {
				t.Errorf("tls_handshake_failures = %d, want %d", got, tc.wantHandshak)
			}
		})
	}
}

// TestGnmiPlaintextModeServesCapabilities pins -gnmi-tls=false. The
// response is compared against the TLS path's so the plaintext mode
// cannot quietly serve something different.
func TestGnmiPlaintextModeServesCapabilities(t *testing.T) {
	_, _, plainAddr := startRealGnmiServer(t, false, true)

	conn, err := grpc.NewClient(plainAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("plaintext NewClient: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	plainResp, err := gnmipb.NewGNMIClient(conn).Capabilities(ctx, &gnmipb.CapabilityRequest{})
	if err != nil {
		t.Fatalf("plaintext Capabilities: %v", err)
	}

	// Same request over a TLS listener, for comparison.
	_, _, tlsAddr := startRealGnmiServer(t, true, true)
	tlsConn := dialTestGnmi(t, tlsAddr)
	defer tlsConn.Close()
	tlsResp, err := gnmipb.NewGNMIClient(tlsConn).Capabilities(ctx, &gnmipb.CapabilityRequest{})
	if err != nil {
		t.Fatalf("TLS Capabilities: %v", err)
	}

	if plainResp.String() != tlsResp.String() {
		t.Errorf("plaintext and TLS Capabilities differ:\nplain=%s\n  tls=%s",
			plainResp.String(), tlsResp.String())
	}
}

// TestGnmiPlaintextModeRejectsTLSClient: the mode is a choice, not a
// fallback. Serving both on one port would leave a client unable to
// tell from the port what it gets (design.md D7).
func TestGnmiPlaintextModeRejectsTLSClient(t *testing.T) {
	_, _, addr := startRealGnmiServer(t, false, true)

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	if err := tc.Handshake(); err == nil {
		t.Fatal("TLS handshake succeeded against a plaintext listener")
	}
}

// TestGnmiPlaintextModeNeedsNoSharedCert: the sharedTLSCert
// precondition must sit INSIDE the TLS branch, or a plaintext fleet
// cannot start on a manager without a certificate.
func TestGnmiPlaintextModeNeedsNoSharedCert(t *testing.T) {
	_, dev, addr := startRealGnmiServer(t, false, false)

	if dev.gnmiServer == nil {
		t.Fatal("gnmiServer is nil: startGnmiServer did not bind without a shared cert")
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("plaintext NewClient: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := gnmipb.NewGNMIClient(conn).Capabilities(ctx, &gnmipb.CapabilityRequest{}); err != nil {
		t.Fatalf("Capabilities on a certless plaintext device: %v", err)
	}
}

// TestGnmiTLSRequiresSharedCert is the other half: under the TLS
// default a manager with no certificate must still fail loudly, as it
// did before nl6#663.
func TestGnmiTLSRequiresSharedCert(t *testing.T) {
	mgr := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
	}
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{Port: gnmiDefaultPort, TLSEnabled: true}); err != nil {
		t.Fatalf("StartGnmiSubsystem: %v", err)
	}
	prev := manager
	manager = mgr
	defer func() { manager = prev }()

	dev := newTestGnmiDevice(t, 1)
	dev.IP = net.IPv4(127, 0, 0, 1)
	dev.mu.Lock()
	err := dev.startGnmiServer(0)
	dev.mu.Unlock()
	if err == nil {
		dev.mu.Lock()
		dev.stopGnmiServer()
		dev.mu.Unlock()
		t.Fatal("startGnmiServer succeeded with TLS on and no shared certificate")
	}
	if !strings.Contains(err.Error(), "no shared TLS certificate") {
		t.Errorf("error %q does not name the missing certificate", err)
	}
}

// TestGnmiHandshakeFailureLogsOnce pins the fleet-scale log gate. One
// misconfigured collector produces one failure per device per retry —
// the issue's own capture is 132 attempts in four minutes from a single
// client against 11,000 devices. The counter carries the volume; the
// log line is gated, matching trap_exporter.go's logFirstEncodeErr.
func TestGnmiHandshakeFailureLogsOnce(t *testing.T) {
	const attempts = 12

	// NOT the package's captureLog helper: it hands out a bytes.Buffer
	// with no mutex, which is correct for a synchronous log but races
	// here — the handshake, and therefore the log write, happens on
	// gRPC's own goroutine after the client's write has returned.
	sink := &syncLogSink{}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(sink)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()

	mgr, _, addr := startRealGnmiServer(t, true, true)
	for i := 0; i < attempts; i++ {
		if _, err := sendPlaintextPreface(t, addr); err != nil {
			_ = err // the read error is the point; nothing to assert per-attempt
		}
	}
	waitForCounter(t, &mgr.gnmiTLSHandshakeFailures, attempts)
	// The counter is incremented before the Once fires, so settle for the
	// line rather than reading straight after the count.
	waitForLogLine(t, sink, "gNMI handshake failed")
	out := sink.String()

	if got := atomic.LoadUint64(&mgr.gnmiTLSHandshakeFailures); got != attempts {
		t.Errorf("tls_handshake_failures = %d after %d failures, want %d", got, attempts, attempts)
	}
	if n := strings.Count(out, "gNMI handshake failed"); n != 1 {
		t.Errorf("got %d handshake log lines for %d failures, want exactly 1\n%s", n, attempts, out)
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Errorf("log line does not name the device IP:\n%s", out)
	}
}

// syncLogSink is a mutex-guarded log destination. gRPC writes the
// handshake log from its own goroutine, so an unguarded buffer read
// races the writer under -race.
type syncLogSink struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitForLogLine polls the sink until `want` appears, then waits a beat
// so a SECOND line — the thing the test is asserting cannot happen —
// has a chance to show up rather than being outrun.
func waitForLogLine(t *testing.T, sink *syncLogSink, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(sink.String(), want) {
			time.Sleep(200 * time.Millisecond)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("log line %q never appeared within 5s; got:\n%s", want, sink.String())
}

// waitForCounter polls an atomic counter until it reaches want. The
// handshake runs on gRPC's own goroutine after the client's write
// returns, so the counter is not synchronous with the test's read.
func waitForCounter(t *testing.T, c *uint64, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint64(c) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("counter reached %d, want %d within 5s", atomic.LoadUint64(c), want)
}

// interfaceGuard keeps the credentials wrapper honest at compile time.
var _ credentials.TransportCredentials = (*gnmiHandshakeCountingCreds)(nil)
