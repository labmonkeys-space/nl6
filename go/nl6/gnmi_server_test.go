/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Tests in this file mutate the package-level `manager` global via
// `startTestGnmiServer` (save-and-restore around the test body). They
// therefore CANNOT be run with `t.Parallel()` — concurrent tests would
// race on the same global. The mutation pattern is unavoidable while
// `manager` lives at package scope; refactoring it into a per-test
// scoped value is out of scope for this change.

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// generateTestTLSCert produces a self-signed cert valid for 127.0.0.1
// suitable for fronting a per-test gRPC listener.
func generateTestTLSCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nl6-test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return &cert
}

// startTestGnmiServer wires a per-test SimulatorManager + DeviceSimulator
// + gnmi gRPC server bound to 127.0.0.1:0 (free port). Returns the
// server's listening address and a cleanup func.
func startTestGnmiServer(t *testing.T) (mgr *SimulatorManager, dev *DeviceSimulator, addr string, cleanup func()) {
	t.Helper()

	// Manager with shared TLS cert, gNMI subsystem enabled.
	mgr = &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
		sharedTLSCert:   generateTestTLSCert(t),
	}
	if err := mgr.StartGnmiSubsystem(GnmiSubsystemConfig{Port: 0, Disabled: false}); err != nil {
		t.Fatalf("StartGnmiSubsystem: %v", err)
	}

	// Hook the package-level `manager` global so startGnmiServer can
	// reach the shared cert. Save and restore around the test.
	prev := manager
	manager = mgr

	// Synthetic device with cycler.
	resolver := newTestPathResolver(t, 2)
	dev = resolver.device
	mgr.devices["test"] = dev

	// Pick an ephemeral port. We can't use mgr.gnmiPort=0 with
	// startGnmiServer because the listener is created internally; bind
	// our own listener and run the same wiring inline so we control
	// the address. We then store the result on the device fields the
	// way startGnmiServer would.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(mgr.sharedTLSCert)))
	gnmipb.RegisterGNMIServer(server, newGnmiServer(
		dev,
		&mgr.gnmiActiveSubscriptions,
		&mgr.gnmiUpdatesSent,
		&mgr.gnmiUpdatesDropped,
	))
	dev.gnmiServer = server
	dev.gnmiListener = listener

	go func() { _ = server.Serve(listener) }()

	addr = listener.Addr().String()
	cleanup = func() {
		dev.stopGnmiServer()
		manager = prev
	}
	return mgr, dev, addr, cleanup
}

// dialTestGnmi opens a TLS-wrapped gRPC client to addr. We use the
// deprecated `grpc.DialContext` rather than `grpc.NewClient` because we
// want WithBlock + WithReturnConnectionError semantics so dial failures
// surface here, not at first RPC — `grpc.NewClient` silently ignores
// both options. The deprecation only affects the call site; the
// returned ClientConn behaves identically once connected.
func dialTestGnmi(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // self-signed test cert
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr, //nolint:staticcheck // need WithBlock semantics
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithBlock(),                 //nolint:staticcheck
		grpc.WithReturnConnectionError(), //nolint:staticcheck
	)
	if err != nil {
		t.Fatalf("grpc.DialContext: %v", err)
	}
	return conn
}

func TestGnmiServer_LifecycleAndCapabilities(t *testing.T) {
	_, _, addr, cleanup := startTestGnmiServer(t)
	defer cleanup()

	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	client := gnmipb.NewGNMIClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.Capabilities(ctx, &gnmipb.CapabilityRequest{})
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if resp.GetGNMIVersion() != gnmiVersion {
		t.Errorf("gNMI version: got %q, want %q", resp.GetGNMIVersion(), gnmiVersion)
	}
}

func TestGnmiServer_StopTerminatesListener(t *testing.T) {
	_, dev, addr, cleanup := startTestGnmiServer(t)
	t.Cleanup(cleanup)

	// Stop the device's gNMI server. GracefulStop drains synchronously
	// (or falls back to Stop after gnmiGracefulStopTimeout) so by the
	// time this returns the listener has been closed.
	dev.stopGnmiServer()

	// Verify the listener is closed: a subsequent dial must fail with
	// connection-refused. We poll briefly because GracefulStop may
	// finalise the socket close on a separate goroutine and the
	// port-table update isn't guaranteed atomic with our return.
	//
	// Note: an earlier revision of this test attempted a deterministic
	// rebind on the same address. That works on Linux but is unreliable
	// on macOS/BSD where the kernel reserves the port briefly after
	// close even without TIME_WAIT (no client ever connected, so there
	// is no TIME_WAIT — yet bind still fails for ~100ms). Polling for
	// connection-refused sidesteps the issue: we only need to confirm
	// "no one is accepting" which is the actual safety property.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return // listener closed — success
		}
		_ = c.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("listener at %s still accepting connections after stopGnmiServer", addr)
}

// TestGnmiServer_MaxConcurrentStreams_Cap16 verifies the per-device
// gRPC server caps concurrent streams at 16 (§D9 of add-interface-state,
// lowered from 64). The 17th concurrent Subscribe stream against one
// device must fail. gRPC reports breached MaxConcurrentStreams as the
// stream blocking until a slot frees, NOT as ResourceExhausted on
// connect, so we observe via timing: 16 streams complete their
// initial-sync handshake; the 17th does not finish within a generous
// deadline because it's queued waiting for a slot.
func TestGnmiServer_MaxConcurrentStreams_Cap16(t *testing.T) {
	// Build a production-shaped server: same options as startGnmiServer
	// so the cap matches what real devices see.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer listener.Close()

	cert := generateTestTLSCert(t)
	server := grpc.NewServer(
		grpc.Creds(credentials.NewServerTLSFromCert(cert)),
		grpc.MaxConcurrentStreams(gnmiMaxConcurrentStreams),
	)
	resolver := newTestPathResolver(t, 1)
	var active int64
	var sent, dropped uint64
	gnmipb.RegisterGNMIServer(server, newGnmiServer(resolver.device, &active, &sent, &dropped))
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	addr := listener.Addr().String()

	// Constant must be 16 (regression on the §D9 design lock).
	if gnmiMaxConcurrentStreams != 16 {
		t.Fatalf("gnmiMaxConcurrentStreams = %d, want 16 (locked by §D9)", gnmiMaxConcurrentStreams)
	}

	// gRPC's MaxConcurrentStreams is an HTTP/2 SETTINGS frame applied
	// per-connection. To exercise the cap we open all streams on ONE
	// grpc.ClientConn — separate connections each get their own quota.
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	client := gnmipb.NewGNMIClient(conn)

	const slots = 16
	streams := make([]gnmipb.GNMI_SubscribeClient, slots)
	cancels := make([]context.CancelFunc, slots)
	for i := 0; i < slots; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels[i] = cancel
		stream, err := client.Subscribe(ctx)
		if err != nil {
			t.Fatalf("Subscribe[%d]: %v", i, err)
		}
		streams[i] = stream
		if err := stream.Send(&gnmipb.SubscribeRequest{
			Request: &gnmipb.SubscribeRequest_Subscribe{
				Subscribe: &gnmipb.SubscriptionList{
					Mode: gnmipb.SubscriptionList_STREAM,
					Subscription: []*gnmipb.Subscription{{
						Path:           pathFromString(t, "/interfaces/interface[name=*]/state/ifindex"),
						Mode:           gnmipb.SubscriptionMode_SAMPLE,
						SampleInterval: uint64(time.Second),
					}},
				},
			},
		}); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
		// Drain at least one response so we know the stream is live
		// and holding a slot.
		if _, err := stream.Recv(); err != nil {
			t.Fatalf("Recv[%d]: %v", i, err)
		}
	}
	defer func() {
		for i := 0; i < slots; i++ {
			cancels[i]()
		}
	}()

	// 17th stream on the same connection. gRPC queues it until a slot
	// frees on the server. With a short ctx deadline, Recv must NOT
	// produce a SubscribeResponse (it's blocked client-side waiting
	// for the server to accept the HEADERS frame).
	ctx17, cancel17 := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel17()
	stream17, err := client.Subscribe(ctx17)
	if err != nil {
		return // also acceptable — some gRPC versions error at Subscribe time
	}
	_ = stream17.Send(&gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{{
					Path:           pathFromString(t, "/interfaces/interface[name=*]/state/ifindex"),
					Mode:           gnmipb.SubscriptionMode_SAMPLE,
					SampleInterval: uint64(time.Second),
				}},
			},
		},
	})
	gotResp := make(chan error, 1)
	go func() {
		_, err := stream17.Recv()
		gotResp <- err
	}()
	select {
	case err := <-gotResp:
		if err == nil {
			t.Error("17th concurrent stream got an initial response; MaxConcurrentStreams cap NOT enforced")
		}
	case <-time.After(1700 * time.Millisecond):
		// Recv blocked at ctx deadline → cap enforced; pass.
	}
}
