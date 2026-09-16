/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// gnmiGracefulStopTimeout caps how long stopGnmiServer waits for
// in-flight RPCs before forcing a Stop().
const gnmiGracefulStopTimeout = 2 * time.Second

// Slowloris-hardening defaults applied to every per-device gNMI gRPC
// server (P14). These bound the resources a misbehaving (or hostile)
// client can hold open: a capped concurrent stream count, an
// idle-connection reaper, and a keepalive-ping-with-timeout so dead
// peers are noticed without waiting for TCP retransmit timeouts.
//
// `gnmiFirstRecvTimeout` is enforced inside Subscribe to bound how long
// a client can hold the server-side stream goroutine open without
// sending the initial SubscriptionList.
//
// gnmiMaxConcurrentStreams was lowered 64 → 16 by the add-interface-state
// change (§D9). Per-device ON_CHANGE fan-out adds one listener channel
// per subscriber; the cap bounds the worst case for runaway client
// behavior. The realistic ceiling is 2–3 streams per device (primary
// collector + maybe a debug session), at which point per-stream cost
// is depth-16 × ~64 B per StateChange entry × 3 streams ≈ 3 KiB per
// device, or ~90 MiB at 30k devices.
//
// **Soft-breaking change:** the cap is HTTP/2-level (set via the
// SETTINGS_MAX_CONCURRENT_STREAMS frame). Clients that open >16
// concurrent Subscribe streams on the same TCP connection will see the
// 17th QUEUE at the transport layer rather than receive a gRPC status
// code — gRPC reports breached MaxConcurrentStreams as the stream
// blocking until a slot frees, not as `codes.ResourceExhausted`. To
// service >16 parallel streams, open a second TCP connection.
const (
	gnmiMaxConcurrentStreams uint32 = 16
	gnmiFirstRecvTimeout            = 30 * time.Second
)

// startGnmiServer binds a gRPC listener inside the device's netns (or
// the root ns if isolation is off) and registers the gNMI service.
// Mirrors the SSH and HTTPS REST start patterns. Returns any error to
// the caller; on error the device-create call fails.
//
// The transport is TLS by default and plaintext under -gnmi-tls=false
// (`mgr.gnmiTLSEnabled`). The shared-certificate precondition is
// checked INSIDE the TLS branch: under plaintext there is no cert to
// require, and hoisting the check would stop a plaintext fleet from
// starting on a manager that has none (nl6#663).
//
// P4 lock discipline: caller MUST hold `d.mu`. Both reads of and
// writes to `d.gnmiServer` / `d.gnmiListener` happen with the caller
// holding the device lock so a concurrent `stopGnmiServer` (also
// requiring the caller hold `d.mu`) observes a consistent
// (server, listener) pair. The Serve goroutine is spawned outside the
// lock — gRPC's GracefulStop is the lifetime owner and tolerates
// concurrent Stop while Serve is mid-flight.
func (d *DeviceSimulator) startGnmiServer(port int) error {
	if d == nil {
		return fmt.Errorf("nil device")
	}
	mgr := manager
	if mgr == nil {
		return fmt.Errorf("simulator manager not initialised")
	}
	if mgr.gnmiTLSEnabled && mgr.sharedTLSCert == nil {
		return fmt.Errorf("no shared TLS certificate available for gNMI on %s", d.IP)
	}

	addr := fmt.Sprintf("%s:%d", d.IP.String(), port)
	var rawListener net.Listener
	var err error
	if d.netNamespace != nil {
		rawListener, err = d.netNamespace.ListenTCPInNamespace("tcp", addr)
	} else {
		lc := net.ListenConfig{Control: setSocketBufferSize}
		rawListener, err = lc.Listen(context.Background(), "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("failed to start gNMI server on %s: %v", addr, err)
	}

	// Wrap the raw listener so Accept failures increment a
	// manager-level counter visible via GET /api/v1/gnmi/status. Accept
	// errors are LISTENER faults; handshake failures are counted
	// separately at the credentials seam below (nl6#663).
	listener := newGnmiFailureCountingListener(rawListener, &mgr.gnmiListenerAcceptFailures)

	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(gnmiMaxConcurrentStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if mgr.gnmiTLSEnabled {
		opts = append(opts, grpc.Creds(mgr.gnmiServerCredsFor(d.IP.String())))
	}

	server := grpc.NewServer(opts...)
	gnmipb.RegisterGNMIServer(server, newGnmiServer(
		d,
		&mgr.gnmiActiveSubscriptions,
		&mgr.gnmiUpdatesSent,
		&mgr.gnmiUpdatesDropped,
	))

	// Caller holds d.mu — assignments are atomic w.r.t. stopGnmiServer.
	d.gnmiServer = server
	d.gnmiListener = listener

	go func() {
		if err := server.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			log.Printf("gNMI server error on %s: %v", addr, err)
		}
	}()
	return nil
}

// stopGnmiServer gracefully shuts down the device's gNMI server with a
// 2-second timeout, falling back to a forced Stop if it doesn't drain.
// Idempotent.
//
// P4 lock discipline: caller MUST hold `d.mu`. The (server, listener)
// pair is read and cleared with the caller's lock held, so a racing
// `startGnmiServer` (also requiring `d.mu`) cannot observe a torn
// state. The lock is held across GracefulStop, which is safe because
// no gNMI request handler in this package takes `d.mu` — handlers
// only touch atomic counters and `metricsCycler.ifCounters` (a
// sync.Map).
func (d *DeviceSimulator) stopGnmiServer() {
	if d == nil || d.gnmiServer == nil {
		return
	}
	server := d.gnmiServer
	d.gnmiServer = nil
	d.gnmiListener = nil // closed by GracefulStop / Stop

	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(gnmiGracefulStopTimeout):
		server.Stop()
	}
}

// gnmiServerCredsFor returns the TLS credentials for one device's gNMI
// listener, wrapped so a failed handshake is counted and the first one
// is logged.
//
// The underlying credentials are built ONCE per manager: a wrapper is a
// three-word struct, but `credentials.NewServerTLSFromCert` builds a
// tls.Config per call, and this runs once per device at 30k devices.
func (sm *SimulatorManager) gnmiServerCredsFor(deviceIP string) credentials.TransportCredentials {
	sm.gnmiBaseCredsOnce.Do(func() {
		sm.gnmiBaseCreds = credentials.NewServerTLSFromCert(sm.sharedTLSCert)
	})
	return &gnmiHandshakeCountingCreds{
		TransportCredentials: sm.gnmiBaseCreds,
		mgr:                  sm,
		deviceIP:             deviceIP,
	}
}

// gnmiHandshakeCountingCreds counts TLS handshakes that fail on an
// already-accepted connection, and logs the first one per process.
//
// This is the ONLY point in gRPC's server path that observes a
// handshake outcome. `Server.Serve` calls `lis.Accept()` and then hands
// the connection to `handleRawConn`, which runs `ServerHandshake` — so
// a listener wrapper sees a healthy connection and learns nothing about
// what happens to it next. Counting at Accept (what nl6 did before
// nl6#663) therefore reported 0 for every client-side transport
// mismatch, including a plaintext gRPC client against this TLS
// listener, which is the single most likely misconfiguration here.
//
// A `grpc.StatsHandler` is not an alternative: `ConnBegin`/`ConnEnd`
// carry no error, so a failed handshake is indistinguishable from a
// connection that closed normally.
type gnmiHandshakeCountingCreds struct {
	credentials.TransportCredentials
	mgr      *SimulatorManager
	deviceIP string
}

// ServerHandshake delegates to the wrapped credentials and records a
// failure. The log line is gated to one per process while the counter
// moves on every occurrence — the trap/syslog fire-path convention
// (`logFirstEncodeErr`), for the same reason: one misconfigured
// collector retrying against a 30k fleet is a fleet-sized log volume
// describing a single fault.
func (c *gnmiHandshakeCountingCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ServerHandshake(rawConn)
	if err != nil && c.mgr != nil {
		atomic.AddUint64(&c.mgr.gnmiTLSHandshakeFailures, 1)
		peer := "unknown"
		if rawConn != nil && rawConn.RemoteAddr() != nil {
			peer = rawConn.RemoteAddr().String()
		}
		c.mgr.gnmiFirstHandshakeErrOnce.Do(func() {
			log.Printf("gNMI handshake failed on %s from %s: %v "+
				"(a plaintext gNMI client against the TLS listener looks exactly like this; "+
				"use --skip-verify, or start nl6 with -gnmi-tls=false. "+
				"Further handshake errors are suppressed; see tls_handshake_failures "+
				"on GET /api/v1/gnmi/status)", c.deviceIP, peer, err)
		})
	}
	return conn, info, err
}

// Clone preserves the wrapper. gRPC clones server credentials, and a
// Clone that returned the bare inner credentials would silently drop
// the counting for the cloned copy.
func (c *gnmiHandshakeCountingCreds) Clone() credentials.TransportCredentials {
	return &gnmiHandshakeCountingCreds{
		TransportCredentials: c.TransportCredentials.Clone(),
		mgr:                  c.mgr,
		deviceIP:             c.deviceIP,
	}
}

// gnmiFailureCountingListener is a thin net.Listener wrapper that
// increments `failures` whenever Accept returns an error other than
// net.ErrClosed (which is the expected signal during shutdown).
//
// It counts LISTENER faults — fd exhaustion at 30k listeners is the
// realistic one. It does NOT see TLS handshake failures: those happen
// after Accept returns, and are counted by gnmiHandshakeCountingCreds.
type gnmiFailureCountingListener struct {
	net.Listener
	failures *uint64
}

func newGnmiFailureCountingListener(inner net.Listener, failures *uint64) *gnmiFailureCountingListener {
	return &gnmiFailureCountingListener{Listener: inner, failures: failures}
}

// Accept counts errors that aren't the listener-closed sentinel.
func (l *gnmiFailureCountingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			atomic.AddUint64(l.failures, 1)
		}
		return nil, err
	}
	return c, nil
}
